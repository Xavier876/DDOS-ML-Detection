"""Analyst workflow: verdicts, review files, SIEM alert export and labelled feedback export.

Everything here works on plain arrays so it can be unit-tested without Qt.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from .features import FEATURES

VERDICTS = ["unreviewed", "confirmed attack", "false positive", "unsure"]
UNREVIEWED, CONFIRMED, FALSE_POSITIVE, UNSURE = range(4)
FEEDBACK_LABEL = {CONFIRMED: 1, FALSE_POSITIVE: 0}     # unsure / unreviewed are excluded
REVIEW_FORMAT = 1

# Alert fields, in order. Tracing fields appear only when the input CSV had those columns.
ALERT_FIELDS = ["alert_id", "row_number", "source_file", "timestamp", "src_ip", "dst_ip", "dst_port",
                "model_name", "model_version", "model_score", "threshold", "flag",
                "top_feature_1", "top_feature_2", "top_feature_3"]
TRACING_FIELDS = {"timestamp", "src_ip", "dst_ip", "dst_port"}


@dataclass
class Review:
    """Verdict codes (one per loaded row) and free-text notes keyed by row position."""
    verdicts: np.ndarray
    notes: dict[int, str] = field(default_factory=dict)
    dirty: bool = False

    @classmethod
    def empty(cls, n: int) -> "Review":
        return cls(np.zeros(n, dtype=np.int8))

    def set(self, pos: int, verdict: int | None = None, note: str | None = None):
        if verdict is not None:
            self.verdicts[pos] = verdict
        if note is not None:
            if note.strip():
                self.notes[pos] = note.strip()
            else:
                self.notes.pop(pos, None)
        self.dirty = True

    def reviewed_positions(self) -> np.ndarray:
        pos = set(np.flatnonzero(self.verdicts != UNREVIEWED).tolist()) | set(self.notes)
        return np.array(sorted(pos), dtype=np.int64)


def default_review_name(source_file: str) -> str:
    return f"review_{Path(source_file).stem}.json"


def save_review(path: Path, review: Review, rows: np.ndarray, scores: np.ndarray, flags: np.ndarray,
                threshold: float, source_file: str, model_name: str, model_version: str) -> int:
    items = []
    for pos in review.reviewed_positions():
        s = scores[pos]
        items.append({
            "row_number": int(rows[pos]),
            "source_file": source_file,
            "model_score": None if np.isnan(s) else round(float(s), 6),
            "flag": str(flags[pos]),
            "threshold": threshold,
            "verdict": VERDICTS[int(review.verdicts[pos])],
            "note": review.notes.get(int(pos), ""),
            "model_name": model_name,
            "model_version": model_version,
        })
    doc = {"format": REVIEW_FORMAT, "source_file": source_file, "model_name": model_name,
           "model_version": model_version, "saved": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "reviews": items}
    Path(path).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    review.dirty = False
    return len(items)


@dataclass
class LoadReport:
    applied: int
    missing_rows: list[int]
    other_source: bool
    file_source: str


def load_review(path: Path, review: Review, rows: np.ndarray, source_file: str) -> LoadReport:
    """Apply a saved review to the loaded data, matching by original row number."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    pos_of = {int(r): i for i, r in enumerate(rows)}
    applied, missing = 0, []
    for item in doc.get("reviews", []):
        pos = pos_of.get(int(item["row_number"]))
        if pos is None:
            missing.append(int(item["row_number"]))
            continue
        verdict = item.get("verdict", "unreviewed")
        review.set(pos, VERDICTS.index(verdict) if verdict in VERDICTS else UNREVIEWED, item.get("note", ""))
        applied += 1
    review.dirty = False
    src = doc.get("source_file", "")
    return LoadReport(applied, missing, bool(src) and src != source_file, src)


def alert_records(positions: np.ndarray, rows: np.ndarray, scores: np.ndarray, flags: np.ndarray,
                  threshold: float, source_file: str, model_name: str, model_version: str,
                  top3: list[list[str]], tracing: dict[str, np.ndarray]) -> list[dict]:
    """One record per alert. `tracing` maps tracing field names (timestamp, src_ip, ...) to
    arrays; only fields present in the input are included. No model-input values are included."""
    stem = Path(source_file).stem
    out = []
    for i, pos in enumerate(positions):
        rec = {"alert_id": f"{stem}:{int(rows[pos])}", "row_number": int(rows[pos]), "source_file": source_file}
        for f in ("timestamp", "src_ip", "dst_ip", "dst_port"):
            if f in tracing:
                rec[f] = str(tracing[f][pos])
        rec.update({"model_name": model_name, "model_version": model_version,
                    "model_score": round(float(scores[pos]), 6), "threshold": threshold,
                    "flag": str(flags[pos])})
        feats = top3[i] + [""] * (3 - len(top3[i]))
        rec.update({"top_feature_1": feats[0], "top_feature_2": feats[1], "top_feature_3": feats[2]})
        out.append(rec)
    return out


def write_alerts(base_path: Path, records: list[dict]) -> tuple[Path, Path]:
    """Write <base>.csv and <base>.jsonl with the same records."""
    base = Path(base_path)
    if base.suffix.lower() in (".csv", ".jsonl"):
        base = base.with_suffix("")
    csv_path, jsonl_path = base.with_suffix(".csv"), base.with_suffix(".jsonl")
    cols = [f for f in ALERT_FIELDS if not records or f in records[0]]
    pd.DataFrame(records, columns=cols).to_csv(csv_path, index=False)
    with open(jsonl_path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return csv_path, jsonl_path


def feedback_frame(review: Review, X: pd.DataFrame, rows: np.ndarray, source_file: str) -> pd.DataFrame:
    """9 feature columns + label (confirmed attack -> 1, false positive -> 0) + source + row.
    Unsure and unreviewed rows are excluded."""
    keep = np.isin(review.verdicts, list(FEEDBACK_LABEL))
    pos = np.flatnonzero(keep)
    out = X.iloc[pos][FEATURES].reset_index(drop=True)
    out["label"] = [FEEDBACK_LABEL[int(v)] for v in review.verdicts[pos]]
    out["source_file"] = source_file
    out["row_number"] = rows[pos]
    return out
