"""Feature notes (the group's Week 3 text) and the evidence from notebook section 9b.

The verdict next to each assumption is computed from feature_evidence.csv, never written by hand.
`single_feature_auc` > 0.5 means attacks have higher values, < 0.5 lower, 0.5 no separation.
  expected "higher"/"lower":
    supported                   AUC at least AUC_MARGIN from 0.5 on the expected side, medians agree
    opposite of the assumption  AUC at least AUC_MARGIN from 0.5 on the other side
    not supported so far        AUC within AUC_MARGIN of 0.5 (the feature alone barely separates)
    unclear                     AUC and medians point different ways
  expected "different": supported when |AUC - 0.5| >= AUC_MARGIN in either direction
  expected "none":      the assumption states no direction for that column; evidence is shown only
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pandas as pd

from .features import REGISTRY

AUC_MARGIN = 0.1
EVIDENCE_COLUMNS = ["attack", "feature", "attack_median", "benign_median_same_day", "direction",
                    "attack_zero_share", "benign_zero_share", "single_feature_auc"]
MISSING_EVIDENCE = "Run notebook section 9b to fill this in."
SUPPORTED, OPPOSITE, NOT_SUPPORTED, UNCLEAR, NO_DIRECTION = (
    "supported", "opposite of the assumption", "not supported so far", "unclear", "no direction stated")


def load_notes(path: Path) -> dict:
    """The notes file, checked against the registry (one entry per feature group, 1-6 and 8-11)."""
    notes = json.loads(Path(path).read_text(encoding="utf-8"))
    have = [g["number"] for g in notes["groups"]]
    want = [g.number for g in REGISTRY]
    if sorted(have) != want:
        raise ValueError(f"feature_notes.json has groups {have}; the registry has {want}")
    return notes


def notes_by_number(notes: dict) -> dict[int, dict]:
    return {g["number"]: g for g in notes["groups"]}


def load_evidence(path: Path) -> Optional[pd.DataFrame]:
    """The evidence table, or None if the file is missing or not in the expected format."""
    p = Path(path)
    if not p.is_file():
        return None
    df = pd.read_csv(p)
    if any(c not in df.columns for c in EVIDENCE_COLUMNS):
        return None
    return df


def assess(expected: str, direction: str, auc: float) -> tuple[str, str]:
    """(verdict, plain-words explanation) for one column's assumption against one tool's evidence."""
    if expected == "none":
        return NO_DIRECTION, "the assumption states no direction for this column"
    if pd.isna(auc):
        return UNCLEAR, "AUC not available"
    if expected == "different":
        if abs(auc - 0.5) >= AUC_MARGIN:
            return SUPPORTED, f"attack values differ from benign (attacks {'higher' if auc > 0.5 else 'lower'}, AUC {auc:.2f})"
        return NOT_SUPPORTED, f"the feature alone barely separates attack from benign (AUC {auc:.2f})"
    sep = (auc - 0.5) if expected == "higher" else (0.5 - auc)
    opposite = {"higher": "lower", "lower": "higher"}[expected]
    if sep >= AUC_MARGIN and direction != opposite:
        return SUPPORTED, f"attacks are {expected} (AUC {auc:.2f})"
    if sep <= -AUC_MARGIN:
        return OPPOSITE, f"attacks are {opposite}, not {expected} (AUC {auc:.2f})"
    if abs(sep) < AUC_MARGIN:
        return NOT_SUPPORTED, f"the feature alone barely separates attack from benign (AUC {auc:.2f})"
    return UNCLEAR, f"AUC {auc:.2f} and the medians ({direction}) point different ways"
