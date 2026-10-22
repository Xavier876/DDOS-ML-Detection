"""Feature notes (assumptions) and the evidence from notebook section 9b.

The verdict next to each assumption is computed from feature_evidence.csv, never written by hand:
  - supported:      the medians move the expected way AND the single-feature AUC is on the
                    expected side of 0.5 by at least AUC_MARGIN
  - contradicted:   the AUC is on the opposite side by at least AUC_MARGIN
  - not supported:  the AUC is within AUC_MARGIN of 0.5 (the feature alone barely separates)
  - unclear:        the AUC and the medians point in different directions
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pandas as pd

AUC_MARGIN = 0.1
EVIDENCE_COLUMNS = ["attack", "feature", "attack_median", "benign_median_same_day", "direction",
                    "attack_zero_share", "benign_zero_share", "single_feature_auc"]
MISSING_EVIDENCE = "Run notebook section 9b to fill this in."


def load_notes(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


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
    """(verdict, explanation) for one assumption against one attack tool's evidence."""
    if pd.isna(auc):
        return "unclear", "AUC not available"
    sep = (auc - 0.5) if expected == "higher" else (0.5 - auc)
    opposite = {"higher": "lower", "lower": "higher"}[expected]
    if sep >= AUC_MARGIN and direction != opposite:
        return "supported", f"attacks are {expected} (AUC {auc:.2f})"
    if sep <= -AUC_MARGIN:
        return "contradicted", f"attacks are {opposite}, not {expected} (AUC {auc:.2f})"
    if abs(sep) < AUC_MARGIN:
        return "not supported", f"the feature alone barely separates attack from benign (AUC {auc:.2f})"
    return "unclear", f"AUC {auc:.2f} and the medians ({direction}) disagree"
