r"""Evidence rows (what the data showed) for the window features 7 and 16-18, in notebook 9b's format.

    .\.venv\Scripts\python.exe DDoSDetector\scripts\feature_evidence_windows.py

Notebook section 9b wrote app\data\feature_evidence.csv for the per-flow features from the two published files.
The window features need the whole capture file with IPs, so their rows are computed here (5 Nov 2026) on the
20 Feb file and the 21 Feb capture rebuilt from the raw packets (train_model.FILES_IP), loaded and built exactly
as training loads them. For each attack tool and column: the attack median, the benign median of the same file
(for 21 Feb: the relabelled capture's genuinely benign flows), the direction of the medians, the share of zeros
on each side and the single-feature AUC (attack = 1) against that file's benign flows. Rows for these columns
are replaced; every other row of the file is kept as 9b wrote it.
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.feature_notes import EVIDENCE_COLUMNS  # noqa: E402
from app.core.features import ATTACK_TOOLS, CAPTURE_COLUMN, CONTEXT_COLUMNS  # noqa: E402
from app.paths import DATA_DIR, FEATURE_EVIDENCE  # noqa: E402
from train.train_model import FILES_IP, load  # noqa: E402


def evidence_rows(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    rows = []
    for tool in ATTACK_TOOLS:
        att = df[df["tool"] == tool]
        if att.empty:
            continue
        same_day = df[(df["tool"] == "Benign") & df[CAPTURE_COLUMN].isin(att[CAPTURE_COLUMN].unique())]
        for c in columns:
            a, b = att[c].dropna(), same_day[c].dropna()
            am, bm = float(a.median()), float(b.median())
            y = np.r_[np.ones(len(a)), np.zeros(len(b))]
            auc = float(roc_auc_score(y, np.r_[a.to_numpy(), b.to_numpy()])) if len(a) and len(b) else np.nan
            rows.append({"attack": tool, "feature": c, "attack_median": am, "benign_median_same_day": bm,
                         "direction": "higher" if am > bm else "lower" if am < bm else "same",
                         "attack_zero_share": float((a == 0).mean()), "benign_zero_share": float((b == 0).mean()),
                         "single_feature_auc": auc})
    return pd.DataFrame(rows, columns=EVIDENCE_COLUMNS)


def main() -> int:
    df = load(DATA_DIR, None, FILES_IP)
    new = evidence_rows(df, CONTEXT_COLUMNS)
    print(new.to_string(index=False))
    old = pd.read_csv(FEATURE_EVIDENCE)
    kept = old[~old["feature"].isin(CONTEXT_COLUMNS)]
    out = pd.concat([kept, new], ignore_index=True)
    out.to_csv(FEATURE_EVIDENCE, index=False)
    print(f"wrote {FEATURE_EVIDENCE}: {len(kept)} rows kept, {len(new)} window rows written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
