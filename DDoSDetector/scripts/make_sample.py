r"""Write small test CSVs from the Wednesday file (all original columns kept).

    python scripts/make_sample.py --rows 50000

Creates in <solution>\data\:
  sample_wed_50k.csv           benign + HOIC + all LOIC-UDP, with Label
  sample_wed_50k_nolabel.csv   same rows without the Label column
  sample_wed_missing_col.csv   200 rows without 'Flow IAT Std' (error-dialog test)
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.features import tools_from_labels  # noqa: E402
from app.paths import DATA_DIR  # noqa: E402

WED = "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, default=DATA_DIR)
    ap.add_argument("--rows", type=int, default=50_000)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    df = pd.read_csv(a.data_dir / WED, low_memory=False)
    tool = tools_from_labels(df["Label"])
    udp = df[tool == "LOIC-UDP"]
    hoic = df[tool == "HOIC"].sample(a.rows // 4, random_state=a.seed)
    ben = df[tool == "Benign"].sample(a.rows - len(udp) - len(hoic), random_state=a.seed)
    out = pd.concat([ben, hoic, udp]).sort_index()   # keep the file's original order

    stem = f"sample_wed_{a.rows // 1000}k"
    out.to_csv(a.data_dir / f"{stem}.csv", index=False)
    out.drop(columns=["Label"]).to_csv(a.data_dir / f"{stem}_nolabel.csv", index=False)
    out.head(200).drop(columns=["Flow IAT Std"]).to_csv(a.data_dir / "sample_wed_missing_col.csv", index=False)
    print(tools_from_labels(out["Label"]).value_counts().to_string(), f"\nwrote {stem}*.csv")


if __name__ == "__main__":
    main()
