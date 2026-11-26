r"""Write small test CSVs from the Wednesday file (all original columns kept).

    python scripts/make_sample.py --seconds 40
    python scripts/make_sample.py --file Wednesday-21-02-2018_victim_capture_labelled.csv --stem sample_wed_ip_slices
                                   (update 5: the relabelled 21 Feb capture with IPs, for the f7ip models)

Feature 7 (flows to the same destination port in the previous 10 s) counts every flow around a
flow, so a random sample of rows would give counts that are far too low. The sample therefore
keeps EVERY flow inside two time slices: the --seconds of the HOIC attack with the most benign flows
(in this file almost all benign flows fall inside the HOIC attack) and the whole LOIC-UDP attack
(from 10 s before it starts). Flows in the first 10 s of each slice still get lower counts than in
the full file.

Creates in <solution>\data\:
  sample_wed_slices.csv           benign + HOIC + all LOIC-UDP, with Label
  sample_wed_slices_nolabel.csv   same rows without the Label column
  sample_wed_missing_col.csv      200 rows without 'Flow IAT Std' (error-dialog test; default --stem only)
  sample_wed_ip_slices*.csv       the same slices cut from the relabelled 21 Feb capture (--file/--stem above)
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.features import TIME, WINDOW_SECONDS, parse_timestamps, tools_from_labels  # noqa: E402
from app.paths import DATA_DIR  # noqa: E402

WED = "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, default=DATA_DIR)
    ap.add_argument("--seconds", type=int, default=40, help="length of the HOIC slice")
    ap.add_argument("--file", default=WED, help="CSV in --data-dir to cut (default: the published 21 Feb file)")
    ap.add_argument("--stem", default="sample_wed_slices", help="output name stem")
    a = ap.parse_args()

    df = pd.read_csv(a.data_dir / a.file, low_memory=False)
    tool = tools_from_labels(df["Label"])
    t = parse_timestamps(df[TIME].astype(str))
    hoic = t[tool == "HOIC"]
    seconds = pd.date_range(hoic.min().floor("s"), hoic.max().floor("s"), freq="s")
    benign_per_s = t[tool == "Benign"].dt.floor("s").value_counts().reindex(seconds, fill_value=0)
    window_end = benign_per_s.rolling(a.seconds).sum().idxmax()
    hoic_start = window_end - pd.Timedelta(seconds=a.seconds - 1)
    udp = t[tool == "LOIC-UDP"]
    in_hoic = t.between(hoic_start, hoic_start + pd.Timedelta(seconds=a.seconds), inclusive="left")
    in_udp = t.between(udp.min() - pd.Timedelta(seconds=WINDOW_SECONDS), udp.max())
    out = df[in_hoic | in_udp]                       # every flow in the slices, in the file's order

    stem = a.stem
    out.to_csv(a.data_dir / f"{stem}.csv", index=False)
    out.drop(columns=["Label"]).to_csv(a.data_dir / f"{stem}_nolabel.csv", index=False)
    if stem == "sample_wed_slices":
        out.head(200).drop(columns=["Flow IAT Std"]).to_csv(a.data_dir / "sample_wed_missing_col.csv", index=False)
    print(tools_from_labels(out["Label"]).value_counts().to_string(),
          f"\nslices: {hoic_start} + {a.seconds} s (HOIC), {udp.min()} .. {udp.max()} (LOIC-UDP)\nwrote {stem}*.csv")


if __name__ == "__main__":
    main()
