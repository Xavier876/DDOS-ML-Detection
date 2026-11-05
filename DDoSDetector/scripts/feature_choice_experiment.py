r"""6 vs 8 feature groups: the current six (f9p) plus the strongest single-feature candidates from notebook 9b
(F13 sender timing, F10 no-reply/empty-payload, F9 connection-ending flags), XGBoost with the detector's settings,
same splits as train_model.py, seeds 0 and 1, threshold 0.5. Writes a CSV to the scratchpad; touches nothing in the
project."""
import sys
import time
from pathlib import Path

import pandas as pd

sys.path.insert(0, r"C:\Users\Xavie\source\repos\DDOS-ML-Detection\DDoSDetector")
from app.core.features import FEATURES_F9P, group  # noqa: E402
from app.core.models import make_model  # noqa: E402
from app.paths import DATA_DIR  # noqa: E402
from train.train_model import evaluate, load, split_all_tools, split_held_out  # noqa: E402

OUT = Path(__file__).with_name("feature_choice.csv")
SETS = {
    "6 groups (f9p)": FEATURES_F9P,
    "+ F13 sender timing": FEATURES_F9P + list(group(13).output_columns),
    "+ F10 no-reply/empty": FEATURES_F9P + list(group(10).output_columns),
    "+ F9 RST/FIN flags": FEATURES_F9P + list(group(9).output_columns),
    "+ F13 + F10 (8 groups)": FEATURES_F9P + list(group(13).output_columns) + list(group(10).output_columns),
    "+ F13 + F9 (8 groups)": FEATURES_F9P + list(group(13).output_columns) + list(group(9).output_columns),
}
SPLITS = [("all tools", None, "random"), ("HOIC held out", "HOIC", "per_day"), ("HOIC held out", "HOIC", "by_file"),
          ("LOIC-HTTP held out", "LOIC-HTTP", "per_day"), ("LOIC-UDP held out", "LOIC-UDP", "per_day")]

df = load(DATA_DIR, None)
for name, cols in SETS.items():
    missing = [c for c in cols if c not in df.columns]
    assert not missing, (name, missing)
rows = []
for seed in (0, 1):
    for label, held, split in SPLITS:
        tr, te = (split_all_tools(df, seed) if held is None else split_held_out(df, seed, held, split)[:2])
        spw = (tr["y"] == 0).sum() / (tr["y"] == 1).sum()
        for name, cols in SETS.items():
            t = time.perf_counter()
            model, _ = make_model("xgboost", spw, seed)
            model.fit(tr[cols], tr["y"])
            m = evaluate(model, te, cols)
            rec = m["recall"][held] if held else min(m["recall"].values())
            rows.append({"split": label, "benign_split": split, "seed": seed, "set": name, "n_cols": len(cols),
                         "recall": rec, "fpr": m["fpr"], "false_alarms": m["false_alarms"], "pr_auc": m.get("pr_auc"),
                         "fit_s": round(time.perf_counter() - t, 1)})
            print(f"seed {seed} | {label:<19} {split:<7} | {name:<24} recall {rec:.4f} FPR {m['fpr']:.4f} "
                  f"({m['false_alarms']:,})", flush=True)
    pd.DataFrame(rows).to_csv(OUT, index=False)
print("done", OUT)
