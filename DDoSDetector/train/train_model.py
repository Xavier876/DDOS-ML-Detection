r"""Train the XGBoost DDoS detector and write model, metadata and SHAP background sample.

    python -m train.train_model --mode all_tools          (run from the DDoSDetector folder)
    python -m train.train_model --mode held_out --held-out HOIC LOIC-HTTP LOIC-UDP
    python -m train.train_model --mode held_out --held-out HOIC --benign-split attack_period
    python -m train.train_model --mode hoic_held_out      (same as --mode held_out --held-out HOIC)
    python -m train.train_model --mode all_tools --seeds 0 1 2 3 4        (seed stability)
    python -m train.train_model --mode all_tools --extra-labelled feedback.csv   (retrain)
    python -m train.train_model --mode all_tools --feature-set f9     (the original nine columns)
Defaults: --data-dir <solution>\data, --out DDoSDetector\models, --feature-set f21.

Follows ddos_xgboost_starter_v2.ipynb:
  all_tools  = section 10 baseline (random 70/30 split stratified by tool; optimistic)
  held_out   = section 7: train on the other tools, test on the held-out tool. Benign split:
               per_day        earlier 70% of each file's benign flows train, later 30% test (notebook)
               by_file        benign of the earlier file trains, the later file tests (notebook)
               attack_period  benign flows inside the held-out tool's attack window test, the rest train
Feature sets come from the registry in app/core/features.py: f9 = the original nine columns,
f15 = fifteen (features 1-6 and 8-11), f14 = f15 without SYN, f21 = f14 + features 12-15 (update 3,
the default). Outputs are named <setup>_<set> (all_tools_f21, ...); f9 keeps the original names
(all_tools, hoic_held_out, ...).
"""
from __future__ import annotations

import argparse
import importlib.metadata as md
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.csv_reader import read_flows  # noqa: E402
from app.core.features import (  # noqa: E402
    ATTACK_TOOLS, CORE_RAW, DEFAULT_FEATURE_SET, EXTRA_RAW, FEATURE_SETS, FEATURES_F9, LABEL,
    LABEL_MAPPING, TIME, build_features, buildable_columns, columns_for, groups_for, summary,
    tools_from_labels,
)
from app.core.model_store import save_bundle  # noqa: E402
from app.core.timing import Stopwatch  # noqa: E402
from app.paths import DATA_DIR, MODELS_DIR  # noqa: E402

FILES = ["Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
         "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"]
BENIGN_CAP = 1_000_000
TRAIN_FRAC = 0.7
BACKGROUND_PER_TOOL = 250   # SHAP background: equal rows per tool (LOIC-UDP is tiny)
MODES = ["all_tools", "held_out", "hoic_held_out"]   # hoic_held_out = held_out with HOIC (kept for old commands)
BENIGN_SPLITS = {
    "per_day": "per_day: earlier 70% of each file's benign train, later 30% test",
    "by_file": "by_file: benign of the earlier file trains, benign of the later file tests",
    "attack_period": "attack_period: benign inside the held-out tool's attack window test, all other benign train",
}


def slug(tool: str) -> str:
    return tool.lower().replace("-", "_")


def setup_name(mode: str, held_out: str | None, split: str, feature_set: str = "f9") -> str:
    """Output name: all_tools, hoic_held_out_f15, loic_http_held_out_attack_period, ..."""
    suffix = "" if feature_set == "f9" else f"_{feature_set}"
    if mode == "all_tools":
        return "all_tools" + suffix
    return f"{slug(held_out)}_held_out" + ("" if split == "per_day" else f"_{split}") + suffix


def setup_title(mode: str, held_out: str | None, split: str) -> str:
    if mode == "all_tools":
        return "All tools (benign + LOIC-HTTP + LOIC-UDP + HOIC)"
    others = " + ".join(t for t in ATTACK_TOOLS if t != held_out)
    return f"{held_out} held out (trained on {others} + benign; {split.replace('_', '-')} benign split)"


def hyperparams(spw: float, seed: int) -> dict:
    return dict(n_estimators=300, max_depth=6, learning_rate=0.1, tree_method="hist",
                scale_pos_weight=float(spw), n_jobs=-1, random_state=seed)


def load(data_dir: Path, nrows: int | None) -> pd.DataFrame:
    """Load both days, keep benign + DDoS, clean exactly as the notebook does."""
    parts = []
    for name in FILES:
        t0 = time.time()

        def keep_known(chunk):
            chunk["tool"] = tools_from_labels(chunk[LABEL])
            return chunk[chunk["tool"] != "Other"]

        d = read_flows(data_dir / name, chunksize=1_000_000, chunk_filter=keep_known, nrows=nrows,
                       required_for=FEATURES_F9)       # extra columns are read when present
        d = d.drop(columns=["row"])
        d[TIME] = parse_time(d[TIME])
        d["source_file"] = name
        for c in EXTRA_RAW:
            if c not in d.columns:
                print(f"   optional column missing in {name} (left as missing values): {c}")
        print(f"  {name}: {len(d):,} benign/DDoS rows ({time.time() - t0:.0f}s)")
        parts.append(d)
    df = pd.concat(parts, ignore_index=True)
    df["y"] = (df["tool"] != "Benign").astype(int)

    n0 = len(df)
    # As in the notebook: drop rows with NaN/inf in the ORIGINAL columns only (extras may be missing),
    # and judge duplicates on the original columns only, so row counts match earlier runs.
    df = df.dropna(subset=CORE_RAW)   # inf already turned into NaN
    df = df.drop_duplicates(subset=[c for c in df.columns if c not in EXTRA_RAW + ["source_file"]])
    print(f"  cleaning: {n0:,} -> {len(df):,} rows")
    df = df.reset_index(drop=True)
    cols = buildable_columns(df.columns)
    df[cols] = build_features(df, cols)
    return df


def parse_time(s: pd.Series) -> pd.Series:
    t = pd.to_datetime(s, format="%d/%m/%Y %H:%M:%S", errors="coerce")
    bad = t.isna() & s.notna()
    if bad.any():  # fall back to the notebook's flexible day-first parsing
        t[bad] = pd.to_datetime(s[bad], dayfirst=True, errors="coerce")
    return t


def split_all_tools(df: pd.DataFrame, seed: int):
    ben = df[df["tool"] == "Benign"]
    ben = ben.sample(min(BENIGN_CAP, len(ben)), random_state=seed)
    d = pd.concat([ben, df[df["tool"] != "Benign"]])
    return train_test_split(d, test_size=1 - TRAIN_FRAC, stratify=d["tool"], random_state=seed)


def split_held_out(df: pd.DataFrame, seed: int, held_out: str = "HOIC", split: str = "per_day"):
    """Train on the other tools, test on `held_out`. Returns (train, test, info)."""
    d = df[df[TIME].notna()]
    ben, att = d[d["tool"] == "Benign"], d[d["tool"] != "Benign"]
    held = att[att["tool"] == held_out]
    if held.empty:
        raise SystemExit(f"No {held_out} flows in the loaded data.")
    info = {}
    if split == "per_day":     # notebook section 7
        pct = ben.groupby("source_file")[TIME].rank(pct=True, method="first")
        in_test = pct > TRAIN_FRAC
    elif split == "by_file":   # notebook section 7: earlier file's benign trains, later file's tests
        order = ben.groupby("source_file")[TIME].min().sort_values().index
        in_test = ben["source_file"] == order[-1]
    else:                      # attack_period: benign flows during the held-out attack, same file(s)
        start, end = held[TIME].min(), held[TIME].max()
        in_test = ben["source_file"].isin(held["source_file"].unique()) & ben[TIME].between(start, end)
        info["attack_window"] = [str(start), str(end)]
    ben_tr, ben_te = ben[~in_test], ben[in_test]
    if ben_te.empty:
        raise SystemExit(f"No benign flows fall in the {held_out} test period.")
    tr = pd.concat([ben_tr.sample(min(len(ben_tr), BENIGN_CAP), random_state=seed),
                    att[att["tool"] != held_out]])
    te = pd.concat([ben_te, held])
    return tr, te, info


def evaluate(model, te: pd.DataFrame, cols: list[str]) -> dict:
    p = model.predict_proba(te[cols])[:, 1]
    y, tool = te["y"].to_numpy(), te["tool"].to_numpy()
    pred = p >= 0.5
    m = {"threshold": 0.5, "n_test_benign": int((y == 0).sum()), "n_test_attack": int((y == 1).sum()),
         "recall": {}, "n_test": {}}
    for t in ATTACK_TOOLS:
        mask = tool == t
        if mask.any():
            m["recall"][t] = round(float(pred[mask].mean()), 4)
            m["n_test"][t] = int(mask.sum())
    m["fpr"] = round(float(pred[y == 0].mean()), 4)
    m["false_alarms"] = int(pred[y == 0].sum())
    if 0 < y.sum() < len(y):
        m["pr_auc"] = round(float(average_precision_score(y, p)), 4)
        m["roc_auc"] = round(float(roc_auc_score(y, p)), 4)
    m["base_rate"] = round(float(y.mean()), 4)
    m["threshold_sweep"] = [
        {"threshold": t, "recall": round(float((p[y == 1] >= t).mean()), 4),
         "fpr": round(float((p[y == 0] >= t).mean()), 4)}
        for t in (0.5, 0.2, 0.1, 0.05, 0.01)]
    return m


def print_metrics(m: dict) -> None:
    print(f"  test: {m['n_test_benign']:,} benign, {m['n_test_attack']:,} attack")
    for t, r in m["recall"].items():
        print(f"  recall {t}: {r:.3f} (n={m['n_test'][t]:,})")
    print(f"  false positive rate: {m['fpr']:.4f} ({m['false_alarms']:,} false alarms)")
    if "pr_auc" in m:
        print(f"  PR-AUC: {m['pr_auc']:.3f} (base rate {m['base_rate']:.3f})")
    for s in m["threshold_sweep"][1:]:
        print(f"  threshold {s['threshold']}: recall {s['recall']:.3f}, FPR {s['fpr']:.4f}")


def background_sample(tr: pd.DataFrame, seed: int, cols: list[str]) -> pd.DataFrame:
    parts = [g.sample(min(len(g), BACKGROUND_PER_TOOL), random_state=seed) for _, g in tr.groupby("tool")]
    bg = pd.concat(parts)
    return bg[cols + ["tool"]].reset_index(drop=True)


def versions() -> dict:
    out = {"python": sys.version.split()[0]}
    for pkg in ("xgboost", "shap", "scikit-learn", "pandas", "numpy"):
        try:
            out[pkg] = md.version(pkg)
        except md.PackageNotFoundError:
            out[pkg] = None
    return out


def load_extra_labelled(paths: list[Path], cols: list[str] = FEATURES_F9) -> pd.DataFrame:
    """Analyst feedback exported by the app (File -> Export labelled feedback):
    the model's feature columns + label (1 = confirmed attack, 0 = false positive).
    The file must contain every column of the feature set being trained."""
    core = [c for c in cols if c in FEATURES_F9]
    parts = []
    for p in paths:
        d = pd.read_csv(p)
        missing = [c for c in cols + ["label"] if c not in d.columns]
        if missing:
            raise SystemExit(f"{p}: missing column(s) {missing}; export the feedback with a model that "
                             "uses this feature set")
        d = d[cols + ["label"]].apply(pd.to_numeric, errors="coerce")
        d = d.replace([np.inf, -np.inf], np.nan).dropna(subset=core + ["label"])
        d = d[d["label"].isin([0, 1])]
        d["y"] = d["label"].astype(int)
        d["tool"] = np.where(d["y"] == 1, "Feedback attack", "Feedback benign")
        parts.append(d.drop(columns=["label"]))
        print(f"  extra labelled: {p}: {int((d.y == 1).sum())} attack, {int((d.y == 0).sum())} benign")
    return pd.concat(parts, ignore_index=True)


def train_one(df: pd.DataFrame, a, seed: int, extra: pd.DataFrame | None, base: str,
              held_out: str | None, cols: list[str]) -> Path:
    info = {}
    if a.mode == "all_tools":
        tr, te = split_all_tools(df, seed)
    else:
        tr, te, info = split_held_out(df, seed, held_out, a.benign_split)
    if extra is not None:   # feedback goes into training only; the test split stays comparable
        tr = pd.concat([tr, extra], ignore_index=True)
    if tr["y"].nunique() < 2:
        raise SystemExit("Training data has only one class; use more rows.")
    spw = (tr["y"] == 0).sum() / (tr["y"] == 1).sum()
    params = hyperparams(spw, seed)
    print(f"Training {base}, seed {seed}: {(tr.y == 0).sum():,} benign, {(tr.y == 1).sum():,} attack, "
          f"scale_pos_weight={spw:.2f}")
    with Stopwatch() as train_sw:
        model = XGBClassifier(**params).fit(tr[cols], tr["y"])
    print(f"  trained in {train_sw.seconds:.1f}s")

    with Stopwatch() as pred_sw:
        metrics = evaluate(model, te, cols)
    print_metrics(metrics)

    name = base if seed == 0 else f"{base}_seed{seed}"
    split = "random" if a.mode == "all_tools" else a.benign_split
    meta = {
        "title": setup_title(a.mode, held_out, split) + f", {summary(cols)}"
                 + (" + analyst feedback" if extra is not None else "") + ("" if seed == 0 else f", seed {seed}"),
        "feature_columns": cols,      # exactly these, in this order (the app builds them from the registry)
        "feature_groups": [{"number": g.number, "key": g.key, "title": g.title,
                            "columns": [c for c in g.output_columns if c in cols]} for g in groups_for(cols)],
        "feature_set": a.feature_set,
        "label_mapping": LABEL_MAPPING,
        "positive_class": "DDoS (any tool) = 1, Benign = 0",
        "mode": a.mode,
        "setup": base,          # models sharing a setup are seed variants (seed stability chart)
        "held_out_tool": held_out,
        "benign_split_mode": split,
        "benign_split": "random 70/30 stratified by tool" if a.mode == "all_tools" else BENIGN_SPLITS[split],
        **info,
        "timing": {"train_seconds": round(train_sw.seconds, 2), "train_rows": int(len(tr)),
                   "predict_seconds": round(pred_sw.seconds, 3), "predict_rows": int(len(te)),
                   "note": "measured with time.perf_counter; prediction time includes computing the test metrics"},
        "seed": seed,
        "data_files": FILES,
        "nrows_per_file": a.nrows,
        "extra_labelled": [str(p) for p in a.extra_labelled] if a.extra_labelled else None,
        "rows_after_cleaning": {t: int(n) for t, n in df["tool"].value_counts().items()},
        "train_rows": {t: int(n) for t, n in tr["tool"].value_counts().items()},
        "test_rows": {t: int(n) for t, n in te["tool"].value_counts().items()},
        "hyperparameters": params,
        "metrics": metrics,
        "versions": versions(),
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    meta_path = save_bundle(a.out, name, model, meta, background_sample(tr, seed, cols))
    print(f"Wrote {meta_path} (+ model and background sample)")
    return meta_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", type=Path, default=DATA_DIR)
    ap.add_argument("--out", type=Path, default=MODELS_DIR)
    ap.add_argument("--mode", choices=MODES, default="all_tools")
    ap.add_argument("--held-out", nargs="+", choices=ATTACK_TOOLS, default=["HOIC"], metavar="TOOL",
                    help="with --mode held_out: tool(s) to hold out, one model each (HOIC LOIC-HTTP LOIC-UDP)")
    ap.add_argument("--benign-split", choices=list(BENIGN_SPLITS), default="per_day",
                    help="held-out benign split (default per_day, as in the notebook)")
    ap.add_argument("--feature-set", choices=list(FEATURE_SETS), default=DEFAULT_FEATURE_SET,
                    help="f21 = 21 columns, update 3 (default); f15 = fifteen; f14 = f15 without SYN; "
                         "f9 = the original nine")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--seeds", type=int, nargs="+",
                    help="train one model per seed (data loaded once), e.g. --seeds 0 1 2 3 4")
    ap.add_argument("--extra-labelled", type=Path, nargs="+", metavar="FILE",
                    help="analyst feedback CSV(s) from the app, added to the training split only")
    ap.add_argument("--name", help="output name (default: <mode>, or <mode>_feedback with --extra-labelled; "
                                   "seeds other than 0 get _seed<N>)")
    ap.add_argument("--nrows", type=int, help="read only the first N rows of each file (quick test)")
    a = ap.parse_args(argv)
    if a.mode == "hoic_held_out":
        a.mode, a.held_out = "held_out", ["HOIC"]
    if a.name and a.mode == "held_out" and len(a.held_out) > 1:
        ap.error("--name can only be used with a single --held-out tool")

    print(f"Loading data from {a.data_dir} ...")
    df = load(a.data_dir, a.nrows)
    print(df["tool"].value_counts().to_string())

    # The feature set's columns; a group whose raw columns are absent from every file is left out
    # (the notebook's rule) and reported, never silently.
    wanted = columns_for(a.feature_set)
    cols = [c for c in wanted if c in df.columns and df[c].notna().any()]
    dropped = [c for c in wanted if c not in cols]
    if dropped:
        print(f"  NOTE: left out (raw columns missing from the files): {dropped}")
    print(f"  model inputs ({summary(cols)}): {cols}")
    extra = load_extra_labelled(a.extra_labelled, cols) if a.extra_labelled else None

    for held in (a.held_out if a.mode == "held_out" else [None]):
        base = a.name or (setup_name(a.mode, held, a.benign_split, a.feature_set)
                          + ("_feedback" if extra is not None else ""))
        for seed in (a.seeds or [a.seed]):
            train_one(df, a, seed, extra, base, held, cols)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
