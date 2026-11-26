r"""Feature search with the relabelled 21 Feb capture and IP-window candidates, for all three model types
(5 Nov 2026; XGBoost main, Random Forest and linear SVM comparison models).

Data: the published 20 Feb CSV (LOIC-HTTP + whole-network benign, has IPs) and the 21 Feb CSV rebuilt from the
raw victim capture (data\Wednesday-21-02-2018_victim_capture_labelled.csv: HOIC complete, LOIC-UDP with its
ICMP replies, the few real benign flows). Candidates: registry groups 1-13 except 5 (14 and 15 need Active/Idle
Mean and Fwd Act Data Pkts, which the rebuilt file does not have) plus three IP-window groups, F16-F18
(since update 5 these are registry groups and the loader builds them; ip_window_features.py delegates).
Result (5 Nov 2026): F16 F18 F17 F3 F10 F11 became the default set f7ip. Threshold 0.5, the same splits as train_model.py, each model with its settings from
app/core/models.py. The linear SVM is treated as the app treats it: rows with a missing value in any model
column are "Not scored" (never flagged) and are left out of its training.

Stages
  A  the six groups (f9p) against the six plus each candidate group, seeds 0 and 1, every model -> the group's rule
     (better: every seed's held-out recall above the base's best AND false-alarm rate not above the base's worst)
  B  greedy forward selection from nothing to 8 groups, per model, seed 0, objective = mean held-out recall over
     the three held-out tools; sets with a false-alarm rate above 2% on any split are skipped
  C  the base and each model's best 6 and best 8 from stage B, evaluated with every model, seeds 0-2, all
     splits, no cap on rows

Training rows are capped in A (attack rows per tool, --cap-attack) and more tightly in B (--cap-b-benign,
--cap-b-attack) to keep ~900 fits affordable; test rows are never capped. Writes
docs\feature_search_ip_<date>.csv (every fit) and docs\feature_search_ip_path_<date>.json (the selection paths).
"""
import argparse
import json
import sys
import time
from datetime import date
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
from app.core.features import ATTACK_TOOLS, FEATURE_SETS, group, group_by_key, group_week3  # noqa: E402
from app.core.models import ACCEPTS_MISSING, MODEL_TYPES, make_model  # noqa: E402
from app.paths import DATA_DIR, SOLUTION_DIR  # noqa: E402
from ip_window_features import CANDIDATES, build_candidates  # noqa: E402
from train.train_model import load, split_all_tools, split_held_out  # noqa: E402

FILES = ["Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv", "Wednesday-21-02-2018_victim_capture_labelled.csv"]
# Labels here are Week 3 document numbers (F1-F13) plus F16-F18 for the IP windows, as in the findings document;
# the app renumbered its catalogue afterwards (1-6 = the default model's inputs), hence group_week3().
GROUPS: dict[str, list[str]] = {f"F{n}": list(group_week3(n).output_columns) for n in range(1, 14)}
GROUPS["F7"] = list(group_by_key("port_window").output_columns)     # F7 in the search = the update-4 port window
GROUPS.pop("F5")                                     # SYN flag count: dropped by the group (update 3)
TITLES = {f"F{n}": group_week3(n).title for n in range(1, 14)}
TITLES["F7"] = group_by_key("port_window").title
IP_TITLES = {"F16": "Flows to the same destination IP", "F17": "Flows from the same source IP",
             "F18": "Distinct source IPs to the same destination IP"}
for key, col in zip(IP_TITLES, CANDIDATES):
    GROUPS[key] = [col]
    TITLES[key] = IP_TITLES[key]
BASE = [f"F{group(n).week3}" for n in FEATURE_SETS["f9p"]]       # the six groups in the model's column order
SPLITS = [("all tools", None, "random"), ("HOIC held out", "HOIC", "per_day"),
          ("LOIC-HTTP held out", "LOIC-HTTP", "per_day"), ("LOIC-UDP held out", "LOIC-UDP", "per_day")]
HELD = [s for s in SPLITS if s[1]]
FPR_LIMIT = 0.02
SHORT = {"xgboost": "XGB", "random_forest": "RF", "linear_svm": "SVM"}


def cols_of(keys) -> list[str]:
    return [c for k in keys for c in GROUPS[k]]


def cap_rows(tr: pd.DataFrame, cap_attack: int | None, cap_benign: int | None, seed: int) -> pd.DataFrame:
    parts = []
    for t, g in tr.groupby("tool"):
        cap = cap_benign if t == "Benign" else cap_attack
        parts.append(g.sample(min(len(g), cap), random_state=seed) if cap else g)
    return pd.concat(parts)


def fit_eval(tr, te, cols, seed, held, model_type):
    """Fit one model and score the test split the way the app does (threshold 0.5; rows the model cannot
    score count as not flagged)."""
    Xtr, ytr = tr[cols], tr["y"]
    if not ACCEPTS_MISSING[model_type]:
        ok = np.isfinite(Xtr.to_numpy(dtype="float64")).all(axis=1)
        Xtr, ytr = Xtr[ok], ytr[ok]
    spw = (ytr == 0).sum() / (ytr == 1).sum()
    model, _ = make_model(model_type, spw, seed)
    t = time.perf_counter()
    model.fit(Xtr, ytr)
    fit_s = time.perf_counter() - t
    Xte = te[cols]
    scorable = np.isfinite(Xte.to_numpy(dtype="float64")).all(axis=1) if not ACCEPTS_MISSING[model_type] \
        else np.ones(len(Xte), dtype=bool)
    pred = np.zeros(len(Xte), dtype=bool)
    if scorable.any():
        pred[scorable] = model.predict_proba(Xte[scorable])[:, 1] >= 0.5
    y, tool = te["y"].to_numpy(), te["tool"].to_numpy()
    recall = {tl: round(float(pred[tool == tl].mean()), 4) for tl in ATTACK_TOOLS if (tool == tl).any()}
    rec = recall[held] if held else min(recall.values())
    return {"recall": rec, "fpr": round(float(pred[y == 0].mean()), 4), "false_alarms": int(pred[y == 0].sum()),
            "not_scored": int((~scorable).sum()), "recall_by_tool": recall, "fit_s": round(fit_s, 1)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", choices=list(MODEL_TYPES), default=list(MODEL_TYPES))
    ap.add_argument("--cap-attack", type=int, default=500_000, help="stage A: attack rows per tool in training")
    ap.add_argument("--cap-b-attack", type=int, default=200_000, help="stage B: attack rows per tool in training")
    ap.add_argument("--cap-b-benign", type=int, default=300_000, help="stage B: benign rows in training")
    ap.add_argument("--max-groups", type=int, default=8)
    ap.add_argument("--final-seeds", type=int, nargs="+", default=[0, 1, 2])
    ap.add_argument("--out-dir", type=Path, default=SOLUTION_DIR / "docs")
    a = ap.parse_args(argv)
    tag = date.today().isoformat()
    out_csv = a.out_dir / f"feature_search_ip_{tag}.csv"
    out_json = a.out_dir / f"feature_search_ip_path_{tag}.json"

    t0 = time.perf_counter()
    df = load(DATA_DIR, None, files=FILES, extra_columns=("Src IP", "Dst IP"))
    print(f"loaded {len(df):,} rows in {time.perf_counter() - t0:.0f} s; tools {df['tool'].value_counts().to_dict()}", flush=True)
    t1 = time.perf_counter()
    todo = [c for c in CANDIDATES if c not in df.columns]      # since update 5 the loader builds them itself
    if todo:
        df = pd.concat([df, build_candidates(df, todo)], axis=1)
    print(f"IP-window candidates built in {time.perf_counter() - t1:.0f} s", flush=True)
    print("medians by tool (per capture file):")
    print(df.groupby(["source_file", "tool"])[list(CANDIDATES) + ["dst_port_flows_10s"]].median().round(1).to_string(), flush=True)
    for k, cols in GROUPS.items():
        missing = [c for c in cols if c not in df.columns]
        assert not missing, (k, missing)
    rows = []

    def record(stage, model_type, seed, split, set_name, keys, r):
        rows.append({"stage": stage, "model": model_type, "seed": seed, "split": split[0], "benign_split": split[2],
                     "set": set_name, "groups": " ".join(keys), "n_cols": len(cols_of(keys)),
                     **{k: v for k, v in r.items() if k != "recall_by_tool"},
                     **{f"recall_{t}": v for t, v in r["recall_by_tool"].items()}})
        pd.DataFrame(rows).to_csv(out_csv, index=False)

    def line(stage, model_type, seed, label, name, keys, r):
        print(f"{stage} {SHORT[model_type]:<3} seed {seed} | {label:<19} | {name:<44} {' '.join(keys):<36} "
              f"recall {r['recall']:.4f} FPR {r['fpr']:.4f} ({r['false_alarms']:,}) "
              + (f"not scored {r['not_scored']:,} " if r['not_scored'] else "") + f"{r['fit_s']}s", flush=True)

    # --- stage A --------------------------------------------------------------------------------------------
    print("\n=== stage A: six groups vs six + one candidate (seeds 0, 1; every model) ===", flush=True)
    sets_a = {"6 groups (f9p)": BASE}
    for k in GROUPS:
        if k not in BASE:
            sets_a[f"+ {k} {TITLES[k]}"] = BASE + [k]
    for seed in (0, 1):
        for split in SPLITS:
            label, held, mode = split
            tr, te = (split_all_tools(df, seed) if held is None else split_held_out(df, seed, held, mode)[:2])
            tr = cap_rows(tr, a.cap_attack, None, seed)
            for model_type in a.models:
                for name, keys in sets_a.items():
                    r = fit_eval(tr, te, cols_of(keys), seed, held, model_type)
                    record("A", model_type, seed, split, name, keys, r)
                    line("A", model_type, seed, label, name, keys, r)
    A = pd.DataFrame([x for x in rows if x["stage"] == "A"])
    print("\nstage A verdicts (the group's rule, per model and held-out tool):")
    for model_type in a.models:
        Am = A[A["model"] == model_type]
        base = Am[Am["set"] == "6 groups (f9p)"]
        for name in sets_a:
            if name == "6 groups (f9p)":
                continue
            verdicts = []
            for label, held, _ in HELD:
                b = base[base["split"] == label]
                c = Am[(Am["set"] == name) & (Am["split"] == label)]
                if c["recall"].min() > b["recall"].max() and c["fpr"].max() <= b["fpr"].max():
                    v = "BETTER"
                elif c["recall"].max() < b["recall"].min():
                    v = "worse"
                elif c["recall"].min() > b["recall"].max():
                    v = "mixed (more recall, more false alarms)"
                else:
                    v = "no change"
                verdicts.append(f"{held} {v} ({c['recall'].min():.3f}-{c['recall'].max():.3f} vs {b['recall'].min():.3f}-{b['recall'].max():.3f})")
            print(f"  {SHORT[model_type]:<3} {name:<44} " + " | ".join(verdicts), flush=True)

    # --- stage B --------------------------------------------------------------------------------------------
    print("\n=== stage B: forward selection per model (seed 0, three held-out tools) ===", flush=True)
    seed = 0
    held_splits = []
    for split in HELD:
        tr, te = split_held_out(df, seed, split[1], split[2])[:2]
        held_splits.append((split, cap_rows(tr, a.cap_b_attack, a.cap_b_benign, seed), te))
    paths = {}
    for model_type in a.models:
        chosen: list[str] = []
        path = []
        while len(chosen) < a.max_groups:
            best = None
            for k in GROUPS:
                if k in chosen:
                    continue
                keys = chosen + [k]
                res = [fit_eval(tr, te, cols_of(keys), seed, split[1], model_type) for split, tr, te in held_splits]
                mean_rec = float(np.mean([r["recall"] for r in res]))
                max_fpr = float(np.max([r["fpr"] for r in res]))
                ok = max_fpr <= FPR_LIMIT
                for split, r in zip(HELD, res):
                    record("B", model_type, seed, split, f"step {len(keys)}: {' '.join(keys)}", keys, r)
                print(f"B {SHORT[model_type]:<3} step {len(keys)} try {k:<4} mean held-out recall {mean_rec:.4f} max FPR {max_fpr:.4f}  "
                      + " ".join(f"{s[1]} {r['recall']:.3f}" for s, r in zip(HELD, res)) + ("" if ok else "  [FPR over limit]"), flush=True)
                score = (ok, mean_rec, -max_fpr)
                if best is None or score > best[0]:
                    best = (score, k, res, mean_rec, max_fpr)
            _, k, res, mean_rec, max_fpr = best
            chosen.append(k)
            path.append({"size": len(chosen), "groups": list(chosen), "mean_held_out_recall": round(mean_rec, 4),
                         "max_fpr": round(max_fpr, 4), "recall": {s[1]: r["recall"] for s, r in zip(HELD, res)}})
            print(f"B {SHORT[model_type]:<3} chose {k} ({TITLES[k]}): {chosen} mean held-out recall {mean_rec:.4f} max FPR {max_fpr:.4f}", flush=True)
            paths[model_type] = path
            out_json.write_text(json.dumps({"paths": paths, "titles": TITLES, "groups": GROUPS}, indent=1), encoding="utf-8")

    # --- stage C --------------------------------------------------------------------------------------------
    print("\n=== stage C: base and each model's best 6 / best 8, every model, seeds", a.final_seeds, "no cap ===", flush=True)
    sets_c = {"6 groups (f9p)": BASE}
    for model_type, path in paths.items():
        for size in (6, min(a.max_groups, 8)):
            step = next((p for p in path if p["size"] == size), None)
            if step and step["groups"] not in sets_c.values():
                sets_c[f"best {size} by {SHORT[model_type]}"] = step["groups"]
    for seed in a.final_seeds:
        for split in SPLITS:
            label, held, mode = split
            tr, te = (split_all_tools(df, seed) if held is None else split_held_out(df, seed, held, mode)[:2])
            for model_type in a.models:
                for name, keys in sets_c.items():
                    r = fit_eval(tr, te, cols_of(keys), seed, held, model_type)
                    record("C", model_type, seed, split, name, keys, r)
                    line("C", model_type, seed, label, name, keys, r)
    print(f"\ndone in {(time.perf_counter() - t0) / 60:.0f} min: {out_csv} and {out_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
