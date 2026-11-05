"""Project handoff features: held-out rotation, attack-period split, threshold sweep,
flash-crowd check, model stability, training timing."""
import matplotlib

matplotlib.use("Agg")

import numpy as np
import pandas as pd
import pytest
from matplotlib.figure import Figure
from xgboost import XGBClassifier

from app.core import impact
from app.core.explain import ExplainerCache
from app.core.features import FEATURES_F9, build_features, tools_from_labels
from app.core.model_store import held_out_results, load_bundle, save_bundle
from app.core.scoring import score
from app.plots.base import ChartContext, registry
from conftest import make_flows


# --- training: naming and splits ---------------------------------------------------------
def test_setup_names_and_titles():
    from train.train_model import setup_name, setup_title
    assert setup_name("all_tools", None, "per_day") == "all_tools"
    assert setup_name("held_out", "HOIC", "per_day") == "hoic_held_out"          # unchanged old name
    assert setup_name("held_out", "LOIC-HTTP", "attack_period") == "loic_http_held_out_attack_period"
    assert "trained on HOIC + LOIC-UDP + benign" in setup_title("held_out", "LOIC-HTTP", "per_day")


def _frame():
    """Two files; HOIC attacks 10:00-11:00 in file B; benign spread over the day in both files."""
    rows = []
    for f, day in (("A.csv", "2018-02-20"), ("B.csv", "2018-02-21")):
        for h in range(8, 18):
            rows.append({"source_file": f, "Timestamp": pd.Timestamp(f"{day} {h:02d}:30"), "tool": "Benign"})
    for m in (0, 20, 40, 59):
        rows.append({"source_file": "B.csv", "Timestamp": pd.Timestamp(f"2018-02-21 10:{m:02d}"), "tool": "HOIC"})
    rows.append({"source_file": "A.csv", "Timestamp": pd.Timestamp("2018-02-20 12:00"), "tool": "LOIC-HTTP"})
    rows.append({"source_file": "B.csv", "Timestamp": pd.Timestamp("2018-02-21 15:00"), "tool": "LOIC-UDP"})
    df = pd.DataFrame(rows)
    df["y"] = (df["tool"] != "Benign").astype(int)
    for c in FEATURES_F9:
        df[c] = 1.0
    return df


def test_attack_period_split_puts_benign_inside_the_attack_window_in_test():
    from train.train_model import split_held_out
    tr, te, info = split_held_out(_frame(), 0, "HOIC", "attack_period")
    ben_te = te[te["tool"] == "Benign"]
    assert len(ben_te) == 1 and ben_te["source_file"].iloc[0] == "B.csv"      # only B 10:30 is in the window
    assert ben_te["Timestamp"].iloc[0] == pd.Timestamp("2018-02-21 10:30")
    assert set(te["tool"]) == {"Benign", "HOIC"} and "HOIC" not in set(tr["tool"])
    assert set(tr["tool"]) == {"Benign", "LOIC-HTTP", "LOIC-UDP"} and (tr["tool"] == "Benign").sum() == 19
    assert info["attack_window"] == ["2018-02-21 10:00:00", "2018-02-21 10:59:00"]


def test_per_day_split_matches_notebook_rule():
    from train.train_model import split_held_out
    tr, te, info = split_held_out(_frame(), 0, "LOIC-UDP", "per_day")
    assert (te["tool"] == "Benign").sum() == 6          # later 30% of 10 benign flows in each of 2 files
    assert set(te["tool"]) == {"Benign", "LOIC-UDP"} and info == {}


# --- threshold sweep / ranking (hand calculation) -----------------------------------------
def test_threshold_sweep_hand_calculation():
    scores = np.array([0.9, 0.6, 0.3, 0.7, 0.2, 0.1, np.nan])
    tools = np.array(["HOIC", "HOIC", "HOIC", "Benign", "Benign", "Benign", "HOIC"])
    sw = impact.threshold_sweep(scores, tools, [0.5, 0.25, 0.0])
    np.testing.assert_allclose(sw["recall"]["HOIC"], [2 / 3, 1, 1])
    np.testing.assert_allclose(sw["fpr"], [1 / 3, 1 / 3, 1])
    assert sw["n"]["HOIC"] == 3 and sw["n_benign"] == 3          # NaN score excluded
    rk = impact.ranking_metrics(scores, tools)
    # attacks 0.9/0.6/0.3 vs benign 0.7/0.2/0.1: 7 of the 9 pairs rank the attack higher
    assert rk["base_rate"] == pytest.approx(0.5) and rk["roc_auc"] == pytest.approx(7 / 9)


def test_high_rate_fpr():
    n = 100
    values = np.arange(1, n + 1, dtype=float)               # benign rate 1..100
    scores = np.where(values >= 96, 0.9, 0.1)                # only the 5 busiest benign flows are flagged
    tools = np.array(["Benign"] * n)
    r = impact.high_rate_fpr(scores, tools, values, 0.5, 90)
    assert r["all"] == {"n": 100, "false_positives": 5, "fpr": 0.05}
    assert r["high"]["n"] == 10 and r["high"]["fpr"] == 0.5 and r["cutoff"] == pytest.approx(90.1)


# --- models folder: comparison table, model card, stability --------------------------------
@pytest.fixture(scope="module")
def models_dir(tmp_path_factory, flows):
    d = tmp_path_factory.mktemp("models")
    X = build_features(flows)
    y = (flows["Label"] != "Benign").astype(int)
    m = XGBClassifier(n_estimators=10, max_depth=3, random_state=0).fit(X, y)
    m2 = XGBClassifier(n_estimators=10, max_depth=2, subsample=0.6, random_state=1).fit(X, y)
    timing = {"train_seconds": 1.5, "train_rows": 100, "predict_seconds": 0.5, "predict_rows": 50}
    base = {"features": FEATURES_F9, "seed": 0, "timing": timing}
    save_bundle(d, "all_tools", m, {**base, "mode": "all_tools", "setup": "all_tools", "metrics": {
        "recall": {"HOIC": 0.999, "LOIC-HTTP": 0.989, "LOIC-UDP": 1.0},
        "n_test": {"HOIC": 200, "LOIC-HTTP": 170, "LOIC-UDP": 5}, "fpr": 0.01, "false_alarms": 3}})
    for tool, split, rec, mm in (("HOIC", "per_day", 0.21, m2), ("HOIC", "attack_period", 0.3, m2),
                                 ("LOIC-HTTP", "per_day", 0.003, m)):
        name = f"{tool.lower().replace('-', '_')}_held_out" + ("" if split == "per_day" else f"_{split}")
        save_bundle(d, name, mm, {**base, "mode": "held_out", "setup": name, "held_out_tool": tool,
                                  "benign_split_mode": split, "metrics": {
                                      "recall": {tool: rec}, "n_test": {tool: 100}, "fpr": 0.008, "false_alarms": 9}})
    save_bundle(d, "all_tools_seed1", m2, {**base, "seed": 1, "setup": "all_tools", "metrics": {"fpr": 0.02}})
    return d


def test_held_out_results_and_comparison_table(models_dir):
    rows = held_out_results(models_dir)
    assert {r["name"] for r in rows} == {"all_tools", "hoic_held_out", "hoic_held_out_attack_period",
                                         "loic_http_held_out"}                        # seed 1 excluded
    from app.plots.held_out_comparison import comparison_table
    t = comparison_table(rows)
    assert t["seen"]["HOIC"][0] == 0.999 and t["per_day"]["HOIC"][0] == 0.21
    assert t["attack_period"]["HOIC"][0] == 0.3 and "LOIC-UDP" not in t["per_day"]


def test_model_card_shows_timing_and_held_out_table(models_dir):
    from app.ui.about_dialog import model_card_html
    meta = load_bundle(models_dir / "hoic_held_out.meta.json").meta
    h = model_card_html(meta, models_dir=models_dir)
    assert "1.5 s on 100 rows" in h and "Held-out results for every f9 XGBoost model" in h and "loic_http_held_out" in h


def _ctx(models_dir, with_label=True):
    b = load_bundle(models_dir / "all_tools.meta.json")
    df = make_flows(300, seed=7, with_label=with_label)
    X, scores = score(b, df)
    cache = ExplainerCache()
    cache.reset(b.model, X, 1)
    tools = tools_from_labels(df["Label"]).to_numpy() if with_label else None
    return ChartContext(model=b.model, model_title="t", X=X, scores=scores, threshold=0.5, tools=tools,
                        sample_size=150, cache=cache, model_meta=b.meta, model_name=b.name, models_dir=models_dir)


@pytest.mark.parametrize("with_label", [True, False])
def test_new_charts_render(models_dir, with_label):
    names = {"Held-out comparison", "Threshold sweep", "Flash-crowd check", "Model stability"}
    plugins = [c for c in registry() if c.name in names]
    assert {c.name for c in plugins} == names
    ctx = _ctx(models_dir, with_label)
    for cls in plugins:
        if cls.needs_label and not with_label:
            continue
        fig = Figure()
        p = cls()
        p.prepare(ctx)
        p.render(fig, ctx)
        texts = " ".join(t.get_text() for t in fig.texts) + " ".join(
            t.get_text() for ax in fig.axes for t in ax.texts)
        assert fig.axes and "Could not" not in texts, cls.name


def test_model_stability_compares_seed0_of_each_setup(models_dir):
    from app.plots.model_stability import setup_models
    from app.plots.seed_stability import mean_abs_shap_for
    entries = setup_models(models_dir)
    assert [n for n, _ in entries][0] == "all_tools" and "all_tools_seed1" not in [n for n, _ in entries]
    table = mean_abs_shap_for(_ctx(models_dir), entries)
    assert table.shape == (9, 4)


def test_charts_without_held_out_models_show_a_message(tmp_path, models_dir):
    from app.plots.held_out_comparison import HeldOutComparison
    ctx = _ctx(models_dir)
    ctx.models_dir = tmp_path          # empty folder
    fig = Figure()
    HeldOutComparison().render(fig, ctx)
    assert "No held-out models" in fig.axes[0].texts[0].get_text()
