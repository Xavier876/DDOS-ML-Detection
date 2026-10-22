"""Handoff update 1: operational impact, analyst workflow, features panel, timing, seed stability."""
import json
import re
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import numpy as np
import pandas as pd
import pytest
import shap
from matplotlib.figure import Figure
from xgboost import XGBClassifier

from app.core import impact
from app.core import review as rv
from app.core.explain import ExplainerCache, contributions, top_features
from app.core.feature_notes import assess, load_evidence, load_notes
from app.core.features import FEATURES_F9, REGISTRY, build_features, column_label, tools_from_labels
from app.core.model_store import load_bundle, save_bundle
from app.core.scoring import FLAG_NAMES, flag_codes, score
from app.core.timing import RunTimings, Stopwatch
from app.paths import FEATURE_NOTES, PROJECT_DIR
from app.plots.base import ChartContext, registry
from conftest import make_flows


# --- wording -------------------------------------------------------------------------
def test_original_nine_columns_are_6_groups():
    from app.core.features import groups_for, summary
    assert [g.number for g in groups_for(FEATURES_F9)] == [1, 2, 3, 4, 5, 6]
    assert summary(FEATURES_F9) == "6 feature groups (9 columns)"


def test_no_confidence_or_probability_wording_in_app():
    """Acceptance 11: the model score is never called a confidence or a probability."""
    bad = re.compile(r"confidence|probabilit", re.IGNORECASE)
    hits = []
    for p in list((PROJECT_DIR / "app").rglob("*.py")) + list((PROJECT_DIR / "app").rglob("*.json")):
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if bad.search(line):
                hits.append(f"{p.name}:{i}: {line.strip()}")
    readme = PROJECT_DIR.parent / "README.md"
    for i, line in enumerate(readme.read_text(encoding="utf-8").splitlines(), 1):
        if bad.search(line) and "not a probability" not in line.lower():
            hits.append(f"README.md:{i}: {line.strip()}")
    assert hits == []


# --- A: operational impact (acceptance 12) ----------------------------------------------
def test_impact_matches_hand_calculation():
    # 4 attacks (3 caught), 6 benign (1 false alarm), 1 unscored, 1 unknown label
    scores = np.array([0.9, 0.8, 0.7, 0.2, 0.6, 0.1, 0.1, 0.3, 0.4, 0.05, np.nan, 0.99])
    tools = np.array(["HOIC", "HOIC", "LOIC-UDP", "LOIC-UDP"] + ["Benign"] * 6 + ["HOIC", "Other"])
    c = impact.confusion(scores, impact.label_vector(tools), 0.5)
    assert (c.tp, c.fn, c.fp, c.tn, c.excluded) == (3, 1, 1, 5, 2)
    r = impact.rates(c)
    assert r["recall"] == pytest.approx(3 / 4)
    assert r["precision"] == pytest.approx(3 / 4)
    assert r["f1"] == pytest.approx(0.75)
    assert r["fpr"] == pytest.approx(1 / 6)
    assert r["accuracy"] == pytest.approx(8 / 10)
    per = {t["tool"]: t for t in impact.per_tool_recall(scores, tools, 0.5)}
    assert per["HOIC"]["recall"] == 1.0 and per["HOIC"]["n"] == 2 and per["LOIC-UDP"]["recall"] == 0.5
    assert per["HOIC"]["small"]       # fewer than 1,000 flows -> noisy warning
    # prevalence illustration: p = 0.1% -> 0.75*0.001 / (0.75*0.001 + (1/6)*0.999)
    assert impact.expected_precision(0.75, 1 / 6, 0.001) == pytest.approx(0.00075 / (0.00075 + 0.1665))
    assert impact.false_alarms_per_million(1 / 6, 0.001) == pytest.approx(166_500)


def test_operational_impact_chart_renders_with_prevalence_option(bundle):
    ctx = _ctx(bundle)
    from app.plots.operational_impact import OperationalImpact
    plugin = OperationalImpact()
    ctx.options[plugin.option_key("prevalence")] = 1.0
    fig = Figure()
    plugin.render(fig, ctx)
    texts = " ".join(t.get_text() for ax in fig.axes for t in ax.texts) + fig._suptitle.get_text()
    assert "1% attacks" in texts and "Accuracy alone can mislead" in texts
    assert "True positives" in texts and "Expected precision" in texts


# --- B: analyst workflow -------------------------------------------------------------
def _loaded(bundle, n=200, seed=1):
    df = make_flows(n, seed=seed)
    df["row"] = np.arange(1, n + 1) + 10
    df["Src IP"] = [f"10.0.0.{i % 250}" for i in range(n)]
    df["Dst Port"] = "80"
    X, scores = score(bundle, df)
    return df, X, scores


def test_review_roundtrip_restores_verdicts_and_notes(bundle, tmp_path):
    """Acceptance 13: save, 'close', reload the same CSV, open the review -> all restored."""
    df, X, scores = _loaded(bundle)
    rows = df["row"].to_numpy()
    r1 = rv.Review.empty(len(df))
    r1.set(3, rv.CONFIRMED, "SYN burst")
    r1.set(7, rv.FALSE_POSITIVE, "backup job")
    r1.set(9, rv.UNSURE)
    r1.set(12, note="look again tomorrow")
    path = tmp_path / rv.default_review_name("flows.csv")
    flags = FLAG_NAMES[flag_codes(scores, 0.5)]
    assert rv.save_review(path, r1, rows, scores, flags, 0.5, "flows.csv", "m", "abc") == 4
    doc = json.loads(path.read_text())
    assert doc["reviews"][0]["row_number"] == 14 and doc["reviews"][0]["model_version"] == "abc"

    r2 = rv.Review.empty(len(df))                        # fresh app, same CSV
    rep = rv.load_review(path, r2, rows, "flows.csv")
    assert rep.applied == 4 and not rep.missing_rows and not rep.other_source
    assert (r2.verdicts == r1.verdicts).all() and r2.notes == r1.notes


def test_review_from_other_file_is_flagged(bundle, tmp_path):
    df, X, scores = _loaded(bundle)
    rows = df["row"].to_numpy()
    r1 = rv.Review.empty(len(df))
    r1.set(0, rv.CONFIRMED)
    rv.save_review(tmp_path / "r.json", r1, rows, scores, FLAG_NAMES[flag_codes(scores, 0.5)], 0.5, "a.csv", "m", "v")
    rep = rv.load_review(tmp_path / "r.json", rv.Review.empty(5), np.arange(500, 505), "b.csv")
    assert rep.other_source and rep.missing_rows == [11] and rep.applied == 0


def test_alert_export_csv_and_jsonl(bundle, tmp_path):
    """Acceptance 14: valid CSV + JSON Lines; only the allowed fields, no feature values."""
    df, X, scores = _loaded(bundle)
    rows = df["row"].to_numpy()
    codes = flag_codes(scores, 0.5)
    pos = np.flatnonzero(codes == 1)
    assert len(pos) > 0
    top3 = top_features(contributions(bundle.model, X.iloc[pos]), list(X.columns))
    tracing = {"src_ip": df["Src IP"].to_numpy(), "dst_port": df["Dst Port"].to_numpy()}
    recs = rv.alert_records(pos, rows, scores, FLAG_NAMES[codes], 0.5, "flows.csv", "m", "v1", top3, tracing)
    csv_path, jsonl_path = rv.write_alerts(tmp_path / "alerts_flows.jsonl", recs)

    lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    parsed = [json.loads(line) for line in lines]          # every line parses
    assert len(parsed) == len(pos)
    allowed = set(rv.ALERT_FIELDS)
    for rec in parsed:
        assert set(rec) <= allowed
        assert not set(rec) & set(FEATURES_F9)                # no model-input columns
        assert "dst_ip" not in rec                         # absent in input -> absent in alert
        assert rec["flag"] == "DDoS" and rec["model_score"] >= 0.5
        assert re.fullmatch(r".+ \(F\d+\): pushes toward (DDoS|Benign)", rec["top_feature_1"])
    csv = pd.read_csv(csv_path)
    assert len(csv) == len(pos) and list(csv.columns) == list(parsed[0].keys())


def test_top_features_follow_shap(bundle, flows):
    X = build_features(flows)
    vals = contributions(bundle.model, X.head(5))
    t = top_features(vals, list(X.columns))
    j = int(np.argmax(np.abs(vals[0])))
    assert t[0][0] == f"{column_label(X.columns[j])}: pushes toward {'DDoS' if vals[0, j] > 0 else 'Benign'}"


def test_xgboost_contributions_equal_shap(bundle, flows):
    X = build_features(flows).head(50)
    a = contributions(bundle.model, X)
    b = shap.TreeExplainer(bundle.model).shap_values(X)
    np.testing.assert_allclose(a, b, atol=1e-4)


def test_feedback_export_excludes_unsure_and_unreviewed(bundle):
    """Acceptance 15."""
    df, X, scores = _loaded(bundle, n=20)
    r = rv.Review.empty(20)
    r.set(1, rv.CONFIRMED)
    r.set(2, rv.FALSE_POSITIVE)
    r.set(3, rv.UNSURE)
    r.set(4, note="only a note")
    out = rv.feedback_frame(r, X, df["row"].to_numpy(), "flows.csv")
    assert list(out.columns) == FEATURES_F9 + ["label", "source_file", "row_number"]
    assert out["label"].tolist() == [1, 0] and out["row_number"].tolist() == [12, 13]


def test_extra_labelled_feedback_is_used_in_training(tmp_path, bundle):
    from train.train_model import load_extra_labelled
    df, X, scores = _loaded(bundle, n=20)
    r = rv.Review.empty(20)
    r.set(1, rv.CONFIRMED)
    r.set(2, rv.FALSE_POSITIVE)
    p = tmp_path / "fb.csv"
    rv.feedback_frame(r, X, df["row"].to_numpy(), "flows.csv").to_csv(p, index=False)
    extra = load_extra_labelled([p])
    assert extra["y"].tolist() == [1, 0] and set(FEATURES_F9) <= set(extra.columns)


# --- C: features panel (acceptance 16) -------------------------------------------------
def test_feature_notes_cover_every_registry_group():
    notes = load_notes(FEATURE_NOTES)          # raises if groups don't match the registry
    by_num = {g["number"]: g for g in notes["groups"]}
    for g in REGISTRY:
        n = by_num[g.number]
        assert set(n["expected"]) == set(g.output_columns)
        assert set(n["expected"].values()) <= {"higher", "lower", "different", "none"}
        for k in ("raw_data", "calculation", "behaviour", "assumption", "lookalike", "evasion"):
            assert n[k]
    assert "draft" not in notes and notes["dropped"]["number"] == 7


def test_features_panel_with_and_without_evidence(tmp_path, qapp):
    from app.ui.features_dialog import FeaturesDialog, features_html
    notes = load_notes(FEATURE_NOTES)
    without = features_html(notes, None)
    assert "Run notebook section 9b to fill this in." in without
    assert "The assumptions below are hypotheses" in without
    ev = pd.DataFrame([{"attack": "HOIC", "feature": "SYN Flag Cnt", "attack_median": 0.0,
                        "benign_median_same_day": 0.0, "direction": "same", "attack_zero_share": 1.0,
                        "benign_zero_share": 1.0, "single_feature_auc": 0.5}])
    p = tmp_path / "feature_evidence.csv"
    ev.to_csv(p, index=False)
    with_ev = features_html(notes, load_evidence(p))
    assert "not supported so far" in with_ev and "AUC 0.50" in with_ev
    FeaturesDialog(None, evidence_path=tmp_path / "missing.csv")   # renders without the file
    FeaturesDialog(None, evidence_path=p)


def test_assess_rules():
    assert assess("higher", "higher", 0.8)[0] == "supported"
    assert assess("lower", "lower", 0.2)[0] == "supported"
    assert assess("higher", "lower", 0.2)[0] == "opposite of the assumption"
    assert assess("higher", "same", 0.52)[0] == "not supported so far"
    assert assess("higher", "lower", 0.65)[0] == "unclear"
    assert assess("different", "lower", 0.3)[0] == "supported"
    assert assess("different", "higher", 0.55)[0] == "not supported so far"
    assert assess("none", "higher", 0.9)[0] == "no direction stated"


# --- D: timing (acceptance 17) ------------------------------------------------------------
def test_stopwatch_measures_positive_duration():
    with Stopwatch() as sw:
        time.sleep(0.01)
    assert sw.seconds > 0


def test_shap_timing_is_recorded(bundle, flows):
    t = RunTimings()
    cache = ExplainerCache(on_timing=t.record_shap)
    cache.reset(bundle.model, build_features(flows), 1)
    cache.explain_row(0)
    cache.explain_sample(np.arange(len(flows)), 50)
    assert t.shap["selected flow"][0] > 0 and t.shap["global sample"][1] == 50
    t.load_s, t.load_rows, t.score_s, t.score_rows = 1.0, 100, 0.5, 100
    assert "200 flows/s" in t.lines()[1]


# --- E: seed stability ------------------------------------------------------------------
def test_seed_stability_chart(tmp_path, flows):
    X = build_features(flows)
    y = (flows["Label"] != "Benign").astype(int)
    for seed in (0, 1, 2):
        m = XGBClassifier(n_estimators=15, max_depth=3, subsample=0.7, random_state=seed).fit(X, y)
        name = "toy" if seed == 0 else f"toy_seed{seed}"
        save_bundle(tmp_path, name, m, {"features": FEATURES_F9, "mode": "toy", "setup": "toy", "seed": seed})
    save_bundle(tmp_path, "other", m, {"features": FEATURES_F9, "setup": "other", "seed": 0})
    b = load_bundle(tmp_path / "toy.meta.json")
    assert b.setup == "toy" and len(b.version) == 10

    from app.plots.seed_stability import SeedStability, mean_abs_shap_by_seed, seed_variants
    assert [s for s, _, _ in seed_variants(tmp_path, "toy")] == [0, 1, 2]
    ctx = _ctx(b, models_dir=tmp_path)
    table = mean_abs_shap_by_seed(ctx)
    assert list(table.columns) == ["seed 0", "seed 1", "seed 2"] and list(table.index) == [column_label(c) for c in FEATURES_F9]
    fig = Figure()
    plugin = SeedStability()
    plugin.prepare(ctx)
    plugin.render(fig, ctx)
    titles = [t.get_text() for t in fig.texts] + [ax.get_title(loc="left") for ax in fig.axes]
    assert any("Spearman" in t for t in titles)


def test_new_charts_are_registered():
    names = [c.name for c in registry()]
    assert "Operational impact" in names and "Seed stability" in names


# --- helpers ----------------------------------------------------------------------------
@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def _ctx(bundle, models_dir=None):
    df = make_flows(300, seed=5)
    X, scores = score(bundle, df)
    cache = ExplainerCache()
    cache.reset(bundle.model, X, data_id=1)
    return ChartContext(model=bundle.model, model_title="test", X=X, scores=scores, threshold=0.5,
                        tools=tools_from_labels(df["Label"]).to_numpy(), sample_size=200, cache=cache,
                        model_meta=bundle.meta, model_name=bundle.name, models_dir=models_dir)
