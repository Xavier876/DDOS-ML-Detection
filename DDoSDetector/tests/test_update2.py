"""Handoff update 2: feature registry (15 columns / 10 groups), legacy models, group SHAP,
feature-set comparison, model card from metadata, acceptance criteria 18-22."""
import json
import re

import matplotlib

matplotlib.use("Agg")

import numpy as np
import pandas as pd
import pytest
from matplotlib.figure import Figure
from xgboost import XGBClassifier

from app.core import features as F
from app.core.csv_reader import MissingColumnsError, read_flows
from app.core.explain import ExplainerCache, contributions, group_shap
from app.core.model_store import load_bundle, save_bundle
from app.core.scoring import build_all, score
from app.paths import FEATURE_NOTES, PROJECT_DIR
from app.plots.base import BY_GROUP, ChartContext, registry, shap_view
from conftest import make_flows, write_csv

EXPECTED_F15 = ["Flow Pkts/s", "Flow Byts/s", "Flow Duration", "Flow IAT Mean", "Flow IAT Std", "SYN Flag Cnt",
                "Fwd Pkt Len Mean", "Fwd Pkt Len Std", "fwd_bwd_ratio",
                "Bwd Pkt Len Mean", "RST Flag Cnt", "FIN Flag Cnt", "no_reply", "empty_payload", "iat_cv"]


# --- registry --------------------------------------------------------------------------
def test_registry_column_order_and_groups():
    assert F.columns_for("f15") == EXPECTED_F15          # order matters for a trained model
    assert F.columns_for("f9") == EXPECTED_F15[:9]
    assert [g.number for g in F.REGISTRY] == [1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15]   # no group 7
    assert F.summary(F.FEATURES_F15) == "10 feature groups (15 columns)"
    assert F.column_label("empty_payload") == "empty_payload (F10)"
    assert F.feature_set_of(EXPECTED_F15) == "f15" and F.feature_set_of(EXPECTED_F15[:9]) == "f9"


def test_each_group_builds_its_columns():
    df = make_flows(20)
    for g in F.REGISTRY:
        out = g.build(df)
        assert list(out.columns) == list(g.output_columns), g.key
        assert len(out) == len(df)


def test_word_document_worked_example():
    """Week 3 worked example: forward lengths 60, 500, 500; replies 60 and 1,000;
    gaps 0.1, 0.1, 0.1, 0.2 s (IAT mean 125,000 us, std 50,000 us)."""
    df = pd.DataFrame([{
        "Flow Pkts/s": 10.0, "Flow Byts/s": 4240.0, "Flow Duration": 500_000, "Flow IAT Mean": 125_000,
        "Flow IAT Std": 50_000, "SYN Flag Cnt": 1, "Fwd Pkt Len Mean": 1060 / 3, "Fwd Pkt Len Std": 254.0,
        "Tot Fwd Pkts": 3, "Tot Bwd Pkts": 2, "Bwd Pkt Len Mean": 530.0, "RST Flag Cnt": 0, "FIN Flag Cnt": 0}])
    X = F.build_features(df, F.FEATURES_F15)
    r = X.iloc[0]
    assert r["fwd_bwd_ratio"] == pytest.approx(1.0)
    assert r["Bwd Pkt Len Mean"] == 530 and r["no_reply"] == 0 and r["empty_payload"] == 0
    assert r["iat_cv"] == pytest.approx(50_000 / 125_001) and r["iat_cv"] == pytest.approx(0.39999, abs=1e-5)


def test_edge_cases():
    df = make_flows(4, with_label=False)
    df["Tot Bwd Pkts"] = [0, 3, 0, 1]
    df["Fwd Pkt Len Mean"] = [0.0, 50.0, 10.0, 0.0]
    df["Flow IAT Mean"] = [-1.0, 10.0, 5.0, 3.0]       # -1 + 1 = 0 -> inf -> missing
    X = F.build_features(df, F.FEATURES_F15)
    assert X["no_reply"].tolist() == [1, 0, 1, 0]
    assert X["empty_payload"].tolist() == [1, 0, 0, 1]
    assert np.isnan(X.loc[0, "iat_cv"]) and not np.isinf(X["iat_cv"]).any()
    assert F.valid_mask(X).all()                        # missing iat_cv does not stop scoring
    assert F.extra_missing_mask(X).tolist() == [True, False, False, False]


def test_missing_extras_do_not_drop_rows_and_missing_originals_are_named(tmp_path, bundle, bundle15):
    df = make_flows(30).drop(columns=["Bwd Pkt Len Mean"])
    p = write_csv(tmp_path / "noextra.csv", df)
    with pytest.raises(MissingColumnsError) as e:      # the 15-column model needs it
        read_flows(p, required_for=bundle15.features)
    assert e.value.missing == ["Bwd Pkt Len Mean"]
    flows = read_flows(p, required_for=bundle.features)   # acceptance 19: nine-column model scores it
    X, scores = score(bundle, flows)
    assert len(scores) == 30 and not np.isnan(scores).any()
    assert "Bwd Pkt Len Mean" not in build_all(flows).columns
    # NaN in an extra column keeps the row scored by the 15-column model
    full = make_flows(30)
    full.loc[[2, 5], "Bwd Pkt Len Mean"] = np.nan
    X15, s15 = score(bundle15, F.clean_frame(full))
    assert not np.isnan(s15).any() and F.extra_missing_mask(X15).sum() == 2
    assert F.missing_columns(make_flows(3).drop(columns=["Tot Fwd Pkts"]).columns) == ["Tot Fwd Pkts"]


def test_legacy_nine_column_model_still_loads_and_scores(tmp_path, flows):
    X = F.build_features(flows)
    y = (flows["Label"] != "Benign").astype(int)
    m = XGBClassifier(n_estimators=5, max_depth=2).fit(X, y)
    save_bundle(tmp_path, "old", m, {"title": "old model with no column list"})    # no feature_columns
    b = load_bundle(tmp_path / "old.meta.json")
    assert b.features == F.FEATURES_F9 and b.feature_set == "f9"
    Xs, s = score(b, flows)
    assert list(Xs.columns) == F.FEATURES_F9 and len(s) == len(flows)


# --- SHAP groups -------------------------------------------------------------------------
def test_group_shap_additivity_and_margin(bundle15, flows):
    X = F.build_features(flows, F.FEATURES_F15)
    cache = ExplainerCache()
    cache.reset(bundle15.model, X, 1)
    s = cache.explain_sample(np.arange(len(X)), 80)
    margin = bundle15.model.predict(X.iloc[s.rows], output_margin=True)
    np.testing.assert_allclose(s.base_value + s.values.sum(1), margin, atol=1e-4)
    gv, labels = group_shap(s.values, list(s.data.columns))
    assert gv.shape == (80, 10) and labels[0].startswith("F1 ") and not any(l.startswith("F7 ") for l in labels)
    np.testing.assert_allclose(gv.sum(1), s.values.sum(1), atol=1e-9)
    vals, names, data = shap_view(s.values, s.data, BY_GROUP)
    assert data is None and len(names) == 10


def test_beeswarm_colours_binary_columns_consistently():
    from app.plots.shap_beeswarm import colour_values
    c = colour_values(np.array([0, 1, 1, 0, 1, np.nan], dtype=float))
    assert c[:5].tolist() == [0, 1, 1, 0, 1] and np.isnan(c[5])
    assert colour_values(np.array([3.0, 3.0, 3.0])).tolist() == [0.5, 0.5, 0.5]


@pytest.mark.parametrize("view", [0, 1])
def test_shap_charts_render_15_columns_both_views(bundle15, view):
    df = make_flows(300, seed=9)
    X, scores = score(bundle15, df)
    cache = ExplainerCache()
    cache.reset(bundle15.model, X, 1)
    ctx = ChartContext(model=bundle15.model, model_title="t", X=X, scores=scores, threshold=0.5,
                       tools=F.tools_from_labels(df["Label"]).to_numpy(), selected=3, sample_size=150,
                       cache=cache, model_meta=bundle15.meta, model_name=bundle15.name, X_all=build_all(df))
    for cls in registry():
        if cls.name in ("Global importance (bar)", "Global beeswarm", "SHAP by tool", "Flow explanation (waterfall)"):
            p = cls()
            if "view" in p.options:
                ctx.options[p.option_key("view")] = view
            fig = Figure()
            p.prepare(ctx)
            p.render(fig, ctx)
            labels = [t.get_text() for ax in fig.axes for t in ax.get_yticklabels()]
            assert any("(F10)" in l or "F10 " in l for l in labels), cls.name


# --- feature-set comparison chart ---------------------------------------------------------
def _comparison_csv(path):
    rows = []
    for held, mode in (("HOIC", "per_day"), ("HOIC", "by_file"), ("LOIC-HTTP", "per_day")):
        for seed in (0, 1):
            for fs, r in (("base (9 columns)", 0.2), ("+reply", 0.21), ("all (15 columns)", 0.2)):
                rows.append({"recall": r + 0.01 * seed, "fpr": 0.008, "false_alarms": 100 + seed, "pr_auc": 0.8,
                             "median_attack_score": 0.1, "held_out": held, "benign_mode": mode, "seed": seed,
                             "feature_set": fs, "n_features": 9})
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def test_feature_set_comparison_summary_and_chart(tmp_path, bundle15):
    from app.plots.feature_set_comparison import CAPTION, FILE_KIND, FeatureSetComparison, summarise
    p = _comparison_csv(tmp_path / "feature_set_comparison.csv")
    s = summarise(pd.read_csv(p))
    row = s[(s.held_out == "HOIC") & (s.benign_mode == "per_day") & (s.feature_set == "+reply")].iloc[0]
    assert row.recall == pytest.approx(0.215) and (row.recall_min, row.recall_max) == (0.21, 0.22) and row.seeds == 2
    ctx = ChartContext(model=bundle15.model, model_title="t", X=pd.DataFrame(), scores=np.array([]),
                       threshold=0.5, model_meta=bundle15.meta, models_dir=tmp_path / "empty")
    fig = Figure()
    FeatureSetComparison().render(fig, ctx)                      # no file -> explanation
    assert "Run notebook section 9c" in fig.axes[0].texts[0].get_text()
    ctx.files[FILE_KIND] = p
    fig = Figure()
    FeatureSetComparison().render(fig, ctx)
    text = " ".join(t.get_text() for t in fig.texts)
    assert CAPTION in text and len(fig.axes) == 9 and "best" not in text.lower()


# --- model card from metadata ------------------------------------------------------------
def test_model_card_for_15_columns_uses_only_metadata(tmp_path):
    from app.ui.about_dialog import NINE_COLUMN_RESULTS, model_card_html
    meta = {"feature_columns": F.FEATURES_F15, "feature_set": "f15", "mode": "all_tools", "seed": 0,
            "title": "All tools, 10 feature groups (15 columns)",
            "metrics": {"recall": {"HOIC": 0.9871}, "n_test": {"HOIC": 10}, "fpr": 0.0123, "false_alarms": 4}}
    h = model_card_html(meta, models_dir=tmp_path)
    assert "0.987" in h and "0.0123" in h and "10 feature groups (15 columns)" in h
    for _, recorded in NINE_COLUMN_RESULTS:              # acceptance 21: no hard-coded nine-column numbers
        assert recorded not in h
    assert "0.156" not in h and "0.0084" not in h
    assert "nine-column model" in h.lower()               # framing: the finding was observed with nine columns
    h9 = model_card_html({"features": F.FEATURES_F9, "title": "old"})
    assert NINE_COLUMN_RESULTS[0][1] in h9 and "Recorded project results (nine-column model)" in h9


def test_training_metadata_contains_columns_and_results(tmp_path, flows):
    from train.train_model import setup_name
    assert setup_name("all_tools", None, "per_day", "f15") == "all_tools_f15"
    assert setup_name("held_out", "HOIC", "by_file", "f15") == "hoic_held_out_by_file_f15"
    assert setup_name("held_out", "HOIC", "per_day", "f9") == "hoic_held_out"
    real = sorted((PROJECT_DIR / "models").glob("*_f15.meta.json"))
    if not real:
        pytest.skip("no trained f15 models in the models folder")
    meta = json.loads(real[0].read_text(encoding="utf-8"))
    assert meta["feature_columns"] == F.FEATURES_F15 and meta["feature_set"] == "f15"
    assert [g["number"] for g in meta["feature_groups"]] == [1, 2, 3, 4, 5, 6, 8, 9, 10, 11]
    assert meta["metrics"]["recall"] and "fpr" in meta["metrics"] and meta["versions"]["xgboost"]


# --- acceptance 18, 20, 22 -----------------------------------------------------------------
def test_no_feature_list_outside_the_registry():
    """Acceptance 18: no module other than features.py writes out a list of model columns."""
    pattern = re.compile(r"\[\s*\"(Flow Pkts/s|Flow Duration|Fwd Pkt Len Mean)\"\s*,\s*\"")
    offenders = []
    for p in (PROJECT_DIR / "app").rglob("*.py"):
        if p.name != "features.py" and pattern.search(p.read_text(encoding="utf-8")):
            offenders.append(p.name)
    for p in (PROJECT_DIR / "train").rglob("*.py"):
        if pattern.search(p.read_text(encoding="utf-8")):
            offenders.append(p.name)
    assert offenders == []


def test_features_panel_lists_ten_groups(tmp_path, qapp):
    """Acceptance 20."""
    from app.core.feature_notes import load_evidence, load_notes
    from app.ui.features_dialog import features_html
    notes = load_notes(FEATURE_NOTES)
    without = features_html(notes, None)
    numbers = [int(n) for n in re.findall(r"<h3>Feature (\d+):", without)]
    assert numbers == [1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 7]   # update-3 groups, then 7 as dropped
    assert "Run notebook section 9b" in without and "<td>0." not in without   # no numbers invented
    ev = pd.DataFrame([{"attack": "HOIC", "feature": "no_reply", "attack_median": 1.0,
                        "benign_median_same_day": 0.0, "direction": "higher", "attack_zero_share": 0.2,
                        "benign_zero_share": 0.9, "single_feature_auc": 0.85}])
    p = tmp_path / "ev.csv"
    ev.to_csv(p, index=False)
    with_ev = features_html(notes, load_evidence(p))
    assert "supported</b>: attacks are higher (AUC 0.85)" in with_ev


def test_no_claim_that_features_8_to_15_help():
    """Acceptance 22: scan app text and the README."""
    bad = re.compile(r"(features? (8|12) (to|-|–) (11|15)|new features?|added features?)[^.\n]{0,60}"
                     r"\b(improv|help(s|ed)? (detect|the model)|better|boost)", re.IGNORECASE)
    texts = [p.read_text(encoding="utf-8") for p in (PROJECT_DIR / "app").rglob("*.py")]
    texts.append((PROJECT_DIR / "app" / "data" / "feature_notes.json").read_text(encoding="utf-8"))
    texts.append((PROJECT_DIR.parent / "README.md").read_text(encoding="utf-8"))
    hits = [m.group(0) for t in texts for m in bad.finditer(t)]
    assert hits == []


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])
