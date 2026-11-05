"""Three model types (group decision, Nov 2026): XGBoost (main), Random Forest and a linear SVM.
Each one trains, saves, loads, scores and is explained with SHAP values that add up exactly."""
import json
from argparse import Namespace

import numpy as np
import pandas as pd
import pytest

from app.core import features as F
from app.core.explain import ExplainerCache, contributions, output_unit, score_of
from app.core.model_store import (held_out_results, load_bundle, load_model_of, model_type_from, save_bundle)
from app.core.models import (LINEAR_SVM, MODEL_TYPES, RANDOM_FOREST, XGBOOST, LinearSVMModel, make_model,
                             model_type_of)
from app.core.scoring import score

KINDS = list(MODEL_TYPES)


def _data(flows, cols=None):
    X = F.build_features(flows, cols or F.FEATURES_F9P)
    y = (flows["Label"] != "Benign").astype(int)
    return X, y


@pytest.fixture(scope="module")
def models(flows):
    X, y = _data(flows)
    out = {}
    for kind in KINDS:
        model, params = make_model(kind, spw=(y == 0).sum() / (y == 1).sum(), seed=0)
        if kind == XGBOOST:
            model.set_params(n_estimators=20, max_depth=3)       # small and fast for tests
        elif kind == RANDOM_FOREST:
            model.set_params(n_estimators=10, min_samples_leaf=2)
        out[kind] = model.fit(X, y)
    return out


@pytest.fixture(scope="module")
def models_dir(tmp_path_factory, models, flows):
    """A models folder with an all-tools model of each type plus held-out models of two types."""
    d = tmp_path_factory.mktemp("models")
    X, _ = _data(flows)
    suffix = {XGBOOST: "", RANDOM_FOREST: "_rf", LINEAR_SVM: "_svm"}
    for k, (kind, model) in enumerate(models.items()):
        cols = F.FEATURES_F9P
        recall = {"HOIC": 0.99 - k / 10, "LOIC-HTTP": 0.98, "LOIC-UDP": 0.9}
        save_bundle(d, f"all_tools_f9p{suffix[kind]}", model,
                    {"title": f"{kind} all tools", "feature_columns": cols, "mode": "all_tools", "seed": 0,
                     "setup": f"all_tools_f9p{suffix[kind]}",
                     "metrics": {"recall": recall, "n_test": {t: 100 for t in recall}, "fpr": 0.001 * (k + 1),
                                 "false_alarms": k + 1}}, X.head(20))
        if kind != LINEAR_SVM:
            save_bundle(d, f"hoic_held_out_f9p{suffix[kind]}", model,
                        {"title": f"{kind} HOIC held out", "feature_columns": cols, "mode": "held_out",
                         "seed": 0, "held_out_tool": "HOIC", "benign_split_mode": "per_day",
                         "metrics": {"recall": {"HOIC": 0.2 + k / 10}, "n_test": {"HOIC": 100}, "fpr": 0.002,
                                     "false_alarms": 2}})
    return d


# --- training settings --------------------------------------------------------------------
def test_each_type_gives_a_score_from_0_to_1(models, flows):
    X, y = _data(flows)
    for kind, model in models.items():
        assert model_type_of(model) == kind
        s = model.predict_proba(X)[:, 1]
        assert s.min() >= 0 and s.max() <= 1
        assert ((s >= 0.5) == y).mean() > 0.9, kind          # the synthetic attacks are easy


def test_svm_score_is_the_sigmoid_of_its_decision_value(models, flows):
    X, _ = _data(flows)
    svm = models[LINEAR_SVM]
    d = svm.decision_function(X)
    assert np.allclose(svm.predict_proba(X)[:, 1], 1 / (1 + np.exp(-d)))
    assert ((svm.predict_proba(X)[:, 1] >= 0.5) == (d >= 0)).all()       # 0.5 is the SVM's own boundary


def test_unknown_model_type_is_refused():
    with pytest.raises(ValueError):
        make_model("gaussian_process", 1.0, 0)
    with pytest.raises(TypeError):
        model_type_of(object())


# --- storage ------------------------------------------------------------------------------
@pytest.mark.parametrize("kind", KINDS)
def test_save_and_load_keep_the_type_and_the_scores(tmp_path, models, flows, kind):
    X, _ = _data(flows)
    model = models[kind]
    meta_path = save_bundle(tmp_path, f"m_{kind}", model, {"title": "t", "feature_columns": F.FEATURES_F9P})
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["model_type"] == kind and model_type_from(meta) == kind
    assert meta["model_file"] == f"m_{kind}" + (".json" if kind == XGBOOST else ".joblib")
    b = load_bundle(meta_path)
    assert b.model_type == kind and b.model_type_name == MODEL_TYPES[kind] and b.version
    assert np.allclose(b.model.predict_proba(X)[:, 1], model.predict_proba(X)[:, 1])
    assert np.allclose(load_model_of(meta_path).predict_proba(X)[:, 1], model.predict_proba(X)[:, 1])


def test_models_without_a_type_are_xgboost():
    assert model_type_from({}) == XGBOOST and model_type_from({"model_type": None}) == XGBOOST


def test_a_file_of_the_wrong_type_is_refused(tmp_path, models):
    meta_path = save_bundle(tmp_path, "rf", models[RANDOM_FOREST], {"feature_columns": F.FEATURES_F9P})
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["model_type"] = LINEAR_SVM                      # metadata says SVM, the file holds a forest
    with pytest.raises(ValueError):
        load_model_of(meta_path, meta)


# --- SHAP ---------------------------------------------------------------------------------
@pytest.mark.parametrize("kind", KINDS)
def test_shap_values_add_up_to_the_model_output(models, flows, kind):
    """base value + sum of SHAP values = f(x), and the model score follows from f(x), for every type."""
    X, _ = _data(flows)
    model = models[kind]
    cache = ExplainerCache()
    cache.reset(model, X, "data")
    rows = np.arange(0, len(X), 37)
    r = cache.explain_rows(rows, ("test", kind))
    fx = r.base_value + r.values.sum(axis=1)
    assert np.allclose(cache.score_of(fx), model.predict_proba(X.iloc[rows])[:, 1], atol=1e-5)
    assert np.allclose(score_of(model, fx), model.predict_proba(X.iloc[rows])[:, 1], atol=1e-5)
    assert np.allclose(contributions(model, X.iloc[rows]), r.values, atol=1e-5)     # same values both ways
    one = cache.explain_row(int(rows[1]))
    assert one.values.shape == (1, len(F.FEATURES_F9P)) and np.allclose(one.values[0], r.values[1], atol=1e-6)


def test_units_per_type(models):
    assert output_unit(models[XGBOOST]) == "log-odds"
    assert output_unit(models[RANDOM_FOREST]) == "model score"
    assert output_unit(models[LINEAR_SVM]) == "SVM decision value"


def test_svm_shap_is_weight_times_standardised_input(models, flows):
    X, _ = _data(flows)
    svm: LinearSVMModel = models[LINEAR_SVM]
    z = svm.pipe[:-1].transform(X.head(5))
    assert np.allclose(svm.contributions(X.head(5)), z * svm.weights)
    assert np.allclose(svm.contributions(X.head(5)).sum(axis=1) + svm.intercept, svm.decision_function(X.head(5)))


# --- scoring ------------------------------------------------------------------------------
def test_svm_does_not_score_rows_with_missing_values(flows):
    """Features 8-15 may be missing; the tree models score such rows, the linear SVM cannot."""
    from app.core.model_store import ModelBundle
    df = flows.copy()
    df[F.EXTRA_RAW[0]] = df[F.EXTRA_RAW[0]].astype("float64")
    df.loc[df.index[:5], F.EXTRA_RAW[0]] = np.nan                  # gaps in a feature 8-15 input
    X21 = F.build_features(df, F.FEATURES_F21)
    gaps = X21.isna().any(axis=1).to_numpy()
    assert gaps[:5].all() and F.valid_mask(X21)[:5].all()          # allowed: not a core column
    y = (df["Label"] != "Benign").astype(int)
    svm = LinearSVMModel().fit(X21[~gaps], y[~gaps])
    rf, _ = make_model(RANDOM_FOREST, 1.0, 0)
    rf.set_params(n_estimators=5)
    rf.fit(X21, y)
    for model, kind in ((svm, LINEAR_SVM), (rf, RANDOM_FOREST)):
        b = ModelBundle(name=kind, model=model, meta={"feature_columns": F.FEATURES_F21, "model_type": kind})
        _, s = score(b, df)
        assert np.isnan(s[:5]).all() == (kind == LINEAR_SVM), kind
        assert not np.isnan(s[~gaps & F.valid_mask(X21)]).any()


# --- training script ------------------------------------------------------------------------
def test_setup_names_get_the_model_suffix():
    from train.train_model import setup_name
    assert setup_name("all_tools", None, "per_day", "f9p") == "all_tools_f9p"                 # unchanged
    assert setup_name("all_tools", None, "per_day", "f9p", RANDOM_FOREST) == "all_tools_f9p_rf"
    assert setup_name("held_out", "HOIC", "by_file", "f9p", LINEAR_SVM) == "hoic_held_out_by_file_f9p_svm"
    assert setup_name("all_tools", None, "per_day", "f9", RANDOM_FOREST) == "all_tools_rf"


@pytest.mark.parametrize("kind", KINDS)
def test_train_one_writes_each_type(tmp_path, flows, kind):
    from train.train_model import train_one
    df = F.build_features(flows, F.FEATURES_F9P)
    df["tool"] = F.tools_from_labels(flows["Label"])
    df["y"] = (df["tool"] != "Benign").astype(int)
    a = Namespace(mode="all_tools", out=tmp_path, benign_split="per_day", feature_set="f9p", model=kind,
                  extra_labelled=None, nrows=None)
    meta_path = train_one(df, a, 0, None, "all_tools_f9p" + {XGBOOST: "", RANDOM_FOREST: "_rf",
                                                              LINEAR_SVM: "_svm"}[kind], None, F.FEATURES_F9P)
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["model_type"] == kind and meta["metrics"]["recall"] and meta["feature_columns"] == F.FEATURES_F9P
    assert meta["title"].startswith("" if kind == XGBOOST else MODEL_TYPES[kind])
    assert load_bundle(meta_path).model_type == kind


# --- model folder, charts, model card -----------------------------------------------------------
def test_held_out_results_filter_by_type(models_dir):
    rows = held_out_results(models_dir, "f9p")
    assert {r["model_type"] for r in rows} == set(KINDS)
    rf = held_out_results(models_dir, "f9p", RANDOM_FOREST)
    assert {r["name"] for r in rf} == {"all_tools_f9p_rf", "hoic_held_out_f9p_rf"}


def test_model_card_names_the_type_and_compares_types(models_dir):
    from app.ui.about_dialog import SCORE_READING, model_card_html
    meta = json.loads((models_dir / "all_tools_f9p_rf.meta.json").read_text(encoding="utf-8"))
    h = model_card_html(meta, models_dir=models_dir)
    assert "Active model: <b>Random Forest</b>" in h and SCORE_READING[RANDOM_FOREST] in h
    assert "Model types compared (f9p" in h and "Linear SVM" in h
    assert "Held-out results for every f9p Random Forest model" in h and "hoic_held_out_f9p_rf" in h
    assert "hoic_held_out_f9p<" not in h.split("Held-out results for every")[1]      # XGBoost's not listed
    assert "Recorded project results" not in h
    old = model_card_html({"features": F.FEATURES_F9, "title": "old"})               # nine-column XGBoost
    assert "Recorded project results (nine-column model)" in old and "Active model: <b>XGBoost</b>" in old


def _ctx(models, flows, models_dir, kind):
    from app.plots.base import ChartContext
    X, _ = _data(flows)
    model = models[kind]
    name = "all_tools_f9p" + {XGBOOST: "", RANDOM_FOREST: "_rf", LINEAR_SVM: "_svm"}[kind]
    meta = json.loads((models_dir / f"{name}.meta.json").read_text(encoding="utf-8"))
    cache = ExplainerCache()
    cache.reset(model, X, "d")
    return ChartContext(model=model, model_title="t", X=X, scores=model.predict_proba(X)[:, 1], threshold=0.5,
                        tools=F.tools_from_labels(flows["Label"]).to_numpy(), selected=3, sample_size=100,
                        cache=cache, model_meta=meta, model_name=name, models_dir=models_dir, X_all=X)


@pytest.mark.parametrize("kind", KINDS)
def test_every_chart_draws_for_each_type(models, flows, models_dir, kind):
    import matplotlib
    matplotlib.use("Agg")
    from matplotlib.figure import Figure
    from app.plots.base import registry
    ctx = _ctx(models, flows, models_dir, kind)
    for cls in registry():
        chart = cls()
        if cls.needs_label and ctx.tools is None:
            continue
        chart.prepare(ctx)
        fig = Figure()
        chart.render(fig, ctx)
        texts = " ".join(t.get_text() for ax in fig.axes for t in [ax.xaxis.label, ax.title]) + " ".join(
            t.get_text() for t in fig.texts)
        if cls.__name__ == "ShapWaterfall":
            assert output_unit(ctx.model) in texts
            if kind == XGBOOST:
                assert "log-odds" in texts


def test_model_types_charts_compare_the_types(models, flows, models_dir):
    import matplotlib
    matplotlib.use("Agg")
    from matplotlib.figure import Figure
    from app.plots.model_types import ModelTypes, by_model_type
    from app.plots.model_types_features import ModelTypesFeatures, all_tools_by_type
    table = by_model_type(held_out_results(models_dir, "f9p"))
    assert set(table) == set(KINDS) and table[LINEAR_SVM]["held"] == {}
    assert [label for label, _ in all_tools_by_type(models_dir, "f9p")] == list(MODEL_TYPES.values())
    ctx = _ctx(models, flows, models_dir, XGBOOST)
    fig = Figure()
    ModelTypes().render(fig, ctx)
    assert len(fig.axes) == 3
    chart = ModelTypesFeatures()
    chart.prepare(ctx)
    imp = chart._table(ctx)
    assert list(imp.columns) == list(MODEL_TYPES.values()) and len(imp) == len(F.FEATURES_F9P)
    fig = Figure()
    chart.render(fig, ctx)
    assert len(fig.axes) >= 2
