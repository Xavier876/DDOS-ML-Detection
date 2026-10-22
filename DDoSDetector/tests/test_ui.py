"""Chart plugins, table model and workers (headless Qt, QT_QPA_PLATFORM=offscreen)."""
import time

import matplotlib

matplotlib.use("Agg")

import numpy as np
import pytest
from matplotlib.figure import Figure
from PySide6.QtCore import QThread, Qt
from PySide6.QtWidgets import QApplication

from app.core.explain import ExplainerCache
from app.core.features import build_features, tools_from_labels
from app.core.scoring import CODE_BENIGN, CODE_DDOS, CODE_NOT_SCORED, score
from app.plots.base import ChartContext, ChartPlugin, registry
from app.ui.results_table import ResultsData, ResultsTableModel
from app.workers import Jobs
from conftest import make_flows


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def make_ctx(bundle, with_label=True, selected=3):
    df = make_flows(300, seed=5, with_label=with_label)
    df.loc[4, "Flow Duration"] = np.nan
    X, scores = score(bundle, df)
    cache = ExplainerCache()
    cache.reset(bundle.model, X, data_id=1)
    tools = tools_from_labels(df["Label"]).to_numpy() if with_label else None
    return ChartContext(model=bundle.model, model_title="test", X=X, scores=scores, threshold=0.5,
                        tools=tools, selected=selected, row_numbers=np.arange(1, 301),
                        sample_size=200, cache=cache)


# --- registry -----------------------------------------------------------------------
def test_registry_discovers_all_charts():
    names = [c.name for c in registry()]
    assert names[0] == "Flow explanation (waterfall)"
    for n in ("Global importance (bar)", "Global beeswarm", "SHAP by tool", "Model score histogram"):
        assert n in names
    by_name = {c.name: c for c in registry()}
    assert by_name["SHAP by tool"].needs_label and by_name["Flow explanation (waterfall)"].scope == "row"
    assert all(issubclass(c, ChartPlugin) for c in registry())


@pytest.mark.parametrize("with_label", [True, False])
def test_every_chart_renders(bundle, with_label):
    ctx = make_ctx(bundle, with_label)
    for cls in registry():
        if cls.needs_label and not ctx.has_label:
            continue
        fig = Figure()
        plugin = cls()
        plugin.prepare(ctx)
        plugin.render(fig, ctx)
        assert fig.axes, cls.name


def test_waterfall_handles_no_selection_and_unscored_row(bundle):
    from app.plots.shap_waterfall import ShapWaterfall
    for sel in (None, 4):          # row 4 has NaN -> not scored
        fig = Figure()
        ShapWaterfall().render(fig, make_ctx(bundle, selected=sel))
        assert "explain" in fig.axes[0].texts[0].get_text() or "not scored" in fig.axes[0].texts[0].get_text()


def test_registering_a_new_chart_is_one_class():
    from app.plots import base

    @base.register
    class Dummy(ChartPlugin):
        name, needs_shap = "Dummy", False

        def render(self, figure, context):
            figure.add_subplot()

    try:
        assert Dummy in registry()
    finally:
        base._REGISTRY.remove(Dummy)


# --- table model --------------------------------------------------------------------
def make_model(qapp):
    scores = np.array([0.9, 0.1, np.nan, 0.6, 0.3, 0.75])
    X = build_features(make_flows(6, with_label=False))
    data = ResultsData(rows=np.arange(10, 16), scores=scores, X=X, labels=np.array(["a"] * 6),
                       tools=np.array(["HOIC"] * 6))
    m = ResultsTableModel()
    m.set_results(data)
    return m


def col(m, c):
    return [m.data(m.index(r, c)) for r in range(m.rowCount())]


def test_table_threshold_sort_filter(qapp):
    m = make_model(qapp)
    assert m.rowCount() == 6 and m.columnCount() == 5 + 9 + 1
    assert m.columns[:5] == ["Row", "Flag", "Model score", "Analyst verdict", "Note"]
    assert col(m, 1) == ["DDoS", "Benign", "Not scored", "DDoS", "Benign", "DDoS"]
    m.set_threshold(0.7)
    assert col(m, 1) == ["DDoS", "Benign", "Not scored", "Benign", "Benign", "DDoS"]
    m.sort(2, Qt.SortOrder.DescendingOrder)
    assert col(m, 0) == ["10", "15", "13", "14", "11", "12"]     # NaN stays last
    m.set_filter({CODE_DDOS}, (0.0, 1.0))
    assert col(m, 0) == ["10", "15"]
    m.set_filter({CODE_BENIGN, CODE_DDOS, CODE_NOT_SCORED}, (0.2, 0.8))
    assert col(m, 0) == ["15", "13", "14", "12"]                 # unscored kept by flag filter
    assert m.position(0) == 5
    out = m.export_frame()
    assert list(out["row"]) == list(range(10, 16)) and list(out["flag"])[2] == "Not scored"
    assert "model_score" in out.columns and "confidence" not in out.columns
    m.set_review(5, verdict=1, note="checked")
    assert m.data(m.index(0, 3)) == "confirmed attack" and m.data(m.index(0, 4)) == "checked"


def test_table_handles_a_million_rows(qapp):
    n = 1_000_000
    rng = np.random.default_rng(0)
    X = build_features(make_flows(n, with_label=False))
    data = ResultsData(rows=np.arange(1, n + 1), scores=rng.random(n), X=X)
    m = ResultsTableModel()
    t0 = time.perf_counter()
    m.set_results(data)
    m.set_threshold(0.3)
    m.sort(5, Qt.SortOrder.AscendingOrder)
    m.set_filter({CODE_DDOS}, (0.2, 0.8))
    assert time.perf_counter() - t0 < 3.0
    assert 0 < m.rowCount() < n


# --- workers ------------------------------------------------------------------------
def test_worker_callbacks_run_on_ui_thread(qapp):
    jobs, seen = Jobs(), {}

    def work(progress, cancelled):
        progress(0.5)
        return QThread.currentThread()

    def on_result(worker_thread):
        seen["worker"] = worker_thread
        seen["callback"] = QThread.currentThread()

    jobs.start(work, on_result=on_result, on_progress=lambda f: seen.setdefault("p", f))
    t0 = time.time()
    while "callback" not in seen and time.time() - t0 < 10:
        qapp.processEvents()
    assert seen["callback"] is qapp.thread() and seen["worker"] is not qapp.thread()
    assert seen["p"] == 0.5


def test_worker_reports_errors(qapp):
    jobs, seen = Jobs(), {}

    def boom(progress, cancelled):
        raise ValueError("bad file")

    jobs.start(boom, on_error=lambda e, tb: seen.setdefault("e", e))
    t0 = time.time()
    while "e" not in seen and time.time() - t0 < 10:
        qapp.processEvents()
    assert isinstance(seen["e"], ValueError)
