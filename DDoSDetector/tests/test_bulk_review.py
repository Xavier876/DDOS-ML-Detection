"""Bulk labelling: several selected rows, or every row the filters show, get one verdict at once."""
import numpy as np
import pytest
from PySide6.QtCore import QItemSelection, QItemSelectionModel, Qt
from PySide6.QtWidgets import QApplication

from app.core import review as rv
from app.core.features import build_features
from app.core.scoring import CODE_DDOS
from app.ui.results_table import ResultsData, ResultsTableModel
from conftest import make_flows

SELECT_ROWS = QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def make_data(n=300):
    scores = np.random.default_rng(1).random(n)
    scores[[3, 7]] = np.nan
    X = build_features(make_flows(n, with_label=False))
    return ResultsData(rows=np.arange(1, n + 1), scores=scores, X=X)


@pytest.fixture
def window(qapp, monkeypatch):
    from app.paths import MODELS_DIR
    from app.ui.main_window import MainWindow
    win = MainWindow(MODELS_DIR)                  # the shipped default model; no file opened
    data = make_data()
    win.results = data
    win.table_model.threshold = 0.5
    win.table_model.set_results(data)
    asked = []
    monkeypatch.setattr(win, "_confirm_bulk", lambda n, verdict, which: asked.append((n, verdict, which)) or True)
    yield win, data, asked
    data.review.dirty = False                     # no "save review?" question on close
    win.close()


def test_review_set_many():
    r = rv.Review.empty(10)
    r.set_many([], rv.CONFIRMED)
    assert not r.dirty
    r.set_many(np.array([1, 4, 4, 9]), rv.CONFIRMED)
    assert r.dirty and list(np.flatnonzero(r.verdicts)) == [1, 4, 9]
    r.set_many([4], rv.FALSE_POSITIVE)
    assert r.verdicts[4] == rv.FALSE_POSITIVE and r.verdicts[1] == rv.CONFIRMED


def test_table_maps_view_rows_to_positions(qapp):
    m, data = ResultsTableModel(), make_data()
    m.set_results(data)
    m.sort(m.column_of("Model score"), Qt.SortOrder.DescendingOrder)
    assert list(m.positions([0, 1, 2])) == [m.position(i) for i in range(3)]
    m.set_filter({CODE_DDOS}, (0.0, 1.0))
    shown = m.shown_positions()
    assert len(shown) == m.rowCount() and (data.scores[shown] >= 0.5).all()
    m.set_review_many(shown, rv.CONFIRMED)
    others = np.setdiff1d(np.arange(len(data)), shown)
    assert (data.review.verdicts[shown] == rv.CONFIRMED).all() and (data.review.verdicts[others] == 0).all()
    assert m.data(m.index(0, m.column_of("Analyst verdict"))) == "confirmed attack"


def test_verdict_applies_to_every_selected_row(window):
    win, data, asked = window
    m, sm = win.table_model, win.table.selectionModel()
    rows = list(range(5, 15)) + [40]                   # a Shift range plus a Ctrl-click
    for r in rows:
        sm.select(m.index(r, 0), SELECT_ROWS)
    win.set_verdict_selected(rv.CONFIRMED)
    assert sorted(np.flatnonzero(data.review.verdicts == rv.CONFIRMED)) == sorted(m.positions(rows))
    assert asked == []                                 # 11 rows: no question below the limit


def test_one_selected_row_still_works(window):
    win, data, asked = window
    win.table.selectRow(2)
    win.set_verdict_selected(rv.UNSURE)
    assert np.flatnonzero(data.review.verdicts == rv.UNSURE).tolist() == [win.table_model.position(2)]


def test_large_selection_asks_first(window):
    from app.ui.main_window import BULK_CONFIRM
    win, data, asked = window
    m = win.table_model
    n = BULK_CONFIRM + 50
    win.table.selectionModel().select(QItemSelection(m.index(0, 0), m.index(n - 1, m.columnCount() - 1)),
                                      SELECT_ROWS)
    win.set_verdict_selected(rv.FALSE_POSITIVE)
    assert asked == [(n, "false positive", "selected")]
    assert int((data.review.verdicts == rv.FALSE_POSITIVE).sum()) == n


def test_declining_changes_nothing(window, monkeypatch):
    win, data, _ = window
    monkeypatch.setattr(win, "_confirm_bulk", lambda *a: False)
    m = win.table_model
    win.table.selectionModel().select(QItemSelection(m.index(0, 0), m.index(199, 0)), SELECT_ROWS)
    win.set_verdict_selected(rv.CONFIRMED)
    win.set_verdict_shown(rv.CONFIRMED)
    assert not data.review.verdicts.any() and not data.review.dirty


def test_all_shown_rows_follow_the_filters(window):
    win, data, asked = window
    win.f_benign.setChecked(False)
    win.f_ns.setChecked(False)                        # show DDoS flags only
    shown = win.table_model.shown_positions()
    win.set_verdict_shown(rv.CONFIRMED)
    assert asked == [(len(shown), "confirmed attack", "shown")]
    assert int((data.review.verdicts == rv.CONFIRMED).sum()) == len(shown) > 0
    assert (data.scores[shown] >= 0.5).all()


def test_right_click_menu_offers_selected_and_shown_rows(window):
    win, _, _ = window
    m = win.table_model
    win.table.selectionModel().select(QItemSelection(m.index(10, 0), m.index(24, 0)), SELECT_ROWS)
    menu = win._build_table_menu()
    texts = [a.text() for a in menu.actions()]
    assert texts[0] == "15 rows selected" and not menu.actions()[0].isEnabled()
    assert "Verdict: confirmed attack" in texts and f"All {m.rowCount():,} shown rows" in texts
    shown = next(a.menu() for a in menu.actions() if a.text().startswith("All "))
    assert [a.text() for a in shown.actions()] == [f"Verdict: {v}" for v in
                                                   ("confirmed attack", "false positive", "unsure", "unreviewed")]


def test_bulk_labels_reach_the_feedback_export(window):
    win, data, _ = window
    win.table_model.set_review_many(np.arange(0, 120), rv.CONFIRMED)
    win.table_model.set_review_many(np.arange(120, 150), rv.FALSE_POSITIVE)
    out = rv.feedback_frame(data.review, data.X, data.rows, "flows.csv")
    assert len(out) == 150 and int(out["label"].sum()) == 120
