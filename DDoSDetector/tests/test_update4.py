"""Update 4: six feature groups; SYN Flag Cnt replaced by feature 7 (flows to the same destination port
in the previous 10 s), set f9p, the default until update 5 (test_update5.py), now the comparison baseline."""
import json

import numpy as np
import pandas as pd
import pytest

from app.core import features as F
from app.core.feature_notes import load_notes, notes_by_number
from app.paths import FEATURE_NOTES, PROJECT_DIR
from conftest import make_flows, write_csv

WIN = "dst_port_flows_10s"


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture(scope="module")
def bundle9p(flows):
    from xgboost import XGBClassifier
    from app.core.model_store import ModelBundle
    X = F.build_features(flows, F.FEATURES_F9P)
    y = (flows["Label"] != "Benign").astype(int)
    model = XGBClassifier(n_estimators=20, max_depth=3, random_state=0).fit(X, y)
    meta = {"feature_columns": F.FEATURES_F9P, "feature_set": "f9p", "title": "test model f9p"}
    return ModelBundle(name="test9p", model=model, meta=meta, background=X.head(50), _id=9)


def _flows(rows):
    return pd.DataFrame(rows, columns=["Timestamp", "Dst Port"])


# --- the set -------------------------------------------------------------------------
def test_f9p_is_the_update4_set():
    assert F.columns_for("f9p") == F.FEATURES_F9P and F.feature_set_of(F.FEATURES_F9P) == "f9p"
    assert F.FEATURES_F9P == [c for c in F.FEATURES_F9 if c != "SYN Flag Cnt"] + [WIN]   # SYN swapped out
    assert F.summary(F.FEATURES_F9P) == "6 feature groups (9 columns)"
    assert F.group(12).core and F.group(12).window and WIN in F.CONTEXT_COLUMNS
    assert F.column_label(WIN) == "dst_port_flows_10s (F12)" and F.group(12).week3 == 7
    assert F.required_raw([WIN]) == ["Timestamp", "Dst Port"]
    assert not set(F.CONTEXT_RAW) & set(F.ALL_RAW)            # never coerced to numbers by clean_frame


# --- feature 7 -------------------------------------------------------------------------
def test_port_window_hand_example():
    t = "21/02/2018 02:00:"
    df = _flows([(t + "00", "80"), (t + "00", "80"), (t + "05", "80"), (t + "05", "443"),
                 (t + "09", "80"), (t + "10", "80"), (t + "11", "80"), (None, "80"), (t + "11", "x")])
    got = F.build_features(df, [WIN])[WIN].tolist()
    # row 4 (second 9): seconds -1..8 on port 80 -> rows 0, 1, 2 = 3; row 5 (second 10): seconds 0..9 -> 4;
    # row 6 (second 11): seconds 1..10 -> rows 2, 4, 5 = 3; flows in the same second are not counted
    assert got[:7] == [0, 0, 2, 0, 3, 4, 3]
    assert np.isnan(got[7]) and np.isnan(got[8])           # unreadable time or port -> missing


def test_port_window_never_crosses_capture_files_and_ignores_row_order():
    t = "21/02/2018 02:00:0"
    df = _flows([(t + "1", "80"), (t + "2", "80"), (t + "3", "80"), (t + "3", "80")])
    df["source_file"] = ["A", "B", "A", "B"]
    got = F.build_features(df, [WIN])[WIN]
    assert got.tolist() == [0, 0, 1, 1]
    shuffled = df.sample(frac=1, random_state=3)
    pd.testing.assert_series_equal(F.build_features(shuffled, [WIN])[WIN].sort_index(), got)


def test_text_and_parsed_timestamps_give_the_same_counts(flows):
    parsed = flows.assign(Timestamp=F.parse_timestamps(flows["Timestamp"]))
    pd.testing.assert_frame_equal(F.build_features(flows, [WIN]), F.build_features(parsed, [WIN]))


def test_missing_time_or_port_is_not_scored(bundle9p):
    from app.core.scoring import score
    df = make_flows(60)
    df.loc[3, "Timestamp"] = None
    df.loc[5, "Dst Port"] = "unknown"
    X, scores = score(bundle9p, df)
    assert np.isnan(scores[[3, 5]]).all() and np.isfinite(np.delete(scores, [3, 5])).all()
    assert list(X.columns) == F.FEATURES_F9P


def test_csv_round_trip_keeps_port_as_text(tmp_path, bundle9p):
    from app.core.csv_reader import read_flows
    from app.core.scoring import score
    path = write_csv(tmp_path / "flows.csv", make_flows(80), header_spaces=True)
    df = read_flows(path)
    assert df["Dst Port"].iloc[0] in ("80", "53", "443", "3389")    # tracing field stays text
    X, scores = score(bundle9p, df)
    assert not np.isnan(scores).any() and X[WIN].max() > 0


def test_csv_without_time_or_port_names_them():
    have = [c for c in make_flows(5).columns if c not in ("Timestamp", "Dst Port")]
    assert F.missing_columns(have, F.FEATURES_F9P) == ["Timestamp", "Dst Port"]
    assert F.missing_columns(have, F.FEATURES_F9) == []


# --- app ------------------------------------------------------------------------------
def test_f9p_stays_as_the_fallback_model_and_panel_marks_5_and_7(qapp):
    from app.ui.features_dialog import features_html
    from app.ui.main_window import DEFAULT_MODELS
    assert "all_tools_f9p" in DEFAULT_MODELS            # offered when a CSV has no IP columns
    h = features_html(load_notes(FEATURE_NOTES), None)
    assert "Feature 10: SYN flag count — not in the default set" in h
    assert "Feature 12: Flows to the same destination port — not in the default set <span" in h and "update 4" in h
    assert "Week 3 document: feature 7)" in h


def test_model_card_for_f9p(bundle9p):
    import html
    from app.ui.about_dialog import PORT_WINDOW_FRAMING, model_card_html
    h = model_card_html(bundle9p.meta)
    assert html.escape(PORT_WINDOW_FRAMING) in h and "Recorded project results" not in h
    assert "destination port" in h and "random sample of rows" in h


def test_update4_notes():
    notes = load_notes(FEATURE_NOTES)
    by = notes_by_number(notes)
    assert any(t.startswith("Update 4 (31 Oct 2026)") for t in by[10]["notes"])     # SYN flag count
    assert by[12]["expected"] == {WIN: "higher"} and "drafted in the project chat" in notes["update4_note"]
    assert "no longer the default" in notes["update3_note"]


def test_trained_f9p_models_have_the_f9p_columns():
    from train.train_model import setup_name
    assert setup_name("all_tools", None, "per_day", "f9p") == "all_tools_f9p"
    metas = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((PROJECT_DIR / "models").glob("*_f9p*.meta.json"))]
    if not metas:
        pytest.skip("no trained f9p models in the models folder")
    for meta in metas:
        assert meta["feature_columns"] == F.FEATURES_F9P and meta["feature_set"] == "f9p", meta.get("title")
        assert [g["number"] for g in meta["feature_groups"]] == [4, 7, 8, 9, 11, 12]
