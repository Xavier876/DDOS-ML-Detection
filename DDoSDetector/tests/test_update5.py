"""Update 5 (5 Nov 2026): the IP-window groups 16-18 and the default set f7ip (16, 18, 17, 3, 10, 11),
chosen by the three-model feature search on the relabelled 21 Feb capture."""
import json

import numpy as np
import pandas as pd
import pytest

from app.core import features as F
from app.core.feature_notes import load_notes, notes_by_number
from app.paths import FEATURE_NOTES, PROJECT_DIR
from conftest import make_flows, write_csv

DST, SRC, DIST = "dst_ip_flows_10s", "src_ip_flows_10s", "dst_ip_src_ips_10s"
IP_COLS = [DST, DIST, SRC]


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture(scope="module")
def bundle7ip(flows):
    from xgboost import XGBClassifier
    from app.core.model_store import ModelBundle
    X = F.build_features(flows, F.FEATURES_F7IP)
    y = (flows["Label"] != "Benign").astype(int)
    model = XGBClassifier(n_estimators=20, max_depth=3, random_state=0).fit(X, y)
    meta = {"feature_columns": F.FEATURES_F7IP, "feature_set": "f7ip", "title": "test model f7ip"}
    return ModelBundle(name="test7ip", model=model, meta=meta, background=X.head(50), _id=11)


def _frame(stamps, src, dst):
    return pd.DataFrame({"Timestamp": stamps, "Src IP": src, "Dst IP": dst})


# --- the set -------------------------------------------------------------------------
def test_f7ip_is_the_default_set():
    assert F.DEFAULT_FEATURE_SET == "f7ip" and F.columns_for("f7ip") == F.FEATURES_F7IP
    assert F.FEATURES_F7IP == IP_COLS + ["fwd_bwd_ratio", "no_reply", "empty_payload", "iat_cv"]
    assert F.summary(F.FEATURES_F7IP) == "6 feature groups (7 columns)"
    assert [g.number for g in F.groups_for(F.FEATURES_F7IP)] == [1, 2, 3, 4, 5, 6]
    assert [F.group(n).week3 for n in range(1, 7)] == [7, None, None, 3, 10, 11]
    assert F.group_week3(7).number == 1 and F.group_week3(1).key == "rate" and F.group_by_key("rate").number == 7
    assert F.feature_set_of(F.FEATURES_F7IP) == "f7ip" and F.feature_set_of(F.FEATURES_F9P) == "f9p"
    for n in (1, 2, 3):
        assert F.group(n).core and F.group(n).window
    assert not F.group(4).window and not F.group(5).window
    assert F.CONTEXT_COLUMNS == [DST, DIST, SRC, "dst_port_flows_10s"]   # registry order
    assert F.required_raw(F.FEATURES_F7IP) == ["Timestamp", "Dst IP", "Src IP", "Tot Fwd Pkts", "Tot Bwd Pkts",
                                               "Fwd Pkt Len Mean", "Flow IAT Std", "Flow IAT Mean"]   # registry order
    assert F.CONTEXT_RAW == ("Timestamp", "Dst Port", "Src IP", "Dst IP")
    assert not set(F.CONTEXT_RAW) & set(F.ALL_RAW)           # addresses are never coerced to numbers
    assert F.column_label(DIST) == "dst_ip_src_ips_10s (F2)"
    assert "Flow Pkts/s" not in F.FEATURES_F7IP and "Dst IP" not in F.ALL_COLUMNS   # IPs are not inputs


# --- the window features -------------------------------------------------------------
def test_ip_windows_hand_example():
    stamps = ["21/02/2018 10:00:%02d" % s for s in (0, 0, 1, 5, 12, 20, 21)]
    df = _frame(stamps, ["A", "B", "A", "C", "A", "B", "B"], ["X", "X", "X", "Y", "X", "X", "X"])
    r = F.build_features(df, IP_COLS)
    # second 0: nothing before; second 1: flows at 0 (A, B) -> 2 flows, 2 sources; second 5: Y has none;
    # second 12: window 2..11 is empty; second 20: window 10..19 holds the flow at 12 (A) -> 1;
    # second 21: window 11..20 holds 12 (A) and 20 (B) -> 2 flows, 2 distinct sources; B at 21 saw B at 20
    assert r[DST].tolist() == [0, 0, 2, 0, 0, 1, 2]
    assert r[DIST].tolist() == [0, 0, 2, 0, 0, 1, 2]
    assert r[SRC].tolist() == [0, 0, 1, 0, 0, 0, 1]


def test_distinct_sources_count_each_source_once():
    t = "21/02/2018 10:00:"
    df = _frame([t + "00", t + "01", t + "02", t + "03", t + "09", t + "12"],
                ["A", "A", "A", "B", "C", "D"], ["X"] * 6)
    r = F.build_features(df, IP_COLS)
    assert r[DST].tolist() == [0, 1, 2, 3, 4, 3]        # at 12 the window 2..11 holds the flows at 2, 3 and 9
    assert r[DIST].tolist() == [0, 1, 1, 1, 2, 3]        # A once however many flows; at 12: A (at 2), B, C


def test_ip_windows_never_cross_capture_files_and_ignore_row_order():
    t = "21/02/2018 02:00:0"
    df = _frame([t + "1", t + "2", t + "3", t + "3"], ["A", "A", "B", "C"], ["X"] * 4)
    df["source_file"] = ["one", "two", "one", "two"]
    got = F.build_features(df, IP_COLS)
    assert got[DST].tolist() == [0, 0, 1, 1] and got[DIST].tolist() == [0, 0, 1, 1]
    shuffled = df.sample(frac=1, random_state=5)
    pd.testing.assert_frame_equal(F.build_features(shuffled, IP_COLS).sort_index(), got)


def test_missing_address_or_time_is_not_scored(bundle7ip):
    from app.core.scoring import score
    df = make_flows(80)
    df.loc[2, "Src IP"] = None
    df.loc[4, "Dst IP"] = None
    df.loc[6, "Timestamp"] = "not a time"
    X, scores = score(bundle7ip, df)
    assert np.isnan(scores[[2, 4, 6]]).all() and np.isfinite(np.delete(scores, [2, 4, 6])).all()
    assert np.isnan(X.loc[2, SRC]) and np.isnan(X.loc[2, DIST]) and np.isfinite(X.loc[2, DST])   # Dst IP is there
    assert list(X.columns) == F.FEATURES_F7IP


def test_csv_round_trip_keeps_addresses_as_text(tmp_path, bundle7ip):
    from app.core.csv_reader import read_flows
    from app.core.scoring import score
    path = write_csv(tmp_path / "flows.csv", make_flows(120), header_spaces=True)
    df = read_flows(path, required_for=F.FEATURES_F7IP)
    assert df["Src IP"].str.count(r"\.").eq(3).all() and df["Dst IP"].dtype == "string"
    X, scores = score(bundle7ip, df)
    assert not np.isnan(scores).any()
    attack = (df["Label"] != "Benign").to_numpy()
    assert X.loc[attack, DIST].median() > X.loc[~attack, DIST].median()   # ten attackers on one victim


def test_csv_without_addresses_names_them_and_f9p_still_fits():
    have = [c for c in make_flows(5).columns if c not in ("Src IP", "Dst IP")]
    assert F.missing_columns(have, F.FEATURES_F7IP) == ["Dst IP", "Src IP"]
    assert F.missing_columns(have, F.FEATURES_F9P) == []


# --- training ------------------------------------------------------------------------
def test_training_builds_the_windows_per_file_and_refuses_a_file_without_ips(tmp_path, capsys):
    from train.train_model import drop_unscorable, load, main, setup_name
    assert setup_name("all_tools", None, "per_day", "f7ip") == "all_tools_f7ip"
    assert setup_name("held_out", "HOIC", "per_day", "f7ip", "random_forest") == "hoic_held_out_f7ip_rf"
    a = make_flows(300, seed=1)
    b = make_flows(300, seed=2).drop(columns=["Src IP", "Dst IP"])
    write_csv(tmp_path / "a.csv", a)
    write_csv(tmp_path / "b.csv", b)
    df = load(tmp_path, None, ["a.csv", "b.csv"])
    assert df.loc[df.source_file == "a.csv", DST].notna().all() and df.loc[df.source_file == "b.csv", DST].isna().all()
    assert df.loc[df.source_file == "a.csv", "dst_port_flows_10s"].notna().all()
    assert "Src IP" in df.columns and df["Src IP"].dtype == "string"
    with pytest.raises(SystemExit, match="b.csv cannot provide"):
        drop_unscorable(df, F.FEATURES_F7IP)
    assert len(drop_unscorable(df, F.FEATURES_F9P)) == len(df)
    with pytest.raises(SystemExit, match="b.csv cannot provide"):
        main(["--data-dir", str(tmp_path), "--out", str(tmp_path / "m"), "--files", "a.csv", "b.csv"])
    out = main(["--data-dir", str(tmp_path), "--out", str(tmp_path / "m"), "--files", "a.csv"])
    assert out == 0
    meta = json.loads((tmp_path / "m" / "all_tools_f7ip.meta.json").read_text(encoding="utf-8"))
    assert meta["feature_columns"] == F.FEATURES_F7IP and meta["feature_set"] == "f7ip"
    assert [g["number"] for g in meta["feature_groups"]] == [1, 2, 3, 4, 5, 6]
    assert [g["week3"] for g in meta["feature_groups"]] == [7, None, None, 3, 10, 11]
    assert meta["data_files"] == ["a.csv"] and meta["metrics"]["recall"]


def test_training_leaves_out_rows_without_a_window_value(tmp_path):
    from train.train_model import drop_unscorable, load
    a = make_flows(200, seed=3)
    a.loc[[1, 2], "Dst IP"] = None
    write_csv(tmp_path / "a.csv", a)
    df = load(tmp_path, None, ["a.csv"])
    kept = drop_unscorable(df, F.FEATURES_F7IP)
    assert len(kept) == len(df) - 2 and kept[F.FEATURES_F7IP[:3]].notna().all().all()


# --- app ------------------------------------------------------------------------------
def test_f7ip_is_the_app_default_and_the_panel_marks_the_set(qapp):
    from app.ui.features_dialog import features_html
    from app.ui.main_window import DEFAULT_MODELS
    assert DEFAULT_MODELS[0] == "all_tools_f7ip"
    h = features_html(load_notes(FEATURE_NOTES), None)
    assert "Model features (default set f7ip): 6 feature groups (7 columns)" in h
    assert "Added in update 5" in h and "has not been confirmed by the group" in h
    for n in (1, 2, 3, 4, 5, 6):
        assert f"Feature {n}: {F.group(n).title} <span" in h, n
    for n in range(7, 19):
        assert f"Feature {n}: {F.group(n).title} — not in the default set" in h, n
    assert "Input 1 of 6 · Feature 1: Flows to the same destination IP <span" in h
    assert "(dst_ip_flows_10s; Week 3 document: feature 7)" in h and "(dst_ip_src_ips_10s; not in the Week 3 document)" in h


def test_model_card_for_f7ip(bundle7ip):
    import html
    from app.ui.about_dialog import IP_WINDOW_FRAMING, PORT_WINDOW_FRAMING, model_card_html
    h = model_card_html(bundle7ip.meta)
    assert html.escape(IP_WINDOW_FRAMING) in h and html.escape(PORT_WINDOW_FRAMING) not in h
    assert html.escape(F.IP_WINDOW_NOTE) in h and html.escape(F.GROUP_7_NOTE) not in h
    assert "Recorded project results" not in h and "ten attacking machines" in h
    assert "F1 Flows to the same destination IP" in h and "Feature set</b></td><td>f7ip" in h


def test_update5_notes():
    notes = load_notes(FEATURE_NOTES)
    by = notes_by_number(notes)
    assert by[1]["expected"] == {DST: "higher"} and by[3]["expected"] == {SRC: "higher"}
    assert by[2]["expected"] == {DIST: "higher"}
    assert by[1]["behaviour"] == by[12]["behaviour"] and by[1]["assumption"] == by[12]["assumption"]  # the group's text
    assert by[1]["week3_number"] == 7 and by[2]["week3_number"] is None and by[12]["week3_number"] == 7
    assert [g["week3_number"] for g in notes["groups"]] == [F.group(g["number"]).week3 for g in notes["groups"]]
    for n in (2, 3):
        assert by[n]["status"] == "update5" and by[n]["notes"][0].startswith("Drafted on 5 Nov 2026")
    assert "not been confirmed by the group" in notes["update5_note"]
    assert "Features 1 to 6 are the inputs of the default model" in notes["added_note"]


def test_trained_f7ip_models_have_the_f7ip_columns():
    metas = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((PROJECT_DIR / "models").glob("*_f7ip*.meta.json"))]
    if not metas:
        pytest.skip("no trained f7ip models in the models folder")
    for meta in metas:
        assert meta["feature_columns"] == F.FEATURES_F7IP and meta["feature_set"] == "f7ip", meta.get("title")
        assert [g["number"] for g in meta["feature_groups"]] == [1, 2, 3, 4, 5, 6]
        assert meta["data_files"][1] == "Wednesday-21-02-2018_victim_capture_labelled.csv"


def test_every_shipped_model_uses_a_default_set():
    """Only f7ip (update 5) and f9p (update 4, the baseline) models ship in the models folder."""
    metas = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((PROJECT_DIR / "models").glob("*.meta.json"))]
    if not metas:
        pytest.skip("no trained models in the models folder")
    for meta in metas:
        assert meta["feature_set"] in ("f7ip", "f9p"), meta.get("title")
        assert meta["feature_columns"] == F.columns_for(meta["feature_set"])


# --- held-out comparison chart: one model type at a time ---------------------------------------
def test_held_out_chart_shows_only_the_active_model_type(tmp_path, flows):
    from xgboost import XGBClassifier
    from app.core.model_store import save_bundle
    from app.core.models import LINEAR_SVM, XGBOOST, make_model
    from app.plots.held_out_comparison import held_out_table
    X = F.build_features(flows, F.FEATURES_F7IP)
    y = (flows["Label"] != "Benign").astype(int)
    xgb = XGBClassifier(n_estimators=5, max_depth=2, random_state=0).fit(X, y)
    svm, _ = make_model(LINEAR_SVM, 1.0, 0)
    svm.fit(X, y)
    for model, suffix, rec in ((xgb, "", 0.9), (svm, "_svm", 0.1)):
        for name, held in (("all_tools_f7ip", None), ("hoic_held_out_f7ip", "HOIC")):
            save_bundle(tmp_path, name + suffix, model,
                        {"feature_columns": F.FEATURES_F7IP, "held_out_tool": held, "seed": 0,
                         "benign_split_mode": "random" if held is None else "per_day",
                         "metrics": {"recall": {"HOIC": rec}, "n_test": {"HOIC": 10}, "fpr": 0.0, "false_alarms": 0}})
    table, fset, kind = held_out_table(tmp_path, {"feature_columns": F.FEATURES_F7IP, "model_type": XGBOOST})
    assert (fset, kind) == ("f7ip", XGBOOST)
    assert table["per_day"]["HOIC"][0] == 0.9 and table["per_day"]["HOIC"][4] == "hoic_held_out_f7ip"
    assert table["seen"]["HOIC"][4] == "all_tools_f7ip"
    table, _, kind = held_out_table(tmp_path, {"feature_columns": F.FEATURES_F7IP, "model_type": LINEAR_SVM})
    assert kind == LINEAR_SVM and table["per_day"]["HOIC"][0] == 0.1 and table["per_day"]["HOIC"][4] == "hoic_held_out_f7ip_svm"


# --- trimmed surfaces (5 Nov 2026): the panel shows the loaded model's inputs, the menu its main models ----
def test_features_panel_defaults_to_the_loaded_models_inputs(qapp):
    from app.ui.features_dialog import FeaturesDialog, features_html
    notes = load_notes(FEATURE_NOTES)
    short = features_html(notes, None, F.FEATURES_F7IP, full=False)
    assert "Input 6 of 6 · Feature 6:" in short and "<h3>Feature 7:" not in short and "12 more feature groups" in short
    base = features_html(notes, None, F.FEATURES_F9P, full=False)
    assert "loaded model's set f9p" in base and "Input 1 of 6 · Feature 7:" in base and "<h3>Input 1 of 6 · Feature 1:" not in base
    full = features_html(notes, None, F.FEATURES_F7IP, full=True)
    assert "<h3>Feature 18:" in full
    d = FeaturesDialog(None, columns=F.FEATURES_F7IP)
    assert not d.full.isChecked() and "Feature 18:" not in d.browser.toPlainText()
    d.full.setChecked(True)
    assert "Feature 18:" in d.browser.toPlainText()


def test_model_menu_shows_main_default_models_and_folds_the_rest(qapp, tmp_path, flows):
    from xgboost import XGBClassifier
    from app.core.model_store import save_bundle
    from app.ui.main_window import MainWindow
    X7, X9 = F.build_features(flows, F.FEATURES_F7IP), F.build_features(flows, F.FEATURES_F9P)
    y = (flows["Label"] != "Benign").astype(int)
    m7 = XGBClassifier(n_estimators=5, max_depth=2, random_state=0).fit(X7, y)
    m9 = XGBClassifier(n_estimators=5, max_depth=2, random_state=0).fit(X9, y)
    specs = [("all_tools_f7ip", m7, F.FEATURES_F7IP, "all_tools", "random"),
             ("hoic_held_out_f7ip", m7, F.FEATURES_F7IP, "held_out", "per_day"),
             ("hoic_held_out_by_file_f7ip", m7, F.FEATURES_F7IP, "held_out", "by_file"),
             ("all_tools_f7ip_seed1", m7, F.FEATURES_F7IP, "all_tools", "random"),
             ("all_tools_f9p", m9, F.FEATURES_F9P, "all_tools", "random")]
    for name, model, cols, mode, split in specs:
        save_bundle(tmp_path, name, model, {"feature_columns": cols, "mode": mode, "benign_split_mode": split,
                                            "seed": 1 if "seed1" in name else 0, "title": name})
    win = MainWindow(tmp_path)
    top = [a.text() for a in win.model_menu.actions() if not a.menu() and a.isCheckable()]
    subs = {a.text(): [b.text() for b in a.menu().actions()] for a in win.model_menu.actions() if a.menu()}
    assert top == ["all_tools_f7ip", "hoic_held_out_f7ip"]
    assert subs["XGBoost: Other benign splits (1: by file, attack period)"] == ["hoic_held_out_by_file_f7ip"]
    assert subs["XGBoost: Baseline and other feature sets (1)"] == ["all_tools_f9p"]
    assert subs["XGBoost: Seed variants (1, for the Seed stability chart)"] == ["all_tools_f7ip_seed1"]
    win.close()
