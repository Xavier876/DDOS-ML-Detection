"""Update 4: the group settled on the original six feature groups; f9 (nine columns) is the default again."""
import json

import pytest

from app.core import features as F
from app.core.feature_notes import load_notes, notes_by_number
from app.paths import FEATURE_NOTES, PROJECT_DIR


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_f9_is_the_default_set():
    assert F.DEFAULT_FEATURE_SET == "f9" and F.columns_for("f9") == F.FEATURES_F9
    assert F.summary(F.FEATURES_F9) == "6 feature groups (9 columns)"
    assert "SYN Flag Cnt" in F.FEATURES_F9


def test_f9_is_the_app_default_and_panel_marks_8_to_15(qapp):
    from app.ui.features_dialog import features_html
    from app.ui.main_window import DEFAULT_MODELS
    assert DEFAULT_MODELS == ("all_tools",)            # only nine-column models ship (update 4)
    h = features_html(load_notes(FEATURE_NOTES), None)
    assert "Model features (default set f9): 6 feature groups (9 columns)" in h
    assert "Feature 5: SYN flag count — not in the default set" not in h
    for n in (8, 9, 10, 11, 12, 13, 14, 15):
        assert f"Feature {n}: {F.group(n).title} — not in the default set" in h


def test_update4_notes():
    notes = load_notes(FEATURE_NOTES)
    assert any(t.startswith("Update 4 (31 Oct 2026)") for t in notes_by_number(notes)[5]["notes"])
    assert "no longer the default" in notes["update3_note"]


def test_trained_default_models_have_the_nine_columns():
    from train.train_model import setup_name
    assert setup_name("all_tools", None, "per_day", "f9") == "all_tools"
    metas = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((PROJECT_DIR / "models").glob("*.meta.json"))]
    if not metas:
        pytest.skip("no trained models in the models folder")
    for meta in metas:   # every model shipped in the folder is a nine-column model
        assert meta["feature_columns"] == F.FEATURES_F9 and meta["feature_set"] == "f9", meta.get("title")
        assert [g["number"] for g in meta["feature_groups"]] == [1, 2, 3, 4, 5, 6]
