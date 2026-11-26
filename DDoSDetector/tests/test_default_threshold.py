"""The per-model default threshold (6 Nov 2026): the lowest tested threshold whose false-alarm rate on the model's
own benign test split is within the budget (0.1 %), 0.5 otherwise; chosen from the benign side only."""
from pathlib import Path

import pytest

from app.core.model_store import FALLBACK_THRESHOLD, FPR_BUDGET, default_threshold, read_meta

MODELS_DIR = Path(__file__).resolve().parents[1] / "models"


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def _meta(fprs, recalls=None):
    ts = (0.5, 0.2, 0.1, 0.05, 0.01)
    recalls = recalls or [0.5] * 5
    return {"metrics": {"threshold_sweep": [{"threshold": t, "recall": r, "fpr": f} for t, r, f in zip(ts, recalls, fprs)]}}


def test_budget_is_one_in_a_thousand():
    assert FPR_BUDGET == 0.001 and FALLBACK_THRESHOLD == 0.5


def test_lowest_threshold_within_budget_wins():
    t, why = default_threshold(_meta([0.0, 0.0, 0.0, 0.0001, 0.0005], recalls=[0.01, 0.48, 0.5, 0.96, 0.96]))
    assert t == 0.01
    assert "0.05%" in why and "0.960" in why and "benign side" in why


def test_partial_sweep_stops_at_the_last_threshold_within_budget():
    t, _ = default_threshold(_meta([0.0, 0.0005, 0.0015, 0.0031, 0.0191]))
    assert t == 0.2


def test_budget_boundary_is_inclusive():
    t, _ = default_threshold(_meta([0.0, 0.0, 0.0, 0.0, 0.001]))
    assert t == 0.01


def test_falls_back_to_half_when_nothing_is_within_budget():
    t, why = default_threshold(_meta([0.1488, 0.1675, 0.168, 0.1685, 0.448]))
    assert t == FALLBACK_THRESHOLD
    assert "no tested threshold" in why and "14.88%" in why


def test_falls_back_to_half_without_a_sweep():
    assert default_threshold({})[0] == FALLBACK_THRESHOLD
    assert default_threshold({"metrics": {"recall": {"HOIC": 1.0}}})[0] == FALLBACK_THRESHOLD


def test_custom_budget():
    assert default_threshold(_meta([0.0, 0.0005, 0.0015, 0.0031, 0.0191]), fpr_budget=0.01)[0] == 0.05


def test_window_starts_each_model_at_its_own_default(qapp, tmp_path, flows):
    from xgboost import XGBClassifier
    from app.core import features as F
    from app.core.model_store import save_bundle
    from app.ui.main_window import MainWindow
    X = F.build_features(flows, F.FEATURES_F7IP)
    y = (flows["Label"] != "Benign").astype(int)
    model = XGBClassifier(n_estimators=5, max_depth=2, random_state=0).fit(X, y)
    low = _meta([0.0, 0.0, 0.0, 0.0001, 0.0005], recalls=[0.01, 0.48, 0.5, 0.96, 0.96])
    save_bundle(tmp_path, "all_tools_f7ip", model, {"feature_columns": F.FEATURES_F7IP, "mode": "all_tools",
                                                     "benign_split_mode": "random", "title": "sweep", **low})
    save_bundle(tmp_path, "hoic_held_out_f7ip", model, {"feature_columns": F.FEATURES_F7IP, "mode": "held_out",
                                                         "benign_split_mode": "per_day", "title": "no sweep"})
    win = MainWindow(tmp_path)                    # opens all_tools_f7ip first
    assert win.thr.value() == pytest.approx(0.01) and win.slider.value() == 10
    assert "0.05%" in win.model_label.toolTip()
    win.set_model(tmp_path / "hoic_held_out_f7ip.meta.json")
    assert win.thr.value() == pytest.approx(0.5) and "no threshold sweep" in win.model_label.toolTip()
    win.close()


@pytest.mark.parametrize("name, expected", [
    ("loic_http_held_out_f7ip", 0.01),          # unseen LOIC-HTTP scores 0.1-0.4: 0.01 keeps false alarms at 0.05 %
    ("hoic_held_out_by_file_f7ip", 0.5),        # 0.45 % false alarms even at 0.5: nothing within budget
    ("all_tools_f7ip_svm", 0.5),                # the SVM's false alarms jump above 0.1 % below 0.5
])
def test_shipped_models(name, expected):
    p = MODELS_DIR / f"{name}.meta.json"
    if not p.exists():
        pytest.skip(f"{name} not in the models folder")
    assert default_threshold(read_meta(p))[0] == expected
