"""Update 3: features 12-15 added, SYN Flag Cnt dropped from f21 (21 columns). The default set is f9
again since update 4 (test_update4.py)."""
import json

import numpy as np
import pandas as pd
import pytest

from app.core import features as F
from app.core.feature_notes import load_notes, notes_by_number
from app.core.scoring import build_all, score
from app.paths import FEATURE_NOTES, PROJECT_DIR
from conftest import make_flows

CANDIDATE_COLUMNS = ["bwd_fwd_bytes_ratio", "Fwd IAT Mean", "Fwd IAT Min", "Active Mean", "Idle Mean",
                     "PSH Flag Cnt", "data_share"]


def test_feature_sets_without_syn():
    f14, f21 = F.columns_for("f14"), F.columns_for("f21")
    assert "SYN Flag Cnt" not in f14 and "SYN Flag Cnt" not in f21
    assert f14 == [c for c in F.FEATURES_F15 if c != "SYN Flag Cnt"]       # same order, SYN removed
    assert f21 == f14 + CANDIDATE_COLUMNS
    assert F.summary(f14) == "9 feature groups (14 columns)"
    assert F.summary(f21) == "13 feature groups (21 columns)"
    assert F.columns_for("f15") == F.FEATURES_F15 and len(F.FEATURES_F15) == 15   # kept for comparison
    assert F.FEATURES_F21 == f21
    assert F.column_label("bwd_fwd_bytes_ratio") == "bwd_fwd_bytes_ratio (F12)"
    assert F.column_label("data_share") == "data_share (F15)"


def test_candidate_formulas():
    df = pd.DataFrame([
        {"TotLen Fwd Pkts": 1060, "TotLen Bwd Pkts": 1060, "Fwd IAT Mean": 1e5, "Fwd IAT Min": 1e5,
         "Active Mean": 0, "Idle Mean": 0, "PSH Flag Cnt": 1, "Fwd Act Data Pkts": 3, "Tot Fwd Pkts": 3},
        {"TotLen Fwd Pkts": 0, "TotLen Bwd Pkts": 0, "Fwd IAT Mean": 0, "Fwd IAT Min": 0,
         "Active Mean": 5, "Idle Mean": 7, "PSH Flag Cnt": 0, "Fwd Act Data Pkts": 0, "Tot Fwd Pkts": 0},
    ])
    out = pd.concat([F.group(n).build(df) for n in (12, 13, 14, 15)], axis=1)
    assert out.loc[0, "bwd_fwd_bytes_ratio"] == pytest.approx(1060 / 1061)
    assert out.loc[1, "bwd_fwd_bytes_ratio"] == 0
    assert out.loc[0, "data_share"] == 1.0 and np.isnan(out.loc[1, "data_share"])   # 0/0 -> missing
    assert out.loc[0, "PSH Flag Cnt"] == 1 and out.loc[1, "Idle Mean"] == 7


def test_candidates_are_optional_extras():
    # not core: missing values don't stop scoring, rows are not dropped on them
    for n in (12, 13, 14, 15):
        assert not F.group(n).core
    assert set(F.EXTRA_RAW) >= {"TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd IAT Mean", "Fwd IAT Min",
                                "Active Mean", "Idle Mean", "PSH Flag Cnt", "Fwd Act Data Pkts"}
    assert "Tot Fwd Pkts" in F.CORE_RAW                    # shared with feature 3 stays core


def test_csv_without_candidate_columns_still_works_for_f15(bundle15):
    df = make_flows(40)
    raw_candidates = ["TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd IAT Mean", "Fwd IAT Min",
                      "Active Mean", "Idle Mean", "PSH Flag Cnt", "Fwd Act Data Pkts"]
    assert set(raw_candidates) <= set(df.columns)          # the synthetic flows carry them
    slim = df.drop(columns=raw_candidates)
    assert F.missing_columns(slim.columns, F.FEATURES_F15) == []
    X, scores = score(bundle15, slim)
    assert X.shape[1] == 15 and not np.isnan(scores).any()
    assert not set(CANDIDATE_COLUMNS) & set(build_all(slim).columns)
    assert set(CANDIDATE_COLUMNS) <= set(build_all(df).columns)


def test_update3_notes_are_marked():
    notes = load_notes(FEATURE_NOTES)
    by = notes_by_number(notes)
    for n in (12, 13, 14, 15):
        assert by[n]["status"] == "update3"
        assert set(by[n]["expected"]) == set(F.group(n).output_columns)
    for n in (1, 2, 3, 4, 5, 6, 8, 9, 10, 11):
        assert "status" not in by[n]
    assert "drafted in the project chat" in notes["update3_note"]
    assert any("dropped from the default feature set" in t for t in by[5]["notes"])


@pytest.fixture(scope="module")
def bundle21(flows):
    from xgboost import XGBClassifier
    from app.core.model_store import ModelBundle
    X = F.build_features(flows, F.FEATURES_F21)
    y = (flows["Label"] != "Benign").astype(int)
    model = XGBClassifier(n_estimators=20, max_depth=3, random_state=0).fit(X, y)
    meta = {"feature_columns": F.FEATURES_F21, "feature_set": "f21", "title": "test model f21"}
    return ModelBundle(name="test21", model=model, meta=meta, background=X.head(50), _id=21)


def test_f21_model_scores_without_the_syn_column(bundle21):
    df = make_flows(40).drop(columns=["SYN Flag Cnt"])
    assert F.missing_columns(df.columns, F.FEATURES_F21) == []
    X, scores = score(bundle21, df)
    assert list(X.columns) == F.FEATURES_F21 and not np.isnan(scores).any()
    assert bundle21.feature_set == "f21"


def test_trained_f21_models_have_the_registry_columns():
    from train.train_model import setup_name
    assert setup_name("all_tools", None, "per_day", "f21") == "all_tools_f21"
    real = sorted((PROJECT_DIR / "models").glob("*_f21.meta.json"))
    if not real:
        pytest.skip("no trained f21 models in the models folder")
    for p in real:
        meta = json.loads(p.read_text(encoding="utf-8"))
        assert meta["feature_columns"] == F.FEATURES_F21 and meta["feature_set"] == "f21"
        assert [g["number"] for g in meta["feature_groups"]] == [1, 2, 3, 4, 6, 8, 9, 10, 11, 12, 13, 14, 15]
