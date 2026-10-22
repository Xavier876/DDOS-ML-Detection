import json

import numpy as np
import pandas as pd
import pytest

from app.core import features as F
from app.core.csv_reader import Cancelled, MissingColumnsError, read_flows
from app.core.explain import ExplainerCache, sigmoid
from app.core.model_store import check_features, list_models, load_bundle, save_bundle
from app.core.scoring import BENIGN, DDOS, NOT_SCORED, flags, label_metrics, score
from conftest import make_flows, write_csv


# --- label mapping -------------------------------------------------------------------
@pytest.mark.parametrize("raw, tool", [
    ("Benign", "Benign"), ("BENIGN", "Benign"),
    ("DDoS attacks-LOIC-HTTP", "LOIC-HTTP"),
    ("DDOS attack-HOIC", "HOIC"),
    ("DDOS attack-LOIC-UDP", "LOIC-UDP"),
    ("DoS attacks-Hulk", "Other"), ("nan", "Other"),
])
def test_tool_of(raw, tool):
    assert F.tool_of(raw) == tool


# --- feature building ---------------------------------------------------------------
def test_fwd_bwd_ratio_and_order():
    df = make_flows(5, with_label=False)
    df["Tot Fwd Pkts"] = [10, 3, 0, 7, 1]
    df["Tot Bwd Pkts"] = [4, 0, 0, 6, 1]          # zero backward packets -> divide by 1
    X = F.build_features(df)
    assert list(X.columns) == F.FEATURES_F9 and len(F.FEATURES_F9) == 9
    np.testing.assert_allclose(X["fwd_bwd_ratio"], [2.0, 3.0, 0.0, 1.0, 0.5])


# --- cleaning -----------------------------------------------------------------------
def test_clean_frame_headers_inf_nan():
    df = make_flows(6)
    df.columns = [f" {c} " for c in df.columns]
    df = df.astype(object)
    df.iloc[2] = [f" {c} " for c in df.columns]        # repeated header row, with spaces
    df.iloc[1, 0] = "inf"
    df.iloc[3, 1] = np.inf
    df.iloc[4, 2] = "garbage"
    out = F.clean_frame(df)
    assert "Label" in out.columns and "Flow Pkts/s" in out.columns
    assert len(out) == 5                                  # header row dropped, nothing else
    X = F.build_features(out)
    ok = F.valid_mask(X)
    assert ok.sum() == 2 and not np.isinf(X.to_numpy()).any()


def test_missing_columns():
    cols = [c for c in F.ALL_RAW if c != "Tot Bwd Pkts"] + [" Flow Pkts/s "]
    assert F.missing_columns(cols) == ["Tot Bwd Pkts"]


def test_read_flows_keeps_row_numbers(tmp_path):
    df = make_flows(50)
    df.loc[7, "Flow Duration"] = np.inf
    p = write_csv(tmp_path / "f.csv", df, header_spaces=True)
    out = read_flows(p, chunksize=8)
    assert len(out) == 50 and out["row"].tolist() == list(range(1, 51))
    assert np.isnan(out.loc[7, "Flow Duration"])


def test_read_flows_missing_column(tmp_path):
    p = write_csv(tmp_path / "f.csv", make_flows(10).drop(columns=["SYN Flag Cnt"]))
    with pytest.raises(MissingColumnsError) as e:
        read_flows(p)
    assert e.value.missing == ["SYN Flag Cnt"]


def test_read_flows_cancel(tmp_path):
    p = write_csv(tmp_path / "f.csv", make_flows(50))
    with pytest.raises(Cancelled):
        read_flows(p, chunksize=10, cancelled=lambda: True)


# --- scoring ------------------------------------------------------------------------
def test_score_shape_and_flags(bundle):
    df = make_flows(100, seed=3)
    df.loc[[5, 9], "Flow Byts/s"] = np.nan
    X, scores = score(bundle, df)
    assert X.shape == (100, 9) and scores.shape == (100,)
    assert np.isnan(scores[[5, 9]]).all() and (~np.isnan(scores)).sum() == 98
    for t in (0.1, 0.5, 0.9):
        f = flags(scores, t)
        assert (f[[5, 9]] == NOT_SCORED).all()
        ok = ~np.isnan(scores)
        assert ((f[ok] == DDOS) == (scores[ok] >= t)).all()
        assert set(f[ok]) <= {BENIGN, DDOS}
    assert (flags(scores, 0.1) == DDOS).sum() >= (flags(scores, 0.9) == DDOS).sum()


def test_label_metrics():
    scores = np.array([0.9, 0.2, 0.7, np.nan, 0.6, 0.1])
    tools = np.array(["HOIC", "HOIC", "Benign", "Benign", "Benign", "LOIC-UDP"])
    m = label_metrics(scores, tools, 0.5)
    assert m["recall"]["HOIC"] == 0.5 and m["recall"]["LOIC-UDP"] == 0.0
    assert m["false_positives"] == 2 and m["n_benign"] == 2 and m["fpr"] == 1.0


# --- SHAP additivity ----------------------------------------------------------------
def test_shap_additivity(bundle, flows):
    X = F.build_features(flows)
    cache = ExplainerCache()
    cache.reset(bundle.model, X, data_id=1)
    margin = bundle.model.predict(X, output_margin=True)
    for pos in (0, 17, 123):
        r = cache.explain_row(pos)
        assert r.base_value + r.values.sum() == pytest.approx(margin[pos], abs=1e-4)
    s = cache.explain_sample(np.arange(len(X)), 100)
    np.testing.assert_allclose(s.base_value + s.values.sum(1), margin[s.rows], atol=1e-4)
    # model score shown in the table equals sigmoid of the log-odds
    p = bundle.model.predict_proba(X.iloc[[17]])[:, 1][0]
    assert sigmoid(margin[17]) == pytest.approx(p, abs=1e-5)


# --- model store --------------------------------------------------------------------
def test_model_roundtrip(tmp_path, bundle, flows):
    meta = {"features": F.FEATURES_F9, "title": "roundtrip"}
    save_bundle(tmp_path, "m1", bundle.model, meta, background=F.build_features(flows).head(20))
    assert list_models(tmp_path) == [tmp_path / "m1.meta.json"]
    b = load_bundle(tmp_path / "m1.meta.json")
    assert b.name == "m1" and b.features == F.FEATURES_F9 and len(b.background) == 20
    X = F.build_features(flows)
    np.testing.assert_allclose(b.model.predict_proba(X), bundle.model.predict_proba(X), atol=1e-6)
    assert check_features(b.meta, X.columns) == []
    assert check_features({"features": F.FEATURES_F9 + ["extra"]}, X.columns) == ["extra"]
    assert json.loads((tmp_path / "m1.meta.json").read_text())["model_file"] == "m1.json"
