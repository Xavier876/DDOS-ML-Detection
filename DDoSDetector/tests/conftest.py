"""Shared fixtures: a tiny synthetic dataset and model, so tests never need the real CSVs."""
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from xgboost import XGBClassifier

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.features import ALL_RAW, FEATURES_F9, FEATURES_F15, build_features  # noqa: E402
from app.core.model_store import ModelBundle  # noqa: E402

LABELS = ["Benign", "DDOS attack-HOIC", "DDoS attacks-LOIC-HTTP", "DDOS attack-LOIC-UDP"]


def make_flows(n=400, seed=0, with_label=True):
    rng = np.random.default_rng(seed)
    lab = rng.choice(LABELS, n, p=[0.6, 0.2, 0.15, 0.05])
    attack = lab != "Benign"
    df = pd.DataFrame({c: rng.random(n) * 100 for c in ALL_RAW})
    df["Flow Pkts/s"] = np.where(attack, 5000 + rng.random(n) * 1000, rng.random(n) * 100)
    df["Tot Bwd Pkts"] = rng.integers(0, 5, n)
    for flag in ("RST Flag Cnt", "FIN Flag Cnt", "SYN Flag Cnt"):
        df[flag] = rng.integers(0, 3, n)
    df["Fwd Pkt Len Mean"] = np.where(rng.random(n) < 0.2, 0.0, df["Fwd Pkt Len Mean"])
    # feature 7 inputs (text, as in the CSVs): attacks crowd port 80 within two minutes
    start = pd.Timestamp("2018-02-21 02:00:00")
    secs = np.sort(rng.integers(0, 120, n))
    df["Timestamp"] = [(start + pd.Timedelta(seconds=int(s))).strftime("%d/%m/%Y %H:%M:%S") for s in secs]
    df["Dst Port"] = np.where(attack, "80", rng.choice(["53", "443", "3389"], n))
    # features 16-18 inputs (text): ten attacking machines hit one victim; benign flows are spread out
    attackers = [f"18.218.115.{i}" for i in range(60, 70)]
    df["Src IP"] = np.where(attack, rng.choice(attackers, n), [f"10.0.{rng.integers(0, 40)}.{rng.integers(1, 250)}" for _ in range(n)])
    df["Dst IP"] = np.where(attack, "172.31.69.28", rng.choice(["172.31.69.28", "172.31.69.30", "172.31.69.31", "8.8.8.8"], n))
    if with_label:
        df["Label"] = lab
    return df


@pytest.fixture(scope="session")
def flows():
    return make_flows()


@pytest.fixture(scope="session")
def bundle(flows):
    X = build_features(flows)
    y = (flows["Label"] != "Benign").astype(int)
    model = XGBClassifier(n_estimators=20, max_depth=3, random_state=0).fit(X, y)
    meta = {"features": FEATURES_F9, "title": "test model"}     # legacy-style metadata (nine columns)
    return ModelBundle(name="test", model=model, meta=meta, background=X.head(50), _id=1)


@pytest.fixture(scope="session")
def bundle15(flows):
    X = build_features(flows, FEATURES_F15)
    y = (flows["Label"] != "Benign").astype(int)
    model = XGBClassifier(n_estimators=20, max_depth=3, random_state=0).fit(X, y)
    meta = {"feature_columns": FEATURES_F15, "feature_set": "f15", "title": "test model f15"}
    return ModelBundle(name="test15", model=model, meta=meta, background=X.head(50), _id=2)


def write_csv(path, df, header_spaces=False):
    out = df.copy()
    if header_spaces:
        out.columns = [f" {c} " for c in out.columns]
    out.to_csv(path, index=False)
    return path
