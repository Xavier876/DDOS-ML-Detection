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

from app.core.features import FEATURES, REQUIRED_COLUMNS, build_features  # noqa: E402
from app.core.model_store import ModelBundle  # noqa: E402

LABELS = ["Benign", "DDOS attack-HOIC", "DDoS attacks-LOIC-HTTP", "DDOS attack-LOIC-UDP"]


def make_flows(n=400, seed=0, with_label=True):
    rng = np.random.default_rng(seed)
    lab = rng.choice(LABELS, n, p=[0.6, 0.2, 0.15, 0.05])
    attack = lab != "Benign"
    df = pd.DataFrame({c: rng.random(n) * 100 for c in REQUIRED_COLUMNS})
    df["Flow Pkts/s"] = np.where(attack, 5000 + rng.random(n) * 1000, rng.random(n) * 100)
    df["Tot Bwd Pkts"] = rng.integers(0, 5, n)
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
    meta = {"features": FEATURES, "title": "test model"}
    return ModelBundle(name="test", model=model, meta=meta, background=X.head(50), _id=1)


def write_csv(path, df, header_spaces=False):
    out = df.copy()
    if header_spaces:
        out.columns = [f" {c} " for c in out.columns]
    out.to_csv(path, index=False)
    return path
