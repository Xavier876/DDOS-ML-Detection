"""Cleaning and feature building.

Single source of truth for the model inputs: used by train/train_model.py AND the app,
so training and inference cannot drift apart. Logic follows ddos_xgboost_starter_v2.ipynb.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

LABEL, TIME = "Label", "Timestamp"

BASE_FEATURES = [
    "Flow Pkts/s", "Flow Byts/s", "Flow Duration",
    "Flow IAT Mean", "Flow IAT Std", "SYN Flag Cnt",
    "Fwd Pkt Len Mean", "Fwd Pkt Len Std",
]
COUNT_COLS = ["Tot Fwd Pkts", "Tot Bwd Pkts"]  # only used to build fwd_bwd_ratio
FEATURES = BASE_FEATURES + ["fwd_bwd_ratio"]   # exactly 9 model inputs, in this order

# 6 feature groups (9 columns). The planned 7th group, flows to the same destination in a
# 10 s window, was dropped: the 21 Feb file has no Dst IP.
FEATURE_GROUPS = {
    "Rate": ["Flow Pkts/s", "Flow Byts/s"],
    "Duration": ["Flow Duration"],
    "Forward/backward ratio": ["fwd_bwd_ratio"],
    "Inter-arrival time": ["Flow IAT Mean", "Flow IAT Std"],
    "SYN flag count": ["SYN Flag Cnt"],
    "Forward packet length": ["Fwd Pkt Len Mean", "Fwd Pkt Len Std"],
}
FEATURE_SUMMARY = "6 feature groups (9 columns)"

# Kept for tracing alerts back to hosts when present. NEVER model inputs.
TRACING_COLUMNS = {"Src IP": "src_ip", "Dst IP": "dst_ip", "Dst Port": "dst_port"}

# Columns the input CSV must contain to be scored (Label / Timestamp are optional).
REQUIRED_COLUMNS = BASE_FEATURES + COUNT_COLS
OPTIONAL_COLUMNS = [LABEL, TIME]

TOOLS = ["Benign", "HOIC", "LOIC-HTTP", "LOIC-UDP"]
ATTACK_TOOLS = ["HOIC", "LOIC-HTTP", "LOIC-UDP"]

# Human-readable version of tool_of, stored in model metadata.
LABEL_MAPPING = {
    "contains 'benign'": "Benign",
    "contains 'udp'": "LOIC-UDP",
    "contains 'hoic'": "HOIC",
    "contains 'http'": "LOIC-HTTP",
    "anything else": "Other",
}


def tool_of(label) -> str:
    """Map an inconsistent raw label to a tool name (order matters, as in the notebook)."""
    s = str(label).lower()
    if "benign" in s:
        return "Benign"
    if "udp" in s:
        return "LOIC-UDP"
    if "hoic" in s:
        return "HOIC"
    if "http" in s:
        return "LOIC-HTTP"
    return "Other"


def tools_from_labels(labels: pd.Series) -> pd.Series:
    # Map unique values only: millions of rows share a handful of labels.
    uniq = pd.unique(labels.astype(str))
    return labels.astype(str).map({u: tool_of(u) for u in uniq})


def normalise_columns(columns) -> list[str]:
    """CICFlowMeter headers sometimes carry stray spaces."""
    return [str(c).strip() for c in columns]


def missing_columns(columns) -> list[str]:
    have = set(normalise_columns(columns))
    return [c for c in REQUIRED_COLUMNS if c not in have]


def clean_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Strip header names, drop repeated header rows, coerce numerics, inf -> NaN.

    Rows with NaN are NOT dropped here: training drops them, the app reports them as
    "Not scored".
    """
    df = df.copy()
    df.columns = normalise_columns(df.columns)
    if LABEL in df.columns:
        df = df[df[LABEL].astype(str).str.strip() != LABEL]
    for c in REQUIRED_COLUMNS:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    num = [c for c in REQUIRED_COLUMNS if c in df.columns]
    df[num] = df[num].replace([np.inf, -np.inf], np.nan)
    return df


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return the 9 model inputs (float64) for an already-cleaned frame."""
    X = df[BASE_FEATURES].astype("float64").copy()
    X["fwd_bwd_ratio"] = df["Tot Fwd Pkts"].astype("float64") / (df["Tot Bwd Pkts"].astype("float64") + 1)
    X = X.replace([np.inf, -np.inf], np.nan)
    return X[FEATURES]


def valid_mask(X: pd.DataFrame) -> np.ndarray:
    """True for rows whose model inputs are all finite (these can be scored)."""
    return np.isfinite(X[FEATURES].to_numpy(dtype="float64")).all(axis=1)
