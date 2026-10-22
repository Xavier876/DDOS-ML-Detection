"""Batch scoring and threshold logic."""
from __future__ import annotations

import numpy as np
import pandas as pd

from .features import ATTACK_TOOLS, build_features, buildable_columns, valid_mask
from .model_store import ModelBundle, check_features

BENIGN, DDOS, NOT_SCORED = "Benign", "DDoS", "Not scored"
FLAG_NAMES = np.array([BENIGN, DDOS, NOT_SCORED])
# Integer flag codes (index into FLAG_NAMES) keep 1M-row tables cheap.
CODE_BENIGN, CODE_DDOS, CODE_NOT_SCORED = 0, 1, 2


def build_all(df: pd.DataFrame) -> pd.DataFrame:
    """Every registry column the CSV's raw columns allow (used by charts that compare models)."""
    return build_features(df, buildable_columns(df.columns))


def score(bundle: ModelBundle, df: pd.DataFrame) -> tuple[pd.DataFrame, np.ndarray]:
    """Score every row of a cleaned frame with exactly the model's `feature_columns`.

    Returns (X, scores): X holds the model inputs for every row and scores is the model score
    (0..1), NaN for rows that could not be scored (NaN/inf in a core column). Missing values in
    features 8-11 are allowed. No row is dropped.
    """
    missing = check_features(bundle.meta, buildable_columns(df.columns))
    if missing:
        raise ValueError("Model expects features that cannot be built from this CSV: " + ", ".join(missing))
    X = build_features(df, bundle.features)
    ok = valid_mask(X)
    scores = np.full(len(X), np.nan)
    if ok.any():
        scores[ok] = bundle.model.predict_proba(X[ok])[:, 1]
    return X, scores


def flag_codes(scores: np.ndarray, threshold: float) -> np.ndarray:
    codes = np.where(scores >= threshold, CODE_DDOS, CODE_BENIGN).astype(np.int8)
    codes[np.isnan(scores)] = CODE_NOT_SCORED
    return codes


def flags(scores: np.ndarray, threshold: float) -> np.ndarray:
    return FLAG_NAMES[flag_codes(scores, threshold)]


def label_metrics(scores: np.ndarray, tools: np.ndarray, threshold: float) -> dict:
    """Recall per attack tool and false positives on benign, over scored rows only."""
    scored = ~np.isnan(scores)
    pred = np.zeros(len(scores), dtype=bool)
    pred[scored] = scores[scored] >= threshold
    out = {"recall": {}, "n": {}}
    for t in ATTACK_TOOLS:
        m = scored & (tools == t)
        if m.any():
            out["recall"][t] = float(pred[m].mean())
            out["n"][t] = int(m.sum())
    att = scored & np.isin(tools, ATTACK_TOOLS)
    out["recall_all"] = float(pred[att].mean()) if att.any() else None
    ben = scored & (tools == "Benign")
    out["n_benign"] = int(ben.sum())
    out["false_positives"] = int(pred[ben].sum())
    out["fpr"] = float(pred[ben].mean()) if ben.any() else None
    return out
