"""SHAP wrappers with a cached TreeExplainer.

SHAP values for XGBoost binary classification are in LOG-ODDS (the model's raw margin):
    base_value + shap_values.sum() == model.predict(X, output_margin=True)
The table shows the model score = sigmoid(f(x)), a number from 0 to 1 that is NOT a calibrated
chance of attack (training used scale_pos_weight).
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, Optional

import numpy as np
import pandas as pd
import shap
import xgboost as xgb

from .features import column_label, groups_for
from .timing import Stopwatch


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.asarray(z, dtype=float)))


def contributions(model, X: pd.DataFrame) -> np.ndarray:
    """Exact TreeSHAP values (log-odds) via XGBoost's own multithreaded implementation.

    Same values as shap.TreeExplainer(model) in tree_path_dependent mode, but much faster for
    hundreds of thousands of rows (used for alert export and seed stability).
    """
    out = model.get_booster().predict(xgb.DMatrix(X), pred_contribs=True)
    return np.asarray(out[:, :-1], dtype=float)   # last column is the bias (base value)


def top_features(values: np.ndarray, names: list[str], k: int = 3) -> list[list[str]]:
    """For each row, the k largest |SHAP| columns as 'Flow Duration (F2): pushes toward DDoS'."""
    order = np.argsort(-np.abs(values), axis=1)[:, :k]
    labels = np.asarray([column_label(n) for n in names])
    out = []
    for r, idx in enumerate(order):
        out.append([f"{labels[j]}: pushes toward {'DDoS' if values[r, j] > 0 else 'Benign'}" for j in idx])
    return out


def group_shap(values: np.ndarray, columns: list[str]) -> tuple[np.ndarray, list[str]]:
    """Per-row SHAP value of each feature GROUP = sum of its columns' SHAP values (SHAP is
    additive, so the row total is unchanged). Returns (values, group labels like 'F10 ...')."""
    groups = groups_for(columns)
    idx = {c: i for i, c in enumerate(columns)}
    out = np.column_stack([values[:, [idx[c] for c in g.output_columns if c in idx]].sum(axis=1)
                           for g in groups]) if groups else np.zeros((len(values), 0))
    return out, [g.label for g in groups]


@dataclass
class ShapResult:
    rows: np.ndarray          # positions into the loaded feature frame
    values: np.ndarray        # (n, n_features) log-odds contributions
    base_value: float         # expected model output in log-odds
    data: pd.DataFrame        # feature values for those rows


class ExplainerCache:
    """Holds one TreeExplainer per model and caches SHAP results per dataset.

    Call reset(model, X, data_id) whenever the model or the data changes.
    Thread-safe enough for one worker at a time plus UI reads.
    `on_timing(label, seconds, n)` is called with measured times for new computations.
    """

    def __init__(self, on_timing: Optional[Callable[[str, float, int], None]] = None):
        self._lock = threading.RLock()   # re-entrant: memo() computations may call explain_*()
        self._explainer = None
        self._model_key = None
        self.X: pd.DataFrame | None = None
        self.data_id = None
        self._rows: dict[int, np.ndarray] = {}
        self._global: dict[tuple, ShapResult] = {}
        self.on_timing = on_timing

    def reset(self, model, X: pd.DataFrame | None, data_id) -> None:
        with self._lock:
            if model is not self._model_key:
                # Default tree_path_dependent mode: exact and fast for XGBoost.
                self._explainer = shap.TreeExplainer(model) if model is not None else None
                self._model_key = model
            self.X, self.data_id = X, data_id
            self._rows.clear()
            self._global.clear()

    @property
    def base_value(self) -> float:
        ev = self._explainer.expected_value
        return float(np.ravel(ev)[0])

    def _shap(self, X: pd.DataFrame, label: str) -> np.ndarray:
        with Stopwatch() as sw:
            sv = self._explainer.shap_values(X)
        if self.on_timing:
            self.on_timing(label, sw.seconds, len(X))
        if isinstance(sv, list):  # some shap versions return [neg, pos]
            sv = sv[-1]
        return np.asarray(sv, dtype=float)

    def explain_row(self, pos: int) -> ShapResult:
        with self._lock:
            if pos not in self._rows:
                self._rows[pos] = self._shap(self.X.iloc[[pos]], "selected flow")[0]
            vals = self._rows[pos]
        return ShapResult(np.array([pos]), vals[None, :], self.base_value, self.X.iloc[[pos]])

    def explain_sample(self, candidates: np.ndarray, n: int, seed: int = 0) -> ShapResult:
        """SHAP for a random sample of n rows drawn from `candidates` (positions)."""
        key = ("sample", n, seed)
        with self._lock:
            if key not in self._global:
                rng = np.random.default_rng(seed)
                rows = candidates if len(candidates) <= n else np.sort(rng.choice(candidates, n, replace=False))
                data = self.X.iloc[rows]
                self._global[key] = ShapResult(rows, self._shap(data, "global sample"), self.base_value, data)
            return self._global[key]

    def memo(self, key, compute: Callable[[], object]):
        """Cache any derived result (e.g. other models' SHAP) until the next reset()."""
        with self._lock:
            if ("memo", key) not in self._global:
                self._global[("memo", key)] = compute()
            return self._global[("memo", key)]

    def explain_rows(self, rows: np.ndarray, key) -> ShapResult:
        """SHAP for specific rows, cached under `key` until the next reset()."""
        with self._lock:
            if key not in self._global:
                data = self.X.iloc[rows]
                self._global[key] = ShapResult(np.asarray(rows), self._shap(data, str(key[0])),
                                               self.base_value, data)
            return self._global[key]
