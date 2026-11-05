"""SHAP wrappers with a cached explainer, for every model type in app/core/models.py.

What the SHAP values add up to (base_value + shap_values.sum() == f(x) for every flow):
  XGBoost        LOG-ODDS (the raw margin, model.predict(X, output_margin=True)); score = sigmoid(f(x))
  Random Forest  the model score itself (TreeSHAP on the forest's output); score = f(x)
  Linear SVM     the SVM decision value; score = sigmoid(f(x)); exact: w_j * z_j (models.py)
The table shows the model score, a number from 0 to 1 that is NOT a calibrated chance of attack.
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
from .models import LINEAR_SVM, RANDOM_FOREST, XGBOOST, model_type_of
from .timing import Stopwatch

# (unit of f(x) and the SHAP values, whether model score = sigmoid(f(x)))
UNITS = {XGBOOST: ("log-odds", True), RANDOM_FOREST: ("model score", False),
         LINEAR_SVM: ("SVM decision value", True)}


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.asarray(z, dtype=float)))


def output_unit(model) -> str:
    """'log-odds', 'model score' or 'SVM decision value': the unit of f(x) and of the SHAP values."""
    return UNITS[model_type_of(model)][0]


def score_of(model, fx):
    """Model score (0..1) for an output f(x) in the model's SHAP units."""
    return sigmoid(fx) if UNITS[model_type_of(model)][1] else np.asarray(fx, dtype=float)


def _ddos_part(sv) -> np.ndarray:
    """TreeExplainer returns one set of values per class for a Random Forest; keep DDoS (the last)."""
    if isinstance(sv, list):
        sv = sv[-1]
    sv = np.asarray(sv, dtype=float)
    return sv[..., -1] if sv.ndim == 3 else sv


def contributions(model, X: pd.DataFrame) -> np.ndarray:
    """Exact SHAP values for many rows, in the model's own units (see the module docstring).

    XGBoost: its own multithreaded TreeSHAP (same values as shap.TreeExplainer(model) in
    tree_path_dependent mode, much faster for hundreds of thousands of rows). Random Forest:
    shap.TreeExplainer. Linear SVM: w_j * z_j. Used for alert export and the stability charts.
    """
    kind = model_type_of(model)
    if kind == XGBOOST:
        out = model.get_booster().predict(xgb.DMatrix(X), pred_contribs=True)
        return np.asarray(out[:, :-1], dtype=float)   # last column is the bias (base value)
    if kind == LINEAR_SVM:
        return np.asarray(model.contributions(X), dtype=float)
    return _ddos_part(shap.TreeExplainer(model).shap_values(X))


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
    values: np.ndarray        # (n, n_features) contributions, in the model's units (output_unit)
    base_value: float         # expected model output, same units
    data: pd.DataFrame        # feature values for those rows


class ExplainerCache:
    """Holds one explainer per model and caches SHAP results per dataset.

    XGBoost and Random Forest use shap.TreeExplainer (default tree_path_dependent mode: exact). The
    linear SVM needs no explainer: its SHAP values are w_j * z_j (models.LinearSVMModel).
    Call reset(model, X, data_id) whenever the model or the data changes.
    Thread-safe enough for one worker at a time plus UI reads.
    `on_timing(label, seconds, n)` is called with measured times for new computations.
    """

    def __init__(self, on_timing: Optional[Callable[[str, float, int], None]] = None):
        self._lock = threading.RLock()   # re-entrant: memo() computations may call explain_*()
        self._explainer = None
        self._model = None
        self._kind = None
        self.X: pd.DataFrame | None = None
        self.data_id = None
        self._rows: dict[int, np.ndarray] = {}
        self._global: dict[tuple, ShapResult] = {}
        self.on_timing = on_timing

    def reset(self, model, X: pd.DataFrame | None, data_id) -> None:
        with self._lock:
            if model is not self._model:
                self._kind = model_type_of(model) if model is not None else None
                self._explainer = (shap.TreeExplainer(model)
                                   if model is not None and self._kind != LINEAR_SVM else None)
                self._model = model
            self.X, self.data_id = X, data_id
            self._rows.clear()
            self._global.clear()

    @property
    def unit(self) -> str:
        return UNITS[self._kind][0] if self._kind else UNITS[XGBOOST][0]

    def score_of(self, fx):
        """Model score (0..1) for a model output in this explainer's units."""
        return sigmoid(fx) if (UNITS[self._kind][1] if self._kind else True) else np.asarray(fx, dtype=float)

    @property
    def base_value(self) -> float:
        if self._kind == LINEAR_SVM:
            return self._model.intercept
        ev = self._explainer.expected_value
        return float(np.ravel(ev)[-1])   # one value per class for a Random Forest: DDoS is the last

    def _shap(self, X: pd.DataFrame, label: str) -> np.ndarray:
        with Stopwatch() as sw:
            sv = (self._model.contributions(X) if self._kind == LINEAR_SVM
                  else self._explainer.shap_values(X))
        if self.on_timing:
            self.on_timing(label, sw.seconds, len(X))
        return _ddos_part(sv)

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
