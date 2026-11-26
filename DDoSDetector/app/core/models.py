"""The model types the app can train, save, load, score and explain.

XGBoost is the main model. Random Forest and a linear SVM are the group's comparison models (decided
in November 2026). Training (train/train_model.py) and the app both build models through this module,
so they always agree on the settings and on how a model is stored.

Storage: XGBoost uses its own JSON format; the scikit-learn models are saved with joblib, which is a
pickle, so only open model files you made yourself. Each model's .meta.json records `model_type`
(models without it are XGBoost).

Model score: every model gives a number from 0 to 1 for "DDoS". It is not calibrated:
  XGBoost        sigmoid(log-odds), with class weights (scale_pos_weight)
  Random Forest  the average over its trees of the DDoS share in the leaf the flow reaches
  Linear SVM     sigmoid(SVM decision value), so 0.5 is the SVM's own boundary
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.svm import LinearSVC
from xgboost import XGBClassifier

XGBOOST, RANDOM_FOREST, LINEAR_SVM = "xgboost", "random_forest", "linear_svm"
MODEL_TYPES = {XGBOOST: "XGBoost", RANDOM_FOREST: "Random Forest", LINEAR_SVM: "Linear SVM"}
NAME_SUFFIX = {XGBOOST: "", RANDOM_FOREST: "_rf", LINEAR_SVM: "_svm"}     # all_tools_f7ip, all_tools_f7ip_rf, ...
FILE_SUFFIX = {XGBOOST: ".json", RANDOM_FOREST: ".joblib", LINEAR_SVM: ".joblib"}
# Missing values (NaN in a non-core group) are allowed for the tree models; the linear SVM cannot use them,
# so the app counts such rows as "Not scored" for it and training refuses feature sets that have them.
ACCEPTS_MISSING = {XGBOOST: True, RANDOM_FOREST: True, LINEAR_SVM: False}


def xgboost_params(spw: float, seed: int) -> dict:
    return dict(n_estimators=300, max_depth=6, learning_rate=0.1, tree_method="hist",
                scale_pos_weight=float(spw), n_jobs=-1, random_state=seed)


# Shallower than the update-4 experiment's forest (depth 20, 2 flows per leaf) so SHAP explanations stay
# fast in the app. Measured on the f9p all-tools split (seed 0, 4 Nov 2026): recall 0.9997 / 0.9998 / 1.0,
# FPR 0.0003, 1.3 MB, SHAP for 500 flows 0.9 s; depth 20 / leaf 2 gave 0.9999 / 0.9999 / 1.0, FPR 0.0002,
# 2.0 MB, 4.0 s.
RF_PARAMS = dict(n_estimators=100, max_depth=12, min_samples_leaf=20, class_weight="balanced", n_jobs=-1)
SVM_PARAMS = dict(C=1.0, class_weight="balanced", dual=False, max_iter=5000)


def signed_log(X):
    """log(1 + |x|) with the sign kept: rates and counts span many orders of magnitude."""
    X = np.asarray(X, dtype="float64")
    return np.sign(X) * np.log1p(np.abs(X))


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.asarray(z, dtype="float64")))


class LinearSVMModel:
    """Linear SVM on log-scaled, standardised inputs. decision value d(x) = w·z + b, where z are the
    standardised inputs; model score = sigmoid(d(x))."""

    def __init__(self, seed: int = 0, **params):
        self.params = {**SVM_PARAMS, **params}
        self.pipe = make_pipeline(FunctionTransformer(signed_log), StandardScaler(),
                                  LinearSVC(random_state=seed, **self.params))

    def fit(self, X: pd.DataFrame, y):
        self.pipe.fit(X, y)
        self.feature_names_in_ = np.asarray(X.columns)
        return self

    def decision_function(self, X) -> np.ndarray:
        return self.pipe.decision_function(X)

    def predict_proba(self, X) -> np.ndarray:   # scikit-learn's name for "score per class"
        s = sigmoid(self.decision_function(X))
        return np.column_stack([1 - s, s])

    @property
    def weights(self) -> np.ndarray:
        return self.pipe[-1].coef_[0]

    @property
    def intercept(self) -> float:
        return float(self.pipe[-1].intercept_[0])

    def contributions(self, X) -> np.ndarray:
        """Exact SHAP values of the decision value: w_j * z_j. The inputs are standardised on the training
        data, so their average there is 0 and the base value is the intercept b."""
        return self.pipe[:-1].transform(X) * self.weights


def make_model(model_type: str, spw: float, seed: int):
    """A new, untrained model and the settings to record in its metadata."""
    if model_type == XGBOOST:
        params = xgboost_params(spw, seed)
        return XGBClassifier(**params), params
    if model_type == RANDOM_FOREST:
        params = {**RF_PARAMS, "random_state": seed}
        return RandomForestClassifier(**params), params
    if model_type == LINEAR_SVM:
        model = LinearSVMModel(seed=seed)
        return model, {**model.params, "inputs": "log(1 + |x|) with sign, then standardised", "random_state": seed}
    raise ValueError(f"unknown model type: {model_type}")


def model_type_of(model) -> str:
    if isinstance(model, XGBClassifier):
        return XGBOOST
    if isinstance(model, RandomForestClassifier):
        return RANDOM_FOREST
    if isinstance(model, LinearSVMModel):
        return LINEAR_SVM
    raise TypeError(f"not a supported model: {type(model).__name__}")


def save_model(model, path_stem) -> Path:
    """Save next to the metadata (path_stem + the type's file suffix); returns the file written."""
    kind = model_type_of(model)
    path = Path(f"{path_stem}{FILE_SUFFIX[kind]}")
    if kind == XGBOOST:
        model.save_model(path)
    else:
        joblib.dump(model, path, compress=3)
    return path


def load_model(path, model_type: str = XGBOOST):
    if model_type == XGBOOST:
        model = XGBClassifier()
        model.load_model(path)
        return model
    model = joblib.load(path)
    if model_type_of(model) != model_type:
        raise ValueError(f"{path}: expected a {MODEL_TYPES[model_type]} model")
    return model
