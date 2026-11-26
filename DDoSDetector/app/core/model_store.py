"""Load and save trained models plus their metadata.

A model is three files sharing a name in the models folder:
    <name>.json or .joblib  the model (XGBoost's own format, or joblib for Random Forest / linear SVM)
    <name>.meta.json        model type, feature list, training info, metrics, library versions
    <name>.background.parquet (or .csv)  SHAP background sample of training features
Any model with a .meta.json can be opened from the Model menu without code changes.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pandas as pd

from .features import FEATURES_F9, feature_set_of
from .models import FILE_SUFFIX, MODEL_TYPES, XGBOOST, load_model, model_type_of, save_model

META_SUFFIX = ".meta.json"


@dataclass
class ModelBundle:
    name: str
    model: object               # XGBClassifier, RandomForestClassifier or models.LinearSVMModel
    meta: dict
    background: Optional[pd.DataFrame] = None
    meta_path: Optional[Path] = None
    _id: int = field(default=0, repr=False)
    version: str = ""           # short SHA-1 of the model file: identifies exactly which model scored

    @property
    def features(self) -> list[str]:
        return model_columns(self.meta)

    @property
    def feature_set(self) -> str:
        return feature_set_of(self.features)

    @property
    def title(self) -> str:
        return self.meta.get("title", self.name)

    @property
    def setup(self) -> str:
        """Models with the same setup and different seeds are seed variants of each other."""
        return setup_of(self.meta, self.name)

    @property
    def model_type(self) -> str:
        return model_type_from(self.meta)

    @property
    def model_type_name(self) -> str:
        return MODEL_TYPES[self.model_type]


def model_type_from(meta: dict) -> str:
    """'xgboost', 'random_forest' or 'linear_svm'; models saved before the field existed are XGBoost."""
    return meta.get("model_type") or XGBOOST


def model_columns(meta: dict) -> list[str]:
    """The model's input columns, in order. Models trained before the feature registry stored
    them as `features`; a model with neither is one of the original nine-column models."""
    return list(meta.get("feature_columns") or meta.get("features") or FEATURES_F9)


FPR_BUDGET = 0.001          # the default threshold may cost at most 0.1 % false alarms on the model's benign test split
FALLBACK_THRESHOLD = 0.5


def default_threshold(meta: dict, fpr_budget: float = FPR_BUDGET) -> tuple[float, str]:
    """The threshold the app starts at for this model, and a one-sentence reason for the Model card.

    Rule (6 Nov 2026): the LOWEST threshold in the model's own threshold sweep (recall and false-alarm rate on its
    test split, written by the training script) whose false-alarm rate is within the budget. It is chosen from the
    benign side only, so a held-out tool's scores never set it: a model's scores are calibrated to the tools it was
    trained on, and an unseen tool's scores can sit well below 0.5. Falls back to 0.5 when the metadata has no
    sweep or no tested threshold stays within the budget (the by-file and attack-period splits).
    """
    sweep = [s for s in (meta.get("metrics") or {}).get("threshold_sweep") or [] if s.get("fpr") is not None]
    budget = f"{fpr_budget:.1%}"
    if not sweep:
        return FALLBACK_THRESHOLD, f"{FALLBACK_THRESHOLD}: this model's metadata has no threshold sweep."
    within = [s for s in sweep if s["fpr"] <= fpr_budget]
    if not within:
        least = min(sweep, key=lambda s: (s["fpr"], -s["threshold"]))
        return FALLBACK_THRESHOLD, (f"{FALLBACK_THRESHOLD}: no tested threshold keeps false alarms within {budget} on "
                                    f"this model's benign test split (the lowest is {least['fpr']:.2%} at "
                                    f"{least['threshold']}).")
    best = min(within, key=lambda s: s["threshold"])
    return float(best["threshold"]), (f"{best['threshold']}: the lowest tested threshold whose false-alarm rate on "
                                      f"this model's benign test split is within {budget} ({best['fpr']:.2%}); "
                                      f"recall there {best['recall']:.3f}. Chosen from the benign side only.")


def setup_of(meta: dict, name: str = "") -> str:
    return meta.get("setup") or meta.get("mode") or name


def file_version(path: Path) -> str:
    return hashlib.sha1(Path(path).read_bytes()).hexdigest()[:10]


def _paths(models_dir: Path, name: str) -> dict[str, Path]:
    d = Path(models_dir)
    return {
        "meta": d / f"{name}{META_SUFFIX}",
        "parquet": d / f"{name}.background.parquet",
        "csv": d / f"{name}.background.csv",
    }


def save_bundle(models_dir: Path, name: str, model, meta: dict,
                background: Optional[pd.DataFrame] = None) -> Path:
    p = _paths(models_dir, name)
    Path(models_dir).mkdir(parents=True, exist_ok=True)
    meta["model_type"] = model_type_of(model)
    model_file = save_model(model, Path(models_dir) / name)
    if background is not None:
        try:
            background.to_parquet(p["parquet"], index=False)
            meta["background_file"] = p["parquet"].name
        except ImportError:  # pyarrow not installed
            background.to_csv(p["csv"], index=False)
            meta["background_file"] = p["csv"].name
    meta["model_file"] = model_file.name
    meta["version"] = file_version(model_file)
    p["meta"].write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return p["meta"]


def model_file_of(meta_path: Path, meta: dict) -> Path:
    name = meta_path.name[: -len(META_SUFFIX)] if meta_path.name.endswith(META_SUFFIX) else meta_path.stem
    return meta_path.parent / meta.get("model_file", f"{name}{FILE_SUFFIX[model_type_from(meta)]}")


def load_model_of(meta_path: Path, meta: dict | None = None):
    """Just the model object of a saved bundle (used by charts that compare several models)."""
    meta_path = Path(meta_path)
    meta = meta if meta is not None else read_meta(meta_path)
    return load_model(model_file_of(meta_path, meta), model_type_from(meta))


_next_id = 0


def load_bundle(meta_path: Path) -> ModelBundle:
    global _next_id
    meta_path = Path(meta_path)
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    name = meta_path.name[: -len(META_SUFFIX)] if meta_path.name.endswith(META_SUFFIX) else meta_path.stem
    model_file = model_file_of(meta_path, meta)
    if not model_file.exists():
        raise FileNotFoundError(f"Model file not found: {model_file}")
    model = load_model(model_file, model_type_from(meta))

    background = None
    bg = meta.get("background_file")
    if bg and (meta_path.parent / bg).exists():
        bg_path = meta_path.parent / bg
        background = pd.read_parquet(bg_path) if bg_path.suffix == ".parquet" else pd.read_csv(bg_path)
    _next_id += 1
    return ModelBundle(name=name, model=model, meta=meta, background=background,
                       meta_path=meta_path, _id=_next_id, version=file_version(model_file))


def list_models(models_dir: Path) -> list[Path]:
    d = Path(models_dir)
    if not d.is_dir():
        return []
    return sorted(d.glob(f"*{META_SUFFIX}"))


def read_meta(meta_path: Path) -> dict:
    return json.loads(Path(meta_path).read_text(encoding="utf-8"))


def read_metas(models_dir: Path) -> list[tuple[str, dict]]:
    """(name, metadata) for every model in models_dir; unreadable files are skipped."""
    out = []
    for p in list_models(models_dir):
        try:
            out.append((p.name[: -len(META_SUFFIX)], json.loads(p.read_text(encoding="utf-8"))))
        except (OSError, ValueError):
            continue
    return out


def held_out_results(models_dir: Path, feature_set: str | None = None,
                     model_type: str | None = None) -> list[dict]:
    """One row per seed-0 model: held-out tool (None = all tools seen), split, feature set and its
    own test metrics (optionally only models of one feature set and/or one model type). Used by the
    Held-out comparison chart and the model card."""
    rows = []
    for name, meta in read_metas(models_dir):
        m = meta.get("metrics") or {}
        if not m or meta.get("seed", 0) != 0 or meta.get("extra_labelled"):
            continue
        fset = feature_set_of(model_columns(meta))
        if feature_set is not None and fset != feature_set:
            continue
        if model_type is not None and model_type_from(meta) != model_type:
            continue
        tool = meta.get("held_out_tool")
        split = meta.get("benign_split_mode") or ("random" if not tool else "per_day")
        rows.append({"name": name, "held_out": tool, "split": split, "feature_set": fset,
                     "model_type": model_type_from(meta),
                     "recall": m.get("recall", {}), "n_test": m.get("n_test", {}),
                     "fpr": m.get("fpr"), "false_alarms": m.get("false_alarms"),
                     "pr_auc": m.get("pr_auc"), "base_rate": m.get("base_rate"),
                     "sweep": m.get("threshold_sweep", []), "timing": meta.get("timing")})
    return rows


def check_features(meta: dict, columns) -> list[str]:
    """Model input features missing from a feature frame's columns (empty = OK)."""
    have = set(columns)
    return [f for f in model_columns(meta) if f not in have]
