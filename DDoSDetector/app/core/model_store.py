"""Load and save trained models plus their metadata.

A model is three files sharing a name in the models folder:
    <name>.json             XGBoost model (model.save_model)
    <name>.meta.json        feature list, training info, metrics, library versions
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
from xgboost import XGBClassifier

META_SUFFIX = ".meta.json"


@dataclass
class ModelBundle:
    name: str
    model: XGBClassifier
    meta: dict
    background: Optional[pd.DataFrame] = None
    meta_path: Optional[Path] = None
    _id: int = field(default=0, repr=False)
    version: str = ""           # short SHA-1 of the model file: identifies exactly which model scored

    @property
    def features(self) -> list[str]:
        return list(self.meta["features"])

    @property
    def title(self) -> str:
        return self.meta.get("title", self.name)

    @property
    def setup(self) -> str:
        """Models with the same setup and different seeds are seed variants of each other."""
        return setup_of(self.meta, self.name)


def setup_of(meta: dict, name: str = "") -> str:
    return meta.get("setup") or meta.get("mode") or name


def file_version(path: Path) -> str:
    return hashlib.sha1(Path(path).read_bytes()).hexdigest()[:10]


def _paths(models_dir: Path, name: str) -> dict[str, Path]:
    d = Path(models_dir)
    return {
        "model": d / f"{name}.json",
        "meta": d / f"{name}{META_SUFFIX}",
        "parquet": d / f"{name}.background.parquet",
        "csv": d / f"{name}.background.csv",
    }


def save_bundle(models_dir: Path, name: str, model: XGBClassifier, meta: dict,
                background: Optional[pd.DataFrame] = None) -> Path:
    p = _paths(models_dir, name)
    Path(models_dir).mkdir(parents=True, exist_ok=True)
    model.save_model(p["model"])
    if background is not None:
        try:
            background.to_parquet(p["parquet"], index=False)
            meta["background_file"] = p["parquet"].name
        except ImportError:  # pyarrow not installed
            background.to_csv(p["csv"], index=False)
            meta["background_file"] = p["csv"].name
    meta["model_file"] = p["model"].name
    meta["version"] = file_version(p["model"])
    p["meta"].write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return p["meta"]


_next_id = 0


def load_bundle(meta_path: Path) -> ModelBundle:
    global _next_id
    meta_path = Path(meta_path)
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if "features" not in meta:
        raise ValueError(f"{meta_path.name} has no 'features' list")
    name = meta_path.name[: -len(META_SUFFIX)] if meta_path.name.endswith(META_SUFFIX) else meta_path.stem
    model_file = meta_path.parent / meta.get("model_file", f"{name}.json")
    if not model_file.exists():
        raise FileNotFoundError(f"Model file not found: {model_file}")
    model = XGBClassifier()
    model.load_model(model_file)

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


def read_metas(models_dir: Path) -> list[tuple[str, dict]]:
    """(name, metadata) for every model in models_dir; unreadable files are skipped."""
    out = []
    for p in list_models(models_dir):
        try:
            out.append((p.name[: -len(META_SUFFIX)], json.loads(p.read_text(encoding="utf-8"))))
        except (OSError, ValueError):
            continue
    return out


def held_out_results(models_dir: Path) -> list[dict]:
    """One row per seed-0 model: held-out tool (None = all tools seen), split, and its own test
    metrics. Used by the Held-out comparison chart and the model card."""
    rows = []
    for name, meta in read_metas(models_dir):
        m = meta.get("metrics") or {}
        if not m or meta.get("seed", 0) != 0 or meta.get("extra_labelled"):
            continue
        tool = meta.get("held_out_tool")
        split = meta.get("benign_split_mode") or ("random" if not tool else "per_day")
        rows.append({"name": name, "held_out": tool, "split": split,
                     "recall": m.get("recall", {}), "n_test": m.get("n_test", {}),
                     "fpr": m.get("fpr"), "false_alarms": m.get("false_alarms"),
                     "pr_auc": m.get("pr_auc"), "base_rate": m.get("base_rate"),
                     "sweep": m.get("threshold_sweep", []), "timing": meta.get("timing")})
    return rows


def check_features(meta: dict, columns) -> list[str]:
    """Model input features missing from a feature frame's columns (empty = OK)."""
    have = set(columns)
    return [f for f in meta["features"] if f not in have]
