"""Explanation stability across MODELS (setups): do models trained on different data
(all tools, each tool held out, each benign split) rank the features the same way?

Uses the seed-0 model of every setup in the models folder with the active model's feature set and
model type (feedback-retrained models excluded). The three model types are compared in the
"Model types" and "Model types: features" charts (model_types.py, model_types_features.py).
"""
import json

import pandas as pd

from app.core.features import feature_set_of
from app.core.models import MODEL_TYPES
from app.core.model_store import META_SUFFIX, list_models, model_columns, model_type_from

from . import _style as S
from .base import ChartPlugin, message, register
from .seed_stability import draw_rank_comparison, mean_abs_shap_for


def setup_models(models_dir, feature_set: str | None = None,
                 model_type: str | None = None) -> list[tuple[str, object]]:
    """(name, meta_path) of the seed-0 model of each setup (optionally one feature set and/or one
    model type only), the all-tools model first."""
    out = []
    for p in list_models(models_dir):
        try:
            meta = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if feature_set is not None and feature_set_of(model_columns(meta)) != feature_set:
            continue
        if model_type is not None and model_type_from(meta) != model_type:
            continue
        if meta.get("seed", 0) == 0 and not meta.get("extra_labelled"):
            out.append((p.name[: -len(META_SUFFIX)], p))
    return sorted(out, key=lambda e: (not e[0].startswith("all_tools"), e[0]))


@register
class ModelStability(ChartPlugin):
    name = "Model stability"
    scope = "global"
    order = 62

    def _table(self, ctx):
        fset, kind = feature_set_of(model_columns(ctx.model_meta)), model_type_from(ctx.model_meta)
        key = ("model_stability", ctx.sample_size, ctx.seed, fset, kind)
        return ctx.cache.memo(key, lambda: mean_abs_shap_for(ctx, setup_models(ctx.models_dir, fset, kind)))

    def prepare(self, ctx):
        if ctx.models_dir is not None:
            self._table(ctx)

    def render(self, figure, ctx):
        S.style_figure(figure)
        imp = self._table(ctx) if ctx.models_dir is not None else pd.DataFrame()
        if imp.shape[1] < 2:
            return message(figure, "Needs at least two trained setups in the models folder\n"
                                   "(e.g. all_tools and the held-out models).")
        fset = feature_set_of(model_columns(ctx.model_meta))
        kind = MODEL_TYPES[model_type_from(ctx.model_meta)]
        draw_rank_comparison(figure, imp, f"Do different models rely on the same features? ({kind}, {fset})",
                             "models", short_labels=list(imp.columns))
