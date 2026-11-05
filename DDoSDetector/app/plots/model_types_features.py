"""Model types, features: do XGBoost, Random Forest and the linear SVM rank the features the same way?

Mean |SHAP| per column for the seed-0 all-tools model of each type (the active model's feature set),
on the same sample of loaded flows. The SHAP values are in each model's own units (log-odds, model
score, SVM decision value), so the chart compares RANKS, not sizes.
"""
import json

import pandas as pd

from app.core.features import feature_set_of
from app.core.model_store import META_SUFFIX, list_models, model_columns, model_type_from
from app.core.models import MODEL_TYPES

from . import _style as S
from .base import ChartPlugin, message, register
from .seed_stability import draw_rank_comparison, mean_abs_shap_for


def all_tools_by_type(models_dir, feature_set: str) -> list[tuple[str, object]]:
    """(model type name, meta_path) of the seed-0 all-tools model of each type with this feature set."""
    found = {}
    for p in list_models(models_dir):
        try:
            meta = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if (meta.get("mode") == "all_tools" and meta.get("seed", 0) == 0 and not meta.get("extra_labelled")
                and feature_set_of(model_columns(meta)) == feature_set):
            kind = model_type_from(meta)
            name = p.name[: -len(META_SUFFIX)]
            if kind not in found or name == meta.get("setup"):   # prefer the plain setup name
                found[kind] = p
    return [(MODEL_TYPES[k], found[k]) for k in MODEL_TYPES if k in found]


@register
class ModelTypesFeatures(ChartPlugin):
    name = "Model types: features"
    scope = "global"
    order = 67

    def _table(self, ctx):
        fset = feature_set_of(model_columns(ctx.model_meta))
        key = ("model_types_features", ctx.sample_size, ctx.seed, fset)
        return ctx.cache.memo(key, lambda: mean_abs_shap_for(ctx, all_tools_by_type(ctx.models_dir, fset)))

    def prepare(self, ctx):
        if ctx.models_dir is not None:
            self._table(ctx)

    def render(self, figure, ctx):
        S.style_figure(figure)
        imp = self._table(ctx) if ctx.models_dir is not None else pd.DataFrame()
        fset = feature_set_of(model_columns(ctx.model_meta))
        if imp.shape[1] < 2:
            return message(figure, f"Needs all-tools models of at least two types with the feature set {fset}.\n\n"
                                   "Train them with, for example:\ntrain_model.py --mode all_tools --model random_forest\n"
                                   "train_model.py --mode all_tools --model linear_svm")
        draw_rank_comparison(figure, imp, f"Do the three model types rely on the same features? ({fset})",
                             "model types", short_labels=list(imp.columns))
