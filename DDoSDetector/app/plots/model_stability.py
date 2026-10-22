"""Explanation stability across MODELS (setups): do models trained on different data
(all tools, each tool held out, each benign split) rank the features the same way?

Uses the seed-0 model of every setup in the models folder (feedback-retrained models excluded).
"""
import json

import pandas as pd

from app.core.model_store import META_SUFFIX, list_models

from . import _style as S
from .base import ChartPlugin, message, register
from .seed_stability import draw_rank_comparison, mean_abs_shap_for


def setup_models(models_dir) -> list[tuple[str, object]]:
    """(name, meta_path) of the seed-0 model of each setup, all_tools first."""
    out = []
    for p in list_models(models_dir):
        try:
            meta = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if meta.get("seed", 0) == 0 and not meta.get("extra_labelled"):
            out.append((p.name[: -len(META_SUFFIX)], p))
    return sorted(out, key=lambda e: (e[0] != "all_tools", e[0]))


@register
class ModelStability(ChartPlugin):
    name = "Model stability"
    scope = "global"
    order = 62

    def _table(self, ctx):
        key = ("model_stability", ctx.sample_size, ctx.seed)
        return ctx.cache.memo(key, lambda: mean_abs_shap_for(ctx, setup_models(ctx.models_dir)))

    def prepare(self, ctx):
        if ctx.models_dir is not None:
            self._table(ctx)

    def render(self, figure, ctx):
        S.style_figure(figure)
        imp = self._table(ctx) if ctx.models_dir is not None else pd.DataFrame()
        if imp.shape[1] < 2:
            return message(figure, "Needs at least two trained setups in the models folder\n"
                                   "(e.g. all_tools and the held-out models).")
        draw_rank_comparison(figure, imp, "Do different models rely on the same features?", "models",
                             short_labels=list(imp.columns))
