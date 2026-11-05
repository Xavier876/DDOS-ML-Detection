"""Seed stability of the explanation: does the mean |SHAP| feature ranking change between
models trained with different random seeds (same setup)?

Train seed variants with:  train_model.py --mode all_tools --seeds 0 1 2 3 4
The ranking/correlation drawing is shared with the Model stability chart (model_stability.py).
"""
import json

import numpy as np
import pandas as pd

from app.core.explain import contributions
from app.core.features import column_label
from app.core.model_store import META_SUFFIX, list_models, load_model_of, model_columns, setup_of

from . import _style as S
from .base import ChartPlugin, message, register


def seed_variants(models_dir, setup: str) -> list[tuple[int, str, object]]:
    """(seed, name, meta_path) for every model in models_dir with this setup, sorted by seed."""
    out = []
    for p in list_models(models_dir):
        try:
            meta = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        name = p.name[: -len(META_SUFFIX)]
        if setup_of(meta, name) == setup and "seed" in meta:
            out.append((int(meta["seed"]), name, p))
    return sorted(out)


def mean_abs_shap_for(ctx, entries: list[tuple[str, object]]) -> pd.DataFrame:
    """Features x models table of mean |SHAP| on the SAME sample of loaded flows.
    `entries` is a list of (column label, meta_path). Each model's SHAP values are in its own units
    (see app/core/explain.py); the charts compare ranks, which do not depend on the units."""
    sample = ctx.sample_shap()
    source = ctx.X_all.iloc[sample.rows] if ctx.X_all is not None else sample.data
    cols = {}
    for label, meta_path in entries:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        features = model_columns(meta)
        if any(c not in source.columns for c in features):
            continue            # this model needs columns the loaded CSV cannot provide
        model = load_model_of(meta_path, meta)
        cols[label] = pd.Series(np.abs(contributions(model, source[features])).mean(axis=0), index=features)
    out = pd.DataFrame(cols)
    out.index = [column_label(c) for c in out.index]
    return out


def mean_abs_shap_by_seed(ctx) -> pd.DataFrame:
    setup = setup_of(ctx.model_meta, ctx.model_name)
    return mean_abs_shap_for(ctx, [(f"seed {s}", p) for s, _, p in seed_variants(ctx.models_dir, setup)])


def draw_rank_comparison(figure, imp: pd.DataFrame, title: str, what: str, short_labels=None):
    """Rank heatmap (features x columns) + Spearman correlation matrix between the columns."""
    ranks = imp.rank(ascending=False, method="min").astype(int)          # 1 = most important
    order = ranks.mean(axis=1).sort_values().index
    ranks, imp = ranks.loc[order], imp.loc[order]
    rho = imp.corr(method="spearman")
    off_diag = rho.to_numpy()[~np.eye(len(rho), dtype=bool)]
    short = short_labels or [str(c) for c in rho.columns]

    gs = figure.add_gridspec(1, 2, width_ratios=[1.35, 1], left=0.2, right=0.97, top=0.8,
                             bottom=0.16, wspace=0.35)
    ax = figure.add_subplot(gs[0, 0])
    n = len(ranks)
    ax.imshow(ranks.to_numpy(), cmap=S.SEQ_CMAP.reversed(), vmin=1, vmax=n, aspect="auto")
    for i in range(n):
        for j in range(ranks.shape[1]):
            ax.text(j, i, str(ranks.iat[i, j]), ha="center", va="center", fontsize=8.5, color=S.THEME["ink"])
    ax.set_xticks(range(ranks.shape[1]), short, fontsize=8, rotation=30 if len(max(short, key=len)) > 8 else 0,
                  ha="right" if len(max(short, key=len)) > 8 else "center")
    ax.set_yticks(range(n), ranks.index, fontsize=8.5)
    ax.tick_params(length=0, colors=S.THEME["ink2"])
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("Feature rank by mean |SHAP| (1 = most important)", loc="left", fontsize=9,
                 color=S.THEME["ink"])

    ax2 = figure.add_subplot(gs[0, 1])
    ax2.imshow(rho.to_numpy(), cmap=S.SEQ_CMAP, vmin=min(0.0, off_diag.min()), vmax=1)
    for i in range(len(rho)):
        for j in range(len(rho)):
            ax2.text(j, i, f"{rho.iat[i, j]:.2f}", ha="center", va="center", fontsize=8, color=S.THEME["ink"])
    idx = [str(k + 1) for k in range(len(rho))] if short_labels else [c.replace("seed ", "") for c in rho.columns]
    ax2.set_xticks(range(len(rho)), idx, fontsize=8)
    ax2.set_yticks(range(len(rho)), idx, fontsize=8)
    ax2.tick_params(length=0, colors=S.THEME["ink2"])
    for s in ax2.spines.values():
        s.set_visible(False)
    ax2.set_title(f"Spearman ρ between {what}", loc="left", fontsize=9, color=S.THEME["ink"])
    if short_labels:
        ax2.set_xlabel("  ".join(f"{k + 1}={c}" for k, c in enumerate(short)), fontsize=7,
                       color=S.THEME["muted"], wrap=True)

    top3 = {tuple(ranks[c].sort_values().index[:3]) for c in ranks.columns}
    S.title(figure, ax, title,
            f"{imp.shape[1]} {what}, same sample of the loaded file. Lowest Spearman ρ between {what}: "
            f"{off_diag.min():.3f}. Top-3 features {'identical' if len(top3) == 1 else 'differ'} across {what}.")


@register
class SeedStability(ChartPlugin):
    name = "Seed stability"
    scope = "global"
    order = 60

    def _table(self, ctx):
        key = ("seed_stability", ctx.sample_size, ctx.seed, ctx.model_name)
        return ctx.cache.memo(key, lambda: mean_abs_shap_by_seed(ctx))

    def prepare(self, ctx):
        if ctx.models_dir is not None:
            self._table(ctx)

    def render(self, figure, ctx):
        S.style_figure(figure)
        setup = setup_of(ctx.model_meta, ctx.model_name)
        imp = self._table(ctx) if ctx.models_dir is not None else pd.DataFrame()
        if imp.shape[1] < 2:
            return message(figure, f"Only {imp.shape[1]} model found for setup '{setup}'.\n\n"
                                   "Train seed variants of this setup to check explanation stability,\n"
                                   "e.g. train_model.py --mode all_tools --seeds 0 1 2 3 4")
        draw_rank_comparison(figure, imp, f"Is the explanation stable across random seeds? ({setup})", "seeds")
