"""Global beeswarm: one dot per sampled flow per feature, x = SHAP value, colour = feature value.

Drawn natively (shap.plots.beeswarm draws its colour bar on pyplot's current figure,
which does not work for a figure embedded in a Qt widget).
"""
import numpy as np
import pandas as pd
from matplotlib.cm import ScalarMappable
from matplotlib.colors import Normalize

from . import _style as S
from .base import VIEW_OPTION, ChartPlugin, register, shap_view


def swarm_offsets(x: np.ndarray, nbins: int = 120, width: float = 0.38) -> np.ndarray:
    """Vertical offsets that spread dots with similar x (dense regions get wider)."""
    if len(x) == 0:
        return x
    span = np.ptp(x) or 1.0
    bins = np.floor((x - x.min()) / span * (nbins - 1)).astype(int)
    order = np.lexsort((np.random.default_rng(0).random(len(x)), bins))
    offs = np.zeros(len(x))
    counts = np.bincount(bins, minlength=nbins)
    rank = np.arange(len(x)) - np.repeat(np.cumsum(counts) - counts, counts)
    sign = np.where(rank % 2 == 0, 1, -1)
    offs[order] = sign * ((rank + 1) // 2)
    peak = max(counts.max() / 2, 1)
    return offs / peak * width


def colour_values(v: np.ndarray) -> np.ndarray:
    """0..1 colour position per value; NaN stays NaN (drawn grey).
    Two-value columns (flags, no_reply, empty_payload) use low/high directly, so identical values
    always get the same colour; other columns use the percentile rank (ties share a rank),
    because the features are heavy-tailed."""
    out = np.full(len(v), np.nan)
    ok = ~np.isnan(v)
    if not ok.any():
        return out
    uniq = np.unique(v[ok])
    if len(uniq) == 1:
        out[ok] = 0.5
    elif len(uniq) == 2:
        out[ok] = (v[ok] == uniq[1]).astype(float)
    else:
        r = pd.Series(v[ok]).rank(method="average").to_numpy()
        out[ok] = (r - r.min()) / (r.max() - r.min())
    return out


@register
class ShapBeeswarm(ChartPlugin):
    name = "Global beeswarm"
    scope = "global"
    order = 30
    options = {"view": VIEW_OPTION}

    def render(self, figure, ctx):
        S.style_figure(figure)
        r = ctx.sample_shap()
        sv, names, data = shap_view(r.values, r.data, self.option(ctx, "view"))
        X = data.to_numpy(dtype=float) if data is not None else None
        order = np.argsort(np.abs(sv).mean(axis=0))
        names = np.array(names)

        ax = figure.add_subplot()
        S.style_axes(ax, grid_axis="x")
        norm = Normalize(0, 1)
        for y, j in enumerate(order):
            offs = y + swarm_offsets(sv[:, j])
            if X is None:          # group view: a group has several columns, so no single value to colour by
                ax.scatter(sv[:, j], offs, color=S.SERIES, s=6, linewidths=0, alpha=0.6, rasterized=True)
                continue
            c = colour_values(X[:, j])
            nan = np.isnan(c)
            ax.scatter(sv[~nan, j], offs[~nan], c=c[~nan], cmap=S.FEATURE_CMAP, norm=norm,
                       s=6, linewidths=0, alpha=0.85, rasterized=True)
            if nan.any():
                ax.scatter(sv[nan, j], offs[nan], color=S.THEME["muted"], s=6, linewidths=0, alpha=0.6,
                           rasterized=True)
        ax.axvline(0, color=S.THEME["axis"], linewidth=1)
        ax.set_yticks(range(len(order)))
        ax.set_yticklabels(names[order], fontsize=8)
        ax.set_xlabel(f"SHAP value (impact on the {ctx.unit}; > 0 pushes towards DDoS)")
        if X is not None:
            cb = figure.colorbar(ScalarMappable(norm=norm, cmap=S.FEATURE_CMAP), ax=ax, pad=0.01,
                                 aspect=40, ticks=[0, 1])
            cb.ax.set_yticklabels(["low", "high"], fontsize=8, color=S.THEME["ink2"])
            cb.set_label("feature value (percentile in sample; 0/1 columns: 0 / 1)", fontsize=8,
                         color=S.THEME["ink2"])
            cb.outline.set_visible(False)
            note = "colour = feature value; grey = missing value"
        else:
            note = "group view: each dot is the sum of the group's column SHAP values (no colour by value)"
        S.title(figure, ax, "How feature values push individual flows",
                f"{len(r.rows):,} randomly sampled scored flows; each dot is one flow; {note}.")
        S.finish(figure)
