"""Global beeswarm: one dot per sampled flow per feature, x = SHAP value, colour = feature value.

Drawn natively (shap.plots.beeswarm draws its colour bar on pyplot's current figure,
which does not work for a figure embedded in a Qt widget).
"""
import numpy as np
from matplotlib.cm import ScalarMappable
from matplotlib.colors import Normalize

from . import _style as S
from .base import ChartPlugin, register


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


@register
class ShapBeeswarm(ChartPlugin):
    name = "Global beeswarm"
    scope = "global"
    order = 30

    def render(self, figure, ctx):
        S.style_figure(figure)
        r = ctx.sample_shap()
        sv, X = r.values, r.data.to_numpy(dtype=float)
        order = np.argsort(np.abs(sv).mean(axis=0))
        names = np.array(r.data.columns)

        ax = figure.add_subplot()
        S.style_axes(ax, grid_axis="x")
        norm = Normalize(0, 1)
        for y, j in enumerate(order):
            # Colour by within-sample percentile rank: features are heavy-tailed.
            v = X[:, j]
            ranks = np.argsort(np.argsort(v, kind="stable"), kind="stable") / max(len(v) - 1, 1)
            ax.scatter(sv[:, j], y + swarm_offsets(sv[:, j]), c=ranks, cmap=S.FEATURE_CMAP, norm=norm,
                       s=6, linewidths=0, alpha=0.85, rasterized=True)
        ax.axvline(0, color=S.THEME["axis"], linewidth=1)
        ax.set_yticks(range(len(order)))
        ax.set_yticklabels(names[order], fontsize=8.5)
        ax.set_xlabel("SHAP value (impact on log-odds; > 0 pushes towards DDoS)")
        cb = figure.colorbar(ScalarMappable(norm=norm, cmap=S.FEATURE_CMAP), ax=ax, pad=0.01,
                             aspect=40, ticks=[0, 1])
        cb.ax.set_yticklabels(["low", "high"], fontsize=8, color=S.THEME["ink2"])
        cb.set_label("feature value (percentile in sample)", fontsize=8, color=S.THEME["ink2"])
        cb.outline.set_visible(False)
        S.title(figure, ax, "How feature values push individual flows",
                f"{len(r.rows):,} randomly sampled scored flows; each dot is one flow.")
        S.finish(figure)
