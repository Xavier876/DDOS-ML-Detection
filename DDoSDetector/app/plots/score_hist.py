"""Histogram of the model score for every scored flow, with the threshold line."""
import numpy as np

from . import _style as S
from .base import ChartPlugin, register


@register
class ScoreHistogram(ChartPlugin):
    name = "Model score histogram"
    scope = "global"
    needs_shap = False
    order = 50

    def render(self, figure, ctx):
        S.style_figure(figure)
        p = ctx.scores[~np.isnan(ctx.scores)]
        ax = figure.add_subplot()
        S.style_axes(ax, grid_axis="y")
        bins = np.linspace(0, 1, 51)
        counts, _ = np.histogram(p, bins=bins)
        ax.bar(bins[:-1], counts, width=np.diff(bins) * 0.9, align="edge", color=S.SERIES)
        ax.set_yscale("log")
        ax.set_ylim(bottom=0.8)
        ax.axvline(ctx.threshold, color=S.THEME["ink"], linewidth=1.5, linestyle="--")
        n_ddos = int((p >= ctx.threshold).sum())
        ax.annotate(f"threshold {ctx.threshold:.2f}\n{n_ddos:,} flagged DDoS",
                    xy=(ctx.threshold, 1), xycoords=("data", "axes fraction"), xytext=(6, -4),
                    textcoords="offset points", va="top", fontsize=8, color=S.THEME["ink"])
        ax.set_xlim(0, 1)
        ax.set_xlabel("model score (0 to 1, not calibrated)")
        ax.set_ylabel("flows (log scale)")
        S.title(figure, ax, "Distribution of model scores",
                f"All {len(p):,} scored flows; most sit near 0 or 1, the middle holds the uncertain ones.")
        S.finish(figure)
