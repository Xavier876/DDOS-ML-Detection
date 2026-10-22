"""Global importance: mean |SHAP| per feature over a random sample of loaded flows."""
import numpy as np

from . import _style as S
from .base import ChartPlugin, register


@register
class ShapBarGlobal(ChartPlugin):
    name = "Global importance (bar)"
    scope = "global"
    order = 20

    def render(self, figure, ctx):
        S.style_figure(figure)
        r = ctx.sample_shap()
        imp = np.abs(r.values).mean(axis=0)
        order = np.argsort(imp)
        names = np.array(r.data.columns)[order]

        ax = figure.add_subplot()
        S.style_axes(ax, grid_axis="x")
        ax.barh(names, imp[order], height=0.6, color=S.SERIES)
        for y, v in enumerate(imp[order]):
            ax.text(v, y, f"  {v:.3f}", va="center", fontsize=8, color=S.THEME["ink2"])
        ax.set_xlabel("mean |SHAP value| (average impact on log-odds)")
        ax.margins(x=0.12)
        S.title(figure, ax, "Which features drive the model overall",
                f"Mean absolute SHAP value over {len(r.rows):,} randomly sampled scored flows "
                f"(model: {ctx.model_title}).")
        S.finish(figure)
