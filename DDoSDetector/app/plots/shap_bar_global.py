"""Global importance: mean |SHAP| per column (or per feature group) over a random sample of loaded flows."""
import numpy as np

from . import _style as S
from .base import BY_GROUP, VIEW_OPTION, ChartPlugin, register, shap_view


@register
class ShapBarGlobal(ChartPlugin):
    name = "Global importance (bar)"
    scope = "global"
    order = 20
    options = {"view": VIEW_OPTION}

    def render(self, figure, ctx):
        S.style_figure(figure)
        r = ctx.sample_shap()
        view = self.option(ctx, "view")
        values, labels, _ = shap_view(r.values, r.data, view)
        imp = np.abs(values).mean(axis=0)
        order = np.argsort(imp)
        names = np.array(labels)[order]

        ax = figure.add_subplot()
        S.style_axes(ax, grid_axis="x")
        ax.barh(names, imp[order], height=0.6, color=S.SERIES)
        for y, v in enumerate(imp[order]):
            ax.text(v, y, f"  {v:.3f}", va="center", fontsize=8, color=S.THEME["ink2"])
        ax.tick_params(axis="y", labelsize=8.5)
        ax.set_xlabel("mean |SHAP value| (average impact on log-odds)")
        ax.margins(x=0.12)
        what = ("feature group (sum of its columns' SHAP values per flow)" if int(view) == BY_GROUP
                else "column; (F#) = Week 3 feature number")
        S.title(figure, ax, "Which features drive the model overall",
                f"Mean absolute SHAP value per {what}, over {len(r.rows):,} randomly sampled scored flows "
                f"(model: {ctx.model_title}).")
        S.finish(figure)
