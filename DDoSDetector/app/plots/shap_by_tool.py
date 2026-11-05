"""Mean |SHAP| per feature, grouped by the ACTUAL tool (needs a Label column).

Key chart for the report: shows whether different DDoS tools are detected through
different features. The sample is stratified by tool so small tools (LOIC-UDP) appear.
"""
import numpy as np

from app.core.features import TOOLS

from . import _style as S
from .base import BY_GROUP, VIEW_OPTION, ChartPlugin, register, shap_view


@register
class ShapByTool(ChartPlugin):
    name = "SHAP by tool"
    needs_label = True
    scope = "global"
    order = 40
    options = {"view": VIEW_OPTION}

    def _rows(self, ctx):
        """Positions for a sample of up to sample_size/4 scored flows per tool."""
        rng = np.random.default_rng(ctx.seed)
        scored = ctx.scored_rows
        per_tool = max(ctx.sample_size // len(TOOLS), 1)
        out = []
        for t in TOOLS:
            rows = scored[ctx.tools[scored] == t]
            if len(rows) > per_tool:
                rows = rng.choice(rows, per_tool, replace=False)
            out.append(np.sort(rows))
        return out

    def prepare(self, ctx):
        return [(t, ctx.cache.explain_rows(rows, key=("by_tool", t, ctx.sample_size, ctx.seed)))
                for t, rows in zip(TOOLS, self._rows(ctx)) if len(rows)]

    def render(self, figure, ctx):
        S.style_figure(figure)
        groups = self.prepare(ctx)   # cached after the worker's first call
        view = self.option(ctx, "view")
        views = [shap_view(r.values, r.data, view) for _, r in groups]
        names = views[0][1]
        imp = np.array([np.abs(v).mean(axis=0) for v, _, _ in views])  # (tools, features or groups)
        order = np.argsort(imp.max(axis=0))
        ax = figure.add_subplot()
        S.style_axes(ax, grid_axis="x")
        k = len(groups)
        h = 0.8 / k
        for g, (t, r) in enumerate(groups):
            y = np.arange(len(names)) + 0.4 - h * (g + 0.5)   # first tool on top, as in the legend
            ax.barh(y, imp[g, order], height=h * 0.85, color=S.TOOL_COLORS.get(t, S.SERIES),
                    label=f"{t} (n={len(r.rows):,})")
        ax.set_yticks(range(len(names)))
        ax.set_yticklabels(np.array(names)[order], fontsize=8)
        ax.set_xlabel(f"mean |SHAP value| ({ctx.unit})")
        ax.legend(loc="lower right", fontsize=8, frameon=False, labelcolor=S.THEME["ink2"])
        per = "feature group" if int(view) == BY_GROUP else "column"
        S.title(figure, ax, "Do different tools rely on different features?",
                f"Mean |SHAP| per {per}, grouped by the actual tool from the Label column "
                "(sample stratified by tool).")
        S.finish(figure)
