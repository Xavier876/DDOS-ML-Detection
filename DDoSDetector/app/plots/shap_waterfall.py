"""Per-flow SHAP waterfall: how each feature moves this flow's score from the base value.

Drawn natively with matplotlib (not shap.plots.waterfall) so it renders into the
widget's own Figure and can label the model's own units (log-odds for XGBoost, the model score for
Random Forest, the SVM decision value for the linear SVM) and the model score side by side.
"""
import numpy as np

from app.core.features import column_label
from app.core.numbers import readable

from . import _style as S
from .base import ChartPlugin, message, register


@register
class ShapWaterfall(ChartPlugin):
    name = "Flow explanation (waterfall)"
    scope = "row"
    order = 10

    def render(self, figure, ctx):
        S.style_figure(figure)
        if ctx.selected is None:
            return message(figure, "Select a flow in the table to explain it.")
        r = ctx.row_shap()
        if r is None:
            return message(figure, "This flow was not scored (NaN or infinite input values),\n"
                                   "so it has no explanation.")
        vals, x = r.values[0], r.data.iloc[0]
        names = list(r.data.columns)
        order = np.argsort(np.abs(vals))          # largest contribution at the top
        base = r.base_value
        fx = base + vals.sum()

        ax = figure.add_subplot()
        S.style_axes(ax, grid_axis="x")
        # Walk from the base value (top) down to f(x) (bottom), largest contribution first.
        cum, starts = base, {}
        for i in order[::-1]:
            starts[i] = cum
            cum += vals[i]
        for y, i in enumerate(order):
            v, s = vals[i], starts[i]
            ax.barh(y, v, left=s, height=0.6, color=S.TO_DDOS if v > 0 else S.TO_BENIGN)
            # label just outside the bar end, in points so it never overlaps the bar
            ax.annotate(f"{v:+.3f}", xy=(s + v, y), xytext=(4 if v >= 0 else -4, 0),
                        textcoords="offset points", va="center", ha="left" if v >= 0 else "right",
                        fontsize=8, color=S.THEME["ink2"])
            if y < len(order) - 1:   # connector to the next bar up
                ax.plot([s, s], [y + 0.3, y + 0.7], color=S.THEME["axis"], linewidth=0.8)
        ax.set_yticks(range(len(order)))
        ax.set_yticklabels([f"{column_label(names[i])} = "
                            + readable(x.iloc[i]) for i in order],
                           fontsize=8 if len(order) > 10 else 8.5)
        ax.axvline(base, color=S.THEME["muted"], linewidth=1, linestyle=":")
        ax.axvline(fx, color=S.THEME["ink"], linewidth=1.2)
        top = len(order) - 0.4
        ax.text(base, top, " base", va="bottom", ha="left", fontsize=8, color=S.THEME["muted"])
        ax.text(fx, top, " f(x)", va="bottom", ha="left", fontsize=8, color=S.THEME["ink"])
        lo = min([base, fx] + [starts[i] + min(vals[i], 0) for i in order])
        hi = max([base, fx] + [starts[i] + max(vals[i], 0) for i in order])
        pad = 0.18 * (hi - lo or 1)
        ax.set_xlim(lo - pad, hi + pad)
        ax.set_ylim(-0.6, len(order) - 0.1)
        unit = ctx.unit
        ax.set_xlabel(f"model output: {unit} (SHAP units)")

        row_no = f"Row {ctx.row_numbers[ctx.selected]}. " if ctx.row_numbers is not None else ""
        flag = "DDoS" if ctx.scores[ctx.selected] >= ctx.threshold else "Benign"
        score, base_score = float(ctx.score_of(fx)), float(ctx.score_of(base))
        if unit == "model score":   # Random Forest: SHAP values add up to the score itself
            how = f"Base value {base:.3f} + sum of SHAP values {vals.sum():+.3f} = model score {fx:.4f}."
        else:
            how = (f"Base value {base:.3f} {unit} (score {base_score:.3f}) + sum of SHAP values "
                   f"{vals.sum():+.3f} = f(x) {fx:.3f} {unit}; model score = sigmoid(f(x)) = {score:.4f}.")
        S.title(figure, ax,
                f"Why this flow scored {score:.4f}: {flag} at threshold {ctx.threshold:.2f}",
                f"{row_no}{how} Red pushes towards DDoS, blue towards Benign.")
        S.finish(figure, top=0.82)
