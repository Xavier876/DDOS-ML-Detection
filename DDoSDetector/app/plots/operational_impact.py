"""Operational impact at the current threshold (needs a Label column).

Confusion matrix, recall / precision / F1 / FPR / accuracy, per-tool recall, and an
illustration of precision and false alarms at an assumed real-world attack prevalence.
"""
import numpy as np

from app.core import impact

from . import _style as S
from .base import ChartPlugin, Option, register

TESTBED_WARNING = ("The test data come from the same testbed as the training data. These numbers are "
                   "an upper bound, not expected real-world performance.")


def _fmt(v, pct=False):
    if v is None:
        return "n/a"
    return f"{100 * v:.2f}%" if pct else f"{v:.4f}"


@register
class OperationalImpact(ChartPlugin):
    name = "Operational impact"
    needs_label = True
    needs_shap = False
    scope = "global"
    order = 45
    options = {"prevalence": Option("Assumed attack prevalence", default=0.1, minimum=0.001,
                                    maximum=50.0, decimals=3, step=0.05, suffix=" %")}

    def render(self, figure, ctx):
        S.style_figure(figure)
        ink, ink2, muted = S.THEME["ink"], S.THEME["ink2"], S.THEME["muted"]
        y = impact.label_vector(ctx.tools)
        c = impact.confusion(ctx.scores, y, ctx.threshold)
        r = impact.rates(c)
        tools = impact.per_tool_recall(ctx.scores, ctx.tools, ctx.threshold)
        p = self.option(ctx, "prevalence") / 100.0

        gs = figure.add_gridspec(2, 2, height_ratios=[1.1, 1], width_ratios=[1, 1.25],
                                 left=0.13, right=0.98, top=0.86, bottom=0.03, hspace=0.25, wspace=0.16)

        # --- confusion matrix (rows = actual, columns = predicted)
        ax = figure.add_subplot(gs[0, 0])
        cells = np.array([[c.tp, c.fn], [c.fp, c.tn]])
        names = np.array([["True positives", "False negatives"], ["False positives", "True negatives"]])
        ax.imshow(np.log10(cells + 1), cmap=S.SEQ_CMAP, vmin=0, vmax=np.log10(max(cells.max(), 1) + 1) * 1.15)
        for i in range(2):
            for j in range(2):
                ax.text(j, i - 0.12, f"{cells[i, j]:,}", ha="center", va="center", fontsize=12,
                        fontweight="bold", color=ink)
                ax.text(j, i + 0.2, names[i, j], ha="center", va="center", fontsize=8, color=ink2)
        ax.set_xticks([0, 1], ["Flagged DDoS", "Flagged Benign"], fontsize=8.5, color=ink2)
        ax.set_yticks([0, 1], ["Actual DDoS", "Actual Benign"], fontsize=8.5, color=ink2)
        ax.tick_params(length=0)
        for s in ax.spines.values():
            s.set_visible(False)
        ax.set_title("Confusion matrix (raw counts)", loc="left", fontsize=9.5, color=ink)

        # --- rates (accuracy last, with its caveat)
        ax = figure.add_subplot(gs[0, 1])
        ax.axis("off")
        lines = [("Recall (attacks caught)", _fmt(r["recall"])),
                 ("Precision (alerts that are attacks)", _fmt(r["precision"])),
                 ("F1", _fmt(r["f1"])),
                 ("False positive rate (benign flagged)", _fmt(r["fpr"])),
                 ("Accuracy", _fmt(r["accuracy"]))]
        ax.text(0, 1, "Measured on the loaded flows", fontsize=9.5, color=ink, va="top", transform=ax.transAxes)
        for k, (label, val) in enumerate(lines):
            yy = 0.86 - k * 0.12
            ax.text(0, yy, label, fontsize=9, color=ink2, va="top", transform=ax.transAxes)
            ax.text(1, yy, val, fontsize=9, color=ink, va="top", ha="right", transform=ax.transAxes)
        ax.text(0, 0.24, "Accuracy alone can mislead because most flows are benign.", fontsize=8,
                color=muted, va="top", style="italic", transform=ax.transAxes)
        ax.text(0, 0.12, f"Counted: {c.n:,} flows with a score and a known label"
                + (f" ({c.excluded:,} excluded)" if c.excluded else ""), fontsize=8, color=muted,
                va="top", transform=ax.transAxes)

        # --- per-tool recall
        ax = figure.add_subplot(gs[1, 0])
        ax.axis("off")
        ax.text(0, 1, "Recall per tool", fontsize=9.5, color=ink, va="top", transform=ax.transAxes)
        yy = 0.86
        if not tools:
            ax.text(0, yy, "No attack flows in this file.", fontsize=9, color=ink2, va="top", transform=ax.transAxes)
        for t in tools:
            ax.text(0, yy, f"{t['tool']}", fontsize=9, color=ink2, va="top", transform=ax.transAxes)
            ax.text(0.32, yy, f"{t['recall']:.4f}", fontsize=9, color=ink, va="top", transform=ax.transAxes)
            ax.text(0.52, yy, f"{t['detected']:,} / {t['n']:,} flows", fontsize=8.5, color=ink2, va="top",
                    transform=ax.transAxes)
            yy -= 0.12
            if t["tool"] == "LOIC-UDP":     # tiny in the whole dataset, so always noisy
                msg = "⚠ LOIC-UDP has only about 1,730 flows in total,\n    so this number is noisy"
            elif t["small"]:
                msg = f"⚠ fewer than {impact.SMALL_TOOL_N:,} flows,\n    so this number is noisy"
            else:
                msg = ""
            if msg:
                ax.text(0.02, yy, msg, fontsize=8, color=S.WARN, va="top", transform=ax.transAxes)
                yy -= 0.2

        # --- prevalence illustration
        ax = figure.add_subplot(gs[1, 1])
        ax.axis("off")
        ax.text(0, 1, f"Illustration at an assumed prevalence of {100 * p:.3g}% attacks",
                fontsize=9.5, color=ink, va="top", transform=ax.transAxes)
        if r["recall"] is None or r["fpr"] is None:
            ax.text(0, 0.86, "Needs both attack and benign flows in the loaded file.", fontsize=9,
                    color=ink2, va="top", transform=ax.transAxes)
        else:
            ep = impact.expected_precision(r["recall"], r["fpr"], p)
            fa = impact.false_alarms_per_million(r["fpr"], p)
            ax.text(0, 0.86, "Expected precision", fontsize=9, color=ink2, va="top", transform=ax.transAxes)
            ax.text(1, 0.86, _fmt(ep), fontsize=9, color=ink, va="top", ha="right", transform=ax.transAxes)
            ax.text(0, 0.74, "Expected false alarms per million flows", fontsize=9, color=ink2, va="top",
                    transform=ax.transAxes)
            ax.text(1, 0.74, f"{fa:,.0f}", fontsize=9, color=ink, va="top", ha="right", transform=ax.transAxes)
            ax.text(0, 0.62, "precision = recall·p / (recall·p + FPR·(1−p))\nusing the measured recall and FPR.",
                    fontsize=8, color=muted, va="top", transform=ax.transAxes)
            ax.text(0, 0.42, "An illustration, not a measurement: the dataset's\nattack share is much "
                    "higher than in real traffic.", fontsize=8, color=muted, va="top", style="italic",
                    transform=ax.transAxes)

        S.title(figure, ax, f"Operational impact at threshold {ctx.threshold:.3f}", "⚠ " + TESTBED_WARNING)
