"""Threshold sweep on the loaded flows (needs a Label column): recall per tool and false
positive rate at every threshold, the precision-recall curve, PR-AUC and ROC-AUC."""
import numpy as np

from app.core import impact

from . import _style as S
from .base import ChartPlugin, message, register

THRESHOLDS = np.unique(np.concatenate([np.linspace(0, 1, 201), np.logspace(-4, 0, 41)]))


@register
class ThresholdSweep(ChartPlugin):
    name = "Threshold sweep"
    needs_label = True
    needs_shap = False
    scope = "global"
    order = 47

    def render(self, figure, ctx):
        S.style_figure(figure)
        sw = impact.threshold_sweep(ctx.scores, ctx.tools, THRESHOLDS)
        rk = impact.ranking_metrics(ctx.scores, ctx.tools)
        if sw["n_attack"] == 0 or sw["n_benign"] == 0 or rk is None:
            return message(figure, "The threshold sweep needs both attack and benign flows with labels.")
        gs = figure.add_gridspec(2, 2, width_ratios=[1.25, 1], left=0.09, right=0.98, top=0.84,
                                 bottom=0.08, hspace=0.35, wspace=0.28)
        t = sw["thresholds"]

        ax = figure.add_subplot(gs[0, 0])
        S.style_axes(ax, grid_axis="y")
        for tool, rec in sw["recall"].items():
            ax.plot(t, rec, color=S.TOOL_COLORS.get(tool, S.SERIES), linewidth=2,
                    label=f"{tool} (n={sw['n'][tool]:,})")
        ax.axvline(ctx.threshold, color=S.THEME["ink"], linewidth=1, linestyle="--")
        ax.set_xlim(0, 1)
        ax.set_ylim(-0.02, 1.05)
        ax.set_ylabel("recall", fontsize=8.5)
        ax.legend(fontsize=7.5, frameon=False, labelcolor=S.THEME["ink2"], loc="lower left")
        ax.set_title("Recall per tool vs threshold", loc="left", fontsize=9, color=S.THEME["ink"])

        ax2 = figure.add_subplot(gs[1, 0], sharex=ax)
        S.style_axes(ax2, grid_axis="y")
        fpr = np.where(sw["fpr"] > 0, sw["fpr"], np.nan)
        ax2.plot(t, fpr, color=S.TOOL_COLORS["Benign"], linewidth=2)
        ax2.set_yscale("log")
        ax2.axvline(ctx.threshold, color=S.THEME["ink"], linewidth=1, linestyle="--")
        ax2.set_xlabel("threshold (flag DDoS when model score ≥ threshold)", fontsize=8.5)
        ax2.set_ylabel("false positive rate (log)", fontsize=8.5)
        ax2.set_title(f"False positive rate vs threshold ({sw['n_benign']:,} benign flows)", loc="left",
                      fontsize=9, color=S.THEME["ink"])

        ax3 = figure.add_subplot(gs[0, 1])
        S.style_axes(ax3, grid_axis="both")
        ax3.plot(rk["recall"], rk["precision"], color=S.SERIES, linewidth=2)
        ax3.axhline(rk["base_rate"], color=S.THEME["muted"], linewidth=1, linestyle=":")
        ax3.text(0.02, rk["base_rate"], f" base rate {rk['base_rate']:.3f}", va="bottom", fontsize=7.5,
                 color=S.THEME["muted"])
        ax3.set_xlim(0, 1.02)
        ax3.set_ylim(0, 1.05)
        ax3.set_xlabel("recall", fontsize=8.5)
        ax3.set_ylabel("precision", fontsize=8.5)
        ax3.set_title(f"Precision-recall curve\nPR-AUC {rk['pr_auc']:.3f} · ROC-AUC {rk['roc_auc']:.3f}",
                      loc="left", fontsize=9, color=S.THEME["ink"])

        ax4 = figure.add_subplot(gs[1, 1])
        ax4.axis("off")
        tab = impact.threshold_sweep(ctx.scores, ctx.tools, impact.SWEEP_TABLE)
        ax4.text(0, 1, "threshold recall  FPR      false alarms", fontsize=8,
                 family="monospace", color=S.THEME["ink"], va="top", transform=ax4.transAxes)
        for k, th in enumerate(impact.SWEEP_TABLE):
            fa = int(round(tab["fpr"][k] * tab["n_benign"]))
            ax4.text(0, 0.86 - 0.12 * k,
                     f"{th:<9} {tab['recall_all'][k]:<7.4f} {S.fmt_rate(tab['fpr'][k]):<8} {fa:,}",
                     fontsize=8, family="monospace", color=S.THEME["ink2"], va="top", transform=ax4.transAxes)
        ax4.text(0, 0.18, "recall = all attack tools together", fontsize=7.5, color=S.THEME["muted"],
                 va="top", transform=ax4.transAxes)
        S.title(figure, ax, f"Threshold sweep (current threshold {ctx.threshold:.3f}, dashed)",
                "⚠ Picking a threshold on the same flows you evaluate is optimistic: choose it on separate "
                "data. Measured on the loaded file only.")
