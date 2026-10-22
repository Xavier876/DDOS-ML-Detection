"""Feature-set comparison from notebook section 9c (feature_set_comparison.csv).

For each held-out experiment: recall (with the min-max spread across seeds), false alarms and
PR-AUC for every feature set (the base nine columns, each added group alone, all fifteen).
This chart REPORTS the notebook's numbers; it does not recommend a feature set.
"""
from pathlib import Path

import numpy as np
import pandas as pd

from . import _style as S
from .base import ChartPlugin, message, register

FILE_KIND = "feature_set_comparison"
FILE_NAME = "feature_set_comparison.csv"
CAPTION = "Differences smaller than the spread between seeds are noise. Seed changes the benign sample only."
NEEDED = ["held_out", "benign_mode", "seed", "feature_set", "recall", "false_alarms", "pr_auc"]
HOW_TO = ("No feature-set comparison results found.\n\n"
          "Run notebook section 9c (notebooks/ddos_xgboost_starter_v2.ipynb). It writes\n"
          f"{FILE_NAME} into DDoSDetector\\models, which this chart reads,\n"
          "or open the file with File → Open comparison results…")


def comparison_path(ctx) -> Path | None:
    p = ctx.files.get(FILE_KIND)
    if p:
        return Path(p)
    if ctx.models_dir is not None and (Path(ctx.models_dir) / FILE_NAME).is_file():
        return Path(ctx.models_dir) / FILE_NAME
    return None


def summarise(df: pd.DataFrame) -> pd.DataFrame:
    """Mean over seeds per (experiment, feature set), with recall min/max, in the file's order."""
    missing = [c for c in NEEDED if c not in df.columns]
    if missing:
        raise ValueError("feature_set_comparison.csv is missing column(s): " + ", ".join(missing))
    g = df.groupby(["held_out", "benign_mode", "feature_set"], sort=False)
    return g.agg(recall=("recall", "mean"), recall_min=("recall", "min"), recall_max=("recall", "max"),
                 false_alarms=("false_alarms", "mean"), pr_auc=("pr_auc", "mean"),
                 seeds=("seed", "nunique")).reset_index()


@register
class FeatureSetComparison(ChartPlugin):
    name = "Feature-set comparison"
    scope = "global"
    needs_shap = False
    order = 70

    def render(self, figure, ctx):
        S.style_figure(figure)
        path = comparison_path(ctx)
        if path is None:
            return message(figure, HOW_TO)
        s = summarise(pd.read_csv(path))
        experiments = list(dict.fromkeys(zip(s["held_out"], s["benign_mode"])))
        n = len(experiments)
        gs = figure.add_gridspec(n, 3, width_ratios=[1.3, 1, 1], left=0.2, right=0.97, top=0.83,
                                 bottom=0.07, hspace=0.85, wspace=0.12)
        for i, (held, mode) in enumerate(experiments):
            e = s[(s["held_out"] == held) & (s["benign_mode"] == mode)]
            y = np.arange(len(e))[::-1]
            for j, (col, label, fmt) in enumerate([("recall", "recall on the held-out tool", "{:.3f}"),
                                                    ("false_alarms", "false alarms (mean)", "{:,.0f}"),
                                                    ("pr_auc", "PR-AUC", "{:.3f}")]):
                ax = figure.add_subplot(gs[i, j])
                S.style_axes(ax, grid_axis="x")
                vals = e[col].to_numpy(dtype=float)
                if col == "recall":
                    err = np.vstack([vals - e["recall_min"].to_numpy(), e["recall_max"].to_numpy() - vals])
                    ax.barh(y, vals, height=0.6, color=S.SERIES, xerr=err,
                            error_kw={"ecolor": S.THEME["ink"], "capsize": 3, "linewidth": 1})
                    ax.set_xlim(0, max(1.0, float(e["recall_max"].max()) * 1.1))
                else:
                    ax.barh(y, vals, height=0.6, color=S.THEME["muted"])
                    ax.set_xlim(0, max(float(np.nanmax(vals)) * 1.25, 1e-9))
                ends = e["recall_max"].to_numpy(dtype=float) if col == "recall" else vals
                for yy, v, end in zip(y, vals, ends):
                    ax.text(end, yy, "  " + fmt.format(v), va="center", fontsize=7, color=S.THEME["ink2"])
                ax.set_yticks(y, e["feature_set"].tolist() if j == 0 else [""] * len(e), fontsize=7.5)
                ax.tick_params(axis="x", labelsize=7)
                ax.set_xlabel(label, fontsize=7.5)
                if j == 0:
                    ax.text(-0.02, 1.06, f"{held} held out, {mode.replace('_', '-')} benign split "
                            f"({int(e['seeds'].max())} seed(s))", transform=ax.transAxes, fontsize=8.5,
                            fontweight="bold", color=S.THEME["ink"], ha="left")
        S.title(figure, figure.axes[0], "Feature-set comparison (notebook section 9c)",
                f"{CAPTION} Error bars on recall = min to max across seeds. Source: {path.name}.")
