"""Model types: XGBoost, Random Forest and the linear SVM side by side (the group's three models).

Recall on each tool when it was seen in training (all-tools model, random split) and when it was
held out (per-day benign split), plus the all-tools model's false positive rate. Every number comes
from the models' own metadata (their own test splits), so the chart does not depend on the loaded CSV.
Only models with the active model's feature set are compared.
"""
import numpy as np

from app.core.features import ATTACK_TOOLS, feature_set_of, summary
from app.core.model_store import held_out_results, model_columns
from app.core.models import MODEL_TYPES

from . import _style as S
from .base import ChartPlugin, message, register


def by_model_type(rows: list[dict]) -> dict:
    """{model_type: {"seen": row or None, "held": {tool: row}}} from held_out_results()."""
    out = {}
    for kind in MODEL_TYPES:
        mine = [r for r in rows if r["model_type"] == kind]
        seen = next((r for r in mine if r["held_out"] is None and r["split"] == "random"), None)
        held = {r["held_out"]: r for r in mine if r["held_out"] in ATTACK_TOOLS and r["split"] == "per_day"}
        if seen is not None or held:
            out[kind] = {"seen": seen, "held": held}
    return out


@register
class ModelTypes(ChartPlugin):
    name = "Model types"
    scope = "global"
    needs_shap = False
    order = 66

    def render(self, figure, ctx):
        S.style_figure(figure)
        fset = feature_set_of(model_columns(ctx.model_meta))
        table = by_model_type(held_out_results(ctx.models_dir, fset)) if ctx.models_dir else {}
        if len(table) < 2:
            return message(figure, f"Needs models of at least two types with the feature set {fset}.\n\n"
                                   "Train them with, for example:\ntrain_model.py --mode all_tools --model random_forest\n"
                                   "train_model.py --mode all_tools --model linear_svm\n(add --mode held_out "
                                   "--held-out HOIC LOIC-HTTP LOIC-UDP for the held-out bars)")
        kinds = list(table)
        gs = figure.add_gridspec(1, 3, width_ratios=[1.3, 1.3, 0.8], left=0.07, right=0.98, top=0.74,
                                 bottom=0.13, wspace=0.32)
        x = np.arange(len(ATTACK_TOOLS))
        w = 0.8 / len(kinds)
        panels = [("seen", "Tool seen in training (all-tools model)"), ("held", "Tool held out (per-day split)")]
        axes = []
        for col, (part, heading) in enumerate(panels):
            ax = figure.add_subplot(gs[0, col])
            S.style_axes(ax, grid_axis="y")
            for k, kind in enumerate(kinds):
                for i, tool in enumerate(ATTACK_TOOLS):
                    r = table[kind]["seen"] if part == "seen" else table[kind]["held"].get(tool)
                    v = (r or {}).get("recall", {}).get(tool)
                    if v is None:
                        continue
                    xi = x[i] - 0.4 + w * (k + 0.5)
                    ax.bar(xi, v, width=w * 0.88, color=S.MODEL_TYPE_COLORS[kind], label=MODEL_TYPES[kind])
                    ax.text(xi, v, f"{v:.3f}", ha="center", va="bottom", fontsize=7, rotation=90,
                            color=S.THEME["ink2"])
            ax.set_xticks(x, ATTACK_TOOLS, fontsize=8.5)
            ax.set_ylim(0, 1.25)
            ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
            ax.set_title(heading, loc="left", fontsize=9, color=S.THEME["ink"])
            if col == 0:
                ax.set_ylabel("recall on the tool (threshold 0.5)", fontsize=8.5)
            axes.append(ax)

        ax = figure.add_subplot(gs[0, 2])
        S.style_axes(ax, grid_axis="y")
        vmax = 0
        for k, kind in enumerate(kinds):
            seen = table[kind]["seen"]
            if seen is None or seen["fpr"] is None:
                continue
            vmax = max(vmax, seen["fpr"])
            ax.bar(k, seen["fpr"], width=0.7, color=S.MODEL_TYPE_COLORS[kind])
            ax.text(k, seen["fpr"], S.fmt_rate(seen["fpr"]), ha="center", va="bottom", fontsize=7.5,
                    color=S.THEME["ink2"])
        ax.set_xticks(range(len(kinds)), [MODEL_TYPES[k].replace(" ", "\n") for k in kinds], fontsize=8)
        ax.set_ylim(0, max(vmax * 1.3, 0.001))
        ax.set_title("False positive rate\n(all-tools model)", loc="left", fontsize=9, color=S.THEME["ink"])

        handles, labels = axes[0].get_legend_handles_labels()
        uniq = dict(zip(labels, handles))
        axes[0].legend(uniq.values(), uniq.keys(), fontsize=8, frameon=False, loc="upper left", ncol=3,
                       labelcolor=S.THEME["ink2"])
        S.title(figure, axes[0], "Do the three model types detect the same attacks?",
                f"Models with {summary(model_columns(ctx.model_meta))}; numbers from each model's own metadata "
                "(its own test split, threshold 0.5). Seen in training = optimistic upper bound (random split). "
                "Scores of different model types are on different scales, so threshold 0.5 is not the same "
                "cut-off for each. LOIC-UDP has about 1,730 flows: a stress test, not a reliable number.")
