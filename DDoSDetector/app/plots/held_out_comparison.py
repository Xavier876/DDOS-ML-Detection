"""Held-out comparison: recall on each DDoS tool when it was SEEN in training (all_tools model)
vs when it was HELD OUT (one model per tool and benign split), plus each model's false
positive rate. Built from the models' own test metrics in the .meta.json files, so it does not
depend on the loaded CSV.
"""
import numpy as np

from app.core.features import ATTACK_TOOLS, feature_set_of, summary
from app.core.model_store import held_out_results, model_columns, model_type_from
from app.core.models import MODEL_TYPES, NAME_SUFFIX

from . import _style as S
from .base import ChartPlugin, message, register

GROUPS = [("seen", "Seen in training (all tools)", "#2a78d6"),
          ("per_day", "Held out, per-day benign split", "#eb6834"),
          ("by_file", "Held out, by-file benign split", "#eda100"),
          ("attack_period", "Held out, attack-period benign split", "#1baf7a")]


def comparison_table(rows: list[dict]) -> dict:
    """{group: {tool: (recall, n, fpr, false_alarms, name)}} from held_out_results()."""
    table = {g: {} for g, _, _ in GROUPS}
    for r in rows:
        if r["held_out"] is None and r["split"] == "random":
            for t in ATTACK_TOOLS:
                if t in r["recall"]:
                    table["seen"][t] = (r["recall"][t], r["n_test"].get(t), r["fpr"], r["false_alarms"], r["name"])
        elif r["held_out"] in ATTACK_TOOLS and r["split"] in table:
            t = r["held_out"]
            table[r["split"]][t] = (r["recall"].get(t), r["n_test"].get(t), r["fpr"], r["false_alarms"], r["name"])
    return table


@register
class HeldOutComparison(ChartPlugin):
    name = "Held-out comparison"
    scope = "global"
    needs_shap = False
    order = 65

    def render(self, figure, ctx):
        S.style_figure(figure)
        fset = feature_set_of(model_columns(ctx.model_meta))
        table = comparison_table(held_out_results(ctx.models_dir, fset)) if ctx.models_dir else {}
        if not any(len(v) for k, v in table.items() if k != "seen"):
            return message(figure, f"No held-out models with the active model's feature set ({fset}) "
                                   "in the models folder.\n\nTrain them with:\ntrain_model.py --mode held_out "
                                   f"--held-out HOIC LOIC-HTTP LOIC-UDP --feature-set {fset}")
        table = {k: v for k, v in table.items() if v or k == "seen"}
        groups = [g for g in GROUPS if g[0] in table]
        gs = figure.add_gridspec(2, 1, height_ratios=[1.3, 1], left=0.09, right=0.98, top=0.8,
                                 bottom=0.08, hspace=0.45)
        x = np.arange(len(ATTACK_TOOLS))
        w = 0.8 / len(groups)
        for panel, (key, ylabel) in enumerate([(0, "recall on the tool (threshold 0.5)"),
                                               (2, "false positive rate on benign")]):
            ax = figure.add_subplot(gs[panel, 0])
            S.style_axes(ax, grid_axis="y")
            vmax = 0
            for g, (group, label, color) in enumerate(groups):
                for i, tool in enumerate(ATTACK_TOOLS):
                    cell = table[group].get(tool)
                    if cell is None or cell[key] is None:
                        continue
                    v = cell[key]
                    vmax = max(vmax, v)
                    xi = x[i] - 0.4 + w * (g + 0.5)
                    ax.bar(xi, v, width=w * 0.88, color=color, label=label)   # duplicates merged below
                    txt = f"{v:.3f}" if panel == 0 else S.fmt_rate(v)
                    ax.text(xi, v, txt, ha="center", va="bottom", fontsize=7.5, color=S.THEME["ink2"])
            ax.set_xticks(x, ATTACK_TOOLS, fontsize=8.5)
            ax.set_ylabel(ylabel, fontsize=8.5)
            if panel == 0:
                ax.set_ylim(0, 1.12)
                handles, labels = ax.get_legend_handles_labels()
                uniq = dict(zip(labels, handles))
                ax.legend(uniq.values(), uniq.keys(), fontsize=8, frameon=False, loc="lower left",
                          bbox_to_anchor=(0, 1.0), labelcolor=S.THEME["ink2"], ncol=2)
            else:
                ax.set_ylim(0, max(vmax * 1.3, 0.001))
                ax.set_title("FPR of each model on its own benign test flows (lower is better; the "
                             "all-tools bar is the same model in every group)",
                             loc="left", fontsize=8.5, color=S.THEME["ink2"])
        note = ("With the nine-column model, held-out LOIC-UDP was still caught almost entirely through "
                "fwd_bwd_ratio (~120,000 vs under 2 for HOIC and benign): one extreme feature, not general transfer."
                if fset == "f9" else
                "LOIC-UDP has only about 1,730 flows, so its bars are a stress test, not a reliable number.")
        S.title(figure, figure.axes[0], "Does the model detect a DDoS tool it never saw?",
                f"Models with {summary(model_columns(ctx.model_meta))}. Numbers from each model's own metadata (its own test split). Seen in training = optimistic upper "
                "bound (random split); tool and capture day are confounded. " + note)
