"""Flash-crowd check (needs a Label column): are benign BUSY flows flagged more often?

A flash crowd (many real users at once) is the classic false positive for DDoS detection. The
dataset has no labelled flash crowd, so benign flows at or above a high percentile of a "busyness"
column are used as a proxy: the packet and byte rates (feature 7) and, when the file allows them,
the window counts (flows to the same destination IP, feature 1, or port, feature 12). The columns
come from the loaded file whether or not the active model uses them.
"""
import numpy as np

from app.core import impact
from app.core.features import column_label, group_by_key

from . import _style as S
from .base import ChartPlugin, Option, message, register

PROXIES = [c for key in ("rate", "dst_ip_window", "port_window") for c in group_by_key(key).output_columns]


@register
class FlashCrowd(ChartPlugin):
    name = "Flash-crowd check"
    needs_label = True
    needs_shap = False
    scope = "global"
    order = 48
    options = {"percentile": Option("High-rate = benign flows at or above percentile", default=99.0,
                                    minimum=50.0, maximum=99.99, decimals=2, step=0.5)}

    def render(self, figure, ctx):
        S.style_figure(figure)
        pct = self.option(ctx, "percentile")
        source = ctx.X_all if ctx.X_all is not None else ctx.X
        have = [f for f in PROXIES if f in source.columns]
        if not have:
            return message(figure, "The loaded file has none of the busyness columns this check uses\n"
                                   "(Flow Pkts/s, Flow Byts/s, dst_ip_flows_10s, dst_port_flows_10s).")
        res = {f: impact.high_rate_fpr(ctx.scores, ctx.tools, source[f].to_numpy(), ctx.threshold, pct) for f in have}
        res = {f: r for f, r in res.items() if r is not None}
        if not res:
            return message(figure, "No scored benign flows in the loaded file.")
        ax = figure.add_subplot()
        S.style_axes(ax, grid_axis="y")
        x = np.arange(len(res))
        w = 0.36
        vmax = 0
        for j, (key, label, color) in enumerate([("all", "All benign flows", S.TOOL_COLORS["Benign"]),
                                                 ("high", f"High-rate benign (≥ {pct:g}th percentile)", S.TO_DDOS)]):
            for i, (f, r) in enumerate(res.items()):
                part = r[key]
                v = part["fpr"] or 0.0
                vmax = max(vmax, v)
                xi = x[i] - w / 2 + j * w
                ax.bar(xi, v, width=w * 0.9, color=color, label=label if i == 0 else None)
                ax.text(xi, v, f"{S.fmt_rate(v)}\n{part['false_positives']:,} of {part['n']:,}", ha="center",
                        va="bottom", fontsize=8, color=S.THEME["ink2"])
        ax.set_xticks(x, [f"{column_label(f)}\n(cutoff {r['cutoff']:,.4g})" for f, r in res.items()], fontsize=8.5)
        ax.set_ylim(0, vmax * 1.35 if vmax > 0 else 1e-4)
        ax.set_ylabel(f"false positive rate at threshold {ctx.threshold:.3f}", fontsize=8.5)
        ax.legend(fontsize=8, frameon=False, labelcolor=S.THEME["ink2"], loc="upper left")
        all_fpr = next(iter(res.values()))["all"]["fpr"] or 0
        worst = max((r["high"]["fpr"] or 0) for r in res.values())
        ratio = f"{worst / all_fpr:.1f}× the overall rate" if all_fpr else "overall rate is 0"
        S.title(figure, ax, "Are busy benign flows mistaken for DDoS? (flash-crowd proxy)",
                f"Highest false positive rate among busy benign flows: {S.fmt_rate(worst)} ({ratio}). The dataset has "
                "no labelled flash crowd; benign flows with a high rate or at a busy destination are only a proxy for one.")
        S.finish(figure)
