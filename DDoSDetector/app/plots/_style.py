"""Shared chart colours and axis styling (one place to change the look of every chart).

Colours: a validated categorical palette in fixed order, and a blue<->red diverging pair
with a grey midpoint (blue = pushes towards Benign, red = pushes towards DDoS).
"""
from matplotlib.colors import LinearSegmentedColormap

LIGHT = dict(surface="#fcfcfb", ink="#0b0b0b", ink2="#52514e", muted="#898781",
             grid="#e1e0d9", axis="#c3c2b7")
DARK = dict(surface="#1a1a19", ink="#f0efec", ink2="#c3c2b7", muted="#898781",
            grid="#2c2c2a", axis="#383835")
THEME = dict(LIGHT)

TO_DDOS = "#e34948"     # SHAP > 0: pushes the score towards DDoS
TO_BENIGN = "#2a78d6"   # SHAP < 0: pushes the score towards Benign
SERIES = "#2a78d6"

# Fixed tool -> colour (colour follows the entity, never its rank).
TOOL_COLORS = {"Benign": "#898781", "HOIC": "#2a78d6", "LOIC-HTTP": "#eb6834", "LOIC-UDP": "#1baf7a"}

FEATURE_CMAP = LinearSegmentedColormap.from_list("low_high", ["#2a78d6", "#d6d5cf", "#e34948"])
SEQ_CMAP = LinearSegmentedColormap.from_list("seq_blue", ["#f4f8fd", "#86b6ef", "#2a78d6"])
WARN = "#b85c00"        # warning text (always paired with a ⚠ symbol and words)


def fmt_rate(v) -> str:
    """Rates like FPR: 4 decimals, or scientific when tiny so 7 in 360,833 doesn't print as 0.0000."""
    if v is None:
        return "n/a"
    return f"{v:.4f}" if v == 0 or v >= 0.001 else f"{v:.1e}"


def set_dark(dark: bool) -> None:
    THEME.clear()
    THEME.update(DARK if dark else LIGHT)


def style_figure(figure) -> None:
    figure.set_facecolor(THEME["surface"])


def style_axes(ax, grid_axis="x") -> None:
    ax.set_facecolor(THEME["surface"])
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(THEME["axis"])
    ax.tick_params(colors=THEME["ink2"], labelsize=9, length=0)
    ax.xaxis.label.set_color(THEME["ink2"])
    ax.yaxis.label.set_color(THEME["ink2"])
    ax.title.set_color(THEME["ink"])
    if grid_axis:
        ax.grid(axis=grid_axis, color=THEME["grid"], linewidth=0.8)
        ax.set_axisbelow(True)


def title(figure, ax, text: str, sub: str = "") -> None:
    """Bold chart title and a wrapped explanatory subtitle at the top of the figure."""
    figure.suptitle(text, x=0.015, y=0.985, ha="left", va="top", fontsize=12, fontweight="bold",
                    color=THEME["ink"])
    if sub:
        figure.text(0.015, 0.925, sub, ha="left", va="top", fontsize=9, color=THEME["ink2"], wrap=True)


def finish(figure, top: float = 0.84, bottom: float = 0.0) -> None:
    """Lay out the axes below the title block (tight_layout ignores figure texts)."""
    figure.tight_layout(rect=(0, bottom, 1, top))
