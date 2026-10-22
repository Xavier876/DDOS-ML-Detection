"""Chart plugin interface and registry.

To add a chart, create one new module in app/plots/ containing:

    from .base import ChartPlugin, register

    @register
    class MyChart(ChartPlugin):
        name = "My chart"           # tab title
        needs_label = False         # True -> tab disabled when the CSV has no Label column
        scope = "global"            # "global" (sample of rows) or "row" (selected row)
        needs_shap = True           # False if the chart only uses scores/features
        # Optional inputs shown above the chart; values arrive in context.options[key]:
        options = {"k": Option("Some setting", default=1.0, minimum=0.0, maximum=10.0)}

        def render(self, figure, context):
            ax = figure.add_subplot()
            ...

Modules in this package are imported automatically, so nothing else needs editing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

from app.core.explain import ExplainerCache, ShapResult

_REGISTRY: list[type["ChartPlugin"]] = []


@dataclass
class Option:
    """A numeric input the chart panel shows above a chart (a spin box)."""
    label: str
    default: float
    minimum: float
    maximum: float
    decimals: int = 3
    step: float = 0.1
    suffix: str = ""


@dataclass
class ChartContext:
    model: object                       # XGBClassifier
    model_title: str
    X: pd.DataFrame                     # model inputs for every loaded row
    scores: np.ndarray                  # model score 0..1 (not calibrated), NaN = not scored
    threshold: float
    tools: Optional[np.ndarray] = None  # actual tool per row (Label present) or None
    selected: Optional[int] = None      # position of the selected row
    row_numbers: Optional[np.ndarray] = None  # original CSV row number per position
    sample_size: int = 2000
    seed: int = 0
    cache: ExplainerCache = field(default_factory=ExplainerCache)
    model_meta: dict = field(default_factory=dict)   # active model's .meta.json
    model_name: str = ""
    models_dir: Optional[Path] = None   # where other trained models live (seed stability)
    options: dict = field(default_factory=dict)      # values of every plugin's Option inputs

    @property
    def has_label(self) -> bool:
        return self.tools is not None

    @property
    def scored_rows(self) -> np.ndarray:
        return np.flatnonzero(~np.isnan(self.scores))

    # SHAP is computed lazily and cached; the chart panel calls these from a worker
    # thread (via ChartPlugin.prepare) so render() only reads cached results.
    def row_shap(self) -> Optional[ShapResult]:
        if self.selected is None or np.isnan(self.scores[self.selected]):
            return None
        return self.cache.explain_row(self.selected)

    def sample_shap(self) -> ShapResult:
        return self.cache.explain_sample(self.scored_rows, self.sample_size, self.seed)


class ChartPlugin:
    name: str = "Chart"
    needs_label: bool = False
    scope: str = "global"
    needs_shap: bool = True
    options: dict = {}      # key -> Option; shown above the chart

    def option(self, context: ChartContext, key: str) -> float:
        return float(context.options.get(self.option_key(key), self.options[key].default))

    @classmethod
    def option_key(cls, key: str) -> str:
        return f"{cls.__name__}.{key}"     # namespaced so two charts can both use e.g. "n"

    def prepare(self, context: ChartContext) -> None:
        """Heavy work (runs in a worker thread). Default: compute the SHAP values needed."""
        if not self.needs_shap:
            return
        if self.scope == "row":
            context.row_shap()
        else:
            context.sample_shap()

    def render(self, figure, context: ChartContext) -> None:  # pragma: no cover - interface
        raise NotImplementedError


def register(cls: type[ChartPlugin]) -> type[ChartPlugin]:
    if cls not in _REGISTRY:
        _REGISTRY.append(cls)
    return cls


def registry() -> list[type[ChartPlugin]]:
    """All registered chart classes, sorted by their `order` attribute (default 100)."""
    import app.plots  # noqa: F401  (triggers auto-discovery)
    return sorted(_REGISTRY, key=lambda c: getattr(c, "order", 100))


def message(figure, text: str) -> None:
    """Draw a centred message instead of a chart (e.g. 'select a row')."""
    ax = figure.add_subplot()
    ax.axis("off")
    ax.text(0.5, 0.5, text, ha="center", va="center", wrap=True, fontsize=11, color="#555555")
