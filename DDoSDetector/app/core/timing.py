"""Measured timings (time.perf_counter), shown in the status bar / About and logged."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


class Stopwatch:
    """with Stopwatch() as sw: ...   then sw.seconds holds the measured duration."""

    def __init__(self):
        self.start = self.seconds = 0.0

    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.seconds = time.perf_counter() - self.start
        return False


@dataclass
class RunTimings:
    """Timings for the most recent load / score / SHAP runs (None = not measured yet)."""
    load_s: float | None = None          # read + clean the CSV
    load_rows: int = 0
    score_s: float | None = None         # model scoring
    score_rows: int = 0
    shap: dict = field(default_factory=dict)   # label -> (seconds, n explanations)

    def record_shap(self, label: str, seconds: float, n: int):
        self.shap[label] = (seconds, n)
        log.info("timing: SHAP %s: %d explanation(s) in %.3f s (%.3f ms each)",
                 label, n, seconds, 1000 * seconds / max(n, 1))

    def lines(self) -> list[str]:
        out = []
        if self.load_s is not None:
            out.append(f"Load + clean: {self.load_s:.2f} s for {self.load_rows:,} rows")
        if self.score_s is not None:
            rate = self.score_rows / self.score_s if self.score_s > 0 else float("inf")
            out.append(f"Scoring: {self.score_rows:,} flows in {self.score_s:.2f} s ({rate:,.0f} flows/s)")
        for label, (s, n) in self.shap.items():
            out.append(f"SHAP ({label}): {n:,} in {s:.2f} s ({1000 * s / max(n, 1):.3f} ms per explanation)")
        return out

    def short(self) -> str:
        parts = []
        if self.load_s is not None:
            parts.append(f"load {self.load_s:.1f} s")
        if self.score_s is not None and self.score_s > 0:
            parts.append(f"score {self.score_rows / self.score_s:,.0f} flows/s")
        if self.shap:
            label, (s, n) = list(self.shap.items())[-1]
            parts.append(f"SHAP {1000 * s / max(n, 1):.2f} ms/flow")
        return " · ".join(parts)
