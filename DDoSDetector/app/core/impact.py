"""Operational impact at a threshold: confusion matrix, rates, and a prevalence illustration.

Only rows that were scored AND have a known label (Benign or a DDoS tool) are counted.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import numpy as np

from .features import ATTACK_TOOLS

SMALL_TOOL_N = 1000   # below this, a per-tool recall is flagged as noisy


@dataclass
class Confusion:
    tp: int
    fp: int
    tn: int
    fn: int
    excluded: int = 0   # unscored rows or unknown labels

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.tn + self.fn


def _div(a: float, b: float) -> Optional[float]:
    return a / b if b else None


def label_vector(tools: np.ndarray) -> np.ndarray:
    """1 = DDoS tool, 0 = Benign, -1 = unknown label."""
    y = np.full(len(tools), -1, dtype=np.int8)
    y[tools == "Benign"] = 0
    y[np.isin(tools, ATTACK_TOOLS)] = 1
    return y


def confusion(scores: np.ndarray, y: np.ndarray, threshold: float) -> Confusion:
    ok = ~np.isnan(scores) & (y >= 0)
    pred = scores[ok] >= threshold
    t = y[ok] == 1
    return Confusion(tp=int((pred & t).sum()), fp=int((pred & ~t).sum()),
                     tn=int((~pred & ~t).sum()), fn=int((~pred & t).sum()),
                     excluded=int((~ok).sum()))


def rates(c: Confusion) -> dict:
    recall = _div(c.tp, c.tp + c.fn)
    precision = _div(c.tp, c.tp + c.fp)
    f1 = _div(2 * precision * recall, precision + recall) if recall is not None and precision is not None else None
    return {"recall": recall, "precision": precision, "f1": f1,
            "fpr": _div(c.fp, c.fp + c.tn), "accuracy": _div(c.tp + c.tn, c.n)}


def per_tool_recall(scores: np.ndarray, tools: np.ndarray, threshold: float) -> list[dict]:
    out = []
    scored = ~np.isnan(scores)
    for t in ATTACK_TOOLS:
        m = scored & (tools == t)
        n = int(m.sum())
        if n:
            hit = int((scores[m] >= threshold).sum())
            out.append({"tool": t, "n": n, "detected": hit, "recall": hit / n, "small": n < SMALL_TOOL_N})
    return out


def expected_precision(recall: float, fpr: float, prevalence: float) -> Optional[float]:
    """precision = recall*p / (recall*p + FPR*(1-p))  -- an illustration, not a measurement."""
    return _div(recall * prevalence, recall * prevalence + fpr * (1 - prevalence))


def false_alarms_per_million(fpr: float, prevalence: float) -> float:
    """Expected benign flows flagged per 1,000,000 flows at this prevalence."""
    return fpr * (1 - prevalence) * 1_000_000


# --- threshold sweep -------------------------------------------------------------------
SWEEP_TABLE = (0.5, 0.2, 0.1, 0.05, 0.01)


def _share_at_or_above(sorted_scores: np.ndarray, thresholds: np.ndarray) -> np.ndarray:
    """Fraction of `sorted_scores` >= each threshold (vectorised)."""
    if len(sorted_scores) == 0:
        return np.full(len(thresholds), np.nan)
    below = np.searchsorted(sorted_scores, thresholds, side="left")
    return (len(sorted_scores) - below) / len(sorted_scores)


def threshold_sweep(scores: np.ndarray, tools: np.ndarray, thresholds) -> dict:
    """Recall per attack tool, recall over all attacks, and FPR at each threshold.
    Only scored rows with a known label are used."""
    t = np.asarray(thresholds, dtype=float)
    ok = ~np.isnan(scores)
    out = {"thresholds": t, "recall": {}, "n": {}}
    for tool in ATTACK_TOOLS:
        s = np.sort(scores[ok & (tools == tool)])
        if len(s):
            out["recall"][tool] = _share_at_or_above(s, t)
            out["n"][tool] = len(s)
    att = np.sort(scores[ok & np.isin(tools, ATTACK_TOOLS)])
    ben = np.sort(scores[ok & (tools == "Benign")])
    out["recall_all"] = _share_at_or_above(att, t)
    out["fpr"] = _share_at_or_above(ben, t)
    out["n_attack"], out["n_benign"] = len(att), len(ben)
    return out


def ranking_metrics(scores: np.ndarray, tools: np.ndarray) -> Optional[dict]:
    """PR curve, PR-AUC (average precision), ROC-AUC and base rate; None without both classes."""
    from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score
    y = label_vector(tools)
    ok = ~np.isnan(scores) & (y >= 0)
    y, s = y[ok], scores[ok]
    if len(np.unique(y)) < 2:
        return None
    precision, recall, _ = precision_recall_curve(y, s)
    return {"precision": precision, "recall": recall, "pr_auc": float(average_precision_score(y, s)),
            "roc_auc": float(roc_auc_score(y, s)), "base_rate": float(y.mean())}


# --- flash-crowd proxy -----------------------------------------------------------------
def high_rate_fpr(scores: np.ndarray, tools: np.ndarray, values: np.ndarray, threshold: float,
                  percentile: float) -> Optional[dict]:
    """False positive rate on all benign flows vs benign flows whose `values` (e.g. Flow Pkts/s)
    are at or above the given percentile of benign flows. A proxy for flash crowds."""
    ben = ~np.isnan(scores) & (tools == "Benign") & ~np.isnan(values)
    if not ben.any():
        return None
    cutoff = float(np.percentile(values[ben], percentile))
    high = ben & (values >= cutoff)
    flagged = scores >= threshold

    def part(mask):
        n = int(mask.sum())
        fp = int((flagged & mask).sum())
        return {"n": n, "false_positives": fp, "fpr": fp / n if n else None}

    return {"cutoff": cutoff, "percentile": percentile, "all": part(ben), "high": part(high)}
