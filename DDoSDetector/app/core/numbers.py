"""Readable numbers for the table, the waterfall and the Features panel (no scientific notation).

Flow timings are in microseconds and run to tens of millions, while ratios such as iat_cv can be
millionths, so one fixed format does not fit both.
"""
from __future__ import annotations

import math


def readable(v, missing: str = "missing") -> str:
    """58,800,000 / 9,488 / 0.933824 / 0.0000016 / 0 instead of 5.88e+07 or 1.6e-06."""
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return missing
    v = float(v)
    if math.isinf(v):
        return "infinite" if v > 0 else "-infinite"
    a = abs(v)
    if v == int(v) and a < 1e15:
        return f"{v:,.0f}"
    if a >= 1000:
        return f"{v:,.0f}"
    if a >= 1:
        return _trim(f"{v:.3f}")
    # small: keep two significant digits after the leading zeros
    decimals = max(4, -math.floor(math.log10(a)) + 1)
    return _trim(f"{v:.{decimals}f}")


def _trim(s: str) -> str:
    return s.rstrip("0").rstrip(".") if "." in s else s
