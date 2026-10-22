"""Chunked CSV reading shared by training and the app.

Reads only the needed columns, reports progress (by bytes read) and supports cancel.
Keeps the original data-row number (1 = first row under the header) so results can be
mapped back to the source file.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

import pandas as pd

from .features import (ALL_RAW, LABEL, OPTIONAL_COLUMNS, TRACING_COLUMNS, clean_frame,
                       missing_columns, normalise_columns)

ROW_COL = "row"


class Cancelled(Exception):
    pass


class MissingColumnsError(ValueError):
    def __init__(self, path: Path, missing: list[str]):
        self.missing = missing
        super().__init__(f"{Path(path).name} is missing required column(s): " + ", ".join(missing))


def read_header(path: Path) -> list[str]:
    return pd.read_csv(path, nrows=0).columns.tolist()


def read_flows(
    path: Path,
    extra_columns: tuple[str, ...] = (),
    chunksize: int = 500_000,
    progress: Optional[Callable[[float], None]] = None,
    cancelled: Optional[Callable[[], bool]] = None,
    chunk_filter: Optional[Callable[[pd.DataFrame], pd.DataFrame]] = None,
    nrows: Optional[int] = None,
    required_for=None,
) -> pd.DataFrame:
    """Read every feature-registry raw column present (+ Label/Timestamp + extra_columns) in chunks.

    `required_for` is the list of model columns that must be buildable (default: the original
    nine); MissingColumnsError names the raw CSV columns they need but the file lacks.
    Returns a cleaned frame (see features.clean_frame) with a `row` column.
    """
    path = Path(path)
    raw_header = read_header(path)
    missing = missing_columns(raw_header, required_for)
    if missing:
        raise MissingColumnsError(path, missing)

    wanted = set(ALL_RAW) | set(OPTIONAL_COLUMNS) | set(extra_columns)
    usecols = [raw for raw, clean in zip(raw_header, normalise_columns(raw_header)) if clean in wanted]
    # Read as strings where repeated header rows might appear; clean_frame coerces numerics.
    # Tracing columns (IPs, port) are kept as text: they are never model inputs.
    as_text = {LABEL, "Timestamp", *TRACING_COLUMNS}
    dtype = {c: "string" for c in usecols if c.strip() in as_text}

    total = max(path.stat().st_size, 1)
    parts, offset = [], 0
    with open(path, "rb") as fh:
        reader = pd.read_csv(fh, usecols=usecols, chunksize=chunksize, dtype=dtype,
                             low_memory=False, nrows=nrows)
        for chunk in reader:
            if cancelled and cancelled():
                raise Cancelled()
            chunk.index = pd.RangeIndex(offset + 1, offset + 1 + len(chunk))
            offset += len(chunk)
            chunk = clean_frame(chunk)
            chunk[ROW_COL] = chunk.index.to_numpy()
            if chunk_filter is not None:
                chunk = chunk_filter(chunk)
            parts.append(chunk)
            if progress:
                progress(min(fh.tell() / total, 1.0))
    df = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=usecols + [ROW_COL])
    if progress:
        progress(1.0)
    return df
