"""Virtual results table: a QAbstractTableModel over NumPy arrays.

Only visible cells are ever formatted, so 1M rows stays responsive. Sorting and filtering
work on an index array (`view`) of row positions instead of moving data around.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import pandas as pd
from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor

from app.core.features import column_label
from app.core.review import CONFIRMED, FALSE_POSITIVE, UNSURE, VERDICTS, Review
from app.core.scoring import CODE_DDOS, CODE_NOT_SCORED, FLAG_NAMES, flag_codes


@dataclass
class ResultsData:
    rows: np.ndarray                    # original 1-based data-row numbers in the source CSV
    scores: np.ndarray                  # model score 0..1 (not calibrated), NaN = not scored
    X: pd.DataFrame                     # model inputs (9 columns)
    labels: Optional[np.ndarray] = None
    tools: Optional[np.ndarray] = None
    timestamps: Optional[np.ndarray] = None
    source: str = ""
    tracing: dict = field(default_factory=dict)   # src_ip / dst_ip / dst_port -> array (never inputs)
    review: Optional[Review] = None

    def __post_init__(self):
        if self.review is None:
            self.review = Review.empty(len(self.scores))

    def __len__(self):
        return len(self.scores)


ROW, FLAG, SCORE, VERDICT, NOTE = "Row", "Flag", "Model score", "Analyst verdict", "Note"
FIXED = [ROW, FLAG, SCORE, VERDICT, NOTE]
_FLAG_BG = {CODE_DDOS: QColor(220, 60, 60, 70), CODE_NOT_SCORED: QColor(128, 128, 128, 70)}
_VERDICT_BG = {CONFIRMED: QColor(220, 60, 60, 45), FALSE_POSITIVE: QColor(42, 120, 214, 45),
               UNSURE: QColor(237, 161, 0, 50)}
_TOOLTIPS = {
    ROW: "Data-row number in the source CSV (1 = first row under the header)",
    FLAG: "Benign / DDoS at the current threshold; Not scored = invalid values",
    SCORE: "Model score from 0 to 1 (not calibrated: 0.9 is not a 90% chance of attack)",
    VERDICT: "Analyst verdict: right-click a row to set it",
    NOTE: "Analyst note: right-click a row to edit it",
}


class ResultsTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data_: Optional[ResultsData] = None
        self.codes = np.zeros(0, dtype=np.int8)
        self.view = np.zeros(0, dtype=np.int64)
        self.threshold = 0.5
        self.show_codes = {0, 1, 2}
        self.score_range = (0.0, 1.0)
        self._sort: Optional[tuple[int, Qt.SortOrder]] = None
        self._columns: list[str] = []
        self._feature_col: dict[str, int] = {}
        self._Xv = np.zeros((0, 0))

    # --- setup -------------------------------------------------------------------
    def set_results(self, data: Optional[ResultsData]):
        self.beginResetModel()
        self.data_ = data
        if data is None:
            self._columns, self.codes, self.view = [], np.zeros(0, np.int8), np.zeros(0, np.int64)
        else:
            self._columns = FIXED + list(data.X.columns)
            self._feature_col = {c: i for i, c in enumerate(data.X.columns)}
            if data.labels is not None:
                self._columns.append("Label")
            if data.timestamps is not None:
                self._columns.append("Timestamp")
            self._Xv = data.X.to_numpy(dtype="float64")
            self.codes = flag_codes(data.scores, self.threshold)
            self._sort = None
            self.view = self._filtered()
        self.endResetModel()

    @property
    def columns(self) -> list[str]:
        return self._columns

    def column_of(self, name: str) -> int:
        return self._columns.index(name)

    # --- threshold / filter / sort ---------------------------------------------------
    def set_threshold(self, t: float):
        self.threshold = float(t)
        if self.data_ is None:
            return
        self.codes = flag_codes(self.data_.scores, self.threshold)
        if self.show_codes != {0, 1, 2}:
            self._refilter()   # the set of visible rows depends on the flags
        elif self.rowCount():
            c = self.column_of(FLAG)
            self.dataChanged.emit(self.index(0, c), self.index(self.rowCount() - 1, c))

    def set_filter(self, show_codes: set[int], score_range: tuple[float, float]):
        self.show_codes, self.score_range = set(show_codes), score_range
        self._refilter()

    def _filtered(self) -> np.ndarray:
        d = self.data_
        keep = np.isin(self.codes, list(self.show_codes))
        lo, hi = self.score_range
        if (lo, hi) != (0.0, 1.0):
            s = d.scores
            keep &= ((s >= lo) & (s <= hi)) | np.isnan(s)   # unscored rows follow the flag filter
        return self._sorted(np.flatnonzero(keep))

    def _refilter(self):
        if self.data_ is None:
            return
        self.beginResetModel()
        self.view = self._filtered()
        self.endResetModel()

    def _sort_key(self, col: int) -> np.ndarray:
        d, name = self.data_, self._columns[col]
        if name == ROW:
            return d.rows
        if name == FLAG:
            return self.codes
        if name == SCORE:
            return d.scores
        if name == VERDICT:
            return d.review.verdicts
        if name == NOTE:
            return np.array([0 if i in d.review.notes else 1 for i in range(len(d))])
        if name == "Label":
            return pd.factorize(d.labels, sort=True)[0]
        if name == "Timestamp":
            return pd.factorize(d.timestamps, sort=True)[0]
        return self._Xv[:, self._feature_col[name]]

    def _sorted(self, view: np.ndarray) -> np.ndarray:
        if self._sort is None:
            return view
        col, order = self._sort
        key = self._sort_key(col)[view]
        idx = np.argsort(key, kind="stable")       # NaN sorts last
        if order == Qt.SortOrder.DescendingOrder:
            nan = np.isnan(key[idx]) if key.dtype.kind == "f" else np.zeros(len(idx), bool)
            idx = np.concatenate([idx[~nan][::-1], idx[nan]])
        return view[idx]

    def sort(self, column: int, order=Qt.SortOrder.AscendingOrder):
        if self.data_ is None or column < 0:
            return
        self.layoutAboutToBeChanged.emit()
        old_view = self.view
        self._sort = (column, order)
        self.view = self._sorted(np.sort(self.view))
        # Keep the selection on the same flows after reordering.
        inv = np.empty(len(self.data_), dtype=np.int64)
        inv[self.view] = np.arange(len(self.view))
        old = self.persistentIndexList()
        new = [self.index(int(inv[old_view[i.row()]]), i.column()) for i in old]
        self.changePersistentIndexList(old, new)
        self.layoutChanged.emit()

    def position(self, view_row: int) -> int:
        """Row position in the loaded data for a row of the (sorted/filtered) view."""
        return int(self.view[view_row])

    def view_row_of(self, position: int) -> int:
        hits = np.flatnonzero(self.view == position)
        return int(hits[0]) if len(hits) else -1

    # --- analyst verdicts ------------------------------------------------------------
    def set_review(self, pos: int, verdict: int | None = None, note: str | None = None):
        self.data_.review.set(pos, verdict, note)
        r = self.view_row_of(pos)
        if r >= 0:
            self.dataChanged.emit(self.index(r, self.column_of(VERDICT)), self.index(r, self.column_of(NOTE)))

    def review_reloaded(self):
        if self.rowCount():
            self.dataChanged.emit(self.index(0, self.column_of(VERDICT)),
                                  self.index(self.rowCount() - 1, self.column_of(NOTE)))

    # --- Qt model API ------------------------------------------------------------------
    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.view)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._columns)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or self.data_ is None:
            return None
        pos = int(self.view[index.row()])
        name = self._columns[index.column()]
        d = self.data_
        if role == Qt.ItemDataRole.DisplayRole:
            if name == ROW:
                return str(d.rows[pos])
            if name == FLAG:
                return FLAG_NAMES[self.codes[pos]]
            if name == SCORE:
                s = d.scores[pos]
                return "" if np.isnan(s) else f"{s:.4f}"
            if name == VERDICT:
                return VERDICTS[int(d.review.verdicts[pos])]
            if name == NOTE:
                return d.review.notes.get(pos, "")
            if name == "Label":
                return str(d.labels[pos])
            if name == "Timestamp":
                return str(d.timestamps[pos])
            v = self._Xv[pos, self._feature_col[name]]
            return "missing" if np.isnan(v) else f"{v:.6g}"
        if role == Qt.ItemDataRole.BackgroundRole:
            if name == FLAG:
                return _FLAG_BG.get(int(self.codes[pos]))
            if name == VERDICT:
                return _VERDICT_BG.get(int(d.review.verdicts[pos]))
        if role == Qt.ItemDataRole.TextAlignmentRole and (name in self._feature_col or name in (ROW, SCORE)):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.ToolTipRole:
            if name == FLAG and self.codes[pos] == CODE_NOT_SCORED:
                return "Not scored (invalid values: NaN or infinite in a model input)"
            if name == NOTE and pos in d.review.notes:
                return d.review.notes[pos]
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation != Qt.Orientation.Horizontal or section >= len(self._columns):
            return None
        name = self._columns[section]
        if role == Qt.ItemDataRole.DisplayRole:
            return column_label(name) if name in self._feature_col else name
        if role == Qt.ItemDataRole.ToolTipRole:
            return _TOOLTIPS.get(name, "Model input feature" if name in self._feature_col else None)
        return None

    # --- export ------------------------------------------------------------------------
    def export_frame(self) -> pd.DataFrame:
        d = self.data_
        out = pd.DataFrame({"row": d.rows, "flag": FLAG_NAMES[self.codes], "model_score": d.scores,
                            "analyst_verdict": np.array(VERDICTS)[d.review.verdicts],
                            "analyst_note": [d.review.notes.get(i, "") for i in range(len(d))]})
        for c in d.X.columns:
            out[c] = d.X[c].to_numpy()
        if d.labels is not None:
            out["Label"] = d.labels
            out["actual_tool"] = d.tools
        if d.timestamps is not None:
            out["Timestamp"] = d.timestamps
        out["threshold"] = self.threshold
        return out
