"""Readable numbers in the table, waterfall and Features panel (no scientific notation)."""
import math

import numpy as np
import pandas as pd
from PySide6.QtCore import Qt

from app.core.numbers import readable
from app.ui.results_table import ResultsData, ResultsTableModel


def test_readable_numbers():
    assert readable(5.88e7) == "58,800,000"           # microsecond timings
    assert readable(4.00029e6) == "4,000,290"
    assert readable(9488.25) == "9,488"
    assert readable(418.145) == "418.145"
    assert readable(0.933824) == "0.9338"
    assert readable(1.64531e-06) == "0.0000016"       # tiny iat_cv values
    assert readable(0) == "0" and readable(1.0) == "1" and readable(-1.0) == "-1"
    assert readable(math.nan) == "missing" and readable(math.inf) == "infinite"
    for v in (5.88e7, 1.64531e-06, 0.000123, 7.2e4):
        assert "e" not in readable(v)


def test_table_shows_readable_values_and_exact_tooltip():
    X = pd.DataFrame({"Fwd IAT Mean": [5.88e7, np.nan], "iat_cv": [1.64531e-06, 0.5]})
    m = ResultsTableModel()
    m.set_results(ResultsData(rows=np.array([1, 2]), scores=np.array([0.2, 0.9]), X=X))
    c = m.column_of("Fwd IAT Mean")
    assert m.data(m.index(0, c)) == "58,800,000" and m.data(m.index(1, c)) == "missing"
    assert m.data(m.index(0, m.column_of("iat_cv"))) == "0.0000016"
    assert m.data(m.index(0, c), Qt.ItemDataRole.ToolTipRole) == "58800000.0"
