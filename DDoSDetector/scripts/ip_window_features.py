r"""IP-window features: the experiment of 5 Nov 2026 that became registry groups 16-18 (update 5).

Everything is now in app/core/features.py (groups 16 dst_ip_flows_10s, 17 src_ip_flows_10s and
18 dst_ip_src_ips_10s, set f7ip). This file only keeps the names feature_search_ip.py uses and delegates
to the registry, so the search can be re-run. Run it directly for a small self-test.
"""
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.features import DST_IP, SRC_IP, TIME, build_features  # noqa: E402

CANDIDATES = {"dst_ip_flows_10s": (DST_IP,), "src_ip_flows_10s": (SRC_IP,), "dst_ip_src_ips_10s": (DST_IP, SRC_IP)}


def build_candidates(df: pd.DataFrame, names=tuple(CANDIDATES)) -> pd.DataFrame:
    """The named window columns, built by the registry on every row of `df` (per capture file)."""
    return build_features(df, list(names))


if __name__ == "__main__":   # self-test on a hand-made frame
    stamps = ["21/02/2018 10:00:%02d" % s for s in (0, 0, 1, 5, 12, 20, 21)]
    d = pd.DataFrame({TIME: stamps, SRC_IP: ["A", "B", "A", "C", "A", "B", "B"],
                      DST_IP: ["X", "X", "X", "Y", "X", "X", "X"]})
    r = build_candidates(d)
    print(pd.concat([d, r], axis=1).to_string())
    # second 0: nothing before; second 1: 2 flows to X before (A, B); second 5: Y has none; second 12: window is
    # seconds 2..11 -> nothing; second 20: window 10..19 holds the flow at 12 (A) -> 1; second 21: window 11..20
    # holds 12 (A) and 20 (B) -> 2 flows, 2 distinct sources
    assert r["dst_ip_flows_10s"].tolist() == [0, 0, 2, 0, 0, 1, 2], r["dst_ip_flows_10s"].tolist()
    assert r["dst_ip_src_ips_10s"].tolist() == [0, 0, 2, 0, 0, 1, 2], r["dst_ip_src_ips_10s"].tolist()
    assert r["src_ip_flows_10s"].tolist() == [0, 0, 1, 0, 0, 0, 1], r["src_ip_flows_10s"].tolist()
    print("self-test ok")
