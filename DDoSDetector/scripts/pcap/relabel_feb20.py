r"""Fix the labels of the published 20 Feb 2018 CSV and write a copy the app and training can use.

Why (found 5 Nov 2026 by scanning every row of Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv):
  - 797 UDP flows from the ten attacker IPs to port 80 are labelled "DDoS attacks-LOIC-HTTP". They are the 20 Feb
    LOIC-UDP flood (13:14-13:29; 32-byte payloads, ~134,000 packets per flow, no replies, 120 s), the same shape as the
    21 Feb flood, and the dataset's own schedule lists LOIC-UDP on 20 Feb at 13:13-13:32.
  - 702 UDP flows from the victim (172.31.69.25) to attacker port 80 are labelled Benign. They are the server's ICMP
    "port unreachable" replies to that flood, recorded as UDP flows by CICFlowMeter (PacketReader.java's
    hasHeader(udp) branch; the same rows on 21 Feb are the 1,598 "Benign" UDP flows during LOIC-UDP).
  - 130 TCP flows from the victim's port 80 to an attacker are labelled Benign. They are LOIC-HTTP connections that
    CICFlowMeter recorded server-to-attacker (its timeout branch keeps the old flow's direction, FlowGenerator.java
    line 104), labelled Benign because the labelling keyed on attacker *source* IPs.
Everything else in the file is left as it is: it already has Src IP / Dst IP, it is complete (7.95 M rows, the whole
network), and its flows follow the same CICFlowMeter V3 rules as the rebuilt 21 Feb file.

Rules (the same as label_flows.py for 21 Feb, decided with the user on 5 Nov 2026): a flow is an attack flow when either
end is one of the ten attacker addresses; the tool is LOIC-UDP for UDP flows (protocol 17) and LOIC-HTTP otherwise;
a "Label Reason" column says why. Rows without an attacker IP keep their published label.

Timestamps: the published file is on a 12-hour clock without AM/PM (rows at "01:00"-"07:59" are 13:00-19:59; the
capture ran 08:00-19:59, nothing at 0-7 or after 20). They are rewritten as 24-hour "dd/mm/yyyy HH:MM:SS", the form the
relabelled 21 Feb file uses and the app parses directly. The file's row order is kept (it is not in time order).

Usage: relabel_feb20.py [--in data\Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv]
                        [--out data\Tuesday-20-02-2018_relabelled.csv]
Reads in chunks (the file is 3.9 GB); about three minutes.
"""
import argparse
import sys
import time
from pathlib import Path

import pandas as pd

DATA = Path(__file__).resolve().parents[3] / "data"
VICTIM = "172.31.69.25"
# The same ten addresses as label_flows.py (21 Feb); on 20 Feb every published attack row has one of them as source.
ATTACKERS = {"18.216.200.189", "18.218.229.235", "18.218.115.60", "18.218.11.51", "18.216.24.42", "18.219.9.1",
             "18.219.32.43", "18.218.55.126", "52.14.136.135", "18.219.5.43"}
LOIC_HTTP = "DDoS attacks-LOIC-HTTP"      # the published 20 Feb spelling
LOIC_UDP = "DDOS attack-LOIC-UDP"         # the published 21 Feb spelling (the app maps both by substring)
REASON_COL = "Label Reason"


def to_24h(stamps: pd.Series) -> pd.Series:
    """'dd/mm/yyyy hh:mm:ss' on a 12-hour clock -> 24-hour, assuming the capture ran between 08:00 and 19:59."""
    hour = stamps.str.slice(11, 13).astype(int)
    if ((hour < 1) | (hour > 12)).any():
        raise ValueError("timestamps are not on a 12-hour clock (hour outside 1-12)")
    h24 = hour.where(hour >= 8, hour + 12)
    return stamps.str.slice(0, 11) + h24.map("{:02d}".format) + stamps.str.slice(13)


def relabel(chunk: pd.DataFrame) -> pd.DataFrame:
    chunk = chunk[chunk["Label"] != "Label"].copy()            # repeated header rows
    src_att, dst_att = chunk["Src IP"].isin(ATTACKERS), chunk["Dst IP"].isin(ATTACKERS)
    involved = src_att | dst_att
    udp = chunk["Protocol"].astype(str) == "17"
    tool = pd.Series(LOIC_HTTP, index=chunk.index, dtype="object").where(~udp, LOIC_UDP)
    short = tool.str.replace(r"DD[oO]S attacks?-", "", regex=True)
    published = chunk["Label"].astype(str)

    lab = published.copy()
    why = pd.Series("published label (no attacker IP involved)", index=chunk.index, dtype="object")
    lab[involved] = tool[involved]
    why[involved & src_att & ~udp] = ("attacker IP to victim (" + short + ", protocol " + chunk["Protocol"].astype(str)
                                      + ", port " + chunk["Dst Port"].astype(str) + ")")
    why[involved & src_att & udp] = ("attacker IP to victim (LOIC-UDP flood, protocol 17, port " + chunk["Dst Port"].astype(str)
                                     + "; the published file labels it LOIC-HTTP)")
    why[involved & ~src_att & udp] = ("victim ICMP port-unreachable reply to attacker IP (LOIC-UDP; recorded as a UDP flow "
                                      "by CICFlowMeter, published label Benign)")
    why[involved & ~src_att & ~udp] = ("victim reply flow to attacker IP (" + short + "; recorded server-to-attacker by "
                                       "CICFlowMeter's timeout quirk, published label " + published + ")")
    chunk["Label"] = lab
    chunk[REASON_COL] = why
    chunk["Timestamp"] = to_24h(chunk["Timestamp"].astype(str))
    chunk["_published"] = published
    return chunk


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", type=Path, default=DATA / "Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv")
    ap.add_argument("--out", type=Path, default=DATA / "Tuesday-20-02-2018_relabelled.csv")
    a = ap.parse_args(argv)
    t0 = time.perf_counter()
    rows, header = 0, True
    changed = {}
    labels = {}
    reasons = {}
    span = [None, None]
    for chunk in pd.read_csv(a.inp, dtype=str, chunksize=500_000, low_memory=False, na_filter=False):
        out = relabel(chunk)
        moved = out[out["_published"] != out["Label"]]
        for (p, n), k in moved.groupby(["_published", "Label"]).size().items():
            changed[(p, n)] = changed.get((p, n), 0) + int(k)
        for k, v in out["Label"].value_counts().items():
            labels[k] = labels.get(k, 0) + int(v)
        for k, v in out[REASON_COL].str.replace(r", port \d+\)", ")", regex=True).value_counts().items():
            reasons[k] = reasons.get(k, 0) + int(v)
        lo, hi = out["Timestamp"].min(), out["Timestamp"].max()
        span = [lo if span[0] is None else min(span[0], lo), hi if span[1] is None else max(span[1], hi)]
        out.drop(columns="_published").to_csv(a.out, index=False, mode="w" if header else "a", header=header)
        header = False
        rows += len(out)
        print(f"  {rows:,} rows, {time.perf_counter() - t0:.0f} s", flush=True)
    print(f"wrote {a.out}: {rows:,} rows in {time.perf_counter() - t0:.0f} s")
    print("\nlabels changed (published -> new):")
    for (p, n), k in sorted(changed.items()):
        print(f"  {p:<24} -> {n:<24} {k:>8,}")
    print("\nlabel counts:")
    for k, v in sorted(labels.items(), key=lambda kv: -kv[1]):
        print(f"  {k:<24} {v:>10,}")
    print("\nlabel reasons:")
    for k, v in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print(f"  {v:>10,}  {k}")
    print(f"\ntimestamps (24-hour): {span[0]} .. {span[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
