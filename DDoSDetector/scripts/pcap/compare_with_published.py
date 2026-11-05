r"""Compare flows we built from the 21 Feb PCAP (victim server 172.31.69.28) with the published 21 Feb CSV.
Usage: compare_flows.py new_flows.csv [--published path] [--label "flows_cicflowmeter"]
The published file has no IPs, so matching uses (Timestamp, Dst Port, Protocol, Flow Duration, Tot Fwd Pkts,
Tot Bwd Pkts, TotLen Fwd Pkts). Timestamps in the published file are "dd/MM/yyyy hh:mm:ss" 12-hour without
AM/PM; the new file is written the same way. Reports: time span, flows per minute on port 80 in both, exact-match
rate within the new file's time span, and how the nine model columns compare on matched flows."""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PUB = Path(r"C:\datasets\cse-cic-ids2018\processed\Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv")
KEY = ["Timestamp", "Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts"]
NINE = ["Flow Pkts/s", "Flow Byts/s", "Flow Duration", "Flow IAT Mean", "Flow IAT Std", "Fwd Pkt Len Mean",
        "Fwd Pkt Len Std"]


# CICFlowMeter V4 (the GitHub tool) uses long names; the published V3 CSVs use short ones.
V4_TO_V3 = {"Total Fwd Packet": "Tot Fwd Pkts", "Total Bwd packets": "Tot Bwd Pkts",
            "Total Length of Fwd Packet": "TotLen Fwd Pkts", "Total Length of Bwd Packet": "TotLen Bwd Pkts",
            "Fwd Packet Length Mean": "Fwd Pkt Len Mean", "Fwd Packet Length Std": "Fwd Pkt Len Std",
            "Bwd Packet Length Mean": "Bwd Pkt Len Mean", "Flow Bytes/s": "Flow Byts/s",
            "Flow Packets/s": "Flow Pkts/s"}


def parse_stamp(s: pd.Series) -> pd.Series:
    """12-hour stamps with AM/PM (V4 tool) or without (published CSVs, our assembler)."""
    t = pd.to_datetime(s, format="%d/%m/%Y %I:%M:%S %p", errors="coerce")
    missing = t.isna()
    if missing.any():
        t[missing] = pd.to_datetime(s[missing], format="%d/%m/%Y %I:%M:%S", errors="coerce")
    return t


def load_new(path):
    d = pd.read_csv(path, low_memory=False)
    d.columns = [c.strip() for c in d.columns]
    d = d.rename(columns=V4_TO_V3)
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("new")
    ap.add_argument("--published", default=str(PUB))
    ap.add_argument("--port", default="80", help="destination port for the per-minute table (HOIC and LOIC-UDP: 80)")
    ap.add_argument("--protocol", default=None, help="protocol number for the per-minute table (6 = TCP/HOIC, 17 = UDP/LOIC-UDP); default any")
    a = ap.parse_args()
    new = load_new(a.new)
    print(f"new flows: {len(new):,} from {a.new}")
    pub = pd.read_csv(a.published, low_memory=False, dtype={"Timestamp": str, "Dst Port": str, "Protocol": str})
    pub = pub[pub["Dst Port"] != "Dst Port"]                      # repeated header rows
    for c in ["Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts"] + NINE:
        pub[c] = pd.to_numeric(pub[c], errors="coerce")
    print(f"published flows: {len(pub):,}; labels: {pub['Label'].value_counts().to_dict()}")

    # The published stamps are 12-hour WITHOUT AM/PM, so everything is compared on the 12-hour clock
    # ("dd/MM/yyyy hh:mm:ss"). The capture machine and the dataset makers may also sit in different time
    # zones: pick the whole-hour shift of the new stamps that gives the most matches on
    # (12-hour second, Dst Port, Flow Duration).
    new_t = parse_stamp(new["Timestamp"])
    pub_k = parse_stamp(pub["Timestamp"]).dt.strftime("%d/%m/%Y %I:%M:%S")
    print(f"new span (capture machine's clock): {new_t.min()} .. {new_t.max()}")
    pp = pd.DataFrame({"_k": pub_k, "Dst Port": pub["Dst Port"].astype(str),
                       "Flow Duration": pub["Flow Duration"].astype("int64")}).drop_duplicates()
    step = max(1, len(new) // 200_000)                  # spread the probe over the whole file: the published
    probe = new.iloc[::step]                              # CSV covers some periods very thinly (the 21 Feb morning)
    probe_t = new_t.iloc[::step]
    best, best_n = 0, -1
    for h in range(-6, 7):
        q = pd.DataFrame({"_k": (probe_t + pd.Timedelta(hours=h)).dt.strftime("%d/%m/%Y %I:%M:%S"),
                          "Dst Port": probe["Dst Port"].astype(str),
                          "Flow Duration": probe["Flow Duration"].astype("int64")})
        n_ = len(q.merge(pp, on=["_k", "Dst Port", "Flow Duration"], how="inner"))
        if n_ > best_n:
            best, best_n = h, n_
    print(f"time shift that matches best: {best:+d} h ({best_n:,} of {len(probe):,} probe flows match)")
    new_t = new_t + pd.Timedelta(hours=best)
    new["Timestamp"] = new_t.dt.strftime("%d/%m/%Y %I:%M:%S")
    pub["Timestamp"] = pub_k
    new_min = new_t.dt.strftime("%d/%m/%Y %I:%M")
    pub_min = pub_k.str.slice(0, 16)
    pub_in = pub[pub_min.isin(set(new_min))]
    print(f"published flows in the new file's minutes: {len(pub_in):,}; labels: "
          f"{pub_in['Label'].value_counts().to_dict()}")

    sel_n = new["Dst Port"].astype(str) == a.port
    sel_p = pub_in["Dst Port"] == a.port
    if a.protocol is not None:
        sel_n &= new["Protocol"].astype(str) == a.protocol
        sel_p &= pub_in["Protocol"].astype(str) == a.protocol
    nm = new[sel_n].groupby(new_min[sel_n]).size()
    pm = pub_in[sel_p].groupby(pub_min[pub_in.index][sel_p]).size()
    both = pd.concat({"new": nm, "published": pm}, axis=1).fillna(0).astype(int).sort_index()
    what = f"port {a.port}" + (f", protocol {a.protocol}" if a.protocol is not None else "")
    print(f"\nflows per minute to {what} (12-hour clock; first 12 and last 6 minutes):")
    print(both.head(12).to_string()); print("  ..."); print(both.tail(6).to_string())

    # exact matches on the key
    n = new.copy()
    n["Dst Port"] = n["Dst Port"].astype(str); n["Protocol"] = n["Protocol"].astype(str)
    p = pub_in.copy()
    for c in ["Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts"]:
        n[c] = n[c].astype("int64"); p[c] = p[c].astype("int64")
    pk = p.drop_duplicates(KEY)
    m = n.merge(pk, on=KEY, how="inner", suffixes=("_new", "_pub"))
    print(f"\nexact key matches: {len(m):,} of {len(n):,} new flows ({len(m) / len(n):.1%}); "
          f"{len(pk):,} distinct published keys in span")
    if len(m):
        lab = "Label_pub" if "Label_pub" in m.columns else "Label"
        print("labels of matched flows:", m[lab].value_counts().to_dict())
        print("\nnine-column agreement on matched flows (share within 1% or both inf/0):")
        for c in NINE:
            if c in KEY:
                continue                                  # equal by construction of the match
            a_, b_ = m[f"{c}_new"].astype(float), m[f"{c}_pub"].astype(float)
            same = (np.isclose(a_, b_, rtol=0.01, atol=1e-6) | (np.isinf(a_) & np.isinf(b_))).mean()
            print(f"  {c:<18} {same:.3f}   new median {a_.median():>14,.3f}   published median {b_.median():>14,.3f}")
    # loose match: same second, port, duration (drops packet counts)
    loose = n.merge(pk.drop_duplicates(["Timestamp", "Dst Port", "Flow Duration"]),
                    on=["Timestamp", "Dst Port", "Flow Duration"], how="inner")
    print(f"\nloose matches (second + port + duration): {len(loose):,} ({len(loose) / len(n):.1%})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
