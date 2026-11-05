r"""Assemble bidirectional flows from a tshark packet export, following CICFlowMeter's rules (read from its source,
FlowGenerator.java and BasicFlow.java, 4 Nov 2026):
  - key: 5-tuple, bidirectional; the first packet's sender is the forward direction
  - a packet more than FLOW_TIMEOUT after the flow's first packet closes the flow and starts a new one
  - FIN: the flow closes on the FIRST FIN from either side (the FIN packet is included) and the packets
    after it start a new flow. This is the rule that reproduces the published CSE-CIC-IDS2018 CSVs
    (CICFlowMeter-V3): checked on the 21 Feb HOIC minutes, where the GitHub V4 code (which, through a typo,
    closes only on the responder's FIN) reproduces exactly half the flows and this rule all of them.
    Use --fin-rule v4 for the GitHub code's behaviour.
  - RST closes the flow at once (the RST packet is included); a packet with FIN and RST counts as FIN
  - lengths are TCP/UDP payload bytes; Flow IAT mixes both directions; std is the sample std (n-1);
    Flow Byts/s and Flow Pkts/s divide by the duration in seconds (inf when the duration is 0)
  - single-packet flows are dropped (CICFlowMeter's dump keeps packetCount > 1)
  - Timestamp = flow start in "dd/MM/yyyy hh:mm:ss" (12-hour, no AM/PM, as in the published CSVs), in the
    capture's local time zone (UTC offset given on the command line; the dataset was made in UTC-4)
Usage: assemble_flows.py packets.tsv flows.csv [--utc-offset -4]
Input columns (tshark -T fields): frame.time_epoch ip.src ip.dst ip.proto tcp.srcport tcp.dstport udp.srcport
udp.dstport tcp.len udp.length tcp.flags.fin tcp.flags.syn tcp.flags.reset tcp.flags.push tcp.flags.ack
tcp.flags.urg frame.len"""
import argparse
import math
import sys
import time
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

FLOW_TIMEOUT = 120_000_000          # microseconds (CICFlowMeter default 120 s)
COLS = ["t", "src", "dst", "proto", "tsp", "tdp", "usp", "udp", "tlen", "ulen", "fin", "syn", "rst", "psh", "ack",
        "urg", "flen"]
OUT_COLS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp", "start_us", "Flow Duration",
            "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd Pkt Len Mean", "Fwd Pkt Len Std",
            "Bwd Pkt Len Mean", "Flow Byts/s", "Flow Pkts/s", "Flow IAT Mean", "Flow IAT Std", "Fwd IAT Mean",
            "Fwd IAT Min", "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt", "URG Flag Cnt",
            "end_reason"]


def std_sample(n, s, s2):
    if n < 2:
        return 0.0
    v = (s2 - s * s / n) / (n - 1)
    return math.sqrt(v) if v > 0 else 0.0


class Flow:
    __slots__ = ("src", "sport", "dst", "dport", "proto", "start", "last", "n_f", "n_b", "b_f", "b_b", "fl_s", "fl_s2",
                 "bl_s", "iat_n", "iat_s", "iat_s2", "f_last", "fiat_n", "fiat_s", "fiat_min", "fin_f", "fin_b",
                 "flags")

    def __init__(self, t, src, sport, dst, dport, proto, plen, fl):
        self.src, self.sport, self.dst, self.dport, self.proto = src, sport, dst, dport, proto
        self.start = self.last = self.f_last = t
        self.n_f, self.n_b, self.b_f, self.b_b = 1, 0, plen, 0
        self.fl_s, self.fl_s2, self.bl_s = plen, plen * plen, 0
        self.iat_n = self.iat_s = self.iat_s2 = 0
        self.fiat_n, self.fiat_s, self.fiat_min = 0, 0, None
        self.fin_f = self.fin_b = 0
        self.flags = list(fl)

    def add(self, t, forward, plen, fl):
        gap = t - self.last
        self.iat_n += 1
        self.iat_s += gap
        self.iat_s2 += gap * gap
        self.last = t
        if forward:
            self.n_f += 1
            self.b_f += plen
            self.fl_s += plen
            self.fl_s2 += plen * plen
            fg = t - self.f_last
            self.fiat_n += 1
            self.fiat_s += fg
            self.fiat_min = fg if self.fiat_min is None else min(self.fiat_min, fg)
            self.f_last = t
        else:
            self.n_b += 1
            self.b_b += plen
            self.bl_s += plen
        for i, v in enumerate(fl):
            self.flags[i] += v

    def row(self, reason, tz):
        dur = self.last - self.start
        n = self.n_f + self.n_b
        secs = dur / 1_000_000
        stamp = (datetime.fromtimestamp(self.start / 1_000_000, tz)).strftime("%d/%m/%Y %I:%M:%S")
        return (f"{self.src}-{self.dst}-{self.sport}-{self.dport}-{self.proto}", self.src, self.sport, self.dst,
                self.dport, self.proto, stamp, self.start, dur, self.n_f, self.n_b, self.b_f, self.b_b,
                self.fl_s / self.n_f, std_sample(self.n_f, self.fl_s, self.fl_s2),
                (self.bl_s / self.n_b) if self.n_b else 0.0,
                (self.b_f + self.b_b) / secs if secs > 0 else math.inf, n / secs if secs > 0 else math.inf,
                (self.iat_s / self.iat_n) if self.iat_n else 0.0, std_sample(self.iat_n, self.iat_s, self.iat_s2),
                (self.fiat_s / self.fiat_n) if self.fiat_n else 0.0, self.fiat_min if self.fiat_min is not None else 0,
                *self.flags, reason)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("packets")
    ap.add_argument("out")
    ap.add_argument("--utc-offset", type=float, default=-4.0, help="hours; the dataset's local time (UNB, Feb 2018 = -4)")
    ap.add_argument("--fin-rule", choices=["v3", "v4"], default="v3",
                    help="v3: first FIN from either side closes the flow (published CSVs); v4: responder's FIN only")
    a = ap.parse_args()
    tz = timezone(timedelta(hours=a.utc_offset))
    flows: dict = {}
    out, n_pkts, n_dropped, t0 = [], 0, 0, time.perf_counter()
    writer_header = True

    def flush():
        nonlocal out, writer_header
        if out:
            pd.DataFrame(out, columns=OUT_COLS).to_csv(a.out, index=False, mode="w" if writer_header else "a",
                                                       header=writer_header)
            writer_header = False
            out = []

    def emit(key, flow, reason):
        if flow.n_f + flow.n_b > 1:
            out.append(flow.row(reason, tz))
        del flows[key]

    for chunk in pd.read_csv(a.packets, sep="\t", names=COLS, header=None, dtype=str, na_filter=False,
                             chunksize=2_000_000, quoting=3):
        t_us = (chunk["t"].astype("float64") * 1_000_000).round().astype("int64").to_numpy()
        proto = chunk["proto"].to_numpy()
        sport = np.where(proto == "6", chunk["tsp"], chunk["usp"])
        dport = np.where(proto == "6", chunk["tdp"], chunk["udp"])
        ulen = pd.to_numeric(chunk["ulen"], errors="coerce").fillna(8).to_numpy() - 8
        tlen = pd.to_numeric(chunk["tlen"], errors="coerce").fillna(0).to_numpy()
        plen = np.where(proto == "6", tlen, np.maximum(ulen, 0)).astype("int64")
        fl = np.column_stack([chunk[c].isin(["1", "True", "true"]).to_numpy() for c in
                              ("fin", "syn", "rst", "psh", "ack", "urg")]).astype("int64")
        for t, s, d, p, sp, dp, L, f in zip(t_us, chunk["src"].to_numpy(), chunk["dst"].to_numpy(), proto, sport, dport,
                                            plen, fl):
            n_pkts += 1
            if not sp or not dp:
                n_dropped += 1
                continue
            key = (s, sp, d, dp, p) if (s, sp) <= (d, dp) else (d, dp, s, sp, p)
            flow = flows.get(key)
            if flow is None:
                flows[key] = Flow(t, s, sp, d, dp, p, int(L), f)
                continue
            if t - flow.start > FLOW_TIMEOUT:
                emit(key, flow, "timeout")
                flows[key] = Flow(t, s, sp, d, dp, p, int(L), f)
                continue
            forward = (s == flow.src and sp == flow.sport)
            if f[0]:                                     # FIN
                flow.add(t, forward, int(L), f)
                if forward:
                    flow.fin_f = 1
                else:
                    flow.fin_b = 1
                if a.fin_rule == "v3" or flow.fin_b == 1:   # see the docstring
                    emit(key, flow, "fin")
            elif f[2]:                                   # RST
                flow.add(t, forward, int(L), f)
                emit(key, flow, "rst")
            elif (forward and flow.fin_f == 0) or (not forward and flow.fin_b == 0):
                flow.add(t, forward, int(L), f)
            else:
                n_dropped += 1                           # CICFlowMeter: "FLOW already closed", packet discarded
        if len(out) > 500_000:
            flush()
        print(f"  {n_pkts:,} packets, {len(flows):,} open flows, {time.perf_counter() - t0:.0f} s", flush=True)
    for key in list(flows):
        emit(key, flows[key], "end")
    flush()
    print(f"done: {n_pkts:,} packets, {n_dropped:,} dropped (no port, or after FIN), wrote {a.out} "
          f"in {time.perf_counter() - t0:.0f} s", flush=True)


if __name__ == "__main__":
    sys.exit(main())
