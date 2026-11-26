r"""Label the flows rebuilt from the raw 21 Feb 2018 victim capture and write one CSV the app can open.

Why: the published Wednesday-21-02-2018 CSV has no IP addresses, stops at 02:33 (Excel's row limit) and labels
most attack by-products "Benign": 358,523 HOIC request/response flows that CICFlowMeter recorded in the
server-to-attacker direction (its timeout branch keeps the old flow's source/destination, FlowGenerator.java
line 104, and the labelling keyed on attacker *source* IPs), and 1,598 ICMP "port unreachable" replies to the
LOIC-UDP flood that it recorded as UDP flows (PacketReader.java, the hasHeader(udp) branch). Verified flow by
flow in compare_with_published.py and the session notes (5 Nov 2026).

Rules (decided with the user on 5 Nov 2026): a flow is an attack flow when either end is one of the ten attacker
addresses; the label is the tool of that period (LOIC-UDP in the morning, HOIC in the afternoon) and a
"Label Reason" column says why (attacker to victim; victim reply; ICMP reply). Everything else is Benign with the
reason "no attacker IP involved". Timestamps are written as 24-hour "dd/mm/yyyy HH:MM:SS" in the dataset's zone
(UTC-4), which the app parses directly; the published files use a 12-hour clock without AM/PM.

Usage: label_flows.py part1_flows.csv part2_flows.csv out.csv
"""
import argparse
import sys
from datetime import datetime, timedelta, timezone

import pandas as pd

VICTIM = "172.31.69.28"
# The ten addresses that send the HOIC and LOIC-UDP traffic in the capture (nine of them are in the dataset's
# published attacker list; 52.14.136.135 sends the same traffic and its flows are labelled as attacks in the
# published CSV too).
ATTACKERS = {"18.216.200.189", "18.218.229.235", "18.218.115.60", "18.218.11.51", "18.216.24.42", "18.219.9.1",
             "18.219.32.43", "18.218.55.126", "52.14.136.135", "18.219.5.43"}
NOON_LOCAL = 12   # before noon (dataset zone) = LOIC-UDP period, after = HOIC period
HOIC, LOIC_UDP, BENIGN = "DDOS attack-HOIC", "DDOS attack-LOIC-UDP", "Benign"


def label(df: pd.DataFrame, tz: timezone) -> pd.DataFrame:
    src_att, dst_att = df["Src IP"].isin(ATTACKERS), df["Dst IP"].isin(ATTACKERS)
    involved = src_att | dst_att
    local = pd.to_datetime(df["start_us"], unit="us", utc=True).dt.tz_convert(tz)
    morning = local.dt.hour < NOON_LOCAL
    proto = df["Protocol"].astype(int)

    lab = pd.Series(BENIGN, index=df.index, dtype="object")
    why = pd.Series("no attacker IP involved", index=df.index, dtype="object")
    tool = pd.Series(HOIC, index=df.index, dtype="object").where(~morning, LOIC_UDP)
    short = tool.str.replace("DDOS attack-", "", regex=False)
    lab[involved] = tool[involved]
    why[involved & src_att] = "attacker IP to victim (" + short + ", protocol " + proto.astype(str) + ", port " + df["Dst Port"].astype(str) + ")"
    why[involved & ~src_att & (proto == 1)] = ("victim ICMP port-unreachable reply to attacker IP (" + short
                                                + "; the published file records these as UDP flows labelled Benign)")
    why[involved & ~src_att & (proto != 1)] = "victim reply flow to attacker IP (" + short + ", protocol " + proto.astype(str) + ")"
    out = df.copy()
    out["Timestamp"] = local.dt.strftime("%d/%m/%Y %H:%M:%S")
    out["Label"] = lab
    out["Label Reason"] = why
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("flows", nargs="+", help="flow CSVs from assemble_flows.py (part 1, part 2)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--utc-offset", type=float, default=-4.0)
    a = ap.parse_args(argv)
    tz = timezone(timedelta(hours=a.utc_offset))
    parts = [pd.read_csv(p, low_memory=False) for p in a.flows]
    df = pd.concat(parts, ignore_index=True).sort_values("start_us", kind="stable").reset_index(drop=True)
    print(f"flows: {len(df):,} from {len(parts)} file(s)")
    out = label(df, tz)
    out.to_csv(a.out, index=False)
    print(f"wrote {a.out}")
    print("\nlabel counts:")
    print(out["Label"].value_counts().to_string())
    print("\nlabel x reason (reason shortened):")
    r = out["Label Reason"].str.replace(r", port \d+\)", ")", regex=True).str.replace(r"\(.*?;", "(", regex=True)
    print(out.groupby(["Label", r]).size().to_string())
    t = pd.to_datetime(out["Timestamp"], format="%d/%m/%Y %H:%M:%S")
    for lab_ in (HOIC, LOIC_UDP):
        m = out["Label"] == lab_
        print(f"\n{lab_}: {m.sum():,} flows, {t[m].min()} .. {t[m].max()}")
    ben = out["Label"] == BENIGN
    print(f"{BENIGN}: {ben.sum():,} flows; src IPs {out.loc[ben, 'Src IP'].nunique()}, dst IPs {out.loc[ben, 'Dst IP'].nunique()}; "
          f"top dst ports {out.loc[ben, 'Dst Port'].value_counts().head(5).to_dict()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
