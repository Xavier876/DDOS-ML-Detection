"""Feature registry, cleaning and feature building.

The ONE place that defines the model inputs. Training, scoring, SHAP charts, the Features panel
and the tests all read this registry; nothing else lists feature columns. Logic follows
notebooks/ddos_xgboost_starter_v2.ipynb (sections 5 and 6).

Numbering (update 5, renumbered on 5 Nov 2026 at the user's request): features 1-6 are the inputs
of the default model, in its column order; 7-18 are the other catalogue groups, kept so that older
models (the update-4 baseline f9p, the notebook comparisons) still load and are explained. Each group
also records `week3`, its number in the group's Week 3 project document (1-15; of the three IP
windows only the destination-IP window is in it, as the document's feature 7), so the report and the
document can be reconciled:

    app   week3  group                                   app   week3  group
    1     7      flows to the same destination IP        10    5      SYN flag count
    2     -      distinct source IPs to the same dst IP  11    6      forward packet length
    3     -      flows from the same source IP           12    7      flows to the same destination port
    4     3      forward/backward packet ratio           13    8      reply behaviour
    5     10     no-reply / empty-payload indicators     14    9      connection-ending flags
    6     11     timing regularity                       15    12     response size ratio (update 3)
    7     1      packet and byte rate                    16    13     sender timing (update 3)
    8     2      flow duration                           17    14     activity pattern (update 3)
    9     4      inter-arrival time                      18    15     payload signals (update 3)

History: update 3 (22 Oct 2026) added the week-3 groups 12-15 and dropped SYN from the set f21;
update 4 (31 Oct 2026) settled on six groups with the port window replacing SYN (set f9p); update 5
(5 Nov 2026, feature search on the 21 Feb capture rebuilt with IP addresses) chose the six groups that
carry over to an unseen attack tool for all three model types (set f7ip, 7 columns): the three IP
windows, the forward/backward ratio, the indicators and timing regularity.

Groups 1-3 and 12 are the window groups, built from many rows: they need the whole capture file, so
they must be built on every row of a file (the app scores the whole loaded CSV; training builds them
per file before its own cleaning). Timestamp, Dst Port, Src IP and Dst IP are used only to count
flows; they are never model inputs themselves.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import numpy as np
import pandas as pd

LABEL, TIME = "Label", "Timestamp"
OPTIONAL_COLUMNS = [LABEL, TIME]

# Kept for tracing alerts back to hosts when present. NEVER model inputs.
TRACING_COLUMNS = {"Src IP": "src_ip", "Dst IP": "dst_ip", "Dst Port": "dst_port"}

# Window groups (1-3 and 12): these columns are read as text and used only to count flows. Counts
# never cross capture files: training concatenates files and marks each row's file in CAPTURE_COLUMN;
# the app opens one file.
PORT, SRC_IP, DST_IP = "Dst Port", "Src IP", "Dst IP"
CONTEXT_RAW = (TIME, PORT, SRC_IP, DST_IP)
CAPTURE_COLUMN = "source_file"
WINDOW_SECONDS = 10

TOOLS = ["Benign", "HOIC", "LOIC-HTTP", "LOIC-UDP"]
ATTACK_TOOLS = ["HOIC", "LOIC-HTTP", "LOIC-UDP"]

# Human-readable version of tool_of, stored in model metadata.
LABEL_MAPPING = {
    "contains 'benign'": "Benign",
    "contains 'udp'": "LOIC-UDP",
    "contains 'hoic'": "HOIC",
    "contains 'http'": "LOIC-HTTP",
    "anything else": "Other",
}


# --- the registry -----------------------------------------------------------------------
def _as_float(cols):
    return lambda df: df[list(cols)].astype("float64")


def _ratio(df):    # feature 4 (week 3: 3)
    return pd.DataFrame({"fwd_bwd_ratio": df["Tot Fwd Pkts"].astype("float64")
                         / (df["Tot Bwd Pkts"].astype("float64") + 1)})


def _indicators(df):    # feature 5 (week 3: 10); NaN inputs stay NaN rather than becoming 0
    bwd, fwd = df["Tot Bwd Pkts"].astype("float64"), df["Fwd Pkt Len Mean"].astype("float64")
    return pd.DataFrame({"no_reply": (bwd == 0).astype("float64").where(bwd.notna()),
                         "empty_payload": (fwd == 0).astype("float64").where(fwd.notna())})


def _iat_cv(df):    # feature 6 (week 3: 11): inf (IAT mean of -1 exists in these files) becomes missing
    cv = df["Flow IAT Std"].astype("float64") / (df["Flow IAT Mean"].astype("float64") + 1)
    return pd.DataFrame({"iat_cv": cv.replace([np.inf, -np.inf], np.nan)})


def _bytes_ratio(df):    # feature 15 (week 3: 12, update 3 candidate): reply bytes per request byte
    r = df["TotLen Bwd Pkts"].astype("float64") / (df["TotLen Fwd Pkts"].astype("float64") + 1)
    return pd.DataFrame({"bwd_fwd_bytes_ratio": r})


def _payload_signals(df):    # feature 18 (week 3: 15, update 3 candidate)
    share = df["Fwd Act Data Pkts"].astype("float64") / df["Tot Fwd Pkts"].astype("float64")
    return pd.DataFrame({"PSH Flag Cnt": df["PSH Flag Cnt"].astype("float64"),
                         "data_share": share.replace([np.inf, -np.inf], np.nan)})


def parse_timestamps(s: pd.Series) -> pd.Series:
    """CICFlowMeter 'dd/mm/yyyy HH:MM:SS' text -> datetime (already-parsed values pass through)."""
    if pd.api.types.is_datetime64_any_dtype(s):
        return s
    t = pd.to_datetime(s, format="%d/%m/%Y %H:%M:%S", errors="coerce")
    bad = t.isna() & s.notna()
    if bad.any():  # fall back to the notebook's flexible day-first parsing
        t[bad] = pd.to_datetime(s[bad], dayfirst=True, errors="coerce")
    return t


def _seconds(df: pd.DataFrame) -> pd.Series:
    """Whole seconds since the epoch of each flow's start (NaN when unreadable), whatever the datetime unit."""
    t = parse_timestamps(df[TIME])
    return np.floor((t - pd.Timestamp("1970-01-01")).dt.total_seconds())


def _capture(df: pd.DataFrame) -> pd.Series:
    return df[CAPTURE_COLUMN] if CAPTURE_COLUMN in df.columns else pd.Series(0, index=df.index)


def _key(df: pd.DataFrame, col: str) -> pd.Series:
    """A numeric code per distinct value of a context column (NaN when missing or, for the port, not a
    number), so that the counting below works for ports and IP addresses alike."""
    if col == PORT:
        return pd.to_numeric(df[col], errors="coerce")
    codes = pd.factorize(df[col].astype("string"))[0].astype("float64")
    codes[df[col].isna().to_numpy()] = np.nan
    return pd.Series(codes, index=df.index)


def _window_count(df: pd.DataFrame, keys: tuple[str, ...], name: str) -> pd.DataFrame:
    """For a flow starting in second s: flows of the same capture file with the same `keys` that started
    in seconds s-10 .. s-1 (looks back only, never at its own second). Missing or unreadable time or key
    -> missing (the row is then "Not scored")."""
    by = ["cap", *keys]
    key = pd.DataFrame({"cap": _capture(df), "sec": _seconds(df), **{k: _key(df, k) for k in keys}},
                       index=df.index).dropna()
    out = pd.Series(np.nan, index=df.index, name=name)
    if key.empty:
        return out.to_frame()
    c = key.groupby(by + ["sec"]).size().rename("n").reset_index().sort_values(by + ["sec"])
    c["before"] = c.groupby(by)["n"].cumsum() - c["n"]                      # flows with sec < s
    look = c[by + ["sec"]].assign(target=c["sec"] - WINDOW_SECONDS).sort_values("target")
    right = c[by + ["sec", "before", "n"]].rename(columns={"sec": "rsec"}).sort_values("rsec")
    m = pd.merge_asof(look, right, left_on="target", right_on="rsec", by=by,
                      direction="backward", allow_exact_matches=False)   # last second before s-10
    m["before_window"] = (m["before"] + m["n"]).fillna(0)                   # flows with sec < s-10
    c = c.merge(m[by + ["sec", "before_window"]], on=by + ["sec"], how="left")
    c["count"] = c["before"] - c["before_window"]
    rows = key.reset_index().merge(c[by + ["sec", "count"]], on=by + ["sec"], how="left")
    out.loc[rows["index"].to_numpy()] = rows["count"].to_numpy(dtype="float64")
    return out.to_frame()


def _distinct_in_window(df: pd.DataFrame, by_col: str, distinct_col: str, name: str) -> pd.DataFrame:
    """Distinct values of `distinct_col` that had a flow with the same `by_col` (same capture file) in the
    previous 10 s. Each (by, distinct) pair is "present" in seconds p+1 .. p+10 after a flow in second p;
    overlapping presence intervals are merged so a pair counts once, and a difference array per `by`
    gives the count at any second."""
    p = pd.DataFrame({"cap": _capture(df), "by": _key(df, by_col), "d": _key(df, distinct_col),
                      "sec": _seconds(df)}, index=df.index)
    valid = p.dropna()
    out = pd.Series(np.nan, index=df.index, name=name)
    if valid.empty:
        return out.to_frame()
    pres = valid.drop_duplicates(["cap", "by", "d", "sec"]).sort_values(["cap", "by", "d", "sec"]).reset_index(drop=True)
    g = pres[["cap", "by", "d"]].ne(pres[["cap", "by", "d"]].shift()).any(axis=1)
    new_run = g | ((pres["sec"] - pres["sec"].shift()) >= WINDOW_SECONDS)   # gap >= window: new interval
    run = new_run.cumsum()
    start = pres.loc[new_run, ["cap", "by", "sec"]].assign(sec=lambda x: x["sec"] + 1).set_index(run[new_run])
    end = pres.groupby(run)["sec"].max() + WINDOW_SECONDS + 1              # first second no longer covered
    ev = pd.concat([start.assign(delta=1.0),
                    start[["cap", "by"]].assign(sec=end.reindex(start.index).to_numpy(), delta=-1.0)])
    ev = ev.groupby(["cap", "by", "sec"])["delta"].sum().reset_index().sort_values(["cap", "by", "sec"])
    ev["value"] = ev.groupby(["cap", "by"])["delta"].cumsum()
    look = valid.reset_index()[["index", "cap", "by", "sec"]].sort_values("sec")
    m = pd.merge_asof(look, ev.sort_values("sec")[["cap", "by", "sec", "value"]], on="sec", by=["cap", "by"],
                      direction="backward", allow_exact_matches=True)
    out.loc[m["index"].to_numpy()] = m["value"].fillna(0).to_numpy(dtype="float64")
    return out.to_frame()


def _dst_ip_window(df):    # feature 1 (week 3: 7): flows to the same Dst IP in the previous 10 s
    return _window_count(df, (DST_IP,), "dst_ip_flows_10s")


def _src_ips_per_dst(df):  # feature 2 (update 5): distinct Src IPs with a flow to the same Dst IP
    return _distinct_in_window(df, DST_IP, SRC_IP, "dst_ip_src_ips_10s")


def _src_ip_window(df):    # feature 3 (update 5): flows from the same Src IP in the previous 10 s
    return _window_count(df, (SRC_IP,), "src_ip_flows_10s")


def _port_window(df):      # feature 12 (update 4's port version of week-3 feature 7)
    return _window_count(df, (PORT,), "dst_port_flows_10s")


@dataclass(frozen=True)
class FeatureGroup:
    number: int                         # app number since update 5 (1-6 = the default model's inputs)
    week3: int | None                   # the number in the group's Week 3 document (None = not in it)
    key: str                            # group name used in metadata
    title: str                          # short human title
    output_columns: tuple[str, ...]     # model input columns this group produces
    required_raw: tuple[str, ...]       # CSV columns needed to build them
    build: Callable[[pd.DataFrame], pd.DataFrame]
    core: bool                          # original nine columns and the window groups: NaN/inf -> row "Not scored"

    @property
    def label(self) -> str:
        return f"F{self.number} {self.title}"

    @property
    def window(self) -> bool:
        """Built from the whole capture file (groups 1-3 and 12), not from the row alone."""
        return any(r in CONTEXT_RAW and r != TIME for r in self.required_raw)


REGISTRY: tuple[FeatureGroup, ...] = (
    # 1-6: the default model's inputs (set f7ip, update 5), in its column order.
    FeatureGroup(1, 7, "dst_ip_window", "Flows to the same destination IP", ("dst_ip_flows_10s",),
                 (TIME, DST_IP), _dst_ip_window, True),
    FeatureGroup(2, None, "src_ips_per_dst", "Distinct source IPs to the same destination IP", ("dst_ip_src_ips_10s",),
                 (TIME, DST_IP, SRC_IP), _src_ips_per_dst, True),
    FeatureGroup(3, None, "src_ip_window", "Flows from the same source IP", ("src_ip_flows_10s",),
                 (TIME, SRC_IP), _src_ip_window, True),
    FeatureGroup(4, 3, "fwd_bwd_ratio", "Forward to backward packet ratio", ("fwd_bwd_ratio",),
                 ("Tot Fwd Pkts", "Tot Bwd Pkts"), _ratio, True),
    FeatureGroup(5, 10, "indicators", "No-reply and empty-payload indicators", ("no_reply", "empty_payload"),
                 ("Tot Bwd Pkts", "Fwd Pkt Len Mean"), _indicators, False),
    FeatureGroup(6, 11, "timing_regularity", "Timing regularity", ("iat_cv",),
                 ("Flow IAT Std", "Flow IAT Mean"), _iat_cv, False),
    # 7-14: the rest of the original catalogue (the nine columns, the port window, groups added after the
    # first experiments); used by the update-4 baseline f9p and the older sets.
    FeatureGroup(7, 1, "rate", "Packet and byte rate", ("Flow Pkts/s", "Flow Byts/s"),
                 ("Flow Pkts/s", "Flow Byts/s"), _as_float(("Flow Pkts/s", "Flow Byts/s")), True),
    FeatureGroup(8, 2, "duration", "Flow duration", ("Flow Duration",), ("Flow Duration",),
                 _as_float(("Flow Duration",)), True),
    FeatureGroup(9, 4, "inter_arrival", "Inter-arrival time", ("Flow IAT Mean", "Flow IAT Std"),
                 ("Flow IAT Mean", "Flow IAT Std"), _as_float(("Flow IAT Mean", "Flow IAT Std")), True),
    FeatureGroup(10, 5, "syn_flag", "SYN flag count", ("SYN Flag Cnt",), ("SYN Flag Cnt",),
                 _as_float(("SYN Flag Cnt",)), True),
    FeatureGroup(11, 6, "fwd_pkt_len", "Forward packet length", ("Fwd Pkt Len Mean", "Fwd Pkt Len Std"),
                 ("Fwd Pkt Len Mean", "Fwd Pkt Len Std"), _as_float(("Fwd Pkt Len Mean", "Fwd Pkt Len Std")), True),
    FeatureGroup(12, 7, "port_window", "Flows to the same destination port", ("dst_port_flows_10s",),
                 (TIME, PORT), _port_window, True),
    FeatureGroup(13, 8, "reply", "Reply behaviour", ("Bwd Pkt Len Mean",), ("Bwd Pkt Len Mean",),
                 _as_float(("Bwd Pkt Len Mean",)), False),
    FeatureGroup(14, 9, "conn_end_flags", "Connection-ending flags", ("RST Flag Cnt", "FIN Flag Cnt"),
                 ("RST Flag Cnt", "FIN Flag Cnt"), _as_float(("RST Flag Cnt", "FIN Flag Cnt")), False),
    # 15-18: update 3 (22 Oct 2026) candidates, in the set f21; tested in notebook 9b/9c.
    FeatureGroup(15, 12, "response_ratio", "Response size ratio", ("bwd_fwd_bytes_ratio",),
                 ("TotLen Bwd Pkts", "TotLen Fwd Pkts"), _bytes_ratio, False),
    FeatureGroup(16, 13, "sender_timing", "Sender timing", ("Fwd IAT Mean", "Fwd IAT Min"),
                 ("Fwd IAT Mean", "Fwd IAT Min"), _as_float(("Fwd IAT Mean", "Fwd IAT Min")), False),
    FeatureGroup(17, 14, "activity", "Activity pattern", ("Active Mean", "Idle Mean"),
                 ("Active Mean", "Idle Mean"), _as_float(("Active Mean", "Idle Mean")), False),
    FeatureGroup(18, 15, "payload_signals", "Payload signals", ("PSH Flag Cnt", "data_share"),
                 ("PSH Flag Cnt", "Fwd Act Data Pkts", "Tot Fwd Pkts"), _payload_signals, False),
)
PORT_WINDOW_NOTE = ("Feature 12 counts flows to the same destination port in the previous 10 seconds of the "
                    "same capture file. The group planned it with the destination IP (Week 3 feature 7, now feature 1), "
                    "but the published 21 Feb file has no Dst IP column, so update 4 used the port instead.")
GROUP_7_NOTE = PORT_WINDOW_NOTE   # older name
IP_WINDOW_NOTE = ("Features 1 to 3 count, over the previous 10 seconds of the same capture file, the flows to the "
                  "same destination IP, the distinct source IPs that reached the same destination IP and the flows "
                  "from the same source IP. They need the Src IP and Dst IP columns (the published 21 Feb file has "
                  "neither; the 21 Feb capture rebuilt from the raw packets has both). Addresses are used only to "
                  "count flows and are never model inputs.")

# Column order matters for a trained model. In every set the columns are listed in the order the
# model was trained with. f7ip (update 5, the default) = 1-6 in that order. The older sets use the
# app numbers of the original catalogue: the original nine (week 3: 1, 2, 4, 5, 6, then the derived
# ratio 3) are app groups 7, 8, 9, 10, 11, 4; f9p (update 4) replaces SYN (10) with the port window (12);
# f15 = f9 + 13, 14, 5, 6; f14 = f15 without SYN; f21 = f14 + 15-18 (update 3).
FEATURE_SETS = {"f7ip": (1, 2, 3, 4, 5, 6),
                "f9p": (7, 8, 9, 11, 4, 12),
                "f9": (7, 8, 9, 10, 11, 4),
                "f15": (7, 8, 9, 10, 11, 4, 13, 14, 5, 6),
                "f14": (7, 8, 9, 11, 4, 13, 14, 5, 6),
                "f21": (7, 8, 9, 11, 4, 13, 14, 5, 6, 15, 16, 17, 18)}
DEFAULT_FEATURE_SET = "f7ip"

_BY_NUMBER = {g.number: g for g in REGISTRY}
_BY_KEY = {g.key: g for g in REGISTRY}
# Week 3 feature 7 has two versions (1 = destination IP, the document's; 12 = update 4's port version): the
# lower app number wins here, so group_week3(7) is the destination-IP window.
_BY_WEEK3 = {g.week3: g for g in reversed(REGISTRY) if g.week3 is not None}
_BY_COLUMN = {c: g for g in REGISTRY for c in g.output_columns}


def group(number: int) -> FeatureGroup:
    return _BY_NUMBER[number]


def group_by_key(key: str) -> FeatureGroup:
    return _BY_KEY[key]


def group_week3(number: int) -> FeatureGroup:
    """The group that the Week 3 document numbers `number` (older scripts and notes use those numbers)."""
    return _BY_WEEK3[number]


def group_of(column: str) -> FeatureGroup:
    return _BY_COLUMN[column]


def columns_for(feature_set: str) -> list[str]:
    return [c for n in FEATURE_SETS[feature_set] for c in _BY_NUMBER[n].output_columns]


FEATURES_F9 = columns_for("f9")      # the original nine columns
FEATURES_F15 = columns_for("f15")
FEATURES_F21 = columns_for("f21")    # update 3
FEATURES_F9P = columns_for("f9p")    # the update-4 default (the baseline the search compared against)
FEATURES_F7IP = columns_for("f7ip")  # the default (update 5)
ALL_COLUMNS = list(dict.fromkeys(FEATURES_F7IP + FEATURES_F15 + FEATURES_F21 + FEATURES_F9P))   # every registry column
CORE_COLUMNS = [c for c in ALL_COLUMNS if group_of(c).core]
CONTEXT_COLUMNS = [c for g in REGISTRY if g.window for c in g.output_columns]   # built from the whole file
CORE_RAW = list(dict.fromkeys(r for n in FEATURE_SETS["f9"] for r in _BY_NUMBER[n].required_raw))
# Numeric raw columns (coerced by clean_frame). The window groups' Timestamp, Dst Port and IPs stay text.
ALL_RAW = list(dict.fromkeys(r for g in REGISTRY for r in g.required_raw if r not in CONTEXT_RAW))
EXTRA_RAW = [r for r in ALL_RAW if r not in CORE_RAW]     # Bwd Pkt Len Mean, RST/FIN Flag Cnt, ...


def groups_for(columns) -> list[FeatureGroup]:
    """The groups a column list uses, in registry order."""
    used = {group_of(c).number for c in columns}
    return [g for g in REGISTRY if g.number in used]


def feature_set_of(columns) -> str:
    """'f7ip', 'f9p', 'f9', 'f15', 'f14', 'f21' or 'custom' for a model's column list."""
    for name in FEATURE_SETS:
        if list(columns) == columns_for(name):
            return name
    return "custom"


def summary(columns) -> str:
    return f"{len(groups_for(columns))} feature groups ({len(columns)} columns)"


def column_label(column: str) -> str:
    """'no_reply (F5)': the column with its feature number."""
    g = _BY_COLUMN.get(column)
    return f"{column} (F{g.number})" if g else column


def required_raw(columns) -> list[str]:
    """CSV columns needed to build these model columns."""
    return list(dict.fromkeys(r for g in groups_for(columns) for r in g.required_raw))


# --- labels ----------------------------------------------------------------------------
def tool_of(label) -> str:
    """Map an inconsistent raw label to a tool name (order matters, as in the notebook)."""
    s = str(label).lower()
    if "benign" in s:
        return "Benign"
    if "udp" in s:
        return "LOIC-UDP"
    if "hoic" in s:
        return "HOIC"
    if "http" in s:
        return "LOIC-HTTP"
    return "Other"


def tools_from_labels(labels: pd.Series) -> pd.Series:
    # Map unique values only: millions of rows share a handful of labels.
    uniq = pd.unique(labels.astype(str))
    return labels.astype(str).map({u: tool_of(u) for u in uniq})


# --- cleaning and building -------------------------------------------------------------------
def normalise_columns(columns) -> list[str]:
    """CICFlowMeter headers sometimes carry stray spaces."""
    return [str(c).strip() for c in columns]


def missing_columns(header, columns=None) -> list[str]:
    """Raw CSV columns needed for `columns` (default: the original nine) that the header lacks."""
    have = set(normalise_columns(header))
    return [c for c in required_raw(columns or FEATURES_F9) if c not in have]


def clean_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Strip header names, drop repeated header rows, coerce numerics, inf -> NaN.

    Rows with NaN are NOT dropped here: training drops them (core columns only), the app
    reports them as "Not scored".
    """
    df = df.copy()
    df.columns = normalise_columns(df.columns)
    if LABEL in df.columns:
        df = df[df[LABEL].astype(str).str.strip() != LABEL]
    num = [c for c in ALL_RAW if c in df.columns]
    for c in num:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df[num] = df[num].replace([np.inf, -np.inf], np.nan)
    return df


def buildable_columns(df_columns) -> list[str]:
    """Registry columns whose raw inputs are all present (in model order)."""
    have = set(df_columns)
    return [c for c in ALL_COLUMNS if all(r in have for r in group_of(c).required_raw)]


def build_features(df: pd.DataFrame, columns=None) -> pd.DataFrame:
    """Build exactly `columns` (default: the original nine), in that order, as float64."""
    columns = list(columns or FEATURES_F9)
    parts = [g.build(df) for g in groups_for(columns)]
    X = pd.concat(parts, axis=1) if parts else pd.DataFrame(index=df.index)
    return X[columns].replace([np.inf, -np.inf], np.nan)


def valid_mask(X: pd.DataFrame) -> np.ndarray:
    """True for rows whose CORE inputs (the original nine columns, the window groups) are all finite
    (these can be scored). Missing values in the other groups (the indicators, timing regularity, reply
    behaviour, the flag counts, the update-3 groups) are allowed: the tree models handle them (the linear
    SVM cannot; scoring.score excludes such rows for it)."""
    core = [c for c in X.columns if c in _BY_COLUMN and group_of(c).core]
    return np.isfinite(X[core].to_numpy(dtype="float64")).all(axis=1)


def extra_missing_mask(X: pd.DataFrame) -> np.ndarray:
    """True for rows with a missing value in any non-core column."""
    extra = [c for c in X.columns if c in _BY_COLUMN and not group_of(c).core]
    if not extra:
        return np.zeros(len(X), dtype=bool)
    return X[extra].isna().to_numpy().any(axis=1)
