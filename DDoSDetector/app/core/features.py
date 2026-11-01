"""Feature registry, cleaning and feature building.

The ONE place that defines the model inputs. Training, scoring, SHAP charts, the Features panel
and the tests all read this registry; nothing else lists feature columns. Logic follows
notebooks/ddos_xgboost_starter_v2.ipynb (sections 5 and 6).

Feature groups are numbered as in Week 3 of the project document (1-15). Group 7 was planned as
flows to the same destination IP in a 10 s window and dropped because the 21 Feb file has no Dst IP.
Update 3 added groups 12-15 and dropped group 5 (SYN) from the set f21 (13 groups, 21 columns).
Update 4 (31 Oct 2026): the group settled on six feature groups. Group 7 came back as a port
version (flows to the same destination port in the previous 10 s), which replaces SYN in the
default set f9p (groups 1-4, 6 and 7, nine columns); f9 is the original nine. Groups 8-15 stay in
the registry for the notebook comparison. Each model's .meta.json lists the exact
`feature_columns` it was trained on, so 9-, 15- and 21-column models all load and score.

Group 7 is the only group built from many rows: it needs the whole capture file, so it must be
built on every row of a file (the app scores the whole loaded CSV; training builds it per file
before its own cleaning). Timestamp and Dst Port are used only to count flows; they are never
model inputs themselves.
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

# Feature 7 (update 4): read as text, used only to count flows. Counts never cross capture files:
# training concatenates files and marks each row's file in CAPTURE_COLUMN; the app opens one file.
PORT = "Dst Port"
CONTEXT_RAW = (TIME, PORT)
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


def _ratio(df):    # feature 3
    return pd.DataFrame({"fwd_bwd_ratio": df["Tot Fwd Pkts"].astype("float64")
                         / (df["Tot Bwd Pkts"].astype("float64") + 1)})


def _indicators(df):    # feature 10 (NaN inputs stay NaN rather than becoming 0)
    bwd, fwd = df["Tot Bwd Pkts"].astype("float64"), df["Fwd Pkt Len Mean"].astype("float64")
    return pd.DataFrame({"no_reply": (bwd == 0).astype("float64").where(bwd.notna()),
                         "empty_payload": (fwd == 0).astype("float64").where(fwd.notna())})


def _iat_cv(df):    # feature 11: inf (IAT mean of -1 exists in these files) becomes missing
    cv = df["Flow IAT Std"].astype("float64") / (df["Flow IAT Mean"].astype("float64") + 1)
    return pd.DataFrame({"iat_cv": cv.replace([np.inf, -np.inf], np.nan)})


def _bytes_ratio(df):    # feature 12 (update 3 candidate): reply bytes per request byte
    r = df["TotLen Bwd Pkts"].astype("float64") / (df["TotLen Fwd Pkts"].astype("float64") + 1)
    return pd.DataFrame({"bwd_fwd_bytes_ratio": r})


def _payload_signals(df):    # feature 15 (update 3 candidate)
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


def _port_window(df):    # feature 7 (update 4): flows to the same Dst Port in the previous 10 s
    """For a flow starting in second s: flows of the same capture file to the same destination
    port that started in seconds s-10 .. s-1 (looks back only, never at its own second).
    Missing or unreadable time or port -> missing (the row is then "Not scored")."""
    t = parse_timestamps(df[TIME])
    sec = np.floor((t - pd.Timestamp("1970-01-01")).dt.total_seconds())   # independent of datetime unit
    cap = df[CAPTURE_COLUMN] if CAPTURE_COLUMN in df.columns else pd.Series(0, index=df.index)
    key = pd.DataFrame({"cap": cap, "port": pd.to_numeric(df[PORT], errors="coerce"), "sec": sec}).dropna()
    out = pd.Series(np.nan, index=df.index, name="dst_port_flows_10s")
    if key.empty:
        return out.to_frame()
    c = key.groupby(["cap", "port", "sec"]).size().rename("n").reset_index().sort_values(["cap", "port", "sec"])
    c["before"] = c.groupby(["cap", "port"])["n"].cumsum() - c["n"]        # flows with sec < s
    look = c[["cap", "port", "sec"]].assign(target=c["sec"] - WINDOW_SECONDS).sort_values("target")
    right = c[["cap", "port", "sec", "before", "n"]].rename(columns={"sec": "rsec"}).sort_values("rsec")
    m = pd.merge_asof(look, right, left_on="target", right_on="rsec", by=["cap", "port"],
                      direction="backward", allow_exact_matches=False)   # last second before s-10
    m["before_window"] = (m["before"] + m["n"]).fillna(0)                   # flows with sec < s-10
    c = c.merge(m[["cap", "port", "sec", "before_window"]], on=["cap", "port", "sec"], how="left")
    c["count"] = c["before"] - c["before_window"]
    rows = key.reset_index().merge(c[["cap", "port", "sec", "count"]], on=["cap", "port", "sec"], how="left")
    out.loc[rows["index"].to_numpy()] = rows["count"].to_numpy(dtype="float64")
    return out.to_frame()


@dataclass(frozen=True)
class FeatureGroup:
    number: int                         # Week 3 feature number (1-15)
    key: str                            # group name used in metadata
    title: str                          # short human title
    output_columns: tuple[str, ...]     # model input columns this group produces
    required_raw: tuple[str, ...]       # CSV columns needed to build them
    build: Callable[[pd.DataFrame], pd.DataFrame]
    core: bool                          # original nine columns and feature 7: NaN/inf -> row "Not scored"

    @property
    def label(self) -> str:
        return f"F{self.number} {self.title}"


REGISTRY: tuple[FeatureGroup, ...] = (
    FeatureGroup(1, "rate", "Packet and byte rate", ("Flow Pkts/s", "Flow Byts/s"),
                 ("Flow Pkts/s", "Flow Byts/s"), _as_float(("Flow Pkts/s", "Flow Byts/s")), True),
    FeatureGroup(2, "duration", "Flow duration", ("Flow Duration",), ("Flow Duration",),
                 _as_float(("Flow Duration",)), True),
    FeatureGroup(3, "fwd_bwd_ratio", "Forward to backward packet ratio", ("fwd_bwd_ratio",),
                 ("Tot Fwd Pkts", "Tot Bwd Pkts"), _ratio, True),
    FeatureGroup(4, "inter_arrival", "Inter-arrival time", ("Flow IAT Mean", "Flow IAT Std"),
                 ("Flow IAT Mean", "Flow IAT Std"), _as_float(("Flow IAT Mean", "Flow IAT Std")), True),
    FeatureGroup(5, "syn_flag", "SYN flag count", ("SYN Flag Cnt",), ("SYN Flag Cnt",),
                 _as_float(("SYN Flag Cnt",)), True),
    FeatureGroup(6, "fwd_pkt_len", "Forward packet length", ("Fwd Pkt Len Mean", "Fwd Pkt Len Std"),
                 ("Fwd Pkt Len Mean", "Fwd Pkt Len Std"), _as_float(("Fwd Pkt Len Mean", "Fwd Pkt Len Std")), True),
    # Update 4 (31 Oct 2026): the port version of the group's dropped feature 7; in the default set f9p.
    FeatureGroup(7, "port_window", "Flows to the same destination port", ("dst_port_flows_10s",),
                 CONTEXT_RAW, _port_window, True),
    FeatureGroup(8, "reply", "Reply behaviour", ("Bwd Pkt Len Mean",), ("Bwd Pkt Len Mean",),
                 _as_float(("Bwd Pkt Len Mean",)), False),
    FeatureGroup(9, "conn_end_flags", "Connection-ending flags", ("RST Flag Cnt", "FIN Flag Cnt"),
                 ("RST Flag Cnt", "FIN Flag Cnt"), _as_float(("RST Flag Cnt", "FIN Flag Cnt")), False),
    FeatureGroup(10, "indicators", "No-reply and empty-payload indicators", ("no_reply", "empty_payload"),
                 ("Tot Bwd Pkts", "Fwd Pkt Len Mean"), _indicators, False),
    FeatureGroup(11, "timing_regularity", "Timing regularity", ("iat_cv",),
                 ("Flow IAT Std", "Flow IAT Mean"), _iat_cv, False),
    # Update 3 (22 Oct 2026): in the default set f21; tested in notebook 9b/9c.
    FeatureGroup(12, "response_ratio", "Response size ratio", ("bwd_fwd_bytes_ratio",),
                 ("TotLen Bwd Pkts", "TotLen Fwd Pkts"), _bytes_ratio, False),
    FeatureGroup(13, "sender_timing", "Sender timing", ("Fwd IAT Mean", "Fwd IAT Min"),
                 ("Fwd IAT Mean", "Fwd IAT Min"), _as_float(("Fwd IAT Mean", "Fwd IAT Min")), False),
    FeatureGroup(14, "activity", "Activity pattern", ("Active Mean", "Idle Mean"),
                 ("Active Mean", "Idle Mean"), _as_float(("Active Mean", "Idle Mean")), False),
    FeatureGroup(15, "payload_signals", "Payload signals", ("PSH Flag Cnt", "data_share"),
                 ("PSH Flag Cnt", "Fwd Act Data Pkts", "Tot Fwd Pkts"), _payload_signals, False),
)
GROUP_7_NOTE = ("Feature 7 counts flows to the same destination port in the previous 10 seconds of the "
                "same capture file. The group planned it with the destination IP, but the 21 Feb file has no "
                "Dst IP column, so the port is used instead.")

# Column order matters for a trained model. The original nine come first in the notebook's order
# (groups 1, 2, 4, 5, 6, then the derived ratio of group 3), then groups 8-11, then 12-15.
# f14 = f15 without SYN Flag Cnt (group 5); f21 = f14 + groups 12-15 (update 3).
# f9p = f9 with SYN replaced by group 7, the default since update 4.
FEATURE_SETS = {"f9": (1, 2, 4, 5, 6, 3), "f15": (1, 2, 4, 5, 6, 3, 8, 9, 10, 11),
                "f14": (1, 2, 4, 6, 3, 8, 9, 10, 11), "f21": (1, 2, 4, 6, 3, 8, 9, 10, 11, 12, 13, 14, 15),
                "f9p": (1, 2, 4, 6, 3, 7)}
DEFAULT_FEATURE_SET = "f9p"

_BY_NUMBER = {g.number: g for g in REGISTRY}
_BY_COLUMN = {c: g for g in REGISTRY for c in g.output_columns}


def group(number: int) -> FeatureGroup:
    return _BY_NUMBER[number]


def group_of(column: str) -> FeatureGroup:
    return _BY_COLUMN[column]


def columns_for(feature_set: str) -> list[str]:
    return [c for n in FEATURE_SETS[feature_set] for c in _BY_NUMBER[n].output_columns]


FEATURES_F9 = columns_for("f9")      # the original nine columns
FEATURES_F15 = columns_for("f15")
FEATURES_F21 = columns_for("f21")    # update 3
FEATURES_F9P = columns_for("f9p")    # the default (update 4)
ALL_COLUMNS = list(dict.fromkeys(FEATURES_F15 + FEATURES_F21 + FEATURES_F9P))   # every registry column
CORE_COLUMNS = [c for c in ALL_COLUMNS if group_of(c).core]
CONTEXT_COLUMNS = list(group(7).output_columns)   # built from the whole capture file, not one row
CORE_RAW = list(dict.fromkeys(r for n in FEATURE_SETS["f9"] for r in _BY_NUMBER[n].required_raw))
# Numeric raw columns (coerced by clean_frame). Feature 7's Timestamp and Dst Port stay text.
ALL_RAW = list(dict.fromkeys(r for g in REGISTRY for r in g.required_raw if r not in CONTEXT_RAW))
EXTRA_RAW = [r for r in ALL_RAW if r not in CORE_RAW]     # Bwd Pkt Len Mean, RST/FIN Flag Cnt


def groups_for(columns) -> list[FeatureGroup]:
    """The groups a column list uses, in registry order."""
    used = {group_of(c).number for c in columns}
    return [g for g in REGISTRY if g.number in used]


def feature_set_of(columns) -> str:
    """'f9', 'f15', 'f14', 'f21', 'f9p' or 'custom' for a model's column list."""
    for name in FEATURE_SETS:
        if list(columns) == columns_for(name):
            return name
    return "custom"


def summary(columns) -> str:
    return f"{len(groups_for(columns))} feature groups ({len(columns)} columns)"


def column_label(column: str) -> str:
    """'empty_payload (F10)': the column with its Week 3 feature number."""
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
    """True for rows whose CORE inputs (the original nine, feature 7) are all finite (these can be
    scored). Missing values in features 8-15 are allowed: XGBoost handles them."""
    core = [c for c in X.columns if c in _BY_COLUMN and group_of(c).core]
    return np.isfinite(X[core].to_numpy(dtype="float64")).all(axis=1)


def extra_missing_mask(X: pd.DataFrame) -> np.ndarray:
    """True for rows with a missing value in any non-core column (features 8-15)."""
    extra = [c for c in X.columns if c in _BY_COLUMN and not group_of(c).core]
    if not extra:
        return np.zeros(len(X), dtype=bool)
    return X[extra].isna().to_numpy().any(axis=1)
