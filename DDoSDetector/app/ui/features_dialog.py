"""Help -> Features: each feature group's Week 3 text next to what the data showed (notebook 9b).

Groups and columns come from the feature registry; the text from app/data/feature_notes.json; the
numbers only from feature_evidence.csv. Nothing here fills in numbers by itself.
"""
from __future__ import annotations

import html
from pathlib import Path

import pandas as pd
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QTextBrowser, QVBoxLayout

from app.core.feature_notes import (AUC_MARGIN, MISSING_EVIDENCE, NO_DIRECTION, NOT_SUPPORTED, OPPOSITE,
                                    SUPPORTED, UNCLEAR, assess, load_evidence, load_notes, notes_by_number)
from app.core.features import DEFAULT_FEATURE_SET, FEATURE_SETS, REGISTRY, columns_for, summary
from app.core.numbers import readable
from app.paths import FEATURE_EVIDENCE, FEATURE_NOTES

_VERDICT_STYLE = {SUPPORTED: "#0b7a0b", OPPOSITE: "#c0392b", NOT_SUPPORTED: "#b85c00", UNCLEAR: "#52514e",
                  NO_DIRECTION: "#52514e"}
_FIELDS = [("raw_data", "Raw data needed"), ("calculation", "How it is calculated"),
           ("behaviour", "Security behaviour"), ("assumption", "Assumption"),
           ("lookalike", "Could legitimate behaviour look the same?"),
           ("evasion", "Could an attacker avoid it?")]


def _num(v) -> str:
    return "n/a" if pd.isna(v) else readable(v)


def evidence_html(evidence: pd.DataFrame | None, column: str, expected: str) -> str:
    if evidence is None:
        return f"<p><i>What the data showed:</i> {MISSING_EVIDENCE}</p>"
    rows = evidence[evidence["feature"] == column]
    if rows.empty:
        return f"<p><i>What the data showed ({html.escape(column)}):</i> no rows in feature_evidence.csv. {MISSING_EVIDENCE}</p>"
    out = [f"<p><i>What the data showed for <b>{html.escape(column)}</b></i> (each attack tool vs benign flows "
           f"from the same file; expected: {html.escape(expected)}):</p>",
           "<table border='1' cellspacing='0' cellpadding='3'><tr><th>Tool</th><th>Attack median</th>"
           "<th>Benign median</th><th>Direction</th><th>Zero share (attack / benign)</th>"
           "<th>Single-feature AUC</th><th>Assumption</th></tr>"]
    for _, r in rows.iterrows():
        verdict, why = assess(expected, str(r["direction"]), r["single_feature_auc"])
        out.append(
            f"<tr><td>{html.escape(str(r['attack']))}</td><td>{_num(r['attack_median'])}</td>"
            f"<td>{_num(r['benign_median_same_day'])}</td><td>{html.escape(str(r['direction']))}</td>"
            f"<td>{r['attack_zero_share']:.0%} / {r['benign_zero_share']:.0%}</td>"
            f"<td>{_num(r['single_feature_auc'])}</td>"
            f"<td style='color:{_VERDICT_STYLE[verdict]}'><b>{verdict}</b>: {html.escape(why)}</td></tr>")
    out.append("</table>")
    return "".join(out)


def features_html(notes: dict, evidence: pd.DataFrame | None) -> str:
    by_num = notes_by_number(notes)
    default = FEATURE_SETS[DEFAULT_FEATURE_SET]
    out = [f"<h2>Model features (default set {DEFAULT_FEATURE_SET}): "
           f"{html.escape(summary(columns_for(DEFAULT_FEATURE_SET)))}</h2>",
           f"<p style='padding:6px; background:#fff4e5; border-left:4px solid #b85c00'>"
           f"<b>{html.escape(notes['hypothesis_note'])}</b></p>",
           f"<p style='color:#52514e'>Source: {html.escape(notes.get('source', ''))}</p>",
           f"<p style='color:#52514e'>{html.escape(notes.get('added_note', ''))}</p>",
           f"<p style='color:#52514e'>{html.escape(notes.get('direction_note', ''))}</p>"]
    if evidence is None:
        out.append(f"<p style='color:#b85c00'>⚠ Evidence file not found ({FEATURE_EVIDENCE.name}). "
                   f"{MISSING_EVIDENCE}</p>")
    out.append("<p style='color:#52514e'>How the verdict is decided: <b>supported</b> when the single-feature "
               f"AUC is at least {AUC_MARGIN} from 0.5 on the expected side and the medians agree; "
               f"<b>opposite of the assumption</b> when it is at least {AUC_MARGIN} on the other side; "
               f"<b>not supported so far</b> when it is within {AUC_MARGIN} of 0.5 (the feature alone does not "
               "separate attack from benign); <b>unclear</b> when AUC and medians disagree. For assumptions that "
               "only say 'different', any AUC at least "
               f"{AUC_MARGIN} from 0.5 counts. A feature can still help the model in combination with others "
               "when it does not separate on its own.</p>")
    for g in REGISTRY:
        n = by_num[g.number]
        if n.get("status") == "update3" and not any(by_num[p.number].get("status") == "update3"
                                                    for p in REGISTRY if p.number < g.number):
            out.append(f"<h2>Added in update 3</h2>"
                       f"<p style='color:#b85c00'>⚠ {html.escape(notes.get('update3_note', ''))}</p>")
        not_default = "" if g.number in default else " — not in the default set"
        out.append(f"<h3>Feature {g.number}: {html.escape(g.title)}{not_default} "
                   f"<span style='color:#52514e; font-weight:normal'>({html.escape(', '.join(g.output_columns))})</span></h3>")
        out.append("<table cellpadding='2'>")
        for key, label in _FIELDS:
            out.append(f"<tr><td valign='top' width='230'><b>{label}</b></td>"
                       f"<td>{html.escape(n.get(key, ''))}</td></tr>")
        out.append("</table>")
        for note in n.get("notes", []):
            out.append(f"<p style='color:#52514e'>{html.escape(note)}</p>")
        for col in g.output_columns:
            out.append(evidence_html(evidence, col, n["expected"].get(col, "none")))
    d = notes.get("dropped")
    if d:
        out.append(f"<h3>Feature {d['number']}: {html.escape(d['title'])} (dropped)</h3>"
                   f"<p><b>Assumption:</b> {html.escape(d['assumption'])}</p><p>{html.escape(d['status'])}</p>")
    return "\n".join(out)


class FeaturesDialog(QDialog):
    def __init__(self, parent=None, notes_path: Path = FEATURE_NOTES, evidence_path: Path = FEATURE_EVIDENCE):
        super().__init__(parent)
        self.setWindowTitle("Features: assumptions and evidence")
        self.resize(980, 820)
        self.browser = QTextBrowser()
        try:
            text = features_html(load_notes(notes_path), load_evidence(evidence_path))
        except (OSError, ValueError, KeyError) as e:
            text = f"<p>Could not read the feature notes ({html.escape(str(notes_path))}): {html.escape(str(e))}</p>"
        self.browser.setHtml(text)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(self.browser)
        lay.addWidget(buttons)
