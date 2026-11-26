"""Help -> Features: each feature group's Week 3 text next to what the data showed (notebook 9b).

Groups and columns come from the feature registry; the text from app/data/feature_notes.json; the
numbers only from feature_evidence.csv. Nothing here fills in numbers by itself.
"""
from __future__ import annotations

import html
from pathlib import Path

import pandas as pd
from PySide6.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QTextBrowser, QVBoxLayout

from app.core.feature_notes import (AUC_MARGIN, MISSING_EVIDENCE, NO_DIRECTION, NOT_SUPPORTED, OPPOSITE,
                                    SUPPORTED, UNCLEAR, assess, load_evidence, load_notes, notes_by_number)
from app.core.features import DEFAULT_FEATURE_SET, FEATURE_SETS, REGISTRY, columns_for, groups_for, summary
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


def _group_html(g, n: dict, notes: dict, evidence, in_default: bool, position: str = "") -> list[str]:
    """One group's section. Feature numbers are the app's (1-6 = the default model's inputs since 5 Nov 2026);
    the group's Week 3 document number is shown next to the columns."""
    out = []
    not_default = "" if in_default else " — not in the default set"
    week3 = f"; Week 3 document: feature {g.week3}" if g.week3 is not None else "; not in the Week 3 document"
    out.append(f"<h3>{position}Feature {g.number}: {html.escape(g.title)}{not_default} "
               f"<span style='color:#52514e; font-weight:normal'>({html.escape(', '.join(g.output_columns))}{week3})</span></h3>")
    if n.get("status") == "update4":
        out.append(f"<p style='color:#b85c00'>⚠ {html.escape(notes.get('update4_note', ''))}</p>")
    out.append("<table cellpadding='2'>")
    for key, label in _FIELDS:
        out.append(f"<tr><td valign='top' width='230'><b>{label}</b></td>"
                   f"<td>{html.escape(n.get(key, ''))}</td></tr>")
    out.append("</table>")
    for note in n.get("notes", []):
        out.append(f"<p style='color:#52514e'>{html.escape(note)}</p>")
    for col in g.output_columns:
        out.append(evidence_html(evidence, col, n["expected"].get(col, "none")))
    return out


def features_html(notes: dict, evidence: pd.DataFrame | None, columns=None, full: bool = True) -> str:
    """The inputs of `columns` (default: the default set) first, in the model's column order; with `full`
    the other registry groups follow, otherwise only a one-line pointer to them."""
    by_num = notes_by_number(notes)
    columns = list(columns) if columns is not None else columns_for(DEFAULT_FEATURE_SET)
    inputs = [g.number for g in groups_for(columns)]            # registry order
    fset = next((n for n, nums in FEATURE_SETS.items() if sorted(nums) == inputs), "custom")
    default = list(FEATURE_SETS[fset]) if fset != "custom" else inputs   # the model's column order
    label = f"default set {DEFAULT_FEATURE_SET}" if fset == DEFAULT_FEATURE_SET else f"loaded model's set {fset}"
    out = [f"<h2>Model features ({label}): {html.escape(summary(columns))}</h2>",
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
    by_number = {g.number: g for g in REGISTRY}
    out.append(f"<h2>Inputs of the {'default' if fset == DEFAULT_FEATURE_SET else 'loaded'} model ({fset}), "
               "in the model's column order</h2>")
    if any(by_num[n].get("status") == "update5" for n in default):
        out.append("<h3>Added in update 5 (5 Nov 2026): features 1 to 3</h3>"
                   f"<p style='color:#b85c00'>⚠ {html.escape(notes.get('update5_note', ''))}</p>")
    out.append("<p style='color:#52514e'>Features 1 to 6 are the model's inputs (the catalogue was renumbered on "
               "5 Nov 2026); each heading also gives the group's number in the Week 3 project document, and numbers "
               "inside the group's own text are those Week 3 numbers.</p>")
    for i, number in enumerate(default, start=1):
        out += _group_html(by_number[number], by_num[number], notes, evidence, True, f"Input {i} of {len(default)} · ")
    if not full:
        others = len(REGISTRY) - len(default)
        out.append(f"<p style='color:#52514e'>The registry holds {others} more feature groups (the update-4 baseline "
                   "f9p and the notebook comparisons). Tick \"Show the full catalogue\" to list them.</p>")
        return "\n".join(out)
    out.append("<h2>Other feature groups in the registry (not inputs of this model)</h2>"
               "<p style='color:#52514e'>Kept so that the update-4 baseline models (f9p: features 7, 8, 9, 11, 4 and 12) "
               "and models from the notebook comparisons can be opened and explained. Help → About lists the "
               "inputs of the model that is loaded.</p>")
    for g in REGISTRY:
        if g.number in default:
            continue
        n = by_num[g.number]
        if n.get("status") == "update3" and not any(by_num[p.number].get("status") == "update3"
                                                    for p in REGISTRY if p.number < g.number):
            out.append(f"<h3>Added in update 3</h3>"
                       f"<p style='color:#b85c00'>⚠ {html.escape(notes.get('update3_note', ''))}</p>")
        out += _group_html(g, n, notes, evidence, False)
    d = notes.get("dropped")
    if d:
        out.append(f"<h3>Feature {d['number']}: {html.escape(d['title'])} (dropped)</h3>"
                   f"<p><b>Assumption:</b> {html.escape(d['assumption'])}</p><p>{html.escape(d['status'])}</p>")
    return "\n".join(out)


class FeaturesDialog(QDialog):
    """Help -> Features. Shows the loaded model's inputs; a tick box adds the rest of the catalogue."""

    def __init__(self, parent=None, notes_path: Path = FEATURE_NOTES, evidence_path: Path = FEATURE_EVIDENCE,
                 columns=None):
        super().__init__(parent)
        self.setWindowTitle("Features: assumptions and evidence")
        self.resize(980, 820)
        self.columns = columns
        self.browser = QTextBrowser()
        self.full = QCheckBox("Show the full catalogue (all 18 feature groups, including the baseline's)")
        self.full.toggled.connect(self._render)
        try:
            self.notes, self.evidence = load_notes(notes_path), load_evidence(evidence_path)
            self.error = None
        except (OSError, ValueError, KeyError) as e:
            self.notes, self.evidence = None, None
            self.error = f"<p>Could not read the feature notes ({html.escape(str(notes_path))}): {html.escape(str(e))}</p>"
        self._render()
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(self.full)
        lay.addWidget(self.browser)
        lay.addWidget(buttons)

    def _render(self):
        if self.error:
            self.browser.setHtml(self.error)
            return
        try:
            self.browser.setHtml(features_html(self.notes, self.evidence, self.columns, full=self.full.isChecked()))
        except KeyError as e:          # a model with a column the notes file does not know
            self.browser.setHtml(f"<p>Could not describe this model's features: {html.escape(str(e))}</p>")
