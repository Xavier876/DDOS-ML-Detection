"""Help -> Features: each feature's assumption next to what the data showed (notebook 9b)."""
from __future__ import annotations

import html
from pathlib import Path

import pandas as pd
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QTextBrowser, QVBoxLayout

from app.core.feature_notes import AUC_MARGIN, MISSING_EVIDENCE, assess, load_evidence, load_notes
from app.paths import FEATURE_EVIDENCE, FEATURE_NOTES

_VERDICT_STYLE = {"supported": "#0b7a0b", "contradicted": "#c0392b", "not supported": "#b85c00",
                  "unclear": "#52514e"}
_FIELDS = [("raw_data", "Raw data needed"), ("calculation", "How it is calculated"),
           ("assumption", "Security assumption"), ("legitimate_lookalike", "Legitimate look-alike"),
           ("evasion", "How an attacker could evade it")]


def _num(v) -> str:
    return "n/a" if pd.isna(v) else f"{v:.4g}"


def evidence_html(evidence: pd.DataFrame | None, column: str, expected: str) -> str:
    if evidence is None:
        return f"<p><i>What the data showed:</i> {MISSING_EVIDENCE}</p>"
    rows = evidence[evidence["feature"] == column]
    if rows.empty:
        return f"<p><i>What the data showed:</i> no rows for this feature in feature_evidence.csv.</p>"
    out = ["<p><i>What the data showed</i> (each attack tool vs benign flows from the same day):</p>",
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
    out = [f"<h2>Model features: {html.escape(notes.get('summary', ''))}</h2>",
           f"<p style='padding:6px; background:#fff4e5; border-left:4px solid #b85c00'>"
           f"<b>{html.escape(notes['hypothesis_note'])}</b></p>"]
    if notes.get("draft"):
        out.append(f"<p style='color:#b85c00'>⚠ {html.escape(notes.get('source', 'Draft text.'))}</p>")
    if evidence is None:
        out.append(f"<p style='color:#b85c00'>⚠ Evidence file not found ({FEATURE_EVIDENCE.name}). "
                   f"{MISSING_EVIDENCE}</p>")
    out.append(f"<p style='color:#52514e'>How the verdict is decided: <b>supported</b> when the medians move "
               f"the expected way and the single-feature AUC is at least {AUC_MARGIN} from 0.5 on the expected "
               f"side; <b>contradicted</b> when the AUC is at least {AUC_MARGIN} on the other side; <b>not "
               f"supported</b> when the AUC is within {AUC_MARGIN} of 0.5 (the feature alone does not separate "
               "attack from benign); <b>unclear</b> when AUC and medians disagree. AUC 0.5 = no separation; "
               "above 0.5 = attacks have higher values; below = lower. A feature can still help the model in "
               "combination with others even when it does not separate on its own.</p>")
    for g in notes["groups"]:
        out.append(f"<h3>{html.escape(g['group'])}</h3>")
        for f in g["features"]:
            out.append(f"<h4>{html.escape(f['column'])}</h4><table cellpadding='2'>")
            for key, label in _FIELDS:
                extra = (f" <i>(expects attacks to be {f['expected_direction']})</i>"
                         if key == "assumption" else "")
                out.append(f"<tr><td valign='top' width='190'><b>{label}</b></td>"
                           f"<td>{html.escape(f.get(key, ''))}{extra}</td></tr>")
            out.append("</table>")
            out.append(evidence_html(evidence, f["column"], f["expected_direction"]))
    if notes.get("dropped"):
        out.append(f"<h3>Dropped</h3><p>{html.escape(notes['dropped'])}</p>")
    return "\n".join(out)


class FeaturesDialog(QDialog):
    def __init__(self, parent=None, notes_path: Path = FEATURE_NOTES, evidence_path: Path = FEATURE_EVIDENCE):
        super().__init__(parent)
        self.setWindowTitle("Features: assumptions and evidence")
        self.resize(900, 800)
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
