"""About / Model card: honest framing and limitations, plus the active model's own metadata.

Results are NOT hard-coded for current models: every number comes from model metadata. The group's
recorded results are shown only for nine-column models, labelled as such (handoff update 2).
"""
from __future__ import annotations

import html

from PySide6.QtWidgets import QDialog, QDialogButtonBox, QTextBrowser, QVBoxLayout

from app.core.features import DROPPED_GROUP_7, column_label, feature_set_of, groups_for, summary
from app.core.model_store import held_out_results, model_columns

NINE_COLUMN_FINDING = ("Observed with the nine-column model: the model detects DDoS tools it was trained on "
                       "but does not transfer to unseen tools.")
FIFTEEN_COLUMN_FRAMING = ("Detection of known tools versus no transfer to unseen tools was observed with the "
                          "nine-column model. Whether that changes with this model's columns is what the "
                          "numbers below report; they come from the training script's own evaluation "
                          "(model metadata). Features 8 to 11 were added after the first experiments and 12 to 15 "
                          "in update 3; notebook section 9c and the Feature-set comparison tab report their effect.")

CALIBRATION_NOTE = ("The score is the model's raw output and has not been calibrated. Do not read 0.9 "
                    "as a 90% chance of an attack.")

SOC_WORKFLOW = (
    "Flows are scored by the model, and flows at or above the threshold are exported as alerts "
    "(File → Export alerts for SIEM) for a SIEM to ingest. An analyst reviews each alert with its SHAP "
    "explanation and records a verdict (confirmed attack, false positive or unsure), which is saved in a "
    "review file. Confirmed attacks and false positives are exported as new labelled examples (File → "
    "Export labelled feedback) and added to the training data when the model is retrained "
    "(train_model.py --extra-labelled). Retraining is periodic and manual, and would be triggered by "
    "drift in the traffic or a rise in the false alarm rate. This app is a prototype of that loop; it "
    "does not connect to a real SIEM or block anything.")

# The group's recorded results: nine-column model only (shown only for nine-column models).
NINE_COLUMN_RESULTS = [
    ("Random split, all 3 tools seen in training",
     "Recall HOIC 0.999, LOIC-HTTP 0.987, LOIC-UDP 1.000 (only 519 test flows); "
     "false positive rate 0.0084"),
    ("HOIC held out",
     "Recall 0.156 (per-day benign split) / 0.195 (by-file benign split) at threshold 0.5; "
     "at most about 0.40 at any threshold tried"),
    ("LOIC-HTTP held out", "Recall 0.003; false positive rate 0.0054"),
]

LIMITATIONS = [
    "Random-split results are an optimistic upper bound: near-duplicate flows from the "
    "same attack burst appear in both the training and the test set.",
    "Attack tool and capture day are confounded: LOIC-HTTP is only in the 20 Feb file, HOIC "
    "and LOIC-UDP only in the 21 Feb file.",
    "LOIC-UDP has only about 1,730 flows, so any LOIC-UDP result is noisy.",
    "Feature 7 (flows to the same destination in a window) was dropped: the 21 Feb file has no Dst IP "
    "column, so each flow is judged alone. IP addresses and timestamps are never model inputs.",
    "This is a university demo (COMP6310), not a production intrusion detection system. "
    "Scores on traffic from other networks, dates or tools should not be trusted.",
    "SHAP values explain the model, not the attack: they show what the model relies on, "
    "which may be an artefact of this dataset.",
]


def _metrics_html(meta: dict) -> str:
    m = meta.get("metrics") or {}
    if not m:
        return "<p><i>No evaluation metrics stored with this model.</i></p>"
    rows = "".join(f"<tr><td>Recall {html.escape(t)}</td><td>{r:.3f} (n={m.get('n_test', {}).get(t, 0):,})</td></tr>"
                   for t, r in m.get("recall", {}).items())
    if m.get("fpr") is not None:
        of = f" out of {m['n_test_benign']:,} benign" if "n_test_benign" in m else ""
        rows += (f"<tr><td>False positive rate</td><td>{m['fpr']:.4f} "
                 f"({m.get('false_alarms', 0):,} false alarms{of})</td></tr>")
    if "pr_auc" in m:
        rows += f"<tr><td>PR-AUC</td><td>{m['pr_auc']:.3f} (base rate {m['base_rate']:.3f})</td></tr>"
    sweep = " · ".join(f"t={s['threshold']}: recall {s['recall']:.3f}, FPR {s['fpr']:.4f}"
                       for s in m.get("threshold_sweep", []))
    return (f"<table cellpadding='3'>{rows}</table>"
            + (f"<p style='color:#52514e'>Threshold sweep: {sweep}</p>" if sweep else ""))


def _inputs_html(columns: list[str]) -> str:
    items = "".join(f"<li><b>F{g.number} {html.escape(g.title)}</b>: "
                    f"{html.escape(', '.join(c for c in g.output_columns if c in columns))}</li>"
                    for g in groups_for(columns))
    return (f"<h3>Model inputs: {summary(columns)}</h3><ul>{items}</ul>"
            f"<p style='color:#52514e'>{html.escape(DROPPED_GROUP_7)} Help → Features shows each feature's "
            "assumption next to what the data showed.</p>")


def model_card_html(meta: dict | None, timings=None, version: str = "", models_dir=None) -> str:
    columns = model_columns(meta or {})
    fset = feature_set_of(columns)
    nine = fset == "f9"
    out = ["<h2>Explainable DDoS detection: model card</h2>",
           "<p>COMP6310 group project: <i>Explainable Machine Learning for DDoS Attack Detection "
           "in Network Traffic</i>. XGBoost on CICFlowMeter flows from CSE-CIC-IDS2018 "
           "(20 and 21 Feb 2018), explained with SHAP (TreeExplainer).</p>",
           f"<p style='font-size:14px; padding:8px; background:#fdecec; border-left:4px solid #e34948'>"
           f"<b>{html.escape(NINE_COLUMN_FINDING if nine else FIFTEEN_COLUMN_FRAMING)}</b></p>"]
    if nine:
        out.append("<h3>Recorded project results (nine-column model)</h3>"
                   "<table border='1' cellspacing='0' cellpadding='5'><tr><th>Setting</th><th>Result</th></tr>"
                   + "".join(f"<tr><td>{html.escape(s)}</td><td>{html.escape(r)}</td></tr>"
                             for s, r in NINE_COLUMN_RESULTS) + "</table>"
                   "<p style='color:#52514e'>Recorded in an earlier notebook run whose duplicate check also used "
                   "the Dst IP column; the current pipeline removes slightly more duplicates, so this model's "
                   "own numbers below differ a little.</p>")
    out.append("<h3>Limitations</h3><ul>" + "".join(f"<li>{html.escape(x)}</li>" for x in LIMITATIONS) + "</ul>")
    out.append("<h3>Reading the scores</h3>"
               f"<p><b>{html.escape(CALIBRATION_NOTE)}</b></p>"
               "<p>The table's <b>model score</b> is a number from 0 to 1. SHAP values are in "
               "<b>log-odds</b>: base value + sum of SHAP values = the model's raw output f(x), and "
               "model score = 1 / (1 + e<sup>−f(x)</sup>). A flow is flagged DDoS when its score is at "
               "or above the threshold.</p>")
    out.append(_inputs_html(columns))
    out.append(f"<h3>How this fits a SOC workflow</h3><p>{html.escape(SOC_WORKFLOW)}</p>")

    if timings is not None and timings.lines():
        out.append("<h3>Timing of the last run (measured)</h3><ul>"
                   + "".join(f"<li>{html.escape(x)}</li>" for x in timings.lines()) + "</ul>")

    if meta:
        out.append(f"<h3>Active model: {html.escape(meta.get('title', '?'))}</h3>")
        info = [("Model version", version or meta.get("version")),
                ("Feature set", f"{fset}: {summary(columns)}"),
                ("Training mode", meta.get("mode")), ("Held-out tool", meta.get("held_out_tool") or "none"),
                ("Benign split", meta.get("benign_split")), ("Seed", meta.get("seed")),
                ("Created", meta.get("created")),
                ("Input columns", ", ".join(column_label(c) for c in columns)),
                ("Train rows", ", ".join(f"{k} {v:,}" for k, v in (meta.get("train_rows") or {}).items())),
                ("Test rows", ", ".join(f"{k} {v:,}" for k, v in (meta.get("test_rows") or {}).items())),
                ("Training time", _timing_text(meta.get("timing"))),
                ("Libraries", ", ".join(f"{k} {v}" for k, v in (meta.get("versions") or {}).items()))]
        out.append("<table cellpadding='3'>" + "".join(
            f"<tr><td valign='top'><b>{html.escape(k)}</b></td><td>{html.escape(str(v))}</td></tr>"
            for k, v in info if v is not None) + "</table>")
        out.append("<h4>Evaluation on this model's own test split (threshold 0.5, from its metadata)</h4>")
        out.append(_metrics_html(meta))
        if meta.get("mode") == "all_tools":
            out.append("<p style='color:#52514e'>Random split: optimistic upper bound (see limitations).</p>")
    if models_dir is not None:
        out.append(_held_out_html(held_out_results(models_dir, fset), fset))
    return "\n".join(out)


def _timing_text(t: dict | None) -> str | None:
    if not t:
        return None   # models trained before timing was recorded
    rate = t["predict_rows"] / t["predict_seconds"] if t.get("predict_seconds") else 0
    return (f"{t['train_seconds']:.1f} s on {t['train_rows']:,} rows; test prediction + metrics "
            f"{t['predict_seconds']:.2f} s for {t['predict_rows']:,} rows ({rate:,.0f} flows/s)")


def _held_out_html(rows: list[dict], fset: str) -> str:
    rows = [r for r in rows if r["held_out"]]
    if not rows:
        return (f"<p style='color:#52514e'>No held-out models with this feature set ({fset}) in the models "
                "folder.</p>")
    body = "".join(
        f"<tr><td>{html.escape(r['held_out'])}</td><td>{html.escape(r['split'].replace('_', '-'))}</td>"
        f"<td>{r['recall'].get(r['held_out'], float('nan')):.3f}</td>"
        f"<td>{r['n_test'].get(r['held_out'], 0):,}</td><td>{r['fpr']:.4f} ({r['false_alarms']:,})</td>"
        f"<td>{html.escape(r['name'])}</td></tr>"
        for r in sorted(rows, key=lambda r: (r["held_out"], r["split"])))
    note = ("With this nine-column model set, held-out LOIC-UDP was still caught almost entirely through "
            "fwd_bwd_ratio (~120,000 forward packets per backward packet, far beyond any benign or HOIC flow): "
            "one extreme value, on 1,730 flows, not evidence of transfer to unseen tools." if fset == "f9" else
            "LOIC-UDP has only about 1,730 flows, so its row is a stress test, not a reliable number.")
    return (f"<h3>Held-out results for every {fset} model in the models folder (from their metadata)</h3>"
            "<table border='1' cellspacing='0' cellpadding='4'><tr><th>Held-out tool</th><th>Benign split</th>"
            "<th>Recall on it</th><th>Test flows</th><th>FPR (false alarms)</th><th>Model</th></tr>"
            + body + "</table><p style='color:#52514e'>Each model's own test split, threshold 0.5. "
            f"Chart: Held-out comparison tab. {note}</p>")


class AboutDialog(QDialog):
    def __init__(self, meta: dict | None, parent=None, timings=None, version: str = "", models_dir=None):
        super().__init__(parent)
        self.setWindowTitle("About / Model card")
        self.resize(780, 760)
        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(True)
        self.browser.setHtml(model_card_html(meta, timings, version, models_dir))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(self.browser)
        lay.addWidget(buttons)
