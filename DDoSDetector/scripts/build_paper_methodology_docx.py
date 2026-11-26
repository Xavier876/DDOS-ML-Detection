r"""Methodology section of the group paper, in the IEEE conference template's styles.

    .\.venv\Scripts\python.exe DDoSDetector\scripts\build_paper_methodology_docx.py

Reuses the package parts (styles, numbering, footer, theme) of the IEEE "conference-template-letter.docx" and writes a
new word/document.xml holding only the Methodology section and the references it cites, in the template's two-column
layout. The text was drafted on 22 Nov 2026 from the project's current state (update 6: six features, three model
types, the relabelled capture days, the per-model threshold rule). Paste the section into the full paper; the
heading number and the reference numbers then follow the paper's own sequence.
"""
import re
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

TEMPLATE = Path(r"C:\Users\Xavie\OneDrive\Desktop\conference-template-letter.docx")
OUT = Path(r"C:\Users\Xavie\source\repos\DDOS-ML-Detection\docs\Paper_Methodology_section.docx")

body: list[str] = []


def run(text, italic=False, bold=False, sup=False):
    rpr = ""
    if italic or bold or sup:
        rpr = "<w:rPr>" + ("<w:b/>" if bold else "") + ("<w:i/>" if italic else "") + \
              ('<w:vertAlign w:val="superscript"/>' if sup else "") + "</w:rPr>"
    return f'<w:r>{rpr}<w:t xml:space="preserve">{escape(text)}</w:t></w:r>'


def runs(text):
    """*italic* markers inside a string."""
    out = []
    for part in re.split(r"(\*[^*]+\*)", text):
        if not part:
            continue
        out.append(run(part[1:-1], italic=True) if part.startswith("*") else run(part))
    return "".join(out)


def para(text, style="BodyText", ppr_extra=""):
    body.append(f'<w:p><w:pPr><w:pStyle w:val="{style}"/>{ppr_extra}</w:pPr>{runs(text)}</w:p>')


def h1(text):
    para(text, "Heading1")


def h2(text):
    para(text, "Heading2")


def p(text):
    para(text)


def bullet(text):
    para(text, "bulletlist")


def equation(lhs_text, number):
    """The template's equation style switches to the Symbol font; set Times New Roman on the runs explicitly."""
    tnr = '<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman"/>'
    out = []
    for part in re.split(r"(\*[^*]+\*)", lhs_text):
        if not part:
            continue
        it = "<w:i/>" if part.startswith("*") else ""
        txt = part[1:-1] if part.startswith("*") else part
        out.append(f'<w:r><w:rPr>{tnr}{it}</w:rPr><w:t xml:space="preserve">{escape(txt)}</w:t></w:r>')
    body.append('<w:p><w:pPr><w:pStyle w:val="equation"/></w:pPr><w:r><w:tab/></w:r>' + "".join(out)
                + f'<w:r><w:tab/></w:r><w:r><w:rPr>{tnr}</w:rPr><w:t>({number})</w:t></w:r></w:p>')


def table(title, header, rows, widths_pt):
    """Template-style table: 'tablehead' caption above, 'tablecolhead' header row, 'tablecopy' body."""
    para(title, "tablehead", "<w:keepNext/>")
    grid = "".join(f'<w:gridCol w:w="{int(w * 20)}"/>' for w in widths_pt)

    def cell(text, w, style):
        return (f'<w:tc><w:tcPr><w:tcW w:w="{w}pt" w:type="dxa"/><w:vAlign w:val="center"/></w:tcPr>'
                f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr>{runs(text)}</w:p></w:tc>')

    xml = ['<w:tbl><w:tblPr><w:tblW w:w="0pt" w:type="dxa"/><w:jc w:val="center"/><w:tblBorders>'
           '<w:top w:val="single" w:sz="2" w:space="0" w:color="auto"/><w:start w:val="single" w:sz="2" w:space="0" w:color="auto"/>'
           '<w:bottom w:val="single" w:sz="2" w:space="0" w:color="auto"/><w:end w:val="single" w:sz="2" w:space="0" w:color="auto"/>'
           '<w:insideH w:val="single" w:sz="2" w:space="0" w:color="auto"/><w:insideV w:val="single" w:sz="2" w:space="0" w:color="auto"/>'
           '</w:tblBorders><w:tblLayout w:type="fixed"/><w:tblLook w:firstRow="0" w:lastRow="0" w:firstColumn="0" w:lastColumn="0" '
           'w:noHBand="0" w:noVBand="0"/></w:tblPr>', f"<w:tblGrid>{grid}</w:tblGrid>",
           '<w:tr><w:trPr><w:cantSplit/><w:tblHeader/><w:jc w:val="center"/></w:trPr>'
           + "".join(cell(h, w, "tablecolhead") for h, w in zip(header, widths_pt)) + "</w:tr>"]
    for r in rows:
        xml.append('<w:tr><w:trPr><w:cantSplit/><w:jc w:val="center"/></w:trPr>'
                   + "".join(cell(c, w, "tablecopy") for c, w in zip(r, widths_pt)) + "</w:tr>")
    xml.append("</w:tbl>")
    body.append("".join(xml))
    body.append('<w:p><w:pPr><w:pStyle w:val="BodyText"/></w:pPr></w:p>')


def reference(text):
    body.append('<w:p><w:pPr><w:pStyle w:val="references"/><w:ind w:start="17.70pt" w:hanging="17.70pt"/></w:pPr>'
                + runs(text) + "</w:p>")


# =====================================================================================================
# CONTENT
# =====================================================================================================
h1("Methodology")
p("This section describes how the detector was built and how it was tested. The work went through several revisions, "
  "and rather than present only the final design we have tried to say where a decision was changed and why, because "
  "two of those changes (rebuilding one capture day from packets, and replacing the feature set) altered the results "
  "more than any modelling choice did. The overall approach is supervised: flow records with labels are used to train "
  "a classifier, the classifier scores new flows, and each score is explained with SHAP values [5]. Three model types "
  "are trained on identical data so that differences between them can be read as differences between learners rather "
  "than between experiments.")

h2("Data")
p("The data come from CSE-CIC-IDS2018 [1], a dataset recorded on a test network in Amazon Web Services with a victim "
  "organisation and a set of attacking machines outside it. We used the two days that contain denial-of-service "
  "floods: Tuesday 20 February 2018, on which the Low Orbit Ion Cannon (LOIC) was run in HTTP mode and then, briefly, "
  "in UDP mode against the server 172.31.69.25, and Wednesday 21 February 2018, with a LOIC-UDP flood in the morning "
  "and the High Orbit Ion Cannon (HOIC) in the afternoon against 172.31.69.28. All three attacks come from the same ten "
  "attacker addresses. The published files are flow records produced by CICFlowMeter version 3 [2], with 80 columns per "
  "flow and a label.")
p("We did not use the published 21 February file as it stands. Comparing it with the raw packet capture, which the "
  "dataset also provides, showed three problems: the file has no source or destination address columns; it is truncated "
  "at 1,048,575 rows, so roughly two thirds of the HOIC attack is absent; and 358,523 of its 360,833 rows labelled "
  "\u201cBenign\u201d are in fact HOIC connections that the exporter recorded from the server\u2019s side, together with "
  "1,598 ICMP replies to the UDP flood. The labelling appears to have keyed on the attacker as the flow source, which "
  "the exporter\u2019s timeout behaviour does not guarantee. We therefore reassembled flows for that day from the victim "
  "server\u2019s packets, following the exporter\u2019s rules (bidirectional flows on the five-tuple, a 120 s timeout, "
  "closure on the first FIN from either side or on RST, payload bytes, sample standard deviations, single-packet flows "
  "dropped), and verified the result flow by flow against the published file: every published HOIC and LOIC-UDP flow "
  "was reproduced, with the model columns agreeing to within one per cent. Labels were then assigned by address: a flow "
  "is an attack flow if either endpoint is one of the ten attacker addresses, and a reason column records whether it is "
  "attacker-to-victim traffic, a reply from the victim, or an ICMP reply. The group chose to keep the victim\u2019s "
  "replies labelled as attack by-products rather than benign. The 20 February file has the same fault on a smaller "
  "scale (797 UDP-flood flows labelled LOIC-HTTP and 702 ICMP replies labelled benign); we corrected those 1,629 labels "
  "by the same rule and converted the file\u2019s 12-hour timestamps to 24-hour, which matters for the time-based splits "
  "described below. Table I summarises what remained after cleaning.")
table("Flows used for training and testing, after cleaning",
      ["Class", "20 Feb", "21 Feb", "Total"],
      [["Benign", "7,180,931", "1,982", "7,182,913"],
       ["HOIC", "\u2013", "2,116,841", "2,116,841"],
       ["LOIC-HTTP", "575,506", "\u2013", "575,506"],
       ["LOIC-UDP", "1,499", "3,328", "4,827"]],
      [60, 60, 60, 60])
p("Two features of the benign side should be stated plainly. On 20 February the benign traffic is a whole corporate "
  "network for a day; on 21 February only 1,982 flows are genuinely benign, most of them administrative (IKE, SSH, "
  "SMB) traffic at the victim server. LOIC-UDP is small in flows but not in packets: each flood flow lasts the full "
  "120 s timeout and carries about 130,000 packets.")

h2("Flow records and cleaning")
p("A row is one bidirectional flow. The exporter ends a flow after 120 s, at the first FIN, or at an RST, so a long HTTP "
  "connection may appear as several rows and an HTTP exchange is often split into two flows, the request and response "
  "followed by a short tail. We mention this because several recall figures in our results sit near one half, which "
  "we read as a model recognising one of the two halves. Cleaning follows the group\u2019s starter notebook: repeated "
  "header rows are removed, numeric columns coerced, infinite values treated as missing, and rows that are duplicates on "
  "the original columns dropped. The duplicate check deliberately ignores the port, the addresses and the window "
  "features, so that it gives the same row count as earlier runs. A row with a missing value in a core input is never "
  "silently dropped: the application shows it as \u201cnot scored\u201d, and training leaves it out and reports the "
  "count per file. The same code performs cleaning and feature construction for training and for scoring, which we "
  "found necessary after an early version drifted between the two.")

h2("Feature engineering")
p("The feature set went through four versions. The group\u2019s initial set used the nine per-flow columns commonly "
  "taken from this dataset (packet and byte rates, duration, inter-arrival statistics, SYN count and forward packet "
  "lengths) plus a derived forward-to-backward packet ratio; later versions added reply, flag, timing and payload "
  "groups and, when the destination address was not available, a window count keyed on the destination port. None "
  "of these transferred to an attack tool that had been held out of training. The final set was chosen by asking what "
  "a flooding attack cannot avoid producing at its target, a framing we took from the characterisation of floods and "
  "flash crowds in [8] and [9]: volume on one destination, many or repeating senders, requests the target cannot answer "
  "in kind, and machine-like timing. Table II lists the six groups (seven columns) in the order the model receives them.")
table("Model inputs (feature set f7ip)",
      ["#", "Column", "Definition"],
      [["1", "dst_ip_flows_10s", "flows to the same destination address that started in the previous 10 s"],
       ["2", "dst_ip_src_ips_10s", "distinct source addresses with a flow to that destination in the previous 10 s"],
       ["3", "src_ip_flows_10s", "flows from the same source address in the previous 10 s"],
       ["4", "fwd_bwd_ratio", "forward packets / (backward packets + 1)"],
       ["5", "no_reply, empty_payload", "1 if no backward packet; 1 if mean forward packet length is 0"],
       ["6", "iat_cv", "inter-arrival std. dev. / (mean + 1)"]],
      [14, 80, 146])
p("The three window features are counted over the whole capture file rather than from the row alone. For a flow "
  "starting in second *s*, feature 1 is")
equation("*f*1(*x*) = |{ *y* : dst(*y*) = dst(*x*), *s* \u2212 10 \u2264 *t*(*y*) \u2264 *s* \u2212 1 }|", 1)
p("where *t*(*y*) is the start second of flow *y* and the set is restricted to the same capture file. Features 2 and 3 "
  "are defined in the same way with the distinct source addresses and the source address respectively. The window "
  "looks back only and excludes the current second, so a value never depends on traffic that arrives later; this is "
  "what makes the feature computable as traffic arrives in a live deployment. Timing regularity is")
equation("iat_cv = *\u03c3* / (*\u03bc* + 1)", 2)
p("with \u03c3 and \u03bc the standard deviation and mean of the packet inter-arrival times reported by the exporter; "
  "an infinite value (the exporter writes a mean of \u22121 for some flows) is treated as missing. Addresses, ports and "
  "timestamps are used only to count flows and are never model inputs, which is a rule the group set in week 2 and "
  "which we have kept. One consequence is that the window features require the complete capture: on a random sample "
  "of rows the counts are far too low, so our test files are whole time slices.")

h2("Feature selection")
p("Which six groups to keep was decided by a search rather than by preference, run on the two files above with all "
  "three model types, in the spirit of the wrapper approach to feature selection [6]: a candidate subset is judged by "
  "the model it produces, here on an attack tool the model never saw. The search had three stages. In the first, the "
  "earlier six-group set was compared with the same set plus each of twelve candidate groups, for two random seeds and "
  "each of the three tools held out in turn, with attack rows capped at 500,000 per tool to keep the number of fits "
  "manageable. A candidate was accepted only if, for every seed, its recall on the held-out tool exceeded the best "
  "recall of the base set without a higher false-alarm rate; this rule had been agreed before the search ran. In the "
  "second stage a forward selection added, from nothing, the group that most raised the mean held-out recall across the "
  "three tools (subject to a 2% false-alarm ceiling), per model type, up to eight groups. In the third stage the base "
  "set and each model type\u2019s best six and best eight were refitted without row caps, for two seeds and every "
  "split. The set in Table II is the one that held up for all three model types; an eight-group alternative helped "
  "the random forest only and cost the other two learners on an unseen tool, so we stopped at six. Every fit of the "
  "search is recorded in a results file in the repository. We should note that the search ran on the published 20 "
  "February labels; the label correction described above came afterwards and changed one of its conclusions, which we "
  "report in the results rather than hide here.")

h2("Models")
p("XGBoost [3] is the main model, with a random forest and a linear support vector machine from scikit-learn [4] as "
  "comparisons; the forest tests whether boosting matters, and the linear model shows what a single boundary through "
  "the inputs can do while keeping the explanations easy to check by hand. None of the settings was tuned. XGBoost uses "
  "300 trees of depth 6, a learning rate of 0.1, the histogram method, and a positive-class weight equal to the "
  "benign-to-attack ratio of the training split. The forest uses 100 trees of depth at most 12 with at least 20 flows "
  "per leaf and balanced class weights; a deeper forest gave the same recall to three decimals but made SHAP "
  "explanations several times slower in the application. The SVM is a LinearSVC with C = 1 and balanced class weights, "
  "on inputs transformed by sign(x)\u00b7log(1 + |x|) and standardised, because the counts and ratios span several "
  "orders of magnitude; its decision value is passed through a logistic function so that all three models produce a "
  "score between 0 and 1. The score is not calibrated and is reported as a model score, not a probability.")

h2("Evaluation protocol")
p("Every model is trained and evaluated by one script that loads the two files, cleans them, builds the features per "
  "file, splits, fits, and stores its test metrics with the saved model, so that the application only ever displays "
  "numbers that were measured. Two kinds of split are used. The all-tools split is a random 70/30 division stratified "
  "by tool, with benign flows capped at one million; it is an optimistic upper bound, since near-identical flows from "
  "one burst land on both sides and the window counts of training and test flows come from the same seconds. The "
  "held-out split trains on two attack tools plus benign traffic and tests on the third, which the model has never "
  "seen; this is the test the project is really about. The benign test flows for a held-out model are chosen in three "
  "ways: the later 30% of each file\u2019s benign flows by time (per day, 2,154,875 flows), the later file\u2019s "
  "benign flows only (by file, the 1,982 flows of 21 February), or only the benign flows inside the held-out "
  "attack\u2019s time window (attack period). The per-day split is the main result; the other two are small and we "
  "use them to look at the cost of window features on benign traffic at the attacked server.")
p("Recall is reported per tool and the false-positive rate on benign flows, together with precision\u2013recall and ROC "
  "areas [7] and a sweep of thresholds from 0.9 to 0.001, because a single number at 0.5 turned out to hide a model "
  "that ranks an unseen tool correctly but scores it low. The alert threshold is set per model by a rule chosen from "
  "the benign side only: the lowest tested threshold whose false-alarm rate on the model\u2019s own benign test split is "
  "within 0.1%, falling back to 0.5 when no tested threshold qualifies. The rule does not look at the held-out tool, so "
  "an unseen attack never sets its own threshold. The all-tools models are trained with five seeds per type for a "
  "stability check of the explanations; the held-out models are seed 0, and the search used two seeds. No "
  "cross-validation was run. We are aware that choosing a threshold and reporting on the same test split is "
  "optimistic, and the results say so.")

h2("Explanations and prototype")
p("Each scored flow is explained with SHAP values [5]: TreeExplainer for the two tree models and, for the linear SVM, "
  "the exact contribution of each standardised input times its weight. In every case the base value plus the sum of "
  "the contributions equals the model\u2019s raw output, in that model\u2019s own units (log-odds for XGBoost, a leaf "
  "share for the forest, a decision value for the SVM), and the score follows from it. The prototype is a desktop "
  "application in Python with PySide6 that opens a flow file, scores every row in a background thread, shows the flag, "
  "the score and a per-flow explanation, lets an analyst record a verdict, and exports alerts and labelled feedback that "
  "the training script accepts. A single feature registry is shared by training and the application, and an automated "
  "test fails if any other file lists model columns; 139 tests on synthetic data cover the feature calculations against "
  "hand-worked examples, the splits, every chart and every model type. The deployment design in which the same "
  "components run on network sensors is described later; what was built and measured is the prototype on recorded "
  "files.")

para("References", "Heading5")
reference("I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, \u201cToward generating a new intrusion detection dataset "
          "and intrusion traffic characterization,\u201d in *Proc. 4th Int. Conf. Inf. Syst. Secur. Privacy (ICISSP)*, "
          "Funchal, Portugal, 2018, pp. 108\u2013116.")
reference("A. H. Lashkari, G. Draper-Gil, M. S. I. Mamun, and A. A. Ghorbani, \u201cCharacterization of Tor traffic using "
          "time based features,\u201d in *Proc. 3rd Int. Conf. Inf. Syst. Secur. Privacy (ICISSP)*, Porto, Portugal, 2017, "
          "pp. 253\u2013262.")
reference("T. Chen and C. Guestrin, \u201cXGBoost: A scalable tree boosting system,\u201d in *Proc. 22nd ACM SIGKDD Int. "
          "Conf. Knowl. Discovery Data Mining*, San Francisco, CA, USA, 2016, pp. 785\u2013794.")
reference("F. Pedregosa et al., \u201cScikit-learn: Machine learning in Python,\u201d *J. Mach. Learn. Res.*, vol. 12, "
          "pp. 2825\u20132830, 2011.")
reference("S. M. Lundberg and S.-I. Lee, \u201cA unified approach to interpreting model predictions,\u201d in *Advances "
          "in Neural Information Processing Systems 30*, Long Beach, CA, USA, 2017, pp. 4765\u20134774.")
reference("I. Guyon and A. Elisseeff, \u201cAn introduction to variable and feature selection,\u201d *J. Mach. Learn. "
          "Res.*, vol. 3, pp. 1157\u20131182, 2003.")
reference("T. Fawcett, \u201cAn introduction to ROC analysis,\u201d *Pattern Recognit. Lett.*, vol. 27, no. 8, "
          "pp. 861\u2013874, 2006.")
reference("J. Jung, B. Krishnamurthy, and M. Rabinovich, \u201cFlash crowds and denial of service attacks: "
          "Characterization and implications for CDNs and web sites,\u201d in *Proc. 11th Int. Conf. World Wide Web*, "
          "Honolulu, HI, USA, 2002, pp. 293\u2013304.")
reference("J. Mirkovic and P. Reiher, \u201cA taxonomy of DDoS attack and DDoS defense mechanisms,\u201d *ACM SIGCOMM "
          "Comput. Commun. Rev.*, vol. 34, no. 2, pp. 39\u201353, 2004.")

# =====================================================================================================
# BUILD: the template's package with a new document.xml (its root tag and two-column section kept)
# =====================================================================================================
zin = zipfile.ZipFile(TEMPLATE)
src = zin.read("word/document.xml").decode("utf-8")
root_tag = src[src.index("<w:document"):src.index(">", src.index("<w:document")) + 1]
sects = re.findall(r"<w:sectPr.*?</w:sectPr>", src, flags=re.S)
two_col = next(s for s in sects if 'w:num="2"' in s)
two_col = re.sub(r' w:rsid\w*="[^"]*"', "", two_col)
document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' + root_tag + "<w:body>" + "".join(body)
            + two_col + "</w:body></w:document>")
with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        if item.filename == "word/document.xml":
            zout.writestr(item, document.encode("utf-8"))
        else:
            zout.writestr(item, zin.read(item.filename))
print("wrote", OUT, f"({len(body)} body elements)")
