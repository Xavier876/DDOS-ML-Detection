r"""Weeks 1-5 project document, written from scratch for the six-feature model (update 5, 5 Nov 2026).

Builds docs\Weeks_1_to_5_-_DDoS_Detection_Project_UPDATE5.docx by reusing the package parts (styles, numbering,
theme) of the previous build and writing a new word/document.xml. Numbers updated on 15 Nov 2026 to the models
retrained on the relabelled 20 Feb file (docs\retrain_on_relabelled_feb20_2026-11-05.md) and the update-6 notebook.
"""
import re
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(r"C:\Users\Xavie\source\repos\DDOS-ML-Detection")
OUT = ROOT / "docs" / "Weeks_1_to_5_-_DDoS_Detection_Project_UPDATE5.docx"
TEMPLATE = OUT          # the package parts (styles, numbering, theme) of the previous build are reused

BULLET, DECIMAL = "1001", "1004"
body: list[str] = []
_num_seq = 2000


def run(text, bold=False, italic=False):
    rpr = ("<w:rPr>" + ("<w:b/><w:bCs/>" if bold else "") + ("<w:i/><w:iCs/>" if italic else "") + "</w:rPr>") if (bold or italic) else ""
    return f'<w:r>{rpr}<w:t xml:space="preserve">{escape(text)}</w:t></w:r>'


def runs(text):
    """**bold** and *italic* markers inside a string."""
    out = []
    for part in re.split(r"(\*\*[^*]+\*\*|\*[^*]+\*)", text):
        if not part:
            continue
        if part.startswith("**"):
            out.append(run(part[2:-2], bold=True))
        elif part.startswith("*"):
            out.append(run(part[1:-1], italic=True))
        else:
            out.append(run(part))
    return "".join(out)


def para(text, style="BodyText", extra=""):
    body.append(f'<w:p><w:pPr><w:pStyle w:val="{style}"/>{extra}</w:pPr>{runs(text)}</w:p>')


def title(text):
    para(text, "Title")


def subtitle(text):
    para(text, "Subtitle")


def h1(text):
    body.append(f'<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr>{run(text)}</w:p>')


def h2(text):
    body.append(f'<w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr>{run(text)}</w:p>')


def h3(text):
    body.append(f'<w:p><w:pPr><w:pStyle w:val="Heading3"/></w:pPr>{run(text)}</w:p>')


def p(text):
    para(text)


def bullets(items):
    for it in items:
        body.append(f'<w:p><w:pPr><w:pStyle w:val="Compact"/><w:numPr><w:ilvl w:val="0"/><w:numId w:val="{BULLET}"/></w:numPr></w:pPr>{runs(it)}</w:p>')
    body.append('<w:p><w:pPr><w:pStyle w:val="BodyText"/></w:pPr></w:p>')


def numbered(items):
    """A fresh decimal list each time (its own w:num is added to numbering.xml)."""
    global _num_seq
    _num_seq += 1
    for it in items:
        body.append(f'<w:p><w:pPr><w:pStyle w:val="Compact"/><w:numPr><w:ilvl w:val="0"/><w:numId w:val="{_num_seq}"/></w:numPr></w:pPr>{runs(it)}</w:p>')
    body.append('<w:p><w:pPr><w:pStyle w:val="BodyText"/></w:pPr></w:p>')
    return _num_seq


def table(header, rows, widths=None, caption=None):
    n = len(header)
    widths = widths or [int(9000 / n)] * n
    grid = "".join(f'<w:gridCol w:w="{w}"/>' for w in widths)

    def cell(text, w, bold=False):
        keep = "<w:keepNext/>" if bold else ""           # the header row stays with the first body row
        return (f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/></w:tcPr><w:p><w:pPr><w:pStyle w:val="Compact"/>{keep}'
                f'<w:jc w:val="left"/></w:pPr>{runs("**" + text + "**") if bold and text else runs(text)}</w:p></w:tc>')

    xml = ['<w:tbl><w:tblPr><w:tblStyle w:val="Table"/><w:tblW w:type="pct" w:w="5000"/>'
           '<w:tblLook w:firstRow="1" w:lastRow="0" w:firstColumn="0" w:lastColumn="0" w:noHBand="0" w:noVBand="0" w:val="0020"/>'
           '<w:jc w:val="start"/></w:tblPr>', f"<w:tblGrid>{grid}</w:tblGrid>",
           '<w:tr><w:trPr><w:tblHeader w:val="true"/></w:trPr>' + "".join(cell(h, w, True) for h, w in zip(header, widths)) + "</w:tr>"]
    for r in rows:
        xml.append("<w:tr><w:trPr><w:cantSplit/></w:trPr>" + "".join(cell(str(c), w) for c, w in zip(r, widths)) + "</w:tr>")
    xml.append("</w:tbl>")
    body.append("".join(xml))
    if caption:
        para(caption, "TableCaption")
    else:
        body.append('<w:p><w:pPr><w:pStyle w:val="BodyText"/></w:pPr></w:p>')


def page_break():
    body.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')


# =====================================================================================================
# CONTENT
# =====================================================================================================
title("Explainable Machine Learning for DDoS Attack Detection in Network Traffic")
subtitle("COMP6310 group project, Weeks 1 to 5. Version of 15 November 2026, written for the six-feature model.")
p("This document answers the weekly questions of the project brief for the detector as it stands on 15 November 2026: "
  "a supervised model that scores network flows with six feature groups built from the traffic around each flow, "
  "explained with SHAP, with a desktop prototype that an analyst can use to review alerts. Every number in it comes "
  "from a run we can repeat (the training script's metadata, the Week 5 notebook or the feature-search results), and "
  "where something is a design rather than a thing we built, it says so. The numbers are those of the models retrained "
  "on 5 November after both capture days were relabelled from the raw packets; where an earlier result turned out to be "
  "contaminated by a labelling error, the text says what it was and why it changed.")
p("**Status of the feature choice.** The six features were chosen on 5 November 2026 from a search run on the 21 February "
  "capture rebuilt with IP addresses. The group had agreed on six feature groups on 31 October; this document uses the "
  "six that came out of the search and the group has not yet confirmed them. Section 7 of Week 3 shows the evidence so "
  "the group can decide.")

# ----------------------------------------------------------------------------------------- Week 1
page_break()
h1("Week 1: Defining our cybersecurity detection problem")
h2("1. The cybersecurity problem")
p("A distributed denial-of-service (DDoS) attack makes a service unavailable by sending it more traffic than it can "
  "handle. The attacker does not break in; it exhausts something: the server's connection table, its request handlers, "
  "its bandwidth, or the bandwidth of the link in front of it. The traffic comes from many machines at once, which is "
  "what makes it hard to stop by blocking one address, and each packet on its own can look like an ordinary request.")
p("The attacks in our data are the volumetric and application-layer floods produced by three public tools, run from "
  "ten attacking machines against one web server:")
bullets(["**HOIC** (High Orbit Ion Cannon): repeated HTTP requests over many short TCP connections; in our data 2.1 million "
         "flows in 55 minutes, the busiest attack.",
         "**LOIC-HTTP** (Low Orbit Ion Cannon, HTTP mode): also HTTP requests over TCP, at a lower rate per machine.",
         "**LOIC-UDP**: a UDP flood of 32-byte packets to port 80, run on both days; the server never answers, except "
         "with ICMP \"port unreachable\" messages. Few flows (each lasts the full 120-second timeout) but about 130,000 "
         "packets per flow: in packets it is the largest attack in the data."])
p("These three are the same family of attack (floods against one target) carried out by different programs. That "
  "distinction matters for the whole project: a detector that learns what one program's packets look like will not "
  "recognise the next program, while a detector that learns what a flood does to the target has a chance of doing so.")

h2("2. Detection target and scope")
p("The detector decides, for each network flow reaching the protected server, whether that flow is part of a DDoS attack. "
  "A flow is one conversation between two endpoints (the five-tuple of addresses, ports and protocol), summarised by the "
  "flow exporter CICFlowMeter into one record with counts, sizes and timings. The output is a flag (DDoS or Benign) and "
  "a model score for every flow, plus an explanation of which features drove the score.")
table(["In scope", "Out of scope"], [
    ["Flood attacks against a web server (HTTP floods and a UDP flood), as recorded in flow records.",
     "Other attack classes in the same dataset (brute force, web attacks, infiltration, botnet); we do not train on them."],
    ["Detecting an attack tool the model has never seen (the test we care most about).",
     "Attributing the attack to a person or organisation."],
    ["Producing alerts an analyst can read and act on, with a feedback path back to training.",
     "Blocking, rate-limiting or any automatic response; the prototype only exports alerts to a file."],
    ["One victim network over two days of recorded traffic (the data we have).",
     "Claims about busy production networks or other years; we have no such data to test on."],
], widths=[4500, 4500])

h2("3. Why this is a cybersecurity concern")
p("Availability is one of the three security properties, and a DDoS attacks it directly. The cost is lost service for every "
  "legitimate user for as long as the flood lasts, plus the staff time spent telling attack traffic from a sudden rush "
  "of real users (a \"flash crowd\"), which is the classic false alarm for this problem. A flood is also used as cover: "
  "while the operations team is busy, something else happens. Detection that is fast, explainable and honest about its "
  "uncertainty lets a security operations centre (SOC) respond early and with evidence, rather than guessing.")
p("For a machine-learning detector the specific concern is generalisation. Attack tools change; the thing that stays "
  "the same is what a flood must produce at the victim: many flows arriving at one target in a short time, from many "
  "senders or from senders that keep coming back, with requests the target cannot answer in kind, and with the regular "
  "timing of a program rather than a person. Our feature choice (Week 3) is built on exactly that list.")

h2("4. Expected detection output")
bullets(["**Per flow:** a flag (DDoS or Benign, decided by a threshold on the score), the model score from 0 to 1, and a "
         "SHAP explanation listing how much each of the seven input columns pushed the score up or down.",
         "**Per file or per time window:** counts of flagged flows, recall per attack tool when labels are present, and "
         "the false-positive rate on benign flows.",
         "**For the analyst:** the alert carries the flow's time, source and destination addresses and port (used for "
         "tracing only, never as model inputs), the score, the model version and the top features.",
         "**Not a probability.** The score is the model's raw output after training with class weights; 0.9 does not mean "
         "a 90 per cent chance of attack. We use the word \"model score\" throughout and never \"confidence\"."])

h2("5. Response after detection")
p("In the design (Week 5) a flagged flow becomes an alert in the SOC's SIEM. An analyst reviews it with its explanation, "
  "records a verdict (confirmed attack, false positive, unsure), and the confirmed and rejected alerts become new "
  "labelled examples for the next retraining. People approve every response; the detector never blocks anything by "
  "itself. The prototype implements the review and feedback steps on recorded files and exports the alerts as a file "
  "a SIEM could ingest.")

h2("6. Evidence of progress")
bullets(["A working desktop prototype (Python, PySide6) that opens flow CSVs, scores every flow, explains flows with SHAP, "
         "lets an analyst label them and exports alerts and feedback.",
         "A feature registry shared by training and the app, so a model can never be trained on columns the app does not build.",
         "Trained models for three model types (XGBoost, Random Forest, linear SVM) on the same splits, with their test "
         "results stored as metadata the app displays.",
         "The 21 February attack capture rebuilt from the raw packets, because the published flow file for that day has no "
         "IP addresses and mislabels most of its \"benign\" rows, and the 20 February file relabelled where its labels were "
         "wrong (Week 2).",
         "A feature search over 18 candidate groups and all three model types, which produced the six features.",
         "Automated tests (137) that check the pipeline on synthetic data, and a Week 5 notebook with the threshold and "
         "retraining evidence."])

h2("7. Questions we should be ready to answer")
bullets(["Why flows and not packets? A flow record is what the exporter and the SIEM already produce, it is small enough to "
         "score at hundreds of thousands per second, and the flood signal is visible at flow level once we count the flows "
         "around each flow.",
         "Why not a rule such as \"more than N requests per second\"? A fixed rule needs N for every server and misses slow "
         "floods; the model combines several weak signals and reports its reasoning.",
         "What happens with a flash crowd? It raises the same window counts as a flood. We say so, we show the proxy check "
         "we could do, and we do not claim the model separates the two.",
         "How do we know the model is not memorising the tool? We hold each tool out of training and test on it (Week 4)."])

# ----------------------------------------------------------------------------------------- Week 2
page_break()
h1("Week 2: Detection approach, data and observations")
h2("1. Is the approach signature-based, behavioural, anomaly-based or hybrid?")
p("It is a **supervised behavioural** detector. There are no signatures (no byte patterns, no known addresses): the model "
  "learns from labelled examples what attack flows and benign flows look like, and the inputs describe behaviour, "
  "including the behaviour of the traffic around a flow in the previous ten seconds. It is not an anomaly detector: it "
  "does not model \"normal\" and flag departures from it, which is why it needs labelled attack data and why it can only "
  "be trusted on attack behaviour it has seen or that resembles it. The window features give it a hybrid flavour: a "
  "sudden rise in flows to one address is the kind of thing an anomaly detector would notice, here it is one input among six.")

h2("2. What security data will be used?")
p("The data is CSE-CIC-IDS2018, a public dataset recorded by the Canadian Institute for Cybersecurity on an AWS test "
  "network with a victim organisation and attacking machines outside it. We use the two DDoS days:")
table(["Day", "Attack", "What we use", "Rows after cleaning"], [
    ["Tuesday 20 Feb 2018", "LOIC-HTTP, then a short LOIC-UDP run, against 172.31.69.25",
     "The published flow CSV (whole network, with IP addresses), with 1,629 labels corrected and its 12-hour timestamps made 24-hour.",
     "Benign 7,180,931; LOIC-HTTP 575,506; LOIC-UDP 1,499"],
    ["Wednesday 21 Feb 2018", "LOIC-UDP in the morning, HOIC in the afternoon, against 172.31.69.28",
     "Flows rebuilt from the raw packet capture of the victim server, labelled by attacker address.",
     "HOIC 2,116,841; LOIC-UDP 3,328; Benign 1,982"],
], widths=[1500, 2200, 3000, 2300])
p("Why the 21 February day had to be rebuilt. The published flow file for that day has three defects we found by comparing "
  "it with the raw capture:")
bullets(["It has no source or destination IP columns, so flows cannot be grouped by target or sender, which the six features need.",
         "It is cut off at 1,048,575 rows (a spreadsheet limit), so about two thirds of the HOIC attack is missing.",
         "358,523 of its 360,833 \"Benign\" rows are HOIC flows recorded in the server-to-attacker direction, and 1,598 more are the "
         "server's ICMP replies to the UDP flood. The labelling had keyed on attacker source addresses, so a flow that "
         "the exporter happened to start from the server's side was called benign. Only about 2,000 flows of the day are "
         "genuinely benign."])
p("The 20 February file has the same kind of fault on a smaller scale: 797 flows of a LOIC-UDP run that afternoon are "
  "labelled LOIC-HTTP, the 702 ICMP replies to it are labelled benign, and 130 LOIC-HTTP connections recorded from the "
  "server's side are labelled benign. We corrected those 1,629 labels by the same attacker-address rule and converted the "
  "file's 12-hour timestamps to 24-hour (the published stamps sort the afternoon before the morning, which had silently "
  "changed what \"the earlier 70 per cent of the day\" meant in our time-based split).")
p("We downloaded the raw capture (53 GB), extracted the victim server's packets, reassembled flows with the same rules as "
  "the dataset's exporter (CICFlowMeter version 3: bidirectional flows, 120-second timeout, a flow closed by the first FIN "
  "from either side or by RST, single-packet flows dropped) and checked the result flow by flow against the published "
  "file: every published HOIC and LOIC-UDP flow is reproduced exactly, and the model columns agree within one per cent. "
  "We then labelled a flow as an attack flow when either end is one of the ten attacker addresses, with a column saying "
  "why (attacker to victim, victim reply, victim ICMP reply), and everything else as benign. The group chose to keep the "
  "server's replies labelled as attack by-products rather than benign; the consequence is visible in every LOIC-UDP "
  "result (section 6 of Week 4). Across both days LOIC-UDP is 4,827 rows: 2,527 flood flows and 2,300 reply rows.")

h2("3. What does one row of the final dataset represent?")
p("One row is one bidirectional flow: all packets between one source address and port and one destination address and "
  "port with one protocol, until the flow ends. The exporter ends a flow after 120 seconds of life, at the first FIN "
  "from either side, or at an RST. A long HTTP connection can therefore appear as several rows, and an HTTP exchange is "
  "often cut into two flows (the request and response, then a short tail), which is why some recall figures sit near "
  "one half when a model recognises only one of the halves.")
p("Each row carries the exporter's 80 columns (counts, byte totals, packet-length statistics, inter-arrival statistics, "
  "flag counts), the start time, the addresses and ports, and a label. The model reads seven derived columns from it "
  "(Week 3). Addresses, ports and timestamps are never model inputs; they are used to count flows and to trace alerts.")

h2("4. How are raw events converted into flows, sessions or windows?")
numbered(["**Packets to flows.** A packet capture at the victim (or a mirror port in the live design) goes through "
          "CICFlowMeter, which groups packets into flows and writes one record per flow. We reproduced this step in "
          "Python for the rebuilt day and verified it against the published output.",
          "**Flow records to clean rows.** Header rows repeated inside the file are dropped, numeric columns are coerced, "
          "infinite values become missing, and rows that are exact duplicates on the original columns are removed "
          "(the two files give 9,880,087 rows: Benign 7,182,913, HOIC 2,116,841, LOIC-HTTP 575,506, LOIC-UDP 4,827). A row with "
  "a missing value in a core column is kept and shown as "
          "\"Not scored\" in the app; training leaves such rows out and reports the count per file.",
          "**Rows to window features.** For each flow starting in second s, three counts are made over the flows of the "
          "same capture file that started in seconds s-10 to s-1: flows to the same destination address, distinct source "
          "addresses that reached that destination, and flows from the same source address. They look back only, so they "
          "can be computed while traffic arrives, and they must be computed over the whole file: a random sample of rows "
          "gives counts that are far too low.",
          "**Rows to the other inputs.** The forward/backward packet ratio, the two indicators and the timing-regularity "
          "ratio are arithmetic on the exporter's columns for that row alone."])
p("The same code (the feature registry in the app) performs steps 2 to 4 for training and for scoring, so a model is "
  "always scored on exactly the columns it was trained on, in the same order.")

h2("Progress this week")
p("The data pipeline above exists and is tested. The one open decision from this stage is the label for the server's "
  "replies in the UDP flood (attack by-product, as chosen, or benign): no model flags a reply row, so with the chosen "
  "label a model that has seen the flood tops out near 0.52 recall on LOIC-UDP in the all-tools split. The correction of "
  "the 20 February labels mattered more than we expected: it removed 797 flood flows from the training data of the "
  "models that were supposed never to have seen LOIC-UDP, and the result for that tool changed completely (Week 4).")

# ----------------------------------------------------------------------------------------- Week 3
page_break()
h1("Week 3: Feature engineering and security assumptions")
h2("Overview")
p("The model reads **six feature groups, seven columns**. Three are window counts over the previous ten seconds, "
  "built from the whole capture file; three are computed from the flow's own record. They were chosen by asking what "
  "a flood cannot avoid producing at the victim, and then testing that idea against 18 candidate groups with all three "
  "model types (section 7). Feature numbers below are the app's numbers (1 to 6 are the model's inputs in its column "
  "order); where a feature was in our earlier catalogue under another number, that number is given once.")

h2("1. Feature summary")
table(["#", "Feature (column)", "Raw data needed", "How it is calculated"], [
    ["1", "Flows to the same destination IP (dst_ip_flows_10s)", "Destination address and start time of every flow in the capture",
     "Number of flows to the same destination address that started in the ten whole seconds before this flow's start second"],
    ["2", "Distinct source IPs to the same destination IP (dst_ip_src_ips_10s)", "Source and destination addresses and start times of every flow",
     "Number of different source addresses that started at least one flow to the same destination address in those ten seconds"],
    ["3", "Flows from the same source IP (src_ip_flows_10s)", "Source address and start time of every flow",
     "Number of flows from the same source address that started in those ten seconds"],
    ["4", "Forward to backward packet ratio (fwd_bwd_ratio)", "Packets sent by the initiator and by the responder (Tot Fwd Pkts, Tot Bwd Pkts)",
     "Tot Fwd Pkts divided by (Tot Bwd Pkts + 1); the +1 avoids division by zero"],
    ["5", "No-reply and empty-payload indicators (no_reply, empty_payload)", "Responder packet count; mean length of the initiator's packets (Fwd Pkt Len Mean)",
     "no_reply = 1 when Tot Bwd Pkts is 0, else 0; empty_payload = 1 when Fwd Pkt Len Mean is 0, else 0"],
    ["6", "Timing regularity (iat_cv)", "Mean and standard deviation of the gaps between packets (Flow IAT Mean, Flow IAT Std)",
     "Flow IAT Std divided by (Flow IAT Mean + 1); an infinite result is treated as missing"],
], widths=[400, 2600, 2800, 3200])
p("Earlier catalogue numbers, for reading older notes: feature 1 was the group's Week 3 feature 7 (the destination-IP window the "
  "published data could not provide) and features 4, 5 and 6 were features 3, 10 and 11; the feature-search document of "
  "5 November labels the six F16, F18, F17, F3, F10 and F11.")

h2("2. How each feature is calculated")
p("**The three windows (1 to 3).** Every flow has a start time. We take its start second s and count, among the flows of "
  "the same capture file, those that started in seconds s-10 to s-1. For feature 1 the count is restricted to flows with "
  "the same destination address; for feature 3 to flows with the same source address; for feature 2 we count how many "
  "different source addresses appear among the flows to the same destination address in that window. Flows that start "
  "in the same second as the flow being scored are not counted, so the value never depends on anything that arrives "
  "later. A flow with no readable time or address gets no value and is shown as \"Not scored\".")
p("The counts are computed with a sorted cumulative count per key and a merge on the window boundary, so the whole "
  "20 February file (7.9 million flows) takes about thirty seconds; the app computes them for the file it opens, and the "
  "training script computes them per file before any cleaning, so a dropped duplicate still counts as traffic that "
  "arrived. Counts never cross files.")
p("**The ratio (4).** Packets from the initiator divided by packets from the responder plus one. A normal web exchange "
  "has a ratio near one; a flood the server cannot answer has a high ratio.")
p("**The indicators (5).** Two yes/no columns that say whether the server answered at all and whether the initiator sent "
  "any payload. They restate information in the counts and lengths, but they make explanations readable (\"no reply from "
  "the target\").")
p("**Timing regularity (6).** The standard deviation of the gaps between packets divided by the mean gap, a scale-free "
  "measure of how even the sending is. The dataset records a mean gap of -1 for some flows; the ratio is then infinite "
  "and is treated as missing (the tree models accept a missing value, the linear SVM leaves such rows unscored).")

h2("3. Feature justification and assumptions")
p("Each feature answers one question about what a flood must produce at the victim. The assumptions are hypotheses; "
  "section 6 says what the data showed for each.")
table(["#", "Security behaviour", "Assumption (direction)", "Why a flood cannot avoid it"], [
    ["1", "Volume on one target: many flows arriving at the same server at the same time.",
     "Higher during an attack than in normal operation.", "A flood works by volume; spreading it over time or targets stops it being a flood."],
    ["2", "Distribution: many different senders hitting the same target at once, the \"distributed\" in DDoS.",
     "Higher during an attack.", "Many senders are the point of a distributed attack; a single sender shows in feature 3 instead."],
    ["3", "Repetition: one sender opening flow after flow.",
     "Higher during an attack.", "Each attacking machine must send many requests to do damage; slowing each one down lowers the damage."],
    ["4", "One-sidedness: requests the target cannot answer in kind.",
     "Different from benign (higher when the target is overwhelmed; the HTTP tools sit near normal).", "An overwhelmed server answers less; a UDP flood is never answered."],
    ["5", "Whether the exchange happened at all and whether the request carried data.",
     "Higher (more flows with no reply or no payload).", "Cheap requests are what makes a flood affordable; real requests that get real replies cost the attacker more."],
    ["6", "Machine timing: a program sends at even intervals, a person does not.",
     "Lower (more regular) for a tool; in practice the direction differs by tool.", "The attacker can add random delays, at some cost in rate."],
], widths=[400, 3000, 2600, 3000])

h2("4. Relationship between raw data and features")
p("From the wire to the model: packets are captured at the victim (or at a mirror port in the live design); the exporter "
  "turns them into flow records with counts, lengths and timings; the three window features are counted over the "
  "records of the whole capture; the ratio, the indicators and the timing ratio are computed from the record itself; "
  "and the seven resulting columns, in a fixed order, are the model's inputs. Addresses and times are consumed by the "
  "counting step and go no further. The alert keeps them for the analyst.")
table(["Stage", "Produces", "Used by"], [
    ["Packet capture or mirror port", "Packets with time, addresses, ports, flags, lengths", "The flow exporter"],
    ["CICFlowMeter (or our verified reimplementation)", "One record per flow, 80 columns", "Cleaning and the registry"],
    ["Registry: window counts over the file", "Features 1, 2, 3", "The model"],
    ["Registry: per-flow arithmetic", "Features 4, 5, 6", "The model"],
    ["Registry: tracing fields", "Timestamp, Src IP, Dst IP, Dst Port (text)", "Alerts and the review table only"],
], widths=[3200, 3200, 2600])

h2("5. Limitations, evasion and false positives")
bullets(["**Flash crowds and busy servers.** A popular server, a product launch or a news event raises features 1 and 2 for "
         "legitimate traffic exactly as a flood does. Our benign data is one quiet network (the victim saw a median of "
         "seven flows per ten seconds outside the attacks), so we have not tested this case and do not claim to handle it. "
         "The prototype has a proxy check (false-positive rate among the busiest benign flows); it is a proxy, not a flash crowd.",
         "**Ten attacking machines.** Feature 2 learned that \"about ten senders\" means attack. A real botnet has hundreds or "
         "thousands, and a busy legitimate server has more than ten normal senders in ten seconds. Feature 1 (volume) is the "
         "more general of the two and we expect it to carry over better.",
         "**Proxies and NAT.** A gateway that carries many users starts many flows from one address and raises feature 3 "
         "for normal traffic.",
         "**Evasion.** An attacker can slow each machine (lowers 3), use more machines (raises 2, which is the point), "
         "send real requests that get real replies (lowers 4 and 5, at a higher cost per request) or randomise timing "
         "(defeats 6). No single feature is robust; the combination raises the attacker's cost.",
         "**Input requirements.** Features 1 to 3 need the source and destination address columns and the complete capture. "
         "A file without addresses cannot be scored by this model; the app then offers the earlier six-feature baseline "
         "(packet rates, duration, inter-arrival time, packet length, the ratio and a port-based window), which does not need them.",
         "**A UDP flood the model has not seen is missed entirely.** With the labels corrected, every model with LOIC-UDP held "
         "out catches 0 of its 2,527 flood flows at any threshold down to 0.01. Each flood flow lasts the full 120 seconds, so "
         "the windows see almost nothing, and on this network an unanswered flow is not unusual, so features 4 and 5 alone do "
         "not mark it as an attack. The six carry over between the two HTTP floods, not to a flood of a different kind.",
         "**Reply rows.** 2,300 of the 4,827 LOIC-UDP rows are the server's ICMP replies, labelled as attack by-products by our "
         "choice. No model flags them, which caps LOIC-UDP recall near 0.52 even for a model that has seen the flood."])

h2("6. What the data showed")
p("For each attack tool, the median of each column over the attack flows and over the benign flows of the same file, and "
  "the area under the ROC curve (AUC) of the column alone (1 = the column separates attack from benign perfectly, 0.5 = "
  "no separation). Computed on the same two files the models are trained on.")
table(["Column", "Tool", "Attack median", "Benign median", "AUC alone", "Reading"], [
    ["dst_ip_flows_10s (1)", "HOIC", "7,068", "0", "0.94", "supported"],
    ["", "LOIC-HTTP", "1,530", "8", "0.98", "supported"],
    ["", "LOIC-UDP", "4", "0", "0.72", "supported (few, long flows)"],
    ["dst_ip_src_ips_10s (2)", "HOIC", "11", "0", "0.93", "supported"],
    ["", "LOIC-HTTP", "10", "4", "0.56", "barely separates alone"],
    ["", "LOIC-UDP", "1", "0", "0.69", "supported"],
    ["src_ip_flows_10s (3)", "HOIC", "710", "0", "1.00", "supported"],
    ["", "LOIC-HTTP", "154", "8", "0.92", "supported"],
    ["", "LOIC-UDP", "6", "0", "0.95", "supported"],
    ["fwd_bwd_ratio (4)", "HOIC", "2.0", "1.7", "0.75", "higher, weak alone"],
    ["", "LOIC-HTTP", "0.6", "0.9", "0.62", "lower, weak alone"],
    ["", "LOIC-UDP", "119,759", "1.7", "1.00", "the flood is never answered"],
    ["no_reply (5)", "HOIC", "1", "0", "0.88", "supported"],
    ["", "LOIC-HTTP", "0", "0", "0.66", "weak alone"],
    ["", "LOIC-UDP", "1", "0", "1.00", "supported"],
    ["empty_payload (5)", "HOIC", "1", "0", "0.88", "supported"],
    ["", "LOIC-HTTP", "0", "0", "0.64", "weak alone"],
    ["", "LOIC-UDP", "0", "0", "0.50", "no separation (UDP packets carry 32 bytes)"],
    ["iat_cv (6)", "HOIC", "0.0", "1.3", "0.15", "attacks more regular, as assumed"],
    ["", "LOIC-HTTP", "2.4", "0.8", "0.57", "opposite: less regular"],
    ["", "LOIC-UDP", "20.1", "1.3", "1.00", "opposite: less regular"],
], widths=[2100, 1200, 1300, 1300, 1000, 2100])
p("Two honest notes. Feature 2 barely separates LOIC-HTTP on its own (ten attackers against a benign median of four senders), "
  "and timing regularity runs the opposite way for two of the three tools; both still help in combination, which is what "
  "the search measures. Feature 3 is the single strongest column for HOIC, and feature 4 alone identifies the UDP flood.")

h2("7. Final feature choice and how it was made")
p("The group agreed on six feature groups on 31 October 2026. Which six was decided by a search run on 5 November on the "
  "two files above, with all three model types, in three stages:")
numbered(["**One candidate at a time.** The earlier six (packet rate, duration, inter-arrival time, packet length, the ratio and "
          "the port window) against the same six plus each of twelve candidates, two seeds, every model type, on four "
          "splits: all tools seen, and each tool held out of training. The rule: a candidate is better only if every seed's "
          "recall on the held-out tool beats the base's best and false alarms do not rise. Only the address windows passed "
          "it, for every model type.",
          "**Forward selection.** Starting from nothing, add the group that most raises the mean held-out recall across the "
          "three tools (false alarms at most two per cent), per model type, up to eight groups. Every model type picked an "
          "address window first.",
          "**Final check without row caps.** The earlier six and each model type's best six and best eight, every model type, "
          "two seeds, all splits. The set that held up for all three types is the one in this document."])
p("Result on the honest test at the time of the search (the tool held out of training, benign flows split by time of day, "
  "seeds 0 and 1 averaged, threshold 0.5, the published 20 February labels):")
table(["Model type, unseen tool", "Earlier six (recall / false-alarm rate)", "These six (recall / false-alarm rate)"], [
    ["XGBoost, HOIC", "0.18 / 0.0023", "0.9999 / 0.0000"],
    ["XGBoost, LOIC-HTTP", "0.005 / 0.0011", "0.90 / 0.0000 (0.96 at threshold 0.01 after the relabel, 0.01 at 0.5; see Week 4)"],
    ["Random Forest, HOIC", "0.19 / 0.0049", "0.88 / 0.0000"],
    ["Random Forest, LOIC-HTTP", "0.0045 / 0.0011", "0.43 / 0.0000"],
    ["Linear SVM, HOIC", "0.49 / 0.018", "0.9999 / 0.0012"],
    ["Linear SVM, LOIC-HTTP", "0.16 / 0.022", "0.98 / 0.0004"],
    ["Any type, LOIC-UDP", "0.52 (not a held-out result: 797 flood flows sat in training under the wrong label)",
     "0.52 at the time; 0.000 once the labels were corrected"],
], widths=[3000, 3000, 3000])
p("The earlier six describe the attack tool (how big and fast its packets are), so a model trained on LOIC learns LOIC. "
  "These six describe the attack itself, and carry over between the two HTTP floods. They do not carry over to the UDP "
  "flood: the search's LOIC-UDP rows were contaminated by the 797 mislabelled flood flows, and the retrained models "
  "(Week 4) show 0.000 on it when it is held out. An eight-group set (these six plus the port window and the reply length) "
  "helped Random Forest only and cost XGBoost and the SVM on an unseen tool, so we stopped at six.")
p("**Decision needed from the group:** adopt these six as the project's feature set, or keep the 31 October six with these "
  "results as the comparison. This document and the prototype are written for the former.")

# ----------------------------------------------------------------------------------------- Week 4
page_break()
h1("Week 4: Machine-learning method and model development")
h2("Overview")
p("XGBoost is the main model. Random Forest and a linear support-vector machine are trained on exactly the same splits "
  "and columns as comparisons: the forest shows whether boosting matters, the linear model shows what a straight "
  "boundary through the inputs can do and makes the explanations easy to check by hand. All three live in the "
  "prototype and are scored and explained the same way.")

h2("1. Do reliable labels exist?")
p("Yes, with two qualifications. The dataset's labels come from the attack schedule and the attacker addresses, which is "
  "reliable for the attacker-to-victim flows. For the 21 February day we rebuilt the labels ourselves (Week 2) because "
  "the published ones called most of the HOIC traffic benign; we label by attacker address with a reason column, so "
  "every label can be checked. The remaining judgement is the label of the server's replies to the UDP flood, which the "
  "group chose to keep as attack by-products. Benign traffic is whatever the ten attackers did not touch: on 20 February "
  "that is a whole corporate network for a day (7.2 million flows), on 21 February only 2,002 flows at the victim server "
  "(mostly IKE, SSH and SMB administration traffic).")

h2("2. Why a supervised method?")
p("We have labelled examples of both classes, the question is a yes/no decision per flow, and we need to report recall on "
  "named attack tools and a false-positive rate on benign flows, which only a supervised set-up measures directly. An "
  "anomaly detector would need a model of normal traffic for this network and would flag every flash crowd; it is a "
  "sensible complement, not what the brief asks for.")

h2("3. Why does XGBoost fit the detection problem?")
bullets(["The inputs are counts and ratios on very different scales (a window count of 7,000 next to a ratio of 0.6); "
         "trees split on thresholds and do not care about scale.",
         "The useful boundaries are interactions (\"many flows to this target and no reply\"), which boosted trees learn without "
         "us writing them down.",
         "It accepts missing values, which the timing ratio produces.",
         "Class weights handle the imbalance between benign and attack flows without discarding data.",
         "It trains in about ten seconds on 2.6 million flows and scores hundreds of thousands of flows per second, and "
         "SHAP's TreeExplainer gives exact per-feature contributions for every flow, which the brief's \"explainable\" requires.",
         "Settings (not tuned): 300 trees, depth 6, learning rate 0.1, histogram method, class weight equal to the "
         "benign-to-attack ratio of the training set, fixed random seed."])
p("Random Forest: 100 trees, depth 12, at least 20 flows per leaf, balanced class weights (shallow enough for SHAP to "
  "stay fast in the app). Linear SVM: inputs log-scaled with their sign kept and standardised, C = 1, balanced class "
  "weights; its decision value is squashed to 0 to 1 so the app can show one score scale.")

h2("4. What features are given to the model?")
p("The seven columns of Week 3, in this order: dst_ip_flows_10s, dst_ip_src_ips_10s, src_ip_flows_10s, fwd_bwd_ratio, "
  "no_reply, empty_payload, iat_cv. Nothing else: no addresses, no ports, no timestamps, no packet rates or sizes. The "
  "feature list lives in one registry file that training and the app both import; a test fails if any other file lists "
  "model columns, and each saved model records its exact column list so the app builds exactly those.")

h2("5. What does the model output?")
p("A model score from 0 to 1 for \"DDoS\" and, at the model's threshold, a flag. The score is not calibrated: with "
  "class weights, 0.9 is not a 90 per cent chance of attack, and the three model types put their scores on different "
  "scales (XGBoost a sigmoid of log-odds, the forest a share of trees, the SVM a squashed decision value). The app "
  "therefore shows the score as \"model score\" and the flag, and the explanation of every scored flow: base value plus the "
  "seven SHAP contributions equals the model's output exactly, for each model type in its own units.")

h2("6. How will training and testing be carried out?")
p("Every model is trained by one script that loads the two files, cleans them, builds the features per file, splits, "
  "trains, evaluates on the test split at threshold 0.5 (and at eight lower thresholds, stored as a sweep) and stores the "
  "results with the model. Three kinds of split:")
bullets(["**All tools seen (random split):** benign flows capped at one million, all attack flows, 70/30 split stratified by "
         "tool. This is an optimistic upper bound: near-identical flows from the same burst land on both sides, and the window "
         "counts of training and test flows come from the same seconds.",
         "**One tool held out:** train on the other two tools plus benign, test on the held-out tool plus benign flows the "
         "model did not train on. Benign split by time (\"per day\": the later 30 per cent of each file's benign flows are the "
         "test, 2,154,875 flows), by file (the rebuilt 21 February day's 1,982 benign flows are the test) or by attack period "
         "(only the benign flows inside the held-out attack's time window are the test: 474 for HOIC, 900,104 for LOIC-HTTP). "
         "This is the test that matters: it asks whether the model detects a tool it has never seen.",
         "**Seeds:** the all-tools model is trained with five seeds per type for the explanation-stability chart; the "
         "held-out models are seed 0 (the search used two seeds; Random Forest varied between them)."])
p("No cross-validation was run; the splits above are the evaluation. Results of the shipped models (each model's own test "
  "split, threshold 0.5, from its metadata):")
table(["Model type", "All tools seen: recall HOIC / LOIC-HTTP / LOIC-UDP", "False alarms of 300,000 benign",
       "HOIC held out", "LOIC-HTTP held out", "LOIC-UDP held out", "False alarms of 2,154,875 benign (HOIC / LOIC-HTTP held out)"], [
    ["XGBoost", "1.000 / 1.000 / 0.989", "8", "1.000", "0.010 at 0.5; 0.96 at 0.01", "0.000", "74 / 18"],
    ["Random Forest", "1.000 / 1.000 / 0.973", "1", "0.755", "0.483", "0.000", "269 / 103"],
    ["Linear SVM", "1.000 / 0.999 / 0.500", "155", "1.000", "0.971", "0.000", "1,827 / 439"],
], widths=[1300, 1900, 1150, 1000, 1500, 1000, 1150])
p("How to read it. On the tools they saw, the three types are equally good at threshold 0.5 (the SVM's 0.50 on LOIC-UDP is the "
  "reply-row cap; the trees also flag the replies when they have seen them). On a tool they never saw: unseen HOIC is caught "
  "entirely by XGBoost and the SVM and three quarters of it by the forest, with 74, 1,827 and 269 false alarms among 2.15 "
  "million benign flows. Unseen LOIC-HTTP is caught by the SVM (0.97) and half of it by the forest; XGBoost scores it below "
  "its 0.5 line (recall 0.010 there) but ranks it correctly (precision-recall AUC 0.999): at threshold 0.01 it catches 0.96 "
  "with 1,076 false alarms (0.05 per cent), the same on three seeds. That is why the app now starts each model at its own "
  "threshold (section 4 of Week 5). Unseen LOIC-UDP is not caught by any model at any threshold. With the earlier six "
  "features the same per-day rows were 0.18 to 0.49 for HOIC and 0.005 to 0.16 for LOIC-HTTP, so the gain on the HTTP floods "
  "comes from the features, not the model type.")
p("The smaller benign test sets show the cost of window features. In the HOIC hour, 291 of the 474 genuinely benign flows go "
  "to the attacked server and look like HOIC in features 1 and 2 (about 7,000 flows to the destination, 11 senders); what "
  "sets them apart is feature 3 (0 flows from the same source, against 710 for HOIC). XGBoost flags 4 of the 474, the "
  "forest 71, the SVM 217. And trained on 20 February's benign traffic only, the forest and the SVM flag 10 to 15 per cent "
  "of the 21 February administration traffic, XGBoost half a per cent except for the LOIC-HTTP-held-out model (by file: "
  "0.149, recall 0.481), which is the same threshold effect as above seen on a different benign set.")
p("The 4 per cent of unseen LOIC-HTTP flows XGBoost still misses at threshold 0.01 have the same window counts as the flows "
  "it catches except for 12 distinct senders instead of 10; the model trained on HOIC's 11 and benign traffic's 4 never saw "
  "12. That is the ten-machine limit in one number: feature 2 learned a count, not \"many\". The split points tell the same "
  "story the other way: the HOIC-trained model's upper splits sit at about 3,960 flows to the destination, 12 sources and "
  "436 flows per source, and LOIC-HTTP (1,530 / 10 / 154) falls below all three, in a range the busiest one per cent of "
  "20 February's benign flows also reach. Transfer worked from the smaller flood to the bigger one, not the other way round. "
  "The unseen UDP flood is missed for a different reason: each flow is alone in its window (feature 1 of about 5 pushes the "
  "score towards benign), and the model's ratio splits, learned on floods that are answered, treat an unanswered high-ratio "
  "flow like the benign scans it saw in training.")

h2("7. Prototype and tools")
bullets(["Python 3.14, pandas, scikit-learn, XGBoost, SHAP, PySide6 (Qt) for the desktop app; matplotlib for the charts.",
         "The app opens a flow CSV, scores it in a background thread (about 170,000 flows per second on the sample), shows every "
         "flow with its flag and score, explains the selected flow with a SHAP waterfall, and has fourteen charts: global "
         "importance, beeswarm, SHAP by tool, operational impact (confusion matrix at the chosen threshold), threshold sweep, "
         "a flash-crowd proxy, explanation stability across seeds and across models, held-out comparison, and the three-model comparisons.",
         "The analyst can label flows (confirmed, false positive, unsure), save the review, export alerts as CSV and JSON Lines "
         "for a SIEM, and export confirmed and rejected flows as labelled feedback that the training script accepts.",
         "A feature registry shared by training and the app; a model card built only from metadata; 137 automated tests on "
         "synthetic data covering the feature calculations (hand-worked examples), the splits, every chart and every model type."])

h2("8. Progress and discussion")
p("All three model types are trained and in the app for both feature sets (these six and the 31 October six as the "
  "baseline). The results above are measured, not projected. The relabelling taught us two things about evaluation: a "
  "held-out test is only as honest as the labels that define it (797 mislabelled flows turned a 0.52 into a 0.000), and a "
  "single number at threshold 0.5 can hide a model that ranks the attack correctly but scores it low. Three things we would "
  "do with more time: train the held-out models with several seeds (the forest varies most), test on a busy legitimate "
  "server or a flash crowd if any such labelled data can be found, and run the whole pipeline on a third day of the dataset "
  "that we have not touched.")

# ----------------------------------------------------------------------------------------- Week 5
page_break()
h1("Week 5: Deployment, detection pipeline and continuous data collection")
h2("Overview")
p("This week describes a **live deployment** of the detector in an organisation's network and SOC. It is a design: what we "
  "built and measured is the prototype on recorded files, and section 8 says exactly where the two differ. The group's "
  "decisions are kept: an alert is the model's flag at a threshold chosen after testing, and retraining is shown by a "
  "demonstration rather than built as a service. Since 6 November the threshold is chosen per model by a rule applied to "
  "the model's own test results (section 4).")

h2("1. Where does live data come from?")
p("From network taps or switch mirror ports that copy traffic to a sensor without being in its path: one outside the "
  "firewall (sees the flood before it is dropped), one in the DMZ in front of the web servers, one in the core, and one "
  "in the cloud environment where the organisation's public services run (a virtual mirror). Each sensor runs the flow "
  "exporter live. A sensor sees everything that passes its point, so the window features are counted over everything "
  "reaching the protected servers, which is what they need.")

h2("2. Where and how are features generated?")
p("On the sensor. The exporter emits a flow record when the flow ends (timeout, FIN or RST), with the addresses and start "
  "time. The feature code keeps the last ten seconds of flow starts per destination address and per source address and "
  "counts the three windows for each new record as it arrives; because the windows look back only, no record waits for "
  "later traffic. The ratio, the indicators and the timing ratio are computed from the record. This is the same registry "
  "code as the prototype; the only new part is keeping the ten-second history in memory instead of reading a file.")

h2("3. How does the model receive new observations?")
p("The sensor scores each record as soon as its features exist, with the model file and its metadata deployed alongside "
  "(the metadata names the exact columns, so a sensor with the wrong exporter version refuses to score rather than scoring "
  "the wrong columns). At the rates we measured (hundreds of thousands of flows per second on one core), a sensor keeps up "
  "with the flow rate of our attack data with room to spare. The model is updated by replacing the file, never by learning "
  "on the sensor.")

h2("4. What causes an alert to be generated?")
p("A flow with a model score at or above the model's threshold raises an alert. The group's proposal was 0.5 for every "
  "model; testing on the app's models (the Week 5 notebook) showed that one number does not fit all of them:")
bullets(["For the tools the model knows (XGBoost, all tools), every threshold from 0.9 down to 0.01 keeps recall at 1.000 for "
         "HOIC and LOIC-HTTP; false alarms among 300,000 benign flows go from 8 at 0.5 to 257 (0.09 per cent) at 0.01.",
         "For an unseen tool the scores sit lower. Unseen HOIC is still 1.000 from 0.7 down to 0.001 (74 false alarms among "
         "2.15 million at 0.5, 769 at 0.05). Unseen LOIC-HTTP is 0.010 at 0.5, 0.48 from 0.3 to 0.1 and 0.96 at 0.05 and 0.01 "
         "(159 and 1,076 false alarms, 0.007 and 0.05 per cent): the attack's median score is 0.096, far above the benign "
         "99.9th percentile of 0.005 but below the 0.5 line. Unseen LOIC-UDP is 0.000 at every threshold.",
         "The forest's scores for unseen tools sit between 0.3 and 0.5 (unseen HOIC 0.755 at 0.5 and 0.9999 at 0.3 with 570 false "
         "alarms; unseen LOIC-HTTP 0.48 at 0.5 and 0.99 at 0.2 with 384); the SVM's own boundary is 0.5 and its false alarms "
         "explode below it (0.5 per cent at 0.3, 5 per cent at 0.2). The three types are on different scales.",
         "**The rule now used.** Each model starts at the lowest tested threshold whose false-alarm rate on its own benign test "
         "split is within 0.1 per cent, else 0.5. It is chosen from the benign side only, so a held-out tool's scores never set "
         "it. This gives 0.01 for the all-tools XGBoost model (0.09 per cent false alarms, recall 1.000) and for the "
         "LOIC-HTTP-held-out one (0.05 per cent, recall 0.961), 0.05 for the HOIC-held-out one, 0.05 to 0.1 for the forests and "
         "0.5 for the SVMs; the model card states the threshold and the reason. For an unseen UDP flood the rule still yields "
         "0.000, which is the honest number.",
         "These numbers are measured on the same test data the rule is reported on, so they are optimistic; a deployment would "
         "re-check the threshold on its own traffic."])
p("Single flows do not need to be the unit of alerting in a SOC: the design groups alerts by destination address and "
  "minute, so a flood produces one incident with a count, a list of top senders and the explanation of a representative flow.")

h2("5. Where does the alert go?")
p("To the SIEM in the SOC, over the sensor's log channel, as one record per alert with: time, source and destination "
  "addresses and port, protocol, model score, model type and version, the flag threshold, and the top contributing "
  "features with their SHAP values. The prototype writes exactly this record to a file (CSV and JSON Lines) and the SIEM "
  "would ingest it with a parser. The analyst sees the alert with its explanation and decides; the sensor never blocks. "
  "Responses (rate limiting at the edge, upstream scrubbing, blocking a sender) are the SOC's decisions, taken by people.")

h2("6. How are confirmed attacks and false positives captured as new data?")
p("The analyst's verdict on each alert (confirmed attack, false positive, unsure) is recorded in the SIEM case and, in the "
  "prototype, in a review file next to the flow file. Confirmed attacks and false positives are exported as labelled rows "
  "with exactly the model's input columns and a label, plus the source file and row number for traceability. The training "
  "script accepts these files and adds them to the training split only, so the test split stays comparable with the "
  "previous model. Unsure verdicts are not used for training. Window features in feedback rows are the values the sensor "
  "computed at the time, so a retrained model sees what the deployed one saw.")

h2("7. How would the model be retrained as behaviour changes?")
p("Periodically and by hand in the SOC, triggered by drift (a rising false-alarm rate, a new tool caught late, a change in "
  "the protected services), never automatically on the sensor. The demonstration in the Week 5 notebook plays through the "
  "case that matters most, a new attack tool appearing: the model was trained without one tool, that tool attacks, "
  "analysts label the first 100, 1,000 or 10,000 flows of the incident, and the model is retrained and tested on the rest "
  "of the attack and the same benign flows (seeds 0 and 1).")
table(["Scenario (XGBoost, tool held out; threshold 0.5)", "Before any label", "After 1,000 labelled flows", "After 10,000 labelled flows", "Retraining time"], [
    ["HOIC appears: recall on the rest of the attack / false alarms", "1.000 / 61 to 98", "1.000 / about the same", "1.000 / about the same", "about 6 s"],
    ["LOIC-HTTP appears: recall on the rest of the attack / false alarms", "0.002 (0.960 at 0.01) / 18 to 82", "0.96 / tens", "0.971 (0.995 at 0.01) / 28 to 35", "about 12 s"],
], widths=[3000, 1700, 1500, 1800, 1000])
p("For HOIC the held-out model already catches everything and retraining only moves the false alarms by a handful. For "
  "LOIC-HTTP retraining is the rescue case at the 0.5 line: 100 labelled flows change nothing, 1,000 raise recall to 0.96 "
  "and 10,000 to 0.97 (0.995 at threshold 0.01) with 28 to 35 false alarms among 2.15 million. Two warnings the demonstration "
  "produced for the SOC loop: labelling only the alerts (the 3,800 to 4,500 flows the old model flagged among the first "
  "10,000) reaches only 0.73 to 0.74, so analysts must label the whole incident; and a quick update that adds 50 trees to "
  "the old model reaches 0.96 but with 150 to 180 false alarms at 0.5 and over 10,000 at 0.01. So the rule is: label the "
  "whole incident, retrain fully (6 to 12 seconds on 3 million rows), and check the new model on a held-out benign set before "
  "it replaces the deployed one.")

h2("8. Live deployment versus what we built")
table(["Live design", "What exists and was measured"], [
    ["Taps and mirror ports feeding sensors outside the firewall, in the DMZ, the core and the cloud.",
     "Recorded packet captures and flow files from one victim network, two days."],
    ["The flow exporter running live on the sensor.", "The dataset's exporter output, and our reimplementation verified against it on the rebuilt day."],
    ["Window features kept in memory over the last ten seconds.", "Window features computed over a whole file with the same look-back rule."],
    ["Scoring on the sensor at line rate.", "Scoring of a loaded file at about 170,000 to 1,300,000 flows per second, depending on the file."],
    ["Alerts into a SIEM; incidents grouped by destination and minute.", "Alerts exported to CSV and JSON Lines; one record per flow."],
    ["Analyst verdicts in SIEM cases; retraining in the SOC.", "Verdicts in the app's review file; feedback export; retraining script and the notebook demonstration."],
    ["Threshold re-checked on the organisation's traffic.", "A per-model threshold from a fixed rule on the dataset's test splits."],
    ["Busy legitimate servers, flash crowds, large botnets.", "Not tested: one quiet network, ten attacking machines."],
], widths=[4500, 4500])

h2("9. Progress and discussion")
p("The pipeline from packets to an alert with an explanation exists end to end on recorded data, and every stage of the "
  "live design maps onto a piece of it. The group's open decisions are the feature set (Week 3, section 7) and the label "
  "for the UDP flood's reply rows (Week 2). The limits we would state in any presentation: two days of one network; "
  "ten attacking machines, so feature 2 learned a count; thresholds measured on the test data; the forest's variation "
  "between seeds; no transfer to a flood of a different kind (UDP); and no flash crowd to test against. What the work "
  "shows is narrower and, we think, more useful than \"the model detects DDoS\": with features that describe what a flood "
  "does to its target rather than what a tool's packets look like, a detector trained on one HTTP flood tool caught the "
  "other HTTP flood tool it had never seen, and it did not catch a UDP flood, which is exactly the kind of limit a SOC "
  "needs to know about.")

# =====================================================================================================
# BUILD
# =====================================================================================================
W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
document = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:document {W}><w:body>' + "".join(body)
            + '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" '
              'w:header="708" w:footer="708" w:gutter="0"/></w:sectPr></w:body></w:document>')

import io
zin = zipfile.ZipFile(io.BytesIO(TEMPLATE.read_bytes()))   # read fully before OUT is overwritten
numbering = zin.read("word/numbering.xml").decode("utf-8")
extra_nums = "".join(f'<w:num w:numId="{n}"><w:abstractNumId w:val="99411"/>'
                     f'<w:lvlOverride w:ilvl="0"><w:startOverride w:val="1"/></w:lvlOverride></w:num>'
                     for n in range(2001, _num_seq + 1) if f'w:numId="{n}"' not in numbering)
numbering = numbering.replace("</w:numbering>", extra_nums + "</w:numbering>")
core = zin.read("docProps/core.xml").decode("utf-8")
core = re.sub(r"<dc:title>.*?</dc:title>", "<dc:title>Explainable Machine Learning for DDoS Attack Detection in Network Traffic: Weeks 1 to 5 (update 5)</dc:title>", core, flags=re.S)
with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        if item.filename == "word/document.xml":
            zout.writestr(item, document.encode("utf-8"))
        elif item.filename == "word/numbering.xml":
            zout.writestr(item, numbering.encode("utf-8"))
        elif item.filename == "docProps/core.xml":
            zout.writestr(item, core.encode("utf-8"))
        else:
            zout.writestr(item, zin.read(item.filename))
print("wrote", OUT, f"({len(body)} body elements)")
