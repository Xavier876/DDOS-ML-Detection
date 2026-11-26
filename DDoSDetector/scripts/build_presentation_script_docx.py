r"""Spoken script for the Part 2 slides (feature selection and cybersecurity justification), six minutes.

    .\.venv\Scripts\python.exe DDoSDetector\scripts\build_presentation_script_docx.py

Writes docs\Feature_selection_presentation_script.docx using the package parts (styles) of the Weeks 1-5 document.
One block per slide with its time budget; the words are meant to be said, not read.
"""
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(r"C:\Users\Xavie\source\repos\DDOS-ML-Detection")
TEMPLATE = ROOT / "docs" / "Weeks_1_to_5_-_DDoS_Detection_Project_UPDATE5.docx"
OUT = ROOT / "docs" / "Feature_selection_presentation_script.docx"

body: list[str] = []


def run(text, bold=False, italic=False):
    rpr = ("<w:rPr>" + ("<w:b/>" if bold else "") + ("<w:i/>" if italic else "") + "</w:rPr>") if (bold or italic) else ""
    return f'<w:r>{rpr}<w:t xml:space="preserve">{escape(text)}</w:t></w:r>'


def para(text, style="BodyText", bold=False, italic=False):
    body.append(f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr>{run(text, bold, italic)}</w:p>')


def slide(number, title, seconds, cue, *paragraphs):
    body.append(f'<w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr>{run(f"Slide {number}: {title}")}'
                f'{run(f"   ({seconds})", italic=True)}</w:p>')
    para(cue, "Compact", italic=True)
    for t in paragraphs:
        para(t)


para("Feature selection and cybersecurity justification: speaking script", "Title")
para("Part 2 of the COMP6310 group presentation. Six minutes. Timings are a budget, not a stopwatch; the places to "
     "cut if the earlier parts run long are marked.", "Subtitle")
para("About 910 spoken words: six minutes at a brisk pace, six and a half at a measured one; the marked cut on slide 4 takes out half a minute. The slides carry the numbers, so the script does not read them all "
     "out; it says what they mean. Square brackets are stage directions, not words to say.", "BodyText", italic=True)

slide(1, "Title", "0:20",
      "[Advance as you start speaking. Do not read the title.]",
      "Thanks. My part is the second criterion: which features we chose, and the security reasoning behind them. I "
      "want to make one argument and then show the evidence. The argument is that we chose features that describe "
      "what a flood does to the server it hits, not what one attack tool's packets look like.")

slide(2, "A flood cannot hide four things at the victim", "0:45",
      "[Point at each card in turn; do not read the small print.]",
      "We started from the threat rather than from the column list. However a flood is built, it has to do certain "
      "things where the victim is. Traffic piles up on one target. It comes from many senders, or from senders that "
      "keep coming back. The requests are cheap ones the target cannot answer in kind, so there are no replies, or far "
      "more packets out than back. And the timing is a program's timing, not a person's.",
      "A feature that measures one of those is measuring the attack. A feature that measures packet sizes or rates is "
      "measuring the tool, and the next tool will look different. Our data has three tools, which turned out to be a "
      "fair test of exactly that.")

slide(3, "The six features, and how they are collected", "0:50",
      "[Gesture at the table; the last column is the one to point at.]",
      "Six groups, seven columns. The first three are window counts over the previous ten seconds: flows to this "
      "destination, distinct senders to it, and flows from this sender. The other three come from the flow record on "
      "its own: the ratio of packets out to packets back, two flags for no reply and no payload, and how regular the "
      "packet timing is.",
      "Can they be collected live? I think so, with one condition. Everything comes from a standard flow exporter, the "
      "same tool that produced the dataset. The windows need the sensor to keep ten seconds of flow starts in memory, "
      "and they only look backwards. The addresses are used only to count; the model never sees one, so it cannot "
      "learn an attacker by address.")

slide(4, "Assumptions checked against the data", "0:50",
      "[Point at rows 1 and 3, then row 2 for the caveat. If short of time, say only the first paragraph.]",
      "For each feature we wrote the assumption down first and then checked it: the attack median against the benign "
      "median from the same day, and the AUC of the column on its own, where one means it separates perfectly and "
      "0.5 means it does nothing. The three windows separate HOIC almost perfectly and LOIC-HTTP well.",
      "Two things did not go as assumed, and I would rather say so. Distinct senders barely separates LOIC-HTTP on its "
      "own, because ten attackers against a benign median of four is not a large gap. And timing regularity runs the "
      "other way for LOIC: it is burstier than normal traffic, not steadier. Both still help in combination, which "
      "is what the search measures rather than any one column.")

slide(5, "The obvious features describe the tool", "1:00",
      "[Left card first, then the three before-and-after numbers.]",
      "The rubric asks whether we considered irrelevant or misleading features. We did, and most of the obvious ones "
      "failed. The group's first set used packet rate, duration and packet length, which is more or less a tool's "
      "fingerprint. With those, a model trained on LOIC caught about eighteen per cent of a HOIC attack it had never "
      "seen. With the six we chose, same test, same models, XGBoost and the SVM catch all of it and the forest about "
      "three quarters. Only the columns changed.",
      "SYN count was misleading: it is zero or one in this data and no attack flow ever sets it. Our first window "
      "used the destination port, because the published file had no addresses; it mixed every server on port 80, so "
      "we replaced it once we had rebuilt the capture. One redundancy we kept on purpose: the no-reply and "
      "empty-payload flags restate the counts, but they let an analyst read 'no reply from the target' in the "
      "explanation.")

slide(6, "How we chose them: a search, not a preference", "0:40",
      "[Walk A, B, C left to right. Do not read the card text.]",
      "Which six was decided by a search with a rule fixed in advance: a candidate counted as better only if, for "
      "every random seed, it raised recall on the tool the model had never seen without raising false alarms. Each "
      "candidate alone against the base set, then forward selection, then a final check without row caps, for all "
      "three model types, because a feature that only helps one learner is probably telling you about the learner.",
      "Only the address windows passed the first stage for every type, and the six that survived the final check "
      "for all three are the ones you have seen. Eight groups helped the forest and cost the other two, so we stopped "
      "at six.")

slide(7, "Where the features fail, and what evasion costs", "0:50",
      "[Left card: limits. Right card: evasion. Do not rush these.]",
      "Where it fails, measured rather than guessed. An unseen UDP flood is missed entirely: each of its flows lasts "
      "the full two-minute timeout, so the ten-second windows barely see it, and on this network an unanswered flow "
      "is not unusual. We had ten attacking machines, so the distinct-senders feature learned a number rather than "
      "the idea of many. And benign flows to the server under attack share its window counts; the source window "
      "saves XGBoost there, not the other two.",
      "If an attacker knew the features: slow each machine down, which costs damage; use more machines, which is what "
      "feature 2 is for; send real requests that get replies, which costs effort; or randomise timing, which is cheap, "
      "and that is why timing is our weakest feature. No feature survives alone. The combination raises the "
      "attacker's cost, and the windows are the hardest to hide from.")

slide(8, "What the model receives", "0:25",
      "[Hand over on the last sentence.]",
      "So the model receives these seven columns and nothing else, built by one piece of code that training and the "
      "application share, so a model cannot be scored on something it was not trained on. The next part covers why "
      "we chose a supervised approach and XGBoost, and what the three model types do with these inputs.")

body.append('<w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr>' + run("If asked") + "</w:p>")
para("What about this threat led to these features? The four things a flood cannot hide at the victim; we worked "
     "backwards from those to the columns.")
para("How does the system exploit the difference from legitimate behaviour? Through volume, senders and one-sidedness "
     "taken together. A flash crowd shares the first two, which is a limit we state rather than a problem we have solved.")
para("If detection recall were 95 per cent, what happens to the rest? A flood is many flows, so missing five per cent "
     "delays the alert slightly but rarely hides the attack; the dangerous miss is a whole tool we never saw, which is "
     "what the UDP result shows.")
para("How could an attacker adapt? Slow down, spread out, send real requests, randomise timing. Each has a cost, and "
     "the windows are the hardest of the six to beat.")

# ---------------------------------------------------------------------------------------------- build
W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
document = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:document {W}><w:body>' + "".join(body)
            + '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" '
              'w:header="708" w:footer="708" w:gutter="0"/></w:sectPr></w:body></w:document>')
zin = zipfile.ZipFile(TEMPLATE)
with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        zout.writestr(item, document.encode("utf-8") if item.filename == "word/document.xml" else zin.read(item.filename))
print("wrote", OUT, f"({len(body)} body elements)")
