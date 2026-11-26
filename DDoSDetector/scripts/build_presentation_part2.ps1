# Builds the Part 2 deck on the group's "folder with tabs" frame (docs\presentation_frame.png, one picture per
# slide) and draws our content inside the panel. Speaker notes on every slide; a References slide (APA 7) at the end.
param([string]$FramePng = "C:\Users\Xavie\source\repos\DDOS-ML-Detection\docs\presentation_frame.png",
      [string]$Out = "C:\Users\Xavie\source\repos\DDOS-ML-Detection\docs\Feature_selection_and_justification_presentation.pptx",
      [string]$PngDir = "C:\Users\Xavie\AppData\Local\Temp\claude\e21e746ccf705a9c\4b46c128-d8e1-4b52-8f65-b1219b465875\scratchpad\deck_png")

function RGB([int]$r, [int]$g, [int]$b) { return $r + ($g * 256) + ($b * 65536) }
$INK   = RGB 52 52 52        # the frame's text colour (#343434)
$MUTED = RGB 105 95 90
$BROWN = RGB 157 125 110     # the folder and its tabs (sampled from the frame)
$BEIGE = RGB 230 222 210     # the pills / cards
$ROW   = RGB 241 234 238     # table banding (close to the speckled panel)
$WHITE = RGB 255 255 255
$FONT = "Arial"              # the frame's Futura falls back to Arial on Windows; match what is on screen

# Panel (the pale speckled area of the frame) on the 1440 x 810 slide
$PX = 150; $PY = 196; $PW = 1140; $PH = 480

$app = New-Object -ComObject PowerPoint.Application
$pres = $app.Presentations.Add(0)          # no window
$pres.PageSetup.SlideWidth = 1440; $pres.PageSetup.SlideHeight = 810
# The frame (the group's folder, tabs with "Chapter II" active, and the speckled panel) is one picture,
# docs\presentation_frame.png, taken from the group's deck on 15 Nov 2026; importers such as Canva keep a picture
# where they drop the picture-filled shapes the original frame was made of.
$frame = $pres.Slides.Add(1, 12)
$bg = $frame.Shapes.AddPicture($FramePng, 0, -1, 0, 0, 1440, 810); $bg.Name = "Frame background"
$script:n = 0

function NewSlide() {
    $script:n++
    $s = $frame.Duplicate().Item(1)
    $s.MoveTo($script:n + 1)
    return $s
}
function Text($slide, $x, $y, $w, $h, [string]$text, [int]$size, [int]$color, [bool]$bold = $false, [int]$align = 1) {
    $tb = $slide.Shapes.AddTextbox(1, $PX + $x, $PY + $y, $w, $h)
    $tf = $tb.TextFrame; $tf.WordWrap = -1; $tf.AutoSize = 0
    $tf.MarginLeft = 0; $tf.MarginRight = 0; $tf.MarginTop = 0; $tf.MarginBottom = 0
    $tr = $tf.TextRange; $tr.Text = $text
    $tr.Font.Name = $FONT; $tr.Font.Size = $size; $tr.Font.Color.RGB = $color; $tr.Font.Bold = $(if ($bold) { -1 } else { 0 })
    $tr.ParagraphFormat.Alignment = $align
    $tr.ParagraphFormat.SpaceWithin = 1.05
    return $tb
}
function Bullets($slide, $x, $y, $w, $h, [string[]]$items, [int]$size, [int]$color) {
    $tb = Text $slide $x $y $w $h ($items -join "`r") $size $color
    $tr = $tb.TextFrame.TextRange
    $tr.ParagraphFormat.Bullet.Visible = -1
    $tr.ParagraphFormat.Bullet.Character = 8226
    $tr.ParagraphFormat.Bullet.Font.Color.RGB = $BROWN
    $tr.ParagraphFormat.SpaceAfter = 6
    $tb.TextFrame.Ruler.Levels(1).FirstMargin = 0; $tb.TextFrame.Ruler.Levels(1).LeftMargin = 20
    return $tb
}
function Card($slide, $x, $y, $w, $h, [int]$fill) {
    $r = $slide.Shapes.AddShape(5, $PX + $x, $PY + $y, $w, $h)
    $r.Adjustments.Item(1) = 0.12
    $r.Fill.Solid(); $r.Fill.ForeColor.RGB = $fill; $r.Line.Visible = 0; $r.Shadow.Visible = 0
    return $r
}
function Circle($slide, $x, $y, $d, [int]$fill, [string]$label) {
    $c = $slide.Shapes.AddShape(9, $PX + $x, $PY + $y, $d, $d)
    $c.Fill.Solid(); $c.Fill.ForeColor.RGB = $fill; $c.Line.Visible = 0
    $tr = $c.TextFrame.TextRange; $tr.Text = $label; $tr.Font.Name = $FONT; $tr.Font.Size = 20; $tr.Font.Bold = -1
    $tr.Font.Color.RGB = $WHITE; $tr.ParagraphFormat.Alignment = 2
    $c.TextFrame.MarginLeft = 0; $c.TextFrame.MarginRight = 0
    return $c
}
function Title($slide, [string]$text) { Text $slide 0 0 $PW 50 $text 34 $INK $true | Out-Null }
function Table($slide, $x, $y, $w, [double[]]$colw, [string[][]]$rows, [int]$size = 14, [double]$rowh = 34) {
    $nr = $rows.Count; $nc = $rows[0].Count
    $t = $slide.Shapes.AddTable($nr, $nc, $PX + $x, $PY + $y, $w, $rowh * $nr)
    $tbl = $t.Table
    for ($c = 1; $c -le $nc; $c++) { $tbl.Columns($c).Width = $colw[$c - 1] }
    for ($r = 1; $r -le $nr; $r++) {
        $tbl.Rows($r).Height = $rowh
        for ($c = 1; $c -le $nc; $c++) {
            $cell = $tbl.Cell($r, $c)
            $tr = $cell.Shape.TextFrame.TextRange
            $tr.Text = $rows[$r - 1][$c - 1]
            $tr.Font.Name = $FONT; $tr.Font.Size = $size; $tr.Font.Color.RGB = $INK
            $tr.Font.Bold = $(if ($r -eq 1) { -1 } else { 0 })
            $cell.Shape.TextFrame.MarginLeft = 7; $cell.Shape.TextFrame.MarginRight = 7
            $cell.Shape.TextFrame.MarginTop = 3; $cell.Shape.TextFrame.MarginBottom = 3
            $cell.Shape.Fill.Solid()
            $cell.Shape.Fill.ForeColor.RGB = $(if ($r -eq 1) { $BROWN } elseif ($r % 2 -eq 0) { $ROW } else { $WHITE })
            if ($r -eq 1) { $tr.Font.Color.RGB = $WHITE }
            foreach ($side in 1, 2, 3, 4) { $cell.Borders($side).Visible = 0 }
        }
    }
    return $t
}
function Notes($slide, [string]$text) { $slide.NotesPage.Shapes.Placeholders(2).TextFrame.TextRange.Text = $text }

# ------------------------------------------------------------------------------------- 1 title
$s = NewSlide
Text $s 0 110 $PW 40 "PART 2 OF 7" 22 $BROWN $true 2 | Out-Null
Text $s 60 160 ($PW - 120) 130 "FEATURE SELECTION AND`rCYBERSECURITY JUSTIFICATION" 44 $INK $true 2 | Out-Null
Text $s 120 300 ($PW - 240) 70 "Six features that describe what a DDoS flood does to its target, not what one attack tool looks like" 22 $MUTED $false 2 | Out-Null
Text $s 0 420 $PW 30 "Explainable Machine Learning for DDoS Attack Detection in Network Traffic  |  Presenter: Xavier Watson" 16 $MUTED $false 2 | Out-Null
Notes $s @"
(About 20 seconds.)
My part is the second criterion of the rubric: which features we selected, why, what evidence supports them, whether they can be collected live, and which features we rejected. The one idea to hold on to: we chose features that describe what a flood must do to its target, not what a particular attack tool's packets look like. Everything else follows from that.
"@

# ------------------------------------------------------------------------------------- 2 must-haves
$s = NewSlide
Title $s "A flood cannot hide four things at the victim"
$cards = @(
    @("1", "Volume on one target", "Many flows reach the same server in a few seconds. Spread it out and it stops being a flood."),
    @("2", "Many or repeating senders", "Either many machines hit the target (the distributed part) or each machine keeps coming back."),
    @("3", "One-sided requests", "Cheap requests the target cannot answer in kind: no reply, or far more packets out than back."),
    @("4", "Machine timing", "A program sends at regular intervals; a person does not.")
)
$i = 0
foreach ($c in $cards) {
    $x = 0 + ($i % 2) * 580; $y = 70 + [math]::Floor($i / 2) * 170
    Card $s $x $y 560 150 $BEIGE | Out-Null
    Circle $s ($x + 20) ($y + 20) 54 $BROWN $c[0] | Out-Null
    Text $s ($x + 90) ($y + 22) 450 40 $c[1] 24 $INK $true | Out-Null
    Text $s ($x + 90) ($y + 66) 450 80 $c[2] 17 $MUTED | Out-Null
    $i++
}
Text $s 0 420 $PW 56 "Flooding attacks exhaust the target's capacity with traffic from many sources (Mirkovic & Reiher, 2004; Zargar et al., 2013); the classic look-alike is a flash crowd (Jung et al., 2002). Threat model: HOIC and LOIC-HTTP (HTTP floods over many short TCP connections) and LOIC-UDP (a UDP flood), ten attacking machines against one web server in CSE-CIC-IDS2018 (Sharafaldin et al., 2018)." 13 $MUTED | Out-Null
Notes $s @"
(About 40 seconds.)
We started from the threat, not from the column list. Whatever tool an attacker uses, a flood has to produce these four things where the victim sits: traffic piling up on one target, many senders or senders that keep coming back, requests the target cannot answer in kind, and the regular timing of a program. If a feature measures one of these, it is measuring the attack. If it measures packet sizes or rates, it is measuring the tool, and the next tool will look different. Our three attack tools, HOIC, LOIC in HTTP mode and LOIC in UDP mode, are three programs doing the same thing, which is exactly the test we need.
"@

# ------------------------------------------------------------------------------------- 3 the six
$s = NewSlide
Title $s "The six features, and how they are collected"
$rows = @(
    @("#", "Feature (column)", "What it measures", "How it is computed", "Live?"),
    @("1", "Flows to the same destination IP", "Volume on one target", "Count of flows to the same destination address in the previous 10 s", "Yes"),
    @("2", "Distinct source IPs to that destination", "Many senders", "Distinct source addresses with a flow to the same destination in the previous 10 s", "Yes"),
    @("3", "Flows from the same source IP", "Repeating sender", "Count of flows from the same source address in the previous 10 s", "Yes"),
    @("4", "Forward / backward packet ratio", "One-sided exchange", "Packets from the initiator divided by (packets back + 1)", "Yes"),
    @("5", "No-reply and empty-payload flags", "No answer, no data", "1 when the responder sent nothing; 1 when the initiator's mean packet length is 0", "Yes"),
    @("6", "Timing regularity", "Machine timing", "Std. dev. of packet gaps divided by (mean gap + 1)", "Yes")
)
Table $s 0 62 $PW @(44, 310, 200, 520, 66) $rows 14 44 | Out-Null
Text $s 0 385 $PW 90 "Inputs come from the flow exporter CICFlowMeter (Lashkari et al., 2017), the tool that produced the dataset's own flow records (Sharafaldin et al., 2018), running on a tap or mirror port. Features 1 to 3 need the last 10 seconds of flow starts kept in memory and look back only, so they can be computed as traffic arrives. Addresses and times are used to count flows and are never model inputs; the alert keeps them for the analyst." 15 $MUTED | Out-Null
Notes $s @"
(About 45 seconds.)
Six feature groups, seven columns. The first three are window counts over the previous ten seconds: how many flows hit this destination, how many different senders hit it, and how often this sender comes back. The last three come from the flow record itself: the packet ratio, two yes-or-no flags for no reply and no payload, and a scale-free measure of timing regularity.
On collection: all of this comes out of a standard flow exporter. The windows need the sensor to remember ten seconds of flow starts, and they only look backwards, so nothing waits for later traffic. The IP addresses are only used to count; the model never sees an address, so it cannot learn an attacker's IP.
"@

# ------------------------------------------------------------------------------------- 4 evidence
$s = NewSlide
Title $s "Assumptions checked against the data"
$rows = @(
    @("Feature", "Assumption", "HOIC vs benign (same day)", "LOIC-HTTP vs benign", "Verdict"),
    @("1  Flows to destination", "Higher during an attack", "median 7,068 vs 0; AUC 0.94", "1,530 vs 8; AUC 0.98", "Supported"),
    @("2  Distinct sources", "Higher during an attack", "11 vs 0; AUC 0.93", "10 vs 4; AUC 0.56", "Supported; weak alone"),
    @("3  Flows from source", "Higher during an attack", "710 vs 0; AUC 1.00", "154 vs 8; AUC 0.92", "Supported"),
    @("4  Fwd/bwd ratio", "Target answers less", "2.0 vs 1.7; AUC 0.75", "0.6 vs 0.9; AUC 0.62", "Weak alone; decisive for the UDP flood (ratio 119,759)"),
    @("5  No reply / empty", "More unanswered flows", "1 vs 0; AUC 0.88", "0 vs 0; AUC 0.66", "Supported for HOIC and UDP"),
    @("6  Timing regularity", "Tools are more regular", "0.0 vs 1.3; AUC 0.15 (more regular)", "2.4 vs 0.8; AUC 0.57 (less regular)", "Direction differs by tool")
)
Table $s 0 62 $PW @(222, 210, 256, 222, 230) $rows 14 42 | Out-Null
Text $s 0 372 $PW 100 "AUC = the area under the ROC curve (Fawcett, 2006): how well the column alone separates attack from benign (1.0 perfect, 0.5 nothing), computed on the two capture days. The window features and the source window carry the signal; the per-flow features are weak alone but decide the cases the windows cannot, such as the UDP flood, which never gets a reply." 15 $MUTED | Out-Null
Notes $s @"
(About 45 seconds.)
The rubric asks what observations suggested these were meaningful. For every feature we wrote the assumption down first and then checked it on the data: the median for attack flows against the benign flows of the same day, and the AUC of the column on its own.
The three windows separate HOIC almost perfectly and LOIC-HTTP well. Two honest notes. Feature 2, distinct senders, barely separates LOIC-HTTP on its own, because ten attackers against a benign median of four senders is not a big gap. And timing regularity runs the opposite way for LOIC: HOIC is machine-regular, LOIC is burstier than normal traffic. Both still help in combination, which is what the search in a moment measures. Feature 4, the ratio, is weak for the HTTP tools but is the one column that identifies the UDP flood, which sends 120,000 packets and gets nothing back.
"@

# ------------------------------------------------------------------------------------- 5 rejected
$s = NewSlide
Title $s "The obvious features describe the tool"
Card $s 0 62 560 330 $BEIGE | Out-Null
Text $s 24 78 512 34 "Considered and rejected" 22 $INK $true | Out-Null
Bullets $s 24 122 512 260 @(
    "Packet and byte rate, flow duration, packet length: the fingerprint of one tool's traffic; a model trained on LOIC learns LOIC",
    "SYN flag count: 0 or 1 in this data and never set on an attack flow (misleading)",
    "Port-based window (our stand-in before we had IP addresses): mixes every server on port 80",
    "Reply length, RST/FIN counts, the update-3 groups: no gain larger than the seed-to-seed spread"
) 16 $INK | Out-Null
Card $s 580 62 560 330 $BEIGE | Out-Null
Text $s 604 78 512 34 "Unseen HOIC, recall at threshold 0.5" 22 $INK $true | Out-Null
$stats = @(@("XGBoost", "0.18", "1.00"), @("Random Forest", "0.19", "0.76"), @("Linear SVM", "0.49", "1.00"))
$j = 0
foreach ($st in $stats) {
    $yy = 130 + $j * 80
    Text $s 604 ($yy + 12) 200 40 $st[0] 18 $MUTED $true | Out-Null
    Text $s 810 ($yy - 6) 130 70 $st[1] 40 $MUTED $true | Out-Null
    Text $s 935 ($yy - 4) 50 60 ">" 34 $BROWN $true 2 | Out-Null
    Text $s 990 ($yy - 6) 140 70 $st[2] 40 $BROWN $true | Out-Null
    $j++
}
Text $s 604 366 512 24 "per-flow six (rate, duration, length, ratio, port window)  >  the six here" 13 $MUTED | Out-Null
Text $s 0 408 $PW 70 "Unseen LOIC-HTTP: linear SVM 0.16 to 0.97; XGBoost ranks it correctly (PR-AUC 0.999) but scores it low, 0.96 at its own threshold of 0.01; Random Forest 0.005 to 0.48. Kept despite redundancy: the no-reply and empty-payload flags restate the counts, but they make the SHAP explanation (Lundberg & Lee, 2017) readable for the analyst. Models: XGBoost (Chen & Guestrin, 2016), Random Forest and a linear SVM." 14 $MUTED | Out-Null
Notes $s @"
(About 50 seconds.)
The rubric asks whether we considered irrelevant, redundant or misleading features. Yes, and most of the obvious ones failed. Packet rate, duration and packet length are the fingerprint of a tool: with those six features a model trained on LOIC caught 18 per cent of HOIC it had never seen. With the six we chose, the same test gives 100 per cent for XGBoost and the SVM, and three quarters for the forest. SYN count was misleading: it is zero or one in this data and no attack flow ever sets it. Our first window feature used the destination port because the published data had no addresses; it mixed every server on port 80, so once we rebuilt the capture with addresses we replaced it.
One redundancy we kept on purpose: the no-reply and empty-payload flags restate information in the counts, but they let the analyst read 'no reply from the target' in the explanation.
"@

# ------------------------------------------------------------------------------------- 6 how chosen
$s = NewSlide
Title $s "How we chose them: a search, not a preference"
$steps = @(
    @("A", "One candidate at a time", "The per-flow six against the six plus each of 12 candidates, two seeds, three model types, each tool held out. A candidate counts only if every seed beats the base on the unseen tool with no more false alarms. Only the address windows passed, for all three models."),
    @("B", "Forward selection", "From nothing, add the group that most raises mean recall on the unseen tools (false alarms under 2 per cent), per model type, up to eight groups. Every model type picked an address window first."),
    @("C", "Final check, no row caps", "The base and each model's best six and best eight, every model type, two seeds, all splits. The six that held up for all three types are the six on the previous slides. Eight helped the forest only and cost XGBoost and the SVM.")
)
$k = 0
foreach ($st in $steps) {
    $x = $k * 386
    Card $s $x 62 368 290 $BEIGE | Out-Null
    Circle $s ($x + 20) 80 54 $BROWN $st[0] | Out-Null
    Text $s ($x + 88) 90 262 40 $st[1] 20 $INK $true | Out-Null
    Text $s ($x + 20) 148 328 200 $st[2] 15 $MUTED | Out-Null
    $k++
}
Text $s 0 372 $PW 100 "Stages B and C follow the wrapper approach to feature selection (Guyon & Elisseeff, 2003): judge a subset by the model it produces, here on an attack tool the model never saw. Why three model types: a feature that only helps one learner is a property of that learner. The rule for 'better' was agreed before the search ran. Data: the 20 Feb file and the 21 Feb capture rebuilt from raw packets with addresses and corrected labels (9.9 million flows). Every fit is in the results table in the repository." 15 $MUTED | Out-Null
Notes $s @"
(About 40 seconds.)
The group had agreed on six groups; which six was decided by a search with a rule we set in advance: a candidate is better only if every seed improves recall on the tool the model never saw, without more false alarms. Three stages: each candidate alone against the base, then forward selection, then a final check without row caps. We ran it for all three model types because a feature that only helps one learner is telling you about the learner. Only the address windows passed stage A for every model, every model picked one first in stage B, and the six that survived the final check for all three types are the six you have seen. Eight groups helped the forest and hurt the other two, so we stopped at six.
"@

# ------------------------------------------------------------------------------------- 7 limits
$s = NewSlide
Title $s "Where the features fail, and what evasion costs"
Card $s 0 62 560 352 $BEIGE | Out-Null
Text $s 24 78 512 34 "Measured limits" 22 $INK $true | Out-Null
Bullets $s 24 122 512 290 @(
    "An unseen UDP flood is not caught (0.000): its flows last the full 120 s, so the windows see almost nothing, and 'no reply' alone is normal on this network",
    "Ten attacking machines: feature 2 learned 'about ten senders'; LOIC-HTTP flows with 12 senders were missed",
    "Benign flows to the attacked server during the attack share its window counts; XGBoost flags 4 of 474, the forest 71, the SVM 217",
    "One quiet network: a flash crowd or a busy server raises features 1 and 2 for normal traffic; not tested"
) 15 $INK | Out-Null
Card $s 580 62 560 352 $BEIGE | Out-Null
Text $s 604 78 512 34 "Evasion, and what it costs the attacker" 22 $INK $true | Out-Null
Bullets $s 604 122 512 290 @(
    "Slow each machine down (lowers 3): less damage per machine",
    "Use more machines (raises 2): that is what feature 2 is for",
    "Send real requests that get real replies (lowers 4 and 5): more effort per request",
    "Randomise timing (defeats 6): cheap, which is why 6 is the weakest",
    "No single feature is robust; the combination raises the cost, and the windows are the hardest to hide from"
) 15 $INK | Out-Null
Text $s 0 428 $PW 46 "Mitigations we would add: more senders in training data or a real botnet trace, a flash-crowd baseline per protected server (Jung et al., 2002), and retraining from analyst-confirmed incidents (part 7). Attackers adapting to monitored features is the standard arms race described by Mirkovic and Reiher (2004)." 13 $MUTED | Out-Null
Notes $s @"
(About 45 seconds.)
Where it fails, measured. First, an unseen UDP flood is missed entirely: each of its flows lasts the full timeout, so the ten-second windows barely see it, and on this network an unanswered flow is not unusual. Second, we had ten attacking machines, so the distinct-senders feature learned a number rather than 'many': LOIC-HTTP flows with twelve senders were pushed towards benign. Third, benign flows to the server under attack share its window counts; the source window saves XGBoost there but not the other two models. And we have no flash crowd to test against.
If an attacker knew the features: slow each machine down, which costs damage; use more machines, which is what feature 2 detects; send real requests that get real replies, which costs effort; or randomise timing, which is cheap and why timing is our weakest feature. No feature survives alone; the combination raises the attacker's cost.
"@

# ------------------------------------------------------------------------------------- 8 handover
$s = NewSlide
Title $s "What the model receives"
Text $s 0 60 $PW 60 "Seven columns, in a fixed order, built by one registry shared by training and the app, so every alert's SHAP explanation (Lundberg & Lee, 2017; Wang et al., 2020) refers to exactly these inputs. No addresses, ports, timestamps, packet rates or sizes." 17 $MUTED | Out-Null
$chips = @("dst_ip_flows_10s", "dst_ip_src_ips_10s", "src_ip_flows_10s", "fwd_bwd_ratio", "no_reply", "empty_payload", "iat_cv")
$cx = 0
foreach ($ch in $chips) {
    $w = 18 + $ch.Length * 9.4
    $r = $s.Shapes.AddShape(5, $PX + $cx, $PY + 140, $w, 44); $r.Adjustments.Item(1) = 0.5
    $r.Fill.Solid(); $r.Fill.ForeColor.RGB = $BROWN; $r.Line.Visible = 0
    $r.TextFrame.WordWrap = 0; $r.TextFrame.AutoSize = 0
    $r.TextFrame.MarginLeft = 2; $r.TextFrame.MarginRight = 2; $r.TextFrame.MarginTop = 0; $r.TextFrame.MarginBottom = 0
    $tr = $r.TextFrame.TextRange; $tr.Text = $ch; $tr.Font.Name = "Consolas"; $tr.Font.Size = 15; $tr.Font.Color.RGB = $WHITE; $tr.Font.Bold = -1
    $tr.ParagraphFormat.Alignment = 2
    $cx += $w + 10
}
Text $s 0 220 $PW 34 "Questions I am ready for" 22 $BROWN $true | Out-Null
Bullets $s 0 262 $PW 150 @(
    "What about this threat led to these features?  The four things a flood cannot hide at the victim.",
    "How does the system exploit the difference from legitimate behaviour?  Volume, senders and one-sidedness together, not any one of them.",
    "How could an attacker adapt?  Slow down, spread out, send real requests, randomise timing; each has a cost, and the windows are the hardest to beat."
) 16 $INK | Out-Null
Text $s 0 440 $PW 30 "Next: Part 3, the machine-learning approach (XGBoost, with Random Forest and a linear SVM as comparisons)" 14 $MUTED | Out-Null
Notes $s @"
(About 20 seconds.)
To hand over: the model receives these seven columns and nothing else, built by one piece of code that both training and the app use, so the model can never be scored on something it was not trained on. The next part covers why we chose a supervised approach and XGBoost, and what the three model types do with these features.
"@

# ------------------------------------------------------------------------------------- 9 references
$s = NewSlide
Title $s "References"
$refs = @(
    "Chen, T., & Guestrin, C. (2016). XGBoost: A scalable tree boosting system. In Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (pp. 785-794). ACM. https://doi.org/10.1145/2939672.2939785",
    "Fawcett, T. (2006). An introduction to ROC analysis. Pattern Recognition Letters, 27(8), 861-874. https://doi.org/10.1016/j.patrec.2005.10.010",
    "Guyon, I., & Elisseeff, A. (2003). An introduction to variable and feature selection. Journal of Machine Learning Research, 3, 1157-1182.",
    "Jung, J., Krishnamurthy, B., & Rabinovich, M. (2002). Flash crowds and denial of service attacks: Characterization and implications for CDNs and web sites. In Proceedings of the 11th International Conference on World Wide Web (pp. 293-304). ACM. https://doi.org/10.1145/511446.511485",
    "Lashkari, A. H., Draper-Gil, G., Mamun, M. S. I., & Ghorbani, A. A. (2017). Characterization of Tor traffic using time based features. In Proceedings of the 3rd International Conference on Information Systems Security and Privacy (ICISSP 2017) (pp. 253-262). SCITEPRESS. https://doi.org/10.5220/0006105602530262",
    "Lundberg, S. M., & Lee, S.-I. (2017). A unified approach to interpreting model predictions. In Advances in Neural Information Processing Systems 30 (pp. 4765-4774). Curran Associates.",
    "Mirkovic, J., & Reiher, P. (2004). A taxonomy of DDoS attack and DDoS defense mechanisms. ACM SIGCOMM Computer Communication Review, 34(2), 39-53. https://doi.org/10.1145/997150.997156",
    "Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. In Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP 2018) (pp. 108-116). SCITEPRESS. https://doi.org/10.5220/0006639801080116",
    "Wang, M., Zheng, K., Yang, Y., & Wang, X. (2020). An explainable machine learning framework for intrusion detection systems. IEEE Access, 8, 73127-73141. https://doi.org/10.1109/ACCESS.2020.2988359",
    "Zargar, S. T., Joshi, J., & Tipper, D. (2013). A survey of defense mechanisms against distributed denial of service (DDoS) flooding attacks. IEEE Communications Surveys & Tutorials, 15(4), 2046-2069. https://doi.org/10.1109/SURV.2013.031413.00127"
)
$tb = Text $s 0 58 $PW 420 ($refs -join "`r") 13 $INK
$tr = $tb.TextFrame.TextRange
$tr.ParagraphFormat.SpaceAfter = 5
$tb.TextFrame.Ruler.Levels(1).FirstMargin = 0; $tb.TextFrame.Ruler.Levels(1).LeftMargin = 28   # hanging indent (APA 7)
$italics = @("Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining",
             "Pattern Recognition Letters, 27", "Journal of Machine Learning Research, 3",
             "Proceedings of the 11th International Conference on World Wide Web",
             "Proceedings of the 3rd International Conference on Information Systems Security and Privacy (ICISSP 2017)",
             "Advances in Neural Information Processing Systems 30", "ACM SIGCOMM Computer Communication Review, 34",
             "Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP 2018)",
             "IEEE Access, 8", "IEEE Communications Surveys & Tutorials, 15")
foreach ($it in $italics) { $found = $tr.Find($it); if ($found -ne $null) { $found.Font.Italic = -1 } }
Notes $s @"
Not presented; here for the assessors. APA 7th edition. Dataset: Sharafaldin et al. (2018); flow exporter: Lashkari et al. (2017); DDoS characterisation and defences: Mirkovic and Reiher (2004), Zargar et al. (2013); flash crowds: Jung et al. (2002); feature selection method: Guyon and Elisseeff (2003); AUC: Fawcett (2006); models and explanations: Chen and Guestrin (2016), Lundberg and Lee (2017), Wang et al. (2020).
"@

# ------------------------------------------------------------------------------------- save + export
$frame.Delete()
if (Test-Path $Out) { Remove-Item $Out -Force }
$pres.SaveAs($Out)
New-Item -ItemType Directory -Force $PngDir | Out-Null
Get-ChildItem $PngDir -Filter *.png | Remove-Item -Force
for ($i = 1; $i -le $pres.Slides.Count; $i++) { $pres.Slides($i).Export((Join-Path $PngDir ("slide-{0:d2}.png" -f $i)), "PNG", 1600, 900) }
"saved $Out with $($pres.Slides.Count) slides; PNGs in $PngDir"
$pres.Close(); $app.Quit()
