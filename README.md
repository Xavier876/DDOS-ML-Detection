# Explainable DDoS detection (COMP6310)

A desktop app (Python, PySide6) that loads CICFlowMeter flow CSVs from CSE-CIC-IDS2018,
scores every flow with a trained model (**flag** Benign / DDoS + **model score** from 0 to 1),
explains the model with **SHAP** charts, and supports an analyst review and feedback loop. XGBoost is
the main model; Random Forest and a linear SVM are the group's comparison models, trained on the same
splits and columns and usable in the app the same way (Model menu).

> **Observed with the nine-column model** (and with the update-4 set `f9p`): it detects DDoS tools it was
> trained on but does not transfer to unseen tools. **Update 5 (5 Nov 2026):** with the IP-window set
> `f7ip` (below) a tool the model never saw can be caught: held-out HOIC by all three model types, held-out
> LOIC-HTTP by the SVM and, below threshold 0.5, by XGBoost; an unseen UDP flood (LOIC-UDP) is not caught at all
> (retrained 5 Nov 2026 on the relabelled 20 Feb file: `docs\retrain_on_relabelled_feb20_2026-11-05.md`); the
> limits of that result are listed with the numbers. See Help → About / Model card and the
> Held-out comparison tab.

The model score is the model's raw output and has not been calibrated (training uses class weights:
`scale_pos_weight` for XGBoost, balanced class weights for the other two), so it is not a probability:
do not read 0.9 as a 90% chance of an attack. Scores of different model types are on different scales.

**Model inputs (default, update 5): 6 feature groups (7 columns)**, set `f7ip` = features 1 to 6. On
5 Nov 2026 the feature catalogue was renumbered so that **1 to 6 are the default model's inputs** in its
column order and 7 to 18 are the other groups; the table also gives each group's number in Week 3 of the
project document, which is how the report and the notes refer to them. The group settled on six feature
groups on 31 Oct 2026 (set `f9p` = features 7, 8, 9, 11, 4 and 12: rate, duration, inter-arrival time,
forward packet length, the ratio and the port window; update 4). A feature search
on 5 Nov 2026 (`docs\feature_search_findings_2026-11-05.md`) on the 21 Feb capture rebuilt from the raw
packets, with IP addresses, found that the per-flow size, rate and duration groups describe the attack
*tool* and do not carry over to a tool the model has not seen, while six groups describing what a flood
cannot avoid producing at the victim (traffic piling up on one target, many or repeating senders,
one-sided requests, machine timing) do, for XGBoost, Random Forest and the linear SVM alike. Those six
are now the default; the `f9p` models stay in the models folder as the baseline. **The group has not yet
confirmed this choice.** Groups 7 to 18 stay in the registry but are not inputs of the default:

| # | Week 3 doc | Group | Columns |
|---|---|---|---|
| 1 | 7 | **flows to the same destination IP** | `dst_ip_flows_10s` = flows of the same file to the same `Dst IP` that started in the 10 whole seconds before this flow (looks back only) |
| 2 | – | **distinct source IPs to the same destination IP** | `dst_ip_src_ips_10s` = distinct `Src IP` values with a flow to the same `Dst IP` in the 10 whole seconds before this flow |
| 3 | – | **flows from the same source IP** | `src_ip_flows_10s` = flows of the same file from the same `Src IP` in the 10 whole seconds before this flow |
| 4 | 3 | **forward/backward ratio** | `fwd_bwd_ratio` = `Tot Fwd Pkts / (Tot Bwd Pkts + 1)` |
| 5 | 10 | **no-reply and empty-payload indicators** | `no_reply` = (`Tot Bwd Pkts` == 0), `empty_payload` = (`Fwd Pkt Len Mean` == 0) |
| 6 | 11 | **timing regularity** | `iat_cv` = `Flow IAT Std / (Flow IAT Mean + 1)` (infinite → missing) |
| 7 | 1 | *not in the default set* (`f9p`): rate | `Flow Pkts/s`, `Flow Byts/s` |
| 8 | 2 | *not in the default set* (`f9p`): duration | `Flow Duration` |
| 9 | 4 | *not in the default set* (`f9p`): inter-arrival time | `Flow IAT Mean`, `Flow IAT Std` |
| 10 | 5 | *not in the default set*: SYN flag count | `SYN Flag Cnt` (0/1 only in this data; no attack flow has it) |
| 11 | 6 | *not in the default set* (`f9p`): forward packet length | `Fwd Pkt Len Mean`, `Fwd Pkt Len Std` |
| 12 | 7 (port version) | *not in the default set* (`f9p`): flows to the same destination port | `dst_port_flows_10s` = flows of the same file to the same `Dst Port` that started in the 10 whole seconds before this flow (looks back only) |
| 13 | 8 | *not in the default set*: reply behaviour | `Bwd Pkt Len Mean` |
| 14 | 9 | *not in the default set*: connection-ending flags | `RST Flag Cnt`, `FIN Flag Cnt` |
| 15 | 12 | *not in the default set*: response size ratio | `bwd_fwd_bytes_ratio` = `TotLen Bwd Pkts / (TotLen Fwd Pkts + 1)` |
| 16 | 13 | *not in the default set*: sender timing | `Fwd IAT Mean`, `Fwd IAT Min` |
| 17 | 14 | *not in the default set*: activity pattern | `Active Mean`, `Idle Mean` (0 in most flows) |
| 18 | 15 | *not in the default set*: payload signals | `PSH Flag Cnt`, `data_share` = `Fwd Act Data Pkts / Tot Fwd Pkts` (0/0 → missing) |

Groups 7 to 11 and 4 are the original nine columns (Week 3 features 1 to 6); 13, 14, 5 and 6 (Week 3
features 8 to 11) were added after the first experiments and 15 to 18 (Week 3 features 12 to 15) in
update 3 (22 Oct 2026; their text was drafted in the project chat and is in Week 3 of
`docs\Weeks_1_to_4_-_DDoS_Detection_Project_UPDATE3.docx`). Notebook sections 9b/9c measured the added
groups; the first comparison showed no recall change larger than the spread between seeds.

**The window features (1 to 3 and 12)** are the only features built from many rows: a 10-second
look-back over the whole capture file, keyed on the destination IP (1), both IPs (2), the source IP (3)
or the destination port (12). They need the **complete capture file** (on a random sample of rows the
counts are far too low; `scripts\make_sample.py` therefore cuts whole time slices), and the CSV must
contain `Timestamp` plus `Src IP` and `Dst IP` (1 to 3) or `Dst Port` (12). Those columns are used
only to count flows; IP addresses, ports and timestamps are never model inputs themselves. The window
features describe the traffic around a flow, so a flash crowd or a busy legitimate server also gets high
counts. Feature 12 was the update-4 stand-in for feature 1 because the published 21 Feb file has no `Dst IP`
column; the 21 Feb capture rebuilt from the raw packets (`DDoSDetector\scripts\pcap\README.md`,
`data\Wednesday-21-02-2018_victim_capture_labelled.csv`) has both IPs and corrected labels, and the
`f7ip` models are trained on it together with the 20 Feb file. Experiments and caveats:
`notebooks\ddos_update4_experiments.ipynb` (the port window), `docs\feature_search_findings_2026-11-05.md`
(the IP windows, three model types; that document uses the pre-renumbering labels F16, F18, F17, F3, F10,
F11 for what are now features 1 to 6).

Feature sets in the registry: `f7ip` (features 1 to 6, **the default**, update 5), `f9p` (7, 8, 9, 11, 4
and 12, update 4, the baseline), `f9` (the original nine: 7, 8, 9, 10, 11 and 4), `f15` (`f9` + 13, 14, 5, 6),
`f14` (`f15` without SYN Flag Cnt), `f21` (`f14` + 15 to 18, update 3). Train any of them with
`--feature-set`.
They are all defined in **one registry**, `DDoSDetector\app\core\features.py`, which training, scoring,
SHAP, the Features panel and the tests read. Each model's `.meta.json` lists its exact
`feature_columns`, so seven-, nine-, fifteen- and twenty-one-column models all load and score (models
without that field are treated as the original nine).

This is a university demo, not a production IDS.

## Folder layout

```
DDOS-ML-Detection\                 solution folder
  DDOS-ML-Detection.sln            open this in Visual Studio
  README.md  requirements.txt  .gitignore
  .venv\                           Python environment (git-ignored)
  data\                            CICFlowMeter CSVs (git-ignored)
  docs\                            handoffs (desktop app, update 1, update 2, project, session 1)
                                   and the Weeks 1-4 project document
  notebooks\                       the group's Jupyter notebooks (read ..\data; v2 §9b writes
                                   DDoSDetector\app\data\feature_evidence.csv, §9c writes
                                   DDoSDetector\models\feature_set_comparison.csv)
  DDoSDetector\                    the Visual Studio project
    DDoSDetector.pyproj
    app\         the desktop app
      main.py      entry point
      paths.py     folder locations (data, models, logs)
      workers.py   background threads
      core\        features.py (feature registry), csv_reader.py, model_store.py, scoring.py, explain.py,
                   impact.py (operational impact), review.py (verdicts, alerts, feedback),
                   feature_notes.py (assumption vs evidence), timing.py
      data\        feature_notes.json (Week 3 text per feature group), feature_evidence.csv (notebook 9b)
      plots\       one file per chart + base.py (plugin interface) and _style.py
      ui\          main_window.py, results_table.py, plot_panel.py, about_dialog.py, features_dialog.py
    train\       train_model.py
    scripts\     make_sample.py, feature_search_ip.py + ip_window_features.py (the 5 Nov 2026 search),
                 feature_evidence_windows.py, feature_choice_experiment.py, pcap\ (raw capture -> flows with IPs)
    tests\       pytest tests
    models\      trained models (.json, .meta.json, .background.parquet)
    logs\        app.log (created at runtime, git-ignored)
    build_exe.ps1  packages the app (output in bin\Release, git-ignored)
```

## Setup (Windows)

From the solution folder:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

Put the CSVs in `data\`. For the default `f7ip` models: `Tuesday-20-02-2018_relabelled.csv` (the published 20 Feb
file with its labels corrected by `DDoSDetector\scripts\pcap\relabel_feb20.py`) and the rebuilt 21 Feb file
`Wednesday-21-02-2018_victim_capture_labelled.csv` (built from the raw capture with `DDoSDetector\scripts\pcap\`;
see its README). The two published files, `Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` and
`Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv`, are only needed to retrain the `f9p` baseline or to re-run
`relabel_feb20.py` / `make_sample.py`; they were removed from `data\` on 5 Nov 2026 and live in
`C:\datasets\cse-cic-ids2018\processed` (copy them back when needed; that folder spells the first one "Thuesday").

## Run

**Visual Studio:** open `DDOS-ML-Detection.sln` and press **F5**. The project uses `.venv` as its
Python environment and `app\main.py` as its startup file. To open a CSV on launch, put its path in
Project → Properties → Debug → Script Arguments. Tests run from Test Explorer (pytest). A new `.py`
file runs without being added to the project; to see it in Solution Explorer use
right-click → Add → Existing Item.

**Command line** (from the solution folder):

```powershell
.\.venv\Scripts\python DDoSDetector\app\main.py                 # optional: path to a CSV
```

- **File → Open flows CSV…** reads in the background (progress bar + Cancel). The CSV must contain
  the raw columns the **active model** needs (for the default `f7ip` model: `Tot Fwd Pkts`,
  `Tot Bwd Pkts`, `Fwd Pkt Len Mean`, `Flow IAT Mean`, `Flow IAT Std`, and for the windows `Timestamp`,
  `Src IP` and `Dst IP`; for the `f9p` baseline the original nine columns plus `Timestamp` and `Dst Port`).
  Open the **whole capture file** (or a time slice of it), not a random sample of rows: the window
  features count the flows around each flow. If some columns are missing, a dialog names them and, when
  another model doesn't need them, offers to score with that model instead (a CSV without IP columns,
  such as the published 21 Feb file, gets the `all_tools_f9p` offer); it never scores with fewer features
  silently. `Label` is optional. Rows with NaN/infinite values in the model's core columns, or with an
  unreadable time, port or address for a window feature, are kept and shown as **Not scored**; for models
  opened by hand that use features 13, 14 or 15 to 18, missing values there are allowed (the tree models handle
  them; the linear SVM cannot, so for it such rows are Not scored) and counted in the summary bar.
- The default model is `all_tools_f7ip`; `all_tools_f9p` and the other `f9p` models ship alongside as the
  baseline. The status bar shows the model's name, its feature set and version. Sample files:
  `data\sample_wed_ip_slices.csv` (time slices of the rebuilt 21 Feb capture, with IPs) for the default;
  `data\sample_wed_slices.csv` (the published file, no IPs) exercises the fallback dialog.
- **Threshold** slider/spin box re-flags instantly. It starts at the loaded model's own default: the lowest
  tested threshold (0.5, 0.2, 0.1, 0.05, 0.01) whose false-alarm rate on that model's benign test split is within
  0.1 %, or 0.5 when none is; the Model card says which and why. The rule uses the benign side only, so a held-out
  tool never sets it. One threshold does not fit every model: a held-out model scores the unseen tool low (unseen
  LOIC-HTTP sits at 0.1–0.4 for XGBoost), so its default is 0.01 while the all-tools SVM's is 0.5. The budget is
  measured on the model's random test split; on `sample_wed_ip_slices.csv` (the attack hour on the attacked server)
  the default model at 0.01 flags 3 of the 88 benign flows and catches 0.989 of the attack, against 0 and 0.977 at
  0.5: the known cost of the window features on benign traffic *during* an attack. Filter by flag
  and by model-score range (the *Uncertain* button shows 0.2–0.8). Click a column header to sort.
- **Select a row** to see its SHAP waterfall (one bar per column, labelled with its feature
  number, e.g. `dst_ip_flows_10s (F1)`). Other tabs: global importance (bar), beeswarm, SHAP by tool, model
  score histogram, **Operational impact**, **Threshold sweep**, **Flash-crowd check**, **Seed
  stability**, **Model stability**, **Held-out comparison**, **Model types**, **Model types: features**,
  **Feature-set comparison**. Each chart has
  *Save as PNG* and *Copy to clipboard*. Tabs that need a `Label` column are disabled without one.
- **By column / by feature group**: the global bar, beeswarm and SHAP-by-tool charts have a choice
  above the chart. A group's value for a flow is the sum of its columns' SHAP values (SHAP is
  additive); importance is the mean absolute value of that sum. In the beeswarm, 0/1 columns are
  coloured by their value (0 = low, 1 = high) and missing values are grey.
- **Feature-set comparison**: reads `feature_set_comparison.csv` from notebook section 9c (from
  `DDoSDetector\models\` when present, or File → Open comparison results…; the file is no longer
  shipped since the 5 Nov 2026 clean-up, so the tab shows a message until one is opened). For each experiment it shows recall
  with the min–max spread across seeds, false alarms and PR-AUC for every feature set. It reports;
  it does not pick a "best" set. Differences smaller than the spread between seeds are noise.
- **Operational impact** (needs `Label`): confusion matrix with raw counts, recall, precision, F1,
  false positive rate and accuracy at the current threshold; per-tool recall with a warning below
  1,000 flows; and, for an **assumed attack prevalence** (default 0.1%), the expected precision and
  false alarms per million flows: `precision = recall·p / (recall·p + FPR·(1−p))`. That last part
  is an illustration, not a measurement. All of it is an upper bound: test and training data come
  from the same testbed.
- **Seed stability**: mean |SHAP| feature ranks for every model of the same setup trained with
  different seeds, on the same sample of loaded flows, plus the Spearman rank correlation between seeds.
- **Model stability**: the same comparison across *models* with the active model's feature set and
  model type (the seed-0 model of every setup: all tools, each tool held out, each benign split).
- **Model types**: XGBoost, Random Forest and the linear SVM side by side: recall per tool when the
  tool was seen in training and when it was held out (per-day split), and the all-tools model's false
  positive rate, from the models' metadata. **Model types: features** ranks the columns by mean |SHAP|
  for the all-tools model of each type on the same sample of loaded flows (ranks, because the SHAP
  units differ by type).
- **Held-out comparison**: recall on each tool when it was seen in training vs held out (per-day,
  by-file and attack-period benign splits), and each model's false positive rate, from the metadata
  of the models with the active model's feature set.
- **Threshold sweep** (needs `Label`): recall per tool and FPR at every threshold, the precision-recall
  curve with PR-AUC, ROC-AUC and the base rate, and a table at 0.5/0.2/0.1/0.05/0.01. Choosing a
  threshold on the same data is optimistic; the chart says so.
- **Flash-crowd check** (needs `Label`): false positive rate on all benign flows vs benign flows at or
  above a percentile (default 99th) of a "busyness" column: `Flow Pkts/s`, `Flow Byts/s` and, when the
  file allows them, the window counts `dst_ip_flows_10s` and `dst_port_flows_10s` (taken from the loaded
  file whether or not the active model uses them). The dataset has no labelled flash crowd, so busy
  benign flows are a proxy.
- **Help → Features…** lists the inputs of the loaded model ("Input 1 of 6 · Feature 1 …", in the
  model's column order, with the update-5 note for 1 to 3). A tick box, "Show the full catalogue", adds
  the other groups (7 to 18, marked "not in the default set"; 15 to 18 under "Added in update 3", 12
  with its update-4 note). Each heading also gives the group's number in the Week 3 project document (numbers
  inside the group's own text are those Week 3 numbers). Each group shows the Week 3 text (raw data, calculation,
  security behaviour, assumption, legitimate look-alike, evasion, notes), and for every column *what the data showed*: medians against benign flows from the same
  file, zero shares and single-feature AUC from `app\data\feature_evidence.csv` (notebook section 9b),
  with a computed verdict in plain words (supported / not supported so far / opposite of the
  assumption / unclear). The text lives in `app\data\feature_notes.json`. The only addition to the
  document's wording is an expected direction per column ("our reading of the assumption"), shown as
  such; the group should check it.
- **About / Model card** shows numbers only from the active model's metadata (and the other models
  with the same feature set). The group's recorded results (0.999 / 0.156 / 0.003 …) are shown only for
  nine-column models, labelled as such.
- **Model** menu lists every `DDoSDetector\models\*.meta.json`; switching re-scores the loaded file
  and keeps the analyst verdicts. The status bar shows the model version (a short hash of the model file).
- **Timing**: the status bar shows the measured load time, scoring speed (flows/s) and SHAP time per
  explanation for the last run; Help → About lists them in full; all are logged.
- **File → Export results CSV…** writes original row number, flag, model score, analyst verdict and
  note, the model's feature columns (and Label/actual tool when present).
- Errors are shown in dialogs and logged to `DDoSDetector\logs\app.log`.

Units: the table's model score is a number from 0 to 1 (not calibrated). SHAP values are in the
model's own units, and `base value + sum(SHAP) = f(x)` for every flow:

| Model | SHAP units, f(x) | Model score | Explainer |
|---|---|---|---|
| XGBoost | log-odds | `sigmoid(f(x))` | TreeSHAP (XGBoost's own, = shap's TreeExplainer) |
| Random Forest | model score itself | `f(x)` (average over trees of the DDoS share in the leaf) | shap's TreeExplainer |
| Linear SVM | SVM decision value | `sigmoid(f(x))`, so 0.5 is the SVM's own boundary | exact: weight × standardised log-scaled input |

The charts label their axes with the active model's units.

### Analyst workflow and feedback

1. **Verdicts:** right-click a row (or Ctrl+1 / Ctrl+2 / Ctrl+3 / Ctrl+0) to mark it *confirmed
   attack*, *false positive*, *unsure* or *unreviewed*; *Edit note…* (Ctrl+N) adds free text to the
   current row.
   **Bulk labelling:** Shift-click selects a range of rows and Ctrl-click adds rows; the verdict then
   applies to every selected row (more than 100 rows asks first). Right-click → *All N shown rows*
   gives every row the current filters show one verdict (always asks first). To label a whole
   incident, filter and sort the table (for example by Timestamp or Label), select the incident's
   rows and mark them. Labelling only the alerts teaches a retrained model little: in the Week 5
   retraining demonstration (`notebooks\ddos_week5_threshold_retraining_update6.ipynb`, section 4) about 4,000 alert
   labels left recall on a new tool at about 0.42, while 10,000 flows of the incident raised it to 0.99.
2. **File → Save review… / Open review…** stores `review_<csvname>.json`: row number, source file,
   model score, flag and threshold at review time, verdict, note, model name and version. Opening it
   with the same CSV restores every verdict and note (matched by row number). The app asks before
   discarding unsaved verdicts.
3. **File → Export alerts for SIEM…** writes the flows flagged DDoS at the current threshold to both
   `alerts_<name>.csv` and `alerts_<name>.jsonl`, one record per alert: `alert_id`, `row_number`,
   `source_file`, `timestamp`, `src_ip`, `dst_ip`, `dst_port` (tracing fields, only if those columns
   are in the input; never model inputs), `model_name`, `model_version`, `model_score`, `threshold`,
   `flag`, `top_feature_1..3` (e.g. `Flow Duration (F2): pushes toward DDoS`). It's a file only;
   there is no SIEM integration.
4. **File → Export labelled feedback…** writes the active model's feature columns plus `label`
   (*confirmed attack* → 1, *false positive* → 0; *unsure* and *unreviewed* are left out),
   `source_file` and `row_number`. Retrain with the same feature set as the model that exported it.
5. **Retraining is a manual step:**
   ```powershell
   .\.venv\Scripts\python DDoSDetector\train\train_model.py --mode all_tools --extra-labelled feedback_x.csv
   ```
   The feedback rows are added to the training split only (the test split stays comparable) and the
   new model is saved as `all_tools_f7ip_feedback` (use `--name` to change it), so the shipped model is
   not overwritten. Open it with Model → Open model… (or restart the app; the Model menu lists the
   models found at start-up). Feedback must come from the same version of the app as the training
   script: a file exported by an older version of the app lacks the current columns and is refused.

## Train

```powershell
# the default set f7ip needs the files with IP addresses (the published 21 Feb file has none):
.\.venv\Scripts\python DDoSDetector\train\train_model.py --mode all_tools --files Tuesday-20-02-2018_relabelled.csv Wednesday-21-02-2018_victim_capture_labelled.csv
.\.venv\Scripts\python DDoSDetector\train\train_model.py --mode held_out --held-out HOIC LOIC-HTTP LOIC-UDP --files Tuesday-20-02-2018_relabelled.csv Wednesday-21-02-2018_victim_capture_labelled.csv
.\.venv\Scripts\python DDoSDetector\train\train_model.py --mode all_tools --feature-set f9p   # update 4's six on the published pair (copy them into data\ first, see Install)
.\.venv\Scripts\python DDoSDetector\train\train_model.py --mode all_tools --feature-set f9    # original nine
.\.venv\Scripts\python DDoSDetector\train\train_model.py --mode all_tools --model random_forest --files ...
.\.venv\Scripts\python DDoSDetector\train\train_model.py --mode all_tools --model linear_svm --files ...
```

`--files` names the CSVs in `data\` to train on (default: the two published files). A file that cannot
provide a core input of the chosen set stops the run with a message naming the missing column; rows
with no readable time, port or address for a window feature are left out (counted per file), as the
app leaves them Not scored.

`--model` picks the model type (default `xgboost`); the settings of every type are in
`DDoSDetector\app\core\models.py`, shared with the app. Random Forest: 100 trees, depth 12, at least 20
flows per leaf, balanced class weights (shallower than the update-4 experiment's forest, so SHAP stays
fast: 0.9 s for 500 flows instead of 4.0 s, same recall to three decimals). Linear SVM: inputs
log-scaled (`sign(x)·log(1+|x|)`) and standardised, `C=1`, balanced class weights. Names get `_rf` or
`_svm` (`all_tools_f9p_rf`, `hoic_held_out_f9p_svm`, …). Every type gets exactly the same splits for a
given seed, so their test numbers are comparable.

`--feature-set f7ip` (default) names the output `<setup>_f7ip` (`f9p` → `<setup>_f9p`, `f21` →
`<setup>_f21`, `f15` → `<setup>_f15`, `f14` → `<setup>_f14`); `f9` keeps the original names (`all_tools`,
`hoic_held_out`, …). The window features are counted per file on every row read, before cleaning, as the app does for the file it
opens. As in the notebook, rows with
missing/infinite values in the original columns are dropped for training, duplicates are judged on
the original columns only (not the port, the IPs or the window features, so the row count is unchanged: 8,788,935), and
missing values in the new columns are left for XGBoost. If a file lacks a new raw column, the script
prints it and leaves that group out (recorded in the metadata).

Defaults read from `data\` and write to `DDoSDetector\models\` (override with `--data-dir`, `--out`).
Each run takes about a minute (reading the 3.9 GB file is most of it) and writes:

| File | Contents |
|---|---|
| `<name>.json` or `<name>.joblib` | the model: XGBoost's own JSON format, or joblib for Random Forest and the linear SVM (joblib is a pickle: only open model files you made) |
| `<name>.meta.json` | `feature_columns` (in order), `feature_groups`, `feature_set`, label mapping, split, seed, row counts, hyperparameters, this model's own test metrics, timing, library versions |
| `<name>.background.parquet` | 1,000 training rows (250 per tool) as a SHAP reference sample |

**Held-out rotation** (hold out each tool in turn; data loaded once):

```powershell
.\.venv\Scripts\python DDoSDetector\train\train_model.py --mode held_out --held-out HOIC LOIC-HTTP LOIC-UDP
.\.venv\Scripts\python DDoSDetector\train\train_model.py --mode held_out --held-out HOIC LOIC-HTTP LOIC-UDP --benign-split attack_period
```

`--benign-split per_day` (default, as in the notebook): the earlier 70% of each file's benign flows
train, the later 30% test. `by_file` (notebook): benign flows of the earlier file train, the later
file's test. `attack_period`: benign flows inside the held-out tool's attack window (same file) test,
all other benign flows train. `--mode hoic_held_out` still works (= `held_out --held-out HOIC`).

Options: `--seed N` (output name becomes `<name>_seedN`), `--seeds 0 1 2 3 4` (loads the data once
and trains one model per seed, for the Seed stability chart; the metadata records `setup` and
`seed`), `--extra-labelled FILE…` (analyst feedback, see above), `--name`, and `--nrows N` for a
quick run on the first N rows of each file. Each model's metadata records its measured training time
and test-prediction time (shown in Help → About).

Models in `DDoSDetector\models\` now (each model's own test split, threshold 0.5, from its metadata).

`f7ip` (the default, update 5; retrained 5 Nov 2026 on the relabelled 20 Feb file + the rebuilt 21 Feb capture,
`scripts\pcap\relabel_feb20.py` and `label_flows.py`: 9,880,087 flows, Benign 7,182,913, HOIC 2,116,841,
LOIC-HTTP 575,506, LOIC-UDP 4,827 = 2,527 flood flows + 2,300 ICMP reply rows labelled as attack by-products).
Benign test flows: all tools 300,000; held out per day 2,154,875; by file 1,982 (the 21 Feb capture's genuinely
benign flows); attack period 474 (HOIC), 900,104 (LOIC-HTTP, the attack hour on 20 Feb) and 3,342,719 (LOIC-UDP:
its two runs are on different days, so its "attack period" spans the 20 Feb afternoon and the 21 Feb morning and
that row says little). The numbers before this retrain, and why they changed, are in
`docs\retrain_on_relabelled_feb20_2026-11-05.md`.

| Model | XGBoost | Random Forest | Linear SVM |
|---|---|---|---|
| `all_tools_f7ip*` (seeds 0–4): recall HOIC / LOIC-HTTP / LOIC-UDP | 1.000 / 1.000 / 0.986–0.990 | 1.000 / 1.000 / 0.970–0.975 | 1.000 / 0.999 / 0.494–0.505 |
| `all_tools_f7ip*`: FPR (false alarms of 300,000 benign) | 0.0000 (5–10) | 0.0000 (0–3) | 0.0005 (145–164) |
| `hoic_held_out_f7ip*` per day / `_by_file_` / `_attack_period_`: HOIC | 1.000 / 1.000 / 1.000 | 0.755 / 0.999 / 0.996 | 1.000 / 1.000 / 1.000 |
| the same: FPR (false alarms) | 0.0000 (74) / 0.0045 (9) / 0.0084 (4) | 0.0001 (269) / 0.037 (73) / 0.150 (71) | 0.0008 (1,827) / 0.115 (228) / 0.458 (217) |
| `loic_http_held_out_f7ip*` per day / by file / attack period: LOIC-HTTP | 0.010 / 0.481 / 0.958 | 0.483 / 0.495 / 0.493 | 0.971 / 0.958 / 0.974 |
| the same: FPR (false alarms) | 0.0000 (18) / 0.149 (295) / 0.0000 (23) | 0.0000 (103) / 0.146 (289) / 0.0000 (11) | 0.0002 (439) / 0.102 (203) / 0.0007 (630) |
| `loic_udp_held_out_f7ip*` per day / by file / attack period: LOIC-UDP | 0.000 / 0.000 / 0.000 | 0.000 / 0.000 / 0.000 | 0.000 / 0.000 / 0.000 |
| the same: FPR (false alarms) | 0.0000 (21) / 0.0045 (9) / 0.0000 (25) | 0.0000 (2) / 0.117 (232) / 0.0000 (2) | 0.0000 (4) / 0.146 (289) / 0.0000 (7) |
| Training time, all tools (2.6 million flows) | 13–15 s | 39–40 s | 4 s |

How to read it: the **per-day held-out rows** are the main result. Unseen HOIC is caught by all three types
(XGBoost and the SVM 1.000; Random Forest 0.76, and it varies between seeds). Unseen LOIC-HTTP is caught by the
SVM (0.97) and half of it by Random Forest (0.48); XGBoost scores it 0.010 at threshold 0.5 but 0.48 at 0.2 and
0.96 at 0.01 (FPR 0.0005), the same on three seeds: it ranks the flows right (PR-AUC 0.999) but scores them low,
so quote its threshold sweep, not one number. **Unseen LOIC-UDP is not caught at all** (0.000 at every threshold,
every model type, every split). The 0.52 reported before the 5 Nov retrain was not a held-out result: 797 of the
20 Feb flood flows are labelled LOIC-HTTP in the published file, so they sat inside the training set of the
"LOIC-UDP never seen" models. The flood's window features are tiny (each flow lasts the full 120 s) and "no
reply" alone is not an attack signal in this data. With `f9p` the per-day rows were 0.18–0.49 for HOIC and
0.005–0.16 for LOIC-HTTP. The **by-file and attack-period rows** are the honest look at the cost of window
features, on small benign sets: benign flows on the attacked network *during* the attack get high counts too, so
in the HOIC hour XGBoost flags 4 of the 474 genuinely benign flows, Random Forest 71 and the SVM 217; and trained
on 20 Feb benign only (by file), Random Forest and the SVM flag 10–15 % of the 21 Feb capture's benign flows
(mostly IKE, SSH and SMB admin traffic the 20 Feb network did not have), XGBoost 0.5 % except for LOIC-HTTP held
out (0.149, recall 0.481). What lets XGBoost keep the HOIC-hour false alarms at 4 of 474 is the source window: the
benign flows to the attacked server come from addresses that sent nothing else (0 flows from the same source,
against 710 for HOIC). The all-tools rows are the optimistic upper bound as before (LOIC-UDP 0.99 there because
the model has seen both the flood and the ICMP reply rows). Limits that apply to every number: one network, two days, ten
attacking machines (feature 2 learned "about ten senders"), a quiet victim server (median 7 flows per 10 s
outside the attacks); a busy legitimate server or a flash crowd was not available to test.

`f9p` (update 4, the baseline; trained 31 Oct 2026 on the two published files):

| Model | Recall on the tool | FPR (false alarms) |
|---|---|---|
| `all_tools_f9p` (seeds 0–4) | HOIC 1.000, LOIC-HTTP 1.000, LOIC-UDP 1.000 | 0.0002–0.0003 (70–103) |
| `hoic_held_out_f9p` / `_by_file_f9p` / `_attack_period_f9p` | HOIC 0.397 / 0.369 / 0.362 | 0.0020 (4,514) / 0.0000 (0) / 0.0000 (0) |
| `loic_http_held_out_f9p` / `_attack_period_f9p` | LOIC-HTTP 0.002 / 0.003 | 0.0005 (1,218) / 0.0045 (25,701) |
| `loic_udp_held_out_f9p` / `_attack_period_f9p` | LOIC-UDP 0.994 / 0.994 (1,730 flows) | 0.0023 (5,238) / 0.0000 (0) |

The comparison models (trained 4 Nov 2026, same splits and columns; names end in `_rf` / `_svm`):

| Model | Random Forest | Linear SVM |
|---|---|---|
| `all_tools_f9p_*` (seeds 0–4): recall HOIC / LOIC-HTTP / LOIC-UDP | 0.9997–0.9998 / 0.9998–0.9999 / 1.000 | 0.997 / 0.998–0.999 / 0.898–0.929 |
| `all_tools_f9p_*`: FPR (false alarms of 300,000 benign) | 0.0003–0.0004 (87–114) | 0.0044–0.0046 (1,325–1,366) |
| `hoic_held_out_f9p_*` / `_by_file_` / `_attack_period_`: HOIC | 0.393 / 0.374 / 0.377 | 0.799 / 0.622 / 0.627 |
| `hoic_held_out_f9p_*` (per day): FPR (false alarms) | 0.0049 (11,120) | 0.0081 (18,411) |
| `loic_http_held_out_f9p_*` / `_attack_period_`: LOIC-HTTP | 0.003 / 0.014 | 0.026 / 0.013 |
| `loic_udp_held_out_f9p_*` / `_attack_period_`: LOIC-UDP | 0.999 / 1.000 | 0.000 / 0.000 |
| Training time, all tools (1.6 million flows) | 46–53 s (XGBoost 9–10 s) | 4–5 s |
| SHAP per flow (batches of 2,000) | 2.2 ms (XGBoost 0.15 ms) | 0.005 ms |

How to read it: on tools seen in training XGBoost and Random Forest are equally good and the linear SVM
is clearly worse (misses 7–10% of LOIC-UDP, about 13 times the false alarms). On unseen tools no model
transfers reliably: the SVM catches more unseen HOIC but with more false alarms, misses unseen LOIC-UDP
completely, and no model catches unseen LOIC-HTTP. On the HOIC flows the SVM catches and XGBoost misses,
both see the high port count as attack-like; the inter-arrival time pushes XGBoost strongly towards
benign (−10.2 log-odds on average) while the SVM gives it little weight. All three rank the port window first
by mean |SHAP|. XGBoost stays the main model. Random Forest SHAP is slow, so with a forest the Seed
stability and Model stability charts and the alert export take seconds to tens of seconds (a worker
thread; the window stays usable).

How to read it: the **all-tools** numbers are not trustworthy with the port window, because training and test
flows share the same seconds of the same attack. The held-out rows are the honest test: unseen HOIC is
caught at about 0.36–0.40 (nine columns: 0.15–0.21), unseen LOIC-HTTP still at 0.002–0.003. The
attack-period benign flows of the 21 Feb file are mostly the HOIC replies described below, so its zero
false alarms say little about normal users. Each held-out row is one seed. Held-out LOIC-UDP is caught
almost entirely through `fwd_bwd_ratio` (its flows send ~120,000 forward packets per backward packet):
one extreme feature on 1,730 flows, not evidence of transfer to unseen tools. The experiment behind the
choice (two seeds, every swap candidate, Random Forest and logistic regression) is in
`notebooks\ddos_update4_experiments.ipynb`.

Other feature sets are not shipped on this branch. They are in Git history (commit `a61c4fa` has the
nine-column models, branch `main` the 21-column ones) and can be retrained with `--feature-set`:
- nine columns (`all_tools`, `hoic_held_out`, …, `f9`): all tools HOIC 0.999, LOIC-HTTP 0.987–0.990,
  LOIC-UDP 1.000, FPR 0.0091–0.0108; held out HOIC 0.212 / 0.149 / 0.153, LOIC-HTTP 0.003, LOIC-UDP 1.000;
- twenty-one columns (`*_f21`, on `main`): all tools HOIC 0.999, LOIC-HTTP 0.989–0.990, LOIC-UDP 1.000,
  FPR 0.0079–0.0084; held out HOIC 0.214 / 0.180 / 0.153 (per day / by file / attack period),
  LOIC-HTTP 0.003, LOIC-UDP 1.000 / 0.994;
- fifteen columns (`*_f15`, in history up to commit `c94cb33`): all tools HOIC 0.999, LOIC-HTTP
  0.987–0.988, LOIC-UDP 0.998–1.000, FPR 0.0091–0.0097; held out HOIC 0.212 / 0.149 / 0.153,
  LOIC-HTTP 0.003, LOIC-UDP 1.000 / 0.994.

| Mode | Split (follows `notebooks\ddos_xgboost_starter_v2.ipynb`) |
|---|---|
| `all_tools` | benign capped at 1M + all attacks, random 70/30 split stratified by tool (notebook §10; optimistic upper bound) |
| `held_out` | trained on the other two tools + benign, tested on the held-out tool; per-day or by-file (notebook §7) or attack-period benign split |

Small test files from the Wednesday CSV:
`.\.venv\Scripts\python DDoSDetector\scripts\make_sample.py --seconds 40` (writes
`sample_wed_slices.csv`, a no-label copy and a missing-column file to `data\`). Because of the window features
it keeps every flow in two time slices (40 s of HOIC with the most benign flows, and the whole
LOIC-UDP attack) instead of sampling rows at random; flows in the first 10 s of a slice get lower
counts than in the full file. The older random-row samples (`sample_wed_50k*.csv`) gave window counts
that were far too low and were deleted on 5 Nov 2026. These rows overlap with the training data, so metrics on
them are optimistic.

**Data quirk (21 Feb file):** almost all of its 360,833 benign flows fall inside the HOIC attack
(02:17–02:33), about one per HOIC flow, sent to high TCP client ports (median 56,825, each port reused
by many flows).
They look like the web server's side of the HOIC connections labelled benign (our reading; the
dataset does not say). So the attack-period benign split mostly tests those flows, not normal users
of a busy server.

**Notebook outputs the app reads:** in `notebooks\ddos_xgboost_starter_v2.ipynb`, section 9b writes
`DDoSDetector\app\data\feature_evidence.csv` (Help → Features) and section 9c writes
`DDoSDetector\models\feature_set_comparison.csv` (Feature-set comparison tab; not shipped since the
5 Nov 2026 clean-up, re-run 9c to recreate it). The whole notebook runs in about 7 minutes on the full
data (it needs sections 0–6 first).

## Add a chart

Create one file in `DDoSDetector\app\plots\`, e.g. `my_chart.py`:

```python
from . import _style as S
from .base import ChartPlugin, register

@register
class MyChart(ChartPlugin):
    name = "My chart"        # tab title
    needs_label = False      # True: tab disabled when the CSV has no Label column
    scope = "global"         # "global" = sample of rows, "row" = the selected row
    needs_shap = True        # False if you only use scores/features
    order = 70               # tab position
    # optional inputs shown above the chart (read with self.option(ctx, "k")):
    # options = {"k": Option("Some setting", default=1.0, minimum=0.0, maximum=10.0)}
    # or a choice (combo box), e.g. the shared column/group switch: options = {"view": VIEW_OPTION}
    # and then: values, labels, data = shap_view(r.values, r.data, self.option(ctx, "view"))

    def render(self, figure, ctx):
        S.style_figure(figure)
        r = ctx.sample_shap()          # cached ShapResult: .values, .base_value, .data, .rows
        ax = figure.add_subplot()
        ax.hist(r.values[:, 0])
        S.title(figure, ax, "My chart", "what it shows")
        S.finish(figure)
```

That's all: modules in `app\plots\` are discovered automatically. `ctx` (`ChartContext` in
`app\plots\base.py`) holds the model, features `X`, `scores`, `threshold`, `tools` (or `None`),
`selected` row, the model's metadata and folder, option values, and lazily cached SHAP
(`ctx.row_shap()`, `ctx.sample_shap()`, `ctx.cache.explain_rows(rows, key)`, or
`ctx.cache.memo(key, fn)` for anything else). Heavy work happens in `prepare()`, which runs in a worker
thread; `render()` runs on the UI thread and must draw onto the given `figure` (never `plt.figure()`).

## Add a model

Train it with `train_model.py` (or any script that calls `app.core.model_store.save_bundle`
with a `features` list in the metadata) and put the files in `DDoSDetector\models\`. A new model type
needs an entry in `app\core\models.py` (settings, save/load, `model_type_of`) and, if SHAP needs
something other than TreeExplainer, a case in `app\core\explain.py`. It appears in
the Model menu, or use *Open model…* for a `.meta.json` elsewhere. The feature list is checked
before scoring. The Model menu groups models by type (XGBoost, Random Forest, Linear SVM). At the top level
it lists the default set's main models (all tools, and each tool held out with the per-day benign split);
submenus per type hold the other benign splits (by file, attack period), the baseline `f9p` models, and
the seed variants (`*_seed1..4`, used by the Seed stability chart).

## Tests

```powershell
.\.venv\Scripts\python -m pytest DDoSDetector\tests
```

Covers label mapping, feature building (incl. `fwd_bwd_ratio` with zero backward packets),
cleaning (inf/NaN/repeated headers/stray spaces), missing columns, scoring and flags at several
thresholds, SHAP additivity (`base + sum(SHAP) == predict(output_margin=True)`), model save/load,
the chart registry and every chart rendering (with and without Label), the table model
(threshold, sort, filter, 1M rows) and worker threading; and for update 1: the operational-impact
numbers against a hand calculation, review save/reload, alert CSV + JSON Lines (every line parsed,
only allowed fields), feedback export rules, `--extra-labelled`, the Features panel with and without
the evidence file, measured timings, seed stability, XGBoost TreeSHAP = shap's TreeExplainer, and a
scan of the app and this README for wording that misdescribes the model score (acceptance 11); and
for the held-out rotation: setup names, both benign splits on a hand-built example, the threshold
sweep and ROC-AUC against a hand calculation, the high-rate false positive rate, the held-out results
table, the model card's timing and held-out table, and the new charts; and for update 2: the
registry's column order and groups, the Week 3 worked example (ratio 1.0, `Bwd Pkt Len Mean` 530,
`iat_cv` 50,000/125,001), edge cases (no replies, empty payload, IAT mean −1), missing new columns
(dialog + nine-column model still scores), legacy models without `feature_columns`, group SHAP
additivity on a 15-column model, both chart views, the feature-set comparison chart, the model card
using only metadata, a scan that no feature list exists outside the registry, the Features panel's 10
groups, and a scan for any claim that the added groups improve detection; for update 3: the f14/f21
sets, the formulas of the update-3 groups and a 21-column model scoring without `SYN Flag Cnt`; and for
update 4: the `f9p` set, the port window against a hand-worked example (look
back only, same second not counted, per capture file, row order irrelevant, text and parsed times
equal, unreadable time or port → Not scored), the port staying text through the CSV reader, the
missing-column check naming `Timestamp`/`Dst Port`, the model card and Features panel wording, and
every model in `DDoSDetector\models\` using `f9p`; and for bulk labelling: verdicts on several
selected rows, the confirmation above 100 rows (and nothing changing when it is declined), *All shown
rows* following the filters, the right-click menu, and bulk labels reaching the feedback export; for
update 5: `f7ip` as the default set and app default, the three IP windows against hand-worked examples
(look back only, a source counted once however many flows it sends, per capture file, row order
irrelevant), a missing address or time → Not scored, addresses staying text through the CSV reader, the
missing-column check naming `Dst IP`/`Src IP` while `f9p` still fits, training building the windows per
file and stopping on a file without IPs, the Features panel and model card wording, and every model in
`DDoSDetector\models\` using `f7ip` or `f9p`; and
for the three model types: a 0–1 score from each, the SVM's score = sigmoid(decision value), save and
load keeping the type and the scores, a file of the wrong type refused, SHAP additivity per type
(`base + sum(SHAP) = f(x)` and the score following from it), the SVM's SHAP = weight × standardised
input, the SVM not scoring rows with missing values, training each type with `--model`, the output
names, the model card and every chart for each type, and the two Model types charts.
Tests use synthetic data, not the CSVs (the f9p check reads the trained models' metadata).

## Package

```powershell
powershell -ExecutionPolicy Bypass -File DDoSDetector\build_exe.ps1
```

Builds `DDoSDetector\bin\Release\DDoSExplainer\DDoSExplainer.exe` with the models copied next to
it (about 430 MB; zip the `DDoSExplainer` folder to share it). Logs go to a `logs\` folder next to
the `.exe`. PyInstaller's intermediate files go to `DDoSDetector\obj\`.
