# Explainable DDoS detection (COMP6310)

A desktop app (Python, PySide6) that loads CICFlowMeter flow CSVs from CSE-CIC-IDS2018,
scores every flow with an XGBoost model (**flag** Benign / DDoS + **model score** from 0 to 1),
explains the model with **SHAP** charts, and supports an analyst review and feedback loop.

> **Observed with the nine-column model:** it detects DDoS tools it was trained on but does not
> transfer to unseen tools. For the fifteen-column model, the app and the training script report the
> numbers; see Help → About / Model card and the Held-out comparison tab.

The model score is the model's raw output and has not been calibrated (training uses
`scale_pos_weight`), so it is not a probability: do not read 0.9 as a 90% chance of an attack.

**Model inputs: 10 feature groups (15 columns)**, numbered as in Week 3 of the project document
(feature 7 was dropped):

| # | Group | Columns |
|---|---|---|
| 1 | rate | `Flow Pkts/s`, `Flow Byts/s` |
| 2 | duration | `Flow Duration` |
| 3 | forward/backward ratio | `fwd_bwd_ratio` = `Tot Fwd Pkts / (Tot Bwd Pkts + 1)` |
| 4 | inter-arrival time | `Flow IAT Mean`, `Flow IAT Std` |
| 5 | SYN flag count | `SYN Flag Cnt` |
| 6 | forward packet length | `Fwd Pkt Len Mean`, `Fwd Pkt Len Std` |
| 7 | *dropped* | flows to the same destination in a 10 s window: the 21 Feb file has no `Dst IP` |
| 8 | reply behaviour | `Bwd Pkt Len Mean` |
| 9 | connection-ending flags | `RST Flag Cnt`, `FIN Flag Cnt` |
| 10 | indicators | `no_reply` = (`Tot Bwd Pkts` == 0), `empty_payload` = (`Fwd Pkt Len Mean` == 0) |
| 11 | timing regularity | `iat_cv` = `Flow IAT Std / (Flow IAT Mean + 1)` (infinite → missing) |

Groups 1–6 are the original nine columns; 8–11 were added after the first experiments. Notebook
section 9c measures whether they help. They are all defined in **one registry**,
`DDoSDetector\app\core\features.py`, which training, scoring, SHAP, the Features panel and the tests read.
Each model's `.meta.json` lists its exact `feature_columns`, so nine- and fifteen-column models both
load and score (models without that field are treated as the original nine).

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
    scripts\     make_sample.py
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

Put the CSVs in `data\`:
`Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`, `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv`.

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
  the raw columns the **active model** needs (for the fifteen-column model also `Bwd Pkt Len Mean`,
  `RST Flag Cnt`, `FIN Flag Cnt`). If some are missing, a dialog names them and, when another model
  doesn't need them (e.g. the nine-column `all_tools`), offers to score with that model instead; it
  never scores with fewer features silently. `Label` and `Timestamp` are optional. Rows with
  NaN/infinite values in the original nine columns are kept and shown as **Not scored**; missing
  values in features 8–11 are allowed (XGBoost handles them) and counted in the summary bar.
- The default model is `all_tools_f15` (falls back to `all_tools`). The status bar shows the model's
  name, its feature set and version.
- **Threshold** slider/spin box re-flags instantly. Filter by flag and by model-score range
  (the *Uncertain* button shows 0.2–0.8). Click a column header to sort.
- **Select a row** to see its SHAP waterfall (one bar per column, labelled with its feature number,
  e.g. `empty_payload (F10)`). Other tabs: global importance (bar), beeswarm, SHAP by tool, model
  score histogram, **Operational impact**, **Threshold sweep**, **Flash-crowd check**, **Seed
  stability**, **Model stability**, **Held-out comparison**, **Feature-set comparison**. Each chart has
  *Save as PNG* and *Copy to clipboard*. Tabs that need a `Label` column are disabled without one.
- **By column / by feature group**: the global bar, beeswarm and SHAP-by-tool charts have a choice
  above the chart. A group's value for a flow is the sum of its columns' SHAP values (SHAP is
  additive); importance is the mean absolute value of that sum. In the beeswarm, 0/1 columns are
  coloured by their value (0 = low, 1 = high) and missing values are grey.
- **Feature-set comparison**: reads `feature_set_comparison.csv` from notebook section 9c (from
  `DDoSDetector\models\`, or File → Open comparison results…). For each experiment it shows recall
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
- **Model stability**: the same comparison across *models* with the active model's feature set (the
  seed-0 model of every setup: all tools, each tool held out, each benign split).
- **Held-out comparison**: recall on each tool when it was seen in training vs held out (per-day,
  by-file and attack-period benign splits), and each model's false positive rate, from the metadata
  of the models with the active model's feature set.
- **Threshold sweep** (needs `Label`): recall per tool and FPR at every threshold, the precision-recall
  curve with PR-AUC, ROC-AUC and the base rate, and a table at 0.5/0.2/0.1/0.05/0.01. Choosing a
  threshold on the same data is optimistic; the chart says so.
- **Flash-crowd check** (needs `Label`): false positive rate on all benign flows vs benign flows at or
  above a percentile (default 99th) of `Flow Pkts/s` and `Flow Byts/s`. The dataset has no labelled
  flash crowd, so high-rate benign flows are a proxy.
- **Help → Features…** lists the 10 feature groups (1–6, 8–11, and 7 as dropped) with the group's
  Week 3 text (raw data, calculation, security behaviour, assumption, legitimate look-alike, evasion,
  notes), and for every column *what the data showed*: medians against benign flows from the same
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

Units: the table's model score is a number from 0 to 1 (not calibrated); SHAP values are
**log-odds**. `base value + sum(SHAP) = f(x)` and `model score = sigmoid(f(x))`.

### Analyst workflow and feedback

1. **Verdicts:** right-click a row (or Ctrl+1 / Ctrl+2 / Ctrl+3 / Ctrl+0) to mark it *confirmed
   attack*, *false positive*, *unsure* or *unreviewed*; *Edit note…* (Ctrl+N) adds free text.
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
   new model is saved as `all_tools_f15_feedback` (use `--name` to change it), so the shipped model is
   not overwritten. Open it from the Model menu.

## Train

```powershell
.\.venv\Scripts\python DDoSDetector\train\train_model.py --mode all_tools                    # 15 columns
.\.venv\Scripts\python DDoSDetector\train\train_model.py --mode all_tools --feature-set f9   # original nine
.\.venv\Scripts\python DDoSDetector\train\train_model.py --mode hoic_held_out
```

`--feature-set f15` (default) trains on all fifteen columns and names the output `<setup>_f15`;
`f9` keeps the original names (`all_tools`, `hoic_held_out`, …). As in the notebook, rows with
missing/infinite values in the original columns are dropped for training, duplicates are judged on
the original columns only, and missing values in the new columns are left for XGBoost. If a file
lacks a new raw column, the script prints it and leaves that group out (recorded in the metadata).

Defaults read from `data\` and write to `DDoSDetector\models\` (override with `--data-dir`, `--out`).
Each run takes about a minute (reading the 3.9 GB file is most of it) and writes:

| File | Contents |
|---|---|
| `<name>.json` | XGBoost model |
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

Fifteen columns (`*_f15`):

| Model | Recall on the tool | FPR (false alarms) |
|---|---|---|
| `all_tools_f15` (seeds 0–4) | HOIC 0.999, LOIC-HTTP 0.987–0.988, LOIC-UDP 0.998–1.000 | 0.0091–0.0097 |
| `hoic_held_out_f15` / `_by_file_f15` / `_attack_period_f15` | HOIC 0.212 / 0.149 / 0.153 | 0.0077 (17,460) / 0.0000 (7) / 0.0000 (0) |
| `loic_http_held_out_f15` / `_attack_period_f15` | LOIC-HTTP 0.003 / 0.003 | 0.0055 (12,352) / 0.0062 (35,386) |
| `loic_udp_held_out_f15` / `_attack_period_f15` | LOIC-UDP 1.000 / 0.994 (1,730 flows) | 0.0091 (20,628) / 0.0042 (7) |

Nine columns (original names):

| Model | Recall on the tool | FPR (false alarms) |
|---|---|---|
| `all_tools` (seeds 0–4) | HOIC 0.999, LOIC-HTTP 0.987–0.990, LOIC-UDP 1.000 | 0.0091–0.0108 |
| `hoic_held_out` / `_attack_period` | HOIC 0.212 / 0.153 | 0.0077 (17,493) / 0.0000 (0) |
| `loic_http_held_out` / `_attack_period` | LOIC-HTTP 0.003 / 0.003 | 0.0055 (12,450) / 0.0062 (35,537) |
| `loic_udp_held_out` / `_attack_period` | LOIC-UDP 1.000 / 1.000 (1,730 flows) | 0.0092 (20,754) / 0.0042 (7) |

With nine columns, held-out LOIC-UDP was still caught almost entirely through `fwd_bwd_ratio` (its flows
send ~120,000 forward packets per backward packet; HOIC never exceeds 2, 99% of benign flows are
under 1.7): one extreme feature on 1,730 flows, not evidence of transfer to unseen tools.

| Mode | Split (follows `notebooks\ddos_xgboost_starter_v2.ipynb`) |
|---|---|
| `all_tools` | benign capped at 1M + all attacks, random 70/30 split stratified by tool (notebook §10; optimistic upper bound) |
| `held_out` | trained on the other two tools + benign, tested on the held-out tool; per-day or by-file (notebook §7) or attack-period benign split |

Small test files from the Wednesday CSV:
`.\.venv\Scripts\python DDoSDetector\scripts\make_sample.py --rows 50000` (writes
`sample_wed_50k.csv`, a no-label copy and a missing-column file to `data\`). These rows overlap
with the training data, so metrics on them are optimistic.

**Notebook outputs the app reads:** in `notebooks\ddos_xgboost_starter_v2.ipynb`, section 9b writes
`DDoSDetector\app\data\feature_evidence.csv` (Help → Features) and section 9c writes
`DDoSDetector\models\feature_set_comparison.csv` (Feature-set comparison tab). The whole notebook
runs in about 7 minutes on the full data (it needs sections 0–6 first).

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
with a `features` list in the metadata) and put the files in `DDoSDetector\models\`. It appears in
the Model menu, or use *Open model…* for a `.meta.json` elsewhere. The feature list is checked
before scoring.

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
groups, and a scan for any claim that features 8–11 improve detection. Tests use synthetic data, not the CSVs.

## Package

```powershell
powershell -ExecutionPolicy Bypass -File DDoSDetector\build_exe.ps1
```

Builds `DDoSDetector\bin\Release\DDoSExplainer\DDoSExplainer.exe` with the models copied next to
it (about 430 MB; zip the `DDoSExplainer` folder to share it). Logs go to a `logs\` folder next to
the `.exe`. PyInstaller's intermediate files go to `DDoSDetector\obj\`.
