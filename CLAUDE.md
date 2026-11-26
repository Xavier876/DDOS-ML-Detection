# CLAUDE.md

Guidance for Claude Code in this repository.

## What this is

COMP6310 group project: *Explainable Machine Learning for DDoS Attack Detection in Network Traffic*.
A PySide6 desktop app scores CICFlowMeter flows (CSE-CIC-IDS2018, 20–21 Feb 2018) with XGBoost (main
model; Random Forest and a linear SVM are the comparison models, user's request of 4 Nov 2026),
explains them with SHAP, and supports an analyst review/feedback loop. It is a university demo and
evidence for the report, **not a production IDS**. Correctness and honesty about the model's limits
matter more than polish.

Specs, in order of precedence: update 5 (5 Nov 2026, the user's decision "Build the six" in the session
chat after the three-model feature search, `docs/feature_search_findings_2026-11-05.md`: the group's
original feature 7 came back (flows to the same destination IP) with two more IP windows (distinct source
IPs to the same destination IP; flows from the same source IP); default set `f7ip` = 7 columns, trained on
the 20 Feb file + the relabelled 21 Feb capture; `f9p` models stay as the baseline; **not yet confirmed by
the group**, so tell the user it is their call to present. Later on 5 Nov 2026 the user had the catalogue
**renumbered**: app features 1–6 are the default model's inputs in column order (1 dst-IP flows, 2 distinct
sources per dst IP, 3 src-IP flows, 4 fwd/bwd ratio, 5 indicators, 6 timing regularity), 7–18 the rest
(7 rate, 8 duration, 9 inter-arrival, 10 SYN, 11 fwd pkt len, 12 port window, 13 reply, 14 RST/FIN, 15–18
the update-3 groups); `FeatureGroup.week3` keeps each group's Week 3 document number, and the findings
document and search script keep the old labels (F16/F18/F17/F3/F10/F11 = app 1–6)) wins over
update 4 (31 Oct 2026, project chat, no handoff file: the group settled on six feature groups; SYN Flag Cnt
was replaced by feature 7, a port version of the group's dropped "flows to the same destination in a
window", giving the set `f9p` = 9 columns; done on branch `nine-column`, while `main` keeps update 3),
which wins over update 3 (decided in the project chat on 22 Oct
2026, no handoff file: features 12–15 added, SYN Flag Cnt dropped, feature set `f21` = 21 columns), which wins over
`docs/HANDOFF_UPDATE_2.md` (15 columns, feature registry), which wins over
`docs/HANDOFF_UPDATE_1.md`, which wins over `docs/HANDOFF_desktop_app.md`;
`notebooks/ddos_xgboost_starter_v2.ipynb` is the source of truth for the data pipeline (if it and a
handoff disagree, the notebook wins and the user is told). The group's Week 3 feature text is in
`docs/Weeks_1_to_4_-_DDoS_Detection_Project_UPDATED.docx` (keep unchanged); the user asked for a new
copy with Weeks 3 and 4 updated for update 3: `docs/Weeks_1_to_4_-_DDoS_Detection_Project_UPDATE3.docx`,
and on 4 Nov 2026 one with Weeks 3–4 updated for update 4 plus a new Week 5 (deployment pipeline):
`docs/Weeks_1_to_5_-_DDoS_Detection_Project_UPDATE4.docx` (built from the UPDATE3 copy by exact-match XML
edits; update-4 changes are marked "Update 4" next to the earlier text). Week 5 answers the seven pipeline
questions for a **live deployment** (the user said on 4 Nov 2026 that the group's offline assumption was
wrong): taps/mirror ports feed sensors (CICFlowMeter live, features.py, XGBoost, SHAP) outside the firewall,
in the DMZ, in the core and in the cloud; alerts go to a SIEM in the SOC; feedback and retraining happen in
the SOC; people approve every response. It is a design, not built: the prototype on recorded files is the
evidence. Group decisions kept: alerts = flag at a threshold chosen after testing (proposal: 0.5; since 6 Nov 2026
the app starts each model at its own default, `model_store.default_threshold`: the lowest tested threshold whose
false-alarm rate on the model's benign test split is within 0.1 %, else 0.5, shown on the Model card),
retraining shown by a demonstration. Its evidence is `notebooks/ddos_week5_threshold_retraining_update6.ipynb`
(6 Nov 2026: the relabelled data, the retrained models and the per-model threshold rule; outputs saved. The
update-5 and pre-update-5 copies and the superseded `ddos_xgboost_detector` / `ddos_xgboost_starter` notebooks
were removed on 5–6 Nov 2026 to slim the repo; they are in git history).
On 4 Nov 2026 the user also asked for a pass against the grading guide (PDF in the user's OneDrive, `...\Assignments\MACHINE LEARNING FOR CYBERSECURITY - Group Project Assessment  Grading Guide.pdf`): Weeks 1–4 got
"Update (4 November 2026)" notes (near-real-time deployment, live data source, what was actually run: no CV,
class weights; a security evaluation with confusion matrices from metadata), and Week 3 got a new Section 7,
the final feature choice in the guide's table format: **keep the six groups**; a 7th/8th group (F13, F10, F9,
alone and in pairs) was tested on the same splits (`DDoSDetector/scripts/feature_choice_experiment.py`, results
`docs/feature_choice_6_vs_8_groups_2026-11-04.csv`): nothing passed the group's rule; F13 raised unseen
LOIC-HTTP to 0.017–0.031 only with more false alarms ("mixed"). The docx build scripts live in the session
scratchpad (`w5/build_weeks5.py` + `rubric_update.py`, `week3_choice.py`, `week5_live.py`, `three_models.py`).
`docs/COMP6310_Project_Handoff.md` is the project-level summary from another chat (testing plan,
papers, user preferences); it predates the app, so where it conflicts with the update (e.g. it says
"confidence score") the update wins. The latest session summary is `docs/HANDOFF_SESSION_2.md`
(it continues `docs/HANDOFF_SESSION_1.md`).

The user (Xavier) wants plain, easy-to-explain language, step-by-step Windows instructions, and
honest flags on anything unverified.

## Commands (Windows, run from the solution folder)

Python is the project venv `.venv` (Python 3.14; the only interpreter on this machine). Always use
`.\.venv\Scripts\python.exe`, never a bare `python`.

```powershell
.\.venv\Scripts\python.exe -m pytest DDoSDetector\tests            # 122 pass + 2 skipped, ~30 s, synthetic data
.\.venv\Scripts\python.exe DDoSDetector\app\main.py [data\x.csv]   # run the app
.\.venv\Scripts\python.exe DDoSDetector\train\train_model.py --mode all_tools --files Tuesday-20-02-2018_relabelled.csv Wednesday-21-02-2018_victim_capture_labelled.csv [--seeds 0 1 2 3 4] [--model xgboost|random_forest|linear_svm]   # default set f7ip needs the IP files (= FILES_IP)
.\.venv\Scripts\python.exe DDoSDetector\train\train_model.py --mode all_tools --feature-set f9p [--feature-set f9|f15|f14|f21]   # the published pair (default --files): copy them back into data\ from C:\datasets\cse-cic-ids2018\processed first (removed from data\ on 5 Nov 2026; the master copy spells it "Thuesday")
.\.venv\Scripts\python.exe DDoSDetector\train\train_model.py --mode held_out --held-out HOIC LOIC-HTTP LOIC-UDP [--benign-split by_file|attack_period]
.\.venv\Scripts\python.exe DDoSDetector\scripts\make_sample.py --seconds 40      # time-slice test CSVs in data\
powershell -ExecutionPolicy Bypass -File DDoSDetector\build_exe.ps1             # PyInstaller -> bin\Release
```

Visual Studio: open `DDOS-ML-Detection.sln`, F5. To check the solution builds:
`& "<vswhere installationPath>\MSBuild\Current\Bin\MSBuild.exe" DDOS-ML-Detection.sln -p:VisualStudioVersion=18.0`.
Training reads the 3.9 GB Tuesday CSV (~45 s load); run it in the background.

## Layout

```
DDOS-ML-Detection.sln, README.md, requirements.txt, CLAUDE.md
data/        CSVs (git-ignored, never commit)     docs/  handoffs     notebooks/  group notebooks
DDoSDetector/                       the VS project (DDoSDetector.pyproj); working dir when run from VS
  app/paths.py                      all folder locations (data, models, logs, app/data) — use it, no cwd paths
  app/core/                         Qt-free logic, unit-tested:
    features.py                     THE feature registry (groups 1-18; f7ip/f9p/f9/f15/f14/f21 sets) + window counts + cleaning
    models.py                       the 3 model types: settings, save/load (XGBoost JSON; RF/SVM joblib)
    csv_reader.py, scoring.py, model_store.py, explain.py (SHAP per model type, units, cache),
    impact.py, review.py, feature_notes.py, timing.py
  app/plots/                        one file per chart plugin (auto-discovered); base.py = interface
  app/ui/                           main_window, results_table (virtual model), plot_panel, dialogs
  app/data/                         feature_notes.json (group's Week 3 text), feature_evidence.csv (notebook 9b)
  models/                           *.json / *.joblib + *.meta.json (f7ip = update 5, f9p = update-4 baseline)
  app/workers.py                    QRunnable workers; callbacks use QueuedConnection
  train/train_model.py, scripts/make_sample.py, tests/, models/
```

## Rules that must hold

- **Never call the model output a "confidence" or a "probability"** (UI, exports, code, docs). It is the
  "model score" (0–1, uncalibrated because of `scale_pos_weight`). A test scans `app/` and README.
- **Feature columns are defined only in the registry** (`app/core/features.py`): never write a list
  of model columns anywhere else (a test scans for it). Default model (update 5, branch `nine-column`):
  **6 feature groups (7 columns)**, set `f7ip` = features 1–6, model `all_tools_f7ip`
  (`DEFAULT_MODELS = ("all_tools_f7ip", "all_tools_f9p")`: the f9p one is the fallback offered for a CSV
  without IP columns). Only `f7ip` and `f9p` models ship on this branch (a test checks every
  `models/*.meta.json`); don't add other sets back to `models/`. Groups 7–18 stay in the registry for the
  baseline (`f9p` = 7, 8, 9, 11, 4, 12) and the notebook comparisons; refer to groups by `key` in code
  (`group_by_key`), by `week3` number in anything that quotes the group's document (`group_week3`). On `main`, update 3 still holds (`f21`). The code
  loads any model opened by hand (tests use synthetic f9/f15/f21/f9p/f7ip models). Use `summary(columns)`
  for wording. Each model's `.meta.json` has `feature_columns`; the app builds exactly those
  (`model_columns(meta)`; no field = the original nine). IP addresses, ports and timestamps are **never**
  model inputs (`Src IP`/`Dst IP`/`Dst Port` are alert tracing fields). The window groups 1–3 and 12 use
  `Timestamp`, `Dst Port`, `Src IP`, `Dst IP` only to count flows; they stay text (`CONTEXT_RAW`, not
  coerced; `FeatureGroup.window` marks the groups, `CONTEXT_COLUMNS` their outputs).
- The window features (1–3, 12) are built from **every row of a capture file** (per `source_file` in
  training, before cleaning; the whole loaded CSV in the app). Never build them on a subset or a random
  sample of rows. Training's duplicate check ignores the port, the IPs and the window features, so the
  published pair still gives 8,788,935 rows; the 20 Feb + relabelled 21 Feb pair gives 9,880,087.
- Rows with NaN/inf in the original nine columns (or the packet counts), or with no readable time, port
  or IP for a window feature, are "Not scored", never silently dropped; NaN in a non-core group is allowed
  and counted. Training leaves such rows out (`drop_unscorable`, counted per file) and stops when a whole
  file cannot provide a core input (the published 21 Feb CSV has no IPs, so `f7ip` needs
  `--files ... Wednesday-21-02-2018_victim_capture_labelled.csv`). The linear SVM: a few training rows
  with a missing value are left out and counted (`train_rows_dropped_missing`); more than 1 % refuses.
- **Never claim the groups added after the first experiments (Week 3 features 8–15) help** (a test scans
  the app and README for that wording). Report 9c numbers, no "best set".
- Model card: numbers only from metadata. The recorded results (0.999 / 0.156 / 0.003, FPR 0.0084)
  are nine-column results, shown only for nine-column models and labelled. "No transfer to unseen
  tools" was observed with nine columns; don't state a conclusion for fifteen. No blocking/mitigation,
  no real SIEM/network integration (alert export is a file only).
- Training and inference must share `app/core/features.py`; don't duplicate cleaning logic.
- Model types (XGBoost, Random Forest, linear SVM) are defined only in `app/core/models.py` (settings,
  save/load); training and the app both use it. `meta["model_type"]` (missing = XGBoost); names get
  `_rf` / `_svm`. SHAP units differ by type (log-odds / model score / SVM decision value): use
  `explain.output_unit` / `score_of`, never hard-code "log-odds". The 0.9 / 0.156 recorded results are
  nine-column **XGBoost** results. The linear SVM cannot use missing values: such rows are "Not scored"
  for it, and training refuses feature sets with gaps for it.
- New charts: one file in `app/plots/` with `@register`; never edit `main_window.py` for a chart.
  Heavy work in `prepare()` (worker thread), drawing in `render()` onto the given Figure — never
  `plt.figure()` / pyplot state. Shared colours/styles come from `app/plots/_style.py`.
- Worker threads must not touch widgets or read window attributes; capture values before starting.
- Do not edit the group's project documents. `feature_notes.json` holds the group's Week 3 text;
  the only addition is `expected` (our reading of each assumption's direction), shown as such.
  Each entry has `number` (app) and `week3_number`; numbers inside the group's own text are Week 3 numbers.
  Features 15–18 (`"status": "update3"`) have text drafted in the project chat (also in the UPDATE3
  docx); replace it if the group rewrites it. Feature 12 (`"status": "update4"`) uses the group's Week 3
  text for feature 7, except "raw data" and "calculation" (port version, drafted in the chat). Feature 1
  (`"status": "update5"`) is the group's Week 3 feature 7 text with the Week 3 table's raw data/calculation;
  features 2 and 3 were drafted in this session on 5 Nov 2026 and say so ("not yet confirmed by the
  group"). Don't invent feature text; ask the user. Verdicts are computed from `feature_evidence.csv`;
  the rows for the window columns (1–3, 12) come from `scripts\feature_evidence_windows.py` (5 Nov 2026,
  on the 20 Feb + relabelled 21 Feb files), the rest from notebook 9b.
- When running notebooks, execute a **copy** (nbclient, cwd = `notebooks/`); don't save outputs into
  the user's notebooks.
- Local Git repo (first commit 22 Oct 2026, identity set for this repo only); no remote. Branches:
  `main` (update 3, 21 columns) and `nine-column` (update 4, from 31 Oct 2026). A detached worktree
  of the old nine-column app (`be5a288`) is at `..\DDOS-ML-Detection-9col`; its `.venv` is a junction to
  this `.venv`. Don't commit or push unless asked.
- Report only what was run. For GUI work, test headless and say what still needs a hand check.

## Gotchas

- Results in the handoffs (8,872,017 rows, FPR 0.0084, HOIC held-out 0.156) come from an **older**
  notebook that also loaded `Dst IP`, so its duplicate check was finer. The v2 pipeline gives
  8,788,935 rows, FPR ≈ 0.0104, HOIC held-out ≈ 0.212. This is expected, not a bug.
- pandas 3: assigning a string into a float column raises; cast to `object` first in test fixtures.
- Headless Qt: set `QT_QPA_PLATFORM=offscreen` and `QT_QPA_FONTDIR=C:\Windows\Fonts` (otherwise text
  renders as boxes in screenshots). Matplotlib backend is set to `QtAgg` in `app/main.py`; tests use Agg.
  In headless scripts wait for workers with `app.processEvents()` + `time.sleep()`, not `QTest.qWait`:
  qWait starves the worker thread and makes load/score timings look ~100x slower (some app.log lines
  from 26 and 31 Oct headless runs are slow for this reason; the app itself scores ~400,000 flows/s).
- `ExplainerCache` uses an `RLock` because `memo()` computations call back into it.
- Random Forest and SVM models are joblib files (a pickle): only open model files you made. RF SHAP
  uses shap's TreeExplainer (no fast `pred_contribs`), so explaining many alerts is slower than XGBoost.
- PyInstaller: `--collect-all xgboost` fails (imports `xgboost.testing`); `--add-data` sources must be
  absolute (resolved relative to `--specpath`); `--collect-submodules app` is needed for plugin discovery.
- PowerShell is the main shell; inline `python -c` with nested quotes breaks easily — write a script
  file in the scratchpad instead.
- Docstrings containing Windows paths need `r"""` (invalid escape warnings).
- Models matching `*_seed*` are git-ignored but needed locally by the Seed stability chart (f7ip and
  f9p seeds 1–4 are in `models\`). On 5 Nov 2026 the user had everything not from the update-4/5 builds
  removed from `models\`: the old nine- and 21-column seed folders (`_f9_seeds`, `_f21_seeds`, were
  git-ignored, gone for good; retrain with `--feature-set f9|f21 --seeds 1 2 3 4` if `main` needs them),
  `hybrid_comparison.csv`, and the tracked `all_tools_f9p_feedback` bundle and `feature_set_comparison.csv`
  (notebook 9c's table; still in git history at `cfb1a61`; the Feature-set comparison tab shows a message
  until a file is opened by hand or 9c is re-run).
- The 15- and 21-column results so far are the same as or very close to the nine-column ones (e.g.
  HOIC held out 0.212); notebook 9c shows no recall change larger than the seed spread. Report, don't
  interpret. The port window (update-4 experiment, `notebooks\ddos_update4_experiments.ipynb`) is the one
  change that passed the group's rule on held-out HOIC; held-out LOIC-HTTP stayed near 0.003.
- Update 5 (5 Nov 2026): the IP-window set `f7ip` is the first that carried over to an unseen tool for all
  three model types (search: `scripts\feature_search_ip.py`, write-up
  `docs\feature_search_findings_2026-11-05.md`; built-in results in each model's metadata and README).
  Say its limits every time: needs `Src IP`/`Dst IP`; one quiet network (median 7 flows per 10 s at the
  victim) and ten attacker machines (feature 2 learned "about ten senders"); LOIC-UDP recall tops at 0.52
  because the 1,598 ICMP reply rows are labelled attack and never flagged; Random Forest varies between
  seeds; threshold 0.5 uncalibrated. Never say the window features are proven on a busy network.
- pandas 3 parses these timestamps as `datetime64[us]`: never turn datetimes into seconds with
  `astype("int64") // 10**9`; subtract the epoch and use `.dt.total_seconds()` (as `_port_window` does).
- 21 Feb file quirk (verified against the raw capture, 5 Nov 2026): 358,523 of its 360,833 "Benign" rows are
  HOIC flows recorded in the server→attacker direction (CICFlowMeter's timeout branch keeps the old flow's
  src/dst when an attacker reuses a client port; the labelling keyed on attacker source IPs), and 1,598 are
  ICMP replies to the LOIC-UDP flood; only ~2,000 flows of the day are genuinely benign. The attack-period
  benign split and any 21 Feb FPR therefore tested mislabelled HOIC flows; say so. The relabelled day is
  `data\Wednesday-21-02-2018_victim_capture_labelled.csv` (`scripts\pcap\label_flows.py`, with IPs and a
  `Label Reason` column); `train_model.load(files=..., extra_columns=...)` can train on it.
- Sample CSVs: `make_sample.py` cuts whole time slices (`sample_wed_slices*.csv` from the published 21 Feb
  file, no IPs: the app offers the `f9p` fallback; `sample_wed_ip_slices*.csv` from the relabelled capture,
  with IPs, for the `f7ip` default: `--file Wednesday-21-02-2018_victim_capture_labelled.csv --stem
  sample_wed_ip_slices`); the older random-row `sample_wed_50k*.csv` gave window counts far too low and were
  deleted on 5 Nov 2026 (so were the published 20/21 Feb CSVs in `data\`, the build output and three old notebooks).
- Git Bash heredocs feeding Python can turn `\a`/`\f` in Windows paths into control characters;
  write scripts to the scratchpad with the Write tool instead. PowerShell sometimes swallows a Python
  script's stdout; Bash shows it.
- Word documents: no `zip`, LibreOffice or `pdftoppm` here. Zip with Python `zipfile` (keep the
  original entry order), export PDF through Word COM (`ExportAsFixedFormat`), render pages with
  `pymupdf` (installed in the venv).
- Raw PCAP work (4 Nov 2026): see `DDoSDetector/scripts/pcap/README.md`. The published 21 Feb CSV is incomplete
  (1,048,575 rows = Excel's limit; half the port-80 flows from 02:18; none after 02:33) and its times are 12-hour
  without AM/PM in UTC-4. `assemble_flows.py` reproduces its HOIC and LOIC-UDP flows exactly from the raw capture,
  with IPs (`flows_assembled\part1_flows.csv` = the morning, `part2_flows.csv` = the HOIC afternoon). The morning is
  complete in the published file; 1,598 of its 2,140 "Benign" rows are the server's ICMP port-unreachable replies to
  the LOIC-UDP flood, which CICFlowMeter records as UDP flows to port 80 (found via the quoted inner UDP header).
  The official tool is cloned for inspection at `..\CICFlowMeter` (`FINDINGS.md` there lists the code lines).
  IP-window candidate features (dst-IP flows, src-IP flows, distinct sources per dst IP; 10 s look-back) live in
  `scripts\ip_window_features.py` and are searched by `scripts\feature_search_ip.py` (results in `docs\`); they
  are an experiment, not registry groups, until the group decides.
- Windows Application Control (Smart App Control) blocked a freshly built `DDoSExplainer.exe` from
  starting on 22 Oct 2026, and on 26 Oct 2026 started blocking the PyPI build of
  `.venv\Lib\site-packages\shap\_cutils.pyd` (`import shap` fails, so the app and most tests do too;
  the Code Integrity log shows event 3077). The user rebuilt shap 0.54.1 from source in `.venv`
  (`pip install --force-reinstall --no-deps --no-binary shap`), which loads. Don't try to bypass it;
  tell the user. The bare `pip` on PATH belongs to the global Python, not `.venv`.
