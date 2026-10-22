# CLAUDE.md

Guidance for Claude Code in this repository.

## What this is

COMP6310 group project: *Explainable Machine Learning for DDoS Attack Detection in Network Traffic*.
A PySide6 desktop app scores CICFlowMeter flows (CSE-CIC-IDS2018, 20–21 Feb 2018) with XGBoost,
explains them with SHAP, and supports an analyst review/feedback loop. It is a university demo and
evidence for the report, **not a production IDS**. Correctness and honesty about the model's limits
matter more than polish.

Specs, in order of precedence: `docs/HANDOFF_UPDATE_2.md` (15 columns, feature registry) wins over
`docs/HANDOFF_UPDATE_1.md`, which wins over `docs/HANDOFF_desktop_app.md`;
`notebooks/ddos_xgboost_starter_v2.ipynb` is the source of truth for the data pipeline (if it and a
handoff disagree, the notebook wins and the user is told). The group's Week 3 feature text is in
`docs/Weeks_1_to_4_-_DDoS_Detection_Project_UPDATED.docx`.
`docs/COMP6310_Project_Handoff.md` is the project-level summary from another chat (testing plan,
papers, user preferences); it predates the app, so where it conflicts with the update (e.g. it says
"confidence score") the update wins. The latest session summary is `docs/HANDOFF_SESSION_1.md`.

The user (Xavier) wants plain, easy-to-explain language, step-by-step Windows instructions, and
honest flags on anything unverified.

## Commands (Windows, run from the solution folder)

Python is the project venv `.venv` (Python 3.14; the only interpreter on this machine). Always use
`.\.venv\Scripts\python.exe`, never a bare `python`.

```powershell
.\.venv\Scripts\python.exe -m pytest DDoSDetector\tests            # 71 tests, ~5 s, synthetic data
.\.venv\Scripts\python.exe DDoSDetector\app\main.py [data\x.csv]   # run the app
.\.venv\Scripts\python.exe DDoSDetector\train\train_model.py --mode all_tools [--seeds 0 1 2 3 4] [--feature-set f9|f15]
.\.venv\Scripts\python.exe DDoSDetector\train\train_model.py --mode held_out --held-out HOIC LOIC-HTTP LOIC-UDP [--benign-split by_file|attack_period]
.\.venv\Scripts\python.exe DDoSDetector\scripts\make_sample.py --rows 50000      # test CSVs in data\
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
    features.py                     THE feature registry (groups 1-6, 8-11; f9/f15 sets) + cleaning
    csv_reader.py, scoring.py, model_store.py, explain.py (TreeExplainer cache, pred_contribs),
    impact.py, review.py, feature_notes.py, timing.py
  app/plots/                        one file per chart plugin (auto-discovered); base.py = interface
  app/ui/                           main_window, results_table (virtual model), plot_panel, dialogs
  app/data/                         feature_notes.json (group's Week 3 text), feature_evidence.csv (notebook 9b)
  models/                           *.json + *.meta.json (+ feature_set_comparison.csv from notebook 9c)
  app/workers.py                    QRunnable workers; callbacks use QueuedConnection
  train/train_model.py, scripts/make_sample.py, tests/, models/
```

## Rules that must hold

- **Never call the model output a "confidence" or a "probability"** (UI, exports, code, docs). It is the
  "model score" (0–1, uncalibrated because of `scale_pos_weight`). A test scans `app/` and README.
- **Feature columns are defined only in the registry** (`app/core/features.py`): never write a list
  of model columns anywhere else (a test scans for it). Current model: **10 feature groups
  (15 columns)**; the original nine are feature set `f9`. Use `summary(columns)` for wording. Each
  model's `.meta.json` has `feature_columns`; the app builds exactly those (`model_columns(meta)`;
  no field = the original nine). IP addresses and timestamps are **never** model inputs
  (`Src IP`/`Dst IP`/`Dst Port` are kept only as alert tracing fields).
- Rows with NaN/inf in the original nine columns (or the packet counts) are "Not scored", never
  silently dropped; NaN in features 8–11 is allowed and counted. Training drops core-NaN rows only.
- **Never claim features 8–11 help** (a test scans the app and README). Report 9c numbers, no
  "best set".
- Model card: numbers only from metadata. The recorded results (0.999 / 0.156 / 0.003, FPR 0.0084)
  are nine-column results, shown only for nine-column models and labelled. "No transfer to unseen
  tools" was observed with nine columns; don't state a conclusion for fifteen. No blocking/mitigation,
  no real SIEM/network integration (alert export is a file only).
- Training and inference must share `app/core/features.py`; don't duplicate cleaning logic.
- New charts: one file in `app/plots/` with `@register`; never edit `main_window.py` for a chart.
  Heavy work in `prepare()` (worker thread), drawing in `render()` onto the given Figure — never
  `plt.figure()` / pyplot state. Shared colours/styles come from `app/plots/_style.py`.
- Worker threads must not touch widgets or read window attributes; capture values before starting.
- Do not edit the group's project documents. `feature_notes.json` holds the group's Week 3 text;
  the only addition is `expected` (our reading of each assumption's direction), shown as such.
  Don't invent feature text; ask the user. Verdicts are computed from `feature_evidence.csv`.
- When running notebooks, execute a **copy** (nbclient, cwd = `notebooks/`); don't save outputs into
  the user's notebooks.
- No git repo exists yet. Don't `git init`, commit or push unless asked.
- Report only what was run. For GUI work, test headless and say what still needs a hand check.

## Gotchas

- Results in the handoffs (8,872,017 rows, FPR 0.0084, HOIC held-out 0.156) come from an **older**
  notebook that also loaded `Dst IP`, so its duplicate check was finer. The v2 pipeline gives
  8,788,935 rows, FPR ≈ 0.0104, HOIC held-out ≈ 0.212. This is expected, not a bug.
- pandas 3: assigning a string into a float column raises; cast to `object` first in test fixtures.
- Headless Qt: set `QT_QPA_PLATFORM=offscreen` and `QT_QPA_FONTDIR=C:\Windows\Fonts` (otherwise text
  renders as boxes in screenshots). Matplotlib backend is set to `QtAgg` in `app/main.py`; tests use Agg.
- `ExplainerCache` uses an `RLock` because `memo()` computations call back into it.
- PyInstaller: `--collect-all xgboost` fails (imports `xgboost.testing`); `--add-data` sources must be
  absolute (resolved relative to `--specpath`); `--collect-submodules app` is needed for plugin discovery.
- PowerShell is the main shell; inline `python -c` with nested quotes breaks easily — write a script
  file in the scratchpad instead.
- Docstrings containing Windows paths need `r"""` (invalid escape warnings).
- Models matching `*_seed*` are git-ignored but needed locally by the Seed stability chart.
- The 15-column results so far are the same as or very close to the nine-column ones (e.g. HOIC
  held out 0.212); notebook 9c shows near-identical recall across feature sets. Report, don't interpret.
- Windows Application Control (Smart App Control) blocked a freshly built `DDoSExplainer.exe` from
  starting on 22 Oct 2026. Don't try to bypass it; tell the user.
