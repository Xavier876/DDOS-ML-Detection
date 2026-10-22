# Handoff: build a PySide6 desktop app for explainable DDoS detection

Paste this whole file into Claude Code as the first message (or save it as `HANDOFF.md` in the project root and tell Claude Code to read it).

## 1. What I want built

A Windows desktop application (Python, **PySide6**; PyQt6 is acceptable if you have a strong reason) that:

1. Loads a CSV of CICFlowMeter network flows.
2. Scores every flow with a trained XGBoost model and shows a **flag (Benign / DDoS) plus a confidence score**.
3. Explains the model with **SHAP charts**: a per-flow explanation for a selected row, and global explanations for the loaded data.
4. Is structured so that more chart types and models can be added later without rewriting the app (see section 7).

This is a university project (COMP6310, group project: "Explainable Machine Learning for DDoS Attack Detection in Network Traffic"). The app is a demo and evidence for the report, not a production IDS. Correctness and honesty about the model's limits matter more than polish.

## 2. Project context

- Dataset: CSE-CIC-IDS2018, processed CICFlowMeter CSVs for 20 and 21 February 2018.
  - `Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` (3.9 GB, 84 columns, contains LOIC-HTTP and benign)
  - `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` (321 MB, 80 columns, contains HOIC, LOIC-UDP and benign)
  - The Wednesday file has **no `Dst IP`** column. This is why the planned "flows to the same destination in a 10 s window" feature was dropped.
- Three DDoS tools: LOIC-HTTP (Tuesday only), HOIC and LOIC-UDP (Wednesday only). The DoS attacks of 15 and 16 February are out of scope.
- Project folder on the developer's machine (Windows): `C:\Users\Xavie\source\repos\DDOS-ML-Detection`, with the CSVs in `data\`. **Do not commit the CSVs to Git** (add `data/` and model artefacts over a size limit to `.gitignore`).
- An existing notebook, `ddos_xgboost_starter_v2.ipynb`, holds the working data pipeline and experiments. Read it first; treat it as the source of truth for the logic below. If anything in this handoff disagrees with the notebook, the notebook wins, and tell me about the difference.

## 3. Data and model facts to build on

### Label mapping
Raw labels are inconsistent: `Benign`, `DDoS attacks-LOIC-HTTP`, `DDOS attack-HOIC`, `DDOS attack-LOIC-UDP`. Map by lowercase substring: contains "benign" -> Benign; "udp" -> LOIC-UDP; "hoic" -> HOIC; "http" -> LOIC-HTTP. `y = 1` for any DDoS tool, `0` for benign.

### Model inputs (exactly 9 columns, this order)
```
Flow Pkts/s, Flow Byts/s, Flow Duration, Flow IAT Mean, Flow IAT Std,
SYN Flag Cnt, Fwd Pkt Len Mean, Fwd Pkt Len Std, fwd_bwd_ratio
```
- `fwd_bwd_ratio = Tot Fwd Pkts / (Tot Bwd Pkts + 1)`, so the input CSV must also contain `Tot Fwd Pkts` and `Tot Bwd Pkts`.
- IP addresses and timestamps are **never** model inputs.
- Column names in CICFlowMeter files sometimes have stray spaces; strip them when reading.

### Cleaning (apply identically at inference)
- Some files contain repeated header rows: drop rows where `Label == "Label"` if a Label column exists; coerce all feature columns with `pd.to_numeric(errors="coerce")`.
- Replace `inf`/`-inf` with NaN. For inference, **do not silently drop** rows with NaN or inf: keep them in the results table, mark them "Not scored (invalid values)", and report how many. (In training the notebook drops them, along with duplicates.)

### Training recipe (from the notebook)
```python
XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
              tree_method="hist", scale_pos_weight=n_benign/n_attack,
              n_jobs=-1, random_state=seed)
```
Benign flows are randomly capped at 1,000,000 for training (full data is 7.6M benign).

### Which model the app ships
- **Default model ("all tools")**: trained on benign + LOIC-HTTP + LOIC-UDP + HOIC, 70/30 stratified split by tool, seed 0, evaluated on the 30% (this is the notebook's "baseline" in section 10).
- **Optional second model ("HOIC held out")**: trained on LOIC-HTTP + LOIC-UDP + benign only, to demonstrate the generalisation failure. Selectable in the UI. Include it only if it is cheap to add; it is the pluggable-model feature from section 7 in action.

### Results the app's "About / Model card" panel must state honestly
| Setting | Result |
|---|---|
| Random split, all 3 tools seen in training | Recall HOIC 0.999, LOIC-HTTP 0.987, LOIC-UDP 1.000 (only 519 test flows), false positive rate 0.0084 |
| HOIC held out | Recall 0.156 (per-day benign split) / 0.195 (by-file benign split) at threshold 0.5; at most about 0.40 at any threshold tried |
| LOIC-HTTP held out | Recall 0.003, false positive rate 0.0054 |

Key message to display: **the model detects DDoS tools it was trained on but does not transfer to unseen tools.** The random-split numbers are an optimistic upper bound (near-duplicate flows from the same attack burst appear in both train and test). Also note: attack tool and capture day are confounded; LOIC-UDP has only 1,730 flows; `SYN Flag Cnt` has median 0 for every tool and showed no importance in the held-out model.

## 4. Deliverables

Create these in the repo (suggested layout; adjust if you see a better one and say why):

```
DDOS-ML-Detection/
  app/
    __init__.py
    main.py                  # entry point: python -m app.main
    ui/
      main_window.py         # QMainWindow, menus, layout
      results_table.py       # QTableView + QAbstractTableModel (virtual, handles 1M rows)
      plot_panel.py          # tabbed chart area + export buttons
      about_dialog.py        # model card text from section 3
    core/
      features.py            # cleaning + feature building (single source of truth, used by training AND app)
      model_store.py         # load/save model + metadata (feature list, training info, metrics)
      scoring.py             # batch scoring, returns DataFrame with prob, flag, status
      explain.py             # SHAP wrappers, cached explainer
    plots/
      base.py                # ChartPlugin interface + registry
      shap_waterfall.py      # per-flow
      shap_bar_global.py     # mean |SHAP|, global
      shap_beeswarm.py       # global
      shap_by_tool.py        # mean |SHAP| per class/tool (only when Label column present)
      score_hist.py          # confidence histogram
    workers.py               # QThread/QRunnable workers
  train/
    train_model.py           # CLI: reads data\ CSVs, trains, writes models\*.json + *.meta.json
  models/                    # trained artefacts (git-ignored if large)
  tests/
  requirements.txt
  README.md                  # how to train, run, package
```

### 4.1 `train/train_model.py`
- CLI: `python -m train.train_model --data-dir data --out models --mode all_tools|hoic_held_out --seed 0`.
- Reuse `app/core/features.py` so training and inference cannot drift apart.
- Load only needed columns with `usecols`; read the 3.9 GB file in chunks (or with `usecols` plus dtype downcasting) so memory stays reasonable. Filter to the benign and DDoS labels while loading.
- Save: `model.save_model("models/<name>.json")` and a `<name>.meta.json` with: feature list, label mapping, training mode, seed, row counts per tool, hyperparameters, the evaluation numbers above computed on its own test split, library versions (xgboost, shap, scikit-learn, pandas), and a creation timestamp.
- Also save a **SHAP background sample** (about 500 to 1,000 rows of training features, stratified by tool) to `models/<name>.background.parquet` (or `.csv` if pyarrow is unavailable). The app uses this for explanations.
- Print evaluation: recall per tool, false positive rate with the raw count of false alarms, and PR-AUC with the base rate beside it.

### 4.2 The app (`app/main.py`)
**Layout:** main window with a left/top results table and a right/bottom chart panel in a `QSplitter`.

**Menu and toolbar:** File -> Open flows CSV..., Open model..., Export results CSV..., Exit. Model -> choose the active model. Help -> About / Model card.

**Open flows CSV:**
- Read in a worker thread (never block the UI). Use chunked reading with a progress bar and a Cancel button. Files can be hundreds of MB.
- Validate columns up front. If any required column is missing, show a clear dialog listing exactly which, and do not crash.
- If a `Label` column exists, keep it and enable the "actual vs predicted" features (confusion matrix summary, per-tool recall, SHAP by tool). If it does not, those features are hidden or disabled, not broken.
- Preserve the original row index so the user can map results back to the source file.

**Results table** (virtualised, so 1M rows stays responsive; use a custom `QAbstractTableModel` over a DataFrame/NumPy arrays, never a widget-per-row):
- Columns: row number, flag (Benign / DDoS / Not scored), confidence (probability of DDoS, 0 to 1), the 9 features, and optionally Label and Timestamp if present.
- Sort, filter by flag, and a confidence-range filter (e.g. show flows with confidence between 0.2 and 0.8 to find uncertain ones).
- A threshold control (default 0.5, slider plus spin box) that re-flags instantly without re-scoring.
- Summary bar: total flows, number flagged DDoS, number not scored, and (with Label) recall/false positives at the current threshold.
- Selecting a row triggers its per-flow SHAP waterfall in the chart panel.

**Chart panel:** tabs, one per registered chart plugin (section 7). Each chart has "Save as PNG" and "Copy to clipboard".

**Charts to ship:**
1. **Per-flow SHAP waterfall** for the selected row. Show the base value, each feature's contribution, and the final score. State the units clearly: SHAP values for XGBoost binary classification are in **log-odds**, while the table's confidence is a **probability**. Show both, labelled.
2. **Global SHAP bar** (mean |SHAP| per feature) over a sample of the loaded flows.
3. **Global SHAP beeswarm** over the same sample.
4. **SHAP by tool** (mean |SHAP| per feature, grouped by actual tool), only when `Label` is present. This is the key chart for the report because it shows whether different tools are driven by different features.
5. **Confidence histogram** of all scored flows, with the threshold line.

**Performance rules for SHAP:**
- Compute SHAP only for what is displayed: the selected row for the waterfall, and a random sample (default 2,000 rows, user-adjustable up to maybe 20,000) for global charts.
- Run it in a worker thread with a progress indicator; cache the explainer and results; invalidate the cache when the model or data changes.
- Use `shap.TreeExplainer(model)` (fast, exact for XGBoost). Do not use KernelExplainer.

**Matplotlib embedding:** use `matplotlib.backends.backend_qtagg.FigureCanvasQTAgg` inside the PySide6 widgets. Call SHAP plotting functions with `show=False` and draw onto a figure owned by the widget, then `canvas.draw_idle()`. Clear and redraw the figure each time; do not leak figures (call `figure.clear()`, never create unbounded `plt.figure()`s). Set the backend explicitly to the Qt one at startup.

**Threading:** all file reading, scoring and SHAP work goes through `QThread`/`QRunnable` workers with signals back to the UI thread. No Qt widget calls from worker threads. Provide cancel for long jobs.

**Error handling:** never crash on bad input; show a message box with a clear reason and keep the app usable. Log to a file in a `logs/` folder.

## 5. Dependencies

`requirements.txt` (pin versions after you confirm they work together; XGBoost, SHAP and NumPy version mismatches are a known source of breakage, so run a real SHAP computation as a smoke test before pinning):

```
PySide6
pandas
numpy
xgboost
scikit-learn
shap
matplotlib
pyarrow
joblib
pytest
pyinstaller   # only for packaging
```
Python 3.10 to 3.12 (check what SHAP and numba support on the developer's machine; SHAP depends on numba and may lag the newest Python). The developer is on Windows 11 and runs the project from `C:\Users\Xavie\source\repos\DDOS-ML-Detection`. Make sure all paths use `pathlib` so Windows backslashes are not a problem.

## 6. Acceptance criteria

The work is done when, on the developer's Windows machine:

1. `python -m train.train_model --data-dir data --out models --mode all_tools` completes and writes the model, metadata and background sample. The printed baseline numbers should be close to the table in section 3 (small differences from different random sampling are fine; large differences mean something is wrong, so investigate).
2. `python -m app.main` opens the window. File -> Open flows CSV loads a test CSV (use the small Wednesday file, 321 MB, or a 50,000-row sample of it) with a visible progress bar and the UI never freezes.
3. Flows appear with flag and confidence; the threshold control re-flags instantly; sorting and filtering work on at least 500,000 rows without lag.
4. Selecting a flow shows its SHAP waterfall within a couple of seconds; the base value plus the contributions matches the model's raw log-odds for that row (add a unit test for this: `base_value + shap_values.sum()` equals `model.predict(X, output_margin=True)` within tolerance).
5. Global bar, beeswarm and confidence histogram render from a sample; SHAP-by-tool renders when the CSV has a `Label` column and is disabled (not erroring) otherwise.
6. Loading a CSV with a missing required column shows a clear dialog and does not crash; rows with NaN/inf are listed as "Not scored", not silently dropped.
7. "Save as PNG" works for every chart; "Export results CSV" writes the flags, confidences and original row numbers.
8. The About / Model card shows the honest results and limitations from section 3, including the sentence that the model does not generalise to unseen tools.
9. `pytest` passes. Tests cover at least: label mapping, feature building (including `fwd_bwd_ratio` and the zero-backward-packet case), cleaning of inf/NaN/repeated headers, scoring output shape and flag logic at different thresholds, the SHAP additivity check above, and the chart plugin registry.
10. README explains: how to train, how to run, how to add a chart, how to package. A PyInstaller build is a stretch goal (see section 8).

## 7. Extensibility requirement ("adding SHAP charts etc.")

Adding a new chart or model must not require editing the main window. Implement:

```python
# app/plots/base.py
class ChartPlugin:
    name: str                       # tab title
    needs_label: bool = False       # hide/disable if no Label column
    scope: str = "global"           # "global" (sample of rows) or "row" (selected row)

    def render(self, figure, context): ...   # draw onto a matplotlib Figure
```
- `context` is a small dataclass holding: model, feature DataFrame, scores, labels (optional), SHAP values and explainer (lazily computed and cached), selected row index, threshold.
- A registry (decorator or entry list) discovers chart plugins; the chart panel builds one tab per plugin. A new chart is one new file.
- Models are loaded through `model_store.py` using the `.meta.json` file, so a new trained model (for example one retrained with SMOTE, or a different seed) can be opened from the Model menu without code changes. The metadata's feature list is checked against the CSV columns before scoring.

## 8. Nice to have (only after the acceptance criteria pass)

- Seed-stability view: a chart that loads several models trained with different seeds and shows the rank stability of mean |SHAP| per feature (this is a planned Week 4 analysis).
- A dependence plot for any chosen feature.
- Threshold-vs-recall/false-positive table for the loaded data when Label is present, clearly marked as optimistic if the threshold is tuned on the same data.
- Dark mode.
- PyInstaller one-folder build (`pyinstaller --noconfirm --windowed app/main.py`, with hidden imports and data files for shap and xgboost). Expect it to be large (hundreds of MB). If it proves fiddly, document the problem rather than spending long on it.

## 9. Non-goals (do not build these)

- Live packet capture or a flow extractor (the app takes CICFlowMeter CSVs only).
- Any use of IP addresses or timestamps as model inputs.
- A "window feature" built from destination IP (not possible for the Wednesday file).
- Network/IDS deployment features, authentication, databases, or a web server.
- Hyperparameter search or SMOTE (a different Week 4 task).

## 10. Working agreement

- First read `ddos_xgboost_starter_v2.ipynb` and this file, then give me a short plan (files you will create, the order, and any risk) **before** writing code, and ask me only about things that block you.
- Build in small steps and run things as you go: core (features, model store, scoring, tests) first; then the training script and run it on a small sample; then the UI skeleton with the table; then SHAP and charts; then polish and README.
- Do not report something as working unless you have run it. If you cannot run the GUI in your environment, say so, test the non-GUI core thoroughly, and list exactly what I need to check by hand.
- Keep the code readable and commented lightly; a classmate should be able to follow it. No hardcoded absolute paths.
- Tell me about every place where you deviated from this document and why.
- Do not make commits or push anything unless I ask.

## 11. Open questions (ask me, or take the stated default and flag it)

1. Default model: "all tools" (default here) or "HOIC held out"? Default: ship both, with "all tools" preselected.
2. Is a packaged `.exe` required, or is "run from Python" enough? Default: run from Python; PyInstaller is a stretch goal.
3. Should the app include the 15 and 16 February DoS data? Default: no (out of scope).
