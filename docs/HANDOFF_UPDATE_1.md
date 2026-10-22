# Handoff update 1: read this together with HANDOFF_desktop_app.md

Where this update and `HANDOFF_desktop_app.md` disagree, **this update wins**. Everything else in the original handoff still applies (stack, layout, plugin design, acceptance criteria, non-goals, working agreement).

Reason for the update: we compared the project documents with the course's grading guide and found the app should support the assessed items (security evaluation, feature justification, analyst workflow, feedback and retraining), not just show SHAP charts. We also found some wording that was wrong.

## 1. Corrections to the original handoff

1. **Do not call the output a "confidence" or a "probability".** The project documents say "model score, not a probability unless calibrated", and our models use `scale_pos_weight`, which makes the scores uncalibrated. Everywhere in the UI, the exports, the code and the README, use **"model score"** (a number from 0 to 1). The table column is `model_score`, not `confidence`. The About / Model card says: "The score is the model's raw output and has not been calibrated. Do not read 0.9 as a 90% chance of an attack."
2. **Feature count wording.** The model has **9 input columns** from **6 feature groups**: rate (`Flow Pkts/s`, `Flow Byts/s`), duration (`Flow Duration`), forward/backward ratio (`fwd_bwd_ratio`), inter-arrival time (`Flow IAT Mean`, `Flow IAT Std`), SYN flag count (`SYN Flag Cnt`), forward packet length (`Fwd Pkt Len Mean`, `Fwd Pkt Len Std`). The seventh feature in the project documents (flows to the same destination in a 10 s window) is **dropped**, because the Wednesday file has no `Dst IP`. Use "6 feature groups (9 columns)" in all text.
3. **The notebook changed.** `ddos_xgboost_starter_v2.ipynb` now has a new section **9b** that writes `feature_evidence.csv` (see section 3 below). Read the notebook again.

## 2. New requirements (priority order)

Do these after acceptance criteria 1 to 9 in the original handoff pass. If time is short, do A and B first.

### A. Operational impact panel (supports the "security evaluation" marks)
When the loaded CSV has a `Label` column, add a panel (a tab, via the chart plugin interface) showing, at the **current threshold**:
- The confusion matrix: true positives, false positives, true negatives, false negatives, with raw counts.
- Recall, precision, F1, false positive rate, and accuracy (accuracy shown last, with the note "accuracy alone can mislead because most flows are benign").
- Per-tool recall (HOIC, LOIC-HTTP, LOIC-UDP), with the number of flows in each, and a visible warning when a tool has fewer than 1,000 flows ("LOIC-UDP has only about 1,730 flows in total, so this number is noisy").
- An **assumed attack prevalence** input (default 0.1%, adjustable). Using the measured recall and false positive rate, compute and show the **expected precision** and the **expected false alarms per million flows** at that prevalence. Formula: `precision = recall*p / (recall*p + FPR*(1-p))`. Label it clearly as an illustration, not a measurement, because the dataset's attack share is much higher than real traffic.
- The warning "The test data come from the same testbed as the training data. These numbers are an upper bound, not expected real-world performance."

### B. Analyst workflow and feedback (supports the Week 5 and "new data and feedback" marks)
The course asks how alerts reach an analyst and how confirmed attacks and false positives become new training data. Add a small, honest version of that loop:
1. **Analyst verdict column** in the results table with values: `unreviewed` (default), `confirmed attack`, `false positive`, `unsure`. The analyst sets it with a dropdown or right-click menu on a selected row, and can add a free-text note.
2. **Save/Load review file**: File -> Save review (`review_<csvname>.json` or CSV) and Open review. It stores the original row number, source file name, the model score and flag at the time, the verdict, the note, and the model name and version.
3. **Export alerts**: File -> Export alerts for SIEM. Writes the flows currently flagged as DDoS to CSV **and** JSON Lines, one record per alert, with fields: `alert_id`, `row_number`, `source_file`, `timestamp` and `src_ip`/`dst_ip`/`dst_port` **if those columns exist in the input** (shown for tracing only; never model inputs), `model_name`, `model_version`, `model_score`, `threshold`, `flag`, and the top 3 SHAP features with direction (for example `Flow Duration: pushes toward DDoS`). Keep the field names simple and stable. This is a prototype of what a SIEM would ingest, so do not integrate with any real SIEM.
4. **Export feedback for retraining**: File -> Export labelled feedback. Writes the 9 feature columns plus the analyst's verdict mapped to a label (`confirmed attack` -> 1, `false positive` -> 0, `unsure` excluded), with the source file and row number. Document in the README that retraining from this file is a manual step in `train/train_model.py` (add a `--extra-labelled <file>` option if it is simple; otherwise just document it).
5. In the About dialog add a short "How this fits a SOC workflow" text: flows scored -> alerts exported to a SIEM -> analyst reviews with the SHAP explanation -> verdicts saved -> verdicts exported as new labelled examples -> periodic retraining, triggered by a drift or false alarm rate increase. Keep it to one paragraph; the group will present the full architecture separately.

### C. Feature notes panel (supports the "feature engineering" marks, the largest block)
Add a **Features** dialog or tab listing all 9 columns grouped by the 6 feature groups. For each: raw data needed, how it is calculated, the security assumption, a legitimate look-alike, how an attacker could evade it, and **what the data showed**. Store this as a data file, `app/data/feature_notes.json`, not hard-coded in the UI.
- The first five fields come from the project's Week 3 documents, which the group will provide. Until then, use the one-line descriptions in `train/train_model.py`.
- "What the data showed" comes from `feature_evidence.csv`, produced by notebook section 9b. If the file is not there, show "run notebook section 9b to fill this in". Do not invent numbers.
- Show a short note: "The assumptions below are hypotheses. Where the data did not support an assumption, this is stated."

### D. Timing display (the Week 4 plan promises timing)
Show in the status bar or the About dialog, for the last run: time to load and clean the CSV, time to score N flows (flows per second), and time to compute SHAP for the selected sample (per explanation). Log them to the log file as well. Measure with `time.perf_counter()`; do not estimate.

### E. Seed-stability chart (was "nice to have", now wanted)
The project plan promises a check of explanation stability across runs. Add a chart plugin that loads all models in `models/` whose `.meta.json` mark them as seed variants of the same setup (add a `"setup"` and `"seed"` field to the metadata), computes mean |SHAP| per feature on the same sample, and shows the feature ranking for each seed plus the Spearman rank correlation between seeds. `train/train_model.py` needs a `--seeds 0 1 2 3 4` option for this.

## 3. Evidence file from the notebook (section 9b)

Notebook section 9b compares each attack tool with benign flows **from the same file** and writes `feature_evidence.csv` with these columns: `attack`, `feature`, `attack_median`, `benign_median_same_day`, `direction` (higher/lower/same), `attack_zero_share`, `benign_zero_share`, `single_feature_auc`.

How to read `single_feature_auc`: 0.5 means the feature alone does not separate attack from benign; far above or far below 0.5 means it does (below means attacks have lower values). Use `direction` and AUC together before calling an assumption supported.

Findings already observed (medians only, from the earlier notebook runs; section 9b will give the full picture, and **its output overrides these**): attack flows were not faster or shorter than Wednesday benign flows; `SYN Flag Cnt` had median 0 for every tool; HOIC and LOIC-UDP had forward packet length std of 0; the forward/backward ratio was extreme only for LOIC-UDP. These contradict some assumptions in the group's Week 3 table, which is why the Features panel must show the data next to each assumption.

## 4. Additional acceptance criteria (add to the original 10)

11. Nowhere in the UI, exports or docs does the word "confidence" or "probability" describe the model score. Search for both words before finishing.
12. With a CSV that has `Label`, the Operational impact panel shows the confusion matrix and the expected-precision illustration, and its numbers match a hand calculation in a unit test (use a tiny synthetic example).
13. Setting a verdict, saving the review, closing the app and reopening it with the same CSV and review file restores every verdict and note.
14. "Export alerts" writes valid CSV and valid JSON Lines (a test parses every line), and no alert record contains any model-input value that did not come from the 9 features, apart from the tracing fields listed above.
15. "Export labelled feedback" excludes `unsure` rows and `unreviewed` rows and writes only the 9 feature columns plus label, source file and row number.
16. The Features panel renders without `feature_evidence.csv` (showing the "run section 9b" message) and with it.
17. Timing is reported using measured values, and a unit test checks that the timing helper returns a positive duration.

## 5. Non-goals (unchanged, plus)

- No real SIEM, email, webhook or network integration. The "SIEM export" is a file only.
- No automatic blocking or mitigation (out of scope in the project definition).
- No claims in the UI that the model detects unseen DDoS tools. The About / Model card must keep the honest results from section 3 of the original handoff.
- Do not edit the group's project documents. If the feature notes need text from them, ask me.

## 6. Order of work

1. Corrections in section 1 (rename to "model score" everywhere).
2. Operational impact panel (A).
3. Analyst verdicts, review save/load and exports (B).
4. Features panel (C) and timing (D).
5. Seed-stability chart (E).
Give me a short plan first, as in the original working agreement, and tell me what you could not test.
