# Handoff update 2: the model now has 15 input columns (features 8 to 11 added)

Read this together with `HANDOFF_desktop_app.md` and `HANDOFF_UPDATE_1.md`. **Where this update disagrees with them, this update wins.** It changes the feature set, so everything that mentioned "9 columns" or "6 feature groups" is now out of date. Everything else (PySide6, project layout, chart plugin interface, threading rules, the "model score" wording, the operational impact panel, analyst verdicts and exports, timing, non-goals, working agreement) still applies. It is written for any coding agent.

Files to read first (I will attach them): `ddos_xgboost_starter_v2.ipynb` (source of truth for the logic) and `Weeks_1_to_4_-_DDoS_Detection_Project_UPDATED.docx` (Week 3 holds the feature descriptions you will turn into the Features panel). If the notebook and this file disagree, the notebook wins; tell me about the difference.

## 1. What changed

The model now has **15 input columns from 10 feature groups**. Feature 7 (flows to the same destination in a window) is **dropped**, because the 21 February file has no `Dst IP`. Features 8 to 11 were **added after the first experiments**, chosen for their security meaning. I do not yet know whether they improve results on the real data; the notebook (section 9c) measures it. **Do not display or write any text that claims they help.**

Exact input columns, in this order (the order matters for the trained model):

```
Flow Pkts/s, Flow Byts/s, Flow Duration, Flow IAT Mean, Flow IAT Std, SYN Flag Cnt,
Fwd Pkt Len Mean, Fwd Pkt Len Std, fwd_bwd_ratio,
Bwd Pkt Len Mean, RST Flag Cnt, FIN Flag Cnt, no_reply, empty_payload, iat_cv
```

| Feature # | Group name | Columns | Source in the CSV / formula |
|---|---|---|---|
| 1 | rate | `Flow Pkts/s`, `Flow Byts/s` | CSV columns |
| 2 | duration | `Flow Duration` | CSV column |
| 3 | fwd_bwd_ratio | `fwd_bwd_ratio` | `Tot Fwd Pkts / (Tot Bwd Pkts + 1)` |
| 4 | inter_arrival | `Flow IAT Mean`, `Flow IAT Std` | CSV columns |
| 5 | syn_flag | `SYN Flag Cnt` | CSV column |
| 6 | fwd_pkt_len | `Fwd Pkt Len Mean`, `Fwd Pkt Len Std` | CSV columns |
| 7 | (dropped) | none | needs `Dst IP`, absent from the 21 Feb file |
| 8 | reply | `Bwd Pkt Len Mean` | CSV column |
| 9 | conn_end_flags | `RST Flag Cnt`, `FIN Flag Cnt` | CSV columns |
| 10 | indicators | `no_reply`, `empty_payload` | `no_reply = (Tot Bwd Pkts == 0)` as 0/1; `empty_payload = (Fwd Pkt Len Mean == 0)` as 0/1 |
| 11 | timing_regularity | `iat_cv` | `Flow IAT Std / (Flow IAT Mean + 1)`, with inf/-inf turned into missing |

So the CSV must contain these raw columns: the nine original ones minus `fwd_bwd_ratio`, plus `Tot Fwd Pkts`, `Tot Bwd Pkts`, `Bwd Pkt Len Mean`, `RST Flag Cnt`, `FIN Flag Cnt`. Strip stray spaces from column names when reading.

## 2. Required design change: a feature registry

Do **not** hard-code the nine or fifteen columns in several places. Build `app/core/features.py` around one **registry**: each entry has `feature_number`, `group_name`, `output_columns`, `required_raw_columns`, `build(df)`, and the text fields in section 4. Then:
- Training, scoring, the SHAP charts, the Features panel and the tests all read the registry.
- A model's `.meta.json` lists its `feature_columns` (in order) and the groups it used. The app builds **exactly** the columns that model lists, so a 9-column model and a 15-column model both load and score correctly.
- If the loaded CSV lacks raw columns that the active model needs, show a dialog naming the missing columns. If a model that does not need them exists (for example the 9-column one), offer it; never silently score with fewer features.
- Models trained before this update have no `feature_columns`; treat a missing field as the original nine columns.

## 3. Changes to the existing handoff items

**Training (`train/train_model.py`)**
- Add `--feature-set f9|f15` (default `f15`) and name outputs accordingly (for example `all_tools_f15`, `hoic_held_out_f15`). Keep `--mode all_tools|hoic_held_out` and `--seeds`.
- Load the extra raw columns with `usecols`; if a file lacks one, print it and continue with the groups that remain (the same rule the notebook uses). Do not drop rows because of missing values in the new columns (XGBoost handles missing values). Rows with missing or infinite values in the original nine columns or in `Tot Fwd Pkts` / `Tot Bwd Pkts` are dropped for training, as in the notebook. Duplicates are judged on the original columns only.
- Write into the metadata: `feature_columns`, `feature_groups`, and **the evaluation results computed by this script for this feature set** (baseline recall per tool and false positive rate; held-out HOIC and LOIC-HTTP recall at threshold 0.5), plus counts and library versions.

**Scoring and validation of input rows**
- Rows with missing or infinite values in the original nine columns or in the two packet-count columns are listed as "Not scored (invalid values)", not dropped silently, as before.
- Missing values in the six new columns are **allowed** (the model handles them). Count them and show the number in the summary bar ("N flows have missing values in features 8 to 11").
- `iat_cv` can be infinite when `Flow IAT Mean + 1` is zero (negative inter-arrival times exist in these files); convert to missing.

**About / Model card**
- Do **not** hard-code results. The numbers in the original handoff (baseline recall 0.999, 0.987, 1.000; HOIC held out 0.156 to 0.195; LOIC-HTTP held out 0.003) are for the **original nine columns only**. For a 15-column model, show the numbers from its own metadata. For a 9-column model you may show those figures, labelled "nine-column model".
- Keep the honest framing: detection of known tools versus no transfer to unseen tools **was observed with nine columns**; whether it changes with 15 columns is exactly what the training script reports. Do not state a conclusion in the app text; show the metadata numbers and the warnings (upper bound for random splits, LOIC-UDP has only about 1,730 flows, tool and day are confounded).

**SHAP**
- Per-row waterfall: one bar per **column**, labelled with its feature number (for example `empty_payload (F10)`).
- Global bar and beeswarm: add a toggle **"by column / by feature group"**. Group value for each row is the **sum of the SHAP values of that group's columns** (SHAP is additive); the importance is then the mean absolute value of that sum. Show feature numbers 1 to 11 (no group 7).
- SHAP by tool (needs `Label`): same toggle.
- The binary columns (`no_reply`, `empty_payload`, flags) should render sensibly in the beeswarm; check that the colour scale does not break when a column has only two values.

**Features panel (from Update 1, section C), now for all 15 columns / 10 groups**
- Build `app/data/feature_notes.json` from Week 3 of the Word document: for each feature group the raw data needed, how it is calculated, the security assumption, a legitimate look-alike, and how an attacker could evade it. Ask me for the text if you cannot read the document; do not invent it. Short reference for the new groups:
  - **8 reply** (`Bwd Pkt Len Mean`): assumption, the target's replies are smaller or absent during an attack; look-alike, uploads, streaming, errors; evasion, not directly controllable by the attacker.
  - **9 conn_end_flags** (RST, FIN): assumption, attack flows end differently from normal browsing; look-alike, network faults and timeouts; evasion, closing connections properly. UDP has no TCP flags, so LOIC-UDP gets no information from these.
  - **10 indicators**: assumption, many flood flows are one-sided or carry no data; look-alike, port scans, keepalives, one-way UDP; evasion, sending real requests that get replies. They restate information already in packet counts and lengths, so they may add little accuracy; included because they make explanations readable.
  - **11 timing_regularity** (`iat_cv`): assumption, automated sending is regular; look-alike, polling and heartbeats; evasion, adding random delays.
- "What the data showed" comes from `feature_evidence.csv` (notebook section 9b, now covering all 15 columns): per attack tool, medians against benign flows **from the same file**, zero shares and a single-feature AUC. Show direction and AUC next to each assumption; where the data does not support an assumption, say so in plain words ("not supported so far"). One already observed fact: the SYN flag count median is 0 for all three attack tools and the first held-out model did not use it. If the file is missing, show "run notebook section 9b".

**New chart plugin: feature-set comparison**
- Reads `feature_set_comparison.csv` (written by notebook section 9c) from a path chosen with File -> Open comparison results, or from the models folder if present.
- For each experiment (HOIC `per_day`, HOIC `by_file`, LOIC-HTTP `per_day`) show recall, false alarms and PR-AUC for each feature set (base nine columns, each group added alone, all 15), with the spread across seeds as error bars (`recall_min` to `recall_max` come from the seed runs). Add the caption: "Differences smaller than the spread between seeds are noise. Seed changes the benign sample only." Without the file, show an explanation of how to produce it.
- This chart reports; it does not recommend. No "best set" wording.

**Operational impact panel, analyst workflow, exports, timing, seed-stability chart:** unchanged, but they must work for any model through `feature_columns`. Alert exports list the top 3 SHAP columns with their feature numbers.

## 4. Tests to add or change

- Feature registry: each group builds the right columns on a small DataFrame; output column order equals the list above.
- **Worked example from the Word document** (five packets: forward lengths 60, 500, 500; replies 60 and 1,000; gaps 0.1, 0.1, 0.1, 0.2 s): `Tot Fwd Pkts=3`, `Tot Bwd Pkts=2` gives `fwd_bwd_ratio = 1.0`; `Bwd Pkt Len Mean = 530`; `no_reply = 0`; `empty_payload = 0` (forward mean is about 353); with `Flow IAT Mean = 125000` and `Flow IAT Std = 50000`, `iat_cv` is about 0.39999 (that is 50000 / 125001).
- Edge cases: `Tot Bwd Pkts = 0` gives `no_reply = 1`; `Fwd Pkt Len Mean = 0` gives `empty_payload = 1`; `Flow IAT Mean = -1` gives `iat_cv` missing, not infinite; missing extras do not drop rows; missing original columns are reported by name.
- A 9-column legacy model (or a model with no `feature_columns` in its metadata) still loads and scores.
- SHAP group aggregation: the sum of the per-column values over all columns equals the sum of the group values for each row (additivity), and `base_value + sum == model margin` still holds for the 15-column model.
- Training metadata contains `feature_columns` and results, and the model card renders from them.
- The feature-set comparison chart renders from a small synthetic CSV and shows the explanation when the file is absent.

## 5. Additional acceptance criteria (add to the earlier lists)

18. Changing the model changes the columns the app builds; no feature list is duplicated outside the registry (search the code before finishing).
19. A CSV without `Bwd Pkt Len Mean` (or another new raw column) produces the missing-column dialog, and a 9-column model can still score it.
20. The Features panel lists 10 groups (numbers 1 to 6 and 8 to 11), shows the data evidence when `feature_evidence.csv` exists, and never fills in numbers by itself.
21. The About / Model card for a 15-column model shows only numbers from its own metadata.
22. No text anywhere says features 8 to 11 improve detection.

## 6. What has and has not been verified

- The notebook was tested end to end on **synthetic** CSVs shaped like the real files (repeated header rows, `Infinity` values, duplicates, a Wednesday file without `Dst IP`, and a variant missing some new columns). It has **not** been run on the real data, so I cannot give you real 15-column results, and the numbers you see in the synthetic test mean nothing.
- Section 11 of the notebook (SHAP) has never been run. Check that SHAP works with the installed XGBoost version before you pin versions.
- Tell me what you could not test, especially anything that needs the desktop window.

## 7. Order of work

1. The feature registry, the metadata format, the training script with `--feature-set`, and the tests for them.
2. Scoring with validation, then the table and threshold control (using the registry).
3. SHAP with feature numbers and the group toggle.
4. The Features panel, the model card from metadata, and the feature-set comparison chart.
5. Everything left over from Update 1 (operational impact, verdicts and exports, timing, seed stability), adjusted for `feature_columns`.

Give me a short plan first, as in the original working agreement. Do not make commits or push anything unless I ask.
