# Handoff: session 2 (22–23 Oct 2026), update 3, model clean-up, hybrid experiment

Continues `HANDOFF_SESSION_1.md` (app build, handoff updates 1 and 2; its sections 10 and 11 hold
the detailed update-3 and hybrid tables). `CLAUDE.md` in the solution folder has the commands and the
rules for working in this repo. Everything below was run on the developer's machine (Windows 11,
Python 3.14 venv) unless it says otherwise.

## 1. What was asked in this session

1. Suggest more features that could be built from the dataset; then **update 3**: add features 12–15,
   leave out the initial window size (testbed leak), drop SYN Flag Cnt, test them in notebook 9b/9c on
   identical splits.
2. Update Week 3 of the project document for update 3, as a **new** Weeks 1–4 document; then Week 4
   (21 columns, "model score" wording).
3. Train the 21-column models and make them the app default.
4. Commit everything to the local Git repo.
5. Remove the nine-column models from this version, then the fifteen-column models too ("only the
   21-column version"). The user asked to be told what will be deleted **before** deleting.
6. Fix how values are shown in the table (scientific notation, cut-off headers).
7. Explain why held-out HOIC flows are flagged Benign; what that says about XGBoost and zero-day
   attacks; how a hybrid approach could work; whether other datasets contain HOIC; whether SMOTE
   would help.
8. Run the hybrid experiment (notebook section 9d).

## 2. Current state

| Item | Status |
|---|---|
| Default feature set | `f21`: 13 feature groups, 21 columns (section 3) |
| Models shipped (`DDoSDetector\models\`) | 12 × `*_f21`: `all_tools_f21` (+ seeds 1–4, git-ignored), held out HOIC / LOIC-HTTP / LOIC-UDP (per day), HOIC by file, all three attack period. No 9- or 15-column models |
| App default / fallback | `all_tools_f21`; no fallback model. A CSV missing an update-3 column gets the missing-column message |
| Tests | 80 pass, 1 skipped (`test_update2.py` metadata check needs real f15 model files, which were removed) |
| Documents | `docs\Weeks_1_to_4_-_DDoS_Detection_Project_UPDATE3.docx` (new; Weeks 3 and 4 updated). `..._UPDATED.docx` is unchanged |
| Notebook | `notebooks\ddos_xgboost_starter_v2.ipynb`: features 12–15 in section 6, 9b/9c extended, new 9d (hybrid). Saved without outputs; runs were on copies |
| Git (`main`, no remote) | Latest commit `26f8b98`. Uncommitted: notebook metadata only (language info, added when the notebook was opened and saved in an editor, not by Claude) |
| Not checked by hand | The real window (only headless runs); the packaged exe (blocked by Smart App Control on 22 Oct, not bypassed) |

Commits this session (newest first):

| Commit | What |
|---|---|
| `26f8b98` | Notebook section 9d: hybrid experiment (XGBoost + Isolation Forest) |
| `136b0ed` | Readable numbers (no scientific notation) and table columns sized to their headers |
| `66b66ce` | Remove the fifteen-column models; ship only 21-column models |
| `c94cb33` | Remove the nine-column models |
| `d6034a8` | Update 3: 21 input columns (features 12–15 added, SYN dropped) |

The removed models can be restored from Git history (nine-column up to `d6034a8`, fifteen-column up to
`c94cb33`); their seed copies were never committed and would have to be retrained.

## 3. Feature set f21 (the default)

Features 1–4 and 6 (original), 8–11 (update 2), 12–15 (update 3). Feature 5 (SYN) is not in f21;
feature 7 was dropped earlier (no Dst IP in the 21 Feb file).

| # | Group | Columns |
|---|---|---|
| 12 | response size ratio | `bwd_fwd_bytes_ratio` = TotLen Bwd Pkts / (TotLen Fwd Pkts + 1) |
| 13 | sender timing | `Fwd IAT Mean`, `Fwd IAT Min` |
| 14 | activity pattern | `Active Mean`, `Idle Mean` (0 in most flows) |
| 15 | payload signals | `PSH Flag Cnt` (0/1 only), `data_share` = Fwd Act Data Pkts / Tot Fwd Pkts (0/0 → missing) |

The wording for features 12–15 (six questions, data checks) was drafted in the project chat; it is in
`feature_notes.json` (`"status": "update3"`) and Week 3 of the UPDATE3 document. The group should confirm
or rewrite it.

## 4. Results (reported, not interpreted)

**Notebook 9c, same splits, 2 seeds:** HOIC held out per day: recall 0.209 (15 columns), 0.209 (14,
no SYN), 0.214 (21; seed range 0.207–0.220), false alarms ~19,400 / ~19,400 / ~15,100. HOIC by file
0.164 / 0.164 / 0.165. LOIC-HTTP 0.003 for every set. Removing SYN changed nothing. No feature group
raised recall by more than the seed spread.

**Trained f21 models (threshold 0.5; held-out rows are one seed):**

| Model | Recall | FPR (false alarms) |
|---|---|---|
| `all_tools_f21` seeds 0–4 | HOIC 0.999, LOIC-HTTP 0.989–0.990, LOIC-UDP 1.000 | 0.0079–0.0084 |
| `hoic_held_out_f21` / `_by_file_f21` / `_attack_period_f21` | HOIC 0.214 / 0.180 / 0.153 | 0.0058 / 0.0000 (2) / 0.0000 (0) |
| `loic_http_held_out_f21` / `_attack_period_f21` | LOIC-HTTP 0.003 / 0.003 | 0.0054 / 0.0061 |
| `loic_udp_held_out_f21` / `_attack_period_f21` | LOIC-UDP 1.000 / 0.994 (1,730 flows) | 0.0070 / 0.0012 |

**Notebook 9d, hybrid (Isolation Forest on benign training flows only, threshold at the 99th / 99.9th
percentile of held-back benign flows, same splits as 9c):** the anomaly layer flagged **no** held-out
attack flows (recall 0.000 for HOIC and LOIC-HTTP), so "either flags" had the same recall as XGBoost
alone, with more false alarms (HOIC per day: 15,106 → 39,475 at 99%, → 17,093 at 99.9%). It flagged
almost no high-rate benign flows (flash-crowd proxy). Per-run numbers: `DDoSDetector\models\hybrid_comparison.csv`
(local, git-ignored); table in `HANDOFF_SESSION_1.md` section 11.

## 5. Points for the report (as discussed with the user)

- **Held-out flows flagged Benign are the expected result**, not a bug: `hoic_held_out_*` models never
  saw HOIC. Example: a HOIC flow scored 0.4424 because short flow duration pushed it towards Benign more
  than the empty payload pushed it towards DDoS.
- **XGBoost and zero-day attacks:** strong on tools it was trained on (~0.99 recall), weak on an unseen
  HTTP flood tool (0.003–0.21). The cause is supervised learning on few tools plus trees not
  extrapolating, not XGBoost specifically. LOIC-UDP "transfer" was one extreme feature on 1,730 flows
  (checked with nine columns). Held-out tool ≠ true zero-day; tool and capture day are confounded.
- **Hybrid:** in this dataset a per-flow Isolation Forest added false alarms without catching the
  unseen tools. A likely (unverified) reason: HOIC/LOIC-HTTP flows resemble common benign flows, so they
  are not rare. A cross-flow (aggregate) signal like dropped feature 7 might behave differently but
  cannot be built from the 21 Feb file. Supports the Week 4 single-method decision; Week 4 not changed.
- **SMOTE (reasoning only, not tested):** training classes are within a factor of two (e.g. 700,000
  benign vs 872,455 attack; held-out HOIC 1,000,000 vs 577,904) and `scale_pos_weight` already balances
  them; recall on seen tools is already ~0.99. SMOTE interpolates between known attack flows, so it
  cannot create an unseen tool. Risks: unrealistic values for 0/1 and count columns; it must be applied
  after the split. Suggested report sentence is in the chat.
- **HOIC data:** only the 21 Feb file of CSE-CIC-IDS2018 (~686,000 flows before dedup). CIC-IDS2017 uses
  LOIC; CIC-DDoS2019 (from knowledge, not confirmed) has reflection/SYN/UDP attacks, not HOIC. The 15/16
  Feb CSE-CIC-IDS2018 files (Hulk, SlowHTTPTest, GoldenEye, Slowloris: DoS, not DDoS) would be an extra
  unseen-tool test with the same columns.

## 6. What changed in the code this session

- `app/core/features.py`: groups 12–15, sets `f14` and `f21`, `DEFAULT_FEATURE_SET = "f21"`, `FEATURES_F21`.
- `app/core/numbers.py` (new): `readable()` (58,800,000 / 0.0000016, never scientific notation), used by
  the results table (exact value in the tooltip), the waterfall labels and the Features panel.
- `app/ui/main_window.py`: `DEFAULT_MODELS = ("all_tools_f21",)`; missing-column dialog offers models in
  that order; `_fit_columns_to_headers()` sizes columns to header and first value.
- `app/ui/features_dialog.py`: "Model features (default set f21)", "Added in update 3", feature 5 marked
  "not in the default set". `app/data/feature_notes.json`: 12–15 text, `update3_note`.
- `app/plots/held_out_comparison.py`: feature-set summary moved to the subtitle (title was clipped).
- `train/train_model.py`: `--feature-set` default `f21`, help lists f9/f15/f14/f21.
- Tests: `test_update3.py` (sets, formulas, f21 scores without SYN, default model, panel, trained metas),
  `test_numbers.py`; `test_update2.py` claim scan covers features 8–15.
- README, CLAUDE.md, `HANDOFF_SESSION_1.md` (sections 10–11) updated.

## 7. Open items / suggestions

1. The group should confirm the wording of features 12–15 (`feature_notes.json`, UPDATE3 docx Week 3).
2. Week 4 §7 ("prototype has not been run yet") and §8 ("Next: download the files") still describe the
   plan before the first run. Not changed because not asked.
3. Hybrid results are not in the Word document (offered; user did not choose yet).
4. Extra unseen-tool test on the 15/16 Feb DoS files: user said "not now".
5. SMOTE vs class weights on identical splits would need `imbalanced-learn` (not installed). Not run.
6. The skipped test in `test_update2.py` (real f15 metadata) could be removed or pointed at f21 (the
   f21 check already exists in `test_update3.py`).
7. Waterfall value labels slightly overlap some bars (pre-existing, cosmetic).
8. Check the real window by hand: table formatting, column widths, Model menu with 12 models.

## 8. How to verify quickly

```powershell
.\.venv\Scripts\python.exe -m pytest DDoSDetector\tests                # 80 passed, 1 skipped
.\.venv\Scripts\python.exe DDoSDetector\app\main.py data\sample_wed_50k.csv
git log --oneline
```

In the app: the status bar should read `Model: all_tools_f21, 13 feature groups (21 columns)`; the
Model menu lists only `*_f21` models; feature columns show plain numbers with `(F#)` headers.
