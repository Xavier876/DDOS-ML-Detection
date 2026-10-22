# COMP6310 DDoS Detection Project: Handoff for a New Chat

Paste or attach this file at the start of a new chat. It summarises everything decided and produced so far, so the new chat can continue without re-asking.

## 1. Who and what

- User: Xavier (COMP6310 group project, network intrusion detection).
- Project title: **Explainable Machine Learning for DDoS Attack Detection in Network Traffic**.
- The attack of interest is **DDoS** (not DoS in general). The user briefly considered DoS and then reverted to DDoS. Keep DDoS everywhere.
- Dataset: **CSE-CIC-IDS2018**, processed CICFlowMeter CSV files, using flow records only.
- Each group member reviews two papers. The group presents for about 10 minutes.

## 2. Decisions the group has made

- Detection approach: **behavioural, supervised**. Not signature-based, not unsupervised anomaly detection, hybrid considered and set aside.
- Model: a **single supervised model, XGBoost**, with an **XAI component (SHAP, TreeExplainer)**.
- Model output: a **flag** (benign or DDoS) plus a **confidence score** between 0 and 1. DDoS is the positive class.
- Labels: the dataset is labelled and will be cleaned as needed (missing, infinite and duplicate values).
- Unit of observation: one bidirectional network flow (CICFlowMeter-V3). The dataset creators already converted raw packets into flows.
- IP addresses and timestamps are kept out of the model inputs (used only for tracing alerts and to build one derived feature).
- Detection mode: offline, on recorded flows.

## 3. Data scope

- Use the DDoS days, **20 and 21 February 2018**. Benign flows come from the same days.
- Three DDoS tools: **LOIC-HTTP, LOIC-UDP, HOIC**. From memory (not verified): LOIC-HTTP is in the 20 February file, LOIC-UDP and HOIC in the 21 February file.
- Out of scope: the DoS attacks of 15 and 16 February (GoldenEye, Slowloris, SlowHTTPTest, Hulk).
- Expect LOIC-UDP to be the smallest class, so its separate results may be unreliable.
- The user's files on their Windows machine: `C:\Users\Xavie\source\repos\DDOS-ML-Detection\data`
  - `Thuesday-20-02-2018_TrafficForML_CICFlowMeter` (about 3.9 GB). Note the dataset's spelling "Thuesday".
  - `Wednesday-21-02-2018_TrafficForML_CICFlowMeter` (about 321 MB).
  - File Explorer hides the `.csv` ending; the real names should end in `.csv`.

## 4. Week 3 features (seven)

1. Packet and byte rate (Flow Pkts/s, Flow Byts/s)
2. Flow duration
3. Forward to backward packet ratio: Tot Fwd Pkts / (Tot Bwd Pkts + 1) (derived)
4. Inter-arrival time (Flow IAT Mean, Std)
5. SYN flag count (SYN Flag Cnt). Says nothing for UDP flows.
6. Forward packet length (Fwd Pkt Len Mean, Std)
7. Flows to the same destination IP in a 10-second window (derived; needs Dst IP and Timestamp, and the user must drop it if those columns are missing in a file)

Column names are from memory and must be confirmed against the real CSVs.

## 5. Testing and evaluation plan

- Split before balancing. Use SMOTE or class weights **only inside training data**.
- **Hold out one DDoS tool.** Recommended main held-out tool: **HOIC** (train on LOIC-HTTP and LOIC-UDP). Then rotate through the other two as secondary results; LOIC-UDP held out is a stress test. The group has **not** confirmed this choice.
- Benign flows are split by time: benign inside the held-out tool's attack period goes to the test set, the rest to training.
- Metrics: DDoS recall, precision, false-alarm rate, F1, confusion matrix, ROC and PR AUC, results per tool, threshold sweep, plus training, prediction and explanation time.
- False-alarm test on benign high-rate flows (flash crowd is the classic false positive).
- Explanation checks: compare SHAP top features with known DDoS behaviour and check stability across random seeds and models (neither reviewed paper measured stability).

## 6. Papers reviewed

- **Karatas, Demir & Sahingoz (2020), IEEE Access 8, 32150-32162.** Imbalanced and up-to-date dataset (CSE-CIC-IDS2018), SMOTE, six classifiers, five-fold cross-validation. AdaBoost overall accuracy 99.69% to 99.60% after SMOTE; average accuracy per attack type 95.49% to 99.32%. Weaknesses: SMOTE applied before the folds (possible optimism), one dataset, no unseen tool, DoS is a single label.
- **Wang, Zheng, Yang & Wang (2020), IEEE Access 8, 73127-73141.** SHAP framework for neural-network IDS on NSL-KDD, one-vs-all and multiclass models, accuracy about 0.806 and 0.803. Neptune (SYN flood) example: 93% vs 89% confidence, different reasons; three of the top four reasons are SYN-error rates for one-vs-all. Weaknesses: old data, about 80% accuracy, explanations judged by eye, no stability measure, SHAP too slow for real time.
- **Dhaliwal, Nahid & Abbas (2018), Information 9(7), 149.** XGBoost on NSL-KDD, 98.70% accuracy. Kept as a spare review because it is the weakest fit (old data, "positive" means normal, train and test files merged). The user swapped it out for Wang.
- Other group reading (from the chat, labels may need correcting): CNN-LSTM (Halbouni et al. 2022), CNN-GRU (Cao et al. 2022), a botnet explanation paper, SHAP/LIME papers.
- Outside XGBoost defence sources (existence confirmed by search, not read in full): Chen & Guestrin 2016 (XGBoost), Grinsztajn et al. 2022, Shwartz-Ziv & Armon 2022, Lundberg et al. 2020 (TreeSHAP). Liu et al. 2022 (dataset label errors) was seen by abstract only.

## 7. Files already produced (all in the outputs folder of the original session)

- `Review - Karatas et al 2020.docx`, `Review - Wang et al 2020.docx`, `Review - Dhaliwal et al 2018.docx` (spare)
- `COMP6310_Two_Paper_Reviews_10min.pptx`: 10-slide deck on Karatas and Wang with presenter notes; title slide carries the user's name and ID line. `..._Dhaliwal_version.pptx` is the earlier version.
- `Week 2 - Detection Approach, Data and Observations.docx`
- `Week 3 - Feature Engineering and Security Assumptions.docx` (seven features, six questions each, calculation section with a worked example)
- `Week 4 - Machine-Learning Method and Model Development.docx` (XGBoost-only group draft)
- `Week 4 - XGBoost Defences and Testing Overview (Xavier).docx` (the user's individual task, due Monday or Tuesday: defences for XGBoost from the literature, and an overview of testing and evaluation methods in the papers)
- `Weeks 1 to 4 - DDoS Detection Project.docx`: all four weeks combined (Week 1 taken from the group's own file)
- `ddos_xgboost_starter.ipynb`: starter notebook (load, inspect labels, clean, build features, held-out-tool split, XGBoost, metrics, SHAP). Tested only on made-up data; not yet run on the real files.

## 8. Where things stand right now

The user runs the notebook in Jupyter on their own Windows machine. The load cell failed with `FileNotFoundError` because the `FILES` list had "Tuesday" and no `.csv` ending. The fix:

```python
FILES = ["Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
         "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"]
```

(or set `DATA_DIR = Path(r"C:\Users\Xavie\source\repos\DDOS-ML-Detection\data")`). Possible memory trouble loading the 3.9 GB file; if the kernel crashes, change the notebook to load lighter (fewer columns as float32, category dtype for labels, or chunked reading).

## 9. Next steps

1. Get the load cell working and read the output: file names, column counts, any "MISSING column" lines, label counts per file.
2. Confirm column names, whether Dst IP and Timestamp exist in both files (decides whether feature 7 stays), and which tool is in which file.
3. Confirm the held-out tool with the group, then run the experiment for all three tools and compare.
4. Check explanation stability across random seeds and false alarms on benign high-rate flows.
5. Update Week 2 to 4 wording where it depends on the real data (column names, class sizes).
6. Submit the individual Week 4 contribution to the group by Monday or Tuesday.

## 10. How the user likes to work

- Plain, easy-to-explain language; the user asked for "humanized" text, short and clear presentation material, and presenter notes that are easy to say aloud.
- Documents are Word (.docx) in a consistent clean style; decks are made as .pptx with presenter notes.
- The user is not a deep Python user: give step-by-step instructions for their own machine (Windows, Jupyter), and ask them to paste error messages.
- Be honest about what is unverified (column names, dataset file contents, citations not read in full) and flag it in the documents.
