# Feature search on the relabelled data: which six to eight feature groups help all three models (5 Nov 2026)

Run: `DDoSDetector\scripts\feature_search_ip.py --final-seeds 0 1` (196 min). Every fit is in
`docs\feature_search_ip_2026-11-05.csv` (1,236 rows); the forward-selection paths are in
`docs\feature_search_ip_path_2026-11-05.json`.

**Built in later the same day (update 5, the user's decision "Build the six"):** the six are the app's features 1 to 6
(the catalogue was renumbered afterwards at the user's request: F16 → 1, F18 → 2, F17 → 3, F3 → 4, F10 → 5, F11 → 6; the
labels below are the pre-renumbering ones, which are also the Week 3 document numbers plus 16–18), feature set `f7ip`, the app's default model `all_tools_f7ip` (XGBoost; `_rf` and `_svm` variants and the held-out
models alongside), trained on the 20 Feb file plus the relabelled 21 Feb capture. The built-in results are in each model's
metadata and in the README; the Week 5 questions are re-run in `notebooks\ddos_week5_threshold_retraining_update6.ipynb` (6 Nov 2026; the update-5 copy was removed).
The group has not confirmed the choice.

## Short answer

**Recommended six groups (all three models): F16, F18, F17, F3, F10, F11.**

| Group | What it measures | What a DDoS cannot avoid showing |
|---|---|---|
| F16 Flows to the same destination IP (10 s look-back) | how many flows hit this server in the last 10 s | the flood itself: traffic piles up on one target |
| F18 Distinct source IPs to the same destination IP (10 s) | how many different senders hit this server | many machines on one target (or one, see F17) |
| F17 Flows from the same source IP (10 s) | how often this sender repeats | one machine hammering |
| F3 Forward to backward packet ratio | packets sent vs packets answered | the victim cannot answer in kind |
| F10 No-reply and empty-payload indicators | no reply at all, or nothing in the request | cheap, one-sided requests |
| F11 Timing regularity | how even the gaps between packets are | a tool, not a person, is sending |

The base six (F1 F2 F4 F6 F3 F7) describe **the tool** (its packet sizes, byte totals, rates, port use), which is why they do
not carry over to a tool the model has not seen. The six above describe **the attack** (volume on one target, many or
repeating senders, one-sided traffic, machine timing), and they carry over.

**Eight-group option: the six plus F7 (flows to the same destination port) and F8 (reply behaviour).** It is better for
Random Forest only; it costs XGBoost on unseen LOIC-HTTP and it breaks the SVM on unseen LOIC-UDP. Other eight-group
combinations (for example the six plus F7 and F6) were not tested.

## Results (stage C: no caps, seeds 0 and 1 averaged, threshold 0.5)

"Held out" = the model never saw that tool in training. FPR = false-alarm rate on the benign test flows (about 2.15 M
flows for the held-out splits, 300 k for the all-tools split). LOIC-UDP recall has a ceiling of 0.520: 1,730 of its
3,328 rows are the flood, the other 1,598 are the server's ICMP replies (labelled as attack by-products, by our choice on
5 Nov); every "0.52" below means **every flood flow was caught** and no reply row was.

### XGBoost (the main model)

| Split | Base six (f9p) | Recommended six | Eight (six + F7 F8) |
|---|---|---|---|
| All tools, worst tool recall / FPR | 0.999 / 0.0003 | 0.975 / 0.0001 | 0.993 / 0.0000 |
| HOIC held out | 0.182 / 0.0023 | **0.9999 / 0.0000** | 0.9994 / 0.0008 |
| LOIC-HTTP held out | 0.005 / 0.0011 | **0.904 / 0.0000** (0.96, 0.85) | 0.700 / 0.0000 |
| LOIC-UDP held out | 0.517 / 0.0056 | 0.520 / 0.0000 | 0.446 / 0.0008 |

The all-tools "worst tool" with the six is LOIC-UDP (0.975); HOIC and LOIC-HTTP are 1.000 there.

### Random Forest

| Split | Base six (f9p) | Recommended six | Eight (six + F7 F8) |
|---|---|---|---|
| All tools, worst tool recall / FPR | 0.975 / 0.0003 | 0.953 / 0.0001 | 0.974 / 0.0000 |
| HOIC held out | 0.188 / 0.0049 | 0.877 / 0.0000 (0.75, 0.999) | **0.9994 / 0.0000** |
| LOIC-HTTP held out | 0.0045 / 0.0011 | 0.429 / 0.0000 (0.37, 0.49) | **0.497 / 0.0000** |
| LOIC-UDP held out | 0.518 / 0.0032 | 0.518 / 0.0000 | 0.518 / 0.0000 |

Random Forest is the least stable between seeds (HOIC 0.75 vs 0.999 with the six).

### Linear SVM

| Split | Base six (f9p) | Recommended six | Eight (six + F7 F8) |
|---|---|---|---|
| All tools, worst tool recall / FPR | 0.499 / 0.0058 | 0.496 / 0.0005 | 0.496 / 0.0005 |
| HOIC held out | 0.491 / 0.0178 | **0.9999 / 0.0012** | 0.9999 / 0.0013 |
| LOIC-HTTP held out | 0.160 / 0.0217 | **0.979 / 0.0004** | 0.978 / 0.0004 |
| LOIC-UDP held out | 0.000 / 0.0226 | 0.437 / 0.0002 | 0.001 / 0.0005 |

The SVM's "all tools" worst tool is always LOIC-UDP at about 0.5 (it catches the flood, not the reply rows); its false-alarm
rate drops from about 2 % to 0.05 % with the six.

### Why "0.49" keeps appearing

Many sets score 0.487–0.497 on held-out HOIC or LOIC-HTTP. CICFlowMeter cuts each HTTP connection into two flows at the
first FIN (the request/response exchange and a short tail of the packets after it), so a set that recognises only one of
the two halves scores about one half. Our reading, not checked flow by flow.

## How the search was run

- Data: the published 20 Feb file (whole network, with IPs; 7.95 M rows) plus the rebuilt 21 Feb victim-capture file
  with IPs and corrected labels (2.17 M rows). After cleaning: 9,880,087 flows (Benign 7,183,744; HOIC 2,116,841;
  LOIC-HTTP 576,174; LOIC-UDP 3,328).
- Candidates: registry groups F1–F13 except F5 (dropped in update 4), plus three new IP-window features built the same
  way as feature 7 (10 s look-back, per capture file): F16 flows to the same destination IP, F17 flows from the same
  source IP, F18 distinct source IPs to the same destination IP. F14 and F15 were not tested (the rebuilt 21 Feb file has
  no Active/Idle columns).
- Models: XGBoost, Random Forest and linear SVM with the app's settings (`app/core/models.py`). SVM: rows with missing
  values are dropped from training and counted as not flagged in testing (none occurred in stage C).
- Stage A: base six vs base six + one candidate, seeds 0 and 1, every model, attack rows capped at 500 k. Verdicts by
  the group's rule (better only if every seed beats the base's best recall without more false alarms):
  XGBoost: F16 better on HOIC and LOIC-HTTP, F18 better on HOIC and LOIC-HTTP; F8–F13 no change or worse.
  Random Forest: only F16 on LOIC-HTTP (0.004 to 0.067). SVM: F16 better on all three, F17 better on HOIC and LOIC-HTTP,
  F12 better on HOIC; F13 mixed.
- Stage B: forward selection per model, seed 0, 200 k attack / 300 k benign training rows, objective = mean held-out
  recall with false alarms at most 2 %. All three models picked a window feature first (XGBoost and RF: F18; SVM: F16).
  XGBoost and RF peaked at three groups (F18 F3 F10: HOIC 0.996, LOIC-HTTP 0.993, LOIC-UDP 0.52) and every further
  group lowered the mean; the "best 6 by XGBoost" (F18 F3 F10 F11 F12 F6) was then worse than the three in stage C, so
  stage B on capped data is a rough guide only. The recommended six is RF's stage-B path; it was the only six that held up
  for all three models in stage C.
- Stage C: base six and each model's best 6 and best 8, every model, seeds 0 and 1, no caps.

## Medians of the window features (per capture file)

| | dst-IP flows 10 s (F16) | src-IP flows 10 s (F17) | distinct sources (F18) | dst-port flows 10 s (F7) |
|---|---|---|---|---|
| 20 Feb Benign | 7 | 7 | 4 | 393 |
| 20 Feb LOIC-HTTP | 1,530 | 154 | 10 | 1,752 |
| 21 Feb Benign | 0 | 0 | 0 | 0 |
| 21 Feb HOIC | 6,756 | 678 | 11 | 7,066 |
| 21 Feb LOIC-UDP | 4 | 6 | 1 | 21 |

LOIC-UDP flows are few (each lasts the full 120 s timeout), so the window features see almost nothing for it; what catches
the UDP flood is F3/F10 (no reply at all).

## Limits (say these in the report)

1. **The window features need `Src IP` and `Dst IP`.** The published 21 Feb CSV has neither (we rebuilt it from the raw
   capture); any file without them cannot be scored by these models. Live CICFlowMeter output has both, so this fits the
   Week 5 live design, but the app and the registry do not have F16–F18 yet.
2. **The benign side is one quiet network.** 7.18 M of the 7.19 M benign flows are the 20 Feb whole-network file, and the
   victim server was nearly idle (median 7 flows per 10 s). A busy legitimate server (a popular website, a DNS server)
   would push F16 and F17 up for normal traffic too. Not tested; no such data here.
3. **Only ten attacker machines.** F18 learned "about 10 senders in 10 s", not "hundreds". A real botnet is larger; a busy
   server has more legitimate senders than that. F16 (volume) is the more general of the two.
4. **Seeds.** Stage C used two seeds; Random Forest varied a lot between them (HOIC 0.75 vs 0.999; LOIC-HTTP 0.37 vs 0.49).
   XGBoost and SVM were stable except XGBoost on LOIC-HTTP (0.96 vs 0.85).
5. **Caps in stages A and B** (500 k / 200 k attack rows) and seed 0 only in stage B.
6. **LOIC-UDP** stays at 0.52 everywhere because the 1,598 ICMP reply rows are never flagged. If the group prefers, relabel
   them Benign (they are the server's replies, not the attacker's packets) and the LOIC-UDP recall becomes 1.00 with the
   same models.
7. **Threshold 0.5** throughout; no calibration (the score is a model score, not a probability).
8. **Same two days as always.** Held-out tool is the only unseen-data test; a different network or a later year is not.

## What would come next (not done)

- Add F16, F17, F18 to the feature registry (`app/core/features.py`) with `Src IP`/`Dst IP` as context columns, train
  `all_tools` and held-out models on the six, and let the app build the three window features from the whole loaded file
  (as it does for feature 7). This is the group's decision; it replaces five of the six current groups.
- Re-run the Week 5 threshold notebook with the new models.
- If the group keeps the eight, note per model which tool it costs.
