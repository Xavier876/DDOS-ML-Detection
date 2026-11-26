# Flows with IP addresses from the raw 21 Feb 2018 capture

Done on 4 Nov 2026. The published 21 Feb CSV has no `Src IP`/`Dst IP`; the raw capture does.

1. Download (AWS CLI, no account): `aws s3 cp --no-sign-request --region ca-central-1
   "s3://cse-cic-ids2018/Original Network Traffic and Log data/Wednesday-21-02-2018/pcap.zip" <folder>`
   (53.5 GB; 448 per-machine captures, 80.6 GB unpacked). Local copy: `C:\datasets\cse-cic-ids2018\raw\Wednesday-21-02-2018`.
2. `unpack_victim_capture.py` extracts only the victim web server's capture `UCAP172.31.69.28` (part 1: 203 M packets,
   07:32–09:43 machine clock; part 2: 10.8 M packets, 12:55–16:29, holds the HOIC attack).
3. Packets to TSV with tshark (Wireshark 4.6): see the command in `assemble_flows.py`'s docstring. In Git Bash use
   `MSYS_NO_PATHCONV=1` or `-E separator=/t` becomes a path.
4. `assemble_flows.py packets.tsv flows.csv --utc-offset -4` builds bidirectional flows with CICFlowMeter's rules
   (120 s timeout; first FIN from either side closes the flow; RST closes; payload bytes; sample std; single-packet
   flows dropped). Part 2: 2,166,048 flows in 111 s. Part 1: 3,869 flows from 203 M packets in 1,445 s (the
   LOIC-UDP flood is 1,730 flows of ~120,000 packets each).
5. `compare_with_published.py flows.csv [--port 80 --protocol 6|17]` checks against the published CSV (the port
   and protocol only choose the per-minute table). Result for part 2: every published HOIC
   flow is reproduced exactly (686,053 key matches for 686,012 HOIC rows) and the nine model columns agree to
   within 1% on 99.9–100% of matched flows. The published file is incomplete: it has exactly 1,048,575 rows
   (Excel's limit), half the port-80 flows per minute from 02:18 on, and nothing after 02:33, while the capture
   shows the attack continuing to 03:05 (12-hour clock, dataset makers' zone = UTC-4; the capture machine's
   clock is one hour behind).
6. Part 1 (the morning, 08:33–10:43 in the dataset's zone; done 5 Nov 2026): the published file has 3,870 rows for
   it and we build 3,869, so the morning is complete in the published file; the truncation is all in the afternoon.
   All 1,730 published LOIC-UDP flows match exactly (UDP to port 80 on 172.31.69.28 from ten AWS attacker IPs
   `18.2xx.x.x` / `52.14.136.135`, 120 source ports, 32-byte payloads, no reply packets, nearly all cut by the 120 s
   timeout) and the nine model columns agree on 100% of them. Of the 2,140 "Benign" rows in that period, 1,598 are
   the server's ICMP "port unreachable" replies to the flood: CICFlowMeter (`PacketReader.java`, the
   `hasHeader(udp)` branch) finds the UDP header quoted inside the ICMP message and records them as UDP flows to
   port 80 with the server as source, labelled Benign because the source is not an attacker IP. Our assembler keeps
   them as protocol 1; matched on second + port + duration + counts they are the same 1,598 flows. So, like the
   21 Feb HOIC "benign" flows, most of the morning's benign rows are attack by-products, not normal traffic.
7. The HOIC hour's "Benign" rows (5 Nov 2026): **358,523 of the 358,693 published Benign rows between 01:55 and
   02:33 are HOIC request/response flows recorded in the server-to-attacker direction.** Mechanism, read in the
   tool's code and checked on the packets: when a flow times out, `FlowGenerator.java` line 104 starts the
   replacement flow with the *old* flow's source and destination. Each attacker reuses its client ports every
   ~7 minutes (port 56963 of 18.216.24.42 was last used 409 s earlier and left a single server ACK behind), so from
   02:17 on half the HOIC connections inherit "server → attacker", and the labelling script, keyed on attacker
   *source* IPs, called them Benign. Proof: every one of those rows matches one of our flows with the direction
   flipped and the first packet counted forward (published fwd = our bwd + 1, bwd = our fwd − 1, bytes swapped,
   same second and duration): 358,523 matches; per minute ~24 k HOIC + ~24 k flipped = our 47.9 k. Together with
   item 6 this means the published 21 Feb file has about 2,000 genuinely benign flows, not 360,833, and the
   "half the port-80 flows from 02:18" in item 5 is this flip, not truncation (the truncation is after 02:33).
8. `label_flows.py part1_flows.csv part2_flows.csv --out data\Wednesday-21-02-2018_victim_capture_labelled.csv`
   writes the relabelled day for the app (decided with the user on 5 Nov 2026): a flow is an attack flow when
   either end is one of the ten attacker addresses, labelled with the tool of its period
   (`DDOS attack-LOIC-UDP` before noon, `DDOS attack-HOIC` after), and a `Label Reason` column says why
   (attacker IP to victim / victim reply flow / victim ICMP port-unreachable reply); everything else is `Benign`
   ("no attacker IP involved"). Timestamps are 24-hour `dd/mm/yyyy HH:MM:SS` in the dataset's zone. Result:
   2,169,917 flows = HOIC 2,164,587 (14:11–15:05; 2,164,577 attacker → victim, 10 victim replies), LOIC-UDP
   3,328 (1,730 flood + 1,598 ICMP replies), Benign 2,002 (341 source hosts; mostly IKE 500, SSH 22, SMB 445).
   Checked with the app's own reader and models: it opens in 9 s, no row is "Not scored"; `all_tools_f9p`
   flags HOIC 0.9993 and LOIC-UDP 0.52 (the flood, not the ICMP replies) with 3 false alarms on the 2,002 benign;
   `hoic_held_out_f9p` gets 0.186 on the complete attack (its recorded ~0.2 was on the published 686 k).
   The file also has `Src IP`/`Dst IP`, so the app's alert tracing shows the attacker addresses.
9. The published **20 Feb** file does not need rebuilding (checked 5 Nov 2026 by scanning every row): it already has
   `Src IP`/`Dst IP`, it is complete (7,948,748 rows, the whole network, LOIC-HTTP at a steady ~9,200 flows per minute
   from 10:13 to 11:16) and its flows follow the same V3 rules. Only its labels are wrong, in the same three ways as
   21 Feb: **797 UDP flows from the attacker IPs are labelled LOIC-HTTP** (they are the 20 Feb LOIC-UDP flood,
   13:14–13:29, 32-byte payloads, ~134,000 packets per flow, no replies; the dataset's schedule lists LOIC-UDP on 20 Feb
   at 13:13–13:32), 702 victim ICMP port-unreachable replies recorded as UDP flows are labelled Benign, and 130
   LOIC-HTTP flows recorded server-to-attacker by the timeout quirk are labelled Benign.
   `relabel_feb20.py` applies the 21 Feb rules (either end an attacker IP → attack; UDP → LOIC-UDP, else LOIC-HTTP;
   `Label Reason` column) and rewrites the 12-hour stamps as 24-hour (the file runs 08:00–19:59, so "01:00–07:59" is
   13:00–19:59), writing `data\Tuesday-20-02-2018_relabelled.csv` (4.4 GB, 275 s). Result: Benign 7,371,725,
   LOIC-HTTP 575,524, LOIC-UDP 1,499 (797 flood + 702 ICMP replies); 1,629 labels changed, nothing else. Checked
   with the app's reader and `f7ip` feature builder: 7,948,748 rows, no missing columns, 0 "Not scored". To train on
   it: `--files Tuesday-20-02-2018_relabelled.csv Wednesday-21-02-2018_victim_capture_labelled.csv` (`FILES_IP` in
   `train_model.py` still names the published file). All 42 `f7ip` models were retrained on it the same evening
   (12 runs, 44 min; app tests pass): all-tools results unchanged or slightly better, but **LOIC-UDP held out drops
   from 0.52 to 0.00** (the old 0.52 came from the 797 mislabelled 20 Feb flood flows sitting in the training set
   as LOIC-HTTP) and XGBoost LOIC-HTTP held out (per-day split) becomes threshold-sensitive (0.01 at 0.5, 0.96 at
   0.01, same on three seeds). Details and the full before/after table: `docs\retrain_on_relabelled_feb20_2026-11-05.md`.

The official GitHub CICFlowMeter (V4) was also built (a full clone for inspection and fixes at
`C:\Users\Xavie\source\repos\CICFlowMeter` with `build.ps1`, `run.ps1` and `FINDINGS.md`; a depth-1 build at
`C:\Users\Xavie\source\tools\CICFlowMeter`; JDK 27, javac with the jars in `lib\`, its own jnetpcap.dll + Npcap) and runs; it gives the same flows as `assemble_flows.py
--fin-rule v4`, which differs from the published V3 output on the FIN rule (V4 only closes on the responder's FIN,
a typo in its code), so only half the HOIC flows match it. Run it with
`java -Djava.library.path=jnetpcap/win/jnetpcap-1.4.r1425 -cp "out;lib/*;jnetpcap/win/jnetpcap-1.4.r1425/jnetpcap.jar" cic.cs.unb.ca.ifm.Cmd <pcap> <outdir>`
with `C:\Windows\System32\Npcap` on PATH.
