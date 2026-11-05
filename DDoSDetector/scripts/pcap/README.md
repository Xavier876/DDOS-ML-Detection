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

The official GitHub CICFlowMeter (V4) was also built (a full clone for inspection and fixes at
`C:\Users\Xavie\source\repos\CICFlowMeter` with `build.ps1`, `run.ps1` and `FINDINGS.md`; a depth-1 build at
`C:\Users\Xavie\source\tools\CICFlowMeter`; JDK 27, javac with the jars in `lib\`, its own jnetpcap.dll + Npcap) and runs; it gives the same flows as `assemble_flows.py
--fin-rule v4`, which differs from the published V3 output on the FIN rule (V4 only closes on the responder's FIN,
a typo in its code), so only half the HOIC flows match it. Run it with
`java -Djava.library.path=jnetpcap/win/jnetpcap-1.4.r1425 -cp "out;lib/*;jnetpcap/win/jnetpcap-1.4.r1425/jnetpcap.jar" cic.cs.unb.ca.ifm.Cmd <pcap> <outdir>`
with `C:\Windows\System32\Npcap` on PATH.
