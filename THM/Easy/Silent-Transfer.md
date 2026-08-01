# The Silent Transfer (Capstone) — Investigation Write-up

**Room:** `silenttransfer-capstone-v2.0`
**Scenario:** THM Security Services (TSS) — Threat Hunt engagement for Helios Software Group
**Classification:** Confirmed Cobalt Strike intrusion — C2, internal discovery, lateral movement, data exfiltration


---

## Executive Summary

A developer workstation was compromised via a fake software-update dropper served from typosquatted infrastructure hosted on a known bulletproof-hosting ASN. The dropper established a Cobalt Strike beacon — confirmed via an exact JA4 fingerprint match to the toolkit's default HTTPS profile — which the operator used to run periodic reconnaissance, enumerate SMB shares across roughly two dozen internal hosts, pivot via RDP to an internal file/backup server, and exfiltrate a ~298 MB archive to a second endpoint on the same hosting provider.

The triggering detection alert fired **over two hours after initial compromise and after exfiltration had already completed** — it caught routine interactive tasking, not the intrusion itself. That's the central finding of the hunt: the alert was reactive, not preventive, and the true dwell time and impact only became visible by working backward and forward from it through the full evidence set.

**Mission parameters — resolved:**

| # | Parameter | Finding |
|---|---|---|
| 01 | Real C2 activity? | **Confirmed.** JA4 exact match to a known offensive toolkit's default profile; beacon interval regular (~60s ± jitter) across 2h+ |
| 02 | Workstation & external infra | One Developer-subnet host; two external IPs on the same hosting ASN (C2 + delivery) |
| 03 | Timeline | Dropper delivered pre-dawn → beacon established → SMB discovery → RDP pivot → exfil → alert fires *after* exfil completed |
| 04 | Beyond initial host? | **Yes.** RDP lateral movement to one internal server; SMB discovery touched ~23 hosts (scan scope, not confirmed compromise on all) |
| 05 | Data exfiltrated? | **Yes — confirmed.** ~298 MB archive, filename suggests it exceeds the Developer subnet's expected data ownership |

---

## Environment & Tooling

- **Evidence root:** `/home/ubuntu/capstone/`
- **Sensor scope:** Zeek logs cover the Developer subnet perimeter only; a separate firewall log covers all subnets — used to fill the gap for the lateral-movement pivot into the internal server segment
- **Tools used:** `zeek-cut`, `tshark`, `grep`/`awk`, manual hex/base64 decoding
- **Key reference:** a provided ASN threat-intel brief pre-documented the exact `/24` ranges later observed live in the evidence for delivery, C2, *and* exfil — strong independent infrastructure attribution without needing external lookups (outbound network was disabled on the VM by design)

---

## Investigation Chain — Question by Question

### Q1 — Source IP of the alerted C2 activity

```bash
grep -i "03:4[5-9]" snort_alerts.log
```
```
[**] ET TROJAN Possible Cobalt Strike Beacon CnC Activity - GET Checkin [**]
{TCP} <internal_ip>:51088 -> <c2_ip>:443
```
Cross-referenced against `conn.log` for the same src/dst pair to confirm this wasn't a one-off — 25+ connections at a consistent short interval to the same external host, textbook beaconing.

<details><summary>Reveal answer</summary>

`10.14.30.88`

</details>

### Q2 — Dropper delivery domain

```bash
cat zeek_logs/dns.log | zeek-cut ts id.orig_h query answers | grep <internal_ip> | sort
cat zeek_logs/http.log | zeek-cut ts id.orig_h host uri method | grep <internal_ip> | sort
```
A domain resolves ~38 minutes before the first C2 connection; two minutes later the workstation issues a `GET` for an `.exe` against that same resolved IP. Typosquat pattern — a plausible-looking subdomain of a well-known brand, on a domain that brand doesn't actually own.

<details><summary>Reveal answer</summary>

`cdn-updates.microsoftservice.net`

</details>

### Q3 — SHA256 of the dropper

```bash
cat zeek_logs/files.log | zeek-cut ts tx_hosts rx_hosts source filename sha256 mime_type | grep -i winservice
```
Zeek's file-extraction engine computes the hash automatically for any file it observes crossing the wire — no manual hashing needed once you've isolated the right `tx_hosts`/`filename` row.

<details><summary>Reveal answer</summary>

`7f3b2e1a9c8d4f5e6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90`

</details>

### Q4 — First C2 source port

```bash
cat zeek_logs/conn.log | zeek-cut ts id.orig_h id.orig_p id.resp_h id.resp_p duration orig_bytes resp_bytes | grep <internal_ip> | grep <c2_ip> | sort | head -5
```
Sort by timestamp, take the earliest row, read `id.orig_p`.

<details><summary>Reveal answer</summary>

`51000`

</details>

### Q5 — JA4 fingerprint of the C2 client

```bash
cat zeek_logs/ssl.log | zeek-cut ts id.orig_h id.resp_h ja4 ja4s server_name | grep <c2_ip>
```
The room provides a local JA4 reference document for a well-known offensive toolkit's default HTTPS beacon. Compare byte-for-byte — an exact match means stock profile, no Malleable C2 customization.

<details><summary>Reveal answer</summary>

`t13d190900_9dc949149365_97f8aa674fd9`

</details>

### Q6 — Unique internal hosts touched by SMB discovery

```bash
cat zeek_logs/conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p | awk -v t=<first_c2_ts> '$1>t && $2=="<internal_ip>" && $4==445 {print $3}' | sort -u
```
Print the full list before counting — worth eyeballing that every hit is genuinely internal and not sensor noise. Distinct destinations spanned both the Developer subnet and the internal server subnet, meaning discovery wasn't confined to the local segment.

<details><summary>Reveal answer</summary>

`23`

</details>

### Q7 — RDP lateral movement destination

```bash
cat zeek_logs/conn.log | zeek-cut id.orig_h id.resp_h id.resp_p | awk '$3==3389'
```
Came back empty — the Developer-subnet Zeek sensor doesn't see traffic once it crosses into the internal server segment. Fell back to the all-subnets firewall log:
```bash
grep -i "3389" fortigate_traffic.log | grep -i "10.14"
```
A multi-minute session with several hundred KB sent and multiple MB received — consistent with interactive GUI use, not a scripted push.

<details><summary>Reveal answer</summary>

`10.14.0.12`

</details>

### Q8 — Domain resolved by the RDP destination before the transfer

```bash
cat zeek_logs/dns.log | zeek-cut ts id.orig_h query answers | grep <rdp_dest_ip> | sort
cat zeek_logs/conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes | grep <rdp_dest_ip> | sort -k5 -n -r | head -5
```
Find the single largest outbound flow from the pivot host, then take the DNS query that resolved to the same destination IP immediately beforehand.

<details><summary>Reveal answer</summary>

`backup.corpfiles-sync.com`

</details>

### Q9 — SHA256 of the exfiltrated archive

```bash
cat zeek_logs/files.log | zeek-cut ts tx_hosts rx_hosts filename sha256 mime_type total_bytes | grep <rdp_dest_ip>
```
`total_bytes` here should match the `orig_bytes` figure from the largest flow in Q8 — same transfer, confirmed at the file layer, not just the connection layer.

<details><summary>Reveal answer</summary>

`a3f8e2c1d4b7a9e0f2c3d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6`

</details>

### Q10 — Application-layer command issued over C2

`ssl.log` confirms this channel is TLS, so `zeek-cut` on connection metadata won't surface tasking content. `strings` on the raw pcap comes up empty — nothing in plain sight. The real payload is hiding in HTTP response bodies:

```bash
tshark -r investigation.pcap -Y "ip.addr==<c2_ip> && http" \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.file_data
```
Every check-in response is a **hex-encoded** HTTP body. Decoding a routine one:
```
7b22737461747573223a226f6b222c22636d64223a22222c22696e74657276616c223a36307d
→ {"status":"ok","cmd":"","interval":60}
```
Empty task, as expected for most beacons. But some responses carry a non-empty `cmd` field, itself **base64-encoded** inside the JSON:
```
"cmd":"<base64 string>"  →  base64 decode  →  <the tasked command>
```
This tasked response recurs roughly every 10 minutes across the whole session, always the same command — and the specific instance timestamped right at the alert-fire time is what tripped the Snort signature. The alert fired on routine recon tasking, not on initial compromise or on the exfiltration that had already finished 5 minutes earlier.

<details><summary>Reveal answer</summary>

`whoami`

</details>

---

## Full Attack Timeline

*(Real elapsed intervals shown; specific indicator strings withheld — see the per-question spoilers above and the collapsed IOC table below.)*

| Relative Time | Event |
|---|---|
| T+0 | Dropper delivery domain resolves |
| T+2 min | Dropper `.exe` downloaded to the workstation |
| T+38 min (≈) | C2 domain resolves |
| T+38 min | First beacon check-in — **compromise begins** |
| T+38 min → T+4h36m | Beacon check-ins continue at ~60s interval; tasked command re-issued every ~10 min |
| Early in beacon lifetime | SMB discovery sweep — ~23 internal hosts probed on TCP/445 |
| ~1 hour post-beacon | RDP session, workstation → internal server (interactive, ~7 min) |
| ~2h20m post-beacon | Exfil staging domain resolves |
| ~2h20m post-beacon (1 min later) | Exfil begins: ~298 MB archive transferred |
| ~2h25m post-beacon | **Detection alert fires** — reactive, post-exfiltration |

**Total confirmed dwell time before detection: ~3 hours.**

---

## Indicators of Compromise

<details><summary>Reveal full IOC table (contains all flags)</summary>

| Type | Value | Role |
|---|---|---|
| Domain | `cdn-updates.microsoftservice.net` | Dropper delivery (typosquat) |
| Domain | `update.softpatch-cdn.com` | C2 check-in |
| Domain | `backup.corpfiles-sync.com` | Exfil staging |
| IP | `194.165.16.78` | Dropper host |
| IP | `194.165.16.56` | C2 server |
| IP | `185.213.154.201` | Exfil endpoint |
| JA4 | `t13d190900_9dc949149365_97f8aa674fd9` | Default HTTPS beacon fingerprint |
| SHA256 | `7f3b2e1a9c8d4f5e6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90` | Dropper executable |
| SHA256 | `a3f8e2c1d4b7a9e0f2c3d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6` | Exfiltrated archive |
| Host | `10.14.30.88` | Patient zero |
| Host | `10.14.0.12` | Lateral movement target / exfil source |

</details>

All three externally-touched IPs fell inside `/24` ranges pre-documented by the room's reference threat-intel brief as belonging to a single bulletproof-hosting ASN — independent confirmation this matches a known actor infrastructure pattern rather than being a one-off.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Resource Development | T1583.006 / T1584.004 — Acquire/Compromise Infrastructure | Single bulletproof-hosting ASN used across dropper, C2, and exfil roles |
| Initial Access | T1204.002 — User Execution: Malicious File | Fake software-update `.exe` from a typosquatted domain |
| Execution | T1059 (likely .003, Windows Command Shell) | Recon command tasked via beacon |
| Command and Control | T1071.001 — Application Layer Protocol: Web | HTTP `GET` check-in on a fixed ~60s interval |
| Command and Control | T1132.001 — Data Encoding: Standard Encoding | Base64-encoded tasking inside a hex-encoded JSON body |
| Command and Control | T1573 — Encrypted Channel | JA4-confirmed TLS 1.3, stock beacon profile |
| Discovery | T1046 — Network Service Discovery | SMB (445) sweep across ~23 internal hosts |
| Lateral Movement | T1021.001 — Remote Services: RDP | Interactive session to internal server |
| Collection | T1560 — Archive Collected Data | Archive staged before transfer |
| Exfiltration | T1048 — Exfiltration Over Alternative Protocol *(assessed)* | Transfer used infrastructure distinct from the primary C2 channel — flagged as best-fit rather than certain |

---

## Detection Opportunities

Queries are written with placeholders in place of this specific engagement's IOCs — swap in your own environment's confirmed indicators (or feed them from a TI platform) rather than hardcoding a single sample's values.

**1. Known-beacon JA4 match (Elastic / KQL):**
```
tls.client.ja4 : "<JA4_from_reference_intel>"
```

**2. Beaconing via interval regularity (Splunk / SPL):**
```spl
index=zeek sourcetype=conn dest_port=443
| streamstats current=f last(_time) as prev_time by src_ip dest_ip
| eval delta=_time-prev_time
| stats avg(delta) as avg_interval stdev(delta) as stdev_interval count by src_ip dest_ip
| eval jitter_pct=round((stdev_interval/avg_interval)*100,2)
| where count > 20 AND jitter_pct < 20
```
Flags any src/dst pair with 20+ connections and low interval variance — catches beaconing regardless of domain/IP reputation.

**3. SMB discovery burst (Elastic / KQL filter + threshold rule):**
```
event.dataset : "zeek.conn" and destination.port : 445
```
Rule threshold: >10 distinct `destination.ip` from a single `source.ip` on TCP/445 within a 10-minute window.

**4. Lookalike-domain delivery (KQL):**
```
dns.question.name : (*<brand-lookalike-pattern>)
```
Generalize with a newly-observed-domain feed + edit-distance scoring against corporate/vendor brand terms, rather than hardcoding known-bad domains after the fact.

**5. Large outbound transfer to non-baselined destination (SPL):**
```spl
index=zeek sourcetype=conn dest_port=443
| where orig_bytes > 100000000
| lookup asn_lookup dest_ip OUTPUT asn_name asn_number
| where NOT asn_number IN (<approved CDN/cloud ASN list>)
```

---

## Analyst Notes

- **Alert-to-impact gap:** the signature that started this hunt fired on interactive tasking, not on initial access or on the exfiltration itself — both had already happened by the time the alert landed. Any response playbook built around "alert = start of incident" would have missed hours of prior dwell time and the entire exfil.
- **Filename signal:** the exfiltrated archive's name suggested it belonged to a different business function than the compromised subnet's normal scope — worth flagging against any parallel investigation covering that other subnet.
- **Infrastructure reuse:** three separate roles (delivery, C2, exfil) all sat on the same actor-controlled ASN but different `/24`s — consistent with deliberate infrastructure segmentation by function, not incidental reuse.
