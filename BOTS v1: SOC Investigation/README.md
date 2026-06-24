# 13 - BOTS v1: Boss of the SOC Investigation

**Phase:** 4 -- Threat Detection & Hunting  
**Difficulty:** Advanced  
**Tool:** Splunk Free · BOTS v1 Dataset  
**Lab Environment:** Kali Linux · VirtualBox  
**Dataset:** [Splunk BOTS v1](https://github.com/splunk/botsv1)

---

## 🎯 What I Did

I loaded the Splunk Boss of the SOC (BOTS) v1 dataset -- a real attack dataset from splunk -- and worked through a structured SOC investigation using SPL to answer specific questions about what happened, who attacked the network, what malware was used, where it called home, and whether data was exfiltrated. I documented my methodology, findings, and what I got right and wrong compared to the official answers.

BOTS v1 is one of the most widely recognised practical SOC training exercises in the industry. Working through it in Splunk is the closest a home lab gets to a real production SOC investigation.

---

## 🧠 Background -- What is BOTS?

Boss of the SOC (BOTS) is a dataset created by Splunk containing real attack data from a simulated compromise. It contains:

- Web application attack traffic (scanning, SQLi, file upload)
- Malware infection and execution
- C2 communication
- Data exfiltration attempts

The dataset includes multiple sourcetypes -- IDS alerts, Windows Event Logs, Sysmon, firewall logs, DNS, HTTP -- simulating a real SOC environment with multiple data sources feeding into a SIEM simultaneously.

---

## 🏢 Scenario

> *Wayne Enterprises has been attacked. You are the SOC analyst on duty. The CISO wants a full incident report by end of shift. Investigate the attack using only what is in Splunk.*

---

## 🔬 Dataset Overview

```
index=botsv1
| stats count by sourcetype
| sort -count
```

| Sourcetype | Description |
|---|---|
| `stream:http` | HTTP traffic captures |
| `stream:dns` | DNS query and response data |
| `suricata` | Suricata IDS/IPS alerts |
| `iis` | Windows IIS web server logs |
| `wineventlog` | Windows Security Event Log |
| `sysmon` | Windows Sysmon endpoint telemetry |
| `pan:traffic` | Palo Alto firewall traffic logs |
| `pan:threat` | Palo Alto threat alerts |

---

## 🔬 Investigation -- Questions and Methodology

### Q1 -- What is the IP address of the web scanner?

**My approach:**
```splunk
index=botsv1 sourcetype=suricata
| stats count by src_ip
| sort -count
```

```splunk
index=botsv1 sourcetype="stream:http"
| stats count by src_ip
| sort -count
```

**Answer:** [update with your finding]

**Reasoning:** The IP that appeared most frequently across both IDS alerts and HTTP traffic, generating a volume of requests far beyond any normal user, is the scanner.

---

### Q2 -- What web scanner tool was used?

**My approach:**
```splunk
index=botsv1 sourcetype="stream:http"
| stats count by http_user_agent
| sort -count
```

**Answer:** [update with your finding]

**Reasoning:** Web scanners identify themselves in the User-Agent header. The non-browser User-Agent string appearing in the attacker's traffic revealed the specific tool used.

---

### Q3 -- What file was uploaded to the server?

**My approach:**
```splunk
index=botsv1 sourcetype="stream:http" http_method=POST
| stats count by uri, src_ip
| sort -count
```

```splunk
index=botsv1 sourcetype="stream:http"
| search "filename" OR "upload" OR ".php"
| table _time src_ip uri http_method
```

**Answer:** [update with your finding]

**Reasoning:** File uploads arrive as HTTP POST requests. Filtering for POST to unusual URIs -- particularly PHP scripts which are commonly used as web shells -- identified the uploaded file.

---

### Q4 -- What was the first URI scanned by the attacker?

**My approach:**
```splunk
index=botsv1 sourcetype="stream:http"
| sort _time
| table _time src_ip uri http_method
| head 20
```

**Answer:** [update with your finding]

---

### Q5 -- What is the MD5 hash of the malware?

**My approach:**
```splunk
index=botsv1 sourcetype=sysmon EventCode=11
| table _time TargetFilename MD5
| sort _time
```

**Answer:** [update with your finding]

**Reasoning:** Sysmon EventCode 11 records file creation events including the MD5 hash of the created file. Filtering for file creation events around the time of the upload identified the malware hash.

---

### Q6 -- What C2 IP did the malware connect to?

**My approach:**
```splunk
index=botsv1 sourcetype="stream:http"
| search NOT (dest_ip="10.*" OR dest_ip="192.168.*" OR dest_ip="172.16.*")
| stats count by dest_ip
| sort -count
```

```splunk
index=botsv1 sourcetype="stream:dns"
| stats count by query
| sort -count
```

**Answer:** [update with your finding]

**Reasoning:** C2 connections go to external IPs. Filtering out RFC 1918 private address space from outbound HTTP connections revealed the C2 server.

---

### Q7 -- What malware family was involved?

**My approach:**
```splunk
index=botsv1 sourcetype=suricata
| stats count by alert.signature
| sort -count
```

**Answer:** [update with your finding]

**Reasoning:** Suricata IDS alerts include the malware family name in the signature field when a known threat is detected.

---

### Q8 -- Was data exfiltrated? What was taken?

**My approach:**
```splunk
index=botsv1 sourcetype="pan:traffic"
| stats sum(bytes_out) as total_out by dest_ip
| sort -total_out
| head 10
```

```splunk
index=botsv1 sourcetype="stream:dns"
| where len(query) > 50
| table _time query src_ip
| sort _time
```

**Answer:** [update with your finding]

---

## 📋 Investigation Report

### Executive Summary

> Update after completing your investigation. Format:
> On [date], Wayne Enterprises suffered a targeted web application attack. The attacker ([IP]) used [scanner tool] to scan the web application, identified a file upload vulnerability, and uploaded a [malware type] web shell named [filename]. The malware established C2 communication with [C2 IP], and [data/no data] was exfiltrated.

### Findings Summary

| Question | Finding | Confidence |
|---|---|---|
| Scanner IP | [update] | High / Medium / Low |
| Scanner tool | [update] | High / Medium / Low |
| Uploaded file | [update] | High / Medium / Low |
| First URI scanned | [update] | High / Medium / Low |
| Malware MD5 | [update] | High / Medium / Low |
| C2 IP | [update] | High / Medium / Low |
| Malware family | [update] | High / Medium / Low |
| Data exfiltrated | [update] | High / Medium / Low |

### Self-Assessment

After completing my investigation I compared findings against the official BOTS v1 answers:

- **Correct findings:** [update -- list what you got right]
- **Missed findings:** [update -- list what you missed and why]
- **Key learning:** [update -- what this taught you about your analytical process]

---

## 💡 What I Learned

> Update this section after completing your investigation with genuine observations about what surprised you, what was harder than expected, and what techniques worked best.

- **[Update -- your most important finding about the investigation process]**
- **[Update -- what sourcetype was most useful and why]**
- **[Update -- what you would do differently next time]**
- **[Update -- how this compares to the earlier projects in the portfolio]**

---

## 🔗 SOC Relevance

| Skill Demonstrated | Real SOC Application |
|---|---|
| Multi-sourcetype correlation | Investigating alerts that span network, endpoint, and IDS data |
| Web attack investigation | Responding to WAF or IDS alerts about web application attacks |
| Malware hash extraction | IOC extraction for EDR hunting and threat intel sharing |
| C2 identification | Network blocking and threat intel enrichment |
| Exfiltration analysis | Data loss assessment for breach notification decisions |
| Structured incident report | Deliverable to CISO and legal during a real incident |

### MITRE ATT&CK Mapping

| Technique | ID | Evidence in Dataset |
|---|---|---|
| Active Scanning | T1595 | Web scanner traffic in stream:http |
| Exploit Public-Facing Application | T1190 | File upload vulnerability |
| Web Shell | T1505.003 | Uploaded PHP/script file |
| Remote Access Tools / C2 | T1219 / T1071 | Outbound C2 connections |
| Exfiltration Over C2 | T1041 | Large outbound transfers |

---

## 🛠️ Tools I Used

- **Splunk Free** -- SIEM investigation platform
- **BOTS v1 Dataset** -- real attack data from Splunk
- **Kali Linux** -- lab environment

---

*Project 13 of 14 · [Back to Main Portfolio](../README.md)*
