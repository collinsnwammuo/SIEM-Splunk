# SIEM & Log Analysis with Splunk

**Platform:** Splunk Free (Enterprise)  
**Lab Environment:** Kali Linux · VirtualBox  
**Focus:** SOC operations · Log analysis · Threat detection · Incident investigation

---

## 👨‍💻 About This Repository

This repository documents my hands-on Splunk SIEM lab work, built as part of my SOC analyst training. Each project covers a specific skill area -- from initial setup and log ingestion through SPL query development, dashboard building, alert creation, and live threat detection.

Every project includes the SPL queries I used, annotated screenshots of my findings, and a written analysis explaining what I detected and how. This is a companion to my [Wireshark Network Analysis Portfolio](https://github.com/collinsnwammuo/Wireshark-projects) -- where Wireshark shows me what happened at the packet level, Splunk shows me what happened at the log level. Together they represent the two primary data sources a SOC analyst works with during an investigation.

---

## 🗂️ Project Index

### Phase 1 -- Getting Data In

| # | Project | Key Skills | Status |
|---|---------|------------|--------|
| 01 | [Ingesting Syslog and Apache Logs](https://github.com/collinsnwammuo/SIEM-Splunk/tree/main/Ingesting%20Syslog%20and%20Apache%20Logs) | Multi-source ingestion, sourcetypes, index management | ✅ Complete |

---

### Phase 2 -- SPL Fundamentals

| # | Project | Key Skills | Status |
|---|---------|------------|--------|
| 02 | [Search and Filter Commands](https://github.com/collinsnwammuo/SIEM-Splunk/tree/main/Search%20and%20Filter%20Commands) | search, table, fields, where, dedup | ✅ Complete |
| 03 | [Stats and Aggregation](https://github.com/collinsnwammuo/SIEM-Splunk/tree/main/Stats%20and%20Aggregation) | stats, count, by, sort, head, rare, top | ✅ Complete |
| 04 | [Timechart -- Visualising Events Over Time](https://github.com/collinsnwammuo/SIEM-Splunk/tree/main/Timechart%20--%20Visualising%20Events%20Over%20Time) | timechart, span, time bucketing, line charts | ✅ Complete |
| 05 | [Field Extraction with Rex](https://github.com/collinsnwammuo/SIEM-Splunk/tree/main/Field%20Extraction%20with%20Rex) | rex, field extraction, regex in SPL | ✅ Complete |
| 06 | [Eval and Calculated Fields](https://github.com/collinsnwammuo/SIEM-Splunk/tree/main/Eval%20and%20Calculated%20Fields) | eval, if, case, calculated fields, conditionals | ✅ Complete |

---

### Phase 3 -- Dashboards & Alerts

| # | Project | Key Skills | Status |
|---|---------|------------|--------|
| 07 | [Failed SSH Login Dashboard](https://github.com/collinsnwammuo/SIEM-Splunk/tree/main/SSH%20Login%20Dashboard) | Dashboard builder, panel types, visualisations | ✅ Complete |
| 08 | [Brute Force Detection Alert](https://github.com/collinsnwammuo/SIEM-Splunk/tree/main/Brute%20Force%20Detection%20Alert) | Saved alerts, trigger conditions, threshold alerting | ✅ Complete|
| 09 | [Ingest Wireshark PCAPs via Zeek](https://github.com/collinsnwammuo/SIEM-Splunk/tree/main/Ingest%20Wireshark%20PCAPs%20via%20Zeek) | Zeek log ingestion, conn.log, PCAP to SIEM pipeline | ✅ Complete |
| 10 | [Correlate Wireshark Findings in Splunk](https://github.com/collinsnwammuo/SIEM-Splunk/tree/main/Correlate%20Wireshark%20Findings%20in%20Splunk) | IOC correlation, multi-source analysis, evidence linking | ✅ Complete |

---

### Phase 4 -- Threat Detection & Hunting

| # | Project | Key Skills | Status |
|---|---------|------------|--------|
| 11 | [Live Attack Detection -- SSH Brute Force](./Project%2011) | Live capture + SIEM correlation, parallel analysis | ⏳ Planned |
| 12 | [Live Attack Detection -- Nmap Scan](./Project%2012) | Reconnaissance detection, port scan signatures in logs | ⏳ Planned |
| 13 | [BOTS v1 -- Boss of the SOC Challenge](./Project%2013) | Real-world investigation, CTF methodology, IR report | ⏳ Planned |
| 14 | [SOC Detection Use Case Library](./Project%2014) | Detection engineering, use case documentation, MITRE mapping | ⏳ Planned |

---

## 🧰 SPL Quick Reference

A running reference of the SPL commands I use across projects. Updated as I progress.

### Search and Filter
```splunk
index=soc_lab                                    # Search specific index
index=soc_lab sourcetype=linux_secure            # Filter by sourcetype
index=soc_lab "Failed password"                  # Keyword search
index=soc_lab earliest=-24h latest=now           # Time range filter
index=soc_lab | search src_ip="192.168.56.*"     # Filter on field value
```

### Aggregation and Stats
```splunk
index=soc_lab | stats count by src_ip            # Count events by field
index=soc_lab | stats count by src_ip, user      # Multi-field grouping
index=soc_lab | sort -count                      # Sort descending
index=soc_lab | head 10                          # Top 10 results
index=soc_lab | top limit=10 src_ip              # Top values by frequency
```

### Time-based Analysis
```splunk
index=soc_lab | timechart count                  # Events over time
index=soc_lab | timechart count by src_ip        # Events per IP over time
index=soc_lab | timechart span=1m count          # 1-minute buckets
```

### Field Extraction
```splunk
index=soc_lab
  | rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"   # Extract IP with regex
  | table _time src_ip user                       # Display specific fields
```

### Detection Queries
```splunk
index=soc_lab "Failed password"
  | stats count by src_ip
  | where count > 10                              # Brute force threshold

index=soc_lab sourcetype=linux_secure
  | timechart span=1m count by src_ip
  | where count > 20                              # Rate-based detection
```

---

## 🔗 Connection to Wireshark Portfolio

This repository is the SIEM layer of my SOC analyst home lab. It builds directly on the network-level evidence documented in my Wireshark projects:

| Wireshark Project | Splunk Equivalent |
|---|---|
| SSH Brute Force Detection (PCAP) | Project 09 -- Brute Force Alert + Project 12 -- Live Detection |
| Nmap Scan Detection (PCAP) | Project 13 -- Scan Detection in Splunk |
| Malware PCAP Investigation | Project 10 -- Zeek log ingestion from PCAPs |
| ARP Spoofing / MITM Detection | Project 11 -- IOC correlation in Splunk |

The goal is to be able to investigate the same attack from both angles -- what it looks like in a raw packet capture and what it looks like in structured SIEM logs. That dual-layer analysis is what real SOC investigations require.

---

## 🎓 Lab Environment

```
Kali Linux VM (VirtualBox)
  Splunk Free -- http://localhost:8000
  Index: soc_lab
  Log sources:
    /var/log/auth.log       (authentication events)
    /var/log/syslog         (system events)
    /var/log/apache2/       (web server logs)
    Zeek logs               (network traffic from PCAPs)
```

---

## 🛠️ Tools Used Across This Repository

- **Splunk Free** -- SIEM platform (500MB/day ingestion limit)
- **Zeek** -- network traffic analyser for converting PCAPs to structured logs
- **Kali Linux** -- lab environment
- **Wireshark** -- companion tool for packet-level analysis

---


*Companion repo: [Wireshark Network Analysis Portfolio](https://github.com/collinsnwammuo/Wireshark-projects)*  
*Main profile: [github.com/collinsnwammuo](https://github.com/collinsnwammuo)*
