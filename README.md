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

---

### Phase 1 -- SPL Fundamentals

| # | Project | Key Skills | Status |
|---|---------|------------|--------|
| 01 | [Ingesting Syslog and Apache Logs](./Project%2002) | Multi-source ingestion, sourcetypes, index management | ⏳ Planned |
| 02 | [Search and Filter Commands](./Project%2003) | search, table, fields, where, dedup | ⏳ Planned |
| 03 | [Stats and Aggregation](./Project%2004) | stats, count, by, sort, head, rare, top | ⏳ Planned |
| 04 | [Timechart -- Visualising Events Over Time](./Project%2005) | timechart, span, time bucketing, line charts | ⏳ Planned |
| 05 | [Field Extraction with Rex](./Project%2006) | rex, field extraction, regex in SPL | ⏳ Planned |
| 06 | [Eval and Calculated Fields](./Project%2007) | eval, if, case, calculated fields, conditionals | ⏳ Planned |

---

### Phase 2 -- Dashboards & Alerts

| # | Project | Key Skills | Status |
|---|---------|------------|--------|
| 07 | [Failed SSH Login Dashboard](./Project%2008) | Dashboard builder, panel types, visualisations | ⏳ Planned |
| 08 | [Brute Force Detection Alert](./Project%2009) | Saved alerts, trigger conditions, threshold alerting | ⏳ Planned |
| 09 | [Ingest Wireshark PCAPs via Zeek](./Project%2010) | Zeek log ingestion, conn.log, PCAP to SIEM pipeline | ⏳ Planned |
| 10 | [Correlate Wireshark Findings in Splunk](./Project%2011) | IOC correlation, multi-source analysis, evidence linking | ⏳ Planned |

---

### Phase 3 -- Threat Detection & Hunting

| # | Project | Key Skills | Status |
|---|---------|------------|--------|
| 11 | [Live Attack Detection -- SSH Brute Force](./Project%2012) | Live capture + SIEM correlation, parallel analysis | ⏳ Planned |
| 12 | [Live Attack Detection -- Nmap Scan](./Project%2013) | Reconnaissance detection, port scan signatures in logs | ⏳ Planned |
| 13 | [BOTS v1 -- Boss of the SOC Challenge](./Project%2014) | Real-world investigation, CTF methodology, IR report | ⏳ Planned |
| 14 | [SOC Detection Use Case Library](./Project%2015) | Detection engineering, use case documentation, MITRE mapping | ⏳ Planned |

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
| SSH Brute Force Detection (PCAP) | Project 08 -- Brute Force Alert + Project 12 -- Live Detection |
| Nmap Scan Detection (PCAP) | Project 12 -- Scan Detection in Splunk |
| Malware PCAP Investigation | Project 09 -- Zeek log ingestion from PCAPs |
| ARP Spoofing / MITM Detection | Project 12 -- IOC correlation in Splunk |

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
