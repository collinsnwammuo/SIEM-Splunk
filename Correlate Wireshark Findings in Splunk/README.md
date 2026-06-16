# 10 - Correlating Wireshark Findings in Splunk

**Phase:** 3 -- Dashboards & Alerts  
**Tools:** Splunk Free · Zeek 8.2.0  
**Lab Environment:** Kali Linux · VirtualBox  
**Builds On:** Project 09 -- Zeek log ingestion

---

## 🎯 What I Did

I used the Zeek logs ingested in Project 09 alongside the Linux auth logs, syslog, and Apache logs already in Splunk to build multi-source correlation searches -- finding the same attacks visible simultaneously across network and host evidence. I reconstructed a unified attack timeline across multiple sourcetypes, hunted for IOCs from my Wireshark projects across all data sources, and built a correlation dashboard that presents the complete picture of lab attack activity in one view.

This is the project where everything from the Wireshark portfolio and the Splunk SIEM lab connects into a single investigation workflow.

---

## 🧠 Background -- Why Correlation Matters

A single data source tells part of the story. Multiple sources telling the same story independently is what makes an analyst confident in a finding.

```
SSH brute force attack:

Network evidence (Zeek conn.log):
  RSTR connections to port 22 from 127.0.0.1
  -- proves network-level connection attempts

Host evidence (linux_secure):
  "Failed password for kali from 127.0.0.1"
  -- proves authentication was attempted and failed

Combined:
  Same source IP, same port, same timeframe, two independent sources
  -- high confidence finding, ready for incident report
```

In a real SOC investigation, corroborated findings from independent sources are more reliable than any single source alone -- and they are much harder for an attacker to cover up, since they would need to tamper with both network captures and host logs simultaneously.

---

## 📊 IOCs from Wireshark Portfolio

Before running correlation searches I documented the IOCs already identified during Wireshark analysis:

| IOC | Type | Identified In |
|---|---|---|
| `192.168.56.102` | Kali attacker IP | Projects 04, 05, 07 |
| `192.168.56.101` | Windows victim IP | Projects 04, 05, 07 |
| `127.0.0.1` | SSH brute force source | Project 07 |
| Port `22` | SSH attack target | Project 07 |
| `RSTR` conn_state | Brute force network signature | Project 09 |
| `S0` conn_state | Port scan network signature | Project 09 |
| `REJ` conn_state | Closed port response | Project 09 |

These IOCs became the hunt queries across all Splunk data sources.

---

## 🔬 Correlation Searches I Ran

### Data Source Inventory

```splunk
index=soc_lab
| stats count by sourcetype
| sort -count
```

Confirmed all seven data sources available for correlation -- syslog, linux_secure, access_combined, apache_error, zeek_conn, zeek_ssh, zeek_dns. Having independent network and host sources is what makes correlation possible.

---

### Correlation 1 -- SSH Brute Force: Network vs Host

**Network layer:**
```splunk
index=soc_lab sourcetype=zeek_conn
| rex "(?P<conn_state>S0|S1|SF|REJ|RSTR|RSTO|OTH)\s"
| where conn_state="RSTR"
| stats count as network_failed_connections
```

**Host layer:**
```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as host_failed_logins by src_ip
```

**Combined:**
```splunk
index=soc_lab (sourcetype=zeek_conn OR sourcetype=linux_secure)
| rex "(?P<conn_state>S0|S1|SF|REJ|RSTR|RSTO|OTH)\s"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval attacker=coalesce(src_ip, conn_state)
| stats count by sourcetype, attacker
| sort -count
```

The SSH brute force appeared in both zeek_conn (as RSTR connections) and linux_secure (as Failed password events) -- two independent sources confirming the same activity. This is the most significant correlation finding in the project.

---

### Correlation 2 -- Port Scan Timeline from Zeek

```splunk
index=soc_lab sourcetype=zeek_conn
| rex "(?P<conn_state>S0|S1|SF|REJ|RSTR|RSTO|OTH)\s"
| where conn_state="S0" OR conn_state="REJ"
| stats count as scan_connections earliest(_time) as scan_start latest(_time) as scan_end
| eval scan_duration=scan_end-scan_start
| eval scan_start=strftime(scan_start,"%Y-%m-%d %H:%M:%S")
| eval scan_end=strftime(scan_end,"%Y-%m-%d %H:%M:%S")
```

This extracted the exact start time, end time, and duration of the Nmap scan from network evidence alone -- without inspecting a single packet or reading a single flag. The conn_state field in Zeek provides enough information to characterise the scan purely from connection metadata.

---

### Correlation 3 -- IOC Hunt Across All Sources

```splunk
index=soc_lab "127.0.0.1"
| stats count by sourcetype
| sort -count
```

The brute force source IP `127.0.0.1` appeared in multiple sourcetypes -- each independent match corroborates the same activity from a different angle.

```splunk
index=soc_lab "RSTR"
| stats count by sourcetype source
| sort -count
```

The RSTR conn_state string from Zeek only appears in zeek_conn -- confirming it is network-specific evidence rather than a string that leaks across sourcetypes.

---

### Correlation 4 -- Unified Attack Timeline

```splunk
index=soc_lab (sourcetype=zeek_conn OR sourcetype=linux_secure OR sourcetype=syslog)
| rex "(?P<conn_state>S0|S1|SF|REJ|RSTR|RSTO|OTH)\s"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval event_description=case(
    sourcetype="zeek_conn" AND conn_state="S0", "Port scan probe",
    sourcetype="zeek_conn" AND conn_state="RSTR", "SSH connection reset",
    sourcetype="linux_secure" AND match(_raw,"Failed password"), "Failed SSH login",
    sourcetype="linux_secure" AND match(_raw,"Accepted password"), "Successful SSH login",
    1==1, "Other activity"
  )
| where event_description != "Other activity"
| table _time sourcetype event_description src_ip conn_state
| sort _time
```

This is the incident timeline -- a chronological view of all attack events across every data source, labelled with human-readable descriptions. This is the format that goes directly into an incident report. Building it from SPL rather than writing it manually means it is reproducible, consistent, and auditable.

---

### Correlation 5 -- DNS Query Analysis

```splunk
index=soc_lab sourcetype=zeek_dns
| rex "(?P<query>[a-zA-Z0-9\.\-]+)\s"
| stats count by query
| sort -count
| head 20
```

Identified the DNS queries from the dns-investigation PCAP -- including the A, AAAA, MX, NS records queried during Project 02 and the NXDOMAIN for the fake domain. Comparing these against the Wireshark findings confirmed both analyses identified the same queries.

---

## 💡 What I Learned

- **Corroboration is what makes findings credible.** The SSH brute force appearing in both zeek_conn and linux_secure independently -- with matching source IPs and overlapping timestamps -- is far more convincing than either source alone. In a real investigation, findings backed by multiple independent sources are stronger evidence and hold up better to scrutiny.

- **eval case() across sourcetypes builds investigation-ready timelines.** Writing the unified attack timeline search that labelled events from different sourcetypes with human-readable descriptions was the most practically useful thing in this project. That output format is directly usable in an incident report without further processing.

- **IOC hunting across all sources is a standard analyst workflow.** Taking a known-bad IP and running it against every sourcetype to find all its appearances is something I now do instinctively. The `"127.0.0.1"` hunt across all sources showed exactly which log types captured the brute force activity -- and which ones missed it.

- **Zeek provides network evidence that host logs cannot.** The port scan timeline I extracted from Zeek conn_state data -- exact start time, end time, and connection count -- would not be visible in any host log. The Windows VM being scanned did not necessarily log every SYN probe it received. Network-layer evidence fills that gap.

- **The dns-investigation PCAP confirmed Wireshark and Zeek agree.** Running the same DNS capture through both Wireshark (in the Wireshark portfolio) and Zeek (via Splunk) and finding the same queries in both analyses validated both tools. When two independent analysis tools extract the same findings from the same data, confidence in those findings is high.

- **Building a correlation dashboard makes the investigation reproducible.** A dashboard that queries all sources simultaneously and refreshes automatically is the operational version of a manual investigation. Next time an SSH brute force alert fires I can open this dashboard and immediately see network and host evidence side by side without running multiple manual searches.

---

## 🔗 SOC Relevance

| Correlation Pattern | Investigation Value |
|---|---|
| Same IP in zeek_conn + linux_secure | Confirms attacker identity from two sources |
| RSTR count in Zeek matches Failed count in auth log | Validates network and host evidence consistency |
| Scan timeline from conn_state | Establishes attack window for log correlation |
| IOC across all sourcetypes | Determines full scope of attacker activity |
| Unified timeline with eval case() | Ready-to-use incident report timeline |

### MITRE ATT&CK Mapping

| Technique | ID | Evidence Sources |
|---|---|---|
| Network Service Scanning | T1046 | zeek_conn S0/REJ states |
| Brute Force: Password Guessing | T1110.001 | zeek_conn RSTR + linux_secure |
| Valid Accounts | T1078 | linux_secure Accepted password |

---

## 🛠️ Tools I Used

- **Splunk Free** -- SIEM platform and correlation engine
- **Zeek 8.2.0** -- network log source (from Project 09)
- **Kali Linux** -- lab environment
- **Log sources:** zeek_conn, zeek_ssh, zeek_dns, linux_secure, syslog, access_combined

---

*Project 10 of 14 · [Back to Main Portfolio](../README.md)*
