# 09 - Ingesting Wireshark PCAPs via Zeek

**Phase:** 3 -- Dashboards & Alerts  
**Tools:** Splunk Free · Zeek 8.2.0  
**Lab Environment:** Kali Linux · VirtualBox  
**Connection:** Bridges [Wireshark Portfolio](https://github.com/collinsnwammuo/Wireshark-projects) with Splunk SIEM

---

## 🎯 What I Did

I took PCAPs captured during my Wireshark portfolio projects, processed them through Zeek 8.2.0 to generate structured log files, ingested those logs into Splunk as a custom `zeek_conn` sourcetype, and ran SPL queries to detect port scan signatures and SSH brute force patterns from network-level evidence. This project connects the packet analysis work in my Wireshark portfolio directly to SIEM-based detection.

---

## ⚠️ Installation Notes

Zeek was not available through the standard Kali apt repository due to a libc6 dependency conflict. I resolved this by installing via the official Zeek package and creating a symlink to make it accessible system-wide:

```bash
# Zeek installed to /opt/zeek/bin/zeek
sudo ln -s /opt/zeek/bin/zeek /usr/local/bin/zeek

# Confirmed working
zeek --version
# zeek version 8.2.0
```

All PCAPs required the `-C` flag to ignore invalid TCP checksums

```bash
zeek -C -r '/home/kali/ssh capture.pcapng'
```

---

## 🧠 Background -- The PCAP to SIEM Pipeline

In a real SOC environment, raw packet captures do not go directly into a SIEM. They are processed by a network analysis framework like Zeek first, which converts raw packets into structured log files. Those logs are then ingested into the SIEM where analysts can search, correlate, and alert on them.

```
Network traffic (live or PCAP)
        |
        v
      Zeek 8.2.0
  (protocol analysis)
        |
        v
Structured log files:
  conn.log    -- all TCP/UDP/ICMP connections
  ssh.log     -- SSH session details
  dns.log     -- DNS queries and responses
  dhcp.log    -- DHCP activity
  weird.log   -- protocol anomalies
        |
        v
     Splunk
  sourcetype: zeek_conn / zeek_ssh / zeek_dns
        |
        v
SPL detection queries
```

---

## 🔬 PCAPs I Processed

| PCAP | Source Project | Zeek Logs Generated |
|---|---|---|
| `ssh capture.pcapng` | Project 07 -- SSH Brute Force | conn.log, ssh.log, dhcp.log, weird.log |
| `scan 1 syn scan.pcapng` | Project 04 -- Nmap Detection | conn.log (227KB) |
| `dns-investigation.pcapng` | Project 02 -- DNS Analysis | conn.log, dns.log |

### Processing Commands

```bash
# SSH brute force
mkdir -p ~/zeek-analysis/ssh-bruteforce
cd ~/zeek-analysis/ssh-bruteforce
zeek -C -r '/home/kali/ssh capture.pcapng'

# Nmap SYN scan
mkdir -p ~/zeek-analysis/nmap-scan
cd ~/zeek-analysis/nmap-scan
zeek -C -r '/home/kali/scan 1 syn scan.pcapng'

# DNS investigation
mkdir -p ~/zeek-analysis/dns
cd ~/zeek-analysis/dns
zeek -C -r /home/kali/dns-investigation.pcapng

### Permissions Fix for Splunk

```bash
sudo chmod -R 644 ~/zeek-analysis/
sudo chmod 755 ~/zeek-analysis/
sudo chmod 755 ~/zeek-analysis/*/
```

---

## 📊 Zeek conn.log -- Connection State Reference

The `conn_state` field is Zeek's most powerful detection field. It describes what happened during each connection:

| State | Meaning | Attack Indicator |
|---|---|---|
| `S0` | SYN sent, no response | Port scan -- closed or filtered port |
| `S1` | Connection established | Normal session start |
| `SF` | Normal open and close | Completed legitimate session |
| `REJ` | Connection rejected (RST) | Port closed |
| `RSTR` | Reset by responder | Service refused -- seen in SSH brute force |
| `RSTO` | Reset by originator | Nmap SYN scan signature |
| `OTH` | No SYN seen | Mid-stream or ICMP traffic |

---

## 🔬 Splunk Ingestion

### Sourcetype Configuration

Splunk does not have a built-in Zeek sourcetype. I created a custom sourcetype `zeek_conn` using the Save As option during data input configuration. Zeek logs are tab-separated -- Splunk reads them as raw text with the connection data visible in the event body.

| Log File | Custom Sourcetype | Index |
|---|---|---|
| ssh-bruteforce/conn.log | `zeek_conn` | `soc_lab` |
| nmap-scan/conn.log | `zeek_conn` | `soc_lab` |
| ssh-bruteforce/ssh.log | `zeek_ssh` | `soc_lab` |
| dns/dns.log | `zeek_dns` | `soc_lab` |

### Field Extraction Note

Because Zeek logs are tab-separated and Splunk does not automatically parse the zeek_conn format, I used `rex` to extract fields for analysis rather than relying on automatic field extraction:

```splunk
index=soc_lab sourcetype=zeek_conn
| rex "(?P<conn_state>S0|S1|SF|REJ|RSTR|RSTO|OTH)\s"
| stats count by conn_state
| sort -count
```

---

## 🔬 Detection Searches I Ran

### Connection State Breakdown -- Attack Signature Analysis

```splunk
index=soc_lab sourcetype=zeek_conn
| rex "(?P<conn_state>S0|S1|SF|REJ|RSTR|RSTO|OTH)\s"
| stats count by conn_state
| sort -count
```

This single search across both PCAPs revealed the distinct signatures of two different attacks:

- **RSTR** -- dominant in the SSH brute force capture. Each failed SSH authentication attempt appears as a connection reset by the responder after the auth exchange.
- **S0 and REJ** -- dominant in the Nmap SYN scan capture. Unanswered SYNs (S0) for filtered ports and RST responses (REJ) for closed ports -- the textbook port scan pattern.

---

### Suspicious Connection State Filter

```splunk
index=soc_lab sourcetype=zeek_conn
| rex "(?P<conn_state>S0|S1|SF|REJ|RSTR|RSTO|OTH)\s"
| where conn_state="S0" OR conn_state="REJ" OR conn_state="RSTR"
| stats count by source
| sort -count
```

Filtered to only suspicious connection states -- the nmap-scan conn.log dominated due to the volume of S0 and REJ connections from the port scan. The ssh-bruteforce conn.log contributed RSTR connections from each failed authentication attempt.

---

### Source File Inventory

```splunk
index=soc_lab sourcetype=zeek_conn
| stats count by source
| sort -count
```

Shows each ingested log file and its event count -- confirming both PCAPs were processed and ingested correctly.

---

### Cross-Source Correlation

```splunk
index=soc_lab (sourcetype=zeek_conn OR sourcetype=linux_secure)
| stats count by sourcetype, source
| sort -count
```

Queried both Zeek network logs and Linux auth logs simultaneously. The SSH brute force activity was visible in both sources -- as RSTR connections in zeek_conn and as "Failed password" events in linux_secure -- confirming the same attack captured at both the network and host layer.

---

## 💡 What I Learned

- **Zeek is not always straightforward to install.** The Kali repository version had a libc6 dependency conflict that prevented installation. The fix was using the official Zeek package and manually symlinking the binary. In a real environment, dependency management and alternative installation methods are practical skills that matter.

- **The `-C` flag is essential for locally captured PCAPs.** NIC checksum offloading means locally captured traffic almost always has invalid checksums. Without `-C` Zeek silently discards most packets and produces near-empty logs. This would have been a confusing silent failure without understanding what the warning message meant.

- **conn_state is the single most valuable field Zeek produces.** Before this project I would have needed to inspect individual packet flags to identify scan types. With conn_state, a simple `stats count by conn_state` across a capture immediately reveals what type of activity dominated -- S0/REJ for scans, RSTR for brute force, SF for normal sessions. One field, instant classification.

- **Custom sourcetypes are necessary for non-standard log formats.** Splunk does not know about Zeek out of the box. Creating the `zeek_conn` sourcetype and using rex for field extraction is the practical approach when working with any log format that Splunk does not natively support -- which happens regularly with custom applications and security tools in real environments.

- **The Nmap scan generated 227KB of conn.log data.** That single number communicates the scale of reconnaissance activity better than packet counts alone -- hundreds of connections to sequential ports in a few seconds, all recorded by Zeek with their connection states. Seeing that file size compared to the small conn.log from normal traffic makes the scan's footprint immediately obvious.

- **Cross-source correlation is where the value lies.** The search combining zeek_conn and linux_secure that confirmed the SSH brute force in both network and host logs simultaneously was the most satisfying result in this project. Independent evidence sources agreeing on the same activity is what makes an analyst confident in a finding during a real investigation.

---

## 🔗 SOC Relevance

| Zeek Field / Log | Detection Use Case |
|---|---|
| conn_state = S0 flood | Port scan without packet inspection |
| conn_state = RSTR high count on port 22 | SSH brute force network indicator |
| ssh.log auth_success=false | SSH authentication failure at network layer |
| dns.log query volume | DNS reconnaissance or DGA activity |
| weird.log entries | Protocol anomalies and evasion techniques |
| Cross-source: zeek + auth log | Complete attack picture from two evidence layers |

### MITRE ATT&CK Mapping

| Technique | ID | Detected Via |
|---|---|---|
| Network Service Scanning | T1046 | conn.log S0/REJ state flood |
| Brute Force: Password Guessing | T1110.001 | conn.log RSTR on port 22 |
| SSH | T1021.004 | ssh.log + conn.log port 22 |

---

## 🛠️ Tools I Used

- **Zeek 8.2.0** -- network traffic analysis framework
- **Splunk Free** -- SIEM platform
- **Wireshark PCAPs** -- source captures from Wireshark portfolio
- **Kali Linux** -- lab environment
---

*Project 09 of 14 · [Back to Main Portfolio](../README.md)*
