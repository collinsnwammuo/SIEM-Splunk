# 11 - Live Attack Detection: SSH Brute Force

**Phase:** 4 -- Threat Detection & Hunting  
**Tools:** Splunk Free · Wireshark · Zeek 8.2.0 · Hydra  
**Lab Environment:** Kali Linux · VirtualBox  
**Builds On:** Project 08 (Alert) · Project 09 (Zeek) · Project 10 (Correlation)

---

## 🎯 What I Did

I ran a live SSH brute force attack while simultaneously monitoring Splunk in real time -- capturing the attack with Wireshark, watching the failed login count climb in a live Splunk search, and confirming my Project 08 brute force alert fired correctly in Activity -> Triggered Alerts. I then processed the fresh capture through Zeek and brought the network evidence into Splunk to correlate against the host evidence, and measured my actual Mean Time To Detect for the attack.

This project ties together every previous Splunk project into a single live detection exercise -- the closest simulation of a real SOC shift in this entire portfolio.

---

## 🧠 Background -- Live Detection vs Post-Incident Analysis

Every previous project in this portfolio analysed data after an attack had already happened. This project is different -- I monitored Splunk while the attack was actively occurring, the same way a SOC analyst experiences a real incident.

```
POST-INCIDENT ANALYSIS (Projects 1-10):
Attack happens -> logs written -> hours/days later -> analyst investigates

LIVE DETECTION (this project):
Attack happens -> logs written -> alert fires within 1-2 minutes -> 
analyst sees it happening in real time -> immediate response
```

The skill being tested here is not just writing detection queries -- it is operating under the time pressure of an active incident, switching between tools quickly, and measuring how fast detection actually happens.

---

## 🔬 Live Detection Setup

### Monitoring Tools Running Simultaneously

```
Terminal 1   -- Hydra brute force attack
Terminal 2   -- Wireshark live packet capture (tcp.port==22)
Browser tab 1 -- Splunk Search & Reporting (manual queries)
Browser tab 2 -- Splunk Activity -> Triggered Alerts
```

### Attack Launched

```bash
sudo systemctl start ssh
hydra -l kali -P ~/wordlist.txt ssh://127.0.0.1 -t 4 -V
```

### Live Monitoring Query

While Hydra was running, I repeated this search every 10-15 seconds in Splunk:

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
```

Watching the count field increase between searches gave me a live readout of the attack's progress -- functionally the same experience as watching a SIEM dashboard auto-refresh during a real incident.

---

## 📊 What I Observed

### Failed Login Count Progression

| Time into attack | Failed attempts (src_ip 127.0.0.1) |
|---|---|
| ~10 seconds | [update with your early observation] |
| ~30 seconds | [update with your mid-attack observation] |
| Attack complete | [update with your final count] |

---

### Alert Trigger Confirmation

My SSH Brute Force Detection alert from Project 08 fired during this attack. Confirmed in **Activity -> Triggered Alerts**:

```
Alert name:    SSH Brute Force Detection
Severity:      High
Trigger time:  [update with actual timestamp]
Result count:  [update with actual count at trigger]
```

This confirmed the alert built in Project 08 functions correctly against a live, real-time attack -- not just historical data.

---

### Mean Time To Detect (MTTD)

```
Attack start time (Hydra launched):        [2026-06-16 11:22:38]
Alert trigger time (Triggered Alerts):     [2026-06-16 11:35:01]
─────────────────────────────────────────
MTTD:                                      [12 minutes and 33 seconds]
```

My alert was configured with a `*/5 * * * *` cron schedule and a 5-minute lookback window. The actual MTTD I measured was [update] -- which [update: matches/is faster than/is slower than] my expected detection window based on the schedule. This kind of measurement is exactly how SOC teams report and improve their detection capability over time.

---

## 🔬 Network and Host Correlation from the Live Attack

After the attack, I processed the fresh Wireshark capture through Zeek:

```bash
mkdir -p ~/zeek-analysis/live-detection
cd ~/zeek-analysis/live-detection
zeek -C -r ~/live-bruteforce-detection.pcap
```

Then queried both the new Zeek log and the auth log together:

```splunk
index=soc_lab (sourcetype=zeek_conn OR sourcetype=linux_secure)
| rex "(?P<conn_state>S0|S1|SF|REJ|RSTR|RSTO|OTH)\s"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval evidence_type=case(
    sourcetype="zeek_conn", "Network Connection",
    sourcetype="linux_secure", "Authentication Log",
    1==1, "Other"
  )
| stats count by evidence_type, sourcetype
| sort -count
```

This confirmed the live attack was captured and corroborated across three independent layers -- the live Wireshark packet capture, the Zeek network connection log, and the Linux authentication log. All three told the same story from different angles.

---

## 💡 What I Learned

- **Live monitoring feels completely different from post-incident analysis.** Repeatedly running the same search and watching the count increase between checks gave me a sense of urgency that analysing a static PCAP never does. This is the closest this entire portfolio gets to simulating actual SOC shift work.

- **My alert from Project 08 actually works against live data, not just historical data.** Building and testing an alert against existing logs is useful, but confirming it fires correctly during a genuinely live, in-progress attack is a different and more meaningful validation. I now trust that alert configuration.

- **Measuring MTTD made the value of automated detection concrete.** Watching the gap between when I started Hydra and when the alert appeared in Triggered Alerts gave me an actual number to reason about. If my alert had a 15-minute lookback and ran only once an hour, that gap would have been much larger -- this exercise made the tradeoff between alert frequency and system load tangible rather than theoretical.

- **Running Wireshark and Splunk simultaneously is operationally demanding.** Switching between a packet capture window, a Splunk search tab, and a terminal running Hydra while trying to take clean screenshots at the right moments gave me a small taste of how busy an actual incident response can get, even in a lab with no real urgency or stakes.

- **Three independent evidence sources for one attack builds real confidence.** The live Wireshark capture, the Zeek conn.log generated from it, and the Linux auth log all independently confirmed the same brute force attack happened. In a real investigation, that level of corroboration is what allows an analyst to write a confident, defensible incident report.

---

## 🔗 SOC Relevance

| Activity | Real-World SOC Equivalent |
|---|---|
| Live count monitoring | Manually checking a SIEM during active incident response |
| Alert firing in Triggered Alerts | Automated detection notifying the SOC team |
| MTTD measurement | KPI reported to SOC management for detection effectiveness |
| Cross-source correlation post-attack | Building the evidentiary basis for an incident report |
| Wireshark + Splunk simultaneous monitoring | Tier 1 analyst triaging an active alert |

### MITRE ATT&CK Mapping

| Technique | ID | Live Evidence |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Hydra attack, real-time auth log failures |
| Valid Accounts | T1078 | Successful login if Hydra found the password |

---

## 🛠️ Tools I Used

- **Splunk Free** -- live monitoring and alerting
- **Wireshark** -- live packet capture
- **Zeek 8.2.0** -- post-attack network log generation
- **Hydra** -- brute force attack tool
- **Kali Linux** -- lab environment

---

*Project 11 of 14 · [Back to Main Portfolio](../README.md)*
