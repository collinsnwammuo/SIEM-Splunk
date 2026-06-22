# 12 - Live Attack Detection: Nmap Scan + HTTP Policy Violations

**Phase:** 4 -- Threat Detection & Hunting  
**Tools:** Splunk Free · Nmap · Apache2 · curl  
**Lab Environment:** Kali Linux · VirtualBox  

---

## 🎯 What I Did

This project has two parts. In Part A I ran a live Nmap version scan against my own machine while watching Splunk detect the unusual HTTP probe requests in real time through the Apache access log. In Part B I simulated an employee visiting websites blocked by corporate policy -- social media, gambling, streaming, hacking tools, torrent sites, and cryptocurrency exchanges -- and built a Web Policy Enforcement dashboard in Splunk that categorises violations, identifies repeat offenders, and fires an alert when a client exceeds a violation threshold.

The key insight this project demonstrates is that HTTP logs are a live data source -- policy violations appear in Splunk the moment the request hits the web server, making HTTP monitoring genuinely real-time.

---

## ⚠️ Disclaimer

All activity was performed within my isolated Kali Linux lab environment. The policy violation traffic was simulated using curl with Host headers pointing to real domain names -- no actual connections to external websites were made through the Apache server. The Nmap scan targeted localhost only.

---

## 🧠 Background

### Part A -- Why Nmap Shows Up in HTTP Logs

When Nmap runs a version scan (`-sV`) against a target, it does not just probe TCP ports -- it sends actual application-layer probes to identify services. Against port 80 (HTTP) it sends crafted HTTP requests to read server banners and identify the web server software. These requests appear in the Apache access log with:
- Nmap's User-Agent string
- Unusual HTTP methods (HEAD, OPTIONS)
- Probe URIs it does not expect to find
- Rapid successive requests from the same IP

This makes an Nmap version scan detectable through web server logs even without packet capture.

### Part B -- HTTP as a Live Detection Source

Unlike syslog or auth logs which may buffer writes, Apache writes to access.log synchronously with each request. This means:

```
Employee visits facebook.com
        |
        v (milliseconds)
Apache access.log updated
        |
        v (seconds)
Splunk ingests new log line
        |
        v (next alert run)
Policy violation alert fires
```

HTTP monitoring is one of the fastest real-time detection channels available in a web-facing environment.

### Blocked Site Policy Categories

| Category | Sites Monitored | Policy Reason |
|---|---|---|
| Social Media | facebook.com, twitter.com, instagram.com, tiktok.com | Productivity |
| Gambling | bet365.com, draftkings.com | AUP violation |
| Streaming | netflix.com, youtube.com, twitch.tv | Bandwidth |
| Hacking Tools | exploit-db.com, hackforums.net | Security risk |
| Torrent | thepiratebay.org | Legal/copyright |
| Cryptocurrency | binance.com, coinbase.com | Financial policy |

---

## 🔬 Part A -- Live Nmap Detection

### Setup

```bash
# Confirm Apache is running and logging
sudo systemctl start apache2
sudo tail -f /var/log/apache2/access.log
```

### Attack Launched

```bash
sudo nmap -sV -A 127.0.0.1
```

### Detection Searches

**Nmap probe requests in Apache log:**
```splunk
index=soc_lab sourcetype=access_combined
| rex "\"(?P<http_method>GET|POST|PUT|DELETE|HEAD|OPTIONS) (?P<uri_path>[^\s]+)[^\"]*\" (?P<status_code>\d{3})"
| stats count by clientip, http_method, status_code
| sort -count
```

**Nmap User-Agent detection:**
```splunk
index=soc_lab sourcetype=access_combined
| rex "\"(?P<useragent>[^\"]+)\"$"
| where like(useragent, "%Nmap%") OR like(useragent, "%nmap%")
| table _time clientip useragent
```

Nmap's version scan sent HTTP probes with its own User-Agent string and used HEAD and OPTIONS methods that normal browsers never send. These appeared immediately in the Apache access log and were detectable in Splunk within seconds of the scan starting.

---

## 🔬 Part B -- HTTP Policy Violation Detection

### Policy Violation Traffic Generated

```bash
# Social media
curl -s -H "Host: facebook.com" http://localhost/ > /dev/null
curl -s -H "Host: twitter.com" http://localhost/ > /dev/null
curl -s -H "Host: instagram.com" http://localhost/ > /dev/null
curl -s -H "Host: tiktok.com" http://localhost/ > /dev/null

# Gambling
curl -s -H "Host: bet365.com" http://localhost/ > /dev/null
curl -s -H "Host: draftkings.com" http://localhost/ > /dev/null

# Streaming
curl -s -H "Host: netflix.com" http://localhost/ > /dev/null
curl -s -H "Host: youtube.com" http://localhost/ > /dev/null
curl -s -H "Host: twitch.tv" http://localhost/ > /dev/null

# Hacking tools
curl -s -H "Host: exploit-db.com" http://localhost/ > /dev/null
curl -s -H "Host: hackforums.net" http://localhost/ > /dev/null

# Torrent
curl -s -H "Host: thepiratebay.org" http://localhost/ > /dev/null

# Cryptocurrency
curl -s -H "Host: binance.com" http://localhost/ > /dev/null
curl -s -H "Host: coinbase.com" http://localhost/ > /dev/null

# Repeat offender simulation
for i in {1..10}; do curl -s -H "Host: facebook.com" http://localhost/ > /dev/null; done
for i in {1..5}; do curl -s -H "Host: thepiratebay.org" http://localhost/ > /dev/null; done
```

### Core Detection Search

```splunk
index=soc_lab sourcetype=access_combined
| rex field=_raw "(?P<host_header>facebook\.com|twitter\.com|instagram\.com|tiktok\.com|bet365\.com|draftkings\.com|netflix\.com|youtube\.com|twitch\.tv|exploit-db\.com|hackforums\.net|thepiratebay\.org|binance\.com|coinbase\.com)"
| where isnotnull(host_header)
| eval category=case(
    host_header="facebook.com" OR host_header="twitter.com" OR host_header="instagram.com" OR host_header="tiktok.com", "Social Media",
    host_header="bet365.com" OR host_header="draftkings.com", "Gambling",
    host_header="netflix.com" OR host_header="youtube.com" OR host_header="twitch.tv", "Streaming",
    host_header="exploit-db.com" OR host_header="hackforums.net", "Hacking Tools",
    host_header="thepiratebay.org", "Torrent",
    host_header="binance.com" OR host_header="coinbase.com", "Cryptocurrency",
    1==1, "Other"
  )
| stats count as visits by host_header, category, clientip
| sort -visits
```

### Repeat Offender Detection

```splunk
index=soc_lab sourcetype=access_combined
| rex field=_raw "(?P<host_header>facebook\.com|twitter\.com|instagram\.com|tiktok\.com|bet365\.com|draftkings\.com|netflix\.com|youtube\.com|twitch\.tv|exploit-db\.com|hackforums\.net|thepiratebay\.org|binance\.com|coinbase\.com)"
| where isnotnull(host_header)
| stats count as total_violations dc(host_header) as unique_sites by clientip
| where total_violations > 5
| eval risk_level=case(
    total_violations >= 20, "CRITICAL",
    total_violations >= 10, "HIGH",
    total_violations >= 5, "MEDIUM",
    1==1, "LOW"
  )
| table clientip total_violations unique_sites risk_level
| sort -total_violations
```

### Policy Violation Alert

```splunk
index=soc_lab sourcetype=access_combined
| rex field=_raw "(?P<host_header>facebook\.com|twitter\.com|instagram\.com|tiktok\.com|bet365\.com|draftkings\.com|netflix\.com|youtube\.com|twitch\.tv|exploit-db\.com|hackforums\.net|thepiratebay\.org|binance\.com|coinbase\.com)"
| where isnotnull(host_header)
| stats count as violations by clientip
| where violations > 3
```

```
Title:       Web Policy Violation Detection
Schedule:    */5 * * * *
Time range:  Last 10 minutes
Trigger:     Number of Results > 0
Severity:    Medium
```

---

## 📊 Findings

### Part A -- Nmap Detection Results

| Indicator | Value |
|---|---|
| Nmap probes detected in Apache log | Yes |
| Nmap User-Agent found | Yes |
| Unusual HTTP methods observed | HEAD, OPTIONS |
| Detection time after scan start | Real-time (next Splunk ingest cycle) |

### Part B -- Policy Violation Summary

| Category | Sites Visited | Total Requests |
|---|---|---|
| Social Media | facebook.com, twitter.com, instagram.com, tiktok.com | [update] |
| Gambling | bet365.com, draftkings.com | [update] |
| Streaming | netflix.com, youtube.com, twitch.tv | [update] |
| Hacking Tools | exploit-db.com, hackforums.net | [update] |
| Torrent | thepiratebay.org | [update] |
| Cryptocurrency | binance.com, coinbase.com | [update] |

> Update with actual counts from your Splunk search results.

---

## 💡 What I Learned

- **HTTP logs are a genuine real-time detection source.** Unlike scheduled batch log shipping, Apache writes to access.log synchronously with each request. Policy violations appeared in Splunk within seconds of the curl commands running -- making web monitoring one of the fastest detection channels available.

- **Nmap version scans leave clear HTTP evidence.** The `-sV` flag causes Nmap to send actual HTTP requests to web services to identify them. These requests -- with Nmap's User-Agent, unusual methods like HEAD and OPTIONS, and rapid succession from one IP -- are easily detectable in Apache access logs without any packet capture. This surprised me -- I assumed Nmap was invisible without network-level monitoring.

- **The Host header is the key field for policy monitoring in a proxy environment.** In a real corporate proxy setup, every HTTP request passes through the proxy which logs the requested domain in the Host header. My curl simulation with `-H "Host: facebook.com"` replicates exactly how a proxy logs employee web activity -- the domain visited is recorded regardless of what internal IP actually served the content.

- **Category-based detection scales better than domain-based detection.** Hardcoding individual domain names works for a small list but real web filtering policies have thousands of blocked domains. The `eval case()` category assignment approach I used here is the right pattern -- it groups domains into policy categories so you alert on the category rather than individual sites, making the detection more maintainable.

- **Repeat offender detection adds enforcement value.** Detecting a single visit to a blocked site might be accidental mistype. Detecting 15 visits to 4 different blocked sites from the same IP is deliberate policy circumvention. The repeat offender search with risk classification provides the context that turns a raw detection into an actionable HR/security finding.

---

## 🔗 SOC Relevance

| Detection | Real SOC Use Case |
|---|---|
| Nmap User-Agent in web logs | Pre-exploitation reconnaissance detection |
| HEAD/OPTIONS flood from one IP | Automated scanner or version probe |
| Social media visits | HR/productivity policy enforcement |
| Gambling/torrent visits | AUP violation -- HR escalation |
| Hacking tools access | Security policy -- immediate investigation |
| Repeat offender risk score | Prioritise HR/security follow-up |
| Policy violation alert | Automated notification to security team |

### MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Active Scanning: Vulnerability Scanning | T1595.002 | Nmap probes in Apache access log |
| Gather Victim Host Info | T1592 | Nmap version scan User-Agent |

---

## 🛠️ Tools I Used

- **Splunk Free** -- SIEM, detection, dashboards, alerts
- **Nmap** -- live port and version scan
- **Apache2** -- web server generating real-time access logs
- **curl** -- HTTP client for policy violation simulation
- **Kali Linux** -- lab environment

---

*Project 12 of 14 · [Back to Main Portfolio](../README.md)*
