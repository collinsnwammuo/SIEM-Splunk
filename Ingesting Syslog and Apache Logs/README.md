# 01 - Ingesting Syslog and Apache Logs

**Phase:** 1 -- Getting Data In  
**Difficulty:** Beginner  
**Tool:** Splunk Free  
**Lab Environment:** Kali Linux · VirtualBox

---

## 🎯 What I Did

I added two new log sources to my Splunk SIEM -- the system syslog and Apache web server access and error logs. I then ran multi-source SPL searches across all of them simultaneously, including a search that identified reconnaissance-style HTTP requests I deliberately generated against the Apache server to simulate attacker behaviour.

Having multiple log sources in one SIEM and being able to correlate across them is the core of what SOC analysts do all day.

---

## 🧠 Why These Log Sources Matter

### Syslog (`/var/log/syslog`)

Syslog captures system-level events -- service starts and stops, kernel messages, scheduled tasks, daemon activity. In a real SOC environment, syslog feeds are one of the most important sources for detecting:
- Unusual service restarts (malware maintaining persistence)
- Cron jobs added or modified (persistence mechanism)
- Kernel errors following exploitation
- System configuration changes

### Apache Access Log (`/var/log/apache2/access.log`)

Every HTTP request to the web server is logged here. For a SOC analyst this is a goldmine for detecting:
- Web application attacks (SQLi, XSS, directory traversal)
- Reconnaissance scanning (automated tools probing for admin panels, config files, CMSs)
- Brute force attacks against login pages
- Unusual user agents suggesting automated scanners

### Apache Error Log (`/var/log/apache2/error.log`)

Records server-side errors, permission denials, and application failures. Useful for detecting exploitation attempts that caused errors and identifying misconfigurations attackers might target.

---

## 🔬 How I Set It Up

### Log Sources Added

| Source | Path | Sourcetype | Index |
|---|---|---|---|
| Auth log | `/var/log/auth.log` | `linux_secure` | `soc_lab` |
| Syslog | `/var/log/syslog` | `syslog` | `soc_lab` |
| Apache access | `/var/log/apache2/access.log` | `access_combined` | `soc_lab` |
| Apache error | `/var/log/apache2/error.log` | `apache_error` | `soc_lab` |

All four configured via Settings -> Data Inputs -> Files & Directories.

### Traffic I Generated

To populate the Apache logs with realistic data I ran a series of curl requests simulating both normal and suspicious web activity:

```bash
# Normal requests
curl http://localhost
curl http://localhost/index.html

# Reconnaissance simulation -- common attacker probes
curl http://localhost/admin
curl http://localhost/login
curl http://localhost/.env
curl http://localhost/wp-admin
curl http://localhost/phpmyadmin
curl http://localhost/nonexistent404
```

The last group simulates what automated scanners and attackers do when they first hit a web server -- probing for admin interfaces, configuration files, and common CMS installation paths.

---

## 📊 What I Found

### Log Source Summary

```
index=soc_lab | stats count by sourcetype | sort -count
```

| Sourcetype | Event Count |
|---|---|
| syslog | [update with actual count] |
| linux_secure | [update with actual count] |
| access_combined | [update with actual count] |
| apache_error | [update with actual count] |


---

### Apache Access Log Analysis

**All HTTP requests:**
```
index=soc_lab sourcetype=access_combined
| table _time clientip request status bytes
```

I could see every request I made to the Apache server with full details -- client IP, the exact URI requested, HTTP status code, and response size.

**404 errors -- file not found:**
```
index=soc_lab sourcetype=access_combined status=404
| table _time clientip request status
```

Every request for a non-existent resource returned a 404. From a SOC perspective, a high volume of 404s from a single IP in a short time window is a strong indicator of automated scanning.

**Reconnaissance URI detection:**
```
index=soc_lab sourcetype=access_combined
| search request="*admin*" OR request="*wp-admin*"
  OR request="*.env*" OR request="*phpmyadmin*"
| table _time clientip request status
```

This search caught every probe I made for admin panels and config files. In a real environment I would save this as an alert -- any hit on these URIs from an external IP warrants investigation.

---

### Syslog Analysis

**Events by process:**
```
index=soc_lab sourcetype=syslog
| stats count by process
| sort -count
```

Shows which system processes are generating the most log volume. Unusual processes appearing in this list -- especially ones that should not be running -- are worth investigating.

---

### Multi-Source Correlation

**Combined search across all sources:**
```
index=soc_lab (sourcetype=linux_secure OR sourcetype=access_combined)
| stats count by sourcetype, host
```

This is what makes a SIEM powerful -- a single search returning data from completely different log sources in one result set. In a real investigation I might correlate a suspicious IP appearing in Apache logs with authentication attempts in auth.log to build a fuller picture of attacker activity.

---

## 💡 What I Learned

- **Sourcetype assignment is critical.** When I initially set Apache access logs to `linux_secure` by mistake, Splunk tried to parse web server entries as authentication events and extracted completely wrong fields. Changing to `access_combined` immediately gave me properly parsed fields -- clientip, request, status, bytes -- all extracted automatically. The right sourcetype is the difference between useful structured data and unreadable raw text.

- **Generating realistic traffic before analysis makes the results meaningful.** The curl requests I ran against Apache -- particularly the reconnaissance probes for admin panels and config files -- gave me something actually interesting to hunt for. Searching for `.env` and `wp-admin` requests and finding them in the results made the detection workflow feel real rather than theoretical.

- **Multi-source search is where SIEM earns its value.** Running a single SPL query across auth logs, syslog, and Apache logs simultaneously and getting correlated results is something no individual log file can offer. This is the core capability that makes Splunk useful in a real SOC environment.

- **404 volume is a detection signal.** I generated eight requests, five of which returned 404s. In a real environment an automated scanner would generate hundreds or thousands of 404s per minute from a single IP. A simple threshold alert on 404 count per source IP per minute is a practical first detection rule for web reconnaissance.

- **Syslog shows the health of the whole system.** Looking at events by process in syslog gave me a picture of everything running on the machine -- cron jobs, system services, kernel activity. In a compromise scenario, unusual entries here (an unfamiliar process, a service restarting repeatedly, a cron job that was not there before) would be early warning indicators.

---

## 🔗 SOC Relevance

| Search I Ran | Detection Use Case |
|---|---|
| 404 errors from single IP | Web scanner / reconnaissance detection |
| Admin URI probes | Targeted attack against web application |
| Stats by sourcetype | Log source health monitoring |
| Syslog by process | Unusual process or persistence detection |
| Multi-source correlation | Building full attack timeline across sources |

---

## 🛠️ Tools I Used

- **Splunk Free** -- SIEM platform
- **Apache2** -- web server generating access and error logs
- **curl** -- HTTP client for generating test traffic
- **Kali Linux** -- lab environment

---

*Project 01 of 14 · [Back to Main Portfolio](../README.md)*
