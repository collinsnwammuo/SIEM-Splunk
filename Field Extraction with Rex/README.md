# 05 - Field Extraction with Rex

**Phase:** 2 -- SPL Fundamentals  
**Tool:** Splunk Free  
**Lab Environment:** Kali Linux · VirtualBox

---

## 🎯 What I Did

I used Splunk's `rex` command to write regular expression patterns that extract structured fields from raw log lines -- pulling attacker IPs, targeted usernames, source ports, HTTP methods, URI paths, and status codes out of auth logs, Apache access logs, and syslog entries. I then combined rex with `stats` and `table` to turn those extracted fields into proper detection queries.

This is the project that fills the gap when Splunk's automatic field extraction is not enough -- which happens regularly in real SOC work with custom or legacy log formats.

---

## 🧠 Background -- Why Rex is Necessary

Splunk automatically extracts common fields from well-known log formats. But the extraction is not always complete. Looking at a raw failed SSH login event:

```
2026-06-09T11:58:14 kali sshd: Failed password for kali from 127.0.0.1 port 52341 ssh2
```

Splunk extracts `host`, `source`, `sourcetype`, and timestamp automatically. But `127.0.0.1` (the attacker IP), `kali` (the targeted username), and `52341` (the source port) are not automatically available as searchable fields. They are buried in the raw text.

Rex is how I pull them out:

```splunk
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+)"
```

After this command, `attacker_ip` exists as a proper field I can filter, group, and aggregate on -- exactly like any other Splunk field.

### Rex Pattern Structure

```
"anchor_text (?P<field_name>regex_pattern)"
     |              |              |
 literal text   field to         regex that
 to find the    create in        matches the
 right position Splunk           value you want
```

---

## 🔬 Extractions I Built

### Auth Log -- Attacker IP

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| table _time attacker_ip
```

Pattern breakdown:
- `from ` -- anchor: the IP always follows the word "from"
- `\d+\.\d+\.\d+\.\d+` -- four groups of digits separated by dots -- an IPv4 address

---

### Auth Log -- Targeted Username

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "Failed password for (?P<targeted_user>\w+) from"
| table _time targeted_user
```

Pattern breakdown:
- `Failed password for ` -- anchor text before the username
- `\w+` -- one or more word characters (letters, digits, underscore)
- ` from` -- end anchor after the username

---

### Auth Log -- Combined Extraction

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "Failed password for (?P<targeted_user>\w+) from"
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+) port (?P<src_port>\d+)"
| table _time attacker_ip src_port targeted_user
```

Multiple rex commands chain together -- each one adds a new field to the event. This single pipeline extracts three fields from one raw log line.

---

### Apache Logs -- HTTP Method and URI

```splunk
index=soc_lab sourcetype=access_combined
| rex "\"(?P<http_method>GET|POST|PUT|DELETE) (?P<uri_path>[^\s]+)[^\"]*\" (?P<status_code>\d{3})"
| table _time http_method uri_path status_code
```

Pattern breakdown:
- `\"` -- opening quote before the HTTP request section
- `(?P<http_method>GET|POST|PUT|DELETE)` -- one of four HTTP methods
- ` (?P<uri_path>[^\s]+)` -- everything up to the next space is the URI
- `[^\"]*\"` -- skip everything to the closing quote
- ` (?P<status_code>\d{3})` -- three-digit status code after the quote

---

### Apache Logs -- 404 Detection with Extracted Fields

```splunk
index=soc_lab sourcetype=access_combined
| rex "\"(?P<http_method>GET|POST|PUT|DELETE) (?P<uri_path>[^\s]+)[^\"]*\" (?P<status_code>\d{3})"
| table _time http_method uri_path status_code
| where status_code="404"
```

Extracting the status code as a field then filtering on it is more precise than keyword searching for `404` -- which might match in other parts of the log line.

---

### Syslog -- Process Name and PID

```splunk
index=soc_lab sourcetype=syslog
| rex "(?P<syslog_process>\w+)\[(?P<pid>\d+)\]"
| table _time syslog_process pid
```

Pattern breakdown:
- `(?P<syslog_process>\w+)` -- process name before the bracket
- `\[` -- literal opening bracket
- `(?P<pid>\d+)` -- digits inside the bracket are the PID
- `\]` -- literal closing bracket

---

### Rex Combined with Stats -- Detection Queries

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "Failed password for (?P<targeted_user>\w+) from"
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by attacker_ip, targeted_user
| sort -count
```

This is the complete picture of a brute force attack -- which IP attacked which accounts and how many times. Rex extracted the fields, stats aggregated them.

```splunk
index=soc_lab sourcetype=access_combined
| rex "\"(?P<http_method>GET|POST|PUT|DELETE) (?P<uri_path>[^\s]+)[^\"]*\" (?P<status_code>\d{3})"
| stats count by uri_path, status_code
| sort -count
```

Every URI path requested against the web server with its status code and frequency -- a complete picture of web activity.

---

## 📊 Rex Patterns Reference

| Pattern | Matches | Use Case |
|---|---|---|
| `\d+` | One or more digits | Port numbers, counts |
| `\d+\.\d+\.\d+\.\d+` | IPv4 address | Extracting IPs |
| `\w+` | Word characters (letters, digits, _) | Usernames, process names |
| `[^\s]+` | Everything up to next space | URIs, file paths |
| `\d{3}` | Exactly three digits | HTTP status codes |
| `GET\|POST\|PUT\|DELETE` | One of these HTTP methods | Web request method |
| `(?P<name>pattern)` | Named capture group | Creates Splunk field |
| `^` | Start of line | Anchoring to line start |
| `mode=sed` | Substitution mode | Modifying field values |

---

## 💡 What I Learned

- **Rex unlocks logs that Splunk cannot parse automatically.** Before this project I was limited to fields Splunk extracted on its own. After it I can extract any value from any log line as long as I can describe its pattern in regex. That massively expands what I can search and alert on.

- **Anchor text makes regex patterns reliable.** The most common mistake with rex is writing a pattern that could match in the wrong place. Using literal anchor text like `"from "` before the IP pattern and `" port "` after it ensures the extraction always finds the right value even in long complex log lines.

- **Multiple rex commands chain cleanly.** I initially tried to write one giant regex pattern to extract everything at once. Splitting it into separate rex commands -- one for IP, one for username, one for port -- made each pattern simpler, easier to debug, and easier to reuse in other searches.

- **Rex plus stats is the complete detection pattern.** Rex alone gives you extracted fields. Stats alone gives you aggregates. Together they give you "attacker IP X made 54 attempts against account Y" -- which is a complete, actionable finding rather than a raw observation.

- **Testing patterns in the terminal before Splunk saves time.** Running a quick `grep -oP` test against a copied log line in the terminal told me immediately whether my regex pattern worked before I built a full SPL query around it. That feedback loop is much faster than running a full Splunk search to debug a pattern.

---

## 🔗 SOC Relevance

| Rex Extraction | Detection Use Case |
|---|---|
| Attacker IP from failed SSH | Brute force source identification |
| Targeted username from failed SSH | Account being attacked identification |
| URI path from Apache logs | Web reconnaissance path analysis |
| HTTP status code extraction | 404 spike detection, error analysis |
| Process name and PID from syslog | Unusual process detection |
| Rex + stats count by attacker_ip | Brute force threshold detection |

---

## 🛠️ Tools I Used

- **Splunk Free** -- SIEM platform
- **regex101.com** -- regex testing tool
- **Kali Linux** -- lab environment
- **Log sources:** linux_secure, access_combined, syslog

---

*Project 05 of 14 · [Back to Main Portfolio](../README.md)*
