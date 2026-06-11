# 06 - Eval and Calculated Fields

**Phase:** 2 -- SPL Fundamentals  
**Tool:** Splunk Free  
**Lab Environment:** Kali Linux · VirtualBox

---

## 🎯 What I Did

I worked through Splunk's `eval` command -- using conditional logic, math operations, string functions, and time formatting to create calculated fields from raw log data. The most significant search in this project is the severity classification query, which uses `eval case()` to automatically assign CRITICAL, HIGH, MEDIUM, or LOW severity to brute force attempts based on attempt count. That is a production-ready detection pattern.

---

## 🧠 Background -- What eval Does

`eval` creates a new field by computing a value. That value can come from:
- A static string or number
- An existing field
- A function applied to an existing field
- Conditional logic based on field values
- Math operations on numeric fields

```
Without eval:
_time                    _raw
2026-06-09 11:58:14     kali sshd: Failed password for kali from 127.0.0.1...

With eval login_status=if(match(_raw,"Failed password"),"FAILED","SUCCESS"):
_time                    login_status
2026-06-09 11:58:14     FAILED
```

The computed field behaves exactly like any other Splunk field -- you can filter on it, group by it, visualise it, and alert on it.

---

## 🔬 Searches I Ran

### Basic Eval

```splunk
index=soc_lab sourcetype=linux_secure
| eval login_status=if(match(_raw,"Failed password"),"FAILED","SUCCESS")
| table _time USER login_status
```

Every auth event now has a clean FAILED or SUCCESS label. Much easier to work with than searching raw text.

---

### Event Type Classification with case

```splunk
index=soc_lab sourcetype=linux_secure
| eval event_type=case(
    match(_raw,"Failed password"), "Brute Force Attempt",
    match(_raw,"Accepted password"), "Successful Login",
    match(_raw,"session opened"), "Session Started",
    match(_raw,"session closed"), "Session Ended",
    1==1, "Other"
  )
| stats count by event_type
```

This categorises every auth log event into a meaningful type. The `1==1` at the end is the default catch-all -- anything that does not match the earlier conditions gets labelled Other. The stats output gives a complete picture of all authentication activity in one clean table.

---

### Risk Scoring

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by attacker_ip
| eval risk_score=failed_attempts * 10
| table attacker_ip failed_attempts risk_score
| sort -risk_score
```

Multiplying failed attempt count by 10 creates a numeric risk score. Simple but the principle is the same as commercial SIEM risk models -- higher activity means higher risk score means higher priority for analyst review.

---

### Severity Classification

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as attempts by attacker_ip
| eval severity=case(
    attempts >= 50, "CRITICAL",
    attempts >= 20, "HIGH",
    attempts >= 10, "MEDIUM",
    attempts >= 1,  "LOW"
  )
| table attacker_ip attempts severity
| sort -attempts
```

This is the most practical search in this project. Automatic severity assignment based on threshold bands is how real SIEM platforms prioritise alerts. An analyst triaging a queue of alerts goes to CRITICAL first -- this query produces exactly that prioritised view.

---

### Time-based Analysis with strftime

```splunk
index=soc_lab sourcetype=linux_secure
| eval event_hour=strftime(_time, "%H")
| stats count by event_hour
| sort event_hour
```

Activity broken down by hour of day. In a corporate environment this baseline tells you what normal looks like -- and deviations from it (logins at 3 AM, activity on weekends) stand out immediately.

---

### Attack Summary with String Concatenation

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "Failed password for (?P<targeted_user>\w+) from"
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| eval attack_summary=attacker_ip." attacked account: ".targeted_user
| table _time attack_summary
```

The `.` operator joins strings in eval. This creates a single readable summary field that combines multiple extracted values -- exactly the kind of field that goes into an alert description or an incident report finding.

---

### Long Command Detection

```splunk
index=soc_lab sourcetype=linux_secure COMMAND=*
| eval cmd_length=len(COMMAND)
| where cmd_length > 50
| table _time USER COMMAND cmd_length
```

`len()` measures string length. Commands over 50 characters are often more complex and potentially suspicious -- attackers frequently use long base64-encoded commands to obfuscate malicious activity. This search surfaces them for review.

---

### Readable Timestamps with fieldformat

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as attempts earliest(_time) as first_seen by attacker_ip
| fieldformat first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| table attacker_ip attempts first_seen
```

Without `fieldformat` the `first_seen` column shows as a Unix epoch timestamp like `1749470294`. With it the same value reads as `2026-06-09 11:58:14`. This matters when presenting findings -- readable timestamps in reports reduce the chance of misinterpretation.

---

## 📊 Eval Functions Reference

| Function | Purpose | Example |
|---|---|---|
| `if(condition, a, b)` | Return a if true, b if false | `eval status=if(match(_raw,"Failed"),"FAIL","OK")` |
| `case(c1,v1, c2,v2...)` | Multi-condition branching | `eval sev=case(count>=50,"CRITICAL",count>=10,"HIGH",1==1,"LOW")` |
| `match(field,"pattern")` | Regex match returning true/false | `match(_raw,"Failed password")` |
| `upper(field)` | Convert to uppercase | `eval u=upper(USER)` |
| `lower(field)` | Convert to lowercase | `eval l=lower(USER)` |
| `len(field)` | String length | `eval cmd_len=len(COMMAND)` |
| `substr(field,start,len)` | Substring extraction | `eval first3=substr(USER,1,3)` |
| `strftime(_time,"%H")` | Format timestamp | `eval hour=strftime(_time,"%H")` |
| `field1.".".field2` | String concatenation | `eval summary=ip.": ".user` |
| `fieldformat` | Display formatting only | `fieldformat ts=strftime(ts,"%Y-%m-%d")` |

---

## 💡 What I Learned

- **`eval case()` with severity tiers is immediately production-applicable.** The CRITICAL/HIGH/MEDIUM/LOW classification query I built is essentially the same logic used in commercial SIEM alert triage systems. Understanding that most SIEM severity rules are just threshold comparisons like this demystified a concept that previously seemed complex.

- **`strftime` for hour-based analysis is underused in beginner labs.** Breaking activity down by hour of day is one of the most practical detection techniques -- almost every insider threat and many external attacks show up as anomalous activity outside normal business hours. Building this baseline analysis is something I will include in every investigation going forward.

- **`fieldformat` separates analysis from presentation.** The actual `_time` value stays as a Unix timestamp internally (which is what Splunk needs for calculations) but `fieldformat` makes it readable in the output. Understanding the difference between changing a value with eval and changing its display with fieldformat matters when building searches that chain multiple operations.

- **String concatenation with eval is useful for incident reporting.** The attack summary field combining attacker IP and targeted username in one readable string is the kind of concise finding description that goes directly into an incident report. Building that field in SPL means it is consistent and reproducible -- not written by hand each time.

- **Long command detection is a real technique.** After learning about attackers using base64-encoded commands in APT exercises, the `len(COMMAND) > 50` filter started making sense as a practical detection heuristic. It will not catch everything but it surfaces anomalies worth reviewing.

---

## 🔗 SOC Relevance

| Eval Pattern | Detection / Investigation Use |
|---|---|
| `eval status=if(match...,"FAILED","SUCCESS")` | Clean login result classification |
| `eval event_type=case(...)` | Automatic event categorisation |
| `eval risk_score=count * weight` | Alert prioritisation scoring |
| `eval severity=case(count>=50,"CRITICAL"...)` | Severity triage for analyst queue |
| `eval hour=strftime(_time,"%H")` | Off-hours activity detection |
| `eval cmd_length=len(COMMAND)` | Suspicious command length flagging |
| `fieldformat timestamp=strftime(...)` | Readable timestamps in IR reports |

---

## 🛠️ Tools I Used

- **Splunk Free** -- SIEM platform
- **Kali Linux** -- lab environment
- **Log sources:** linux_secure, syslog, access_combined

---

*Project 06 of 14 · [Back to Main Portfolio](../README.md)*
