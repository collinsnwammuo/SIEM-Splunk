# 03 - Stats and Aggregation

**Phase:** 2 -- SPL Fundamentals  
**Difficulty:** Beginner to Intermediate  
**Tool:** Splunk Free  
**Lab Environment:** Kali Linux · VirtualBox

---

## 🎯 What I Did

I worked through Splunk's aggregation commands -- `stats`, `top`, `rare`, `dc`, and `values` -- using real auth log, syslog, and Apache data from my `soc_lab` index. The highlight of this project was building a working brute force detection query from scratch using `stats count by src` with a threshold filter, then running Hydra against my own machine to generate real attack data and confirming the detection fired correctly.

This is the project where SPL starts feeling like a proper detection tool rather than just a log viewer.

---

## 🧠 Why Aggregation Matters for SOC Work

Raw log events are individually meaningless at scale. A single failed login is noise. 847 failed logins from the same IP in 10 minutes is an attack. The `stats` command is what turns noise into signal -- it collapses thousands of individual events into the summary that actually tells you something is wrong.

```
Without stats:
Jun 8 10:23:41 kali sshd: Failed password for kali from 127.0.0.1
Jun 8 10:23:42 kali sshd: Failed password for kali from 127.0.0.1
Jun 8 10:23:43 kali sshd: Failed password for kali from 127.0.0.1
... (hundreds more identical lines) ...

With stats:
src           count
127.0.0.1     847     <- immediately obvious this is a brute force
```

---

## 🔬 Searches I Ran

### Basic Count and Inventory

```splunk
index=soc_lab | stats count by sourcetype | sort -count
```

My SIEM inventory at a glance -- how many events from each log source. syslog dominated with the most events, which is expected since it captures everything system-level.

---

### User Activity Analysis

```splunk
index=soc_lab sourcetype=linux_secure
| stats count by USER
| sort -count
```

Every user account in the auth log ranked by activity. Immediately shows the most active accounts -- useful for spotting unusual accounts or service accounts behaving unexpectedly.

```splunk
index=soc_lab sourcetype=linux_secure
| stats count by USER, COMMAND
| sort -count
```

Added COMMAND to the grouping to see which user ran which command and how many times. This is a privilege audit -- it shows the full picture of what elevated commands were executed and by whom.

---

### top and rare

```splunk
index=soc_lab sourcetype=linux_secure | top limit=10 COMMAND
```

The ten most frequently run sudo commands. Expected commands like `ls`, `systemctl`, `cat` dominate.

```splunk
index=soc_lab sourcetype=linux_secure | rare limit=10 COMMAND
```

The least frequently run commands. From a security perspective this is often more interesting than `top` -- unusual one-off commands on a system can indicate an attacker running tools that are not part of normal operations.

---

### Brute Force Detection

I generated real attack data by running Hydra against my own SSH service:

```bash
hydra -l kali -P ~/wordlist.txt ssh://127.0.0.1 -t 4 -V
```

Then built the detection query step by step:

**Step 1 -- Find all failed logins:**
```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| stats count by src
| sort -count
```

The Hydra source IP appeared immediately with a count far higher than any other entry.

**Step 2 -- Add threshold to create detection rule:**
```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| stats count by src
| where count > 5
| sort -count
```

Any IP exceeding 5 failed attempts is flagged. This is a functional brute force detection rule.

**Step 3 -- Enrich with targeted account information:**
```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| stats dc(user) as targeted_accounts count as total_attempts by src
| sort -total_attempts
```

Now I can see not just how many attempts each IP made but how many different accounts it targeted -- distinguishing a targeted attack on one account from a credential stuffing attack against many.

---

### Attack Timeline

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| stats count earliest(_time) as first_seen latest(_time) as last_seen by src
| eval duration = last_seen - first_seen
| sort -count
```

This search shows when the attack started, when it ended, and how long it ran. Combined with the event count it tells a complete story of the attack timeline.

---

### Distinct Count

```splunk
index=soc_lab sourcetype=linux_secure
| stats dc(USER) as unique_users count as total_events
```

One line of output -- total unique users and total events. A quick scope assessment at the start of any investigation.

---

### Values -- Command Audit per User

```splunk
index=soc_lab sourcetype=linux_secure
| stats values(COMMAND) as commands_run by USER
```

One row per user showing all commands they ran as a list. This is a concise privilege audit view -- in a real investigation following a compromise I would run this to understand everything the attacker did if they achieved privilege escalation.

---

### Apache HTTP Status Analysis

```splunk
index=soc_lab sourcetype=access_combined
| stats count by status
| sort -count
```

HTTP status code distribution. 200s are successful requests, 404s are missing resources, 403s are access denied. A spike in 404s from one IP is reconnaissance.

```splunk
index=soc_lab sourcetype=access_combined status=404
| stats count by clientip
| sort -count
| where count > 3
```

Any IP generating more than 3 404 errors is probing for resources. This query is a basic web reconnaissance detection rule.

---

## 📊 SPL Aggregation Commands Reference

| Command | Purpose | Example |
|---|---|---|
| `stats count` | Count all matching events | `\| stats count` |
| `stats count by X` | Count grouped by field | `\| stats count by USER` |
| `stats count by X, Y` | Count grouped by multiple fields | `\| stats count by USER, COMMAND` |
| `top limit=N field` | Most frequent N values | `\| top limit=10 COMMAND` |
| `rare limit=N field` | Least frequent N values | `\| rare limit=10 COMMAND` |
| `stats dc(field)` | Count unique values | `\| stats dc(USER)` |
| `stats values(field) by X` | List all values grouped by field | `\| stats values(COMMAND) by USER` |
| `stats earliest(_time)` | First event timestamp | `\| stats earliest(_time) as first_seen` |
| `stats latest(_time)` | Last event timestamp | `\| stats latest(_time) as last_seen` |
| `where count > N` | Threshold filter | `\| where count > 5` |

---

## 💡 What I Learned

- **`stats` is the command that makes SIEM useful.** Before this project Splunk was a log viewer. After it Splunk is a detection tool. The ability to collapse thousands of events into a ranked summary with a threshold filter is what actually identifies attacks rather than just storing evidence of them.

- **The brute force detection query is simple but production-ready.** `stats count by src | where count > 5` is essentially what many commercial SIEM brute force detection rules look like under the hood. The threshold value would be tuned based on environment baseline, but the logic is the same.

- **`rare` is underrated.** Everyone focuses on `top` but from a detection perspective unusual activity is more interesting than common activity. A command that appears once on a server that normally only runs three commands is worth investigating even if the absolute count is low.

- **`dc` for scoping investigations.** When I first investigate an incident I want to know scope quickly -- how many accounts, how many hosts, how many IPs. `dc` answers all of those in a single fast query before I dive into the details.

- **Attack timeline with `earliest` and `latest` is the foundation of incident reporting.** Every incident report needs a timeline. Building it from `stats earliest(_time) as first_seen latest(_time) as last_seen` is much faster and more accurate than manually scrolling through events looking for the first and last occurrence.

---

## 🔗 SOC Relevance

| Detection Query | Attack It Detects |
|---|---|
| `"Failed password" \| stats count by src \| where count > 5` | SSH brute force |
| `status=404 \| stats count by clientip \| where count > 3` | Web reconnaissance scanning |
| `stats dc(user) as accounts count by src \| where accounts > 3` | Credential stuffing |
| `rare limit=10 COMMAND` | Unusual privileged commands |
| `stats earliest latest by src` | Attack timeline reconstruction |

---

## 🛠️ Tools I Used

- **Splunk Free** -- SIEM platform
- **Hydra** -- brute force tool to generate real attack data
- **Kali Linux** -- lab environment
- **Log sources:** linux_secure, syslog, access_combined

---

*Project 03 of 14 · [Back to Main Portfolio](../README.md)*
