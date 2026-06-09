# 02 - Search and Filter Commands

**Phase:** 2 -- SPL Fundamentals  
**Difficulty:** Beginner  
**Tool:** Splunk Free  
**Lab Environment:** Kali Linux · VirtualBox

---

## 🎯 What I Did

I worked through the core SPL search and filter commands using the real log data already flowing into my `soc_lab` index -- auth logs, syslog, and Apache error logs. This project focused on building the muscle memory for the commands I will use in every single investigation going forward: `table`, `fields`, `where`, `search`, `dedup`, `rename`, and time-based filtering.

The goal was not just to learn the syntax but to understand when and why each command is useful in an actual analyst workflow.

---

## 🧠 Background -- How SPL Works

SPL (Search Processing Language) processes events through a pipeline. Each command takes the output of the previous one and transforms it. Understanding this left-to-right flow is the mental model for everything in Splunk.

```
index=soc_lab sourcetype=linux_secure COMMAND=*
       |                                   |
  where to look                      keyword filter
       |
       | pipeline starts here
       v
| table _time USER COMMAND PWD
       |
  select these fields as columns
       |
       v
| rename USER as "Username"
       |
  rename for clean output
       |
       v
| sort -_time
       |
  most recent first
```

Every search is a series of transformations applied to your event data.

---

## 🔬 Searches I Ran

### Basic Index and Sourcetype Filtering

```splunk
index=soc_lab                              # All events in soc_lab
index=soc_lab sourcetype=linux_secure      # Auth log events only
index=soc_lab sourcetype=syslog            # Syslog events only
index=soc_lab sourcetype=apache_error      # Apache error events only
```

Starting every search by specifying the index and sourcetype is good practice -- it narrows the search space immediately and makes queries faster.

---

### Keyword Search

```splunk
index=soc_lab sourcetype=linux_secure COMMAND=*
```

This returns every event where the COMMAND field has any value -- meaning every sudo command that was executed on the system. Every command I ran with sudo during the lab setup showed up here with the exact command, the user who ran it, and the working directory.

---

### table Command

```splunk
index=soc_lab sourcetype=linux_secure COMMAND=*
| table _time USER COMMAND PWD
```

Without `table`, Splunk shows raw log lines that are hard to read quickly. With `table` I selected exactly the fields I cared about as clean columns. This is how I would present sudo activity findings to a team lead or in an incident report.

---

### where Command

```splunk
index=soc_lab sourcetype=linux_secure
| where USER="root"
```

```splunk
index=soc_lab sourcetype=linux_secure
| where COMMAND!="/usr/bin/ls"
```

`where` filters on extracted field values rather than raw text. The second search -- excluding `/usr/bin/ls` from results -- is a practical noise-reduction technique. In a real environment you would filter out routine commands to focus on unusual activity.

---

### dedup Command

```splunk
index=soc_lab sourcetype=linux_secure
| dedup USER
| table USER COMMAND _time
```

`dedup` removes duplicate values for a given field, keeping only the most recent event for each unique value. Useful for answering questions like "which unique users have been active" without wading through repeated entries.

---

### Full Pipeline Search

```splunk
index=soc_lab sourcetype=linux_secure COMMAND=*
| search USER="kali"
| table _time USER COMMAND PWD
| rename USER as "Username" COMMAND as "Command Run" PWD as "Working Directory"
| sort -_time
```

This is what a real analyst search looks like -- multiple commands chained together, each one refining the output. It returns all sudo commands run by the kali user, in a clean renamed table, sorted most recent first.

---

### Time-based Filtering

```splunk
index=soc_lab sourcetype=linux_secure earliest=-1h latest=now
```

```splunk
index=soc_lab sourcetype=syslog earliest=-24h latest=now
| table _time host process message
```

Controlling time inside the SPL query itself rather than the UI picker is important for reproducible searches -- if I save a search or share it with a colleague, the time range travels with it.

---

## 📊 SPL Commands Reference -- What I Learned

| Command | Purpose | Example |
|---|---|---|
| `index=` | Specify which index to search | `index=soc_lab` |
| `sourcetype=` | Filter by log source type | `sourcetype=linux_secure` |
| `table` | Display specific fields as columns | `\| table _time USER COMMAND` |
| `fields` | Include or exclude fields | `\| fields - punct linecount` |
| `where` | Filter on field values | `\| where USER="root"` |
| `search` | Keyword filter inside pipeline | `\| search "session opened"` |
| `dedup` | Remove duplicate field values | `\| dedup USER` |
| `rename` | Rename fields for clean output | `\| rename USER as "Username"` |
| `sort` | Sort results by field | `\| sort -_time` |
| `earliest/latest` | Time range inside SPL | `earliest=-24h latest=now` |

---

## 💡 What I Learned

- **`table` is the most immediately useful command.** Raw Splunk events are long and hard to read quickly. The moment I added `| table _time USER COMMAND PWD` the results became a clean, scannable table. In a real investigation where I need to brief someone on findings, presenting a clean table is far more effective than scrolling through raw log lines.

- **The pipeline model makes complex searches readable.** Breaking a search into steps -- filter, then select fields, then rename, then sort -- makes each step's purpose obvious. I found it much easier to build searches incrementally, adding one command at a time and checking the result, rather than trying to write the whole thing at once.

- **`where` is more precise than keyword search.** Searching for the string "root" would match any event containing that word anywhere. Using `where USER="root"` matches only events where the USER field specifically equals root. In a noisy log environment that precision matters enormously.

- **Noise reduction is as important as detection.** The `where COMMAND!="/usr/bin/ls"` search taught me that real analyst work involves filtering out the known-good as much as hunting for the bad. A SIEM full of noisy benign events is almost as useless as one with no data -- tuning searches to surface only meaningful events is a real skill.

- **`dedup` is useful for baselining.** Running `dedup USER` to get unique users who have been active is the kind of quick baseline check an analyst does at the start of an investigation to understand the scope of activity before diving into details.

---

## 🔗 SOC Relevance

| Command Combination | Analyst Use Case |
|---|---|
| `sourcetype=linux_secure COMMAND=* \| table _time USER COMMAND` | Audit all privileged commands run on a host |
| `where USER="root" \| sort -_time` | Investigate root activity on a compromised host |
| `dedup USER \| table USER` | Identify all unique accounts that were active |
| `earliest=-1h \| stats count by USER` | Triage recent activity during an active incident |
| `rename` fields | Present findings in a readable format for reporting |

---

## 📁 Files in This Folder

---

## 🛠️ Tools I Used

- **Splunk Free** -- SIEM platform
- **Kali Linux** -- lab environment
- **Log sources:** linux_secure, syslog, apache_error

---

*Project 02 of 14 · [Back to Main Portfolio](../README.md)*
