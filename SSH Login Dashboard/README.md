# 07 - Failed SSH Login Dashboard

**Phase:** 3 -- Dashboards & Alerts    
**Tool:** Splunk Free  
**Lab Environment:** Kali Linux · VirtualBox

---

## 🎯 What I Did

I built a six-panel SOC monitoring dashboard in Splunk that provides a complete view of SSH brute force activity -- combining everything from Phase 2 into a single operational screen. The dashboard shows attack timelines, source IPs, targeted accounts, severity classification, login ratios, and recent raw events simultaneously. I generated realistic attack data using Hydra against multiple usernames before building the dashboard so every panel populated with meaningful data.

This is the first project in the portfolio that looks like something from an actual SOC environment rather than a search exercise.

---

## ⚠️ Disclaimer

All attack data was generated in my isolated VirtualBox lab against my own machines. No external systems were involved.

---

## 🧠 Background -- Why Dashboards Matter

Individual SPL searches answer specific questions. Dashboards answer multiple questions simultaneously and keep answering them in real time. A SOC analyst monitoring an environment does not run manual searches every few minutes -- they watch dashboards that update automatically and draw their attention to anomalies.

The dashboard I built answers six questions at once:
- **When** did attacks happen? (timechart panel)
- **Where** did they come from? (top IPs panel)
- **What** accounts were targeted? (top usernames panel)
- **How severe** is each source? (severity table)
- **What is the overall ratio** of failed to successful logins? (pie chart)
- **What just happened?** (recent events table)

---

## 🔬 Dashboard Architecture

### Lab Data Generated

```bash
# Multiple Hydra runs against different accounts
hydra -l kali  -P ~/wordlist.txt ssh://127.0.0.1 -t 4 -V
hydra -l root  -P ~/wordlist.txt ssh://127.0.0.1 -t 4 -V
hydra -l admin -P ~/wordlist.txt ssh://127.0.0.1 -t 4 -V

# Legitimate logins between attacks
ssh kali@127.0.0.1
```

Running Hydra against three different usernames gave the targeted usernames panel meaningful variety and pushed the attacking IP into CRITICAL severity territory.

---

### Panel 1 -- Failed SSH Logins Over Time

**Type:** Line Chart  
**Purpose:** Show when attacks happened and their intensity

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| timechart span=1m count by attacker_ip
```

The timechart shows the distinct Hydra runs as separate spikes -- each attack burst clearly visible as a sharp rise and fall. The gaps between spikes correspond to when I ran Hydra against different usernames.

---

### Panel 2 -- Top Attacking IP Addresses

**Type:** Bar Chart  
**Purpose:** Identify which source IPs are generating the most failures

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as attempts by attacker_ip
| sort -attempts
| head 10
```

In my lab all attacks came from `127.0.0.1`. In a real environment this panel would show multiple external IPs ranked by activity -- the top entry is the highest-priority investigation target.

---

### Panel 3 -- Most Targeted Usernames

**Type:** Bar Chart  
**Purpose:** Identify which accounts are under attack

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "Failed password for (?P<targeted_user>\w+) from"
| stats count as attempts by targeted_user
| sort -attempts
| head 10
```

Running Hydra against `kali`, `root`, and `admin` separately gave this panel three distinct bars. `kali` had the most attempts because I ran Hydra against it multiple times. `root` and `admin` show that an attacker was probing for common privileged accounts.

---

### Panel 4 -- Attacker Severity Classification

**Type:** Statistics Table  
**Purpose:** Prioritise which sources need immediate investigation

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

After multiple Hydra runs, `127.0.0.1` accumulated enough failed attempts to reach CRITICAL severity. This panel would be the first thing an analyst looks at when triaging a brute force alert -- it immediately answers whether this is a low-priority probe or an active ongoing attack.

---

### Panel 5 -- Failed vs Successful Login Ratio

**Type:** Pie Chart  
**Purpose:** Show overall authentication health at a glance

```splunk
index=soc_lab sourcetype=linux_secure
| eval login_result=if(match(_raw,"Failed password"),"Failed","Successful")
| stats count by login_result
```

A healthy environment should have a very high ratio of successful to failed logins. A pie chart dominated by the Failed slice is an immediate visual indicator that something is wrong -- the ratio alone communicates the problem before an analyst reads a single number.

---

### Panel 6 -- Recent Failed Login Events

**Type:** Statistics Table  
**Purpose:** Show the raw evidence of the most recent activity

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "Failed password for (?P<targeted_user>\w+) from"
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| table _time attacker_ip targeted_user
| sort -_time
| head 20
```

The most recent 20 failed attempts in a clean table. When an alert fires this is the first raw evidence an analyst examines -- exact timestamps, source IPs, and targeted accounts in a readable format.

---

## 💡 What I Learned

- **Building a dashboard forces you to think about what questions matter.** I started by planning six questions I wanted the dashboard to answer before writing any SPL. That planning step made the dashboard coherent -- each panel has a specific purpose rather than just being another chart.

- **Panel arrangement communicates priority.** Putting the timechart at the top (when did it happen) and the severity table prominently in the middle (how bad is it) means an analyst's eye naturally flows from context to action. Layout is not just aesthetic -- it affects how quickly someone can triage an alert.

- **The pie chart is the most immediately readable panel.** A pie chart dominated by the red Failed slice communicates a problem faster than any table or number. For an executive or manager glancing at a screen it provides instant situational awareness without needing to understand SPL or log formats.

- **Generating data against multiple usernames made the dashboard more realistic.** Running Hydra only against one account produces a boring single-bar chart. Running it against `kali`, `root`, and `admin` gave the usernames panel meaningful variety that looks more like a real credential stuffing attack.

- **A dashboard is a living investigation tool, not just a screenshot.** The time range input I added means the same dashboard can show the last hour, last 24 hours, or last week with one click. That flexibility is what makes dashboards useful operationally rather than just for documentation.

---

## 🔗 SOC Relevance

| Dashboard Panel | Analyst Action Triggered |
|---|---|
| Timechart spike | Identify attack window for log correlation |
| Top attacking IP | Initiate threat intel lookup on source IP |
| Top targeted username | Check if account is compromised, force password reset |
| CRITICAL severity row | Immediate escalation, consider IP block |
| Failed:Success ratio > 10:1 | Active brute force in progress, raise P1 alert |
| Recent events table | Gather IOCs for incident report |

---

## 🛠️ Tools I Used

- **Splunk Free** -- SIEM platform and dashboard builder
- **Hydra** -- brute force tool for generating attack data
- **OpenSSH** -- SSH server on Kali
- **Kali Linux** -- lab environment

---

*Project 07 of 14 · [Back to Main Portfolio](../README.md)*
