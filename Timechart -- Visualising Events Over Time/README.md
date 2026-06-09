# 04 - Timechart: Visualising Events Over Time

**Phase:** 2 -- SPL Fundamentals  
**Difficulty:** Beginner to Intermediate  
**Tool:** Splunk Free  
**Lab Environment:** Kali Linux · VirtualBox

---

## 🎯 What I Did

I used Splunk's `timechart` command to visualise my lab attack data as time-series graphs -- turning raw event counts into visual patterns that make attacks immediately recognisable. The centrepiece of this project is the brute force spike graph: a timechart of failed SSH logins during a Hydra attack that shows a sudden burst of activity at a granular 10-second span, making the automated attack pattern unmistakable at a glance.

This is the project where Splunk stops feeling like a log database and starts feeling like a monitoring tool.

---

## 🧠 Why Timechart Matters for SOC Work

Numbers tell you something happened. Graphs tell you when, how fast, and for how long. The difference between "54 failed logins" and a graph showing all 54 concentrated in a 90-second window is the difference between a note and an alert.

```
stats approach:
src_ip        count
127.0.0.1     54     <- something happened

timechart approach:
time     count
11:57    0
11:58    54    <<<< SPIKE -- automated tool running
11:59    0
12:00    0     <- attack stopped
```

The timechart view also reveals patterns that stats cannot -- the regular intervals of C2 beaconing, the gradual escalation of a slow scan, the abrupt cutoff when an attacker achieves their goal.

---

## 🔬 Searches I Ran

### Baseline Activity Graph

```splunk
index=soc_lab | timechart count
```

My overall event volume over time. The spikes correspond to my lab activity -- the Hydra run, the curl reconnaissance, sudo commands. This established what normal versus anomalous activity looks like in my environment.

---

### Multi-Source Monitoring

```splunk
index=soc_lab | timechart count by sourcetype
```

One line per log source on the same graph. I could see syslog running continuously at a steady rate while linux_secure spiked during authentication activity and access_combined spiked when I generated web traffic. This is how a SOC dashboard monitors multiple log sources simultaneously.

---

### Controlling Granularity with span

```splunk
index=soc_lab | timechart span=1h count by sourcetype   # hourly buckets
index=soc_lab | timechart span=5m count by sourcetype   # 5-minute buckets
index=soc_lab | timechart span=1m count                 # 1-minute buckets
```

The span value changes what the graph can show. At `span=1h` a 90-second brute force is invisible -- it just looks like a slightly elevated hour. At `span=10s` the same attack is a dramatic spike. Choosing the right span is a tuning decision every SOC analyst makes based on what they are looking for.

---

### Brute Force Spike -- The Main Detection Visual

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| timechart span=10s count by src_ip
```

This is the headline search of this project. Running it after a Hydra attack produces the clearest possible visual of automated brute force activity -- a sharp spike concentrated in a narrow time window followed by complete silence. The pattern is unmistakable because no human generates authentication attempts at that rate.

---

### Failed vs Successful Logins

```splunk
index=soc_lab sourcetype=linux_secure
| eval login_result=if(match(_raw,"Failed password"),"Failed","Successful")
| timechart span=1m count by login_result
```

Two lines on the same graph -- failed and successful logins over time. During the Hydra run the Failed line spikes while Successful stays flat. The moment Hydra found the correct password a single Successful event appears at the end of the Failed burst. This before-and-after pattern is exactly what a SOC analyst looks for when triaging a brute force alert.

---

### Apache Traffic by Status Code

```splunk
index=soc_lab sourcetype=access_combined
| timechart span=1m count by status
```

HTTP status codes over time. I generated a loop of 20 curl requests to non-existent URLs which produced a 404 spike. The visual pattern of a sudden burst of 404s from a short period mirrors what automated web scanning looks like in production environments.

---

### Threshold Visualisation

```splunk
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| timechart span=10s count as failed_logins
| eval threshold=5
```

Adding a flat threshold line at 5 shows visually exactly when the activity exceeded the alert threshold. Every point where the count line crosses above the threshold is a trigger point. This is the visual representation of how SIEM alert rules work.

---

## 📊 SPL Timechart Reference

| Command | Purpose | Example |
|---|---|---|
| `timechart count` | Events over time | `\| timechart count` |
| `timechart count by X` | Events per field value over time | `\| timechart count by sourcetype` |
| `span=Ns` | Set time bucket size in seconds | `\| timechart span=10s count` |
| `span=Nm` | Set time bucket size in minutes | `\| timechart span=5m count` |
| `span=Nh` | Set time bucket size in hours | `\| timechart span=1h count` |
| `limit=N` | Cap number of series on graph | `\| timechart count by src limit=5` |
| `eval threshold=N` | Add flat threshold line | `\| eval threshold=5` |

---

## 💡 What I Learned

- **span is the most important tuning parameter.** The same attack looks completely different at different span values. A brute force invisible at `span=1h` becomes unmistakable at `span=10s`. In a real SOC environment choosing the right span for a detection dashboard requires knowing the attack patterns you are hunting for.

- **The Failed vs Successful login graph tells the whole story of a brute force.** Seeing the Failed line spike for 90 seconds and then a single Successful event appear at the end shows the exact moment the attacker achieved their goal. That transition from failed to successful is the most important moment in the timeline of a credential attack.

- **Visual pattern recognition is a core analyst skill.** After running several timechart searches I started recognising attack patterns by shape before reading the numbers -- the sharp narrow spike of an automated tool, the gradual ramp of a slow scan, the flat regular intervals of beaconing. Building this visual vocabulary is something that only comes from repeatedly looking at attack data.

- **The threshold line converts a timechart into a decision tool.** Without the threshold line a timechart shows activity. With it the chart shows whether that activity crossed the alert boundary -- turning a monitoring view into a detection view.

- **Splunk's chart type switcher is more useful than I expected.** The same data as a line chart and a column chart communicates differently. Line charts show trends and continuity. Column charts show discrete bursts. For a brute force attack the column chart is more honest -- it shows the attack as the discrete timed events it actually is rather than implying continuous smooth activity.

---

## 🔗 SOC Relevance

| Timechart Pattern | What It Indicates |
|---|---|
| Sharp narrow spike then silence | Automated tool ran briefly -- brute force, scanner |
| Regular low-volume intervals | C2 beaconing -- malware checking in |
| Gradual ramp over hours | Slow scan -- attacker trying to evade rate limits |
| Simultaneous spikes across sourcetypes | Coordinated attack affecting multiple systems |
| Failed spike followed by single Successful | Brute force succeeded -- credential compromise |
| 404 burst from single clientip | Web reconnaissance -- automated scanner |

---

## 🛠️ Tools I Used

- **Splunk Free** -- SIEM platform
- **Hydra** -- brute force tool to generate attack data
- **curl** -- HTTP client for Apache traffic generation
- **Kali Linux** -- lab environment
- **Log sources:** linux_secure, syslog, access_combined

---

*Project 04 of 14 · [Back to Main Portfolio](../README.md)*
