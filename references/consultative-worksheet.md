# Consultative Threat Hunting Worksheet: Mapping Security Intent to Behavioral Analytics

> ⚡ **JETSKI / MCP AGENT INSTRUCTION**:
> Inspect this master worksheet during **Phase 1A** when an analyst specifies an entity or hunting objective without naming an exact statistical model or telemetry metric.
> 
> **EXPERT BYPASS RULE**: If the analyst provides both the target metric (e.g. `network_bytes_outbound`) and statistical model (e.g. `MAD` or `Z-score`), **DO NOT CONSULT**. Bypass this worksheet immediately and emit the Pre-Flight Card.

---

## 🧭 First Principles: The 5 Behavioral Telemetry Deformations

Every threat—known, emerging, or zero-day—physically deforms telemetry in one of five distinct ways. When an analyst describes a scenario, classify the underlying deformation to select the optimal statistical model:

```
┌─────────────────────────────┬───────────────────────────────┬──────────────────────────────────────┐
│ Telemetry Deformation       │ Physical Telemetry Signature │ Recommended Mathematical Model       │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 1. Persistent Accumulation  │ Low-and-slow volume creep      │ Longitudinal CUSUM Drift             │
│    ("The Slow Creep")       │ staying below static alerts   │ or Poisson Rarity                    │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 2. State Transition         │ Transition from 0 to positive │ Two-Part Hurdle Model                │
│    ("The Dormancy Break")   │ activity (volume is minor)    │ (Zero-Inflation Logistic Gate)       │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 3. Volumetric Shock         │ Sudden explosive surge over   │ Piecewise CRI (The Shock Absorber)   │
│    ("The Spiky Rupture")    │ individual/peer baseline      │ or Asymmetric Directional Z (ReLU)   │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 4. Volatility Regularity    │ Unnatural clockwork intervals │ Hourly Temporal Z-Score              │
│    ("The Machine Pulse")    │ or collapsed entropy (C2)     │ or Fano Factor / Dispersion          │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 5. Orthogonal Dispersion    │ Mild elevations across 3–5    │ 360° Decoupled Behavioral Radar      │
│    ("The Multi-Vector Fog") │ unrelated telemetry sectors   │ with Euclidean Distance (D >= 3.5σ)  │
└─────────────────────────────┴───────────────────────────────┴──────────────────────────────────────┘
```

---

## 🎯 The Three Threat Tiers

### Tier 1: Known Knowns (Immediate SOC Objectives)
* **High-Volume Exfiltration**: Mass downloads, large network egress (`workspace_total_download_actions`, `network_bytes_outbound`).
* **Credential Stuffing & Sprays**: High auth failures with IP rotation (`auth_attempts_fail`).
* **Unauthorized Process Launches**: Suspicious binaries on endpoints (`file_executions_*`).
* **Rogue Cloud Infrastructure**: Spikes in VM or container provisioning (`resource_creation_total`).

### Tier 2: Known Unknowns (High-Impact Threats Static Rules Miss)
* **Administrative Sabotage & Evidence Deletion**: Bulk deletion of storage buckets, logs, or IAM changes (`resource_deletion_*`, `workspace_total_change_actions`).
* **Low-Volume Lateral Reconnaissance**: Dormant service account enumerating new databases or configs (`resource_read_total`).
* **Covert Signaling & DNS Egress**: High DNS payload volumes or NXDOMAIN ratios bypassing web proxies (`dns_bytes_outbound`, `dns_queries_fail`).
* **Email-Based Exfiltration & Phishing**: Spikes in sent messages from compromised accounts (`workspace_emails_sent_total`).
* **Defense Evasion via Alert Dilution**: Sub-threshold EDR alert accumulation on critical servers (`alert_event_name_count`).

### Tier 3: Unknown Unknowns (Complex Multi-Vector Discovery)
* **Cross-Sector Multi-Vector Drift**: Advanced insider threat or persistent campaign where no single event or metric breaches static thresholds, but the compound vector trajectory reveals an anomalous kill chain (`D >= 3.5σ` across 5 sectors).

---

## 📋 The 5 Canonical Hunting Domains & Summary View Menus

When engaging the analyst during Phase 1A, use the **Summary View** templates below to present 2–3 targeted hypotheses mapped to the failure modes of static detection rules.

### Domain 1: Data Hoarding & Exfiltration
* **Why Static Rules Miss It**: Fixed threshold alerts (e.g. `bytes > 5GB`) are easily bypassed by chunked daily transfers (e.g. 400MB/day), and blanket rules cannot distinguish routine developer egress from unauthorized dumps.
* **Summary View Options**:
  1. *Low-and-Slow Trickle*: Accumulate minor daily upload deviations over 14–30 days (**Longitudinal CUSUM Drift** on `network_bytes_outbound`).
  2. *Bulk Hoarding Burst*: Penalize sudden exponential download surges while absorbing routine daily variance (**Piecewise CRI / Shock Absorber** on `workspace_total_download_actions`).
  3. *Covert Protocol Egress*: Detect data staging and tunneling via DNS queries (**Poisson-Gamma Bayesian** on `dns_bytes_outbound`).
* *Deep Dive Guide*: `references/consultative/data-exfiltration.md`

### Domain 2: Identity, Credential Abuse & Privilege Drift
* **Why Static Rules Miss It**: Attackers rotate source IPs and stay below lockout thresholds (e.g. 3 attempts/hour), while dormant service accounts and API tokens are never monitored for first-time use.
* **Summary View Options**:
  1. *Low-Frequency Credential Spray*: Detect rare failure clusters across multiple users without tripping lockouts (**Beta-Binomial Bayesian** on `auth_attempts_fail`).
  2. *Dormant Account Wakeup*: Surface idle users or service accounts suddenly initiating sessions (**Two-Part Hurdle Model** on `auth_attempts_success` or `workspace_auth_attempts_total`).
  3. *Off-Hours / Unusual Login Volume*: Identify sudden access surges against a user's 30-day baseline (**Standard Z-Score** on `auth_attempts_total`).
* *Deep Dive Guide*: `references/consultative/identity-and-access.md`

### Domain 3: Cloud Infrastructure Tampering & Sabotage
* **Why Static Rules Miss It**: Cloud admin accounts frequently generate noise; static rules either trigger endless false positives or are tuned down, missing rogue infrastructure creations and bulk deletions.
* **Summary View Options**:
  1. *Dormant Service Account Provisioning*: Flag inactive service accounts suddenly spinning up compute or storage (**Two-Part Hurdle Model** on `resource_creation_total`).
  2. *High-Velocity Sabotage*: Detect explosive spikes in resource deletions while ignoring normal system updates (**Asymmetric Directional Z** on `resource_deletion_total`).
  3. *Cross-Database Enumeration*: Isolate service account access strictly by vendor, product, and resource name to catch unauthorized sweeps (**Local-Baseline Isolation** on `resource_read_total`).
* *Deep Dive Guide*: `references/consultative/cloud-infrastructure.md`

### Domain 4: Endpoint Activity, Living-off-the-Land & Covert Signaling
* **Why Static Rules Miss It**: Attackers utilize dual-use built-in utilities (`powershell.exe`, `certutil.exe`) or communicate via periodic low-frequency beacons that generate no discrete EDR detections.
* **Summary View Options**:
  1. *Time-of-Day Execution Anomalies*: Detect endpoint binary launches occurring during historically dead hours (**Hourly Temporal Z-Score** on `file_executions_total`).
  2. *Living-off-the-Land Surge*: Surface statistically rare binary executions for a specific host and hash (**Poisson Rarity** on `file_executions_success`).
  3. *EDR Alert Accumulation*: Detect subtle increases in vendor alerts on critical assets before an incident is declared (**Longitudinal CUSUM Drift** on `alert_event_name_count`).
* *Deep Dive Guide*: `references/consultative/endpoint-and-covert.md`

### Domain 5: Comprehensive Insider Risk & Multi-Vector Health Check
* **Why Static Rules Miss It**: Security tools operate in operational silos. Individual telemetry logs (a few extra logins, a few extra file downloads, mild cloud reads) appear completely benign in isolation.
* **Summary View Options**:
  1. *360° Multi-Sector Radar*: Profile Authentication, Cloud CRUD, Google Workspace, Network Egress, and DNS simultaneously against 30-day baselines (**Euclidean Distance D >= 3.5σ**).
  2. *Peer Group Discrepancy*: Compare an individual's multi-vector footprint against their departmental peers (**Fleet Prevalence Shield**).
* *Deep Dive Guide*: `references/consultative/insider-risk-360.md`

---

## 🎛️ Pre-Flight Card Assembly Instructions

Once the analyst selects an option (or agrees to a proposed hypothesis), formulate the **Pre-Flight Card** using operational language:

```markdown
PRE-FLIGHT HUNTING SPECIFICATION:
• Target Entity / Scope:  [Target User/Host ID, Team Cohort, or Fleet]
• Threat Hypothesis:      [Hypothesis Summary: e.g. Low-and-Slow Exfiltration avoiding volume alerts]
• Recommended Method:     [Model Name, e.g. Longitudinal CUSUM Drift (Solves threshold evasion)]
• Baseline Horizon Spine: 30-Day Pre-Computed (period: 1d, window: 30d)
• Significance Threshold: [High Confidence (Z >= 3.0σ) | Investigative Band (2.0σ <= Z < 3.0σ) | D >= 3.5σ]
• Evaluation Horizon:     Fleet Ranking Today (Option A) vs. 30-Day Daily Timeline (Option B)
```
