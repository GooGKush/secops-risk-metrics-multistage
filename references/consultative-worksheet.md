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
* **Cross-Sector Multi-Vector Drift**: Advanced insider threat or persistent campaign where no single event or metric breaches static thresholds, but the compound vector trajectory reveals an anomalous kill chain (`D >= 3.5σ` across 6 sectors).

---

## 🔬 Common-Sense Analytical Rigor: The 4 Investigative Inquiries

Analytical rigor strengthens threat hunting when grounded in clear, practical security questions. Rather than confronting an analyst with abstract statistical formulas, lead with common-sense inquiries that establish falsifiability, verify baseline integrity, and rule out innocent explanations:

```
┌─────────────────────────────────┬───────────────────────────────────┬────────────────────────────────────────────────────────┐
│ Statistical Discipline          │ Common-Sense SOC Inquiry          │ Operational Security Context                           │
├─────────────────────────────────┼───────────────────────────────────┼────────────────────────────────────────────────────────┤
│ 1. Hypothesis & Falsifiability │ The "What Proves It Innocent?"    │ Identify normal operational activities (scheduled     │
│                                 │ Check                             │ backups, maintenance, bulk data transfers) and agree  │
│                                 │                                   │ on what evidence would immediately rule out a threat.  │
├─────────────────────────────────┼───────────────────────────────────┼────────────────────────────────────────────────────────┤
│ 2. Zero-Inflation / Dormancy    │ The "Quiet Entity Trap"           │ Determine whether the entity is normally active daily  │
│                                 │ Check                             │ or mostly dormant. For dormant accounts, apply a       │
│                                 │                                   │ tripwire hurdle instead of a standard volume curve.    │
├─────────────────────────────────┼───────────────────────────────────┼────────────────────────────────────────────────────────┤
│ 3. Skew & Baseline Distortion   │ The "Past Noise Camouflage"       │ Check whether historical bulk jobs inflate arithmetic  │
│                                 │ Check                             │ averages. Use distortion-proof medians (MAD) to keep   │
│                                 │                                   │ past one-off spikes from masking subtle new attacks.   │
├─────────────────────────────────┼───────────────────────────────────┼────────────────────────────────────────────────────────┤
│ 4. Confounder Elimination       │ The "Crowd / Patch Tuesday"       │ Check whether many peers are experiencing the same     │
│                                 │ Check                             │ surge concurrently. Apply fleet prevalence shielding   │
│                                 │                                   │ to discount shared enterprise-wide activities.         │
└─────────────────────────────────┴───────────────────────────────────┴────────────────────────────────────────────────────────┘
```

---

## 🗣️ Dual-Register Conversational Alignment

The consultative dialogue adapts dynamically to the analyst's background while maintaining full analytical rigor:

* **Default Register (Operational SOC Analyst)**: Use intuitive, physical terminology. Frame choices around operational outcomes, innocent explanations, and practical triage SLAs.
* **Specialist Register (Data Science / Quantitative Hunter)**: When the analyst uses formal mathematical concepts (e.g., *MAD*, *Poisson rate*, *CUSUM slack parameter*, *Beta-Binomial shrinkage*), match their vocabulary with formal statistical formulations ($H_0/H_1$, non-parametric breakdown points, dispersion ratios, prior confidence weighting).

| Operational SOC Question | Formal Data Science Equivalent | Mathematical Grounding |
| :--- | :--- | :--- |
| *"What normal activity could explain this?"* | Null Hypothesis ($H_0$) & Disproof Criterion | $H_0: x_t \sim F_0(\mu, \sigma^2)$ vs. $H_1: x_t \sim F_1$; specify rejection bound. |
| *"Is this account normally silent?"* | Zero-Inflation / Sparsity Verification | Two-Part Hurdle: Logistic activation gate $P(X > 0)$ + conditional continuous volume. |
| *"Could past huge transfers distort the average?"* | Heavy-Tail / Skewness Assessment | Breakdown point $50\%$ (MAD / Median) vs. $0\%$ (Gaussian Mean $\bar{x}$). |
| *"Are other machines doing this right now?"* | Confounder / Covariate Control | Dual-Plane Hyperbolic Dampening $1.0 / (k_{\text{fleet}} + 1.0)$ on shared token. |
| *"How high should we set the alarm bar?"* | Significance Level & Tail Probability | Chebyshev bound ($P \le 11.1\%$ at $3\sigma$) vs. Gaussian tail ($\alpha = 0.0013$). |

---

## 📋 The 6 Canonical Hunting Domains & Summary View Menus

When engaging the analyst during Phase 1A, use the **Summary View** templates below to present 2–3 targeted hypotheses mapped to the failure modes of static detection rules.


### Domain 1: Data Hoarding & Exfiltration
* **Why Static Rules Miss It**: Fixed threshold alerts (e.g. `bytes > 5GB`) are easily bypassed by chunked daily transfers (e.g. 400MB/day), and blanket rules cannot distinguish routine developer egress from unauthorized dumps.
* **Common-Sense Rigor Check**: Check for scheduled backups, cloud file synchronization, or developer builds before assuming exfiltration; use median-anchored baselines (MAD) when historic large transfers distort averages.
* **Summary View Options**:
  1. *Low-and-Slow Trickle*: Accumulate minor daily upload deviations over 14–30 days (**Longitudinal CUSUM Drift** on `network_bytes_outbound`).
  2. *Bulk Hoarding Burst*: Penalize sudden exponential download surges while absorbing routine daily variance (**Piecewise CRI / Shock Absorber** on `workspace_total_download_actions`).
  3. *Covert Protocol Egress*: Detect data staging and tunneling via DNS queries (**Poisson-Gamma Bayesian** on `dns_bytes_outbound`).
  4. *Multilevel Network Triad Breakout*: Compare Outbound, Inbound, and Total Byte volume simultaneously against team cohort and enterprise wholes to catch asymmetric data siphoning (**Part-of-the-Whole Triad** via `part_of_the_whole_triad_multilevel.yl2`).
  5. *High-Frequency Session Surge & C2 Beaconing*: Detect micro-payload, high-frequency outbound connection bursts that bypass volumetric thresholds (**Flow Frequency Anomaly** on `network_flows_outbound` via `c2_beacon_flow_frequency_2stage.yl2`).
* *Deep Dive Guide*: `references/consultative/data-exfiltration.md`

### Domain 2: Identity, Credential Abuse & Privilege Drift
* **Why Static Rules Miss It**: Attackers rotate source IPs and stay below lockout thresholds (e.g. 3 attempts/hour), while dormant service accounts and API tokens are never monitored for first-time use.
* **Common-Sense Rigor Check**: Distinguish dormant service accounts (tripwire hurdle) from daily active users; verify whether password expiration policies or VPN re-authentications explain auth failure spikes.
* **Summary View Options**:
  1. *Low-Frequency Credential Spray*: Detect rare failure clusters across multiple users without tripping lockouts (**Beta-Binomial Bayesian** on `auth_attempts_fail`).
  2. *Dormant Account Wakeup*: Surface idle users or service accounts suddenly initiating sessions (**Two-Part Hurdle Model** on `auth_attempts_success` or `workspace_auth_attempts_total`).
  3. *Off-Hours / Unusual Login Volume*: Identify sudden access surges against a user's 30-day baseline (**Standard Z-Score** on `auth_attempts_total`).
  4. *Multilevel Authentication Triad*: Simultaneously compare an individual's Total, Failed, and Successful attempts against their peer team cohort and enterprise whole to distinguish high legitimate login volume from targeted credential attacks (**Part-of-the-Whole Triad** via `part_of_the_whole_triad_multilevel.yl2`).
* *Deep Dive Guide*: `references/consultative/identity-and-access.md`

### Domain 3: Cloud Infrastructure Tampering & Sabotage
* **Why Static Rules Miss It**: Cloud admin accounts frequently generate noise; static rules either trigger endless false positives or are tuned down, missing rogue infrastructure creations and bulk deletions.
* **Common-Sense Rigor Check**: Screen for automated Terraform / CI/CD pipeline deployments or cloud provider maintenance before concluding administrative sabotage.
* **Summary View Options**:
  1. *Cloud Resource CRUD & Data Access Mutations (Focus 1)*: Monitor sensitive data access, bulk resource reads, and infrastructure deletions across cloud repositories (**Dual-Branch Directional Z-Score** on `metrics.resource_read_total` and `metrics.resource_deletion_total` with `$vendor` and `$product` via `cloud_repository_scope_dual_branch.yl2`).
  2. *Dormant Service Account Provisioning & Token Drift (Focus 2)*: Detect inactive service accounts suddenly spinning up compute or initiating privileged API sessions (**Two-Part Hurdle Model** on `metrics.resource_creation_total`).
  3. *Cross-Vector Behavioral Radar & Health Check (Focus 3)*: Profile service account activity omnidirectionally across Cloud, Auth, Workspace, Network, DNS, and Web & Proxy (**6-Sector Behavioral Radar** with Euclidean Distance D >= 3.5σ).
* *Deep Dive Guide*: `references/consultative/cloud-infrastructure.md`

### Domain 4: Endpoint Activity, Living-off-the-Land & Covert Signaling
* **Why Static Rules Miss It**: Attackers utilize dual-use built-in utilities (`powershell.exe`, `certutil.exe`) or communicate via periodic low-frequency beacons that generate no discrete EDR detections.
* **Common-Sense Rigor Check**: Verify whether new process launches or hash sightings coincide with fleetwide software updates (Fleet Prevalence Shield on SHA256) or administrative cron schedules.
* **Summary View Options**:
  1. *Time-of-Day Execution Anomalies*: Detect endpoint binary launches occurring during historically dead hours (**Hourly Temporal Z-Score** on `file_executions_total`).
  2. *Living-off-the-Land Surge*: Surface statistically rare binary executions for a specific host and hash (**Poisson Rarity** on `file_executions_success`).
  3. *EDR Alert Accumulation*: Detect subtle increases in vendor alerts on critical assets before an incident is declared (**Longitudinal CUSUM Drift** on `alert_event_name_count`).
  4. *Enterprise Software Rollout / Patch Tuesday Normalization*: Separate targeted endpoint malware execution from corporate package updates (**Archetype 3: Dual-Plane Fleet Prevalence Normalization** via `templates/pipelines/hybrid_metric_fleet_prevalence_2stage.yl2` using token-centric match topology `$token by 1d` on binary hash `target.process.file.sha256 = $token` and hyperbolic prevalence dampener `1.0 / (k_fleet + 1.0)`).
* *Deep Dive Guide*: `references/consultative/endpoint-and-covert.md`

### Domain 5: Comprehensive Insider Risk & Multi-Vector Health Check
* **Why Static Rules Miss It**: Security tools operate in operational silos. Individual telemetry logs (a few extra logins, a few extra file downloads, mild cloud reads) appear completely benign in isolation.
* **Common-Sense Rigor Check**: Require simultaneous elevation across multiple decoupled sectors before declaring high risk; rule out single-vector spikes that reflect normal isolated operational duties.
* **Summary View Options**:
  1. *360° Multi-Sector Radar*: Profile Authentication, Cloud CRUD, Google Workspace, Network Egress, DNS, and Web & Proxy Activity simultaneously against 30-day baselines (**Euclidean Distance D >= 3.5σ**).
  2. *Peer Group Discrepancy*: Compare an individual's multi-vector footprint against their departmental peers (**Fleet Prevalence Shield**).
* *Deep Dive Guide*: `references/consultative/insider-risk-360.md`

### Domain 6: Web, Proxy & Covert HTTP Channels
* **Why Static Rules Miss It**: Fixed User-Agent blacklists are bypassed by standard browser spoofing or legitimate system agents, fixed error thresholds miss low-and-slow directory fuzzing and API enumeration, and enterprise browser updates trigger false-positive storms.
* **Common-Sense Rigor Check**: Check whether proxy error surges or User-Agent shifts reflect corporate browser updates, CDN misconfigurations, or identity provider timeouts rather than automated web fuzzing.
* **Summary View Options**:
  1. *User-Agent Tooling vs. Enterprise Rollout*: Separate individual novel User-Agent adoption from fleetwide browser updates using dual-plane hyperbolic prevalence dampening (**Fleet Prevalence Shield** via `hybrid_metric_http_ua_prevalence_2stage.yl2` on `metrics.http_queries_total`).
  2. *Web Application / Proxy Error Ratio Surge*: Detect web fuzzing, API enumeration, or broken exfiltration loops by evaluating $4xx/5xx$ failure baseline departures alongside in-stage failure ratio (**Two-Stage Error Ratio Surge** via `http_error_ratio_surge_2stage.yl2` on `metrics.http_queries_fail`).
  3. *Web Server & Cloud API Hammering*: Isolate acute volumetric departures against a specific web host or API gateway to detect DoS or automated scraping (**Target-Centric Surge** via `http_target_surge_2stage.yl2` on `metrics.http_queries_total` with `target.hostname`).
  4. *Multilevel Web Request Triad*: Simultaneously compare an entity's Total, Successful, and Failed HTTP queries against their peer cohort and enterprise baseline (**Part-of-the-Whole Triad** via `part_of_the_whole_triad_multilevel.yl2`).
* *Deep Dive Guide*: `references/consultative/web-and-proxy.md`

---

## 🎛️ Pre-Flight Card Assembly & Dialogue Protocol

Once the analyst selects an option (or agrees to a proposed hypothesis), formulate the **Pre-Flight Card** using operational, common-sense language:

```markdown
PRE-FLIGHT HUNTING SPECIFICATION:
• Target Entity / Scope:  [Target User/Host ID, Team Cohort, or Fleet]
• Threat Hypothesis:      [Specific abnormal behavior under investigation, e.g. Low-and-Slow Exfiltration]
• Rule-Out Condition:     [Innocent explanation criteria, e.g. fleet concurrence > 5 or approved maintenance]
• Baseline Integrity:    [Distortion-Proof (Median/MAD) | Standard Average (Z-score) | Hurdle (Tripwire)]
• Activity Profile:       [Active Daily Baseline vs. Dormant Account Tripwire]
• Crowd Shield:           [Active (dampens fleet-wide spikes) | N/A (isolated target)]
• Recommended Method:     [Model Name, e.g. Longitudinal CUSUM Drift (Solves threshold evasion)]
• Baseline Horizon Spine: 30-Day Pre-Computed (period: 1d, window: 30d)
• Significance Threshold: [High Confidence (Z >= 3.0σ) | Investigative Band (2.0σ <= Z < 3.0σ) | D >= 3.5σ]
• Evaluation Horizon:     Fleet Ranking Today (Option A) vs. 30-Day Daily Timeline (Option B)
```

---

## 🔄 Pre-Flight Tuning & Clarification Loop

When the analyst asks a question or requests parameter adjustments prior to giving Mode A/B clearance:

1. **Answer Conversationally**: Address the question directly using plain-English analogies or data-science depth matching the analyst's conversational register.
2. **Maintain Active Context**: Retain the active entity scope, telemetry vectors, and hunt objective in working context.
3. **Update Specification**: Present the updated Pre-Flight Card reflecting the adjusted parameters (threshold, horizon, baseline model).
4. **Re-Verify Query**: Probe the updated multi-stage YARA-L query via `udm_search` when query logic changes, and display the refreshed candidate query block.
5. **Prompt for Clearance**: Conclude by asking whether to proceed with Mode A (Today vs 30-Day Baseline) or Mode B (2–14 Day Timeline).

