# Consultative Threat Hunting Worksheet: Mapping Security Intent to Behavioral Analytics

> ⚡ **JETSKI / MCP AGENT INSTRUCTION**:
> Inspect this master worksheet during **Phase 1A** when an analyst specifies an entity or hunting objective without naming an exact statistical model or telemetry metric.
> 
> **EXPERT BYPASS RULE**: If the analyst provides both the target metric (e.g. `network_bytes_outbound`) and statistical model (e.g. `MAD` or `Z-score`), **DO NOT CONSULT**. Bypass this worksheet immediately and emit the Pre-Flight Card.

---

## 🧭 First Principles: The 10 Behavioral Telemetry Deformations

Every threat—known, emerging, or zero-day—physically deforms telemetry in one of ten distinct ways (6 volumetric/temporal + 4 structural/directional/geospatial/contextual). When an analyst describes a scenario, classify the underlying deformation to select the optimal statistical model:

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
│ 4. Volatility Regularity    │ Unnatural clockwork intervals │ Circadian von Mises Temporal Dist    │
│    ("The Machine Pulse")    │ or cyclic 24h clock shifts    │ or Hourly Temporal Z-Score / Fano    │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 5. Orthogonal Dispersion    │ Mild elevations across 3–5    │ 360° Decoupled Behavioral Radar      │
│    ("The Multi-Vector Fog") │ unrelated telemetry sectors   │ with Euclidean Distance (D >= 3.5σ)  │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 6. Kinetic Acceleration     │ Runaway velocity departure    │ MACD Dual-Spine Momentum Indicator   │
│    ("The Runaway Train")    │ breaking historical ceilings  │ (Fast vs Slow Velocity Divergence)   │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 7. Bipartite Graph Topology │ 1→N fan-out (lateral scan /   │ East-West Lateral Fan-Out Fusion or  │
│    ("The Web / Staging Hub")│ spray) or N→1 fan-in staging  │ Privileged Lateral Expansion (Handoff│
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 8. Directional Flow Ratio   │ Net consumer flips to net     │ Part-of-the-Whole Network Triad or   │
│    ("Role Inversion")       │ producer (log(out+1)-log(in+1)│ Producer–Consumer Ratio Inversion    │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 9. Geospatial Kinematics    │ Consecutive logins exceeding  │ Impossible Travel Geo-Velocity       │
│    ("Impossible Travel")    │ physical flight speed (>800kmh│ (math.geo_distance / Δt; Handoff)    │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 10. Persona & Event Priors  │ Sensitivity conditioned on    │ Data Table Priors (%ueba_entity_     │
│    ("Role / T0 Changepoint")│ actor class or T0 regime shift│ priors) + Dual-Baseline Delta-Z      │
└─────────────────────────────┴───────────────────────────────┴──────────────────────────────────────┘
```

### 👤 Persona-Conditioned Prior Matrix (Condition Before Model Selection)
Before selecting a mathematical model in Phase 1A/1B, condition the statistical prior on the target actor class:
* **Interactive Human User**: High diurnal variance and broad process/destination diversity are normal. *Diagnostic Deformations*: Circadian phase shift (`circadian_von_mises_2stage.yl2`), peer-cohort divergence (`part_of_the_whole_multilevel.yl2`), or machine-like low jitter (`CV <= 0.20`).
* **Service Account / Daemon / Workload Identity**: Near-zero variance (`$stddev == 0`) and fixed origin IP/host are normal. *Diagnostic Deformations*: Origin-IP/host breadth expansion (`> 1` source IP), interactive logon types, or first-time repository access (`cloud_repository_scope_dual_branch.yl2` / `two_part_hurdle.yl2`).
* **CI/CD Runner / Admin Jump Host / Ephemeral Compute**: High process launch churn is normal; outbound network destinations follow a strict allowlist. *Diagnostic Deformations*: Rare external domain/IP contact (`rare_destination_ecg_3stage.yl2`), parent-child Markov transition surprisal, or Zipfian long-tail binary execution.

### ⏱️ Pre/Post Event-Anchored Changepoint Framing ($T_0$ Regime Shift)
When an analyst asks *"Did behavior change after event $T_0$?"* (e.g., IAM role grant, credential reset, MFA re-registration, or HR offboarding notice):
* Anchor the 30-day pre-computed baseline (`period: 1d, window: 30d`) to the pre-event regime $[T_0 - 30\text{d}, T_0)$ and evaluate the post-$T_0$ window $[T_0, \text{now})$ using **Mode B (`TIMELINE_BREAKDOWN`)** or **Longitudinal CUSUM (`longitudinal_cusum.yl2`)** to isolate persistent post-event regime drift.

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
│                                 │ Check                             │ averages. Use MAD or 1-stage Quantile/Bowley Skewness  │
│                                 │                                   │ (QUANTILE_IQR_SKEW) to defeat baseline masking.        │
├─────────────────────────────────┼───────────────────────────────────┼────────────────────────────────────────────────────────┤
│ 4. Confounder Elimination       │ The "Crowd / Patch Tuesday"       │ Check whether many peers are experiencing the same     │
│                                 │ Check                             │ surge concurrently. Apply fleet prevalence shielding   │
│                                 │                                   │ to discount shared enterprise-wide activities.         │
└─────────────────────────────────┴───────────────────────────────────┴────────────────────────────────────────────────────────┘
```

### 🛠️ Executable Confounder Disambiguation & SecOps Data Table Controls
Pair each of the 4 Investigative Inquiries with its concrete query-level control or SecOps Data Table (`%<table_name>`) join:
1. **Innocent Explanation Control**: Exclude known vulnerability scanners or scheduled maintenance windows via Data Table join (`not $entity in %authorized_scanners.hostname`) or VIP/departing-employee risk prior weights (`$entity = %ueba_entity_priors.entity`).
2. **Quiet Entity Trap Control**: Route dormant accounts ($N < 7$ active baseline days) to `two_part_hurdle.yl2` or `poisson_rarity.yl2` rather than standard Gaussian $Z$-scores.
3. **Past Noise Camouflage Control**: Route heavy-tailed volumetric vectors to true Median Absolute Deviation (`stage2_math_models/mad.yl2`, `mad_robust_z_4stage.yl2`) or 1-Stage Non-Parametric Quantile & Skewness-Adjusted Tukey Fence (`stage2_math_models/quantile_iqr_skew.yl2`, `quantile_iqr_skew_3stage.yl2`), which computes `$p10, $q25, $q50, $q75, $p90` in 1 stage and frees Stage 3 for Entity Context Graph rarity filtering.
4. **Crowd / Patch Tuesday Control**: Apply `hybrid_metric_fleet_prevalence_2stage.yl2` (hyperbolic dampener `1.0 / ($k_fleet + 1.0)`) or `dual_baseline_3stage` ($\Delta Z = Z_{\text{personal}} - Z_{\text{fleet}}$). For cross-phase hunts (> 25 entities or persistent cohort bridging), upon explicit analyst approval in State 3 materialize Stage 1 suspect cohorts into `%ueba_hunt_bridge` (`hybrid_data_table_bridge_2stage.yl2`).

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

## 📋 The 7 Canonical Hunting Domains & Summary View Menus

When engaging the analyst during Phase 1A, use the **Summary View** templates below to present 2–3 targeted hypotheses mapped to the failure modes of static detection rules.

### Phase 1A Consultative Response Structure Mandate
Every Phase 1A consultative response must be formatted with the following explicit sections:
1. `### Threat Hypothesis`: Formulate the target security hypothesis, distinguishing malicious deformation from benign operational activity.
2. `### Summary View` (or `### Recommended Method`): Detail the recommended telemetry vectors, baseline metrics (`metrics.*`), and mathematical anomaly model.
3. `### Alternative Vectors`: Provide 2–3 alternate vectors or consultative pivots (e.g. Cloud vs. Asset vs. Handoff).

### Cross-Vector Pairing (when 2 or more vectors are relevant)
When the hypothesis touches two or more vectors, do not stop at listing them. Propose concrete pairs and the template that fuses them, using `references/metric-sector-catalog.md` (*Fusion pairing rules* and *Choosing the template for a cross-vector request*):
1. **Pick pairs that share an entity kind and identifier.** Name the join field for each pair, e.g. network bytes + HTTP on `principal.asset.ip`; failed logins + process execution on the host. Probe that the identifier is populated in both sectors before promising the pair (rule 7).
2. **Map each pair to a template**: two fusion-capable sectors → `dual_sector_fusion_3stage.yl2` (`multi_sector_fusion_4stage.yl2` to rank against the fleet); a composite-only sector (process execution, cloud resource, alert) → `rollup_sector_fusion_4stage.yl2`; three metrics of one family → the sibling triad; three or more families → the 360 radar's decoupled micro-queries (a query holds at most two event stages).
3. **Offer an Entity Graph filter** when a destination or binary is involved: rare domains or IPs (`rare_destination_ecg_3stage.yl2`, `fusion_rare_destination_3stage.yl2`) or rare binaries (derived file prevalence). It narrows; say that entities without a graph record drop out.
4. **Reject invalid pairs with the reason** (user ↔ host, no shared identifier, a third event sector) and offer the nearest valid pair.
5. Put the chosen pair, join field and template in the Pre-Flight Card (`Recommended Method`).


### Domain 1: Data Hoarding & Exfiltration
* **Why Static Rules Miss It**: Fixed threshold alerts (e.g. `bytes > 5GB`) are easily bypassed by chunked daily transfers (e.g. 400MB/day), and blanket rules cannot distinguish routine developer egress from unauthorized dumps.
* **Common-Sense Rigor Check**: Check for scheduled backups, cloud file synchronization, or developer builds before assuming exfiltration; use median-anchored baselines (MAD) when historic large transfers distort averages.
* **Summary View Options**:
  1. *Low-and-Slow Trickle*: Accumulate minor daily upload deviations over up to 14 days (**Longitudinal CUSUM Drift** on `network_bytes_outbound`; one request, the multi-stage search limit).
  2. *Bulk Hoarding Burst*: Penalize sudden exponential download surges while absorbing routine daily variance (**Piecewise CRI / Shock Absorber** on `workspace_total_download_actions`).
  3. *Covert Protocol Egress*: Detect data staging and tunneling via DNS queries (**Poisson-Gamma Bayesian** on `dns_bytes_outbound`).
  4. *Multilevel Network Triad Breakout*: Compare Outbound, Inbound, and Total Byte volume simultaneously against team cohort and enterprise wholes to catch asymmetric data siphoning (**Part-of-the-Whole Triad** via `part_of_the_whole_triad_multilevel.yl2`).
  5. *High-Frequency Session Surge & C2 Beaconing*: Detect micro-payload, high-frequency outbound connection bursts that bypass volumetric thresholds (**Flow Frequency Anomaly** on `network_flows_outbound` via `c2_beacon_flow_frequency_2stage.yl2`).
  6. *Context-Enhanced WHOIS Egress*: Cross-reference outbound transfer departures against WHOIS registration dates and expiration status to apply 2.5x–3.0x risk multipliers on Newly Registered Domains or expired infrastructure (**WHOIS Domain Lifecycle** via `templates/pipelines/hybrid_metric_whois_domain_lifecycle_2stage.yl2`).
  7. *Runaway Velocity Divergence*: Detect sudden, unconstrained egress acceleration that shatters historical 30-day ceilings (**MACD Dual-Spine Momentum Indicator** on `network_bytes_outbound` via `macd_momentum_velocity_2stage.yl2`).
  8. *Egress to Rare Destinations*: Score outbound bytes per host and keep only hosts that contacted domains or IPs seen on <= 3 hosts enterprise-wide (**Rare Destination Filter** via `rare_destination_ecg_3stage.yl2`).
  9. *1-Stage Quantile & Bowley Skewness Egress Fence*: Compute 5-point empirical quantiles (`$p10, $q25, $q50, $q75, $p90`), Bowley quartile skewness (`$bowley_skew`), and Skewness-Adjusted Tukey Fence alongside 30d `metrics.*` Z in 3 stages (**Quantile IQR Skew** via `quantile_iqr_skew_3stage.yl2`).
  10. *Intra-Bucket Per-Flow Payload Quantile Shape ($P_{50}$ vs $P_{90}$)*: Pair 30-day `metrics.network_bytes_outbound` macro Z-scores with in-stage `window.percentile(network.sent_bytes, 50)` and `window.percentile(network.sent_bytes, 90)` to expose stealth burst exfiltration hidden inside normal daily totals.
* *Deep Dive Guide*: `references/consultative/data-exfiltration.md`

### Domain 2: Identity, Credential Abuse & Privilege Drift
* **Why Static Rules Miss It**: Attackers rotate source IPs and stay below lockout thresholds (e.g. 3 attempts/hour), while dormant service accounts and API tokens are never monitored for first-time use.
* **Common-Sense Rigor Check**: Distinguish dormant service accounts (tripwire hurdle) from daily active users; verify whether password expiration policies or VPN re-authentications explain auth failure spikes.
* **Summary View Options**:
  1. *Low-Frequency Credential Spray*: Detect rare failure clusters across multiple users without tripping lockouts (**Beta-Binomial Bayesian** on `auth_attempts_fail`).
  2. *Dormant Account Wakeup*: Surface idle users or service accounts suddenly initiating sessions (**Two-Part Hurdle Model** on `auth_attempts_success` or `workspace_auth_attempts_total`).
  3. *Off-Hours / Unusual Login Volume*: Identify sudden access surges against a user's 30-day baseline (**Standard Z-Score** on `auth_attempts_total`).
  4. *Multilevel Authentication Triad*: Simultaneously compare an individual's Total, Failed, and Successful attempts against their peer team cohort and enterprise whole to distinguish high legitimate login volume from targeted credential attacks (**Part-of-the-Whole Triad** via `part_of_the_whole_triad_multilevel.yl2`).
  5. *Circadian Clock Phase Shift*: Catch off-hours or night-shift credential replay using circular 24-hour distance penalties without linear wrap distortion (**Circadian von Mises Temporal Distance** on `auth_attempts_total` via `circadian_von_mises_2stage.yl2`).
* *Deep Dive Guide*: `references/consultative/identity-and-access.md`

### Domain 3: Cloud Infrastructure Tampering & Sabotage
* **Why Static Rules Miss It**: Cloud admin accounts frequently generate noise; static rules either trigger endless false positives or are tuned down, missing rogue infrastructure creations and bulk deletions.
* **Common-Sense Rigor Check**: Screen for automated Terraform / CI/CD pipeline deployments or cloud provider maintenance before concluding administrative sabotage.
* **Summary View Options**:
  1. *Cloud Resource CRUD & Data Access Mutations (Focus 1)*: Monitor sensitive data access, bulk resource reads, writes, and infrastructure deletions across cloud repositories (**Dual-Branch Directional Z-Score** concurrently baselining destination reads via `metrics.resource_read_total`, destination writes via `metrics.resource_written_total`, and deletions via `metrics.resource_deletion_total` with `$vendor`, `$product`, and `$resource` via `cloud_repository_scope_dual_branch.yl2`).
  2. *Dormant Service Account Provisioning & Token Drift (Focus 2)*: Detect inactive service accounts suddenly spinning up compute or initiating privileged API sessions (**Two-Part Hurdle Model** on `metrics.resource_creation_total`).
  3. *Cross-Vector Behavioral Radar & Health Check (Focus 3)*: Profile service account activity omnidirectionally across Cloud, Auth, Workspace, Network, DNS, and Web & Proxy (**6-Sector Behavioral Radar** with Euclidean Distance D >= 3.5σ).
* *Deep Dive Guide*: `references/consultative/cloud-infrastructure.md`

### Domain 4: Endpoint Activity, Living-off-the-Land & Covert Signaling
* **Why Static Rules Miss It**: Attackers utilize dual-use built-in utilities (`powershell.exe`, `certutil.exe`) or communicate via periodic low-frequency beacons that generate no discrete EDR detections.
* **Common-Sense Rigor Check**: Verify whether new process launches or hash sightings coincide with fleetwide software updates (Fleet Prevalence Shield on SHA256) or administrative cron schedules.
* **Summary View Options**:
  1. *Time-of-Day Execution Anomalies*: Detect endpoint binary launches occurring during historically dead hours (**Hourly Temporal Z-Score** on `file_executions_total`).
  2. *Living-off-the-Land Surge*: Surface statistically rare binary executions for a specific host and hash (**Poisson Rarity** on `file_executions_success`).
  3. *EDR Alert Accumulation & Novel Rule Breakout*: Detect subtle increases or first-time rule firings (`$d_days = 0`) in vendor alerts on critical assets or user+host+process tuples before an incident is declared (**Longitudinal CUSUM Drift** or **2-Stage Alert Surge** on `alert_event_name_count` via `MultiStageTemplateRouter.build_alert_surge_query`).
  4. *Enterprise Software Rollout / Patch Tuesday Normalization*: Separate targeted endpoint malware execution from corporate package updates (**Archetype 3: Dual-Plane Fleet Prevalence Normalization** via `templates/pipelines/hybrid_metric_fleet_prevalence_2stage.yl2` using token-centric match topology `$token by 1d` on binary hash `target.process.file.sha256 = $token` and hyperbolic prevalence dampener `1.0 / (k_fleet + 1.0)`).
  5. *Derived Context File Prevalence Sieve*: Isolate execution bursts (`file_executions_total`, `file_executions_fail`, or `file_executions_success` across `ASSET` or `USER`) strictly to binaries observed on <= 3 endpoints across enterprise history, filtering out all high-prevalence corporate rollouts (**Derived File Prevalence** via `templates/pipelines/hybrid_metric_derived_file_prevalence_2stage.yl2`).
* *Deep Dive Guides*: `references/consultative/endpoint-and-covert.md`, `references/consultative/security-edr-alerts.md`

### Domain 5: Comprehensive Insider Risk & Multi-Vector Health Check
* **Why Static Rules Miss It**: Security tools operate in operational silos. Individual telemetry logs (a few extra logins, a few extra file downloads, mild cloud reads) appear completely benign in isolation.
* **Common-Sense Rigor Check**: Require simultaneous elevation across multiple decoupled sectors before declaring high risk; rule out single-vector spikes that reflect normal isolated operational duties.
* **Summary View Options**:
  1. *360° Multi-Sector Radar*: Profile Authentication, Cloud CRUD, Google Workspace, Network Egress, DNS, and Web & Proxy Activity simultaneously against 30-day baselines (**Euclidean Distance D >= 3.5σ**).
  2. *Peer Group Discrepancy*: Compare an individual against a named peer roster and the roster against the enterprise (**Part-of-the-Whole** via `part_of_the_whole_multilevel.yl2` or the triad; peers mentioned but not named → AD TEAM LOOKUP for the subject's team, then ask for the roster only if AD has none).
  3. *Pairwise Sector Fusion*: Fuse the two most relevant sectors for one entity (see *Cross-Vector Pairing* above; e.g. network bytes + HTTP via `dual_sector_fusion_3stage.yl2`, process execution + failed logins via `rollup_sector_fusion_4stage.yl2`).
* *Deep Dive Guide*: `references/consultative/insider-risk-360.md`

### Domain 6: Web, Proxy & Covert HTTP Channels
* **Why Static Rules Miss It**: Fixed User-Agent blacklists are bypassed by standard browser spoofing or legitimate system agents, fixed error thresholds miss low-and-slow directory fuzzing and API enumeration, and enterprise browser updates trigger false-positive storms.
* **Common-Sense Rigor Check**: Check whether proxy error surges or User-Agent shifts reflect corporate browser updates, CDN misconfigurations, or identity provider timeouts rather than automated web fuzzing.
* **Summary View Options**:
  1. *User-Agent Tooling vs. Enterprise Rollout*: Separate individual novel User-Agent adoption from fleetwide browser updates using dual-plane hyperbolic prevalence dampening (**Fleet Prevalence Shield** via `hybrid_metric_http_ua_prevalence_2stage.yl2` on `metrics.http_queries_total`).
  2. *Web Application / Proxy Error Ratio Surge*: Detect web fuzzing, API enumeration, or broken exfiltration loops by evaluating $4xx/5xx$ failure baseline departures alongside in-stage failure ratio (**Two-Stage Error Ratio Surge** via `http_error_ratio_surge_2stage.yl2` on `metrics.http_queries_fail`).
  3. *Web Server & Cloud API Hammering*: Isolate acute volumetric departures against a specific web host or API gateway to detect DoS or automated scraping (**Target-Centric Surge** via `http_target_surge_2stage.yl2` on `metrics.http_queries_total` with `target.hostname`).
  4. *Multilevel Web Request Triad*: Simultaneously compare an entity's Total, Successful, and Failed HTTP queries against their peer cohort and enterprise baseline (**Part-of-the-Whole Triad** via `part_of_the_whole_triad_multilevel.yl2`).
  5. *Derived Context Domain Rarity Sieve*: Filter HTTP request-count departures strictly to external hostnames observed on <= 3 endpoints enterprise-wide, pruning standard CDN and SaaS noise (**Derived Domain Prevalence** via `templates/pipelines/hybrid_metric_derived_domain_prevalence_2stage.yl2`). It counts requests only; outbound bytes to rare web domains is Domain 1 option 8 (`rare_destination_ecg_3stage.yl2`).
  6. *WHOIS Lifecycle & Expired Domain Check*: Detect web departures to Newly Registered Domains (NRD <= 30d) or expired domain infrastructure vulnerable to hijacking (**WHOIS Domain Lifecycle** via `templates/pipelines/hybrid_metric_whois_domain_lifecycle_2stage.yl2`).
* *Deep Dive Guide*: `references/consultative/web-and-proxy.md`

### Domain 7: MITRE ATT&CK Tactics & Multi-Stage Kill-Chain Progression
* **Why Static Rules Miss It**: Single-tactic alerts fire on isolated events that adversaries intentionally keep below static thresholds (e.g. $2.5\sigma$ per sector) or split across user identities, endpoints, and cloud service accounts.
* **Common-Sense Rigor Check**: Verify whether both stages of a multi-stage kill chain share a single entity class (`USER` or `ASSET`) for atomic Euclidean fusion ($D = \sqrt{\sum \max(0, Z_i)^2} \ge 3.5\sigma$), or cross entity boundaries requiring a Two-Phase Chained Bridge (`$user` $\leftrightarrow$ `$host` $\leftrightarrow$ `$caller_ip`, optionally materialized into `%ueba_hunt_bridge`).
* **Summary View Options**:
  1. *Same-Entity 2-Sector Kill-Chain Fusion*: Score two sequential MITRE tactics on the same entity (`RECON_ENUMERATION_TO_INITIAL_ACCESS`, `RESOURCE_DEV_NRD_TO_C2_EGRESS`, `CREDENTIAL_ACCESS_TO_EXECUTION`, `INITIAL_ACCESS_TO_DISCOVERY`, `EXECUTION_TO_C2_DNS`, `EXECUTION_TO_EXFILTRATION`, `CREDENTIAL_ACCESS_TO_LATERAL_MOVEMENT`, `EAST_WEST_LATERAL_FANOUT`, `CLOUD_DISCOVERY_TO_COLLECTION`, or `DEFENSE_EVASION_ALERT_TO_EXFILTRATION` via `dual_sector_fusion_3stage.yl2` / `rollup_sector_fusion_4stage.yl2`).
  2. *C2 Beaconing to Rare Destination Exfiltration*: Fuse outbound byte departures (`network_bytes_outbound`) with HTTP/DNS destination surges (`http_queries_total`) gated by Entity Context Graph rarity (`rolling_max <= 3`, `day_count = 10` via `C2_BEACON_TO_RARE_DESTINATION_EXFIL` / `fusion_rare_destination_3stage.yl2`).
  3. *Cross-Entity Two-Phase Kill-Chain Bridge*: Execute Phase 1 UEBA outlier detection to extract bridge keys (`$user`, `$host`, `$caller_ip`, `$sha256` or materialize into `%ueba_hunt_bridge`), then pivot into Phase 2 across the entity boundary (`USER_CREDENTIAL_TO_HOST_EXECUTION`, `HOST_EXECUTION_TO_CLOUD_SA_ACCESS`, `HOST_ALERT_TO_PROCESS_EXECUTION`, or `USER_WORKSPACE_HOARDING_TO_HOST_EGRESS`).
* *Deep Dive Guide*: `references/consultative/mitre-attack-killchain.md`

---

## 🎛️ Pre-Flight Card Assembly & Dialogue Protocol

Once the analyst selects an option (or agrees to a proposed hypothesis), formulate the **Pre-Flight Card** using operational, common-sense language:

```markdown
PRE-FLIGHT HUNTING SPECIFICATION:
• Target Entity / Scope:  [Target User/Host ID, Team Cohort, or Fleet]
• Threat Hypothesis:      [Specific abnormal behavior under investigation, e.g. Low-and-Slow Exfiltration]
• Baseline Horizon Spine: 30-Day (period: 1d, 30d)
• Peer Cohort & Roster:   [Team/Dept, e.g. IT (Frank, Tim) / N/A]
• Entity Graph Dimension: [Prevalence (day_count = 10, rolling_max <= 3) | WHOIS NRD (< 30d) | Infant Asset (< 7d) | N/A]
• Evaluation Horizon Mode:[chosen mode only: A today | B 2–7d + baseline dates | C per-day shards]
• Statistical Model:      [Model & Template, e.g. CUSUM Drift (`longitudinal_cusum.yl2`)]
• Significance Threshold: [Model gate (model-concordance-guide.md §2.1): Z >= 3.0σ | 2.0σ <= Z < 3.0σ | >= 2.0× baseline | D >= 3.5σ | N/A (Fano)]
```

---

## 🔄 Pre-Flight Tuning & Clarification Loop

When the analyst asks a question or requests parameter adjustments prior to giving Mode A/B clearance:

1. **Answer Conversationally**: Address the question directly using plain-English analogies or data-science depth matching the analyst's conversational register.
2. **Maintain Active Context**: Retain the active entity scope, telemetry vectors, and hunt objective in working context.
3. **Update Specification**: Present the updated Pre-Flight Card reflecting the adjusted parameters (threshold, horizon, baseline model).
4. **Re-Verify Query**: Probe the updated single-event UDM filter via `udm_search(maxEvents=1)` when query logic changes, and display the refreshed candidate query block.
5. **Prompt for Clearance**: Conclude by asking whether to proceed with Mode A (Today vs 30-Day Baseline) or Mode B (2–7 Day Fixed-Baseline Timeline), plus Mode C (Per-Day Baseline) when `run_command` is present.

---

## 📐 Non-Parametric Quantile, Bowley Skewness & Intra-Bucket Shape Patterns (`window.percentile`)

### Pattern 1: 4-Stage Quantile/Bowley Skewness Fence + Entity Context Graph Rare Domain Sieve
Because `stage quantile_envelope` computes `$q25, $q50, $q75` in **1 intermediate stage** (saving 1 stage compared to 2-stage `mad_center -> mad_spread`), Stage 3 is free to join `DERIVED_CONTEXT` domain prevalence (`rolling_max <= 3`, `day_count = 10`) in a single 4-stage query:

```yara
// Goal: Hunt for outbound byte surges that breach the Skewness-Adjusted Tukey Fence and contact rare external domains (<= 3 hosts)
stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $host
    target.hostname = $domain
    $host != ""
    $domain != ""

  match:
    $host, $domain by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)
    $in_scoring_window = max(if(timestamp.get_date(metadata.event_timestamp.seconds) >= "2026-10-21", 1, 0))
    $historical_avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $historical_stddev = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
}

stage quantile_envelope {
    $host = $stage1_extract.host

  match:
    $host

  outcome:
    $q25 = window.percentile($stage1_extract.observed_val, 25)
    $q50 = window.percentile($stage1_extract.observed_val, 50)
    $q75 = window.percentile($stage1_extract.observed_val, 75)
    $raw_active_days = count_distinct($stage1_extract.window_start)
}

stage stage3_rare_domain {
    $g.graph.metadata.entity_type = "DOMAIN_NAME"
    $g.graph.metadata.source_type = "DERIVED_CONTEXT"
    $g.graph.entity.domain.name = $domain
    $domain != ""
    $g.graph.entity.domain.prevalence.day_count = 10
    $g.graph.entity.domain.prevalence.rolling_max > 0
    $g.graph.entity.domain.prevalence.rolling_max <= 3

  match:
    $domain

  outcome:
    $domain_prevalence = min($g.graph.entity.domain.prevalence.rolling_max)
}

$host = $stage1_extract.host
$host = $quantile_envelope.host
$domain = $stage1_extract.domain
$domain = $stage3_rare_domain.domain
$ws = $stage1_extract.window_start

match:
  $host, $ws by 1d

outcome:
  $observed = sum($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $q25_val = max($quantile_envelope.q25)
  $q50_val = max($quantile_envelope.q50)
  $q75_val = max($quantile_envelope.q75)
  $raw_active_days = max($quantile_envelope.raw_active_days)
  $in_scoring_window = max($stage1_extract.in_scoring_window)
  $min_domain_prevalence = min($stage3_rare_domain.domain_prevalence)
  $rare_domains = array_distinct($domain)

  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $personal_z = ($observed - $hist_avg) / $safe_stddev

  $iqr = $q75_val - $q25_val
  $q50_floor = $q50_val * 0.05 + 1.0
  $safe_iqr = if($iqr > 0, $iqr, $q50_floor)
  $bowley_skew = ($q75_val + $q25_val - (2.0 * $q50_val)) / $safe_iqr
  $pos_skew = if($bowley_skew > 0, $bowley_skew, 0.0)
  $adj_upper_fence = $q75_val + (1.5 * math.pow(2.718281828, 3.0 * $pos_skew) * $safe_iqr)
  $safe_fence = if($adj_upper_fence > 0, $adj_upper_fence, 1.0)
  $tukey_fence_ratio = $observed / $safe_fence

condition:
  $in_scoring_window = 1 and $raw_active_days >= 7 and $tukey_fence_ratio >= 2.0

order:
  $tukey_fence_ratio desc
```

### Pattern 2: Macro 30-Day `metrics.*` Baseline + Intra-Bucket Per-Flow Payload Quantile Shape ($P_{50}$ vs $P_{90}$)
Pre-computed `metrics.network_bytes_outbound` tracks only the daily `sum(network.sent_bytes)`. By adding `window.percentile(network.sent_bytes, 50)` and `window.percentile(network.sent_bytes, 90)` directly inside `stage1_extract`, we simultaneously evaluate the 30-day macro $Z$-score AND the intra-day per-flow payload concentration (`$flow_tail_burst_ratio = $p90_bytes / $safe_p50`), exposing adversaries who hide high-volume burst uploads alongside routine small heartbeats:

```yara
// Goal: Combine 30-day metrics.network_bytes_outbound macro Z-score with intra-bucket per-flow P50/P90 payload quantile shape fingerprinting
stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = $host
    $host != ""

  match:
    $host by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)
    $flow_count = count(metadata.id)
    $flow_p50_bytes = window.percentile(network.sent_bytes, 50)
    $flow_p90_bytes = window.percentile(network.sent_bytes, 90)
    $historical_avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $historical_stddev = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $historical_active_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
}

$host = $stage1_extract.host
$ws = $stage1_extract.window_start

match:
  $host, $ws by 1d

outcome:
  $observed = max($stage1_extract.observed_val)
  $flows = max($stage1_extract.flow_count)
  $p50_bytes = max($stage1_extract.flow_p50_bytes)
  $p90_bytes = max($stage1_extract.flow_p90_bytes)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $personal_z = ($observed - $hist_avg) / $safe_stddev

  $safe_p50 = if($p50_bytes > 0, $p50_bytes, 1.0)
  $flow_tail_burst_ratio = $p90_bytes / $safe_p50

condition:
  $active_days >= 7 and $personal_z >= 2.0 and $flow_tail_burst_ratio >= 10.0

order:
  $flow_tail_burst_ratio desc
```
