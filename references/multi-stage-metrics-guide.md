# Multi-Stage Risk Metrics Implementation Guide

This guide details how to construct multi-stage YARA-L DAG queries that use pre-computed risk metrics as Stage 1 and execute statistical calculations in Stage 2+.

---

## 1. The Universal 6-Point Stage 1 Outcome Contract

To guarantee that any Stage 2+ mathematical model (Z-Score, MAD, Variance, Poisson, CV) can execute without variable mismatches, every Stage 1 `.yl2` template must emit this exact 6-variable outcome tuple:

```yara
outcome:
  // 1. Current 24h observed activity
  $observed_val = count(metadata.id) // or sum(network.sent_bytes)

  // 2. Pre-computed 30d historical mean
  $historical_avg = max(metrics.metric_name(
      period: 1d, window: 30d, metric: event_count_sum, agg: avg, ...
  ))

  // 3. Pre-computed 30d historical standard deviation
  $historical_stddev = max(metrics.metric_name(
      period: 1d, window: 30d, metric: event_count_sum, agg: stddev, ...
  ))

  // 4. Pre-computed 30d active baseline days (Confidence Floor)
  $historical_active_days = max(metrics.metric_name(
      period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods, ...
  ))

  // 5. Pre-computed 30d maximum peak observation
  $historical_max = max(metrics.metric_name(
      period: 1d, window: 30d, metric: event_count_sum, agg: max, ...
  ))

  // 6. Pre-computed 30d cumulative volume
  $historical_sum = max(metrics.metric_name(
      period: 1d, window: 30d, metric: event_count_sum, agg: sum, ...
  ))
```

---

## 2. Temporal Windowing: Intra-Day vs. 30-Day Baselines

Multi-stage DAG queries support two distinct temporal evaluation modes:

### Mode A: Cross-Sectional Fleet Outlier (24h Daily Bucket)
* **Stage 1:** `match: $entity by 1d` -> Evaluates the full 24-hour total per entity.
* **Stage 2:** `match: ` (empty group-by) -> Aggregates across the entire fleet population.
* **Root Stage:** `match: $entity, $window_start by 1d` -> Compares each entity against both its 30-day baseline and the fleet distribution.

### Mode B: Intra-Day Temporal Surge (1h Hourly Bucket)
* **Stage 1:** `match: $entity by 1h` -> Yields 24 distinct hourly observations per entity.
* **Stage 2:** `match: $entity` -> Aggregates intra-day statistics (`avg`, `stddev`, `window.median`) across all 24 hours for that entity.
* **Root Stage:** `match: $entity, $window_start by 1h` -> Pinpoints the specific anomalous hour within the 24-hour timeline.

---

## 3. Hourly Metrics Compiler Constraints (`period: 1h`)

1. **Window Lock:** When using `period: 1h`, the `window` parameter **must be `today`**.
2. **Mandatory Daily Metric Join:** Any query utilizing `period: 1h, window: today` **must also bind a daily metric (`period: 1d, window: 30d`)** for that entity in the same query.

---

## 4. Multi-Stage DAG Anti-Patterns to Avoid

| ❌ Anti-Pattern | ✓ Correct Practice | Why |
| :--- | :--- | :--- |
| `events:` header inside `stage` blocks | Declare predicates directly inside `stage name { ... }` | Stage blocks in Multi-Stage YARA-L do not use `events:`. |
| Wrapping the final stage in `stage name { ... }` | Unwrapped root level | The final stage must be at the root level of the query file. |
| Stage search window > 24h (e.g. 7d) | Clamp Stage 1 search window to exactly 24h / 1d | Daily metrics already embed 30 days of data; expanding search window causes metric duplicate joins. |
| `stage_name.$variable` or `stage_name.variable` | `$stage_name.variable` | In YARA-L, stage references require the leading `$` on the stage identifier (e.g. `$stage1_extract.actual`). Placing `$` after the dot causes an ANTLR syntax crash (`no viable alternative at input 'stage.$'`). |
| Cross-sector joins in 360° profiling (e.g. Auth + Egress) | Decoupled parallel micro-queries | Multi-stage queries are inner joins; joining orthogonal sectors silently drops entities with zero events in either sector. |
| Inverting `principal` vs `target` for User profiling | Use `target.user.userid` for `USER_LOGIN`; use `principal.user.userid` for Cloud CRUD, Workspace, Network, Endpoint | Login events target an account (`target.user.userid`); operational events are initiated by an actor (`principal.user.userid`). Metrics filters must match these dimensions. |
| Using Display Name in User metric filters (e.g. "James Holden") | Resolve to technical `userid` (e.g. "jholden") via spot check (`user_display_name = "<name>" nocase`) or user confirmation | Pre-computed `metrics.*` tables are indexed strictly by technical `user.userid`, never display names. Literal display names yield zero matches. |
| `graph.entity.metrics.*` in predicates | Use `metrics.*()` in `outcome:` | `metrics` is a built-in function, not an Entity Graph protobuf field. |
| Direct literal filter without match variable (`target.user.userid = "name"` with `match: $user`) | `target.user.userid = "name"`<br>`$user = target.user.userid` | Any placeholder variable in `match:` must be explicitly assigned to a UDM field in that stage's event predicates (`$user = target.user.userid`). |

---

## 5. Mandatory Non-Entity Dimension Filters

Certain pre-computed Risk Metrics require specific auxiliary UDM fields as dimension filters in addition to entity identifiers and values:

### File Executions (`metrics.file_executions_*`)
* **Mandatory Argument:** `metadata.event_type` **must** be passed as a filter in every `metrics.file_executions_*` call.
* **Syntax Example:**
  ```yara
  stage stage1_extract {
      $event_type = metadata.event_type
      $event_type = "PROCESS_LAUNCH"
      principal.asset.hostname = $host
      principal.process.file.sha256 = $sha256

    match:
      $host, $sha256 by 1d

    outcome:
      $hist_avg = max(metrics.file_executions_total(
          period: 1d, window: 30d, metric: event_count_sum, agg: avg,
          metadata.event_type: $event_type,
          principal.asset.hostname: $host,
          principal.process.file.sha256: $sha256
      ))
  }
  ```

---

## 6. Standard 3-Tier Tuning Pattern in Condition Blocks

Every multi-stage query generated for threat hunting should embed this standard tuning structure in its root `condition:` block:

```yara
condition:
  // --- TIER 0: Smoke Test Floor (Default) ---
  $observed_vol > 0

  // --- TIER 1: Strict / High Confidence Alerting (Uncomment to apply) ---
  // $observed_vol >= 10
  // and $active_days >= 7
  // and $sigma > 0
  // and $z_score >= 3.0

  // --- TIER 2: Balanced Threat Hunting (Uncomment to apply) ---
  // $observed_vol >= 5
  // and $active_days >= 5
  // and $sigma > 0
  // and $z_score >= 2.0

  // --- TIER 3: Broad Exploratory Discovery (Uncomment to apply) ---
  // $observed_vol >= 1
  // and $active_days >= 3
  // and ($z_score >= 1.5 or $surge_multiplier >= 2.0)
```

---

## 6. Inline Condition Tuning Pattern

For early iterations or broad requests, construct the `condition:` section with a permissive test floor and commented production parameters:

```yara
condition:
  // Permissive condition for smoke testing (returns all active results)
  $observed_val > 0

  // For a Strict/Production Hunt, replace the condition above with:
  // $observed_val >= 10
  // and $active_days >= 7
  // and $sigma > 0
  // and $z_score >= 3.0
```

---

## 7. How the UI Search Window & Root Match Keys Control Search Results

Understanding the interaction between the **UI Search Time Picker**, **Stage 1 Event Matching**, and **Root Stage Rollups** is essential to avoid query misinterpretation:

### 1. The UI Search Window Bounds Stage 1
* Stage 1 scans the raw UDM event log **strictly within the time boundaries selected in the UI time picker** (e.g. Last 48 Hours vs Last 30 Days).
* If your search window is 2 days, Stage 1 can only emit up to 2 daily buckets per entity.

### 2. YARA-L is Event-Driven (No Rows for Silent Days)
* Stage 1 (`match: $entity by 1d`) creates a row **only for calendar days where at least 1 raw event occurred**.
* If an endpoint generated events on Day 1 of a 30-day search and was turned off for the remaining 29 days, Stage 1 emits **exactly 1 row**, not 30 rows.

### 3. Root Stage Match Mode: Timeline Breakdown vs Fleet Rollup

| Objective | Root Stage Match Clause | Output Behavior |
| :--- | :--- | :--- |
| **Daily Timeline Breakdown** | `match: $entity by 1d`<br>*(Root stage: `$ws = $stage1.window_start`, `match: $entity, $ws by 1d`)* | **1 row per active calendar day**.<br>Preserves the chronological progression for charting and daily $Z$-score tracking. |
| **Fleet Rollup Summary** | `match: $entity` | **1 row per entity** across the entire search window.<br>Collapses all days to calculate overall summaries (e.g. `sum($stage1.is_burst_day)`, `max($stage1.daily_z)`). |

### 4. Metrics Functions are Baseline Decorators, Not Time-Series Generators
* Calling `metrics.*(period: 1d, window: 30d)` does **not** generate 30 rows of historical data.
* It returns **single pre-computed numbers** (the 30-day mean $\mu$, standard deviation $\sigma$, and active days count) that decorate the active day's observation.

---

## 8. User Intent & Downstream Matching Framework

When generating multi-stage search queries, determine the analyst's analytical intent to select the appropriate Root Stage match structure and recommend optimal UI search time ranges:

### 1. Intent Classification & Root Match Selection

| Analyst Intent | Trigger Keywords | Root Stage Match Clause | Visual / UI Destination |
| :--- | :--- | :--- | :--- |
| **📈 Timeline / Charting Mode** | *"Show trend", "Plot over time", "Break out by day", "When did the spike occur?", "Timeline"* | `match: $entity by 1d`<br>*(or `match: $entity by day`)* | **Line Charts, Time-Series Bar Graphs** (1 row per calendar day). |
| **🏆 Rollup / Leaderboard Mode** | *"Top 10 bursty hosts", "Which machines spiked?", "Fleet summary", "Rank by anomalies"* | `match: $entity`<br>*(unwindowed)* | **Tabular Leaderboards, Summary Ranking Cards** (1 row per host across the full month). |

### 2. Recommended Search Time Ranges by Query Archetype

* **📅 Multi-Day Baseline Trend Analysis**: **30 Days** *(e.g., Full Month, July 1 - July 31)* with `by 1d`.
  * *Why:* Provides enough daily data points to visually see the calm baseline vs the sudden surge day.
* **⏱️ Intra-Day Hourly Volatility Hunting**: **24 to 72 Hours** with `by 1h`.
  * *Why:* Captures granular hourly shifts without overloading the query engine with thousands of time buckets.
* **🔍 Fleet Outlier Discovery / Rollup**: **7 to 30 Days** with unwindowed `match: $entity`.
  * *Why:* Gathers sufficient multi-day evidence to count how many distinct days breached thresholds.

---

## 9. Platform Time Range Constraint: 14-Day Limit for Multi-Stage Searches

> [!IMPORTANT]
> **Hard Engine Constraint: Maximum 14 Days for Multi-Stage / Join Queries**
> In Google SecOps, interactive Multi-Stage DAG and Join queries are enforced with a hard maximum search duration of **14 Days (`336 hours`)**.
> * Attempting to run a multi-stage search with a time picker range > 14 days (e.g. 30 days) triggers: `The request time range is greater than maximum duration of 14 days allowed for multistage queries.`
> * **Recommended Operational Range:** Set UI search time picker to **14 Days** (e.g. 2-week block like `2026-07-01` to `2026-07-14`).
> * **Underlying 30-Day Baselines are Unaffected:** Even within a 14-day search window, `metrics.*(window: 30d)` still evaluates against the full 30-day trailing baseline for every active day!

---

## 10. Common Compiler Grammar for Multi-Stage Search

Google SecOps's **Common Compiler** (SIEM Search Engine) governs Multi-Stage UDM Search execution:

1. **Named Stages (`stage <name> { ... }`)**:
   * Each stage defines its own event scope, match group-by (`match: ... by 1d`), and outcomes (`outcome:`).
2. **Mandatory Root Stage `match:` and `outcome:` Sections**:
   * The Root Stage must bind upstream stage variables and contain **both a `match:` and `outcome:` section** (e.g. `match: $entity, $ws by 1d` and `outcome: ...`):
     ```yara
     $user = $stage_1.user
     $user = $stage_2.user
     $ws = $stage_1.window_start
     $ws = $stage_2.window_start

     match:
       $user, $ws by 1d

     outcome:
       $fusion_threat_score = ...
     ```
3. **Zero `condition:` Block in Multi-Stage Search**:
   * The `condition:` keyword is strictly reserved for streaming detection rules. Multi-stage search queries execute their scalar transformations inside the Root Stage `outcome:` section and order results via `order:`.

---

## 11. Architectural Assurance: Background 30-Day Rolling Pre-Computation

A common question analysts ask is:  
*"If our search query is only running across 1 day or 14 days, how does Chronicle know the 30-day baseline?"*

### The Underlying Mechanism:
1. **Background Analytics Aggregation**:
   * Google SecOps continuously runs a scheduled analytical pipeline that aggregates daily telemetry into pre-computed BigQuery summary tables for every entity (User, Asset, Resource, Email).
   * For every entity and day, Chronicle pre-calculates the historical rolling mean ($\mu$), standard deviation ($\sigma$), sum, count, min, and max across 30 trailing days.
2. **Constant-Time $O(1)$ Function Calls**:
   * When YARA-L 2.0 invokes `metrics.metric_name(period: 1d, window: 30d, ...)`, it is **not** running an ad-hoc 30-day scan of raw petabytes of event logs.
   * Instead, it performs an immediate index lookup against the pre-aggregated summary tables for that specific calendar day.
3. **Statistical Independence Guaranteed**:
   * Because the 30-day baseline is pre-aggregated, an entity evaluated on `2026-08-25` is measured against their established behavioral profile from the preceding 30 calendar days—ensuring today's burst does not contaminate or inflate the baseline mean.

---

## 12. Entity Graph Prevalence & Domain/Hash Rarity Hunting

In Google SecOps, the **Entity Graph** pre-computes trailing prevalence context for domains, file hashes, and IP addresses.

### 1. Canonical Entity Graph Prevalence Fields
| Entity Type | Join Field | Day Count Field | Rolling Max Field |
| :--- | :--- | :--- | :--- |
| **Domain** | `$graph.graph.entity.hostname = $domain` | `$graph.graph.entity.domain.prevalence.day_count = 10` | `$graph.graph.entity.domain.prevalence.rolling_max <= 3` |
| **File (Hash)** | `$graph.graph.entity.file.sha256 = $sha256` | `$graph.graph.entity.file.prevalence.day_count = 10` | `$graph.graph.entity.file.prevalence.rolling_max <= 3` |
| **IP Address** | `$graph.graph.entity.ip = $ip` | `$graph.graph.entity.artifact.prevalence.day_count = 10` | `$graph.graph.entity.artifact.prevalence.rolling_max <= 3` |

### 2. Mandatory Rules for Prevalence Joins:
1. **Source Type Filter**: Always set `$graph.graph.metadata.source_type = "DERIVED_CONTEXT"`.
2. **Day Count Anchor**: Always set `$graph.graph.entity.<type>.prevalence.day_count = 10` to distinguish Prevalence from First/Last Seen records.
3. **Non-Zero Bound**: Always include `rolling_max > 0` alongside `rolling_max <= 3` to avoid false positives on unpopulated entity stubs.

### 3. Hard Platform Limitation: 10-Day Period Invariant (`day_count = 10`):
* **Platform Invariant**: In Google SecOps Entity Graph, prevalence tables are indexed strictly on a **fixed 10-day rolling window**.
* **Syntactic Enforcement**: The anchor `$graph.graph.entity.<type>.prevalence.day_count = 10` is an invariant required by Chronicle's engine. Attempting to change `day_count` to other values (e.g. `30`, `7`, `14`) will fail or return no data.
* **Consultative Response Protocol (When Analyst Requests a Change)**:
  If an analyst asks to change the prevalence timeframe (e.g. "Can we look at 30-day prevalence?"), explain:
  > *"Google SecOps Entity Graph prevalence is hard-anchored to a 10-day rolling window by the platform backend (`day_count = 10`). While the 10-day window cannot be changed, we can adjust the asset count threshold (`rolling_max <= N`, e.g. strict single-host $\le 1$ vs $\le 5$) or combine it with 30/60/90-day First-Seen novelty (`first_seen_time < 30d`) for longer-term rarity hunting."*


---

## 13. Entity Graph First-Seen & Last-Seen Novelty Matrix

Google SecOps continuously calculates and stores `first_seen_time` and `last_seen_time` across 5 primary entity types to support tenant-wide novelty hunting:

### 1. Enriched Fields Matrix Across Entity Types
| Entity Type | Entity Graph Metadata Type | First-Seen Field | Last-Seen Field | Prevalence Field |
| :--- | :--- | :--- | :--- | :--- |
| **💻 Asset** | `metadata.entity_type = "ASSET"` | `entity.asset.first_seen_time` | *(N/A)* | *(N/A)* |
| **👤 User** | `metadata.entity_type = "USER"` | `entity.user.first_seen_time` | *(N/A)* | *(N/A)* |
| **🌍 IP Address** | `metadata.entity_type = "IP_ADDRESS"` | `entity.artifact.first_seen_time` | `entity.artifact.last_seen_time` | `entity.artifact.prevalence.*` |
| **🌐 Domain** | `metadata.entity_type = "DOMAIN_NAME"` | `entity.domain.first_seen_time` | `entity.domain.last_seen_time` | `entity.domain.prevalence.*` |
| **📁 File (Hash)** | `metadata.entity_type = "FILE"` | `entity.file.first_seen_time` | `entity.file.last_seen_time` | `entity.file.prevalence.*` |

### 2. Operational Use Cases:
* **Brand New User / Dormant Account Activation**:
  * Filter for users first observed in the tenant within the past 24–48 hours:
    `$e.graph.entity.user.first_seen_time.seconds > timestamp.current_seconds() - (2 * 86400)`
* **Infant Device / Rogue Asset Discovery**:
  * Filter for new MAC/hostnames connecting to internal subnets:
    `$e.graph.entity.asset.first_seen_time.seconds > timestamp.current_seconds() - (7 * 86400)`
* **Stale / Abandoned C2 Re-activation via Last-Seen**:
  * Detect when a file hash or domain not seen in >180 days suddenly re-appears:
    `$e.graph.entity.domain.last_seen_time.seconds < timestamp.current_seconds() - (180 * 86400)`

---

## 14. Avoiding the Part-of-the-Whole Antipattern & Decoupled Context Fusion

### The Part-of-the-Whole Fallacy (Subset vs. Universe):
When evaluating statistical baselines (`metrics.*`), never filter the stage on external threat attributes (e.g. WHOIS NRD domains, GCTI Tor IPs, or Safe Browsing hashes):
* **Why it fails**: The `metrics.*` table represents the entity's **Universal Total History** across all destinations.
* Filtering Stage 1 to a threat subset reduces the observed volume ($X_{\text{threat}}$), causing $Z = (X_{\text{threat}} - \mu_{\text{total}}) / \sigma_{\text{total}}$ to produce a **false negative or large negative $Z$-score**.

### The Decoupled 3-Stage Architectural Pattern:
1. **Stage 1 (Universal Anomaly Baseline)**:
   * Match general event telemetry without subset filters against `metrics.*` to obtain true $Z_{\text{total}}$.
2. **Stage 2 (Isolated Context Threat Match)**:
   * Match specific `GLOBAL_CONTEXT` or `DERIVED_CONTEXT` attributes (maximum **1 ECG lookup per stage**) to count threat hits ($N_{\text{threat}}$).
3. **Root Fusion Stage**:
   * Join `$entity` and compute the composite threat score: $\text{Threat} = Z_{\text{total}} \times (N_{\text{threat}} + 1)$.

---

## 15. Refinement Dimensions in Threat Triage ("What You Can Do Next")

When presenting initial baseline findings to analysts, suggest refining the hunt by layering these 4 orthogonal dimensions:

1. **🌐 Fleet Rarity**: Layer Entity Graph Domain/Hash Prevalence (`rolling_max <= 3`, `day_count = 10`).
2. **⏳ Infrastructure Novelty**: Layer Entity Graph First-Seen age (`first_seen_time < 30/60/90 days`).
3. **🎯 Threat Intel Matches**: Layer GCTI feeds (`Tor Exit Nodes`, `Remote Access Tools`, `Google Safe Browsing`).
4. **📅 WHOIS Domain Lifecycle**: Layer WHOIS domain registration age (`< 30 days`) or expiration status.

---

## 16. Inner-Join Semantic Warning & "Including But Not Limited To" Pattern

### The Inner-Join Semantic Trap:
* In Google SecOps YARA-L 2.0, binding common entity variables across stages (`$host = $s1.host` and `$host = $s2.host`) operates strictly as an **INNER JOIN**.
* If Stage 2 filters on an attribute (e.g. `GLOBAL_CONTEXT` IOC matches, Safe Browsing, or specific external domains), any host that has 0 events matching Stage 2 will have **zero records in Stage 2 and will be completely dropped from the root stage output**.
* If the analyst asks for *"all network connections / hosts including (but not limited to) known bad domains"*, creating an isolated Stage 2 with an IOC filter will drop all benign/novel high-volume anomalous hosts!

### The Syntactic Solution (Full Population Preservation):
To preserve 100% of the fleet while still profiling domains and threat flags:
1. **Single-Stage Fleet Population Sweep (Mode A Snapshot)**:
   * Evaluate all network connections per host against `metrics.network_bytes_outbound`.
   * Capture contacted domains and IPs using `$contacted_domains = array_distinct(target.hostname)` and `$contacted_ips = array_distinct(target.ip)`.
   * Extract security verdicts and threat labels directly via `$threat_categories = array_distinct(security_result.category_details)`.
   * Score statistical deviation ($Z$-Score / CRI) across the full population without dropping non-threat entities.

### Consultative Protocol (Setting Analyst Expectations on IOC Demarcation):
When an analyst asks whether a baseline hunt can "include but not be limited to IOCs", set clear expectations upfront:
* **Truth in Baseline Scope**: The statistical baseline query evaluates 100% of hosts and surfaces all contacted external destinations uniformly. However, the baseline table itself does **not** dynamically separate, label, or badge IOCs vs. novel/benign domains in the output.
* **Triage via Follow-Up Drilldowns**: Domain threat triage (evaluating specific contacted domains against IOC lists, WHOIS age, or Safe Browsing) is provided as actionable, 1-click investigation queries in Section 5 of the report.

---

## 17. Variable Role Classification & Threat-to-Telemetry Decomposition Matrix

For automated threat hunting and headless pipeline execution, the agent and query compiler must ensure that threat indicators are actively modeled in mathematical calculations or data pruning rather than acting solely as passive reporting strings.

### 1. The 4 Variable Functional Roles:
| Variable Role | Definition | Validation Rule |
| :--- | :--- | :--- |
| **`[JOIN_KEY]`** | Binds intermediate stages to the root stage (`$host`, `$user`, `$ws`). | Must appear in stage and root `match:` blocks. |
| **`[SCORING_DIMENSION]`** | Directly computes an anomaly score ($Z$, $D$, $\Delta Z$, Bayes). | Must be part of the root mathematical formula. |
| **`[ACTIVE_FILTER]`** | Constrains data volume (e.g. `rolling_max <= 3`, `$fleet_hosts <= 2`). | Must appear in stage filters or root `condition:`. |
| **`[TRIAGE_DECORATION]`** | Informational context only (`array_distinct(command_line)`). | Cannot be the *sole* representation of a primary threat vector. |

### 2. The Anti-Passive-Decoration Invariant:
* **The Problem**: In YARA-L, extracting `$cmds = array_distinct(principal.process.command_line)` in `outcome:` renders the strings in the results table, creating an illusion of detection. However, without an active rarity filter or baseline metric, single-execution droppers ($\Delta \text{count} = 1$) are lost in high-volume background noise.
* **The Mandatory Rule**: If a threat intelligence narrative or analyst prompt specifies a qualitative behavior (e.g. `wscript.exe` running `.js` droppers, LOLBins, rare PowerShell arguments, or unusual staging domains), that telemetry field **MUST NEVER act solely as a `[TRIAGE_DECORATION]`**.
* **Syntactic Enforcement**: The query must bind the qualitative indicator to an **Active Cross-Sectional Fleet Rarity Stage** (`count_distinct(principal.asset.hostname) <= 2`) or an **Entity Graph Derived Context constraint** (`rolling_max <= 3`).

### 3. The Threat-to-Telemetry Decomposition Matrix:
| Attack Characteristic | Telemetry Scope | Mandatory Analytical DAG Pattern |
| :--- | :--- | :--- |
| **Volumetric Surges** (Auth sprays, data egress bursts, DNS flooding) | `metadata.event_type` + Entity ID | **Stage 1: $O(1)$ Pre-Computed Metrics** (`metrics.*`) $\to$ Parametric $Z$-Score / Delta-$Z$. |
| **Unbounded Qualitative / LOLBins** (Command lines, script args, unique paths) | `principal.process.command_line` | **Stage 2: Cross-Sectional Fleet Rarity DAG** (`match: $cmd by 1d` $\to$ `$fleet_hosts <= 2`). |
| **High-Churn Infrastructure** (TDS landing pages, rotating subdomains) | `target.hostname`, `sha256` | **Stage 2: Entity Graph Derived Context** (`prevalence.rolling_max <= 3`, `day_count = 10`, `first_seen < 30d`). |
| **Multi-Step Killchains** (Web Lure $\to$ ZIP Download $\to$ Script Dropper) | Multi-Event Telemetry | **Root Stage: Causal Cross-Stage Fusion** (`$host = $s1.host = $s2.host`, `$ws = $s1.ws = $s2.ws by 1d`). |

---

## 18. Pre-Composed Multi-Stage Pipeline Library

To prevent runtime syntactic improvisation and avoid streaming rule syntax confusion, the skill maintains complete composite pipeline templates in `templates/pipelines/`:

| Pipeline Template File | Stages | Analytical Model | Primary Use Case |
| :--- | :--- | :--- | :--- |
| **`mad_modified_z_2stage.yl2`** | 2 Stages | Robust MAD / Modified $Z$-Score ($M_Z$) | Heavy-tailed egress network bytes, skewed volume. |
| **`standard_z_score_2stage.yl2`** | 2 Stages | Parametric Standard $Z$-Score ($Z$) | Volumetric bursts, auth attempts, process counts. |
| **`poisson_rarity_2stage.yl2`** | 2 Stages | Discrete Poisson Rarity ($Z_P$) | Rare administrative binary launches, low $\lambda$. |
| **`longitudinal_cusum_2stage.yl2`** | 2 Stages | Longitudinal CUSUM Drift ($S^+$) | Multi-day low-and-slow exfiltration and behavioral drift. |
| **`dual_baseline_delta_z_3stage.yl2`** | 3 Stages | Dual-Baseline Delta-$Z$ ($\Delta Z$) | Patch Tuesday fleet suppression, enterprise-wide spikes. |
| **`hierarchical_empirical_bayes_3stage.yl2`** | 3 Stages | Hierarchical Empirical Bayes | Peer group shrinkage, regularizing inactive accounts. |
| **`multi_sector_fusion_4stage.yl2`** | 4 Stages | Multi-Sector Fusion ($D \sim \chi_3$) | Full-killchain cross-vector correlation (IAM + Proc + Net). |

---

## 19. Consultative Scope & Vector Discovery Framework

When an analyst's inquiry is open-ended (e.g. *"find privilege abuse"*, *"look for insider threats"*, *"deviations from peers"*), the agent must not prematurely converge on a single vector (like logins) or unilaterally assume an enterprise-wide scope.

### 1. The 3 Cohort Granularity Tiers:
| Scope Tier | When to Recommend | Analytical Rationale |
| :--- | :--- | :--- |
| **1. Specific Suspect User** | Analyst has an identity in mind (`user@domain.com`). | Compares the individual directly against their department or historical baseline. |
| **2. Role / Department Cohort** | High-privilege teams (DevOps, DBAs, Cloud Ops, Finance). | **Prevents Heterogeneous Population Noise**: Comparing a Cloud Admin to an HR recruiter yields false positives; pooling within role peers ensures true baselining. |
| **3. Enterprise-Wide Leaderboard** | Open fleet-wide anomaly audit. | Evaluates all active identities and ranks top statistical outliers via Delta-$Z$ or CRI. |

### 2. The 6 Operational Behavioral Vector Families:
1. ☁️ **Cloud Infrastructure CRUD**: `metrics.resource_creation_*`, `metrics.resource_deletion_*`, `metrics.resource_written_*` (GCP CloudAudit, AWS CloudTrail, Azure Activity).
2. 📁 **Workspace Data Hoarding & Exfiltration**: `metrics.workspace_total_download_actions`, `metrics.workspace_total_change_actions` (Google Drive mass exports, permission sharing changes).
3. ⚙️ **Endpoint Administrative Execution**: `PROCESS_LAUNCH` (LOLBins, script interpreters, administrative shells).
4. 🌐 **Outbound Data Egress**: `metrics.network_bytes_outbound` (data siphoning and egress volume surges).
5. 🔑 **Authentication & Credential Access**: `metrics.auth_attempts_*` (off-hours logins, brute force, spray).
6. 🔀 **Multi-Sector Threat Fusion**: Cross-correlating orthogonal vectors (e.g. Auth Surge + Resource Deletions + Outbound Egress) into a single composite distance $D$.

### 3. Anti-Auth-Defaulting Guardrail:
* **The Principle**: Authentication is only 1 of 6 vectors. When investigating privilege abuse or insider deviations, the agent MUST present the full vector canvas and proactively recommend multi-sector cross-correlation rather than defaulting to login counts.

### 4. The 2-Turn Staging Mandate (Conversational Break):
* **Phase 1A (Turn 1)**: For broad or open-ended inquiries, the agent is **STRICTLY PROHIBITED** from emitting a Pre-Flight Hunting Specification Card or YARA-L query preview on Turn 1. The agent must present the 6 vector options, inquire about the user/team scope, and **yield the turn immediately**.
* **Phase 1B (Turn 2)**: Only after the analyst confirms their chosen vector(s) and scope does the agent generate the Pre-Flight Card, the tailored YARA-L query preview, and the Mode A vs Mode B clearance prompt.

### 5. CTI & Threat Intel Report Mapping Protocol:
* **The Principle**: When an analyst provides an external threat report (e.g. DFIR advisory, CVE list, threat actor campaign, or blog URL), the report itself supplies the specific attack vectors and threat context.
* **Direct Transition to Phase 1B**: Instead of forcing the analyst through generic Phase 1A vector polling, the agent:
  1. Extracts the attack lifecycle stages from the report.
  2. Maps them directly to the corresponding `metrics.*` tables and statistical models.
  3. Proposes the primary recommended behavioral hunt.
  4. Renders the structured **Pre-Flight Hunting Specification Card** and literal YARA-L query preview, asking only the operational workload scoping question (e.g. enterprise fleet vs. target server cluster) before yielding the turn (0 tools called).

---

## 20. Compiler Grammar Invariants & Query vs. Rule Nomenclature Mandate

### 1. The Query vs. Rule Nomenclature Standard:
* **Ad-Hoc & Dashboard Logic is a Query**: Multi-stage YARA-L logic executed in UDM search, threat hunts, or dashboards MUST ALWAYS be labeled as **"Multi-Stage YARA-L Query"** or **"Executed Multi-Stage YARA-L Query"**.
* **The Term 'Rule' is Strictly Reserved**: The word **"Rule"** or **"Hunting Rule"** must **NEVER** be used to describe ad-hoc search logic. In Google SecOps, a Rule is an active continuous detection rule running inside the rules engine (`rule <name> { ... }`). Referring to ad-hoc query logic as a "Rule" is a **Critical Nomenclature Violation**.

### 2. Zero-Hallucination Compiler Grammar Rules:
1. **Strict Reference-List Only `in` Operator**: In YARA-L, `field in ("A", "B")` with literal tuples is **INVALID SYNTAX**. The `in` operator is strictly for reference lists (`field in %ref_list`). Multiple literal strings MUST be written as `(field = "A" or field = "B")` or regex `field = /A|B/`.
2. **Strict Function-Call Metric Syntax**: Metric functions are NEVER object properties (e.g. `metrics.auth_attempts_24h.mean` is **INVALID SYNTAX**). All metric baselines MUST use canonical function calls: `max(metrics.<name>(period: 1d, window: 30d, metric: <field>, agg: <agg>, ...))`.
3. **Daily Match Window Syntax**: Daily match windows MUST use `by 1d` (e.g. `match: $entity by 1d`). Using `by 24h` is **INVALID SYNTAX**.
4. **Linear Outcome Arithmetic**: YARA-L outcome expressions do not support nested `max(0, ...)` or inline `sqrt(...)` inside arithmetic. Compute squared terms `$z_sq = $z * $z`, sum them `$d_sq = $z1_sq + $z2_sq`, and order by `$d_sq desc`.
5. **The Chronicle 4-Join Limit & UEBA Join Accounting Formula**:
   In Chronicle Common Compiler (`compiler.go`), queries are strictly limited to `maxJoinCount = 4`.
   $$\text{Total Joins} = \sum_{\text{stages}} \text{UEBA Joins} + (\text{Named Stages} - 1) \le 4$$
   - Each `metrics.*` function inside a named stage is an internal JOIN with the pre-computed UEBA table ($1\text{ join}$).
   - The Root Stage joining $K$ named stages consumes $K - 1$ joins.
   - **Maximum Supported UEBA Multi-Stage DAG**: **2 Named UEBA Stages + Root Stage** (Total joins = $1 + 1 + 1 = \mathbf{3\text{ joins}} \le 4$, e.g. `dual_sector_fusion_3stage.yl2`).
   - Attempting to chain 3 or 4 independent named stages with UEBA metrics in a single search query yields 5 to 7 joins and triggers `compilation error maximum number of joins exceeded. limit query to at most 4 joins`.
   - For 4-sector cross-vector profiling (e.g. Auth + Cloud + Workspace + Network + Endpoint), execute decoupled parallel 2-stage micro-queries (the 360° behavioral radar pattern) or route raw non-metrics correlation to `secops-statistical-hunter`. Do NOT abandon search mode to improvise continuous detection rules.

---

## 21. Dual Multi-Stage Architecture & Boundary with `secops-statistical-hunter`

A critical architectural boundary exists between Google SecOps skills that emit multi-stage YARA-L search queries (`stage ... { }` + unwrapped Root Stage) for Chronicle UDM Search (`udm_search`). Understanding the underlying data plane prevents syntax errors, compilation failures, and domain drift.

### 1. Data Plane Demarcation

| Architectural Dimension | `secops-risk-metrics-multistage` (This Skill) | `secops-statistical-hunter` (Ad-Hoc Hunter) |
| :--- | :--- | :--- |
| **Underlying Data Plane** | Pre-computed daily/hourly summary tables (`metrics.*`) | Raw telemetry logs (`UDM_EVENTS`) & detections (`RULE_DETECTIONS`) |
| **Lookback Horizon** | **Fixed Rolling 30-Day Windows** (`window: 30d`, `period: 1d`) with $O(1)$ pre-aggregated lookups | **Arbitrary Time Slices**: Any custom timestamp range (e.g., 2h, 7d, 14d, 30d) |
| **Join Model & Limits** | Subject to Chronicle `maxJoinCount = 4` (each `metrics.*` function consumes 1 join) | Join-free single-event or multi-stage event correlation without UEBA table joins |
| **Primary Use Case** | 30-day baseline deviations, team/peer department cohorts, 360° health checks, longitudinal CUSUM drift | Ad-hoc threat hunting across un-baselined TTPs (C2 timing jitter, DGA, raw volume bursts, Tukey fences) |

### 2. Shared Multi-Stage Model Disambiguation

Both skills support multi-stage YARA-L execution and share similar mathematical terminology. When an analyst inquiry references these models, apply this routing and disambiguation matrix:

1. **Dual-Baseline Delta-$Z$**:
   * **In `secops-risk-metrics-multistage` (This Skill)**: Evaluates an individual's 30-day behavioral baseline (`metrics.auth_attempts_*`) against a pre-computed peer department/cohort baseline. Suppresses false positives caused by team-wide operational changes (e.g., DevOps sprint migrations).
   * **In `secops-statistical-hunter`**: The *Patch Tuesday Shield*—compares an entity's raw log surge today against the concurrent enterprise fleet shift ($\Delta Z = Z_{\text{personal}} - Z_{\text{fleet}}$) over raw events to suppress company-wide software updates.
2. **Multi-Sector Threat Fusion**:
   * **In `secops-risk-metrics-multistage` (This Skill)**: Fuses decoupled 30-day baseline deviations ($D = \sqrt{\sum Z_i^2}$) across UEBA tables (Auth, Cloud CRUD, Workspace Exfil, Network Egress, Endpoint Tools) using the 360° radar micro-query pattern (respecting the 4-join limit).
   * **In `secops-statistical-hunter`**: The *Combined Arms Radar*—fuses raw event counts across orthogonal silos (Auth + Process + Network) in a single historical search window.
3. **Timing Jitter ($CV \le 0.20$) & Inter-Arrival Analysis ($\Delta t$)**:
   * **Exclusive to `secops-statistical-hunter`**: Pre-computed UEBA tables aggregate daily event sums and cannot compute packet/connection inter-arrival intervals ($\Delta t_i = t_i - t_{i-1}$). Timing regularity, sleep-delay analysis, and robotic beaconing MUST be evaluated over raw UDM telemetry.
4. **30-Day Pre-Computed Baselines, Peer Cohorts & 360° Health Checks**:
   * **Exclusive to `secops-risk-metrics-multistage`**: Requires pre-computed behavioral baselines. Route all requests targeting `metrics.*` or 30-day UEBA envelopes to this skill.

### 3. Prescriptive Skill Handoff Protocol

If an analyst inquiry targets ad-hoc telemetry without pre-computed baselines, requests sub-second timing regularity (inter-arrival jitter CV), or requires arbitrary short-horizon time slices:
1. Do **NOT** attempt to write streaming detection rules (`rule <name> { ... }`).
2. Do **NOT** force `metrics.*` functions onto raw log types that lack pre-computed tables.
3. Render the **Skill Handoff Card** and hand off execution cleanly to `secops-statistical-hunter`.

---
*Created and maintained by Greg Kushmerek for Google SecOps Chronicle SIEM threat hunting workflows.*







