# Multi-Stage Risk Metrics Implementation Guide

> ⚡ **JETSKI / WORKSPACE & MCP AGENT DIRECTIVE**:
> Reference the compiler-verified templates in `templates/` directly via `view_file`.
> Do NOT execute local Python scripts during hunting. All query assembly and execution is native.

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

### 1.1 Outcome Projection & Aggregation Type Matching (Compiler Contract)
Chronicle SIEM's Malachite Common Compiler strictly validates argument types for aggregate functions in `outcome:`:
* **Match Variables Are Auto-Projected**: Variables declared in the `match:` block (e.g. `match: $entity by 1d` or `match: $token by 1d`) are automatically preserved as primary row keys. They do **not** need to be re-aggregated in `outcome:`.
* **`max(...)` and `min(...)` Are Strictly Numeric**: `max()` and `min()` only accept numeric data types (`TypeInt` and `TypeFloat`). Applying `max()` or `min()` to string variables (such as `$token`, `$sha256`, `$hash`, `$user`, `$host`, or `$ip`) causes an immediate compiler crash (`400 Request contains an invalid argument`).
* **Non-Match Categorical / String Attributes**: When an attribute is not part of the `match:` key but must be projected across the aggregation window, use:
  - `array_distinct($str_field)`: Gathers all unique string values seen across the window into an array (e.g. `$affected_hosts = array_distinct($stage1.entity)`).
  - `count_distinct($str_field)`: Counts unique string cardinality (e.g. `$fleet_adopters = count_distinct(principal.asset.hostname)`).
  - `any_value($str_field)`: Emits an arbitrary scalar string from the aggregated group.

### 1.2 Outcomes in Outcomes (OIO) & In-Stage Mathematical Derivations
In Chronicle SIEM's Malachite Common Compiler, Outcome variables can reference previously defined Outcome variables within the same `outcome:` block (`UsesOutcomesInOutcomes`).
The compiler evaluates this via **AST Expression Inlining** (`substituteOutcomeVarsInAssignments`), resolving parent references into a single composite projection tree at compile time.

#### Benefits in Multi-Stage DAGs
1. **Bandwidth & Column Reduction**: Eliminates the need to export 3–6 raw baseline metrics (`obs`, `avg`, `stddev`, etc.) per stage into intermediate query state. Stages export a pre-computed `$z_score` or `$anomaly_ratio`, cutting intermediate projection width by up to 66%.
2. **Match-Key Isolation Across Multi-Sector Fusions**: When an intermediate stage matches on companion dimensions (e.g. `$user, $vendor, $product by 1d` in Cloud CRUD or `$user, $hash, $event by 1d` in Endpoint tools), computing the sector $Z$-score inside that stage preserves the local per-dimension baseline before the Root stage aggregates entities across the enterprise.
3. **Streamlined Root Stage**: The Root stage simply aggregates `$z_sector = max($stage.z_sector)` rather than re-computing compound arithmetic.

#### Invariant Compiler Rules for OIO
* **Strict Definition-Before-Reference**: Parent outcome variables must precede referencing outcome variables (`outcomeDefinedBeforeReference`).
* **Acyclic Dependency Graph**: No circular references (`noCyclicalOutcomeDependency`).
* **No Nested Aggregations on Outcomes**: An outcome variable cannot be enclosed inside an aggregate function within the same stage (e.g. `$x = max($z)` inside Stage 1 is prohibited). Math operations (`-`, `+`, `*`, `/`, `if()`) are fully supported.
* **No Outcomes Inside Metric Arguments**: Outcome variables cannot be passed as entity parameters into `metrics.*` function calls (`noAggregationOrOutcomeInUEBACall`).
* **50 Operator Cap**: Top-level arithmetic expressions have a safety cap of 50 operations (`validateNumberOfArithmeticOperations`).

---

## 2. Temporal Windowing: Intra-Day vs. 30-Day Baselines

Multi-stage DAG queries support two distinct temporal evaluation modes:

### Mode A: Cross-Sectional Fleet Outlier (Daily Bucket)
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
| Assigning literal string to match variable (`$sa = "ola.burch"`) | Direct UDM field filter with field-to-variable binding:<br>`principal.user.userid = "ola.burch"`<br>`$sa = principal.user.userid` | In YARA-L, match variables (`$var`) represent event fields or upstream stage outcomes; they cannot be assigned string literals directly (`$var = "literal"`). Entity filters must always be declared directly on canonical UDM attributes in the event predicates, then bound to variables. |
| Direct string literal in metric dimension argument (`principal.user.userid: "sa-storage-sync"`) | Bind to a stage match variable:<br>`principal.user.userid = "sa-storage-sync"`<br>`$sa = principal.user.userid`<br>`metrics.resource_read_total(..., principal.user.userid: $sa)` | Dimension arguments in `metrics.*` accept only bound match variables (`$sa`, `$host`, `$vendor`) or direct UDM `EventField` paths, never string literals. Literal strings cause live Chronicle compiler rejection (`Request contains an invalid argument`). |
| Passing lowered stage placeholders (`metadata.vendor_name: $vendor, metadata.product_name: $product`) inside `metrics.resource_*(...)` when running in SecOps Search UI | Pass direct UDM `EventField` paths inside the metric call:<br>`metadata.vendor_name: metadata.vendor_name,`<br>`metadata.product_name: metadata.product_name`<br>(and enable **Case Sensitivity On** when running in the SecOps Search UI) | When a query is pasted into the SecOps Search UI with the default **Case Sensitivity Off** toggle (`case_insensitive_query: true`), the YARA-L parser rewrites stage string placeholder bindings (`$vendor = metadata.vendor_name`) to `strings.to_lower(metadata.vendor_name)`. Because pre-computed `metrics.*` tables store Title Case values (`"Google"`, `"Security Command Center"`, `"Google Cloud Platform"`) and join via case-sensitive `=`, passing `$vendor`/`$product` placeholders silently zeroes out 30-day baselines (`$historical_active_days = 0`) and triggers false-positive dormant hits. Direct `EventField` arguments (`metadata.vendor_name: metadata.vendor_name`) bypass placeholder lowering. |

---

## 5. Mandatory Non-Entity Dimension Filters

Certain pre-computed Risk Metrics require specific auxiliary UDM fields as dimension filters in addition to entity identifiers and values:

### Cloud Resource Lifecycle (`metrics.resource_*`) & SecOps UI Case Sensitivity
* **Mandatory Arguments:** `metadata.vendor_name` and `metadata.product_name` **must** be passed in every `metrics.resource_*(...)` call alongside the user identity (`principal.user.userid` or `target.user.userid`).
* **SecOps Search UI Case-Sensitivity Protection:** Pass `metadata.vendor_name: metadata.vendor_name` and `metadata.product_name: metadata.product_name` as direct UDM `EventField` paths inside `metrics.resource_*(...)` rather than `$vendor` / `$product` placeholders, and instruct analysts to enable **Case Sensitivity On** when pasting multi-stage `metrics.*` queries into the SecOps Search UI so pre-computed Title Case dimensions are never lowered to `0` baseline rows.

### File Executions (`metrics.file_executions_*`)
* **Mandatory Argument:** `metadata.event_type` **must** be passed as a filter in every `metrics.file_executions_*` call.
* **Syntax Example:**
  <!-- yara-fragment: single-stage syntax example for the mandatory event_type filter -->
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

## 6. Threshold Tuning, Hurdle Gating, and Ordering in Multi-Stage Search

> [!IMPORTANT]
> **Root Stage Hurdle & Threshold Gating via `condition:`**:
> In the Google SecOps / Chronicle Malachite Common Compiler, the root stage of a multi-stage query is parsed as a `yl2_block`, which natively supports `condition:` for post-aggregation filtering (`HAVING`) alongside `order:`.
> - **Discrete Boolean Hurdles & Threshold Gating**: Place all statistical threshold cutoffs, hurdle models (e.g. dormant account awakening, sub-threshold multi-evidence fusion, Euclidean distance thresholds), and minimum baseline maturity checks (`$active_days >= 7`) under `condition:`.
> - **Mathematical Derivations & Safe Divisors**: Outcome blocks evaluate mathematical derivations, ratios, and safe conditional divisors (`if(condition, then_clause, else_clause)` is supported in `outcome:`, provided the `then` clause contains only placeholders, fields, or constants, and the `else` clause is provided).
> - **Final Outlier Sorting**: Queries terminate with `order: <metric> [desc|asc]` to rank qualifying breached entities.

### 6.1 Noise Level Tuning & Sensitivity Bands via `condition:`

Threat hunting requires adaptable sensitivity depending on operational objectives. Analysts frequently need to isolate different statistical tiers:
1. **High-Confidence Extreme Outliers ($Z \ge 3.0\sigma$ or $Z \ge 4.0\sigma$)**: Used for immediate high-priority triage on large fleets where analysts want zero background chatter.
2. **Borderline / Investigative Band ($2.0\sigma \le Z < 3.0\sigma$)**: Critical for proactive threat hunting. Advanced persistent threats (APTs) and living-off-the-land (LOL) campaigns deliberately avoid extreme volumetric spikes to blend into standard deviations. Filtering specifically for the $2.0\sigma \le Z < 3.0\sigma$ band uncovers low-and-slow behavioral drift before full adversary exfiltration.
3. **Directional Outliers / Quiet Failures ($Z \le -3.0\sigma$)**: Detects anomalous cessation of telemetry, such as security agent uninstalls, heartbeat drop-offs, or disabled audit pipelines.
4. **Multi-Evidence Hybrid Hurdles**: Fuses Euclidean distance thresholds ($D^2 \ge 16.0$) with sub-threshold additive log-odds scores and raw evidence counts.

#### Syntax & Operator Support in Root Stage `condition:`
The Malachite compiler accepts compound boolean expressions in the root stage `condition:` block:
* **Relational Operators**: `>`, `>=`, `<`, `<=`, `==`, `!=`
* **Logical Operators**: `and`, `not` (bare boolean `or` is rejected in root `condition:`)
* **Match Count Operators**: `1 of [ ... ]`, `ANY of [ ... ]` (supported for expressions evaluating variables within the same stage)
* **Cross-Stage Disjunctions**: When evaluating disjunctions across distinct stages (e.g. Stage 1 read surge OR Stage 2 delete surge), compute the composite flag in `outcome:` via `if()` (e.g. `$is_outlier = if($read_z >= 3.0 or $del_z >= 3.0, 1, 0)`) and gate in `condition:` with `$is_outlier = 1`.
* **Grouping**: Parentheses `(...)` for nested logic
* **Universal Grammar Placement**: Must be placed **strictly after `outcome:`** and **strictly before `order:`**.

#### Concrete Root Stage Gating Examples

##### Example 1: Standard High-Confidence Gating ($Z \ge 3.0\sigma$)
```yara
// Root Stage: High-confidence outlier filter
$host = $stage1_extract.host
$ws = $stage1_extract.window_start

match:
  $host, $ws by 1d

outcome:
  $obs = max($stage1_extract.observed_val)
  $mu = max($stage1_extract.historical_avg)
  $sigma = max($stage1_extract.historical_stddev)
  $personal_z = ($obs - $mu) / if($sigma > 0, $sigma, 1.0)

condition:
  $personal_z >= 3.0

order:
  $personal_z desc
```

##### Example 2: Borderline / Investigative Band ($2.0\sigma \le Z < 3.0\sigma$)
```yara
// Root Stage: Emerging behavioral drift (Investigative Band)
$user = $stage1_extract.user
$ws = $stage1_extract.window_start

match:
  $user, $ws by 1d

outcome:
  $obs = max($stage1_extract.observed_val)
  $mu = max($stage1_extract.historical_avg)
  $sigma = max($stage1_extract.historical_stddev)
  $personal_z = ($obs - $mu) / if($sigma > 0, $sigma, 1.0)

condition:
  $personal_z >= 2.0 and $personal_z < 3.0

order:
  $personal_z desc
```

##### Example 3: Multi-Evidence Hybrid Hurdle Fusion
```yara
// Root Stage: 2D Euclidean Distance or Sub-Threshold Joint Odds Hurdle
$entity = $stage1_macro.entity
$entity = $stage2_micro.entity

match:
  $entity by 1d

outcome:
  $z_intensity = max($stage1_macro.z_score)
  $raw_hits = max($stage2_micro.raw_hits)
  $z_breadth = max($stage2_micro.z_breadth)
  $threat_distance_sq = ($z_intensity * $z_intensity) + ($z_breadth * $z_breadth)
  $joint_odds = (0.6 * $z_intensity) + (0.4 * $z_breadth)

condition:
  $threat_distance_sq >= 16.0 or ($joint_odds >= 2.5 and $raw_hits >= 3)

order:
  $threat_distance_sq desc
```

##### Example 4: Baseline Maturity + Volume + Significance Hurdle
```yara
// Root Stage: Suppress noise on immature or unestablished accounts
$entity = $stage1_extract.entity
$ws = $stage1_extract.window_start

match:
  $entity, $ws by 1d

outcome:
  $personal_z = max($stage1_extract.z_score)
  $active_baseline_days = max($stage1_extract.hist_active_days)
  $observed_volume = max($stage1_extract.observed_val)

condition:
  $personal_z >= 3.0 and $active_baseline_days >= 7 and $observed_volume >= 5

order:
  $personal_z desc
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
3. **Hurdle Gating in Root Stage `condition:`**:
   * Root stage queries execute continuous scalar transformations inside `outcome:`, evaluate multi-evidence hurdle boundaries and statistical significance thresholds inside `condition:`, and rank qualifying results via `order:`.

### 10.1 Variable Binding and Entity Scoping Rules (Compiler Contract)

When scoping a hunt to a specific entity or transitioning from a fleet-wide sweep to an individual drilldown (e.g. drilling down to `ola.burch`):

1. **UDM Field Predicate Filtering**:
   Declare entity filters directly against canonical UDM attributes in the event stage predicates:
   ```yara
   stage auth_risk {
       metadata.event_type = "USER_LOGIN"
       target.user.userid = "ola.burch"
       $user = target.user.userid
     match:
       $user by 1d
   ```
2. **Variable Role Distinction**:
   * **Event and Match Variables (`$var`)**: In YARA-L 2.0, dollar-prefixed variables represent event dimensions, aggregation keys, or upstream stage outcomes. They bind to UDM fields (`$user = target.user.userid`) or upstream stages (`$user = $stage1.user`).
   * **Compiler Invariant**: Assigning a literal string directly to a variable (e.g. `$sa = "ola.burch"` or `$user = "ola.burch"`) is invalid YARA-L syntax and results in a compiler syntax error.
   * **Entity Drilldowns from Fleet Sweeps**: When pivoting from a fleet sweep (`$user = target.user.userid`) to a single entity drilldown, place the literal string equality constraint on the UDM field in the stage body (`target.user.userid = "ola.burch"`), maintaining valid variable-to-field binding (`$user = target.user.userid`).

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
4. **Mode A Freshness**: Set `startTime` to two days back at 00:00Z (D-2) and add `timestamp.get_date(metadata.event_timestamp.seconds) = "<today UTC, YYYY-MM-DD>"` to every event stage. A window that starts today 00:00Z overlaps no built prevalence records, so zero rows from it are a freshness gap, not a clean hunt. Mode B keeps its window and omits the date filter. See `references/entity-context-graph-guide.md`, Rule 5.

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

When presenting initial baseline findings to analysts, suggest refining the hunt by layering these 4 orthogonal dimensions (see `references/entity-context-graph-guide.md` for complete hunter playbooks on Narrowing vs. Enhancing):

1. **🌐 Fleet Rarity**: Layer Entity Graph Domain/Hash Prevalence (`rolling_max <= 3`, `day_count = 10`) via `hybrid_metric_derived_file_prevalence_2stage.yl2` (execution counts) or `hybrid_metric_derived_domain_prevalence_2stage.yl2` (HTTP request counts); for DNS volume (keyed on `network.dns.questions.name`), outbound bytes, or any other measure, use `rare_destination_ecg_3stage.yl2`.
2. **⏳ Infrastructure Novelty**: Layer Entity Graph First-Seen age (`first_seen_time < 7/30/60/90 days`) or infant asset age via `hybrid_metric_derived_asset_age_2stage.yl2`.
3. **🎯 Threat Intel Matches**: Layer GCTI feeds (`Tor Exit Nodes`, `Remote Access Tools`, `Google Safe Browsing`).
4. **📅 WHOIS Domain Lifecycle**: Layer WHOIS domain registration age (`< 30 days` NRD) or expiration status via `hybrid_metric_whois_domain_lifecycle_2stage.yl2`.

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
| **`[ACTIVE_FILTER]`** | Constrains data volume (e.g. `rolling_max <= 3`, `$fleet_hosts <= 2`). | Must appear in stage event filters or root match predicates. |
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

To prevent runtime syntactic improvisation and avoid streaming rule syntax confusion, the skill maintains 32 complete composite pipeline templates in `templates/pipelines/`:

| Pipeline Template File | Stages | Analytical Model | Primary Use Case |
| :--- | :--- | :--- | :--- |
| **`mad_modified_z_2stage.yl2`** | 2 Stages | Robust MAD / Modified $Z$-Score ($M_Z$) | Heavy-tailed egress network bytes, skewed volume. |
| **`standard_z_score_2stage.yl2`** | 2 Stages | Parametric Standard $Z$-Score ($Z$) | Volumetric bursts, auth attempts, process counts. |
| **`poisson_rarity_2stage.yl2`** | 2 Stages | Discrete Poisson Rarity ($Z_P$) | Rare administrative binary launches, low $\lambda$. |
| **`longitudinal_cusum_2stage.yl2`** | 2 Stages | Longitudinal CUSUM Drift ($S^+$) | Multi-day low-and-slow exfiltration and behavioral drift. |
| **`macd_momentum_velocity_2stage.yl2`** | 2 Stages | MACD Dual-Spine Momentum ($\Delta Z = Z_{\text{fast}} - Z_{\text{slow}}$) | Kinetic acceleration breakouts past 30-day ceiling and historical max. |
| **`circadian_von_mises_2stage.yl2`** | 2 Stages | Circadian von Mises Temporal Distance ($D_{\text{circ}}^2 / 72.0$) | Cyclic 24-hour clock-face departures, off-hours authentication & bandwidth. |
| **`c2_beacon_flow_frequency_2stage.yl2`** | 2 Stages | Outbound Flow Frequency Baseline ($Z_{\text{flows}}$) | High-frequency micro-session C2 beaconing and keep-alive heartbeats. |
| **`http_error_ratio_surge_2stage.yl2`** | 2 Stages | HTTP Failure Baseline + Error Ratio Surge | Web application/proxy $4xx/5xx$ fuzzing, API enumeration, broken C2 loops. |
| **`http_target_surge_2stage.yl2`** | 2 Stages | Target-Centric HTTP Surge (`target.hostname`) | Web server hammering, automated scraping, cloud API gateway abuse. |
| **`cloud_repository_scope_dual_branch.yl2`** | 3 Stages | Dual-Branch Cloud Repository & Origin IP Isolation | 5-tuple service account resource CRUD isolation + unseen source IP pivot. |
| **`dual_baseline_delta_z_3stage.yl2`** | 3 Stages | Dual-Baseline Delta-$Z$ ($\Delta Z$) | Patch Tuesday fleet suppression, enterprise-wide spikes. |
| **`hierarchical_empirical_bayes_3stage.yl2`** | 3 Stages | Hierarchical Empirical Bayes | Peer group shrinkage, regularizing inactive accounts. |
| **`part_of_the_whole_multilevel.yl2`** | 3 Stages (4 with a peer group) | Multilevel Hierarchical Z ($Z_{\text{personal}}, Z_{\text{vs\_enterprise}}$; with a peer group $Z_{\text{vs\_team}}, Z_{\text{team\_vs\_enterprise}}$) | Personal + fleet by default; user → named group → enterprise when a roster is given. |
| **`part_of_the_whole_triad_multilevel.yl2`** | 3 Stages (4 with a peer group) | Multilevel Triad Breakdown (3 Sibling Metrics + Composite $D$) | Sibling metric ratio analysis (e.g. Total + Fail + Success) against personal baseline and fleet; team cohort only when a peer group is named. |
| **`dual_sector_fusion_3stage.yl2`** | 3 Stages | Dual-Sector Fusion (rectified $D$, any 2 catalog sectors) | Cross-vector correlation of any two metrics for the same entity (sector slots from `references/metric-sector-catalog.md`). |
| **`multi_sector_fusion_4stage.yl2`** | 4 Stages | Multi-Sector Fusion (rectified $D$, any 2 catalog sectors + Fleet Norm) | Same as dual-sector plus cross-sectional fleet $\Delta Z$, within the 2-UDM-stage Search limit. |
| **`rollup_sector_fusion_4stage.yl2`** | 4 Stages | Roll-up Sector Fusion (composite-only metric rolled up per entity + 1 catalog sector) | Process execution / cloud resource / alert metric fused with another sector (e.g. process + DNS by host). |
| **`rollup_sector_fusion_5stage.yl2`** | 5 Stages | Roll-up Sector Fusion + Fleet Norm | As above plus fleet $\Delta Z$. 4 named stages + root: supported but does not always work; prefer the 4-stage variant. |
| **`radar_360_decoupled_sector.yl2`** | 2 Stages | Decoupled 360° Radar Sector Micro-Query | Parallel per-sector evaluation feeding Euclidean Threat Distance $D$. |
| **`radar_360_sector_web_http.yl2`** | 2 Stages | 360° Radar Spoke 6 (Web & Proxy HTTP) | Dedicated Web & Proxy HTTP baseline spoke for 6-sector 360° Risk Radar. |
| **`radar_360_sector_alert.yl2`** | 2 Stages | 360° Radar Alert Spoke (`alert_event_name_count`) | Host + rule alert frequency baseline spoke for endpoint/EDR triage. |
| **`hybrid_metric_derived_file_prevalence_2stage.yl2`** | 2 Stages | Derived Context File Prevalence ($Z \times M_{\text{rare}}$) | Living-off-the-land surges, rare binary isolation (drops rollout binaries; to normalize a surge against a rollout use `hybrid_metric_fleet_prevalence_2stage.yl2`). |
| **`hybrid_metric_derived_domain_prevalence_2stage.yl2`** | 2 Stages | Derived Context Domain Prevalence ($Z \times M_{\text{rare}}$) | HTTP request counts to novel SaaS/C2 hostnames, corporate CDN pruning. DNS volume (keyed on `network.dns.questions.name`), bytes, or any other measure: `rare_destination_ecg_3stage.yl2`. |
| **`hybrid_metric_whois_domain_lifecycle_2stage.yl2`** | 2 Stages | WHOIS Domain Lifecycle (NRD & Expiration Fusion) | Acute web/DNS/network egress to Newly Registered Domains (<= 30d) or expired domains. |
| **`hybrid_metric_derived_asset_age_2stage.yl2`** | 2 Stages | Derived Context Infant Asset Age ($Z \times M_{\text{infant}}$) | Rogue machine onboarding, infant endpoints (<= 7d) undergoing auth storms or egress. |
| **`hybrid_metric_http_ua_prevalence_2stage.yl2`** | 2 Stages | HTTP User-Agent Token Fleet Prevalence Shield | Hyperbolic fleet adopter dampening ($1 / (k_{\text{fleet}} + 1)$) for custom/rare user-agent strings. |
| **`hybrid_metric_fleet_prevalence_2stage.yl2`** | 2 Stages | Cross-Sectional Token Fleet Prevalence Shield | Normalizes host/user surges against concurrent enterprise token adoption. |
| **`hybrid_metric_entropy_concentration_2stage.yl2`** | 2 Stages | Metric Baseline + Target Concentration / Diversity Deficit | Fuses 30-day volume surge with single-destination elephant flow concentration. |
| **`hybrid_metric_orthogonal_space_2stage.yl2`** | 2 Stages | Metric Baseline + Orthogonal Companion Dimension | Fuses 30-day metric baseline with unindexed raw UDM companion dimensions. |
| **`hybrid_metric_raw_enrichment_2stage.yl2`** | 2 Stages | Metric Baseline + Raw Forensic Enrichment | Projects distinct command lines, URIs, and IPs onto 30-day metric outliers. |
| **`rare_destination_ecg_3stage.yl2`** | 3 Stages + Root (2 UDM + graph) | Sector $Z$ filtered to Entity Graph-rare destinations | "Unusual outbound bytes / DNS / HTTP to low-prevalence domains or IPs" (domain via `target.hostname` or `network.dns.questions.name`; IP via `target.ip`). |
| **`fusion_rare_destination_3stage.yl2`** | 3 Stages + Root (2 UDM + graph) | Dual-sector rectified $D$ through rare destinations | Two sectors on one host where the second is per (host, destination) and the destination is rare (e.g. DNS volume + HTTP to rare domains). |

---

## 19. Consultative Scope & Vector Discovery Framework

When an analyst's inquiry is open-ended (e.g. *"find privilege abuse"*, *"look for insider threats"*, *"deviations from peers"*), the agent must not prematurely converge on a single vector (like logins) or unilaterally assume an enterprise-wide scope.

### 1. The 3 Cohort Granularity Tiers:
| Scope Tier | When to Recommend | Analytical Rationale |
| :--- | :--- | :--- |
| **1. Specific Suspect User** | Analyst has an identity in mind (`user@domain.com`). | Compares the individual directly against their department or historical baseline. |
| **2. Role / Department Cohort** | High-privilege teams (DevOps, DBAs, Cloud Ops, Finance). | **Prevents Heterogeneous Population Noise**: Comparing a Cloud Admin to an HR recruiter yields false positives; pooling within role peers ensures true baselining. |
| **3. Enterprise-Wide Leaderboard** | Open fleet-wide anomaly audit. | Evaluates all active identities and ranks top statistical outliers via Delta-$Z$ or CRI. |

### 3-Part Multilevel "Part-of-the-Whole" Modeling (`part_of_the_whole_multilevel.yl2`)
When comparing an individual to a team cohort, single-tier comparisons create blind spots:
1. **Enterprise-only comparisons** flag high-volume roles (DevOps/SRE) as false positives and conceal compromises in low-volume roles (HR/Legal).
2. **Team-only comparisons** suffer from small-$N$ instability ($N < 7$) and miss team-wide operational rollouts.
3. **The 3-Part Solution**: Evaluates an entity simultaneously across three tiers via `templates/pipelines/part_of_the_whole_multilevel.yl2`:
   - **Personal Historical $Z$**: $Z_{\text{personal}} = (\text{obs} - \mu_{\text{personal}}) / \max(\sigma_{\text{personal}}, 1.0)$
   - **Team Cross-Sectional $Z$**: $Z_{\text{vs\_team}} = (\text{obs} - \mu_{\text{team}}) / \max(\sigma_{\text{team}}, 1.0)$
   - **Enterprise Cross-Sectional $Z$**: $Z_{\text{vs\_enterprise}} = (\text{obs} - \mu_{\text{enterprise}}) / \max(\sigma_{\text{enterprise}}, 1.0)$
   - **Group vs Enterprise**: $Z_{\text{team\_vs\_enterprise}} = (\mu_{\text{team}} - \mu_{\text{enterprise}}) / \sigma_{\text{enterprise}}$ (`$z_team_vs_enterprise`; triad: `$z*_team_vs_enterprise`, `$d_team_vs_fleet_sq`). This is the defined user → group → enterprise path: the user against the group, and the group against the whole.
4. **Peer group rule**: no peers mentioned → delete the template's `// >>> TEAM COHORT` blocks (personal + fleet, rank by `$z_vs_enterprise`). Peers named → keep the blocks and rank by `$z_vs_team`. Peers mentioned but not named ("vs his team", "his group") → run the **AD TEAM LOOKUP** below in Turn 1, fill the roster from it, and show it in the Pre-Flight as `• Peer Cohort & Roster: <team> (AD department | AD group): <members>` above a candidate query that already contains the filled TEAM COHORT blocks. Ask for the roster only if the lookup finds no team for the subject; never drop the comparison silently. A roster from any source (named, supplied in a later turn, or AD) keeps the blocks. The roster is a list of identifiers in the query (`$u = "a" or $u = "b"`), subject included.

   **AD TEAM LOOKUP** (Active Directory records in the Entity Graph, `ENTITY_CONTEXT`). This is the one Turn 1 query allowed besides the compiler probe: it reads AD user records only, never events, so it is context resolution, not hunt execution. Window: the last 30 days (AD records are not daily prevalence records, so Rule 5 freshness does not apply). Replace `frank.kolzig` with the subject. Verified live on gus-sdl: returns `Information Technology` → `frank.kolzig, tim.smith, tim.smith_admin, bobby.fuhr`.
   ```
   graph.metadata.source_type = "ENTITY_CONTEXT"
   graph.metadata.entity_type = "USER"
   $dept = graph.entity.user.department
   $dept != ""
   match:
     $dept
   outcome:
     $has_subject = max(if(graph.entity.user.userid = "frank.kolzig", 1, 0))
     $members = array_distinct(graph.entity.user.userid)
     $team_size = count_distinct(graph.entity.user.userid)
   order:
     $has_subject desc, $team_size asc
   limit:
     1
   ```
   * `$has_subject = 1` → that department is the team.
   * `$has_subject = 0` or no row → run it once more keyed on AD group membership: replace the `$dept` lines with `$grp = graph.relations.entity.group.group_display_name`, `$grp != ""`, `$grp != "Domain Users"` and `match: $grp`. Ordering by `$team_size asc` picks the smallest group the subject belongs to; name that group in the Pre-Flight so the analyst can change it.
   * Still `$has_subject = 0` → ask the analyst for the roster and yield.
   * Team size below 7 → keep the team stage and flag `⚠️ Sparse Baseline Caution (N < 7)`.

This produces 4 diagnostic states: **Individual Rogue** (high $Z_{\text{team}}$ & high $Z_{\text{enterprise}}$), **Role Benign** (low $Z_{\text{team}}$ & high $Z_{\text{enterprise}}$), **Stealth Compromise** (high $Z_{\text{team}}$ & low $Z_{\text{enterprise}}$), and **Team Campaign/Rollout** (low $Z_{\text{team}}$ & high $Z_{\text{team\_vs\_enterprise}}$).

### 4. Intra-Event Metric Triad Breakouts (`part_of_the_whole_triad_multilevel.yl2`)
When hunting within a single telemetry vector, single-metric evaluations can obscure behavioral context:
* **The Sibling Metric Advantage**: One stage observes 3 sibling metrics of the same family (e.g. `auth_attempts_total`, `auth_attempts_fail`, `auth_attempts_success`) for one entity, so all three get personal and fleet baselines without extra UDM stages.
* **Peer group is optional (default = fleet only)**: keep the template's `// >>> TEAM COHORT` blocks only when a roster is known (named, supplied later, or from the AD TEAM LOOKUP in the Peer group rule above). Without a peer list the team stage recomputes the fleet, so delete the blocks and rank by `$d_vs_fleet_sq`.
* **Math (as the template computes it)**: For each metric $m \in \{1, 2, 3\}$: $Z_{\text{personal}, m}$ and $Z_{\text{vs\_enterprise}, m}$ (plus $Z_{\text{vs\_team}, m}$ with a peer group), fused into
  $$D_{\text{vs\_fleet}}^2 = \sum_{m=1}^3 Z_{\text{vs\_enterprise}, m}^2$$
  ($D_{\text{vs\_team}}^2$ likewise when a peer group is kept).
  The terms are two-sided: a collapse (success drops while fail rises) also raises $D$.
* **Valid triads and every slot value**: `references/metric-sector-catalog.md` § *Sibling triads* (Auth, DNS, HTTP, Network bytes, Network flows). It gives the shared stage filter, the conditional-sum observed values and the entity fields valid for all three metrics. Do not build a triad from the individual metric rows: pasting one metric's own filter line into the shared stage zeroes its siblings.
* **No process or cloud-resource triads**: `file_executions_*` and `resource_*` are composite-only (no entity-only baseline), so the single-entity triad stage cannot carry them.

### 2. The 6 Operational Behavioral Vector Families:
1. ☁️ **Cloud Infrastructure & Data Store CRUD**: `metrics.resource_read_*`, `metrics.resource_written_*`, `metrics.resource_creation_*`, `metrics.resource_deletion_*` (GCP CloudAudit, AWS CloudTrail, Azure Activity). Supports baselining service accounts (`principal.user.userid`) and caller origin IPs (`principal.ip`) against cloud data repositories (`target.resource.name`).
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
2. **Strict Function-Call Metric Syntax & Valid Metric Types**: Metric functions are NEVER object properties (e.g. `metrics.auth_attempts_24h.mean` is **INVALID SYNTAX**). All metric baselines MUST use canonical function calls: `max(metrics.<name>(period: 1d, window: 30d, metric: <type>, agg: <agg>, ...))`.
   * The Common Compiler strictly supports only two operational metric types:
     - `metric: value_sum`: Strictly required for byte/bandwidth volume baselines (`metrics.network_bytes_*`, `metrics.dns_bytes_*`, `metrics.workspace_network_bytes_*`). Retrieves `metric.sum_measure.value`. Passing `total_bytes` or `metric_value_sum` causes fatal compiler failure (`unsupported metric type`).
     - `metric: event_count_sum`: Required for all event count baselines (`metrics.auth_attempts_*`, `metrics.resource_*`, `metrics.http_queries_*`, `metrics.file_executions_*`, `metrics.network_flows_*`, `metrics.dns_queries_*`, `metrics.workspace_total_*`, `metrics.alert_event_name_count`). Retrieves `metric.total_events`.
3. **Daily Match Window Syntax**: Daily match windows MUST use `by 1d` (e.g. `match: $entity by 1d`). Using `by 24h` is **INVALID SYNTAX**.
4. **Linear Outcome Arithmetic & Square Root Invariants**: YARA-L outcome expressions do not support nested `max(0, ...)` or bare `sqrt(...)` inside arithmetic. To derive square roots in outcome expressions, use the namespaced factory function `math.sqrt(...)` on a single variable or expression (e.g. `$sqrt_lambda = math.sqrt($safe_lambda)`). For Euclidean vector norms, compute squared terms `$z_sq = $z * $z`, sum them `$d_sq = $z1_sq + $z2_sq`, and order by `$d_sq desc` (or take `$d = math.sqrt($d_sq)`). Bare `sqrt(...)` without the `math.` namespace is invalid syntax.
5. **The Chronicle 4-Join Limit & UEBA Join Accounting Formula**:
   In Chronicle Common Compiler (`compiler.go`) and Malachite Search (`get_structured_query_view_utils.cc:3040-3064`), multi-stage search queries are governed by two hard ceilings:
   - **Data Source Ceiling (`ValidateDataSourcesUsed`)**: Total UDM event stages across a multi-stage query are capped at **`SourceCount["udm"] <= 2`** (`FLAGS_malachite_search_join_query_max_event_tables_joined = 2`; exceeding 2 UDM stages fails with `Number of UDM events exceeded max limit: 3 > 2`), and Entity Context Graph stages are capped at **`SourceCount["entity"] <= 1`** (`Number of ECG events exceeded max limit: 2 > 1`). Stage-to-stage references (`$stage.var`) do not consume UDM or ECG source slots.
   - **Join Ceiling (`maxJoinCount = 4`)**:
   $$\text{Total Joins} = \sum_{\text{stages}} \text{UEBA Joins} + (\text{Named Stages} - 1) \le 4$$
   - Each `metrics.*` function inside a named stage is an internal JOIN with the pre-computed UEBA table ($1\text{ join}$).
   - The Root Stage joining $K$ named stages consumes $K - 1$ joins.
   - **Maximum Supported UEBA Multi-Stage DAG**: **2 Named UDM UEBA Stages + Root Stage** (`dual_sector_fusion_3stage.yl2`), or **2 Named UDM UEBA Stages + 1 Stage-to-Stage Fleet Normalization Stage + Root Stage** (`multi_sector_fusion_4stage.yl2`, which stays at `SourceCount["udm"] = 2`). Roll-up fusions add one stage-to-stage roll-up stage: `rollup_sector_fusion_4stage.yl2` (3 named + root) and `rollup_sector_fusion_5stage.yl2` (4 named + root), both at 2 UDM stages. **4 named stages + root is supported but does not always work**; the conditions under which it fails are not yet characterized, so prefer the 3-named-stage variant and fall back to it if the 5-stage query fails.
   - **Multi-Sector Threat Fusion Affirmative Template Selection**:
     When hunting for coordinated anomalies across ANY two metric sectors for the same entity (e.g. DNS failures + HTTP requests, HTTP requests + outbound bytes, auth failures + outbound bytes, process execution + DNS) using Euclidean threat distance:
     * Both sectors have an entity-only baseline: `templates/pipelines/dual_sector_fusion_3stage.yl2` (or `multi_sector_fusion_4stage.yl2` for cross-sectional fleet $\Delta Z$).
     * One sector is composite-only (`file_executions_*`, `resource_*`, `alert_event_name_count`): `templates/pipelines/rollup_sector_fusion_4stage.yl2` (or `_5stage.yl2`). A detail stage scores each (entity, companion key) against its own baseline; a stage-to-stage roll-up keeps the max per-key Z per entity.
     * Fill every `{{sector_a_*}}` / `{{sector_b_*}}` slot from the metric's row in `references/metric-sector-catalog.md`, and apply the **Fusion pairing rules** at the top of that file (entity kind, identifier, roll-up limits, `// ADVISORY:` lines). Those rules are authoritative; they are not restated here.
     * Root Stage: joins on `$entity` and fuses the rectified, baseline-gated `$z_a` and `$z_b` into `$composite_threat_norm_sq = $z_a_sq + $z_b_sq` (take `math.sqrt($composite_threat_norm_sq)` for $D$).
   - Attempting to chain 3 or 4 independent named UDM stages in a single search query violates `SourceCount["udm"] <= 2` (`Number of UDM events exceeded max limit: 3 > 2`) and `maxJoinCount = 4` (`compilation error maximum number of joins exceeded. limit query to at most 4 joins`).
   - For 3+ sector cross-vector profiling (e.g. Auth + Cloud + Workspace + Network + DNS + Web), execute decoupled parallel 2-stage micro-queries (the 360° behavioral radar pattern) or route raw non-metrics correlation to `secops-statistical-hunter`. Do NOT abandon search mode to improvise continuous detection rules.
6. **Regular Expression Pattern Matching Syntax**: Regular expression pattern evaluation in YARA-L 2.0 event predicates uses direct regex assignment `$var = /pattern/ nocase` or `re.regex($var, /pattern/)`. Alternation between multiple regex patterns on a single variable uses internal regex alternation within a single regex literal: `$var = /pattern1|pattern2/ nocase` (e.g. `$sa = /@.*gserviceaccount\.com$|^arn:aws:(iam|sts)::|sa-storage-sync/ nocase`). Placing the pipe operator `|` between separate regex literals is invalid syntax. Avoid inner forward slashes inside `/.../` literals.
7. **No `variance()` Aggregate**: YARA-L 2.0 does **not** support `variance(...)`. The compiler accepts only `avg()`, `stddev()`, `min()`, `max()`, `sum()`, `count()`, and `count_distinct()`. To obtain variance, export `stddev(...)` from the intermediate stage and square it in the root outcome (`$sigma_sq = $sigma * $sigma`).
8. **Strict Math Namespacing**: Bare numeric functions are illegal. Use `math.round(...)`, never `round(...)`.
9. **Stage Name Grammar**: Stage identifiers must NOT begin with `$`. Write `stage stage1_extract`, never `stage $stage1_extract`.
10. **Outcome Aggregation Function Grammar (`count()` vs. `sum(if())`)**:
    - `count()` accepts ONLY a single event attribute (e.g., `count(metadata.id)`). Wrapping conditionals or function expressions inside `count(...)` (such as `count(if(...))`) is **INVALID SYNTAX** rejected by the Chronicle compiler with `Request contains an invalid argument`.
    - For conditional event counting within an outcome block, always formulate as `sum(if(<condition>, 1, 0))` (e.g., `$fail_obs = sum(if(network.http.response_code >= 400, 1, 0))`).


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
   * **In `secops-risk-metrics-multistage` (This Skill)**: Fuses decoupled 30-day baseline deviations ($D = \sqrt{\sum \max(0, Z_i)^2}$) across UEBA tables (Auth, Cloud CRUD, Workspace Exfil, Network Egress, Endpoint Tools) using the 360° radar micro-query pattern (respecting the 4-join limit).
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

## 22. Service Account Cloud Repository Scope, Origin IP Outliers & Local-Baseline Isolation

When investigating service accounts accessing data repositories out of their normal behavioral scope, dormant service accounts going active, or unexpected host origins, analysts face three critical failure modes:
1. **The Product Narrowing Antipattern**: Hardcoding a query to a single product (e.g. `BigQuery` or `Storage`) when asked about broad cloud data repositories.
2. **The Single-CRUD Narrowing Antipattern (Dormant Service Account Blindspot)**: Narrowing a general service account or dormant service account awakening hunt exclusively to `RESOURCE_READ` / `USER_RESOURCE_ACCESS` (`metrics.resource_read_total`) misses dormant accounts that wake up to provision (`RESOURCE_CREATION` / `USER_RESOURCE_CREATION`), modify (`RESOURCE_WRITTEN` / `USER_RESOURCE_UPDATE_CONTENT`), or delete (`RESOURCE_DELETION` / `USER_RESOURCE_DELETION`) cloud resources.
3. **The "Elephant and Mouse" Dynamic Range Masking Problem**: High-volume routine background activity (e.g., 1,000,000 GCS telemetry sync reads) completely masks an acute targeted exfiltration dump from a sensitive repository (e.g., 2,500 reads against a quiet Spanner database or S3 bucket) if the service account's activity is evaluated against an account-level aggregate baseline.

### 1. Architectural Solution: Local-Baseline Isolation
To preserve sensitivity across disparate repositories, the query MUST slice dynamically by:
$$\text{Match Key} = (\$sa, \$vendor, \$product, \$resource, \$ip \text{ by } 1d)$$
By matching each destination resource individually against `metrics.resource_read_total`, `metrics.resource_written_total`, `metrics.resource_deletion_total`, and `metrics.resource_creation_total` (passing `metadata.vendor_name: metadata.vendor_name, metadata.product_name: metadata.product_name`), each repository is evaluated strictly against its own local historical parameters $(\mu_r, \sigma_r, N_r)$ across all 4 Cloud CRUD families.

### 2. Dual-Branch Mathematical Outlier Formulation
The pipeline computes two orthogonal anomaly scores:
- **Branch 1: Destination Depth & Novelty Anomaly ($Z_{\text{dest}}, Z_{\text{write}}, Z_{\text{del}}, Z_{\text{create}}$)**:
  - *Established Destinations ($\mu_r > 0, \text{active days} \ge 3$)*: Evaluates depth volumetric surges via standard $Z$-score:
    $$Z_{\text{depth}} = \frac{\text{Obs} - \mu_r}{\sigma_r + 1.0}$$
  - *Novel / Unobserved Destinations ($\mu_r = 0, \text{active days} = 0$)*: Under the universal dispersion floor ($+ 1.0$), when $\mu_r = 0$ and $\sigma_r = 0$:
    $$Z_{\text{novelty}} = \frac{\text{Obs} - 0}{0 + 1.0} = \text{Obs}$$
    Any access to a completely novel cloud repository immediately yields an acute anomaly score proportional to the extraction volume.
- **Branch 2: Caller Origin Host Anomaly ($Z_{\text{origin}}$)**:
  - Caller origin IP is evaluated via `principal.ip: $ip`.
  - For unobserved or foreign host origins ($\mu_{\text{origin}} = 0$):
    $$Z_{\text{origin}} = \frac{\text{Obs} - 0}{0 + 1.0} = \text{Obs}$$
- **Composite Outlier Score**:
  $$Z_{\text{composite}} = \max(0, Z_{\text{dest}}) + \max(0, Z_{\text{write}}) + \max(0, Z_{\text{del}}) + \max(0, Z_{\text{create}}) + \max(0, Z_{\text{origin}})$$
  Surfaces entities that hit novel/surging repositories across any CRUD operation or from novel caller IPs.

### 3. Canonical Compiler-Verified Pipeline
This architecture is codified in `templates/pipelines/cloud_repository_scope_dual_branch.yl2` and verified by `PIPE-08-CLOUD-SCOPE`. It consumes only 1 internal UEBA join ($\le 4$ join limit) and enforces mandatory companion dimensions (`metadata.vendor_name: metadata.vendor_name`, `metadata.product_name: metadata.product_name`).

### 4. Multi-Database Account Binding Contract
When hunting compromised or dormant service accounts (e.g. Scattered Spider, OAuth token theft, dormant SA awakening) across multiple databases or cloud resources:
1. **Mandatory Dimension Binding**: Bind `target.resource.name: $resource` in both the Stage 1 match key (`$sa, $vendor, $product, $resource, $ip by 1d`) and the Root stage match key (`$sa, $product, $resource, $ip, $ws by 1d`).
2. **Routing Rule**: For cloud infrastructure or repository activity on a service account entity (unless the analyst explicitly requests a single CRUD verb), use `templates/pipelines/cloud_repository_scope_dual_branch.yl2` to concurrently baseline destination reads (`resource_read_total`), writes (`resource_written_total`), deletions (`resource_deletion_total`), and creations (`resource_creation_total`) against target resources.
3. **Linter Enforcement**: `StatisticalAntipatternAuditor` flags `STAT_ANTIPATTERN_DYNAMIC_RANGE_MASKING` on any query using cloud resource store metrics under an account entity if `target.resource.name` is omitted from the match key, preventing account-level aggregation.

### 5. Multi-Tier Cloud Telemetry Spectrum & UDM Enum Taxonomy (`GCP_CLOUDAUDIT`)
Threat hunting across cloud audit logs must not be constrained to basic CRUD operations (`RESOURCE_READ`, `RESOURCE_WRITTEN`, `RESOURCE_CREATION`, `RESOURCE_DELETION`). Real-world cloud audit telemetry parsed into Chronicle UDM contains critical user actions, IAM manipulations, and credential modifications.

#### Empirical 30-Day Distribution (Tenant: `gus-sdl`):
* `GENERIC_EVENT` (30,999): High-volume control-plane and routine API automation.
* `RESOURCE_WRITTEN` (2,575) & `USER_RESOURCE_UPDATE_CONTENT` (559): System bulk writes vs. user content tampering.
* `RESOURCE_CREATION` (980) & `USER_RESOURCE_CREATION` (30): System infrastructure vs. user-initiated resources.
* `RESOURCE_DELETION` (936) & `USER_RESOURCE_DELETION` (60): System teardowns vs. targeted user asset deletion.
* `USER_RESOURCE_UPDATE_PERMISSIONS` (378): Critical vector for resource-level IAM/ACL tampering (buckets, secrets).
* `USER_CHANGE_PERMISSIONS` (150): Project/organization level IAM role assignments and privilege escalation.
* `RESOURCE_READ` (124) & `USER_RESOURCE_ACCESS` (43): System data queries vs. user secret/object access.
* `USER_LOGIN` (96): Cloud Console / OAuth session establishment.
* `USER_CREATION` (62) & `USER_CHANGE_PASSWORD` (60): Service account creation and service account key generation.
* `GROUP_MODIFICATION` (32): Group-based privilege escalation.
* `USER_UNCATEGORIZED` (537) & `STATUS_UNCATEGORIZED` (64): Uncategorized operations.

#### Critical UDM Enum Naming Rule:
* **Reading/Accessing Resources**: In Chronicle UDM, user-initiated read operations are parsed as `USER_RESOURCE_ACCESS` (or system-level `RESOURCE_READ`). **`USER_RESOURCE_READ` DOES NOT EXIST IN UDM** and will be rejected by the compiler.
* **Modifying Content**: `RESOURCE_WRITTEN` (generic) or `USER_RESOURCE_UPDATE_CONTENT` (user).
* **Modifying Permissions**: `USER_RESOURCE_UPDATE_PERMISSIONS` (resource ACL) or `USER_CHANGE_PERMISSIONS` (IAM role).
* **Credential Minting**: `USER_CHANGE_PASSWORD` (used for service account key creation in GCP Cloud Audit).

---

## 24. Threat Hunting Lifecycles: Fleet/Vector Outlier Hunts vs. 360° Entity Pivot

Threat hunting follows a two-tier investigative lifecycle:

### Tier 1: Fleet/Vector Outlier Hunting (Broad Discovery)
* **Goal**: Surface top anomalous identities or resources across an entire fleet or category on a specific vector (e.g. Cloud CRUD, Network Bytes, Authentication Spikes).
* **Execution**: Single atomic multi-stage YARA-L query (Mode A current-day snapshot or Mode B 2–14d timeline).
* **Reporting Standard**:
  * **Pillar 1**: Renders the distribution or timeline of the *target hunt itself* (e.g., bar chart of observed vs baseline $\mu$ for Mode A, or multi-day inception curve for Mode B).
  * **Pillars 2–5**: Query, ranked fleet summary, forensic threat breakdown, and 1-click investigation queries.
  * **Pillar 4 Pivot**: Concludes with the **Consultative 360° Pivot Card**.

### Tier 2: 360° Multi-Sector Entity Deep-Dive (Targeted Verification)
* **Trigger**: Triggered **only** upon:
  1. Explicit analyst request (e.g. *"run a 360 health check on svc-analytics"*, *"compare admin@... to all sectors"*), OR
  2. Analyst confirms the Consultative 360° Pivot Card offered at the conclusion of a Tier 1 fleet hunt.
* **Execution**: Dispatches 6 decoupled parallel sector micro-queries via `scripts/radar_collector.py`.
* **Reporting Standard**: Pillar 1 renders the full 360° Behavioral Risk Radar (`<agent-embed>` or Markdown Data-URI SVG) with all 6 sector scores.

### The Consultative 360° Pivot Card Pattern
When a Tier 1 fleet hunt discovers an entity with severe statistical anomalies ($Z \ge 3.0\sigma$, $\text{CRI} \ge 50$, or acute novelty departure), Pillar 4 must proactively suggest a 360° health check:

```markdown
> [!TIP]
> **💡 Recommended Investigative Next Step: 360° Behavioral Radar Deep-Dive**
> Service account `[entity_id]` exhibited an acute behavioral anomaly ($Z = +[X.XX]\sigma$, CRI: [YY]) on [Target Metric].
> Would you like to run a full **360° Behavioral Risk Radar** across all 6 telemetry sectors (Authentication, Cloud Infrastructure, Workspace Data, Network Egress, DNS Resolution, Web & Proxy Activity) to verify if this identity is exhibiting concurrent compromise indicators?
```

---

## 25. Multi-Turn Continuity & Conversational Anaphora Resolution

In multi-turn threat hunting dialogues, security analysts frequently issue follow-up prompts that refer anaphorically to the preceding query while modifying one or more search parameters:
* *"Can you run the same search but for user 'admin' and looking backwards 14 days starting from August 18?"*
* *"Now do the same hunt for svc-deployer@my-project.iam.gserviceaccount.com"*
* *"Look back 14 days on that same vector"*

### The Anti-Context-Collapse Mandate
Under no circumstances should the assistant treat a follow-up query as a prompt to abandon the active UEBA Multi-Stage Risk Analytics architecture or degrade into raw log retrieval (`udm_search` on `GCP_CLOUDAUDIT`, raw Windows Event logs, or unfiltered Sysmon). 

1. **Architecture Persistence**: The phrase *"same search"* explicitly binds the execution to the current active pipeline:
   * Pre-computed 30-day baselines (`metrics.*`).
   * Multi-stage YARA-L 2.0 DAG constructs (`stage ...` + Root Stage).
   * Statistical outlier formulation ($Z$-score, MAD, Poisson rarity, or $\Delta Z$).
   * Canonical 6-Pillar triage report structure upon clearance.

2. **Entity Parameter Substitution**:
   * Replace the previous target entity with the new target (`principal.user.userid = "admin"` or designated service account).
   * If the entity is a display name with spaces, apply the **Identity Disambiguation Protocol** (spot-check $\le 5$ events; if 0 events match, halt and ask for technical account identifier).

3. **Time Horizon Substitution & Anchor Mapping**:
   * Standard snapshot queries operate in **Mode A** (current-day snapshot vs 30d baseline).
   * Follow-up phrases such as *"looking backwards 14 days starting from [Date]"* or *"14-day timeline"* map directly to **Mode B: Longitudinal Sliding Timeline (`TIMELINE_BREAKDOWN`)**.
   * **Date-Anchor Resolution**:
     $$\text{endTime} = \text{Anchor Date (e.g. 2026-08-18T23:59:59Z)}$$
     $$\text{startTime} = \text{Anchor Date} - 14\text{d (e.g. 2026-08-04T00:00:00Z)}$$
   * **Timeline Query Semantics**: Multi-stage YARA-L groups daily observations: `match: $entity by 1d` evaluated against the 30-day baseline spine (`window: 30d`).

4. **Follow-Up Clearance Protocol**:
   * If both the entity scope and telemetry vectors are unambiguously known from the context, present the updated **Pre-Flight Hunting Specification Card** and literal **Multi-Stage YARA-L Query Preview**.
   * Ask for execution clearance (Mode A vs. Mode B confirmation) and yield the turn (zero search or ingestion tools called on Turn 1 of the follow-up).

### 25.1 In-Flight Dialogue & Pre-Clearance Parameter Tuning
When the analyst asks questions, requests methodological explanations, or adjusts parameters (significance thresholds, dates, mathematical models) prior to giving Mode A/B clearance:
1. **Colloquial Explanation**: Answer the question directly using plain-English security analogies or quantitative depth matching the analyst's conversational register.
2. **Context Retention**: Maintain the active entity scope, telemetry vectors, and baseline configuration in working memory without restarting discovery.
3. **Specification Refresh**: Present the refreshed Pre-Flight Hunting Specification Card reflecting updated thresholds or models.
4. **Query Re-Verification**: When query logic changes, execute a 1-shot probe (`udm_search(query=..., maxEvents=1)`) and display the updated candidate query block.
5. **Prompt for Clearance**: Conclude by asking whether to proceed with Mode A (Today vs 30-Day Baseline) or Mode B (2–14 Day Timeline) and yield the turn.


---

## 26. Metric Entity Affinity, Cross-Entity Boundaries & The Consultative Pivot Protocol

When an analyst proposes a hunting hypothesis that spans multiple architectural domains (such as correlating endpoint process executions with cloud API activity), the skill must respect Chronicle's physical metric schemas and guide the analyst toward viable detection strategies.

### A. The Metric Entity Affinity Matrix
In Google SecOps Malachite, pre-computed UEBA metric tables are indexed by the dimension sets listed in the compiler's `config.textproto`. The filter arguments of one `metrics.*()` call must map to exactly one valid set; anything else fails at compile time (`compilation error: validating predicates: validating ueba functions: unsupported filters for metric ...`). The authoritative per-metric list, including every identifier field, is `references/metric-sector-catalog.md`. Summary:

| Metric Family | Canonical Metric Table | Entity Keys Valid Alone | Mandatory Companion Dimensions | Not Valid |
| :--- | :--- | :--- | :--- | :--- |
| **File & Process Execution** | `metrics.file_executions_*` | None (composite-only) | `metadata.event_type` + `principal.process.file.sha256`, optionally plus ONE of `principal.asset.*` or `principal.user.*` | Any entity key without event type + hash; `target.*` keys |
| **Cloud Resource CRUD** | `metrics.resource_*` | None (composite-only) | `principal.user.*` or `target.user.*` + `metadata.vendor_name` + `metadata.product_name` | Any `*.asset.*` (host) key |
| **Authentication & IAM** | `metrics.auth_attempts_*` | `target.user.*`, `principal.user.*`, `principal.asset.*` | None | `target.asset.*` alone or with `principal.asset.*` |
| **Workspace & SaaS** | `metrics.workspace_*` | `principal.user.*` (auth also `target.user.*`) | None | Any `*.asset.*` (host) key |
| **DNS Queries / DNS Bytes** | `metrics.dns_queries_*`, `metrics.dns_bytes_outbound` | `principal.user.*`, `principal.asset.*` | Optional: `network.dns_domain`, `network.dns.questions.type` (queries); `target.ip` (bytes) | `network.dns.questions.name`, `target.hostname`, `target.user.*` |
| **HTTP & Web Proxy** | `metrics.http_queries_*` | `principal.user.*`, `principal.asset.*`, `target.hostname` | Optional: `network.http.user_agent`, `target.hostname` | `target.url`, `target.ip`, `network.http.response_code` |
| **Network Bytes / Flows** | `metrics.network_bytes_*`, `metrics.network_flows_*` | `principal.user.*`, `principal.asset.*` | Optional (bytes): `target.asset.*`, principal country, security category, target network org | `target.user.*` |
| **Security & EDR Alerts** | `metrics.alert_event_name_count` | None (composite-only) | `principal.asset.*` + `security_result.rule_name` | Any key without both |

`*.user.*` means any of `userid`, `email_addresses`, `windows_sid`, `employee_id`, `product_object_id`; `*.asset.*` means any of `hostname`, `ip`, `mac`, `asset_id`, `product_object_id`.

### B. The Cross-Entity Boundary & The Anti-Forced-Join Invariant
In YARA-L multi-stage DAGs, stages that join in the root must share the exact same match variable (`match: $key by 1d`). 
* `metrics.file_executions_*` baselines are keyed per **binary hash** (optionally narrowed to a host or user), never per entity alone, while `metrics.resource_*` baselines are keyed per **user + vendor + product**. Their Z-scores describe different units, so they **CANNOT** be fused on `$user` inside a single multi-stage YARA-L query.
* **Strict Anti-Hallucination Invariant**: An agent is strictly prohibited from stripping `$sha256` or `metadata.event_type` from `file_executions_*` calls, or dropping `metadata.vendor_name` / `metadata.product_name` from `resource_*` calls, to force a join.

### C. The 3 Canonical Consultative Pivot Paths
When an analyst requests a cross-entity scenario (such as an endpoint workstation pivoting into Google Cloud), the agent must clearly explain the dimensional boundary and guide the analyst using one of three canonical paths:

1. **Path 1: Cloud-First 2-Phase Pivot (Recommended within Risk Metrics)**:
   * **Step 1 (Pre-Computed UEBA)**: Search for user accounts exhibiting extreme cloud resource creation surges ($Z \ge 3.0\sigma$) via `metrics.resource_creation_total`. Project `principal.ip` (the caller's origin IP) and event timestamps.
   * **Step 2 (Targeted EDR Drilldown)**: Using the caller IP or user identity, query endpoint telemetry for rare process launches on that workstation around the attack window.
2. **Path 2: Workstation-Centric Baseline (within Risk Metrics)**:
   * Baseline known developer workstations or jump boxes using `metrics.file_executions_total` (`$host, $sha256 by 1d`). Flag acute execution spikes ($Z \ge 3.0\sigma$) and cross-reference with outbound cloud network connections.
3. **Path 3: Raw Log Statistical Outlier Handoff (`secops-statistical-hunter`)**:
   * If the analyst needs ad-hoc statistical outlier hunting directly across raw `PROCESS_LAUNCH` logs (e.g. inline MAD, CV, Poisson rarity, or Tukey fences on user-process pairs without pre-computed table limits), seamlessly transition to `secops-statistical-hunter`.

### D. The Web & HTTP URI Granularity Boundary (When to Pivot to Statistical Hunter)
Chronicle Malachite maintains 30-day historical baselines for `metrics.http_queries_*` across exactly 9 pre-computed dimensions: host, user, target hostname, and user-agent token. It does **not** maintain baseline tables for full URL paths (`target.url`), URI query parameters, or payload transfer bytes.
* **Stay in `secops-risk-metrics-multistage`**: When baselining request volume, failure/4xx ratios, target hostname frequency, novel user-agents, or cross-vector 360° radar vectors.
* **Hybrid 2-Stage Architecture**: When baselining on `target.hostname` in Stage 1 and extracting high-cardinality URI paths in Stage 2 companion forensics (`$sample_uris = array_distinct(target.url)`).
* **Pivot to `secops-statistical-hunter`**: When the analyst explicitly requires ad-hoc mathematical anomaly detection directly on URI strings (e.g., path entropy, directory traversal frequency, parameter fuzzing, payload byte distributions) over raw `NETWORK_HTTP` logs.

### E. The Pre-Preview Compilation Probe Gate (Compiler Verification)
Before outputting any candidate multi-stage YARA-L query in the Phase 1B Pre-Flight Specification Card:
* The agent executes a 1-shot compilation probe via `udm_search(query="<query>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`. Timestamps MUST be absolute ISO 8601 UTC; relative offsets (`"now-10m"`, `"now"`) are rejected by the API — see section 30C.
* **Zero Broken Previews**: If the probe fails with a compilation error, the agent is strictly prohibited from rendering the broken query in markdown. It must auto-correct syntax or trigger the Consultative Pivot Protocol immediately.

---

## 27. Template-First Query Architecture & Post-Flight Integrity

### A. Template-First Assembly (template selection rule)
To eliminate runtime syntax failures and semantic distortions, assemble every multi-stage query from the canonical templates below rather than authoring one from scratch. Open the chosen `.yl2` with `view_file` and fill in its placeholders — the template files are the authoritative source, and no script needs to be read or run to select one:
1. **Stage 1 Extractors (`templates/stage1_extractors/`)**: Provide guaranteed 6-point outcome tuples (`$observed_val`, `$historical_avg`, `$historical_stddev`, `$historical_active_days`, `$historical_max`, `$historical_sum`) with immutable entity bindings.
2. **Stage 2 Math Models (`templates/stage2_math_models/`)**: Provide clean AST implementations of all 16 models: Standard $Z$, Robust MAD, Discrete Poisson Rarity, Fano Factor Dispersion, Coefficient of Variation, Hourly Temporal $Z$, Bayesian Gamma & Beta-Binomial, Longitudinal CUSUM, Two-Part Hurdle, Asymmetric Directional ReLU, Piecewise Winsorized CRI, Fleet Prevalence Shield, Adaptive Context Sensitivity, MACD Momentum Velocity, and Circadian von Mises Temporal Distance.
3. **Pre-Composed Pipelines (`templates/pipelines/`)**: End-to-end validated pipelines for complex multi-stage hunts (e.g. `cloud_repository_scope_dual_branch.yl2`, `mad_modified_z_2stage.yl2`).

### B. The `RAW_LOG_DUMP_DETECTED` Post-Flight Inspection Rule
Before generating any report, audit which responses the analysis rests on. Two things separate a legitimate call from a violation: its position in the hunt lifecycle, and whether it carries its own aggregation.

* **Scoping probes** precede the analytical query. Bare UDM filters that resolve an identity, confirm an asset exists, or establish that a telemetry vector is populated (e.g. `principal.user.userid = "j.doe" nocase`, `metadata.event_type = "USER_LOGIN"`). These legitimately return `"events"` and are never flagged.
* **Analytical queries** are multi-stage queries carrying `metrics.*` lookups in `outcome:`, whose results populate the 6-Pillar report or the 360° Radar.
* **Once the analysis is under way, every query carries its own `match:` / `outcome:` aggregation.** A stage whose *events section* selects raw rows is entirely normal — every YARA-L query selects rows, and `match:` / `outcome:` are what turn them into statistics. What is forbidden is a query with no aggregation at all, whose rows land in context to be counted by hand.

**Worked example — a permitted hybrid.** Stage 1 baselines outbound network bytes against `metrics.network_bytes_outbound`. Stage 2 hands off to the `secops-statistical-hunter` plane to characterise observed user-agent strings: its events section selects the raw HTTP rows, `match:` buckets them by entity and agent string, and `outcome:` aggregates them into counts and a concentration score. That stage returns `"stats"` and is fully compliant. It would only become a violation if the same user-agent rows were fetched with no `match:` / `outcome:` and tallied in the agent's head.

`RAW_LOG_DUMP_DETECTED` is flagged when any of these holds:
1. An **analytical** query returns `"events"` without `"stats"` — the `metrics.*` lookup did not execute.
2. A query with **no** `match:` / `outcome:` aggregation is issued **after** the analytical query and returns `"events"` — the agent is gathering its own data rather than reading aggregates.
3. A report is generated when **no** aggregated `"stats"` response was returned at any point — raw rows have become the evidence base.

Statistics are computed by the F1 data plane and read from `"stats"`. Deriving a mean, standard deviation, entropy, or Z-score from returned `"events"` rows — in Python or by inspection — is the failure this rule exists to catch. Where a baseline is genuinely unavailable from `metrics.*`, the sanctioned route is the `secops-statistical-hunter` interface, which aggregates inside the query; it is not a licence to pull rows into context.

On detection, `CommonMarkTriageFormatter` aborts 6-Pillar report generation, presents an auto-corrected canonical template (or initiates the Consultative Pivot Protocol), and prompts the analyst for execution clearance.

### C. Clean Hand-Off & SOAR Playbook Integration
* **Clean Hand-Off Schema**: See `references/clean-handoff-udm-schema.md` for the synthetic UDM event structure used to promote outliers ($Z \ge 3.0\sigma$, $\text{CRI} \ge 50$) to Chronicle alerts and cases.
* **SOAR Playbook Radar Hook**: See `references/soar-playbook-radar-integration.md` for wiring 360° behavioral fingerprinting directly into Chronicle SOAR playbooks.

---

## 28. Two-Phase Chained Hunt Specification & Data Provenance Protocol

When an analyst's hypothesis crosses physical entity boundaries (such as correlating endpoint process executions with cloud audit activity), multi-stage queries must respect the boundary between Statistical Baselining and Targeted Forensics.

### A. The Two-Phase Chained Architecture
1. **Phase 1 (Statistical UEBA Baseline Search)**:
   * **Engine**: Google SecOps Risk Analytics (`metrics.*`).
   * **Scope**: Evaluates population or fleet-wide activity against 30-day historical distributions ($N = 30\text{d}$).
   * **Output**: Identifies the high-significance anomaly (e.g. Host `ws-finance-04`, Binary `cloud_sync.exe`, $Z \ge 3.0\sigma$) and the exact anomaly timestamp window.
2. **The Bridge Contract**:
   * Instead of attempting an in-engine inner join across disjoint entity keys and private NAT boundaries, the pipeline extracts the concrete investigative keys:
     * `$host`: The compromised asset hostname.
     * `$timestamp`: The execution window.
     * `$user`: The principal user logged into that asset.
     * `$caller_ip`: The external egress NAT/public IP associated with that host.
3. **Phase 2 (Targeted Forensic Drilldown Search)**:
   * **Engine**: Chronicle SIEM Raw UDM Search.
   * **Scope**: High-precision forensic search scoped to the extracted user or caller IP around the Phase 1 timestamp.
   * **Output**: Detailed chronological timeline of cloud API calls, bucket operations, or IAM modifications.

### B. Tool-Precondition Code Block Embargo (Zero Broken Queries)
* Under no circumstances may an agent render a candidate YARA-L query in markdown (\`\`\`yara) without having executed a 1-shot pre-preview probe (`udm_search(query="<event filter>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`) in the immediately preceding tool call. Timestamps MUST be absolute ISO 8601 UTC — see section 30C.
* The probe is the candidate's event filter alone: no `stage`, `match:`, `outcome:` or `metrics.` calls. Running the candidate itself before clearance, even with `maxEvents: 1`, is execution, not a probe. The candidate first runs on Turn 2 clearance.
* If the probe returns an invalid argument or syntax error, withhold the preview and correct the filter, or present the Two-Phase Consultative Pivot.

### C. Data Provenance & Execution Stamping
To prevent fabricated results or recycled numbers, reports must stamp execution provenance directly from the Chronicle API response:
* Scanned event volume.
* Engine query execution timestamp.
* Projected schema columns from the `stats` payload.

### D. The Zero-Code Handoff Invariant & Dual-Layer Trickle Defense
1. **Zero-Code Handoff Invariant**:
   * Under NO circumstances may an agent emit candidate ```yara query blocks inside or alongside a Skill Handoff Card.
   * Handoff cards are strictly conceptual and architectural. They specify target telemetry, mathematical model, and rationale, but withhold executable YARA-L code.
   * Code emission belongs exclusively to the destination skill once invoked (or after handoff clearance and invocation). Emitting unvalidated candidate code for another skill during handoff violates the Tool-Precondition Code Block Embargo, because the source skill cannot validate code designed for the destination skill's grammar.
2. **Dual-Layer Trickle Defense (Low-Volume Stealth Attacks)**:
   * When investigating low-volume trickle attacks with randomized jitter (e.g., SUNBURST DNS), an agent must NOT prematurely surrender risk metrics.
   * **Layer 1 (Longitudinal CUSUM Drift)**: Mode B Longitudinal CUSUM Drift ($S_t^+ \ge 4.0\sigma$ on `metrics.dns_queries_total`) detects cumulative, multi-day low-volume drift ($k = 0.5\sigma$, $h = 4.0\sigma$) over 14–30 days even when daily volume is low.
   * **Layer 2 (Ad-Hoc Timing Jitter Handoff)**: Handoff to `secops-statistical-hunter` is reserved strictly for evaluating sub-minute or hourly inter-arrival timing jitter ($CV \le 0.20$) on raw connection timestamps (`metadata.event_timestamp.seconds`).

---

## 29. Scheduled & Automated Exfiltration: The Two-Answer Hybrid Workflow

When an analyst asks whether Google SecOps can detect automated or scheduled exfiltration patterns (such as recurring server-to-server outbound transfers, cron-driven data dumps, or periodic sync jobs), the agent must **NEVER force a purely volumetric daily baseline onto a temporal regularity problem**.

A scheduled cron job exfiltrating 5 GB at 02:00 UTC looks identical in daily rollups (`period: 1d`) to standard business operations, and recurring transfers will gradually contaminate a 30-day baseline. Furthermore, pre-computed `metrics.*` tables aggregate event volumes and cannot calculate inter-arrival delta times ($\Delta t$) or coefficient of variation ($CV$).

To provide maximum analytical value without compromising mathematical integrity, the agent must execute the **Two-Answer Consultative Workflow**:

### A. Answer 1: Immediate Risk Metrics Execution via Low-Prevalence Screening
1. **The Rationale**:
   Rather than attempting to calculate second-level timing across millions of raw events or relying solely on volume, the agent leverages **Entity Graph Derived Context** to screen for external destinations with isolated enterprise prevalence ($\le 3$ internal hosts over 10 days).
2. **The Compilable Multi-Stage Query (`PIPE-09-PREVALENCE`)**:
   The query pairs raw `NETWORK_CONNECTION` events with `metrics.network_bytes_outbound` (for host-level historical context) and joins with `graph.entity.artifact.prevalence` (`rolling_max <= 3`, `day_count = 10`).
   **Mode A window**: `startTime` two days back at 00:00Z (D-2), `endTime` now, and today's UTC date in the `get_date` line. A window that starts today 00:00Z matches no built graph days; zero rows from it are a freshness gap, not a clean hunt. For Mode B, delete the `get_date` line and keep the 2–14 day window (Rule 5, `references/entity-context-graph-guide.md`).
   ```yara
   // Stage 1: Measure outbound network connection activity and 30-day baseline per host and external IP
   stage host_egress {
       $net.network.sent_bytes > 0
       $net.network.sent_bytes < 1000000000000000
       timestamp.get_date($net.metadata.event_timestamp.seconds) = "<today UTC, YYYY-MM-DD>"   // Mode A only
       $net.principal.asset.hostname = $host
       $net.target.ip = $dst_ip

       // Exclude internal RFC 1918 traffic
       not net.ip_in_range_cidr($dst_ip, "10.0.0.0/8")
       not net.ip_in_range_cidr($dst_ip, "172.16.0.0/12")
       not net.ip_in_range_cidr($dst_ip, "192.168.0.0/16")

     match:
       $host, $dst_ip by 1d

     outcome:
       $observed_bytes = sum($net.network.sent_bytes)
       $hist_avg = max(metrics.network_bytes_outbound(
           period: 1d, window: 30d, metric: value_sum, agg: avg,
           principal.asset.hostname: $host
       ))
       $hist_stddev = max(metrics.network_bytes_outbound(
           period: 1d, window: 30d, metric: value_sum, agg: stddev,
           principal.asset.hostname: $host
       ))
       $hist_active_days = max(metrics.network_bytes_outbound(
           period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
           principal.asset.hostname: $host
       ))
   }

   // Stage 2: Entity Graph Derived Context - External IP Prevalence (<= 3 internal hosts across 10d)
   stage destination_prevalence {
       $graph.graph.metadata.entity_type = "IP_ADDRESS"
       $graph.graph.metadata.source_type = "DERIVED_CONTEXT"
       $graph.graph.entity.ip = $dst_ip
       $graph.graph.entity.artifact.prevalence.day_count = 10
       $graph.graph.entity.artifact.prevalence.rolling_max > 0
       $graph.graph.entity.artifact.prevalence.rolling_max <= 3

     match:
       $dst_ip by 1d

     outcome:
       $fleet_prevalence = max($graph.graph.entity.artifact.prevalence.rolling_max)
   }

   // Root Stage: Join host egress with destination rarity and evaluate statistical deviation
   $host = $host_egress.host
   $dst_ip = $host_egress.dst_ip
   $dst_ip = $destination_prevalence.dst_ip

   match:
     $host, $dst_ip by 1d

   outcome:
     $actual_bytes = max($host_egress.observed_bytes)
     $historical_mean = max($host_egress.hist_avg)
     $historical_stddev = max($host_egress.hist_stddev)
     $baseline_active_days = max($host_egress.hist_active_days)
     $destination_prevalence_10d = max($destination_prevalence.fleet_prevalence)
     $z_score = ($actual_bytes - $historical_mean) / if($historical_stddev > 0, $historical_stddev, 1.0)

   order:
     $z_score desc
   ```
3. **Mandatory Prevalence Assumption Callout**:
   In Pillar 4 (Forensic Vector Breakdown), the report MUST explicitly state:
   > [!NOTE]
   > **⚠️ Prevalence Screening Assumption**:  
   > This query specifically isolates external destinations with low enterprise prevalence ($\le 3$ internal hosts over a 10-day lookback). It effectively detects rogue VPS drop points, isolated C2 servers, and unapproved staging endpoints. **However, it assumes the adversary is not using high-prevalence public cloud infrastructure.**

### B. Answer 2: Consultative Bridge for High-Prevalence / Living-Off-The-Cloud Targets
1. **The Consultative Gate**:
   In Pillar 6 (or Next Steps), the agent proactively asks the hunter:
   > *"Would you also like to evaluate automated exfiltration targeting **high-prevalence public cloud infrastructure** (e.g., AWS S3, Google Cloud Storage, Cloudflare Workers, GitHub, Box, Dropbox) where destination prevalence filtering cannot be used? That analysis runs in `secops-statistical-hunter`, which tests cron timing regularity on raw event timestamps."*
2. **The Structured Skill Handoff Card (Zero-Code Handoff Invariant)**:
   When the hunter requests cloud exfiltration coverage, the agent emits a **Skill Handoff Card** steering to `secops-statistical-hunter`:
   ```markdown
   ┌────────────────────────────────────────────────────────────────────────┐
   │                        SKILL HANDOFF CARD                              │
   │ • Source Skill:       secops-risk-metrics-multistage                   │
   │ • Destination Skill:  secops-statistical-hunter                        │
   │ • Target Telemetry:   Raw UDM_EVENTS (NETWORK_CONNECTION / DNS)        │
   │ • Statistical Model:  C2_BEACONING_JITTER (CV <= 0.20) & Cron Minute   │
   │ • Target Scope:       High-Prevalence Cloud (AWS S3, GCS, Cloudflare)  │
   │ • Candidate Hosts:    [Candidate host IDs from Phase 1 or full fleet]  │
   │ • Operational Rationale: Evaluates sub-minute inter-arrival variance   │
   │   (Δt) and minute :00 synchronization over raw timestamps to prove     │
   │   scheduled automation without relying on volume or prevalence.        │
   └────────────────────────────────────────────────────────────────────────┘
   ```
3. **Handoff Execution**:
   The agent instructs the destination skill to evaluate:
   * **Timing Regularity ($CV \le 0.20$)**: Low coefficient of variation on connection intervals proves robotic execution.
   * **Cron Minute Alignment**: Aggregating `timestamp.get_minute($e.metadata.event_timestamp.seconds, "UTC")` to detect transfers synchronized to exact minute boundaries (`:00`, `:15`, `:30`).
   * **Process-to-Network Correlation**: Correlating `/usr/sbin/cron` or `systemd` process launches with outbound network connections within 60 seconds.

---

## 30. Pre-Flight Clearance Hard Gate, Identity Spot-Check, and ISO 8601 Probe Contracts (Release v1.4.4)

### A. The Hard Pre-Flight Clearance Gate (NO QUERY = NO CLEARANCE)
A critical guardrail failure occurs when an agent presents a Pre-Flight Hunting Specification Card, omits the YARA-L query preview (due to probe failure or compiler hesitation), and yet proceeds to ask the Step 5 clearance question:
> *"Would you like to run Mode A (Today vs 30-Day Baseline) or Mode B (2–14 Day Timeline)?"*

Under the **Hard Pre-Flight Clearance Gate**, this sequence is strictly prohibited:
1. **Query Preview Is Mandatory for Clearance**: Step 5 clearance question MUST NEVER be asked unless a valid, compilable multi-stage YARA-L query has been successfully probed (200 OK via `udm_search`) and displayed in a ````yara code block under the Pre-Flight Card on that turn.
2. **Immediate Halt on Query Failure**: If the query cannot be probed or compiled, the agent MUST NOT ask for clearance. The agent must halt immediately, state the compilation or data issue, and ask the analyst for clarification.

### B. Identity Disambiguation & 14-Day UDM Spot-Check
1. **The Single-Token Trap vs. Qualified Technical User IDs**:
   Analyst inputs with single unqualified first names (e.g., `"greg"`, `"frank"`) or display names containing spaces (`"Frank Kolzig"`) must NOT be presumed to be valid technical user IDs (`user.userid`).
   Conversely, qualified identifier strings containing a dot (e.g. `laura.hill`, `frank.kolzig`) or `@` email addresses (`user@company.com`) are already standardized technical `user.userid` values. They require zero display-name resolution and are ready immediately for baseline lookups and 1-shot compiler probing.
2. **Pre-Execution 14-Day UDM Spot-Check (For Unqualified Names Only)**:
   Before generating a Pre-Flight Hunting Specification Card for a standalone first name or human display name:
   ```python
   udm_search(
       query='target.user.userid = "<name>" nocase or principal.user.userid = "<name>" nocase or target.user.user_display_name = "<name>" nocase or principal.user.user_display_name = "<name>" nocase',
       startTime="<ISO_14D_AGO>",
       endTime="<ISO_NOW>",
       maxEvents=5
   )
   ```
3. **Hard Resolution Gate**:
   - If $\ge 1$ events match: Extract the authoritative `user.userid` and record: `• Target Entity / Scope: <Name> (Verified User ID: <id>)`.
   - If 0 events match or query fails: **HALT IMMEDIATELY (0 tools called)**. Do NOT guess a username. Do NOT emit a Pre-Flight Card. Ask:
     > *"I could not resolve an active technical `user.userid` for '<Name>' in recent UDM telemetry. What is their corporate email or technical username?"*

### C. Strict ISO 8601 Timestamps for Compiler Probes
1. **API Rejection of Relative Time Offsets**:
   Chronicle's `udm_search` API endpoint strictly requires absolute ISO 8601 UTC timestamps (e.g., `2026-09-04T17:00:00Z`). Passing relative strings such as `"now-10m"` or `"now"` causes the underlying API to fail with an unrecoverable `Internal error encountered`.
2. **Probe Protocol**:
   All 1-shot compiler validation probes must compute the current UTC timestamp and a 10-minute historical boundary formatted as explicit ISO 8601 strings:
   `udm_search(query="<query>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`

### D. Pillar 2 Executed Multi-Stage Query Integrity
1. **Executed Multi-Stage YARA-L Query Requirement**:
   In Step 2 of the triage report, Pillar 2 MUST display the literal executed multi-stage YARA-L query passed to `udm_search(query=...)`.
2. **Prohibition of Raw Event Filters in Pillar 2**:
   Raw UDM event filters (such as `principal.user.userid = "greg" or target.user.userid = "greg"`) do NOT compute statistical baselines and are strictly prohibited in Pillar 2. For 360 Entity Behavioral Risk Radar hunts, Pillar 2 must present the executed multi-stage sector micro-queries.

---

## 31. Dual-Plane Macro Baseline & Micro Telemetry Correlation (Release v1.6.0)

### A. The "Elephant & Script" Threat Model
Threat actors frequently leverage automated scripts or tools (`curl`, `python-requests`, PowerShell WebClient) to exfiltrate bulk data from enterprise servers.
* **Macro Risk Metrics**: Efficiently detect that host $H$ pushed $+3.5\sigma$ anomalous bytes today relative to its 30-day baseline via `metrics.network_bytes_outbound`.
* **Micro Telemetry Forensics**: Raw `NETWORK_HTTP` logs verify whether that volume was driven by an interactive browser with rich User-Agent diversity ($N \ge 10$) or an automated script ($N \le 2$).

### B. Pattern A: Intra-Query Golden Template (`hybrid_metric_raw_enrichment_2stage.yl2`)
When the exfiltration channel is known in advance to be HTTP, both planes can be joined in a single YARA-L 2.0 query:
* **Stage 1 (Macro Baseline)**: Scopes to `NETWORK_CONNECTION`, queries `metrics.network_bytes_outbound`, and groups by `$entity by 1d`.
* **Stage 2 (Micro Signature)**: Scopes to `NETWORK_HTTP`, groups by `$entity by 1d`, and aggregates `distinct_signatures = count_distinct(target.user_agent)`.
* **Root Stage (Fusion)**: Inner-joins `$entity by 1d` and enforces `$macro_z_score >= 3.0 and $signature_diversity <= 2`.
* **Join Budget**: 1 metric lookup + 1 stage join = **2 joins total** (safe under Chronicle limit $\le 4$).

### C. Pattern B: Two-Phase Federated Funnel (`RAW_TELEMETRY_ENRICHMENT`)
* **The Inner-Join Cliff**: If an adversary exfiltrates over raw TCP, SFTP, or DNS, Stage 2 yields 0 events, dropping the host from a Pattern A query entirely.
* **The Two-Phase Funnel**: When protocol is unconstrained, Phase 1 evaluates 50,000 hosts via `metrics.*` in seconds. The top outlier hosts are emitted in a `secops-threat-hunt-handoff-v1` payload with `intent: "RAW_TELEMETRY_ENRICHMENT"`, handing off to `secops-statistical-hunter` for targeted micro-forensic probes.

---

## 32. Family of 3 Canonical 2-Stage Hybrid Pipeline Archetypes (Mathematical Models 1–6)

To operationalize advanced statistical models without tripping Chronicle's join limit ($\le 4$) or Common Compiler outcome restrictions, Google SecOps utilizes a family of **three canonical 2-stage hybrid pipeline archetypes**. Each archetype executes as a single, native multi-stage YARA-L 2.0 query inside Chronicle SIEM (`udm_search`), consuming exactly **2 joins** (1 `metrics.*` pre-computed baseline lookup + 1 Root inter-stage join).

### Archetype 1: Entropy & Concentration (`hybrid_metric_entropy_concentration_2stage.yl2`)
* **Match Topology**: Symmetrical entity match (`$entity by 1d`).
* **Telemetry Join**: Macro network baseline (`NETWORK_CONNECTION` + `metrics.*`) $\bowtie$ Micro request vocabulary (`NETWORK_HTTP` or `NETWORK_DNS`).
* **Model 1: Information-Theoretic Diversity Deficit (Entropy Proxy)**:
  $$\text{Diversity Ratio} = \frac{k_{\text{distinct}}}{N_{\text{raw}} + 1.0}$$
  A low ratio ($\le 0.10$) reveals extreme repetition (e.g., automated scripts hitting 1–2 endpoints across thousands of requests), exposing entropy collapse without non-linear logarithms.
* **Model 2: Concentration Index & "Elephant Flow" Isolation (HHI / Gini Proxy)**:
  $$\text{Concentration Ratio} = \frac{\text{Peak Single Event Transfer}}{\sum \text{Raw Transfers} + 1.0}$$
  A high ratio ($\ge 0.75$) isolates massive single-destination transfers (elephant flows) from diffuse distributed web traffic.

### Archetype 2: Orthogonal Threat Space (`hybrid_metric_orthogonal_space_2stage.yl2`)
* **Routing Triggers**: Dormant account awakening, cold-start entity activity, sub-threshold multi-target probing, orthogonal threat space, joint Bayesian log-odds fusion, or multi-dimensional threat distance norm ($D^2$).
* **Match Topology**: Symmetrical entity match (`$entity by 1d`).
* **Telemetry Join**: Macro historical intensity baseline $\bowtie$ Contemporary forensic breadth hits.
* **Model 3: Joint Bayesian Additive Log-Odds Score**:
  $$\text{Joint Odds} = (0.6 \cdot Z_{\text{intensity}}) + (0.4 \cdot Z_{\text{breadth}})$$
  Fuses two sub-threshold anomalies ($Z \approx 2.2\sigma$) that individually escape alerting into a high-confidence compound detection.
* **Model 4: Two-Part Hurdle Model (Dormant Account / Cold-Start Awakening)**:
  $$\text{Condition: } \text{Active Days} \le 2 \land \text{Breadth} \ge 3 \land N_{\text{raw}} \ge 1$$
  Accounts for zero-inflated distributions by checking the discrete hurdle (was entity dormant?) before measuring contemporary burst volume.
* **Model 5: 2D Euclidean Threat Distance Norm**:
  $$D^2 = Z_{\text{intensity}}^2 + Z_{\text{breadth}}^2 \ge 16.0 \quad (\implies D \ge 4.0\sigma)$$
  Evaluates geometric distance from nominal behavior in coordinate space. Ranking directly by squared threat norm ($D^2$) avoids unnecessary square root computations; when deriving Euclidean distance $D$, use namespaced `math.sqrt($norm_sq)` (bare `sqrt()` is invalid).
* **Canonical YARA-L 2.0 Multi-Stage Search DAG**:
  ```yara
  // Stage 1: Macro Baseline (Axis 1: Historical Intensity)
  stage stage1_macro_intensity {
      network.sent_bytes > 0
      network.sent_bytes < 1000000000000000
      principal.asset.hostname = $host
      $host != ""

    match:
      $host by 1d

    outcome:
      $observed_intensity = sum(network.sent_bytes)
      $hist_mean = max(metrics.network_bytes_outbound(
          period: 1d, window: 30d, metric: value_sum, agg: avg,
          principal.asset.hostname: $host
      ))
      $hist_stddev = max(metrics.network_bytes_outbound(
          period: 1d, window: 30d, metric: value_sum, agg: stddev,
          principal.asset.hostname: $host
      ))
      $hist_active_days = max(metrics.network_bytes_outbound(
          period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
          principal.asset.hostname: $host
      ))

      $z_intensity = ($observed_intensity - $hist_mean) / if($hist_stddev > 0, $hist_stddev, 1.0)
  }

  // Stage 2: Micro Telemetry (Axis 2: Contemporary Forensic Breadth)
  stage stage2_micro_breadth {
      metadata.event_type = "NETWORK_CONNECTION"
      principal.asset.hostname = $host
      $host != ""
      target.ip != ""

    match:
      $host by 1d

    outcome:
      $raw_hits = count(metadata.id)
      $distinct_breadth = count_distinct(target.ip)
      $destination_sample = array_distinct(target.ip)
  }

  // Root Stage: Common Compiler Orthogonal Threat Space Fusion
  $host = $stage1_macro_intensity.host
  $host = $stage2_micro_breadth.host

  match:
    $host by 1d

  outcome:
    $z_intensity = max($stage1_macro_intensity.z_intensity)
    $hist_days = max($stage1_macro_intensity.hist_active_days)
    $raw_hits = max($stage2_micro_breadth.raw_hits)
    $breadth_count = max($stage2_micro_breadth.distinct_breadth)

    // Standardized Micro Breadth Score (Zero-dispersion floor safe)
    $z_breadth = ($breadth_count - 1.0) / (2.0 + 1.0)

    // Model 5: 2D Euclidean Threat Distance (Squared Norm)
    $intensity_sq = $z_intensity * $z_intensity
    $breadth_sq = $z_breadth * $z_breadth
    $threat_distance_sq = $intensity_sq + $breadth_sq

    // Model 3: Joint Bayesian Additive Log-Odds Score
    $joint_odds_score = (0.6 * $z_intensity) + (0.4 * $z_breadth)

    // Continuous Linear Outcome Regularization
    $z = (0.5 * $joint_odds_score) + (0.5 * $threat_distance_sq)

  condition:
    $threat_distance_sq >= 16.0 or ($joint_odds_score >= 2.5 and $raw_hits >= 3) or ($hist_days <= 2 and $breadth_count >= 3 and $raw_hits >= 1)

  order:
    $threat_distance_sq desc
  ```

### Archetype 3: Fleet Prevalence Normalization (`hybrid_metric_fleet_prevalence_2stage.yl2`)
* **Routing Triggers**: Workstations with abnormal file execution spikes launching rare binaries or unfamiliar hashes, Patch Tuesday fleet rollouts, corporate software rollout shielding, or fleet-wide token prevalence normalization (`prevalence.rolling_max <= 3`).
* **Match Topology**: Token-centric match key (`$token by 1d`), joining an entity's anomalous execution to fleet-wide breadth.
* **Telemetry Join**: Personal process execution baseline (`metrics.file_executions_total`) $\bowtie$ Fleet-wide host execution count and Entity Graph Derived Context on the same binary hash (`principal.process.file.sha256`).
* **Model 6: Cross-Sectional Odds Ratio (Patch Tuesday / Corporate Rollout Shield)**:
  $$\text{Dampener} = \frac{1.0}{k_{\text{fleet}} + 1.0}, \quad \text{Normalized Score} = Z_{\text{personal}} \cdot \text{Dampener}$$
  If 500 endpoints execute an updated binary today, the prevalence dampener collapses the score to $\sim 0.002$, neutralizing false positive fleet-wide alerts. If only 1–2 endpoints execute the binary, full anomaly weight ($\ge 0.33$) is preserved.
* **Affirmative Template Selection**:
  When hunting for abnormal file execution surges across workstations normalized against fleet-wide rollouts (Patch Tuesday Shield), directly deploy `templates/pipelines/hybrid_metric_fleet_prevalence_2stage.yl2`:
  * Stage 1 (`stage1_personal_surge`): `metadata.event_type = "PROCESS_LAUNCH"`, `metrics.file_executions_total(...)` with `principal.asset.hostname = $entity` and `principal.process.file.sha256 = $token`, computing `$personal_z = ($observed_val - $hist_mean) / if($hist_stddev > 0, $hist_stddev, 1.0)`.
  * Stage 2 (`stage2_fleet_prevalence`): `metadata.event_type = "PROCESS_LAUNCH"`, `principal.process.file.sha256 = $token`, matching `$token by 1d`, computing `$fleet_adopters = count_distinct(principal.asset.hostname)`.
  * Root Stage: Matching `$token by 1d`, computing `$prevalence_dampener = 1.0 / ($fleet_adopters + 1.0)` and `$normalized_odds_score = $personal_z * $prevalence_dampener`, ordered by `$normalized_odds_score desc`.
* **Implementation Paths in Stage 2**:
  For rare binary or rare domain hunting, pair primary UDM telemetry with Entity Graph Derived Context:
  ```yara
  metadata.event_type = "PROCESS_LAUNCH"
  timestamp.get_date(metadata.event_timestamp.seconds) = "<today UTC, YYYY-MM-DD>"   // Mode A: startTime D-2 00:00Z (Rule 5)
  principal.process.file.sha256 = $token
  $graph.graph.metadata.entity_type = "FILE"
  $graph.graph.metadata.source_type = "DERIVED_CONTEXT"
  $graph.graph.entity.file.sha256 = $token
  $graph.graph.entity.file.prevalence.day_count = 10
  $graph.graph.entity.file.prevalence.rolling_max <= 3
  $graph.graph.entity.file.prevalence.rolling_max > 0
  ```

---
*Created and maintained by Greg Kushmerek for Google SecOps Chronicle SIEM threat hunting workflows.*

---

## 32. Authoritative UDM Schema & Anti-Hallucination Field Guide

To prevent query compilation errors caused by invalid UDM field references (e.g. `target.user_agent` vs `network.http.user_agent`), always verify UDM fields against the canonical field dictionary in [`references/udm-hunting-field-dictionary.md`](references/udm-hunting-field-dictionary.md).

Key Invariants:
- **`NETWORK_HTTP`**: User agent is `network.http.user_agent`. HTTP methods and response codes are `network.http.method` and `network.http.response_code`. Destination URLs are `target.url` and `target.hostname`.
- **`NETWORK_FLOW` / `NETWORK_CONNECTION`**: Transfer volumes are `network.sent_bytes` and `network.received_bytes`. L4 protocol is `network.ip_protocol` (`"TCP"`, `"UDP"`). L7 protocol is `network.application_protocol` (`"HTTP"`, `"DNS"`).
- **`PROCESS_LAUNCH`**: Executable paths and hashes are under the file sub-message: `principal.process.file.full_path` and `principal.process.file.sha256`. Command line is `principal.process.command_line`.
- **`USER_LOGIN`**: Authenticated account is `target.user.userid`. Client source machine is `principal.asset.hostname` / `principal.asset.ip`.

---

## 33. Network Session Frequency & C2 Beaconing Detection (`metrics.network_flows_*`)

### A. The Volumetric Blindspot in Command & Control (C2)
Traditional network anomaly detection relies heavily on `metrics.network_bytes_outbound` to catch data exfiltration. However, advanced command-and-control (C2) implants, reverse shells, and automated keep-alive polling exhibit the opposite profile:
* **Payload Footprint**: Extremely low (e.g. 64–512 bytes per packet).
* **Connection Frequency**: Exceptionally high (hundreds or thousands of periodic sessions per day).

When evaluated against a host's volumetric baseline (e.g. 500 MB/day), 2,000 beaconing sessions transferring a total of 1 MB will produce **zero baseline deviation** ($Z_{\text{bytes}} \approx 0.0\sigma$).

### B. The Flow-Frequency Solution (`metrics.network_flows_outbound`)
To detect stealthy beaconing, micro-session tunneling, and port/host sweeps, the pipeline queries `metrics.network_flows_outbound`:
* **Engine Pre-Computation**: Shards 10, 11, and 12 in Malachite aggregate every non-zero byte session as `1 AS total_events`.
* **Compiler Rule**: Strictly requires `metric: event_count_sum`.
* **Behavioral Baseline**: Evaluates whether the host is opening an abnormal number of outbound connections compared to its personal 30-day baseline ($Z_{\text{flows}} \ge 3.0\sigma$).

### C. Payload Density & Elephant Flow Classification
By combining observed outbound bytes with observed outbound flows in Stage 1, the pipeline calculates **Payload Concentration (Bytes per Flow)**:

$$\text{Payload Concentration} = \frac{\sum \text{network.sent\_bytes}}{\text{count}(\text{metadata.id}) + 0.001}$$

* **Low Payload Concentration (< 2,048 bytes/flow) + High $Z_{\text{flows}}$**: Confirms lightweight C2 heartbeats, port scanning, or recon polling.
* **High Payload Concentration (> 1,000,000 bytes/flow) + High $Z_{\text{bytes}}$**: Confirms bulk exfiltration or "Elephant Flow" data staging.

### D. Canonical Pipeline Template: `c2_beacon_flow_frequency_2stage.yl2`
Use the pre-built pipeline in `templates/pipelines/c2_beacon_flow_frequency_2stage.yl2` for out-of-the-box C2 beaconing detection combining flow frequency baselining with target IP persistence analysis.

