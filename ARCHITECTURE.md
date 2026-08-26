# ARCHITECTURE.md: Risk Analytics Multi-Stage Statistical Skill

## Objective
Develop a specialized, production-grade Agentic Skill (`secops-risk-metrics-multistage`) that constructs, validates, and executes multi-stage YARA-L DAG queries in Google Security Operations (SecOps). The skill utilizes pre-computed Google SecOps Risk Analytics metrics (`metrics.*`) as the Stage 1 data foundation and evaluates statistical outliers (MAD, Standard Z-Score, Variance/Fano Factor, Poisson Rarity, Coefficient of Variation) across subsequent stages.

---

## Core Architectural Constraints

### 1. Template Routing Engine (`.yl2` Library)
* The LLM is **strictly prohibited from generating YARA-L from scratch**.
* The LLM functions solely as an Intent and Parameterization Engine, selecting the metric, entity type, and statistical model.
* Python logic routes selections to a pre-validated library of composable `.yl2` templates (`templates/stage1_extractors/*.yl2` + `templates/stage2_math_models/*.yl2`).

### 2. Stage 1 Data Foundation & Universal Outcome Contract
* Stage 1 extracts active 24-hour UDM telemetry and joins 30-day pre-computed behavioral baselines via outcome metric functions (`metrics.<function_name>(period: 1d, window: 30d, ...)`).
* **Universal 6-Point Outcome Contract**: Every Stage 1 template emits the following standardized variables to guarantee downstream mathematical compatibility:
  1. `$observed_val`: Current window observed activity (count, bytes, flows).
  2. `$historical_avg`: 30-day baseline mean (`agg: avg`).
  3. `$historical_stddev`: 30-day baseline standard deviation (`agg: stddev`).
  4. `$historical_active_days`: 30-day baseline active periods (`agg: num_metric_periods`).
  5. `$historical_max`: 30-day peak observation (`agg: max`).
  6. `$historical_sum`: 30-day cumulative volume (`agg: sum`).

### 3. Strict 24-Hour (Current Day) Execution Window Clamping
* Pre-computed daily metrics (`period: 1d, window: 30d`) operate over 30-day historical rollup tables.
* Executing a Stage 1 search over $> 1\text{d}$ (e.g. 7d or 14d) produces metric alignment corruption.
* The execution layer **strictly clamps the Stage 1 search window to exactly 24 hours (the current day / today)**. Cross-day correlation or multi-source joins are handled downstream by the Python agent / MCP server.

### 4. Hourly Metric Constraints
* Hourly metrics (`period: 1h`) are strictly locked to `window: today`.
* Hourly metrics must always be paired with at least one daily metric (`period: 1d, window: 30d`) for that entity.
* Intra-day temporal windowing can also be achieved by Stage 1 matching `by 1h`, aggregating in Stage 2 across the 24 hours, and evaluating each hour in the Root Stage.

### 5. Pre-Flight Ingestion & Dimension Audit
* The Python validation layer checks the requested metric against the 38-metric catalog ([`references/metrics-catalog.md`](file:///usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/references/metrics-catalog.md)).
* Validates entity dimension combinations (`USER` vs `ASSET`) and warns the analyst if required backing log sources (EDR, Firewall, IdP, DNS) are missing or baseline confidence floors (`$historical_active_days < 7`) are violated.

### 6. Data Reduction & 4-Tier CommonMark Triage Formatting
* The Python layer truncates the SecOps API response to prevent LLM context exhaustion.
* Emits a CommonMark Cyber-First 4-Tier Structured Triage Report (Ranked Outliers, Baseline Envelope, Threat Translation Callout Card, SOC Triage Playbook, and 1-click drill-down query) plus typed Vega-Lite visualization specifications.

---

## Skill Input Schema
* `target_metric` (string): Pre-computed metric name (e.g. `network_bytes_outbound`, `auth_attempts_total`, `file_executions_total`, `dns_queries_total`).
* `entity_type` (enum): `USER` or `ASSET`.
* `entity_field` (optional string): Explicit UDM field override (e.g. `target.user.userid`, `principal.asset.hostname`).
* `statistical_model` (enum): `STANDARD_Z_SCORE`, `MAD`, `VARIANCE`, `POISSON`, `COEFFICIENT_OF_VARIATION`.
* `anomaly_threshold` (float): Extraction threshold (e.g. $Z > 3.0$, $M_Z > 3.0$, $F > 4.0$, $Z_P > 3.5$).
* `min_baseline_days` (optional int, default 7): Confidence threshold for active historical days.

## ⚙️ Verified Malachite Compiler & Grammar Specifications

1. **Stage 1 Tumbling Windows (`match: $entity by 1d`)**:
   - Emits discrete calendar daily buckets matching the 30-day baseline tables (`period: 1d`).
   - Root stage matches on `$entity` (unwindowed) to evaluate final stats without multi-level hop collisions.

2. **Linear AST Outcome Math**:
   - Outcome variable arithmetic is strictly linear (`$diff = $a - $b`, `$z = $diff / $c`).
   - Grouping parentheses `(` and bare `if()` calls on outcome variables are rejected by the parser.
   - Zero-division / flat-baseline protection is enforced in `condition: $stddev > 0 and $z >= 3.0`.

3. **Conditional Event Counting (`sum(if(..., 1, 0))`)**:
   - In YARA-L, counting events matching a condition must use `sum(if(condition, 1, 0))` rather than `count(if(..., metadata.id))`.

4. **Dual-Anchor Hourly Metric Constraint**:
   - Whenever an hourly metric (`period: 1h, window: today`) is queried in a stage, that stage MUST ALSO declare at least one daily anchor metric (`period: 1d, window: 30d`).

5. **No `options:` in UDM Search Queries**:
   - The `options:` block is valid only in continuous detection rules, not ad-hoc search queries.

### ⚠️ Log-Type Filtering & Subset-to-Whole Baseline Integrity

- **The Integrity Principle**: Pre-computed Risk Metrics (`metrics.*`) aggregate across **all telemetry sources** matching the metric's event type (e.g., `metrics.http_queries_total` aggregates all web logs: proxies, firewalls, and Chrome).
- **The Anti-Pattern**: Filtering Stage 1 to a specific log type (e.g. `metadata.log_type = "CHROME_MANAGEMENT"`) when the metric baseline includes multiple log sources creates an **asymmetrical Part-to-Whole comparison** ($x_{\\text{subset}} < \\mu_{\\text{total}}$), mathematically distorting Z-scores.
- **Skill Requirement**: When an analyst requests filtering by a specific log source, vendor, or product:
  1. Verify if the underlying Risk Metric is scoped to that source in `config.textproto` (e.g., `WORKSPACE_*` is already scoped to Google Workspace).
  2. If the metric is broad, **issue a clear integrity advisory** informing the user of the potential baseline skew unless that log type is their sole telemetry source.
  3. Allow applying the filter if confirmed by the analyst.

6. **String Outcome Aggregation (`array_distinct`)**:
   - `max()` and `min()` only accept numeric data types (`int`, `float`, `timestamp`).
   - String fields (e.g., `principal.process.command_line`, `principal.process.file.full_path`) in the `outcome:` section **must** use `array_distinct(...)` or `array(...)`.

7. **Two-Step Filter-First Binding Pattern in Stage 1**:
   - Always declare the UDM filter predicate first (`metadata.event_type = "PROCESS_LAUNCH"`).
   - Follow immediately with the variable binding on the next line (`$event_type = metadata.event_type`).
   - This ensures the compiler parser resolves predicate evaluation before binding variables for metric argument passing.

8. **Inline Condition Tuning Comments**:
   - Deliver permissive smoke-test condition by default (`$observed > 0`).
   - Include a concise commented block directly beneath it showing production/strict thresholds (`$active_days >= 7`, `$sigma > 0`, `$z_score >= 3.0`).

9. **Timeline Breakdown Assumption (Preserving Temporal Windows)**:
   - For 30-day baseline metrics (`period: 1d, window: 30d`), downstream stages **must always preserve the daily breakdown**:
     `$day_bucket = $stage1.window_start` and `match: $entity, $day_bucket by 1d`.
   - For daily intra-day metrics (`period: 1h, window: today`), downstream stages **must always preserve the hourly breakdown**:
     `$hour_bucket = $stage1.window_start` and `match: $entity, $hour_bucket by 1h`.
   - This ensures the results table displays chronological timeline data points rather than grouping away/collapsing days.

10. **Equality Comparison Operator (`=` vs `==`)**:
    - YARA-L 2.0 uses a single equal sign (`=`) for both variable binding and equality comparison (e.g., `$events_today = 0`, `$action = "ALLOW"`).
    - Double equals (`==`) is invalid syntax in YARA-L and causes a compilation parser error.

11. **window_start is a Built-in Stage Property**:
    - `window_start` has type `timestamp` and is automatically exposed on windowed stage outputs (e.g. `$stage1.window_start`).
    - Do not attempt to assign `$var = max(window_start)` inside Stage 1's outcome block (`max()` expects `int/float`).
    - In downstream stages, reference `$stage1.window_start` directly or use `count_distinct($stage1.window_start)`.

12. **UI Search Range & Dual Match Architecture**:
    - Clearly separate **Timeline Mode** (`match: $entity, $day_bucket by 1d`) from **Rollup Mode** (`match: $entity`).
    - Explain that `metrics.*` decorates active days with 30-day trailing statistics, but does not synthesize rows for silent/inactive calendar days.

13. **Intent-Driven Match Mode Selection**:
    - Query generator must differentiate between Timeline/Plotting queries (`match: by 1d`) and Rollup/Ranking queries (`match: $entity`).
    - Provide explicit user guidance on the recommended time range for the chosen query archetype.

14. **14-Day Maximum Multi-Stage Search Limit**:
    - Multi-stage DAG and join queries are hard-capped at 14 days (`336h`) by the search service.
    - Query guidance must strictly instruct analysts to bound searches to $\\le 14$ days.
