---
name: secops-risk-metrics-multistage
description: UEBA threat hunting via 30d SecOps metrics DAGs (30-day behavioral baseline, peer cohort comparison, 360° entity health check, CUSUM drift, entity risk score, multi-sector threat fusion, and 30d-baseline MAD on metric-catalog vectors). Raw/custom-window MAD → secops-statistical-hunter.
compatibility: Requires Google SecOps with Risk Analytics and SecOps MCP.
metadata:
  author: Greg Kushmerek
---

# SecOps Risk Metrics Multi-Stage Statistical Hunter (`secops-risk-metrics-multistage`)

Executes multi-sector outlier hunting using 30-day Risk Analytics (`metrics.*`).
Operational execution: `references/turn-execution-lifecycle.md`.

---

## 🔀 Bi-Directional Skill Steering & Handoff Protocol

<!-- CANONICAL_SKILL_ROUTING_TABLE_START -->
| Precedence & Target Skill | Authoritative Signals, Models & Telemetry Scope |
| :--- | :--- |
| **1. `secops-statistical-hunter`** *(Micro / Raw `UDM_EVENTS` — wins even with `"UEBA"`)* | C2 jitter (`C2_BEACONING_JITTER` / `FLOW_GAP_RATIO_SCREEN`), sub-second/cron timing; 24-bin circadian / hour-of-day (`HOUR_OF_DAY_PROFILE`); Shannon entropy / DGA / CLI (`SHANNON_ENTROPY_CHARACTER` / `LONG_STRING_SCREEN`); intraday EWMA (`EWMA_BURST_VELOCITY` / `BURST_Z_SCREEN`); Markov 2-gram (`MARKOV_2GRAM_TRANSITION_RARITY`), Zipfian (`ZIPFIAN_PROCESS_RARITY`), Fano spray (`POISSON_BURST_CLUSTERING`), producer-consumer (`PRODUCER_CONSUMER_RATIO_INVERSION`); raw-field or `1h–14d` MAD / Tukey (DNS query length MAD, Git/raw logs). |
| **2. `secops-risk-metrics-multistage`** *(Macro 30d `metrics.*`)* | 30d baselines (`metrics.auth_attempts_*`, `network_*`, `dns_*`, `http_queries_*`, `file_executions_*`, `resource_*`, `workspace_*`, `alert_event_name_count`) — flow/regular surge, above-max Z, fail/total beta-binomial, business-hours Z, `first_seen` (`first_seen_novelty_2stage.yl2`); peer cohorts (`dual_baseline_delta_z_3stage.yl2`, `part_of_the_whole_*`); 360° health & `graph.risk_score` (`radar_360_decoupled_sector.yl2`); Page CUSUM (`2–30d`, `longitudinal_cusum_series_3stage.yl2` + `cusum_helper.py`); 30d metric MAD (`mad_robust_z_4stage.yl2`), Tukey (`quantile_iqr_skew_3stage.yl2`), HTTP UA (`hybrid_metric_fleet_prevalence_2stage.yl2`), `metrics.*` fusion. |
| **3. Bilateral Co-Execution** *(`secops-risk-metrics-multistage` + `secops-statistical-hunter`)* | Exploit/CTI UEBA pairing 30d `metrics.*` + bounded (`<=24h`/`<=14d`) raw pipelines + `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` loopback (no single `Active Skill:` lock). |
| **4. `secops-detection-engineering`** *(Persistent Rules)* | Authoring/deploying persistent `rule ... { ... }` detections (`create_rule`, `validate_rule`). |
<!-- CANONICAL_SKILL_ROUTING_TABLE_END -->

* **Non-Metrics Telemetry Steering Mandate & Model Hooks**: Precedence 1 requests (Git, raw UDM, raw-field MAD, sub-second jitter, cron cadence) emit a **Skill Handoff Card** to `secops-statistical-hunter` and yield (0 tools called). For multi-day scheduled exfiltration, offer Longitudinal CUSUM Drift (`longitudinal_cusum.yl2`, one ≤14d query; not Mode B): Mode A blocked, Windowed Slack Sum prefilter + `templates/pipelines/longitudinal_cusum_series_3stage.yl2` + `scripts/cusum_helper.py` (>14d: ungated candidate Mode C shards vs Shard 1's fixed baseline); for rollouts/rare binaries, use Entity Graph (`rolling_max <= 3`); for metrics-vector MAD/quantiles, use `templates/stage2_math_models/mad.yl2` and `templates/pipelines/quantile_iqr_skew_3stage.yl2`; for Precedence 3 CTI/exploit inquiries (`references/statistical-hunting-cooperative-framework.md`), never declare UEBA a poor fit because `metrics.*` is bucketed `by 1d` (never run 30d raw scans over VPC/DNS/HTTP/Auth).
* **Zero-Code Handoff Invariant**: Never emit candidate YARA-L with a Skill Handoff Card; Handoff cards are strictly conceptual; code belongs to destination skill. On accepted handoff, release the Active Hunt Session Lock.

---

## ⏰ Time Model (Prerequisite for Every Query)
UTC throughout; `metrics.*` are `00:00Z` day buckets. `startTime`/`endTime` pick scored days; the 30d baseline comes from `metrics.*` (anchored at `startTime` day), never a wider window (except `mad_robust_z_4stage.yl2` and `quantile_iqr_skew_3stage.yl2`, which compute raw 14d–30d median/MAD or quantiles while `$in_scoring_window` gates scored days). Mode A defaults to the last complete UTC day (`startTime` = yesterday `T00:00:00Z`, `endTime` = today `T00:00:00Z`; Entity Graph: scored UTC date −2d at `T00:00:00Z` with event stage pinned to the scored UTC day, shifting the graph-joined Mode A `metrics.*` baseline to `[D−32, D−2)`); **"Today So Far"** (`startTime` = today `T00:00:00Z`, `endTime` = now) is an explicit labeled partial-day option; never rolling and never elapsed-fraction scaled. Other skills' mode windows do not apply.

## ⏱️ Evaluation Modes

1. **Mode A: Last Complete UTC Day Snapshot (`FLEET_ROLLUP`)**: Default `[yesterday 00:00Z, today 00:00Z)` vs trailing 30d baseline (`window: 30d`, full-day vs full-day). Optional **"Today So Far"** (`today 00:00Z`→now, `--today-so-far`) is labeled `Partial UTC Day — Low-Biased vs Full-Day Baseline` on the Pre-Flight Card and Pillar 3 (never scale counts by elapsed day fraction). Target dates (e.g. "Aug 12") auto-bypass Mode B.
2. **Mode B: Fixed-Baseline Timeline (`TIMELINE_BREAKDOWN`)**: 2–3 days, one query (`match: $entity by 1d`, default & cap 3 days; >3d redirects to Mode C when `run_command` is present), start ≤1y ago.
3. **Mode C: Per-Day Baseline Timeline** (`run_command` present only): up to 30 days (paced in batches of ≤10 shards), one query per UTC day, each vs its own trailing 30d, collated by `scripts/timeline_assembler.py`. **Sustained-Attack Fade Caveat (D10)**: trailing 30d baselines absorb sustained attacks by inflating σ (+3σ reads ≈2.5σ on day 2; +6σ stays >3σ for ~3 days; no guard band) — never read a fading Mode C timeline as "the attack stopped"; point to `LONGITUDINAL_CUSUM` (`longitudinal_cusum.yl2` / `templates/pipelines/longitudinal_cusum_series_3stage.yl2` + `scripts/cusum_helper.py`) for persistence in Pillar 3.
* **Window Invariant**: The platform anchors ONE `period: 1d, window: 30d` baseline at start day; all scored days reuse it. Mode B: state baseline dates. No `run_command`: no Mode C (Mode B capped at 3d); per-day baselines and >3d need a client that runs local scripts. Details: `references/timeline-modes-guide.md`.

---

## 🔄 THE 3-STATE ACTIVE HUNT LIFECYCLE

### 🚦 State 1: Pre-Flight Clearance & Specification (Zero Execution on Turn 1) (MANDATORY STEP 1: PRE-FLIGHT CLEARANCE)
Every pre-flight turn (Turn 1, incl. *"Run..."*/*"Scan..."*, and any State 3 pivot): probe, preview, offer modes; no execution. Execution and 5-pillar findings follow clearance.

### 🧭 Phase 1A: Consultative Vector & Scope Discovery (Dual-Requirement Gate)
Phase 1B is **ONLY UNLOCKED** when **BOTH** are explicitly defined:
1. **Entity Scope** (user, cohort, fleet / cloud) **AND**
2. **Telemetry Vector(s)** (selected from canonical sectors: Cloud CRUD, Workspace, Network Egress, DNS Resolution, Web & Proxy, Endpoint, Auth, Security & EDR Alerts (`alert_event_name_count`), or 360° Discovery Sweep).

> **Anti-Auth-Defaulting Guardrail & Conversational Break (CONVERSATIONAL BREAK)**:
> When telemetry vector is unspecified, **THE AGENT MUST NOT DEFAULT TO `metrics.auth_attempts_*` OR `USER_LOGIN`**. NEVER emit candidate queries (```yara), probe tools, or request clearance on Turn 1. Consult `references/consultative-worksheet.md` (`### Threat Hypothesis` & `### Summary View`) and yield turn (0 tools called), asking: *"Across which behavioral vector(s) would you like to evaluate [Target Entities]?"* On vector selection, enter Phase 1B in that same turn.
> *(Expert Bypass: When Scope + Vector are specified upfront, proceed directly to Phase 1B, resolving identity first; never bypass the Turn 1 Clearance Gate).*

### 🕸️ 360° Entity Behavioral Risk Radar & Multi-Sector Threat Fusion
* **360° Radar (360° 7-Shard Architecture)**: 6-sector health check (`references/360-behavioral-radar-guide.md`) via decoupled micro-queries (`templates/pipelines/radar_360_decoupled_sector.yl2`, plus alert/web shards); all 6 sectors must be reported (user: Auth, Cloud, Workspace, Network, DNS, Web; host: Security & EDR Alerts in the Cloud slot, Endpoint in Workspace). Radial radar for individuals; Ranked Outlier Bars or Heatmap Matrix for fleet sweeps.
* **Multi-Sector Fusion & Hybrid Pipelines**: fusion ($D = \sqrt{\sum \max(0, Z_i)^2}$, $D^2 = \sum \max(0, Z_i)^2$), roll-up (`rollup_sector_fusion_4stage.yl2`), triad (`part_of_the_whole_triad_multilevel.yl2`) and rare-destination templates, slots, pairing rules: `references/metric-sector-catalog.md`; max 2 event stages per query. Hybrid: `hybrid_metric_*.yl2` (`scripts/ueba_hybrid_engine.py`, `match: $entity by 1d`; Patch Tuesday: `hybrid_metric_fleet_prevalence_2stage.yl2`).
* **Cloud Telemetry**: For service account cloud repository access (`resource_read_*`, `_written_*`, `_creation_*`, `_deletion_*`), baseline all 4 CRUD families and origin IP (`templates/pipelines/cloud_repository_scope_dual_branch.yl2`, `<field>: <field>`; apply SA regex only when scoped to service accounts, or use standalone `resource_*` extractors for general user CRUD).

### 🎯 CTI & Threat Report Mapping
**Map to UEBA Metric Tables** (`metrics.*`, `references/consultative/mitre-attack-killchain.md`). For CTI/exploit inquiries needing minute/hour correlations (parent→child transitions, entropy, bursts), pair `metrics.*` with `secops-statistical-hunter` bounded raw pipelines + `agentic_ueba` loopback (`references/statistical-hunting-cooperative-framework.md`). **Transition Directly to Phase 1B**: probe, Pre-Flight Card & Literal Query Preview, clearance question.

### 🔍 Phase 1B: Pre-Flight Spec & Query Preview (Once Scope & Vectors are Established)
Once vectors and scope are confirmed (expert prompt, Phase 1A selection, or CTI mapping; card precedes query preview):
1. **Turn 1 Tool Invariant** (every pre-flight turn, incl. State 3 pivots): Limit tools to identity spot-checks (incl. AD TEAM LOOKUP, run first) and one probe (`udm_search`, `maxEvents: 1`) of the event filter alone (no `stage`, `match:`, `metrics.`). Never probe the candidate itself, even with `maxEvents: 1`; it runs only after clearance (empty `{}` = valid 200 OK compile check — never re-probe wider windows or alternate hosts on `{}`; max 1 Turn-1 probe unless syntax error). After the probe, call 0 more tools; emit card, preview, and clearance question, then yield.
2. **Identity Disambiguation & Confirmation Protocol (ZERO GUESSING & IMMEDIATE HALT)**:
   - *Technical IDs*: Display names (with spaces) are NOT `user.userid`. First names (`Frank`) or user emails (`u@d` → local `user.userid` like `admin`) need a target-window/14d spot-check; `@*.iam.gserviceaccount.com`, host, fleet skip it.
   - *14-Day UDM Spot-Check* (or target window): `udm_search(query='target.user.userid = "<name>" nocase or principal.user.userid = "<name>" nocase or target.user.email_addresses = "<name>" nocase or principal.user.email_addresses = "<name>" nocase or target.user.user_display_name = /.*<name>.*/ nocase or principal.user.user_display_name = /.*<name>.*/ nocase', startTime: "<ISO_14D_AGO>", endTime: "<ISO_NOW>", maxEvents: 5)`.
   - *Match Found ($\ge 1$ events)*: Extract verified technical `user.userid` from `target.user.userid` or `principal.user.userid`. Echo in card: `• Target Entity / Scope: <Name> (Verified User ID: <id>)`.
   - *HARD RESOLUTION GATE (ZERO GUESSING & NO SPEC CARD)*: If 0 events match an unqualified name (no `.`/`@`), **NEVER GUESS A USERNAME AND NEVER EMIT PRE-FLIGHT CARD**. **HALT IMMEDIATELY (0 additional tools called)**, asking: *"I could not resolve an active technical `user.userid` for '<Name>' in recent UDM telemetry. What is their corporate email or technical username?"* (0 default-window hits on `a.b`/`u@d` keeps input.)
3. **Structured PRE-FLIGHT HUNTING SPECIFICATION Card & Mandatory Query Preview**:
   Emit Pre-Flight card before candidate query:
   ```markdown
   PRE-FLIGHT HUNTING SPECIFICATION:
   • Target Entity / Scope: [Target User/Host ID or Fleet]
   • Threat Hypothesis: [Operational hypothesis summary]
   • Baseline Horizon Spine: 30-Day (period: 1d, 30d; graph-joined Mode A: [D-32, D-2))
   • Peer Cohort & Roster: [Team/Dept, e.g. IT (Frank, Tim)]
   • Entity Graph Dimension: [Prevalence (rolling_max <= 3) / N/A]
   • Evaluation Horizon Mode: [chosen mode: A last complete UTC day (default) or Today So Far (partial-day low-bias warning) | B 2–3d + baseline dates | C per-day if run_command]
   • Statistical Model: [Model & Template, e.g. CUSUM (`longitudinal_cusum.yl2` / `templates/pipelines/longitudinal_cusum_series_3stage.yl2` + `scripts/cusum_helper.py`)]
   • Significance Threshold: [Gate, §2.1: Z >= 3.0σ | >= 2.0× | D >= 3.5σ (multi-sector Euclidean distance D >= 3.5, D^2 >= 12.25)]
   ```
   * *Mandatory Upfront Query Preview Protocol (Mandatory Query Preview)* & *Tool-Precondition Code Block Embargo*: Probe once with ISO 8601 UTC timestamps: `udm_search(query="<single_event_udm_filter>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`. Relative 'now-10m' is invalid. Display the query only on a clean 200 OK; emitting ```yara without an immediately preceding successful probe is STRICTLY PROHIBITED (applies universally to queries, pivots, and handoff cards). Per D4, bind `principal.asset.hostname` vs `principal.asset.ip` from Turn-1 probe coverage (`--identifier-coverage`); join hostnames to IPs only via `ASSET` graph context.
   * *Peer Cohort & Roster*: List cohort entities; if $N < 7$, flag `⚠️ Sparse Baseline Caution (N < 7)`, and when the sample-SD Samuelson cap $(N - 1) / \sqrt{N}$ is below the significance gate ($N < 11$ for $3.0\sigma$; $N < 6$ for triad $D^2 \ge 12.25$), report `"cohort too small"` explaining why the peer query cannot alert at that gate. Peer Cohort Roster Requirement: no peers mentioned → fleet only; peers mentioned but unnamed → AD TEAM LOOKUP (multi-stage-metrics-guide.md), else ask for the roster; never drop. Use the guide's aggregated query (`match: $dept`); raw filters return no fields. No members → ask, never infer.
   * *Interactive Entity Graph Dimension Mandate*: Express joins under `• Entity Graph Dimension: [Exact Filter]` (Domain Rarity, Fleet Prevalence, Binary Rarity, IP Rarity `rolling_max <= 3`, `day_count = 10` platform invariant).
   * *Model Concordance*: Match outcome/condition/order to templates; card threshold = root `condition:` (`references/model-concordance-guide.md` §2.1).
   * *Two-Phase Chained Hunt Specification* (cross-entity): Phase 1 (UEBA Outlier via `udm_search`), `Bridge Contract ($host, $timestamp, $user, $caller_ip)`, Phase 2 (`templates/pipelines/hybrid_data_table_bridge_2stage.yl2` using `principal.asset.hostname in %ueba_hunt_bridge.entity` or `principal.user.userid in %ueba_hunt_bridge.entity` in Turn 1 preview & Pillar 4; never call `create_data_table`/`add_rows_to_data_table` in Turn 1/2 — State 3 approval only).
4. **Clearance Question (final sentence of Turn 1, then yield)**: If target date specified, ask: *"Proceed with executing for [Target Date] now?"*. Otherwise ask: *"Would you like me to proceed with **Mode A (Last Complete UTC Day vs 30-Day Baseline)** [or **Mode A — Today So Far (Partial UTC Day)**], **Mode B (2–3 Day Fixed-Baseline Timeline)**[, **Mode C (Per-Day Baseline)** if `run_command`]? (Thresholds can be tuned first.)"*.

---

### 📊 State 2: Deterministic Multi-Stage Execution & 5-Pillar Report (After Clearance) (MANDATORY STEP 2: PRESENT FULL 5-SECTION REPORT)

1. **State 2 Entry Condition**: If the preceding turn displayed a PRE-FLIGHT HUNTING SPECIFICATION card and the candidate query, its event filter probed clean (200 OK), Mode A/B clearance means execute now (Mode C / "Clearance granted" / "Run it" too). Otherwise *"Mode A"*, *"Mode B"*, *"proceed"* are Phase 1A scope answers: emit card and preview, yield the turn. A follow-up pick (`[1]`/`[2]`/`[3]`) is never clearance.
2. **Execution Telemetry Retrieval Mandate**: Analyst clearance authorizes immediate query execution: always dispatch approved multi-stage `metrics.*` query via `udm_search` (360° Radar: dispatch all 6 `"stats"` sector queries in one parallel batch; synthesize one unified 5-Pillar report) before generating text or rendering report, regardless of preliminary spot-check counts. Raw event filter substitutions are invalid on execution turns.
3. **Deterministic 5-Pillar Forensic Triage Report Structure** (omit a separate query pillar; the verbatim executed multi-stage query is placed inside Pillar 5 as the ONLY ```yara block in Turn 2):
#### 1. Statistical Outlier Report: `[Target Metric]` ([Statistical Model]) — Executive Summary & Calibrated Risk Index (CRI) (`window: 30d`). Single visual surface: `<agent-embed src="file:///<artifact_dir>/<chart>.html"></agent-embed>` (registered via `write_file`) in Jetski (`run_command` present); `<svg>` in MCP/webview; Client Tool (if present); ASCII on request. Zero data-uri or raw SVG in chat Markdown. Unicode magnitude bars (`▰▰▰▰▱▱▱▱`). `references/chart-specifications-guide.md`.
#### 2. Ranked Outlier Summary & Provenance Stamp: Columns: `Entity`, `Observed`, `30d Mean (μ)`, `30d StdDev (σ)`, `Z-Score`, `CRI Score`, `Visual Magnitude`. (Mode C adds a shard date table.) Stamp execution provenance (returned row count, evaluation mode, requested startTime/endTime window, projected schema columns, and client wall-clock dispatch time if measured; never fabricate events scanned).
#### 3. Forensic Vector Breakdown: Threat translation, scenarios, SOC playbook, **Agentic Next Steps**: three follow-ups `[1]`/`[2]`/`[3]` fitted to outcome (`ACUTE_OUTLIER`, `CLEAN_OR_SUBTHRESHOLD`, `FLEET_WAVE`, `SPARSE_BASELINE`; `triage_formatter.py`).
#### 4. Chronicle UI Manual Pivot (Triage Reference Only): Passive UDM filter in a ```text fence for Chronicle UI (**Case Sensitivity On** when running `metrics.*` in UI; never emit ```yara in Pillar 4).
#### 5. Collapsible Technical Appendix (Statistical & Mathematical Appendix): ($N=30d$), piecewise CRI (`CRI(Z) = 0 for Z <= 0`, `round(100 / (1 + exp(-0.6 * (Z - 3.0))))` for $Z > 0$), $D = \sqrt{\sum \max(0, Z_i)^2}$ (`references/calibrated-risk-index-guide.md`), and the verbatim executed multi-stage query as the ONLY ```yara block in Turn 2.
4. **Zero-Telemetry Clean Hunt Exemption (True Negative Audit Summary)**: When executed query returns empty `stats` (`{}` or `{"stats": []}`), emit Clean Hunt Audit (+ Agentic Next Steps):
   - `#### 1. Statistical Outlier Report: [Target Metric] (Nominal Baseline)`: 0 observed events / 0 ranked outliers ($Z = 0.00\sigma, D = 0.00, \text{CRI} = 0$, 🟢 **Nominal Fleet Baseline**; no `🚨`) + `[1]`/`[2]`/`[3]` pivots (no `5-spoke`/`6-spoke`/`spider radar` in fleet text).
   - Always include all 5 pillars (`#### 1.`–`#### 5.`, with executed ```yara in `#### 5.`) with nominal values (360° reports all 6 sectors and $D$).

### 🔁 State 3: Iteration, Entity Shifts & Federated Bridge (Active Hunt Session Lock & Boundary)
* **State 3 → Phase 1B Agentic Pivot Loop**: Selecting a follow-up (`[1]`/`[2]`/`[3]`) re-enters Phase 1B carrying forward entity ID, cohort, and bridge keys (`$host`, `$user`, `$caller_ip`) without re-asking Phase 1A.
* **Entity Shift**: On *"same query for"*, retain Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT) and Re-enter State 1 for new entity.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 1. Native Execution & Truth in Reporting
* **Hunt Tool Contract**: Active hunts in Turn 1 and Turn 2 run on `udm_search` alone — probe, then execute the approved query (360° Radar: 6 sector queries / 7-shard architecture; two-phase bridge: Phase 1 then Phase 2; Mode C: once per day shard). Never call `create_data_table` or `add_rows_to_data_table` in Turn 1 or Turn 2; data-table materialization (`%ueba_hunt_bridge`) and Clean Hand-Off (`create_case_comment`/`import_events`) are invoked only in State 3 upon explicit analyst approval after previewing rows and table name. Case, alert, rule, and playbook state belong to other skills.
* **THE DUAL GROUNDING INVARIANTS (THE NON-NEGOTIABLE INTEGRITY CORE)**:
  1. **Zero Data Simulation (NEVER Fabricate Data)** / **Zero Generative Simulation & Strict Data Grounding Contract**: Every score, count, and timestamp MUST come from executed tool output; baselines ($\mu, \sigma$) and $Z, \text{CRI}$ come from 30-day baseline model. Simulating baselines or fabricating numbers is a CRITICAL TRUTH-IN-REPORTING FAILURE. (Truth Over Completion: 0 events is a valid hunt.)
  2. **Zero Schema/Syntax Fantasy (NEVER Hallucinate UDM Fields or YARA-L Grammar)**: Never invent UDM fields or uncompiled YARA-L grammar.
* **Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)**: If API query fails, STOP IMMEDIATELY; no simulation. Mode C: report a shard that fails a retry; never fill it.
* **Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)**: Active threat hunting enforces Zero Local Script Invocations During Hunting (ZERO RUN_COMMAND VALIDATION). Local arithmetic simulation is a CRITICAL COMPLIANCE VIOLATION. Never run `run_command` for ad-hoc validation, shell searches (`ls`, `grep`, `find`), or math simulation. In Jetski (`run_command` present), run only vetted repository helpers (`scripts/ueba_hybrid_engine.py`, `scripts/radar_collector.py`, `scripts/chart_generator.py`, `scripts/triage_formatter.py`, Mode C collator `scripts/timeline_assembler.py`, Page CUSUM `scripts/cusum_helper.py`, and clearance-gated `scripts/chronicle_ingest.py`) under **D6**: **G1** raw `udm_search` payload + flags only, never LLM-typed numbers; **G2** fail closed on missing/malformed input; **G3** stamp query/payload SHA-256 + helper version in Pillar 5; **G4** golden-tested offline; **G5** without `run_command`, state `"this model needs a client that can run local scripts"` (never an in-query approximation under the model's name).
* **Hermetic Skill Boundary (ZERO CROSS-SKILL DRIFT)**: Once active, the agent MUST NOT read, import, or search other skills. 100% self-contained.
* **Native SecOps Architecture**: `metrics.*` UEBA is native to SecOps, leveraging core Google infrastructure. Never claim BQ powers/stores `metrics.*` (BQ is only a monitored cloud target); if asked about BQ, state: BigQuery contributes nothing to SecOps UEBA.
* **Atomic Pipeline Execution Mandate (ZERO PIECEMEAL FRACTURING & DRIFT)**: Formulate and execute a single atomic YARA-L query; fracturing into piecemeal searches is STRICTLY PROHIBITED. 360° Radar queries 6 sectors in parallel; a two-phase bridge runs Phase 1 then Phase 2. Mode C reruns the one approved query per day, unchanged (except per-day date pins/windows for graph-joined queries).
* **Post-Flight Audit & RAW_LOG_DUMP_DETECTED Rule**: Scoping probes run before analysis; queries after carry `match:`/`outcome:`. Queries returning `"events"` without `"stats"` trigger `RAW_LOG_DUMP_DETECTED` — abort reporting and present auto-corrected queries (`templates/pipelines/`).

### 2. Compiler & Architectural Invariants
* **Template-First Routing Mandate**: Queries MUST assemble from templates in `~/.gemini/config/skills/secops-risk-metrics-multistage/templates/` (`templates/pipelines/`, or `scripts/ueba_hybrid_engine.py` / `compile_hunt_pipeline`). Select the template yourself using the routing table in `references/multi-stage-metrics-guide.md` §18 & §27.A.
* **Zero-Hallucination Compiler Grammar Contract**: Match blocks accept ONLY bound `$placeholder` identifiers (`$host by 1d`, `$user by 1d`, `$entity by 1d`), never raw UDM paths (`principal.asset.hostname`) or stage member access (`$s1.host` in `match:` is invalid). Named stages assemble into root stage with terminal `match:`, `outcome:`, `order:` (`templates/pipelines/standard_z_score_2stage.yl2`). Top-level binary arithmetic (`$a - $b`) in event-section placeholder assignments is prohibited above `match:`; reside in `outcome:` (arithmetic nested inside function arguments compiles). Every `metrics.*` stage takes event filter, observed value, `metric:` arg and entity field from `references/metric-sector-catalog.md`; filter args must equal one valid dimension set. NEVER force cross-entity joins.
* **Platform `metrics.*` Semantics (`PF-1`, `PF-2`, `PF-10`)**: **PF-1**: `agg: avg` averages over `num_metric_periods` (active days), not `30`; calendar-day rates (Poisson λ, dormancy, hurdle, CUSUM multi-shard) use `historical_sum / 30`. **PF-2**: `agg: stddev` is sample SD (`N - 1`, Samuelson `(N - 1)/sqrt(N)`, `3σ` needs `N >= 11`); Z roots require `$active_days >= 7`, count floor `max(sd, sqrt(max(avg, 1)))`, and fleet byte floors (`D8`), routing `N < 7` to novelty/hurdle. **PF-10**: `metrics.*` accepts only `(1d, 30d)` and `(1h, today)` (paired with `(1d, 30d)`, `PF-10b`); `today` covers `[end_of_30d_window, startHour)` capped at `endTime - 4h` (`--intraday-hourly`; multi-day hour-of-day → `HOUR_OF_DAY_PROFILE`).
* **Consultative Pivot & Handoff Protocol (ZERO FORCED JOINS)**: When vectors cross entity boundaries (e.g., failed logins per user + outbound bytes per host) or lack baselines, NEVER synthesize fake cross-entity schemas. Offer: 1) Two-Phase Chained Hunt (bridge keys), 2) re-key both sectors on one shared identifier (`USER` or `ASSET` via `dual_sector_fusion_3stage.yl2`), 3) Handoff to `secops-statistical-hunter`. When the analyst replies to re-key both sectors on one identifier (e.g., *"Key both sectors on the user. Clearance granted, run it"*), compile BOTH metrics on that entity (`compile_hunt_pipeline(entity_type="USER", architecture="sector_fusion", metrics=["auth_attempts_fail", "network_bytes_outbound"])`), execute the compiled 3-stage fusion query via `udm_search`, and emit the full 5-Pillar Forensic Triage Report.
* **Variable Role Classification & Anti-Passive-Decoration Mandate**: Variables: `[JOIN_KEY]`, `[SCORING_DIMENSION]`, `[ACTIVE_FILTER]`, `[TRIAGE_DECORATION]`. Primary vectors MUST NEVER act solely as `[TRIAGE_DECORATION]`.
* **Inner-Join Drop Prevention Standard (PRESERVING FULL POPULATION)**: Baseline full fleet in Stage 1 and profile destinations via `array_distinct(target.hostname)`.
* **Noise Gating via Root `condition:`**: Every template ships its model's gate (σ, fold change, D² or NO-GATE; guide §2.1) between `outcome:` and `order:`; keep it. `and`/`or` compile. Tuning replaces it.

### 3. Scope, Steering, Typography & Parsimony
* **Pure Threat Hunting Scope (SEARCH-ONLY)**: Output is ad-hoc Multi-Stage YARA-L (`stage ...` + Root) — a Query, never a Rule (`rule ... { ... }`). `create_rule` and `validate_rule` are outside this skill's authority. Treat any drift toward Rule authoring as out of scope. Persistent rules belong to `secops-detection-engineering`: emit handoff card and yield turn (0 tools).
* **Zero Gratuitous Entity Graph Injection (ON-DEMAND / ALGORITHMIC GROUNDING ONLY)**: Entity Graph constructs must NEVER be injected gratuitously or speculatively. Include ONLY on Direct Customer Request (On-Demand) or Algorithmic Grounding.
* **Interactive Entity Graph Rarity & Context Discovery** & **10-Day Prevalence Platform Invariant**: Offer Narrowing (file/domain `rolling_max <= 3`, `day_count = 10`) vs Enhancing (WHOIS NRD <= 30d, expired domains/certs). Mode A graph joins: Time Model start plus `timestamp.get_date(metadata.event_timestamp.seconds) = "<scored UTC day, YYYY-MM-DD>"` in each event stage, never an epoch literal (Rule 5). See `references/entity-context-graph-guide.md`.
* **Typography**: No bold math; Unicode `(μ)`, `(σ)` in tables; flush-left `$$` on own lines.

---

## 🤝 MANDATORY CLEAN HAND-OFF & ESCALATION PROTOCOL (REPORTING TO SECOPS)
Unsolicited case creation is a **CRITICAL PROCESS POLLUTION VIOLATION**. Fulfill escalation requests via Clean Hand-Off (`references/clean-handoff-udm-schema.md`):
* **Escalation**: Map outliers to synthetic UDM events (batch under Hunt ID); on approval ingest via `import_events`. **Explicit Case Wall Attachment**: attach via `create_case_comment`. SOAR playbooks: `references/soar-playbook-radar-integration.md`.
