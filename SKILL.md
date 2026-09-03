---
name: secops-risk-metrics-multistage
author: Greg Kushmerek
description: |
  Multi-stage statistical outlier hunting in Google SecOps using pre-computed Risk Analytics metrics (`metrics.*`) chained into 2-to-4 stage DAGs.
  Triggers: "hunt with risk metrics", "multi-stage metrics outlier", "MAD on network bytes", "z-score on auth", "fleet outlier", "multi-sector fusion", "360 risk radar", "all risk vectors".
compatibility: Requires Google SecOps with Risk Analytics metrics enabled and the SecOps GUS MCP server (udm_search, get_operation).
---

# SecOps Risk Metrics Multi-Stage Statistical Hunter (`secops-risk-metrics-multistage`)

Executes **multi-sector statistical outlier hunting** using **30-day pre-computed Risk Analytics metrics (`metrics.*`)** in **2-to-4 stage DAGs**.

---

## 🔀 Bi-Directional Skill Steering & Handoff Protocol
* **30-Day Baselines** (`metrics.*`) / **Peer Cohorts** / **Multi-Sector Fusion**: Execute this skill (`secops-risk-metrics-multistage`).
* **Non-Metrics Telemetry Steering Mandate** (Git repos, raw UDM): Emit **Skill Handoff Card** and steer to `secops-statistical-hunter`.

---

## ⏱️ Evaluation Modes: Snapshot vs. 30-Day Longitudinal Sliding Timeline

1. **Mode A: Current-Day Snapshot (`FLEET_ROLLUP`)**: 24h search window vs 30d baseline (`window: 30d`). Evaluates current outliers (1 row/entity).
2. **Mode B: 30-Day Longitudinal Sliding Timeline (`TIMELINE_BREAKDOWN`)**: Multi-day horizon (`match: $entity by 1d`). Tracks daily evolution & CUSUM drift.

---

## 💡 How Risk Metrics Multi-Stage Analytics Work
Provide 3-step **Execution Framework Summary**: 1. **30d Baselines** (`metrics.*`), 2. **Multi-Stage DAGs**, 3. **Statistical Framework** ($Z$, MAD, Poisson, $\Delta Z$, CUSUM, $D$). Ask for more information.

---

## 🚦 MANDATORY STEP 1: PRE-FLIGHT CLEARANCE (ZERO EXECUTION ON TURN 1)

Whenever a hunt is initiated, **NEVER CALL SEARCH OR INGESTION TOOLS ON THAT TURN**.

### 🧭 Phase 1A: Consultative Vector & Scope Discovery (Dual-Requirement Gate)
Phase 1B (Query Preview & Spec Card) is **ONLY UNLOCKED** when **BOTH** are explicitly defined:
1. **Entity Scope** (specific user, peer cohort, or enterprise fleet) **AND**
2. **Telemetry Vector(s)** (Cloud CRUD, Workspace, Network Egress, Endpoint, or Auth).

> [!IMPORTANT]
> **Anti-Auth-Defaulting Guardrail & Conversational Break (CONVERSATIONAL BREAK)**:
> If an analyst specifies entities (*"compare user A to user B"*, *"check user X"*) but **omits the telemetry vector**, **THE AGENT MUST NOT DEFAULT TO `metrics.auth_attempts_*` OR `USER_LOGIN`**. Yield turn and ask:
> *"Across which behavioral vector(s) would you like to evaluate [Target Entities]?"* (Cloud CRUD, Workspace, Endpoint Tools, Network Egress, Auth, Multi-Sector Fusion).
> Analyst answers ONLY unlock Phase 1B (Spec Card & Query Preview); they are NOT clearance to execute.

### 🕸️ 360° Entity Behavioral Risk Radar (All-Vectors / Radial Profiling)
When an analyst asks to profile an entity across all vectors (*"visualize all risk vectors"*, *"radial/spider chart"*, *"full spectrum profile"*, *"360 health check"*, *"behavioral fingerprint"*):
1. **Mandatory 5-Sector Roster**: Above Pre-Flight Card, present canonical metric functions:
   • 🔑 **Authentication & Access**: `metrics.auth_attempts_success` (`target.user.userid`)
   • ☁️ **Cloud Resource CRUD**: `metrics.resource_creation_total` (`principal.user.userid`, vendor: "Google Cloud Platform", product: "Google Cloud Platform")
   • 📁 **Workspace & SaaS**: `metrics.workspace_total_download_actions` (`principal.user.userid`)
   • 🌐 **Network Egress**: `metrics.network_bytes_outbound` (`principal.user.userid`)
   • 🌐 **DNS & Web Activity**: `metrics.http_queries_total` (`principal.user.userid`; assets: `metrics.file_executions_total` with sha256).
2. **Compilable Micro-Query Template (ZERO CROSS-SECTOR JOINS)**: Decoupled per sector (`stage stage1_extract` matching `$user by 1d` with `max(metrics.*)` and root `$z_score = ($obs - $mu) / ($sigma + 1.0)`). Avoid multi-vector inner joins that drop quiet entities.
3. **Visualization Strategy (Single visual surface: Client Tool OR Embed OR Inline SVG OR ASCII)**:
   - **Adaptive Single-Surface Routing (NEVER Render Both ASCII & Visual)**:
     • *Jetski (`run_command` present)*: Write visual charts to HTML in `<artifact_dir>/<name>.html`, output ONLY `<agent-embed src="file:///<artifact_dir>/<name>.html"></agent-embed>` and link. Radar: `python3 scripts/radar_collector.py --entity "%(entity)s" --scores "auth=<Z1>,cloud=<Z2>,workspace=<Z3>,net=<Z4>,dns=<Z5>" --output "<artifact_dir>/radar_%(entity)s.html" --format embed`. Zero data-uri or raw SVG in chat Markdown. Omit ASCII card.
     • *Client Tool (if present)*: If active tool declares radar/SVG visualization, invoke with entity and sector scores. Omit ASCII card. Detail in `references/chart-specifications-guide.md`.
     • *Generic MCP (no tool)*: Emit pure inline `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 620 480">` in markdown. Zero data-uri.
     • *CLI / Plaintext*: Render ASCII card ONLY on explicit analyst request ('cli'/'ascii').
   - **Canonical Layout**: Rings $+1\sigma$ to $+4\sigma$; spokes: Auth, Cloud, Workspace, Net, DNS. Detail in `references/chart-specifications-guide.md`.
   - **Mode B (14d Multi-Horizon)**: Render 14-Day Timeline (fleet) or 360° Radar ($Z_{\text{peak}}$) + Timeline (entity).
4. **Dual Scales**: Raw Z-score and CRI ($+3.0\sigma$ / CRI 50 perimeter; Section 6 formula).

### ☁️ Cloud Data Store Scope & Anti-Narrowing Invariant
* **Anti-Narrowing Invariant for Cloud Data Stores**: When hunting service account cloud repository access (`resource_read_*`, `resource_written_*`), NEVER narrow to a single product. Route to `templates/pipelines/cloud_repository_scope_dual_branch.yl2` with `($sa, $vendor, $product, $resource, $ip by 1d)` to evaluate local baseline isolation and prevent masking.

### 🎯 CTI & Threat Report Mapping (Reports, URLs, CVEs, Threat Actors)
When an analyst provides a threat report (URL, CVEs, or threat actor):
1. **Map to UEBA Metric Tables**: Map attack stages to corresponding pre-computed metric tables (`metrics.*`).
2. **Transition Directly to Phase 1B**: Emit **Pre-Flight Hunting Specification Card** and **Literal Query Preview** on Turn 1. Ask for target scoping and **YIELD THE TURN (0 tools called)**.

### 🔍 Phase 1B: Pre-Flight Spec & Query Preview (Once Scope & Vectors are Established)
Once vectors and scope are confirmed (or responding to Phase 1A with *"yes to both"*, or via CTI mapping):
1. **Turn 1 Tool Invariant**: Zero file inspection (`view_file`, `list_dir`). Permitted tools: name resolution spot-check and 1-shot pre-preview compiler probe (`udm_search`).
2. **Identity Disambiguation & Confirmation Protocol (ZERO GUESSING & IMMEDIATE HALT)**:
   - *Technical IDs*: Single-token account IDs without spaces (e.g. `expanse`, `fkolzig`, `srv-01`) are technical IDs. Proceed directly.
   - *Display Names*: Display names (with spaces) are NOT `user.userid`.
     • Execute AT MOST ONE spot-check (14d window): `udm_search(query='target.user.user_display_name = "<name>" nocase or principal.user.user_display_name = "<name>" nocase', startTime: 14d ago, maxEvents: 5)`.
     • *Match Found ($\ge 1$ events)*: Extract verified `user.userid` (`target`/`principal`). In card: `• Target Entity / Scope: <Name> (Verified User ID: <id>)`.
     • *HARD RESOLUTION GATE (ZERO GUESSING)*: If 0 events match or query fails:
       **STRICTLY FORBIDDEN TO GUESS OR SYNTHESIZE A USERNAME** (no heuristic abbreviations). **DO NOT GENERATE SPEC CARD OR DRAFT QUERIES. HALT IMMEDIATELY (0 tools called)**, asking:
       > *"I could not resolve a technical `user.userid` for '<Display Name>' in recent UDM telemetry. What is their technical user ID / account identifier (e.g., username, sAMAccountName)?"*
       Wait for the analyst's answer before generating the Pre-Flight Card.
3. **Plain-English Cyber Analogy (1–2 Sentences)**: Explain statistical approach using a physical concept.
4. **Structured PRE-FLIGHT HUNTING SPECIFICATION Card & Mandatory Query Preview**:
   ```markdown
   ┌─────────────────────────────────────────────────────────────────┐
   │                PRE-FLIGHT HUNTING SPECIFICATION                 │
   │ • Target Entity / Scope:  [Target User/Host ID or Fleet]        │
   │ • Baseline Horizon Spine: 30-Day Pre-Computed (period: 1d, 30d) │
   │ • Peer Cohort & Roster:   [Team/Dept, e.g. IT (Frank, Tim)]     │
   │ • Entity Graph Dimension: [Prevalence (rolling_max <= 3) / N/A] │
   │ • Evaluation Horizon Mode:[Mode A: 24h (Default) OR Mode B: 14d]│
   │ • Statistical Model:      [Model, e.g. Multi-Sector Fusion]     │
   │ • Significance Threshold: [Z >= 3.0σ (CRI >= 50) / D >= 3.5σ]   │
   └─────────────────────────────────────────────────────────────────┘
   ```
   * *Mandatory Upfront Query Preview Protocol (Mandatory Query Preview)*: Execute 1-shot pre-preview compiler probe: `secops-gus:udm_search(query="<query>", startTime="now-10m", endTime="now", maxEvents=1)`. Display query in markdown ONLY if probe compiles cleanly. If probe fails, auto-correct or trigger Consultative Pivot.
   * *Peer Cohort Roster Requirement (Peer Cohort & Roster)*: Resolve and list cohort entities and count in card.
   * *Interactive Entity Graph Dimension Mandate*: Express joins in card under `• Entity Graph Dimension: [Exact Filter]` (Domain Rarity, Fleet Prevalence, Binary Rarity, IP Rarity `rolling_max <= 3`, `day_count = 10` platform invariant).
   * *Canonical 2-Stage Preview*: Match variables bind to active fields (`target.user.userid` for auth, `principal.user.userid` for cloud/SaaS/net/proc, `principal.asset.hostname` for assets). Decouple into `stage stage1_extract` and root math (`+ 1.0` floor).
5. **Explicit Clearance Question & Turn Termination**: Explicitly ask:
   > *"Would you like to run **Mode A (24-Hour Snapshot fleet ranking)** or **Mode B (14-Day Longitudinal Timeline with inception chart)**?"*
   **STOP CALLING TOOLS IMMEDIATELY AND YIELD THE TURN.**

---

## 📊 MANDATORY STEP 2: PRESENT FULL 6-SECTION REPORT (AFTER CLEARANCE)

*Pre-Output Tool Execution Guard*: On clearance, execute the target pipeline (for 360° Radar: 5 parallel sector micro-queries). Emit findings into 6 numbered pillars. Zero `json_chart`.
The report **MUST STRICTLY CONTAIN ALL 6 NUMBERED PILLARS**:
1. **Statistical Outlier Report**: `[Target Metric]` ([Statistical Model]) with 30-day baseline (`window: 30d`). Single visual surface: `<agent-embed>` in Jetski; client visual tool or inline <svg> in generic MCP; ASCII on explicit request. Include Unicode magnitude bars (`▰▰▰▰▱▱▱▱`) in table. Detail in `references/chart-specifications-guide.md`.
2. **Executed Multi-Stage YARA-L Query**: Literal executed multi-stage YARA-L query string passed into `secops-gus:udm_search(query=...)`. Labeled 'Executed Multi-Stage YARA-L Query' (never 'Rule').
3. **Ranked Outlier Summary**: Columns: `Entity`, `24h Observed`, `30d Mean (μ)`, `30d StdDev (σ)`, `Z-Score`, `CRI Score`, `Visual Magnitude`.
4. **Forensic Vector Breakdown**: Threat translation, significance, attack scenarios, SOC playbook. For fleet hunts with severe outliers ($Z \ge 3.0\sigma$), proactively suggest a 360° Behavioral Radar deep-dive.
5. **Immediate 1-Click Investigation Queries**: Raw UDM filter query for analyst drilldown.
6. **Statistical & Mathematical Appendix**: Formulation ($N = 30d$), single-line CRI formula, Euclidean distance norm $D = \sqrt{\sum Z^2}$.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 1. Native Execution & Truth in Reporting
* **Zero Generative Simulation & Strict Data Grounding Contract**: Numbers ($\text{Obs}$, $\mu$, $\sigma$, $Z$, $\text{CRI}$) MUST be extracted from `secops-gus:udm_search`. If `{}` or empty, report `0 observed events`, `Z = 0.00σ`, `🟢 Nominal Baseline`. Fabricating numbers is a **CRITICAL TRUTH-IN-REPORTING FAILURE**.
* **Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)**: If an API query fails, STOP IMMEDIATELY and report the error. Simulating baselines locally is STRICTLY PROHIBITED.
* **Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)**: Detection MUST run inside Chronicle SIEM. Simulating baselines locally in Python is a CRITICAL COMPLIANCE VIOLATION.
* **Zero Local Script Invocations During Hunting (ZERO RUN_COMMAND VALIDATION)**: Zero Python for detection/search. Post-search `run_command` (`scripts/radar_collector.py`) permitted SOLELY for Pillar 1 rendering.
* **Hermetic Skill Boundary (ZERO CROSS-SKILL DRIFT)**: Once active, the agent MUST NOT read, import, or search other skills. This skill is 100% self-contained.
* **Multi-Turn Continuity & Follow-Up Mandate**: On follow-up turns shifting entity or time ("run same for user X", "look back 14d"), MAINTAIN Multi-Stage Risk Analytics (30d baselines, DAGs, 6 pillars). NEVER degrade to raw log dumps.
* **Atomic Pipeline Execution Mandate (ZERO PIECEMEAL FRACTURING & DRIFT)**: Hunts dispatch the single atomic YARA-L query to `udm_search`. Fracturing into piecemeal searches is STRICTLY PROHIBITED. 360° Radar queries 5 canonical sector functions in parallel (<= 5 micro-queries) projecting `$obs`, `$mu`, `$sigma`, `$z_score` in root `outcome:`. If a sector has 0 events or $Z \le 0$, record $0.00\sigma$, CRI 0; never fish for raw logs.
* **Literal Query Display Mandate (ZERO FAKED YARA-L QUERIES)**: Section 2 MUST contain the literal exact query string passed into `secops-gus:udm_search(query=...)`.
* **Zero Unsolicited Ingestion**: Zero ingestion via `import_logs` or `generate_synthetic_events`.
* **Post-Flight Audit & RAW_LOG_DUMP_DETECTED Rule**: If `udm_search` returns `"events"` without `"stats"`, or unaggregated raw logs, abort 6-Pillar formatting immediately. Disguising raw log dumps as baselines is STRICTLY PROHIBITED. Present auto-corrected query (via `MultiStageTemplateRouter`) or trigger consultative pivot and ask: *"Execute this auto-corrected query now, or exit?"*

### 2. Compiler & Architectural Invariants
* **Template-First Routing Mandate & Pre-Composed Pipeline Routing**: Multi-stage queries MUST assemble from validated AST templates in `templates/pipelines/` or `templates/stage1_extractors/` via `MultiStageTemplateRouter`. Freehand composition deviating from canonical schemas is prohibited. Route standard hunts directly to composite templates (e.g. `mad_modified_z_2stage.yl2`, `standard_z_score_2stage.yl2`, `poisson_rarity_2stage.yl2`, `dual_sector_fusion_3stage.yl2`, `cloud_repository_scope_dual_branch.yl2`).
* **Zero-Hallucination Compiler Grammar Contract**:
  - *Entity Role & Match Binding Invariant*: Variables in `match:` MUST bind in event predicates (`target.user.userid` for logins; `principal.user.userid` for cloud/SaaS/net/proc; `principal.asset.hostname` for assets).
  - *Compiler Structural Boundary*: Arithmetic (`$a - $b`, `$a / $b`) is STRICTLY PROHIBITED above `match:`. Placeholders bind directly to fields/functions. Derivations and Z-scores reside in `outcome:` below `match:`.
  - *Syntax Invariants*: No `in ("A", "B")` (use `%list` or `or`); no dot-notation properties (`metrics.foo.mean` is INVALID); no `by 24h` (use `by 1d`); linear outcome arithmetic; canonical metric names end in `_total`.
  - *Mandatory Companion Dimensions & Entity Affinity*: Cloud CRUD (`metrics.resource_*`) requires `metadata.vendor_name` and `metadata.product_name`. File metrics (`metrics.file_executions_*`) are strictly Host/Binary scoped (`$host, $sha256`) requiring `metadata.event_type` and `principal.process.file.sha256`. NEVER bind `principal.user.userid` to file metrics or force cross-entity joins.
* **Consultative Pivot & Handoff Protocol (ZERO FORCED JOINS)**: When vectors cross entity boundaries or lack pre-computed user baselines (e.g. user process launches), NEVER synthesize fake schemas. State boundary and offer 3 paths: 1) Cloud-First 2-Phase Pivot (Cloud CRUD surge ──► trace origin IP ──► inspect workstation EDR logs), 2) Asset-First Pivot (baseline workstation on `file_executions_total`), or 3) Handoff to `secops-statistical-hunter` for raw log statistical outlier hunting. Detail in `references/multi-stage-metrics-guide.md`.
  - *Max 4 Joins Invariant*: YARA-L 2.0 limits queries to <= 4 joins (`maxJoinCount = 4`). Each UEBA stage consumes 1 join; root consumes K-1 joins.
* **Variable Role Classification & Anti-Passive-Decoration Mandate**: Variables must fulfill `[JOIN_KEY]`, `[SCORING_DIMENSION]`, `[ACTIVE_FILTER]`, or `[TRIAGE_DECORATION]`. Primary threat vectors MUST NEVER act solely as `[TRIAGE_DECORATION]`.
* **Inner-Join Drop Prevention Standard (PRESERVING FULL POPULATION)**: Multi-stage joins are inner joins. Baseline full fleet in Stage 1 and profile destinations via `array_distinct(target.hostname)`.

### 3. Scope, Steering, Typography & Parsimony
* **Pure Threat Hunting Scope (SEARCH-ONLY — ZERO RULE CREATION / DEPLOYMENT)**: Zero Streaming Detection Rule Syntax (`create_rule` and `validate_rule` are STRICTLY PROHIBITED). Output ad-hoc Multi-Stage YARA-L (`stage ...` + Root) for `udm_search`. Outputting streaming rules is a **CRITICAL NOMENCLATURE & ARCHITECTURAL VIOLATION**.
* **Strict Nomenclature Mandate**: Ad-hoc hunt logic is a Query, never a Rule. Calling a search query a 'Rule' is a **CRITICAL NOMENCLATURE VIOLATION**.
* **Mandatory 6-Pillar Report**: NEVER substitute generic dossiers (`summarize_entity`, cases, alerts) for 6-Pillar report. Every profile MUST execute native multi-stage YARA-L.
* **Zero In-Query CRI Calculation**: Compute raw scores in YARA-L. CRI [0–100] is computed in post-processing.
* **Zero Gratuitous Entity Graph Injection (ON-DEMAND / ALGORITHMIC GROUNDING ONLY)**: Entity Graph constructs must NEVER be injected gratuitously or speculatively. Include ONLY on Direct Customer Request (On-Demand) or Algorithmic Grounding.
* **Interactive Entity Graph Rarity & Context Discovery & 10-Day Prevalence Platform Invariant**: When requested, bind Entity Graph dimensions (Domain Rarity, Fleet Prevalence, Binary Rarity, IP Rarity; `day_count = 10`) into Stage 2.
* **KaTeX & Typography Invariants (ZERO PARSE FAILURES)**: No bold math (`**$6.28\sigma$**` is invalid); use Unicode `(μ)`, `(σ)` in tables. Formulas: `$$\text{CRI} = \min\left(100, \max\left(0, \frac{Z}{3.0} \times 50\right)\right)$$` and `$$D = \sqrt{\sum_{i=1}^5 Z_i^2}$$.` Flush-left `$$` on own lines.

---

## 🤝 MANDATORY CLEAN HAND-OFF & ESCALATION PROTOCOL (REPORTING TO SECOPS)

> [!IMPORTANT]
> **Strict Escalation Gating Mandate (ZERO UNSOLICITED ESCALATION)**:
> Unsolicited case creation is a **CRITICAL PROCESS POLLUTION VIOLATION**.
> Triggered EXCLUSIVELY when analyst explicitly requests escalation (*"escalate"*, *"open a case"*). NEVER append synthetic UDM events or ingestion prompts to standard hunt reports; terminate cleanly at Pillar 6.

### Intent Routing & Mandatory Workflow (When Escalation Is Explicitly Requested):
* **Path A: General Escalation (No Case ID)**: 1. Preview synthetic event JSON. 2. Ask *"Ingest this event into Chronicle SIEM now to trigger automated case promotion?"* and **STOP CALLING TOOLS AND YIELD THE TURN**. 3. On confirmation, execute `secops-gus:import_logs` (`product_name: "SecOps Risk Metrics Hunter"`).
* **Path B: Explicit Case Wall Attachment (Case ID specified)**: Call `secops-gus:create_case_comment(case_id="<ID>", comment=...)` and confirm.

---

## 📂 Modular References & Template Architecture
* **`references/`**: `metrics-catalog.md`, `statistical-models-taxonomy.md`, `calibrated-risk-index-guide.md`, `multi-stage-metrics-guide.md`, `clean-handoff-udm-schema.md`, `soar-playbook-radar-integration.md`, `compiler-submission-policy.md`
* **Pipelines & Scripts**: `templates/pipelines/`, `templates/stage1_extractors/`, `scripts/` (`template_router.py`, `radar_collector.py`, `submission_tests.py`)
