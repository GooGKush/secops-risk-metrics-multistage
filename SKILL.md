---
name: secops-risk-metrics-multistage
author: Greg Kushmerek
aliases:
  - Chronicle Baseline Hunter
  - Behavioral Outlier Engine
  - Agentic UEBA Core
description: |
  Constructs, validates, and executes multi-stage statistical outlier hunting in Google SecOps
  using pre-computed Risk Analytics behavioral metrics (metrics.*) chained into 2-stage, 3-stage, and 4-stage DAGs.
  Supports 14 statistical models (Z-Score, MAD, Fano, Discrete Poisson, Bayesian Conjugacy, Delta-Z, Multi-Sector Fusion).
  Enforces Step 1 Pre-Flight Gate, 6-Section Triage Reports, Variable Role Classification, and 1:1 synthetic UDM hand-off.
  Triggers: "hunt with risk metrics", "multi-stage metrics outlier", "MAD on network bytes", "z-score on auth", "risk analytics statistical hunt", "fleet outlier", "poisson burst", "fano factor", "bayesian updating", "dual-baseline delta-z", "patch tuesday immunity", "multi-sector threat fusion", "360 health check", "compare to team", "behavioral drift", "top statistical outliers".
compatibility: Requires access to a Google SecOps instance with Risk Analytics metrics enabled and the SecOps GUS MCP server (udm_search, get_operation).
---

# SecOps Risk Metrics Multi-Stage Statistical Hunter (`secops-risk-metrics-multistage`)

Executes **fleet-wide and multi-sector statistical outlier hunting** in Google SecOps using **30-day pre-computed Risk Analytics metrics (`metrics.*`)** chained into **2-stage, 3-stage, and 4-stage mathematical DAG pipelines**.

---

## 🔀 Bi-Directional Skill Steering & Handoff Protocol

| If hunt targets... | Activate... | Operational Action |
| :--- | :--- | :--- |
| • **30-Day Behavioral Baselines** (`metrics.*`)<br>• **Peer / Team Cohort Outliers**<br>• **Multi-Sector Threat Fusion** | 📊 **`secops-risk-metrics-multistage`** *(This Skill)* | Execute native multi-stage `metrics.*` pipeline. |
| • **Ad-Hoc Raw Telemetry Sensors** (C2 jitter CV)<br>• **Non-Metrics Telemetry** | ⚡ **`secops-statistical-hunter`** | Emit **Skill Handoff Card** and Non-Metrics Telemetry Steering Mandate to `secops-statistical-hunter`. |

> [!TIP]
> **🔀 Skill Routing Notice: `secops-statistical-hunter` Recommended**
> Request targets raw telemetry without 30-day UEBA pre-computed tables (`metrics.*`). Routing to **`secops-statistical-hunter`**.

---

## ⏱️ Evaluation Modes: Snapshot vs. 30-Day Longitudinal Sliding Timeline

1. **Mode A: Current-Day Snapshot (`FLEET_ROLLUP`)**: 24h search window (Today) vs 30d baseline (`window: 30d`). Evaluates current outliers (1 row/entity).
2. **Mode B: 30-Day Longitudinal Sliding Timeline (`TIMELINE_BREAKDOWN`)**: Multi-day horizon up to 14–30d (`match: $entity by 1d`). Tracks daily evolution & CUSUM drift.

---

## 💡 How Risk Metrics Multi-Stage Analytics Work (Educational & Overview Inquiries)

When an analyst asks how multi-stage analytics work or requests an explanation, present this **3-Step Overview**:
1. **Step 1: 30-Day Pre-Computed Baselines ($O(1)$ Stage 1 Engine)**: Google SecOps continuously aggregates rolling 30-day historical activity across 38 metric tables (`metrics.*`), performing instant $O(1)$ baseline lookups ($\mu$, $\sigma$, $N_{\text{days}}$) without scanning raw logs.
2. **Step 2: Multi-Stage YARA-L DAG Analytics (Zero-Hop Staging)**: Chains Stage 1 baselines into downstream mathematical stages (Stage 2+) to compute statistical deviations, join Entity Graph context (prevalence, novelty), or correlate orthogonal telemetry silos.
3. **Step 3: Execution Framework Summary (Built-In Behavioral Models & Use Cases)**:
   • 📈 **Volumetric Surges** (*Standard Z-Score / Robust MAD*): High-volume explosions in egress, files, or auth.
   • ⚡ **Automated Bursts** (*Poisson Dispersion / Fano Factor*): Synchronized sprays vs random typos.
   • 🎯 **Rare Inceptions** (*Discrete Poisson Rarity*): Rare LOLBin/admin execution on quiet assets.
   • 🧠 **Sparse Regularization** (*Bayesian Shrinkage*): Regularizes low-activity accounts to eliminate false alarms.
   • 🛡️ **Fleet-Normalized Surges** (*3-Stage Dual-Baseline Delta-$Z$*): Isolates targeted attacks during fleet surges (e.g. Patch Tuesday).
   • 🔀 **Multi-Sector Fusion** (*4-Stage Chi-Square Distance $D$*): Cross-correlates spikes across IAM, Process, and Egress.
   • 📉 **Longitudinal Drift** (*CUSUM $S^+$*): Detects low-and-slow exfiltration or privilege drift over 14–30d.

> [!TIP]
> **Ask for more information** if you would like a deep dive on how any of these models help expose behavioral outliers for your security use cases. *(See `references/statistical-models-taxonomy.md`)*

---

## 🚦 MANDATORY STEP 1: PRE-FLIGHT CLEARANCE & CONVERSATIONAL STAGING (ZERO EXECUTION ON TURN 1)

Whenever a hunt is initiated or parameters refined, **THE AGENT MUST NEVER CALL SEARCH OR INGESTION TOOLS ON THAT TURN**.

### 🧭 Phase 1A: Consultative Vector & Scope Discovery (Dual-Requirement Gate)
Phase 1B (Query Preview & Spec Card) is **ONLY UNLOCKED** when **BOTH** requirements are explicitly defined:
1. **Entity Scope** (e.g. specific user, peer cohort, or enterprise fleet) **AND**
2. **Telemetry Vector(s)** (e.g. Cloud CRUD, Workspace downloads, Network Egress, Endpoint tools, or Auth).

> [!IMPORTANT]
> **Anti-Auth-Defaulting Guardrail & Conversational Break**:
> If an analyst specifies entities (*"compare user A to user B"*, *"check user X for deviations"*) but **omits the telemetry vector**, **THE AGENT MUST NOT DEFAULT TO `metrics.auth_attempts_*` OR `USER_LOGIN`**.  
> The agent MUST act as a consultative partner, yield the turn (Conversational Break), and ask:
> *"Across which behavioral vector(s) would you like to evaluate [Target Entities]?"*
> • ☁️ **Cloud CRUD**: `metrics.resource_creation_*`, `metrics.resource_deletion_*` (GCP/AWS).
> • 📁 **Workspace Exfil**: `metrics.workspace_total_download_actions`, `metrics.workspace_total_change_actions`.
> • ⚙️ **Endpoint Tools**: `PROCESS_LAUNCH` (LOLBins, script engines, admin shells).
> • 🌐 **Network Egress**: `metrics.network_bytes_outbound` (data egress).
> • 🔑 **Authentication**: `metrics.auth_attempts_*` (off-hours logins, brute force).
> • 🔀 **Multi-Sector Fusion**: Cross-correlating multiple vectors into a composite score ($D$).
> **STOP IMMEDIATELY AND YIELD TURN (CONVERSATIONAL BREAK).** Do NOT render query preview until user responds.

### 🎯 CTI & Threat Report Mapping (Reports, URLs, CVEs, Threat Actors)
When an analyst provides a threat report (URL, DFIR advisory, CVEs, or threat actor):
1. **Extract Attack Chain**: Analyze the report to identify core attack stages (initial access, staging, egress, credential abuse).
2. **Map to UEBA Metric Tables**: Map each attack stage directly to corresponding pre-computed metric tables (`metrics.*`) and statistical models.
3. **Transition Directly to Phase 1B**: Emit the structured **Pre-Flight Hunting Specification Card** and **Literal Query Preview** for primary threat vector on Turn 1. Ask for target workload scoping (fleet vs. cluster) and **YIELD THE TURN (0 tools called)**.

### 🔍 Phase 1B: Pre-Flight Spec & Query Preview (Once Scope & Vectors are Established)
Once the analyst specifies or confirms vectors and scope (or via CTI threat report mapping, or for specific prompts like *"MAD on network outbound bytes"*):
1. **ZERO Tool Execution**: 0 tool calls to `udm_search`, `import_logs`, `run_command`, or local python scripts.
2. **Plain-English Cyber Analogy (1–2 Sentences)**: Explain statistical approach using a physical concept. *(See `references/statistical-models-taxonomy.md`)*.
3. **Structured PRE-FLIGHT HUNTING SPECIFICATION Card & Mandatory Query Preview**:
   *Render using high-contrast bold markdown key-value formatting for high visibility in dark CLI themes:*
   ```markdown
   ┌───────────────────────────────────────────────────────────────────────────────────┐
   │                     PRE-FLIGHT HUNTING SPECIFICATION                              │
   │  • Target Entity / Scope:   [Target User/Host ID or Enterprise Fleet]             │
   │  • Baseline Horizon Spine:  30-Day Pre-Computed Metrics (period: 1d, win: 30d)   │
   │  • Peer Cohort & Roster:    [Team/Dept Cohort, e.g. IT Dept (Frank, Tim)]         │
   │  • Entity Graph Dimension:  [Prevalence (rolling_max <= 3) / First-Seen / N/A]   │
   │  • Evaluation Horizon Mode: [Mode A: 24h Snapshot (Default) OR Mode B: 14d]      │
   │  • Statistical Model:       [Model Name, e.g. 4-Stage Multi-Sector Threat Fusion] │
   │  • Significance Threshold:  [e.g. Z >= 3.0σ (CRI >= 50) or Multi-Sector (D >= 3.5σ)]│
   └───────────────────────────────────────────────────────────────────────────────────┘
   ```
   * *Mandatory Upfront Query Preview Protocol*: Display literal multi-stage YARA-L query in markdown prior to clearance.
   * *Peer Cohort Roster Requirement*: Resolve and list cohort entities and count in card (`• Peer Cohort & Roster: ...`).
   * *Interactive Entity Graph Dimension Mandate*: Express Entity Graph joins in card under `• Entity Graph Dimension: [Exact Filter]`.
   * *Interactive Entity Graph Rarity & Context Discovery*: Map qualitative modifiers:
     - **Domain Rarity**: Fleet Prevalence (`graph.entity.domain.prevalence.rolling_max <= 3`).
     - **Binary Rarity**: SHA256 Prevalence (`graph.entity.file.prevalence.rolling_max <= 3`).
     - **IP Rarity**: IP Prevalence (`graph.entity.artifact.prevalence.rolling_max <= 3`).
   * *10-Day Prevalence Platform Invariant*: Prevalence is hard-anchored to a 10-day lookback (`day_count = 10`).
   * *Canonical 2-Stage Preview Invariant*: Named stages MUST NOT use `events:` headers or `$e.` prefixes. Always decouple baseline extraction into `stage stage1_extract` and outcome arithmetic into the Root Stage with `+ 1.0` dispersion floor.
4. **Explicit Clearance Question & Turn Termination**: Explicitly ask:
   > *"Would you like to run **Mode A (24-Hour Snapshot fleet ranking)** or **Mode B (14-Day Longitudinal Timeline with inception chart)**?"*
   **STOP CALLING TOOLS IMMEDIATELY AND YIELD THE TURN.**

---

## 📊 MANDATORY STEP 2: PRESENT FULL 6-SECTION REPORT (AFTER CLEARANCE)

When clearance is granted and native queries execute, the report **MUST STRICTLY CONTAIN ALL 6 NUMBERED PILLARS**:
1. **Statistical Outlier Report**: `[Target Metric]` ([Statistical Model]) with 30-day baseline context (`window: 30d`).
2. **Executed Multi-Stage YARA-L Query**: Literal executed multi-stage YARA-L query string passed into `secops-gus:udm_search(query=...)`. **Strict Nomenclature Mandate**: MUST be labeled 'Executed Multi-Stage YARA-L Query'. Calling ad-hoc query logic a 'Rule' or 'Hunting Rule' is a **CRITICAL NOMENCLATURE VIOLATION**.
3. **Ranked Outlier Summary**: Table with columns: `Entity`, `24h Observed`, `Baseline Mean`, `StdDev`, `Z-Score`, `CRI Score`, `Visual Magnitude`.
4. **Forensic Vector Breakdown**: Threat translation, significance, attack scenarios, false positives, SOC playbook.
5. **Immediate 1-Click Investigation Queries**: Raw UDM filter query for analyst drilldown.
6. **Statistical & Mathematical Appendix**: Formal model formulation ($N = 30d$), Calibrated Risk Index $\text{CRI} = \text{round}\left(\frac{100}{1 + \exp(-0.6 \cdot (Z - 3.0))}\right)$.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 1. Native Execution & Truth in Reporting
* **Zero Generative Simulation & Strict Data Grounding Contract**: Every metric number in Sections 1, 3, and 4 ($\text{Obs}$, $\mu$, $\sigma$, $Z$, $\text{CRI}$) MUST be a direct extraction from the raw output of `secops-gus:udm_search`. If `udm_search` returns `{}` or empty events, the agent MUST report `0 observed events`, `Z = 0.00σ`, and `🟢 Nominal Baseline`. Fabricating synthetic baseline numbers without tool execution is a **CRITICAL TRUTH-IN-REPORTING FAILURE**.
* **Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)**: If an API query fails, STOP IMMEDIATELY and report the error. Simulating baselines locally in scratch scripts is a **CRITICAL COMPLIANCE VIOLATION**.
* **Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)**: Multi-stage statistical anomaly detection MUST run inside Chronicle. Zero baseline calculation in Python.
* **Zero Local Script Invocations During Hunting (ZERO RUN_COMMAND VALIDATION)**: MUST NOT call `run_command` or execute local Python scripts in terminal during chat. Never prompt for terminal permissions.
* **Hermetic Skill Boundary (ZERO CROSS-SKILL DRIFT)**: Once active, the agent MUST NOT read, import, or search other skills. This skill is 100% self-contained.
* **Atomic Pipeline Execution Mandate (ZERO PIECEMEAL FRACTURING & DRIFT)**: Dispatch complete multi-stage DAG in a single atomic YARA-L query passed to `udm_search`. It is **STRICTLY PROHIBITED** to break into isolated 1-metric queries or chase raw log regexes (`target.hostname = /.../`).
* **Literal Query Display Mandate (ZERO FAKED YARA-L QUERIES)**: Section 2 MUST contain the literal, exact query string passed into `secops-gus:udm_search(query=...)`.
* **Zero Unsolicited Ingestion**: Zero unsolicited ingestion via `import_logs` or `generate_synthetic_events`.
* **Post-Flight Audit & Auto-Correction**: If execution is deformed, present auto-corrected query and ask: *"Would you like me to execute this auto-corrected query now, or exit this hunt?"*

### 2. Compiler & Architectural Invariants
* **Pre-Composed Pipeline Template Routing**: Route hunts directly to complete composite pipeline templates in `templates/pipelines/` (e.g. `mad_modified_z_2stage.yl2`, `standard_z_score_2stage.yl2`, `poisson_rarity_2stage.yl2`, `dual_sector_fusion_3stage.yl2`). Perform 1:1 parameter slot-filling rather than dynamic syntax stitching.
* **Zero-Hallucination Compiler Grammar Contract**:
  - *No `in ("A", "B")`*: `in` is strictly reserved for reference lists (`field in %list`). Multiple literals MUST use `(field = "A" or field = "B")` or regex.
  - *No Dot-Notation Metric Properties*: `metrics.foo.mean` is INVALID. Always use canonical function calls `max(metrics.foo(period: 1d, window: 30d, ...))`.
  - *No `by 24h`*: Daily match windows MUST use `by 1d`.
  - *Linear Outcome Arithmetic*: Nested `max(0, ...)` or inline `sqrt(...)` in arithmetic expressions are INVALID. Compute squared norms and order by `$norm_sq desc`.
  - *Max 4 Joins Invariant*: YARA-L 2.0 strictly limits queries to $\le 4$ joins (`maxJoinCount = 4`). In multi-stage DAGs, each UEBA stage consumes 1 join, and root joins consume $K-1$ joins. Stay within $\le 4$ joins. *(See `references/multi-stage-metrics-guide.md`)*.
* **Exact Time Window Arithmetic**: Compute $\text{startTime} = \text{endTime} - N \times 86400\text{s}$ with exact precision matching the user requested horizon (e.g. 14 days ending Aug 29 starts Aug 16 at 00:00:00Z).
* **Variable Role Classification & Anti-Passive-Decoration Mandate**: Every variable must fulfill: `[JOIN_KEY]`, `[SCORING_DIMENSION]`, `[ACTIVE_FILTER]`, or `[TRIAGE_DECORATION]`. Qualitative primary threat vectors MUST NEVER act solely as `[TRIAGE_DECORATION]`; bind them to an active Cross-Sectional Fleet Rarity Stage (`count_distinct(principal.asset.hostname) <= 2`) or Entity Graph constraint. *(See `references/multi-stage-metrics-guide.md`)*.
* **Threat-to-Telemetry Decomposition Matrix**: Decompose unstructured threat descriptions into orthogonal behavioral vectors. *(See `references/multi-stage-metrics-guide.md`)*.
* **Single-ECG Limit & Decoupled Context Fusion**: Max 1 ECG lookup per stage. Never evaluate `metrics.*` inside stages filtered by `GLOBAL_CONTEXT` or `DERIVED_CONTEXT`. Decouple baseline into Stage 1 and threat context into Stage 2.
* **Inner-Join Drop Prevention Standard (PRESERVING FULL POPULATION)**: In YARA-L, multi-stage joins are inner joins. When evaluating all entities including threat domains, do NOT place threat filter in a separate stage. Evaluate full baseline in Stage 1 and profile destinations via `array_distinct(target.hostname)`.

### 3. Scope, Steering & Parsimony
* **Pure Threat Hunting Scope (SEARCH-ONLY — ZERO RULE CREATION / DEPLOYMENT)**: `create_rule` and `validate_rule` are STRICTLY PROHIBITED during threat hunts.
* **Zero Streaming Detection Rule Syntax (SEARCH-ONLY YARA-L DAG MANDATE)**: When designing, proposing, or executing queries, the agent MUST ONLY output ad-hoc Multi-Stage YARA-L Search syntax (`stage name { ... }` + unwrapped Root Stage) for Chronicle UDM Search (`udm_search`). Outputting continuous detection rules (`rule <name> { ... }`), `meta:`, or `condition:` blocks is a **CRITICAL NOMENCLATURE & ARCHITECTURAL VIOLATION**. If an inquiry targets non-metrics telemetry (e.g. inter-arrival timing jitter CV), steer to `secops-statistical-hunter`—NEVER improvise detection rules.
* **Non-Metrics Telemetry Steering Mandate (HANDOFF TO STATISTICAL HUNTER)**: If an analyst targets non-baselined telemetry, emit the **Skill Handoff Card** and steer to `secops-statistical-hunter`.
* **Zero Gratuitous Entity Graph Injection (ON-DEMAND / ALGORITHMIC GROUNDING ONLY)**: Entity Graph constructs must NEVER be injected gratuitously or speculatively. Include ONLY upon **Direct Customer Request (On-Demand)** or explicit **Algorithmic Grounding**.

---

## 🤝 MANDATORY CLEAN HAND-OFF & ESCALATION PROTOCOL (REPORTING TO SECOPS)

### 1. Intent Routing: General Ingestion vs. Explicit Case Wall Attachment
* **Path A: General Escalation & Ingestion (Default when no Case ID is given)**:
  - *Trigger Wording*: *"Send a report about this to Google SecOps"*, *"Escalate to SecOps"*, *"Log in Chronicle"*, *"Create a case"*, *"Promote this finding"*.
  - *Action*: Construct & ingest a synthetic UDM security event to trigger a **brand-new dedicated case** via the catch-all detection rule.
  - *Anti-Pollution Invariant*: The agent MUST NEVER arbitrarily pick an existing case via `list_cases` to attach comments. Doing so is a **CRITICAL PROCESS POLLUTION VIOLATION**.
* **Path B: Explicit Case Wall Attachment (Carved-Out Exception for Active Case Work)**:
  - *Trigger Wording*: The analyst explicitly specifies a target case (e.g. *"Attach this finding to Case 11075"*, *"Add this report to the case wall of Case 11075"*).
  - *Action*: Format a concise Markdown triage summary and call `secops-gus:create_case_comment(case_id="<ID>", comment=...)` on that **explicitly designated Case ID**.

### 2. Mandatory Workflow per Path:
* **For Path A (Synthetic UDM Event Ingestion)**:
  1. *Preview*: Construct and render canonical synthetic UDM event JSON from [`references/clean-handoff-udm-schema.md`](references/clean-handoff-udm-schema.md).
  2. *Gate*: Ask *"Would you like me to ingest this event into Chronicle SIEM now to trigger automated case promotion?"* and **STOP CALLING TOOLS AND YIELD THE TURN**.
  3. *Execute*: Upon explicit confirmation, execute `secops-gus:import_logs` with `product_name: "SecOps Risk Metrics Hunter"`.
* **For Path B (Explicit Case Wall Comment)**:
  1. Format statistical findings into a clear triage comment.
  2. Call `secops-gus:create_case_comment` with user-provided `case_id` and confirm attachment to case wall.

---

## 📂 Modular References & Template Architecture

* **Documentation (`references/`)**: [`metrics-catalog.md`](references/metrics-catalog.md), [`statistical-models-taxonomy.md`](references/statistical-models-taxonomy.md), [`calibrated-risk-index-guide.md`](references/calibrated-risk-index-guide.md), [`multi-stage-metrics-guide.md`](references/multi-stage-metrics-guide.md), [`chart-specifications-guide.md`](references/chart-specifications-guide.md)
* **Automation & Pipelines**: [`templates/`](templates/) (`pipelines/`, `stage1_extractors/`, `stage2_math_models/`), [`scripts/`](scripts/) (`preflight_validator.py`, `chart_generator.py`)

---
*Created and maintained by Greg Kushmerek for Google SecOps Chronicle SIEM threat hunting workflows.*
