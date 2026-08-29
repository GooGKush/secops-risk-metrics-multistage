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
  Triggers: "hunt with risk metrics", "multi-stage metrics outlier", "MAD on network bytes", "z-score on auth", "risk analytics statistical hunt", "fleet outlier", "poisson burst", "fano factor", "bayesian updating", "dual-baseline delta-z", "patch tuesday immunity", "multi-sector threat fusion", "360 health check", "compare to team", "slow and low exfiltration", "behavioral drift", "top statistical outliers".
compatibility: Requires access to a Google SecOps instance with Risk Analytics metrics enabled and the SecOps GUS MCP server (udm_search, get_operation).
---

# SecOps Risk Metrics Multi-Stage Statistical Hunter (`secops-risk-metrics-multistage`)

Empowers an LLM agent to execute **fleet-wide and multi-sector statistical outlier hunting** in Google SecOps using **30-day pre-computed Risk Analytics metrics (`metrics.*`)** chained into **2-stage, 3-stage, and 4-stage mathematical DAG pipelines**.

---

## 🔀 Bi-Directional Skill Steering & Handoff Protocol

| If hunt targets... | Activate... | Operational Action |
| :--- | :--- | :--- |
| • **30-Day Behavioral Baselines** (`metrics.*`)<br>• **Peer / Team Cohort Outliers**<br>• **Multi-Sector Threat Fusion** | 📊 **`secops-risk-metrics-multistage`** *(This Skill)* | Execute native multi-stage `metrics.*` pipeline. |
| • **Ad-Hoc Raw Telemetry Sensors** (C2 jitter CV)<br>• **Non-Metrics Data Sources** (raw VPC flow, un-baselined logs) | ⚡ **`secops-statistical-hunter`** | Emit **Skill Handoff Card** and Non-Metrics Telemetry Steering Mandate to `secops-statistical-hunter`. |

### 🔀 Skill Handoff Card (When hunt targets raw non-metrics sensors):
```markdown
> [!TIP]
> **🔀 Skill Routing Notice: `secops-statistical-hunter` Recommended**
> • **Why This Skill**: Request targets raw telemetry without 30-day UEBA pre-computed tables (`metrics.*`).
> • **Action**: Routing to **`secops-statistical-hunter`** for raw UDM events.
```

---

## ⏱️ Evaluation Modes: Snapshot vs. 30-Day Longitudinal Sliding Timeline

1. **Mode A: Current-Day Snapshot (`FLEET_ROLLUP`)**: 24h search window (Today) vs 30d baseline (`window: 30d`). Evaluates current outliers (1 row/entity).
2. **Mode B: 30-Day Longitudinal Sliding Timeline (`TIMELINE_BREAKDOWN`)**: Multi-day window up to 14–30 calendar days (`match: $entity by 1d`). Tracks daily evolution & CUSUM drift.

> [!NOTE]
> **🛡️ 30-Day Pre-Computed Architectural Assurance**: Google SecOps maintains background rolling 30-day pre-aggregated tables. Regardless of whether the search window is 1 day or 14 days, `window: 30d` performs an $O(1)$ lookup against 30 trailing days.

---

## 🚦 MANDATORY STEP 1: PRE-FLIGHT CLEARANCE & CONVERSATIONAL STAGING (ZERO EXECUTION ON TURN 1)

Whenever an analyst initiates a hunt, selects an archetype, or refines parameters, **THE AGENT MUST NEVER CALL SEARCH OR INGESTION TOOLS ON THAT TURN**.

### 🧭 Phase 1A: Consultative Vector & Scope Discovery (Broad / Open-Ended Inquiries)
When an analyst request is broad (e.g. *"privilege abuse"*, *"insider threat"*), **THE AGENT MUST NOT EMIT A PRE-FLIGHT CARD OR YARA-L PREVIEW ON THIS TURN. THE AGENT MUST NOT DEFAULT TO `metrics.auth_attempts_*` OR ASSUME FLEET-WIDE SCOPE.**

The agent MUST act as a consultative partner and **YIELD THE TURN (CONVERSATIONAL BREAK)**:
1. **Inquire on Cohort Scope**: (a) *Specific Suspect User* (audit target vs team norm), (b) *Role/Department Cohort* (DevOps, DBAs, Cloud Ops to prevent heterogeneous fleet noise), or (c) *Enterprise-Wide Leaderboard* (ranked top outliers).
2. **Present 6 Behavioral Metric Vector Families**:
   • ☁️ **Cloud CRUD**: `metrics.resource_creation_*`, `metrics.resource_deletion_*` (GCP/AWS).
   • 📁 **Workspace Exfil**: `metrics.workspace_total_download_actions`, `metrics.workspace_total_change_actions`.
   • ⚙️ **Endpoint Tools**: `PROCESS_LAUNCH` (LOLBins, script engines, admin shells).
   • 🌐 **Network Egress**: `metrics.network_bytes_outbound` (data egress).
   • 🔑 **Authentication**: `metrics.auth_attempts_*` (off-hours logins).
   • 🔀 **Multi-Sector Fusion**: Cross-correlating vectors (e.g. Auth + Cloud Deletion + Egress).
3. **Anti-Auth-Defaulting Guardrail & Conversational Break**: Ask user for vector(s) and scope. **STOP IMMEDIATELY AND YIELD TURN (CONVERSATIONAL BREAK).** Do NOT render query preview until user responds.

### 🔍 Phase 1B: Pre-Flight Spec & Query Preview (Once Scope & Vectors are Established)
Once the analyst specifies or confirms vectors and scope (or for specific prompts like *"MAD on network outbound bytes"*):
1. **ZERO Tool Execution**: 0 tool calls to `udm_search`, `import_logs`, `run_command`, or local python scripts.
2. **Plain-English Cyber Analogy (1–2 Sentences)**: Explain statistical approach using a physical concept. *(See `references/statistical-models-taxonomy.md`)*.
3. **Structured PRE-FLIGHT HUNTING SPECIFICATION Card & Mandatory Query Preview**:
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
   * *Mandatory Upfront Query Preview Protocol*: The agent MUST ALWAYS display the complete literal multi-stage YARA-L query in markdown on Turn 1 prior to clearance.
   * *Peer Cohort Roster Requirement*: Resolve and list concrete cohort entities and count in card (`• Peer Cohort & Roster: ...`).
   * *Interactive Entity Graph Dimension Mandate*: Explicitly express Entity Graph joins inside card under `• Entity Graph Dimension: [Exact Filter]`.
   * *Interactive Entity Graph Rarity & Context Discovery*: Map qualitative modifiers:
     - **Domain Rarity**: Fleet Prevalence (`graph.entity.domain.prevalence.rolling_max <= 3`).
     - **Binary Rarity**: SHA256 Prevalence (`graph.entity.file.prevalence.rolling_max <= 3`).
     - **IP Rarity**: IP Prevalence (`graph.entity.artifact.prevalence.rolling_max <= 3`).
   * *10-Day Prevalence Platform Invariant*: Prevalence is hard-anchored to a 10-day lookback (`day_count = 10`). Adjust `rolling_max <= N` or combine with First-Seen (`first_seen_time < 30d`).
4. **Explicit Clearance Question & Turn Termination**: Explicitly ask:
   > *"Would you like to run **Mode A (24-Hour Snapshot fleet ranking)** or **Mode B (14-Day Longitudinal Timeline with inception chart)**?"*
   **STOP CALLING TOOLS IMMEDIATELY AND YIELD THE TURN.**

---

## 📊 MANDATORY STEP 2: PRESENT FULL 6-SECTION REPORT (AFTER CLEARANCE)

When clearance is granted and native queries execute, the report **MUST STRICTLY CONTAIN ALL 6 NUMBERED PILLARS**:
1. **Statistical Outlier Report**: `[Target Metric]` ([Statistical Model]) with 30-day baseline context (`window: 30d`).
2. **Executed Multi-Stage YARA-L Query**: Literal executed multi-stage YARA-L query string passed into `secops-gus:udm_search(query=...)`.
3. **Ranked Outlier Summary**: Table with columns: `Entity Identifier`, `24h Observed`, `Baseline Mean`, `StdDev`, `Credibility / Z-Score`, `CRI Score (0–100)`, `Visual Magnitude`.
4. **Forensic Vector Breakdown**: Threat translation, security significance, attack scenarios, false positives, SOC action playbook.
5. **Immediate 1-Click Investigation Queries**: Raw UDM filter query for analyst drilldown.
6. **Statistical & Mathematical Appendix**: Formal model formulation ($N = 30d$), Calibrated Risk Index $	ext{CRI} = 	ext{round}\left(rac{100}{1 + \exp(-0.6 \cdot (Z - 3.0))}ight)$.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 1. Native Execution & Truth in Reporting
* **Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)**: If an API query fails, STOP IMMEDIATELY and report the error. Local scratch scripting to simulate baselines is a **CRITICAL COMPLIANCE VIOLATION**.
* **Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)**: Multi-stage statistical anomaly detection MUST run inside Chronicle. It is **STRICTLY PROHIBITED** to calculate baselines locally in Python.
* **Zero Local Script Invocations During Hunting (ZERO RUN_COMMAND VALIDATION)**: MUST NOT call `run_command` or execute local Python scripts in terminal during chat. Never prompt for terminal permissions.
* **Hermetic Skill Boundary (ZERO CROSS-SKILL DRIFT)**: Once active, the agent MUST NOT read, import, or search other skills. This skill is 100% self-contained.
* **Atomic Pipeline Execution Mandate (ZERO PIECEMEAL FRACTURING & DRIFT)**: Dispatch complete multi-stage DAG in a single atomic YARA-L query passed to `udm_search`. It is **STRICTLY PROHIBITED** to break into isolated 1-metric queries or chase raw log regexes (`target.hostname = /.../`).
* **Literal Query Display Mandate (ZERO FAKED YARA-L QUERIES)**: Section 2 MUST contain the literal, exact query string passed into `secops-gus:udm_search(query=...)`.
* **Zero Unsolicited Ingestion**: Calling `import_logs` or `generate_synthetic_events` without explicit authorization is **STRICTLY PROHIBITED**.
* **Post-Flight Audit & Auto-Correction**: If execution is deformed, present auto-corrected query and ask: *"Would you like me to execute this auto-corrected query now, or exit this hunt?"*

### 2. Compiler & Architectural Invariants
* **Pre-Composed Pipeline Template Routing**: Route hunts directly to complete composite pipeline templates in `templates/pipelines/` (e.g. `mad_modified_z_2stage.yl2`, `standard_z_score_2stage.yl2`, `poisson_rarity_2stage.yl2`, `multi_sector_fusion_4stage.yl2`). Perform 1:1 parameter slot-filling rather than dynamic syntax stitching.
* **Exact Time Window Arithmetic**: Compute $\text{startTime} = \text{endTime} - N \times 86400\text{s}$ with exact precision matching the user's requested horizon (e.g. 14 days ending Aug 29 starts Aug 16 at 00:00:00Z).
* **Variable Role Classification & Anti-Passive-Decoration Mandate**: Every variable must fulfill: `[JOIN_KEY]`, `[SCORING_DIMENSION]`, `[ACTIVE_FILTER]`, or `[TRIAGE_DECORATION]`. **Qualitative primary threat vectors (command lines, LOLBin script args, rare binaries, unique URLs) MUST NEVER act solely as `[TRIAGE_DECORATION]`**; bind them to an active Cross-Sectional Fleet Rarity Stage (`count_distinct(principal.asset.hostname) <= 2`) or Entity Graph constraint. *(See `references/multi-stage-metrics-guide.md`)*.
* **Threat-to-Telemetry Decomposition Matrix**: Volumetric Surges $	o O(1)$ 30d `metrics.*`; LOLBins $	o$ Cross-Sectional Fleet Rarity DAG ($N_{\text{hosts}} \le 2$); High-Churn Infra $	o$ Entity Graph (`rolling_max <= 3`).
* **Single-ECG Limit & Decoupled Context Fusion**: Max 1 ECG lookup per stage (`Number of ECG events exceeded max limit: 2 > 1`). Never evaluate `metrics.*` inside stages filtered by `GLOBAL_CONTEXT` or `DERIVED_CONTEXT`. Decouple baseline into Stage 1 and threat context into Stage 2.
* **Inner-Join Drop Prevention Standard (PRESERVING FULL POPULATION)**: In YARA-L, multi-stage joins are inner joins. When evaluating all entities including threat domains, do NOT place threat filter in a separate stage. Evaluate full baseline in Stage 1 and profile destinations via `array_distinct(target.hostname)`.

### 3. Scope, Steering & Parsimony
* **Pure Threat Hunting Scope (SEARCH-ONLY — ZERO RULE CREATION / DEPLOYMENT)**: `create_rule`, `validate_rule`, and parser activation are **STRICTLY PROHIBITED** during threat hunts.
* **Non-Metrics Telemetry Steering Mandate (HANDOFF TO STATISTICAL HUNTER)**: If an analyst targets non-baselined telemetry, emit the **Skill Handoff Card** and steer to `secops-statistical-hunter`.
* **Zero Gratuitous Entity Graph Injection (ON-DEMAND / ALGORITHMIC GROUNDING ONLY)**: Entity Graph (`graph.*`, `DERIVED_CONTEXT`, `GLOBAL_CONTEXT`) constructs must **NEVER be injected gratuitously or speculatively**. Include ONLY upon **Direct Customer Request (On-Demand)** or explicit **Algorithmic Grounding**.

---

## 📂 Modular References & Template Architecture

* **Metric Catalog (38 Metrics)**: [`references/metrics-catalog.md`](file:///usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/references/metrics-catalog.md)
* **Statistical Models Taxonomy (14 Models)**: [`references/statistical-models-taxonomy.md`](file:///usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/references/statistical-models-taxonomy.md)
* **Calibrated Risk Index Guide (CRI [0–100])**: [`references/calibrated-risk-index-guide.md`](file:///usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/references/calibrated-risk-index-guide.md)
* **Multi-Stage DAG Guide & Contracts**: [`references/multi-stage-metrics-guide.md`](file:///usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/references/multi-stage-metrics-guide.md)
* **YARA-L 2.0 Templates**: [`templates/stage1_extractors/`](file:///usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/templates/stage1_extractors/), [`templates/stage2_math_models/`](file:///usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/templates/stage2_math_models/), [`templates/pipelines/`](file:///usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/templates/pipelines/)
* **Chart Specifications Guide**: [`references/chart-specifications-guide.md`](file:///usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/references/chart-specifications-guide.md)
* **Pre-Flight Validator**: [`scripts/preflight_validator.py`](file:///usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/scripts/preflight_validator.py)
* **Chart Generator**: [`scripts/chart_generator.py`](file:///usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/scripts/chart_generator.py)

---
*Created and maintained by Greg Kushmerek for Google SecOps Chronicle SIEM threat hunting workflows.*
