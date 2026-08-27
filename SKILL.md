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
  Triggers: "hunt with risk metrics", "multi-stage metrics outlier", "MAD on network bytes", "z-score on auth", "risk analytics statistical hunt", "fleet outlier on process metrics", "poisson burst", "fano factor", "bayesian updating", "dual-baseline delta-z", "patch tuesday immunity", "multi-sector threat fusion", "360 health check", "compare to team", "slow and low exfiltration", "behavioral drift", "outbound data siphon", "top statistical outliers".
compatibility: Requires access to a Google SecOps instance with Risk Analytics metrics enabled and the SecOps GUS MCP server (udm_search, get_operation).
---

# SecOps Risk Metrics Multi-Stage Statistical Hunter (`secops-risk-metrics-multistage`)

This skill empowers an LLM agent to execute **fleet-wide, population-level, and multi-sector statistical outlier hunting** in Google SecOps by leveraging **30-day pre-computed Risk Analytics metrics (`metrics.*`)** as the baseline spine, chained into **2-stage, 3-stage, and 4-stage mathematical DAG pipelines**.

---

## 🔀 Bi-Directional Skill Steering & Handoff Protocol

| If the analyst's hunt targets... | Then activate... | Operational Action |
| :--- | :--- | :--- |
| • **30-Day Behavioral Baselines** (`metrics.*`)<br>• **Peer / Team Cohort Outliers**<br>• **360° Entity Health Radar**<br>• **Multi-Sector Threat Fusion** | 📊 **`secops-risk-metrics-multistage`** *(This Skill)* | Execute native multi-stage `metrics.*` pipeline. |
| • **Ad-Hoc Raw Telemetry Sensors** (C2 jitter CV, inter-arrival timing)<br>• **Non-Metrics Data Sources** (raw VPC flow, arbitrary un-baselined logs)<br>• **Custom Time Slices** (e.g. 4-hour raw burst, 7-day raw logs) | ⚡ **`secops-statistical-hunter`** | Emit **Skill Handoff Card** and guide user to `secops-statistical-hunter`. |

### 🔀 Skill Handoff Card (When hunt targets raw non-metrics sensors):
```markdown
> [!TIP]
> **🔀 Skill Routing Notice: `secops-statistical-hunter` Recommended**
> • **Why This Skill**: Your request targets raw telemetry sensors or non-baselined data sources without 30-day UEBA pre-computed tables (`metrics.*`).
> • **Action**: Routing to **`secops-statistical-hunter`** to analyze raw UDM events directly.
```

---

## ⏱️ Evaluation Modes: Snapshot vs. 30-Day Longitudinal Sliding Timeline

1. **Mode A: Current-Day Snapshot (`FLEET_ROLLUP`)**:
   * **Active Search Window**: Exactly 24 hours (Today).
   * **Baseline Context**: Trailing 30-day pre-computed behavioral table (`window: 30d`).
   * **Operational Purpose**: Answers *"Who is anomalous right now today relative to their 30-day norm?"* (1 summary row per entity).
2. **Mode B: 30-Day Longitudinal Sliding Timeline (`TIMELINE_BREAKDOWN`)**:
   * **Active Search Window**: Multi-day window up to 14–30 calendar days (`match: $entity by 1d`).
   * **Operational Purpose**: Answers *"When did drift begin, and how did behavior evolve day-by-day across daily slices?"* (Powers CUSUM drift and baseline envelope charts).

> [!NOTE]
> **🛡️ 30-Day Pre-Computed Architectural Assurance**: Google SecOps automatically maintains background rolling 30-day pre-aggregated entity tables. Regardless of whether the active search window is 1 day or 14 days, `window: 30d` performs an $O(1)$ constant-time lookup against 30 trailing days of pre-computed historical activity.

---

## 🚦 MANDATORY STEP 1: PRE-FLIGHT CLEARANCE & HARD TURN BOUNDARY (ZERO EXECUTION ON TURN 1)

Whenever an analyst initiates a hunt, selects an archetype, or refines parameters, **THE AGENT MUST NEVER CALL SEARCH OR INGESTION TOOLS ON THAT TURN**.

### Mandatory Step 1 Turn Sequence:
1. **ZERO Tool Execution**: Execute 0 tool calls to `udm_search`, `import_logs`, `run_command`, or local python scripts. (Do **NOT** execute python scripts in the terminal to validate queries during chat; templates in `templates/` are already verified).
2. **Plain-English Cyber Analogy (1–2 Sentences)**: Explain the statistical approach using a down-to-earth physical concept.
3. **Structured Pre-Flight Hunting Specification Card & Mandatory Query Preview**:
   ```markdown
   ┌────────────────────────────────────────────────────────────────────────────────────────┐
   │                        PRE-FLIGHT HUNTING SPECIFICATION                                │
   │  • Target Entity / Scope:   [Target User/Host ID or Enterprise Fleet]                  │
   │  • Baseline Horizon Spine:  30-Day Pre-Computed Risk Analytics (period: 1d, win: 30d) │
   │  • Peer Cohort & Roster:    [Team/Dept Cohort, e.g. IT Dept (2 entities: Frank, Tim)]  │
   │  • Entity Graph Dimension:  [Prevalence (rolling_max <= 3) / First-Seen / N/A]        │
   │  • Evaluation Horizon Mode: [Mode A: 24h Snapshot (Default) OR Mode B: 14d Timeline]   │
   │  • Statistical Model:       [Model Name, e.g. 4-Stage Multi-Sector Threat Fusion (D)]  │
   │  • Significance Threshold:  [e.g. Z >= 3.0σ (CRI >= 50) or Multi-Sector (D >= 3.5σ)]   │
   └────────────────────────────────────────────────────────────────────────────────────────┘

   #### 🔍 Pre-Flight Multi-Stage YARA-L Query Preview:
   ```yara
   [Full Literal Multi-Stage YARA-L Query rendered directly in markdown on Turn 1]
   ```
   ```
   * *Sparse Baseline Caution*: If requested horizon is $< 7\text{ days}$ ($N < 7$), include: `> **⚠️ Sparse Baseline Caution (< 7 Days Requested)**: Evaluating entities with fewer than 7 active baseline days ($N < 7$) reduces degrees of freedom. We enforce an active-day floor ($hist_active_days >= 7$) and recommend Empirical Bayes shrinkage.`
   * *Mandatory Upfront Query Preview Protocol*: The agent MUST ALWAYS display the complete literal multi-stage YARA-L query in markdown directly on Turn 1 prior to requesting execution clearance.
   * *Peer Cohort Roster Requirement*: When performing peer/team comparisons, resolve and list the concrete cohort entities and count ($N$) in the specification card.
   * *Interactive Entity Graph Dimension Mandate*: Whenever an Entity Graph join is included (Domain/File/IP Prevalence, First-Seen Novelty, WHOIS age), it MUST be directly and explicitly expressed inside the Pre-Flight Card under `• Entity Graph Dimension: [Exact Filter, e.g. File Prevalence (rolling_max <= 3)]`.
   * *Interactive Entity Graph Rarity & Context Discovery*: When the analyst uses qualitative modifiers (e.g. *"rare domains"*, *"rare binaries"*, *"novel destinations"*, *"first seen"*), **NEVER ignore the modifier**. Actively map it to the relevant SecOps Entity Graph capability:
     - **Domain Rarity**: Fleet Prevalence (`graph.entity.domain.prevalence.rolling_max <= 3`) or First-Seen (`first_seen_time < 30d`).
     - **Binary Rarity**: SHA256 Prevalence (`graph.entity.file.prevalence.rolling_max <= 3`) or First-Seen (`first_seen_time < 30d`).
     - **IP Rarity**: IP Prevalence (`graph.entity.artifact.prevalence.rolling_max <= 3`) or First-Seen (`first_seen_time < 30d`).
     Display the active rarity layer in the Pre-Flight Card (`• Entity Graph Dimension: ...`), render the join in the YARA-L Query Preview, and suggest threshold options.
   * *10-Day Prevalence Platform Invariant*: Google SecOps Entity Graph prevalence is hardcoded to a 10-day rolling lookback window (`day_count = 10`). If an analyst asks to change the prevalence period (e.g. to 30d), explain that `day_count = 10` is an immutable platform backend anchor, and offer adjusting the asset count threshold (`rolling_max <= N`) or layering 30/60/90-day First-Seen novelty (`first_seen_time < 30d`) instead.
   * *IOC Demarcation Expectation Setting*: When an analyst asks to include IOCs along with general traffic, clarify upfront that the baseline query evaluates 100% of fleet traffic and surfaces all contacted domains uniformly, but does not partition or badge IOCs in the output table. Triage of specific domains against threat intel is provided via Section 5 drilldowns.
4. **Explicit Clearance Question & Turn Termination**: Explicitly present **both execution modes** and ask:
   > *"Would you like to run **Mode A (24-Hour Snapshot fleet ranking)** or **Mode B (14-Day Longitudinal Timeline with inception chart)**?"*
   **STOP CALLING TOOLS IMMEDIATELY AND YIELD THE TURN.**

---

## 📊 MANDATORY STEP 2: PRESENT FULL 6-SECTION REPORT (AFTER CLEARANCE)

When clearance is granted and native queries execute, the report **MUST STRICTLY CONTAIN ALL 6 NUMBERED PILLARS**:

```markdown
### ⚡ Statistical Outlier Report: `[Target Metric]` ([Statistical Model])

> [!NOTE]
> **📊 Engine: Google SecOps UEBA & Risk Analytics**
> • **Baseline Horizon**: 30-Day Pre-Computed Behavioral Tables (`window: 30d`)
> • **Confidence Tier**: High-Confidence Population Baseline ($N = 30$ daily observations)

* **Outliers Detected**: **[Count] entities** exceeded the configured threshold (`> [Threshold]`).
* **Active Search Window**: 24-Hour Active Evaluation Window (Today's Observations).
* **Historical Baseline Horizon**: 30-Day Pre-Computed Behavioral Context (`window: 30d`).

---

#### 💻 Executed Multi-Stage YARA-L Query
```yara
[Literal executed multi-stage YARA-L query string passed to API]
```

---

#### 📊 Ranked Outlier Summary (Top Anomalies)
| Entity Identifier | 24h Observed | Baseline Mean (30d) | Baseline StdDev | Credibility / Z-Score | CRI Score (0–100) | Visual Magnitude |
| :---------------- | :----------- | :------------------ | :-------------- | :-------------------- | :---------------- | :--------------- |
| `[Entity ID]`     | `[Obs]`      | `[Mean]`            | `[StdDev]`      | `[Z-Score]`           | `[CRI Score]`     | `[Bar]`          |

---

#### 🔍 Forensic Vector Breakdown & Impact Analysis
> [!IMPORTANT]
> **Threat Translation & Attack Scenarios: [Threat Name]**
> * **The Core Finding**: [Plain-English summary of what happened]
> * **Security Significance**: [Why this is dangerous in the enterprise]
> * **Potential Attack Scenarios**: [Ransomware, lateral movement, insider exfiltration]
> * **Legitimate False Positives**: [Scheduled backups, IT admin deployments]
> * **SOC Action Playbook**: 1. Investigate entity, 2. Check process tree, 3. Review egress destinations.

---

#### 🎯 Immediate 1-Click Investigation Queries
```yara
[Raw UDM filter query for fast analyst verification]
```

---

#### 🔬 Statistical & Mathematical Appendix (Technical Details)
<details open>
<summary>🔬 <b>Statistical & Mathematical Appendix (Technical Details)</b></summary>
* **Model Formulation**: $[Mathematical Formula]$
* **Degrees of Freedom ($N$)**: 30 daily observation periods.
* **Calibrated Risk Index**: $\text{CRI} = \text{round}\left(\frac{100}{1 + \exp(-0.6 \cdot (Z - 3.0))}\right)$.
</details>
```

---

## 🎯 Operational Mindsets & Model Portfolio

| Operational Mindset | Common Analyst Phrasing | Statistical Model Activated | Architecture Tier | Reference File |
| :--- | :--- | :--- | :--- | :--- |
| **1. Baseline Drift** | *"Is [User/Host] acting weird compared to past month?"* | **Standard $Z$-Score** / **Robust MAD** | Tier 1 (1D Macro) | `references/statistical-models-taxonomy.md` |
| **2. Peer Cohort Review** | *"Is Frank doing things his direct teammates don't do?"* | **Hierarchical Peer Bayes** | Tier 2 (1D + Org Context) | `references/statistical-models-taxonomy.md` |
| **3. Multi-Sector Fusion** | *"Correlate low-and-slow spikes across IAM, Process, and Egress."* | **4-Stage Multi-Sector Fusion ($D \sim \chi_3$)** | Tier 3 (3D Multi-Sector) | `templates/pipelines/multi_sector_fusion_4stage.yl2` |
| **4. Low-and-Slow Stealth** | *"Look for quiet multi-day behavioral drift."* | **Longitudinal CUSUM ($S^+$)** | Tier 2 (Multi-Day Longitudinal) | `references/statistical-models-taxonomy.md` |
| **5. 360° Health Radar** | *"Run a complete 360-degree risk check across all metrics."* | **360° Omnibus Radar ($D_{\text{Omni}}$)** | Tier 3 (Multi-Sector Slices) | `references/statistical-models-taxonomy.md` |

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 1. Native Execution & Truth in Reporting
* **Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)**: If an API query fails, the agent MUST **STOP IMMEDIATELY** and report the error. Local scratch scripting to simulate baselines is a **CRITICAL COMPLIANCE VIOLATION**.
* **Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)**: Multi-stage statistical anomaly detection MUST run inside Chronicle's analytics engine. It is **STRICTLY PROHIBITED** to calculate baselines locally in Python.
* **Zero Local Script Invocations During Hunting (ZERO RUN_COMMAND VALIDATION)**: The agent MUST NOT call `run_command` or execute local Python scripts in the terminal to validate queries during chat. Never prompt the user with terminal permissions to run local validator scripts.
* **Hermetic Skill Boundary (ZERO CROSS-SKILL DRIFT)**: Once `secops-risk-metrics-multistage` is active, the agent MUST NOT read, import, or search other skills (e.g. `secops-detection-engineering`, `secops-yara-l`). This skill is 100% self-contained.
* **Atomic Pipeline Execution Mandate (ZERO PIECEMEAL FRACTURING & DRIFT)**: When executing multi-sector or threat-fused archetypes (e.g. 4-Stage Multi-Sector Threat Fusion), the agent MUST dispatch the complete multi-stage DAG in a single atomic YARA-L query passed to `udm_search`. It is **STRICTLY PROHIBITED** to break the pipeline into isolated 1-metric queries or abandon the baseline spine to chase raw log regexes (`target.hostname = /.../`).
* **Literal Query Display Mandate (ZERO FAKED YARA-L QUERIES)**: Section 2 MUST contain the literal, exact query string passed into `secops-gus:udm_search(query=...)`.
* **Zero Unsolicited Ingestion**: Calling `import_logs` or `generate_synthetic_events` without explicit analyst authorization is **STRICTLY PROHIBITED**.
* **Post-Flight Audit & Auto-Correction**: If execution is deformed, present the auto-corrected query and ask: *"Would you like me to execute this auto-corrected query now, or exit this hunt?"*

### 2. Compiler & Architectural Invariants
* **Variable Role Classification & Anti-Passive-Decoration Mandate**: Every variable in an intermediate stage must fulfill an explicit role: `[JOIN_KEY]` (binds stages), `[SCORING_DIMENSION]` (in math formula), `[ACTIVE_FILTER]` (in `condition:` / prevalence threshold), or `[TRIAGE_DECORATION]` (in outcome array). **Qualitative primary threat vectors (command lines, LOLBin script args, rare binaries, unique URLs) MUST NEVER act solely as `[TRIAGE_DECORATION]`**; they must be bound to an active Cross-Sectional Fleet Rarity Stage (`count_distinct(principal.asset.hostname) <= 2`) or Entity Graph Derived Context constraint.
* **Threat-to-Telemetry Decomposition Matrix**:
  - *Volumetric Surges* $\to O(1)$ 30d `metrics.*` baselines + Parametric $Z$ / Delta-$Z$.
  - *Unbounded Qualitative / LOLBins* (wscript, cmdlines) $\to$ Cross-Sectional Fleet Rarity DAG ($N_{\text{hosts}} \le 2$).
  - *High-Churn Infrastructure* $\to$ Entity Graph Prevalence (`rolling_max <= 3`) / First-Seen Novelty.
  - *Multi-Step Killchains* $\to$ Causal Cross-Stage Joins (`$host, $ws by 1d`).
* **Anti-Pattern 5 (Zero Raw Stats Stand-In for UEBA)**: The query MUST strictly use `metrics.*` with pre-computed 30-day baseline tables (`period: 1d, window: 30d`).
* **Anti-Pattern 6 (Single-Stage Multi-Vector Cramming Prohibition)**: Cramming multiple `metadata.event_type` expressions into a single `events:` block with `OR` is **STRICTLY PROHIBITED**. Use independent DAG extractor stages.
* **Anti-Pattern 7 (Non-Existent Metric Functions)**: The agent must ONLY invoke valid metric tables from `METRIC_CATALOG`.
* **Single-ECG Limit & Decoupled Context Fusion**: Max 1 Entity Context Graph (ECG) lookup per stage (`Number of ECG events exceeded max limit: 2 > 1`). Never evaluate `metrics.*` inside stages filtered by `GLOBAL_CONTEXT` or `DERIVED_CONTEXT` (Part-of-the-Whole Fallacy). Decouple baseline into Stage 1 and threat context into Stage 2.
* **Inner-Join Drop Prevention Standard (PRESERVING FULL POPULATION)**: In YARA-L, multi-stage joins operate strictly as inner joins. When an analyst requests "all connections including but not limited to threat domains", do NOT place the threat domain filter in a separate stage (which drops all non-threat entities). Instead, evaluate the full population baseline in Stage 1 and profile destinations/threat stamps via `array_distinct(target.hostname)` and `security_result.category_details`.

### 3. Scope, Steering & Parsimony
* **Pure Threat Hunting Scope (SEARCH-ONLY — ZERO RULE CREATION / DEPLOYMENT)**: `create_rule`, `validate_rule`, and parser activation tools are **STRICTLY PROHIBITED** during threat hunts.
* **Non-Metrics Telemetry Steering Mandate (HANDOFF TO STATISTICAL HUNTER)**: If an analyst targets non-baselined telemetry, emit the **Skill Handoff Card** and steer to `secops-statistical-hunter`.
* **Zero Gratuitous Entity Graph Injection (ON-DEMAND / ALGORITHMIC GROUNDING ONLY)**: Entity Graph (`graph.*`, `DERIVED_CONTEXT`, `GLOBAL_CONTEXT`, WHOIS, Safe Browsing, GCTI) constructs must **NEVER be injected gratuitously or speculatively**. They are included ONLY upon **Direct Customer Request (On-Demand)** or explicit **Algorithmic Grounding**.

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
