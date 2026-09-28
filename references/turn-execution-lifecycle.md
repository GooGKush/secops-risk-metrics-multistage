# Turn-by-Turn Execution Lifecycle & Clearance Protocol

This guide defines the authoritative turn schedule, state machine transitions, and conversational contracts for Google SecOps Multi-Stage Risk Analytics.

---

## 1. The 2-Turn Architectural Model

Multi-stage threat hunting requires strict two-turn conversational discipline to prevent unsolicited execution, premature reporting, and ungrounded data generation.

```
[Turn 1: Analyst Request]
       │
       ├─► Unspecified Vector? ──► Phase 1A: Consultative Discovery (0 tools called) ──► YIELD
       │
       └─► Defined Vector or Expert? ──► Phase 1B: Pre-Flight Alignment
                                               ├─ 1. Identity Check (if unqualified, maxEvents: 5)
                                               ├─ 2. 1-Shot Baseline Probe (maxEvents: 1)
                                               ├─ 3. PRE-FLIGHT HUNTING SPECIFICATION Card
                                               ├─ 4. Candidate YARA-L Preview
                                               └─ 5. Clearance Question ──► YIELD
[Turn 2: Clearance Granted]
       │
       └─► State 2: Multi-Stage Execution
                 ├─ 1. Dispatch Multi-Stage YARA-L via udm_search (returning "stats")
                 └─ 2. Present 6-Pillar Report (or 2-Section Clean Hunt Audit)

[Turn 3+: Entity Shifts / Iteration]
       │
       └─► Re-enter Phase 1B for New Entity Scope ──► YIELD
```

---

## 2. Turn 1: Framing, Pre-Flight Specification & Clearance

Turn 1 is strictly dedicated to understanding the analyst's intent, verifying telemetry availability, presenting a candidate query preview, and securing explicit execution clearance.

### Path A: Phase 1A — Consultative Vector Discovery
When an inquiry specifies an entity or cohort but leaves the behavioral vector open-ended (e.g. *"Check Frank for suspicious behavior"*, *"Audit service account anomalies"*):

1. **Zero Execution**: Call 0 tools and emit 0 candidate code blocks.
2. **Anti-Auth-Defaulting Mandate**: Do not assume authentication or login failures. Present options across the canonical telemetry families:
   - Cloud Infrastructure & Data Access (`metrics.resource_*`)
   - Workspace Document & Drive Access (`metrics.google_workspace_*`)
   - Network Egress Volume & Flows (`metrics.network_*`)
   - DNS Resolution Spikes (`metrics.dns_*`)
   - Web & Proxy Activity (`metrics.http_*`)
   - Endpoint Execution (`metrics.file_executions_*`)
   - Authentication Anomalies (`metrics.auth_*`)
3. **Conversational Break**: Ask the consultative vector question and yield:
   > *"Across which behavioral vector(s) would you like to evaluate [Target Entities]?"*

### Path B: Phase 1B — Pre-Flight Specification & Query Preview
Entered when the analyst selects a vector from Phase 1A, or when the initial prompt specifies both entity scope and telemetry vector.

#### The "Expert Exemption" Clarification
An analyst with deep domain knowledge may specify both a mathematical model and a metric table upfront (e.g. *"Run longitudinal CUSUM on Frank's DNS outbound bytes"* or *"Evaluate Poisson rarity on WRK-SHASEK login failures"*).
* **What the Expert Exemption Is**: Permission to skip Phase 1A consultative questioning and immediately proceed to Phase 1B pre-flight alignment.
* **What the Expert Exemption Is NOT**: A bypass of the Clearance Gate. Expert requests MUST still emit the pre-flight card, provide the candidate preview, ask the clearance question, and **yield the turn**. Turn 1 never executes multi-stage searches or delivers findings reports.

#### Turn 1 Operational Steps in Phase 1B:
1. **Identity Disambiguation**:
   - Single first names (e.g. `"Frank"`) or display names with spaces (`"Frank Kolzig"`) are not technical IDs.
   - Run a 14-day lookback check: `udm_search(query='target.user.userid = "<name>" nocase or principal.user.userid = "<name>" nocase', maxEvents=5)`.
   - If resolved, bind the technical `user.userid`. If unresolved, halt (0 tools called) and ask for the technical username.
2. **Single-Event Baseline Probe (Turn 1 Tool Invariant)**:
   - Run at most one 1-shot baseline/schema probe using a single-event UDM filter with strict ISO 8601 UTC timestamps:
     `udm_search(query="<single_event_filter>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`
   - Passing multi-stage queries (`stage ...`) or executing broad historical searches on Turn 1 is strictly prohibited.
3. **Structured PRE-FLIGHT HUNTING SPECIFICATION Card**:
   ```markdown
   PRE-FLIGHT HUNTING SPECIFICATION:
   • Target Entity / Scope:  [Target User/Host ID or Fleet]
   • Threat Hypothesis:      [Operational hypothesis summary]
   • Baseline Horizon Spine: 30-Day (period: 1d, 30d)
   • Peer Cohort & Roster:   [Team/Dept, e.g. IT (Frank, Tim)]
   • Entity Graph Dimension: [Prevalence (rolling_max <= 3) / N/A]
   • Evaluation Horizon Mode:[Mode A: today OR Mode B: 2–14d]
   • Statistical Model:      [Model & Template, e.g. CUSUM Drift (`longitudinal_cusum.yl2`)]
   • Significance Threshold: [Z >= 3.0σ | 2.0σ <= Z < 3.0σ | D >= 3.5σ]
   ```
4. **Candidate Query Preview**: Render the multi-stage query assembled from `templates/pipelines/` inside a ````yara block.
5. **Clearance Question (Final sentence of Turn 1, then yield)**:
   > *"Would you like me to proceed with **Mode A (Today vs 30-Day Baseline)** or **Mode B (2–14 Day Timeline)**? (Adjust noise level/significance threshold before execution if desired.)"*
   *(If a specific target date was requested: "Proceed with executing for [Target Date] now?")*

---

## 3. Turn 2: Deterministic Multi-Stage Execution & Reporting

Turn 2 executes **strictly after explicit analyst clearance** (*"Mode A"*, *"Mode B"*, *"proceed"*, *"execute"*).

### Step 1: Telemetry Dispatch
Dispatch the approved multi-stage query via `udm_search` (returning `"stats"`). For 360° Radar investigations, dispatch the decoupled sector micro-queries in parallel.

### Step 2: Present Findings

#### Standard 6-Pillar Report (When Outliers Detected)
* **#### 1. Statistical Outlier Report: `[Target Metric]` ([Statistical Model]) (`window: 30d`)**: Single visual surface (inline `<svg>` in webview/MCP or `<agent-embed>` in Jetski), metric summary, and Unicode magnitude bars (`▰▰▰▰▱▱▱▱`).
* **#### 2. Executed Multi-Stage YARA-L Query**: Verbatim mirror of the executed multi-stage query.
* **#### 3. Ranked Outlier Summary**: Columns: `Entity`, `24h Observed`, `30d Mean (μ)`, `30d StdDev (σ)`, `Z-Score`, `CRI Score`, `Visual Magnitude`.
* **#### 4. Forensic Vector Breakdown**: Operational threat interpretation and investigative triage steps.
* **#### 5. Chronicle UI Manual Pivot**: Passive UDM search filter for manual pivot in Chronicle SIEM.
* **#### 6. Statistical & Mathematical Appendix**: Formal KaTeX definitions ($N=30\text{d}$ baseline, CRI normalization, Euclidean norm $D$).

#### 2-Section Clean Hunt Audit (Zero-Telemetry Exemption)
When the executed query returns an empty `stats` payload (`{"stats": []}` or `{}`):
* `#### 1. Statistical Outlier Report: [Target Metric] (Nominal Baseline)`: 0 observed events ($Z = 0.00\sigma, \text{CRI} = 0$, 🟢 **Nominal Fleet Baseline**).
* `#### 2. Executed Multi-Stage YARA-L Query`: Literal query executed.
* *Pillars 3, 4, 5, and 6 are waived.*

---

## 4. Turn 3+: Iteration & Entity Shifts

* **Entity Shifts (*"same search for Laura"*):** Retain session context, re-enter Phase 1B for the new entity (resolve ID, emit pre-flight card + preview), and ask for clearance. Do not execute immediately without re-confirming scope.
* **Skill Boundary Shifts:** Sub-second packet timing or raw log regex requirements emit a delegation card to `secops-statistical-hunter`. Persistent rule authoring emits a delegation card to `secops-detection-engineering`.
