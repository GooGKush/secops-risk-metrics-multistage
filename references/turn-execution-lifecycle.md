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
2. **Anti-Auth-Defaulting Mandate**: Do not assume authentication or login failures. Present options across all 8 canonical telemetry families plus an exploratory 360° sweep:
   - Cloud Infrastructure & Data Access (`metrics.resource_*`)
   - Workspace Document, Drive & Email Access (`metrics.workspace_*`)
   - Network Egress Volume & Flows (`metrics.network_*`)
   - DNS Resolution Spikes (`metrics.dns_*`)
   - Web & Proxy Activity (`metrics.http_*`)
   - Endpoint Execution (`metrics.file_executions_*`)
   - Authentication Anomalies (`metrics.auth_*`)
   - Security & EDR Alerts (`metrics.alert_event_name_count` — see `references/consultative/security-edr-alerts.md`)
   - **Omnidirectional 360° Discovery Sweep**: 6-spoke decoupled behavioral radar across all sectors when the analyst wants to explore the data before committing to a single vector.
3. **Conversational Break**: Ask the consultative vector question and yield:
   > *"Across which behavioral vector(s) would you like to evaluate [Target Entities], or would you like an Omnidirectional 360° Discovery Sweep?"*

### Path B: Phase 1B — Pre-Flight Specification & Query Preview
Entered when the analyst selects a vector from Phase 1A, or when the initial prompt specifies both entity scope and telemetry vector.

* **Transition Invariant (Phase 1A → Phase 1B)**: When the analyst selects a vector from a Phase 1A consultative response, enter Phase 1B immediately in that same turn:
  1. Probe the selected vector via `udm_search` (`maxEvents: 1`).
  2. Emit the full `PRE-FLIGHT HUNTING SPECIFICATION` card.
  3. Emit the complete Candidate Multi-Stage YARA-L Query code block.
  4. Conclude with the mode clearance question (Mode A / Mode B, plus Mode C when `run_command` is present), then yield.
  *Never ask for clearance without presenting both the specification card and candidate query preview in the same turn.*

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
   - The compiler probe on Turn 1 evaluates exclusively simple single-event filters with `maxEvents: 1` using strict ISO 8601 UTC timestamps:
     `udm_search(query="<single_event_filter>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`
   - This verifies connectivity and tenant schema support. Full multi-stage DAG execution belongs strictly to Turn 2 following analyst approval.
3. **Structured PRE-FLIGHT HUNTING SPECIFICATION Card**:
   ```markdown
   PRE-FLIGHT HUNTING SPECIFICATION:
   • Target Entity / Scope:  [Target User/Host ID or Fleet]
   • Threat Hypothesis:      [Operational hypothesis summary]
   • Baseline Horizon Spine: 30-Day (period: 1d, 30d)
   • Peer Cohort & Roster:   [Team/Dept, e.g. IT (Frank, Tim)]
   • Entity Graph Dimension: [Prevalence (rolling_max <= 3) / N/A]
   • Evaluation Horizon Mode:[chosen mode only: A today | B 2–7d + baseline dates]
   • Statistical Model:      [Model & Template, e.g. CUSUM Drift (`longitudinal_cusum.yl2`)]
   • Significance Threshold: [Model gate from model-concordance-guide.md §2.1: Z >= 3.0σ | 2.0σ <= Z < 3.0σ | >= 2.0× baseline | D >= 3.5σ | N/A (Fano)]
   ```
   The `Significance Threshold` line and the query's root `condition:` MUST state the same gate (variable, operator, value). A threshold on the card with no matching `condition:` in the query is a concordance failure.
4. **Candidate Query Preview**: Render the multi-stage query assembled from `templates/pipelines/` inside a ````yara block.
5. **Clearance Question (Final sentence of Turn 1, then yield)**:
   > *"Would you like me to proceed with **Mode A (Today vs 30-Day Baseline)** or **Mode B (2–7 Day Fixed-Baseline Timeline)**[, or **Mode C (Per-Day Baseline)** if `run_command` is present]? (Adjust noise level/significance threshold before execution if desired.)"*
   *(Mode B and C mechanics, baseline anchoring, and the no-shell note: `timeline-modes-guide.md`.)*
   *(If a specific target date was requested: "Proceed with executing for [Target Date] now?")*

---

## 3. Turn 2: Deterministic Multi-Stage Execution & Reporting

Turn 2 executes **strictly after explicit analyst clearance** (*"Mode A"*, *"Mode B"*, *"Mode C"*, *"proceed"*, *"execute"*).

### Step 1: Telemetry Dispatch
Analyst clearance constitutes an explicit directive to execute the search across Chronicle SIEM to verify the baseline. Always dispatch the approved multi-stage query via `udm_search` (returning `"stats"`), regardless of preliminary spot-check counts. For 360° Radar investigations, dispatch the decoupled sector micro-queries in parallel. When telemetry yields zero events or an empty stats payload (`{}` or `{"stats": []}`), format the response affirmatively as a nominal baseline using the two-pillar Zero-Telemetry Clean Hunt structure below.

### Step 2: Present Findings

#### Standard 6-Pillar Report (When Outliers Detected)
* **#### 1. Statistical Outlier Report: `[Target Metric]` ([Statistical Model]) (`window: 30d`)**: Single visual surface (inline `<svg>` in webview/MCP or `<agent-embed>` in Jetski), metric summary, and Unicode magnitude bars (`▰▰▰▰▱▱▱▱`).
* **#### 2. Executed Multi-Stage YARA-L Query**: Verbatim mirror of the executed multi-stage query.
* **#### 3. Ranked Outlier Summary**: Columns: `Entity`, `24h Observed`, `30d Mean (μ)`, `30d StdDev (σ)`, `Z-Score`, `CRI Score`, `Visual Magnitude`.
* **#### 4. Forensic Vector Breakdown**: Operational threat interpretation, investigative triage steps, and **Outcome-Driven Agentic Next Steps** (`ACUTE_OUTLIER`, `CLEAN_OR_SUBTHRESHOLD`, `FLEET_WAVE`, or `SPARSE_BASELINE` via `CommonMarkTriageFormatter.build_agentic_next_steps`) proposing 2–3 concrete Phase 1B follow-up pivots `[A]`, `[B]`, `[C]`.
* **#### 5. Chronicle UI Manual Pivot**: Passive UDM search filter for manual pivot in Chronicle SIEM (never executed automatically by the agent).
* **#### 6. Statistical & Mathematical Appendix**: Formal KaTeX definitions ($N=30\text{d}$ baseline, CRI normalization, Euclidean norm $D$).

#### Clean Hunt Audit (Zero-Telemetry Exemption & Agentic Next Steps)
When the executed query returns an empty `stats` payload (`{"stats": []}` or `{}`):
* `#### 1. Statistical Outlier Report: [Target Metric] (Nominal Baseline)`: 0 observed events ($Z = 0.00\sigma, \text{CRI} = 0$, 🟢 **Nominal Fleet Baseline**).
* `#### 2. Executed Multi-Stage YARA-L Query`: Literal query executed.
* `#### 3. Agentic Next Steps (Sub-Threshold & Pivot Options)`: Propose `[A]` relaxing the significance gate (`1.5σ <= Z < 3.0σ`) or switching to `LONGITUDINAL_CUSUM`, `[B]` pivoting to an orthogonal kill-chain vector, or `[C]` running a 6-spoke 360° Behavioral Radar sweep (`CommonMarkTriageFormatter.format_clean_hunt_report`).
* *Pillars 3 (table), 5, and 6 are waived.*

---

## 4. Turn 3+: State 3 → Phase 1B Agentic Pivot Loop & Entity Shifts

* **State 3 → Phase 1B Agentic Pivot Loop**: When the analyst selects a follow-up option (`[A]`, `[B]`, or `[C]`) from Pillar 4 or a Clean Hunt report, transition directly from State 3 back to **Phase 1B** while carrying forward:
  1. The resolved technical entity ID (`principal.user.userid` or `principal.asset.hostname`) and peer cohort roster from the prior turn (do **not** re-ask Phase 1A scope questions or re-run identity disambiguation for the same entity).
  2. Any bridge keys extracted in State 2 (`$host`, `$user`, `$caller_ip`, `$sha256`, `$resource`) when pivoting across entity boundaries (e.g., Host ↔ User via `ChainedHuntRouter` or `build_alert_surge_query(entity_type=EntityType.USER)`).
  3. Emit the updated Pre-Flight Specification Card and Candidate Multi-Stage YARA-L Query for the new vector/model and ask for execution clearance.
* **Entity Shifts (*"same search for Laura"*):** Retain session context, re-enter Phase 1B for the new entity (resolve ID, emit pre-flight card + preview), and ask for clearance. Do not execute immediately without re-confirming scope.
* **Skill Boundary Shifts:** Sub-second packet timing or raw log regex requirements emit a delegation card to `secops-statistical-hunter`. Persistent rule authoring emits a delegation card to `secops-detection-engineering`.
