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
                                               ├─ 1. Identity Check (if unqualified/email, maxEvents: 1)
                                               ├─ 2. 1-Shot Baseline Probe (maxEvents: 1)
                                               ├─ 3. PRE-FLIGHT HUNTING SPECIFICATION Card
                                               ├─ 4. Candidate YARA-L Preview
                                               └─ 5. Clearance Question ──► YIELD
[Turn 2: Clearance Granted]
       │
       └─► State 2: Multi-Stage Execution
                 ├─ 1. Dispatch Multi-Stage YARA-L via udm_search (returning "stats")
                 └─ 2. Present 5-Pillar Report (or Clean Hunt Audit)

[Turn 3+: Entity Shifts / Iteration]
       │
       └─► Re-enter Phase 1B for New Entity Scope ──► YIELD
```

---

## 2. Turn 1: Framing, Pre-Flight Specification & Clearance

Turn 1 is strictly dedicated to understanding the analyst's intent, verifying telemetry availability, presenting a candidate query preview, and securing explicit execution clearance.

### Path A: Phase 1A — Consultative Vector Discovery
When an inquiry specifies an entity or cohort but leaves the behavioral vector open-ended (e.g. *"Check Frank for suspicious behavior"*, *"Audit service account anomalies"*):

1. **Zero Multi-Stage Execution**: Execute 0 multi-stage `metrics.*` queries and emit 0 candidate code blocks (at most 1 `udm_search` `maxEvents: 1` identity spot-check if a human name/email is given).
2. **Consultative Structure & Anti-Auth-Defaulting Mandate**: Do not assume authentication or login failures. Format the response with explicit `### Threat Hypothesis` and `### Summary View` (or `### Recommended Method`) headings (`references/consultative-worksheet.md` §Phase 1A Consultative Response Structure Mandate), presenting options across all 8 canonical telemetry families plus an exploratory 360° sweep:
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
   - Single first names (e.g. `"Frank"`), display names with spaces (`"Frank Kolzig"`), or corporate user email addresses (`"admin@demo.wsexample.org"`, whose technical `user.userid` in UDM may be the local part `"admin"`) must be verified against UDM telemetry before binding `user.userid`. Standard machine/service accounts (`@*.iam.gserviceaccount.com`, `arn:aws:...`, `sa-*`), hosts, and fleet sweeps proceed directly to the 1-shot event-filter probe (skipping this check).
   - Run a UDM spot-check over the requested target window when a historical date/range is given, or the last 14 days (`<ISO_14D_AGO>` to `<ISO_NOW>`) otherwise:
     `udm_search(query='target.user.userid = "<name>" nocase or principal.user.userid = "<name>" nocase or target.user.email_addresses = "<name>" nocase or principal.user.email_addresses = "<name>" nocase or target.user.user_display_name = /.*<name>.*/ nocase or principal.user.user_display_name = /.*<name>.*/ nocase', startTime="<ISO_START_OR_14D_AGO>", endTime="<ISO_END_OR_NOW>", maxEvents=1)`.
   - If $\ge 1$ events match, always extract and bind the non-empty authoritative `user.userid` from `target.user.userid` or `principal.user.userid` in the matched UDM event (even when the input matched on `email_addresses`; if `userid` is unpopulated on that event, extract the local username stem from `user_display_name` such as `DOMAIN\user` $\to$ `user`), and echo both the full display name (if populated, e.g. `Frank Kolzig`) and verified `user.userid` (`frank.kolzig`) in the Pre-Flight card (`• Target Entity / Scope: Frank Kolzig (Verified User ID: frank.kolzig)`).
   - If 0 events match an unqualified name/alias (no `.` and no `@`), halt immediately (0 additional tools called, no Pre-Flight card) and ask for the corporate email or technical username. If 0 events match an already qualified identifier (`first.last` or `user@domain`) in a default window, retain the input as `user.userid` for the Pre-Flight card without retrying additional identity queries, and probe the event filter without the entity predicate.
2. **Single-Event Baseline Probe (Turn 1 Tool Invariant)**:
   - The event-filter probe on every pre-flight turn evaluates exclusively simple single-event filters with `maxEvents: 1` using strict ISO 8601 UTC timestamps:
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
   • Evaluation Horizon Mode:[chosen mode only: A last complete UTC day (default) or Today So Far (partial-day low-bias warning) | B 2–3d + baseline dates | C per-day shards]
   • Statistical Model:      [Model & Template, e.g. CUSUM Drift (`longitudinal_cusum.yl2`)]
   • Significance Threshold: [Model gate from model-concordance-guide.md §2.1: Z >= 3.0σ | 2.0σ <= Z < 3.0σ | >= 2.0× baseline | D >= 3.5σ | N/A (Fano)]
   ```
   The `Significance Threshold` line and the query's root `condition:` MUST state the same gate (variable, operator, value). A threshold on the card with no matching `condition:` in the query is a concordance failure.
4. **Candidate Query Preview**: Render the multi-stage query assembled from `templates/pipelines/` inside a ````yara block.
5. **Clearance Question (Final sentence of Turn 1, then yield)**:
   > *"Would you like me to proceed with **Mode A (Last Complete UTC Day vs 30-Day Baseline)** [or **Mode A — Today So Far (Partial UTC Day)**], **Mode B (2–3 Day Fixed-Baseline Timeline)**[, or **Mode C (Per-Day Baseline)** if `run_command` is present]? (Adjust noise level/significance threshold before execution if desired.)"*
   *(Mode B and C mechanics, baseline anchoring, and the no-shell note: `timeline-modes-guide.md`.)*
   *(If a specific target date was requested: "Proceed with executing for [Target Date] now?")*

---

## 3. Turn 2: Deterministic Multi-Stage Execution & Reporting

Turn 2 executes **strictly after explicit analyst clearance** (*"Clearance granted"*, *"Run it"*, *"Mode A"*, *"Mode B"*, *"Mode C"*, *"proceed"*, *"execute"*) following a Turn 1 Pre-Flight card and candidate query preview. Always execute that exact candidate query — never re-emit a new Pre-Flight card or substitute a different query on Turn 2.

### Step 1: Telemetry Dispatch
Analyst clearance constitutes an explicit directive to execute the search across Chronicle SIEM to verify the baseline. Always dispatch the approved multi-stage query via `udm_search` (returning `"stats"`), regardless of preliminary spot-check counts. For 360° Radar investigations, dispatch the decoupled sector micro-queries in parallel. When telemetry yields zero events or an empty stats payload (`{}` or `{"stats": []}`), format the response affirmatively as a nominal baseline using the two-pillar Zero-Telemetry Clean Hunt structure below.

### Step 2: Present Findings

#### Standard 5-Pillar Report (When Outliers Detected)
* **#### 1. Statistical Outlier Report: `[Target Metric] ([Statistical Model])` — Executive Summary & Calibrated Risk Index (CRI)**: Headline finding, piecewise CRI badge (`CRI(Z) = 0` for `Z <= 0`, `round(100 / (1 + exp(-0.6 * (Z - 3.0))))` for `Z > 0`), and single visual surface (`<agent-embed>` in Jetski, inline `<svg>` in webview/MCP, or Unicode `▰▰▰▰▱▱▱▱` bars).
* **#### 2. Ranked Outlier Summary & Provenance Stamp**: Columns: `Entity`, `Observed`, `30d Mean (μ)`, `30d StdDev (σ)`, `Z-Score / Metric`, `CRI [0-100]`, plus provenance stamp (`Executed Window`, `Baseline Window`, `Rows Returned`, `Entity Filter`, `Data-Source Status`).
* **#### 3. Forensic Vector Breakdown**: Operational threat interpretation, MITRE ATT&CK kill-chain progression, confounders, investigative triage steps, and **Outcome-Driven Agentic Next Steps** (`ACUTE_OUTLIER`, `CLEAN_OR_SUBTHRESHOLD`, `FLEET_WAVE`, or `SPARSE_BASELINE` via `CommonMarkTriageFormatter.build_agentic_next_steps`) proposing three concrete Phase 1B follow-up pivots labeled `[1]`, `[2]`, `[3]` (numbers, so a pick is never mistaken for Mode A/B clearance).
* **#### 4. Chronicle UI Manual Pivot**: Passive UDM search filter in a ```` ```text ```` code block (never `yara`) for manual timeline inspection in Chronicle SIEM.
* **#### 5. Collapsible Technical Appendix (Statistical & Mathematical Appendix)**: Collapsible `<details>` block containing the **verbatim executed multi-stage query** (in a ```` ```yara ```` fence — the ONLY `yara` block in Turn 2) and formal KaTeX definitions ($N=30\text{d}$ baseline, piecewise CRI normalization, Euclidean norm $D = \sqrt{\sum \max(0, Z_i)^2}$).

#### Clean Hunt Audit (Zero-Telemetry Exemption & Agentic Next Steps)
When the executed query returns an empty `stats` payload (`{"stats": []}` or `{}`) on a non-360° hunt, emit the streamlined 2-pillar Clean Hunt Report:
* `#### 1. Executive Summary & Baseline Status (CRI: 0 / Nominal)`: 0 ranked outlier entities ($Z = 0.00\sigma, D = 0.00\sigma, \text{CRI} = 0$, 🟢 **Nominal Fleet Baseline** — never emit `🚨` on a clean hunt).
* `#### 2. Telemetry Provenance, Diagnostic Coverage & Next Steps`: Provenance stamp (`Executed Window`, `Baseline Window`, `0 rows returned`, `Entity Filter`, `Data-Source Status`), **Agentic Next Steps** bullet block (`[1]` relaxing the significance gate `1.5σ <= Z < 3.0σ` or switching to `LONGITUDINAL_CUSUM`, `[2]` pivoting to an orthogonal kill-chain vector, or `[3]` running an Omnidirectional 360° Multi-Sector Sweep via `CommonMarkTriageFormatter.format_clean_hunt_report` — never write `"5-spoke radar"`, `"6-spoke radar"`, or `"spider radar"` in fleetwide reports), and a collapsible `<details>` block containing the verbatim executed multi-stage query.
* *Pillars 3–5 are waived for non-360° clean hunts. **360° Behavioral Radar / Fleetwide 360° Multi-Sector Threat Fusion Exception**: Single-entity and fleetwide 360° sweeps (`360` / `radar`) are NEVER abbreviated — even when all 6 sectors return 0 events, always emit all **5 numbered Pillars** (`#### 1.` through `#### 5.`), including `#### 2. Ranked Outlier Summary & Provenance Stamp` with all 6 canonical sectors for the entity type and Euclidean Threat Distance $D = \sqrt{\sum \max(0, Z_i)^2}$.*

---

## 4. Turn 3+: State 3 → Phase 1B Agentic Pivot Loop & Entity Shifts

* **State 3 → Phase 1B Agentic Pivot Loop**: When the analyst selects a follow-up option (`[1]`, `[2]`, or `[3]`) from Pillar 3 or a Clean Hunt report, transition directly from State 3 back to **Phase 1B** while carrying forward:
  1. The resolved technical entity ID (`principal.user.userid` or `principal.asset.hostname`) and peer cohort roster from the prior turn (do **not** re-ask Phase 1A scope questions or re-run identity disambiguation for the same entity).
  2. Any bridge keys extracted in State 2 (`$host`, `$user`, `$caller_ip`, `$sha256`, `$resource`) when pivoting across entity boundaries (e.g., Host ↔ User via `ChainedHuntRouter` or `build_alert_surge_query(entity_type=EntityType.USER)`).
  3. Emit the updated Pre-Flight Specification Card and Candidate Multi-Stage YARA-L Query for the new vector/model and ask for execution clearance.
* **Entity Shifts (*"same search for Laura"*):** Retain session context, re-enter Phase 1B for the new entity (resolve ID, emit pre-flight card + preview), and ask for clearance. Do not execute immediately without re-confirming scope.
* **Skill Boundary Shifts:** Sub-second packet timing or raw log regex requirements emit a delegation card to `secops-statistical-hunter`. Persistent rule authoring emits a delegation card to `secops-detection-engineering`.
