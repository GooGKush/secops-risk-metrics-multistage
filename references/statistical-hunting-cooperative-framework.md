# Chronicle SecOps Statistical Threat Hunting: Bilateral Cooperative Framework

This reference architecture establishes the bilateral operating model between the two specialized statistical threat hunting skills in Google SecOps:
1. **`secops-risk-metrics-multistage`** (Macro-Analysis: 30-Day Pre-Computed Baselines & Multi-Sector Fusion)
2. **`secops-statistical-hunter`** (Micro-Analysis: Ad-Hoc Inline Math & Unsupervised Raw Event Outliers)

---

## 1. The Two-Hemisphere Model

In an enterprise SecOps environment, threat hunting across massive telemetry requires two complementary mathematical lenses:

```
                      ┌────────────────────────────────────────┐
                      │      THE ACTIVE HUNT SESSION LOCK      │
                      │  (Multi-Turn Session Affinity Engine)   │
                      └───────────────────┬────────────────────┘
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  ▼                                               ▼
     ┌─────────────────────────┐                     ┌─────────────────────────┐
     │ secops-risk-metrics-    │  Federated Bridge   │    secops-statistical-  │
     │      multistage         │◄───────────────────►│          hunter         │
     ├─────────────────────────┤                     ├─────────────────────────┤
     │ • MACRO-ANALYSIS        │  "Drill down on IP" │ • MICRO-ANALYSIS        │
     │ • 30-day UEBA baselines │ ──────────────────► │ • Raw math (MAD, CV,    │
     │ • Peer group comparison │                     │   Poisson, Tukey)       │
     │ • CUSUM drift detection │ ◄────────────────── │ • Unsupervised outliers │
     │ • 360° Risk Radar (5P)  │  "Roll up to 30d"   │ • Beaconing intervals   │
     └─────────────────────────┘                     └─────────────────────────┘
```

| Dimension | Macro Hemisphere (`secops-risk-metrics-multistage`) | Micro Hemisphere (`secops-statistical-hunter`) |
| :--- | :--- | :--- |
| **Telemetry Foundation** | 30-day pre-computed behavioral baselines (`metrics.*`) | Raw unaggregated UDM events (`udm.metadata`, `udm.network`) |
| **Statistical Toolkit** | Standard $Z$, Delta $Z$ ($\Delta Z$), Longitudinal CUSUM ($S_t^+$), Euclidean Distance ($D$), Calibrated Risk Index (CRI) | Median Absolute Deviation (MAD), Coefficient of Variation ($CV \le 0.20$), Poisson Rarity, Tukey Fences (IQR), Benford's Law |
| **Lookback Horizon** | 30-day pre-computed baseline (1 row/entity per UTC day), anchored once per search request at its `startTime` day; scored windows are UTC days (today `00:00Z` → now) | Ad-hoc search window (e.g. 1h, 4h, 24h, 7d) on raw log streams |
| **Target Problems** | Behavioral drift, peer group deviation, fleet-wide anomaly ranking, multi-sector 360° risk profiling | C2 beaconing jitter, living-off-the-land frequency spikes, rare user-agent hunting, raw port/process outliers |

---

## 2. The Active Hunt Session Lock

### The Problem: Cross-Skill Fall-Through
In multi-turn threat hunts, analysts frequently pivot after viewing an initial report:
* *"Can you perform the same query for user 'admin'?"*
* *"What about user 'frank'?"*
* *"Now check the network egress on host-09."*

Generic host routing often interprets the word *"query"* or a short prompt as a cue to invoke unconstrained generic search skills (e.g. `secops-siem-search`), causing the workflow to collapse into an unhelpful raw log dump.

### The Solution: Multi-Turn Session Persistence
Once either statistical skill is activated in a conversation:
1. **Retain the Active Hunt Session**: Subsequent entity shifts or parameter adjustments inherit the statistical framework.
2. **Never Fall Through to Generic Search**: An entity shift (*"run same for user Y"*) must trigger a new pre-flight cycle within the statistical framework, **NEVER** an unconstrained raw log search.
3. **Hermetic Boundary with Generic Skills**: The agent must maintain strict boundary control against unconstrained search fall-through.

---

## 3. The Closed 3-State Active Hunt Engine

To prevent the accumulation of rigid negative prohibitions, workflows are structured as a closed positive state machine where only one primary action is valid per state:

```
 ┌───────────────────────┐       Clearance Granted       ┌───────────────────────┐
 │  STATE 1: CLEARANCE   │ ────────────────────────────► │  STATE 2: EXECUTION   │
 │ • Spot-check entity   │                               │ • Run collector CLI   │
 │ • Run compiler probe  │                               │ • Render 5 Pillars    │
 │ • Present spec table  │                               │ • Generate Radar SVG  │
 └───────────────────────┘                               └───────────┬───────────┘
             ▲                                                       │
             │                                                       │
             │           ┌───────────────────────┐                   │
             │           │  STATE 3: ITERATION   │ ◄─────────────────┘
             └────────── │ • Entity Shift        │
            "Same query  │ • Micro-Stats Bridge  │
             for admin"  │ • Action Clearance    │
                         └───────────────────────┘
```

### State 1: Pre-Flight Clearance & Specification
* **Identifier Qualification**: Standalone first names (`greg`, `frank`, `admin`) are probed via a 14-day UDM spot-check (`udm_search` with `maxEvents: 1`). If unresolved, halt and ask for technical ID.
* **Single-Event-Filter Probe**: Before displaying the candidate query, run a single-event-filter `udm_search` probe (`maxEvents: 1`, `<ISO_1H_AGO>` to `<ISO_NOW>`) of the event filter alone (no `stage`, `match:`, `metrics.`).
* **Pre-Flight Spec Card**: Present the structured specification card and probed query preview.
* **Hard Clearance Gate**: Ask the explicit clearance question and yield the turn (0 additional tools called).

### State 2: Deterministic Execution & 5-Pillar Reporting
* **Execution**: Run the validated multi-stage query or decoupled sector micro-queries natively via `udm_search` (and collate visual outputs post-search via `radar_collector.py`).
* **The 5 Pillars**:
  1. *Statistical Outlier Report (Multi-Stage Risk Metrics) — Executive Summary & Calibrated Risk Index (CRI)* (Visual surface + CRI summary).
  2. *Ranked Outlier Summary & Provenance Stamp* (Observed, Mean, StdDev, Z, CRI, Unicode magnitude bars).
  3. *Forensic Vector Breakdown* (SOC playbook, threat scenario, and numbered `[1]`, `[2]`, `[3]` Agentic Next Steps).
  4. *Chronicle UI Manual Pivot (Triage Reference Only)* (Passive UDM filter string in a ```` ```text ```` fence for manual browser copy-paste into Chronicle UI; tool execution of this string is strictly prohibited).
  5. *Collapsible Technical Appendix (Statistical & Mathematical Appendix)* (Contains `<details>` with the verbatim executed Multi-Stage YARA-L Query in ```` ```yara ```` and step-by-step math derivations).

### State 3: Iteration, Entity Shifts & Federated Bridge
* **Entity Shift**: When the analyst asks to *"run same for user Y"*, immediately loop back to **State 1** for the new entity.
* **Federated Bridge to `secops-statistical-hunter`**: When the analyst requests micro-mathematical analysis (e.g. C2 beaconing jitter, raw inter-arrival times, inline MAD), emit a Skill Handoff Card and pivot to `secops-statistical-hunter`.
* **Federated Bridge to `secops-risk-metrics-multistage`**: When an ad-hoc outlier is discovered in raw logs, roll up to a 30-day baseline via `secops-risk-metrics-multistage`.
* **Clean Escalation**: Unsolicited case creation is prohibited. Case promotion occurs exclusively after explicit human confirmation.

---

## 4. The Dual Grounding Invariants (The Non-Negotiable Core)

All behaviors in the cooperative framework are bound by two absolute invariants:

1. **Reality Grounding (Zero Data Simulation)**:
   * Every score, event count, entity, and timestamp must originate from an executed tool output.
   * If data is absent, zero, or an error occurs, report that exact reality.
   * *Truth Over Completion*: Reporting "0 observed events across all vectors — Baseline Cannot Be Computed" is a 100% successful hunt. Simulating completeness is a critical security failure.

2. **Schema & Syntax Grounding (Zero Schema Fantasy)**:
   * Never invent non-existent UDM fields or present uncompiled YARA-L syntax.
   * Every query or rule presented to the user must be verified via compiler probe (`<ISO_10M_AGO>` to `<ISO_NOW>`) or `validate_rule` before being asserted as valid.

---

## 5. De-Baiting the Lexicon: Removing Homonym Traps

Prompt bloat and fall-through frequently stem from semantic homonym traps:
* **The Pillar 4 Trap**: Naming Pillar 4 *"Immediate 1-Click Investigation Queries"* baited the model into executing raw UDM searches when asked for the *"same query"*.
* **The Fix**: Renaming to *"Chronicle UI Manual Pivot (Triage Reference Only)"* and formatting filters as non-executable reference strings eliminates the bait at the lexical level without requiring defensive negative rules.

---

## 6. The Federated Handoff Protocol (`secops-threat-hunt-handoff-v1`)

### 6.1 The Consultative Demarcation Problem
When a macro-behavioral risk analysis identifies that a threat vector requires micro-mathematical proof (e.g., proving scheduled cron regularity or micro-second beaconing jitter on raw logs), an agent operating within `secops-risk-metrics-multistage` faces an architectural boundary:
1. Pre-computed 30-day UEBA metrics aggregate volumes, standard deviations, and Z-scores; they cannot calculate event-to-event inter-arrival times or micro-timing dispersion ($CV \le 0.20$).
2. The Zero-Code Handoff Invariant strictly prohibits emitting unvalidated, uncompiled raw YARA-L queries on behalf of another skill.
3. Without a machine-readable protocol, the agent degrades into **consultative paralysis**—emitting an informative lecture explaining why 30-day baselines are insufficient, but failing to advance the threat hunt.

### 6.2 The Protocol Architecture
To resolve consultative demarcation, the skills communicate via the formal `secops-threat-hunt-handoff-v1` protocol. This replaces natural language essays with a structured API payload, an ingestion endpoint, and a mutual ACK contract:

```
[ secops-risk-metrics-multistage ]
                 │
                 │ 1. Emits Handoff Payload (JSON Envelope)
                 ▼
[ Handoff Endpoint (owned by the receiving skill) ]
                 │
                 │ 2. Validates Protocol & Maps Intent
                 │ 3. Compiles Golden Pipeline Template (c2_beaconing_jitter_2stage.yl2)
                 │ 4. Generates ACK (HANDOFF_ACK_ACCEPTED)
                 ▼
[ secops-statistical-hunter ] ──► Assumes execution ownership
                 │
                 │ 5. STEP_OUT_CONFIRMED Directive
                 ▼
[ secops-risk-metrics-multistage ] ──► Immediately yields turn (0 tools called)
```

### 6.3 The Request Envelope Schema
The initiating skill (`secops-risk-metrics-multistage`) constructs the JSON payload via `scripts/federated_handoff.py`:

```json
{
  "protocol": "secops-threat-hunt-handoff-v1",
  "source_skill": "secops-risk-metrics-multistage",
  "target_skill": "secops-statistical-hunter",
  "intent": "SCHEDULED_EXFILTRATION_TIMING",
  "target_entity": {
    "type": "HOSTNAME",
    "value": "site-rev-proxy.lan"
  },
  "search_window": {
    "lookback": "24h"
  },
  "statistical_model": {
    "name": "SCHEDULED_EXFILTRATION_TIMING",
    "sensitivity": "BALANCED",
    "parameters": {
      "max_cv": 0.20,
      "min_observations": 10
    }
  },
  "status": "PENDING_DISPATCH"
}
```

### 6.4 What the Receiving Skill Does With the Payload
`secops-statistical-hunter` owns the ingestion endpoint and runs it itself. This skill never invokes it and never needs to look at it: emit the payload inside the Handoff Card and yield the turn. The steps below are background only, so that the card you render names the correct statistical model.

On receipt, the receiving skill:
1. **Schema Validation**: Verifies `protocol == "secops-threat-hunt-handoff-v1"` and ensures all mandatory envelope fields (`source_skill`, `target_skill`, `intent`, `target_entity`, `search_window`, `statistical_model`) are populated.
2. **Intent Mapping**: Maps high-level security intents to statistical query pipelines:
   * `SCHEDULED_EXFILTRATION_TIMING` ──► `C2_BEACONING_JITTER` (Inter-arrival time delta, mean, stddev, and $CV \le 0.20$).
   * `DATA_EXFILTRATION_SPIKE` ──► `EXFILTRATION_IQR_OUTLIER`.
   * `OFF_HOURS_BURST` ──► `POISSON_RARE_TIMING`.
3. **Template Compilation**: Merges entity identifiers and time parameters into the receiving skill's pre-compiled, syntax-validated multi-stage YARA-L template (e.g., `c2_beaconing_jitter_2stage.yl2`).
4. **ACK Emission**: Returns the standardized acknowledgment payload:

```json
{
  "status": "HANDOFF_ACK_ACCEPTED",
  "action": "STEP_OUT_CONFIRMED",
  "source_skill": "secops-risk-metrics-multistage",
  "target_skill": "secops-statistical-hunter",
  "model_routed": "C2_BEACONING_JITTER",
  "compiled_query": "stage host_intervals ...",
  "step_out_directive": "SOURCE_SKILL_STEP_OUT_CONFIRMED: Yield turn immediately. Hand off execution ownership to secops-statistical-hunter."
}
```

### 6.5 The Step-Out Invariant
Upon dispatching the payload or presenting the Federated Handoff Card containing `HANDOFF_ACK_ACCEPTED`:
* The source skill (`secops-risk-metrics-multistage`) **MUST NOT** attempt to execute the compiled query.
* The source skill **MUST NOT** emit speculative commentary, disclaimers, or mock calculations.
* The source skill **MUST** cleanly yield execution ownership to `secops-statistical-hunter`.

---

## 7. Dual-Plane Macro Baseline + Micro Telemetry Enrichment

### 7.1 The Threat Landscape: The "Elephant & Script" Egress Trap
A persistent gap in SOC alert triage is distinguishing routine high-volume operations (e.g. daily database backups, operating system updates) from targeted malicious data exfiltration:
1. **Volumetric Baselining Alone**: Pre-computed metrics detect that a host transferred $+3.5\sigma$ anomalous bytes, but cannot determine whether the transfer was performed by a standard browser or an automated exfiltration script (`curl`, `python-requests`).
2. **Raw Telemetry Alone**: Millions of raw HTTP events exist enterprise-wide. Searching for scripted user agents produces excessive noise without knowing which hosts breached their historical volume baseline.
3. **The Solution**: Synthesize both planes into a unified detection funnel.

### 7.2 Pattern A: Intra-Query Golden Template (`hybrid_metric_raw_enrichment_2stage.yl2`)
When the exfiltration protocol is known in advance (e.g. hunting specifically for HTTP data theft), Chronicle SIEM supports joining `metrics.*` in Stage 1 with raw `UDM_EVENTS` in Stage 2 within a single multi-stage YARA-L 2.0 query:

* **Stage 1 (Macro Sieve)**:
  <!-- yara-fragment: stage 1 of 3; root stage shown in a later block -->
  ```yara
  stage stage1_macro_baseline {
      network.sent_bytes > 0
      network.sent_bytes < 1000000000000000
      principal.asset.hostname = $entity
    match:
      $entity by 1d
    outcome:
      $observed_val = sum(network.sent_bytes)
      $hist_mean = max(metrics.network_bytes_outbound(...))
      $hist_stddev = max(metrics.network_bytes_outbound(...))
      $z_score = ($observed_val - $hist_mean) / if($hist_stddev > 0, $hist_stddev, 1.0)
  }
  ```
* **Stage 2 (Micro Signature)**:
  <!-- yara-fragment: stage 2 of 3; root stage shown in a later block -->
  ```yara
  stage stage2_raw_telemetry {
      metadata.event_type = "NETWORK_HTTP"
      principal.asset.hostname = $entity
    match:
      $entity by 1d
    outcome:
      $distinct_signatures = count_distinct(network.http.user_agent)
      $sample_signatures = array_distinct(network.http.user_agent)
  }
  ```
* **Root Stage (Fusion)**:
  ```yara
  $entity = $stage1_macro_baseline.entity
  $entity = $stage2_raw_telemetry.entity
  match:
    $entity by 1d
  condition:
    $macro_z_score >= 3.0 and $signature_diversity <= 2
  ```
* **Join Budget**: 1 metric table lookup in Stage 1 + 1 inter-stage join in Root = **2 joins total** (Chronicle limit: $\text{maxJoinCount} \le 4$).
* **The Inner-Join Drop Hazard**: If an attacker exfiltrates over raw TCP, SFTP, or DNS, Stage 2 yields 0 events. Because the Root Stage performs an inner join on `$entity by 1d`, the host is dropped from results. **When transport protocol is unverified, Pattern B must be used.**

### 7.3 Pattern B: Two-Phase Federated Funnel (`RAW_TELEMETRY_ENRICHMENT`)
For enterprise-wide sweeps where transport vector is unconstrained:
1. **Phase 1 (Macro Sieve)**: `secops-risk-metrics-multistage` evaluates 50,000 enterprise hosts against 30-day baselines in seconds and isolates the 2 hosts with $Z \ge 3.5\sigma$.
2. **The Bridge Dispatch**: The skill constructs a `secops-threat-hunt-handoff-v1` payload with `intent: "RAW_TELEMETRY_ENRICHMENT"` and `target_entities: ["host-a", "host-b"]`.
3. **Phase 2 (Targeted Forensic Probe)**: `secops-statistical-hunter` queries raw telemetry strictly for the candidate entities, evaluating User-Agent entropy, URI distribution, or unsigned process launches without whole-fleet noise.
4. **Resilience**: If HTTP yields 0 events, the finding survives: the report confirms the $+3.5\sigma$ volume anomaly and notes non-HTTP egress channels.

---

## 8. The Bilateral UEBA Harness & Telemetry Physics Guardrail (`metrics.*` + `stats-hunter` + `agentic_ueba`)

When an analyst asks for a **UEBA solution to detect an exploit, vulnerability, CTI report, or curated detection gap** (e.g., *"use UEBA to detect http2shell exploits"*, *"design UEBA coverage for this threat behavior"*), the request addresses the **Bilateral UEBA Harness** as a whole rather than a single isolated table.

### 8.1 Why Neither Hemisphere Alone Suffices for Complex Exploit Chains
* **`metrics.*` Alone (`secops-risk-metrics-multistage`)**: Pre-computed metric tables are fixed at `period: 1d, window: 30d` (`by 1d`). They excel at macro behavioral deformations (scanner volume spikes, status-code failure surges, unusual outbound egress volume, CUSUM drift, and Entity Graph prevalence `rolling_max <= 3`), but cannot correlate parent-to-child process execution within a few minutes (`by 5m`/`by 1h`) or compute inline payload/CLI Shannon entropy.
* **Raw UDM Statistical Models Alone (`secops-statistical-hunter`)**: Raw statistical pipelines (`MARKOV_2GRAM_TRANSITION_RARITY`, `SHANNON_ENTROPY_CHARACTER`, `POISSON_BURST_CLUSTERING`, `EWMA_BURST_VELOCITY`, `C2_BEACONING_JITTER`, `ZIPFIAN_PROCESS_RARITY`) capture sub-hour/intra-day structural anomalies (`by 5m`, `by 1h`, `by 2h`, `by 1d`), but running 30-day inline baseline scans over high-volume raw logs (VPC flow logs, DNS, HTTP, Auth) violates Chronicle scan limits and fails with deadline timeouts.
* **Anti-Failure Mandate**: Never tell the analyst *"UEBA is a poor fit because risk metrics cannot measure minute-level process correlation"* and never fall back to static point-in-time UDM string filters. Instead, synthesize a bilateral solution across both skills and `agentic_ueba` (`PlaybookRunner`).

### 8.2 Strict Telemetry Physics & Window Guardrail
| Analytical Need | Assigned Skill Hemisphere | Window & Bucket Constraint | Prohibited Anti-Pattern |
| :--- | :--- | :--- | :--- |
| **30-Day Volumetric / Failure / Ratio Baselines** (HTTP, DNS, VPC Bytes, Auth, Process Counts, Cloud CRUD) | `secops-risk-metrics-multistage` (`metrics.*`) | `by 1d` over 30d pre-computed window (`period: 1d, window: 30d`) | **NEVER** use `secops-statistical-hunter` for 30-day baselines over VPC flows, DNS, HTTP, Auth, or Process counts. |
| **Minute/Hour Windowed Correlations & Structural Lineage** (Web/Java daemon $\to$ shell lineage, CLI/URI entropy, sub-hour bursts, callback jitter) | `secops-statistical-hunter` (raw `UDM_EVENTS`) | `by 5m`, `by 1h`, `by 2h`, `by 1d` over bounded windows (`1h–24h` for high-volume logs; `7d–14d` for filtered/sparse process transitions) | **NEVER** force `metrics.*` to emulate sub-day correlation or discard UEBA when minute/hour correlation is required. |
| **Multi-Query Chaining & Cross-Stage Entity Fusion** | `agentic_ueba` (`PlaybookRunner`) | Option 1: In-DAG Piecewise Unification; Option 2: Upstream Candidate IP/Entity Seeding (`/* UPSTREAM_CANDIDATE_IPS */`); Option 3: Native UDM Loopback (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`, $\ge 2$ hits, $\sum Z_i^2 \ge 25.0$) | **NEVER** exceed Chronicle's 2-raw-event-stage ceiling per individual YARA-L 2.0 query. |


