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
     │ • 360° Risk Radar (6P)  │  "Roll up to 30d"   │ • Beaconing intervals   │
     └─────────────────────────┘                     └─────────────────────────┘
```

| Dimension | Macro Hemisphere (`secops-risk-metrics-multistage`) | Micro Hemisphere (`secops-statistical-hunter`) |
| :--- | :--- | :--- |
| **Telemetry Foundation** | 30-day pre-computed behavioral baselines (`metrics.*`) | Raw unaggregated UDM events (`udm.metadata`, `udm.network`) |
| **Statistical Toolkit** | Standard $Z$, Delta $Z$ ($\Delta Z$), Longitudinal CUSUM ($S_t^+$), Euclidean Distance ($D$), Calibrated Risk Index (CRI) | Median Absolute Deviation (MAD), Coefficient of Variation ($CV \le 0.20$), Poisson Rarity, Tukey Fences (IQR), Benford's Law |
| **Lookback Horizon** | 30-day sliding baseline window (1 row/entity daily rollup) | Ad-hoc search window (e.g. 1h, 4h, 24h, 7d) on raw log streams |
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
 │ • Run compiler probe  │                               │ • Render 6 Pillars    │
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
* **Identifier Qualification**: Standalone first names (`greg`, `frank`, `admin`) are probed via a 14-day UDM spot-check (`udm_search` with 5 events max). If unresolved, halt and ask for technical ID.
* **Compiler Syntax Probe**: Every candidate query must be probed via a live 10-minute compile probe (`startTime="<ISO_10M_AGO>"`, `endTime="<ISO_NOW>"`).
* **Pre-Flight Spec Card**: Present the structured specification card and probed query preview.
* **Hard Clearance Gate**: Ask the explicit clearance question and yield the turn (0 additional tools called).

### State 2: Deterministic Execution & 6-Pillar Reporting
* **Execution**: Run the validated multi-stage query or decoupled sector micro-queries via `radar_collector.py`.
* **The 6 Pillars**:
  1. *Statistical Outlier Report* (Visual surface + Unicode magnitude bars).
  2. *Executed Multi-Stage YARA-L Query* (The literal executed syntax; raw event filters strictly forbidden).
  3. *Ranked Outlier Summary & Provenance Stamp* (Observed, Mean, StdDev, Z, CRI).
  4. *Forensic Vector Breakdown* (SOC playbook & threat scenario).
  5. *Chronicle UI Manual Pivot (Triage Reference Only)* (Passive UDM filter string for manual browser copy-paste into Chronicle UI; tool execution of this string is strictly prohibited).
  6. *Statistical & Mathematical Appendix* (Formulas and baselines).

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
* **The Pillar 5 Trap**: Naming Pillar 5 *"Immediate 1-Click Investigation Queries"* baited the model into executing raw UDM searches when asked for the *"same query"*.
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
[ Endpoint: multistage_query_builder.py --ingest_handoff ]
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

### 6.4 The Ingestion Endpoint
The receiving skill (`secops-statistical-hunter`) exposes an ingestion endpoint in `scripts/multistage_query_builder.py`:

```bash
python3 scripts/multistage_query_builder.py --ingest_handoff '<JSON_PAYLOAD>'
```

The endpoint performs:
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
  ```yara
  stage stage1_macro_baseline {
      metadata.event_type = "NETWORK_CONNECTION"
      principal.asset.hostname = $entity
    match:
      $entity by 1d
    outcome:
      $observed_val = sum(network.sent_bytes)
      $hist_mean = max(metrics.network_bytes_outbound(...))
      $hist_stddev = max(metrics.network_bytes_outbound(...))
      $z_score = ($observed_val - $hist_mean) / ($hist_stddev + 1.0)
  }
  ```
* **Stage 2 (Micro Signature)**:
  ```yara
  stage stage2_raw_telemetry {
      metadata.event_type = "NETWORK_HTTP"
      principal.asset.hostname = $entity
    match:
      $entity by 1d
    outcome:
      $distinct_signatures = count_distinct(target.user_agent)
      $sample_signatures = array_distinct(target.user_agent)
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

