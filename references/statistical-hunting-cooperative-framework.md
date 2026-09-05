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
