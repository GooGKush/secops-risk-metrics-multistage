# Google SecOps Multi-Stage Risk Metrics Threat Hunter (`secops-risk-metrics-multistage`)

[![Version](https://img.shields.io/badge/version-v1.8.1-blue.svg)](RELEASE_NOTES.md) [![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE) [![Unit Tests](https://img.shields.io/badge/unit%20tests-334%2F334%20passing%20(100%25)-brightgreen.svg)](tests/) [![Submission Tests](https://img.shields.io/badge/submission%20tests-32%2F32%20passing%20(100%25)-brightgreen.svg)](scripts/submission_tests.py)

A specialized, production-grade AI agent skill package for **Google Security Operations (SecOps / Chronicle SIEM & SOAR)** that constructs, validates, and executes **Multi-Stage YARA-L 2.0 Directed Acyclic Graph (DAG) statistical threat hunting pipelines**, **360° Entity Behavioral Risk Radars**, and **Progressively Disclosed Consultative Threat Hunting**.

The skill utilizes Google SecOps pre-computed behavioral risk analytics (`metrics.*`) as the Stage 1 baseline foundation ($O(1)$ constant-time lookup) and executes advanced mathematical outlier evaluation across subsequent stages.

---

## 🗺️ Package Structure

This repository is structured to conform strictly with the [Agent Skills Specification](https://agentskills.io):

```
secops-risk-metrics-multistage/
├── SKILL.md                              # Core orchestrator prompt, 360° radar spec, & pre-flight decision matrix
├── README.md                             # Package overview, directory map, & usage guide
├── RELEASE_NOTES.md                      # Comprehensive release notes & ready-to-run queries
├── CONTRIBUTING.md                       # Contribution guidelines & test requirements
├── LICENSE                               # Apache 2.0 License
├── llms.txt                              # AI agent summary & guardrail reference
├── data/                                 # Vendored source-of-truth data (maintainer-side; generates references)
│   ├── malachite/                        # Compiler config (textproto/proto only, no .go/.sql) + provenance README
│   └── metric_baseline_semantics.json    # What each metric's baseline counts + the matching observed event filter
├── docs/
│   └── compiler-submission-policy.md     # Maintainer/CI submission gates & test matrix (NOT runtime guidance)
├── evals/
│   └── evals.json                        # E2E evaluation benchmark prompts & assertions
├── references/                           # Deep-dive engineering guides & data contracts
│   ├── 360-behavioral-radar-guide.md     # Canonical 360° radar execution playbook & visual architecture
│   ├── calibrated-risk-index-guide.md    # CRI [0–100] sigmoid score translation guide
│   ├── chart-specifications-guide.md     # Vega-Lite & Chart.js declarative visual contracts
│   ├── clean-handoff-udm-schema.md       # 9 UDM event schemas, CRI severity ladder & ingestion vectors
│   ├── consultative-worksheet.md         # Master consultative guidance worksheet & attack vector taxonomy
│   ├── consultative/                     # Specialized domain consultative deep-dives
│   │   ├── cloud-infrastructure.md       # Cloud CRUD, service account abuse, & privilege escalation
│   │   ├── data-exfiltration.md          # Volumetric bursts, low-and-slow trickles, & staging
│   │   ├── endpoint-and-covert.md        # Rare binary execution, living-off-the-land, & beaconing
│   │   ├── identity-and-access.md        # Credential compromise, circadian shifts, & dormancy breaks
│   │   ├── insider-risk-360.md           # Holistic multi-silo insider profiling & 360° radar
│   │   └── web-and-proxy.md              # HTTP/proxy surges, error ratios, & rare user agents
│   ├── entity-context-graph-guide.md     # Chronicle Entity Context Graph (DERIVED_CONTEXT & GLOBAL_CONTEXT) guide
│   ├── malachite-function-factory-matrix.md # Chronicle Function Factory built-in functions & AST grammar contracts
│   ├── metric-sector-catalog.md          # GENERATED: per-metric observed filter, value, metric arg, entity fields, fusion rules
│   ├── metrics-catalog.md                # GENERATED: catalog of 38 pre-computed behavioral risk metrics
│   ├── model-concordance-guide.md        # AST concordance contracts, outcome variables & prohibited fallbacks across all 14 models
│   ├── multi-stage-metrics-guide.md      # Multi-stage YARA-L DAG contracts, condition gating, & Entity Graph rules
│   ├── soar-playbook-radar-integration.md# Chronicle SOAR playbook integration for 360° radar
│   ├── statistical-hunting-cooperative-framework.md # Federated bilateral handoff protocol
│   ├── statistical-models-taxonomy.md    # Mathematical taxonomy of all 14 statistical models
│   ├── turn-execution-lifecycle.md       # Codified turn lifecycle, transition invariants, & quiet baseline protocol
│   └── udm-hunting-field-dictionary.md   # Field-level dictionary mapping UDM protobuf fields to hunter dimensions
├── templates/                            # Composable YARA-L 2.0 template library
│   ├── pipelines/                        # Pre-composed multi-stage DAG pipelines (32 templates)
│   │   ├── c2_beacon_flow_frequency_2stage.yl2
│   │   ├── circadian_von_mises_2stage.yl2
│   │   ├── cloud_repository_scope_dual_branch.yl2
│   │   ├── dual_baseline_delta_z_3stage.yl2
│   │   ├── dual_sector_fusion_3stage.yl2           # Generic 2-sector fusion, sectors filled from the catalog
│   │   ├── fusion_rare_destination_3stage.yl2      # 2-sector fusion filtered to rare destinations (Entity Graph)
│   │   ├── hierarchical_empirical_bayes_3stage.yl2
│   │   ├── http_error_ratio_surge_2stage.yl2
│   │   ├── http_target_surge_2stage.yl2
│   │   ├── hybrid_metric_derived_asset_age_2stage.yl2
│   │   ├── hybrid_metric_derived_domain_prevalence_2stage.yl2
│   │   ├── hybrid_metric_derived_file_prevalence_2stage.yl2
│   │   ├── hybrid_metric_entropy_concentration_2stage.yl2
│   │   ├── hybrid_metric_fleet_prevalence_2stage.yl2
│   │   ├── hybrid_metric_http_ua_prevalence_2stage.yl2
│   │   ├── hybrid_metric_orthogonal_space_2stage.yl2
│   │   ├── hybrid_metric_raw_enrichment_2stage.yl2
│   │   ├── hybrid_metric_whois_domain_lifecycle_2stage.yl2
│   │   ├── longitudinal_cusum_2stage.yl2
│   │   ├── macd_momentum_velocity_2stage.yl2
│   │   ├── mad_modified_z_2stage.yl2
│   │   ├── multi_sector_fusion_4stage.yl2          # Generic 2-sector fusion plus each sector's deviation from the fleet
│   │   ├── part_of_the_whole_multilevel.yl2        # User vs. self, vs. peer group, vs. enterprise
│   │   ├── part_of_the_whole_triad_multilevel.yl2
│   │   ├── poisson_rarity_2stage.yl2
│   │   ├── radar_360_decoupled_sector.yl2
│   │   ├── radar_360_sector_alert.yl2
│   │   ├── radar_360_sector_web_http.yl2
│   │   ├── rare_destination_ecg_3stage.yl2         # 1 sector per host, filtered to rare destinations (Entity Graph)
│   │   ├── rollup_sector_fusion_4stage.yl2         # Composite-only metric (process, cloud CRUD, alerts) as a fusion sector
│   │   ├── rollup_sector_fusion_5stage.yl2
│   │   └── standard_z_score_2stage.yl2
│   ├── stage1_extractors/                # Complete catalog of all 38 Stage 1 baseline extractors
│   │   ├── auth_attempts_* (fail, success, total)
│   │   ├── resource_* (creation, deletion, read, written, permissions)
│   │   ├── file_executions_* (fail, success, total)
│   │   ├── network_bytes_* / network_flows_* (inbound, outbound, total)
│   │   ├── dns_queries_* / dns_bytes_* (fail, success, total)
│   │   ├── http_queries_* (fail, success, total)
│   │   └── workspace_* (auth, emails sent, network bytes, downloads, changes)
│   └── stage2_math_models/               # 16 plug-and-play mathematical model templates
│       ├── adaptive_context_threshold.yl2
│       ├── asymmetric_directional_z.yl2
│       ├── beta_binomial_bayesian.yl2
│       ├── circadian_von_mises.yl2
│       ├── coefficient_of_variation.yl2
│       ├── fleet_prevalence_shield.yl2
│       ├── hourly_temporal_zscore.yl2
│       ├── longitudinal_cusum.yl2
│       ├── macd_momentum_velocity.yl2
│       ├── mad.yl2
│       ├── piecewise_cri.yl2
│       ├── poisson_gamma_bayesian.yl2
│       ├── poisson_rarity.yl2
│       ├── standard_z_score.yl2
│       ├── two_part_hurdle.yl2
│       └── variance_fano.yl2
├── scripts/                              # Verification, execution, collector, & formatting utilities
│   ├── chart_generator.py                # Formats hunt outputs into Vega-Lite & Chart.js specs
│   ├── chronicle_ingest.py               # Direct ImportEvents REST ingestion (MCP-independent path)
│   ├── federated_handoff.py              # Cross-skill bilateral threat hunt handoff protocol
│   ├── generate_metric_sector_catalog.py # Generates references/metric-sector-catalog.md from data/ (--check for drift)
│   ├── generate_references.py            # Code-as-SSOT reference documentation generator
│   ├── malachite_catalog.py              # Parses data/malachite: valid dimension sets, entity bindings, fusion rules, filter gaps
│   ├── preflight_validator.py            # Pre-flight syntax and outcome contract validator
│   ├── radar_collector.py                # 6-Sector 360° radar SVG/HTML generator & score collector
│   ├── statistical_validator.py          # Static auditor for statistical antipatterns in candidate queries
│   ├── submission_tests.py               # Canonical 32-case compiler verification test harness
│   ├── sync_malachite_catalog.py         # Re-syncs / drift-checks data/malachite against google3
│   ├── template_router.py                # Maps natural language intent to .yl2 templates with condition filtering
│   └── triage_formatter.py               # Generates 6-section triage reports & CRI scores
└── tests/                                # Automated unit test suite (334 tests across 21 test modules)
    ├── test_chart_specifications.py
    ├── test_chronicle_ingest.py
    ├── test_complex_multistage_syntax.py
    ├── test_cri_and_math.py
    ├── test_doc_query_corpus.py
    ├── test_exhaustive_matrix_syntax.py
    ├── test_federated_handoff.py
    ├── test_global_context_syntax.py
    ├── test_guardrail_contracts.py
    ├── test_hybrid_pipelines.py
    ├── test_malachite_catalog.py
    ├── test_model_concordance.py
    ├── test_radar_collector.py
    ├── test_rare_destination_templates.py
    ├── test_skill_efficiency_and_clarity.py
    ├── test_statistical_antipattern_auditor.py
    ├── test_statistical_assumptions.py
    ├── test_submission_compiler_policy.py
    ├── test_template_router.py
    ├── test_triage_formatter.py
    └── test_yaral_templates.py
```

---

## 🌟 Core Capabilities

1. **Coupled 2-Stage Analytical DAG Architecture**:
   * Couples Stage 1 $O(1)$ constant-time lookups over pre-computed 30-day historical behavioral metrics (`metrics.*`) with Stage 2 ad-hoc observation windowing over real-time telemetry.
   * Executes in a unified YARA-L 2.0 Directed Acyclic Graph (DAG), seamlessly binding baseline means ($\mu$), standard deviations ($\sigma$), and active observation days ($N$) to incoming event streams.
2. **Progressively Disclosed Consultative Support & Turn Execution Lifecycle**:
   * Bridges data science and operational SOC workflows without requiring mathematical background or formula knowledge.
   * Progressively discloses guidance across three analytical tiers:
     * **Tier 1 (Known Knowns)**: Volumetric spikes and acute bursts (Standard $Z$, Piecewise CRI).
     * **Tier 2 (Known Unknowns / Static Rule Blind Spots)**: Low-and-slow trickles, dormancy breaks, off-hours circadian shifts, beaconing jitter, and persistent baseline drift (CUSUM, Two-Part Hurdle, Hourly $Z$, Poisson Rarity).
     * **Tier 3 (Unknown Unknowns / Cross-Silo Anomalies)**: Multi-vector orthogonal dispersion across disparate telemetry silos ($D \ge 3.5\sigma$ 360° Risk Radar).
   * Enforces the **Phase 1A-to-1B Transition Invariant**: upon analyst vector selection during consultative discovery, the agent immediately probes the candidate's event filter alone (`udm_search`, `maxEvents: 1`; never the multi-stage candidate itself), renders the structured Pre-Flight Specification Card, displays the candidate multi-stage YARA-L preview, and solicits clearance (Mode A vs Mode B) within the same turn.
   * Enforces the **Expert Bypass Fast-Track Protocol**: when an experienced practitioner specifies both scope/vector and statistical model up front, consultation is cleanly bypassed directly to Phase 1B pre-flight clearance.
3. **Turn 2 Deterministic Execution Mandate & Quiet Entity Protocol**:
   * Analyst clearance unconditionally authorizes immediate execution of the full multi-stage query via `udm_search(query=...)`, completely eliminating secondary clarification stalls.
   * Quiet entities or zero-observation sweeps evaluate natively in Chronicle SIEM and are reported affirmatively as nominal baselines ($Z = 0.00\sigma, \text{CRI} = 0$) under the **Zero-Telemetry Clean Hunt Exemption**.
4. **360° Entity Behavioral Risk Radar (All-Vectors Profiling)**:
   * Generates comprehensive behavioral fingerprints across the **6 canonical risk sectors**: Authentication & Access, Cloud Resource CRUD, Workspace & SaaS, Network Egress, DNS Resolution, and Web & Proxy Activity (`radar_360_sector_web_http.yl2`).
   * Leverages decoupled 2-stage parallel micro-queries to eliminate inner-join drops (`maxJoinCount = 4` protection), synthesizing findings into the Euclidean Threat Distance norm:
     $$D = \sqrt{\sum_{i=1}^{6} \max(0, Z_i)^2}$$
   * Integrates natively with Chronicle SOAR playbooks (`references/soar-playbook-radar-integration.md`) and generates standalone visual SVG/HTML radar artifacts via `scripts/radar_collector.py`.
5. **Chronicle Malachite Function Factory Modernization (`math.*`) & OIO Inlining**:
   * Natively leverages Chronicle SIEM's namespaced mathematical built-ins (`math.abs`, `math.sqrt`, `math.log`, `math.exp`, `math.min`, `math.max`, `math.round`, `math.pow`).
   * Employs **Outcomes-in-Outcomes (OIO)** in-stage inlining, allowing intermediate outcome variables to directly feed subsequent formulas within the same stage (e.g., `$diff = $obs - $avg`, `$z = $diff / $safe_sd`).
   * Enforces safe non-zero dispersion floor guards (`if($sigma > 0, $sigma, 1.0)`) across all models, eliminating divide-by-zero crashes on quiet baselines without artificial variance blunting.
6. **Entity Context Graph (ECG) Hybrid Correlation**:
   * Correlates 30-day behavioral metrics with Chronicle's persistent Entity Context Graph across specialized hybrid pipeline templates:
     * `DERIVED_CONTEXT` on `ASSET`: Correlates authentication surges with newly provisioned asset first-seen/last-seen age (`hybrid_metric_derived_asset_age_2stage.yl2`).
     * `DERIVED_CONTEXT` on `FILE`: Correlates endpoint execution spikes with enterprise-wide binary rarity (`hybrid_metric_derived_file_prevalence_2stage.yl2`).
     * `DERIVED_CONTEXT` on `DOMAIN_NAME`: Correlates HTTP request-count surges with enterprise domain rarity (`hybrid_metric_derived_domain_prevalence_2stage.yl2`). Bytes or DNS volume to rare domains use the rare-destination filter below.
     * `GLOBAL_CONTEXT` on WHOIS: Correlates outbound connections with newly registered domain (NRD) lifecycles (`hybrid_metric_whois_domain_lifecycle_2stage.yl2`).
     * **Rare destinations** (`DERIVED_CONTEXT` on `DOMAIN_NAME` / `IP_ADDRESS`, used as a filter): keeps a sector's anomalies only for hosts that contacted destinations seen on 3 or fewer hosts — one sector (`rare_destination_ecg_3stage.yl2`) or two fused sectors (`fusion_rare_destination_3stage.yl2`). Domains match on `target.hostname` or `network.dns.questions.name`; IPs on `target.ip`.
   * **Entity Graph freshness (Mode A)**: prevalence records are built once a day and lag about a day, so a window starting today joins nothing. Mode A queries with a graph stage start at D-2 00:00Z and pin every event stage to today with `timestamp.get_date(metadata.event_timestamp.seconds) = "<today, YYYY-MM-DD>"`; the graph stage stays time-free. Zero rows from a window starting today is a freshness gap, not a quiet baseline (`references/entity-context-graph-guide.md`, Rule 5).
7. **Bi-Directional Federated Skill Steering (`secops-threat-hunt-handoff-v1`)**:
   * Formulates a federated, cooperative threat hunting funnel between macro 30-day baselines (`secops-risk-metrics-multistage`) and micro raw UDM event telemetry (`secops-statistical-hunter`).
   * Inquiries involving sub-second C2 timing jitter, packet-level regularity, raw UDM log spikes, or non-metrics telemetry automatically emit the Markdown Skill Handoff Card and yield the turn (0 tools called).
   * Strictly enforces the **Zero-Code Handoff Invariant**: handoff cards provide conceptual architectural guidance and parameters, leaving YARA-L code generation strictly to the destination skill.
8. **Standardized 6-Section CommonMark Triage Reporting**:
   * Synthesizes hunt findings into a rigorous 6-section forensic triage report:
     1. *Executive Summary*: Primary findings, entity scope, and risk classification.
     2. *Calibrated Risk Index (CRI [0–100])*: Sigmoid-normalized score with operational severity badge.
     3. *Forensic Evidence Pillars*: Quantitative tabular breakdown with normalized Unicode ASCII visual bars (`████░░░░░░`).
     4. *Statistical Baseline Distribution Context*: Historical $\mu, \sigma, N$, and deviation ratios.
     5. *Actionable SOC Recommendations*: Concrete investigative steps and containment pivots.
     6. *1-Click Drill-Down Queries*: Ready-to-run raw UDM filter queries for instant event-level pivot.
9. **Noise Level Tuning & Root-Stage `condition:` Gating**:
   * Employs native Chronicle compiler support for root-stage `condition:` post-aggregation filtering (`HAVING` semantics) placed directly before `order:`.
   * Enables precision sensitivity steering across high-confidence alerting (`$z_score >= 3.0`), investigative drift bands (`$z_score >= 2.0 and $z_score < 3.0`), directional silencing (`$z_score <= -3.0`), and baseline maturity hurdles (`$active_days >= 7`).
10. **Cloud Infrastructure CRUD & Origin IP Monitoring**:
    * Evaluates cloud repository and data store operations (`resource_read_*`, `resource_written_*`) across Google Cloud (`GCP_CLOUDAUDIT`), AWS CloudTrail, and Azure Activity logs via dual-branch DAGs (`cloud_repository_scope_dual_branch.yl2`), preventing single-product narrowing traps and capturing origin IP pivots.
11. **Identity Governance & Zero-Guessing Technical ID Disambiguation Gate**:
    * Strictly bans heuristic username synthesis. Scopes technical ID disambiguation spot-checks strictly to ambiguous human display names (e.g. "Frank"), while hostnames, technical identifiers (`user_id`), and fleet-wide scopes proceed directly with pre-flight vector formulation.
    * Uses a 14-day UDM lookback window (`startTime: 14d ago, maxEvents: 5`) across `principal.user` and `target.user`. Halts immediately and prompts the analyst if an ambiguous human identity cannot be resolved from telemetry.
12. **Comprehensive 38-Metric Extractor Matrix & Stage 2 Math Models**:
    * 100% coverage across 38 Stage 1 extractors (Authentication, Cloud CRUD, File Execution, Network Egress/Flows, DNS Activity, HTTP, Google Workspace) and 16 Stage 2 model templates (Standard $Z$, Robust MAD, Poisson Rarity, Hourly Temporal $Z$, $CV$, Fano Factor, Asymmetric $Z$, CUSUM, Two-Part Hurdle, Piecewise CRI, Empirical Bayes Gamma, Beta-Binomial, Fleet Shield, Adaptive Thresholds, MACD Momentum Velocity, Circadian von Mises).
    * Every Stage 1 extractor's observed event filter matches what its pre-computed baseline counts, and each carries a note listing the identifier fields valid for that metric.
    * Pre-composed in 32 pipeline templates in `templates/pipelines/`.
13. **Calibrated Risk Index (CRI [0–100])**:
    * Standardizes multi-dimensional statistics onto a unified, logistic sigmoid 0–100 scale anchoring $3.0\sigma$ at CRI 50 across 4 operational severity tiers: 🟢 Nominal (0–29), 🟡 Elevated (30–49), 🟠 High (50–84), and 🔴 Critical (85–100).
14. **Adaptive Multi-Surface Single-Surface Visualizations**:
    * Renders client-optimized visual surfaces: `<agent-embed>` standalone HTML widgets for Jetski Web / Antigravity, inline `<svg>` for headless MCP webviews, and ASCII progress bars for CommonMark tables, strictly maintaining the Single-Surface Guarantee to eliminate redundant visual clutter.
15. **Lossless Clean Hand-Off Protocol & Direct API Ingestion**:
    * Ingests validated synthetic UDM security analytics events (`CUSTOM_SECURITY_DATA_ANALYTICS`) across 9 specialized `product_event_type` schemas directly into Chronicle Event Store or attaches findings to designated SOAR case walls, gated strictly behind explicit analyst request (zero unsolicited escalation).
16. **Config-Driven Cross-Vector Fusion**:
    * Any two metrics that share an identifier can be fused, not just a fixed set of combinations. The agent fills each sector from `references/metric-sector-catalog.md`, which is generated from the Chronicle compiler's own metric configuration (vendored in `data/malachite/`) and lists, per metric: the observed event filter, observed value, `metric:` argument, valid identifier fields and valid dimension sets.
    * The catalog's pairing rules let the agent judge a requested pair before building it: pairs with the same entity kind and identifier proceed (e.g. network bytes + HTTP on `principal.asset.ip`), user ↔ host pairs are refused with the reason, and a query may hold at most 2 UDM event stages.
    * Metrics that only have composite baselines (`file_executions_*`, `resource_*`, `alert_event_name_count`) join a fusion as a **roll-up sector** (`rollup_sector_fusion_4stage.yl2`), e.g. process execution + DNS by host.
    * Valid sibling triads for part-of-the-whole (auth, DNS, HTTP, network bytes, network flows) are generated into the catalog.
    * The consultative worksheet's Cross-Vector Pairing section maps a requested pair to a template, offers the rare-destination filter where it applies, and explains why an invalid pair is rejected.
17. **User → Peer Group → Enterprise Comparison**:
    * `part_of_the_whole_multilevel.yl2` and its triad variant compare a user to their own baseline and to the enterprise, and to a peer group when one is given. With a peer group they also score the group against the enterprise (`$z_team_vs_enterprise`, `$d_team_vs_fleet_sq`).
    * When the analyst mentions a team without naming members, the agent looks the team up in Active Directory via the Entity Graph (the subject's department, else their smallest AD group excluding Domain Users) and shows the roster in the Pre-Flight card. It asks for a roster only when no AD team is found.

---

## 🚀 How to Install & Use in AI Coding Assistants

### 1. Installation
Clone or copy this directory into your assistant's skills search path (e.g., `~/.gemini/skills/` or `.agents/skills/`):
```bash
git clone https://github.com/GooGKush/secops-risk-metrics-multistage.git ~/.gemini/skills/secops-risk-metrics-multistage
```

---

## 🧭 Triggering Threat Hunts & Consultative Guidance

The skill flexibly handles everything from open-ended consultative inquiries to highly specific mathematical models. Operational threat hunting is organized around four core pillars:

### 1. First Principles: The 5 Behavioral Telemetry Deformations
Every threat physically deforms telemetry in one of five distinct ways. The skill classifies analyst inquiries into these deformations to select the optimal mathematical model:

| Telemetry Deformation | Physical Telemetry Signature | Recommended Mathematical Model | Primary Metric Dimension |
| :--- | :--- | :--- | :--- |
| **1. Persistent Accumulation**<br>*(The Slow Creep)* | Low-and-slow volume creep staying below static threshold alerts | Longitudinal CUSUM Drift (`longitudinal_cusum_2stage.yl2`) or Poisson Rarity | `metrics.network_bytes_outbound`, `metrics.dns_bytes_outbound` |
| **2. State Transition**<br>*(The Dormancy Break)* | Transition from zero historical activity to positive volume | Two-Part Hurdle Model (`two_part_hurdle.yl2`) (Zero-Inflation Logistic Gate) | `metrics.resource_read_total`, `metrics.workspace_total_download_actions` |
| **3. Volumetric Shock**<br>*(The Spiky Rupture)* | Sudden explosive surge over individual or peer baseline | Piecewise CRI (Shock Absorber) or Asymmetric Directional $Z$ (ReLU) | `metrics.auth_attempts_fail`, `metrics.resource_deletion_total` |
| **4. Volatility Regularity**<br>*(The Machine Pulse)* | Unnatural clockwork intervals or collapsed timing entropy | Hourly Temporal $Z$-Score (`hourly_temporal_zscore.yl2`) or Fano Factor | `metrics.dns_queries_total`, `metrics.http_queries_total` |
| **5. Orthogonal Dispersion**<br>*(The Multi-Vector Fog)* | Mild elevations across 3–6 unrelated telemetry sectors | 360° Decoupled Behavioral Radar (`radar_360_decoupled_sector.yl2`, $D \ge 3.5\sigma$) | All 6 Canonical Risk Sectors Coupled |

### 2. Common-Sense Analytical Rigor: The 4 Investigative Inquiries
To ensure actionable findings and eliminate false alarms, the consultative workflow grounds every hunt in four practical SOC questions:
1. **The "What Proves It Innocent?" Check** *(Hypothesis & Falsifiability)*: Agree on innocent explanations (scheduled backups, system maintenance, bulk transfers) and disproof criteria before hunting.
2. **The "Quiet Entity Trap" Check** *(Zero-Inflation & Dormancy)*: Check whether the entity is normally silent. For dormant accounts, apply a tripwire hurdle rather than an arithmetic volume curve.
3. **The "Past Noise Camouflage" Check** *(Skew & Baseline Distortion)*: Ensure historical one-off spikes do not inflate averages. Apply median absolute deviation (MAD) to protect baseline integrity.
4. **The "Crowd / Patch Tuesday" Check** *(Confounder Elimination)*: Check whether peers are experiencing the same surge concurrently. Apply fleet prevalence shielding to discount shared enterprise-wide activities.

### 3. Specialized Domain Consultative Deep-Dives
For deep domain investigations, the skill references specialized consultative worksheets in `references/consultative/`:
* **Cloud Infrastructure & Service Account Abuse** (`cloud-infrastructure.md`): Cloud CRUD spikes, cross-project data store enumeration, and service account privilege escalation.
* **Data Exfiltration** (`data-exfiltration.md`): Large volumetric bursts vs. low-and-slow trickles, DNS tunneling, and staging across Cloud/SaaS storage.
* **Endpoint & Covert Execution** (`endpoint-and-covert.md`): Rare binary execution, living-off-the-land binaries (LOLBins), and enterprise prevalence shielding.
* **Identity & Credential Compromise** (`identity-and-access.md`): Credential sprays, circadian schedule shifts, dormant account awakening, and MFA fatigue.
* **Insider Risk 360°** (`insider-risk-360.md`): Holistic cross-silo employee risk profiling combining HR timelines with multi-sector telemetry.
* **Web, Proxy & Covert HTTP Channels** (`web-and-proxy.md`): User-agent fleet prevalence, proxy error-ratio surges, target-centric API hammering, and the HTTP part-of-the-whole triad.

### 4. Evaluation Modes: Mode A vs. Mode B
During the Pre-Flight Clearance gate, analysts choose between two temporal evaluation horizons:
* **Mode A (Current-Day Snapshot)**: Evaluates today so far (00:00Z to now) against the 30-day historical baseline. Designed for rapid triage, immediate threshold breach identification, and daily operational sweeps. Queries that join the Entity Graph widen the search window to D-2 00:00Z but still score only today's events (see capability 6).
* **Mode B (14-Day Longitudinal Trend)**: Evaluates day-by-day daily buckets (`by 1d`) across a 14-day observation window against the 30-day baseline. Designed for CUSUM drift detection, cumulative exfiltration tracking, and subtle trend slope analysis.

### 5. Natural Language Prompt Examples

#### 🧭 Consultative & Open-Ended Inquiries
* *"I suspect an employee might be preparing to leave with sensitive data, but I don't know which telemetry source to check. Can you help me investigate?"*
* *"Help me find abnormal behavior for user frank.kolzig that static detection rules usually miss."*
* *"What kind of behavioral anomaly hunts can we run against our Google Cloud and AWS infrastructure to catch insider privilege abuse?"*

#### 🕸️ 360° Behavioral Risk Radar & Peer Comparisons
* *"Show me a 360-degree risk metrics view of user Frank Kolzig across all 6 behavioral sectors."*
* *"Is Frank doing things his teammates don't do? Check his authentication activity against his IT Department peer group roster."*
* *"Perform a 360 health check on our top executive service accounts to spot cross-silo behavioral dispersion."*
* *"Compare Frank's logins to his team, and his team to the rest of the company."*

#### 🔗 Cross-Vector Fusion & Rare Destinations
* *"Which hosts are unusual on both outbound network traffic and HTTP activity today?"*
* *"Find hosts running an unusual number of processes that are also making unusual DNS queries."*
* *"Show me hosts with an outbound bytes spike that talked to low-prevalence domains."*
* *"Can we compare process activity and failed logins on the same machines?"* (the agent checks the pair against the catalog first, picks the template, or explains why the pair can't be joined)

#### 📉 Low-and-Slow Trickle Exfiltration & Drift (CUSUM & Hourly Z)
* *"Check for low and slow data exfiltration over the last 14 days using longitudinal CUSUM drift."*
* *"Check for subtle, cumulative baseline drift in DNS query volumes over the past 30 days that might indicate covert tunneling."*
* *"Find users authenticating or touching cloud repositories at abnormal hours relative to their typical 30-day circadian schedule."*

#### ⚡ Dormancy Awakening & Sudden Spikes (Hurdle & Asymmetric Z)
* *"Look for dormant service accounts or identities that suddenly woke up and began downloading large files today (Two-Part Hurdle model)."*
* *"Hunt for workstations uploading an abnormal volume of outbound bytes using an asymmetric directional z-score."*
* *"Hunt for accounts with an authentication spike between 2 and 3 standard deviations to uncover emerging low-and-slow drift."*

#### 🛡️ Fleet Prevalence & Noise Shielding
* *"Hunt across the fleet for workstations with abnormal file execution spikes compared to their historical baseline that are launching rare binaries."*
* *"Find hosts with anomalous outbound network connections, but apply a fleet prevalence shield to dampen false positives from enterprise-wide software updates."*
* *"Hunt across the enterprise for hosts with coordinated anomalies across authentication failures and outbound network bytes."*

#### 🔀 Bilateral Handoff Triggers (Routing to `secops-statistical-hunter`)
Inquiries requiring sub-second packet timing, raw log volume parsing, or non-metrics telemetry automatically yield the turn and emit the Markdown Skill Handoff Card:
* *"Hunt for C2 beaconing with random timing jitter in outbound proxy traffic."*
* *"Calculate Median Absolute Deviation (MAD) directly on raw DNS request logs."*
* *"Find impossible travel velocity anomalies across raw cloud login events."*

---

## 🧪 Testing & Verification

The skill package ships with two test tiers that anyone can run from a clone:

### 1. Automated Unit Test Suite (`pytest` / `unittest`)
```bash
pytest tests/
# or: python3 -m unittest discover tests
```
* **Status**: **334 / 334 passing unit tests** across 21 test modules (100% pass rate).
* **Scope**: Enforces Chronicle AST grammar rules, KaTeX formatting compliance, prompt guardrail contracts, 20,480-byte budget ceilings, template router permutations across all 38 metrics and the Stage 2 models, metric-sector catalog drift against `data/`, and Entity Graph freshness filters in every graph template.

### 2. Google SecOps Malachite Compiler Submission Harness
```bash
# Offline static AST & compiler invariant verification (32 canonical test cases)
python3 scripts/submission_tests.py

# Export the 32 rendered queries, e.g. to run each one through the SecOps MCP udm_search tool
python3 scripts/submission_tests.py --dump-dir <OUTPUT_DIR>
```
* **Status**: **32 / 32 passing submission test cases** offline.
* **Live compilation**: not part of this harness; it sends nothing to Chronicle. To check against a live tenant, export with `--dump-dir` and run each file through `udm_search`.
* **Scope**: Verifies Malachite AST compliance, continuous outcome arithmetic, Function Factory built-ins, and compiler invariants across all composite pipelines, decoupled radar spokes, and router configurations.

---

## 📦 Recent Releases

### v1.8.1 (October 2026) — Date-Based Entity Graph Freshness Filter & Derived Prevalence Scope
* **Entity Graph Freshness**: In Mode A, every event stage of a graph-joined query filters on today's date (`timestamp.get_date(metadata.event_timestamp.seconds) = "<today UTC>"`) instead of a hand-computed epoch, across the 7 graph templates, SKILL.md and the guides' inline examples.
* **Derived Prevalence Scope**: The derived domain template counts HTTP requests only; DNS volume, outbound bytes and other measures against rare domains use `rare_destination_ecg_3stage.yl2`.
* **Skill Handoff**: The scheduled-exfiltration offer for high-prevalence cloud destinations names `secops-statistical-hunter`.
* **Submission Harness**: `--live` no longer reports live results it never ran.

### v1.8.0 (October 2026) — Config-Driven Metric Sectors, Cross-Vector Fusion, Rare-Destination Filtering & Peer Group Path
* **Config-Driven Metric Sectors**: Every `metrics.*` stage now takes its observed filter, observed value, `metric:` argument and identifier field from the generated `references/metric-sector-catalog.md`, built from the Chronicle compiler's metric configuration (vendored in `data/malachite/`). Observed filters in all 38 Stage 1 extractors were aligned to what each baseline counts.
* **Generic Cross-Vector Fusion**: `dual_sector_fusion_3stage.yl2` and `multi_sector_fusion_4stage.yl2` accept any two same-identifier sectors instead of a fixed auth + network pairing. New `rollup_sector_fusion_4stage.yl2` / `_5stage.yl2` let composite-only metrics (process, cloud CRUD, alerts) act as a fusion sector. Catalog pairing rules and a template-choice table let the agent accept or refuse a requested pair.
* **Rare-Destination Filtering**: New `rare_destination_ecg_3stage.yl2` and `fusion_rare_destination_3stage.yl2` keep only hosts that contacted domains or IPs seen on 3 or fewer hosts (Entity Graph `DERIVED_CONTEXT`).
* **Entity Graph Freshness**: Mode A queries that join the graph search from D-2 00:00Z and score only today's events, in all graph templates.
* **Peer Group Path**: User → peer group → enterprise, including group-vs-enterprise scores; unnamed teams are resolved from Active Directory via the Entity Graph.
* **Test Suite**: 334/334 unit tests (new `test_malachite_catalog.py` and `test_rare_destination_templates.py`); 32/32 submission tests.

### v1.7.9 (September 2026) — Security & EDR Alert Decoupled Sector Pipeline
* **Alert Sector**: New `radar_360_sector_alert.yl2` rolls `metrics.alert_event_name_count` up from rule level to host level; wired into the router, preflight validator and radar collector.

### v1.7.8 (September 2026) — Byte-Volume Metric Invariant Alignment
* **`metric: value_sum` on byte metrics**: All 6 byte-volume extractors and the generic 2-stage pipelines bind the correct metric argument (`value_sum` for bytes, `event_count_sum` for counts).
* **Validator**: Regex anchors inside `/.../` literals are no longer flagged as exponent operators; `MalachiteASTValidator` runs inside the submission harness.

### v1.7.7 (September 2026) — DNS Metrics Companion Dimension Normalization & Domain Precomputation Alignment
* **DNS Metric Companion Dimension Normalization**: Resolved compile-time failure (`unsupported filters for metric DNS_QUERIES_TOTAL`) by aligning `metrics.dns_queries_*` to strictly require normalized apex/domain companion dimension `network.dns_domain: $domain` (and `network.dns_domain = $domain` in Stage 1) instead of packet-level `network.dns.questions.name`.
* **Dynamic Pipeline Routing**: Updated `scripts/template_router.py` and hybrid pipelines to dynamically bind `network.dns_domain` for DNS query baselines and `target.hostname` for HTTP query baselines.
* **AST Preflight Validation**: Added validator warnings in `scripts/preflight_validator.py` blocking unsupported companion filters on DNS metrics.
* **Test Suite & Verification**: 272/272 unit tests passing (100%); 31/31 submission tests passing.

### v1.7.6 (September 2026) — MACD Dual-Spine Momentum Velocity & Circadian von Mises Temporal Distance Models
* **MACD Dual-Spine Momentum Velocity**: Fast vs. slow velocity divergence ($Z_{\text{fast}} - Z_{\text{slow}}$) detecting runaway volumetric acceleration over historical 30-day peak ceilings.
* **Circadian von Mises Temporal Distance**: 24-hour circular geometry on hourly telemetry ($\min(\text{raw\_diff}, 24 - \text{raw\_diff})$) penalizing off-hours activity via quadratic arc distance.
* **Chronicle SIEM Compiler Alignment**: Extracts native event timestamp hour in Stage 1 (`max(timestamp.get_hour(...))`) conforming to malachite compiler constraints.
* **Test Suite & Verification**: 270/270 unit tests passing.

### v1.7.5 (September 2026) — Affirmative Tool Guidance Architecture, Turn Execution Invariants & Quiet Entity Baselining
* **Affirmative Tool Guidance**: Refactored directives in `SKILL.md` from repetitive negative prohibitions into lean affirmative recipes. Explicitly codified the hands-off `run_command` restriction (*"There is no blanket approval for `run_command`, only explicit exemptions"*).
* **Turn Execution Lifecycle**: Codified [`references/turn-execution-lifecycle.md`](references/turn-execution-lifecycle.md) establishing clear turn contracts and the Phase 1A-to-1B transition invariant.
* **Quiet Entity Protocol**: Mandated unconditional Turn 2 execution upon clearance; quiet entities or zero-observation sweeps are reported affirmatively as nominal baselines ($Z=0.00\sigma, \text{CRI}=0$) under the Zero-Telemetry Clean Hunt Exemption.
* **Test Suite Expansion**: Expanded automated unit test suite to **270 / 270 passing tests** across 19 test modules.

### v1.7.4 (September 2026) — Malachite Function Factory Modernization, Affirmative Guidance & Data-Anchored Time Spines
* **Chronicle Function Factory Built-Ins**: Adopted namespaced mathematical functions (`math.abs`, `math.sqrt`, `math.log`, `math.exp`, `math.min`, `math.max`, `math.round`) and Outcomes-in-Outcomes (OIO) inlining.
* **Safe Non-Zero Dispersion Floors**: Standardized safe dispersion floor guards (`if($sigma > 0, $sigma, 1.0)`) across all pipeline templates.
* **Data-Anchored Time Spines**: Standardized time spine contracts across hybrid Entity Context Graph pipelines.

### v1.7.3 (September 2026) — Web/HTTP Risk Sector Expansion, Decoupled 360° Radar & SOAR Playbook Integration
* **Web & HTTP Proxy Sector**: Expanded 360° Risk Radar to 6 canonical sectors with dedicated HTTP metrics (`radar_360_sector_web_http.yl2`, `http_target_surge_2stage.yl2`, `http_error_ratio_surge_2stage.yl2`).
* **SOAR Playbook Integration**: Published [`references/soar-playbook-radar-integration.md`](references/soar-playbook-radar-integration.md) for automated alert enrichment.

### v1.7.2 (September 2026) — Dynamic Multi-Surface Visual Architecture & Single-Surface Guarantee
* **Single-Surface Visual Guarantee**: Standardized `<agent-embed>` standalone HTML widgets in Jetski Web, inline `<svg>` in headless MCP webviews, and ASCII progress bars in CommonMark tables.

### v1.7.1 (September 2026) — Bilateral Threat Hunt Handoff Protocol & Federated Cross-Skill Collaboration
* **Federated Protocol Engine**: Codified [`references/statistical-hunting-cooperative-framework.md`](references/statistical-hunting-cooperative-framework.md) and `scripts/federated_handoff.py` for bilateral delegation between macro 30d baselines and micro raw UDM event telemetry.
* **Zero-Code Handoff Invariant**: Standardized conceptual handoff cards without premature YARA-L leakage.

*For full release history and ready-to-run queries, see [RELEASE_NOTES.md](RELEASE_NOTES.md).*

---

## 🤝 Contributions
Contributions to this skill package are highly welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📜 License
This project is licensed under the [Apache License 2.0](LICENSE).
```
Copyright 2026 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

---
*Created and maintained by Greg Kushmerek for Google Security Operations (Chronicle SIEM & SOAR).*
