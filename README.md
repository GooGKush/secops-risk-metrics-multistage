# Google SecOps Multi-Stage Risk Metrics Threat Hunter (`secops-risk-metrics-multistage`)

[![Version](https://img.shields.io/badge/version-v2.1.4-blue.svg)](RELEASE_NOTES.md) [![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE) [![Unit Tests](https://img.shields.io/badge/unit%20tests-433%2F433%20passing%20(100%25)-brightgreen.svg)](tests/) [![Submission Tests](https://img.shields.io/badge/submission%20tests-32%2F32%20passing%20(100%25)-brightgreen.svg)](scripts/submission_tests.py) [![Live Regression](https://img.shields.io/badge/dual--engine%20regression-60%2F60%20live%20passing%20(100%25)-brightgreen.svg)](tests/)

A specialized, production-grade AI agent skill package for **Google Security Operations (SecOps / Chronicle SIEM & SOAR)** that constructs, validates, and executes **Multi-Stage YARA-L 2.0 Directed Acyclic Graph (DAG) statistical threat hunting pipelines**, **360° Entity Behavioral Risk Radars**, and **Progressively Disclosed Consultative Threat Hunting**.

The skill utilizes Google SecOps pre-computed behavioral risk analytics (`metrics.*`) as the Stage 1 baseline foundation ($O(1)$ constant-time lookup) and executes advanced mathematical outlier evaluation across subsequent stages.

---

## 🗺️ Package Structure

This repository is structured to conform strictly with the [Agent Skills Specification](https://agentskills.io):

```
secops-risk-metrics-multistage/
├── SKILL.md                              # Core orchestrator prompt, 360° radar spec, & pre-flight decision matrix
├── GEMINI.md                             # Workspace operational rules for AI coding assistants
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
│   ├── clean-handoff-udm-schema.md       # 10 UDM event schemas, CRI severity ladder & ingestion vectors
│   ├── consultative-worksheet.md         # Master consultative guidance worksheet & attack vector taxonomy
│   ├── consultative/                     # Specialized domain consultative deep-dives (8 guides)
│   │   ├── cloud-infrastructure.md       # Cloud CRUD, service account abuse, & privilege escalation
│   │   ├── data-exfiltration.md          # Volumetric bursts, low-and-slow trickles, & staging
│   │   ├── endpoint-and-covert.md        # Rare binary execution, living-off-the-land, & beaconing
│   │   ├── identity-and-access.md        # Credential compromise, circadian shifts, & dormancy breaks
│   │   ├── insider-risk-360.md           # Holistic multi-silo insider profiling & 360° radar
│   │   ├── mitre-attack-killchain.md     # MITRE ATT&CK kill-chain mapping & multi-stage attack paths
│   │   ├── security-edr-alerts.md        # Security & EDR alert frequency baselining (alert_event_name_count)
│   │   └── web-and-proxy.md              # HTTP/proxy surges, error ratios, & rare user agents
│   ├── entity-context-graph-guide.md     # Chronicle Entity Context Graph (DERIVED_CONTEXT & GLOBAL_CONTEXT) guide
│   ├── malachite-function-factory-matrix.md # Chronicle Function Factory built-in functions & AST grammar contracts
│   ├── metric-sector-catalog.md          # GENERATED: per-metric observed filter, value, metric arg, entity fields, fusion rules
│   ├── metrics-catalog.md                # GENERATED: catalog of 38 pre-computed behavioral risk metrics
│   ├── model-concordance-guide.md        # AST concordance contracts, outcome variables & prohibited fallbacks across all 17 models
│   ├── multi-stage-metrics-guide.md      # Multi-stage YARA-L DAG contracts, condition gating, & Entity Graph rules
│   ├── soar-playbook-radar-integration.md# Chronicle SOAR playbook integration for 360° radar
│   ├── statistical-hunting-cooperative-framework.md # Federated bilateral handoff protocol
│   ├── statistical-models-taxonomy.md    # Mathematical taxonomy of all 17 statistical models
│   ├── timeline-modes-guide.md           # Per-request 30d baseline anchoring, Mode B fixed-baseline bias, Mode C per-day shards
│   ├── turn-execution-lifecycle.md       # Codified turn lifecycle, transition invariants, & quiet baseline protocol
│   └── udm-hunting-field-dictionary.md   # Field-level dictionary mapping UDM protobuf fields to hunter dimensions
├── templates/                            # Composable YARA-L 2.0 template library
│   ├── pipelines/                        # Pre-composed multi-stage DAG pipelines (33 templates)
│   │   ├── c2_beacon_flow_frequency_2stage.yl2
│   │   ├── circadian_von_mises_2stage.yl2
│   │   ├── cloud_repository_scope_dual_branch.yl2
│   │   ├── dual_baseline_delta_z_3stage.yl2
│   │   ├── dual_sector_fusion_3stage.yl2           # Generic 2-sector fusion, sectors filled from the catalog
│   │   ├── fusion_rare_destination_3stage.yl2      # 2-sector fusion filtered to rare destinations (Entity Graph)
│   │   ├── hierarchical_empirical_bayes_3stage.yl2
│   │   ├── http_error_ratio_surge_2stage.yl2
│   │   ├── http_target_surge_2stage.yl2
│   │   ├── hybrid_data_table_bridge_2stage.yl2     # Two-Phase Cross-Entity cohort join via %ueba_hunt_bridge Data Table
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
│   │   ├── mad_robust_z_4stage.yl2               # True median/MAD over the raw window + 30d metrics Z cross-check
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
│   ├── stage1_extractors/                # 37 Stage 1 extractor templates covering all 38 pre-computed behavioral risk metrics
│   │   ├── alert_event_name_count.yl2
│   │   ├── auth_attempts_* (fail, success, total)
│   │   ├── resource_* (creation, deletion, read, written)
│   │   ├── file_executions_* (fail, success, total)
│   │   ├── network_bytes_* / network_flows_* (inbound, outbound, total)
│   │   ├── dns_queries_* / dns_bytes_* (fail, success, total)
│   │   ├── http_queries_* (fail, success, total)
│   │   └── workspace_* (auth, emails sent, network bytes, downloads, changes)
│   └── stage2_math_models/               # 17 plug-and-play mathematical model templates
│       ├── adaptive_context_threshold.yl2
│       ├── asymmetric_directional_z.yl2
│       ├── beta_binomial_bayesian.yl2
│       ├── circadian_von_mises.yl2
│       ├── coefficient_of_variation.yl2
│       ├── fleet_prevalence_shield.yl2
│       ├── hourly_temporal_zscore.yl2
│       ├── longitudinal_cusum.yl2
│       ├── macd_momentum_velocity.yl2
│       ├── mad.yl2                               # True MAD module (mad_center -> mad_spread -> root)
│       ├── piecewise_cri.yl2
│       ├── poisson_gamma_bayesian.yl2
│       ├── poisson_rarity.yl2
│       ├── relative_deviation.yl2                # Fold change vs 30d mean (formerly mislabelled MAD)
│       ├── standard_z_score.yl2
│       ├── two_part_hurdle.yl2
│       └── variance_fano.yl2
├── scripts/                              # Verification, execution, collector, & formatting utilities
│   ├── __init__.py
│   ├── chart_generator.py                # Formats hunt outputs into Vega-Lite & Chart.js specs
│   ├── chronicle_ingest.py               # Direct ImportEvents REST ingestion (MCP-independent path)
│   ├── federated_handoff.py              # Cross-skill bilateral threat hunt handoff protocol
│   ├── generate_metric_sector_catalog.py # Generates references/metric-sector-catalog.md from data/ (--check for drift)
│   ├── generate_references.py            # Code-as-SSOT reference documentation generator
│   ├── malachite_catalog.py              # Parses data/malachite: valid dimension sets, entity bindings, fusion rules, filter gaps
│   ├── preflight_validator.py            # Pre-flight AST validator + QueryIntegrityGate (pre-dispatch & post-execution verification)
│   ├── radar_collector.py                # 6-Sector 360° radar SVG/HTML generator & score collector
│   ├── statistical_validator.py          # Static auditor for statistical antipatterns in candidate queries
│   ├── submission_tests.py               # Canonical 32-case compiler verification test harness
│   ├── sync_malachite_catalog.py         # Re-syncs / drift-checks data/malachite against google3
│   ├── template_router.py                # Maps natural language intent to .yl2 templates with condition filtering & 11 MITRE kill-chains
│   ├── timeline_assembler.py             # Mode C collator: merges per-day single-query or 6-sector 360° radar shards into one timeline report
│   ├── triage_formatter.py               # Generates 5-section triage reports, CRI scores & Post-Data Agentic Next Steps
│   └── ueba_hybrid_engine.py             # Unified Python Hybrid Engine (compile_hunt_pipeline, dispatch_hybrid_handoff, render_forensic_dossier)
└── tests/                                # Automated unit test suite (433 tests across 25 test modules, 100% pass rate)
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
    ├── test_mad_cross_skill_sync.py
    ├── test_malachite_catalog.py
    ├── test_model_concordance.py
    ├── test_radar_collector.py
    ├── test_rare_destination_templates.py
    ├── test_skill_efficiency_and_clarity.py
    ├── test_statistical_antipattern_auditor.py
    ├── test_statistical_assumptions.py
    ├── test_submission_compiler_policy.py
    ├── test_template_router.py
    ├── test_threshold_gate_contract.py
    ├── test_timeline_assembler.py
    ├── test_triage_formatter.py
    ├── test_ueba_hybrid_engine.py
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
   * Generates comprehensive behavioral fingerprints across the **6 canonical risk sectors**: Authentication & Access, Cloud Resource CRUD (all 4 families: `resource_read_total`, `resource_written_total`, `resource_creation_total`, `resource_deletion_total`), Workspace & SaaS, Network Egress, DNS Resolution, and Web & Proxy Activity (`radar_360_sector_web_http.yl2`).
   * Leverages decoupled 2-stage parallel micro-queries with `<field>: <field>` self-binding inside `metrics.*()` to eliminate inner-join drops (`maxJoinCount = 4` protection) and case-sensitivity baseline zeroing, synthesizing findings into the Euclidean Threat Distance norm:
     $$D = \sqrt{\sum_{i=1}^{6} \max(0, Z_i)^2}$$
   * Supports **Mode C per-day 6-sector timeline sharding** (`--shard YYYY-MM-DD:<sector>=<path>` in `scripts/timeline_assembler.py`), pre-screening active sectors across the window first and fusing daily sector Z-scores into per-day $D_t$ and $\text{CRI}_t$. Integrates natively with Chronicle SOAR playbooks (`references/soar-playbook-radar-integration.md`) and generates standalone visual SVG/HTML radar artifacts via `scripts/radar_collector.py`.
5. **Chronicle Malachite Function Factory Modernization (`math.*`) & OIO Inlining**:
   * Natively leverages Chronicle SIEM's namespaced mathematical built-ins (`math.abs`, `math.sqrt`, `math.log`, `math.pow`, `math.floor`, `math.ceil`, `math.round`), expressing general and base-$e$ exponentiation via `math.pow($base, $exp)` / `math.pow(2.718281828, $x)` rather than the unsupported `math.exp()` function identifier.
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
7. **Bi-Directional Federated Skill Steering (`secops-threat-hunt-handoff-v1`) & The Bilateral UEBA Harness**:
   * Formulates a federated, cooperative threat hunting funnel between macro 30-day baselines (`secops-risk-metrics-multistage`), micro raw UDM event telemetry (`secops-statistical-hunter`), and `agentic_ueba` (`PlaybookRunner`) connective tissue.
   * For open-ended threat, exploit, CTI, or detection-gap UEBA inquiries (when `Active Skill:` is not restricted to a single skill), synthesizes a multi-horizon **Bilateral UEBA Harness** combining Plane 1 (30d `by 1d` `metrics.*` baselines & multi-sector fusion), Plane 2 (bounded-window raw `UDM_EVENTS` Markov process transitions, Shannon entropy, and Poisson burst dispersion via `secops-statistical-hunter`), and Plane 3 (`PlaybookRunner` Options 1–3 chaining) while enforcing the **Telemetry Physics & Window Guardrail**.
   * Single-skill inquiries involving sub-second C2 timing jitter, packet-level regularity, raw UDM log spikes, or non-metrics telemetry automatically emit the Markdown Skill Handoff Card and yield the turn (0 tools called), adhering strictly to the **Zero-Code Handoff Invariant**.
8. **Standardized 5-Section CommonMark Triage Reporting, `QueryIntegrityGate` & Post-Data Agentic Loop**:
   * When invoked via the Python hybrid engine (`scripts/ueba_hybrid_engine.py`) or validator CLI (`scripts/preflight_validator.py`), `QueryIntegrityGate.verify_pre_dispatch()` and `QueryIntegrityGate.verify_backend_response()` block unresolved `{{slot}}` placeholders, unscoped entity queries, malformed `%<table_name>.<column>` Data Table joins, or backend query rejections before synthesizing a report.
   * Synthesizes hunt findings into a standardized 5-section forensic triage report:
     1. *Statistical Outlier Report: `[Target Metric] ([Statistical Model]) — Executive Summary & Calibrated Risk Index (CRI)`*: Executive headline, active/baseline window summary, and single-surface visual chart (`<agent-embed>` in Jetski, inline `<svg>` in generic MCP, or Unicode `▰▰▰▰▱▱▱▱` bars in CLI).
     2. *Ranked Outlier Summary & Provenance Stamp*: Quantitative tabular breakdown (`Entity`, `Observed`, `30d Mean (μ)`, `30d StdDev (σ)`, `Z-Score / Metric`, `CRI [0-100]`) with provenance stamp (executed window, baseline window, rows returned, entity filter, data-source status) and Unicode magnitude bars (`▰▰▰▰▱▱▱▱`).
     3. *Forensic Vector Breakdown*: Threat translation, MITRE ATT&CK kill-chain progression, attack scenarios, legitimate confounders, actionable SOC playbook steps, and outcome-driven **Agentic Next Steps (`[1]` / `[2]` / `[3]`)**.
     4. *Chronicle UI Manual Pivot (Triage Reference Only)*: Copy-and-paste raw UDM filter expression in a ```` ```text ```` code block for manual Chronicle UI timeline inspection.
     5. *Collapsible Technical Appendix (Statistical & Mathematical Appendix)*: Collapsible `<details>` containing the verbatim executed multi-stage query (` ```yara `), model parameter derivation, degrees of freedom ($N$), and CRI normalization.
   * **State 3 → Phase 1B Pivot Loop**: Selecting a `[1]` / `[2]` / `[3]` follow-up pivot transitions directly into Phase 1B pre-flight clearance carrying forward the target entity, cohort scope, and evaluation window.
9. **Noise Level Tuning & Root-Stage `condition:` Gating**:
   * Employs native Chronicle compiler support for root-stage `condition:` post-aggregation filtering (`HAVING` semantics) placed directly before `order:`.
   * Enables precision sensitivity steering across high-confidence alerting (`$z_score >= 3.0`), investigative drift bands (`$z_score >= 2.0 and $z_score < 3.0`), directional silencing (`$z_score <= -3.0`), and baseline maturity hurdles (`$active_days >= 7`).
10. **Cloud Infrastructure CRUD & Origin IP Monitoring**:
    * Evaluates cloud repository and data store operations (`resource_read_*`, `resource_written_*`, `resource_deletion_*`, `resource_creation_*` across `total`, `fail`, and `success` modes) across Google Cloud (`GCP_CLOUDAUDIT`), AWS CloudTrail, and Azure Activity logs via dual-branch DAGs (`cloud_repository_scope_dual_branch.yl2`), preventing single-product narrowing traps and capturing origin IP pivots.
11. **Identity Governance & Zero-Guessing Technical ID Disambiguation Gate**:
    * Strictly bans heuristic username synthesis. Resolves human display names (e.g. `"Frank"`, `"Frank Kolzig"`) and corporate user email addresses (`"admin@demo.wsexample.org"`, whose UDM `user.userid` may be indexed as the local username `"admin"`) against UDM telemetry before binding `user.userid`, while standard machine/service accounts (`@*.iam.gserviceaccount.com`, `arn:aws:...`, `sa-*`), hostnames, and fleet-wide scopes proceed directly to the 1-shot event-filter probe.
    * Anchors the UDM identity spot-check to the requested target historical window (when a target date/range is specified) or the last 14 days (`maxEvents: 5`) across `userid`, `email_addresses`, and `user_display_name` on both `principal.user` and `target.user`. Halts immediately and prompts the analyst if an unqualified human name cannot be resolved from telemetry.
12. **Comprehensive 38-Metric Extractor Matrix & Stage 2 Math Models**:
    * 100% coverage across 38 Stage 1 extractors (Authentication, Cloud CRUD, File Execution, Network Egress/Flows, DNS Activity, HTTP, Google Workspace, Security/EDR Alerts) and 17 Stage 2 model templates (Standard $Z$, True MAD / Modified $Z$, Relative Deviation, Poisson Rarity, Hourly Temporal $Z$, $CV$, Fano Factor, Asymmetric $Z$, CUSUM, Two-Part Hurdle, Piecewise CRI, Empirical Bayes Gamma, Beta-Binomial, Fleet Shield, Adaptive Thresholds, MACD Momentum Velocity, Circadian von Mises).
    * Every Stage 1 extractor's observed event filter matches what its pre-computed baseline counts, and each carries a note listing the identifier fields valid for that metric.
    * Pre-composed in 33 pipeline templates in `templates/pipelines/` (including `hybrid_data_table_bridge_2stage.yl2`).
13. **Calibrated Risk Index (CRI [0–100])**:
    * Standardizes multi-dimensional statistics onto a unified piecewise logistic sigmoid 0–100 scale ($\text{CRI}(Z) = 0$ for $Z \le 0$; $\text{CRI}(Z) = \text{round}(100 / (1 + e^{-0.6(Z - 3.0)}))$ for $Z > 0$), anchoring $3.0\sigma$ at CRI 50 across 5 operational triage bands: 🟢 Nominal (0–25), 🟡 Low Drift (26–45), 🟠 Medium Outlier (46–69), 🔴 High Threat (70–89), and 🚨 Critical Outlier (90–100).
14. **Adaptive Multi-Surface Single-Surface Visualizations**:
    * Renders client-optimized visual surfaces: `<agent-embed>` standalone HTML widgets for Jetski Web / Antigravity, inline `<svg>` for headless MCP webviews, and ASCII progress bars for CommonMark tables, strictly maintaining the Single-Surface Guarantee to eliminate redundant visual clutter.
15. **Lossless Clean Hand-Off Protocol & Direct API Ingestion**:
    * Ingests validated synthetic UDM security analytics events (`CUSTOM_SECURITY_DATA_ANALYTICS`) across 10 specialized `product_event_type` schemas directly into Chronicle Event Store or attaches findings to designated SOAR case walls, gated strictly behind explicit analyst request (zero unsolicited escalation).
16. **Config-Driven Cross-Vector Fusion**:
    * Any two metrics that share an identifier can be fused, not just a fixed set of combinations. The agent fills each sector from `references/metric-sector-catalog.md`, which is generated from the Chronicle compiler's own metric configuration (vendored in `data/malachite/`) and lists, per metric: the observed event filter, observed value, `metric:` argument, valid identifier fields and valid dimension sets.
    * The catalog's pairing rules let the agent judge a requested pair before building it: pairs with the same entity kind and identifier proceed (e.g. network bytes + HTTP on `principal.asset.ip`), user ↔ host pairs are refused with the reason, and a query may hold at most 2 UDM event stages.
    * Metrics that only have composite baselines (`file_executions_*`, `resource_*`, `alert_event_name_count`) join a fusion as a **roll-up sector** (`rollup_sector_fusion_4stage.yl2`), e.g. process execution + DNS by host.
    * Valid sibling triads for part-of-the-whole (auth, DNS, HTTP, network bytes, network flows, Google Workspace) and generic failure-to-total ratio surges across all 8 `*_fail` / `*_total` metric families are supported natively.
    * The consultative worksheet's Cross-Vector Pairing section maps a requested pair to a template, offers the rare-destination filter where it applies, and explains why an invalid pair is rejected.
17. **User → Peer Group → Enterprise Comparison**:
    * `part_of_the_whole_multilevel.yl2` and its triad variant compare a user to their own baseline and to the enterprise, and to a peer group when one is given. With a peer group they also score the group against the enterprise (`$z_team_vs_enterprise`, `$d_team_vs_fleet_sq`).
    * When the analyst mentions a team without naming members, the agent looks the team up in Active Directory via the Entity Graph (the subject's department, else their smallest AD group excluding Domain Users) and shows the roster in the Pre-Flight card. It asks for a roster only when no AD team is found.
18. **Full 14-Tactic MITRE ATT&CK Kill-Chain Archetypes, Cross-Entity Bridges & SecOps Data Table Joins**:
    * `KillChainArchetype` (`scripts/template_router.py`) maps **11 MITRE ATT&CK kill-chains** covering **all 14 Enterprise tactics** (`TA0043` Reconnaissance, `TA0042` Resource Development, `TA0001` Initial Access, `TA0002` Execution, `TA0003` Persistence, `TA0004` Privilege Escalation, `TA0005` Defense Evasion, `TA0006` Credential Access, `TA0007` Discovery, `TA0008` Lateral Movement, `TA0009` Collection, `TA0011` Command and Control, `TA0010` Exfiltration, `TA0040` Impact) directly to turnkey multi-stage YARA-L pipelines.
    * `ChainedHuntRouter.build_cross_entity_killchain_plan()` automates two-query sequential bridges across Chronicle's single-identifier-type-per-DAG boundary (`HOST_TO_USER`, `USER_TO_HOST`, and `CLOUD_TO_HOST`). When a cohort exceeds 25 entities or requires persistent cohort bridging, upon explicit analyst approval in **State 3** the workflow materializes Phase 1 outlier cohorts into SecOps Data Table `%ueba_hunt_bridge` (`create_data_table` / `add_rows_to_data_table`) and joins them via `templates/pipelines/hybrid_data_table_bridge_2stage.yl2` (`ChainedHuntRouter.build_data_table_bridge_query()`).
19. **Unified Python Hybrid Engine (`scripts/ueba_hybrid_engine.py`) & Dual-Surface MCP Tooling**:
    * Consolidates pipeline compilation (`compile_hunt_pipeline`), cross-skill federated handoffs (`dispatch_hybrid_handoff`), and 5-section forensic dossier rendering (`render_forensic_dossier`) into a single composable Python engine (`compile`, `handoff`, `render`, `catalog` CLI subcommands).
    * Exposes the same three primitives as native Gemini `FunctionDeclaration` tools in headless MCP clients (`DirectMCPEngine`, `agentic_ueba`), offloading `24.4%` (`177.6 KB` per turn) of static reference/template prose while preserving full combinatorial flexibility across all 12 statistical models, 38 Malachite metrics, and 8 `secops-statistical-hunter` hybrid enrichment topologies.

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

### 1. First Principles: The 10 Behavioral Telemetry Deformations
Every threat physically deforms telemetry in one of ten distinct ways. The skill classifies analyst inquiries into these deformations to select the optimal mathematical model and disambiguation path:

| Telemetry Deformation | Physical Telemetry Signature | Recommended Mathematical Model | Primary Metric / Telemetry Dimension |
| :--- | :--- | :--- | :--- |
| **1. Persistent Accumulation**<br>*(The Slow Creep)* | Low-and-slow volume creep staying below static threshold alerts | Longitudinal CUSUM Drift (`longitudinal_cusum_2stage.yl2`) or Poisson Rarity | `metrics.network_bytes_outbound`, `metrics.dns_bytes_outbound` |
| **2. State Transition**<br>*(The Dormancy Break)* | Transition from zero historical activity to positive volume | Two-Part Hurdle Model (`two_part_hurdle.yl2`) (Zero-Inflation Logistic Gate) | `metrics.resource_read_total`, `metrics.workspace_total_download_actions` |
| **3. Volumetric Shock**<br>*(The Spiky Rupture)* | Sudden explosive surge over individual or peer baseline | Piecewise CRI (Shock Absorber) or Asymmetric Directional $Z$ (ReLU) | `metrics.auth_attempts_fail`, `metrics.resource_deletion_total` |
| **4. Volatility Regularity**<br>*(The Machine Pulse)* | Unnatural clockwork intervals or cyclic 24-hour clock shifts | Circadian von Mises Temporal Distance (`circadian_von_mises_2stage.yl2`), Hourly Temporal $Z$-Score (`hourly_temporal_zscore.yl2`), or Fano Factor | `metrics.auth_attempts_total`, `metrics.dns_queries_total`, `metrics.http_queries_total` |
| **5. Orthogonal Dispersion**<br>*(The Multi-Vector Fog)* | Mild elevations across 3–6 unrelated telemetry sectors | 360° Decoupled Behavioral Radar (`radar_360_decoupled_sector.yl2`, $D \ge 3.5\sigma$) | All 6 Canonical Risk Sectors Coupled |
| **6. Kinetic Acceleration**<br>*(The Runaway Train)* | Runaway velocity departure breaking historical ceilings | MACD Dual-Spine Momentum Indicator (`macd_momentum_velocity_2stage.yl2`) | `metrics.network_bytes_outbound`, `metrics.auth_attempts_total` |
| **7. Graph / Bipartite Fan-Out & Fan-In**<br>*(The Lateral Spray)* | $1 \rightarrow N$ target sweep or $N \rightarrow 1$ distributed concentration | Target Surge (`http_target_surge_2stage.yl2`), Part-of-the-Whole Triad, or Rare Destination ECG (`rare_destination_ecg_3stage.yl2`) | `metrics.http_queries_total`, `metrics.auth_attempts_fail`, `metrics.network_flows_total` |
| **8. Producer-Consumer Role Inversion**<br>*(The Staging Flip)* | Endpoint shifts from net data consumer to net data producer | Directional Asymmetric Z (`asymmetric_directional_z.yl2`) + Outbound/Inbound Fusion or Handoff to `secops-statistical-hunter` (`PRODUCER_CONSUMER_RATIO_INVERSION`) | `metrics.network_bytes_outbound` vs. `metrics.network_bytes_inbound` |
| **9. Geospatial / Physical Velocity**<br>*(Impossible Travel)* | Logins from physically distant coordinates within an impossible time delta | Federated Handoff to `secops-statistical-hunter` (`IMPOSSIBLE_TRAVEL_GEO_VELOCITY`, `math.geo_distance`) or Macro Auth + Asset Age (`hybrid_metric_derived_asset_age_2stage.yl2`) | `principal.ip_geo_artifact.location.*` / `metrics.auth_attempts_success` |
| **10. Persona-Conditioned Priors & Changepoints**<br>*(Role & Event Anchoring)* | Sensitivity conditioned on executive/contractor persona or pre/post incident changepoints | Data Table Priors (`%ueba_entity_priors`) + Dual-Baseline Delta-Z (`dual_baseline_delta_z_3stage.yl2`) | Any `metrics.*` vector joined with `%ueba_entity_priors` or anchored at $T_{\text{event}}$ |

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
* **MITRE ATT&CK Kill-Chain & Attack-Path Mapping** (`mitre-attack-killchain.md`): Maps **11 canonical MITRE ATT&CK multi-stage attack paths** across **all 14 Enterprise tactics** (`TA0043` Reconnaissance through `TA0040` Impact) and cross-entity bridges across user, host, and cloud identities.
* **Security & EDR Alert Frequency Baselining** (`security-edr-alerts.md`): Per-rule historical alert baselining (`metrics.alert_event_name_count`) rolled up by asset (`principal.asset.hostname`) or user (`principal.user.userid`).
* **Web, Proxy & Covert HTTP Channels** (`web-and-proxy.md`): User-agent fleet prevalence, proxy error-ratio surges, target-centric API hammering, and the HTTP part-of-the-whole triad.

### 4. Evaluation Modes: Mode A, Mode B, and Mode C
During the Pre-Flight Clearance gate, analysts choose a temporal evaluation horizon. One search request anchors one 30-day `metrics.*` baseline at its start day (Malachite `query_engine/qesql/ueba.go`), which shapes Modes B and C:
* **Mode A (Current-Day Snapshot)**: Evaluates today so far (00:00Z to now) against the 30-day historical baseline. Designed for rapid triage, immediate threshold breach identification, and daily operational sweeps. Queries that join the Entity Graph widen the search window to D-2 00:00Z but still score only today's events (see capability 6).
* **Mode B (Fixed-Baseline Timeline, 2–7 days)**: One query with daily buckets (`by 1d`). Every scored day reuses the baseline anchored at the first day, so later days face an older baseline; the card states the baseline dates. Works in every client. Longitudinal CUSUM is the exception: it wants that fixed reference and may span up to 14 days in one query.
* **Mode C (Per-Day Baseline Timeline)**: Offered only when the client can run local scripts (`run_command`). Runs the approved query once per UTC day so each day gets its own trailing 30-day baseline, then collates the saved results with `scripts/timeline_assembler.py` (default cap 30 days) — supporting both single-vector (`--shard YYYY-MM-DD=<path>`) and 6-sector 360° Behavioral Radar (`--shard YYYY-MM-DD:<sector>=<path>` with active-sector pre-screening) timelines. See `references/timeline-modes-guide.md`.

### 5. Natural Language Prompt Examples & Consultative Sample Queries

#### 🧭 Consultative & Open-Ended Inquiries
* *"I suspect an employee might be preparing to leave with sensitive data, but I don't know which telemetry source to check. Can you help me investigate?"*
* *"Help me find abnormal behavior for user frank.kolzig that static detection rules usually miss."*
* *"We saw suspicious privilege escalation attempts around August 29 — can you profile `admin@demo.wsexample.org` across that week to see if any cloud resource writes, creations, or deletions spiked alongside login activity?"* (automatically resolves corporate email `admin@demo.wsexample.org` → `user.userid = "admin"` across the August window and recommends a multi-sector 360° / Cloud CRUD + Auth hunt)
* *"What kind of behavioral anomaly hunts can we run against our Google Cloud and AWS infrastructure to catch insider privilege abuse?"*
* *"Hunt for Reconnaissance (`TA0043`) followed by Initial Access (`TA0001`) across our external web/auth perimeter."*
* *"We persisted a cohort of suspect hosts into Data Table `%ueba_hunt_bridge` during Phase 1 — run Phase 2 to score their 30-day outbound network byte departures."*

#### 🧩 Sample Compilable Queries from the Consultative Model

##### Example A: Two-Phase Cross-Entity Cohort Bridge via SecOps Data Table (`templates/pipelines/hybrid_data_table_bridge_2stage.yl2`)
When an investigation crosses entity types (e.g., Phase 1 identifies compromised `USER` accounts and extracts the `ASSET` hostnames they authenticated to into Data Table `%ueba_hunt_bridge`), Phase 2 joins `principal.asset.hostname = %ueba_hunt_bridge.hostname` directly inside Stage 1:

```yara
// Goal: Score 30-day behavioral metric departures for a bridged cohort stored
//       in SecOps Data Table %ueba_hunt_bridge (Two-Phase Chained Bridge)
stage stage1_extract {
    metadata.event_type = "NETWORK_CONNECTION"
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = %ueba_hunt_bridge.hostname
    principal.asset.hostname = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)
    $historical_avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d,
        metric: value_sum,
        agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $historical_stddev = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d,
        metric: value_sum,
        agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $active_baseline_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d,
        metric: value_sum,
        agg: num_metric_periods,
        principal.asset.hostname: principal.asset.hostname
    ))
}

$entity = $stage1_extract.entity

match:
  $entity by 1d

outcome:
  $observed_24h = max($stage1_extract.observed_val)
  $baseline_mean = max($stage1_extract.historical_avg)
  $baseline_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.active_baseline_days)
  $safe_stddev = if($baseline_stddev > 0, $baseline_stddev, 1.0)
  $personal_z = ($observed_24h - $baseline_mean) / $safe_stddev

condition:
  $active_days >= 7 and $personal_z >= 3.0

order:
  $personal_z desc
```

##### Example B: Consultative MITRE ATT&CK Kill-Chain (`RECON_TO_INITIAL_ACCESS` — `TA0043` $\rightarrow$ `TA0001`)
Fuses HTTP probe failures (`metrics.http_queries_fail` for active web reconnaissance `TA0043`) with authentication successes (`metrics.auth_attempts_success` for initial access `TA0001`) on the same asset IP:

```yara
// Goal: Detect Reconnaissance (TA0043) progressing to Initial Access (TA0001)
stage stage1_recon_http_fail {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    network.http.response_code >= 400
    principal.asset.ip = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $obs_s1 = count(metadata.id)
    $avg_s1 = max(metrics.http_queries_fail(
        period: 1d, window: 30d,
        metric: event_count_sum,
        agg: avg,
        principal.asset.ip: principal.asset.ip
    ))
    $std_s1 = max(metrics.http_queries_fail(
        period: 1d, window: 30d,
        metric: event_count_sum,
        agg: stddev,
        principal.asset.ip: principal.asset.ip
    ))
}

stage stage2_initial_access_auth {
    metadata.event_type = "USER_LOGIN"
    security_result.action = "ALLOW"
    principal.asset.ip = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $obs_s2 = count(metadata.id)
    $avg_s2 = max(metrics.auth_attempts_success(
        period: 1d, window: 30d,
        metric: event_count_sum,
        agg: avg,
        principal.asset.ip: principal.asset.ip
    ))
    $std_s2 = max(metrics.auth_attempts_success(
        period: 1d, window: 30d,
        metric: event_count_sum,
        agg: stddev,
        principal.asset.ip: principal.asset.ip
    ))
}

$entity = $stage1_recon_http_fail.entity
$entity = $stage2_initial_access_auth.entity

match:
  $entity by 1d

outcome:
  $recon_obs = max($stage1_recon_http_fail.obs_s1)
  $recon_avg = max($stage1_recon_http_fail.avg_s1)
  $recon_std = max($stage1_recon_http_fail.std_s1)
  $auth_obs = max($stage2_initial_access_auth.obs_s2)
  $auth_avg = max($stage2_initial_access_auth.avg_s2)
  $auth_std = max($stage2_initial_access_auth.std_s2)
  $safe_s1 = if($recon_std > 0, $recon_std, 1.0)
  $safe_s2 = if($auth_std > 0, $auth_std, 1.0)
  $z_recon = ($recon_obs - $recon_avg) / $safe_s1
  $z_auth = ($auth_obs - $auth_avg) / $safe_s2
  $pos_z1 = if($z_recon > 0, $z_recon, 0.0)
  $pos_z2 = if($z_auth > 0, $z_auth, 0.0)
  $threat_distance_sq = ($pos_z1 * $pos_z1) + ($pos_z2 * $pos_z2)

condition:
  $threat_distance_sq >= 12.25

order:
  $threat_distance_sq desc
```

#### 🕸️ 360° Behavioral Risk Radar & Peer Comparisons
* *"Show me a 360-degree risk metrics view of user Frank Kolzig across all 6 behavioral sectors."*
* *"Run a Mode C per-day 360° behavioral radar for `admin@demo.wsexample.org` from August 25 to August 31 so each day is scored against its own trailing 30-day baseline across all 6 sectors."*
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
* *"Calculate Median Absolute Deviation (MAD) on raw DNS query names / URI paths (no `metrics.*` baseline)."*
  *(MAD on a metric-catalog vector, e.g. "Run MAD on outbound bytes for the fleet", stays in this skill: `stage2_math_models/mad.yl2`.)*
* *"Find impossible travel velocity anomalies across raw cloud login events."*

---

## 🧪 Testing & Verification

The skill package ships with two test tiers that anyone can run from a clone:

### 1. Automated Unit Test Suite (`pytest` / `unittest`)
```bash
pytest tests/
# or: python3 -m unittest discover tests
```
* **Status**: **433 / 433 passing unit tests** (plus 218 subtests) across 25 test modules (100% pass rate).
* **Scope**: Enforces Chronicle AST grammar rules, `QueryIntegrityGate` pre-dispatch and post-execution validation, `%<table_name>.<column>` Data Table syntax rules, KaTeX formatting compliance, prompt guardrail contracts, 28,672-byte (28.0 KB) progressive-loading budget ceilings, template router permutations across all 38 metrics and 11 MITRE ATT&CK kill-chains, metric-sector catalog drift against `data/`, and Entity Graph freshness filters in every graph template.

### 2. Google SecOps Malachite Compiler Submission Harness
```bash
# Offline static AST & compiler invariant verification (32 canonical test cases)
python3 scripts/submission_tests.py

# Export the 32 rendered queries, e.g. to run each one through the SecOps MCP udm_search tool
python3 scripts/submission_tests.py --dump-dir <OUTPUT_DIR>
```
* **Status**: **32 / 32 passing submission test cases** offline; **60 / 60 live dual-engine scenarios (`120 / 120` runs across `AgentAPI` + `Direct-MCP`)** passing 100%.
* **Live compilation**: not part of this harness; it sends nothing to Chronicle. To check against a live tenant, export with `--dump-dir` and run each file through `udm_search`.
* **Scope**: Verifies Malachite AST compliance, continuous outcome arithmetic, Function Factory built-ins, and compiler invariants across all composite pipelines, decoupled radar spokes, and router configurations.

---

## 📦 Recent Releases

### v2.1.4 (October 2026) — Documentation & GitHub Markdown Math Rendering Fixes
* **GitHub `cmark-gfm` LaTeX Math & Formatting Fixes (`references/statistical-models-taxonomy.md`, `references/multi-stage-metrics-guide.md`, `references/calibrated-risk-index-guide.md`, `references/consultative/mitre-attack-killchain.md`, `SKILL.md`)**: Resolved KaTeX/MathJax rendering breaks caused by YARA-L `$placeholder` tokens inside single-line `$$...$$` display math blocks and multi-line `$$` fences, and cleaned up minor list/apostrophe/inline-math delimiters (`433/433` unit tests passing; `SKILL.md` is 25,807 bytes / 143 lines).

### v2.1.3 (October 2026) — The Bilateral UEBA Harness (`secops-risk-metrics-multistage` + `secops-statistical-hunter` + `agentic_ueba`), Telemetry Physics Guardrail & Multi-Plane CTI Synthesis
* **The Bilateral UEBA Harness (`SKILL.md`, `references/statistical-hunting-cooperative-framework.md` §8, `references/consultative/mitre-attack-killchain.md`)**: When an analyst asks for an open-ended "UEBA solution" to detect a threat, exploit, vulnerability, CTI report (e.g., `http2shell` / `CVE-2026-111497`), or detection gap without restricting to a single skill, synthesizes a multi-horizon architecture across **Plane 1 (Macro 30d `by 1d` `metrics.*`)**, **Plane 2 (Micro bounded-window raw `UDM_EVENTS` via `secops-statistical-hunter`)**, and **Plane 3 (`agentic_ueba` / `PlaybookRunner` Options 1–3)** instead of declaring `metrics.*` a poor fit for sub-hour process correlation or falling back to static point-in-time UDM string filters.
* **Strict Telemetry Physics & Window Guardrail**: Assigns all 30-day volumetric/failure/ratio baselines (`metrics.*`) and multi-sector fusions to `secops-risk-metrics-multistage` (`by 1d`) and strictly forbids running 30-day raw UDM scans over high-volume logs (VPC flows, DNS, HTTP, Auth, Process volume) in `secops-statistical-hunter`, which operates strictly on bounded minute/hour windows (`by 5m`, `by 1h`, `by 2h`, `by 1d` over `1h–24h` or `7d–14d`).
* **Test Suite & Live Dual-Engine Regression**: **433/433 unit tests** (+218 subtests); **32/32 submission tests**; **60/60 (`100.0%`)** live `AgentAPI` regression pass and **100% cross-skill boundary/handoff parity** across both engines on `gus-sdl`. `SKILL.md` is 25,803 bytes (143 lines).

### v2.1.2 (October 2026) — Full Audit Remediation: Macro-Day/Micro-Hour Burst Localization, Multi-Day Cumulative CUSUM Drift, Rectified Euclidean Fusion, Epoch-Zero ECG Guards & 28.0 KB Progressive-Loading Ceiling
* **Macro-Day (`period: 1d`) Baseline + Micro-Hour (`by 1h`) Burst Localization (`hourly_temporal_zscore.yl2`, `circadian_von_mises.yl2`, `circadian_von_mises_2stage.yl2`)**: Keeps Stage 1 `metrics.*` on its only supported `period: 1d, window: 30d` window while scaling the 24h baseline to hourly rates ($\mu_{\text{1h}} = \mu_{\text{1d}} / 24.0$, $\sigma_{\text{1h}} = \sigma_{\text{1d}} / 4.899$) when evaluating hourly `by 1h` burst stages.
* **Multi-Day Cumulative Drift (`longitudinal_cusum.yl2`, `longitudinal_cusum_2stage.yl2`, `scripts/timeline_assembler.py`)**: Evaluates daily slack excess (`$daily_excess = if($daily_z > 0.5, $daily_z - 0.5, 0.0)`) in an intermediate `by 1d` stage and aggregates multi-day cumulative drift (`$cusum_drift = sum($stage2_daily_drift.daily_excess)`, `$drift_days`) in an unbucketed root stage over Mode B horizons, paired with sequential Page's CUSUM ($S_t = \max(0, S_{t-1} + z_t - 0.5)$) in `scripts/timeline_assembler.py`.
* **Rectified Multi-Sector Fusion & Epoch-Zero ECG Guards (`multi_sector_fusion_4stage.yl2`, `rollup_sector_fusion_*.yl2`, `hybrid_metric_derived_*.yl2`, `hybrid_metric_whois_domain_lifecycle_2stage.yl2`)**: Rectifies negative Z-scores (`if($z > 0, $z, 0.0)`) before squaring in Euclidean fusion ($D = \sqrt{\sum \max(0, Z_i)^2}$), guards missing `first_seen_time` / WHOIS `creation_time` (`> 0`) against epoch-zero false positives, and enforces `agg: num_metric_periods` + `%ueba_hunt_bridge.entity` in `hybrid_data_table_bridge_2stage.yl2`.
* **Compiler-Safe Outcome `if()` & Division Guards Across All Templates & Scripts**: Extracted nested expressions from `if()` branches into intermediate OIO variables, added `"fusion"` / multi-metric auto-promotion to `compile_hunt_pipeline()` in `scripts/ueba_hybrid_engine.py`, reclassified `alert_event_name_count` to `PROCESS_UNCATEGORIZED` (`sigma_floor_value: 2.0`), and updated the `SKILL.md` progressive-loading ceiling to `28.0 KB` (`28,672` bytes) / `275` lines.
* **Test Suite & Live Dual-Engine Regression**: **433/433 unit tests** (+218 subtests); **32/32 submission tests**; **`120/120` (`100.0%` Invariant Parity)** across `AgentAPI` (`60/60`) and `Direct MCP` (`60/60`). `SKILL.md` is 24,450 bytes (142 lines).

### v2.1.1 (October 2026) — Native SecOps UEBA Architectural Grounding, Silent Zero-BigQuery Guardrail & Cloud CRUD Zero-Dispersion Suppression
* **Native SecOps UEBA Data Plane & Silent Zero-BigQuery Guardrail (`SKILL.md`, `references/multi-stage-metrics-guide.md`)**: Clarifies that `metrics.*` pre-computed behavioral baselines and `graph.*` execute 100% natively within Google SecOps, leveraging core Google infrastructure, and states directly when asked that **BigQuery contributes nothing to SecOps UEBA**.
* **Cloud CRUD 360° Radar Per-Product Z-Score (`scripts/radar_collector.py`)**: Computes Cloud CRUD directional Z-scores per `(user, vendor, product)` tuple inside Stage 1 before aggregating across products in the root stage.

### v2.1.0 (October 2026) — Pre/Post `QueryIntegrityGate`, 10 Consultative Deformations, 14-Tactic MITRE Coverage, SecOps Data Table Bridging & 5-Section Triage Reports
* **Pre/Post Execution `QueryIntegrityGate` (`scripts/preflight_validator.py`, `scripts/ueba_hybrid_engine.py`, `SKILL.md`)**: Adds `QueryIntegrityGate.verify_pre_dispatch()` and `QueryIntegrityGate.verify_backend_response()` to block unresolved template placeholders (`{{...}}`), unscoped target entities, malformed `%<table_name>.<column>` Data Table syntax, or Chronicle backend compiler/RPC errors from silently degrading into false `0.00σ` clean baseline reports.
* **Consultative Model Expansion (`references/consultative-worksheet.md`)**: Expands the consultative framework to **10 Behavioral Telemetry Deformations** (adding Graph/Relational Bipartite Fan-Out/Fan-In, Producer-Consumer Role Inversion, Geospatial Physical Velocity Handoffs, Persona-Conditioned Priors via `%ueba_entity_priors`, and Pre/Post Event Changepoint Framing) with **Executable Disambiguation Controls (`[A]` / `[B]` / `[C]`)**.
* **Full 14-Tactic MITRE ATT&CK Enterprise Coverage (`references/consultative/mitre-attack-killchain.md`, `scripts/template_router.py`)**: Adds `TA0043` (Reconnaissance) and `TA0042` (Resource Development) plus 3 new `KillChainArchetype` definitions (`RECON_TO_INITIAL_ACCESS`, `RESOURCE_DEV_TO_EXECUTION`, `EXFILTRATION_OVER_WEB_SERVICE`) for **11 turnkey multi-stage kill-chains** spanning all 14 Enterprise tactics.
* **Native SecOps Data Table Bridging (`templates/pipelines/hybrid_data_table_bridge_2stage.yl2`, `scripts/template_router.py`, `scripts/preflight_validator.py`)**: Adds `templates/pipelines/hybrid_data_table_bridge_2stage.yl2` (`%ueba_hunt_bridge.hostname` / `%ueba_hunt_bridge.entity`) and `ChainedHuntRouter.build_data_table_bridge_query()` so Two-Phase Cross-Entity Chained Hunts (`USER` $\leftrightarrow$ `ASSET` / `IP`) can materialize intermediate cohorts into Chronicle Data Tables upon explicit State 3 analyst approval rather than overflowing 25-item literal `in (...)` lists.
* **Streamlined 5-Section CommonMark Triage Reporting (`SKILL.md`, `scripts/triage_formatter.py`)**: Consolidates Turn 2 reports into 5 sections (`#### 1.` Executive Summary & CRI through `#### 5.` Collapsible Technical Appendix containing the verbatim executed multi-stage query), keeping reports concise while preserving all forensic evidence columns and numbered `[1]` / `[2]` / `[3]` agentic pivots.
* **Test Suite & Live Dual-Engine Regression**: **426/426 unit tests** (+212 subtests); **32/32 submission tests**; **`120/120` (`100.0%`)** across `AgentAPI` (`60/60`) and `Direct MCP` (`60/60`). `SKILL.md` is 20,287 bytes.

### v2.0.2 (October 2026) — Multi-Entry `BEHAVIORAL_RISK_RADAR_360` UDM Schema & Native Float Vector Scores
* **Unbundled Atomic Resource Labels (`references/clean-handoff-udm-schema.md`)**: Replaced the 6 packed `"CRI <n> | Z <z>"` strings in `target.resource.attribute.labels` with atomic roll-up keys (`Peak Vector`, `Peak CRI`, `Peak Z`, `Breached Vectors`).
* **Per-Vector `security_result[]` Entries with Native Floats**: `security_result[0]` carries the `COMPOSITE_360` roll-up (`risk_score` = Composite CRI, omitting `threat_name` and `confidence_score`), while `security_result[1..N]` emit one `SECTOR_VECTOR` entry per non-zero sector sorted descending by Z-score (`threat_name = <SECTOR>`, `risk_score = <Vector CRI>`, `confidence_score = <Vector Z>`, `threat_status = "ACTIVE" | "CLEARED"`). Zero-score vectors are omitted, allowing YARA-L rules (`max($e.security_result.confidence_score)`) and SecOps Native Dashboards (`GROUP BY security_result.threat_name`) to query individual vector CRI and Z-scores directly as numbers.
* **Test Suite**: **425/425 unit tests** (+212 subtests); **32/32 submission tests**. `SKILL.md` unchanged (20,449 bytes).

### v2.0.1 (October 2026) — Mode C 6-Sector 360° Radar Sharding, Email-to-Userid Identity Resolution & 4-Family Cloud CRUD Radar Spoke
* **Email-to-`user.userid` & Historical Window Identity Resolution (`SKILL.md`, `references/identity-governance.md`)**: When an analyst supplies a corporate email address (`*@*`) or display name, the Turn 1 probe tests `principal.user.userid`, `principal.user.email_addresses`, `target.user.userid`, and `target.user.email_addresses` across the user-requested historical evaluation window (`startTime`/`endTime`) and projects `$uid = coalesce(principal.user.userid, target.user.userid)` so `metrics.*` pipelines bind to the exact `user.userid` stored in UDM events (e.g., `admin@demo.wsexample.org` → `user.userid = "admin"`).
* **4-Family Cloud CRUD Radar Spoke (`scripts/radar_collector.py`, `templates/composite_pipelines/radar_360_spokes.yl2`, `references/360-radar-guide.md`)**: Expands the user 360° Behavioral Radar **Cloud Infrastructure (`cloud`)** spoke (`build_radar_spoke_6_cloud_query`) from a 2-family `writes` + `deletions` join to a full 4-family Cloud CRUD join across `resource_read_success`, `resource_written_success`, `resource_creation_success`, and `resource_deletion_success` (`math.max` across all 4 directional Z-scores), while preserving exact Malachite `query_engine/qesql/metrics.go` (`filterResourceMetric`) compatibility.
* **Mode C 6-Sector 360° Radar Sharding (`scripts/timeline_assembler.py`, `references/timeline-modes-guide.md`, `references/360-radar-guide.md`)**: Adds multi-sector Mode C support (`--shard YYYY-MM-DD:<sector>=<path>`) with active-sector pre-screening (`N days × K active sectors`), computing per-day composite `max_z`, peak sector attribution, and per-sector Z-score columns in the Markdown timeline table and multi-sector chart.
* **Strict Numbered Follow-Up Pivot Formatting (`SKILL.md`, `references/reporting-standards.md`, `references/360-radar-guide.md`)**: Enforces `[1]` / `[2]` / `[3]` numbering across all post-hunt and clean-hunt follow-up pivots so follow-up options never collide with `[A]`/`[B]`/`[C]` timeline clearance tokens.
* **Test Suite & Live Dual-Engine Regression**: **425/425 unit tests** (+212 subtests); **32/32 submission tests**; **`116/116` (`100.0%`)** across `AgentAPI` (`58/58`) and `Direct MCP` (`58/58`). `SKILL.md` is 20,449 bytes.

### v2.0.0 (October 2026) — Unified Python Hybrid Engine, Native Headless MCP Tools & 24.4% Prompt Compression
* **Unified Python Hybrid Engine (`scripts/ueba_hybrid_engine.py`)**: Exposes `compile_hunt_pipeline()`, `dispatch_hybrid_handoff()`, and `render_forensic_dossier()` via CLI (`compile`, `handoff`, `render`, `catalog`) and Python API, covering all 12 statistical models, 38 Malachite metrics, 7 pipeline architectures, Turn 1 consultative demarcation handoffs (`secops-threat-hunt-handoff-v1`), and Phase 2 Macro-to-Micro hybrid enrichment with `secops-statistical-hunter`.
* **Headless MCP & Cloud Run Integration (`secops-regress` & `agentic_ueba`)**: Registers `compile_hunt_pipeline`, `dispatch_hybrid_handoff`, and `render_forensic_dossier` as native Gemini `FunctionDeclaration` tools in headless MCP clients, offloading `177.6 KB` (`-24.4%`) of static reference/template prose per turn and accelerating Direct MCP suite runtime by `20.0%` (`35m 51s` → `28m 41s`).
* **Test Suite & Live A/B Benchmark**: **421/421 unit tests** (+212 subtests) across 25 test modules; **32/32 submission tests**; **`116/116` (`100.0%`)** verified across `AgentAPI` (`58/58`) and `Direct MCP` (`58/58`). `SKILL.md` is 20,407 bytes.

### v1.9.3 (October 2026) — Jetski `<agent-embed>` Artifact Registration, Timeline Score Auto-Detection & Ranked Bar Layout
* **Jetski `<agent-embed>` contract (`SKILL.md`, `references/chart-specifications-guide.md`, `references/timeline-modes-guide.md`)**: HTML charts in `<artifact_dir>` must be registered with `write_file` (`UserFacing: true`) rather than written only by a bash subprocess (`--html-out` writes to `<scratch>` first), and `<agent-embed>` requires `src="file:///<artifact_dir>/<chart>.html"></agent-embed>` with the `file:///` URI scheme and an explicit closing tag.
* **Mode C score column auto-detection (`scripts/timeline_assembler.py`)**: `SCORE_CANDIDATES` now includes all template score outcome columns (`personal_z`, `beacon_score`, `shielded_z`, `threat_score`, `threat_distance_sq`, `d_vs_fleet_sq`, `d_vs_team_sq`, `upper_tail_z`, `poisson_z`, `hourly_z`, `flow_z`, `clamped_z`, `fast_z`, `normalized_odds_score`, `cusum_drift_score`, `hurdle_threat_score`, `circadian_threat_score`, `macd_momentum_score`, `sensitivity_excess`, `cri_score`, `surge_ratio`, `bayes_shift_ratio`, `posterior_fail_prob`, `fano_factor`, `ratio`), so Mode C runs over any pipeline template score without `--score-field`.
* **Ranked fleet bar chart layout (`scripts/radar_collector.py`)**: widened SVG canvas (`740px`, `label_width=240`, 28-char label truncation, HTML escaping, host CSS variable theme support) so long FQDNs and user IDs do not collide with horizontal bars.
* **Test Suite**: 402/402 unit tests; 32/32 submission tests. SKILL.md is 20,173 bytes.

### v1.9.2 (October 2026) — Retired Contradictory Directives, Numbered Follow-Ups & Consolidation
* **Numbered follow-ups**: post-hunt pivots are `[1]` / `[2]` / `[3]` (were `[A]`/`[B]`/`[C]`, which could be read as Mode A/B clearance). A follow-up pick is never clearance. Pillar 4 and the 360° report template now name them.
* **Contradictions resolved**: the pre-flight gate covers every pre-flight turn, including follow-up pivots; CTI mapping no longer yields without a probe; the two-phase bridge is admitted by the tool, atomic-pipeline and cross-entity rules; "24h Observed" → "Observed"; CUSUM is no longer called Mode B; host and user radar rosters are both stated.
* **Probe wording**: "compiler probe" → "event-filter probe" across the references; one probe per pre-flight turn (+1 corrected retry); `maxEvents: 1` only.
* **Consolidation**: duplicate and low-value text removed. SKILL.md 20,459 → 20,083 bytes.
* **Test Suite**: 401/401 unit tests; 32/32 submission tests.

### v1.9.1 (October 2026) — Post-Data Agentic Next Steps, MITRE Kill-Chain Archetypes, Cross-Entity Bridges & Underused Metric Promotion
* **Post-Data Agentic Next Steps & State 3 → Phase 1B Pivot Loop**: `CommonMarkTriageFormatter.build_agentic_next_steps()` classifies hunt outcomes into `ACUTE_OUTLIER`, `CLEAN_OR_SUBTHRESHOLD`, `FLEET_WAVE`, and `SPARSE_BASELINE`, appending `[A]` / `[B]` / `[C]` follow-up pivots to Pillar 4 (and to the 2-pillar Clean Hunt report). Picking a pivot goes straight to Phase 1B pre-flight, carrying forward the entity, cohort, and bridge keys.
* **MITRE ATT&CK Tactic Mapping & Kill-Chain Archetypes**: New `references/consultative/mitre-attack-killchain.md` (12 tactics → `metrics.*` vectors and templates; 8 two-tactic archetypes), Domain 7 in `references/consultative-worksheet.md`, `KillChainArchetype` with `build_killchain_hunt_query()`, and Pillar 4 tactic progression via `get_mitre_progression()`.
* **Cross-Entity Bridges & Rare-Destination Routing**: `ChainedHuntRouter.build_cross_entity_killchain_plan()` builds two-query plans (`USER_CREDENTIAL_TO_HOST_EXECUTION`, `HOST_EXECUTION_TO_CLOUD_SA_ACCESS`, `HOST_ALERT_TO_PROCESS_EXECUTION`, `USER_WORKSPACE_HOARDING_TO_HOST_EGRESS`); `RARE_DESTINATION_ECG_3STAGE` and `FUSION_RARE_DESTINATION_3STAGE` are wired into `MultiStageTemplateRouter`.
* **Underused Metric Promotion & Host Radar Spokes**: `references/consultative/security-edr-alerts.md` and host/user `alert_event_name_count` roll-ups (`build_alert_surge_query()`); the host radar gains a Security & EDR Alerts spoke (replacing Cloud Infrastructure) and its Endpoint spoke reads `metrics.file_executions_total`; generic 8-family `*_fail` ratio surges (`build_failure_ratio_surge_query()`).
* **Turn 1 Probe & 360° Fleet Sweep Hardening**: `maxEvents: 1` and a 2-probe cap on Turn 1 pre-flight probes, plus `limit: 20` and canonical 6-sector labels on fleetwide 360° sweeps.
* **Test Suite**: 393/393 unit tests (212 subtests); 32/32 submission tests. SKILL.md is 20,459 bytes.

### v1.9.0 (October 2026) — Time Model, Fixed-Baseline Mode B & Per-Day Mode C
* **Baseline anchoring corrected**: verified in the Malachite query engine (`query_engine/qesql/ueba.go`), one search request gets one 30-day `metrics.*` baseline, anchored at its `startTime` day. The old claim that every scored day gets its own trailing baseline is removed everywhere.
* **Time Model** (new `SKILL.md` section): UTC day buckets; the search window picks the scored days and never supplies the baseline; Mode A starts today `T00:00:00Z` (Entity Graph joins: two UTC dates back at `T00:00:00Z`, with a worked date), never a rolling window.
* **Mode B** is now the **Fixed-Baseline Timeline** (2–7 days, one query). The card states the baseline dates; `references/timeline-modes-guide.md` explains the bias. Longitudinal CUSUM keeps one query of up to 14 days.
* **Mode C (new): Per-Day Baseline Timeline**, offered only when `run_command` is present. One query per UTC day, collated by the new sanctioned script `scripts/timeline_assembler.py`. Clients without shell access get a note that longer or per-day timelines need a client that can run local scripts.
* **AD TEAM LOOKUP**: must use the guide's aggregated query; the guide no longer shows a live tenant roster.
* **Match-window grammar**: `by 24h` is valid and matches `by 1d` buckets; the guide no longer calls it invalid. The skill keeps `by 1d` as its single daily form.
* **Test Suite**: 381/381 unit tests; 32/32 submission tests. SKILL.md is 20,384 bytes.

### v1.8.6 (October 2026) — Root Significance Gate
* **Gate enforced in every query**: every score-producing template carries its model's significance gate as a root `condition:` between `outcome:` and `order:`. The Pre-Flight card's `Significance Threshold` is now applied by the query instead of only being stated.
  * σ models gate Z at 3.0; ratio models (Bayes Gamma, Beta-Binomial, CV, Relative Deviation) gate a 2.0× fold change; fusion and triads gate D >= 3.5σ; MAD gates modified Z >= 3.5.
  * The Fano factor and the 360 radar sector queries are deliberately ungated.
* **Router and card**: analyst thresholds replace the default gate instead of adding to it. The query header shows the gate actually emitted, and the Pre-Flight card states each model's gate (`references/model-concordance-guide.md` §2.1).
* **Docs**: `or` is supported in root `condition:` (confirmed on gus-sdl).
* **Evidence**: 36/36 changed variants compiled live on gus-sdl. Executed queries with a root `condition:` rose from 29–37% to 85–86% in secops-regress.
* **Test Suite**: 360/360 unit tests; 32/32 submission tests.

### v1.8.5 (October 2026) — Minimal 360 Radar Hand-Off Event
* **One shape for both producers**: §10 of `references/clean-handoff-udm-schema.md` (`BEHAVIORAL_RISK_RADAR_360`) now matches the event that the agentic UEBA 4-hourly fleet sweep sends: one event per outlier entity carrying only Hunt Campaign ID, Evaluated Day, Composite CRI, Composite D and one `CRI <n> | Z <z>` label per sector.
* **Event time and entity IDs**: `event_timestamp` is when the hunt query ran; `ingested_timestamp` is left for Chronicle to set. Entity IDs keep the casing used in the source telemetry.
* **Corrected example**: the old example's Z values give D=7.09, not 6.68. The new example uses the real CRI function (CRI 92, `CRITICAL`).
* **Test Suite**: 346/346 unit tests; 32/32 submission tests. SKILL.md unchanged.

### v1.8.4 (October 2026) — Restored SKILL.md Guidance (v1.8.3 Regression Fix)
* **Root cause**: v1.8.3 commit `57d1253` cut SKILL.md wording to stay under the 20,480-byte limit. Three of the cuts changed how the agent behaves: the "Run CUSUM on Frank's DNS" bypass example, the 360 Radar line "all 6 must be reported", and "no exploratory shell searches".
* **Fix**: the three instructions are restored word for word. To pay for them, duplicated wording was shortened in the description, the `metrics.*` mapping step and the Two-Phase Chained Hunt line. SKILL.md is now 20,476 bytes.
* **Evidence**: A/B on REG-P0-04, P1-25 and P1-36 passed 6/6 before the trims, 0/6 on v1.8.3 and 5/6 with the fix. The full regress suite passed 47/52 after one rerun of failures, against 45/52 for v1.8.3. REG-P1-10 was a broken test that required a literal `+ 1.0` floor; it is fixed in secops-regress.
* **Test Suite**: 346/346 unit tests; 32/32 submission tests.

### v1.8.3 (October 2026) — True Median Absolute Deviation (MAD) on Any Metric Vector
* **Real MAD**: `StatisticalModel.MAD` (`stage2_math_models/mad.yl2`, pipeline `mad_robust_z_4stage.yl2`) computes the median and MAD of the raw daily values with `window.median(..., false)` and scores `modified_z` (Iglewicz-Hoaglin, threshold 3.5). It attaches to any of the 38 Stage 1 extractors in Mode A or Mode B. The old "MAD" templates were a rescaled Z-score and a fold change; the fold change is kept as `RELATIVE_DEVIATION`.
* **Masking cross-check**: every row carries the 30d metrics Z (`$personal_z`) and `$z_gap`, so you can see when historic bursts hid an anomaly from the classical Z.
* **Router**: MAD keeps only the 3 `metrics.*` lookups the cross-check reads (was 5); multi-key extractors are grouped by their full baseline tuple; an explicit MAD request on the cloud-repository USER metrics is no longer redirected.
* **Routing**: the skill description states the split. 30d-baseline MAD on metric vectors stays here; raw-field or custom-window MAD goes to `secops-statistical-hunter`.
* **Test Suite**: 346/346 unit tests (new MAD concordance, multi-key and cross-skill sync tests); 32/32 submission tests.

### v1.8.2 (October 2026) — Case-Insensitive Search Protection for `metrics.*` & Full Cloud CRUD Coverage
* **Field Paths in `metrics.*` Calls**: Every `metrics.*(...)` filter argument is written `<field>: <field>` instead of a `$placeholder`, across all templates, the router, the radar collector and the guides. Queries now return the same baselines in the SecOps Search UI with **Case Sensitivity Off** as they do through `udm_search`; Pillar 5 tells analysts to turn **Case Sensitivity On** for `metrics.*` queries.
* **Cloud CRUD Coverage**: `cloud_repository_scope_dual_branch.yl2` baselines all four resource families (read, write, delete, create) per resource plus caller IP, so dormant service accounts that wake up to create or delete resources are no longer missed.
* **Test Suite**: 335/335 unit tests (new `test_no_placeholder_args_inside_metrics_calls`); 32/32 submission tests.

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
