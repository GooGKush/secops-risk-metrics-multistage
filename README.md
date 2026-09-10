# Google SecOps Multi-Stage Risk Metrics Threat Hunter (`secops-risk-metrics-multistage`)

[![Version](https://img.shields.io/badge/version-v1.6.3-blue.svg)](RELEASE_NOTES.md) [![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE) [![Unit Tests](https://img.shields.io/badge/unit%20tests-193%2F193%20passing%20(100%25)-brightgreen.svg)](tests/) [![Submission Tests](https://img.shields.io/badge/submission%20tests-27%2F27%20passing%20(100%25)-brightgreen.svg)](scripts/submission_tests.py) [![Dual Platform Regression](https://img.shields.io/badge/dual--platform%20regression-22%2F22%20passing%20(100%25)-brightgreen.svg)](reports/)

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
├── evals/
│   └── evals.json                        # E2E evaluation benchmark prompts & assertions
├── references/                           # Deep-dive engineering guides & data contracts
│   ├── 360-behavioral-radar-guide.md     # Canonical 360° radar execution playbook & visual architecture
│   ├── calibrated-risk-index-guide.md    # CRI [0–100] sigmoid score translation guide
│   ├── chart-specifications-guide.md     # Vega-Lite & Chart.js declarative visual contracts
│   ├── clean-handoff-udm-schema.md       # 9 UDM event schemas & Catch-All case promotion rule
│   ├── compiler-submission-policy.md     # Chronicle SIEM Malachite compiler grammar & invariants
│   ├── consultative-worksheet.md         # Master consultative guidance worksheet & attack vector taxonomy
│   ├── consultative/                     # Specialized domain consultative deep-dives
│   │   ├── cloud-infrastructure.md       # Cloud CRUD, service account abuse, & privilege escalation
│   │   ├── data-exfiltration.md          # Volumetric bursts, low-and-slow trickles, & staging
│   │   ├── endpoint-and-covert.md        # Rare binary execution, living-off-the-land, & beaconing
│   │   ├── identity-and-access.md        # Credential compromise, circadian shifts, & dormancy breaks
│   │   └── insider-risk-360.md           # Holistic multi-silo insider profiling & 360° radar
│   ├── metrics-catalog.md                # Full catalog of 38 pre-computed behavioral risk metrics
│   ├── multi-stage-metrics-guide.md      # Multi-stage YARA-L DAG contracts, condition gating, & Entity Graph rules
│   ├── soar-playbook-radar-integration.md# Chronicle SOAR playbook integration for 360° radar
│   ├── statistical-hunting-cooperative-framework.md # Federated bilateral handoff protocol
│   └── statistical-models-taxonomy.md    # Mathematical taxonomy of all 14 statistical models
├── templates/                            # Composable YARA-L 2.0 template library
│   ├── pipelines/                        # Pre-composed multi-stage DAG pipelines
│   │   ├── cloud_repository_scope_dual_branch.yl2
│   │   ├── dual_baseline_delta_z_3stage.yl2
│   │   ├── dual_sector_fusion_3stage.yl2
│   │   ├── hierarchical_empirical_bayes_3stage.yl2
│   │   ├── hybrid_metric_entropy_concentration_2stage.yl2
│   │   ├── hybrid_metric_fleet_prevalence_2stage.yl2
│   │   ├── hybrid_metric_orthogonal_space_2stage.yl2
│   │   ├── hybrid_metric_raw_enrichment_2stage.yl2
│   │   ├── longitudinal_cusum_2stage.yl2
│   │   ├── mad_modified_z_2stage.yl2
│   │   ├── multi_sector_fusion_4stage.yl2
│   │   ├── poisson_rarity_2stage.yl2
│   │   ├── radar_360_decoupled_sector.yl2
│   │   └── standard_z_score_2stage.yl2
│   ├── stage1_extractors/                # Complete catalog of all 38 Stage 1 baseline extractors
│   │   ├── auth_attempts_* (fail, success, total)
│   │   ├── resource_* (creation, deletion, read, written, permissions)
│   │   ├── file_executions_* (fail, success, total)
│   │   ├── network_bytes_* / network_flows_* (inbound, outbound, total)
│   │   ├── dns_queries_* / dns_bytes_* (fail, success, total)
│   │   ├── http_queries_* (fail, success, total)
│   │   └── workspace_* (auth, emails sent, network bytes, downloads, changes)
│   └── stage2_math_models/               # Complete library of 14 plug-and-play mathematical models
│       ├── adaptive_context_threshold.yl2
│       ├── asymmetric_directional_z.yl2
│       ├── beta_binomial_bayesian.yl2
│       ├── coefficient_of_variation.yl2
│       ├── fleet_prevalence_shield.yl2
│       ├── hourly_temporal_zscore.yl2
│       ├── longitudinal_cusum.yl2
│       ├── mad.yl2
│       ├── piecewise_cri.yl2
│       ├── poisson_gamma_bayesian.yl2
│       ├── poisson_rarity.yl2
│       ├── standard_z_score.yl2
│       ├── two_part_hurdle.yl2
│       └── variance_fano.yl2
├── scripts/                              # Verification, execution, collector, & formatting utilities
│   ├── chart_generator.py                # Formats hunt outputs into Vega-Lite & Chart.js specs
│   ├── data_reduction.py                 # Multi-stage DAG syntax reduction engine
│   ├── federated_handoff.py              # Cross-skill bilateral threat hunt handoff protocol
│   ├── generate_references.py            # Code-as-SSOT reference documentation generator
│   ├── preflight_validator.py            # Pre-flight syntax and outcome contract validator
│   ├── radar_collector.py                # 5-Sector 360° radar SVG/HTML generator & score collector
│   ├── submission_tests.py               # Canonical 27-case compiler verification test harness
│   ├── template_router.py                # Maps natural language intent to .yl2 templates with condition filtering
│   └── triage_formatter.py               # Generates 6-section triage reports & CRI scores
└── tests/                                # Automated unit test suite (193 tests across 16 test modules)
    ├── test_chart_specifications.py
    ├── test_complex_multistage_syntax.py
    ├── test_cri_and_math.py
    ├── test_exhaustive_matrix_syntax.py
    ├── test_federated_handoff.py
    ├── test_global_context_syntax.py
    ├── test_guardrail_contracts.py
    ├── test_hybrid_pipelines.py
    ├── test_radar_collector.py
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

1. **$O(1)$ Behavioral Baselining Foundation**:
   * Evaluates 30-day historical averages ($\mu$), standard deviations ($\sigma$), and active observation days ($N$) in constant time via pre-computed summary tables (`metrics.*`).
2. **Progressively Disclosed Consultative Support System**:
   * Makes advanced statistical analytics immediately accessible to operational SOC analysts without requiring mathematical background or formula knowledge.
   * Progressively loads guidance to preserve LLM context window efficiency while maximizing analytical fidelity:
     * **Tier 1 (Known Knowns)**: Volumetric spikes and acute bursts (Standard $Z$, Piecewise CRI).
     * **Tier 2 (Known Unknowns / Static Rule Blind Spots)**: Low-and-slow trickles, dormancy breaks, off-hours circadian shifts, beaconing jitter, and persistent baseline drift (CUSUM, Two-Part Hurdle, Hourly $Z$, Poisson Rarity).
     * **Tier 3 (Unknown Unknowns / Cross-Silo Anomalies)**: Multi-vector orthogonal dispersion across disparate telemetry silos ($D \ge 3.5\sigma$ 360° Risk Radar).
   * Formulates an operational **"Summary View"** highlighting the **Threat Hypothesis**, **Recommended Method & Rationale**, and **Alternative Vectors**, protected by a strict **Anti-Auth-Defaulting Guardrail** (preventing default fall-through to authentication logs during open-ended consultative inquiries).
   * Enforces the **Expert Bypass Fast-Track Protocol**: when an experienced practitioner specifies both scope/vector and statistical model up front, consultation is cleanly bypassed directly to Phase 1B pre-flight clearance, eliminating false rule-generation leakage.
3. **360° Entity Behavioral Risk Radar (All-Vectors Profiling)**:
   * Generates comprehensive behavioral fingerprints across the **5 canonical risk sectors**: Authentication & Access, Cloud Resource CRUD, Workspace & SaaS, Network Egress, and DNS & Web Activity.
   * Leverages decoupled 2-stage parallel micro-queries to eliminate inner-join drops (`maxJoinCount = 4` protection), synthesizing findings into the Euclidean Threat Distance norm:
     $$D = \sqrt{\sum_{i=1}^{5} Z_i^2}$$
4. **Adaptive Multi-Surface Visualization & Dual-Platform Parity**:
   * Renders single-surface visual outputs matched to client capabilities: `<agent-embed>` standalone HTML widgets in Jetski Web / Antigravity, clean inline `<svg>` in headless MCP webviews, and Canonical ASCII progress bars in Pillar 3 CommonMark tables. Enforces a strict single-surface guarantee to prevent duplicate visual clutter.
5. **Noise Level Tuning & Root-Stage `condition:` Gating**:
   * Leverages native Chronicle Malachite compiler support for root-stage `condition:` post-aggregation filtering (`HAVING` semantics) placed directly before `order:`.
   * Empowers analysts to steer operational sensitivity:
     * **High Confidence Gating**: `condition: $z_score >= 3.0`
     * **Investigative Drift Band**: `condition: $z_score >= 2.0 and $z_score < 3.0` (uncovering low-and-slow anomalies before threshold breach)
     * **Directional Outliers**: `condition: $z_score <= -3.0` (anomalous telemetry silencing)
     * **Baseline Maturity Hurdles**: `condition: $z_score >= 3.0 and $active_days >= 7`
     * **Multi-Evidence Fusion**: `condition: $threat_distance_sq >= 16.0 or ($joint_odds >= 2.5 and $raw_hits >= 3)`
6. **Cloud Infrastructure CRUD & Origin IP Monitoring**:
   * Evaluates cloud repository and data store operations (`resource_read_*`, `resource_written_*`) across Google Cloud (`GCP_CLOUDAUDIT`), AWS CloudTrail, and Azure Activity logs via dual-branch DAGs (`cloud_repository_scope_dual_branch.yl2`), preventing single-product narrowing traps and capturing origin IP pivots.
7. **Identity Governance & Zero-Guessing Hard Resolution Gate**:
   * Strictly bans heuristic username synthesis. Uses a 14-day UDM lookback window (`startTime: 14d ago, maxEvents: 5`) and compound name matching (`user_display_name` and `first_name`/`last_name`) across `principal.user` and `target.user`.
   * Halts immediately and yields the turn if an identity cannot be resolved from telemetry, prompting the analyst for their technical user ID before proceeding.
8. **Comprehensive 38-Metric Extractor Matrix & 14 Stage 2 Math Models**:
   * Complete 38-metric Stage 1 extractor coverage across Authentication, Cloud CRUD, File Execution, Network Egress/Flows, DNS Activity, and Google Workspace.
   * Full implementation of 14 Stage 2 mathematical models: Standard $Z$-Score, Robust MAD, Poisson Rarity, Hourly Temporal $Z$-Score, Coefficient of Variation ($CV$), Variance Fano Factor, Asymmetric Directional $Z$, Longitudinal CUSUM Drift, Two-Part Hurdle Model, Piecewise CRI, Empirical Bayes Gamma Prior, Beta-Binomial Empirical Bayes Prevalence, Fleet Prevalence Shielding, and Adaptive Dynamic Thresholds.
   * Verified via a complete $38 \times 14 \times 2 = 1,064$ permutation matrix with 100% compilation on the Chronicle Malachite compiler.
9. **Interactive Step 1 Pre-Flight Safety Protocol**:
   * Enforces zero search execution on Turn 1, explains methodologies with physical cyber analogies, presents structured Pre-Flight Specification Cards (including tunable Significance Threshold bands), and renders literal YARA-L query previews before clearance.
10. **Calibrated Risk Index (CRI [0–100])**:
    * Normalizes disparate multi-dimensional statistics onto a unified, sigmoid-bounded 0–100 triage currency across 4 operational severity tiers: 🟢 Nominal (0–29), 🟡 Elevated (30–49), 🟠 High (50–84), and 🔴 Critical (85–100).
11. **Lossless Clean Hand-Off & Case Escalation**:
    * Gated strictly behind explicit analyst request (zero unsolicited escalation). Ingests synthetic UDM security events across 9 specialized `product_event_type` schemas or attaches directly to designated SOAR cases.

---

## 🚀 How to Install & Use in AI Coding Assistants

### 1. Installation
Clone or copy this directory into your assistant's skills search path (e.g., `~/.gemini/skills/` or `.agents/skills/`):
```bash
git clone https://github.com/GooGKush/secops-risk-metrics-multistage.git ~/.gemini/skills/secops-risk-metrics-multistage
```

### 2. Triggering Threat Hunts

Once installed, trigger multi-stage statistical hunting using natural language. The skill flexibly handles everything from open-ended consultative inquiries to highly specific mathematical models:

#### 🧭 Consultative & Open-Ended Inquiries (Guided Method Suggestion)
* *"I suspect an employee might be preparing to leave with sensitive data, but I don't know which telemetry source to check. Can you help me investigate?"*
* *"Help me find abnormal behavior for user frank.kolzig that static detection rules usually miss."*
* *"What kind of behavioral anomaly hunts can we run against our Google Cloud and AWS infrastructure to catch insider privilege abuse?"*

#### 🕸️ 360° Behavioral Risk Radar & Peer Comparisons
* *"Show me a 360-degree risk metrics view of user Frank Kolzig across all 5 behavioral sectors."*
* *"Is Frank doing things his teammates don't do? Check his authentication activity against his IT Department peer group roster."*
* *"Perform a 360 health check on our top executive service accounts to spot cross-silo behavioral dispersion."*

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

---

## 🧪 Testing & Verification

The skill is validated through a comprehensive three-tier testing hierarchy:

### 1. Automated Unit Test Suite (`pytest` / `unittest`)
```bash
python3 -m unittest discover tests
```
* **Status**: **193 / 193 passing unit tests** across 16 test modules (100% pass rate).
* **Scope**: Enforces AST grammar rules, KaTeX formatting compliance, prompt guardrail contracts, 20 KB token efficiency ceilings, and template router permutations.

### 2. Google SecOps Malachite Compiler Submission Harness
```bash
python3 scripts/submission_tests.py
```
* **Status**: **27 / 27 passing submission test cases** (100.0% clean compilation).
* **Scope**: Verifies Malachite AST compliance, continuous outcome arithmetic, and compiler invariants across all composite pipelines, decoupled radar spokes, and router configurations.

### 3. Dual-Platform Conversational Regression Platform (`secops-regress`)
```bash
python3 run_regress.py --engine dual -j 8 --suite all
```
* **Status**: **22 / 22 passing end-to-end scenarios** in Dual Engine mode (100% invariant parity).
* **Scope**: Validated under 8 concurrent worker streams against live Google SecOps customer instances (`gus-sdl`), ensuring identical mathematical findings, nominal baseline agreement, and single-surface visualization compliance across both AgentAPI (Jetski Web) and headless Direct MCP environments.

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
