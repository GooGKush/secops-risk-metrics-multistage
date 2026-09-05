# Google SecOps Multi-Stage Risk Metrics Threat Hunter (`secops-risk-metrics-multistage`)

[![Version](https://img.shields.io/badge/version-v1.5-blue.svg)](RELEASE_NOTES.md) [![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE) [![Submission Tests](https://img.shields.io/badge/submission%20tests-21%2F21%20passing%20(100%25)-brightgreen.svg)](scripts/submission_tests.py)

A specialized, production-grade AI agent skill package for **Google Security Operations (SecOps / Chronicle SIEM & SOAR)** that constructs, validates, and executes **Multi-Stage YARA-L 2.0 Directed Acyclic Graph (DAG) statistical threat hunting pipelines** and **360° Entity Behavioral Risk Radars**.

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
│   ├── calibrated-risk-index-guide.md    # CRI [0–100] sigmoid score translation guide
│   ├── chart-specifications-guide.md     # Vega-Lite & Chart.js declarative visual contracts
│   ├── clean-handoff-udm-schema.md       # 9 UDM event schemas & Catch-All case promotion rule
│   ├── compiler-submission-policy.md     # Chronicle SIEM Malachite compiler grammar & invariants
│   ├── metrics-catalog.md                # Full catalog of 38 pre-computed behavioral risk metrics
│   ├── multi-stage-metrics-guide.md      # Multi-stage YARA-L DAG contracts & Entity Graph rules
│   ├── soar-playbook-radar-integration.md# Chronicle SOAR playbook integration for 360° radar
│   └── statistical-models-taxonomy.md    # Mathematical taxonomy of all 14 statistical models
├── templates/                            # Composable YARA-L 2.0 template library
│   ├── pipelines/                        # Pre-composed 2-stage, 3-stage, and 4-stage DAG pipelines
│   │   ├── dual_baseline_delta_z_3stage.yl2
│   │   ├── dual_sector_fusion_3stage.yl2
│   │   ├── hierarchical_empirical_bayes_3stage.yl2
│   │   ├── longitudinal_cusum_2stage.yl2
│   │   ├── mad_modified_z_2stage.yl2
│   │   ├── multi_sector_fusion_4stage.yl2
│   │   ├── poisson_rarity_2stage.yl2
│   │   └── standard_z_score_2stage.yl2
│   ├── stage1_extractors/                # Standardized Stage 1 telemetry baseline extractors
│   │   ├── auth_attempts_fail.yl2
│   │   ├── auth_attempts_total.yl2
│   │   ├── dns_queries_fail.yl2
│   │   ├── dns_queries_total.yl2
│   │   ├── file_executions_total.yl2
│   │   ├── http_queries_total.yl2
│   │   └── network_bytes_outbound.yl2
│   └── stage2_math_models/               # Plug-and-play Stage 2+ mathematical models
│       ├── beta_binomial_bayesian.yl2
│       ├── coefficient_of_variation.yl2
│       ├── hourly_temporal_zscore.yl2
│       ├── mad.yl2
│       ├── poisson_gamma_bayesian.yl2
│       ├── poisson_rarity.yl2
│       ├── standard_z_score.yl2
│       └── variance_fano.yl2
├── scripts/                              # Verification, execution, collector, & formatting utilities
│   ├── chart_generator.py                # Formats hunt outputs into Vega-Lite & Chart.js specs
│   ├── data_reduction.py                 # Multi-stage DAG syntax reduction engine
│   ├── preflight_validator.py            # Pre-flight syntax and outcome contract validator
│   ├── radar_collector.py                # 5-Sector 360° radar SVG/HTML generator & score collector
│   ├── submission_tests.py               # Canonical 19-case compiler verification test harness
│   ├── template_router.py                # Maps natural language intent to .yl2 templates
│   └── triage_formatter.py               # Generates 6-section triage reports & CRI scores
└── tests/                                # Automated unit test suite
    ├── test_chart_specifications.py
    ├── test_complex_multistage_syntax.py
    ├── test_cri_and_math.py
    ├── test_exhaustive_matrix_syntax.py
    ├── test_global_context_syntax.py
    ├── test_guardrail_contracts.py
    ├── test_radar_collector.py
    ├── test_skill_efficiency_and_clarity.py
    ├── test_statistical_assumptions.py
    ├── test_submission_compiler_policy.py
    ├── test_triage_formatter.py
    └── test_yaral_templates.py
```

---

## 🌟 Core Capabilities

1. **$O(1)$ Behavioral Baselining Foundation**:
   * Evaluates 30-day historical averages ($\mu$), standard deviations ($\sigma$), and active observation days ($N$) in constant time via pre-computed summary tables (`metrics.*`).
2. **360° Entity Behavioral Risk Radar (All-Vectors Profiling)**:
   * Generates comprehensive behavioral fingerprints across the **5 canonical risk sectors**: Authentication & Access, Cloud Resource CRUD, Workspace & SaaS, Network Egress, and DNS & Web Activity.
   * Leverages decoupled 2-stage parallel micro-queries to avoid silent inner-join drops on quiet accounts, synthesizing findings into the Euclidean Threat Distance norm:
     $$D = \sqrt{\sum_{i=1}^{5} Z_i^2}$$
3. **Adaptive Multi-Surface Visualization**:
   * Renders single-surface visual outputs matched to client capabilities: `<agent-embed>` standalone HTML widgets in Jetski Web, clean inline `<svg>` in generic MCP clients, and Canonical ASCII Radar Cards in headless CLI terminals. Enforces a strict single-surface guarantee to prevent duplicate visual clutter.
4. **Identity Governance & Zero-Guessing Hard Resolution Gate**:
   * Strictly bans heuristic username synthesis. Uses a 14-day UDM lookback window (`startTime: 14d ago, maxEvents: 5`) and compound name matching (`user_display_name` and `first_name`/`last_name`) across `principal.user` and `target.user`.
   * Halts immediately and yields the turn if an identity cannot be resolved from telemetry, prompting the analyst for their technical user ID before proceeding.
5. **14 Mathematical Outlier Models**:
   * Standard $Z$-Score, Robust MAD, Coefficient of Variation ($CV$), Hourly Temporal $Z$-Score, Poisson Dispersion (Fano Factor), Discrete Poisson Rarity, Poisson-Gamma Conjugate Updating, Beta-Binomial Failure Rate Regularization, 3-Stage Dual-Baseline Delta-$Z$, 3-Stage Hierarchical Empirical Bayes, 4-Stage Multi-Sector Fusion, 360° Omnibus Entity Radar, Longitudinal CUSUM Drift, and Entity Graph Prevalence Rarity.
6. **Interactive Step 1 Pre-Flight Safety Protocol**:
   * Enforces zero search execution on Turn 1, explains methodologies with physical cyber analogies, presents structured Pre-Flight Specification Cards, and renders literal YARA-L query previews before clearance.
7. **Calibrated Risk Index (CRI [0–100])**:
   * Normalizes disparate multi-dimensional statistics onto a unified, sigmoid-bounded 0–100 triage currency across 4 operational severity tiers: 🟢 Nominal (0–29), 🟡 Elevated (30–49), 🟠 High (50–84), and 🔴 Critical (85–100).
8. **Lossless Clean Hand-Off & Case Escalation**:
   * Gated strictly behind explicit analyst request (zero unsolicited escalation). Ingests synthetic UDM security events across 9 specialized `product_event_type` schemas or attaches directly to designated SOAR cases.

---

## 🚀 How to Install & Use in AI Coding Assistants

### 1. Installation
Clone or copy this directory into your assistant's skills search path (e.g., `~/.gemini/skills/` or `.agents/skills/`):
```bash
git clone https://github.com/GooGKush/secops-risk-metrics-multistage.git ~/.gemini/skills/secops-risk-metrics-multistage
```

### 2. Triggering Threat Hunts
Once installed, trigger multi-stage statistical hunting using natural language:
* *"Show me a 360 view of user Frank Kolzig using ueba risk metrics."*
* *"Hunt across the fleet for workstations with abnormal file execution spikes compared to their historical baseline that are launching rare binaries."*
* *"Hunt across the enterprise for hosts with coordinated anomalies across authentication failures and outbound network bytes."*
* *"Is Frank doing things his teammates don't do? Check his authentication activity against his IT Department peer group."*
* *"Check my environment for low and slow data exfiltration over the last 14 days."*

---

## 🧪 Testing & Verification

Run the official Google SecOps Malachite submission test harness to verify AST compliance and compiler invariants across all templates:
```bash
python3 scripts/submission_tests.py
```
* **Status**: 19/19 passing submission test cases (100.0% clean compilation).
* **Live SIEM Validation**: Validated on live Google SecOps customer instances (`gus-sdl`).

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
