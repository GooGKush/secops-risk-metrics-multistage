# Google SecOps Multi-Stage Risk Metrics Threat Hunter (`secops-risk-metrics-multistage`)

[![Version](https://img.shields.io/badge/version-v1.2.1-blue.svg)](RELEASE_NOTES.md) [![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE) [![Tests](https://img.shields.io/badge/tests-70%2F70%20passing-brightgreen.svg)](tests/)

A specialized, production-grade AI agent skill package for **Google Security Operations (SecOps / Chronicle SIEM & SOAR)** that constructs, validates, and executes **Multi-Stage YARA-L 2.0 Directed Acyclic Graph (DAG) statistical threat hunting pipelines**.

The skill utilizes Google SecOps pre-computed behavioral risk analytics (`metrics.*`) as the Stage 1 baseline foundation ($O(1)$ constant-time lookup) and executes advanced mathematical outlier evaluation across subsequent stages.

---

## 🗺️ Package Structure

This repository is structured to conform strictly with the [Agent Skills Specification](https://agentskills.io):

```
secops-risk-metrics-multistage/
├── SKILL.md                              # Core orchestrator prompt & pre-flight decision matrix
├── ARCHITECTURE.md                       # High-level architecture & DAG execution invariants
├── README.md                             # Package overview & usage guide
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
│   ├── metrics-catalog.md                # Full catalog of 38 pre-computed behavioral risk metrics
│   ├── multi-stage-metrics-guide.md      # Multi-stage YARA-L DAG contracts & Entity Graph rules
│   └── statistical-models-taxonomy.md    # Mathematical taxonomy of all 14 statistical models
├── templates/                            # Composable YARA-L 2.0 template library
│   ├── pipelines/                        # Pre-composed 2-stage, 3-stage, and 4-stage DAG pipelines
│   │   ├── dual_baseline_delta_z_3stage.yl2
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
├── scripts/                              # Local verification, routing, & formatting utilities
│   ├── chart_generator.py                # Formats hunt outputs into Vega-Lite & Chart.js specs
│   ├── data_reduction.py                 # Multi-stage DAG syntax reduction engine
│   ├── preflight_validator.py            # Pre-flight syntax and outcome contract validator
│   ├── template_router.py                # Maps natural language intent to .yl2 templates
│   └── triage_formatter.py               # Generates 6-section triage reports & CRI scores
└── tests/                                # Automated unit test suite (70 unit tests)
    ├── test_chart_specifications.py
    ├── test_complex_multistage_syntax.py
    ├── test_cri_and_math.py
    ├── test_exhaustive_matrix_syntax.py
    ├── test_global_context_syntax.py
    ├── test_guardrail_contracts.py
    ├── test_skill_efficiency_and_clarity.py
    ├── test_statistical_assumptions.py
    ├── test_triage_formatter.py
    └── test_yaral_templates.py
```

---

## 🌟 Core Capabilities

1. **$O(1)$ Behavioral Baselining Foundation**:
   * Evaluates 30-day historical averages ($\mu$), standard deviations ($\sigma$), and active observation days ($N$) in constant time via pre-computed summary tables (`metrics.*`).
2. **14 Mathematical Outlier Models**:
   * Standard $Z$-Score, Robust MAD, Coefficient of Variation ($CV$), Hourly Temporal $Z$-Score, Poisson Dispersion (Fano Factor), Discrete Poisson Rarity, Poisson-Gamma Conjugate Updating, Beta-Binomial Failure Rate Regularization, 3-Stage Dual-Baseline Delta-$Z$, 3-Stage Hierarchical Empirical Bayes, 4-Stage Multi-Sector Fusion ($D = \sqrt{\sum Z_i^2}$), 360° Omnibus Entity Radar, Longitudinal CUSUM Drift, and Entity Graph Prevalence Rarity.
3. **Interactive Step 1 Pre-Flight Safety Protocol**:
   * Enforces zero tool execution on Turn 1, explains methodologies with physical cyber analogies (*The Seasoned SOC Detective*, *The Patch Tuesday Earthquake Shield*), presents structured Pre-Flight Specification Cards with Entity Graph dimensions, and renders complete literal YARA-L query previews before clearance.
4. **Calibrated Risk Index (CRI [0–100])**:
   * Normalizes disparate multi-dimensional statistics onto a unified, sigmoid-bounded 0–100 triage currency across 4 operational severity tiers: 🟢 Nominal (0–29), 🟡 Elevated (30–49), 🟠 High (50–84), and 🔴 Critical (85–100).
5. **Lossless 1:1 Clean Hand-Off & Case Escalation**:
   * Ingests discrete synthetic UDM security events per outlier ($Z \ge 3.0\sigma$, $\text{CRI} \ge 50$) across **9 specialized `product_event_type` schemas**, automatically promoted into Chronicle SOAR cases via tenant catch-all rules.
6. **Declarative Web UI Visualizations**:
   * Generates strictly-typed Vega-Lite (v5) and Chart.js specs for 30-day behavioral envelope charts ($\mu \pm 3\sigma$) and dual-axis volume vs. outlier score charts.
7. **Variable Role Classification & Threat Decomposition Engine (v1.1.0)**:
   * Categorizes intermediate variables into `[JOIN_KEY]`, `[SCORING_DIMENSION]`, `[ACTIVE_FILTER]`, and `[TRIAGE_DECORATION]`. Prevents qualitative threats (command lines, script droppers, LOLBins) from acting solely as passive output strings by actively mapping them to Cross-Sectional Fleet Rarity DAGs ($N_{\text{hosts}} \le 2$).

---

## 🚀 How to Install & Use in AI Coding Assistants

### 1. Installation
Clone or copy this directory into your assistant's skills search path (e.g., `~/.gemini/skills/` or `.agents/skills/`):
```bash
git clone https://github.com/GooGKush/secops-risk-metrics-multistage.git ~/.gemini/skills/secops-risk-metrics-multistage
```

### 2. Triggering Threat Hunts
Once installed, trigger multi-stage statistical hunting using natural language:
* *"Hunt across the fleet for workstations with abnormal file execution spikes compared to their historical baseline that are launching rare binaries."*
* *"Hunt across the enterprise for hosts with coordinated anomalies across authentication failures and outbound network bytes."*
* *"Is Frank doing things his teammates don't do? Check his authentication activity against his IT Department peer group."*
* *"Check my environment for low and slow data exfiltration over the last 14 days."*

---

## 🧪 Testing & Verification

Run the automated test suite to verify mathematical safety and YARA-L template syntax:
```bash
python3 -m unittest discover -s tests -p "test_*.py"
```
* **Status**: 70/70 passing unit tests in $\le 0.2\text{s}$.
* **Live SIEM Validation**: Validated on Google SecOps customer instances (`gus-sdl`).


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
