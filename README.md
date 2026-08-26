# SecOps Risk Metrics Multi-Stage Statistical Skill

A specialized Agentic Skill for executing multi-stage statistical anomaly detection and outlier hunting in Google Security Operations (SecOps), using pre-computed Risk Analytics metrics (`metrics.*`) as Stage 1 data foundation.

## Features
- **38 Risk Metrics Catalog**: Full dimension & log source mapping derived from `config.textproto`.
- **Universal 6-Point Stage 1 Outcome Contract**: Standardized data handoff to downstream mathematical stages.
- **Statistical Models**: Standard Z-Score, MAD (Modified Z-Score), Variance / Fano Factor, Discrete Poisson Rarity, and Coefficient of Variation.
- **Strict 24h Search Window Clamping**: Prevents multi-day metric duplication errors.
- **Context-Safe Data Reduction**: Truncates large API payloads to top N outliers.
- **Cyber-First 4-Tier Triage Reporting**: Clean CommonMark executive reports with SOC playbooks.

---
*Created and maintained by Greg Kushmerek for Google SecOps Chronicle SIEM threat hunting workflows.*
