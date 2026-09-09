# Consultative Deep-Dive: Comprehensive Insider Risk & Multi-Vector Threat Fusion

## 1. The Deterministic Rule Failure Mode
Organizations deploy distinct point solutions for Authentication (Okta), SaaS (Google Workspace), Cloud (GCP/AWS), Network (Palo Alto), and Endpoint (CrowdStrike). Each tool operates in complete isolation:
* Okta sees 4 failed logins followed by success $	o$ Deemed benign.
* Google Workspace sees 10 file downloads $	o$ Deemed benign.
* Cloud Audit sees 2 database reads $	o$ Deemed benign.
* Palo Alto sees 300 MB egress to an external IP $	o$ Deemed benign.

**The Blind Spot**:
Every individual action is intentionally tuned to fall below alert thresholds. The adversary exploits **cross-silo blind spots**, ensuring no single detection team ever receives a high-priority ticket.

---

## 2. The Behavioral Antidotes

### Strategy A: Decoupled Multi-Sector Fusion (The 360° Behavioral Radar)
* **Target Architecture**: `templates/pipelines/radar_360_decoupled_sector.yl2`
* **Telemetry Sectors**: Authentication, Cloud CRUD, Google Workspace, Network Traffic, DNS.
* **Math Model**: **Euclidean Threat Distance ($D = \sqrt{\sum_{i=1}^5 Z_i^2}$)**
* **How It Defeats the Blind Spot**:
  Even if each individual sector generates only a modest score ($Z_i pprox 2.0\sigma$), the Euclidean vector distance reveals a critical statistical outlier:
  $$D = \sqrt{2.0^2 + 2.0^2 + 2.0^2 + 2.0^2 + 2.0^2} = \sqrt{20} pprox 4.47\sigma$$
  An anomaly score of $+4.47\sigma$ represents a one-in-a-million statistical rarity, instantly prioritizing the entity for tier-1 SOC triage.

### Strategy B: Peer Group Divergence (Fleet Prevalence Shield)
* **Target Metric**: Multi-vector evaluation
* **Math Model**: `fleet_prevalence_shield.yl2`
* **How It Defeats the Blind Spot**: Compares the subject's cross-vector footprint against their immediate departmental cohort (e.g. Finance, DevOps, Legal). An individual whose multi-vector activity diverges by $\ge 3.0\sigma$ from their peers is immediately surfaced.

---

## 3. Operational Triage SLA & Chronicle Pivot
When a 360° outlier is surfaced:
1. **Correlate the Timeline**: Examine the sequential order of actions across sectors (e.g. Off-hours login $	o$ Drive file download $	o$ External network egress).
2. **Identity Context Check**: Verify HR status (e.g., flight risk, upcoming resignation, performance review) through internal channels.
