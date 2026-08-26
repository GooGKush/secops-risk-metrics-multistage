# Statistical Models Taxonomy & Mathematical Foundations

This reference defines the mathematical formulations, operational threat translations, **"Down-to-Earth" pre-flight consultative explanations**, and **post-hunt plain-English cyber impact statements** across all Stage 2+ mathematical models and Multi-Stage DAG Pipeline architectures (2-Stage, 3-Stage, and 4-Stage).

---

## 🧭 Pre-Flight "Down-to-Earth" Guide: How to Explain Multi-Stage Statistical Analysis

Before running a multi-stage statistical hunt, explain the approach to the security practitioner using these intuitive physical analogies:

### 1. Bayesian Belief Updating (The "Seasoned SOC Detective")
> *"Traditional statistics looks at numbers in a vacuum. If a quiet host logs in once and fails once, a traditional detector flags a 100% failure rate alarm. Bayesian belief updating works like an experienced SOC investigator: it inspects 30 days of prior history to gauge how stable the host is, evaluates today's evidence, and assigns credibility weights to blend the past and present. If a host has a rock-solid history, it requires less evidence to confirm a real anomaly; if a host is normally noisy, it requires stronger evidence."*

### 2. 3-Stage Dual-Baseline Delta-$Z$ (The "Patch Tuesday Immunity Shield")
> *"If an earthquake shakes an entire city, one swaying building isn't broken—the whole city moved. If Microsoft pushes Patch Tuesday, every computer in the company downloads massive updates. A single-baseline detector sounds thousands of false alarms. Our 3-stage Dual-Baseline query compares the host's personal spike against the concurrent fleet surge today. If the whole company spiked together, the alert is suppressed; if only one host spiked while the company was quiet, it flags a targeted attack."*

### 3. 4-Stage Multi-Sector Fusion (The "Combined Arms Threat Radar")
> *"Attackers don't stay in one lane: they spray passwords, run discovery tools, and exfiltrate data. If they do each step quietly, single-silo alerts never trigger. Our 4-stage pipeline calculates an orthogonal threat distance combining IAM, Endpoint, and Network signals into a single unified incident score."*

---

## 1. Parametric Standard Z-Score (`STANDARD_Z_SCORE`)
* **Formula:**
  $$Z = \frac{x - \mu}{\sigma}$$
* **Where:**
  * $x$: Observed 24h activity (`$observed_val`)
  * $\mu$: Historical 30d mean (`$historical_avg`)
  * $\sigma$: Historical 30d stddev (`$historical_stddev`)
* **Threat Meaning:** Volume explosion exceeding personal 30-day host baseline (top $0.13\%$ tail for $Z > 3.0$).
* **Down-to-Earth Impact Statement:**
  > *"Host `[entity]` performed `[X]` actions today, exceeding its normal 30-day baseline by `[Z]` standard deviations (a 1-in-1,000 statistical rarity)."*

---

## 2. Median Absolute Deviation (`MAD` / Modified Z-Score)
* **Formula:**
  $$\text{MAD} = \text{median}(|x_i - \tilde{x}|), \quad M_Z = \frac{0.6745 \cdot (x - \tilde{x})}{\text{MAD}}$$
* **Threat Meaning:** Robust volume surge on heavily skewed data (e.g. egress network bytes, DNS) where a few massive database dumps would distort normal averages.
* **Down-to-Earth Impact Statement:**
  > *"Host `[entity]` transferred `[X] MB` today. Using median-anchored baselines, this upload breaks `[M_Z]` robust deviations above the fleet median without being skewed by large server outliers."*

---

## 3. Poisson Dispersion & Fano Factor (`VARIANCE` / `FANO_FACTOR`)
* **Formula:**
  $$F = \frac{\sigma^2}{\mu}$$
* **Threat Meaning:**
  * $F \approx 1.0$: Memoryless random arrival (normal human typos).
  * $F > 4.0$: Super-Poisson **burst clustering** (automated password sprays, brute force waves).
* **Down-to-Earth Impact Statement:**
  > *"Authentication failures for `[entity]` arrived in synchronized, clumpy waves ($F = [F]$) rather than random human typos, indicating automated script iteration."*

---

## 4. Discrete Poisson Rarity Score (`POISSON_RARITY`)
* **Formula:**
  $$Z_P = \frac{k - \lambda}{\sqrt{\lambda}}$$
* **Threat Meaning:** Mathematical improbability of seeing $k$ executions given a near-zero historical arrival rate $\lambda \le 2.0$.
* **Down-to-Earth Impact Statement:**
  > *"Sensitive utility `[process]` executed `[k]` times today on `[entity]`, an extreme mathematical anomaly on a server with an expected rate of only `[λ]` runs per day."*

---

## 5. Poisson-Gamma Bayesian Conjugacy (`BAYESIAN_GAMMA`)
* **Mathematical Derivation via Method of Moments**:
  In a Gamma distribution $\text{Gamma}(\alpha_0, \beta_0)$, $\mathbb{E}[\lambda] = \frac{\alpha_0}{\beta_0} = \mu$ and $\text{Var}(\lambda) = \frac{\alpha_0}{\beta_0^2} = \sigma^2$.
  $$\beta_0 = \frac{\mu}{\sigma^2} = \frac{\$avg\_30d}{\$variance\_30d}, \quad \alpha_0 = \mu \cdot \beta_0 = \frac{\mu^2}{\sigma^2}$$
* **Posterior Updating (Evidence $k = \$observed\_24h$, $t = 1\text{ day}$)**:
  $$\alpha_{\text{post}} = \alpha_0 + k, \quad \beta_{\text{post}} = \beta_0 + 1.0$$
* **Posterior Expected Rate (Bayesian Shrinkage Mean)**:
  $$\mathbb{E}[\lambda \mid k] = \frac{\alpha_{\text{post}}}{\beta_{\text{post}}} = \left(\frac{\beta_0}{\beta_0 + 1}\right)\mu + \left(\frac{1}{\beta_0 + 1}\right)k$$
* **Credibility Weights**:
  $$\text{Prior Weight} = \frac{\beta_0}{\beta_0 + 1}, \quad \text{Evidence Weight} = \frac{1}{\beta_0 + 1}$$

### Post-Hunt Plain-English Cyber Impact Statement Template:
```markdown
> [!IMPORTANT]
> **Bayesian Threat Impact Verdict: Poisson-Gamma Shrinkage**
> * **Prior Baseline Confidence**: Historical baseline rate was $\mu \approx [avg\_30d]\text{ reqs/day}$ with variance $\sigma^2 \approx [variance\_30d]$. The model assigned **[prior_weight]% credibility** to historical habits and **[evidence_weight]% credibility** to today's activity.
> * **Adjusted Bayesian Rate**: Today's raw count of **[observed_24h]** was regularized to an expected posterior rate of **[posterior_mean]** (a **[bayes_shift_ratio]× belief shift**).
> * **Investigative Meaning**: Because this host has historically stable behavior, the observed surge represents a genuine operational breakout rather than background noise.
```

---

## 6. Beta-Binomial Bayesian Conjugacy (`BAYESIAN_BETA_BINOMIAL`)
* **Mathematical Formulation**:
  Models failure ratios (e.g. failed auth attempts / total attempts) where $p \sim \text{Beta}(\alpha_0, \beta_0)$.
  $$\text{Sample Factor } S = \frac{\bar{p}(1-\bar{p})}{\sigma_p^2} - 1, \quad \alpha_0 = \bar{p} \cdot S, \quad \beta_0 = (1-\bar{p}) \cdot S$$
  $$\alpha_{\text{post}} = \alpha_0 + k_{\text{fails}}, \quad \beta_{\text{post}} = \beta_0 + (N_{\text{total}} - k_{\text{fails}}), \quad \hat{p}_{\text{posterior}} = \frac{\alpha_{\text{post}}}{\alpha_{\text{post}} + \beta_{\text{post}}}$$

### Post-Hunt Plain-English Cyber Impact Statement Template:
```markdown
> [!IMPORTANT]
> **Bayesian Threat Impact Verdict: Beta-Binomial Ratio Regularization**
> * **Raw vs. Regularized Rate**: Observed raw failure rate was **[raw_fail_prob]%** across [observed_total] events. Bayesian shrinkage adjusted this to **[posterior_fail_prob]%** by accounting for sample size.
> * **Investigative Meaning**: High-confidence password spraying indicator: high volume coupled with sustained elevated failure probability.
```

---

## 7. Dual-Baseline Delta-Z Fleet Normalization (`DUAL_BASELINE_3STAGE`)
* **Pipeline Architecture**: 3 Stages
  * Stage 1: Individual host 24h activity + 30d personal metric baseline.
  * Stage 2: Cross-sectional aggregation across all endpoints active today ($\mu_{\text{fleet Today}}, \sigma_{\text{fleet Today}}$).
  * Stage 3 (Root): Computes $\Delta Z = Z_{\text{Personal}} - Z_{\text{Fleet Today}}$.
* **Mathematical Formulation**:
  $$Z_{\text{Personal}} = \frac{x_i - \mu_{i, 30\text{d}}}{\sigma_{i, 30\text{d}}}, \quad Z_{\text{Fleet}} = \frac{x_i - \mu_{\text{fleet Today}}}{\sigma_{\text{fleet Today}}}$$
  $$\Delta Z = Z_{\text{Personal}} - Z_{\text{Fleet}}$$
* **Threat Meaning**: Filters out macro company-wide events (Patch Tuesday, cloud outages) and isolates targeted intrusions.

### Post-Hunt Plain-English Cyber Impact Statement Template:
```markdown
> [!IMPORTANT]
> **Dual-Baseline Threat Verdict: Fleet-Normalized Delta-Z (`[target_metric]`)**
> * **Personal vs. Fleet Shift**: Host `[entity]` had a personal surge of **[personal_z]σ**, while the fleet average shift was **[fleet_z]σ**.
> * **Isolated Anomaly Score (ΔZ)**: **[delta_z]σ**.
> * **Investigative Meaning**: Confirms that this anomaly is unique to `[entity]` and not an artifact of an organization-wide software deployment.
```

---

## 8. Multi-Sector Threat Vector Fusion (`MULTI_SECTOR_FUSION_4STAGE`)
* **Pipeline Architecture**: 4 Stages
  * Stage 1: Authentication / IAM Sector (`metrics.auth_attempts_fail` $\implies Z_{\text{Auth}}$)
  * Stage 2: Endpoint / Process Sector (`metrics.file_executions_total` $\implies Z_{\text{Proc}}$)
  * Stage 3: Network / Egress Sector (`metrics.network_bytes_outbound` $\implies Z_{\text{Net}}$)
  * Stage 4 (Root): Joins on `$host` and computes the Euclidean Threat Distance ($D$).
* **Mathematical Formulation**:
  $$\text{Composite Threat Norm } D = \sqrt{Z_{\text{Auth}}^2 + Z_{\text{Proc}}^2 + Z_{\text{Net}}^2}$$
* **Threat Meaning**: Fuses subtle elevations across multiple attack stages into a high-confidence incident score.

### Post-Hunt Plain-English Cyber Impact Statement Template:
```markdown
> [!IMPORTANT]
> **Multi-Sector Threat Fusion Verdict: Composite Threat Distance D**
> * **Sector Breakdown**: Auth Anomaly: **[z_auth]σ** | Process Execution: **[z_proc]σ** | Network Egress: **[z_net]σ**.
> * **Composite Threat Distance (D)**: 🚨 **[threat_norm]σ** (exceeds multi-sector threshold of 3.0σ).
> * **Investigative Meaning**: Coordinated full-killchain intrusion: credential access followed by anomalous execution and network egress staging.
```

---

## 9. Hierarchical Empirical Bayes (`EMPIRICAL_BAYES_3STAGE`)
* **Pipeline Architecture**: 3 Stages
  * Stage 1: Individual host extraction with 30d personal metric.
  * Stage 2: Peer-group hyperprior pooling ($\alpha_{\text{fleet}} = \frac{\mu_{\text{fleet}}^2}{\sigma_{\text{fleet}}^2}, \beta_{\text{fleet}} = \frac{\mu_{\text{fleet}}}{\sigma_{\text{fleet}}^2}$).
  * Stage 3 (Root): James-Stein shrinkage blending host personal baseline with peer-group hyperpriors.
* **Threat Meaning**: Provides robust, noise-free baselining for sparse, newly added, or part-time employee endpoints.

---

## 10. Operational & Statistical Assumptions Guide

When communicating with analysts, SOC managers, or threat hunters, use this guide to clarify the foundational assumptions underlying behavioral risk baselining:

### 1. Division-by-Zero Protection on Quiet Accounts (Dispersion Floor)
* **The Concern**: Inactive accounts or quiet service accounts have a 30-day baseline mean $\mu = 0$ and standard deviation $\sigma = 0$. In standard Z-score math, any single event would cause division-by-zero ($\frac{1 - 0}{0} = \infty$).
* **The Clarification**: The pipeline applies a **Dispersion Floor ($\sigma_{\text{floor}} = 1.0$)** in the denominator:
  $$Z = \frac{\text{Observed} - \mu}{\sigma + 1.0}$$
  This bounds nominal activity, prevents infinite false positives on quiet accounts, and smoothly scales with event volume.

### 2. Weekend & Cyclic Seasonality Dip
* **The Concern**: Standard 30-day trailing averages blend weekdays and weekends together, even though enterprise activity drops by 70–90% on weekends.
* **The Clarification**: For non-seasonal blended baselines, a normal Monday morning may appear mildly elevated, while a Sunday night anomaly might appear less severe. Mode B (Longitudinal Sliding Timeline) breaks down activity day-by-day so analysts can directly inspect day-of-week cyclic trends.

### 3. Cartesian Join Product Prevention (Multi-Stage DAG Isolation)
* **The Concern**: Why can't we search for creation and deletion events in a single un-staged query?
* **The Clarification**: When multiple distinct event types are matched together in a single stage, SIEM engines compute an $N \times M$ Cartesian product join (e.g. 10 creations $\times$ 5 deletions = 50 joined rows), inflating observed counts by 500%–1000% and completely discarding entities with 0 deletions. Multi-stage DAG pipelines isolate each event vector into its own stage before fusing $Z$-scores into a 2D Euclidean Threat Distance ($D$).

### 4. Sparse Baseline Caution & Account Maturity ($N < 7$ Days)
* **The Concern**: Newly created accounts or ephemeral cloud workers may have only 1–2 days of historical logs.
* **The Clarification**: Calculating a Z-score on an entity with fewer than 7 active baseline days ($N < 7$) produces high statistical variance. The skill flags a **Sparse Baseline Caution** and applies Empirical Bayes shrinkage to regularize sparse accounts toward their peer-group norm.

### 5. Multi-Cloud Provider Scoping & Dimension Partitioning
* **The Concern**: Does a user's cloud activity in AWS affect their GCP baseline?
* **The Clarification**: Cloud lifecycle metrics enforce compound dimensions (`metadata.vendor_name`, `metadata.product_name`). This guarantees that AWS CloudTrail, GCP Cloud Audit, and Azure Activity Logs are baselined within their respective cloud provider partitions without cross-cloud contamination.

---

## 11. End-User Guide: Understanding the Calibrated Risk Index (CRI)

The **Calibrated Risk Index (CRI)** is a standardized **0 to 100 risk score** designed to bridge the gap between complex multi-dimensional statistics and actionable SOC operations.

### 1. What is the Calibrated Risk Index (CRI)?
Raw statistical metrics (such as Z-scores or Euclidean threat norms $D$) can range from $-\infty$ to $+\infty$. While a mathematician understands that $D = 4.2\sigma$ on 3 degrees of freedom is rare, a SOC analyst or ticketing system needs a clear, normalized rating to prioritize investigations.

CRI applies a logistic sigmoid transfer function that maps multi-vector statistical distance ($D$) onto a bounded **0–100 scale**:

$$\text{CRI} = \text{round}\left(\frac{100}{1 + \exp(-0.6 \cdot (D - 3.0))}\right)$$

### 2. The 4-Tier Operational Triage Scale

| CRI Score Range | Severity Tier | Statistical Meaning | SOC Action Playbook |
| :--- | :--- | :--- | :--- |
| **85 – 100** | 🔴 **CRITICAL** | Extreme outlier ($D \ge 6.0\sigma$) or multi-stage coordinated killchain. | **Immediate Containment**: Revoke session tokens, isolate host, escalate to Incident Response. |
| **50 – 84** | 🟠 **HIGH** | Statistically confirmed breach of the $3.0\sigma$ boundary ($p < 0.0013$). | **Tier-2 SOC Investigation**: Triage process lineage, check lateral movement, review egress destinations. |
| **30 – 49** | 🟡 **ELEVATED** | Noticeable behavioral drift ($D \approx 2.0–2.9\sigma$) or emerging shift. | **Watchlist & Trend Tracking**: Add entity to 7-day observation queue; correlate with low-severity alerts. |
| **0 – 29** | 🟢 **NOMINAL** | Routine enterprise baseline variance ($D < 2.0\sigma$). | **Noise Suppression**: Normal activity; no analyst intervention required. |

### 3. Key Operational Benefits of CRI
1. **Universal Currency**: Normalizes all mathematical models (1-stage $Z$-score, 3-stage Delta-$Z$, 4-stage Multi-Sector Fusion) into an identical 0–100 ranking.
2. **SOAR & Playbook Integration**: Provides deterministic thresholds (`if CRI >= 85`) for automated ticket creation and SOAR orchestration.
3. **Asymptotic Protection**: Prevents quiet accounts with massive raw $Z$-scores (e.g. $+100\sigma$) from breaking visualization charts or overflowing dashboard scales.
