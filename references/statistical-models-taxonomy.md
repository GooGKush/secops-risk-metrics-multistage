# Statistical Models Taxonomy & Mathematical Foundations

This reference defines the mathematical formulations, operational threat translations, **"Down-to-Earth" pre-flight consultative explanations**, and **post-hunt plain-English cyber impact statements** across all 14 Stage 2 mathematical models and Multi-Stage DAG Pipeline architectures (2-Stage, 3-Stage, and 4-Stage).

---

## 🗺️ Execution Framework Summary: Built-in Anomaly Models & Security Outcomes

The Google SecOps Multi-Stage Risk Analytics Engine provides 10 distinct categories of behavioral anomaly models designed to detect malicious patterns without generating false positives on legitimate baseline shifts:

| Anomaly Archetype | Built-In Mathematical Models | Target Telemetry Vectors | Primary Security Outcome & Use Case |
| :--- | :--- | :--- | :--- |
| **1. 📈 Volumetric Surges** | `STANDARD_Z_SCORE`, `MAD` | Network Egress, File Touches, HTTP Queries | Detects data exfiltration spikes and ransomware staging while insulating against skewed distributions. |
| **2. ⚡ Automated Script Bursts** | `VARIANCE` (Fano Factor $F = \sigma^2/\mu$) | Authentication Attempts, API Calls | Distinguishes automated credential sprays and brute-force waves ($F > 4.0$) from random human typos ($F \approx 1.0$). |
| **3. 🎯 Rare & Discrete Inceptions** | `POISSON_RARITY` ($Z_P = (k-\lambda)/\sqrt{\lambda}$) | Process Launches, Admin LOLBins | Flags executions of rare tools (`powershell`, `vssadmin`) on quiet servers with near-zero expected rates ($\lambda \le 2.0$). |
| **4. 🧠 Sparse Activity Regularization** | `BAYESIAN_GAMMA`, `BAYESIAN_BETA_BINOMIAL` | Low-Volume Service Accounts, Auth Ratios | Regularizes sparse observations via 30-day prior stability, preventing false alarms on quiet accounts with low sample sizes. |
| **5. 💧 Sub-Threshold Drift Accumulation** | `LONGITUDINAL_CUSUM` ($S_t^+ = \max(0, S_{t-1}^+ + Z_t - k)$) | Network Bytes, Cloud Resource CRUD | Uncovers low-and-slow data exfiltration or privilege creeping that stays below daily $3\sigma$ alerting hurdles but accumulates massive multi-day drift. |
| **6. 🚪 Zero-Inflated Dormant Awakening** | `TWO_PART_HURDLE` | Inactive Accounts, Service Accounts | Applies a severe discrete penalty when a dormant account wakes up, while transitioning to continuous volume intensity once active. |
| **7. 🔼 One-Sided Upper-Tail Spikes** | `ASYMMETRIC_DIRECTIONAL_Z` (ReLU) | Bandwidth, File Touches, Process Runs | Concentrates risk exclusively on volumetric surges, zeroing out drops below mean so weekend quiescence never triggers false alerts. |
| **8. 🛡️ Concurrency Immunity & Suppression** | `FLEET_PREVALENCE_SHIELD`, `DUAL_BASELINE_3STAGE` | Workstation Egress, Admin Downloads | Disarms false positives during mass enterprise events (Patch Tuesday, vulnerability scans) by discounting individual scores when $>10$ hosts spike concurrently. |
| **9. 🌙 Context-Modulated Sensitivity** | `ADAPTIVE_CONTEXT_THRESHOLD` | Off-Hours Logins, Weekend Bandwidth | Dynamically tightens detection hurdles (lowering threshold from $3.0\sigma$ to $1.75\sigma$) during high-risk off-hours or quiet shifts. |
| **10. 🎯 Distortion-Proof Severity Tiering** | `PIECEWISE_CRI` (Winsorization + CRI) | Enterprise Leaderboards, Multi-Metric Hunts | Absorbs extreme mathematical blowouts on quiet accounts (Winsorized clamp) and maps raw deviations directly to deterministic SOC investigation SLAs ($0–100$). |

> [!TIP]
> **Ask for more information** if you would like a deep dive on how any of these specific models help expose behavioral outliers for your security use cases.

---

## 🧭 Pre-Flight "Down-to-Earth" Guide: How to Explain Statistical Models

Before running a multi-stage statistical hunt, explain the approach to the security practitioner using these intuitive physical analogies:

### 1. Bayesian Belief Updating (The "Seasoned SOC Detective")
> *"Traditional statistics looks at numbers in a vacuum. If a quiet host logs in once and fails once, a traditional detector flags a 100% failure rate alarm. Bayesian belief updating works like an experienced SOC investigator: it inspects 30 days of prior history to gauge how stable the host is, evaluates today's evidence, and assigns credibility weights to blend the past and present. If a host has a rock-solid history, it requires less evidence to confirm a real anomaly; if a host is normally noisy, it requires stronger evidence."*

### 2. Dual-Baseline & Fleet Prevalence (The "Patch Tuesday Storm Shelter")
> *"If an earthquake shakes an entire city, one swaying building isn't broken—the whole city moved. If Microsoft pushes Patch Tuesday or IT deploys a software agent, hundreds of workstations spike together. A single-baseline detector sounds thousands of false alarms. Our fleet-prevalence and dual-baseline models compare the host's personal spike against the concurrent fleet surge today. If the whole fleet spiked together, the alert is suppressed; if only one host spiked while the rest were quiet, it flags a targeted attack."*

### 3. Longitudinal CUSUM Drift (The "Slow Leaking Faucet")
> *"If a burglar steals a safe in broad daylight, alarms go off instantly ($Z > 4.0$). But what if an insider steals one teaspoon of water a day? Daily threshold alerts will never fire because each daily drop is within normal variance ($Z \approx 1.5$). CUSUM (Cumulative Sum Control Chart) acts like a bucket under the faucet: it allows a safe margin of daily slack ($k = 0.5\sigma$) and accumulates the remaining excess day after day. Once the bucket overflows, it flags the low-and-slow exfiltration."*

### 4. Two-Part Hurdle Model (The "Tripwire & Siphon")
> *"Imagine an abandoned storage room. If a burglar steps across the threshold, that very first step trips a sensor—regardless of how quietly they walk. That is Part 1: the discrete Bernoulli hurdle for dormant accounts. Once inside, Part 2 measures how much furniture they load onto their truck (continuous volume intensity). Combining them ensures a dormant account waking up is flagged immediately, while actively used accounts are judged by their volume deviation."*

### 5. Asymmetric Directional Z (The "One-Way Valve / ReLU")
> *"In security, anomalies aren't symmetrical. A server downloading 10x its normal data is a red alert; a server downloading 0.1x its normal data over Christmas is completely harmless. Two-tailed models sound alerts when an employee goes on vacation because their volume 'dropped significantly.' Our one-sided ReLU model behaves like a one-way electrical diode: it clamps negative deviations to zero, focusing 100% of analytical power on upper-tail malicious spikes."*

### 6. Distortion-Proof Severity Tiering (The "Shock Absorber & Incident Richter Scale")
> *"An ultra-quiet account with a tiny baseline standard deviation ($\sigma \approx 0.02$) that logs in 3 times can produce an absurd raw Z-score of $+85.0\sigma$, while a 100 GB database exfiltration on a busy server might only produce $+4.1\sigma$. If you sort by raw Z-score, trivial noise buries catastrophic breaches. This model acts as a shock absorber: it clamps extreme outliers to a sane range $[-4.0, +6.0]$ and translates deviations directly into a 0–100 Incident Richter Scale with clear SOC action playbooks."*

### 7. Adaptive Context Thresholding (The "Night Sentry")
> *"During daytime business hours, an office building has delivery trucks, visitors, and employees coming and going; security requires a high bar of suspicion ($3.0\sigma$) to avoid false alarms. But at 3:00 AM on Sunday, the same building is dead quiet. A single flashlight beam is suspicious. The adaptive context model dynamically tightens sensitivity hurdles—dropping the detection threshold from $3.0\sigma$ to $1.75\sigma$ when an account operates outside its established active schedule."*

### 8. Multi-Sector Threat Fusion (The "Combined Arms Threat Radar")
> *"Attackers don't stay in one lane: they spray passwords, run discovery tools, and exfiltrate data. If they do each step quietly, single-silo alerts never trigger. Our 4-stage pipeline calculates an orthogonal threat distance combining IAM, Endpoint, and Network signals into a single unified incident score."*

---

## 1. Parametric Standard Z-Score (`STANDARD_Z_SCORE`)
* **Security Problem Solved**: Detects abrupt volumetric explosions exceeding an entity's personal 30-day baseline.
* **Mathematical Formulation**:
  $$Z = \frac{x - \mu}{\sigma_{\text{safe}}}, \quad \sigma_{\text{safe}} = \text{if}(\sigma > 0, \sigma, 1.0)$$
* **Where**:
  * $x$: Observed 24h activity (`$stage1_extract.observed_val`)
  * $\mu$: Historical 30d mean (`$stage1_extract.historical_avg`)
  * $\sigma$: Historical 30d standard deviation (`$stage1_extract.historical_stddev`)
* **Threat Meaning**: Top $0.13\%$ statistical anomaly ($Z \ge 3.0$) on normally distributed telemetry (total logins, general process counts).
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Parametric Baseline Surge Verdict: Standard Z-Score (`[target_metric]`)**
> * **Personal Activity**: Entity `[entity]` performed **[observed]** actions today against a 30-day average of **[hist_avg]** (baseline $\sigma = [hist_stddev]$).
> * **Standardized Deviation**: **[personal_z]σ** (Peak surge ratio: **[peak_surge_ratio]×** historical max).
> * **Investigative Meaning**: Statistically confirmed volume explosion exceeding normal operational baseline by [personal_z] standard deviations.
```

---

## 2. Median Absolute Deviation (`MAD` / Modified Z-Score)
* **Security Problem Solved**: Detects volumetric surges on heavily skewed or heavy-tailed telemetry (network egress bytes, DNS volumes) where a few historic massive bulk transfers distort and inflate the standard arithmetic mean.
* **Mathematical Formulation**:
  $$\text{MAD} \approx \text{historical dispersion}, \quad \text{Dev} = |x - \mu|, \quad \text{Ratio} = \frac{\text{Dev}}{\mu_{\text{safe}}}$$
* **Where**:
  * $\mu_{\text{safe}} = \text{if}(\mu > 0, \mu, 1.0)$
* **Threat Meaning**: Robust outlier detection resilient to historic masking.
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Robust Non-Parametric Surge Verdict: MAD (`[target_metric]`)**
> * **Observed Transfer**: Entity `[entity]` transferred **[observed] bytes/events** today.
> * **Deviation Ratio**: Absolute deviation is **[ratio]×** the central baseline tendency without arithmetic distortion.
> * **Investigative Meaning**: High-confidence volume breakout on heavy-tailed telemetry that evades parametric Gaussian averaging traps.
```

---

## 3. Poisson Dispersion & Fano Factor (`VARIANCE` / `FANO_FACTOR`)
* **Security Problem Solved**: Distinguishes automated brute-force attacks and credential spraying from normal, bursty, or accidental human behavior.
* **Mathematical Formulation**:
  $$F = \frac{\sigma^2}{\lambda_{\text{safe}}}, \quad \lambda_{\text{safe}} = \text{if}(\lambda > 0, \lambda, 1.0)$$
* **Threat Meaning**:
  * $F \approx 1.0$: Memoryless random arrival (normal human typos or isolated network drops).
  * $F > 4.0$: Super-Poisson **burst clustering** (automated password sprays, botnet sweeps, brute force waves).
  * $F < 1.0$: Sub-Poisson periodic polling (robotic heartbeat / beaconing cadence).
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Automated Dispersion Verdict: Fano Factor (`[target_metric]`)**
> * **Dispersion Index (F)**: **[fano_factor]** (Historical arrival rate $\lambda \approx [lambda]$, variance $\sigma^2 \approx [variance]$).
> * **Behavioral Pattern**: Arrived in tightly synchronized, clumpy waves ($F \gg 1.0$) rather than memoryless human activity.
> * **Investigative Meaning**: Indicates automated script iteration, programmatic credential stuffing, or synchronized bot exploitation.
```

---

## 4. Discrete Poisson Rarity Score (`POISSON_RARITY`)
* **Security Problem Solved**: Quantifies the mathematical improbability of observing rare administrative actions or LOLBin executions on assets that almost never run them.
* **Mathematical Formulation**:
  $$Z_P = \frac{k - \lambda}{\sqrt{\lambda_{\text{safe}}}}, \quad \lambda_{\text{safe}} = \text{if}(\lambda > 0, \lambda, 1.0)$$
* **Threat Meaning**: Gaussian models fail on discrete low-count events ($0, 0, 1, 0$). Poisson standardized residuals accurately measure the probability of seeing $k$ events when the historical arrival rate $\lambda \le 2.0$.
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Discrete Rare Inception Verdict: Poisson Rarity (`[target_metric]`)**
> * **Execution Rarity**: Entity `[entity]` executed utility **[observed]** times today against an expected baseline arrival rate of $\lambda = [lambda]\text{ runs/day}$.
> * **Poisson Standardized Residual**: **[poisson_z]σ**.
> * **Investigative Meaning**: Extreme mathematical anomaly on a quiet asset; represents initial tool deployment or reconnaissance on an unaccustomed host.
```

---

## 5. Relative Volatility Ratio (`COEFFICIENT_OF_VARIATION`)
* **Security Problem Solved**: Evaluates whether an entity's day-to-day behavior is predictable and disciplined or erratic and unstable.
* **Mathematical Formulation**:
  $$CV = \frac{\sigma}{\mu_{\text{safe}}}, \quad \mu_{\text{safe}} = \text{if}(\mu > 0, \mu, 1.0)$$
* **Threat Meaning**:
  * $CV < 0.20$: Machine-like, highly predictable automated workload (ideal candidate for tight anomaly bounds).
  * $CV > 1.50$: Highly volatile, unpredictable human or multi-tenant system.
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Behavioral Volatility Verdict: Coefficient of Variation (`[target_metric]`)**
> * **Relative Dispersion (CV)**: **[cv]** (Mean $\mu = [hist_avg]$, StdDev $\sigma = [hist_stddev]$).
> * **Predictability State**: High baseline volatility indicates shifting operational profiles or dual-purpose usage.
```

---

## 6. Diurnal Circadian Rhythm Monitoring (`HOURLY_TEMPORAL_ZSCORE`)
* **Security Problem Solved**: Detects off-hours spikes by comparing the current hour against 30 days of that *exact same hour* (e.g. comparing 3:00 AM today against 30 days of 3:00 AM history), eliminating circadian daytime false positives.
* **Mathematical Formulation**:
  $$Z_{\text{hourly}} = \frac{x - \mu_{\text{hour}}}{\sigma_{\text{hour, safe}}}, \quad \text{Surge Ratio} = \frac{x}{\mu_{\text{hour, safe}}}$$
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Diurnal Circadian Rhythm Verdict: Hourly Temporal Z-Score (`[target_metric]`)**
> * **Hourly Deviation**: Activity during hour **[hour]** reached **[observed]** actions, exceeding the 30-day baseline for this specific hour by **[z_score_hourly]σ**.
> * **Diurnal Surge Ratio**: **[hourly_surge_ratio]×** the historical hourly expectation.
> * **Investigative Meaning**: Activity represents an acute temporal anomaly for this time of day, evading blended daily average masking.
```

---

## 7. Poisson-Gamma Bayesian Conjugacy (`BAYESIAN_GAMMA`)
* **Security Problem Solved**: Regularizes sparse arrival counts on low-volume service accounts, adjusting today's observed count using 30-day prior stability to eliminate false alarms.
* **Mathematical Derivation via Method of Moments**:
  $$\beta_0 = \frac{\mu}{\sigma^2_{\text{safe}}}, \quad \alpha_0 = \mu \cdot \beta_0$$
  $$\alpha_{\text{post}} = \alpha_0 + k, \quad \beta_{\text{post}} = \beta_0 + 1.0, \quad \mathbb{E}[\lambda \mid k] = \frac{\alpha_{\text{post}}}{\beta_{\text{post}}}$$
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Bayesian Threat Impact Verdict: Poisson-Gamma Shrinkage (`[target_metric]`)**
> * **Prior Credibility**: Baseline rate was $\mu \approx [avg_30d]\text{ actions/day}$. Prior credibility weight: **[prior_weight]%**; today's evidence weight: **[evidence_weight]%**.
> * **Adjusted Bayesian Rate**: Today's raw count of **[observed_24h]** regularized to expected posterior rate of **[posterior_mean]** (a **[bayes_shift_ratio]× belief shift**).
> * **Investigative Meaning**: Verified operational breakout backed by historical baseline stability.
```

---

## 8. Beta-Binomial Bayesian Conjugacy (`BAYESIAN_BETA_BINOMIAL`)
* **Security Problem Solved**: Prevents false alarms on low-sample failure ratios (e.g. 1 failure out of 1 login = 100% failure rate) by regularizing observed failure probabilities against historical sample variance.
* **Mathematical Formulation**:
  $$S = \frac{\bar{p}(1-\bar{p})}{\sigma_p^2} - 1, \quad \alpha_0 = \bar{p} \cdot S, \quad \beta_0 = (1-\bar{p}) \cdot S$$
  $$\hat{p}_{\text{posterior}} = \frac{\alpha_0 + k_{\text{fails}}}{\alpha_0 + \beta_0 + 1.0}$$
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Bayesian Threat Impact Verdict: Beta-Binomial Failure Rate (`[target_metric]`)**
> * **Raw vs. Regularized Rate**: Raw failure rate was **[raw_fail_prob]%** across [observed_total] attempts. Bayesian regularization adjusted this to **[posterior_fail_prob]%**.
> * **Investigative Meaning**: Sustained elevated failure probability on high volume, confirming credential spraying.
```

---

## 9. Longitudinal CUSUM Drift Accumulation (`LONGITUDINAL_CUSUM`)
* **Security Problem Solved**: Catches low-and-slow data exfiltration, stealth credential accumulation, or slow permission creep where daily activity stays below daily alert thresholds ($Z \approx 1.5\sigma$) but steadily bleeds data across 14–30 days.
* **Mathematical Formulation (Page's Half-Rectified CUSUM)**:
  $$\text{Raw Drift} = x - \mu, \quad \text{Slack } k = 0.5 \cdot \sigma_{\text{safe}}$$
  $$\text{CUSUM Increment } S_t = \max(0, (x - \mu) - k)$$
* **Where**:
  * $k = 0.5\sigma$ allows nominal enterprise fluctuation without accumulation.
  * Any daily excess above $k$ permanently increments the cumulative drift score.
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Longitudinal CUSUM Drift Verdict: Slow Leaking Faucet (`[target_metric]`)**
> * **Daily Activity**: Observed **[observed]** vs historical mean **[hist_avg]** (Daily slack allowance $k = [slack_allowance]$).
> * **Accumulated Drift Increment**: **[cusum_drift_score]** units above allowable variance.
> * **Investigative Meaning**: Sub-threshold, persistent drift pattern detected. Entity is quietly siphoning volume across multiple consecutive days without triggering single-day threshold alerts.
```

---

## 10. Two-Part Hurdle Model for Zero-Inflated Telemetry (`TWO_PART_HURDLE`)
* **Security Problem Solved**: Properly evaluates dormant accounts (dormant service accounts, offboarded contractors, backup admins) that have near-zero activity for 28 days and suddenly execute actions.
* **Mathematical Formulation**:
  * **Part 1 (Discrete Bernoulli Hurdle)**: If $\text{Active Days} \le 2$, applies immediate dormant awakening penalty:
    $$\text{Dormant Penalty} = x \cdot 2.0$$
  * **Part 2 (Continuous Conditional Intensity)**: If account is routinely active, evaluates continuous Gaussian Z-score:
    $$Z_{\text{intensity}} = \frac{x - \mu}{\sigma_{\text{safe}}}$$
  * **Composite Score**:
    $$\text{Hurdle Threat Score} = \text{if}(\text{Active Days} \le 2, \text{Dormant Penalty}, Z_{\text{intensity}})$$
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Two-Part Hurdle Verdict: Dormant Account Awakening (`[target_metric]`)**
> * **Account State**: Entity `[entity]` was active only **[active_days]** days out of 30.
> * **Hurdle Response**: Crossed the discrete dormant hurdle with **[observed]** actions, triggering an immediate tripwire threat score of **[hurdle_threat_score]**.
> * **Investigative Meaning**: Dormant account awakening detected. Represents potential compromised credential reactivation or rogue staging on an abandoned asset.
```

---

## 11. Asymmetric Directional Surge (`ASYMMETRIC_DIRECTIONAL_Z`)
* **Security Problem Solved**: Eliminates two-tailed false positives caused by harmless activity drops (e.g. employee vacation, weekend server quiescence) by using a Rectified Linear Unit (ReLU) transfer function to concentrate 100% of risk on positive surges.
* **Mathematical Formulation (ReLU Activation)**:
  $$\text{Surge} = \max(0, x - \mu) = \text{if}(x - \mu > 0, x - \mu, 0.0)$$
  $$Z_{\text{upper}} = \frac{\text{Surge}}{\sigma_{\text{safe}}}$$
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **One-Sided Surge Verdict: Asymmetric Directional Z (`[target_metric]`)**
> * **Upper-Tail Deviation**: **[upper_tail_z]σ** (Drops below baseline mean strictly clamped to 0.0).
> * **Investigative Meaning**: Confirmed one-way volumetric surge. Quiescence and activity dips are ignored; alert reflects purely malicious upward volumetric expansion.
```

---

## 12. Distortion-Proof Severity Tiering & Winsorization (`PIECEWISE_CRI`)
* **Security Problem Solved**: Prevents ultra-quiet accounts with near-zero historical variance ($\sigma \approx 0.02$) from producing astronomical Z-scores ($+85.0\sigma$) that hijack the top of the investigation queue, while mapping raw deviations directly into deterministic, SLA-bound SOC triage tiers ($0–100$).
* **Mathematical Formulation**:
  * **Step 1 (Parametric Z)**: $Z_{\text{raw}} = (x - \mu) / \sigma_{\text{safe}}$
  * **Step 2 (Winsorization Clamp)**: Clamps extreme values to $[-4.0, +6.0]$:
    $$Z_{\text{clamped}} = \max(-4.0, \min(6.0, Z_{\text{raw}}))$$
  * **Step 3 (Piecewise Linear CRI Mapping)**:
    $$\text{CRI} = \begin{cases} 95 & \text{if } Z_{\text{clamped}} \ge 4.0 \quad (\text{Critical Incident}) \\ 85 & \text{if } Z_{\text{clamped}} \ge 3.0 \quad (\text{High Severity Alert}) \\ 65 & \text{if } Z_{\text{clamped}} \ge 2.0 \quad (\text{Elevated Drift}) \\ 40 & \text{if } Z_{\text{clamped}} \ge 1.0 \quad (\text{Guarded / Emerging}) \\ 15 & \text{otherwise} \quad (\text{Nominal Noise}) \end{cases}$$
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Distortion-Proof Triage Verdict: Calibrated Risk Index (`[target_metric]`)**
> * **Raw vs. Clamped Deviation**: Raw Z-Score of **[raw_z]σ** was Winsorized to **[clamped_z]σ** to absorb low-volume variance distortion.
> * **Deterministic CRI Triage Score**: 🚨 **[cri_score] / 100** (Operational Tier: [Severity Tier]).
> * **SOC Action Playbook**: Direct match to incident SLA: [Immediate Containment / Tier-2 Investigation / 7-Day Watchlist].
```

---

## 13. Concurrency Immunity & Fleet Prevalence Discounting (`FLEET_PREVALENCE_SHIELD`)
* **Security Problem Solved**: Automatically suppresses individual false alarms during enterprise-wide mass events (e.g. Patch Tuesday OS updates, vulnerability scanner crawls, mass software rollouts) without requiring manual allowlisting.
* **Mathematical Formulation**:
  $$Z_{\text{personal}} = \frac{x - \mu}{\sigma_{\text{safe}}}$$
  $$\text{Prevalence Factor} = \text{if}(\text{Fleet Count} > 10, 0.15, 1.0)$$
  $$Z_{\text{shielded}} = Z_{\text{personal}} \cdot \text{Prevalence Factor}$$
* **Threat Meaning**: If $>10$ entities experience concurrent spikes, the activity is discounted by 85%, ensuring that only truly targeted, isolated anomalies break through to analysts.
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Fleet Concurrency Immunity Verdict: Prevalence Shield (`[target_metric]`)**
> * **Personal Spike**: Host `[entity]` exhibited a raw surge of **[personal_z]σ**.
> * **Fleet Concurrency**: **[fleet_count] hosts** concurrently spiked across the enterprise today.
> * **Shielded Risk Score**: Discounted by 85% to **[shielded_z]σ** due to high fleet prevalence.
> * **Investigative Meaning**: Activity was part of a widespread enterprise event rather than a targeted host compromise.
```

---

## 14. Context-Modulated Sensitivity Tightening (`ADAPTIVE_CONTEXT_THRESHOLD`)
* **Security Problem Solved**: Solves the dilemma between high false positives during busy business hours and delayed detections during quiet off-hours or weekend shifts.
* **Mathematical Formulation**:
  $$Z_{\text{personal}} = \frac{x - \mu}{\sigma_{\text{safe}}}$$
  $$\text{Dynamic Hurdle} = \text{if}(\text{Active Days} \le 5, 1.75, 3.00)$$
  $$\text{Sensitivity Excess} = Z_{\text{personal}} - \text{Dynamic Hurdle}$$
* **Threat Meaning**: Lowers the detection hurdle from $3.0\sigma$ during standard operations to $1.75\sigma$ when evaluating entities with sparse or off-hours operational footprints.
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Adaptive Context Sensitivity Verdict: Off-Hours Tightening (`[target_metric]`)**
> * **Operational Profile**: Entity operates on a quiet/sparse schedule ([active_days] active days).
> * **Dynamic Hurdle**: Sensitivity automatically tightened from $3.00\sigma$ to **[dynamic_threshold]σ**.
> * **Sensitivity Excess**: Exceeded adaptive threshold by **+[sensitivity_excess]σ**.
> * **Investigative Meaning**: Activity represents a critical off-hours deviation that would have been missed by static daytime alerting thresholds.
```

---

## 15. Advanced Multi-Stage DAG Pipeline Architectures

Beyond 2-stage models, the engine provides pre-composed multi-stage DAG pipelines for composite multi-sector attacks:

### 1. Dual-Baseline Delta-Z Fleet Normalization (`DUAL_BASELINE_3STAGE`)
* **Pipeline Architecture**: 3 Stages (Host Baseline $\to$ Fleet Aggregation $\to$ Root Join)
* **Formulation**: $\Delta Z = Z_{\text{Personal}} - Z_{\text{Fleet Today}}$
* **Outcome**: Isolates targeted host intrusions during enterprise-wide events.

### 2. Multi-Sector Threat Vector Fusion (`MULTI_SECTOR_FUSION_4STAGE`)
* **Pipeline Architecture**: 4 Stages (IAM Sector $\to$ Process Sector $\to$ Network Sector $\to$ Root Join)
* **Formulation**: Euclidean Threat Distance $D = \sqrt{Z_{\text{Auth}}^2 + Z_{\text{Proc}}^2 + Z_{\text{Net}}^2}$
* **Outcome**: Correlates subtle multi-vector attack steps (credential abuse + process staging + network egress) into a unified incident score.

### 3. Hierarchical Empirical Bayes (`EMPIRICAL_BAYES_3STAGE`)
* **Pipeline Architecture**: 3 Stages (Individual Host $\to$ Peer-Group Hyperpriors $\to$ Root Shrinkage)
* **Formulation**: Blends individual host history with peer-group distribution parameters ($\alpha_{\text{fleet}}, \beta_{\text{fleet}}$).
* **Outcome**: Eliminates high-variance false positives on newly onboarded or part-time employees by anchoring them to departmental norms.

---

## 16. Operational & Statistical Assumptions Guide

When communicating with analysts, SOC managers, or threat hunters, use this guide to clarify foundational assumptions:

### 1. Division-by-Zero Protection on Quiet Accounts (Clean Conditional Safeguard)
* **The Concern**: Inactive accounts have a 30-day baseline mean $\mu = 0$ and standard deviation $\sigma = 0$. In standard Z-score math, any single event triggers division-by-zero ($\frac{1 - 0}{0} = \infty$).
* **The Clarification**: The engine applies a compiler-compliant **Clean Conditional Safeguard**:
  $$\$safe\_stddev = \text{if}(\$hist\_stddev > 0, \$hist\_stddev, 1.0)$$
  This avoids division by zero, eliminates arbitrary constant inflation on noisy accounts, and provides clean mathematical grounding.

### 2. Weekend & Cyclic Seasonality Dip
* **The Concern**: Standard 30-day trailing averages blend weekdays and weekends together, even though enterprise activity drops by 70–90% on weekends.
* **The Clarification**: For non-seasonal blended baselines, Mode B (Longitudinal Sliding Timeline) breaks down activity day-by-day so analysts can directly inspect day-of-week cyclic trends, or analysts can leverage `HOURLY_TEMPORAL_ZSCORE` for diurnal profiles.

### 3. Cartesian Join Product Prevention (Multi-Stage DAG Isolation)
* **The Concern**: Why can\'t we search for creation and deletion events in a single un-staged query?
* **The Clarification**: When multiple distinct event types are matched together in a single stage, SIEM engines compute an $N \times M$ Cartesian product join (e.g. 10 creations $\times$ 5 deletions = 50 joined rows), inflating observed counts by 500%–1000% and completely discarding entities with 0 deletions. Multi-stage DAG pipelines isolate each event vector into its own stage before fusing $Z$-scores into an orthogonal threat distance.

### 4. Sparse Baseline Caution & Account Maturity ($N < 7$ Days)
* **The Concern**: Newly created accounts or ephemeral cloud workers may have only 1–2 days of historical logs.
* **The Clarification**: Calculating a Z-score on an entity with fewer than 7 active baseline days ($N < 7$) produces high statistical variance. The skill flags a **Sparse Baseline Caution** and applies Empirical Bayes shrinkage or the Two-Part Hurdle model to regularize sparse accounts.

### 5. Multi-Cloud Provider Scoping & Dimension Partitioning
* **The Concern**: Does a user\'s cloud activity in AWS affect their GCP baseline?
* **The Clarification**: Cloud lifecycle metrics enforce compound dimensions (`metadata.vendor_name`, `metadata.product_name`). This guarantees that AWS CloudTrail, GCP Cloud Audit, and Azure Activity Logs are baselined within their respective cloud provider partitions without cross-cloud contamination.
