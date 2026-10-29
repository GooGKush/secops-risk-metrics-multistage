# Statistical Models Taxonomy & Mathematical Foundations

This reference defines the mathematical formulations, operational threat translations, **"Down-to-Earth" pre-flight consultative explanations**, and **post-hunt plain-English cyber impact statements** across all 17 Stage 2 mathematical models and Multi-Stage DAG Pipeline architectures (2-Stage, 3-Stage, and 4-Stage).

---

## 🗺️ Execution Framework Summary: Built-in Anomaly Models & Security Outcomes

The Google SecOps Multi-Stage Risk Analytics Engine provides 12 distinct categories of behavioral anomaly models designed to detect malicious patterns without generating false positives on legitimate baseline shifts:

| Anomaly Archetype | Built-In Mathematical Models | Target Telemetry Vectors | Primary Security Outcome & Use Case |
| :--- | :--- | :--- | :--- |
| **1. 📈 Volumetric Surges** | `STANDARD_Z_SCORE`, `MAD`, `QUANTILE_IQR_SKEW` | Network Egress, File Touches, HTTP Queries | Detects data exfiltration spikes and ransomware staging while insulating against skewed distributions. |
| **2. ⚡ Automated Script Bursts** | `VARIANCE` (Fano Factor $F = \sigma^2/\mu$) | Authentication Attempts, API Calls | Distinguishes automated credential sprays and brute-force waves ($F > 4.0$) from random human typos ($F \approx 1.0$). |
| **3. 🎯 Rare & Discrete Inceptions** | `POISSON_RARITY` ($Z_P = (k-\lambda)/\sqrt{\lambda}$) | Process Launches, Admin LOLBins | Flags executions of rare tools (`powershell`, `vssadmin`) on quiet servers with near-zero expected rates ($\lambda \le 2.0$). |
| **4. 🧠 Sparse Activity Regularization** | `BAYESIAN_GAMMA`, `BAYESIAN_BETA_BINOMIAL` | Low-Volume Service Accounts, Auth Ratios | Regularizes sparse observations via 30-day prior stability, preventing false alarms on quiet accounts with low sample sizes. |
| **5. 💧 Sub-Threshold Drift Accumulation** | `LONGITUDINAL_CUSUM` ($S_t^+ = \max(0, S_{t-1}^+ + Z_t - k)$) | Network Bytes, Cloud Resource CRUD | Uncovers low-and-slow data exfiltration or privilege creeping that stays below daily $3\sigma$ alerting hurdles but accumulates massive multi-day drift. |
| **6. 🚪 Zero-Inflated Dormant Awakening** | `TWO_PART_HURDLE` | Inactive Accounts, Service Accounts | Applies a severe discrete penalty when a dormant account wakes up, while transitioning to continuous volume intensity once active. |
| **7. 🔼 One-Sided Upper-Tail Spikes** | `STANDARD_Z_SCORE` (merged `ASYMMETRIC_DIRECTIONAL_Z`) | Bandwidth, File Touches, Process Runs | Upper-tail positive $Z \ge 3.0$ concentrates risk exclusively on volumetric surges so weekend quiescence never triggers alerts. |
| **8. 🛡️ Concurrency Immunity & Suppression** | `HYBRID_METRIC_FLEET_PREVALENCE_2STAGE`, `DUAL_BASELINE_3STAGE` | Process Executions, Workstation Egress | Disarms false positives during enterprise rollouts via token-scoped `DERIVED_CONTEXT` prevalence or fleet-wide $\Delta Z = Z_{\text{personal}} - Z_{\text{fleet}}$. |
| **9. 🌙 Context-Modulated Sensitivity** | `ADAPTIVE_CONTEXT_THRESHOLD` | Off-Hours Logins, Weekend Bandwidth | Dynamically tightens detection hurdles (lowering threshold from $3.0\sigma$ to $1.75\sigma$) during high-risk off-hours or quiet shifts. |
| **10. 🎯 Calibrated Severity Tiering** | `ueba_constants.calculate_cri` *(retired `PIECEWISE_CRI`)* | Post-Query Triage Reporting | Translates standardized deviations into canonical $[0, 100]$ SOC severity bands in Python reporting (`WS7-01`). |
| **11. 🚀 Above-Historical-Max Z** | `MACD_MOMENTUM_VELOCITY` ($Z_{\text{personal}} + Z_{\text{above\_max}}$) | Network Egress, Auth Attempts, DNS Volumes | Catches linear peak exceedance where today's volume breaks out beyond both the 30-day mean and the 30-day historical maximum. |
| **12. ⏰ Per-Hour-of-Day Profiling** | Handoff to `HOUR_OF_DAY_PROFILE` *(retired `CIRCADIAN_VON_MISES`)* | Off-Hours Authentication, Weekend Bandwidth | Hands off sub-day temporal profiling to `secops-statistical-hunter` `HOUR_OF_DAY_PROFILE` (`D1` / `PF-10`). |

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
> *"Attackers don't stay in one lane: they spray passwords, resolve odd domains, and exfiltrate data. If they do each step quietly, single-silo alerts never trigger. Our 4-stage pipeline calculates an orthogonal threat distance combining two signals for the same user or host (for example IAM and Network, or DNS and Web) into a single unified incident score."*

### 9. MACD Dual-Spine Momentum (The "Highway Speedometer vs Cruise Control")
> *"Cruise control keeps a car at 65 MPH. If the car gradually climbs a gentle hill, the speedometer nudges slightly ($Z \approx 1.2$). But if the driver stomps on the accelerator and blasts past 110 MPH, the instantaneous needle flies completely away from the historical cruise setting. The MACD Dual-Spine model compares today's fast speed needle against the slow 30-day cruise setting and past speed records. If today's acceleration breaks past the historical maximum, it flags high-velocity momentum divergence."*

### 10. Circadian von Mises Temporal Distance (The "24-Hour Circular Clock Face")
> *"If you use standard grade-school subtraction on time, 11:00 PM (23:00) and 1:00 AM (01:00) look 22 hours apart ($|23 - 1| = 22$). But on a round wall clock, they are right next to each other—only 2 hours apart! Linear math fails completely on time of day. The von Mises model treats time like a circular clock face. It measures the shortest arc distance around the circle and applies quadratic scaling, smoothly penalizing actions that occur far away from an entity's normal daytime hours (like 3:00 AM) while treating 11:00 PM and 1:00 AM as natural neighbors."*

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
* **Mathematical Formulation** (Iglewicz & Hoaglin):
  $$\tilde{x} = \text{median}(x_d), \quad \text{MAD} = \text{median}(|x_d - \tilde{x}|), \quad M_z = \frac{x - \tilde{x}}{\text{MAD}/0.6745}$$
* **Where**:
  * $x_d$ = the entity's daily values over the raw search window (~30d); computed natively with `window.median(..., false)` in stages `mad_center` → `mad_spread` (`stage2_math_models/mad.yl2`).
  * MAD $= 0$ → scale $= 1.253314 \cdot \text{meanAD}$; both $0$ → $0.05\,\tilde{x} + 1$.
  * Significance: $M_z \ge 3.5$. Reported next to the 30d metrics $Z$; `$z_gap` $= M_z - Z$.
* **Threat Meaning**: Robust outlier detection resilient to historic masking (50% breakdown point). A large positive `$z_gap` means past bursts inflated the 30d mean/stddev and the classical $Z$ was hiding the anomaly.
* **Related, NOT MAD**: `RELATIVE_DEVIATION` (`relative_deviation.yl2`) reports the fold change $(x-\mu)/\mu$ against the 30d mean.
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Robust Non-Parametric Surge Verdict: MAD (`[target_metric]`)**
> * **Observed Transfer**: Entity `[entity]` transferred **[observed] bytes/events** today.
> * **Robust Deviation**: **[modified_z]** robust σ above the 30-day median of **[median_val]** (MAD = **[mad]**), versus a classical **[personal_z]σ** against the 30-day mean (gap **[z_gap]**).
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

## 5. Regular-Volume Surge (`COEFFICIENT_OF_VARIATION`)
* **Security Problem Solved**: Detects fold-change volume surges (`$surge_ratio >= 2.0`) specifically on entities with regular, predictable day-to-day baselines (`$cv <= 0.5`).
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

## 6. Intra-Day Hourly Burst Localization (`HOURLY_TEMPORAL_ZSCORE`)
* **Security Problem Solved**: Pinpoints the exact 1-hour window (`by 1h`) of an intra-day volumetric burst while anchoring against the entity's 30-day macro baseline (`period: 1d, window: 30d` — the only `period`/`window` granularity supported by `metrics.*`). For true 24-hour clock phase-shift scoring around peak operating hours, pair with `CIRCADIAN_VON_MISES` (`circadian_von_mises_2stage.yl2`).
* **Mathematical Formulation**:
  $$Z_{\text{hourly}} = \frac{x_{\text{hour}} - \mu_{\text{baseline}}}{\sigma_{\text{baseline, safe}}}, \quad \text{Surge Ratio} = \frac{x_{\text{hour}}}{\mu_{\text{baseline, safe}}}$$
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
* **Security Problem Solved**: Prevents false alarms on low-sample failure probabilities by regularizing observed failure rates against historical prior stability. *(Note: Pre-computed `metrics.*_fail` tables store daily failure counts (`event_count_sum`) rather than pre-normalized $[0, 1]$ probabilities; when baselining failure-to-total ratios across `*_fail` and `*_total` metric families, use `http_error_ratio_surge_2stage.yl2` / `build_failure_ratio_surge_query()` or clamp $\bar{p} \in (0, 1)$ before Method-of-Moments prior estimation.)*
* **Mathematical Formulation**:
  $$S = \max\left(1.0, \frac{\bar{p}(1-\bar{p})}{\sigma_p^2} - 1\right), \quad \alpha_0 = \bar{p} \cdot S, \quad \beta_0 = (1-\bar{p}) \cdot S$$
  $$\hat{p}_{\text{posterior}} = \frac{\alpha_0 + k_{\text{fails}}}{\alpha_0 + \beta_0 + n_{\text{trials}}}$$
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Bayesian Threat Impact Verdict: Beta-Binomial Failure Rate (`[target_metric]`)**
> * **Raw vs. Regularized Rate**: Raw failure rate was **[raw_fail_prob]%** across [observed_total] attempts. Bayesian regularization adjusted this to **[posterior_fail_prob]%**.
> * **Investigative Meaning**: Sustained elevated failure probability on high volume, confirming credential spraying.
```

---

## 9. Longitudinal CUSUM Drift Accumulation (`LONGITUDINAL_CUSUM`)
* **Security Problem Solved**: Catches low-and-slow data exfiltration, stealth credential accumulation, or slow permission creep where daily activity stays below single-day alert thresholds ($Z \approx 1.5\sigma$) but steadily bleeds data across multiple days (one YARA-L CUSUM request covers up to 14 days, the multi-stage search limit).
* **Mathematical Formulation**:
  * **Single-Stage / Per-Bucket Slack Excess (`templates/stage2_math_models/longitudinal_cusum.yl2`)**:
    $$\text{Raw Drift} = x - \mu, \quad \text{Slack } k = 0.5 \cdot \sigma_{\text{safe}}, \quad \text{Daily Slack Excess} = \max(0, (x - \mu) - k)$$
  * **Multi-Day Windowed Slack Sum (`templates/pipelines/longitudinal_drift_cusum_2stage.yl2`, via `window.sum($daily_drift)`)**:
    $$Z_d = \frac{x_d - \mu}{\sigma_{\text{safe}}}, \quad \Delta_d = \max(0, Z_d - 0.5), \quad S_{\text{window}} = \sum_{d=1}^{D} \Delta_d$$
  * **Sequential Page's CUSUM in Mode C (`scripts/timeline_assembler.py`)**:
    $$S_t^+ = \max(0, S_{t-1}^+ + Z_t - k) \quad \text{across ordered daily shards}$$
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

## 11. Asymmetric Directional Surge (`ASYMMETRIC_DIRECTIONAL_Z` — Merged into `STANDARD_Z_SCORE` under `D1`)
* **Status**: Merged into `STANDARD_Z_SCORE` (`standard_z_score.yl2`) under `D1` because upper-tail positive thresholding (`$personal_z >= 3.0`) already ignores negative deviations.

---

## 12. Calibrated Risk Index (`PIECEWISE_CRI` — Retired from YARA-L under `D1`)
* **Status**: `piecewise_cri.yl2` is retired under `D1`. Calibrated Risk Index (`CRI`) is computed canonically in Python post-processing via `ueba_constants.calculate_cri` (`WS7-01`).

---

## 13. Fleet Prevalence Normalization (`FLEET_PREVALENCE_SHIELD` — Retired under `D1`)
* **Status**: Single-plane `fleet_prevalence_shield.yl2` is retired under `D1`; use token-scoped `hybrid_metric_fleet_prevalence_2stage.yl2` (`HYBRID_METRIC_FLEET_PREVALENCE_2STAGE`) or `dual_baseline_delta_z_3stage.yl2` (`DUAL_BASELINE_3STAGE`).

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

## 15. Above-Historical-Max Z (`MACD_MOMENTUM_VELOCITY`)
* **Security Problem Solved**: Detects linear peak exceedance where today's volume breaks out above both the 30-day baseline mean and the 30-day historical maximum without quadratic byte overflow.
* **Mathematical Formulation**:
  $$Z_{\text{personal}} = \frac{x_{\text{observed}} - \mu_{\text{30d}}}{\sigma_{\text{safe}}}, \quad Z_{\text{above\_max}} = \frac{\max(0, x_{\text{observed}} - x_{\text{max,30d}})}{\sigma_{\text{safe}}}, \quad Z_{\text{macd}} = Z_{\text{personal}} + Z_{\text{above\_max}}$$

---

## 16. Circadian von Mises Temporal Distance (`CIRCADIAN_VON_MISES`)
* **Security Problem Solved**: Evaluates events across a 24-hour circular clock face to penalize off-hours and night-shift departures without circular boundary wrap distortion.
* **Mathematical Formulation**:
  $$H = \texttt{timestamp.get\_hour}(t_{\text{ws}})$$
  $$\Delta H = |H - H_{\text{peak}}|, \quad \text{where } H_{\text{peak}} = 14 \text{ (2:00 PM UTC baseline anchor)}$$
  $$D_{\text{circ}} = \text{if}(\Delta H > 12, 24 - \Delta H, \Delta H)$$
  $$\text{Von Mises Arc Penalty} = \frac{D_{\text{circ}}^2}{72.0}$$
  $$\text{Circadian Threat Score} = Z_{\text{hourly}} \times (1.0 + \text{Von Mises Arc Penalty})$$
* **Where**:
  * $t_{\text{ws}}$: Bucket start timestamp (`$ws`, UTC)
  * $Z_{\text{hourly}} = \frac{x_{\text{hour}} - \mu_{\text{hour}}}{\sigma_{\text{safe}}}$
  * Maximum possible circular distance $D_{\text{circ}} = 12$ hours (at opposite polarity, penalty multiplier = $1.0 + \frac{144}{72} = 3.0\times$).
* **Threat Meaning**: Smoothly scales volumetric surges according to their temporal improbability on a cyclic 24-hour clock. An egress spike at 3:00 AM receives a $3.0\times$ multiplier penalty, while an identical spike at 2:00 PM receives a neutral $1.0\times$ multiplier.
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Circadian Temporal Distance Verdict: Off-Hours von Mises Departure (`[target_metric]`)**
> * **Hourly Observation**: Entity `[entity]` executed **[observed_hour]** events during hour **[event_hour]:00 UTC** against baseline average of **[avg_hourly]**.
> * **Circular Clock Distance**: **[circ_dist] hours** away from normal 14:00 UTC operational peak.
> * **Temporal Penalty**: Quadratic von Mises multiplier of **[temporal_multiplier]×**.
> * **Combined Threat Score**: **[circadian_threat_score]** (Hourly $Z = [hourly_z]\sigma$).
> * **Investigative Meaning**: High-confidence volumetric departure occurring at an anomalous circadian phase, indicating unauthorized off-hours operation or compromised credential replay from an opposing timezone.
```

---

## 17. Relative Deviation / Fold Change (`RELATIVE_DEVIATION`)
* **Security Problem Solved**: Computes a scale-free relative deviation $(x - \mu)/\mu$ and fold change $x/\mu$ ("3.2× the 30-day average") for straightforward executive and SOC communication when standard deviation is noisy or unintuitive. *(Formerly mislabelled MAD prior to v1.8.3; mean-anchored with 0% breakdown point.)*
* **Mathematical Formulation**:
  $$\text{Relative Deviation} = \frac{x - \mu}{\mu_{\text{safe}}}, \quad \text{Fold Change} = \frac{x}{\mu_{\text{safe}}}, \quad \mu_{\text{safe}} = \text{if}(\mu > 0, \mu, 1.0)$$


---

## 17B. 1-Stage Non-Parametric Quantiles, Bowley Skewness & Skew-Adjusted Tukey Scale-Excess (`QUANTILE_IQR_SKEW`)
* **Security Problem Solved**: Computes a 5-point empirical quantile envelope ($P_{10}, Q_{25}, Q_{50}, Q_{75}, P_{90}$) in **1 intermediate stage** (`stage quantile_envelope` via `window.percentile`) instead of the 2 stages required by `MAD` (`mad_center` $\to$ `mad_spread`), saving a full stage and join slot for Entity Context Graph (`DERIVED_CONTEXT` / `GLOBAL_CONTEXT`) or peer-cohort enrichment while adjusting the Tukey upper fence for right-skewed baselines.
* **Mathematical Formulation** (Bowley 1920; Moors 1988; Hubert & Vandervieren 2008 recalibrated for Bowley $B_{\text{skew}} \in [-1, +1]$):
  $$\text{IQR} = Q_{75} - Q_{25}, \quad B_{\text{skew}} = \frac{Q_{75} + Q_{25} - 2 Q_{50}}{\text{IQR}_{\text{safe}}}, \quad T_{\text{ratio}} = \frac{P_{90} - P_{10}}{\text{IQR}_{\text{safe}}}$$
  $$\text{Fence}_{\text{adj}} = Q_{75} + 1.5 \cdot e^{1.35 \cdot \max(0, B_{\text{skew}})} \cdot \text{IQR}_{\text{safe}}, \quad \sigma_{\text{IQR}} = \frac{\text{IQR}_{\text{safe}}}{1.349}, \quad Z_{\text{excess}} = \frac{x - \text{Fence}_{\text{adj}}}{\sigma_{\text{IQR}}}$$
* **Threat Meaning**: Flags heavy-tailed breakouts (`$tukey_excess_z >= 1.0`) alongside the pre-scoring raw active-day `$personal_z` cross-check (`WS1-03`) without near-zero fence-ratio blowups or uncalibrated medcouple exponential inflation.

---

## 18. Advanced Multi-Stage DAG Pipeline Architectures

Beyond 2-stage models, the engine provides pre-composed multi-stage DAG pipelines for composite multi-sector attacks:

### 1. Dual-Baseline Delta-Z Fleet Normalization (`DUAL_BASELINE_3STAGE`)
* **Pipeline Architecture**: 3 Stages (Host Baseline $\to$ Fleet Aggregation $\to$ Root Join)
* **Formulation**: $\Delta Z = Z_{\text{Personal}} - Z_{\text{Fleet Today}}$
* **Outcome**: Isolates targeted host intrusions during enterprise-wide events.

### 2. Multi-Sector Threat Vector Fusion (`MULTI_SECTOR_FUSION_4STAGE`)
* **Pipeline Architecture**: 4 Stages (Sector A [UDM #1] $\to$ Sector B [UDM #2] $\to$ Cross-Sectional Fleet Normalization [Stage-to-Stage] $\to$ Root Join, respecting `SourceCount["udm"] <= 2`). Sectors are any two fusion-capable metrics that share the same entity identifier (see `references/metric-sector-catalog.md`); the router default is `auth_attempts_fail` + `network_bytes_outbound`.
* **Formulation**: Rectified Euclidean Threat Distance $D^2 = \max(0, Z_A)^2 + \max(0, Z_B)^2 + \max(0, \Delta Z_A)^2 + \max(0, \Delta Z_B)^2$
* **Outcome**: Correlates two attack steps on the same entity (e.g. DNS failures + HTTP volume, HTTP volume + outbound bytes, auth failures + outbound bytes) with cross-sectional fleet normalization into a unified incident score. User and host sectors are never mixed.

### 3. Hierarchical Empirical Bayes (`EMPIRICAL_BAYES_3STAGE`)
* **Pipeline Architecture**: 3 Stages (Individual Host $\to$ Peer-Group Hyperpriors $\to$ Root Shrinkage)
* **Formulation**: Blends individual host history with peer-group distribution parameters ($\alpha_{\text{fleet}}, \beta_{\text{fleet}}$).
* **Outcome**: Eliminates high-variance false positives on newly onboarded or part-time employees by anchoring them to departmental norms.

### 4. Entity Context Graph (ECG) Hybrid Archetypes (`DERIVED_CONTEXT` & `GLOBAL_CONTEXT`)
* **Pipeline Architectures**: 2–3 Stages (Macro Baseline $\to$ Entity Context Graph Lookup $\to$ Root Risk Fusion)
* **Formulation**: Fuses universal macro $Z$-score with persistent enterprise prevalence and threat intelligence:
  - **Derived File Prevalence** (`hybrid_metric_derived_file_prevalence_2stage.yl2`): Keeps only rare binaries (`rolling_max <= 3`, `day_count = 10`), which drops rollout binaries ($Z \times M_{\text{rare}}$). Normalizing a surge against a rollout is `hybrid_metric_fleet_prevalence_2stage.yl2`.
  - **Derived Domain Prevalence** (`hybrid_metric_derived_domain_prevalence_2stage.yl2`): Sifts novel HTTP destinations by request count and prunes enterprise SaaS/CDN noise ($Z \times M_{\text{rare}}$). DNS volume, bytes, or any other measure against rare domains is `rare_destination_ecg_3stage.yl2`.
  - **WHOIS Domain Lifecycle** (`hybrid_metric_whois_domain_lifecycle_2stage.yl2`): Detects high-volume egress to Newly Registered Domains ($Z \times 2.5$ for NRD $\le 30\text{d}$) and expired domain infrastructure ($Z \times 3.0$ for lapsed certs/registrations).
  - **Derived Asset Age** (`hybrid_metric_derived_asset_age_2stage.yl2`): Sifts infant endpoints ($< 7$ days old) experiencing immediate volumetric departures ($Z \times 2.5$).
* **Hunter Tradecraft**: Enables hunters to **Narrow** (pruning common software/domains) or **Enhance** (scaling threat scores on NRDs and expired infrastructure) without falling into the Part-of-the-Whole trap (see `references/entity-context-graph-guide.md`).

---

## 19. Operational & Statistical Assumptions Guide

When communicating with analysts, SOC managers, or threat hunters, use this guide to clarify foundational assumptions:

### 1. Division-by-Zero Protection on Quiet Accounts (Clean Conditional Safeguard)
* **The Concern**: Inactive accounts have a 30-day baseline mean $\mu = 0$ and standard deviation $\sigma = 0$. In standard Z-score math, any single event triggers division-by-zero ($\frac{1 - 0}{0} = \infty$).
* **The Clarification**: The engine applies a compiler-compliant **Clean Conditional Safeguard** (`$safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)`):
  $$\sigma_{\text{safe}} = \text{if}(\sigma_{\text{hist}} > 0, \sigma_{\text{hist}}, 1.0)$$
  This avoids division by zero, eliminates arbitrary constant inflation on noisy accounts, and provides clean mathematical grounding.

### 2. Weekend & Cyclic Seasonality Dip
* **The Concern**: Standard 30-day trailing averages blend weekdays and weekends together, even though enterprise activity drops by 70–90% on weekends.
* **The Clarification**: For non-seasonal blended baselines, Mode B (Fixed-Baseline Timeline) or Mode C (Per-Day Baseline Timeline) breaks down activity day-by-day so analysts can directly inspect day-of-week cyclic trends, or analysts can leverage `HOURLY_TEMPORAL_ZSCORE` for diurnal profiles.

### 3. Cartesian Join Product Prevention (Multi-Stage DAG Isolation)
* **The Concern**: Why can't we search for creation and deletion events in a single un-staged query?
* **The Clarification**: When multiple distinct event types are matched together in a single stage, SIEM engines compute an $N \times M$ Cartesian product join (e.g. 10 creations $\times$ 5 deletions = 50 joined rows), inflating observed counts by 500%–1000% and completely discarding entities with 0 deletions. Multi-stage DAG pipelines isolate each event vector into its own stage before fusing $Z$-scores into an orthogonal threat distance.

### 4. Sparse Baseline Caution & Account Maturity ($N < 7$ Days)
* **The Concern**: Newly created accounts or ephemeral cloud workers may have only 1–2 days of historical logs.
* **The Clarification**: Calculating a Z-score on an entity with fewer than 7 active baseline days ($N < 7$) produces high statistical variance. The skill flags a **Sparse Baseline Caution** and applies Empirical Bayes shrinkage or the Two-Part Hurdle model to regularize sparse accounts.

### 5. Multi-Cloud Provider Scoping & Dimension Partitioning
* **The Concern**: Does a user's cloud activity in AWS affect their GCP baseline?
* **The Clarification**: Cloud lifecycle metrics enforce compound dimensions (`metadata.vendor_name`, `metadata.product_name`). This guarantees that AWS CloudTrail, GCP Cloud Audit, and Azure Activity Logs are baselined within their respective cloud provider partitions without cross-cloud contamination.
