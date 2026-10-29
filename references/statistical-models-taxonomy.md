# Statistical Models Taxonomy & Mathematical Foundations

This reference defines the mathematical formulations, operational threat translations, **"Down-to-Earth" pre-flight consultative explanations**, **post-hunt plain-English cyber impact statements**, and `D1` dispositions across all 14 active Stage 2 mathematical models (`templates/stage2_math_models/*.yl2`) and all 34 Multi-Stage DAG Pipeline templates (`templates/pipelines/*.yl2`).

---

## 🗺️ Execution Framework Summary: Built-in Anomaly Models & Security Outcomes

The Google SecOps Multi-Stage Risk Analytics Engine provides 13 categories of behavioral anomaly models and `D1` routing dispositions designed to detect malicious patterns without generating false positives on legitimate baseline shifts:

| Anomaly Archetype | Built-In Mathematical Models | Target Telemetry Vectors | Primary Security Outcome & Use Case |
| :--- | :--- | :--- | :--- |
| **1. 📈 Volumetric & Fold-Change Surges** | `STANDARD_Z_SCORE`, `MAD`, `QUANTILE_IQR_SKEW`, `RELATIVE_DEVIATION`, `COEFFICIENT_OF_VARIATION` | Network Egress, File Touches, HTTP Queries | Detects data exfiltration spikes, regular-volume breakouts, and ransomware staging while insulating against skewed distributions. |
| **2. 📊 Baseline Dispersion Screen** | `VARIANCE` (Fano Factor $F = \sigma^2/\mu$, `variance_fano.yl2`) | Count-Based Baselines (`event_count_sum`) | 30-day **baseline dispersion screen** (`NO-GATE`, independent of today's value) testing Poisson ($F \approx 1.0$) vs overdispersed ($F > 2.0$) baselines. Active spray hunts belong in `secops-statistical-hunter` `POISSON_BURST_CLUSTERING`. |
| **3. 🎯 Rare & Discrete Inceptions** | `POISSON` (`poisson_rarity.yl2`), `FIRST_SEEN_NOVELTY` (`first_seen_novelty.yl2`) | Process Launches, Admin LOLBins, App Logins | Flags rare discrete count breakouts ($\lambda = S/30$) and first-time 30d entity/sub-key sightings (`first_seen = 0`, boolean novelty flag, never $\sigma$). |
| **4. 🧠 Sparse Activity Regularization** | `BAYESIAN_GAMMA`, `BAYESIAN_BETA_BINOMIAL` | Low-Volume Service Accounts, Paired Fail/Total Ratios | Regularizes sparse observations via fleet Empirical Bayes priors (`Gamma(alpha0, beta0)` and paired `Beta(alpha0, beta0)`), preventing `1/1` single-trial false alarms. |
| **5. 💧 Sub-Threshold Drift Accumulation** | `LONGITUDINAL_CUSUM` ($W = \sum \max(0, Z_t - 0.5)$ + `scripts/cusum_helper.py` $S_t^+$) | Network Bytes, Cloud Resource CRUD, Alerts | Uncovers low-and-slow data exfiltration or privilege creeping across 2–30 days (`Mode A` blocked). |
| **6. 🚪 Zero-Inflated Dormant Awakening** | `TWO_PART_HURDLE` (`two_part_hurdle.yl2`) | Inactive Accounts, Service Accounts | Applies a volume-gated discrete awakening hurdle (`$observed >= min_awakening_volume` and `> hist_max`) when a dormant account wakes up, transitioning to rectified intensity Z once mature (`$active_days >= 7`). |
| **7. 🔼 One-Sided Upper-Tail Spikes** | `STANDARD_Z_SCORE` (merged `ASYMMETRIC_DIRECTIONAL_Z`) | Bandwidth, File Touches, Process Runs | Upper-tail positive $Z \ge 3.0$ concentrates risk exclusively on volumetric surges so weekend quiescence never triggers alerts. |
| **8. 🛡️ Concurrency Immunity & Suppression** | `hybrid_metric_fleet_prevalence_2stage.yl2`, `dual_baseline_delta_z_3stage.yl2` | Process Executions, Workstation Egress | Disarms false positives during enterprise rollouts via token-scoped prevalence dampening or fleet-wide $\Delta Z = Z_{\text{personal}} - Z_{\text{fleet}}$. |
| **9. 🌙 Context-Modulated Sensitivity** | `ADAPTIVE_CONTEXT_THRESHOLD` (`adaptive_context_threshold.yl2`) | Off-Hours Logins, Weekend Bandwidth | Evaluates event local hour/weekday in `{{tenant_tz}}`, tightening detection hurdles from $3.0\sigma$ in business hours to $1.75\sigma$ during off-hours or weekends. |
| **10. 🎯 Calibrated Severity Tiering** | `ueba_constants.calculate_cri` *(retired `piecewise_cri.yl2`)* | Post-Query Triage Reporting | Translates standardized deviations into canonical $[0, 100]$ SOC severity bands (`26 / 46 / 70 / 90`) in Python reporting (`WS7-01`). |
| **11. 🚀 Above-Historical-Max Z** | `MACD_MOMENTUM_VELOCITY` (`macd_momentum_velocity.yl2`) | Network Egress, Auth Attempts, DNS Volumes | Catches linear peak exceedance ($Z_{\text{personal}} + Z_{\text{above\_max}}$) where today's volume breaks out beyond both the 30-day mean and the 30-day historical maximum. |
| **12. ⏰ Per-Hour-of-Day Profiling** | Handoff to `HOUR_OF_DAY_PROFILE` *(retired `hourly_temporal_zscore.yl2`, `circadian_von_mises.yl2`)* | Off-Hours Authentication, Sub-Day Cadence | Hands off per-hour-of-day profiling to `secops-statistical-hunter` `HOUR_OF_DAY_PROFILE` (`D1` / `PF-10`). |
| **13. 📡 Outbound Flow Surge** | `c2_beacon_flow_frequency_2stage.yl2` (**Outbound Flow Surge**) | Outbound Network Sessions (`network_flows_outbound`) | Detects daily outbound connection-count surges and destination breadth; sub-hour C2 callback jitter hands off to `secops-statistical-hunter` `C2_BEACONING_JITTER`. |

> [!TIP]
> **Ask for more information** if you would like a deep dive on how any of these specific models help expose behavioral outliers for your security use cases.

---

## 🧭 Pre-Flight "Down-to-Earth" Guide: How to Explain Statistical Models

Before running a multi-stage statistical hunt, explain the approach to the security practitioner using these intuitive physical analogies:

### 1. Bayesian Belief Updating (The "Seasoned SOC Detective")
> *"If a quiet host logs in once and fails once, a naive detector flags a 100% failure rate alarm. Empirical Bayes updating works like an experienced SOC investigator: it fits a fleet-wide prior from peers, blends it with the entity's 30-day history, and requires proportionate evidence before sounding an alarm—while still firing immediately on a genuine `+10σ` breakout."*

### 2. Dual-Baseline & Fleet Prevalence (The "Patch Tuesday Storm Shelter")
> *"If Microsoft pushes Patch Tuesday or IT deploys a software agent, hundreds of workstations spike together. Our token-scoped fleet-prevalence (`hybrid_metric_fleet_prevalence_2stage.yl2`) and dual-baseline (`dual_baseline_delta_z_3stage.yl2`) pipelines compare the host's personal spike against concurrent fleet adoption today. If the whole fleet moved together, the alert is suppressed; if one host spiked alone, it flags a targeted attack."*

### 3. Longitudinal CUSUM Drift (The "Slow Leaking Faucet")
> *"If an insider exfiltrates a small slice of data each day ($Z \approx 1.5\sigma$), single-day $3\sigma$ alerts never fire. Longitudinal CUSUM screens mature entities with the lossless Windowed Slack Sum prefilter $W = \sum \max(0, Z_t - 0.5)$ and evaluates exact sequential Page's CUSUM $S_t^+$ in `scripts/cusum_helper.py` (including quiet 0-event days) until the accumulated drift crosses the ARL-calibrated threshold $h$."*

### 4. Two-Part Hurdle Model (The "Tripwire & Siphon")
> *"For dormant accounts (`$active_days < 7`), Part 1 acts as a volume-gated tripwire requiring both a meaningful awakening count (`min_awakening_volume`) and an exceedance above any prior 30-day peak. For mature accounts (`$active_days >= 7`), Part 2 measures rectified positive volume intensity."*

### 5. One-Sided Upper-Tail Z (Merged `ASYMMETRIC_DIRECTIONAL_Z` -> `STANDARD_Z_SCORE`)
> *"A server uploading 10× its normal data is a security alert; uploading 0.1× over a holiday weekend is benign. Upper-tail positive thresholding ($Z \ge 3.0\sigma$) focuses analytical power on upward surges without firing on quiet-day drops (which is why `asymmetric_directional_z.yl2` was merged into `standard_z_score.yl2` under `D1`)."*

### 6. Calibrated Risk Index (The "0–100 Incident Richter Scale")
> *"Unbounded raw Z-scores make cross-sector triage difficult. Python post-processing (`ueba_constants.calculate_cri`) maps Z-equivalent scores onto a monotonic `[0, 100]` logistic S-curve anchored at `Z = 3.0 -> CRI 50` (`Z <= 0 -> 0`; retired in-query `piecewise_cri.yl2`)."*

### 7. Adaptive Context Thresholding (The "Night Sentry")
> *"During weekday business hours (`08:00–18:00` in `{{tenant_tz}}`), normal operational traffic warrants a $3.0\sigma$ gate. At 3:00 AM or on Sunday, the building should be quiet—so `adaptive_context_threshold.yl2` tightens the effective gate to $1.75\sigma$ whenever $\ge 50\%$ of observed activity occurs off-schedule."*

### 8. Multi-Sector Threat Fusion (The "Combined Arms Threat Radar")
> *"Attackers chain sub-threshold actions across multiple telemetry planes. Our fusion pipelines compute the rectified Euclidean Threat Distance $D = \sqrt{\sum \max(0, Z_i)^2}$ across sectors on the same entity (noting that positively correlated sectors such as Network + DNS + Web increase joint tail rates relative to independent $\chi^2_k$ assumptions)."*

### 9. Above-Historical-Max Z (`MACD_MOMENTUM_VELOCITY` — "Breaking the 30-Day Record")
> *"When an entity's daily volume not only exceeds its 30-day average ($Z_{\text{personal}}$) but also shatters its highest single-day peak from the prior 30 days ($Z_{\text{above\_max}}$), `macd_momentum_velocity.yl2` sums both linear standardized terms without risking quadratic byte overflow."*

### 10. Per-Hour-of-Day Profiling (`D1` Handoff to `HOUR_OF_DAY_PROFILE`)
> *"Because `metrics.*` pre-computes daily `00:00Z` baselines (`PF-10`), true 24-bin hour-of-day profiling requires multi-day hourly raw event baselines. Legacy `hourly_temporal_zscore.yl2` and `circadian_von_mises_2stage.yl2` are retired under `D1` and hand off cleanly to `secops-statistical-hunter` `HOUR_OF_DAY_PROFILE`."*

---

## 1. Parametric Standard Z-Score (`STANDARD_Z_SCORE` — `standard_z_score.yl2`)
* **Security Problem Solved**: Detects abrupt volumetric explosions exceeding a mature entity's personal 30-day active-day baseline (`$active_days >= 7`, `D8`).
* **Mathematical Formulation**:
  $$\sigma_{\text{floor}} = \begin{cases} \sqrt{\max(\mu, 1.0)} & \text{count metrics} \\ \sigma_{\text{byte\_floor}} & \text{byte metrics} \end{cases}, \quad \sigma_{\text{safe}} = \max(\sigma, \sigma_{\text{floor}}), \quad Z = \frac{x - \mu}{\sigma_{\text{safe}}}$$
* **Threat Meaning**: Upper-tail anomaly ($Z \ge 3.0\sigma$) gated on `$active_days >= 7` so zero-variance (`σ = 0`) or cold-start (`n < 7`) entities never produce artificial blowups.
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Parametric Baseline Surge Verdict: Standard Z-Score (`[target_metric]`)**
> * **Personal Activity**: Entity `[entity]` performed **[observed]** actions against a 30-day active-day mean of **[hist_avg]** ($\sigma = [hist_stddev]$, active days = **[active_days]**).
> * **Standardized Deviation**: **[personal_z]σ** above baseline.
> * **Investigative Meaning**: Statistically confirmed volume breakout exceeding mature 30-day operational history.
```

---

## 2. Median Absolute Deviation (`MAD` — `mad.yl2` & `mad_robust_z_4stage.yl2`)
* **Security Problem Solved**: Detects volumetric surges on heavy-tailed telemetry (network egress bytes, DNS volumes) where historic bulk transfers inflate the arithmetic mean and standard deviation (50% breakdown point).
* **Mathematical Formulation** (Iglewicz & Hoaglin):
  $$\tilde{x} = \text{median}(x_d), \quad \text{MAD} = \text{median}(|x_d - \tilde{x}|), \quad M_z = \frac{x - \tilde{x}}{\text{MAD}/0.6745}$$
  * Computed over the ~30d raw search window (`mad_center` $\to$ `mad_spread`); MAD $= 0$ falls back to $1.253314 \cdot \text{meanAD}$, then $0.05\,\tilde{x} + 1.0$.
  * Pre-scoring raw active-day `$personal_z` (`$in_scoring_window = 0`, `WS1-03`) provides an unstale `$z_gap = M_z - Z_{\text{raw}}$ cross-check without `[D0 - 59d, D0 - 29d)` anchor shift.
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Robust Non-Parametric Surge Verdict: MAD (`[target_metric]`)**
> * **Observed Transfer**: Entity `[entity]` recorded **[observed]** units on the scored day.
> * **Robust Deviation**: **[modified_z]** Modified Z above the 30-day median **[median_val]** (MAD = **[mad]**, pre-scoring classical $Z = [personal_z]\sigma$, gap = **[z_gap]**).
> * **Investigative Meaning**: Heavy-tailed volume breakout exposed despite historic burst contamination.
```

---

## 3. 30-Day Baseline Dispersion Screen (`VARIANCE` — `variance_fano.yl2`)
* **Purpose**: Provides a `NO-GATE` **baseline dispersion screen** over the 30-day pre-computed baseline ($F = \sigma^2 / \mu$, independent of today's `$observed` count) to test whether an entity's daily baseline satisfies Poisson dispersion ($F \le 2.0$) or requires an overdispersed / robust model (`MAD`, `QUANTILE_IQR_SKEW`, or negative-binomial scaling). Active credential spray and brute-force hunts route to `secops-statistical-hunter` `POISSON_BURST_CLUSTERING`.
* **Mathematical Formulation**:
  $$F = \frac{\sigma^2}{\max(\lambda, 1.0)}$$

---

## 4. Discrete Poisson / Negative-Binomial Rarity Score (`POISSON` — `poisson_rarity.yl2`)
* **Security Problem Solved**: Quantifies the improbability of discrete count events (`metric: event_count_sum`; blocked on `value_sum` byte metrics) using per-calendar-day rate $\lambda = S_{30}/30$ (`PF-1`, `WS1-05`) and rebuilt 30-day calendar variance $\sigma^2_{\text{cal}}$.
* **Mathematical Formulation**:
  $$\lambda = \frac{S_{30}}{30}, \quad \lambda_{\text{safe}} = \max(\lambda, 1.0), \quad F_{\text{cal}} = \frac{\sigma_{\text{cal}}^2}{\lambda_{\text{safe}}}, \quad Z_P = \frac{k - \lambda}{\sqrt{\text{eff\_var}}}$$
  where $\text{eff\_var} = \max(\sigma_{\text{cal}}^2, \lambda_{\text{safe}})$ when $n \ge 2 \land F_{\text{cal}} > 2.0$, and $\lambda_{\text{safe}}$ otherwise.

---

## 5. Regular-Volume Surge (`COEFFICIENT_OF_VARIATION` — `coefficient_of_variation.yl2`)
* **Security Problem Solved**: Detects fold-change volume surges (`$surge_ratio >= 2.0`) specifically on mature entities (`$active_days >= 7`) with regular, predictable day-to-day baselines (`$cv <= 0.5`). *(Renamed from CV jitter under `D1`; sub-hour callback periodicity/jitter hands off to `secops-statistical-hunter` `C2_BEACONING_JITTER`.)*
* **Mathematical Formulation**:
  $$\mu_{\text{safe}} = \max(\mu, 1.0), \quad \text{CV} = \frac{\sigma}{\mu_{\text{safe}}}, \quad \text{Surge Ratio} = \frac{x}{\mu_{\text{safe}}} \quad (\text{gated on } N_{\text{active}} \ge 7 \land \text{Surge Ratio} \ge 2.0 \land \text{CV} \le 0.5)$$
* **Post-Hunt Plain-English Cyber Impact Statement Template**:
```markdown
> [!IMPORTANT]
> **Regular-Volume Surge Verdict (`[target_metric]`)**
> * **Fold-Change Breakout**: Mature entity `[entity]` (`[active_days]` active days, baseline $\text{CV} = [cv] \le 0.50$) surged to **[surge_ratio]×** its regular 30-day average (**[observed]** vs **[hist_avg]**).
> * **Investigative Meaning**: Acute volume departure on a normally steady, low-variance workload.
```

---

## 6. `HOURLY_TEMPORAL_ZSCORE` (`hourly_temporal_zscore.yl2` — Retired under `D1` -> `HOUR_OF_DAY_PROFILE`)
* **Status**: **Retired** from `secops-risk-metrics-multistage` (`D1` / `PF-10` / `WS2-02`). Comparing 1-hour buckets against `metrics.*` daily baselines introduces severe scale distortion. Route per-hour-of-day profiling to `secops-statistical-hunter` `HOUR_OF_DAY_PROFILE` (for Mode A earlier-today context on `(1h, today)`, see `WS1-13` `--intraday-hourly` in `references/multi-stage-metrics-guide.md`).

---

## 7. Empirical Bayes Poisson-Gamma Shrinkage (`BAYESIAN_GAMMA` — `poisson_gamma_bayesian.yl2`)
* **Security Problem Solved**: Regularizes sparse arrival counts using a fleet-fitted `Gamma(α₀, β₀)` Empirical Bayes prior (`fit_gamma_prior_from_fleet`) and scores today's count via the posterior-predictive Negative-Binomial residual (`$bayesian_z >= 3.0`) so `+10σ` spikes on mature stable hosts still fire (`WS3-BAYES`, `B-E10`).
* **Mathematical Formulation**:
  $$\hat{\lambda}_{\text{post}} = \frac{\alpha_0 + S_{30}}{\beta_0 + 30}, \quad \sigma^2_{\text{rate}} = \frac{\alpha_0 + S_{30}}{(\beta_0 + 30)^2}, \quad \sigma^2_{\text{excess}} = \max(0, \sigma^2_{\text{cal}} - \mu_{\text{cal}})$$
  $$\sigma^2_{\text{pred}} = \hat{\lambda}_{\text{post}} + \sigma^2_{\text{rate}} + \frac{n}{n + \beta_0}\sigma^2_{\text{excess}}, \quad Z_{\text{Bayes}} = \frac{k - \hat{\lambda}_{\text{post}}}{\sqrt{\max(\sigma^2_{\text{pred}}, 1.0)}}$$

---

## 8. Empirical Bayes Paired Beta-Binomial Failure Rate (`BAYESIAN_BETA_BINOMIAL` — `beta_binomial_bayesian.yl2`)
* **Security Problem Solved**: Prevents `1/1 = 100%` single-trial false alarms on discrete failure proportions (`auth_attempts_*`, `dns_queries_*`, `http_queries_*`, `file_executions_*`, `resource_*`) by pairing Stage-1 failure counts `$obs_fail` and attempt totals `$obs_total` with 30-day sums and a fleet-fitted `Beta(alpha0, beta0)` prior (`fit_beta_prior_from_fleet`, default $\alpha_0 = 1.0, \beta_0 = 19.0$).
* **Mathematical Formulation**:
  $$\alpha_{\text{pre}} = \alpha_0 + F_{30}, \quad \beta_{\text{pre}} = \beta_0 + \max(0, N_{30} - F_{30}), \quad M = \alpha_{\text{pre}} + \beta_{\text{pre}}, \quad \hat{p}_{\text{post}} = \frac{\alpha_{\text{pre}} + f}{M + n}$$
  $$\mu_{\text{pred}} = n \cdot \frac{\alpha_{\text{pre}}}{M}, \quad \sigma_{\text{pred}}^2 = n \cdot \frac{\alpha_{\text{pre}}}{M}\cdot\frac{\beta_{\text{pre}}}{M}\cdot\frac{M + n}{M + 1}, \quad Z_{\text{BB}} = \frac{f - \mu_{\text{pred}}}{\sqrt{\max(\sigma_{\text{pred}}^2, 0.25)}}$$

---

## 9. Multi-Day Cumulative Drift — Windowed Slack Sum & Page CUSUM (`LONGITUDINAL_CUSUM` — `longitudinal_cusum.yl2`)
* **Security Problem Solved**: Catches low-and-slow data exfiltration, stealth credential accumulation, or slow permission creep across 2–30 days (**Mode A blocked** — single-day CUSUM raises an error).
* **Mathematical Formulation (`WS6-01`)**:
  * **Lossless Windowed Slack Sum Prefilter (`longitudinal_cusum.yl2` & `longitudinal_cusum_2stage.yl2`)**:
    $$Z_d = \frac{x_d - \mu}{\sigma_{\text{safe}}}, \quad \Delta_d = \begin{cases} \max(0, Z_d - 0.5) & \text{if } N_{\text{active}} \ge 7 \\ 0 & \text{otherwise} \end{cases}, \quad W = \sum_{d=1}^{D} \Delta_d$$
    Because Page's one-sided statistic satisfies $S_t^+ \le W$, any entity with $W < h$ cannot alarm.
  * **Exact Sequential Page's CUSUM (`longitudinal_cusum_series_3stage.yl2` + `scripts/cusum_helper.py`)**:
    $$S_t^+ = \max(0, S_{t-1}^+ + Z_t - 0.5)$$
    For `<= 14d`, `longitudinal_cusum_series_3stage.yl2` emits the ungated per-day series from the single start-anchored query and `scripts/cusum_helper.py` (`calculate_page_cusum_series`) reconstructs quiet `0`-event calendar days ($Z_t < 0$) against ARL-calibrated thresholds ($h = 4.0$ `BALANCED` [$\text{ARL}_0 \approx 336$], $5.0$ `HIGH_PRECISION` [$\text{ARL}_0 \approx 930$], $3.0$ `HIGH_RECALL`). For `> 14d`, ungated candidate Mode C shards are re-standardized against **Shard 1's fixed calendar-day baseline** (`rebuild_calendar_day_stats`) with explicit reset controls (`--reset-on`, `--reset-after-alarm`, `--reset-every-days`).

---

## 10. Two-Part Hurdle Model for Zero-Inflated Telemetry (`TWO_PART_HURDLE` — `two_part_hurdle.yl2`)
* **Security Problem Solved**: Evaluates dormant or sparse accounts (`$active_days < 7`, `dormant_days = 30 - active_days`) without letting low-volume noise outrank true surges.
* **Mathematical Formulation**:
  * **Part 1 (Dormant Awakening, $N_{\text{active}} < 7$)**: Requires BOTH $x \ge V_{\min}$ (`{{min_awakening_volume}}`, default `25`) AND $x > x_{\max,30\text{d}}$:
    $$S_{\text{dormant}} = \begin{cases} 3.0 + \ln\!\left(\max\!\left(1, \frac{x}{\max(x_{\max,30\text{d}}, V_{\min})}\right)\right) & \text{if } N_{\text{active}} < 7 \land x \ge V_{\min} \land x > x_{\max,30\text{d}} \\ 0 & \text{otherwise} \end{cases}$$
  * **Part 2 (Active Intensity, $N_{\text{active}} \ge 7$)**: $Z_{\text{intensity}} = \max(0, (x - \mu)/\sigma_{\text{safe}})$. Ranked on its own hurdle scale (not true $\sigma$).

---

## 11. Asymmetric Directional Surge (`ASYMMETRIC_DIRECTIONAL_Z` — `asymmetric_directional_z.yl2` Merged under `D1`)
* **Status**: Merged into `STANDARD_Z_SCORE` (`standard_z_score.yl2`) under `D1` because upper-tail positive thresholding (`$personal_z >= 3.0`) already ignores negative deviations (`SILENCE_DETECTION` / `DROP_OUT` aliases rejected as unsupported).

---

## 12. Calibrated Risk Index (`PIECEWISE_CRI` — `piecewise_cri.yl2` Retired under `D1`)
* **Status**: `piecewise_cri.yl2` is retired under `D1`. Calibrated Risk Index (`CRI`) is computed canonically in Python post-processing via `ueba_constants.calculate_cri` (`WS7-01`).

---

## 13. Fleet Prevalence Normalization (`FLEET_PREVALENCE_SHIELD` — `fleet_prevalence_shield.yl2` Retired under `D1`)
* **Status**: Single-plane `fleet_prevalence_shield.yl2` is retired under `D1`; use token-scoped `hybrid_metric_fleet_prevalence_2stage.yl2` or `dual_baseline_delta_z_3stage.yl2`.

---

## 14. Off-Hours & Weekend Adaptive Context Thresholding (`ADAPTIVE_CONTEXT_THRESHOLD` — `adaptive_context_threshold.yl2`)
* **Security Problem Solved**: Tightens detection sensitivity during off-hours and weekends (`WS3-ADAPTIVE`, `D1c`).
* **Mathematical Formulation**:
  * Stage 1 evaluates each event's local hour and weekday (`timestamp.get_hour`, `timestamp.get_day_of_week`) in `{{tenant_tz}}` (default `"UTC"`, business hours `08:00–18:00` Mon–Fri `2..6`, or per-entity learned active hours from `WS5-HOD` `HOUR_OF_DAY_PROFILE`):
    $$Z_{\text{personal}} = \frac{x - \mu}{\sigma_{\text{safe}}}, \quad s_{\text{off}} = \frac{x_{\text{off\_hours}}}{\max(x, 1)}, \quad G_{\text{eff}} = \text{if}(s_{\text{off}} \ge 0.5, 1.75, 3.00), \quad Z_{\text{adaptive}} = \frac{3.0 \cdot Z_{\text{personal}}}{G_{\text{eff}}}$$

---

## 15. Above-Historical-Max Z (`MACD_MOMENTUM_VELOCITY` — `macd_momentum_velocity.yl2`)
* **Security Problem Solved**: Detects linear peak exceedance where today's volume breaks out above both the 30-day baseline mean and the 30-day historical maximum without quadratic byte overflow (`D1`).
* **Mathematical Formulation**:
  $$Z_{\text{personal}} = \frac{x_{\text{observed}} - \mu_{\text{30d}}}{\sigma_{\text{safe}}}, \quad Z_{\text{above\_max}} = \frac{\max(0, x_{\text{observed}} - x_{\text{max,30d}})}{\sigma_{\text{safe}}}, \quad Z_{\text{macd}} = Z_{\text{personal}} + Z_{\text{above\_max}}$$

---

## 16. `CIRCADIAN_VON_MISES` (`circadian_von_mises.yl2` & `circadian_von_mises_2stage.yl2` — Retired under `D1` -> `HOUR_OF_DAY_PROFILE`)
* **Status**: **Retired** from `secops-risk-metrics-multistage` (`D1` / `PF-10` / `WS2-02`). Fixed 14:00 UTC peak assumptions and daily `metrics.*` baselines cannot model per-entity circadian schedules; route per-hour-of-day profiling to `secops-statistical-hunter` `HOUR_OF_DAY_PROFILE`.

---

## 17. Relative Deviation / Fold Change (`RELATIVE_DEVIATION` — `relative_deviation.yl2`)
* **Security Problem Solved**: Computes a scale-free relative deviation $(x - \mu)/\mu$ and fold change $x/\mu$ ("3.2× the 30-day average") with continuous `max(avg, 1.0)` floor and Z-equivalent mapping (`WS7-02`).
* **Mathematical Formulation**:
  $$\mu_{\text{safe}} = \max(\mu, 1.0), \quad \text{Relative Deviation} = \frac{x - \mu_{\text{safe}}}{\mu_{\text{safe}}}, \quad \text{Fold Change} = \frac{x}{\mu_{\text{safe}}}, \quad Z_{\text{equiv}} = \max(0, 3.0 \times \text{Relative Deviation})$$

---

## 17B. 1-Stage Non-Parametric Quantiles, Bowley Skewness & Skew-Adjusted Tukey Scale-Excess (`QUANTILE_IQR_SKEW` — `quantile_iqr_skew.yl2`)
* **Security Problem Solved**: Computes a 5-point empirical quantile envelope ($P_{10}, Q_{25}, Q_{50}, Q_{75}, P_{90}$) in **1 intermediate stage** (`stage quantile_envelope` via `window.percentile`) over a ~30d raw window (`WS1-02`), freeing a stage for Entity Context Graph or peer-cohort enrichment.
* **Mathematical Formulation** (Bowley 1920; Moors 1988; recalibrated Bowley `1.35` exponent):
  $$\text{IQR} = Q_{75} - Q_{25}, \quad B_{\text{skew}} = \frac{Q_{75} + Q_{25} - 2 Q_{50}}{\text{IQR}_{\text{safe}}}, \quad \text{Fence}_{\text{adj}} = Q_{75} + 1.5 \cdot e^{1.35 \cdot \max(0, B_{\text{skew}})} \cdot \text{IQR}_{\text{safe}}, \quad Z_{\text{excess}} = \frac{x - \text{Fence}_{\text{adj}}}{\text{IQR}_{\text{safe}} / 1.349}$$

---

## 17C. First-Seen 30-Day Boolean Novelty Flag (`FIRST_SEEN_NOVELTY` — `first_seen_novelty.yl2` & `first_seen_novelty_2stage.yl2`)
* **Security Problem Solved**: Primary 30-day novelty detector ahead of ECG (`PF-11` / `WS1-12`): flags entities or composite `(entity, sub-key)` tuples (such as `(user, application)`, `(host, domain)`, `(host, sha256)`, or `(sa, vendor, product, resource)`) never seen in the prior 30-day `metrics.*` window (`$prior_first_seen = 0`), enriched with `last_seen` and `period_start_for_max` timestamps (`21/38` metrics populated in `gus-sdl` per `tests/live/baseline_gus_sdl.json`).
* **Mathematical Formulation**:
  $$\text{Novelty Flag} = \mathbb{I}\!\left(\min(\texttt{first\_seen}_{30\text{d}}) = 0 \land x \ge N_{\min}\right) \in \{0, 1\} \quad (\text{boolean flag + context; never reported as }\sigma\text{, CRI = N/A})$$

---

## 18. Complete Multi-Stage DAG Pipeline Inventory (`templates/pipelines/*.yl2` — 34 Active Templates)

1. **Core Single-Sector & Non-Parametric Pipelines**:
   - `standard_z_score_2stage.yl2`: 2-stage parametric Standard Z-Score with `D8` maturity & dispersion floors.
   - `poisson_rarity_2stage.yl2`: 2-stage calendar-rate ($\lambda = S/30$) Poisson / NB rarity pipeline.
   - `macd_momentum_velocity_2stage.yl2`: 2-stage **Above-Historical-Max Z** ($Z_{\text{personal}} + Z_{\text{above\_max}}$) breakout pipeline.
   - `c2_beacon_flow_frequency_2stage.yl2`: 2-stage **Outbound Flow Surge** (`metrics.network_flows_outbound` daily session-count surge + destination IP/port breadth; sub-hour C2 callback jitter hands off to `secops-statistical-hunter` `C2_BEACONING_JITTER`).
   - `mad_robust_z_4stage.yl2`: 4-stage (1 UDM event stage) ~30d raw Median Absolute Deviation / Modified $Z$ pipeline.
   - `quantile_iqr_skew_3stage.yl2`: 3-stage (1 UDM event stage) ~30d `window.percentile` Bowley-recalibrated Tukey scale-excess pipeline.
   - `first_seen_novelty_2stage.yl2`: 2-stage `metric: first_seen, agg: min` 30-day boolean novelty pipeline (+ optional `(1h, today)` earlier-today first-seen context).
   - `longitudinal_cusum_2stage.yl2`: 2-stage Windowed Slack Sum lossless prefilter ($W = \sum \max(0, Z_t - 0.5)$).
   - `longitudinal_cusum_series_3stage.yl2`: 3-stage ungated active-day standardized series extractor feeding `scripts/cusum_helper.py` for exact Page CUSUM $S_t^+$.
2. **Web, Cloud & Peer-Cohort Pipelines**:
   - `http_error_ratio_surge_2stage.yl2`: 2-stage HTTP $4xx/5xx$ failure baseline + in-stage error-ratio surge.
   - `http_target_surge_2stage.yl2`: 2-stage target-centric HTTP destination surge (`target.hostname`).
   - `cloud_repository_scope_dual_branch.yl2`: 3-stage dual-branch service-account 4-CRUD repository + unseen caller-IP isolation.
   - `dual_baseline_delta_z_3stage.yl2`: 3-stage Dual-Baseline $\Delta Z = Z_{\text{personal}} - Z_{\text{fleet}}$ with mature winsorized fleet center.
   - `hierarchical_empirical_bayes_3stage.yl2`: 3-stage Hierarchical Empirical Bayes shrinkage sorted by posterior-predictive Z.
   - `part_of_the_whole_multilevel.yl2`: 3/4-stage multilevel leave-one-out peer cohort & enterprise comparison (with `WS1-09` Samuelson cap).
   - `part_of_the_whole_triad_multilevel.yl2`: 3/4-stage 3-sibling triad (`total` + `fail` + `success`) rectified Euclidean comparison.
3. **Multi-Sector Euclidean Fusion & 360° Behavioral Radar** *(inter-sector correlation caveat: positively correlated sectors such as Network + DNS + Web increase false-positive tail rates above independent $\chi^2_k$ predictions)*:
   - `dual_sector_fusion_3stage.yl2`: 3-stage union-based rectified Euclidean fusion ($D = \sqrt{\sum \max(0, Z_i)^2}$) of any 2 same-entity sectors.
   - `multi_sector_fusion_4stage.yl2`: 4-stage union-based 2-sector rectified Euclidean fusion + cross-sectional fleet $\Delta Z$.
   - `rollup_sector_fusion_4stage.yl2`: 4-stage composite-metric per-entity roll-up fused with a second sector.
   - `rollup_sector_fusion_5stage.yl2`: 5-stage composite roll-up fusion + fleet normalization.
   - `radar_360_decoupled_sector.yl2`: 2-stage `NO-GATE` decoupled 360° Radar sector micro-query.
   - `radar_360_sector_web_http.yl2`: 2-stage `NO-GATE` 360° Radar Web & Proxy HTTP spoke.
   - `radar_360_sector_alert.yl2`: 2-stage `NO-GATE` 360° Radar Security & EDR Alert spoke (`alert_event_name_count`).
4. **Entity Context Graph (ECG), Hybrid Enrichment & Data Table Bridge Pipelines**:
   - `hybrid_metric_derived_file_prevalence_2stage.yl2`: 2-stage `DERIVED_CONTEXT` rare binary hash filter (`rolling_max <= 3`, `day_count = 10`).
   - `hybrid_metric_derived_domain_prevalence_2stage.yl2`: 2-stage `DERIVED_CONTEXT` rare HTTP domain filter (`rolling_max <= 3`, `day_count = 10`).
   - `hybrid_metric_whois_domain_lifecycle_2stage.yl2`: 2-stage `GLOBAL_CONTEXT` WHOIS NRD (`<= 30d`) & expired-domain risk multiplier.
   - `hybrid_metric_derived_asset_age_2stage.yl2`: 2-stage infant asset age (`$active_days >= 7` Z path vs novelty flag on immature assets).
   - `hybrid_metric_http_ua_prevalence_2stage.yl2`: 2-stage HTTP User-Agent token fleet prevalence dampener ($1 / (k_{\text{fleet}} + 1)$).
   - `hybrid_metric_fleet_prevalence_2stage.yl2`: 2-stage cross-sectional binary/token Patch Tuesday prevalence shield.
   - `hybrid_metric_entropy_concentration_2stage.yl2`: 2-stage metric baseline + destination diversity deficit & elephant-flow concentration.
   - `hybrid_metric_raw_enrichment_2stage.yl2`: 2-stage metric baseline + distinct command-line/URI/IP forensic projection.
   - `rare_destination_ecg_3stage.yl2`: 3-stage + Root sector $Z$ narrowed to Entity Graph-rare domains or IPs.
   - `fusion_rare_destination_3stage.yl2`: 3-stage + Root dual-sector rectified $D$ narrowed to Entity Graph-rare destinations.
   - `hybrid_data_table_bridge_2stage.yl2`: 2-stage Phase-2 cross-entity drilldown joining `%ueba_hunt_bridge.entity` with 30-day `metrics.*`.
   - *(Retired under `D1`: `hybrid_metric_orthogonal_space_2stage.yl2` and `circadian_von_mises_2stage.yl2`.)*

---

## 19. Operational & Statistical Assumptions Guide

### 1. Maturity Gate & Dispersion Floor Protection (`D8` / `WS1-04`)
* **The Concern**: Quiet or clockwork accounts can have $\sigma = 0$ (e.g., exactly 103 automated logins every day) or $N < 7$ active baseline days.
* **The Clarification**: Every Z-type root requires `$active_days >= 7` and applies a continuous dispersion floor (`max(sd, sqrt(max(avg, 1.0)))` on count metrics; empirical fleet median `sd` floor on byte metrics). Immature entities (`$active_days < 7`) route to `FIRST_SEEN_NOVELTY` or `TWO_PART_HURDLE`, never raw Z.

### 2. Weekend & Off-Hours Seasonality
* **The Concern**: Trailing 30-day averages blend weekdays and weekends together.
* **The Clarification**: Use Mode B (2–3d Fixed-Baseline Timeline) or Mode C (up to 30d Per-Day Baseline Timeline) to inspect daily patterns, use `ADAPTIVE_CONTEXT_THRESHOLD` (`adaptive_context_threshold.yl2`) for local business-hours vs off-hours/weekend gating, or hand off per-hour-of-day profiling to `secops-statistical-hunter` `HOUR_OF_DAY_PROFILE`.

### 3. Cartesian Join Product Prevention (Multi-Stage DAG Isolation)
* Multi-stage DAG pipelines isolate each event vector into its own stage before fusing rectified $Z$-scores into a composite Euclidean threat distance (up to 2 UDM event stages per query).

### 4. Sparse Baseline Caution & Samuelson Small-Sample Cap (`PF-2` / `WS1-09`)
* Because `metrics.*` `stddev` is the sample SD ($N-1$) over active days (`PF-2`), the maximum achievable Z-score on $N$ samples is bounded by Samuelson's inequality $(N - 1)/\sqrt{N}$ ($3.0\sigma$ requires $N \ge 11$). Small peer cohorts below this cap report `"cohort too small"`.

### 5. Multi-Cloud Provider Scoping & Dimension Partitioning
* Cloud lifecycle metrics enforce compound dimensions (`metadata.vendor_name`, `metadata.product_name`), baselining AWS CloudTrail, GCP Cloud Audit, and Azure Activity Logs within their respective provider partitions.
