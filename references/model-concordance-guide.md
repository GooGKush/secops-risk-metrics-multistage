# 📐 Model Concordance Guide: AST Signatures & Mathematical Invariants

In Google SecOps Multi-Stage Risk Analytics, the **Model Concordance Invariant** bridges the gap between what an analyst or agent promises in human-readable prose (Phase 1B Pre-Flight Card) and what is actually computed in code (YARA-L AST `outcome:` block).

---

## 1. 🏛️ The Architectural Invariant & The Concordance Contract

### The "Aspirational Pre-Flight" Problem
In multi-stage hunting workflows:
1. In **Phase 1B (Pre-Flight Plan)**, the agent declares a statistical model in prose, e.g.:
   `• Statistical Model: Empirical Bayes Poisson-Gamma Conjugate Updating (Shrinkage Prior)`
2. The mandatory compiler probe (`udm_search(..., maxEvents: 1)`) executes against Chronicle SIEM. Crucially, **the probe only validates UDM event predicates** (`metadata.event_type`, `principal.user.userid`). It has zero visibility into the YARA-L Stage 2 DAG or its `outcome:` block arithmetic.
3. Without explicit concordance enforcement, an agent may exhibit "model degradation": declaring an advanced model in prose, but lazily emitting a generic univariate Gaussian $Z$-score (`$z = ($observed - $avg) / $stddev`) in the code block.

### The Concordance Principle
> [!IMPORTANT]
> **Strict Semantic Parity**:
> Every query preview emitted under a Pre-Flight Card and executed in State 2 **MUST** contain the exact mathematical AST structure of the declared model. Emitting a bare univariate $Z$-score when an advanced model is declared is strictly prohibited.

---

## 2. 📊 The 14-Model AST Contract Matrix

| # | `StatisticalModel` Enum | Declared Prose Name | Mandatory `outcome:` Variables | Key Mathematical Operations | Primary `order:` Clause | Prohibited Fallback Anti-Pattern |
|---|---|---|---|---|---|---|
| 1 | `STANDARD_Z_SCORE` | Parametric Historical Z-Score | `$personal_diff`, `$safe_stddev`, `$personal_z` | Linear deviation, positive stddev guard | `order: $personal_z desc` | Missing safe stddev guard (`> 0`) |
| 2 | `MAD` | Non-Parametric Median / Anomaly Ratio | `$dev`, `$safe_hist_avg`, `$ratio` | Relative fold deviation | `order: $ratio desc` | Pure standard deviation normalization |
| 3 | `VARIANCE` | Fano Factor / Index of Dispersion | `$variance`, `$safe_lambda`, `$fano_factor` | Variance calculation ($\sigma^2$), ratio to mean | `order: $fano_factor desc` | Omitting variance calculation |
| 4 | `POISSON` | Discrete Poisson Rarity Z-Score | `$diff`, `$safe_lambda`, `$sqrt_lambda`, `$poisson_z` | `math.sqrt($safe_lambda)` | `order: $poisson_z desc` | Linear stddev denominator instead of square-root mean |
| 5 | `COEFFICIENT_OF_VARIATION` | CV Predictability & Surge Ratio | `$safe_hist_avg`, `$cv`, `$surge_ratio` | Relative dispersion ($\sigma / \mu$) | `order: $surge_ratio desc` | Standard Gaussian $Z$ without CV stability factor |
| 6 | `HOURLY_TEMPORAL_ZSCORE` | Intra-Day Hourly Temporal Z-Score | `$observed_hour`, `$avg_hourly`, `$hourly_diff`, `$safe_stddev_hourly`, `$hourly_z`, `$hourly_surge_ratio` | Match `by 1h`, intra-day fold surge ratio | `order: $hourly_z desc` | Daily aggregation (`by 1d`) when hourly profiling is declared |
| 7 | `BAYESIAN_GAMMA` | Empirical Bayes Poisson-Gamma Conjugate | `$variance_raw`, `$safe_variance`, `$beta_prior`, `$alpha_prior`, `$alpha_post`, `$beta_post`, `$posterior_mean`, `$bayes_shift_ratio` | Method of Moments hyperparameters, posterior conjugate updating | `order: $bayes_shift_ratio desc` | Bare $Z$-score omitting Gamma hyperparameters ($lpha, eta$) |
| 8 | `BAYESIAN_BETA_BINOMIAL` | Beta-Binomial Bayesian Ratio Regularization | `$avg_fail_prob`, `$safe_variance`, `$one_minus_p`, `$sample_factor`, `$alpha_prior`, `$beta_prior`, `$alpha_post`, `$beta_post`, `$posterior_fail_prob` | Binomial variance, sample factor weighting, conjugate update | `order: $posterior_fail_prob desc` | Raw failure counts without Beta prior sample factor |
| 9 | `LONGITUDINAL_CUSUM` | Longitudinal CUSUM Drift Accumulation | `$raw_drift`, `$safe_stddev`, `$slack_allowance`, `$slack_excess`, `$cusum_drift_score` | Page's CUSUM slack allowance ($0.5\sigma$), half-rectification (`if > 0`) | `order: $cusum_drift_score desc` | Standard $Z$-score omitting slack deduction or rectification |
| 10 | `TWO_PART_HURDLE` | Two-Part Hurdle Model (Zero-Inflated) | `$is_active_today`, `$dormant_score`, `$diff`, `$safe_stddev`, `$intensity_z`, `$hurdle_threat_score` | Bernoulli hurdle trigger, conditional continuous intensity | `order: $hurdle_threat_score desc` | Single-equation continuous model without dormant penalty |
| 11 | `ASYMMETRIC_DIRECTIONAL_Z` | Asymmetric Directional Z-Score | `$diff`, `$excess_surge`, `$safe_stddev`, `$upper_tail_z` | ReLU activation (`if($diff > 0, $diff, 0.0)`), upper-tail focus | `order: $upper_tail_z desc` | Two-tailed symmetrical Z-score penalizing activity drops |
| 12 | `PIECEWISE_CRI` | Winsorized Z-Score & Piecewise CRI | `$diff`, `$safe_stddev`, `$raw_z`, `$clamped_low`, `$clamped_z`, `$cri_tier4`, `$cri_tier3`, `$cri_tier2`, `$cri_score` | Winsorization clamp to $[-4.0, +6.0]$, piecewise tiers [0-100] | `order: $cri_score desc` | Unclamped unbounded Z-score |
| 13 | `FLEET_PREVALENCE_SHIELD` | Fleet Prevalence Discounting | `$fleet_count`, `$diff`, `$safe_stddev`, `$personal_z`, `$prevalence_factor`, `$shielded_z` | Fleet aggregation (`count`), immunity factor discounting | `order: $shielded_z desc` | Individual Z-score lacking fleet count suppression |
| 14 | `ADAPTIVE_CONTEXT_THRESHOLD` | Context-Modulated Adaptive Sensitivity | `$diff`, `$safe_stddev`, `$personal_z`, `$is_off_hours`, `$dynamic_threshold`, `$sensitivity_excess` | Off-hours sensitivity tightening ($1.75\sigma$ vs $3.00\sigma$) | `order: $sensitivity_excess desc` | Static uniform threshold across all operating contexts |

---

## 3. 🔬 Canonical AST Specifications & Verification Contracts

### 1. `STANDARD_Z_SCORE` (`standard_z_score.yl2`)
* **Hypothesis**: High-volume burst or sudden departure from individual 30-day baseline mean.
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $hist_max = max($stage1_extract.historical_max)

  $personal_diff = $observed - $hist_avg
  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $personal_z = $personal_diff / $safe_stddev

order:
  $personal_z desc
```

### 2. `MAD` (`mad.yl2`)
* **Hypothesis**: Non-parametric departure robust against baseline historical outliers and skewed distributions.
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  $dev = $observed - $hist_avg
  $safe_hist_avg = if($hist_avg > 0, $hist_avg, 1.0)
  $ratio = $dev / $safe_hist_avg

order:
  $ratio desc
```

### 3. `VARIANCE` (`variance_fano.yl2`)
* **Hypothesis**: Overdispersed behavioral burstiness indicating automated batching or scripting ($Var / \mu > 1.0$).
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $lambda = max($stage1_extract.historical_avg)
  $stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  $variance = $stddev * $stddev
  $safe_lambda = if($lambda > 0, $lambda, 1.0)
  $fano_factor = $variance / $safe_lambda

order:
  $fano_factor desc
```

### 4. `POISSON` (`poisson_rarity.yl2`)
* **Hypothesis**: Discrete integer event arrival rarity where variance equals mean ($\sigma = \sqrt{\lambda}$).
* **Mandatory AST Contract**:
```yara
outcome:
  $k = max($stage1_extract.observed_val)
  $lambda = max($stage1_extract.historical_avg)
  $active_days = max($stage1_extract.historical_active_days)

  $diff = $k - $lambda
  $safe_lambda = if($lambda > 0, $lambda, 1.0)
  $sqrt_lambda = math.sqrt($safe_lambda)
  $poisson_z = $diff / $sqrt_lambda

order:
  $poisson_z desc
```

### 5. `COEFFICIENT_OF_VARIATION` (`coefficient_of_variation.yl2`)
* **Hypothesis**: Evaluation of predictability: high relative surge on low-variance entities represents extreme anomaly.
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  $safe_hist_avg = if($hist_avg > 0, $hist_avg, 1.0)
  $cv = $hist_stddev / $safe_hist_avg
  $surge_ratio = $observed / $safe_hist_avg

order:
  $surge_ratio desc
```

### 6. `HOURLY_TEMPORAL_ZSCORE` (`hourly_temporal_zscore.yl2`)
* **Hypothesis**: Intra-day burst occurring within a narrow 1-hour window compared against hourly historical norms.
* **Mandatory AST Contract**:
```yara
match:
  $entity, $ws by 1h

outcome:
  $observed_hour = max($stage1_extract.observed_val)
  $active_days = max($stage1_extract.historical_active_days)

  $avg_hourly = max($stage1_extract.historical_avg)
  $stddev_hourly = max($stage1_extract.historical_stddev)
  $max_hourly = max($stage1_extract.historical_max)

  $hourly_diff = $observed_hour - $avg_hourly
  $safe_stddev_hourly = if($stddev_hourly > 0, $stddev_hourly, 1.0)
  $hourly_z = $hourly_diff / $safe_stddev_hourly

  $safe_avg_hourly = if($avg_hourly > 0, $avg_hourly, 1.0)
  $hourly_surge_ratio = $observed_hour / $safe_avg_hourly

order:
  $hourly_z desc
```

### 7. `BAYESIAN_GAMMA` (`poisson_gamma_bayesian.yl2`)
* **Hypothesis**: Empirical Bayes conjugate shrinkage updating to avoid false positives on sparse history ($N < 10$).
* **Mandatory AST Contract**:
```yara
outcome:
  $observed_24h = max($stage1_extract.observed_val)
  $avg_30d = max($stage1_extract.historical_avg)
  $stddev_30d = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $max_30d = max($stage1_extract.historical_max)

  $variance_raw = $stddev_30d * $stddev_30d
  $safe_variance = if($variance_raw > 0, $variance_raw, 1.0)
  $beta_prior = $avg_30d / $safe_variance
  $alpha_prior = $avg_30d * $beta_prior

  $alpha_post = $alpha_prior + $observed_24h
  $beta_post = $beta_prior + 1.0

  $posterior_mean = $alpha_post / $beta_post

  $prior_weight = $beta_prior / $beta_post
  $evidence_weight = 1.0 / $beta_post

  $diff = $observed_24h - $avg_30d
  $safe_stddev = if($stddev_30d > 0, $stddev_30d, 1.0)
  $z_score = $diff / $safe_stddev
  $safe_avg = if($avg_30d > 0, $avg_30d, 1.0)
  $bayes_shift_ratio = $posterior_mean / $safe_avg

order:
  $bayes_shift_ratio desc
```

### 8. `BAYESIAN_BETA_BINOMIAL` (`beta_binomial_bayesian.yl2`)
* **Hypothesis**: Ratio and failure probability regularization under small-sample discrete Bernoulli trials.
* **Mandatory AST Contract**:
```yara
outcome:
  $observed_fails = max($stage1_extract.observed_val)
  $avg_fail_prob = max($stage1_extract.historical_avg)
  $stddev_p = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  $variance_raw = $stddev_p * $stddev_p
  $safe_variance = if($variance_raw > 0, $variance_raw, 0.001)
  $one_minus_p = 1.0 - $avg_fail_prob
  $numerator = $avg_fail_prob * $one_minus_p
  $sample_ratio = $numerator / $safe_variance
  $raw_sample_factor = $sample_ratio - 1.0
  $sample_factor = if($raw_sample_factor > 1.0, $raw_sample_factor, 1.0)
  $alpha_prior = $avg_fail_prob * $sample_factor
  $beta_prior = $one_minus_p * $sample_factor

  $alpha_post = $alpha_prior + $observed_fails
  $beta_post = $beta_prior + 1.0
  $total_post = $alpha_post + $beta_post
  $safe_total_post = if($total_post > 0, $total_post, 1.0)

  $posterior_fail_prob = $alpha_post / $safe_total_post

order:
  $posterior_fail_prob desc
```

### 9. `LONGITUDINAL_CUSUM` (`longitudinal_cusum.yl2`)
* **Hypothesis**: Slow, low-and-slow creeping drift that evades 3-sigma single-day thresholds.
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $hist_max = max($stage1_extract.historical_max)

  $raw_drift = $observed - $hist_avg
  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $slack_allowance = 0.5 * $safe_stddev

  $slack_excess = $raw_drift - $slack_allowance
  $cusum_drift_score = if($slack_excess > 0, $slack_excess, 0.0)

order:
  $cusum_drift_score desc
```

### 10. `TWO_PART_HURDLE` (`two_part_hurdle.yl2`)
* **Hypothesis**: Zero-inflated dormant account reactivation: crossing the zero-hurdle warrants distinct penalty.
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $hist_max = max($stage1_extract.historical_max)

  $is_active_today = if($observed > 0, 1.0, 0.0)
  $dormant_score = $observed * 2.0

  $diff = $observed - $hist_avg
  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $intensity_z = $diff / $safe_stddev

  $hurdle_threat_score = if($active_days <= 2, $dormant_score, $intensity_z)

order:
  $hurdle_threat_score desc
```

### 11. `ASYMMETRIC_DIRECTIONAL_Z` (`asymmetric_directional_z.yl2`)
* **Hypothesis**: Security threats represent surges; drops below baseline are benign and should not alert.
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $hist_max = max($stage1_extract.historical_max)

  $diff = $observed - $hist_avg
  $excess_surge = if($diff > 0, $diff, 0.0)

  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $upper_tail_z = $excess_surge / $safe_stddev

order:
  $upper_tail_z desc
```

### 12. `PIECEWISE_CRI` (`piecewise_cri.yl2`)
* **Hypothesis**: Winsorized robust scaling mapped to discrete human-interpretable severity tiers [0-100].
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $hist_max = max($stage1_extract.historical_max)

  $diff = $observed - $hist_avg
  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $raw_z = $diff / $safe_stddev

  $clamped_low = if($raw_z < -4.0, -4.0, $raw_z)
  $clamped_z = if($clamped_low > 6.0, 6.0, $clamped_low)

  $cri_tier4 = if($clamped_z >= 4.0, 95.0, 85.0)
  $cri_tier3 = if($clamped_z >= 3.0, $cri_tier4, 65.0)
  $cri_tier2 = if($clamped_z >= 2.0, $cri_tier3, 40.0)
  $cri_score = if($clamped_z >= 1.0, $cri_tier2, 15.0)

order:
  $cri_score desc
```

### 13. `FLEET_PREVALENCE_SHIELD` (`fleet_prevalence_shield.yl2`)
* **Hypothesis**: Concurrent spikes across many fleet entities indicate global events (e.g. Patch Tuesday), not targeted attacks.
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $fleet_count = count($stage1_extract.observed_val)

  $diff = $observed - $hist_avg
  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $personal_z = $diff / $safe_stddev

  $prevalence_factor = if($fleet_count > 10, 0.15, 1.0)
  $shielded_z = $personal_z * $prevalence_factor

order:
  $shielded_z desc
```

### 14. `ADAPTIVE_CONTEXT_THRESHOLD` (`adaptive_context_threshold.yl2`)
* **Hypothesis**: Sensitivity should dynamically tighten during off-hours or dormant periods ($1.75\sigma$ vs $3.00\sigma$).
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $hist_max = max($stage1_extract.historical_max)

  $diff = $observed - $hist_avg
  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $personal_z = $diff / $safe_stddev

  $is_off_hours = if($active_days <= 5, 1.0, 0.0)
  $dynamic_threshold = if($is_off_hours > 0, 1.75, 3.00)
  $sensitivity_excess = $personal_z - $dynamic_threshold

order:
  $sensitivity_excess desc
```

---

## 4. ✅ Pre-Display Self-Concordance Checklist

Before emitting any query preview under a Pre-Flight Card in Phase 1B, verify:
1. **Model Identification**: Does the declared `• Statistical Model:` in the card correspond to one of the 14 defined models?
2. **Outcome Variable Audit**: Does the emitted query's `outcome:` block contain all mandatory variables specified in the matrix above?
3. **Primary Ranking Target**: Does the `order:` clause sort by the primary model output variable (e.g. `$cusum_drift_score desc`, `$hurdle_threat_score desc`, `$bayes_shift_ratio desc`)?
4. **No Univariate Fallback**: If an advanced model (e.g. Bayesian, CUSUM, Hurdle, Piecewise CRI) was declared, ensure it is NOT replaced by a bare standard $Z$-score.
