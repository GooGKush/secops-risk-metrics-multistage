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

## 2. 📊 The 17-Model AST Contract Matrix

| # | `StatisticalModel` Enum | Declared Prose Name | Mandatory `outcome:` Variables | Key Mathematical Operations | Primary `order:` Clause | Prohibited Fallback Anti-Pattern |
|---|---|---|---|---|---|---|
| 1 | `STANDARD_Z_SCORE` | Parametric Historical Z-Score | `$personal_diff`, `$safe_stddev`, `$personal_z` | Linear deviation, positive stddev guard | `order: $personal_z desc` | Missing safe stddev guard (`> 0`) |
| 2 | `MAD` | True Median Absolute Deviation / Modified $Z$ (with 30d $Z$ cross-check) | `$median_val`, `$mad`, `$mean_abs_dev`, `$robust_scale`, `$safe_robust_scale`, `$modified_z`, `$personal_z`, `$z_gap`, `$raw_active_days`, `$in_scoring_window` | `window.median` over stage1 daily rows (`mad_center` → `mad_spread`), $\text{MAD}/0.6745$, Iglewicz-Hoaglin $1.253314\cdot\text{meanAD}$ fallback | `order: $modified_z desc` | `0.6745 * (x - mean) / stddev` (a rescaled classical $Z$, not MAD) |
| 3 | `VARIANCE` | Fano Factor / Index of Dispersion | `$variance`, `$safe_lambda`, `$fano_factor` | Variance calculation ($\sigma^2$), ratio to mean | `order: $fano_factor desc` | Omitting variance calculation |
| 4 | `POISSON` | Discrete Poisson Rarity Z-Score | `$diff`, `$safe_lambda`, `$sqrt_lambda`, `$poisson_z` | `math.sqrt($safe_lambda)` | `order: $poisson_z desc` | Linear stddev denominator instead of square-root mean |
| 5 | `COEFFICIENT_OF_VARIATION` | CV Predictability & Surge Ratio | `$safe_hist_avg`, `$cv`, `$surge_ratio` | Relative dispersion ($\sigma / \mu$) | `order: $surge_ratio desc` | Standard Gaussian $Z$ without CV stability factor |
| 6 | `HOURLY_TEMPORAL_ZSCORE` | Intra-Day Hourly Temporal Z-Score | `$observed_hour`, `$avg_hourly`, `$hourly_diff`, `$safe_stddev_hourly`, `$hourly_z`, `$hourly_surge_ratio` | Match `by 1h`, intra-day fold surge ratio | `order: $hourly_z desc` | Daily aggregation (`by 1d`) when hourly profiling is declared |
| 7 | `BAYESIAN_GAMMA` | Empirical Bayes Poisson-Gamma Conjugate | `$variance_raw`, `$safe_variance`, `$beta_prior`, `$alpha_prior`, `$alpha_post`, `$beta_post`, `$posterior_mean`, `$bayes_shift_ratio` | Method of Moments hyperparameters, posterior conjugate updating | `order: $bayes_shift_ratio desc` | Bare $Z$-score omitting Gamma hyperparameters ($\alpha, \beta$) |
| 8 | `BAYESIAN_BETA_BINOMIAL` | Beta-Binomial Bayesian Ratio Regularization | `$avg_fail_prob`, `$safe_variance`, `$one_minus_p`, `$sample_factor`, `$alpha_prior`, `$beta_prior`, `$alpha_post`, `$beta_post`, `$posterior_fail_prob` | Binomial variance, sample factor weighting, conjugate update | `order: $posterior_fail_prob desc` | Raw failure counts without Beta prior sample factor |
| 9 | `LONGITUDINAL_CUSUM` | Longitudinal CUSUM Drift Accumulation | `$raw_drift`, `$safe_stddev`, `$slack_allowance`, `$slack_excess`, `$cusum_drift_score` | Page's CUSUM slack allowance ($0.5\sigma$), half-rectification (`if > 0`) | `order: $cusum_drift_score desc` | Standard $Z$-score omitting slack deduction or rectification |
| 10 | `TWO_PART_HURDLE` | Two-Part Hurdle Model (Zero-Inflated) | `$is_active_today`, `$dormant_score`, `$diff`, `$safe_stddev`, `$intensity_z`, `$hurdle_threat_score` | Bernoulli hurdle trigger, conditional continuous intensity | `order: $hurdle_threat_score desc` | Single-equation continuous model without dormant penalty |
| 11 | `ASYMMETRIC_DIRECTIONAL_Z` | Asymmetric Directional Z-Score | `$diff`, `$excess_surge`, `$safe_stddev`, `$upper_tail_z` | ReLU activation (`if($diff > 0, $diff, 0.0)`), upper-tail focus | `order: $upper_tail_z desc` | Two-tailed symmetrical Z-score penalizing activity drops |
| 12 | `PIECEWISE_CRI` | Winsorized Z-Score & Piecewise CRI | `$diff`, `$safe_stddev`, `$raw_z`, `$clamped_low`, `$clamped_z`, `$cri_tier4`, `$cri_tier3`, `$cri_tier2`, `$cri_score` | Winsorization clamp to $[-4.0, +6.0]$, piecewise tiers [0-100] | `order: $cri_score desc` | Unclamped unbounded Z-score |
| 13 | `FLEET_PREVALENCE_SHIELD` | Fleet Prevalence Discounting | `$fleet_count`, `$diff`, `$safe_stddev`, `$personal_z`, `$prevalence_factor`, `$shielded_z` | Fleet aggregation (`count`), immunity factor discounting | `order: $shielded_z desc` | Individual Z-score lacking fleet count suppression |
| 14 | `ADAPTIVE_CONTEXT_THRESHOLD` | Context-Modulated Adaptive Sensitivity | `$diff`, `$safe_stddev`, `$personal_z`, `$is_off_hours`, `$dynamic_threshold`, `$sensitivity_excess` | Off-hours sensitivity tightening ($1.75\sigma$ vs $3.00\sigma$) | `order: $sensitivity_excess desc` | Static uniform threshold across all operating contexts |
| 15 | `MACD_MOMENTUM_VELOCITY` | MACD Dual-Spine Momentum Indicator | `$fast_diff`, `$safe_stddev`, `$fast_z`, `$slow_diff`, `$slow_z`, `$macd_diff`, `$safe_max`, `$velocity_ratio`, `$scaled_diff`, `$macd_momentum_score` | Fast spine deviation, slow reference anchor, velocity ratio amplification | `order: $macd_momentum_score desc` | Univariate standard Z fallback |
| 16 | `CIRCADIAN_VON_MISES` | Circadian von Mises Temporal Distance | `$hourly_diff`, `$safe_stddev_hourly`, `$hourly_z`, `$event_hour`, `$raw_diff`, `$inverted_dist`, `$circ_dist`, `$von_mises_arc`, `$temporal_penalty`, `$temporal_multiplier`, `$circadian_threat_score` | Circular distance on 24h clock, quadratic von Mises penalty ($d^2 / 72.0$) | `order: $circadian_threat_score desc` | Linear Euclidean hour subtraction |
| 17 | `RELATIVE_DEVIATION` | Relative Deviation / Fold Change vs 30d Mean | `$dev`, `$safe_hist_avg`, `$ratio` | $(x-\mu)/\mu$ fold change | `order: $ratio desc` | Labelling it MAD (it is mean-anchored, 0% breakdown point) |

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
* **Hypothesis**: Robust, median-anchored departure that historic bursts cannot mask (breakdown point 50% vs 0% for mean/stddev). Available on request on top of ANY stage1 extractor, in Mode A or Mode B.
* **Topology**: stage1 extractor (event stage) → `mad_center` (median of daily `$observed_val`) → `mad_spread` (MAD and mean absolute deviation) → root. Only one event stage, so the 2-event-stage ceiling is untouched.
* **Search Window Contract**: the raw search window IS the robust baseline (~30d ending at the scoring end date). The scored days are gated by `$in_scoring_window`, a date-string flag injected into stage1 (`timestamp.get_date(...) >= "<first scored date>"`); never wall-clock time, never an epoch literal. Mode A scores 1 day, Mode B 2-14.
* **Mandatory AST Contract** (verified live on gus-sdl, 2026-10-07):
```yara
stage mad_center {
    $entity = $stage1_extract.entity
  match:
    $entity
  outcome:
    $median_val = window.median($stage1_extract.observed_val, false)
    $raw_active_days = count_distinct($stage1_extract.window_start)
}

stage mad_spread {
    $entity = $stage1_extract.entity
    $entity = $mad_center.entity
  match:
    $entity
  outcome:
    $mad = window.median(math.abs($stage1_extract.observed_val - $mad_center.median_val), false)
    $mean_abs_dev = avg(math.abs($stage1_extract.observed_val - $mad_center.median_val))
    $median_val = max($mad_center.median_val)
    $raw_active_days = max($mad_center.raw_active_days)
}

$entity = $stage1_extract.entity
$entity = $mad_spread.entity
$ws = $stage1_extract.window_start

match:
  $entity, $ws by 1d

outcome:
  // ... $observed, $hist_avg, $hist_stddev, $median_val, $mad, $mean_abs_dev, $in_scoring_window ...
  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $personal_z = ($observed - $hist_avg) / $safe_stddev
  $scale_from_mad = $mad / 0.6745
  $scale_from_meanad = $mean_abs_dev * 1.253314
  $robust_scale = if($mad > 0, $scale_from_mad, $scale_from_meanad)
  $median_floor = $median_val * 0.05 + 1.0
  $safe_robust_scale = if($robust_scale > 0, $robust_scale, $median_floor)
  $modified_z = ($observed - $median_val) / $safe_robust_scale
  $z_gap = $modified_z - $personal_z

condition:
  $in_scoring_window = 1 and $raw_active_days >= 7

order:
  $modified_z desc
```
* **Reading the output**: default significance $M_z \ge 3.5$ (Iglewicz-Hoaglin). `$z_gap` $\gg 0$ means the 30d mean/stddev were inflated by historic bursts and the classical $Z$ is masking an anomaly the robust score sees.
* **Caveats**: zero-activity days produce no stage1 row (median over ACTIVE days, biased upward for sparse entities; `$raw_active_days` is the sample size); the scored day sits inside its own baseline (tolerated by the 50% breakdown point).

### 3. `VARIANCE` (`variance_fano.yl2`)
* **Hypothesis**: Overdispersed behavioral burstiness indicating automated batching or scripting ($Var / \mu > 1.0$).
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $lambda = max($stage1_extract.historical_avg)
  $stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  $variance = math.pow($stddev, 2)
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
<!-- yara-fragment: root-stage AST contract excerpt -->
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

  $variance_raw = math.pow($stddev_30d, 2)
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

  $variance_raw = math.pow($stddev_p, 2)
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

### 13. `FLEET_PREVALENCE_SHIELD` (`fleet_prevalence_shield.yl2` & `hybrid_metric_fleet_prevalence_2stage.yl2`)
* **Hypothesis**: Concurrent spikes across many fleet entities indicate global events (e.g. Patch Tuesday / enterprise IT rollouts), not targeted attacks.
* **Variant A: Single-Plane Metric Prevalence Shield (`fleet_prevalence_shield.yl2`)**:
  - *Mandatory AST Contract*:
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
* **Variant B: Dual-Plane Token-Centric Normalization (`hybrid_metric_fleet_prevalence_2stage.yl2`)**:
  - *Use Case*: Process execution hunts for unfamiliar binaries during deployments (`target.process.file.sha256 = $token`).
  - *Match Topology*: Match on `$token by 1d`, joining Stage 1 personal surge with Stage 2 fleet breadth.
  - *Hyperbolic Prevalence Dampener*: `$prevalence_dampener = 1.0 / ($fleet_adopters + 1.0)`
  - *Outlier Scoring*: `$normalized_odds_score = $personal_z * $prevalence_dampener` (order: `$normalized_odds_score desc`).


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

### 15. `MACD_MOMENTUM_VELOCITY` (`macd_momentum_velocity.yl2`)
* **Hypothesis**: Detects sudden momentum acceleration where short-term surge diverges from slow baseline anchor and exceeds historical maximum departure.
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $hist_max = max($stage1_extract.historical_max)

  // 1. Fast Spine: Instantaneous Standardized Deviation (Daily Velocity)
  $fast_diff = $observed - $hist_avg
  $safe_stddev = if($hist_stddev > 0, $hist_stddev, 1.0)
  $fast_z = $fast_diff / $safe_stddev

  // 2. Slow Spine: Historical Baseline Departure (Reference Anchor)
  $slow_diff = $hist_max - $hist_avg
  $slow_z = $slow_diff / $safe_stddev

  // 3. Momentum Velocity & Divergence (MACD Spread)
  $macd_diff = $fast_z - $slow_z
  $safe_max = if($hist_max > 0, $hist_max, 1.0)
  $velocity_ratio = $observed / $safe_max

  // 4. Half-Rectified Acceleration Surge
  $scaled_diff = $macd_diff * $velocity_ratio
  $macd_momentum_score = if($macd_diff > 0, $scaled_diff, $fast_z)

order:
  $macd_momentum_score desc
```

### 16. `CIRCADIAN_VON_MISES` (`circadian_von_mises.yl2`)
* **Hypothesis**: Evaluates hourly telemetry against a 24-hour circular clock to penalize off-hours deviations using von Mises quadratic arc distance.
* **Mandatory AST Contract**:
```yara
outcome:
  $observed_hour = max($stage1_extract.observed_val)
  $avg_hourly = max($stage1_extract.historical_avg)
  $stddev_hourly = max($stage1_extract.historical_stddev)
  $event_hour = max($stage1_extract.event_hour)
  $active_days = max($stage1_extract.historical_active_days)
  $max_hourly = max($stage1_extract.historical_max)

  // 1. Hourly Volumetric Z-Score
  $hourly_diff = $observed_hour - $avg_hourly
  $safe_stddev_hourly = if($stddev_hourly > 0, $stddev_hourly, 1.0)
  $hourly_z = $hourly_diff / $safe_stddev_hourly

  // 2. Circadian von Mises Circular Distance (24-Hour Circular Clock)
  // Expected Peak Operating Hour: 14:00 UTC (Anchor)
  $raw_diff = math.abs($event_hour - 14)
  $inverted_dist = 24 - $raw_diff
  $circ_dist = if($raw_diff > 12, $inverted_dist, $raw_diff)
  $von_mises_arc = math.pow($circ_dist, 2)
  $temporal_penalty = $von_mises_arc / 72.0

  // 3. Combined Circadian Threat Score: Hourly Volume Surge Scaled by Temporal Deviance
  $temporal_multiplier = 1.0 + $temporal_penalty
  $circadian_threat_score = $hourly_z * $temporal_multiplier

order:
  $circadian_threat_score desc
```

### 17. `RELATIVE_DEVIATION` (`relative_deviation.yl2`)
* **Hypothesis**: Scale-free fold change against the 30d mean ("3.2x the usual volume"). Easy to read, but mean-anchored: one historic burst inflates the denominator. This was formerly (mis)labelled `MAD`.
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

---

## 4. ✅ Pre-Display Self-Concordance Checklist

Before emitting any query preview under a Pre-Flight Card in Phase 1B, verify:
1. **Model Identification**: Does the declared `• Statistical Model:` in the card correspond to one of the 17 defined models?
2. **Outcome Variable Audit**: Does the emitted query's `outcome:` block contain all mandatory variables specified in the matrix above?
3. **Primary Ranking Target**: Does the `order:` clause sort by the primary model output variable (e.g. `$cusum_drift_score desc`, `$hurdle_threat_score desc`, `$bayes_shift_ratio desc`)?
4. **No Univariate Fallback**: If an advanced model (e.g. Bayesian, CUSUM, Hurdle, Piecewise CRI) was declared, ensure it is NOT replaced by a bare standard $Z$-score.
5. **Outcome `if(...)` Compiler Invariant**: Chronicle SIEM compiler strictly forbids compound arithmetic (function calls or operations) inside the `then` or `else` clauses of `if(cond, then, else)`. Only placeholders, event fields, and constants are permitted. When computing standardized anomaly scores, construct the one-stop outcome nested logic model directly:
   ```yara
   $personal_z = ($observed_val - $baseline_mean) / if($baseline_stddev > 0, $baseline_stddev, 1.0)
   ```
