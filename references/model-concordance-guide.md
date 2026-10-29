# 📐 Model Concordance Guide: AST Signatures & Mathematical Invariants

In Google SecOps Multi-Stage Risk Analytics, the **Model Concordance Invariant** bridges the gap between what an analyst or agent promises in human-readable prose (Phase 1B Pre-Flight Card) and what is actually computed in code (YARA-L AST `outcome:` block).

---

## 1. 🏛️ The Architectural Invariant & The Concordance Contract

### The "Aspirational Pre-Flight" Problem
In multi-stage hunting workflows:
1. In **Phase 1B (Pre-Flight Plan)**, the agent declares a statistical model in prose, e.g.:
   `• Statistical Model: Empirical Bayes Poisson-Gamma Conjugate Updating (Shrinkage Prior)`
2. The mandatory event-filter probe (`udm_search(..., maxEvents: 1)`) executes against Chronicle SIEM. Crucially, **the probe only validates UDM event predicates** (`metadata.event_type`, `principal.user.userid`). It has zero visibility into the YARA-L Stage 2 DAG or its `outcome:` block arithmetic.
3. Without explicit concordance enforcement, an agent may exhibit "model degradation": declaring an advanced model in prose, but lazily emitting a generic univariate Gaussian $Z$-score (`$z = ($observed - $avg) / $stddev`) in the code block.

### The Concordance Principle
> [!IMPORTANT]
> **Strict Semantic Parity**:
> Every query preview emitted under a Pre-Flight Card and executed in State 2 **MUST** contain the exact mathematical AST structure of the declared model. Emitting a bare univariate $Z$-score when an advanced model is declared is strictly prohibited.

---

## 2. 📊 The 17-Model AST Contract Matrix

| # | `StatisticalModel` Enum | Declared Prose Name | Mandatory `outcome:` Variables | Key Mathematical Operations | Primary `order:` Clause | Prohibited Fallback Anti-Pattern |
|---|---|---|---|---|---|---|
| 1 | `STANDARD_Z_SCORE` | Parametric Historical Z-Score | `$personal_diff`, `$dispersion_floor`, `$safe_stddev`, `$personal_z` | Linear deviation, D8 count/byte dispersion floor (`sqrt(max(avg, 1.0))` or fleet byte floor), `$active_days >= 7` gate | `order: $personal_z desc` | Missing dispersion floor (`1.0` fallback) or missing `$active_days >= 7` gate |
| 2 | `MAD` | True Median Absolute Deviation / Modified $Z$ (with 30d $Z$ cross-check) | `$median_val`, `$mad`, `$mean_abs_dev`, `$robust_scale`, `$safe_robust_scale`, `$modified_z`, `$personal_z`, `$z_gap`, `$raw_active_days`, `$in_scoring_window` | `window.median` over stage1 daily rows (`mad_center` → `mad_spread`), $\text{MAD}/0.6745$, Iglewicz-Hoaglin $1.253314\cdot\text{meanAD}$ fallback | `order: $modified_z desc` | `0.6745 * (x - mean) / stddev` (a rescaled classical $Z$, not MAD) |
| 3 | `VARIANCE` | Fano Factor / Index of Dispersion | `$variance`, `$safe_lambda`, `$fano_factor` | Variance calculation ($\sigma^2$), ratio to mean | `order: $fano_factor desc` | Omitting variance calculation |
| 4 | `POISSON` | Discrete Poisson Rarity Z-Score | `$diff`, `$safe_lambda`, `$sqrt_lambda`, `$poisson_z` | `math.sqrt($safe_lambda)` | `order: $poisson_z desc` | Linear stddev denominator instead of square-root mean |
| 5 | `COEFFICIENT_OF_VARIATION` | CV Predictability & Surge Ratio | `$safe_hist_avg`, `$cv`, `$surge_ratio` | Relative dispersion ($\sigma / \mu$) | `order: $surge_ratio desc` | Standard Gaussian $Z$ without CV stability factor |
| 6 | `HOURLY_TEMPORAL_ZSCORE` | Intra-Day Hourly Temporal Z-Score | `$observed_hour`, `$avg_hourly`, `$hourly_diff`, `$safe_stddev_hourly`, `$hourly_z`, `$hourly_surge_ratio` | Match `by 1h`, intra-day fold surge ratio | `order: $hourly_z desc` | Daily aggregation (`by 1d`) when hourly profiling is declared |
| 7 | `BAYESIAN_GAMMA` | Empirical Bayes Poisson-Gamma Conjugate | `$variance_raw`, `$safe_variance`, `$beta_prior`, `$alpha_prior`, `$alpha_post`, `$beta_post`, `$posterior_mean`, `$bayes_shift_ratio` | Method of Moments hyperparameters, posterior conjugate updating | `order: $bayes_shift_ratio desc` | Bare $Z$-score omitting Gamma hyperparameters ($\alpha, \beta$) |
| 8 | `BAYESIAN_BETA_BINOMIAL` | Beta-Binomial Bayesian Ratio Regularization | `$denom_scale`, `$scaled_prior`, `$scaled_obs`, `$prior_rate`, `$obs_rate`, `$prior_alpha`, `$prior_beta`, `$post_alpha`, `$post_denom`, `$posterior_rate`, `$safe_prior`, `$posterior_lift` | Proportion normalization into `[0, 1]`, M=10 Beta prior, N=10 conjugate update | `order: $posterior_lift desc` | Unnormalized raw counts (>1.0) causing negative `1.0 - p` |
| 9 | `LONGITUDINAL_CUSUM` | Longitudinal CUSUM Drift Accumulation | `$raw_drift`, `$safe_stddev`, `$slack_allowance`, `$slack_excess`, `$daily_excess`, `$cusum_drift`, `$cusum_drift_score`, `$drift_days` | Per-day slack excess ($Z_t - 0.5\sigma$), multi-day `sum($stage2_daily_drift.daily_excess)` across window | `order: $cusum_drift_score desc` | Single-bucket Z-score omitting multi-day drift accumulation |
| 10 | `TWO_PART_HURDLE` | Two-Part Hurdle Model (Zero-Inflated) | `$is_dormant_awakening`, `$raw_diff`, `$safe_stddev`, `$intensity_z`, `$obs_plus_one`, `$log_obs`, `$dormant_score`, `$hurdle_threat_score` | Bernoulli hurdle trigger (`10.0 + math.log($obs_plus_one)`), conditional continuous intensity | `order: $hurdle_threat_score desc` | Single-equation continuous model without dormant penalty |
| 11 | `ASYMMETRIC_DIRECTIONAL_Z` | Asymmetric Directional Z-Score | `$diff`, `$excess_surge`, `$safe_stddev`, `$upper_tail_z` | ReLU activation (`if($diff > 0, $diff, 0.0)`), upper-tail focus | `order: $upper_tail_z desc` | Two-tailed symmetrical Z-score penalizing activity drops |
| 12 | `PIECEWISE_CRI` | Winsorized Z-Score & Piecewise CRI | `$diff`, `$safe_stddev`, `$raw_z`, `$clamped_low`, `$clamped_z`, `$cri_tier4`, `$cri_tier3`, `$cri_tier2`, `$cri_score` | Winsorization clamp to $[-4.0, +6.0]$, piecewise tiers [0-100] | `order: $cri_score desc` | Unclamped unbounded Z-score |
| 13 | `FLEET_PREVALENCE_SHIELD` | Fleet Prevalence Discounting | `$fleet_entities`, `$raw_diff`, `$safe_stddev`, `$personal_z`, `$fleet_count`, `$log_fleet`, `$prevalence_factor`, `$shielded_z` | Cross-entity `stage2_fleet_wave` (`count_distinct`), log-prevalence dampening (`1.0 + math.log($fleet_count)`) | `order: $shielded_z desc` | Per-entity `count()` always equalling 1 or lacking fleet wave stage |
| 14 | `ADAPTIVE_CONTEXT_THRESHOLD` | Baseline-Maturity Adaptive Sensitivity | `$raw_diff`, `$safe_stddev`, `$personal_z`, `$sparse_threshold`, `$mature_threshold`, `$effective_threshold`, `$sensitivity_excess` | Baseline-maturity thresholding ($3.5\sigma$ for sparse `< 7d` vs $2.5\sigma$ for mature `>= 7d`) | `order: $sensitivity_excess desc` | Static uniform threshold or loosening threshold on noisy sparse baselines |
| 15 | `MACD_MOMENTUM_VELOCITY` | MACD Dual-Spine Momentum Indicator | `$fast_diff`, `$safe_stddev`, `$fast_z`, `$slow_diff`, `$slow_z`, `$macd_diff`, `$safe_max`, `$velocity_ratio`, `$breakout_boost`, `$breakout_score`, `$macd_momentum_score` | Fast spine deviation, slow reference anchor, monotone ceiling breakout boost (`$fast_z + $breakout_boost`) | `order: $macd_momentum_score desc` | Non-monotone cliff at historical max or univariate Z fallback |
| 16 | `CIRCADIAN_VON_MISES` | Circadian von Mises Temporal Distance | `$avg_hourly`, `$scaled_hourly_sd`, `$safe_stddev_hourly`, `$hourly_diff`, `$hourly_z`, `$event_hour`, `$raw_hour_diff`, `$abs_hour_diff`, `$wrap_dist`, `$circ_dist`, `$norm_dist`, `$circadian_weight`, `$pos_z`, `$circadian_threat_score` | Hourly baseline normalization (`mean/24`, `sd/4.899`), circular 24h distance, linear off-hours weight (`1.0 + d/12`) | `order: $circadian_threat_score desc` | Comparing 1h count directly against unscaled 24h daily mean |
| 17 | `RELATIVE_DEVIATION` | Relative Deviation / Fold Change vs 30d Mean | `$dev`, `$safe_hist_avg`, `$ratio` | $(x-\mu)/\mu$ fold change | `order: $ratio desc` | Labelling it MAD (it is mean-anchored, 0% breakdown point) |
| 18 | `QUANTILE_IQR_SKEW` | 1-Stage Non-Parametric Quantiles, Bowley Skewness & Skew-Adjusted Tukey Fence | `$q25_val`, `$q50_val`, `$q75_val`, `$iqr`, `$safe_iqr`, `$bowley_skew`, `$tail_heaviness`, `$adj_upper_fence`, `$tukey_fence_ratio` | `window.percentile` 5-point envelope in 1 stage, Bowley skewness, Hubert–Vandervieren fence | `order: $tukey_fence_ratio desc` | Consuming 2 stages when 1-stage quantile envelope suffices |

### 2.1 Default Root Significance Gate (the card's `Significance Threshold`)

Every query carries the model's significance gate as a root `condition:` placed between `outcome:` and `order:`. The gate variable is not always the `order:` variable, and not every model is scored in σ. The Pre-Flight card's `• Significance Threshold:` line MUST state the gate from this table (adjusted if the analyst tunes it), and the emitted `condition:` MUST match it.

| Model | Gate variable | Default root `condition:` | Unit | Card wording | Template placeholder |
|---|---|---|---|---|---|
| `STANDARD_Z_SCORE` | `$active_days`, `$personal_z` | `$active_days >= 7 and $personal_z >= 3.0` | σ | `Z >= 3.0σ` | `{{anomaly_threshold}}` |
| `ASYMMETRIC_DIRECTIONAL_Z` | `$active_days`, `$upper_tail_z` | `$active_days >= 7 and $upper_tail_z >= 3.0` | σ | `Upper-tail Z >= 3.0σ` | `{{anomaly_threshold}}` |
| `POISSON` | `$poisson_z` | `$poisson_z >= 3.0` | σ (√λ) | `Poisson Z >= 3.0σ` | `{{anomaly_threshold}}` |
| `HOURLY_TEMPORAL_ZSCORE` | `$active_days`, `$hourly_z` | `$active_days >= 7 and $hourly_z >= 3.0` | σ (hourly) | `Hourly Z >= 3.0σ` | `{{anomaly_threshold}}` |
| `CIRCADIAN_VON_MISES` | `$active_days`, `$circadian_threat_score` | `$active_days >= 7 and $circadian_threat_score >= 3.0` | σ × off-hours multiplier | `Circadian score >= 3.0` | `{{anomaly_threshold}}` |
| `MACD_MOMENTUM_VELOCITY` | `$active_days`, `$fast_z` | `$active_days >= 7 and $fast_z >= 3.0` (ranked by momentum) | σ | `Fast Z >= 3.0σ` | `{{anomaly_threshold}}` |
| `PIECEWISE_CRI` | `$active_days`, `$clamped_z` | `$active_days >= 7 and $clamped_z >= 3.0` (ranked by CRI tier) | σ (winsorized) | `Z >= 3.0σ (CRI >= 85)` | `{{anomaly_threshold}}` |
| `FLEET_PREVALENCE_SHIELD` | `$active_days`, `$shielded_z` | `$active_days >= 7 and $shielded_z >= 3.0` | σ (fleet-discounted) | `Shielded Z >= 3.0σ` | `{{anomaly_threshold}}` |
| `TWO_PART_HURDLE` | `$active_days`, `$intensity_z` | `$active_days <= 2 or $intensity_z >= 3.0` | dormancy break or σ | `Dormant awakening OR Z >= 3.0σ` | `{{anomaly_threshold}}` |
| `ADAPTIVE_CONTEXT_THRESHOLD` | `$active_days`, `$sensitivity_excess` | `$active_days >= 7 and $sensitivity_excess >= 0.0` | σ above the context threshold (1.75σ / 3.00σ) | `Z >= context threshold` | none (built into the score) |
| `LONGITUDINAL_CUSUM` | `$active_days`, `$cusum_drift_score`, `$drift_days` | `$active_days >= 7 and $cusum_drift_score >= 3.0 and $drift_days >= 2` | cumulative σ excess over 0.5σ slack | `Drift above 0.5σ slack` | `{{anomaly_threshold}}` |
| `BAYESIAN_GAMMA` | `$bayes_shift_ratio` | `$bayes_shift_ratio >= 2.0` | fold change (posterior / 30d mean) | `>= 2.0× baseline (posterior)` | `{{fold_change_threshold}}` |
| `BAYESIAN_BETA_BINOMIAL` | `$posterior_lift` | `$posterior_lift >= 2.0` | fold change (posterior / prior) | `>= 2.0× prior failure rate` | `{{fold_change_threshold}}` |
| `COEFFICIENT_OF_VARIATION` | `$active_days`, `$surge_ratio`, `$cv` | `$active_days >= 7 and $surge_ratio >= 2.0 and $cv <= 0.5` | fold change on a predictable entity | `>= 2.0× baseline, CV <= 0.5` | `{{fold_change_threshold}}` |
| `RELATIVE_DEVIATION` | `$fold_change` | `$fold_change >= 2.0` (ranked by `$ratio`) | fold change | `>= 2.0× baseline` | `{{fold_change_threshold}}` |
| `MAD` | `$modified_z` | `... and $modified_z >= 3.5` (AND-ed with the scoring-window and sample-size gates) | modified Z | `Modified Z >= 3.5` | `{{robust_threshold}}` |
| `QUANTILE_IQR_SKEW` | `$tukey_fence_ratio` | `$in_scoring_window = 1 and $raw_active_days >= 7 and $tukey_fence_ratio >= 2.0` | fold over fence | `Skew-Adjusted Fence >= 2.0×` | `{{fold_change_threshold}}` |
| `VARIANCE` (Fano) | — | **none** (`// NO-GATE`) | — | `N/A (dispersion screen)` | — |

* **Why fold change for the ratio models**: their scores are not in σ, and a fold change ("2× the usual") needs no statistical background to read. The 2.0× default is a convention, not a calibrated tail probability. Tune it like any other threshold.
* **Why Fano has no gate**: $\sigma^2/\mu$ is computed from the 30-day baseline only, so it does not change with the scored day's value. It ranks historical burstiness (a screen for choosing Poisson vs Gaussian), not a day-level anomaly.
* **Pipelines**: σ-scored pipelines gate their score at `{{anomaly_threshold}}` (`$delta_z`, `$z_sector`, `$composite_risk`, `$z_vs_enterprise` / `$z_vs_team`). Euclidean fusion and triads gate D² at `{{fusion_threshold_sq}}` (default `12.25`, i.e. D >= 3.5σ). `hierarchical_empirical_bayes_3stage` gates `$empirical_shift >= {{fold_change_threshold}}`. The three `radar_360_*` sector micro-queries are `NO-GATE` because every sector must be reported, nominal included.
* **Tuning**: an analyst threshold (or a band such as `2.0σ <= Z < 3.0σ`) **replaces** the default gate clause on the same gate variable. It is never added as a second `condition:` block.
* **Zero baselines**: when the 30-day mean is 0, the divisor floor (`if($hist_avg > 0, $hist_avg, 1.0)`) makes any activity a large fold change, so first-seen entities pass fold-change gates. Read such rows as dormancy breaks, not volume surges.

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
  $dispersion_floor = math.sqrt(if($hist_avg > 1.0, $hist_avg, 1.0))
  $safe_stddev = if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)
  $personal_z = $personal_diff / $safe_stddev

condition:
  $active_days >= 7 and $personal_z >= 3.0

order:
  $personal_z desc
```

### 2. `MAD` (`mad.yl2`)
* **Hypothesis**: Robust, median-anchored departure that historic bursts cannot mask (breakdown point 50% vs 0% for mean/stddev). Available on request on top of ANY stage1 extractor, in Mode A or Mode B.
* **Topology**: stage1 extractor (event stage) → `mad_center` (median of daily `$observed_val`) → `mad_spread` (MAD and mean absolute deviation) → root. Only one event stage, so the 2-event-stage ceiling is untouched.
* **Data sources**: MAD and `$modified_z` come only from the raw daily `$observed_val`. `metrics.*` feeds only the `$personal_z` / `$z_gap` cross-check, so the router keeps just the avg, stddev and num_metric_periods lookups for MAD (3 per entity-day; `historical_max` / `historical_sum` are pruned).
* **Multi-key extractors**: MAD groups every stage (stage1, `mad_center`, `mad_spread`, root) by the metric's baseline tuple: the stage1 match variables whose UDM field is a `metrics.*` dimension argument. Match variables that are not dimensions are dropped from stage1, because they would split one baseline into thin per-value series (only `$ip` on `resource_*`). Examples: `resource_*` → `$sa, $vendor, $product, $resource`; `file_executions_*` → `$host, $sha256`; `alert_event_name_count` → `$host, $rule_name`. Caveat: a finer tuple means fewer active days per series, and tuples with fewer than `min_baseline_days` active days drop out of the results.
* **Cloud-repository redirect exemption**: for `resource_read_total`, `resource_written_total`, `resource_written_success` and `resource_written_fail` with a USER entity, every other model renders `cloud_repository_scope_dual_branch.yl2`. An explicit MAD request renders the MAD pipeline instead, keyed per repository tuple as above.
* **Search Window Contract**: the raw search window IS the robust baseline (~30d ending at the scoring end date). The scored days are gated by `$in_scoring_window`, a date-string flag injected into stage1 (`timestamp.get_date(...) >= "<first scored date>"`); never wall-clock time, never an epoch literal. Mode A scores 1 day, Mode B 2-7.
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
  $in_scoring_window = 1 and $raw_active_days >= 7 and $modified_z >= 3.5

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

// NO-GATE: the Fano factor uses only the 30-day baseline (independent of the scored day),
// so no significance threshold applies.
order:
  $fano_factor desc
```

### 4. `POISSON` (`poisson_rarity.yl2`)
* **Hypothesis**: Discrete integer event arrival rarity where variance equals per-calendar-day mean ($\lambda = S/30$, $\sigma = \sqrt{\lambda}$), with rebuilt 30-day calendar variance (`PF-1`, `PF-2`, `WS1-05`).
* **Mandatory AST Contract**:
```yara
outcome:
  $k = max($stage1_extract.observed_val)
  $hist_sum = max($stage1_extract.historical_sum)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  $lambda = $hist_sum / 30.0
  $sum_x = $active_days * $hist_avg
  $df_minus_one = if($active_days > 1, $active_days, 1) - 1
  $sum_x2 = ($df_minus_one * $hist_stddev * $hist_stddev) + ($active_days * $hist_avg * $hist_avg)
  $mu_cal = $sum_x / 30.0
  $raw_var_cal = ($sum_x2 / 30.0) - ($mu_cal * $mu_cal)
  $var_cal = if($raw_var_cal > 0.0, $raw_var_cal, 0.0)
  $sd_cal = math.sqrt($var_cal)

  $diff = $k - $lambda
  $safe_lambda = if($lambda > 0, $lambda, 1.0)
  $sqrt_lambda = math.sqrt($safe_lambda)
  $poisson_z = $diff / $sqrt_lambda

condition:
  $poisson_z >= 3.0

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

condition:
  $active_days >= 7 and $surge_ratio >= 2.0 and $cv <= 0.5

order:
  $surge_ratio desc
```

### 6. `HOURLY_TEMPORAL_ZSCORE` (`hourly_temporal_zscore.yl2`)
* **Hypothesis**: Intra-day burst localized to a 1-hour bucket (`by 1h`) compared against the 30-day macro baseline (`period: 1d, window: 30d` — the only `period`/`window` combination supported on `metrics.*`).
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
  $dispersion_floor = math.sqrt(if($avg_hourly > 1.0, $avg_hourly, 1.0))
  $safe_stddev_hourly = if($stddev_hourly > $dispersion_floor, $stddev_hourly, $dispersion_floor)
  $hourly_z = $hourly_diff / $safe_stddev_hourly

  $safe_avg_hourly = if($avg_hourly > 0, $avg_hourly, 1.0)
  $hourly_surge_ratio = $observed_hour / $safe_avg_hourly

condition:
  $active_days >= 7 and $hourly_z >= 3.0

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

condition:
  $bayes_shift_ratio >= 2.0

order:
  $bayes_shift_ratio desc
```

### 8. `BAYESIAN_BETA_BINOMIAL` (`beta_binomial_bayesian.yl2`)
* **Hypothesis**: Ratio and failure probability regularization under small-sample discrete Bernoulli trials. Normalizes raw count/volume inputs into `[0, 1]` proportions when paired with count/volume extractors, while preserving exact `[0, 1]` ratios when paired with proportion extractors. *(Note: `metrics.*_fail` tables store daily failure counts via `event_count_sum`; for failure-to-total ratio surges across `*_fail` and `*_total` count metrics, use `http_error_ratio_surge_2stage.yl2` / `build_failure_ratio_surge_query()`.)*
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $active_days = max($stage1_extract.historical_active_days)

  $denom_scale = $observed + $hist_avg + 1.0
  $scaled_prior = $hist_avg / $denom_scale
  $scaled_obs = $observed / $denom_scale
  $prior_rate = if($hist_avg <= 1.0 and $observed <= 1.0, $hist_avg, $scaled_prior)
  $obs_rate = if($hist_avg <= 1.0 and $observed <= 1.0, $observed, $scaled_obs)

  $prior_alpha = $prior_rate * 10.0
  $prior_beta = (1.0 - $prior_rate) * 10.0

  $post_alpha = $prior_alpha + ($obs_rate * 10.0)
  $post_denom = $prior_alpha + $prior_beta + 10.0
  $posterior_rate = $post_alpha / $post_denom
  $safe_prior = if($prior_rate > 0.001, $prior_rate, 0.001)
  $posterior_lift = $posterior_rate / $safe_prior

condition:
  $posterior_lift >= 2.0

order:
  $posterior_lift desc
```

### 9. `LONGITUDINAL_CUSUM` (`longitudinal_cusum.yl2` & `longitudinal_drift_cusum_2stage.yl2`)
* **Hypothesis**: Slow, low-and-slow creeping drift that evades 3-sigma single-day thresholds. (`longitudinal_cusum.yl2` extracts per-day positive slack excess in `stage2_daily_drift` and sums it across the multi-day window in the Root Stage; `scripts/timeline_assembler.py` computes true sequential Page's CUSUM $S_t = \max(0, S_{t-1} + Z_t - k)$ across Mode C daily shards.)
* **Mandatory AST Contract**:
```yara
stage stage2_daily_drift {
    $entity = $stage1_extract.entity
    $day_ws = $stage1_extract.window_start

  match:
    $entity, $day_ws by 1d

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
    $daily_z = $raw_drift / $safe_stddev
    $z_minus_slack = $daily_z - 0.5
    $daily_excess = if($z_minus_slack > 0, $z_minus_slack, 0.0)
}

$entity = $stage2_daily_drift.entity

match:
  $entity

outcome:
  $observed = sum($stage2_daily_drift.observed)
  $peak_daily_observed = max($stage2_daily_drift.observed)
  $hist_avg = max($stage2_daily_drift.hist_avg)
  $hist_stddev = max($stage2_daily_drift.hist_stddev)
  $active_days = max($stage2_daily_drift.active_days)
  $hist_max = max($stage2_daily_drift.hist_max)

  $cusum_drift = sum($stage2_daily_drift.daily_excess)
  $cusum_drift_score = $cusum_drift
  $drift_days = sum(if($stage2_daily_drift.daily_excess > 0, 1, 0))
  $max_daily_z = max($stage2_daily_drift.daily_z)

condition:
  $active_days >= 7 and $cusum_drift_score >= 3.0 and $drift_days >= 2

order:
  $cusum_drift_score desc
```

### 10. `TWO_PART_HURDLE` (`two_part_hurdle.yl2`)
* **Hypothesis**: Zero-inflated dormant account reactivation: crossing the zero-hurdle warrants a log-scaled awakening score (`10.0 + math.log($observed + 1.0)`), with per-calendar-day rate (`$hist_sum / 30.0`), `$dormant_days`, and rebuilt calendar statistics (`PF-1`, `PF-2`, `WS1-05`), while active baseline entities are scored by continuous intensity $Z$ with D8 dispersion floor.
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_sum = max($stage1_extract.historical_sum)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  $mu_cal = $hist_sum / 30.0
  $dormant_days = 30.0 - $active_days
  $df_minus_one = if($active_days > 1, $active_days, 1) - 1
  $sum_x2 = ($df_minus_one * $hist_stddev * $hist_stddev) + ($active_days * $hist_avg * $hist_avg)
  $raw_var_cal = ($sum_x2 / 30.0) - ($mu_cal * $mu_cal)
  $sd_cal = math.sqrt(if($raw_var_cal > 0.0, $raw_var_cal, 0.0))

  $is_dormant_awakening = if($active_days <= 2 and $observed > 0, 1.0, 0.0)

  $raw_diff = $observed - $hist_avg
  $dispersion_floor = math.sqrt(if($hist_avg > 1.0, $hist_avg, 1.0))
  $safe_stddev = if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)
  $intensity_z = $raw_diff / $safe_stddev

  $obs_plus_one = $observed + 1.0
  $log_obs = math.log($obs_plus_one)
  $dormant_score = 10.0 + $log_obs
  $hurdle_threat_score = if($active_days <= 2, $dormant_score, $intensity_z)

condition:
  $active_days <= 2 or $intensity_z >= 3.0

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

  $dispersion_floor = math.sqrt(if($hist_avg > 1.0, $hist_avg, 1.0))
  $safe_stddev = if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)
  $upper_tail_z = $excess_surge / $safe_stddev

condition:
  $active_days >= 7 and $upper_tail_z >= 3.0

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
  $dispersion_floor = math.sqrt(if($hist_avg > 1.0, $hist_avg, 1.0))
  $safe_stddev = if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)
  $raw_z = $diff / $safe_stddev

  $clamped_low = if($raw_z < -4.0, -4.0, $raw_z)
  $clamped_z = if($clamped_low > 6.0, 6.0, $clamped_low)

  $cri_tier4 = if($clamped_z >= 4.0, 95.0, 85.0)
  $cri_tier3 = if($clamped_z >= 3.0, $cri_tier4, 65.0)
  $cri_tier2 = if($clamped_z >= 2.0, $cri_tier3, 40.0)
  $cri_score = if($clamped_z >= 1.0, $cri_tier2, 15.0)

condition:
  $active_days >= 7 and $clamped_z >= 3.0

order:
  $cri_score desc
```

### 13. `FLEET_PREVALENCE_SHIELD` (`fleet_prevalence_shield.yl2` & `hybrid_metric_fleet_prevalence_2stage.yl2`)
* **Hypothesis**: Concurrent spikes across many fleet entities indicate global events (e.g. Patch Tuesday / enterprise IT rollouts), not targeted attacks.
* **Variant A: Single-Plane Metric Prevalence Shield (`fleet_prevalence_shield.yl2`)**:
  - *Mandatory AST Contract*:
```yara
stage stage2_fleet_wave {
    $day_ws = $stage1_extract.window_start

  match:
    $day_ws by 1d

  outcome:
    $fleet_entities = count_distinct($stage1_extract.entity)
}

$entity = $stage1_extract.entity
$ws = $stage1_extract.window_start
$day_ws = $stage1_extract.window_start
$day_ws = $stage2_fleet_wave.day_ws

match:
  $entity, $ws by 1d

outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  $raw_diff = $observed - $hist_avg
  $dispersion_floor = math.sqrt(if($hist_avg > 1.0, $hist_avg, 1.0))
  $safe_stddev = if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)
  $personal_z = $raw_diff / $safe_stddev

  $fleet_count = max($stage2_fleet_wave.fleet_entities)

  $log_fleet = math.log($fleet_count)
  $prevalence_factor = 1.0 + $log_fleet
  $shielded_z = $personal_z / $prevalence_factor

condition:
  $active_days >= 7 and $shielded_z >= 3.0

order:
  $shielded_z desc
```
* **Variant B: Dual-Plane Token-Centric Normalization (`hybrid_metric_fleet_prevalence_2stage.yl2`)**:
  - *Use Case*: Process execution hunts for unfamiliar binaries during deployments (`target.process.file.sha256 = $token`).
  - *Match Topology*: Match on `$token by 1d`, joining Stage 1 personal surge with Stage 2 fleet breadth.
  - *Hyperbolic Prevalence Dampener*: `$prevalence_dampener = 1.0 / ($fleet_adopters + 1.0)`
  - *Outlier Scoring*: `$normalized_odds_score = $personal_z * $prevalence_dampener` (order: `$normalized_odds_score desc`).


### 14. `ADAPTIVE_CONTEXT_THRESHOLD` (`adaptive_context_threshold.yl2`)
* **Hypothesis**: Baseline-maturity adaptive thresholding: sparse baselines (`$active_days < 7`) require a stricter $3.5\sigma$ threshold to suppress cold-start noise, whereas mature baselines (`$active_days >= 7`) use a $2.5\sigma$ sensitivity threshold.
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  $raw_diff = $observed - $hist_avg
  $dispersion_floor = math.sqrt(if($hist_avg > 1.0, $hist_avg, 1.0))
  $safe_stddev = if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)
  $personal_z = $raw_diff / $safe_stddev

  $sparse_threshold = 3.5
  $mature_threshold = 2.5
  $effective_threshold = if($active_days < 7, $sparse_threshold, $mature_threshold)

  $sensitivity_excess = $personal_z - $effective_threshold

condition:
  $active_days >= 7 and $sensitivity_excess >= 0.0

order:
  $sensitivity_excess desc
```

### 15. `MACD_MOMENTUM_VELOCITY` (`macd_momentum_velocity.yl2`)
* **Hypothesis**: Detects sudden momentum acceleration where short-term surge diverges from slow baseline anchor and breaks out above the 30-day historical maximum (`$fast_z + $breakout_boost` when `$macd_diff > 0`).
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $hist_max = max($stage1_extract.historical_max)

  $fast_diff = $observed - $hist_avg
  $dispersion_floor = math.sqrt(if($hist_avg > 1.0, $hist_avg, 1.0))
  $safe_stddev = if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)
  $fast_z = $fast_diff / $safe_stddev

  $slow_diff = $hist_max - $hist_avg
  $slow_z = $slow_diff / $safe_stddev

  $macd_diff = $fast_z - $slow_z

  $safe_max = if($hist_max > 0, $hist_max, 1.0)
  $velocity_ratio = $observed / $safe_max

  $breakout_boost = $macd_diff * $velocity_ratio
  $breakout_score = $fast_z + $breakout_boost
  $macd_momentum_score = if($macd_diff > 0, $breakout_score, $fast_z)

condition:
  $active_days >= 7 and $fast_z >= 3.0

order:
  $macd_momentum_score desc
```

### 16. `CIRCADIAN_VON_MISES` (`circadian_von_mises.yl2`)
* **Hypothesis**: Evaluates hourly telemetry against a 24-hour circular clock from a heuristic business-hours center (default `14:00 UTC`, yielding `1.917x` at `03:00 UTC` via $1 + 11/12$ and `2.0x` at the `02:00 UTC` antipode), after normalizing the 30-day daily baseline to 1-hour units (`mean/24.0`, `stddev/4.899`).
* **Mandatory AST Contract**:
```yara
outcome:
  $observed_hour = max($stage1_extract.observed_val)
  $hist_avg_daily = max($stage1_extract.historical_avg)
  $hist_stddev_daily = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $event_hour = max($stage1_extract.event_hour)

  $avg_hourly = $hist_avg_daily / 24.0
  $scaled_hourly_sd = $hist_stddev_daily / 4.899
  $dispersion_floor = math.sqrt(if($avg_hourly > 1.0, $avg_hourly, 1.0))
  $safe_stddev_hourly = if($scaled_hourly_sd > $dispersion_floor, $scaled_hourly_sd, $dispersion_floor)
  $hourly_diff = $observed_hour - $avg_hourly
  $hourly_z = $hourly_diff / $safe_stddev_hourly

  $raw_hour_diff = $event_hour - 14.0
  $abs_hour_diff = math.abs($raw_hour_diff)
  $wrap_dist = 24.0 - $abs_hour_diff
  $circ_dist = if($abs_hour_diff > 12.0, $wrap_dist, $abs_hour_diff)

  $norm_dist = $circ_dist / 12.0
  $circadian_weight = 1.0 + $norm_dist

  $pos_z = if($hourly_z > 0, $hourly_z, 0.0)
  $circadian_threat_score = $pos_z * $circadian_weight

condition:
  $active_days >= 7 and $circadian_threat_score >= 3.0

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

  $fold_change = $observed / $safe_hist_avg

condition:
  $fold_change >= 2.0

order:
  $ratio desc
```

### 18. `QUANTILE_IQR_SKEW` (`quantile_iqr_skew.yl2`)
* **Hypothesis**: 1-stage non-parametric quantile envelope (`$p10, $q25, $q50, $q75, $p90`), Bowley quartile skewness (`$bowley_skew`), Moors tail-heaviness ratio (`$tail_heaviness`), and Hubert–Vandervieren Skewness-Adjusted Tukey Upper Fence (`$adj_upper_fence`) side by side with the 30d `metrics.*` `$personal_z` cross-check. Saves 1 stage and 1 join compared to 2-stage `MAD`.
* **Mandatory AST Contract**:
```yara
stage quantile_envelope {
    $entity = $stage1_extract.entity
  match:
    $entity
  outcome:
    $p10 = window.percentile($stage1_extract.observed_val, 10)
    $q25 = window.percentile($stage1_extract.observed_val, 25)
    $q50 = window.percentile($stage1_extract.observed_val, 50)
    $q75 = window.percentile($stage1_extract.observed_val, 75)
    $p90 = window.percentile($stage1_extract.observed_val, 90)
    $raw_active_days = count_distinct($stage1_extract.window_start)
}

$entity = $stage1_extract.entity
$entity = $quantile_envelope.entity
$ws = $stage1_extract.window_start

match:
  $entity, $ws by 1d

outcome:
  $iqr = $q75_val - $q25_val
  $bowley_skew = ($q75_val + $q25_val - (2.0 * $q50_val)) / $safe_iqr
  $tail_heaviness = (max($quantile_envelope.p90) - max($quantile_envelope.p10)) / $safe_iqr
  $adj_upper_fence = $q75_val + (1.5 * math.pow(2.718281828, 3.0 * $pos_skew) * $safe_iqr)
  $tukey_fence_ratio = $observed / $safe_fence

condition:
  $in_scoring_window = 1 and $raw_active_days >= 7 and $tukey_fence_ratio >= 2.0

order:
  $tukey_fence_ratio desc
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
6. **Threshold Concordance (root `condition:`)**: Does the card's `• Significance Threshold:` line state the model's gate from §2.1 (variable, operator, value, unit), and does the query carry exactly that expression as its root `condition:` between `outcome:` and `order:`? A card threshold with no matching `condition:` is a concordance failure, and so is a σ threshold stated for a fold-change or NO-GATE model. Radar sector micro-queries and the Fano factor are the only ungated queries.
