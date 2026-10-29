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
| 3 | `VARIANCE` | Baseline Dispersion Screen (30-Day Fano Factor) | `$variance`, `$safe_lambda`, `$fano_factor` | 30d baseline dispersion screen ($\sigma^2 / \mu$, independent of `$observed`); spray hunts route to `secops-statistical-hunter` `POISSON_BURST_CLUSTERING` | `order: $fano_factor desc` | Claiming day-level spray detection or omitting variance calculation |
| 4 | `POISSON` | Discrete Poisson / NB Rarity Z-Score | `$diff`, `$safe_lambda`, `$fano_cal`, `$safe_poisson_sd`, `$sqrt_lambda`, `$poisson_z` | $\lambda = S/30$, calendar Fano dispersion check ($F_{\text{cal}} \le 2.0$ uses $\sqrt{\lambda}$; $F_{\text{cal}} > 2.0$ uses NB $\sqrt{\sigma_{\text{cal}}^2}$); blocked on `value_sum` byte metrics | `order: $poisson_z desc` | Applying Poisson to `value_sum` bytes or ignoring overdispersion ($F_{\text{cal}} > 2.0$) |
| 5 | `COEFFICIENT_OF_VARIATION` | Regular-Volume Surge (Low-CV Predictable Baseline) | `$safe_hist_avg`, `$cv`, `$surge_ratio` | Fold-change surge gated on low relative dispersion ($\sigma / \mu \le 0.5$) | `order: $surge_ratio desc` | Standard Gaussian $Z$ without CV stability filter |
| 6 | `HOURLY_TEMPORAL_ZSCORE` *(RETIRED D1)* | Retired — Hand off to `HOUR_OF_DAY_PROFILE` | — | Handed off to `secops-statistical-hunter` `HOUR_OF_DAY_PROFILE` (`PF-10` / `WS2-02`) | — | Comparing 1h buckets against 24h daily `metrics.*` baselines |
| 7 | `BAYESIAN_GAMMA` | Empirical Bayes Poisson-Gamma (Fleet Prior & NB Predictive Z) | `$mu_cal`, `$var_cal`, `$excess_var`, `$posterior_rate`, `$post_rate_var`, `$cred_w`, `$pred_var`, `$safe_pred_sd`, `$bayesian_z` | Fleet-fitted `Gamma(alpha0, beta0)` slots, posterior rate $(\alpha_0 + S)/(\beta_0 + 30)$, NB posterior-predictive residual Z without double-counting $\mu$ (`B-E10`) | `order: $bayesian_z desc` | Self-estimated per-entity $\beta_0 = \mu/\sigma^2$ or posterior/mean fold-change ratio |
| 8 | `BAYESIAN_BETA_BINOMIAL` | Empirical Bayes Paired Beta-Binomial Failure Rate (Predictive Z) | `$obs_fail`, `$obs_total`, `$hist_fail_sum`, `$hist_total_sum`, `$prior_fail_rate`, `$posterior_fail_rate`, `$posterior_rate`, `$pred_mean`, `$pred_var`, `$safe_pred_sd`, `$beta_binomial_z` | Paired Stage-1 `*_fail`/`*_total` counts + 30d sums, fleet `Beta(alpha0, beta0)` prior, Beta-Binomial posterior-predictive residual Z | `order: $beta_binomial_z desc` | Pseudo-trial count normalization or running on unpaired metrics |
| 9 | `LONGITUDINAL_CUSUM` | Longitudinal CUSUM Drift Accumulation | `$raw_drift`, `$safe_stddev`, `$slack_allowance`, `$slack_excess`, `$daily_excess`, `$cusum_drift`, `$cusum_drift_score`, `$drift_days` | Per-day slack excess ($Z_t - 0.5\sigma$), multi-day `sum($stage2_daily_drift.daily_excess)` across window | `order: $cusum_drift_score desc` | Single-bucket Z-score omitting multi-day drift accumulation |
| 10 | `TWO_PART_HURDLE` | Two-Part Hurdle Model (Zero-Inflated) | `$is_dormant_awakening`, `$raw_diff`, `$safe_stddev`, `$intensity_z`, `$obs_plus_one`, `$log_obs`, `$dormant_score`, `$hurdle_threat_score` | Bernoulli hurdle trigger (`10.0 + math.log($obs_plus_one)`), conditional continuous intensity | `order: $hurdle_threat_score desc` | Single-equation continuous model without dormant penalty |
| 11 | `ASYMMETRIC_DIRECTIONAL_Z` *(MERGED D1)* | Merged into `STANDARD_Z_SCORE` | `$personal_diff`, `$dispersion_floor`, `$safe_stddev`, `$personal_z` | Upper-tail positive `$personal_z >= 3.0` is identical to `STANDARD_Z_SCORE` (`standard_z_score.yl2`) | `order: $personal_z desc` | Maintaining duplicate `asymmetric_directional_z.yl2` |
| 12 | `PIECEWISE_CRI` *(RETIRED D1)* | Retired — Computed via `ueba_constants.calculate_cri` | — | CRI is a reporting-only translation computed in Python (`WS7-01`), never in YARA-L | — | Emitting discrete step-ladder CRI in YARA-L |
| 13 | `FLEET_PREVALENCE_SHIELD` *(RETIRED D1)* | Retired — Replaced by `hybrid_metric_fleet_prevalence_2stage.yl2` | — | Replaced by token-scoped `hybrid_metric_fleet_prevalence_2stage.yl2` or `dual_baseline_delta_z_3stage.yl2` | — | Dividing personal Z by raw daily active-entity count `1 + ln(fleet_count)` |
| 14 | `ADAPTIVE_CONTEXT_THRESHOLD` | Baseline-Maturity Adaptive Sensitivity | `$raw_diff`, `$safe_stddev`, `$personal_z`, `$sparse_threshold`, `$mature_threshold`, `$effective_threshold`, `$sensitivity_excess` | Baseline-maturity thresholding ($3.5\sigma$ for sparse `< 7d` vs $2.5\sigma$ for mature `>= 7d`) | `order: $sensitivity_excess desc` | Static uniform threshold or loosening threshold on noisy sparse baselines |
| 15 | `MACD_MOMENTUM_VELOCITY` | Above-Historical-Max Z (Linear Peak Exceedance) | `$personal_diff`, `$safe_stddev`, `$personal_z`, `$exceed_raw`, `$exceed_pos`, `$above_max_z`, `$macd_z`, `$macd_momentum_score` | Linear peak exceedance (`$above_max_z = max(0, obs - hist_max) / safe_stddev`, `$macd_z = $personal_z + $above_max_z`) | `order: $macd_z desc` | Quadratic `* $velocity_ratio` byte overflow or dropping `$personal_z` |
| 16 | `CIRCADIAN_VON_MISES` *(RETIRED D1)* | Retired — Hand off to `HOUR_OF_DAY_PROFILE` | — | Handed off to `secops-statistical-hunter` `HOUR_OF_DAY_PROFILE` (`PF-10` / `WS2-02`) | — | Comparing 1h counts or fixed 14:00 UTC centers against 24h `metrics.*` baselines |
| 17 | `RELATIVE_DEVIATION` | Relative Deviation / Fold Change vs 30d Mean | `$safe_hist_avg`, `$dev`, `$ratio`, `$fold_change`, `$rel_dev_z_equiv` | Continuous `max(avg, 1.0)` floor, `(x - safe_avg) / safe_avg`, Z-equivalent `max(0, 3 * ratio)` | `order: $ratio desc` | Discontinuous `if(avg > 0, avg, 1)` floor or labelling it MAD |
| 18 | `QUANTILE_IQR_SKEW` | 1-Stage Non-Parametric Quantiles, Bowley Skewness & Skew-Adjusted Tukey Scale-Excess | `$q25_val`, `$q50_val`, `$q75_val`, `$iqr`, `$safe_iqr`, `$bowley_skew`, `$tail_heaviness`, `$adj_upper_fence`, `$robust_scale`, `$tukey_excess_z` | `window.percentile` 5-point envelope in 1 stage, Bowley `1.35` fence, `(obs - fence) / (IQR / 1.349)` | `order: $tukey_excess_z desc` | Using `e^{3.0 * B_skew}` medcouple constant on Bowley `B` or `obs / fence` near-zero ratio |

### 2.1 Default Root Significance Gate (the card's `Significance Threshold`)

Every query carries the model's significance gate as a root `condition:` placed between `outcome:` and `order:`. The gate variable is not always the `order:` variable, and not every model is scored in σ. The Pre-Flight card's `• Significance Threshold:` line MUST state the gate from this table (adjusted if the analyst tunes it), and the emitted `condition:` MUST match it.

| Model | Gate variable | Default root `condition:` | Unit | Card wording | Template placeholder |
|---|---|---|---|---|---|
| `STANDARD_Z_SCORE` | `$active_days`, `$personal_z` | `$active_days >= 7 and $personal_z >= 3.0` | σ | `Z >= 3.0σ` | `{{anomaly_threshold}}` |
| `ASYMMETRIC_DIRECTIONAL_Z` | `$active_days`, `$personal_z` | `$active_days >= 7 and $personal_z >= 3.0` | σ | `Z >= 3.0σ (merged into STANDARD_Z_SCORE)` | `{{anomaly_threshold}}` |
| `POISSON` | `$poisson_z` | `$poisson_z >= 3.0` | σ (√λ) | `Poisson Z >= 3.0σ` | `{{anomaly_threshold}}` |
| `HOURLY_TEMPORAL_ZSCORE` | — | **retired (`D1`)** | — | `RETIRED (D1 -> HOUR_OF_DAY_PROFILE)` | — |
| `CIRCADIAN_VON_MISES` | — | **retired (`D1`)** | — | `RETIRED (D1 -> HOUR_OF_DAY_PROFILE)` | — |
| `MACD_MOMENTUM_VELOCITY` | `$active_days`, `$macd_z` | `$active_days >= 7 and $macd_z >= 3.0` | σ | `Above-Max Z >= 3.0σ` | `{{anomaly_threshold}}` |
| `PIECEWISE_CRI` | — | **retired (`D1`)** | — | `RETIRED (D1 -> ueba_constants.calculate_cri)` | — |
| `FLEET_PREVALENCE_SHIELD` | — | **retired (`D1`)** | — | `RETIRED (D1 -> hybrid_metric_fleet_prevalence_2stage.yl2)` | — |
| `TWO_PART_HURDLE` | `$active_days`, `$intensity_z` | `$active_days <= 2 or $intensity_z >= 3.0` | dormancy break or σ | `Dormant awakening OR Z >= 3.0σ` | `{{anomaly_threshold}}` |
| `ADAPTIVE_CONTEXT_THRESHOLD` | `$active_days`, `$sensitivity_excess` | `$active_days >= 7 and $sensitivity_excess >= 0.0` | σ above the context threshold (1.75σ / 3.00σ) | `Z >= context threshold` | none (built into the score) |
| `LONGITUDINAL_CUSUM` | `$active_days`, `$cusum_drift_score`, `$drift_days` | `$active_days >= 7 and $cusum_drift_score >= 3.0 and $drift_days >= 2` | cumulative σ excess over 0.5σ slack | `Drift above 0.5σ slack` | `{{anomaly_threshold}}` |
| `BAYESIAN_GAMMA` | `$bayesian_z` | `$bayesian_z >= 3.0` | σ (NB posterior-predictive) | `Bayesian Z >= 3.0σ` | `{{anomaly_threshold}}` |
| `BAYESIAN_BETA_BINOMIAL` | `$beta_binomial_z` | `$beta_binomial_z >= 3.0` | σ (Beta-Binomial posterior-predictive) | `Beta-Binomial Z >= 3.0σ` | `{{anomaly_threshold}}` |
| `COEFFICIENT_OF_VARIATION` | `$active_days`, `$surge_ratio`, `$cv` | `$active_days >= 7 and $surge_ratio >= 2.0 and $cv <= 0.5` | fold change on a predictable entity | `>= 2.0× baseline, CV <= 0.5` | `{{fold_change_threshold}}` |
| `RELATIVE_DEVIATION` | `$fold_change` | `$fold_change >= 2.0` (ranked by `$ratio`) | fold change | `>= 2.0× baseline` | `{{fold_change_threshold}}` |
| `MAD` | `$modified_z` | `... and $modified_z >= 3.5` (AND-ed with the scoring-window and sample-size gates) | modified Z | `Modified Z >= 3.5` | `{{robust_threshold}}` |
| `QUANTILE_IQR_SKEW` | `$tukey_excess_z` | `$in_scoring_window = 1 and $raw_active_days >= 7 and $tukey_excess_z >= 1.0` | robust scale-excess | `Tukey Scale-Excess >= 1.0` | `{{tukey_excess_threshold}}` |
| `VARIANCE` (Fano) | — | **none** (`// NO-GATE`) | — | `N/A (baseline dispersion screen)` | — |

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
* **Hypothesis**: 30-day **baseline dispersion screen** ($F = \sigma^2 / \mu$, independent of the scored day's `$observed` value) used to test Poisson vs overdispersed historical baselines. Active credential spray and sub-hour burst hunts route to `secops-statistical-hunter` `POISSON_BURST_CLUSTERING`.
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

  $safe_lambda = if($lambda > 1.0, $lambda, 1.0)
  $fano_cal = $var_cal / $safe_lambda
  $nb_var = if($var_cal > $safe_lambda, $var_cal, $safe_lambda)
  $eff_var = if($active_days >= 2 and $fano_cal > 2.0, $nb_var, $safe_lambda)
  $safe_poisson_sd = math.sqrt($eff_var)
  $sqrt_lambda = math.sqrt($safe_lambda)
  $diff = $k - $lambda
  $poisson_z = $diff / $safe_poisson_sd

condition:
  $poisson_z >= 3.0

order:
  $poisson_z desc
```

### 5. `COEFFICIENT_OF_VARIATION` — Regular-Volume Surge (`coefficient_of_variation.yl2`)
* **Hypothesis**: Regular-volume surge on a predictable entity ($\text{CV} \le 0.5$): high relative surge on low-variance entities represents an acute anomaly.
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

### 6. `HOURLY_TEMPORAL_ZSCORE` *(RETIRED — `D1` / `PF-10` / `WS2-02`)*
* **Status**: Retired from `secops-risk-metrics-multistage`. Because `metrics.*` exposes only `period: 1d, window: 30d` baselines, 1-hour bucket standardization cannot be anchored to `metrics.*` without scale bias. Route intra-day / per-hour-of-day profiling to `secops-statistical-hunter` model `HOUR_OF_DAY_PROFILE`.

### 7. `BAYESIAN_GAMMA` (`poisson_gamma_bayesian.yl2`)
* **Hypothesis**: Fleet Empirical Bayes `Gamma(alpha0, beta0)` conjugate shrinkage (`fit_gamma_prior_from_fleet`) scored by the posterior-predictive Negative-Binomial residual (`$bayesian_z`), shrinking sparse baselines toward the fleet prior while ensuring acute spikes (`+10σ`) on mature hosts still fire (`WS3-BAYES`, `B-E10`).
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_sum = max($stage1_extract.historical_sum)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  $mu_cal = $hist_sum / 30.0
  $df_minus_one = if($active_days > 1, $active_days, 1) - 1
  $sum_x2 = ($df_minus_one * $hist_stddev * $hist_stddev) + ($active_days * $hist_avg * $hist_avg)
  $raw_var_cal = ($sum_x2 / 30.0) - ($mu_cal * $mu_cal)
  $var_cal = if($raw_var_cal > 0.0, $raw_var_cal, 0.0)
  $raw_excess_var = $var_cal - $mu_cal
  $excess_var = if($active_days >= 2 and $raw_excess_var > 0.0, $raw_excess_var, 0.0)

  $post_alpha_pre = 0.5 + $hist_sum
  $post_beta_pre = 0.1 + 30.0
  $posterior_rate = $post_alpha_pre / $post_beta_pre
  $post_rate_var = $post_alpha_pre / ($post_beta_pre * $post_beta_pre)

  $cred_w = $active_days / ($active_days + 0.1)
  $pred_var = $posterior_rate + $post_rate_var + ($cred_w * $excess_var)
  $safe_pred_sd = math.sqrt(if($pred_var > 1.0, $pred_var, 1.0))
  $bayesian_z = ($observed - $posterior_rate) / $safe_pred_sd

condition:
  $bayesian_z >= 3.0

order:
  $bayesian_z desc
```

### 8. `BAYESIAN_BETA_BINOMIAL` (`beta_binomial_bayesian.yl2`)
* **Hypothesis**: Paired Empirical Bayes Beta-Binomial failure-rate regularization (`WS3-BETA-BINOMIAL`, `D1b`). Stage 1 pairs a `*_fail` metric with its sibling `*_total` metric (supported across all 8 paired families: `auth_attempts_*`, `dns_queries_*`, `http_queries_*`, `file_executions_*`, `resource_{creation,deletion,read,written}_*`; unpaired metrics raise `ValueError`). A fleet pass (`fit_beta_prior_from_fleet`, default `alpha0 = 1.0, beta0 = 19.0`) supplies the prior slots `{{prior_alpha0}}` and `{{prior_beta0}}`, preventing `1/1` single-trial false alarms while firing on sustained failure surges.
* **Mandatory AST Contract**:
```yara
outcome:
  $obs_fail = sum($stage1_extract.obs_fail)
  $obs_total = sum($stage1_extract.obs_total)
  $observed = $obs_fail
  $hist_fail_sum = max($stage1_extract.hist_fail_sum)
  $hist_total_sum = max($stage1_extract.hist_total_sum)
  $active_days = max($stage1_extract.historical_active_days)

  $raw_hist_succ = $hist_total_sum - $hist_fail_sum
  $hist_succ_sum = if($raw_hist_succ > 0.0, $raw_hist_succ, 0.0)
  $alpha_pre = 1.0 + $hist_fail_sum
  $beta_pre = 19.0 + $hist_succ_sum
  $ab = $alpha_pre + $beta_pre
  $prior_fail_rate = $alpha_pre / $ab

  $posterior_fail_rate = ($alpha_pre + $obs_fail) / ($ab + $obs_total)
  $posterior_rate = $posterior_fail_rate
  $pred_mean = $obs_total * $prior_fail_rate
  $pred_var = $obs_total * $prior_fail_rate * ($beta_pre / $ab) * (($ab + $obs_total) / ($ab + 1.0))
  $safe_pred_sd = math.sqrt(if($pred_var > 0.25, $pred_var, 0.25))
  $beta_binomial_z = ($obs_fail - $pred_mean) / $safe_pred_sd

condition:
  $beta_binomial_z >= 3.0

order:
  $beta_binomial_z desc
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

### 11. `ASYMMETRIC_DIRECTIONAL_Z` *(MERGED INTO `STANDARD_Z_SCORE` — `D1`)*
* **Status**: Merged into `STANDARD_Z_SCORE` (`standard_z_score.yl2`) under `D1`. Under an upper-tail gate (`$personal_z >= 3.0`), ReLU clamping of negative deviations produces identical results to `STANDARD_Z_SCORE`. Passing `ASYMMETRIC_DIRECTIONAL_Z` routes cleanly to `STANDARD_Z_SCORE` with an advisory.

### 12. `PIECEWISE_CRI` *(RETIRED — `D1`)*
* **Status**: Retired from YARA-L templates under `D1`. Calibrated Risk Index (`CRI`) is a reporting-only translation computed canonically in Python via `ueba_constants.calculate_cri` (`WS7-01`), never as a discrete step-ladder in YARA-L.

### 13. `FLEET_PREVALENCE_SHIELD` *(RETIRED — `D1`)*
* **Status**: Single-plane `fleet_prevalence_shield.yl2` is retired under `D1` because dividing `$personal_z` by `1 + ln(fleet_count)` (where `fleet_count` counts every active entity on that day, not surging entities) suppresses real attacks on any active telemetry day.
* **Active Replacements**:
  - **Token-Scoped Binary / Rollout Prevalence (`hybrid_metric_fleet_prevalence_2stage.yl2`)**: Match on `$token by 1d`, joining Stage 1 personal surge with Stage 2 `DERIVED_CONTEXT` binary prevalence (`rolling_max <= 3`, `$normalized_odds_score = $personal_z * $prevalence_dampener`).
  - **Fleet-Wide Mean/Stddev Surge Suppression (`dual_baseline_delta_z_3stage.yl2`)**: Subtracts concurrent fleet Z-score (`$delta_z = $personal_z - $fleet_z`).


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

### 15. `MACD_MOMENTUM_VELOCITY` — Above-Historical-Max Z (`macd_momentum_velocity.yl2`)
* **Hypothesis**: Detects linear peak exceedance where today's volume breaks out above the 30-day historical maximum (`$macd_z = $personal_z + $above_max_z`), avoiding quadratic byte overflow.
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

  $exceed_raw = $observed - $hist_max
  $exceed_pos = if($exceed_raw > 0, $exceed_raw, 0.0)
  $above_max_z = $exceed_pos / $safe_stddev
  $macd_z = $personal_z + $above_max_z
  $macd_momentum_score = $macd_z

condition:
  $active_days >= 7 and $macd_z >= 3.0

order:
  $macd_z desc
```

### 16. `CIRCADIAN_VON_MISES` *(RETIRED — `D1` / `PF-10` / `WS2-02`)*
* **Status**: Retired from `secops-risk-metrics-multistage` (along with `circadian_von_mises_2stage.yl2`). Route per-hour-of-day / off-hours profiling to `secops-statistical-hunter` model `HOUR_OF_DAY_PROFILE`.

### 17. `RELATIVE_DEVIATION` (`relative_deviation.yl2`)
* **Hypothesis**: Scale-free fold change against the 30d mean ("3.2x the usual volume"). Easy to read, but mean-anchored: one historic burst inflates the denominator. This was formerly (mis)labelled `MAD`.
* **Mandatory AST Contract**:
```yara
outcome:
  $observed = max($stage1_extract.observed_val)
  $hist_avg = max($stage1_extract.historical_avg)
  $hist_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)

  $safe_hist_avg = if($hist_avg > 1.0, $hist_avg, 1.0)
  $dev = $observed - $safe_hist_avg
  $ratio = $dev / $safe_hist_avg

  $fold_change = $observed / $safe_hist_avg
  $raw_z_equiv = 3.0 * $ratio
  $rel_dev_z_equiv = if($raw_z_equiv > 0.0, $raw_z_equiv, 0.0)

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
  $adj_upper_fence = $q75_val + (1.5 * math.pow(2.718281828, 1.35 * if($bowley_skew > 0, $bowley_skew, 0.0)) * $safe_iqr)
  $robust_scale = $safe_iqr / 1.349
  $tukey_excess_z = ($observed - $adj_upper_fence) / $robust_scale

condition:
  $in_scoring_window = 1 and $raw_active_days >= 7 and $tukey_excess_z >= 1.0

order:
  $tukey_excess_z desc
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
