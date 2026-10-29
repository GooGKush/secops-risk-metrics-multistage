# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""WS0-04 Synthetic Golden-Math & Offline Helper Verification Suite."""

import datetime
import json
import math
import os
import random
import statistics
import tempfile
import unittest
from unittest import mock
import zoneinfo

from scripts.cusum_helper import (
    evaluate_multishard_cusum,
    evaluate_start_anchored_cusum,
    siegmund_arl,
)
from scripts.preflight_validator import (
    EntityType,
    MalachiteASTValidator,
    PipelineArchitecture,
    StatisticalModel,
)
from scripts.template_router import (
    DEFAULT_BETA_PRIOR_ALPHA0,
    DEFAULT_BETA_PRIOR_BETA0,
    DEFAULT_GAMMA_PRIOR_ALPHA0,
    DEFAULT_GAMMA_PRIOR_BETA0,
    MultiStageTemplateRouter,
    evaluate_samuelson_cohort_cap,
    fit_beta_prior_from_fleet,
    fit_gamma_prior_from_fleet,
    samuelson_max_z,
)
from scripts.timeline_assembler import rebuild_calendar_day_stats


def _chronicle_stats_payload(rows: list[dict]) -> dict:
  """Encodes row dictionaries into Chronicle udm_search stats.results JSON structure."""
  if not rows:
    return {"stats": {"results": []}}
  cols = list(rows[0].keys())
  results = []
  for col in cols:
    values = []
    for row in rows:
      val = row[col]
      if isinstance(val, bool):
        values.append({"value": {"boolVal": val}})
      elif isinstance(val, int):
        values.append({"value": {"int64Val": str(val)}})
      elif isinstance(val, float):
        values.append({"value": {"doubleVal": val}})
      else:
        values.append({"value": {"stringVal": str(val)}})
    results.append({"column": col, "values": values})
  return {"stats": {"results": results}}


class WS004GoldenMathSuiteTest(unittest.TestCase):
  """Deterministic golden-math verification for macro statistical models and offline helpers."""

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  # ---------------------------------------------------------------------------
  # 1. One-Sided Page CUSUM ARL, Windowed Slack Sum Bound & Offline Helper
  # ---------------------------------------------------------------------------

  def test_1a_page_cusum_siegmund_arl_and_monte_carlo_calibration(self):
    """WS6-01: Verifies Siegmund ARL and seeded Monte Carlo ARL0 / ARL1(+1sigma) at k=0.5, h in {4.0, 5.0}."""
    k = 0.5
    # Analytic Siegmund verification against textbook [ARL0, ARL1(+1sigma)] targets:
    #   h = 4.0 -> [336, 8.4],  h = 5.0 -> [930, 10.4]
    arl0_h4 = siegmund_arl(4.0, slack_k=k, shift_sigma=0.0)
    arl1_h4 = siegmund_arl(4.0, slack_k=k, shift_sigma=1.0)
    arl0_h5 = siegmund_arl(5.0, slack_k=k, shift_sigma=0.0)
    arl1_h5 = siegmund_arl(5.0, slack_k=k, shift_sigma=1.0)

    self.assertTrue(336.0 * 0.80 <= arl0_h4 <= 336.0 * 1.20, f"arl0(h=4)={arl0_h4}")
    self.assertTrue(8.4 * 0.80 <= arl1_h4 <= 8.4 * 1.20, f"arl1(h=4)={arl1_h4}")
    self.assertTrue(930.0 * 0.80 <= arl0_h5 <= 930.0 * 1.20, f"arl0(h=5)={arl0_h5}")
    self.assertTrue(10.4 * 0.80 <= arl1_h5 <= 10.4 * 1.20, f"arl1(h=5)={arl1_h5}")

    # Deterministic seeded Monte Carlo simulation of S_t = max(0, S_{t-1} + Z_t - 0.5)
    rng = random.Random(20261029)

    def simulate_arl(h: float, shift: float, n_trials: int) -> float:
      run_lengths = []
      gauss = rng.gauss
      for _ in range(n_trials):
        s_t = 0.0
        steps = 0
        while s_t < h:
          steps += 1
          z_t = gauss(shift, 1.0)
          s_t = s_t + z_t - k
          if s_t < 0.0:
            s_t = 0.0
        run_lengths.append(steps)
      return sum(run_lengths) / len(run_lengths)

    mc_arl0_h4 = simulate_arl(h=4.0, shift=0.0, n_trials=1500)
    mc_arl1_h4 = simulate_arl(h=4.0, shift=1.0, n_trials=2000)
    mc_arl0_h5 = simulate_arl(h=5.0, shift=0.0, n_trials=600)
    mc_arl1_h5 = simulate_arl(h=5.0, shift=1.0, n_trials=2000)

    self.assertTrue(
        336.0 * 0.80 <= mc_arl0_h4 <= 336.0 * 1.20,
        f"Monte Carlo ARL0(h=4.0, k=0.5) = {mc_arl0_h4:.2f} outside +-20% of 336",
    )
    self.assertTrue(
        8.4 * 0.80 <= mc_arl1_h4 <= 8.4 * 1.20,
        f"Monte Carlo ARL1(h=4.0, k=0.5, +1sigma) = {mc_arl1_h4:.2f} outside +-20% of 8.4",
    )
    self.assertTrue(
        930.0 * 0.80 <= mc_arl0_h5 <= 930.0 * 1.20,
        f"Monte Carlo ARL0(h=5.0, k=0.5) = {mc_arl0_h5:.2f} outside +-20% of 930",
    )
    self.assertTrue(
        10.4 * 0.80 <= mc_arl1_h5 <= 10.4 * 1.20,
        f"Monte Carlo ARL1(h=5.0, k=0.5, +1sigma) = {mc_arl1_h5:.2f} outside +-20% of 10.4",
    )

  def test_1b_windowed_slack_sum_lossless_prefilter_inequality(self):
    """WS6-01: Verifies max_t S_t <= W = sum(max(0, Z_t - k)) on all sequences (zero false negatives)."""
    rng = random.Random(20261030)
    k = 0.5
    strict_gap_observed = False

    for _ in range(500):
      seq = [rng.gauss(0.2, 1.5) for _ in range(14)]
      s_t = 0.0
      peak_s = 0.0
      w_sum = 0.0
      for z_t in seq:
        if z_t - k > 0.0:
          w_sum += (z_t - k)
        s_t = max(0.0, s_t + z_t - k)
        peak_s = max(peak_s, s_t)
      self.assertLessEqual(peak_s, w_sum + 1e-12)
      if peak_s + 0.5 < w_sum:
        strict_gap_observed = True

    # Intermittent spikes separated by quiet negative-Z days must decay S_t strictly below W
    self.assertTrue(strict_gap_observed)

  def test_1c_cusum_helper_offline_zero_network_calls_and_quiet_day_decay(self):
    """D6-G4 / WS6-01: Proves cusum_helper.py makes zero network calls in both <=14d and >14d modes."""
    query_text = self.router.build_longitudinal_cusum_series_query(
        target_metric="dns_queries_total",
        entity_type=EntityType.ASSET,
        cusum_h_threshold=4.0,
    )
    self.assertEqual([], MalachiteASTValidator.validate_query(query_text))

    with tempfile.TemporaryDirectory() as tmpdir:
      query_path = os.path.join(tmpdir, "cusum_query.yl2")
      with open(query_path, "w", encoding="utf-8") as f:
        f.write(query_text)

      # Mode 1 (<=14d start-anchored series, 10 calendar days 2026-10-01..2026-10-10):
      # - host-sustained: +2.0 sigma on 4 consecutive days (2026-10-02..05), residual = 1.5/day -> peak S_t = 6.0 >= 4.0 (ALARM)
      # - host-intermittent: +2.7 sigma on Day 1 (obs=47 vs mean=20, sd=10 -> S_1=2.2) then 5 silent 0-event days
      #   (z = -2.0 -> S decays to 0.0), then +2.7 sigma on Day 7 (S_7=2.2): W = 4.4 >= 4.0, but peak S_t = 2.2 < 4.0 (NO ALARM!)
      # - host-immature: active_days = 3 < 7 -> routed to FIRST_SEEN_NOVELTY
      series_rows = [
          {"entity": "host-sustained", "ws": "2026-10-02", "observed_val": 40.0, "baseline_mean": 20.0, "baseline_stddev": 10.0, "active_days": 20},
          {"entity": "host-sustained", "ws": "2026-10-03", "observed_val": 40.0, "baseline_mean": 20.0, "baseline_stddev": 10.0, "active_days": 20},
          {"entity": "host-sustained", "ws": "2026-10-04", "observed_val": 40.0, "baseline_mean": 20.0, "baseline_stddev": 10.0, "active_days": 20},
          {"entity": "host-sustained", "ws": "2026-10-05", "observed_val": 40.0, "baseline_mean": 20.0, "baseline_stddev": 10.0, "active_days": 20},
          {"entity": "host-intermittent", "ws": "2026-10-01", "observed_val": 47.0, "baseline_mean": 20.0, "baseline_stddev": 10.0, "active_days": 20},
          {"entity": "host-intermittent", "ws": "2026-10-07", "observed_val": 47.0, "baseline_mean": 20.0, "baseline_stddev": 10.0, "active_days": 20},
          {"entity": "host-immature", "ws": "2026-10-03", "observed_val": 90.0, "baseline_mean": 5.0, "baseline_stddev": 2.0, "active_days": 3},
      ]
      payload_path = os.path.join(tmpdir, "series_payload.json")
      with open(payload_path, "w", encoding="utf-8") as f:
        json.dump(_chronicle_stats_payload(series_rows), f)

      # Mode 2 (>14d multi-shard fixed-reference across 16 days 2026-10-01..2026-10-16):
      # Even if later shards report inflated trailing active_avg due to slow exfiltration entering the trailing 30d window,
      # Shard 1's fixed calendar-day reference (active_days=30, avg=100, sd=20 -> mu_cal=100, sd_cal~19.66, safe_sd=19.66)
      # prevents baseline fade and catches the persistent +1.5 sigma drift!
      shard_files = {}
      start_dt = datetime.date(2026, 10, 1)
      for d_idx in range(16):
        day_str = (start_dt + datetime.timedelta(days=d_idx)).isoformat()
        faded_trailing_mean = 100.0 + (2.0 * d_idx)
        shard_row = [{
            "entity": "host-slow-drift",
            "observed_val": 130.0,
            "baseline_mean": faded_trailing_mean,
            "baseline_stddev": 20.0,
            "active_days": 30,
            "historical_sum": 30.0 * faded_trailing_mean,
        }]
        s_path = os.path.join(tmpdir, f"shard_{day_str}.json")
        with open(s_path, "w", encoding="utf-8") as f:
          json.dump(_chronicle_stats_payload(shard_row), f)
        shard_files[day_str] = s_path

      with mock.patch("socket.socket", side_effect=AssertionError("D6-G4 network socket forbidden")), mock.patch(
          "urllib.request.urlopen", side_effect=AssertionError("D6-G4 HTTP call forbidden")
      ):
        res_le14 = evaluate_start_anchored_cusum(
            payload_file=payload_path,
            query_file=query_path,
            start_day="2026-10-01",
            end_day="2026-10-10",
            tier="BALANCED",
            metric_name="dns_queries_total",
        )
        res_gt14 = evaluate_multishard_cusum(
            shard_files=shard_files,
            query_file=query_path,
            start_day="2026-10-01",
            end_day="2026-10-16",
            tier="BALANCED",
            metric_name="dns_queries_total",
        )

      self.assertTrue(res_le14["entities"]["host-sustained"]["alarm"])
      self.assertAlmostEqual(res_le14["entities"]["host-sustained"]["peak_s_t"], 6.0, places=3)
      self.assertEqual(res_le14["entities"]["host-sustained"]["onset_day"], "2026-10-04")

      # Quiet reconstructed zero-event days decay S_t to 0.0 between Day 1 and Day 7
      self.assertFalse(res_le14["entities"]["host-intermittent"]["alarm"])
      self.assertAlmostEqual(res_le14["entities"]["host-intermittent"]["peak_s_t"], 2.2, places=3)
      self.assertEqual(len(res_le14["entities"]["host-intermittent"]["series"]), 10)
      self.assertTrue(res_le14["entities"]["host-intermittent"]["series"][1]["reconstructed_zero_day"])

      self.assertEqual(len(res_le14["immature_entities"]), 1)
      self.assertEqual(res_le14["immature_entities"][0]["entity"], "host-immature")
      self.assertEqual(res_le14["immature_entities"][0]["routed_to"], "FIRST_SEEN_NOVELTY")

      self.assertEqual(res_gt14["window_days"], 16)
      self.assertTrue(res_gt14["entities"]["host-slow-drift"]["alarm"])
      self.assertEqual(res_gt14["entities"]["host-slow-drift"]["initial_reference_day"], "2026-10-01")
      self.assertAlmostEqual(res_gt14["entities"]["host-slow-drift"]["mu_cal_ref"], 100.0, places=3)

  # ---------------------------------------------------------------------------
  # 2. Sample-SD Samuelson Cap (N - 1) / sqrt(N)
  # ---------------------------------------------------------------------------

  def test_2_sample_sd_samuelson_cap_exact_identity(self):
    """PF-2 / WS1-09: Verifies max sample-SD Z on [0]*(N-1) + [c] equals (N-1)/sqrt(N) to 1e-12."""
    for n in (2, 5, 7, 10, 11, 30):
      expected_cap = (n - 1.0) / math.sqrt(float(n))
      self.assertAlmostEqual(samuelson_max_z(n), expected_cap, delta=1e-12)
      for c in (1.0, 37.5, 10000.0):
        sample = [0.0] * (n - 1) + [c]
        mean_x = statistics.mean(sample)
        sample_sd = statistics.stdev(sample)  # Bessel-corrected N - 1 sample SD
        empirical_max_z = (c - mean_x) / sample_sd
        self.assertAlmostEqual(empirical_max_z, expected_cap, delta=1e-12)

    cap_10 = evaluate_samuelson_cohort_cap(10, threshold_z=3.0)
    self.assertAlmostEqual(samuelson_max_z(10), 9.0 / math.sqrt(10.0), delta=1e-12)
    self.assertEqual(cap_10["samuelson_max_z"], round(9.0 / math.sqrt(10.0), 4))
    self.assertLess(cap_10["samuelson_max_z"], 3.0)  # 2.84605 < 3.0 -> unreachable!
    self.assertTrue(cap_10["cohort_too_small"])
    self.assertEqual(cap_10["required_min_cohort_size"], 11)

    cap_11 = evaluate_samuelson_cohort_cap(11, threshold_z=3.0)
    self.assertAlmostEqual(samuelson_max_z(11), 10.0 / math.sqrt(11.0), delta=1e-12)
    self.assertEqual(cap_11["samuelson_max_z"], round(10.0 / math.sqrt(11.0), 4))
    self.assertGreater(cap_11["samuelson_max_z"], 3.0)  # 3.01511 >= 3.0 -> reachable!
    self.assertFalse(cap_11["cohort_too_small"])

  # ---------------------------------------------------------------------------
  # 3. Calendar-Day Moment Reconstruction (PF-1, PF-2, WS1-05)
  # ---------------------------------------------------------------------------

  def test_3_calendar_day_moment_reconstruction_exact_identity(self):
    """PF-1 / PF-2 / WS1-05: Verifies rebuild_calendar_day_stats against 30-day zero-padded series incl. maya.goodman."""
    # Canonical maya.goodman fixture: [97, 4] on 2 active days + 28 zero-event calendar days
    maya_series = [97.0, 4.0] + [0.0] * 28
    maya_active = [x for x in maya_series if x > 0.0]
    n_maya = len(maya_active)  # 2
    avg_maya = statistics.mean(maya_active)  # 50.5
    sd_maya = statistics.stdev(maya_active)  # sqrt(4324.5) = 65.7609306505...

    rebuilt_maya = rebuild_calendar_day_stats(
        active_days=n_maya,
        active_avg=avg_maya,
        active_sd=sd_maya,
        window_days=30.0,
    )
    self.assertAlmostEqual(rebuilt_maya["sum_x"], 101.0, places=9)
    self.assertAlmostEqual(rebuilt_maya["sum_x2"], 9425.0, places=9)
    self.assertAlmostEqual(rebuilt_maya["lambda_cal"], 101.0 / 30.0, places=9)
    self.assertAlmostEqual(rebuilt_maya["mu_cal"], statistics.mean(maya_series), places=9)
    self.assertAlmostEqual(rebuilt_maya["var_cal"], statistics.pvariance(maya_series), places=9)
    self.assertAlmostEqual(rebuilt_maya["sd_cal"], math.sqrt(statistics.pvariance(maya_series)), places=9)

    # Additional active-day sparsity profiles: N=1, N=7, N=15, N=30
    synthetic_profiles = [
        [42.0] + [0.0] * 29,
        [12.0, 18.0, 5.0, 90.0, 3.0, 7.0, 15.0] + [0.0] * 23,
        [float(i * 3 + 2) for i in range(15)] + [0.0] * 15,
        [float((i % 7) * 5 + 10) for i in range(30)],
    ]
    for series in synthetic_profiles:
      active = [x for x in series if x > 0.0]
      n_act = len(active)
      avg_act = statistics.mean(active)
      sd_act = statistics.stdev(active) if n_act > 1 else 0.0
      rebuilt = rebuild_calendar_day_stats(
          active_days=n_act,
          active_avg=avg_act,
          active_sd=sd_act,
          window_days=30.0,
      )
      self.assertAlmostEqual(rebuilt["sum_x"], sum(series), places=9)
      self.assertAlmostEqual(rebuilt["sum_x2"], sum(x * x for x in series), places=8)
      self.assertAlmostEqual(rebuilt["mu_cal"], statistics.mean(series), places=9)
      self.assertAlmostEqual(rebuilt["var_cal"], statistics.pvariance(series), places=8)

  # ---------------------------------------------------------------------------
  # 4. MAD Gaussian Constants & Recalibrated Bowley-Tukey Fence
  # ---------------------------------------------------------------------------

  def test_4_mad_gaussian_constants_and_recalibrated_bowley_tukey_fence(self):
    """WS3: Verifies Phi^-1(0.75)=0.6745, sqrt(pi/2)=1.253314 MAD=0 fallback, and Bowley 1.35 Tukey excess Z."""
    # 4a. Exact Gaussian constants in mad.yl2
    phi_inv_75 = statistics.NormalDist().inv_cdf(0.75)
    self.assertAlmostEqual(phi_inv_75, 0.67448975, places=6)
    self.assertAlmostEqual(1.0 / 0.6745, 1.48257969, places=6)
    geary_meanad_const = math.sqrt(math.pi / 2.0)
    self.assertAlmostEqual(geary_meanad_const, 1.25331414, places=6)

    q_mad = self.router.build_query(
        target_metric="dns_queries_total",
        entity_type=EntityType.ASSET,
        statistical_model=StatisticalModel.MAD,
    )
    self.assertEqual([], MalachiteASTValidator.validate_query(q_mad))
    self.assertIn("$mad / 0.6745", q_mad)
    self.assertIn("$mean_abs_dev * 1.253314", q_mad)
    self.assertIn("window.median($stage1_extract.observed_val, false)", q_mad)

    # Zero-inflated / mode-pinned discrete series where >50% of active days equal 1 -> MAD = 0, meanAD > 0
    discrete_series = [1.0] * 20 + [8.0, 9.0, 10.0, 11.0, 12.0]
    med = statistics.median(discrete_series)
    mad_val = statistics.median([abs(x - med) for x in discrete_series])
    mean_ad = statistics.mean([abs(x - med) for x in discrete_series])
    self.assertEqual(med, 1.0)
    self.assertEqual(mad_val, 0.0)
    self.assertGreater(mean_ad, 0.0)
    robust_scale = (mad_val / 0.6745) if mad_val > 0.0 else (mean_ad * 1.253314)
    self.assertAlmostEqual(robust_scale, 1.8 * 1.253314, places=9)
    # Spike to 20 yields finite, reasonable modified Z (~8.42), NOT division-by-zero or flat floor explosion
    mod_z = (20.0 - med) / robust_scale
    self.assertGreater(mod_z, 3.5)
    self.assertLess(mod_z, 12.0)

    # 4b. Recalibrated Bowley-Tukey Fence (quantile_iqr_skew.yl2)
    q_quant = self.router.build_query(
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
        statistical_model=StatisticalModel.QUANTILE_IQR_SKEW,
    )
    self.assertEqual([], MalachiteASTValidator.validate_query(q_quant))
    self.assertIn("1.35 * if($bowley_skew > 0, $bowley_skew, 0.0)", q_quant)
    self.assertIn("$safe_iqr / 1.349", q_quant)

    def eval_bowley_tukey(obs: float, q25: float, q50: float, q75: float) -> tuple[float, float, float]:
      iqr = q75 - q25
      q50_floor = q50 * 0.05 + 1.0
      safe_iqr = iqr if iqr > 0.0 else q50_floor
      bowley = (q75 + q25 - 2.0 * q50) / safe_iqr
      adj_fence = q75 + 1.5 * math.exp(1.35 * max(0.0, bowley)) * safe_iqr
      r_scale = safe_iqr / 1.349
      excess_z = (obs - adj_fence) / r_scale
      return bowley, adj_fence, excess_z

    # Gaussian N(5000, 1000^2): Q25 = 5000 - 674.49, Q50 = 5000, Q75 = 5000 + 674.49 -> IQR = 1348.98
    mu_g, sd_g = 5000.0, 1000.0
    q25_g = mu_g - phi_inv_75 * sd_g
    q50_g = mu_g
    q75_g = mu_g + phi_inv_75 * sd_g
    b_g, fence_g, z_at_fence = eval_bowley_tukey(obs=0.0, q25=q25_g, q50=q50_g, q75=q75_g)
    self.assertAlmostEqual(b_g, 0.0, places=9)
    # Fence sits at Q3 + 1.5*IQR = mu + 2.69796*sigma, so excess Z == 0 at Fence and ~1.0 at mu + 3.70*sigma
    self.assertAlmostEqual((fence_g - mu_g) / sd_g, 4.0 * phi_inv_75, places=6)
    _, _, z_exact_fence = eval_bowley_tukey(obs=fence_g, q25=q25_g, q50=q50_g, q75=q75_g)
    self.assertAlmostEqual(z_exact_fence, 0.0, places=12)
    _, _, z_one_above = eval_bowley_tukey(obs=fence_g + sd_g, q25=q25_g, q50=q50_g, q75=q75_g)
    self.assertAlmostEqual(z_one_above, 1.0, delta=0.001)

    # Right-skewed log-normal X = exp(3.0 + 1.1*Z): B in (0, 1], fence expands above classical Tukey fence,
    # and near-zero Q25=0, Q50=0, Q75=0 never produces NaN/Inf ratio-cliff!
    q25_ln = math.exp(3.0 - 1.1 * phi_inv_75)
    q50_ln = math.exp(3.0)
    q75_ln = math.exp(3.0 + 1.1 * phi_inv_75)
    b_ln, fence_ln, _ = eval_bowley_tukey(obs=q75_ln, q25=q25_ln, q50=q50_ln, q75=q75_ln)
    self.assertGreater(b_ln, 0.20)
    self.assertLessEqual(b_ln, 1.0)
    classical_tukey_ln = q75_ln + 1.5 * (q75_ln - q25_ln)
    self.assertGreater(fence_ln, classical_tukey_ln)

    b_zero, fence_zero, z_zero = eval_bowley_tukey(obs=5.0, q25=0.0, q50=0.0, q75=0.0)
    self.assertEqual(b_zero, 0.0)
    self.assertTrue(math.isfinite(fence_zero) and math.isfinite(z_zero))

  # ---------------------------------------------------------------------------
  # 5. Empirical-Bayes Gamma Shrinkage Direction & NB Overdispersion
  # ---------------------------------------------------------------------------

  def test_5_empirical_bayes_gamma_shrinkage_direction_and_overdispersion(self):
    """WS3 / WS4: Verifies sparse vs dense Gamma shrinkage toward alpha0/beta0, +10sigma fire, and excess_var damping."""
    q_bg = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.BAYESIAN_GAMMA,
    )
    q_eb3 = self.router.build_pipeline_query(
        pipeline_type=PipelineArchitecture.EMPIRICAL_BAYES_3STAGE,
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
    )
    self.assertEqual([], MalachiteASTValidator.validate_query(q_bg))
    self.assertEqual([], MalachiteASTValidator.validate_query(q_eb3))

    def eval_poisson_gamma_nb(
        observed: float,
        hist_sum: float,
        hist_avg: float,
        hist_stddev: float,
        active_days: int,
        alpha0: float,
        beta0: float,
    ) -> dict[str, float]:
      mu_cal = hist_sum / 30.0
      df_minus_one = max(active_days, 1) - 1
      sum_x2 = (df_minus_one * hist_stddev * hist_stddev) + (active_days * hist_avg * hist_avg)
      var_cal = max((sum_x2 / 30.0) - (mu_cal * mu_cal), 0.0)
      excess_var = max(var_cal - mu_cal, 0.0) if active_days >= 2 else 0.0

      post_alpha_pre = alpha0 + hist_sum
      post_beta_pre = beta0 + 30.0
      posterior_rate = post_alpha_pre / post_beta_pre
      post_rate_var = post_alpha_pre / (post_beta_pre * post_beta_pre)
      cred_w = active_days / (active_days + beta0)
      pred_var = posterior_rate + post_rate_var + (cred_w * excess_var)
      safe_pred_sd = math.sqrt(max(pred_var, 1.0))
      bayesian_z = (observed - posterior_rate) / safe_pred_sd
      return {
          "mu_cal": mu_cal,
          "posterior_rate": posterior_rate,
          "cred_w": cred_w,
          "excess_var": excess_var,
          "safe_pred_sd": safe_pred_sd,
          "bayesian_z": bayesian_z,
      }

    # Verify under BOTH default hyperparameters (0.5, 0.1 -> mu0=5.0) and strong fleet prior (50.0, 10.0 -> mu0=5.0):
    # Sparse entity (S=2 over 1 active day, mu_cal=2/30) shrinks strictly closer to fleet prior mu0=5.0 than
    # dense entity (S=600 over 30 active days, mu_cal=20.0), and has strictly lower credibility weight cred_w.
    for alpha0, beta0 in (
        (DEFAULT_GAMMA_PRIOR_ALPHA0, DEFAULT_GAMMA_PRIOR_BETA0),
        (50.0, 10.0),
    ):
      mu0 = alpha0 / beta0
      sparse = eval_poisson_gamma_nb(
          observed=10.0, hist_sum=2.0, hist_avg=2.0, hist_stddev=0.0, active_days=1, alpha0=alpha0, beta0=beta0
      )
      dense = eval_poisson_gamma_nb(
          observed=10.0, hist_sum=600.0, hist_avg=20.0, hist_stddev=4.0, active_days=30, alpha0=alpha0, beta0=beta0
      )
      self.assertLess(abs(sparse["posterior_rate"] - mu0), abs(dense["posterior_rate"] - mu0))
      self.assertLess(sparse["cred_w"], dense["cred_w"])
      self.assertGreater(sparse["posterior_rate"], sparse["mu_cal"])
      self.assertLess(dense["posterior_rate"], dense["mu_cal"])

    # +10 sigma spike on a mature low-variance host (n=30, mean=20.0, sd=4.0 -> obs=60.0) MUST fire Z_pred > 3.0
    mature_spike = eval_poisson_gamma_nb(
        observed=60.0,
        hist_sum=600.0,
        hist_avg=20.0,
        hist_stddev=4.0,
        active_days=30,
        alpha0=DEFAULT_GAMMA_PRIOR_ALPHA0,
        beta0=DEFAULT_GAMMA_PRIOR_BETA0,
    )
    self.assertGreater(mature_spike["bayesian_z"], 3.0)

    # Chronic overdispersion (excess_var > 0: sd=25.0 on same mean=20.0, S=600, n=30) shrinks Z_pred vs stable host
    mature_noisy = eval_poisson_gamma_nb(
        observed=60.0,
        hist_sum=600.0,
        hist_avg=20.0,
        hist_stddev=25.0,
        active_days=30,
        alpha0=DEFAULT_GAMMA_PRIOR_ALPHA0,
        beta0=DEFAULT_GAMMA_PRIOR_BETA0,
    )
    self.assertGreater(mature_noisy["excess_var"], 500.0)
    self.assertLess(mature_noisy["bayesian_z"], mature_spike["bayesian_z"])
    self.assertLess(mature_noisy["bayesian_z"], 3.0)

    # Empirical Bayes fleet method-of-moments fitting recovers positive Gamma(alpha0, beta0) matching fleet mean rate
    fleet_gamma_rows = [{"hist_sum": float(30 * r)} for r in (2, 4, 5, 6, 8)]
    fit_a0, fit_b0 = fit_gamma_prior_from_fleet(fleet_gamma_rows)
    self.assertAlmostEqual(fit_a0 / fit_b0, 5.0, places=4)

  # ---------------------------------------------------------------------------
  # 6. Paired Beta-Binomial Posterior
  # ---------------------------------------------------------------------------

  def test_6_paired_beta_binomial_posterior_single_fail_vs_bruteforce_surge(self):
    """D1 / WS3: Under Beta(1.0, 19.0), 1/1 failure yields Z < 3.0 (no alert) while 25/30 yields Z > 3.5 (alerts)."""
    self.assertEqual(DEFAULT_BETA_PRIOR_ALPHA0, 1.0)
    self.assertEqual(DEFAULT_BETA_PRIOR_BETA0, 19.0)
    fit_ba0, fit_bb0 = fit_beta_prior_from_fleet([
        {"hist_fail_sum": 2.0, "hist_total_sum": 100.0},
        {"hist_fail_sum": 5.0, "hist_total_sum": 100.0},
        {"hist_fail_sum": 8.0, "hist_total_sum": 100.0},
    ])
    self.assertAlmostEqual(fit_ba0 / (fit_ba0 + fit_bb0), 0.05, places=4)

    q_bb = self.router.build_query(
        target_metric="auth_attempts_fail",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.BAYESIAN_BETA_BINOMIAL,
    )
    self.assertEqual([], MalachiteASTValidator.validate_query(q_bb))
    self.assertIn("metrics.auth_attempts_fail(", q_bb)
    self.assertIn("metrics.auth_attempts_total(", q_bb)

    def eval_beta_binomial(
        obs_fail: float,
        obs_total: float,
        hist_fail_sum: float = 0.0,
        hist_total_sum: float = 0.0,
        alpha0: float = DEFAULT_BETA_PRIOR_ALPHA0,
        beta0: float = DEFAULT_BETA_PRIOR_BETA0,
    ) -> tuple[float, float]:
      hist_succ_sum = max(hist_total_sum - hist_fail_sum, 0.0)
      alpha_pre = alpha0 + hist_fail_sum
      beta_pre = beta0 + hist_succ_sum
      ab = alpha_pre + beta_pre
      prior_fail_rate = alpha_pre / ab
      post_fail_rate = (alpha_pre + obs_fail) / (ab + obs_total)
      pred_mean = obs_total * prior_fail_rate
      pred_var = obs_total * prior_fail_rate * (beta_pre / ab) * ((ab + obs_total) / (ab + 1.0))
      safe_pred_sd = math.sqrt(max(pred_var, 0.25))
      beta_binomial_z = (obs_fail - pred_mean) / safe_pred_sd
      return post_fail_rate, beta_binomial_z

    # Case A: f = 1 failure out of n = 1 attempt -> shrunk posterior rate = 2/21 = 9.52%, Z_fail = 1.90 < 3.0 (NO ALERT)
    post_1_1, z_1_1 = eval_beta_binomial(obs_fail=1.0, obs_total=1.0)
    self.assertAlmostEqual(post_1_1, 2.0 / 21.0, places=9)
    self.assertAlmostEqual(z_1_1, 1.90, places=6)
    self.assertLess(z_1_1, 3.0)

    # Case B: f = 25 failures out of n = 30 attempts -> posterior rate = 26/50 = 52.0%, Z_fail = 12.758 > 3.5 (ALERTS)
    post_25_30, z_25_30 = eval_beta_binomial(obs_fail=25.0, obs_total=30.0)
    self.assertAlmostEqual(post_25_30, 26.0 / 50.0, places=9)
    self.assertGreater(z_25_30, 3.5)
    self.assertAlmostEqual(z_25_30, 12.758, places=2)

  # ---------------------------------------------------------------------------
  # 7. Adaptive Context Threshold (Off-Hours / Weekend vs Business Hours)
  # ---------------------------------------------------------------------------

  def test_7_adaptive_context_threshold_local_timezone_off_hours_vs_business_hours(self):
    """D1 / WS3: +2.0sigma event in America/New_York alerts at 02:00 Tue & 14:00 Sat (gate 1.75) but NOT 14:00 Wed (gate 3.0)."""
    tz_name = "America/New_York"
    q_adapt = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD,
        tenant_tz=tz_name,
        biz_start_hour=8,
        biz_end_hour=18,
    )
    self.assertEqual([], MalachiteASTValidator.validate_query(q_adapt))
    self.assertIn(f'timestamp.get_hour(metadata.event_timestamp.seconds, "{tz_name}")', q_adapt)
    self.assertIn(f'timestamp.get_day_of_week(metadata.event_timestamp.seconds, "{tz_name}")', q_adapt)
    self.assertIn("$effective_gate = if($off_hours_share >= 0.5, 1.75, 3.0)", q_adapt)

    tz = zoneinfo.ZoneInfo(tz_name)

    def eval_adaptive_at_local_time(
        local_dt: datetime.datetime,
        observed: float = 40.0,
        hist_avg: float = 20.0,
        hist_stddev: float = 10.0,
        active_days: int = 15,
    ) -> tuple[float, float, bool]:
      # Chronicle timestamp.get_day_of_week convention: 1 = Sunday, 2 = Monday, ..., 6 = Friday, 7 = Saturday
      py_weekday = local_dt.weekday()  # Mon=0 .. Sun=6
      chronicle_dow = 1 if py_weekday == 6 else (py_weekday + 2)
      hour = local_dt.hour
      in_schedule = (2 <= chronicle_dow <= 6) and (8 <= hour < 18)

      off_hours_obs = 0.0 if in_schedule else observed
      disp_floor = math.sqrt(max(hist_avg, 1.0))
      safe_std = max(hist_stddev, disp_floor)
      personal_z = (observed - hist_avg) / safe_std  # +2.0 sigma

      off_hours_share = off_hours_obs / max(observed, 1.0)
      effective_gate = 1.75 if off_hours_share >= 0.5 else 3.0
      adaptive_z = (personal_z * 3.0) / effective_gate
      alerts = (active_days >= 7) and (adaptive_z >= 3.0)
      return personal_z, adaptive_z, alerts

    # 1. 02:00 local Tuesday (2026-10-27T02:00:00 America/New_York) -> off-hours, +2.0sigma -> adaptive_z = 3.43 >= 3.0 (ALERTS)
    pz_tue_2am, az_tue_2am, alert_tue_2am = eval_adaptive_at_local_time(
        datetime.datetime(2026, 10, 27, 2, 0, 0, tzinfo=tz)
    )
    self.assertAlmostEqual(pz_tue_2am, 2.0, places=9)
    self.assertAlmostEqual(az_tue_2am, 6.0 / 1.75, places=6)
    self.assertTrue(alert_tue_2am)

    # 2. 14:00 local Saturday (2026-10-31T14:00:00 America/New_York) -> weekend, +2.0sigma -> adaptive_z = 3.43 >= 3.0 (ALERTS)
    pz_sat_2pm, az_sat_2pm, alert_sat_2pm = eval_adaptive_at_local_time(
        datetime.datetime(2026, 10, 31, 14, 0, 0, tzinfo=tz)
    )
    self.assertAlmostEqual(pz_sat_2pm, 2.0, places=9)
    self.assertAlmostEqual(az_sat_2pm, 6.0 / 1.75, places=6)
    self.assertTrue(alert_sat_2pm)

    # 3. 14:00 local Wednesday (2026-10-28T14:00:00 America/New_York) -> business hours, +2.0sigma -> adaptive_z = 2.0 < 3.0 (NO ALERT)
    pz_wed_2pm, az_wed_2pm, alert_wed_2pm = eval_adaptive_at_local_time(
        datetime.datetime(2026, 10, 28, 14, 0, 0, tzinfo=tz)
    )
    self.assertAlmostEqual(pz_wed_2pm, 2.0, places=9)
    self.assertAlmostEqual(az_wed_2pm, 2.0, places=6)
    self.assertFalse(alert_wed_2pm)


if __name__ == "__main__":
  unittest.main()
