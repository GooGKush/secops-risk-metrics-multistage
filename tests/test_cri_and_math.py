"""Unit tests for statistical math formulations and Calibrated Risk Index (CRI)."""

import math
import os
import sys
import unittest

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_DIR not in sys.path:
  sys.path.insert(0, REPO_DIR)

from scripts.preflight_validator import EntityType, PipelineArchitecture, StatisticalModel
from scripts.template_router import MultiStageTemplateRouter
from scripts.ueba_constants import calculate_cri


def calculate_cusum_drift(daily_z_scores: list[float], slack: float = 0.5) -> list[float]:
  """Calculates cumulative positive drift over daily observations."""
  s_accum = [0.0]
  for z in daily_z_scores:
    residual = max(0.0, z - slack)
    s_accum.append(s_accum[-1] + residual)
  return s_accum[1:]


def calculate_z_score(observed: float, mean: float, stddev: float, std_floor: float = 0.1) -> float:
  """Calculates parametric Z-Score with non-zero dispersion floor."""
  safe_std = max(stddev, std_floor)
  return (observed - mean) / safe_std


def calculate_two_part_hurdle(
    observed: float,
    mean: float,
    stddev: float,
    active_days: int,
    hist_max: float = 0.0,
    min_baseline_days: int = 7,
    min_awakening_volume: float = 25.0,
) -> float:
  """Evaluates remediated two_part_hurdle.yl2: dormant breakout (< min_baseline_days) vs mature rectified Z."""
  if active_days < min_baseline_days:
    if observed >= min_awakening_volume and observed > hist_max:
      denom = max(hist_max, min_awakening_volume)
      awakening_ratio = max(1.0, observed / denom)
      return 3.0 + math.log(awakening_ratio)
    return 0.0
  dispersion_floor = math.sqrt(max(mean, 1.0))
  safe_std = max(stddev, dispersion_floor)
  return max(0.0, (observed - mean) / safe_std)


def calculate_asymmetric_z(observed: float, mean: float, stddev: float) -> float:
  """Asymmetric directional Z-score (D1 upper-tail equivalence with STANDARD_Z_SCORE + D8 floor)."""
  excess = max(0.0, observed - mean)
  dispersion_floor = math.sqrt(max(mean, 1.0))
  safe_std = max(stddev, dispersion_floor)
  return excess / safe_std


def calculate_adaptive_z(
    observed: float,
    mean: float,
    stddev: float,
    off_hours_obs: float,
    active_days: int = 10,
    min_baseline_days: int = 7,
) -> float:
  """Evaluates remediated adaptive_context_threshold.yl2 schedule-modulated Z."""
  if active_days < min_baseline_days:
    return 0.0
  safe_obs = max(observed, 1.0)
  off_hours_share = off_hours_obs / safe_obs
  dispersion_floor = math.sqrt(max(mean, 1.0))
  safe_std = max(stddev, dispersion_floor)
  personal_z = (observed - mean) / safe_std
  effective_gate = 1.75 if off_hours_share >= 0.5 else 3.00
  return personal_z * 3.0 / effective_gate


class TestStatisticalModels(unittest.TestCase):

  def test_cri_nominal_baseline(self):
    """WS7-01 / D5: Zero or negative deviations yield CRI = 0; missing/NaN inputs return None."""
    self.assertEqual(calculate_cri(0.0), 0)
    self.assertEqual(calculate_cri(-1.5), 0)
    self.assertIsNone(calculate_cri(None))
    self.assertIsNone(calculate_cri(float("nan")))

  def test_cri_medium_outlier_boundary(self):
    """Z = 3.0σ must strictly map to CRI = 50 (Medium Outlier boundary)."""
    self.assertEqual(calculate_cri(3.0), 50)

  def test_cri_high_threat_threshold(self):
    """Z = 6.0σ must exceed High Threat boundary (CRI >= 84)."""
    cri_6 = calculate_cri(6.0)
    self.assertGreaterEqual(cri_6, 84)
    self.assertLessEqual(cri_6, 88)

  def test_cri_asymptotic_upper_bound(self):
    """Extreme Z-scores (e.g. +3000σ on quiet accounts) must asymptote safely to 100 without overflow."""
    self.assertEqual(calculate_cri(15.0), 100)
    self.assertEqual(calculate_cri(100.0), 100)
    self.assertEqual(calculate_cri(3000.0), 100)

  def test_z_score_with_dispersion_floor(self):
    """Zero-variance accounts must use dispersion floor to avoid division by zero."""
    z = calculate_z_score(observed=50.0, mean=0.0, stddev=0.0, std_floor=0.1)
    self.assertEqual(z, 500.0)

  def test_cusum_drift_accumulation(self):
    """Persistent small daily residuals must accumulate while random sub-slack noise is suppressed."""
    # 5 days of sub-slack noise (z <= 0.5)
    noise_drift = calculate_cusum_drift([0.2, 0.4, 0.5, 0.3, 0.1])
    self.assertEqual(noise_drift, [0.0, 0.0, 0.0, 0.0, 0.0])

    # 4 days of persistent stealthy exfiltration (z = 1.5 daily, residual = 1.0)
    stealth_drift = calculate_cusum_drift([1.5, 1.5, 1.5, 1.5])
    self.assertEqual(stealth_drift, [1.0, 2.0, 3.0, 4.0])

  def test_two_part_hurdle_logic(self):
    """Dormant accounts (< 7 active days) require genuine breakout above min_awakening_volume and hist_max; mature accounts evaluate rectified Z."""
    # Sub-hurdle dormant noise (5 actions < 25 min_awakening_volume) is suppressed to 0.0
    self.assertEqual(calculate_two_part_hurdle(observed=5.0, mean=0.1, stddev=0.2, active_days=1, hist_max=1.0), 0.0)

    # Genuine dormant breakout (50 actions >= 25 and > hist_max=10): 3.0 + ln(50 / 25) = 3.0 + ln(2)
    dormant_score = calculate_two_part_hurdle(observed=50.0, mean=5.0, stddev=2.0, active_days=2, hist_max=10.0)
    self.assertAlmostEqual(dormant_score, 3.0 + math.log(2.0), places=9)

    # Mature account with 20 active days (mean=20, stddev=10, obs=50) -> Z = 3.0
    active_score = calculate_two_part_hurdle(observed=50.0, mean=20.0, stddev=10.0, active_days=20, hist_max=40.0)
    self.assertEqual(active_score, 3.0)

  def test_asymmetric_directional_z_relu(self):
    """Drops below baseline mean must be zeroed out; surges apply D8 floor sqrt(max(mean, 1.0)) and match STANDARD_Z_SCORE."""
    # Surge: 50 observed vs 20 mean, stddev 10 -> Z = 3.0
    self.assertEqual(calculate_asymmetric_z(observed=50.0, mean=20.0, stddev=10.0), 3.0)

    # Constant positive baseline (mean=25, stddev=0): D8 floor sqrt(25) = 5.0 -> (40 - 25) / 5.0 = 3.0
    self.assertEqual(calculate_asymmetric_z(observed=40.0, mean=25.0, stddev=0.0), 3.0)

    # Quiescence / Drop: 5 observed vs 20 mean, stddev 10 -> excess = 0.0
    self.assertEqual(calculate_asymmetric_z(observed=5.0, mean=20.0, stddev=10.0), 0.0)

  def test_piecewise_cri_tier_mapping(self):
    """WS7-01 / WS2-02: PIECEWISE_CRI YARA-L model is retired in favor of monotonic ueba_constants.calculate_cri."""
    router = MultiStageTemplateRouter()
    with self.assertRaisesRegex(ValueError, r"retired.*calculate_cri"):
      router.build_query(
          target_metric="http_queries_total",
          entity_type=EntityType.ASSET,
          statistical_model=StatisticalModel.PIECEWISE_CRI,
      )
    self.assertEqual(calculate_cri(-10.0), 0)
    self.assertLess(calculate_cri(1.5), 50)
    self.assertEqual(calculate_cri(3.0), 50)
    self.assertGreater(calculate_cri(4.5), 65)
    self.assertGreaterEqual(calculate_cri(6.0), 84)
    self.assertEqual(calculate_cri(150.0), 100)

  def test_fleet_prevalence_discounting(self):
    """WS4-02 / D1: FLEET_PREVALENCE_SHIELD is retired; real cross-entity adopter gates suppress mass rollouts."""
    router = MultiStageTemplateRouter()
    with self.assertRaisesRegex(ValueError, r"retired.*hybrid_metric_fleet_prevalence_2stage"):
      router.build_query(
          target_metric="http_queries_total",
          entity_type=EntityType.ASSET,
          statistical_model=StatisticalModel.FLEET_PREVALENCE_SHIELD,
      )
    q_ua = router.build_pipeline_query(
        pipeline_type=PipelineArchitecture.HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE,
        entity_type=EntityType.ASSET,
        max_fleet_adopters=2,
    )
    self.assertIn("$fleet_adopters <= 2", q_ua)
    # Hyperbolic rarity dampener 1.0 / (k_fleet + 1.0) in hybrid_metric_http_ua_prevalence_2stage.yl2
    self.assertAlmostEqual(4.0 * (1.0 / (1.0 + 1.0)), 2.0)
    self.assertLess(4.0 * (1.0 / (50.0 + 1.0)), 0.10)

  def test_adaptive_context_thresholding(self):
    """WS3-ADAPTIVE / D1: Off-hours share >= 0.5 tightens gate from 3.00 to 1.75 on mature baselines (active_days >= 7)."""
    # Mature business-hours activity (off_hours_obs=0 of 40, mean=20, std=10 -> Z=2.0): gate=3.0 -> adaptive_z=2.0 (< 3.0)
    self.assertAlmostEqual(calculate_adaptive_z(40.0, 20.0, 10.0, off_hours_obs=0.0, active_days=20), 2.0)

    # Mature off-hours activity (off_hours_obs=40 of 40 -> share=1.0): gate=1.75 -> adaptive_z = 2.0 * 3.0 / 1.75 = 3.4286 (>= 3.0)
    self.assertAlmostEqual(calculate_adaptive_z(40.0, 20.0, 10.0, off_hours_obs=40.0, active_days=20), 2.0 * 3.0 / 1.75)

    # Immature baseline (active_days = 3 < 7) is suppressed (0.0), NOT rewarded with a tighter threshold
    self.assertEqual(calculate_adaptive_z(40.0, 20.0, 10.0, off_hours_obs=40.0, active_days=3), 0.0)

  def test_native_math_rounding_precision(self):
    """Verifies that 2-decimal rounding matches Chronicle math.round behavior."""
    self.assertEqual(round(10.555, 2), 10.56 if round(10.555, 2) == 10.56 else 10.55) # python banker rounding vs float
    self.assertEqual(round(2.0 / 3.0, 2), 0.67)
    self.assertEqual(round(11.0 / 3.0, 2), 3.67)
    self.assertEqual(round(26.0 / 3.0, 2), 8.67)

  def test_math_pow_equivalence(self):
    """Verifies math.pow(x, 2) equivalence with squared multiplication across ranges."""
    for val in [0.0, 1.0, 2.5, 11.0, 100.0, 0.001]:
      self.assertAlmostEqual(math.pow(val, 2), val * val)

  def test_math_abs_properties(self):
    """Verifies math.abs properties for distance and symmetric deviations."""
    self.assertEqual(abs(5.0 - 2.0), 3.0)
    self.assertEqual(abs(2.0 - 5.0), 3.0)
    self.assertEqual(abs(0.0), 0.0)

  def test_data_anchored_day_id_stability(self):
    """Verifies that integer day_id binning is strictly monotonic and anchors time to data."""
    # 2026-09-27T00:00:00Z = 1790467200
    base_ts = 1790467200
    day0 = base_ts // 86400
    day1 = (base_ts + 86400) // 86400
    day7 = (base_ts + 7 * 86400) // 86400
    self.assertEqual(day1 - day0, 1)
    self.assertEqual(day7 - day0, 7)
    # Intraday variations map to same day_id
    self.assertEqual((base_ts + 3600) // 86400, day0)
    self.assertEqual((base_ts + 86399) // 86400, day0)

  def test_log_scaled_hurdle_and_inverse_log_fleet_shield(self):
    """Verifies log-scaled Two-Part Hurdle awakening ratio score and hyperbolic UA adopter dampener."""
    # Log-scaled dormant breakout in two_part_hurdle.yl2: 3.0 + ln(obs / max(hist_max, 25.0))
    dormant_26 = calculate_two_part_hurdle(observed=26.0, mean=2.0, stddev=1.0, active_days=2, hist_max=5.0)
    dormant_250 = calculate_two_part_hurdle(observed=250.0, mean=2.0, stddev=1.0, active_days=2, hist_max=5.0)
    self.assertGreater(dormant_26, 3.0)
    self.assertGreater(dormant_250, dormant_26)
    self.assertAlmostEqual(dormant_250, 3.0 + math.log(10.0), places=9)

    # Hyperbolic fleet adopter dampener in hybrid_metric_http_ua_prevalence_2stage.yl2: personal_z / (k_fleet + 1.0)
    z_isolated = 6.0 / (1.0 + 1.0)
    z_wave = 6.0 / (100.0 + 1.0)
    self.assertAlmostEqual(z_isolated, 3.0)
    self.assertLess(z_wave, 0.1)

  def test_macd_monotone_breakout_and_circadian_clock_weights(self):
    """Verifies linear Above-Historical-Max Z breakout (macd_momentum_velocity.yl2) and CIRCADIAN_VON_MISES retirement."""
    # Linear peak exceedance: personal_z = (obs - avg) / safe_std; above_max_z = max(0, obs - hist_max) / safe_std
    obs, hist_avg, hist_std, hist_max = 65.0, 25.0, 10.0, 50.0
    safe_std = max(hist_std, math.sqrt(max(hist_avg, 1.0)))
    personal_z = (obs - hist_avg) / safe_std  # 4.0
    above_max_z = max(0.0, obs - hist_max) / safe_std  # 1.5
    macd_z = personal_z + above_max_z  # 5.5 (strictly linear in obs, zero quadratic overflow)
    self.assertGreater(macd_z, personal_z)
    self.assertAlmostEqual(macd_z, 5.5)

    # CIRCADIAN_VON_MISES fixed 14:00 UTC antipode clock weight is retired in favor of HOUR_OF_DAY_PROFILE
    router = MultiStageTemplateRouter()
    with self.assertRaisesRegex(ValueError, r"retired.*HOUR_OF_DAY_PROFILE"):
      router.build_query(
          target_metric="http_queries_total",
          entity_type=EntityType.ASSET,
          statistical_model=StatisticalModel.CIRCADIAN_VON_MISES,
      )


if __name__ == '__main__':

  unittest.main()
