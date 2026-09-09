"""Unit tests for statistical math formulations and Calibrated Risk Index (CRI)."""

import math
import unittest


def calculate_cri(z_score: float) -> int:
  """Calibrated Risk Index logistic sigmoid function [0-100]."""
  if z_score <= 0:
    return 0
  return round(100.0 / (1.0 + math.exp(-0.6 * (z_score - 3.0))))


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


def calculate_two_part_hurdle(observed: float, mean: float, stddev: float, active_days: int) -> float:
  """Two-part hurdle model: dormant awakening penalty vs continuous intensity."""
  if active_days <= 2:
    return observed * 2.0
  safe_std = stddev if stddev > 0 else 1.0
  return (observed - mean) / safe_std


def calculate_asymmetric_z(observed: float, mean: float, stddev: float) -> float:
  """Asymmetric directional Z-score with ReLU activation."""
  diff = observed - mean
  excess = diff if diff > 0 else 0.0
  safe_std = stddev if stddev > 0 else 1.0
  return excess / safe_std


def calculate_piecewise_cri(z_score: float) -> float:
  """Winsorized Z-score and piecewise linear CRI mapping [0-100]."""
  clamped_low = -4.0 if z_score < -4.0 else z_score
  clamped_z = 6.0 if clamped_low > 6.0 else clamped_low
  if clamped_z >= 4.0:
    return 95.0
  elif clamped_z >= 3.0:
    return 85.0
  elif clamped_z >= 2.0:
    return 65.0
  elif clamped_z >= 1.0:
    return 40.0
  return 15.0


def calculate_fleet_shield(z_score: float, fleet_count: int) -> float:
  """Fleet prevalence concurrency discounting."""
  factor = 0.15 if fleet_count > 10 else 1.0
  return z_score * factor


def calculate_adaptive_excess(z_score: float, active_days: int) -> float:
  """Context-modulated adaptive sensitivity tightening."""
  dynamic_threshold = 1.75 if active_days <= 5 else 3.00
  return z_score - dynamic_threshold


class TestStatisticalModels(unittest.TestCase):

  def test_cri_nominal_baseline(self):
    """Zero or negative deviations must yield CRI = 0 (Nominal)."""
    self.assertEqual(calculate_cri(0.0), 0)
    self.assertEqual(calculate_cri(-1.5), 0)

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
    """Dormant accounts (active <= 2) trigger dormant multiplier; active accounts evaluate Z."""
    # Dormant account awakening with 5 actions
    dormant_score = calculate_two_part_hurdle(observed=5.0, mean=0.1, stddev=0.2, active_days=1)
    self.assertEqual(dormant_score, 10.0)

    # Active account with 20 active days
    active_score = calculate_two_part_hurdle(observed=50.0, mean=20.0, stddev=10.0, active_days=20)
    self.assertEqual(active_score, 3.0)

  def test_asymmetric_directional_z_relu(self):
    """Drops below baseline mean must be zeroed out; surges must produce positive Z."""
    # Surge: 50 observed vs 20 mean, stddev 10 -> Z = 3.0
    self.assertEqual(calculate_asymmetric_z(observed=50.0, mean=20.0, stddev=10.0), 3.0)

    # Quiescence / Drop: 5 observed vs 20 mean, stddev 10 -> excess = 0.0
    self.assertEqual(calculate_asymmetric_z(observed=5.0, mean=20.0, stddev=10.0), 0.0)

  def test_piecewise_cri_tier_mapping(self):
    """Winsorized clamping and step function tiering across boundaries."""
    self.assertEqual(calculate_piecewise_cri(0.5), 15.0)   # Nominal
    self.assertEqual(calculate_piecewise_cri(1.5), 40.0)   # Guarded
    self.assertEqual(calculate_piecewise_cri(2.5), 65.0)   # Elevated
    self.assertEqual(calculate_piecewise_cri(3.5), 85.0)   # High
    self.assertEqual(calculate_piecewise_cri(5.5), 95.0)   # Critical
    self.assertEqual(calculate_piecewise_cri(150.0), 95.0) # Clamped at 6.0 -> 95.0
    self.assertEqual(calculate_piecewise_cri(-10.0), 15.0) # Clamped at -4.0 -> 15.0

  def test_fleet_prevalence_discounting(self):
    """Isolated host spikes retain full score; mass spikes (>10 hosts) are discounted by 85%."""
    # Isolated spike (2 hosts)
    self.assertEqual(calculate_fleet_shield(z_score=4.0, fleet_count=2), 4.0)

    # Enterprise mass spike (50 hosts) -> 4.0 * 0.15 = 0.60
    self.assertAlmostEqual(calculate_fleet_shield(z_score=4.0, fleet_count=50), 0.60)

  def test_adaptive_context_thresholding(self):
    """Sparse / off-hours entities have lower detection hurdle (1.75) than routine entities (3.00)."""
    # Standard account (active_days = 20) with Z = 2.5 -> excess = 2.5 - 3.0 = -0.5 (not flagged)
    self.assertAlmostEqual(calculate_adaptive_excess(z_score=2.5, active_days=20), -0.5)

    # Off-hours / sparse account (active_days = 3) with Z = 2.5 -> excess = 2.5 - 1.75 = +0.75 (flagged!)
    self.assertAlmostEqual(calculate_adaptive_excess(z_score=2.5, active_days=3), 0.75)


if __name__ == '__main__':
  unittest.main()
