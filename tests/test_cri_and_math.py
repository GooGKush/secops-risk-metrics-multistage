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


if __name__ == '__main__':
  unittest.main()
