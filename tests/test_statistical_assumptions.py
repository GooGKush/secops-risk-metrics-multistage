"""Empirical validation and test suite for the 4 core mathematical assumptions in secops-risk-metrics-multistage.

Author: Greg Kushmerek
"""

import math
import random
import statistics
import unittest


class TestStatisticalAssumptions(unittest.TestCase):

  def setUp(self):
    random.seed(42)

  def test_assumption_1_skewness_and_dispersion_floor(self):
    """Assumption 1: Security telemetry is heavy-tailed; D8 dispersion floor sqrt(max(mu, 1.0)) prevents sigma=0 explosions."""
    # Synthetic quiet host telemetry: 28 days of 0 events, 2 days of 1 event
    quiet_history = [0] * 28 + [1, 1]
    mu = statistics.mean(quiet_history)
    sigma = statistics.stdev(quiet_history)
    self.assertLess(mu, 0.1)
    self.assertLess(sigma, 0.3)

    # Observed surge today = 10 events
    obs_today = 10
    # Naive Z-score without floor
    naive_z = (obs_today - mu) / sigma
    self.assertGreater(naive_z, 30.0)  # Extreme, fragile 30+ sigma

    # D8 count dispersion floor: sqrt(max(mu, 1.0)) = 1.0 when mu < 1.0, and sqrt(mu) when mu > 1.0
    safe_sigma = max(sigma, math.sqrt(max(mu, 1.0)))
    self.assertEqual(safe_sigma, 1.0)
    floored_z = (obs_today - mu) / safe_sigma
    self.assertAlmostEqual(floored_z, (10 - mu), delta=0.2)
    self.assertLess(floored_z, 15.0)

    # Constant positive baseline (mu = 25.0, sigma = 0.0): Poisson floor scales as sqrt(25.0) = 5.0, NOT 1.0
    mu_const, sigma_const = 25.0, 0.0
    safe_sigma_const = max(sigma_const, math.sqrt(max(mu_const, 1.0)))
    self.assertEqual(safe_sigma_const, 5.0)
    self.assertAlmostEqual((40.0 - mu_const) / safe_sigma_const, 3.0)

  def test_assumption_2_weekend_seasonality_distortion(self):
    """Assumption 2: Weekday vs Weekend cyclic patterns distort non-seasonal 30-day blended baselines."""
    # 4 weeks: 5 weekdays (mean=100) + 2 weekends (mean=10)
    history = []
    for _ in range(4):
      history.extend([100 + random.gauss(0, 5) for _ in range(5)])
      history.extend([10 + random.gauss(0, 2) for _ in range(2)])

    blended_30d_mean = statistics.mean(history)
    # Blended mean is ~74
    self.assertTrue(70 <= blended_30d_mean <= 78)

    # Sunday observation of 35 events:
    # Relative to Sundays (mean=10), 35 is a massive 3.5x surge (+12 sigma on weekend)
    # But relative to blended 30d mean (74), 35 looks like quiet negative activity (-2.5 sigma)
    sunday_obs = 35
    sunday_mean = 10.0
    sunday_std = 2.0

    weekend_z = (sunday_obs - sunday_mean) / sunday_std
    blended_z = (sunday_obs - blended_30d_mean) / statistics.stdev(history)

    self.assertGreater(weekend_z, 10.0)  # True weekend intrusion detected
    self.assertLess(blended_z, 0.0)       # False negative in blended 30d baseline!

  def test_assumption_3_multi_sector_rectified_norm_and_delta_z(self):
    """Assumption 3: Clamped multi-sector norm D is a rectified mixture, not Chi(3); E[D] ~ 0.97 and P(D = 0) = 12.5%."""
    # Monte Carlo simulation of 20,000 independent 3D standard normal vectors.
    # D clamps each component at zero (see scripts/radar_collector.py), so under
    # the null D is NOT Chi(3). It is the rectified mixture sum_j C(K,j) 2^-K Chi(j):
    # only the j sectors that exceed baseline contribute, and all-quiet yields D = 0.
    n_samples = 20000
    norms = []
    delta_zs = []

    for _ in range(n_samples):
      z_auth = random.gauss(0, 1)
      z_proc = random.gauss(0, 1)
      z_net = random.gauss(0, 1)
      z_fleet = random.gauss(0, 1)

      d = math.sqrt(
          max(0.0, z_auth) ** 2 + max(0.0, z_proc) ** 2 + max(0.0, z_net) ** 2
      )
      norms.append(d)

      delta_z = z_auth - z_fleet
      delta_zs.append(delta_z)

    # Theoretical mean of the rectified mixture (K=3) = 0.9687; Chi(3) would be 1.5957.
    empirical_mean_d = statistics.mean(norms)
    self.assertAlmostEqual(empirical_mean_d, 0.969, delta=0.05)

    # Theoretical E[D^2] = K/2 = 1.5 (half of the Chi-squared(3) value of 3.0).
    empirical_mean_d_sq = statistics.mean(d * d for d in norms)
    self.assertAlmostEqual(empirical_mean_d_sq, 1.5, delta=0.08)

    # Point mass at zero: all K sectors at or below baseline, P = 2^-K = 12.5%.
    # This is the defining feature of clamping and is absent from any Chi distribution.
    p_d_zero = sum(1 for d in norms if d == 0.0) / n_samples
    self.assertTrue(0.110 <= p_d_zero <= 0.140, f"Expected P(D=0) ~ 0.125, got {p_d_zero}")

    # Probability of D >= 3.0 under the rectified mixture is ~0.88%
    # (Chi(3) would give 2.93%, so the unclamped form over-alerts by ~3.3x).
    p_d_ge_3 = sum(1 for d in norms if d >= 3.0) / n_samples
    self.assertTrue(0.006 <= p_d_ge_3 <= 0.013, f"Expected p ~ 0.0088, got {p_d_ge_3}")

    # Clamping moves the critical value matching 1D 3-sigma rarity (p = 0.00135)
    # from 4.02 (Chi(3)) down to 3.586.
    p_d_ge_crit = sum(1 for d in norms if d >= 3.586) / n_samples
    self.assertTrue(0.0007 <= p_d_ge_crit <= 0.0030, f"Expected p ~ 0.00135, got {p_d_ge_crit}")

    # Standard deviation of Delta Z = Z1 - Z2 is sqrt(1 + 1) = sqrt(2) ≈ 1.414
    empirical_std_delta_z = statistics.stdev(delta_zs)
    self.assertAlmostEqual(empirical_std_delta_z, math.sqrt(2), delta=0.05)

  def test_assumption_4_empirical_bayes_shrinkage_on_sparse_entities(self):
    """Assumption 4: Pre-observation 30d Empirical Bayes Gamma-NB shrinkage regularizes sparse entities without leaking obs."""
    # Fleet hyperprior over daily calendar rates: fleet_mu = 5.0/day, fleet_var = 2.5 -> beta0 = 2.0, alpha0 = 10.0
    # Wait: test strong fleet hyperprior beta0 = 15.0, alpha0 = 75.0 (fleet_mu = 5.0/day, equivalent to 15 days of prior exposure)
    fleet_mu = 5.0
    beta0 = 15.0
    alpha0 = fleet_mu * beta0  # 75.0

    # New host with only 2 active days in the 30d baseline (hist_sum = 20, active-day avg = 10.0, active-day std = 1.0)
    # Calendar-day rate mu_cal = 20 / 30 = 0.667; today's observation = 80 events
    hist_sum = 20.0
    host_obs_24h = 80.0
    host_avg_active = 10.0
    host_std_active = 1.0

    # Naive active-day Z-score: (80 - 10) / 1.0 = +70 sigma (wildly inflated by n=2 active-day sample variance)
    naive_z = (host_obs_24h - host_avg_active) / host_std_active
    self.assertEqual(naive_z, 70.0)

    # Pre-observation 30-day conjugate posterior rate (poisson_gamma_bayesian.yl2 / hierarchical_empirical_bayes_3stage.yl2):
    # Today's observation is NEVER added to post_alpha_pre!
    post_alpha_pre = alpha0 + hist_sum       # 75 + 20 = 95.0
    post_beta_pre = beta0 + 30.0             # 15 + 30 = 45.0
    posterior_rate = post_alpha_pre / post_beta_pre  # 95 / 45 = 2.111...

    prior_weight = beta0 / (beta0 + 30.0)     # 15 / 45 = 1/3
    evidence_weight = 30.0 / (beta0 + 30.0)   # 30 / 45 = 2/3
    mu_cal = hist_sum / 30.0

    self.assertAlmostEqual(prior_weight, 1.0 / 3.0, places=9)
    self.assertAlmostEqual(evidence_weight, 2.0 / 3.0, places=9)
    self.assertAlmostEqual(posterior_rate, prior_weight * fleet_mu + evidence_weight * mu_cal, places=9)
    self.assertGreater(posterior_rate, mu_cal)
    self.assertLess(posterior_rate, fleet_mu)

  def test_assumption_4b_shrinkage_behavior_under_extreme_sparsity_n_less_than_3(self):
    """Asserts that sparse entities (hist_sum=2 over N=1 active day) shrink toward fleet prior mu0 = alpha0/beta0."""
    fleet_mu = 20.0
    beta0 = 30.0
    alpha0 = fleet_mu * beta0  # 600.0 (30 prior exposure days at 20/day)

    # Entity with 1 active baseline day (hist_sum = 2, mu_cal = 2/30 = 0.0667)
    hist_sum = 2.0
    mu_cal = hist_sum / 30.0
    post_rate = (alpha0 + hist_sum) / (beta0 + 30.0)  # 602 / 60 = 10.0333

    self.assertGreater(post_rate, mu_cal)
    self.assertLess(post_rate, fleet_mu)
    self.assertAlmostEqual(post_rate, 602.0 / 60.0, places=9)


if __name__ == '__main__':
  unittest.main()
