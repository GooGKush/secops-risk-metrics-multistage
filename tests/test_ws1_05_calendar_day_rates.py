"""Regression & unit tests for WS1-05: Calendar-Day Rates & Rebuilt 30d Statistics (PF-1, PF-2)."""

from __future__ import annotations

import math
import unittest

import scripts.timeline_assembler as timeline_assembler
import scripts.ueba_hybrid_engine as ueba_hybrid_engine
from scripts.preflight_validator import EntityType, MalachiteASTValidator, StatisticalModel
from scripts.template_router import MultiStageTemplateRouter
from scripts.ueba_hybrid_engine import UEBAHybridEngine


class TestWS105CalendarDayRates(unittest.TestCase):
  """Verifies per-calendar-day rates (historical_sum / 30) and rebuilt 30-day statistics."""

  def setUp(self) -> None:
    self.router = MultiStageTemplateRouter()

  def test_maya_goodman_vlive_calendar_day_stats_reconstruction(self) -> None:
    # V-live (PF-1, PF-2): maya.goodman has 2 active days {97, 4} in 30d window:
    #   active_days = 2, active_avg = 50.5, active_sd = sqrt(4324.5) ≈ 65.76093065, sum = 101.
    # Expected calendar-day values:
    #   sum_x = 101.0
    #   sum_x2 = (2 - 1) * 4324.5 + 2 * 50.5^2 = 4324.5 + 5100.5 = 9425.0 (= 97^2 + 4^2)
    #   lambda_cal = mu_cal = 101 / 30 = 3.366667 (rounds to 3.37, NOT 50.5!)
    #   var_cal = 9425 / 30 - (101 / 30)^2 = 302.832222
    active_sd = math.sqrt(4324.5)
    self.assertTrue(hasattr(ueba_hybrid_engine, "rebuild_calendar_day_stats"))
    self.assertTrue(hasattr(timeline_assembler, "rebuild_calendar_day_stats"))
    stats = ueba_hybrid_engine.rebuild_calendar_day_stats(
        active_days=2,
        active_avg=50.5,
        active_sd=active_sd,
        historical_sum=101.0,
    )
    self.assertAlmostEqual(stats["sum_x"], 101.0, places=6)
    self.assertAlmostEqual(stats["sum_x2"], 9425.0, places=6)
    self.assertAlmostEqual(stats["sum_x2"], float(97**2 + 4**2), places=6)
    self.assertAlmostEqual(stats["lambda_cal"], 101.0 / 30.0, places=6)
    self.assertEqual(round(stats["lambda_cal"], 2), 3.37)
    self.assertNotAlmostEqual(stats["lambda_cal"], 50.5, places=2)
    self.assertAlmostEqual(stats["mu_cal"], 101.0 / 30.0, places=6)
    expected_var = (9425.0 / 30.0) - ((101.0 / 30.0) ** 2)
    self.assertAlmostEqual(stats["var_cal"], expected_var, places=6)
    self.assertAlmostEqual(stats["sd_cal"], math.sqrt(expected_var), places=6)
    self.assertAlmostEqual(stats["dormant_days"], 28.0, places=6)

    # Also verify facade and timeline_assembler re-export
    self.assertEqual(UEBAHybridEngine.rebuild_calendar_day_stats(2, 50.5, active_sd), stats)
    self.assertEqual(timeline_assembler.rebuild_calendar_day_stats(2, 50.5, active_sd), stats)

  def test_edge_cases_zero_one_and_thirty_active_days(self) -> None:
    self.assertTrue(hasattr(ueba_hybrid_engine, "rebuild_calendar_day_stats"))
    rebuild_calendar_day_stats = ueba_hybrid_engine.rebuild_calendar_day_stats
    # n = 0 (cold start)
    s0 = rebuild_calendar_day_stats(active_days=0, active_avg=0.0, active_sd=0.0)
    self.assertEqual(s0["sum_x"], 0.0)
    self.assertEqual(s0["sum_x2"], 0.0)
    self.assertEqual(s0["lambda_cal"], 0.0)
    self.assertEqual(s0["var_cal"], 0.0)
    self.assertEqual(s0["dormant_days"], 30.0)

    # n = 1 ({60.0} on 1 day, twenty-nine 0s)
    s1 = rebuild_calendar_day_stats(active_days=1, active_avg=60.0, active_sd=0.0)
    self.assertAlmostEqual(s1["sum_x"], 60.0, places=6)
    self.assertAlmostEqual(s1["sum_x2"], 3600.0, places=6)
    self.assertAlmostEqual(s1["mu_cal"], 2.0, places=6)
    # Population variance over 30 days: 3600/30 - 2^2 = 120 - 4 = 116
    self.assertAlmostEqual(s1["var_cal"], 116.0, places=6)
    self.assertAlmostEqual(s1["dormant_days"], 29.0, places=6)

    # n = 30 (frank.kolzig: 103 every day, sd = 0)
    s30 = rebuild_calendar_day_stats(active_days=30, active_avg=103.0, active_sd=0.0)
    self.assertAlmostEqual(s30["sum_x"], 3090.0, places=6)
    self.assertAlmostEqual(s30["mu_cal"], 103.0, places=6)
    self.assertAlmostEqual(s30["var_cal"], 0.0, places=6)
    self.assertAlmostEqual(s30["sd_cal"], 0.0, places=6)
    self.assertAlmostEqual(s30["dormant_days"], 0.0, places=6)

  def test_poisson_rarity_uses_historical_sum_div_30_and_rebuilds_cal_stats(self) -> None:
    q = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.POISSON,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q), [])
    self.assertNotIn("$lambda = max($stage1_extract.historical_avg)", q)
    self.assertIn("$hist_sum = max($stage1_extract.historical_sum)", q)
    self.assertIn("$lambda = $hist_sum / 30.0", q)
    self.assertIn("$sum_x = $active_days * $hist_avg", q)
    self.assertIn("$sum_x2 = ($df_minus_one * $hist_stddev * $hist_stddev) + ($active_days * $hist_avg * $hist_avg)", q)
    self.assertIn("$mu_cal = $sum_x / 30.0", q)
    self.assertIn("$raw_var_cal = ($sum_x2 / 30.0) - ($mu_cal * $mu_cal)", q)

  def test_poisson_rarity_2stage_pipeline_uses_calendar_day_lambda(self) -> None:
    pipe_path = self.router.template_dir / "pipelines" / "poisson_rarity_2stage.yl2"
    raw = pipe_path.read_text(encoding="utf-8")
    self.assertNotIn("$lambda = max($stage1_extract.historical_avg)", raw)
    self.assertIn("$hist_sum = max($stage1_extract.historical_sum)", raw)
    self.assertIn("$lambda = $hist_sum / 30.0", raw)
    self.assertIn("$sum_x2 =", raw)
    self.assertIn("$mu_cal = $sum_x / 30.0", raw)

  def test_two_part_hurdle_computes_calendar_rate_dormant_days_and_cal_variance(self) -> None:
    q = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.TWO_PART_HURDLE,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q), [])
    self.assertIn("$hist_sum = max($stage1_extract.historical_sum)", q)
    self.assertIn("$mu_cal = $hist_sum / 30.0", q)
    self.assertIn("$dormant_days = 30.0 - $active_days", q)
    self.assertIn("$sum_x2 = ($df_minus_one * $hist_stddev * $hist_stddev) + ($active_days * $hist_avg * $hist_avg)", q)
    self.assertIn("$dispersion_floor = math.sqrt(if($hist_avg > 1.0, $hist_avg, 1.0))", q)


if __name__ == "__main__":
  unittest.main()
