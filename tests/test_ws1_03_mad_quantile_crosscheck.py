"""Regression tests for WS1-03: non-stale pre-scoring raw cross-check in MAD and Quantile."""

import math
from pathlib import Path
import re
import unittest

from scripts.preflight_validator import (
    AuditStatus,
    EntityType,
    MalachiteASTValidator,
    MatchMode,
    PostFlightExecutionAuditor,
    StatisticalModel,
)
from scripts.template_router import MultiStageTemplateRouter
from tests.live.live_compile_harness import _render_standalone_slot_pipeline
from tests.test_mad_cross_skill_sync import mad_signature

REPO_ROOT = Path(__file__).resolve().parent.parent


def _eval_emitted_pre_scoring_personal_z(
    query: str,
    *,
    observed: float,
    pre_daily_values: list[float],
    min_baseline_days: int = 7,
) -> float:
  """Evaluates the exact pre-scoring active-day Z formula emitted in MAD/Quantile queries."""
  assert "$pre_obs = if($in_scoring_window = 0, $obs_float, 0.0)" in query
  assert "$pre_obs_sq = $pre_obs * $pre_obs" in query
  assert "$pre_day = if($in_scoring_window = 0, 1, 0)" in query
  assert "$pre_n = sum($stage1_extract.pre_day)" in query
  assert "$pre_sum = sum($stage1_extract.pre_obs)" in query
  assert "$pre_sum_sq = sum($stage1_extract.pre_obs_sq)" in query
  assert f"if($active_days >= {min_baseline_days}, $raw_personal_z, 0.0)" in query

  pre_n = float(len(pre_daily_values))
  pre_sum = float(sum(pre_daily_values))
  pre_sum_sq = float(sum(v * v for v in pre_daily_values))

  safe_pre_n = pre_n if pre_n > 0 else 1.0
  pre_avg = pre_sum / safe_pre_n
  pre_df_raw = pre_n - 1.0
  safe_pre_df = pre_df_raw if pre_n > 1 else 1.0
  raw_var_num = pre_sum_sq - (pre_n * pre_avg * pre_avg)
  clamped_var_num = raw_var_num if raw_var_num > 0 else 0.0
  pre_sd = math.sqrt(clamped_var_num / safe_pre_df)

  floor_base = pre_avg if pre_avg > 1.0 else 1.0
  dispersion_floor = math.sqrt(floor_base)
  safe_stddev = pre_sd if pre_sd > dispersion_floor else dispersion_floor
  raw_personal_z = (observed - pre_avg) / safe_stddev
  return raw_personal_z if pre_n >= min_baseline_days else 0.0


class TestWS103MadAndQuantileNonStaleCrossCheck(unittest.TestCase):
  """Verifies WS1-03 replaces stale [D0-59d, D0-29d) metrics.* Z cross-check with pre-scoring raw Z."""

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  def test_router_mad_and_quantile_use_pre_scoring_raw_baseline_and_drop_stale_metrics_z(self):
    for model in (StatisticalModel.MAD, StatisticalModel.QUANTILE_IQR_SKEW):
      for mode in (MatchMode.FLEET_ROLLUP, MatchMode.TIMELINE_BREAKDOWN):
        query = self.router.build_query(
            target_metric="auth_attempts_total",
            entity_type=EntityType.USER,
            statistical_model=model,
            match_mode=mode,
            scoring_end_date="2026-10-27",
        )
        # Stale avg/stddev lookups must be dropped; only 1 lightweight num_metric_periods lookup remains.
        self.assertEqual(query.count("metrics."), 1, f"{model.value}/{mode.value}")
        self.assertIn("$historical_active_days =", query)
        self.assertNotIn("$historical_avg =", query)
        self.assertNotIn("$historical_stddev =", query)
        self.assertNotIn("$stage1_extract.historical_avg", query)
        self.assertNotIn("$stage1_extract.historical_stddev", query)

        # Pre-scoring accumulators must appear AFTER $observed_val in stage1_extract.
        obs_pos = query.index("$observed_val =")
        pre_pos = query.index("$pre_obs = if($in_scoring_window = 0, $obs_float, 0.0)")
        self.assertGreater(pre_pos, obs_pos)

        # Must pass AST validation, model concordance, and post-flight execution audit.
        self.assertEqual(MalachiteASTValidator.validate_query(query), [])
        self.assertEqual(MalachiteASTValidator.validate_model_concordance(query, model), [])
        audit = PostFlightExecutionAuditor.audit_execution(
            executed_query=query,
            api_response={"stats": {"results": []}},
            target_metric="auth_attempts_total",
            entity_type=EntityType.USER,
            statistical_model=model,
        )
        self.assertEqual(audit.status, AuditStatus.PASSED, audit.errors)

  def test_standalone_mad_and_quantile_pipelines_use_pre_scoring_raw_baseline(self):
    for filename in ("mad_robust_z_4stage.yl2", "quantile_iqr_skew_3stage.yl2"):
      raw = (REPO_ROOT / "templates" / "pipelines" / filename).read_text(encoding="utf-8")
      self.assertEqual(raw.count("metrics.{{target_metric_name}}("), 1, filename)
      self.assertNotIn("$historical_avg =", raw, filename)
      self.assertNotIn("$historical_stddev =", raw, filename)
      self.assertIn("$pre_obs = if($in_scoring_window = 0, $obs_float, 0.0)", raw, filename)

      rendered = _render_standalone_slot_pipeline(
          filename,
          "auth_attempts_total",
          EntityType.USER,
          target_date="2026-10-27",
      )
      self.assertEqual(MalachiteASTValidator.validate_query(rendered), [], filename)
      # Verify every stage stays within the 20-outcome compiler ceiling, including Root.
      stages, root_body = MalachiteASTValidator._extract_stage_blocks(rendered)
      for sname, sbody in [*stages, ("root", root_body)]:
        m = re.search(r"outcome:\s*(.*?)(?=\n\s*(?:condition|order|$))", sbody, re.S)
        if m:
          outcomes = re.findall(r"\$([a-zA-Z0-9_]+)\s*=", m.group(1))
          self.assertLessEqual(len(outcomes), 20, f"{filename} stage {sname} has {len(outcomes)} outcomes")

  def test_mad_cross_skill_signature_preserved(self):
    for rel in ("templates/stage2_math_models/mad.yl2", "templates/pipelines/mad_robust_z_4stage.yl2"):
      sig = mad_signature((REPO_ROOT / rel).read_text(encoding="utf-8"))
      self.assertEqual(sig["median_calls_ignore_zero_false"], [True, True], f"{rel}: {sig}")
      for key, value in sig.items():
        if key != "median_calls_ignore_zero_false":
          self.assertTrue(value, f"{rel}: MAD signature element '{key}' became False")

  def test_charles_hardy_cross_check_evaluates_to_5_42_sigma_and_immature_is_zero(self):
    # Construct a 10-day series with exact mean 164.6 and sample SD 114.4875:
    # 5 days at (164.6 + d) and 5 days at (164.6 - d), where 10 * d^2 / 9 = 114.4875^2.
    target_mean = 164.6
    target_sd = 114.4875
    delta = math.sqrt(9.0 * (target_sd ** 2) / 10.0)
    charles_series = [target_mean - delta] * 5 + [target_mean + delta] * 5

    for model in (StatisticalModel.MAD, StatisticalModel.QUANTILE_IQR_SKEW):
      query = self.router.build_query(
          target_metric="auth_attempts_total",
          entity_type=EntityType.USER,
          statistical_model=model,
          match_mode=MatchMode.FLEET_ROLLUP,
          scoring_end_date="2026-10-27",
      )
      z_charles = _eval_emitted_pre_scoring_personal_z(
          query,
          observed=785.0,
          pre_daily_values=charles_series,
          min_baseline_days=7,
      )
      self.assertEqual(round(z_charles, 2), 5.42)
      self.assertAlmostEqual(z_charles, (785.0 - 164.6) / 114.4875, places=4)

      # Immature entity (maya.goodman: n = 2 active days {97, 4}) must yield $personal_z = 0.0
      z_maya = _eval_emitted_pre_scoring_personal_z(
          query,
          observed=150.0,
          pre_daily_values=[97.0, 4.0],
          min_baseline_days=7,
      )
      self.assertEqual(z_maya, 0.0)


if __name__ == "__main__":
  unittest.main()
