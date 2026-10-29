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

"""WS0-01 audit regression guards for secondary-entity composite keys, Mode A windows, and zero-avg floors."""

import datetime
import re
import unittest

from scripts.preflight_validator import (
    EntityType,
    MalachiteASTValidator,
    MatchMode,
    PipelineArchitecture,
    StatisticalModel,
)
from scripts.template_router import MultiStageTemplateRouter
from scripts.ueba_hybrid_engine import compile_hunt_pipeline


class WS001AuditGuardsTest(unittest.TestCase):
  """Regression guards pinning XC-1 secondary-entity composite keys, 1d Mode A quantile windows, and RELATIVE_DEVIATION floors."""

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  @staticmethod
  def _extract_match_clauses(query: str) -> list[str]:
    code = "\n".join(
        line.split("//", 1)[0]
        for line in query.splitlines()
        if not line.lstrip().startswith("//")
    )
    return [m.strip() for m in re.findall(r"\bmatch:\s*\n\s*([^\n]+)", code)]

  def test_xc1_composite_key_mixing_across_secondary_entity_types_and_leaves(self):
    """XC-1 guard: secondary entity types and leaves must preserve full composite baseline tuples in Stage 1 and Root match."""
    # 1. (resource_*, EntityType.RESOURCE) across single-stage and multi-stage math models
    for model in (
        StatisticalModel.STANDARD_Z_SCORE,
        StatisticalModel.MAD,
        StatisticalModel.QUANTILE_IQR_SKEW,
        StatisticalModel.BAYESIAN_GAMMA,
        StatisticalModel.FIRST_SEEN_NOVELTY,
    ):
      q = self.router.build_query(
          target_metric="resource_read_total",
          entity_type=EntityType.RESOURCE,
          statistical_model=model,
          match_mode=MatchMode.TIMELINE_BREAKDOWN,
      )
      self.assertEqual([], MalachiteASTValidator.validate_query(q))
      matches = self._extract_match_clauses(q)
      self.assertGreaterEqual(len(matches), 2)
      for idx in (0, -1):
        for comp_var in ("$sa", "$vendor", "$product", "$resource"):
          self.assertIn(comp_var, matches[idx], f"{model.value} match[{idx}] missing {comp_var}: {matches[idx]}")
        self.assertNotIn("$ip", matches[idx], f"{model.value} match[{idx}] leaked non-dimension $ip: {matches[idx]}")

    # 2. (resource_*, EntityType.USER) with secondary user identifier leaves in STANDARD_Z_SCORE (Dual-Branch)
    for id_leaf, expected_field in (
        ("email_addresses", "principal.user.email_addresses"),
        ("windows_sid", "principal.user.windows_sid"),
        ("employee_id", "principal.user.employee_id"),
        ("product_object_id", "principal.user.product_object_id"),
    ):
      q_dual = self.router.build_query(
          target_metric="resource_read_total",
          entity_type=EntityType.USER,
          statistical_model=StatisticalModel.STANDARD_Z_SCORE,
          identifier_field=id_leaf,
      )
      self.assertEqual([], MalachiteASTValidator.validate_query(q_dual))
      self.assertIn(f"$sa = {expected_field}", q_dual)
      self.assertIn(f"{expected_field}: {expected_field}", q_dual)
      self.assertNotIn("principal.user.userid: principal.user.userid", q_dual)

    # 3. (file_executions_total, EntityType.USER) preserves ($host/$user, $sha256) in build_query and entity pipelines
    for q_exec in (
        self.router.build_query(
            target_metric="file_executions_total",
            entity_type=EntityType.USER,
            statistical_model=StatisticalModel.QUANTILE_IQR_SKEW,
        ),
        self.router.build_pipeline_query(
            pipeline_type=PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE,
            target_metric="file_executions_total",
            entity_type=EntityType.USER,
        ),
        self.router.build_longitudinal_cusum_series_query(
            target_metric="file_executions_total",
            entity_type=EntityType.USER,
        ),
    ):
      self.assertEqual([], MalachiteASTValidator.validate_query(q_exec))
      self.assertIn("principal.user.userid", q_exec)
      self.assertIn("principal.process.file.sha256: principal.process.file.sha256", q_exec)
      matches = self._extract_match_clauses(q_exec)
      self.assertIn("$sha256", matches[0])
      self.assertIn("$sha256", matches[-1])

    # 4. (resource_read_fail, EntityType.RESOURCE) failure-ratio surge preserves all 4 Malachite dimensions
    q_res_fail = self.router.build_failure_ratio_surge_query(
        fail_metric="resource_read_fail",
        entity_type=EntityType.RESOURCE,
    )
    self.assertEqual([], MalachiteASTValidator.validate_query(q_res_fail))
    self.assertIn("principal.user.userid: principal.user.userid", q_res_fail)
    self.assertIn("target.resource.name: target.resource.name", q_res_fail)

    # 5. Secondary EntityType.USER (identifier_field=None) in HTTP specialty pipelines rebinds to principal.user.userid
    for pipe in (
        PipelineArchitecture.HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE,
        PipelineArchitecture.HTTP_ERROR_RATIO_SURGE_2STAGE,
        PipelineArchitecture.HTTP_TARGET_SURGE_2STAGE,
    ):
      q_http_user = self.router.build_pipeline_query(
          pipeline_type=pipe,
          entity_type=EntityType.USER,
      )
      self.assertEqual([], MalachiteASTValidator.validate_query(q_http_user))
      self.assertIn("principal.user.userid", q_http_user)
      self.assertNotIn("principal.asset.hostname", q_http_user)

  def test_quantile_iqr_skew_mode_a_never_uses_1d_raw_search_window(self):
    """QUANTILE_IQR_SKEW Mode A guard: raw search window must span 30d while $in_scoring_window gates to D-1 (1d)."""
    ref_time = datetime.datetime(2026, 10, 17, 15, 30, 0, tzinfo=datetime.timezone.utc)
    for metric_name, entity_str in (
        ("dns_queries_total", "ASSET"),
        ("http_queries_total", "USER"),
        ("resource_read_total", "RESOURCE"),
    ):
      bundle = compile_hunt_pipeline(
          target_metric=metric_name,
          entity_type=entity_str,
          statistical_model="QUANTILE_IQR_SKEW",
          mode="A",
          reference_time=ref_time,
      )
      # Scored day is strictly the last complete UTC day D-1 (2026-10-16), NOT partial today
      self.assertEqual(bundle["evaluation_mode_label"], "Mode A: Last Complete UTC Day (2026-10-16)")
      self.assertFalse(bundle["is_partial_day"])

      # Raw udm_search window MUST span 30 calendar days [2026-09-17T00:00:00Z, 2026-10-17T00:00:00Z), NEVER 1d
      self.assertEqual(len(bundle["shards"]), 1)
      shard = bundle["shards"][0]
      self.assertEqual(shard["day"], "2026-10-16")
      self.assertEqual(shard["start_time"], "2026-09-17T00:00:00Z")
      self.assertEqual(shard["end_time"], "2026-10-17T00:00:00Z")
      self.assertEqual(bundle["start_time"], "2026-09-17T00:00:00Z")
      self.assertEqual(bundle["end_time"], "2026-10-17T00:00:00Z")
      raw_start = datetime.datetime.fromisoformat(shard["start_time"].replace("Z", "+00:00"))
      raw_end = datetime.datetime.fromisoformat(shard["end_time"].replace("Z", "+00:00"))
      self.assertEqual((raw_end - raw_start).days, 30)

      # Query AST is valid and pins $in_scoring_window = 1 to 2026-10-16 with raw_active_days >= 7
      q = shard["query"]
      self.assertEqual([], MalachiteASTValidator.validate_query(q))
      self.assertIn('"2026-10-16"', q)
      self.assertIn("$in_scoring_window = 1", q)
      self.assertIn("$raw_active_days >= 7", q)

  def test_relative_deviation_zero_avg_cliff_guard(self):
    """RELATIVE_DEVIATION guard: $safe_hist_avg floors smoothly at 1.0 with zero 100x discontinuity near avg=0."""
    for metric_name, entity_type in (
        ("http_queries_total", EntityType.USER),
        ("network_bytes_outbound", EntityType.ASSET),
    ):
      q = self.router.build_query(
          target_metric=metric_name,
          entity_type=entity_type,
          statistical_model=StatisticalModel.RELATIVE_DEVIATION,
      )
      self.assertEqual([], MalachiteASTValidator.validate_query(q))
      self.assertIn("$safe_hist_avg = if($hist_avg > 1.0, $hist_avg, 1.0)", q)
      self.assertNotIn("0.001", q)
      self.assertNotIn("if($hist_avg > 0,", q)

    def eval_relative_deviation(observed: float, hist_avg: float) -> tuple[float, float]:
      safe_hist_avg = hist_avg if hist_avg > 1.0 else 1.0
      rel_dev = (observed - safe_hist_avg) / safe_hist_avg
      fold_change = observed / safe_hist_avg
      return rel_dev, fold_change

    # Across [0.0, 1.0], safe_hist_avg is continuously pinned at 1.0 (no 500x/5000x spike at avg=0.01 or 0.001)
    for sub_unit_avg in (0.0, 0.001, 0.01, 0.1, 0.5, 1.0):
      rel_dev, fold_change = eval_relative_deviation(observed=5.0, hist_avg=sub_unit_avg)
      self.assertAlmostEqual(rel_dev, 4.0, places=12)
      self.assertAlmostEqual(fold_change, 5.0, places=12)

    # Monotonically decreasing as hist_avg grows above 1.0, continuous at hist_avg = 1.0
    _, fc_1 = eval_relative_deviation(5.0, 1.0)
    _, fc_1_eps = eval_relative_deviation(5.0, 1.0001)
    _, fc_2 = eval_relative_deviation(5.0, 2.0)
    self.assertAlmostEqual(fc_1, fc_1_eps, delta=1e-3)
    self.assertGreater(fc_1, fc_2)


if __name__ == "__main__":
  unittest.main()
