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

"""Exhaustive matrix syntax fuzzer and validator for all YARA-L 2.0 permutations."""

import os
import re
import unittest
from typing import List, Dict, Any

from scripts.preflight_validator import (
    METRIC_CATALOG,
    EntityType,
    MatchMode,
    PipelineArchitecture,
    StatisticalModel,
)
from scripts.template_router import MultiStageTemplateRouter
from scripts.submission_tests import iter_if_calls, if_branch_has_compound_arithmetic


class ExhaustiveMatrixSyntaxTest(unittest.TestCase):
  """Fuzzes and validates syntax across all metric tables, math models, and match modes."""

  def setUp(self):
    self.skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    self.router = MultiStageTemplateRouter()

  def _assert_query_grammar_invariants(self, query: str, context: str):
    # 1. Compiler-compliant if(...) in outcome expressions (no compound then-clause, required else-clause)
    for call_text, args in iter_if_calls(query):
      self.assertGreaterEqual(len(args), 3, f"[{context}] if(...) missing required else-clause: {call_text}")
      self.assertFalse(if_branch_has_compound_arithmetic(args[1]), f"[{context}] if(...) has compound arithmetic in then-clause: {call_text}")
      self.assertFalse(if_branch_has_compound_arithmetic(args[2]), f"[{context}] if(...) has compound arithmetic in else-clause: {call_text}")

    # 2. Zero dummy placeholders ($day_bucket, $hour_bucket) before 'by'
    self.assertNotIn("$day_bucket", query, f"[{context}] Must not contain $day_bucket dummy variable")
    self.assertNotIn("$hour_bucket", query, f"[{context}] Must not contain $hour_bucket dummy variable")

    # 3. Valid stage names (no $ prefix on stage identifiers)
    stage_declarations = re.findall(r'stage\s+([^\s\{]+)\s*\{', query)
    for sname in stage_declarations:
      self.assertFalse(sname.startswith("$"), f"[{context}] Stage name '{sname}' must not have '$' prefix")

    # 4. Mandatory Root Stage match and outcome sections
    if len(stage_declarations) > 0:
      # Must contain a root match and outcome section
      self.assertIn("match:", query, f"[{context}] Multi-stage query must contain match section")
      self.assertIn("outcome:", query, f"[{context}] Multi-stage query must contain outcome section")

    # 5. Outcome variable ceiling (SecOps limit: <= 20 outcome variables per stage)
    outcome_blocks = re.findall(r'outcome:\s*\n((?:[ \t]*\$[^\n]+\n|[ \t]*//[^\n]*\n|\s*\n)*)', query)
    for idx, oblock in enumerate(outcome_blocks):
      vars_in_outcome = re.findall(r'^\s*(\$[a-zA-Z0-9_]+)\s*=', oblock, re.MULTILINE)
      self.assertLessEqual(
          len(vars_in_outcome), 20,
          f"[{context}] Outcome block {idx} exceeds SecOps limit of 20 variables ({len(vars_in_outcome)})"
      )

  def test_fuzz_all_38_metrics_across_all_math_models_and_modes(self):
    """Permutation test: Fuzzes all 38 active metrics across math models and match modes."""

    math_models = [
        StatisticalModel.STANDARD_Z_SCORE,
        StatisticalModel.MAD,
        StatisticalModel.QUANTILE_IQR_SKEW,
        StatisticalModel.RELATIVE_DEVIATION,
        StatisticalModel.VARIANCE,
        StatisticalModel.POISSON,
        StatisticalModel.COEFFICIENT_OF_VARIATION,
        StatisticalModel.BAYESIAN_GAMMA,
        StatisticalModel.BAYESIAN_BETA_BINOMIAL,
        StatisticalModel.LONGITUDINAL_CUSUM,
        StatisticalModel.TWO_PART_HURDLE,
        StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z,
        StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD,
        StatisticalModel.MACD_MOMENTUM_VELOCITY,
    ]
    retired_models_and_replacements = (
        (StatisticalModel.HOURLY_TEMPORAL_ZSCORE, r"retired.*HOUR_OF_DAY_PROFILE"),
        (StatisticalModel.CIRCADIAN_VON_MISES, r"retired.*HOUR_OF_DAY_PROFILE"),
        (StatisticalModel.PIECEWISE_CRI, r"retired.*calculate_cri"),
        (StatisticalModel.FLEET_PREVALENCE_SHIELD, r"retired.*hybrid_metric_fleet_prevalence_2stage"),
    )
    match_modes = [MatchMode.TIMELINE_BREAKDOWN, MatchMode.FLEET_ROLLUP]

    tested_permutations = 0

    for metric_name, mdef in METRIC_CATALOG.items():
      # Only test metrics with extractor templates on disk
      stage1_file = os.path.join(self.skill_dir, "templates", "stage1_extractors", f"{metric_name}.yl2")
      if not os.path.exists(stage1_file):
        continue

      entity_type = mdef.supported_entity_types[0]

      for retired_model, expected_regex in retired_models_and_replacements:
        with self.assertRaisesRegex(ValueError, expected_regex):
          self.router.build_query(
              target_metric=metric_name,
              entity_type=entity_type,
              statistical_model=retired_model,
              anomaly_threshold=3.0,
          )

      from scripts import malachite_catalog as mc
      is_value_sum = mc.baseline_semantics(metric_name).metric_arg == "value_sum"
      is_paired_beta = (
          metric_name.endswith(("_fail", "_total", "_success"))
          and f"{metric_name.rsplit('_', 1)[0]}_fail" in METRIC_CATALOG
          and f"{metric_name.rsplit('_', 1)[0]}_total" in METRIC_CATALOG
      )
      for model in math_models:
        for mode in match_modes:
          context = f"Metric={metric_name}, Model={model.value}, Mode={mode.value}"
          if model == StatisticalModel.POISSON and is_value_sum:
            with self.assertRaisesRegex(ValueError, r"POISSON.*event_count_sum|value_sum|byte"):
              self.router.build_query(
                  target_metric=metric_name,
                  entity_type=entity_type,
                  statistical_model=model,
                  anomaly_threshold=3.0,
                  match_mode=mode,
              )
            tested_permutations += 1
            continue
          if model == StatisticalModel.BAYESIAN_BETA_BINOMIAL and not is_paired_beta:
            with self.assertRaisesRegex(ValueError, r"BAYESIAN_BETA_BINOMIAL.*paired|unpaired|_fail"):
              self.router.build_query(
                  target_metric=metric_name,
                  entity_type=entity_type,
                  statistical_model=model,
                  anomaly_threshold=3.0,
                  match_mode=mode,
              )
            tested_permutations += 1
            continue
          query = self.router.build_query(
              target_metric=metric_name,
              entity_type=entity_type,
              statistical_model=model,
              anomaly_threshold=3.0,
              match_mode=mode,
          )
          self._assert_query_grammar_invariants(query, context)
          tested_permutations += 1

    expected_permutations = len(METRIC_CATALOG) * len(math_models) * len(match_modes)
    self.assertEqual(
        tested_permutations,
        expected_permutations,
        f"Must exhaustively test all {expected_permutations} permutations (tested: {tested_permutations})"
    )

  def test_advanced_pipeline_templates_grammar(self):
    """Validates syntax and invariants across active advanced multi-stage pipelines and rejects retired ones."""
    pipelines = [
        PipelineArchitecture.MULTI_SECTOR_FUSION_4STAGE,
        PipelineArchitecture.DUAL_BASELINE_3STAGE,
        PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE,
    ]
    for ptype in pipelines:
      context = f"Pipeline={ptype.value}"
      query = self.router.build_pipeline_query(
          pipeline_type=ptype,
          target_metric="http_queries_total",
          entity_type=EntityType.ASSET,
          anomaly_threshold=3.0,
      )
      self._assert_query_grammar_invariants(query, context)

    # WS2-02 & WS4-D1 (D1): Retired pipeline enum aliases retained for backward compat but rejected at render time.
    self.assertTrue(hasattr(PipelineArchitecture, "CIRCADIAN_VON_MISES"))
    for retired_pipe in (PipelineArchitecture.CIRCADIAN_VON_MISES_2STAGE, getattr(PipelineArchitecture, "CIRCADIAN_VON_MISES")):
      with self.assertRaisesRegex(ValueError, r"retired.*HOUR_OF_DAY_PROFILE"):
        self.router.build_pipeline_query(
            pipeline_type=retired_pipe,
            target_metric="http_queries_total",
            entity_type=EntityType.ASSET,
        )
    with self.assertRaisesRegex(ValueError, r"retired \(D1\)"):
      self.router.build_pipeline_query(
          pipeline_type=PipelineArchitecture.HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE,
          target_metric="network_bytes_outbound",
          entity_type=EntityType.ASSET,
      )


if __name__ == '__main__':
  unittest.main()
