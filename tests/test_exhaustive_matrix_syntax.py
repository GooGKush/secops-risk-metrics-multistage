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


class ExhaustiveMatrixSyntaxTest(unittest.TestCase):
  """Fuzzes and validates syntax across all metric tables, math models, and match modes."""

  def setUp(self):
    self.skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    self.router = MultiStageTemplateRouter()

  def _assert_query_grammar_invariants(self, query: str, context: str):
    """Rigorous grammar invariant assertion helper."""
    # 1. Zero 'condition:' keyword in multi-stage search queries
    self.assertNotIn("condition:", query, f"[{context}] Search query must not contain 'condition:' block")

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
        StatisticalModel.VARIANCE,
        StatisticalModel.POISSON,
        StatisticalModel.COEFFICIENT_OF_VARIATION,
        StatisticalModel.BAYESIAN_GAMMA,
    ]
    match_modes = [MatchMode.TIMELINE_BREAKDOWN, MatchMode.FLEET_ROLLUP]

    tested_permutations = 0

    for metric_name, mdef in METRIC_CATALOG.items():
      # Only test metrics with extractor templates on disk
      stage1_file = os.path.join(self.skill_dir, "templates", "stage1_extractors", f"{metric_name}.yl2")
      if not os.path.exists(stage1_file):
        continue

      entity_type = mdef.supported_entity_types[0]

      for model in math_models:
        for mode in match_modes:
          context = f"Metric={metric_name}, Model={model.value}, Mode={mode.value}"
          query = self.router.build_query(
              target_metric=metric_name,
              entity_type=entity_type,
              statistical_model=model,
              anomaly_threshold=3.0,
              match_mode=mode,
          )
          self._assert_query_grammar_invariants(query, context)
          tested_permutations += 1

    self.assertGreater(tested_permutations, 50, f"Must test at least 50 permutations (tested: {tested_permutations})")

  def test_advanced_pipeline_templates_grammar(self):
    """Validates syntax and invariants across all advanced multi-stage pipeline templates."""
    pipelines = [
        PipelineArchitecture.MULTI_SECTOR_FUSION_4STAGE,
        PipelineArchitecture.DUAL_BASELINE_3STAGE,
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


if __name__ == '__main__':
  unittest.main()
