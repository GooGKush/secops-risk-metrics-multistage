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

from scripts import malachite_catalog as mc
from scripts.preflight_validator import (
    METRIC_CATALOG,
    EntityType,
    MalachiteASTValidator,
    MatchMode,
    PipelineArchitecture,
    PreFlightValidator,
    StatisticalModel,
)
from scripts.template_router import MultiStageTemplateRouter
from scripts.submission_tests import iter_if_calls, if_branch_has_compound_arithmetic


class ExhaustiveMatrixSyntaxTest(unittest.TestCase):
  """Fuzzes and validates syntax across all metric tables, entity types, math models, and match modes."""

  def setUp(self):
    self.skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    self.router = MultiStageTemplateRouter()

  @staticmethod
  def _strip_comments(query: str) -> str:
    return "\n".join(
        line.split("//", 1)[0]
        for line in query.splitlines()
        if not line.lstrip().startswith("//")
    )

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

  def _assert_valid_ast_and_entity_binding(
      self,
      query: str,
      context: str,
      expected_field: str = "",
  ):
    self._assert_query_grammar_invariants(query, context)
    ast_errors = MalachiteASTValidator.validate_query(query)
    self.assertEqual(
        [],
        ast_errors,
        f"[{context}] MalachiteASTValidator errors: {ast_errors}",
    )
    code_only = self._strip_comments(query)
    if expected_field:
      self.assertIn(
          expected_field,
          code_only,
          f"[{context}] Expected entity field '{expected_field}' missing from rendered query code",
      )
    match_clauses = re.findall(r'\bmatch:\s*\n\s*([^\n]+)', code_only)
    self.assertGreaterEqual(
        len(match_clauses),
        1,
        f"[{context}] Query must contain at least one match: clause",
    )
    root_match_vars = re.findall(r'\$[a-zA-Z0-9_]+', match_clauses[-1])
    self.assertGreaterEqual(
        len(root_match_vars),
        1,
        f"[{context}] Root match clause '{match_clauses[-1]}' must bind at least one $var",
    )

  def test_fuzz_all_38_metrics_across_all_math_models_and_modes(self):
    """WS0-01: Exhaustively validates all 38 metrics x ALL supported entity types x 15 models x 2 modes + secondary identifier leaves."""

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
        StatisticalModel.FIRST_SEEN_NOVELTY,
    ]
    retired_models_and_replacements = (
        (StatisticalModel.HOURLY_TEMPORAL_ZSCORE, r"retired.*HOUR_OF_DAY_PROFILE"),
        (StatisticalModel.CIRCADIAN_VON_MISES, r"retired.*HOUR_OF_DAY_PROFILE"),
        (StatisticalModel.PIECEWISE_CRI, r"retired.*calculate_cri"),
        (StatisticalModel.FLEET_PREVALENCE_SHIELD, r"retired.*hybrid_metric_fleet_prevalence_2stage"),
    )
    match_modes = [MatchMode.TIMELINE_BREAKDOWN, MatchMode.FLEET_ROLLUP]
    secondary_leaves_by_entity = {
        EntityType.ASSET: ("hostname", "ip", "asset_id", "mac", "product_object_id"),
        EntityType.USER: ("userid", "email_addresses", "windows_sid", "employee_id", "product_object_id"),
        EntityType.RESOURCE: (),
    }
    secondary_id_models = (
        StatisticalModel.STANDARD_Z_SCORE,
        StatisticalModel.MAD,
        StatisticalModel.QUANTILE_IQR_SKEW,
        StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD,
        StatisticalModel.FIRST_SEEN_NOVELTY,
    )

    tested_permutations = 0
    tested_secondary_id_permutations = 0
    tested_metric_entity_pairs = 0
    seen_entity_types = set()

    for metric_name, mdef in METRIC_CATALOG.items():
      stage1_file = os.path.join(self.skill_dir, "templates", "stage1_extractors", f"{metric_name}.yl2")
      self.assertTrue(os.path.exists(stage1_file), f"Missing Stage 1 extractor for {metric_name}")

      is_value_sum = mc.baseline_semantics(metric_name).metric_arg == "value_sum"
      is_paired_beta = (
          metric_name.endswith(("_fail", "_total", "_success"))
          and f"{metric_name.rsplit('_', 1)[0]}_fail" in METRIC_CATALOG
          and f"{metric_name.rsplit('_', 1)[0]}_total" in METRIC_CATALOG
      )

      # Iterate over ALL supported entity types (primary + secondary: ASSET, USER, RESOURCE)
      for entity_type in mdef.supported_entity_types:
        tested_metric_entity_pairs += 1
        seen_entity_types.add(entity_type)
        expected_field = PreFlightValidator.resolve_identifier_field(metric_name, entity_type, None)

        for retired_model, expected_regex in retired_models_and_replacements:
          with self.assertRaisesRegex(ValueError, expected_regex):
            self.router.build_query(
                target_metric=metric_name,
                entity_type=entity_type,
                statistical_model=retired_model,
                anomaly_threshold=3.0,
            )

        for model in math_models:
          for mode in match_modes:
            context = f"Metric={metric_name}, Entity={entity_type.value}, Model={model.value}, Mode={mode.value}"
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
            self._assert_valid_ast_and_entity_binding(query, context, expected_field=expected_field)
            tested_permutations += 1

        # Also validate all secondary identifier leaves for this (metric, entity_type) pair
        for id_leaf in secondary_leaves_by_entity[entity_type]:
          expected_leaf_field = PreFlightValidator.resolve_identifier_field(metric_name, entity_type, id_leaf)
          for model in secondary_id_models:
            for mode in match_modes:
              id_ctx = (
                  f"Metric={metric_name}, Entity={entity_type.value}, "
                  f"IdLeaf={id_leaf}, Model={model.value}, Mode={mode.value}"
              )
              query = self.router.build_query(
                  target_metric=metric_name,
                  entity_type=entity_type,
                  statistical_model=model,
                  anomaly_threshold=3.0,
                  match_mode=mode,
                  identifier_field=id_leaf,
              )
              self._assert_valid_ast_and_entity_binding(query, id_ctx, expected_field=expected_leaf_field)
              tested_secondary_id_permutations += 1

    total_supported_pairs = sum(len(m.supported_entity_types) for m in METRIC_CATALOG.values())
    self.assertEqual(total_supported_pairs, 72)
    self.assertEqual(tested_metric_entity_pairs, total_supported_pairs)
    self.assertEqual(seen_entity_types, {EntityType.ASSET, EntityType.USER, EntityType.RESOURCE})

    expected_permutations = total_supported_pairs * len(math_models) * len(match_modes)
    self.assertEqual(
        tested_permutations,
        expected_permutations,
        f"Must exhaustively test all {expected_permutations} core (metric, entity_type, model, mode) permutations (tested: {tested_permutations})",
    )

    expected_secondary_id = (
        sum(
            len(secondary_leaves_by_entity[et])
            for m in METRIC_CATALOG.values()
            for et in m.supported_entity_types
        )
        * len(secondary_id_models)
        * len(match_modes)
    )
    self.assertEqual(tested_secondary_id_permutations, expected_secondary_id)
    self.assertEqual(tested_secondary_id_permutations, 2850)

  def test_advanced_pipeline_templates_grammar(self):
    """WS0-01: Validates AST, grammar, and entity bindings across active pipelines on primary + secondary entity types."""
    # 1. Single-metric longitudinal pipelines across ALL 72 (metric, entity_type) pairs
    for metric_name, mdef in METRIC_CATALOG.items():
      for entity_type in mdef.supported_entity_types:
        expected_field = PreFlightValidator.resolve_identifier_field(metric_name, entity_type, None)

        q_macd = self.router.build_pipeline_query(
            pipeline_type=PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE,
            target_metric=metric_name,
            entity_type=entity_type,
            anomaly_threshold=3.0,
        )
        self._assert_valid_ast_and_entity_binding(
            q_macd,
            f"MACD_2STAGE:{metric_name}:{entity_type.value}",
            expected_field=expected_field,
        )

        q_cusum_2 = self.router.build_longitudinal_cusum_pipeline_query(
            target_metric=metric_name,
            entity_type=entity_type,
            cusum_h_threshold=4.0,
        )
        self._assert_valid_ast_and_entity_binding(
            q_cusum_2,
            f"CUSUM_2STAGE:{metric_name}:{entity_type.value}",
            expected_field=expected_field,
        )

        q_cusum_3 = self.router.build_longitudinal_cusum_series_query(
            target_metric=metric_name,
            entity_type=entity_type,
            cusum_h_threshold=4.0,
        )
        self._assert_valid_ast_and_entity_binding(
            q_cusum_3,
            f"CUSUM_SERIES_3STAGE:{metric_name}:{entity_type.value}",
            expected_field=expected_field,
        )

    # 2. First-seen novelty 2-stage pipeline across ASSET, USER, and RESOURCE (entity-keyed + composite)
    novelty_cases = [
        ("http_queries_total", EntityType.ASSET, None),
        ("http_queries_total", EntityType.USER, None),
        ("http_queries_total", EntityType.USER, "email_addresses"),
        ("auth_attempts_total", EntityType.USER, None),
        ("auth_attempts_total", EntityType.ASSET, None),
        ("dns_queries_total", EntityType.ASSET, "ip"),
        ("resource_read_total", EntityType.USER, None),
        ("resource_read_total", EntityType.USER, "email_addresses"),
        ("resource_read_total", EntityType.RESOURCE, None),
        ("file_executions_total", EntityType.ASSET, None),
        ("file_executions_total", EntityType.USER, None),
    ]
    for metric_name, entity_type, id_leaf in novelty_cases:
      expected_field = PreFlightValidator.resolve_identifier_field(metric_name, entity_type, id_leaf)
      q_nov = self.router.build_pipeline_query(
          pipeline_type=PipelineArchitecture.FIRST_SEEN_NOVELTY_2STAGE,
          target_metric=metric_name,
          entity_type=entity_type,
          identifier_field=id_leaf,
      )
      self._assert_valid_ast_and_entity_binding(
          q_nov,
          f"FIRST_SEEN_NOVELTY_2STAGE:{metric_name}:{entity_type.value}:{id_leaf}",
          expected_field=expected_field,
      )

    # 3. Fleet Dual-Baseline & Hierarchical Empirical Bayes across ASSET and USER
    for ptype in (PipelineArchitecture.DUAL_BASELINE_3STAGE, PipelineArchitecture.EMPIRICAL_BAYES_3STAGE):
      for metric_name, entity_type, id_leaf in (
          ("http_queries_total", EntityType.ASSET, None),
          ("http_queries_total", EntityType.USER, None),
          ("http_queries_total", EntityType.USER, "email_addresses"),
          ("auth_attempts_total", EntityType.USER, None),
          ("auth_attempts_total", EntityType.ASSET, "ip"),
      ):
        expected_field = PreFlightValidator.resolve_identifier_field(metric_name, entity_type, id_leaf)
        q_fleet = self.router.build_pipeline_query(
            pipeline_type=ptype,
            target_metric=metric_name,
            entity_type=entity_type,
            identifier_field=id_leaf,
            anomaly_threshold=3.0,
        )
        self._assert_valid_ast_and_entity_binding(
            q_fleet,
            f"{ptype.value}:{metric_name}:{entity_type.value}:{id_leaf}",
            expected_field=expected_field,
        )

    # 4. Multi-Sector & Dual-Sector Fusion across ASSET and USER
    for entity_type, metrics_pair in (
        (EntityType.ASSET, ["http_queries_total", "network_bytes_outbound"]),
        (EntityType.USER, ["auth_attempts_total", "workspace_total_download_actions"]),
    ):
      q_ms = self.router.build_pipeline_query(
          pipeline_type=PipelineArchitecture.MULTI_SECTOR_FUSION_4STAGE,
          entity_type=entity_type,
          target_metrics=metrics_pair,
      )
      self._assert_valid_ast_and_entity_binding(q_ms, f"MULTI_SECTOR_FUSION_4STAGE:{entity_type.value}")

    for entity_type, metrics_2 in (
        (EntityType.ASSET, ["file_executions_total", "network_bytes_outbound"]),
        (EntityType.USER, ["file_executions_total", "auth_attempts_total"]),
    ):
      q_ds = self.router.build_pipeline_query(
          pipeline_type=PipelineArchitecture.DUAL_SECTOR_FUSION_3STAGE,
          entity_type=entity_type,
          target_metrics=metrics_2,
      )
      self._assert_valid_ast_and_entity_binding(q_ds, f"DUAL_SECTOR_FUSION_3STAGE:{entity_type.value}")

    # 5. Failure-ratio surge & HTTP specialty pipelines across ASSET, USER, and RESOURCE
    fail_metrics = (
        "http_queries_fail",
        "dns_queries_fail",
        "auth_attempts_fail",
        "file_executions_fail",
        "resource_read_fail",
        "resource_written_fail",
        "resource_creation_fail",
        "resource_deletion_fail",
    )
    for fail_m in fail_metrics:
      for entity_type in METRIC_CATALOG[fail_m].supported_entity_types:
        expected_field = PreFlightValidator.resolve_identifier_field(fail_m, entity_type, None)
        q_fail = self.router.build_pipeline_query(
            pipeline_type=PipelineArchitecture.HTTP_ERROR_RATIO_SURGE_2STAGE,
            target_metric=fail_m,
            entity_type=entity_type,
        )
        self._assert_valid_ast_and_entity_binding(
            q_fail,
            f"HTTP_ERROR_RATIO_SURGE_2STAGE:{fail_m}:{entity_type.value}",
            expected_field=expected_field,
        )

    for entity_type, exp_field in (
        (EntityType.ASSET, "principal.asset.hostname"),
        (EntityType.USER, "principal.user.userid"),
    ):
      q_default_err = self.router.build_pipeline_query(
          pipeline_type=PipelineArchitecture.HTTP_ERROR_RATIO_SURGE_2STAGE,
          entity_type=entity_type,
      )
      self._assert_valid_ast_and_entity_binding(
          q_default_err,
          f"HTTP_ERROR_RATIO_SURGE_2STAGE:default:{entity_type.value}",
          expected_field=exp_field,
      )
      q_ua = self.router.build_pipeline_query(
          pipeline_type=PipelineArchitecture.HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE,
          entity_type=entity_type,
      )
      self._assert_valid_ast_and_entity_binding(
          q_ua,
          f"HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE:{entity_type.value}",
          expected_field=exp_field,
      )

    with self.assertRaises(ValueError):
      self.router.build_pipeline_query(
          pipeline_type=PipelineArchitecture.HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE,
          entity_type=EntityType.RESOURCE,
      )

    for entity_type, exp_field in (
        (EntityType.ASSET, "principal.asset.hostname"),
        (EntityType.USER, "principal.user.userid"),
        (EntityType.RESOURCE, "target.hostname"),
    ):
      q_tgt = self.router.build_pipeline_query(
          pipeline_type=PipelineArchitecture.HTTP_TARGET_SURGE_2STAGE,
          entity_type=entity_type,
      )
      self._assert_valid_ast_and_entity_binding(
          q_tgt,
          f"HTTP_TARGET_SURGE_2STAGE:{entity_type.value}",
          expected_field=exp_field,
      )

    # 6. Cloud Repository Scope Dual-Branch across all 5 USER identifier leaves
    for id_leaf in ("userid", "email_addresses", "windows_sid", "employee_id", "product_object_id"):
      exp_user_field = PreFlightValidator.resolve_identifier_field("resource_read_total", EntityType.USER, id_leaf)
      q_cloud = self.router.build_pipeline_query(
          pipeline_type=PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH,
          target_metric="resource_read_total",
          entity_type=EntityType.USER,
          identifier_field=id_leaf,
      )
      self._assert_valid_ast_and_entity_binding(
          q_cloud,
          f"CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH:{id_leaf}",
          expected_field=exp_user_field,
      )

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
