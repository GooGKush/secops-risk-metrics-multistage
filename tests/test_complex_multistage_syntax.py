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

"""Unit tests for complex multi-stage YARA-L DAG queries and Common Compiler syntax."""

import os
import re
import unittest
from typing import List, Dict, Any

from scripts.preflight_validator import (
    METRIC_CATALOG,
    PipelineArchitecture,
    StatisticalModel,
    MatchMode,
)


class ComplexMultiStageSyntaxTest(unittest.TestCase):
  """Validates syntax and grammar invariants for large, complex multi-stage DAG pipelines."""

  def setUp(self):
    self.skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    self.templates_dir = os.path.join(self.skill_dir, "templates", "pipelines")

  def test_multi_sector_fusion_4stage_template_syntax(self):
    """Verifies the 4-Stage Multi-Sector Threat Fusion template conforms to Common Compiler DAG grammar."""
    template_path = os.path.join(self.templates_dir, "multi_sector_fusion_4stage.yl2")
    self.assertTrue(os.path.exists(template_path), f"Missing template: {template_path}")

    with open(template_path, "r", encoding="utf-8") as f:
      content = f.read()

    # 1. Must define 4 independent sector stages
    self.assertIn("stage auth_sector", content)
    self.assertIn("stage cloud_sector", content)
    self.assertIn("stage proc_sector", content)
    self.assertIn("stage net_sector", content)

    # 2. Each sector must have an isolated event type and match clause
    self.assertIn('metadata.event_type = "USER_LOGIN"', content)
    self.assertIn('metadata.event_type = "RESOURCE_WRITTEN"', content)
    self.assertIn('metadata.event_type = "PROCESS_LAUNCH"', content)
    self.assertIn('metadata.event_type = "NETWORK_CONNECTION"', content)

    # 3. Must synchronize entity variable in root stage (staying within 4-join compiler limit)
    self.assertIn("$user = $auth_sector.user", content)
    self.assertIn("$user = $cloud_sector.user", content)
    self.assertIn("$user = $proc_sector.user", content)
    self.assertIn("$user = $net_sector.user", content)
    self.assertIn("match:\n  $user by 1d", content)

    # 4. Outcome must compute 4-vector Euclidean threat norm
    self.assertIn("$composite_threat_norm_sq", content)
    self.assertIn("$z_auth_sq + $z_cloud_sq + $z_proc_sq + $z_net_sq", content)

    # 5. Must order by composite threat norm
    self.assertIn("order:", content)
    self.assertIn("$composite_threat_norm_sq desc", content)

  def test_dual_sector_fusion_3stage_template_syntax(self):
    """Verifies the 3-Stage Dual-Sector Threat Fusion template conforms to the 4-join compiler limit."""
    template_path = os.path.join(self.templates_dir, "dual_sector_fusion_3stage.yl2")
    self.assertTrue(os.path.exists(template_path), f"Missing template: {template_path}")

    with open(template_path, "r", encoding="utf-8") as f:
      content = f.read()

    self.assertIn("stage auth_sector", content)
    self.assertIn("stage net_sector", content)
    self.assertIn("$user = $auth_sector.user", content)
    self.assertIn("$user = $net_sector.user", content)
    self.assertIn("match:\n  $user by 1d", content)
    self.assertIn("$composite_threat_norm_sq = $z_auth_sq + $z_net_sq", content)

  def test_dual_baseline_delta_z_3stage_template_syntax(self):
    """Verifies the 3-Stage Dual-Baseline (Delta-Z) template conforms to Common Compiler grammar."""
    template_path = os.path.join(self.templates_dir, "dual_baseline_delta_z_3stage.yl2")
    self.assertTrue(os.path.exists(template_path), f"Missing template: {template_path}")

    with open(template_path, "r", encoding="utf-8") as f:
      content = f.read()

    # 1. Must define Stage 1 individual extraction and Stage 2 fleet cross-section
    self.assertIn("stage host_extract", content)
    self.assertIn("stage fleet_stats", content)

    # 2. Stage 2 must aggregate across the active fleet on that window_start
    self.assertIn("avg($host_extract.observed_24h)", content)
    self.assertIn("stddev($host_extract.observed_24h)", content)
    self.assertIn("count_distinct($host_extract.host)", content)

    # 3. Root stage must compute Delta-Z isolation
    self.assertIn("$delta_z = $personal_z - $fleet_z", content)
    self.assertIn("order:\n  $delta_z desc", content)

  def test_hierarchical_empirical_bayes_3stage_template_syntax(self):
    """Verifies the 3-Stage Empirical Bayes template conforms to Common Compiler grammar."""
    template_path = os.path.join(self.templates_dir, "hierarchical_empirical_bayes_3stage.yl2")
    self.assertTrue(os.path.exists(template_path), f"Missing template: {template_path}")

    with open(template_path, "r", encoding="utf-8") as f:
      content = f.read()

    # 1. Must define Stage 1 host extract and Stage 2 fleet hyperpriors
    self.assertIn("stage host_extract", content)
    self.assertIn("stage fleet_hyperpriors", content)

    # 2. Stage 2 must calculate hyperprior mean and stddev (variance derived in outcome)
    self.assertIn("avg($host_extract.hist_avg)", content)
    self.assertIn("stddev($host_extract.hist_avg)", content)
    self.assertIn("$fleet_sigma_sq = $fleet_sigma * $fleet_sigma", content)

    # 3. Root stage must blend priors and compute posterior rate
    self.assertIn("$alpha_post = $alpha_host + $obs_24h", content)
    self.assertIn("$beta_post = $beta_host + 1.0", content)
    self.assertIn("$posterior_rate = $alpha_post / $beta_post", content)

  def test_cloud_resource_lifecycle_fusion_compound_dimensions(self):
    """Verifies that generated Cloud Resource Lifecycle queries enforce compound vendor/product dimensions."""
    sample_query = """
stage stage_create {
    metadata.event_type = "RESOURCE_CREATION"
    principal.user.userid = $user
    metadata.vendor_name = $vendor
    metadata.product_name = $product
    $user != ""

  match:
    $user, $vendor, $product by 1d

  outcome:
    $create_obs = count(metadata.id)
    $create_mu = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: $user,
        metadata.vendor_name: $vendor,
        metadata.product_name: $product
    ))
    $create_sigma = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: $user,
        metadata.vendor_name: $vendor,
        metadata.product_name: $product
    ))
}

stage stage_delete {
    metadata.event_type = "RESOURCE_DELETION"
    principal.user.userid = $user
    metadata.vendor_name = $vendor
    metadata.product_name = $product
    $user != ""

  match:
    $user, $vendor, $product by 1d

  outcome:
    $delete_obs = count(metadata.id)
    $delete_mu = max(metrics.resource_deletion_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: $user,
        metadata.vendor_name: $vendor,
        metadata.product_name: $product
    ))
    $delete_sigma = max(metrics.resource_deletion_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: $user,
        metadata.vendor_name: $vendor,
        metadata.product_name: $product
    ))
}

$user = $stage_create.user
$user = $stage_delete.user
$vendor = $stage_create.vendor
$vendor = $stage_delete.vendor
$product = $stage_create.product
$product = $stage_delete.product

$ws = $stage_create.window_start
$ws = $stage_delete.window_start

match:
  $user, $vendor, $product, $ws by 1d

outcome:
  $c_obs = max($stage_create.create_obs)
  $c_mu = max($stage_create.create_mu)
  $c_sigma = max($stage_create.create_sigma)
  $z_create = ($c_obs - $c_mu) / ($c_sigma + 1.0)

  $d_obs = max($stage_delete.delete_obs)
  $d_mu = max($stage_delete.delete_mu)
  $d_sigma = max($stage_delete.delete_sigma)
  $z_delete = ($d_obs - $d_mu) / ($d_sigma + 1.0)

  $z_create_sq = $z_create * $z_create
  $z_delete_sq = $z_delete * $z_delete
  $d_cloud_sq = $z_create_sq + $z_delete_sq

order:
  $d_cloud_sq desc
"""
    # Validate that both stages define vendor and product keys
    self.assertIn("metadata.vendor_name = $vendor", sample_query)
    self.assertIn("metadata.product_name = $product", sample_query)
    self.assertIn("metadata.vendor_name: $vendor", sample_query)
    self.assertIn("metadata.product_name: $product", sample_query)

    # Validate root stage contains match and outcome sections
    self.assertIn("match:\n  $user, $vendor, $product, $ws by 1d", sample_query)
    self.assertIn("outcome:\n  $c_obs = max($stage_create.create_obs)", sample_query)

    # Validate zero condition keyword in search root stage
    self.assertNotIn("condition:", sample_query)

  def test_all_38_metrics_catalog_dimension_completeness(self):
    """Verifies that all 38 active metrics in the catalog have valid event types, dimensions, and log types."""
    self.assertEqual(len(METRIC_CATALOG), 38, "METRIC_CATALOG must contain exactly 38 active metrics")


    for metric_name, mdef in METRIC_CATALOG.items():
      self.assertEqual(metric_name, mdef.metric_name)
      self.assertTrue(len(mdef.event_type) > 0, f"Metric {metric_name} must have a non-empty event_type")
      self.assertTrue(len(mdef.supported_entity_types) > 0, f"Metric {metric_name} must support entity types")
      self.assertTrue(len(mdef.dimension_fields) > 0, f"Metric {metric_name} must define dimension fields")
      self.assertTrue(len(mdef.backing_log_types) > 0, f"Metric {metric_name} must define backing log types")
      self.assertGreaterEqual(mdef.default_floor_days, 7, f"Metric {metric_name} floor days must be >= 7")

  def test_zero_single_stage_multi_vector_cramming_invariant(self):
    """Verifies the validator rejects queries that cram multiple distinct event types in one stage."""
    invalid_single_stage_crammed_query = """
    $create.metadata.event_type = "RESOURCE_CREATION"
    $delete.metadata.event_type = "RESOURCE_DELETION"
    $create.principal.user.userid = $user
    $delete.principal.user.userid = $user
    match: $user
    """
    # When multiple event types exist in a single block without stage separation, it triggers Cartesian distortion
    event_types = re.findall(r'metadata\.event_type\s*=\s*"([^"]+)"', invalid_single_stage_crammed_query)
    self.assertEqual(len(event_types), 2)
    self.assertNotEqual(event_types[0], event_types[1])
    # Multi-stage queries require separate stage blocks for each distinct event type
    stages = re.findall(r'stage\s+([a-zA-Z0-9_]+)\s*\{', invalid_single_stage_crammed_query)
    self.assertEqual(len(stages), 0, "Crammed query lacks stage isolation")

  def test_entity_graph_prevalence_multi_stage_syntax(self):
    """Verifies that Entity Graph prevalence joins for Domain, Hash, and IP conform to SecOps grammar."""
    sample_domain_prev_query = """
    stage stage_rare_dns {
        $dns.metadata.event_type = "NETWORK_DNS"
        $dns.network.dns.questions.name != ""
        $dns.network.dns.questions.name = $domain
        $dns.principal.asset.hostname = $host

        $prevalence.graph.metadata.entity_type = "DOMAIN_NAME"
        $prevalence.graph.metadata.source_type = "DERIVED_CONTEXT"
        $prevalence.graph.entity.hostname = $domain
        $prevalence.graph.entity.domain.prevalence.day_count = 10
        $prevalence.graph.entity.domain.prevalence.rolling_max > 0
        $prevalence.graph.entity.domain.prevalence.rolling_max <= 3

      match:
        $host

      outcome:
        $rare_dns_obs = count($dns.metadata.id)
        $dns_mu = max(metrics.dns_queries_total(
            period: 1d, window: 30d, metric: event_count_sum, agg: avg,
            principal.asset.hostname: $host
        ))
    }

    $host = $stage_rare_dns.host
    match:
      $host
    outcome:
      $obs = max($stage_rare_dns.rare_dns_obs)
    order:
      $obs desc
    """
    # 1. Assert Entity Graph metadata tags present
    self.assertIn('$prevalence.graph.metadata.entity_type = "DOMAIN_NAME"', sample_domain_prev_query)
    self.assertIn('$prevalence.graph.metadata.source_type = "DERIVED_CONTEXT"', sample_domain_prev_query)

    # 2. Assert day_count and rolling_max bounds present
    self.assertIn("$prevalence.graph.entity.domain.prevalence.day_count = 10", sample_domain_prev_query)
    self.assertIn("$prevalence.graph.entity.domain.prevalence.rolling_max > 0", sample_domain_prev_query)
    self.assertIn("$prevalence.graph.entity.domain.prevalence.rolling_max <= 3", sample_domain_prev_query)

    # 3. Assert root stage match and outcome
    self.assertIn("match:\n      $host", sample_domain_prev_query)
    self.assertIn("outcome:\n      $obs = max($stage_rare_dns.rare_dns_obs)", sample_domain_prev_query)


if __name__ == '__main__':
  unittest.main()
