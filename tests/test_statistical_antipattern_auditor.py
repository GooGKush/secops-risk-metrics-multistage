#!/usr/bin/env python3
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

"""Unit tests for StatisticalAntipatternAuditor.

Validates that the 5 core statistical antipatterns are accurately caught,
while all 20 canonical submission test cases pass with zero statistical violations.
"""

from pathlib import Path
import sys
import unittest

# Ensure skill root is in path
SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT))

from scripts.statistical_validator import (
    StatisticalAntipatternAuditor,
    StatisticalAntipatternType,
)
from scripts.submission_tests import SubmissionTestSuite


class TestStatisticalAntipatternAuditor(unittest.TestCase):
  """Tests static AST statistical antipattern detection."""

  @classmethod
  def setUpClass(cls):
    cls.suite = SubmissionTestSuite(SKILL_ROOT)
    cls.matrix = cls.suite.build_canonical_test_matrix()

  def test_all_canonical_cases_have_zero_statistical_antipatterns(self):
    """Asserts that all 20 canonical test cases pass with 0 statistical antipatterns."""
    for tc in self.matrix:
      with self.subTest(test_id=tc.test_id, name=tc.name):
        query = tc.render()
        violations = StatisticalAntipatternAuditor.audit_query(query)
        self.assertEqual(
            violations,
            [],
            f"Canonical test case {tc.test_id} triggered unexpected statistical violation: {violations}",
        )

  def test_catches_scope_asymmetry_part_of_the_whole(self):
    """Detects filtering observed events narrower than the metric baseline indexing dimensions."""
    bad_query = """
    stage s1 {
      metadata.event_type = "RESOURCE_READ"
      metadata.product_name = "BigQuery"
      $user = principal.user.userid
      match: $user by 1d
      outcome:
        $obs = count(metadata.id)
        $mu = max(metrics.resource_read_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: $user, metadata.vendor_name: "Google Cloud Platform"))
    }
    $user = $s1.user
    match: $user by 1d
    outcome:
      $z = 2.0
    """
    violations = StatisticalAntipatternAuditor.audit_query(bad_query)
    self.assertTrue(
        any(v.antipattern == StatisticalAntipatternType.SCOPE_ASYMMETRY for v in violations),
        f"Expected SCOPE_ASYMMETRY, got {violations}",
    )

  def test_catches_scope_asymmetry_with_external_context(self):
    """Detects evaluating metrics inside a stage that filters on GLOBAL_CONTEXT."""
    bad_query = """
    stage s1 {
      metadata.event_type = "NETWORK_CONNECTION"
      $user = principal.user.userid
      $ioc.graph.metadata.entity_type = "GLOBAL_CONTEXT"
      match: $user by 1d
      outcome:
        $obs = count(metadata.id)
        $mu = max(metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: avg, principal.user.userid: $user))
    }
    $user = $s1.user
    match: $user by 1d
    outcome:
      $z = 2.0
    """
    violations = StatisticalAntipatternAuditor.audit_query(bad_query)
    self.assertTrue(
        any(v.antipattern == StatisticalAntipatternType.SCOPE_ASYMMETRY for v in violations),
        f"Expected SCOPE_ASYMMETRY for GLOBAL_CONTEXT, got {violations}",
    )

  def test_catches_dynamic_range_masking(self):
    """Detects multi-resource access evaluated without local-baseline resource isolation."""
    bad_query = """
    stage s1 {
      metadata.event_type = "RESOURCE_READ"
      $user = principal.user.userid
      $resource = target.resource.name
      $v = metadata.vendor_name
      $p = metadata.product_name
      match: $user, $v, $p by 1d
      outcome:
        $obs = count(metadata.id)
        $mu = max(metrics.resource_read_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: $user, metadata.vendor_name: $v, metadata.product_name: $p))
    }
    $user = $s1.user
    match: $user by 1d
    outcome:
      $z = 2.0
    """
    violations = StatisticalAntipatternAuditor.audit_query(bad_query)
    self.assertTrue(
        any(v.antipattern == StatisticalAntipatternType.DYNAMIC_RANGE_MASKING for v in violations),
        f"Expected DYNAMIC_RANGE_MASKING, got {violations}",
    )

  def test_catches_dynamic_range_masking_without_resource_declaration(self):
    """Detects multi-resource access evaluated under an account when resource variable is not even declared."""
    bad_query = """
    stage s1 {
      metadata.event_type = "RESOURCE_READ"
      $user = principal.user.userid
      $v = metadata.vendor_name
      $p = metadata.product_name
      match: $user, $v, $p by 1d
      outcome:
        $obs = count(metadata.id)
        $mu = max(metrics.resource_read_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: $user, metadata.vendor_name: $v, metadata.product_name: $p))
    }
    $user = $s1.user
    match: $user by 1d
    outcome:
      $z = 2.0
    """
    violations = StatisticalAntipatternAuditor.audit_query(bad_query)
    self.assertTrue(
        any(v.antipattern == StatisticalAntipatternType.DYNAMIC_RANGE_MASKING for v in violations),
        f"Expected DYNAMIC_RANGE_MASKING, got {violations}",
    )

  def test_catches_zero_dispersion_hazard(self):
    """Detects division by standard deviation without an additive dispersion floor."""
    bad_query = """
    stage s1 {
      metadata.event_type = "USER_LOGIN"
      $user = target.user.userid
      match: $user by 1d
      outcome:
        $obs = count(metadata.id)
        $mu = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: $user))
        $sigma = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: $user))
        $z_score = ($obs - $mu) / $sigma
    }
    $user = $s1.user
    match: $user by 1d
    outcome:
      $z = max($s1.z_score)
    """
    violations = StatisticalAntipatternAuditor.audit_query(bad_query)
    self.assertTrue(
        any(v.antipattern == StatisticalAntipatternType.ZERO_DISPERSION_HAZARD for v in violations),
        f"Expected ZERO_DISPERSION_HAZARD, got {violations}",
    )

  def test_catches_distribution_mismatch_on_discrete_counts(self):
    """Detects applying continuous Gaussian models to discrete rare events without sample size gating."""
    bad_query = """
    stage s1 {
      metadata.event_type = "USER_LOGIN"
      $user = target.user.userid
      match: $user by 1d
      outcome:
        $obs = count(metadata.id)
        $mu = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: $user))
        $sigma = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: $user))
        $z_score = ($obs - $mu) / ($sigma + 1.0)
    }
    $user = $s1.user
    match: $user by 1d
    outcome:
      $final = max($s1.z_score)
    """
    violations = StatisticalAntipatternAuditor.audit_query(bad_query)
    self.assertTrue(
        any(v.antipattern == StatisticalAntipatternType.DISTRIBUTION_MISMATCH for v in violations),
        f"Expected DISTRIBUTION_MISMATCH, got {violations}",
    )

  def test_catches_collinear_vector_fusion(self):
    """Detects fusing collinear metrics from the same telemetry family under Euclidean distance norms."""
    bad_query = """
    stage auth_success {
      metadata.event_type = "USER_LOGIN"
      $user = target.user.userid
      match: $user by 1d
      outcome:
        $obs = count(metadata.id)
        $mu = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: $user))
        $sigma = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: $user))
        $z_auth1 = ($obs - $mu) / ($sigma + 1.0)
    }
    stage auth_fail {
      metadata.event_type = "USER_LOGIN"
      $user = target.user.userid
      match: $user by 1d
      outcome:
        $obs = count(metadata.id)
        $days = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods, target.user.userid: $user))
        $mu = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: $user))
        $sigma = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: $user))
        $z_auth2 = ($obs - $mu) / ($sigma + 1.0)
    }
    $user = $auth_success.user
    $user = $auth_fail.user
    match: $user by 1d
    outcome:
      $z1_sq = $auth_success.z_auth1 * $auth_success.z_auth1
      $z2_sq = $auth_fail.z_auth2 * $auth_fail.z_auth2
      $composite_threat_norm = $z1_sq + $z2_sq
    order: $composite_threat_norm desc
    """
    violations = StatisticalAntipatternAuditor.audit_query(bad_query)
    self.assertTrue(
        any(v.antipattern == StatisticalAntipatternType.COLLINEAR_VECTOR_FUSION for v in violations),
        f"Expected COLLINEAR_VECTOR_FUSION, got {violations}",
    )

  def test_catches_unprofiled_service_account(self):
    """Detects querying service accounts without identity pattern profiling (allowing machine/OS accounts)."""
    bad_query = """
    stage stage1_extract {
      metadata.event_type = "RESOURCE_READ"
      $sa = principal.user.userid
      $vendor = metadata.vendor_name
      $product = metadata.product_name
      $resource = target.resource.name
      $ip = principal.ip
      $sa != ""
      $resource != ""
      match: $sa, $vendor, $product, $resource, $ip by 1d
      outcome:
        $obs = count(metadata.id)
        $mu = max(metrics.resource_read_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: $sa, metadata.vendor_name: $vendor, metadata.product_name: $product, target.resource.name: $resource))
        $sigma = max(metrics.resource_read_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: $sa, metadata.vendor_name: $vendor, metadata.product_name: $product, target.resource.name: $resource))
    }
    $sa = $stage1_extract.sa
    $product = $stage1_extract.product
    $resource = $stage1_extract.resource
    $ip = $stage1_extract.ip
    match: $sa, $product, $resource, $ip by 1d
    outcome:
      $diff = max($stage1_extract.obs) - max($stage1_extract.mu)
      $z = $diff / (max($stage1_extract.sigma) + 1.0)
    order: $z desc
    """
    violations = StatisticalAntipatternAuditor.audit_query(bad_query)
    self.assertTrue(
        any(v.antipattern == StatisticalAntipatternType.UNPROFILED_SERVICE_ACCOUNT for v in violations),
        f"Expected UNPROFILED_SERVICE_ACCOUNT, got {violations}",
    )


if __name__ == "__main__":
  unittest.main()
