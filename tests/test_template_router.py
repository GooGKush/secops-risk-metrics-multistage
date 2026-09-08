"""Unit tests for MultiStageTemplateRouter and Multi-Database Account Binding."""

import unittest
from scripts.preflight_validator import EntityType, MatchMode, PipelineArchitecture, StatisticalModel
from scripts.statistical_validator import StatisticalAntipatternAuditor
from scripts.template_router import MultiStageTemplateRouter


class TestTemplateRouterMultiDatabase(unittest.TestCase):
  """Validates template router binding of target resources for multi-database accounts."""

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  def test_resource_read_total_auto_routes_to_cloud_repository_scope(self):
    """build_query for resource_read_total under user entity must route to isolated cloud repository scope."""
    query = self.router.build_query(
        target_metric="resource_read_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.STANDARD_Z_SCORE,
        anomaly_threshold=3.0,
    )
    self.assertIn("stage stage1_extract", query)
    self.assertIn("match:\n    $sa, $vendor, $product, $resource, $ip by 1d", query)
    self.assertIn("target.resource.name: $resource", query)
    self.assertIn("order:\n  $composite_risk desc", query)

  def test_resource_written_total_auto_routes_to_cloud_repository_scope(self):
    """build_query for resource_written_total under user entity must route to isolated cloud repository scope."""
    query = self.router.build_query(
        target_metric="resource_written_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.STANDARD_Z_SCORE,
        anomaly_threshold=3.0,
    )
    self.assertIn("match:\n    $sa, $vendor, $product, $resource, $ip by 1d", query)
    self.assertIn("target.resource.name: $resource", query)

  def test_build_cloud_repository_scope_query_fleet_mode(self):
    """build_cloud_repository_scope_query without SA must enforce cloud SA regex construction."""
    query = self.router.build_cloud_repository_scope_query()
    self.assertIn("@.*gserviceaccount\\.com", query)
    self.assertIn("arn:aws:(iam|sts)", query)
    self.assertIn("target.resource.name: $resource", query)
    self.assertIn("principal.ip: $ip", query)

  def test_build_cloud_repository_scope_query_specific_service_account(self):
    """build_cloud_repository_scope_query with specific SA must bind the exact SA ID."""
    sa_id = "svc-analytics@corp-production.iam.gserviceaccount.com"
    query = self.router.build_cloud_repository_scope_query(service_account=sa_id)
    self.assertIn(f'$sa = "{sa_id}"', query)
    self.assertNotIn("@.*gserviceaccount\\.com", query)
    self.assertIn("target.resource.name: $resource", query)

  def test_cloud_repository_query_has_zero_statistical_antipatterns(self):
    """Generated cloud repository query must pass StatisticalAntipatternAuditor with 0 violations."""
    query = self.router.build_cloud_repository_scope_query(
        service_account="svc-data@project.iam.gserviceaccount.com",
        anomaly_threshold=3.5,
    )
    violations = StatisticalAntipatternAuditor.audit_query(query)
    self.assertEqual(
        violations,
        [],
        f"Generated multi-database query produced unexpected violations: {violations}",
    )

  def test_build_query_with_min_and_max_threshold_condition(self):
    """build_query with min_threshold and max_threshold must generate range condition between 2 and 3 sigma."""
    query = self.router.build_query(
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
        statistical_model=StatisticalModel.STANDARD_Z_SCORE,
        min_threshold=2.0,
        max_threshold=3.0,
    )
    self.assertIn("condition:\n  $personal_z >= 2.0 and $personal_z < 3.0", query)
    self.assertIn("order:\n  $personal_z desc", query)
    # Ensure condition precedes order
    cond_pos = query.find("condition:")
    order_pos = query.find("order:")
    self.assertGreater(cond_pos, 0)
    self.assertGreater(order_pos, cond_pos)

  def test_build_query_with_min_threshold_only(self):
    """build_query with min_threshold must generate high-confidence condition filter."""
    query = self.router.build_query(
        target_metric="auth_attempts_fail",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.POISSON,
        min_threshold=3.5,
    )
    self.assertIn("condition:\n  $poisson_z >= 3.5", query)
    self.assertIn("order:\n  $poisson_z desc", query)

  def test_build_query_with_custom_condition_expression(self):
    """build_query with custom condition_expression must insert the exact expression."""
    expr = "$personal_z >= 3.0 and $active_days >= 7"
    query = self.router.build_query(
        target_metric="file_executions_total",
        entity_type=EntityType.ASSET,
        statistical_model=StatisticalModel.STANDARD_Z_SCORE,
        condition_expression=expr,
    )
    self.assertIn(f"condition:\n  {expr}", query)

  def test_cloud_repository_scope_query_with_threshold_band(self):
    """build_cloud_repository_scope_query with min_threshold and max_threshold generates condition block."""
    query = self.router.build_cloud_repository_scope_query(
        service_account="svc-data@project.iam.gserviceaccount.com",
        min_threshold=2.0,
        max_threshold=3.5,
    )
    self.assertIn("condition:\n  $composite_risk >= 2.0 and $composite_risk < 3.5", query)
    self.assertIn("order:\n  $composite_risk desc", query)


if __name__ == "__main__":
  unittest.main()

