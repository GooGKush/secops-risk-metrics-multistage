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


if __name__ == "__main__":
  unittest.main()
