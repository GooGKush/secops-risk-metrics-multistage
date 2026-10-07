"""Unit tests for MultiStageTemplateRouter and Multi-Database Account Binding."""

import unittest
from scripts import malachite_catalog as mc
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
    self.assertIn("target.resource.name: target.resource.name", query)
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
    self.assertIn("target.resource.name: target.resource.name", query)

  def test_build_cloud_repository_scope_query_fleet_mode(self):
    """build_cloud_repository_scope_query without SA must enforce cloud SA regex construction."""
    query = self.router.build_cloud_repository_scope_query()
    self.assertIn("@.*gserviceaccount\\.com", query)
    self.assertIn("arn:aws:(iam|sts)", query)
    self.assertIn("target.resource.name: target.resource.name", query)
    self.assertIn("principal.ip: principal.ip", query)

  def test_build_cloud_repository_scope_query_specific_service_account(self):
    """build_cloud_repository_scope_query with specific SA must bind the exact SA ID."""
    sa_id = "svc-analytics@corp-production.iam.gserviceaccount.com"
    query = self.router.build_cloud_repository_scope_query(service_account=sa_id)
    self.assertIn(f'$sa = "{sa_id}"', query)
    self.assertNotIn("@.*gserviceaccount\\.com", query)
    self.assertIn("target.resource.name: target.resource.name", query)

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

  def test_stage2_new_models_routing_and_antipattern_cleanliness(self):
    """Verifies that all 6 new Stage 2 math models route correctly and have zero statistical violations."""
    test_models = [
        (StatisticalModel.LONGITUDINAL_CUSUM, "cusum_drift_score"),
        (StatisticalModel.TWO_PART_HURDLE, "hurdle_threat_score"),
        (StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z, "upper_tail_z"),
        (StatisticalModel.PIECEWISE_CRI, "cri_score"),
        (StatisticalModel.FLEET_PREVALENCE_SHIELD, "shielded_z"),
        (StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD, "sensitivity_excess"),
    ]

    for model, order_var in test_models:
      query = self.router.build_query(
          target_metric="network_bytes_outbound",
          entity_type=EntityType.ASSET,
          statistical_model=model,
          anomaly_threshold=2.5,
      )
      self.assertIn(f"order:\n  ${order_var} desc", query)
      violations = StatisticalAntipatternAuditor.audit_query(query)
      self.assertEqual(
          violations,
          [],
          f"Model {model.value} produced unexpected statistical violations: {violations}",
      )

  def test_part_of_the_whole_multilevel_pipeline(self):
    """Verifies that PART_OF_THE_WHOLE_MULTILEVEL renders 3-part hierarchy correctly."""
    query = self.router.build_pipeline_query(
        PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL,
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        cohort_entities=["user1", "user2"],
        target_entity="user1",
        hypothesis_goal="Compare user1 to team cohort and enterprise whole",
    )
    self.assertIn("stage all_entities {", query)
    self.assertIn("stage team_cohort_stats {", query)
    self.assertIn("stage enterprise_stats {", query)
    self.assertIn('$u = "user1" or\n      $u = "user2"', query)
    self.assertIn('$user = "user1"', query)
    self.assertIn("$z_personal =", query)
    self.assertIn("$z_vs_team =", query)
    self.assertIn("$z_vs_enterprise =", query)
    self.assertIn("$z_team_vs_enterprise = ($t_avg - $e_avg)", query)
    self.assertIn("order:\n  $z_vs_team desc", query)
    self.assertNotIn("TEAM COHORT\n", query.split("// ======", 2)[-1])
    self.assertNotIn("{{", query)

  def test_part_of_the_whole_single_metric_fleet_only_without_cohort(self):
    """No peer group: team blocks dropped (never a '$u != \"\"' copy of the fleet), fleet ordering."""
    query = self.router.build_pipeline_query(
        PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL,
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
    )
    self.assertIn("stage enterprise_stats {", query)
    self.assertNotIn("stage team_cohort_stats", query)
    self.assertNotIn("$team_cohort_stats", query)
    body = "\n".join(ln for ln in query.splitlines() if not ln.lstrip().startswith("//"))
    self.assertNotIn("$z_vs_team", body)
    self.assertNotIn("$z_team_vs_enterprise", body)
    self.assertNotIn("$u ", body)
    self.assertNotIn("\n\n\n", query, "deleted blocks must not leave double blank lines")
    self.assertIn("order:\n  $z_vs_enterprise desc", query)
    self.assertNotIn("{{", query)

  def test_part_of_the_whole_triad_multilevel_user(self):
    """Verifies that PART_OF_THE_WHOLE_TRIAD_MULTILEVEL renders a 3-metric user auth triad."""
    query = self.router.build_pipeline_query(
        PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
        entity_type=EntityType.USER,
        target_metrics=["auth_attempts_total", "auth_attempts_fail", "auth_attempts_success"],
        cohort_entities=["alice", "bob"],
        target_entity="alice",
        hypothesis_goal="Evaluate Alice against IT team and enterprise across auth triad",
    )
    self.assertIn("stage all_entities {", query)
    self.assertIn("stage team_cohort_stats {", query)
    self.assertIn("stage enterprise_stats {", query)
    self.assertIn("$m1_obs =", query)
    self.assertIn("$m2_obs =", query)
    self.assertIn("$m3_obs =", query)
    self.assertIn("$m1_team_avg = avg($all_entities.m1_obs)", query)
    self.assertIn("$m1_fleet_avg = avg($all_entities.m1_obs)", query)
    self.assertIn("$z1_vs_team =", query)
    self.assertIn("$z2_vs_team =", query)
    self.assertIn("$z3_vs_team =", query)
    self.assertIn("$d_vs_team_sq =", query)
    self.assertIn("$d_vs_fleet_sq =", query)
    self.assertIn("$z1_team_vs_enterprise =", query)
    self.assertIn("$d_team_vs_fleet_sq =", query)
    self.assertIn("order:\n  $d_vs_team_sq desc", query)
    self.assertNotIn("TEAM COHORT\n", query.split("// ======", 2)[-1])
    self.assertNotIn("{{", query)

  def test_part_of_the_whole_triad_fleet_only_without_cohort(self):
    """No peer group: the team stage would recompute the fleet, so it is dropped."""
    query = self.router.build_pipeline_query(
        PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
        entity_type=EntityType.ASSET,
        target_metrics=["dns_queries_total", "dns_queries_fail", "dns_queries_success"],
    )
    self.assertIn("stage all_entities {", query)
    self.assertIn("stage enterprise_stats {", query)
    self.assertNotIn("stage team_cohort_stats", query)
    self.assertNotIn("$team_cohort_stats", query)
    self.assertNotIn("$z1_vs_team", query)
    body = "\n".join(ln for ln in query.splitlines() if not ln.lstrip().startswith("//"))
    self.assertNotIn("$u ", body)
    self.assertNotIn("\n\n\n", query, "deleted blocks must not leave double blank lines")
    self.assertIn("$d_vs_fleet_sq =", query)
    self.assertIn("order:\n  $d_vs_fleet_sq desc", query)
    self.assertIn("$host != \"\"", query)
    self.assertNotIn("{{", query)

  def test_part_of_the_whole_triad_multilevel_host(self):
    """Verifies that PART_OF_THE_WHOLE_TRIAD_MULTILEVEL renders a 3-metric host network triad."""
    query = self.router.build_pipeline_query(
        PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
        entity_type=EntityType.ASSET,
        target_metrics=["network_bytes_outbound", "network_bytes_inbound", "network_bytes_total"],
        cohort_entities=["host-a", "host-b"],
        target_entity="host-a",
        hypothesis_goal="Evaluate host-a against cluster peers and fleet across network triad",
    )
    self.assertIn("stage all_entities {", query)
    self.assertIn("principal.asset.hostname = $host", query)
    self.assertIn('$host = "host-a"', query)
    self.assertIn("$d_vs_team_sq =", query)

  def test_part_of_the_whole_triad_heterogeneous_rejection(self):
    """Verifies that bundling heterogeneous event types raises ValueError."""
    with self.assertRaises(ValueError) as ctx:
      self.router.build_pipeline_query(
          PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
          entity_type=EntityType.USER,
          target_metrics=["auth_attempts_total", "network_bytes_outbound"],
      )
    self.assertIn("Heterogeneous event types not permitted", str(ctx.exception))

  def test_http_ua_prevalence_pipeline_rendering(self):
    """Verifies that HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE renders cleanly."""
    query = self.router.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE,
        hypothesis_goal="Hunt for rare user-agent adoption across fleet",
        min_threshold=2.0,
    )
    self.assertIn("stage stage1_personal_surge", query)
    self.assertIn("metrics.http_queries_total", query)
    self.assertIn("network.http.user_agent = $token", query)
    self.assertIn("stage stage2_fleet_prevalence", query)
    self.assertIn("$fleet_adopters = count_distinct(principal.asset.hostname)", query)
    self.assertIn("condition:\n  $normalized_odds_score >= 2.0", query)
    self.assertIn("order:\n  $normalized_odds_score desc", query)

  def test_http_error_ratio_surge_pipeline_rendering(self):
    """Verifies that HTTP_ERROR_RATIO_SURGE_2STAGE renders with failure ratio derivation."""
    query = self.router.build_pipeline_query(
        PipelineArchitecture.HTTP_ERROR_RATIO_SURGE_2STAGE,
        hypothesis_goal="Detect web application fuzzing and scanning",
    )
    self.assertIn("stage stage1_http_failure_surge", query)
    self.assertIn("metrics.http_queries_fail", query)
    self.assertIn("$fail_ratio = $observed_fails / ($total_events + 0.001)", query)
    self.assertIn("stage stage2_total_traffic", query)
    self.assertIn("order:\n  $recon_score desc", query)

  def test_http_target_surge_pipeline_rendering(self):
    """Verifies that HTTP_TARGET_SURGE_2STAGE renders destination-centric surge."""
    query = self.router.build_pipeline_query(
        PipelineArchitecture.HTTP_TARGET_SURGE_2STAGE,
        hypothesis_goal="Detect target web server surge and beaconing",
    )
    self.assertIn("stage stage1_target_surge", query)
    self.assertIn("target.hostname = $target_host", query)
    self.assertIn("metrics.http_queries_total", query)
    self.assertIn("stage stage2_fleet_target_breadth", query)
    self.assertIn("order:\n  $target_risk_score desc", query)

  def test_radar_360_sector_web_http_rendering(self):
    """Verifies that RADAR_360_SECTOR_WEB_HTTP renders micro-query for web sector."""
    query = self.router.build_pipeline_query(
        PipelineArchitecture.RADAR_360_SECTOR_WEB_HTTP,
    )
    self.assertIn("stage web_http_risk", query)
    # The baseline counts HTTP-populated events of any event_type, so the stage must too.
    self.assertIn(mc.baseline_semantics("http_queries_total").observed_filter[0], query)
    self.assertNotIn('metadata.event_type = "NETWORK_HTTP"', query)
    self.assertIn("metrics.http_queries_total", query)
    self.assertIn("principal.user.userid = $user", query)
    self.assertIn("order:\n  $z desc", query)

  def test_radar_360_sector_alert_rendering(self):
    """Verifies that RADAR_360_SECTOR_ALERT renders micro-query for security & EDR alerts sector."""
    query = self.router.build_pipeline_query(
        PipelineArchitecture.RADAR_360_SECTOR_ALERT,
    )
    self.assertIn("stage alerts_risk", query)
    # The alert baseline selects EDR log types; SCAN_UNCATEGORIZED is not its filter.
    self.assertIn(mc.baseline_semantics("alert_event_name_count").observed_filter[0], query)
    self.assertNotIn("SCAN_UNCATEGORIZED", query)
    self.assertIn("metrics.alert_event_name_count", query)
    self.assertIn("security_result.rule_name = $rule_name", query)
    self.assertIn("security_result.rule_name: security_result.rule_name", query)
    self.assertIn("$host = $alerts_risk.host", query)
    self.assertIn("$z = max($alerts_risk.z)", query)
    self.assertIn("order:\n  $z desc", query)

  def test_http_triad_multilevel_rendering(self):
    """Verifies that PART_OF_THE_WHOLE_TRIAD_MULTILEVEL renders an HTTP triad (total, fail, success)."""
    query = self.router.build_pipeline_query(
        PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
        entity_type=EntityType.USER,
        target_metrics=["http_queries_total", "http_queries_fail", "http_queries_success"],
        cohort_entities=["alice", "bob"],
        target_entity="alice",
        hypothesis_goal="Evaluate alice against web peers across HTTP triad",
    )
    self.assertIn("stage all_entities {", query)
    self.assertIn("    " + mc.baseline_semantics("http_queries_total").observed_filter[0] + "\n", query)
    # Fail / success are conditional counts over the shared HTTP population.
    self.assertIn("$m2_obs = sum(if(network.http.response_code >= 400, 1, 0))", query)
    self.assertIn("$m3_obs = sum(if(network.http.response_code < 400, 1, 0))", query)
    self.assertIn("metrics.http_queries_total", query)
    self.assertIn("metrics.http_queries_fail", query)
    self.assertIn("metrics.http_queries_success", query)
    self.assertIn("$d_vs_team_sq =", query)

  def test_entity_graph_templates_follow_freshness_rule(self):
    """Rule 5 (entity-context-graph-guide.md): every event stage of a graph-joined
    pipeline is pinned to today's UTC date (date string, not an epoch literal); graph-only
    stages carry no time predicate."""
    import datetime
    import re
    now = datetime.datetime.now(datetime.timezone.utc)
    today = now.strftime("%Y-%m-%d")
    graph_pipelines = [
        PipelineArchitecture.HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE,
        PipelineArchitecture.HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE,
        PipelineArchitecture.HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE,
        PipelineArchitecture.HYBRID_METRIC_FLEET_PREVALENCE_2STAGE,
        PipelineArchitecture.HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE,
    ]
    event_field = re.compile(r"(?<![$\w.])(?:metadata|principal|target|network)\.")
    for arch in graph_pipelines:
      with self.subTest(arch=arch.name):
        query = self.router.build_pipeline_query(arch)
        self.assertNotIn("{{", query)
        code = re.sub(r"//[^\n]*", "", query)
        stages = re.findall(r"stage\s+(\w+)\s*\{([^}]+)\}", code)
        self.assertTrue(any(".graph." in body for _, body in stages))
        for name, body in stages:
          preds = re.split(r"^\s*(?:match|outcome)\s*:", body, maxsplit=1, flags=re.MULTILINE)[0]
          has_filter = f'timestamp.get_date(metadata.event_timestamp.seconds) = "{today}"' in preds
          self.assertNotIn("event_timestamp.seconds >=", preds, f"{arch.name}:{name}")
          self.assertEqual(has_filter, bool(event_field.search(preds)), f"{arch.name}:{name}")


if __name__ == "__main__":
  unittest.main()


