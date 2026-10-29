"""Unit tests for MultiStageTemplateRouter and Multi-Database Account Binding."""

from pathlib import Path
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
    self.assertIn("condition:\n  $active_days >= 7 and ($personal_z >= 2.0 and $personal_z < 3.0)", query)
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
    self.assertIn("condition:\n  ($composite_risk >= 2.0 and $composite_risk < 3.5) and ($dest_days >= 7 or $dest_days = 0 or $obs_deletes > 0 or $obs_writes > 0)", query)
    self.assertIn("order:\n  $composite_risk desc", query)

  def test_stage2_new_models_routing_and_antipattern_cleanliness(self):
    """Verifies active Stage 2 math models route cleanly and retired D1 models raise clear ValueErrors."""
    test_models = [
        (StatisticalModel.LONGITUDINAL_CUSUM, "cusum_drift_score"),
        (StatisticalModel.TWO_PART_HURDLE, "hurdle_threat_score"),
        (StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z, "personal_z"),
        (StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD, "adaptive_z"),
    ]

    for model, order_var in test_models:
      query = self.router.build_query(
          target_metric="network_bytes_outbound",
          entity_type=EntityType.ASSET,
          statistical_model=model,
          anomaly_threshold=2.5,
      )
      self.assertIn(f"order:\n  ${order_var} desc", query)
      if model == StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z:
        self.assertTrue(
            any("merged into STANDARD_Z_SCORE" in adv for adv in self.router.last_advisories),
            f"Expected merge advisory on ASYMMETRIC_DIRECTIONAL_Z, got {self.router.last_advisories}",
        )
      violations = StatisticalAntipatternAuditor.audit_query(query)
      self.assertEqual(
          violations,
          [],
          f"Model {model.value} produced unexpected statistical violations: {violations}",
      )

    with self.assertRaisesRegex(ValueError, r"retired \(D1\).*calculate_cri"):
      self.router.build_query(
          target_metric="network_bytes_outbound",
          entity_type=EntityType.ASSET,
          statistical_model=StatisticalModel.PIECEWISE_CRI,
      )
    with self.assertRaisesRegex(ValueError, r"retired \(D1\).*hybrid_metric_fleet_prevalence_2stage"):
      self.router.build_query(
          target_metric="network_bytes_outbound",
          entity_type=EntityType.ASSET,
          statistical_model=StatisticalModel.FLEET_PREVALENCE_SHIELD,
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
        PipelineArchitecture.RARE_DESTINATION_ECG_3STAGE,
        PipelineArchitecture.FUSION_RARE_DESTINATION_3STAGE,
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

  def test_all_12_resource_metrics_auto_route_to_cloud_repository_scope(self):
    """All 12 resource_* metrics (_total, _fail, _success) must route to CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH."""
    from scripts.preflight_validator import METRIC_CATALOG, MalachiteASTValidator
    cloud_metrics = [m for m in METRIC_CATALOG if m.startswith("resource_")]
    self.assertEqual(len(cloud_metrics), 12)
    for m in cloud_metrics:
      with self.subTest(metric=m):
        q = self.router.build_query(
            target_metric=m,
            entity_type=EntityType.USER,
            statistical_model=StatisticalModel.STANDARD_Z_SCORE,
        )
        self.assertIn("match:\n    $sa, $vendor, $product, $resource, $ip by 1d", q)
        self.assertEqual(mc.observed_filter_gaps(q), [])
        self.assertEqual(MalachiteASTValidator.validate_query(q), [])
        if m.endswith("_fail"):
          self.assertIn('not security_result.action = "ALLOW"', q)
          self.assertIn(f"metrics.{m}(", q)
        elif m.endswith("_success"):
          self.assertIn('security_result.action = "ALLOW"', q)
          self.assertIn(f"metrics.{m}(", q)

  def test_failure_ratio_surge_supports_all_eight_fail_metrics(self):
    """build_failure_ratio_surge_query must render compiler-valid 2-stage queries for all 8 *_fail metrics."""
    from scripts.preflight_validator import MalachiteASTValidator
    fail_cases = [
        ("http_queries_fail", EntityType.ASSET),
        ("http_queries_fail", EntityType.USER),
        ("dns_queries_fail", EntityType.ASSET),
        ("auth_attempts_fail", EntityType.USER),
        ("file_executions_fail", EntityType.ASSET),
        ("resource_read_fail", EntityType.USER),
        ("resource_written_fail", EntityType.USER),
        ("resource_creation_fail", EntityType.USER),
        ("resource_deletion_fail", EntityType.USER),
    ]
    for fail_metric, et in fail_cases:
      with self.subTest(fail_metric=fail_metric, entity_type=et.value):
        q = self.router.build_failure_ratio_surge_query(
            fail_metric=fail_metric,
            entity_type=et,
            anomaly_threshold=3.0,
        )
        self.assertIn(f"metrics.{fail_metric}(", q)
        self.assertIn("$fail_ratio = $observed_fails / ($total_events + 0.001)", q)
        self.assertEqual(mc.observed_filter_gaps(q), [])
        self.assertEqual(MalachiteASTValidator.validate_query(q), [])
        self.assertEqual(StatisticalAntipatternAuditor.audit_query(q), [])

  def test_derived_file_prevalence_supports_fail_success_and_user(self):
    """HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE must support file_executions_fail/success and USER."""
    from scripts.preflight_validator import MalachiteASTValidator
    for metric in ("file_executions_total", "file_executions_fail", "file_executions_success"):
      for et in (EntityType.ASSET, EntityType.USER):
        with self.subTest(metric=metric, entity_type=et.value):
          q = self.router.build_pipeline_query(
              PipelineArchitecture.HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE,
              target_metric=metric,
              entity_type=et,
          )
          self.assertIn(f"metrics.{metric}(", q)
          self.assertEqual(mc.observed_filter_gaps(q), [])
          self.assertEqual(MalachiteASTValidator.validate_query(q), [])

  def test_c2_beacon_flow_and_alert_surge_queries(self):
    """WS4-D1 (D1): build_outbound_flow_surge_query (and build_c2_beacon_flow_query alias) and build_alert_surge_query render valid queries."""
    import re
    from scripts.preflight_validator import MalachiteASTValidator
    for flow_metric in ("network_flows_outbound", "network_flows_inbound", "network_flows_total"):
      for et in (EntityType.ASSET, EntityType.USER):
        q = self.router.build_outbound_flow_surge_query(target_metric=flow_metric, entity_type=et)
        q_alias = self.router.build_c2_beacon_flow_query(target_metric=flow_metric, entity_type=et)
        self.assertEqual(q, q_alias)
        self.assertIn("OUTBOUND FLOW SURGE", q)
        self.assertNotIn("timing regularity", q.lower())
        self.assertIn(f"metrics.{flow_metric}(", q)
        self.assertIn("$flow_surge_score = $flow_z", q)
        self.assertIn("$dispersion_floor = math.sqrt(if($hist_flow_avg > 1.0, $hist_flow_avg, 1.0))", q)
        self.assertIn("$active_days >= 7", q)
        self.assertEqual(len(re.findall(r"^stage\s+\w+\s*\{", q, re.M)), 1)
        self.assertEqual(mc.observed_filter_gaps(q), [])
        self.assertEqual(MalachiteASTValidator.validate_query(q), [])
        self.assertEqual(StatisticalAntipatternAuditor.audit_query(q), [])

    for et in (EntityType.ASSET, EntityType.USER):
      q_alert = self.router.build_alert_surge_query(entity_type=et)
      self.assertIn("metrics.alert_event_name_count(", q_alert)
      self.assertEqual(mc.observed_filter_gaps(q_alert), [])
      self.assertEqual(MalachiteASTValidator.validate_query(q_alert), [])
      self.assertEqual(StatisticalAntipatternAuditor.audit_query(q_alert), [])

  def test_all_eight_mitre_killchain_archetypes_render_clean(self):
    """All 11 MITRE ATT&CK KillChainArchetype combinations must render compiler-clean YARA-L across supported entities."""
    from scripts.preflight_validator import KillChainArchetype, MalachiteASTValidator, QueryIntegrityGate
    self.assertEqual(len(KillChainArchetype), 11)
    for archetype in KillChainArchetype:
      spec = MultiStageTemplateRouter.KILLCHAIN_CATALOG[archetype]
      for et in spec["supported_entities"]:
        with self.subTest(archetype=archetype.value, entity_type=et.value):
          q = self.router.build_killchain_hunt_query(archetype, entity_type=et)
          self.assertIn(f"// MITRE ATT&CK Kill-Chain: {spec['mitre_tactics'][0]} -> {spec['mitre_tactics'][1]}", q)
          self.assertIn(f"metrics.{spec['sector_a']}(", q)
          self.assertIn(f"metrics.{spec['sector_b']}(", q)
          self.assertEqual(mc.observed_filter_gaps(q), [])
          self.assertEqual(MalachiteASTValidator.validate_query(q), [])
          self.assertEqual(StatisticalAntipatternAuditor.audit_query(q), [])
          self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(q)["valid"])

  def test_data_table_syntax_and_query_integrity_gate(self):
    """MalachiteASTValidator must validate %<table_name>.<col> syntax and QueryIntegrityGate must verify pre/post query fidelity."""
    from scripts.preflight_validator import MalachiteASTValidator, QueryIntegrityGate
    repo_dir = Path(__file__).resolve().parent.parent
    dt_template = (repo_dir / "templates" / "pipelines" / "hybrid_data_table_bridge_2stage.yl2").read_text(encoding="utf-8")
    rendered = dt_template.replace("{{ENTITY_FILTER}}", 'principal.user.userid != ""')
    self.assertEqual(MalachiteASTValidator.validate_query(rendered), [])
    pre = QueryIntegrityGate.verify_pre_dispatch(rendered)
    self.assertTrue(pre["valid"])

    # Invalid bare %table without column should trigger AST error
    bad_dt = rendered.replace("= %ueba_hunt_bridge.hostname", "= %ueba_hunt_bridge")
    errors = MalachiteASTValidator.validate_query(bad_dt)
    self.assertTrue(any("Data Table" in e for e in errors))

    # Post-response check detects backend query substitution
    ok_post = QueryIntegrityGate.verify_backend_response(rendered, {"events": [], "executed_query": rendered})
    self.assertTrue(ok_post["valid"])
    substituted_post = QueryIntegrityGate.verify_backend_response(
        rendered, {"events": [], "executed_query": 'metadata.event_type = "USER_LOGIN"'}
    )
    self.assertFalse(substituted_post["valid"])
    self.assertTrue(any("DRIFT" in e for e in substituted_post["errors"]))

  def test_chained_hunt_router_cross_entity_killchain_plans(self):
    """ChainedHuntRouter.build_cross_entity_killchain_plan must render valid Phase 1 and Phase 2 queries for all 4 paths."""
    from scripts.preflight_validator import MalachiteASTValidator
    from scripts.template_router import ChainedHuntRouter
    self.assertEqual(len(ChainedHuntRouter.CROSS_ENTITY_PATHS), 4)
    for path_name in ChainedHuntRouter.CROSS_ENTITY_PATHS:
      with self.subTest(path_name=path_name):
        plan = ChainedHuntRouter.build_cross_entity_killchain_plan(path_name, bridge_entity="srv-prod-01")
        self.assertEqual(plan["path_name"], path_name)
        self.assertGreaterEqual(len(plan["bridge_contract"]), 2)
        for key in ("phase1_query", "phase2_query"):
          q = plan[key]
          self.assertEqual(mc.observed_filter_gaps(q), [], f"{path_name}:{key}")
          self.assertEqual(MalachiteASTValidator.validate_query(q), [], f"{path_name}:{key}")
          self.assertEqual(StatisticalAntipatternAuditor.audit_query(q), [], f"{path_name}:{key}")

  def test_ws2_05_router_rejects_silence_and_jitter_aliases(self):
    """WS2-05: MultiStageTemplateRouter.build_query raises clear ValueErrors on SILENCE/DROP_OUT and JITTER/BEACON."""
    for silence_alias in ("SILENCE_DETECTION", "DROP_OUT", "SILENCE", "DROPOUT"):
      with self.subTest(alias=silence_alias):
        with self.assertRaises(ValueError) as ctx:
          self.router.build_query(
              target_metric="auth_attempts_total",
              entity_type=EntityType.USER,
              statistical_model=silence_alias,  # type: ignore[arg-type]
          )
        self.assertIn("not supported", str(ctx.exception).lower())
        with self.assertRaises(ValueError) as ctx_res:
          self.router.build_query(
              target_metric="resource_read_total",
              entity_type=EntityType.USER,
              statistical_model=silence_alias,  # type: ignore[arg-type]
          )
        self.assertIn("not supported", str(ctx_res.exception).lower())

    for jitter_alias in ("JITTER", "BEACON_REGULARITY", "BEACON", "C2_BEACONING_JITTER", "C2_JITTER"):
      with self.subTest(alias=jitter_alias):
        with self.assertRaises(ValueError) as ctx:
          self.router.build_query(
              target_metric="network_flows_outbound",
              entity_type=EntityType.ASSET,
              statistical_model=jitter_alias,  # type: ignore[arg-type]
          )
        self.assertIn("secops-statistical-hunter", str(ctx.exception))
        self.assertIn("C2_BEACONING_JITTER", str(ctx.exception))

  def test_ws2_06_router_rejects_unknown_models_and_preserves_non_z_on_resource_user(self):
    """WS2-06: build_query rejects unknown/invalid models everywhere and keeps non-Z models on (resource_*, USER)."""
    from unittest.mock import patch
    from scripts import ueba_hybrid_engine as engine_mod
    from scripts.preflight_validator import MalachiteASTValidator

    for bad_model in ("MADE_UP_MODEL", "BOGUS_Z", "", "   ", "diversity_deficit", None, 123):
      for metric in ("auth_attempts_total", "resource_read_total"):
        with self.subTest(bad_model=bad_model, metric=metric):
          with self.assertRaises(ValueError):
            self.router.build_query(
                target_metric=metric,
                entity_type=EntityType.USER,
                statistical_model=bad_model,  # type: ignore[arg-type]
            )

    if hasattr(engine_mod, "RETIRED_MODEL_ALIASES"):
      with patch.dict(engine_mod.RETIRED_MODEL_ALIASES, {"LEGACY_TEST_MODEL": "STANDARD_Z_SCORE"}, clear=False):
        with self.assertRaises(ValueError) as ctx_ret:
          self.router.build_query(
              target_metric="resource_read_total",
              entity_type=EntityType.USER,
              statistical_model="legacy-test-model",  # type: ignore[arg-type]
          )
        self.assertIn("is retired; use STANDARD_Z_SCORE.", str(ctx_ret.exception))

    # STANDARD_Z_SCORE (enum or string alias) on (resource_read_total, USER) keeps CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH
    for z_arg in (StatisticalModel.STANDARD_Z_SCORE, "STANDARD_Z_SCORE", "zscore"):
      q_z = self.router.build_query(
          target_metric="resource_read_total",
          entity_type=EntityType.USER,
          statistical_model=z_arg,  # type: ignore[arg-type]
      )
      self.assertIn("order:\n  $composite_risk desc", q_z)

    # Non-Z models on (resource_read_total, USER) must render the requested model, NOT redirect to CLOUD_REPOSITORY_SCOPE
    non_z_expectations = [
        (StatisticalModel.POISSON, "$poisson_z"),
        (StatisticalModel.COEFFICIENT_OF_VARIATION, "$cv"),
        (StatisticalModel.LONGITUDINAL_CUSUM, "$cusum_drift_score"),
        (StatisticalModel.RELATIVE_DEVIATION, "$fold_change"),
    ]
    for model_enum, expected_var in non_z_expectations:
      with self.subTest(model=model_enum.value):
        q = self.router.build_query(
            target_metric="resource_read_total",
            entity_type=EntityType.USER,
            statistical_model=model_enum,
        )
        self.assertIn(expected_var, q)
        self.assertNotIn("$observed_reads", q)
        self.assertNotIn("order:\n  $composite_risk desc", q)
        self.assertEqual(MalachiteASTValidator.validate_query(q), [])
        if model_enum == StatisticalModel.LONGITUDINAL_CUSUM:
          with self.assertRaises(ValueError) as ctx_cusum_a:
            engine_mod.compile_hunt_plan(
                statistical_model=model_enum.value,
                metrics="resource_read_total",
                entity_type="USER",
                mode="A",
            )
          self.assertIn("LONGITUDINAL_CUSUM cannot run in single-day Mode A", str(ctx_cusum_a.exception))
          res_engine = engine_mod.compile_hunt_plan(
              statistical_model=model_enum.value,
              metrics="resource_read_total",
              entity_type="USER",
              mode="B",
              window_days=3,
          )
        else:
          res_engine = engine_mod.compile_hunt_plan(
              statistical_model=model_enum.value,
              metrics="resource_read_total",
              entity_type="USER",
          )
        self.assertEqual(res_engine["architecture"], PipelineArchitecture.LOCAL_2STAGE.value)
        self.assertIn(expected_var, res_engine["compiled_query"])

  def test_ws2_01_composite_keys_expanded_across_all_18_models_and_modes(self):
    """WS2-01: All 18 Stage-2 models and both MatchModes preserve composite baseline keys in Root match:."""
    import re
    from scripts.preflight_validator import MalachiteASTValidator

    composite_cases = [
        ("file_executions_total", EntityType.ASSET, "$host, $sha256"),
        ("file_executions_total", EntityType.USER, "$host, $sha256"),
        ("file_executions_fail", EntityType.ASSET, "$host, $sha256"),
        ("alert_event_name_count", EntityType.ASSET, "$host, $rule_name"),
        ("resource_read_total", EntityType.RESOURCE, "$sa, $vendor, $product, $resource"),
        ("resource_read_total", EntityType.USER, "$sa, $vendor, $product, $resource"),
    ]

    retired_models = {
        StatisticalModel.HOURLY_TEMPORAL_ZSCORE: r"retired.*HOUR_OF_DAY_PROFILE",
        StatisticalModel.CIRCADIAN_VON_MISES: r"retired.*HOUR_OF_DAY_PROFILE",
        StatisticalModel.PIECEWISE_CRI: r"retired.*calculate_cri",
        StatisticalModel.FLEET_PREVALENCE_SHIELD: r"retired.*hybrid_metric_fleet_prevalence_2stage",
    }
    for metric_name, ent_type, expected_tuple in composite_cases:
      for model in StatisticalModel:
        if model in retired_models:
          with self.assertRaisesRegex(ValueError, retired_models[model]):
            self.router.build_query(
                target_metric=metric_name,
                entity_type=ent_type,
                statistical_model=model,
            )
          continue
        if metric_name == "alert_event_name_count" and model == StatisticalModel.BAYESIAN_BETA_BINOMIAL:
          with self.assertRaisesRegex(ValueError, r"BAYESIAN_BETA_BINOMIAL.*paired|unpaired|_fail"):
            self.router.build_query(
                target_metric=metric_name,
                entity_type=ent_type,
                statistical_model=model,
            )
          continue
        if (
            metric_name == "resource_read_total"
            and ent_type == EntityType.USER
            and model == StatisticalModel.STANDARD_Z_SCORE
        ):
          # Default (resource_*, USER, STANDARD_Z_SCORE) routes to CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH,
          # which already isolates baselines per ($sa, $vendor, $product, $resource).
          q_scope = self.router.build_query(
              target_metric=metric_name,
              entity_type=ent_type,
              statistical_model=model,
          )
          self.assertIn("$sa, $vendor, $product, $resource", q_scope)
          self.assertEqual(MalachiteASTValidator.validate_query(q_scope), [])
          self.assertEqual(MalachiteASTValidator.validate_model_concordance(q_scope, model), [])
          continue

        for mode in (MatchMode.TIMELINE_BREAKDOWN, MatchMode.FLEET_ROLLUP):
          with self.subTest(metric=metric_name, entity=ent_type.value, model=model.value, mode=mode.value):
            q = self.router.build_query(
                target_metric=metric_name,
                entity_type=ent_type,
                statistical_model=model,
                match_mode=mode,
                scoring_end_date="2026-10-27",
            )
            self.assertEqual(MalachiteASTValidator.validate_query(q), [], f"AST error on {metric_name}/{model.value}/{mode.value}")
            self.assertEqual(
                MalachiteASTValidator.validate_model_concordance(q, model),
                [],
                f"Concordance error on {metric_name}/{model.value}/{mode.value}",
            )

            clean = re.sub(r"//[^\n]*", "", q)
            clean = re.sub(r"/\*.*?\*/", "", clean, flags=re.S)
            root_body = re.sub(r"stage\s+[A-Za-z0-9_]+\s*\{.*?\n\}", "", clean, flags=re.S)
            root_match = re.search(r"\bmatch:\s*\n\s*([^\n]+)", root_body)
            self.assertIsNotNone(root_match)
            root_keys = root_match.group(1).strip()

            if model == StatisticalModel.LONGITUDINAL_CUSUM:
              self.assertIn(f"match:\n    {expected_tuple}, $day_ws by 1d", clean)
              self.assertEqual(root_keys, expected_tuple)
            elif model in (StatisticalModel.MAD, StatisticalModel.QUANTILE_IQR_SKEW):
              self.assertEqual(root_keys, f"{expected_tuple}, $ws by 1d")
            else:
              expected_root = f"{expected_tuple}, $ws by 1d" if mode == MatchMode.TIMELINE_BREAKDOWN else expected_tuple
              self.assertEqual(root_keys, expected_root)

    # Also verify _mad_group_keys handles multi-arg single-line metrics.* calls and drops non-dimension match vars ($ip).
    synthetic_stage1 = (
        'stage stage1_extract {\n'
        '    metadata.event_type = "RESOURCE_READ"\n'
        '    $sa = principal.user.userid\n'
        '    $ip = principal.ip\n'
        '    $vendor = metadata.vendor_name\n'
        '    $product = metadata.product_name\n'
        '    $resource = target.resource.name\n'
        '  match:\n'
        '    $sa, $ip, $vendor, $product, $resource by 1d\n'
        '  outcome:\n'
        '    $observed_val = count(metadata.id)\n'
        '    $historical_avg = max(metrics.resource_read_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: principal.user.userid, metadata.vendor_name: metadata.vendor_name, metadata.product_name: metadata.product_name, target.resource.name: target.resource.name))\n'
        '}\n'
    )
    keys, dropped = self.router._mad_group_keys(synthetic_stage1)
    self.assertEqual(keys, ["$sa", "$vendor", "$product", "$resource"])
    self.assertEqual(dropped, ["$ip"])

  def test_ws2_03_include_significance_gate_false_emits_no_gate_queries(self):
    """WS2-03: include_significance_gate=False strips significance thresholds while keeping AST validity."""
    from scripts.preflight_validator import MalachiteASTValidator

    q_z = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.STANDARD_Z_SCORE,
        include_significance_gate=False,
    )
    self.assertIsNone(MultiStageTemplateRouter.root_condition(q_z))
    self.assertNotIn("\ncondition:", q_z)
    self.assertIn("// Significance Gate: NONE (NO-GATE decoupled sector for post-query Euclidean fusion)", q_z)
    self.assertEqual(MalachiteASTValidator.validate_query(q_z), [])

    # MAD retains structural scoring-window and sample-size guards while dropping $modified_z >= 3.5
    q_mad = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.MAD,
        scoring_end_date="2026-10-27",
        include_significance_gate=False,
    )
    self.assertEqual(
        MultiStageTemplateRouter.root_condition(q_mad),
        "$in_scoring_window = 1 and $raw_active_days >= 7",
    )
    self.assertNotIn("$modified_z >=", q_mad)
    self.assertEqual(MalachiteASTValidator.validate_query(q_mad), [])

    # Cloud repository scope spoke (both direct and via (resource_*, USER, STANDARD_Z_SCORE) build_query)
    for q_cloud in (
        self.router.build_cloud_repository_scope_query(
            service_account="charles.hardy",
            include_significance_gate=False,
        ),
        self.router.build_query(
            target_metric="resource_read_total",
            entity_type=EntityType.USER,
            statistical_model=StatisticalModel.STANDARD_Z_SCORE,
            include_significance_gate=False,
        ),
    ):
      self.assertIsNone(MultiStageTemplateRouter.root_condition(q_cloud))
      self.assertNotIn("\ncondition:", q_cloud)
      self.assertIn("// Significance Gate: NONE (NO-GATE decoupled sector for post-query Euclidean fusion)", q_cloud)
      self.assertEqual(MalachiteASTValidator.validate_query(q_cloud), [])

    # Alert surge spoke (both ASSET and USER)
    for ent in (EntityType.ASSET, EntityType.USER):
      q_alert = self.router.build_alert_surge_query(
          entity_type=ent,
          include_significance_gate=False,
      )
      self.assertIsNone(MultiStageTemplateRouter.root_condition(q_alert))
      self.assertNotIn("\ncondition:", q_alert)
      self.assertIn("// Significance Gate: NONE (NO-GATE decoupled sector for post-query Euclidean fusion)", q_alert)
      self.assertEqual(MalachiteASTValidator.validate_query(q_alert), [])

    # Default include_significance_gate=True behavior enforces maturity + significance gate
    self.assertEqual(
        MultiStageTemplateRouter.root_condition(
            self.router.build_query("auth_attempts_total", EntityType.USER, StatisticalModel.STANDARD_Z_SCORE)
        ),
        "$active_days >= 7 and $personal_z >= 3.0",
    )
    self.assertIn(
        "$alert_z >= 3.0",
        self.router.build_alert_surge_query(entity_type=EntityType.ASSET),
    )

  def test_ws3_d1_model_renames_and_killchain_routing(self):
    """WS3-D1: Renames CV to regular-volume surge and MACD to above-historical-max Z; killchain avoids retired PIECEWISE_CRI."""
    from scripts.preflight_validator import MalachiteASTValidator
    from scripts.template_router import ChainedHuntRouter

    cv_desc = MultiStageTemplateRouter.MODEL_DESCRIPTIONS[StatisticalModel.COEFFICIENT_OF_VARIATION].lower()
    self.assertIn("regular-volume surge", cv_desc)
    q_cv = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.COEFFICIENT_OF_VARIATION,
    )
    self.assertIn("regular-volume surge", q_cv.lower())
    self.assertIn("$active_days >= 7", q_cv)

    macd_desc = MultiStageTemplateRouter.MODEL_DESCRIPTIONS[StatisticalModel.MACD_MOMENTUM_VELOCITY].lower()
    self.assertIn("above-historical-max z", macd_desc)
    for q_macd in (
        self.router.build_query(
            target_metric="network_bytes_outbound",
            entity_type=EntityType.ASSET,
            statistical_model=StatisticalModel.MACD_MOMENTUM_VELOCITY,
        ),
        self.router.build_pipeline_query(
            PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE,
            target_metric="network_bytes_outbound",
            entity_type=EntityType.ASSET,
        ),
    ):
      self.assertIn("above-historical-max z", q_macd.lower())
      self.assertIn("$exceed_raw = $observed - $hist_max", q_macd)
      self.assertIn("$above_max_z =", q_macd)
      self.assertIn("$macd_z = $personal_z + $above_max_z", q_macd)
      self.assertNotIn("$velocity_ratio", q_macd)
      self.assertNotIn("* $velocity_ratio", q_macd)
      self.assertEqual(MalachiteASTValidator.validate_query(q_macd), [])

    killchain_plan = ChainedHuntRouter().build_cross_entity_killchain_plan(
        "USER_WORKSPACE_HOARDING_TO_HOST_EGRESS"
    )
    self.assertIn("phase1_query", killchain_plan)
    self.assertEqual(MalachiteASTValidator.validate_query(killchain_plan["phase1_query"]), [])

  def test_ws3_reldev_continuous_floor_and_z_equiv(self):
    """WS3-RELDEV: Continuous max(avg, 1.0) floor eliminates 0 -> 0.05 jump discontinuity and emits Z-equivalent."""
    from scripts.preflight_validator import MalachiteASTValidator

    q = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.RELATIVE_DEVIATION,
    )
    self.assertIn("$safe_hist_avg = if($hist_avg > 1.0, $hist_avg, 1.0)", q)
    self.assertNotIn("if($hist_avg > 0,", q)
    self.assertIn("$dev = $observed - $safe_hist_avg", q)
    self.assertIn("$ratio = $dev / $safe_hist_avg", q)
    self.assertIn("$fold_change = $observed / $safe_hist_avg", q)
    self.assertIn("$rel_dev_z_equiv = if($raw_z_equiv > 0.0, $raw_z_equiv, 0.0)", q)
    self.assertEqual(MalachiteASTValidator.validate_query(q), [])
    self.assertEqual(MalachiteASTValidator.validate_model_concordance(q, StatisticalModel.RELATIVE_DEVIATION), [])

    def _eval_reldev(observed: float, hist_avg: float) -> tuple[float, float, float]:
      safe_avg = hist_avg if hist_avg > 1.0 else 1.0
      dev = observed - safe_avg
      ratio = dev / safe_avg
      fold_change = observed / safe_avg
      raw_z_equiv = 3.0 * ratio
      z_equiv = raw_z_equiv if raw_z_equiv > 0.0 else 0.0
      return fold_change, ratio, z_equiv

    # Continuous across hist_avg in [0.0, 1.0]: no 20x jump at hist_avg = 0.05
    for avg in (0.0, 0.05, 0.5, 1.0):
      fc, ratio, z_eq = _eval_reldev(observed=5.0, hist_avg=avg)
      self.assertAlmostEqual(fc, 5.0)
      self.assertAlmostEqual(ratio, 4.0)
      self.assertAlmostEqual(z_eq, 12.0)

    # At default 2.0x gate, fold_change=2.0 -> ratio=1.0 -> z_equiv=3.0; below baseline -> z_equiv=0.0
    self.assertEqual(_eval_reldev(observed=200.0, hist_avg=100.0), (2.0, 1.0, 3.0))
    self.assertEqual(_eval_reldev(observed=80.0, hist_avg=100.0), (0.8, -0.2, 0.0))

  def test_ws3_poisson_blocks_byte_metrics_and_handles_overdispersion(self):
    """WS3-POISSON: Rejects value_sum byte metrics and switches to NB scale when calendar Fano > 2.0."""
    from scripts import malachite_catalog as mc
    from scripts.preflight_validator import METRIC_CATALOG, MalachiteASTValidator
    from scripts.statistical_validator import StatisticalAntipatternAuditor
    import scripts.ueba_hybrid_engine as engine_mod

    byte_metrics = [m for m in METRIC_CATALOG if mc.baseline_semantics(m).metric_arg == "value_sum"]
    self.assertEqual(len(byte_metrics), 6)
    for bm in byte_metrics:
      et = METRIC_CATALOG[bm].supported_entity_types[0]
      with self.assertRaisesRegex(ValueError, r"POISSON.*event_count_sum|value_sum|byte"):
        self.router.build_query(
            target_metric=bm,
            entity_type=et,
            statistical_model=StatisticalModel.POISSON,
        )
      with self.assertRaisesRegex(ValueError, r"POISSON.*event_count_sum|value_sum|byte"):
        engine_mod.compile_hunt_pipeline(
            statistical_model="POISSON",
            metrics=bm,
            entity_type=et.value,
        )

    q = self.router.build_query(
        target_metric="auth_attempts_fail",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.POISSON,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q), [])
    self.assertEqual(MalachiteASTValidator.validate_model_concordance(q, StatisticalModel.POISSON), [])
    self.assertEqual(StatisticalAntipatternAuditor.audit_query(q), [])
    self.assertIn("$fano_cal = $var_cal / $safe_lambda", q)
    self.assertIn("$eff_var = if($active_days >= 2 and $fano_cal > 2.0, $nb_var, $safe_lambda)", q)
    self.assertIn("$safe_poisson_sd = math.sqrt($eff_var)", q)
    self.assertIn("$poisson_z = $diff / $safe_poisson_sd", q)

    pipe_raw = (self.router.template_dir / "pipelines" / "poisson_rarity_2stage.yl2").read_text(encoding="utf-8")
    self.assertIn("$fano_cal = $var_cal / $safe_lambda", pipe_raw)
    self.assertIn("$poisson_z = $diff / $safe_poisson_sd", pipe_raw)

    # Low dispersion (Fano <= 2.0): uses pure Poisson sqrt(safe_lambda) = 1.0 -> (5 - 1) / 1 = 4.0
    z_poisson = engine_mod.calculate_poisson_rarity_z(
        observed=5.0,
        hist_sum=30.0,
        active_days=30,
        hist_avg=1.0,
        hist_stddev=1.0,
    )
    self.assertAlmostEqual(z_poisson, 4.0, places=4)

    # Overdispersed count baseline (charles.hardy: Fano_cal = 181.34 > 2.0): uses calendar NB scale ~99.75 instead of 7.41
    z_overdisp = engine_mod.calculate_poisson_rarity_z(
        observed=785.0,
        hist_sum=1646.0,
        active_days=10,
        hist_avg=164.6,
        hist_stddev=114.4875,
    )
    self.assertAlmostEqual(z_overdisp, 7.3186, places=4)

  def test_ws3_bayesian_gamma_empirical_bayes_shrinkage_and_10sigma_spike(self):
    """WS3-BAYES: Fleet Empirical Bayes Gamma(alpha0, beta0) shrinks sparse entities and fires on +10sigma spikes."""
    from scripts.preflight_validator import MalachiteASTValidator
    from scripts.statistical_validator import StatisticalAntipatternAuditor
    from scripts.submission_tests import validate_template_fragments
    from scripts.template_router import fit_gamma_prior_from_fleet
    import scripts.ueba_hybrid_engine as engine_mod

    # 1. Fleet prior fitting via Method of Moments on entity daily rates (hist_sum / 30.0)
    # Rates = [2.0, 4.0, 6.0, 8.0] -> mean = 5.0, sample_var = 6.6667 -> beta0 = 0.75, alpha0 = 3.75
    fleet_rows = [
        {"entity": "u1", "hist_sum": 60.0, "active_days": 15},
        {"entity": "u2", "hist_sum": 120.0, "active_days": 20},
        {"entity": "u3", "hist_sum": 180.0, "active_days": 25},
        {"entity": "u4", "hist_sum": 240.0, "active_days": 30},
    ]
    alpha0, beta0 = fit_gamma_prior_from_fleet(fleet_rows)
    self.assertAlmostEqual(alpha0 / beta0, 5.0, places=3)
    self.assertAlmostEqual(alpha0, 3.75, places=3)
    self.assertAlmostEqual(beta0, 0.75, places=3)

    # Empty / degenerate fleet falls back safely to positive weak defaults
    fb_a, fb_b = fit_gamma_prior_from_fleet([])
    self.assertGreater(fb_a, 0.0)
    self.assertGreater(fb_b, 0.0)

    # 2. Router & Engine render slots cleanly and pass AST + fragment + antipattern audits
    q = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.BAYESIAN_GAMMA,
        fleet_prior_payload=fleet_rows,
    )
    self.assertNotIn("{{", q)
    self.assertIn("$post_alpha_pre = 3.75 + $hist_sum", q)
    self.assertIn("$post_beta_pre = 0.75 + 30.0", q)
    self.assertIn("$bayesian_z = ($observed - $posterior_rate) / $safe_pred_sd", q)
    self.assertEqual(MultiStageTemplateRouter.root_condition(q), "$bayesian_z >= 3.0")
    self.assertEqual(MalachiteASTValidator.validate_query(q), [])
    self.assertEqual(MalachiteASTValidator.validate_model_concordance(q, StatisticalModel.BAYESIAN_GAMMA), [])
    self.assertEqual(StatisticalAntipatternAuditor.audit_query(q), [])
    self.assertEqual(validate_template_fragments(), [])

    plan = engine_mod.compile_hunt_pipeline(
        statistical_model="BAYESIAN_GAMMA",
        metrics="auth_attempts_total",
        entity_type="USER",
        prior_alpha0=20.0,
        prior_beta0=4.0,
    )
    self.assertIn("$post_alpha_pre = 20.0 + $hist_sum", plan["compiled_query"])
    self.assertIn("$post_beta_pre = 4.0 + 30.0", plan["compiled_query"])

    # 3. Golden test A: Sparse entity shrinks dramatically more toward prior mean (5.0) than mature entity
    sparse = engine_mod.calculate_bayesian_gamma_posterior(
        observed=3.0,
        hist_sum=2.0,
        active_days=2,
        hist_avg=1.0,
        hist_stddev=0.0,
        prior_alpha0=20.0,
        prior_beta0=4.0,
    )
    mature = engine_mod.calculate_bayesian_gamma_posterior(
        observed=10.0,
        hist_sum=300.0,
        active_days=30,
        hist_avg=10.0,
        hist_stddev=3.0,
        prior_alpha0=20.0,
        prior_beta0=4.0,
    )
    sparse_rel_pull = abs(sparse["posterior_rate"] - sparse["mu_cal"]) / max(sparse["mu_cal"], 1e-6)
    mature_rel_pull = abs(mature["posterior_rate"] - mature["mu_cal"]) / max(mature["mu_cal"], 1e-6)
    self.assertGreater(sparse_rel_pull, 5.0 * mature_rel_pull)
    self.assertLess(sparse["cred_w"], mature["cred_w"])

    # 4. Golden test B: +10sigma spike on a mature stable host STILL FIRES (fixing old inverted 1.01x miss!)
    spike_poisson = engine_mod.calculate_bayesian_gamma_posterior(
        observed=200.0,
        hist_sum=3000.0,
        active_days=30,
        hist_avg=100.0,
        hist_stddev=10.0,
    )
    self.assertEqual(spike_poisson["excess_var"], 0.0)  # B-E10: no double-counting of mu!
    self.assertGreaterEqual(spike_poisson["bayesian_z"], 9.5)

    spike_overdisp = engine_mod.calculate_bayesian_gamma_posterior(
        observed=350.0,
        hist_sum=3000.0,
        active_days=30,
        hist_avg=100.0,
        hist_stddev=25.0,
    )
    self.assertGreater(spike_overdisp["excess_var"], 400.0)
    self.assertGreaterEqual(spike_overdisp["bayesian_z"], 9.5)

    # High-volume nominal host on an average day must NOT false-alert under default weak prior
    nominal_busy = engine_mod.calculate_bayesian_gamma_posterior(
        observed=10000.0,
        hist_sum=300000.0,
        active_days=30,
        hist_avg=10000.0,
        hist_stddev=100.0,
    )
    self.assertLess(abs(nominal_busy["bayesian_z"]), 1.0)

  def test_ws3_beta_binomial_paired_metrics_and_golden_alerts(self):
    """WS3-BETA-BINOMIAL: Pairs *_fail/*_total in Stage 1, fits fleet Beta(a0,b0), and verifies 1/1 vs 15/20 golden alerts."""
    from scripts.preflight_validator import METRIC_CATALOG, MalachiteASTValidator
    from scripts.statistical_validator import StatisticalAntipatternAuditor
    from scripts.template_router import fit_beta_prior_from_fleet, resolve_beta_binomial_pair
    import scripts.ueba_hybrid_engine as engine_mod

    paired_prefixes = (
        "auth_attempts_",
        "dns_queries_",
        "http_queries_",
        "file_executions_",
        "resource_creation_",
        "resource_deletion_",
        "resource_read_",
        "resource_written_",
    )
    paired_count = 0
    unpaired_count = 0
    for mname, mdef in METRIC_CATALOG.items():
      ent = mdef.supported_entity_types[0]
      if mname.startswith(paired_prefixes):
        paired_count += 1
        fail_m, total_m = resolve_beta_binomial_pair(mname)
        self.assertTrue(fail_m.endswith("_fail"))
        self.assertTrue(total_m.endswith("_total"))
        q = self.router.build_query(
            target_metric=mname,
            entity_type=ent,
            statistical_model=StatisticalModel.BAYESIAN_BETA_BINOMIAL,
        )
        self.assertIn("$obs_total = count(metadata.id)", q)
        self.assertIn("$obs_fail = sum(if(", q)
        self.assertIn(f"metrics.{fail_m}(", q)
        self.assertIn(f"metrics.{total_m}(", q)
        self.assertIn("$beta_binomial_z = ($obs_fail - $pred_mean) / $safe_pred_sd", q)
        self.assertEqual(MalachiteASTValidator.validate_query(q), [], mname)
        self.assertEqual(MalachiteASTValidator.validate_model_concordance(q, StatisticalModel.BAYESIAN_BETA_BINOMIAL), [], mname)
        violations = StatisticalAntipatternAuditor.audit_query(q)
        if mname.startswith("resource_"):
          violations = [v for v in violations if v.antipattern.name != "UNPROFILED_SERVICE_ACCOUNT"]
        self.assertEqual(violations, [], mname)
      else:
        unpaired_count += 1
        with self.assertRaisesRegex(ValueError, r"BAYESIAN_BETA_BINOMIAL.*paired|unpaired|_fail"):
          self.router.build_query(
              target_metric=mname,
              entity_type=ent,
              statistical_model=StatisticalModel.BAYESIAN_BETA_BINOMIAL,
          )
    self.assertEqual(paired_count, 24)
    self.assertEqual(unpaired_count, 14)

    # Empirical Bayes fleet Beta(alpha0, beta0) moment-matching fit
    fleet_rows = [
        {"hist_fail_sum": f, "hist_total_sum": 1000.0}
        for f in (30.0, 45.0, 50.0, 55.0, 70.0, 40.0, 60.0, 50.0, 35.0, 65.0)
    ]
    a0, b0 = fit_beta_prior_from_fleet(fleet_rows)
    self.assertGreater(a0, 0.5)
    self.assertGreater(b0, 10.0)
    self.assertAlmostEqual(a0 / (a0 + b0), 0.05, places=2)

    q_fleet = self.router.build_query(
        target_metric="auth_attempts_fail",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.BAYESIAN_BETA_BINOMIAL,
        fleet_prior_payload=fleet_rows,
    )
    self.assertIn(f"$alpha_pre = {a0} + $hist_fail_sum", q_fleet)
    self.assertIn(f"$beta_pre = {b0} + $hist_succ_sum", q_fleet)

    # Golden Test 1: 1 failure out of 1 attempt -> shrinks toward 5% prior, Z = 1.90 < 3.0 (DOES NOT ALERT)
    one_of_one = engine_mod.calculate_beta_binomial_posterior(
        obs_fail=1.0,
        obs_total=1.0,
        hist_fail_sum=0.0,
        hist_total_sum=0.0,
        prior_alpha0=1.0,
        prior_beta0=19.0,
    )
    self.assertAlmostEqual(one_of_one["posterior_fail_rate"], 2.0 / 21.0, places=4)
    self.assertAlmostEqual(one_of_one["beta_binomial_z"], 1.90, places=2)
    self.assertLess(one_of_one["beta_binomial_z"], 3.0)

    # Golden Test 2: 15 failures out of 20 attempts -> Z = 10.41 >= 3.0 (ALERTS)
    real_surge = engine_mod.calculate_beta_binomial_posterior(
        obs_fail=15.0,
        obs_total=20.0,
        hist_fail_sum=0.0,
        hist_total_sum=0.0,
        prior_alpha0=1.0,
        prior_beta0=19.0,
    )
    self.assertAlmostEqual(real_surge["posterior_fail_rate"], 0.40, places=4)
    self.assertGreaterEqual(real_surge["beta_binomial_z"], 3.0)
    self.assertGreater(real_surge["beta_binomial_z"], 10.0)

    # Golden Test 3: Mature entity with 2% baseline (6 / 300) surging to 12 / 20 today -> ALERTS
    mature_surge = engine_mod.calculate_beta_binomial_posterior(
        obs_fail=12.0,
        obs_total=20.0,
        hist_fail_sum=6.0,
        hist_total_sum=300.0,
        prior_alpha0=1.0,
        prior_beta0=19.0,
    )
    self.assertGreaterEqual(mature_surge["beta_binomial_z"], 3.0)

  def test_ws3_cusum_windowed_slack_sum_and_site_dc_maturity_guard(self):
    """WS3-CUSUM: Names in-query sum Windowed Slack Sum and zeros/blocks immature entities (SITE-DC$)."""
    from pathlib import Path
    from scripts.preflight_validator import DEFAULT_SIGNIFICANCE_GATES, MalachiteASTValidator
    import scripts.ueba_hybrid_engine as engine_mod

    self.assertIn("Windowed Slack Sum", DEFAULT_SIGNIFICANCE_GATES[StatisticalModel.LONGITUDINAL_CUSUM])
    self.assertIn("Windowed Slack Sum", MultiStageTemplateRouter.MODEL_DESCRIPTIONS[StatisticalModel.LONGITUDINAL_CUSUM])

    q = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.LONGITUDINAL_CUSUM,
    )
    self.assertIn("Windowed Slack Sum", q)
    self.assertIn("$daily_excess = if($active_days >= 7 and $z_minus_slack > 0, $z_minus_slack, 0.0)", q)
    self.assertIn("$windowed_slack_sum = $cusum_drift", q)
    self.assertIn("$active_days >= 7 and $cusum_drift_score >= 3.0 and $drift_days >= 2", q)
    self.assertEqual(MalachiteASTValidator.validate_query(q), [])
    self.assertEqual(MalachiteASTValidator.validate_model_concordance(q, StatisticalModel.LONGITUDINAL_CUSUM), [])

    repo_root = Path(__file__).resolve().parent.parent
    pipe_2stage = (repo_root / "templates" / "pipelines" / "longitudinal_cusum_2stage.yl2").read_text(encoding="utf-8")
    self.assertIn("Windowed Slack Sum", pipe_2stage)
    self.assertIn("$daily_excess = if($historical_active_days >= {{min_baseline_days}} and $deviation > 0.0, $deviation, 0.0)", pipe_2stage)
    self.assertIn("$windowed_slack_sum = $cusum_drift", pipe_2stage)
    self.assertIn("$active_days >= {{min_baseline_days}} and $cusum_drift_score >= {{anomaly_threshold}} and $drift_days >= 2", pipe_2stage)

    # Golden SITE-DC$ cold-start maturity reproduction (active_days=0 and active_days=2): zero slack & blocked
    for immature_n in (0, 2):
      site_dc = engine_mod.calculate_windowed_slack_sum(
          daily_observations=[8622, 8100, 7900, 7800, 7700, 7600, 7500, 7700, 7657],
          hist_avg=0.0,
          hist_stddev=0.0,
          active_days=immature_n,
      )
      self.assertEqual(site_dc["windowed_slack_sum"], 0.0)
      self.assertEqual(site_dc["drift_days"], 0)
      self.assertFalse(site_dc["alerts"])

    # Mature creeping drift (4 days at +1.5 sigma -> daily excess 1.0 -> W = 4.0 >= 3.0 across 4 drift days)
    creeping = engine_mod.calculate_windowed_slack_sum(
        daily_observations=[115.0, 115.0, 115.0, 115.0],
        hist_avg=100.0,
        hist_stddev=10.0,
        active_days=20,
    )
    self.assertAlmostEqual(creeping["windowed_slack_sum"], 4.0, places=4)
    self.assertEqual(creeping["drift_days"], 4)
    self.assertTrue(creeping["alerts"])

  def test_ws3_hurdle_awakening_volume_hist_max_and_maya_goodman_ranking(self):
    """WS3-HURDLE: Dormant branch requires min_awakening_volume & > hist_max; maya.goodman scores 0 below charles.hardy."""
    from scripts.preflight_validator import MalachiteASTValidator
    from scripts.statistical_validator import StatisticalAntipatternAuditor
    import scripts.ueba_hybrid_engine as engine_mod

    q_default = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.TWO_PART_HURDLE,
    )
    self.assertIn("$hist_max = max($stage1_extract.historical_max)", q_default)
    self.assertIn("$dormant_days = 30.0 - $active_days", q_default)
    self.assertIn("$is_dormant_awakening = if($active_days < 7 and $observed >= 25 and $observed > $hist_max, 1.0, 0.0)", q_default)
    self.assertIn("$intensity_z = if($raw_z > 0.0, $raw_z, 0.0)", q_default)
    self.assertIn("$hurdle_threat_score = if($active_days < 7, $dormant_score, $intensity_z)", q_default)
    self.assertEqual(MultiStageTemplateRouter.root_condition(q_default), "$hurdle_threat_score >= 3.0")
    self.assertEqual(MalachiteASTValidator.validate_query(q_default), [])
    self.assertEqual(MalachiteASTValidator.validate_model_concordance(q_default, StatisticalModel.TWO_PART_HURDLE), [])
    self.assertEqual(StatisticalAntipatternAuditor.audit_query(q_default), [])

    # Custom min_awakening_volume slot override via router & compile_hunt_pipeline
    q_custom = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.TWO_PART_HURDLE,
        min_awakening_volume=50,
    )
    self.assertIn("$observed >= 50 and $observed > $hist_max", q_custom)
    compiled = engine_mod.compile_hunt_pipeline(
        statistical_model="TWO_PART_HURDLE",
        metrics="auth_attempts_total",
        entity_type="USER",
        min_awakening_volume=40,
    )
    self.assertTrue(compiled["ast_valid"])
    self.assertIn("$observed >= 40 and $observed > $hist_max", compiled["compiled_query"])

    # V-live maya.goodman (obs=4, n=2, hist_avg=50.5, hist_sd=65.76, hist_max=97) vs charles.hardy (obs=785, n=10, avg=164.6, sd=114.49, max=350)
    maya_score = engine_mod.calculate_two_part_hurdle(
        observed_val=4.0,
        baseline_mean=50.5,
        baseline_stddev=65.76,
        active_days=2,
        hist_max=97.0,
    )
    charles_score = engine_mod.calculate_two_part_hurdle(
        observed_val=785.0,
        baseline_mean=164.6,
        baseline_stddev=114.49,
        active_days=10,
        hist_max=350.0,
    )
    self.assertEqual(maya_score, 0.0)
    self.assertGreater(charles_score, 5.4)
    self.assertGreater(charles_score, maya_score)

    # Active entity with negative Z is rectified to 0.0
    neg_active = engine_mod.calculate_two_part_hurdle(
        observed_val=50.0,
        baseline_mean=100.0,
        baseline_stddev=15.0,
        active_days=20,
        hist_max=140.0,
    )
    self.assertEqual(neg_active, 0.0)

    # Genuine dormant awakening (obs=50 >= 25 and obs=50 > hist_max=10, n=2) alerts (>= 3.0) + supports optional last_seen dormancy
    awaken_details = engine_mod.calculate_two_part_hurdle_details(
        observed_val=50.0,
        baseline_mean=10.0,
        baseline_stddev=0.0,
        active_days=2,
        hist_max=10.0,
        last_seen_seconds=1700000000.0,
        eval_timestamp_seconds=1700000000.0 + 18.0 * 86400.0,
    )
    self.assertTrue(awaken_details["is_dormant_awakening"])
    self.assertGreaterEqual(awaken_details["hurdle_threat_score"], 3.0)
    self.assertAlmostEqual(awaken_details["dormant_days"], 18.0, places=4)
    self.assertFalse(awaken_details["is_true_sigma"])

    # Dossier ranking: hurdle_threat_score is NOT formatted with sigma and charles.hardy ranks above maya.goodman
    dossier = engine_mod.render_forensic_dossier(
        rows=[
            {"entity": "maya.goodman", "observed": 4, "hist_avg": 50.5, "hist_stddev": 65.76, "active_days": 2, "hurdle_threat_score": maya_score},
            {"entity": "charles.hardy", "observed": 785, "hist_avg": 164.6, "hist_stddev": 114.49, "active_days": 10, "hurdle_threat_score": charles_score},
        ],
        executed_query=q_default,
        statistical_model="TWO_PART_HURDLE",
        metric_name="auth_attempts_total",
        entity_type="USER",
    )
    self.assertEqual(dossier["outliers"][0]["entity"], "charles.hardy")
    self.assertFalse(dossier["outliers"][0]["is_true_sigma"])
    self.assertNotIn("σ", dossier["outliers"][0]["score_display"])

  def test_ws3_adaptive_context_schedule_and_golden_alerts(self):
    """WS3-ADAPTIVE (D1c): off-hours/weekend schedule in {{tenant_tz}}, 1.75σ/3.0σ gates, Z-equivalent adaptive_z, and WS5-HOD learned hours."""
    from scripts.preflight_validator import MalachiteASTValidator
    from scripts.ueba_constants import cri_from_model_score
    from scripts import ueba_hybrid_engine as engine_mod

    # 1. Default UTC Mon-Fri 08:00-18:00 schedule + concordance 1.75 / 3.0 gates + adaptive_z
    q_default = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD,
    )
    self.assertIn('$hour = timestamp.get_hour(metadata.event_timestamp.seconds, "UTC")', q_default)
    self.assertIn('$dow = timestamp.get_day_of_week(metadata.event_timestamp.seconds, "UTC")', q_default)
    self.assertIn("$dow >= 2 and $dow <= 6 and $hour >= 8 and $hour < 18", q_default)
    self.assertIn("$off_hours_obs = sum(if($dow >= 2 and $dow <= 6 and $hour >= 8 and $hour < 18, 0, 1))", q_default)
    self.assertIn("$effective_gate = if($off_hours_share >= 0.5, 1.75, 3.0)", q_default)
    self.assertIn("$adaptive_z = ($personal_z * 3.0) / $effective_gate", q_default)
    self.assertEqual(
        MultiStageTemplateRouter.root_condition(q_default),
        "$active_days >= 7 and $adaptive_z >= 3.0",
    )
    self.assertIn("order:\n  $adaptive_z desc", q_default)
    self.assertNotIn("$sparse_threshold", q_default)

    # 2. All 5 Stage-1 $observed_val shapes pass AST, concordance, and antipattern checks
    shape_metrics = [
        ("auth_attempts_total", EntityType.USER),
        ("network_bytes_outbound", EntityType.ASSET),
        ("network_bytes_inbound", EntityType.ASSET),
        ("network_bytes_total", EntityType.ASSET),
        ("workspace_network_bytes_total", EntityType.USER),
    ]
    for metric_name, ent_type in shape_metrics:
      with self.subTest(metric=metric_name):
        q_shape = self.router.build_query(
            target_metric=metric_name,
            entity_type=ent_type,
            statistical_model=StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD,
            tenant_tz="America/Los_Angeles",
            biz_start_hour=9,
            biz_end_hour=17,
        )
        self.assertIn('"America/Los_Angeles"', q_shape)
        self.assertIn("$hour >= 9 and $hour < 17", q_shape)
        self.assertEqual(MalachiteASTValidator.validate_query(q_shape), [])
        self.assertEqual(
            MalachiteASTValidator.validate_model_concordance(q_shape, StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD),
            [],
        )
        self.assertEqual(StatisticalAntipatternAuditor.audit_query(q_shape), [])

    # 3. Per-entity learned active hours from WS5-HOD (HOUR_OF_DAY_PROFILE) via compile_hunt_pipeline
    compiled_hod = engine_mod.compile_hunt_pipeline(
        statistical_model="ADAPTIVE_CONTEXT_THRESHOLD",
        metrics="auth_attempts_total",
        entity_type="USER",
        tenant_tz="America/New_York",
        learned_active_hours=[8, 9, 10, 11, 12, 13, 14, 15, 16],
    )
    self.assertTrue(compiled_hod["ast_valid"], compiled_hod["ast_errors"])
    self.assertEqual(compiled_hod["statistical_violations"], [])
    self.assertIn('"America/New_York"', compiled_hod["compiled_query"])
    self.assertIn("$hour >= 8 and $hour <= 16", compiled_hod["compiled_query"])
    self.assertNotIn("$dow >= 2", compiled_hod["compiled_query"])

    # 4. Golden alerts: off-hours 2.0σ alerts (CRI >= 50, NOT 14); identical 2.0σ in business hours does not alert
    off_hours_res = engine_mod.calculate_adaptive_context_z(
        observed=120.0,
        hist_avg=100.0,
        hist_stddev=10.0,
        active_days=20,
        event_hour=2,
        event_dow=7,  # Saturday 02:00
    )
    self.assertAlmostEqual(off_hours_res["personal_z"], 2.0, places=4)
    self.assertEqual(off_hours_res["effective_gate"], 1.75)
    self.assertAlmostEqual(off_hours_res["adaptive_z"], round(2.0 * 3.0 / 1.75, 4), places=4)
    self.assertTrue(off_hours_res["alerts"])
    self.assertGreaterEqual(cri_from_model_score("adaptive_z", off_hours_res["adaptive_z"]), 50)

    in_hours_res = engine_mod.calculate_adaptive_context_z(
        observed=120.0,
        hist_avg=100.0,
        hist_stddev=10.0,
        active_days=20,
        event_hour=10,
        event_dow=3,  # Tuesday 10:00
    )
    self.assertAlmostEqual(in_hours_res["personal_z"], 2.0, places=4)
    self.assertEqual(in_hours_res["effective_gate"], 3.0)
    self.assertAlmostEqual(in_hours_res["adaptive_z"], 2.0, places=4)
    self.assertFalse(in_hours_res["alerts"])

    # 5. Learned night-shift schedule [22, 23, 0, 1, 2, 3]: 02:00 is normal (no alert at 2.0σ), 14:00 is off-schedule (alerts at 2.0σ)
    night_in_sched = engine_mod.calculate_adaptive_context_z(
        observed=120.0,
        hist_avg=100.0,
        hist_stddev=10.0,
        active_days=20,
        event_hour=2,
        event_dow=7,
        learned_active_hours=[22, 23, 0, 1, 2, 3],
    )
    self.assertEqual(night_in_sched["effective_gate"], 3.0)
    self.assertFalse(night_in_sched["alerts"])

    night_off_sched = engine_mod.calculate_adaptive_context_z(
        observed=120.0,
        hist_avg=100.0,
        hist_stddev=10.0,
        active_days=20,
        event_hour=14,
        event_dow=3,
        learned_active_hours=[22, 23, 0, 1, 2, 3],
    )
    self.assertEqual(night_off_sched["effective_gate"], 1.75)
    self.assertTrue(night_off_sched["alerts"])

    # 6. Negative / zero Z yields CRI 0 and never alerts
    quiet_res = engine_mod.calculate_adaptive_context_z(
        observed=80.0,
        hist_avg=100.0,
        hist_stddev=10.0,
        active_days=20,
        event_hour=2,
        event_dow=1,
    )
    self.assertLess(quiet_res["adaptive_z"], 0.0)
    self.assertFalse(quiet_res["alerts"])
    self.assertEqual(cri_from_model_score("adaptive_z", quiet_res["adaptive_z"]), 0)

  def test_ws4_d1_outbound_flow_surge_cusum_macd_and_orthogonal_retirement(self):
    """WS4-D1: Outbound flow surge rename + single scan, CUSUM 2stage h=4.0/NO-GATE & byte floor, MACD linear Z, and D1 orthogonal retirement."""
    import re
    from scripts.preflight_validator import MalachiteASTValidator
    import scripts.ueba_hybrid_engine as engine_mod

    repo_root = Path(__file__).resolve().parent.parent

    # 1. c2_beacon_flow_frequency_2stage.yl2 renamed to Outbound Flow Surge, single UDM scan, active_days >= 7, continuous Poisson floor
    flow_tpl = (repo_root / "templates" / "pipelines" / "c2_beacon_flow_frequency_2stage.yl2").read_text(encoding="utf-8")
    self.assertIn("OUTBOUND FLOW SURGE", flow_tpl.upper())
    self.assertNotIn("stage2_target_dispersion", flow_tpl)
    self.assertEqual(len(re.findall(r"^stage\s+\w+\s*\{", flow_tpl, re.M)), 1)
    self.assertIn("$dispersion_floor = math.sqrt(if($hist_flow_avg > 1.0, $hist_flow_avg, 1.0))", flow_tpl)
    self.assertIn("$active_days >= 7", flow_tpl)
    self.assertIn("$flow_surge_score = $flow_z", flow_tpl)
    self.assertEqual(MalachiteASTValidator.validate_query(flow_tpl), [])

    res_flow = engine_mod.compile_hunt_pipeline(
        architecture="outbound_flow_surge",
        metrics="network_flows_outbound",
        entity_type="ASSET",
        entity_value="srv-01",
    )
    self.assertTrue(res_flow["ast_valid"], res_flow["ast_errors"])
    self.assertEqual(res_flow["architecture"], "OUTBOUND_FLOW_SURGE_2STAGE")

    # 2. longitudinal_cusum_2stage.yl2 via build_longitudinal_cusum_pipeline_query:
    #    default cusum_h_threshold = 4.0, byte vs count dispersion floor, and NO-GATE prefilter mode.
    cusum_bytes = self.router.build_longitudinal_cusum_pipeline_query(
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
    )
    self.assertIn("Windowed Slack Sum", cusum_bytes)
    self.assertIn("$dispersion_floor = 44979.0", cusum_bytes)
    self.assertIn("$active_days >= 7 and $cusum_drift_score >= 4.0 and $drift_days >= 2", cusum_bytes)
    self.assertEqual(MalachiteASTValidator.validate_query(cusum_bytes), [])

    cusum_counts_nogate = self.router.build_longitudinal_cusum_pipeline_query(
        target_metric="dns_queries_total",
        entity_type=EntityType.ASSET,
        include_significance_gate=False,
    )
    self.assertIn("$dispersion_floor = math.sqrt(if($historical_avg > 1.0, $historical_avg, 1.0))", cusum_counts_nogate)
    self.assertIn("// Significance Gate: NONE", cusum_counts_nogate)
    self.assertIsNone(MultiStageTemplateRouter.root_condition(cusum_counts_nogate))
    self.assertEqual(MalachiteASTValidator.validate_query(cusum_counts_nogate), [])

    # 3. macd_momentum_velocity_2stage.yl2: above-historical-max Z naming, linear math, active_days >= 7, byte/count floor
    macd_bytes = self.router.build_pipeline_query(
        PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE,
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
    )
    self.assertIn("ABOVE-HISTORICAL-MAX Z", macd_bytes.upper())
    self.assertIn("$dispersion_floor = 44979.0", macd_bytes)
    self.assertIn("$macd_z = $personal_z + $above_max_z", macd_bytes)
    self.assertIn("$active_days >= 7 and $macd_z >= 3.0", macd_bytes)
    self.assertEqual(MalachiteASTValidator.validate_query(macd_bytes), [])


if __name__ == "__main__":
  unittest.main()


