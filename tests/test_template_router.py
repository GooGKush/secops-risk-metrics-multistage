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
    """build_c2_beacon_flow_query and build_alert_surge_query must render valid multi-stage queries."""
    from scripts.preflight_validator import MalachiteASTValidator
    for flow_metric in ("network_flows_outbound", "network_flows_inbound", "network_flows_total"):
      for et in (EntityType.ASSET, EntityType.USER):
        q = self.router.build_c2_beacon_flow_query(target_metric=flow_metric, entity_type=et)
        self.assertIn(f"metrics.{flow_metric}(", q)
        self.assertIn("$beacon_score =", q)
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

    for metric_name, ent_type, expected_tuple in composite_cases:
      for model in StatisticalModel:
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
            elif model == StatisticalModel.FLEET_PREVALENCE_SHIELD:
              # Cross-sectional fleet wave stage must stay fleet-wide ($day_ws by 1d)
              self.assertIn("stage stage2_fleet_wave {\n    $day_ws = $stage1_extract.window_start\n\n  match:\n    $day_ws by 1d", clean)
              expected_root = f"{expected_tuple}, $ws by 1d" if mode == MatchMode.TIMELINE_BREAKDOWN else expected_tuple
              self.assertEqual(root_keys, expected_root)
            elif model == StatisticalModel.CIRCADIAN_VON_MISES:
              self.assertIn(f"match:\n    {expected_tuple} by 1h", clean)
              expected_root = f"{expected_tuple}, $ws by 1h" if mode == MatchMode.TIMELINE_BREAKDOWN else expected_tuple
              self.assertEqual(root_keys, expected_root)
            elif model == StatisticalModel.HOURLY_TEMPORAL_ZSCORE:
              expected_root = f"{expected_tuple}, $ws by 1h" if mode == MatchMode.TIMELINE_BREAKDOWN else expected_tuple
              self.assertEqual(root_keys, expected_root)
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


if __name__ == "__main__":
  unittest.main()


