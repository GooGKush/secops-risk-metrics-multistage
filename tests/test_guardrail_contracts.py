"""Unit tests asserting the presence and strict enforcement of the Hard Stop on API Error
and Zero Python Simulation guardrail contracts in secops-risk-metrics-multistage.

Author: Greg Kushmerek
"""

import json
import os
import unittest


class TestGuardrailContracts(unittest.TestCase):

  def setUp(self):
    self.skill_md_path = '/usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/SKILL.md'
    self.assertTrue(os.path.exists(self.skill_md_path), "SKILL.md must exist")
    with open(self.skill_md_path, 'r', encoding='utf-8') as f:
      self.skill_content = f.read()

  def test_hard_stop_on_api_error_contract_present(self):
    """SKILL.md must explicitly contain the Hard Stop on API Error and zero silent fallback contract."""
    self.assertIn(
        "Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)",
        self.skill_content,
        "SKILL.md must define the Hard Stop on API Error contract."
    )
    self.assertIn(
        "STRICTLY PROHIBITED",
        self.skill_content,
        "SKILL.md must strictly prohibit silent local simulation."
    )

  def test_zero_python_simulation_contract_present(self):
    """SKILL.md must explicitly prohibit writing scratch Python scripts to simulate SIEM baselines."""
    self.assertIn(
        "Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)",
        self.skill_content,
        "SKILL.md must define the Native Execution Guarantee prohibiting Python simulation."
    )
    self.assertIn(
        "CRITICAL COMPLIANCE VIOLATION",
        self.skill_content,
        "SKILL.md must define local arithmetic simulation as a critical compliance violation."
    )

  def test_literal_query_display_mandate_present(self):
    """SKILL.md must enforce that Section 2 contains the literal query passed to udm_search."""
    self.assertIn(
        "Literal Query Display Mandate (ZERO FAKED YARA-L QUERIES)",
        self.skill_content,
        "SKILL.md must enforce literal query display."
    )

  def test_evals_contain_zero_simulation_scenario(self):
    """evals.json must define an evaluation scenario for handling API errors with clean stop rather than Python simulation."""
    evals_path = '/usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/evals/evals.json'
    self.assertTrue(os.path.exists(evals_path), "evals.json must exist")
    with open(evals_path, 'r', encoding='utf-8') as f:
      evals_data = json.load(f)
    
    eval_list = evals_data.get("evals", [])
    eval_names = [e.get("name", "") for e in eval_list]
    self.assertTrue(
        any("api_error" in name or "zero_simulation" in name for name in eval_names),
        f"evals.json must include a scenario testing zero simulation on API error. Found: {eval_names}"
    )


  def test_postflight_auditor_flags_raw_event_dump_and_remediates(self):
    """PostFlightExecutionAuditor must detect raw log dumps and generate canonical retry queries."""
    import sys
    sys.path.insert(0, '/usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage')
    from scripts.preflight_validator import PostFlightExecutionAuditor, AuditStatus, EntityType, StatisticalModel

    raw_event_payload = {"events": [{"name": f"ev-{i}", "udm": {"metadata": {"eventType": "USER_LOGIN"}}} for i in range(50)]}
    non_metrics_query = "metadata.event_type = \"USER_LOGIN\" AND principal.user.userid = \"frank\""

    audit = PostFlightExecutionAuditor.audit_execution(
        executed_query=non_metrics_query,
        api_response=raw_event_payload,
        target_metric="auth_attempts_fail",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.STANDARD_Z_SCORE,
    )

    self.assertEqual(audit.status, AuditStatus.RETRY_REQUIRED)
    self.assertFalse(audit.is_valid)
    self.assertTrue(any("RAW_LOG_DUMP_DETECTED" in e for e in audit.errors))
    self.assertTrue(any("NO_METRICS_FUNCTION" in e for e in audit.errors))
    self.assertIsNotNone(audit.recommended_query)
    self.assertIn("metrics.auth_attempts_fail", audit.recommended_query)

  def test_postflight_auditor_passes_valid_metrics_query(self):
    """PostFlightExecutionAuditor must approve valid native multi-stage Risk Metrics executions."""
    import sys
    sys.path.insert(0, '/usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage')
    from scripts.preflight_validator import PostFlightExecutionAuditor, AuditStatus

    valid_query = (
        "// Goal: Hunt for anomalous failed logins\n"
        "// Statistical Model: Standard Z-Score\n"
        "stage s1 {\n"
        "  metadata.event_type = \"USER_LOGIN\"\n"
        "  principal.user.userid = $u\n"
        "  match: $u by 1d\n"
        "  outcome:\n"
        "    $obs = count(metadata.id)\n"
        "    $avg = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: $u))\n"
        "    $std = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: $u))\n"
        "}\n"
        "$u = $s1.u\n"
        "match: $u by 1d\n"
        "outcome:\n"
        "  $diff = $s1.obs - $s1.avg\n"
        "  $z = $diff / $s1.std\n"
        "condition:\n"
        "  $z >= 3\n"
    )
    valid_api_response = {"stats": {"results": [{"column": "u", "values": []}]}}

    audit = PostFlightExecutionAuditor.audit_execution(
        executed_query=valid_query,
        api_response=valid_api_response,
    )
    self.assertEqual(audit.status, AuditStatus.PASSED)
    self.assertTrue(audit.is_valid)
    self.assertEqual(len(audit.errors), 0)

  def test_postflight_auditor_rejects_hallucinated_metric_name(self):
    """PostFlightExecutionAuditor must catch non-existent metric tables."""
    import sys
    sys.path.insert(0, '/usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage')
    from scripts.preflight_validator import PostFlightExecutionAuditor

    fake_metric_query = (
        "stage s1 {\n"
        "  metadata.event_type = \"USER_LOGIN\"\n"
        "  principal.user.userid = $u\n"
        "  match: $u by 1d\n"
        "  outcome:\n"
        "    $avg = max(metrics.fake_hallucinated_metric(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: $u))\n"
        "}\n"
        "$u = $s1.u\n"
        "match: $u by 1d\n"
        "condition: true\n"
    )
    audit = PostFlightExecutionAuditor.audit_execution(
        executed_query=fake_metric_query,
        api_response={"stats": {"results": []}},
    )
    self.assertFalse(audit.is_valid)
    self.assertTrue(any("ANTI-PATTERN 7" in e for e in audit.errors))

  def test_formatter_prompts_user_to_retry_or_exit_on_audit_failure(self):
    """CommonMarkTriageFormatter must ask user whether to retry or exit on audit failure."""
    import sys
    sys.path.insert(0, '/usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage')
    from scripts.preflight_validator import AuditStatus, PostFlightAuditResult
    from scripts.triage_formatter import CommonMarkTriageFormatter

    audit_fail = PostFlightAuditResult(
        status=AuditStatus.RETRY_REQUIRED,
        is_valid=False,
        errors=["NO_METRICS_FUNCTION: Raw query attempted without metrics.*"],
        recommended_query="// Auto-generated canonical query\nstage s1 { ... }",
        remediation_action="Generated canonical query",
    )
    report = CommonMarkTriageFormatter.format_report(
        reduced_data={},
        target_metric="auth_attempts_fail",
        statistical_model="Standard Z-Score",
        anomaly_threshold=3.0,
        audit_result=audit_fail,
    )
    self.assertIn("### 🔄 POST-FLIGHT AUDIT: AUTO-CORRECTED CANONICAL QUERY READY", report)
    self.assertIn("Would you like me to execute this auto-corrected query now, or exit this hunt?", report)


  def test_search_only_prohibits_rule_deployment_tools(self):
    """SKILL.md must strictly prohibit calling create_rule or validate_rule during threat hunting."""
    self.assertIn("Pure Threat Hunting Scope (SEARCH-ONLY — ZERO RULE CREATION / DEPLOYMENT)", self.skill_content)
    self.assertIn("create_rule", self.skill_content)
    self.assertIn("validate_rule", self.skill_content)
    self.assertIn("STRICTLY PROHIBITED", self.skill_content)

  def test_bidirectional_steering_and_handoff_protocol(self):
    """SKILL.md must define the bi-directional steering protocol and handoff to secops-statistical-hunter."""
    self.assertIn("Bi-Directional Skill Steering & Handoff Protocol", self.skill_content)
    self.assertIn("secops-statistical-hunter", self.skill_content)
    self.assertIn("Skill Handoff Card", self.skill_content)
    self.assertIn("Non-Metrics Telemetry Steering Mandate", self.skill_content)

  def test_evaluation_modes_distinguish_snapshot_and_timeline(self):
    """SKILL.md must explicitly distinguish between 24h Snapshot Mode and 30-Day Longitudinal Timeline Mode."""
    self.assertIn("Evaluation Modes: Snapshot vs. 30-Day Longitudinal Sliding Timeline", self.skill_content)
    self.assertIn("Mode A: Current-Day Snapshot", self.skill_content)
    self.assertIn("Mode B: 30-Day Longitudinal Sliding Timeline", self.skill_content)
  def test_zero_gratuitous_entity_graph_injection_contract(self):
    """SKILL.md must strictly mandate that Entity Graph constructs are on-demand or algorithmically grounded only."""
    self.assertIn("Zero Gratuitous Entity Graph Injection (ON-DEMAND / ALGORITHMIC GROUNDING ONLY)", self.skill_content)
    self.assertIn("NEVER be injected gratuitously or speculatively", self.skill_content)
    self.assertIn("Direct Customer Request (On-Demand)", self.skill_content)
    self.assertIn("Algorithmic Grounding", self.skill_content)

  def test_atomic_pipeline_execution_mandate(self):
    """SKILL.md must strictly mandate that multi-sector pipelines are executed atomically without piecemeal fracturing."""
    self.assertIn("Atomic Pipeline Execution Mandate (ZERO PIECEMEAL FRACTURING & DRIFT)", self.skill_content)
    self.assertIn("STRICTLY PROHIBITED", self.skill_content)
    self.assertIn("single atomic YARA-L query", self.skill_content)

  def test_zero_local_script_invocations_contract(self):
    """SKILL.md must prohibit running local python validation scripts via terminal during chat."""
    self.assertIn("Zero Local Script Invocations During Hunting", self.skill_content)
    self.assertIn("ZERO RUN_COMMAND VALIDATION", self.skill_content)

  def test_hermetic_skill_boundary_contract(self):
    """SKILL.md must enforce hermetic skill execution with zero cross-skill reading."""
    self.assertIn("Hermetic Skill Boundary (ZERO CROSS-SKILL DRIFT)", self.skill_content)
    self.assertIn("100% self-contained", self.skill_content)

  def test_inner_join_drop_prevention_contract(self):
    """SKILL.md must prevent inner-join drops when evaluating all entities including but not limited to threat domains."""
    self.assertIn("Inner-Join Drop Prevention Standard (PRESERVING FULL POPULATION)", self.skill_content)
    self.assertIn("array_distinct(target.hostname)", self.skill_content)

  def test_turn1_mandatory_query_preview_and_cohort_roster_contract(self):
    """SKILL.md must mandate query preview and cohort roster on Turn 1 prior to clearance."""
    self.assertIn("Mandatory Query Preview", self.skill_content)
    self.assertIn("Peer Cohort & Roster", self.skill_content)
    self.assertIn("Mandatory Upfront Query Preview Protocol", self.skill_content)
    self.assertIn("Peer Cohort Roster Requirement", self.skill_content)

  def test_interactive_entity_graph_rarity_discovery_contract(self):
    """SKILL.md must mandate interactive discovery and binding of Entity Graph rarity modifiers on Turn 1."""
    self.assertIn("Interactive Entity Graph Rarity & Context Discovery", self.skill_content)
    self.assertIn("Domain Rarity", self.skill_content)
    self.assertIn("Fleet Prevalence", self.skill_content)
    self.assertIn("Binary Rarity", self.skill_content)
    self.assertIn("IP Rarity", self.skill_content)

  def test_entity_graph_dimension_in_preflight_card_mandate(self):
    """SKILL.md must mandate that Entity Graph dimensions are explicitly expressed inside the Pre-Flight Card."""
    self.assertIn("• Entity Graph Dimension:", self.skill_content)
    self.assertIn("Interactive Entity Graph Dimension Mandate", self.skill_content)

  def test_prevalence_10day_platform_invariant_contract(self):
    """SKILL.md must define the 10-day prevalence platform invariant and consultative response protocol."""
    self.assertIn("10-Day Prevalence Platform Invariant", self.skill_content)
    self.assertIn("day_count = 10", self.skill_content)

  def test_clean_handoff_9_product_event_types_contract(self):
    """clean-handoff-udm-schema.md must document all 9 canonical product_event_type variants and Catch-All promotion rule."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ch_path = os.path.join(skill_dir, 'references', 'clean-handoff-udm-schema.md')
    with open(ch_path, 'r', encoding='utf-8') as f:
      ch_content = f.read()

    expected_types = [
        'VOLUMETRIC_BASELINE_ANOMALY',
        'BURST_CLUSTER_ANOMALY',
        'DISCRETE_RARITY_ANOMALY',
        'BAYESIAN_SHRINKAGE_ANOMALY',
        'PEER_COHORT_BREAKOUT_ANOMALY',
        'FLEET_NORMALIZED_DELTA_Z',
        'MULTI_SECTOR_THREAT_FUSION',
        'LONGITUDINAL_CUSUM_DRIFT',
        'ENTITY_GRAPH_RARITY_OUTLIER'
    ]
    for pet in expected_types:
      self.assertIn(pet, ch_content)

    self.assertIn("secops_risk_metrics_synthetic_alert_catchall", ch_content)
    self.assertIn("One Event Per Outlier Entity", ch_content)
    self.assertIn("Hunt Campaign ID", ch_content)

  def test_variable_role_classification_contract(self):
    """SKILL.md and multi-stage guide must define the 4 Variable Functional Roles."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      g_content = f.read()

    roles = ['[JOIN_KEY]', '[SCORING_DIMENSION]', '[ACTIVE_FILTER]', '[TRIAGE_DECORATION]']
    for role in roles:
      self.assertIn(role, s_content)
      self.assertIn(role, g_content)

  def test_anti_passive_decoration_guardrail_contract(self):
    """SKILL.md must explicitly prohibit primary threat indicators from acting solely as triage decorations."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()

    self.assertIn("Variable Role Classification & Anti-Passive-Decoration Mandate", s_content)
    self.assertIn("MUST NEVER act solely as `[TRIAGE_DECORATION]`", s_content)

  def test_threat_to_telemetry_decomposition_matrix_contract(self):
    """SKILL.md and guide must document the Threat-to-Telemetry Decomposition Matrix."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      g_content = f.read()

  def test_precomposed_pipeline_templates_exist(self):
    """All essential analytical models must have pre-composed pipeline templates in templates/pipelines/."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pipelines_dir = os.path.join(skill_dir, 'templates', 'pipelines')
    
    expected_pipelines = [
        'mad_modified_z_2stage.yl2',
        'standard_z_score_2stage.yl2',
        'poisson_rarity_2stage.yl2',
        'longitudinal_cusum_2stage.yl2',
        'dual_baseline_delta_z_3stage.yl2',
        'hierarchical_empirical_bayes_3stage.yl2',
        'multi_sector_fusion_4stage.yl2'
    ]
    for pipeline_file in expected_pipelines:
      full_path = os.path.join(pipelines_dir, pipeline_file)
      self.assertTrue(
          os.path.exists(full_path),
          f"Pre-composed pipeline template '{pipeline_file}' must exist in templates/pipelines/."
      )


  def test_consultative_vector_and_scope_discovery_protocol_contract(self):
    """SKILL.md and multi-stage guide must document the Consultative Vector & Scope Discovery Protocol."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      g_content = f.read()

    self.assertIn("Consultative Vector & Scope Discovery", s_content)
    self.assertIn("Consultative Scope & Vector Discovery", g_content)
    self.assertIn("Cloud CRUD", s_content)
    self.assertIn("Workspace", s_content)
    self.assertIn("Multi-Sector Fusion", s_content)

  def test_cti_threat_report_mapping_contract(self):
    """SKILL.md must document the direct CTI Threat Report Mapping pathway to Phase 1B."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()

    self.assertIn("CTI & Threat Report Mapping", s_content)
    self.assertIn("Transition Directly to Phase 1B", s_content)
    self.assertIn("Map to UEBA Metric Tables", s_content)

  def test_anti_auth_defaulting_guardrail_contract(self):
    """SKILL.md must explicitly prohibit defaulting to auth on open-ended inquiries."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()

    self.assertIn("Anti-Auth-Defaulting Guardrail", s_content)
    self.assertIn("MUST NOT DEFAULT TO `metrics.auth_attempts_*`", s_content)

  def test_conversational_break_mandate_contract(self):
    """SKILL.md and multi-stage guide must mandate a conversational break on Turn 1 of broad inquiries."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      g_content = f.read()

    self.assertIn("CONVERSATIONAL BREAK", s_content)
    self.assertIn("The 2-Turn Staging Mandate", g_content)
    self.assertIn("Phase 1A", s_content)
    self.assertIn("Phase 1B", s_content)

  def test_educational_execution_framework_summary_contract(self):
    """SKILL.md and statistical taxonomy must define the 3-step educational overview and Execution Framework Summary."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    tax_path = os.path.join(skill_dir, 'references', 'statistical-models-taxonomy.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()
    with open(tax_path, 'r', encoding='utf-8') as f:
      t_content = f.read()

    self.assertIn("How Risk Metrics Multi-Stage Analytics Work", s_content)
    self.assertIn("Execution Framework Summary", s_content)
    self.assertIn("Execution Framework Summary", t_content)
    self.assertIn("Ask for more information", s_content)
    self.assertIn("Ask for more information", t_content)

  def test_clean_handoff_and_anti_case_pollution_contract(self):
    """SKILL.md and clean-handoff guide must mandate synthetic UDM event preview and prohibit case comment pollution."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    ch_path = os.path.join(skill_dir, 'references', 'clean-handoff-udm-schema.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()
    with open(ch_path, 'r', encoding='utf-8') as f:
      c_content = f.read()

    self.assertIn("MANDATORY CLEAN HAND-OFF & ESCALATION PROTOCOL", s_content)
    self.assertIn("CRITICAL PROCESS POLLUTION VIOLATION", s_content)
    self.assertIn("Explicit Case Wall Attachment", s_content)
    self.assertIn("Strict Anti-Case-Comment Pollution Prohibition", c_content)
    self.assertIn("No Arbitrary Case Hijacking", c_content)
    self.assertIn("Carved-Out Active Case Exception", c_content)

  def test_query_vs_rule_nomenclature_contract(self):
    """SKILL.md and multi-stage guide must strictly prohibit calling ad-hoc query logic a 'Rule'."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      g_content = f.read()

    self.assertIn("CRITICAL NOMENCLATURE VIOLATION", s_content)
    self.assertIn("Strict Nomenclature Mandate", s_content)
    self.assertIn("Query vs. Rule Nomenclature", g_content)
    self.assertIn("Ad-Hoc & Dashboard Logic is a Query", g_content)

  def test_compiler_syntax_guardrails_contract(self):
    """SKILL.md, guide, and validator must enforce zero-hallucination compiler rules."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      g_content = f.read()

    self.assertIn("Zero-Hallucination Compiler Grammar Contract", s_content)
    self.assertIn("Max 4 Joins Invariant", s_content)
    self.assertIn("Strict Reference-List Only `in` Operator", g_content)
    self.assertIn("Strict Function-Call Metric Syntax", g_content)

    # Validate that MalachiteASTValidator catches the compiler errors from the user's report
    from scripts.preflight_validator import MalachiteASTValidator
    bad_stage = """
    stage stage_cloud {
        metadata.log_type = "GCP_CLOUDAUDIT"
        metadata.event_type in ("RESOURCE_WRITTEN", "RESOURCE_DELETION")
        principal.user.userid = $user
      match:
        $user by 24h
      outcome:
        $cloud_count = count(metadata.id)
        $cloud_mean = avg(metrics.resource_changes_24h.mean)
    }
    """
    errors = MalachiteASTValidator.validate_query(bad_stage)
    self.assertTrue(any("INVALID_IN_SYNTAX" in e for e in errors))
    self.assertTrue(any("INVALID_METRIC_DOT_NOTATION" in e for e in errors))
    self.assertTrue(any("INVALID_WINDOW_SYNTAX" in e for e in errors))

  def test_malachite_ast_validator_catches_hallucinated_constructs(self):
    """MalachiteASTValidator must detect ^, if(), sqrt(), and $var in stage_name."""
    from scripts.preflight_validator import MalachiteASTValidator
    bad_syntax = """
    stage multi_sector_fusion_outlier {
      events:
        $c in baseline_iam_creation_30d
      outcome:
        $z_create = if($c.creation_stddev > 0, ($c.daily_creations - $c.creation_mean) / $c.creation_stddev, 0)
        $composite_distance_d = sqrt(($z_create ^ 2) + 1.0)
    }
    """
    errors = MalachiteASTValidator.validate_query(bad_syntax)
    self.assertTrue(any("INVALID_EXPONENT_OPERATOR" in e for e in errors))
    self.assertTrue(any("INVALID_IF_CONDITIONAL" in e for e in errors))
    self.assertTrue(any("INVALID_SQRT_FUNCTION" in e for e in errors))
    self.assertTrue(any("INVALID_STAGE_IN_SYNTAX" in e for e in errors))
    self.assertTrue(any("INVALID_EVENTS_SECTION_IN_STAGE" in e for e in errors))


if __name__ == '__main__':
  unittest.main()







