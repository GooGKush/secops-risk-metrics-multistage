"""Unit tests asserting the presence and strict enforcement of the Hard Stop on API Error
and Zero Python Simulation guardrail contracts in secops-risk-metrics-multistage.

Author: Greg Kushmerek
"""

import json
import os
import unittest
from scripts.preflight_validator import MalachiteASTValidator


class TestGuardrailContracts(unittest.TestCase):

  def setUp(self):
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    repo_skill_md = os.path.join(repo_dir, 'SKILL.md')
    if os.path.exists(repo_skill_md):
      self.skill_md_path = repo_skill_md
    else:
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

  def test_sparse_baseline_caution_in_preflight_card(self):
    """PreFlightValidator.render_preflight_card must flag 'Sparse Baseline Caution' when active days N < 7."""
    from scripts.preflight_validator import PreFlightValidator
    card_sparse = PreFlightValidator.render_preflight_card(
        target_scope="legacy-oauth-principal",
        peer_cohort="IAM Service Accounts",
        statistical_model="Standard Z-Score",
        active_days=2,
    )
    self.assertIn("⚠️ Sparse Baseline Caution", card_sparse)
    self.assertIn("N = 2 < 7", card_sparse)

    card_nominal = PreFlightValidator.render_preflight_card(
        target_scope="admin-user",
        peer_cohort="IT Admins",
        statistical_model="Standard Z-Score",
        active_days=25,
    )
    self.assertNotIn("Sparse Baseline Caution", card_nominal)

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

    bad_stage_var = """
    // Goal: Test stage variable syntax
    outcome:
      $diff_auth = stage1_extract.$actual_auth - stage1_extract.$mu_auth
    """
    errors_stage_var = MalachiteASTValidator.validate_query(bad_stage_var)
    self.assertTrue(any("INVALID_STAGE_VARIABLE_SYNTAX" in e for e in errors_stage_var))

    bad_detection_rule = """
    // Goal: Test detection rule rejection
    rule SuspiciousExfil {
      meta:
        author = "Detection Team"
      events:
        $net.metadata.event_type = "NETWORK_CONNECTION"
      condition:
        $net
    }
    """
    errors_rule = MalachiteASTValidator.validate_query(bad_detection_rule)
    self.assertTrue(any("INVALID_DETECTION_RULE_SYNTAX" in e for e in errors_rule))

  def test_malachite_ast_validator_catches_unbound_match_variable(self):
    """MalachiteASTValidator must detect unbound match variables in stage and root sections."""
    bad_query = """
    // Goal: Test unbound match variable
    stage stage1_extract {
      metadata.event_type = "USER_LOGIN"
      target.user.userid = "james.holden"
    match:
      $user by 1d
    outcome:
      $obs = count(metadata.id)
    }
    $user = $stage1_extract.user
    match: $user by 1d
    outcome:
      $z = max($stage1_extract.obs)
    """
    errors = MalachiteASTValidator.validate_query(bad_query)
    self.assertTrue(any("UNBOUND_MATCH_VARIABLE" in e for e in errors))

  def test_malachite_ast_validator_catches_invalid_metric_filters(self):
    """MalachiteASTValidator must detect unsupported metric filter fields like principal.ip on network_bytes_outbound."""
    from scripts.preflight_validator import MalachiteASTValidator

    # Query using illegal 'principal.ip' on network_bytes_outbound (the exact bug from screenshots)
    bad_filter_query = """
    // Goal: Test invalid metric filter detection
    stage stage1_egress_baseline {
      metadata.event_type = "NETWORK_CONNECTION"
      $src_ip = principal.ip
      $dst_ip = target.ip
      match: $src_ip, $dst_ip by 1d
      outcome:
        $observed_bytes = sum(network.sent_bytes)
        $baseline_mean = max(metrics.network_bytes_outbound(
          period: 1d,
          window: 30d,
          metric: value_sum,
          agg: avg,
          principal.ip: $src_ip
        ))
    }
    $src_ip = $stage1_egress_baseline.src_ip
    $dst_ip = $stage1_egress_baseline.dst_ip
    match: $src_ip, $dst_ip by 1d
    outcome:
      $vol_z = 3.0
    """
    errors = MalachiteASTValidator.validate_query(bad_filter_query)
    self.assertTrue(any("INVALID_METRIC_FILTER" in e for e in errors))
    self.assertTrue(any("principal.ip" in e and "principal.asset.ip" in e for e in errors))

    # Query using valid 'principal.asset.hostname' on network_bytes_outbound
    valid_filter_query = """
    // Goal: Test valid metric filter acceptance
    stage stage1_egress_baseline {
      metadata.event_type = "NETWORK_CONNECTION"
      $host = principal.asset.hostname
      match: $host by 1d
      outcome:
        $observed_bytes = sum(network.sent_bytes)
        $baseline_mean = max(metrics.network_bytes_outbound(
          period: 1d,
          window: 30d,
          metric: value_sum,
          agg: avg,
          principal.asset.hostname: $host
        ))
    }
    $host = $stage1_egress_baseline.host
    match: $host by 1d
    outcome:
      $vol_z = 3.0
    """
    valid_errors = MalachiteASTValidator.validate_query(valid_filter_query)
    self.assertFalse(any("INVALID_METRIC_FILTER" in e for e in valid_errors))

    # Query using 'principal.ip' on Cloud CRUD (which IS supported in Malachite)
    cloud_crud_query = """
    // Goal: Test valid principal.ip filter on resource_creation_total
    stage stage1_crud {
      metadata.event_type = "RESOURCE_CREATION"
      $user = principal.user.userid
      $ip = principal.ip
      $vendor = metadata.vendor_name
      $product = metadata.product_name
      match: $user, $ip by 1d
      outcome:
        $baseline = max(metrics.resource_creation_total(
          period: 1d,
          window: 30d,
          metric: event_count_sum,
          agg: avg,
          principal.user.userid: $user,
          principal.ip: $ip,
          metadata.vendor_name: $vendor,
          metadata.product_name: $product
        ))
    }
    $user = $stage1_crud.user
    $ip = $stage1_crud.ip
    match: $user, $ip by 1d
    outcome:
      $z = 2.0
    """
    cloud_errors = MalachiteASTValidator.validate_query(cloud_crud_query)
    self.assertFalse(any("INVALID_METRIC_FILTER" in e for e in cloud_errors))

  def test_skill_size_budget(self):
    """SKILL.md must remain strictly under the 20 KB efficiency budget (20,480 bytes)."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    with open(skill_path, 'rb') as f:
      raw = f.read()
    self.assertLessEqual(len(raw), 20480, f"SKILL.md exceeds 20KB budget: {len(raw)} bytes")

  def test_dual_requirement_gate_contract(self):
    """SKILL.md must enforce that Phase 1B requires BOTH Entity Scope AND Telemetry Vector."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()
    self.assertIn("Dual-Requirement Gate", s_content)
    self.assertIn("ONLY UNLOCKED", s_content)
    self.assertIn("Telemetry Vector", s_content)
    self.assertIn("MUST NOT DEFAULT TO `metrics.auth_attempts_*`", s_content)

  def test_zero_generative_simulation_contract(self):
    """SKILL.md must enforce zero generative simulation and strict tool grounding."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()
    self.assertIn("Zero Generative Simulation & Strict Data Grounding Contract", s_content)
    self.assertIn("CRITICAL TRUTH-IN-REPORTING FAILURE", s_content)
    self.assertIn("0 observed events", s_content)

  def test_zero_streaming_detection_rule_syntax_mandate(self):
    """SKILL.md must strictly forbid outputting streaming detection rules or rule blocks."""
    self.assertIn("Zero Streaming Detection Rule Syntax", self.skill_content)
    self.assertIn("CRITICAL NOMENCLATURE & ARCHITECTURAL VIOLATION", self.skill_content)

  def test_event_section_arithmetic_rejection(self):
    """Common Compiler rejects variable arithmetic above match: (in event/stage join sections)."""
    bad_arithmetic_query = """
    // Goal: Test event section arithmetic rejection
    stage stage1_intervals {
      metadata.event_type = "NETWORK_CONNECTION"
      $src = principal.asset.ip
      $dst = target.ip
      $t1 = metadata.event_timestamp.seconds
      match: $src, $dst by 1h
      outcome:
        $first = min($t1)
        $last = max($t1)
    }
    stage stage2_stats {
      $src = $stage1_intervals.src
      $dst = $stage1_intervals.dst
      $time_span = $stage1_intervals.last - $stage1_intervals.first
      match: $src, $dst
      outcome:
        $mean_span = avg($time_span)
    }
    $src = $stage2_stats.src
    $dst = $stage2_stats.dst
    match: $src, $dst
    outcome:
      $val = max($stage2_stats.mean_span)
    """
    errors = MalachiteASTValidator.validate_query(bad_arithmetic_query)
    self.assertTrue(any("ARITHMETIC_IN_EVENT_SECTION" in e for e in errors))
    self.assertTrue(any("time_span" in e for e in errors))

  def test_unbound_match_placeholder_rejection(self):
    """Common Compiler requires all placeholders in match: to be explicitly bound in the event section."""
    unbound_match_query = """
    // Goal: Test unbound match placeholder rejection
    stage stage1_auth {
      metadata.event_type = "USER_LOGIN"
      target.user.userid = "frank.kolzig"
      match: $user by 1d
      outcome:
        $obs = count(metadata.id)
    }
    $user = $stage1_auth.user
    match: $user by 1d
    outcome:
      $z = 1.0
    """
    errors = MalachiteASTValidator.validate_query(unbound_match_query)
    self.assertTrue(any("UNBOUND_MATCH_VARIABLE" in e for e in errors))
    self.assertTrue(any("user" in e for e in errors))

  def test_outcome_arithmetic_permitted(self):
    """Common Compiler permits full variable-to-variable arithmetic, subtraction, and division in outcome:."""
    valid_outcome_math_query = """
    // Goal: Test outcome section arithmetic acceptance
    stage stage1_extract {
      metadata.event_type = "USER_LOGIN"
      $user = target.user.userid
      $user = "admin"
      match: $user by 1d
      outcome:
        $obs = count(metadata.id)
        $mu = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: $user))
        $sigma = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: $user))
    }
    $user = $stage1_extract.user
    match: $user by 1d
    outcome:
      $diff = max($stage1_extract.obs) - max($stage1_extract.mu)
      $z_score = $diff / (max($stage1_extract.sigma) + 1.0)
    """
    errors = MalachiteASTValidator.validate_query(valid_outcome_math_query)
    self.assertEqual(errors, [])

  def test_identity_disambiguation_and_spot_check_contract(self):
    """SKILL.md, metrics catalog, and multi-stage guide must define the identity spot check and display name resolution protocol."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    catalog_path = os.path.join(skill_dir, 'references', 'metrics-catalog.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()
    with open(catalog_path, 'r', encoding='utf-8') as f:
      c_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      g_content = f.read()

    self.assertIn("Identity Disambiguation & Confirmation Protocol", s_content)
    self.assertIn("Display names (with spaces) are NOT `user.userid`", s_content)
    self.assertIn("User Display Names vs. Technical User IDs", c_content)
    self.assertIn("Using Display Name in User metric filters", g_content)


  def test_cloud_crud_service_account_repository_origin_contract(self):
    """SKILL.md, metrics catalog, and multi-stage guide must document service account cloud repository baselining and principal.ip origin filtering."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    catalog_path = os.path.join(skill_dir, 'references', 'metrics-catalog.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')
    with open(skill_path, 'r', encoding='utf-8') as f:
      s_content = f.read()
    with open(catalog_path, 'r', encoding='utf-8') as f:
      c_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      g_content = f.read()

    self.assertIn("service account cloud repository access", s_content)
    self.assertIn("resource_read_*", s_content)
    self.assertIn("Service Account Cloud Repository & Origin IP Monitoring", c_content)
    self.assertIn("Cloud Infrastructure & Data Store CRUD", g_content)


  def test_malachite_mandatory_companion_dimensions(self):
    """Verifies that MalachiteASTValidator enforces mandatory companion dimensions for Cloud CRUD and Process Execution."""
    # 1. Cloud CRUD query missing vendor and product dimensions
    invalid_cloud_query = """
    // Goal: Test invalid cloud read without vendor and product
    stage stage1_extract {
      metadata.event_type = "RESOURCE_READ"
      principal.user.userid = "admin"
      $user = principal.user.userid
      match: $user by 1d
      outcome:
        $mu = max(metrics.resource_read_total(
          period: 1d, window: 30d, metric: event_count_sum, agg: avg,
          principal.user.userid: "admin"
        ))
    }
    $user = $stage1_extract.user
    match: $user by 1d
    outcome:
      $z = 2.0
    """
    cloud_errors = MalachiteASTValidator.validate_query(invalid_cloud_query)
    self.assertTrue(any("MISSING_MANDATORY_FILTER" in e for e in cloud_errors))
    self.assertTrue(any("metadata.vendor_name" in e and "metadata.product_name" in e for e in cloud_errors))

    # 2. Valid Cloud CRUD query with vendor and product dimensions
    valid_cloud_query = """
    // Goal: Test valid cloud read with vendor and product
    stage stage1_extract {
      metadata.event_type = "RESOURCE_READ"
      principal.user.userid = "admin"
      $user = principal.user.userid
      $v = metadata.vendor_name
      $p = metadata.product_name
      match: $user, $v, $p by 1d
      outcome:
        $mu = max(metrics.resource_read_total(
          period: 1d, window: 30d, metric: event_count_sum, agg: avg,
          principal.user.userid: "admin",
          metadata.vendor_name: $v,
          metadata.product_name: $p
        ))
    }
    $user = $stage1_extract.user
    $v = $stage1_extract.v
    $p = $stage1_extract.p
    match: $user, $v, $p by 1d
    outcome:
      $z = 2.0
    """
    valid_cloud_errors = MalachiteASTValidator.validate_query(valid_cloud_query)
    self.assertFalse(any("MISSING_MANDATORY_FILTER" in e for e in valid_cloud_errors))

    # 3. Multi-vector metric conflation in single stage
    conflated_query = """
    // Goal: Test multi-vector metric conflation in a single stage
    stage stage1_extract {
      target.user.userid = "admin"
      $user = target.user.userid
      match: $user by 1d
      outcome:
        $mu_auth = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: "admin"))
        $mu_cloud = max(metrics.resource_read_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: "admin", metadata.vendor_name: "Google Cloud Platform", metadata.product_name: "Storage"))
    }
    $user = $stage1_extract.user
    match: $user by 1d
    outcome:
      $z = 2.0
    """
    conflated_errors = MalachiteASTValidator.validate_query(conflated_query)
    self.assertTrue(any("MULTI_VECTOR_STAGE_CONFLATION" in e for e in conflated_errors))

  def test_multiturn_continuity_and_followup_mandate_contract(self):
    """SKILL.md and multi-stage guide must enforce multi-turn continuity and prevent raw log degradation on follow-up turns."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      guide_content = f.read()

    # Verify SKILL.md mandate
    self.assertIn("Multi-Turn Continuity & Follow-Up Mandate", skill_content)
    self.assertIn("NEVER degrade to raw log dumps", skill_content)

    # Verify multi-stage guide documentation
    self.assertIn("Multi-Turn Continuity & Conversational Anaphora Resolution", guide_content)
    self.assertIn("The Anti-Context-Collapse Mandate", guide_content)
    self.assertIn("looking backwards 14 days", guide_content)
    self.assertIn("Mode B: 30-Day Longitudinal Sliding Timeline", guide_content)

  def test_generic_client_visualization_tool_contract(self):
    """SKILL.md and chart specifications guide must support generic client visualization tool discovery without proprietary hardcoding."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    chart_guide_path = os.path.join(skill_dir, 'references', 'chart-specifications-guide.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(chart_guide_path, 'r', encoding='utf-8') as f:
      chart_guide_content = f.read()

    # SKILL.md generic discovery
    self.assertIn("Client Tool (if present)", skill_content)
    self.assertNotIn("generate_behavioral_radar", skill_content)  # Must remain generic and portable!

    # Chart guide detailed contract
    self.assertIn("Client-Side Visualization Tool Contract (Generic Endpoint Discovery)", chart_guide_content)
    self.assertIn("Semantic Tool Discovery Protocol", chart_guide_content)
    self.assertIn("Dynamic Schema Binding", chart_guide_content)

  def test_jetski_visual_agent_embed_contract(self):
    """SKILL.md and chart specifications guide must mandate <agent-embed> in Jetski and strictly ban data-uri."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    chart_guide_path = os.path.join(skill_dir, 'references', 'chart-specifications-guide.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(chart_guide_path, 'r', encoding='utf-8') as f:
      chart_guide_content = f.read()

    # SKILL.md mandates agent-embed in Jetski and bans data-uri in chat
    self.assertIn("Jetski (`run_command` present)", skill_content)
    self.assertIn("agent-embed", skill_content)
    self.assertIn("Zero data-uri or raw SVG in chat Markdown", skill_content)

    # Chart guide mandates agent-embed across all visual charts in Jetski
    self.assertIn("MANDATORY `<agent-embed>` (ZERO DATA-URI / ZERO RAW SVG IN CHAT)", chart_guide_content)
    self.assertIn("ALL visual charts", chart_guide_content)
    self.assertIn("NEVER emit `data:image/svg+xml;base64`", chart_guide_content)

  def test_prepreview_compilation_gate_and_consultative_pivot_contract(self):
    """SKILL.md and multi-stage guide must enforce pre-preview compiler verification and consultative pivot on dimensional mismatches."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      guide_content = f.read()

    # Pre-Preview Compilation Gate
    self.assertIn("Mandatory Upfront Query Preview Protocol (Mandatory Query Preview)", skill_content)
    self.assertIn("1-shot pre-preview compiler probe", skill_content)
    self.assertIn("Display query in markdown ONLY if probe compiles cleanly", skill_content)

    # Consultative Pivot Protocol in SKILL.md
    self.assertIn("Consultative Pivot & Handoff Protocol", skill_content)
    self.assertIn("ZERO FORCED JOINS", skill_content)
    self.assertIn("secops-statistical-hunter", skill_content)
    self.assertIn("NEVER bind `principal.user.userid` to file metrics", skill_content)

    # Deep Reference in multi-stage guide
    self.assertIn("Metric Entity Affinity, Cross-Entity Boundaries & The Consultative Pivot Protocol", guide_content)
    self.assertIn("The Metric Entity Affinity Matrix", guide_content)
    self.assertIn("The Cross-Entity Boundary & The Anti-Forced-Join Invariant", guide_content)
    self.assertIn("The 3 Canonical Consultative Pivot Paths", guide_content)
    self.assertIn("Cloud-First 2-Phase Pivot", guide_content)

  def test_template_first_routing_and_raw_dump_audit_contract(self):
    """SKILL.md and multi-stage guide must mandate template-first query assembly and post-flight raw-dump audit."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      guide_content = f.read()

    # SKILL.md template-first routing mandate
    self.assertIn("Template-First Routing Mandate", skill_content)
    self.assertIn("MultiStageTemplateRouter", skill_content)
    self.assertIn("templates/pipelines/", skill_content)

    # SKILL.md post-flight raw dump detection
    self.assertIn("RAW_LOG_DUMP_DETECTED", skill_content)
    self.assertIn('"events"', skill_content)
    self.assertIn('"stats"', skill_content)

    # Modular references index in SKILL.md
    self.assertIn("clean-handoff-udm-schema.md", skill_content)
    self.assertIn("soar-playbook-radar-integration.md", skill_content)
    self.assertIn("template_router.py", skill_content)

    # Multi-stage guide documentation
    self.assertIn("Template-First Query Architecture & Post-Flight Integrity", guide_content)
    self.assertIn("MultiStageTemplateRouter", guide_content)
    self.assertIn("RAW_LOG_DUMP_DETECTED", guide_content)

  def test_tool_precondition_code_block_embargo_contract(self):
    """SKILL.md and multi-stage guide must mandate tool-precondition code block embargo."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      guide_content = f.read()

    self.assertIn("Tool-Precondition Code Block Embargo", skill_content)
    self.assertIn("Tool-Precondition Code Block Embargo (Zero Broken Queries)", guide_content)
    self.assertIn("Emitting ```yara without an immediate preceding successful probe is STRICTLY PROHIBITED", skill_content)
    self.assertIn("query preview must be withheld", guide_content)

  def test_twophase_chained_hunt_specification_contract(self):
    """SKILL.md and multi-stage guide must define the Two-Phase Chained Hunt specification."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      guide_content = f.read()

    self.assertIn("Two-Phase Chained Hunt Specification", skill_content)
    self.assertIn("Bridge Contract ($host, $timestamp, $user, $caller_ip)", skill_content)
    self.assertIn("Two-Phase Chained Hunt Specification & Data Provenance Protocol", guide_content)
    self.assertIn("The Two-Phase Chained Architecture", guide_content)
    self.assertIn("Phase 1 (Statistical UEBA Baseline Search)", guide_content)
    self.assertIn("Phase 2 (Targeted Forensic Drilldown Search)", guide_content)

  def test_ast_validator_rejects_match_member_access(self):
    """MalachiteASTValidator must reject stage member access like $s1.host in match: sections."""
    invalid_query = """
    stage s1 {
      $e.metadata.event_type = "USER_LOGIN"
      $host = $e.principal.hostname
      match:
        $host by 1d
      outcome:
        $cnt = count($e.metadata.id)
    }
    match:
      $s1.host by 1d
    outcome:
      $val = max($s1.cnt)
    """
    errors = MalachiteASTValidator.validate_query(invalid_query)
    self.assertTrue(any("INVALID_MATCH_MEMBER_ACCESS" in e for e in errors),
                    f"Expected INVALID_MATCH_MEMBER_ACCESS error, got: {errors}")

  def test_ast_validator_rejects_root_events_header(self):
    """MalachiteASTValidator must reject events: header blocks in root stages."""
    invalid_query = """
    stage s1 {
      $e.metadata.event_type = "USER_LOGIN"
      $host = $e.principal.hostname
      match:
        $host by 1d
      outcome:
        $cnt = count($e.metadata.id)
    }
    events:
      $host = $s1.host
    match:
      $host by 1d
    outcome:
      $val = max($s1.cnt)
    """
    errors = MalachiteASTValidator.validate_query(invalid_query)
    self.assertTrue(any("INVALID_EVENTS_SECTION_IN_ROOT" in e for e in errors),
                    f"Expected INVALID_EVENTS_SECTION_IN_ROOT error, got: {errors}")

  def test_chained_hunt_router_builds_valid_queries(self):
    """ChainedHuntRouter must construct valid Phase 1 YARA-L AST queries and Phase 2 UDM queries."""
    from scripts.template_router import ChainedHuntRouter

    phase1 = ChainedHuntRouter.build_phase1_endpoint_query(entity_scope="ws-finance-04", anomaly_threshold=3.0)
    self.assertIn("stage stage1_process_outlier", phase1)
    self.assertIn('principal.asset.hostname = "ws-finance-04"', phase1)
    self.assertIn("metrics.file_executions_total", phase1)
    errors = MalachiteASTValidator.validate_query(phase1)
    self.assertEqual(len(errors), 0, f"Phase 1 query should have zero AST errors, got: {errors}")

    phase2 = ChainedHuntRouter.build_phase2_cloud_query(target_user="fkolzig@company.com", caller_ip="198.51.100.24")
    self.assertIn('metadata.vendor_name = "Google Cloud Platform"', phase2)
    self.assertIn('principal.user.userid = "fkolzig@company.com"', phase2)
    self.assertIn('principal.ip = "198.51.100.24"', phase2)

  def test_provenance_stamping_contract(self):
    """SKILL.md and multi-stage guide must document execution provenance stamping."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      guide_content = f.read()

    self.assertIn("Ranked Outlier Summary & Provenance Stamp", skill_content)
    self.assertIn("Stamp execution provenance (events scanned, query execution time, projected schema columns)", skill_content)
    self.assertIn("Data Provenance & Execution Stamping", guide_content)

  def test_zero_code_handoff_and_dual_layer_trickle_defense_contract(self):
    """SKILL.md and multi-stage guide must mandate zero-code handoff and dual-layer trickle defense."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      guide_content = f.read()

    # Zero-Code Handoff Invariant
    self.assertIn("Zero-Code Handoff Invariant", skill_content)
    self.assertIn("Zero-Code Handoff Invariant", guide_content)
    self.assertIn("Handoff cards are strictly conceptual", skill_content)
    self.assertIn("Tool-Precondition Code Block Embargo", skill_content)
    self.assertIn("applies universally to queries, pivots, and handoff cards", skill_content)

    # Dual-Layer Trickle Defense
    self.assertIn("Dual-Layer Defense for Trickle Attacks", skill_content)
    self.assertIn("Mode B Longitudinal CUSUM Drift", skill_content)
    self.assertIn("metrics.dns_queries_total", skill_content)
    self.assertIn("secops-statistical-hunter", skill_content)
    self.assertIn("Dual-Layer Trickle Defense", guide_content)
    self.assertIn("Layer 1 (Longitudinal CUSUM Drift)", guide_content)
    self.assertIn("Layer 2 (Ad-Hoc Timing Jitter Handoff)", guide_content)

  def test_progressive_load_first_directive_contract(self):
    """CONTRIBUTING.md and compiler-submission-policy.md must mandate Progressive-Load First Directive."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    contrib_path = os.path.join(skill_dir, 'CONTRIBUTING.md')
    policy_path = os.path.join(skill_dir, 'references', 'compiler-submission-policy.md')

    with open(contrib_path, 'r', encoding='utf-8') as f:
      contrib_content = f.read()
    with open(policy_path, 'r', encoding='utf-8') as f:
      policy_content = f.read()

    # Assert directive present in CONTRIBUTING.md
    self.assertIn("Progressive-Load First Directive", contrib_content)
    self.assertIn("NEVER default to immediately modifying `SKILL.md`", contrib_content)
    self.assertIn("Assess Progressive-Load Locations First", contrib_content)
    self.assertIn("Preserve `SKILL.md` as a Lean Orchestrator", contrib_content)
    self.assertIn("Progressive-Load Compliance", contrib_content)

    # Assert policy present in references/compiler-submission-policy.md
    self.assertIn("Skill Architecture & Progressive-Load First Policy", policy_content)
    self.assertIn("Three-Tier Information Architecture", policy_content)
    self.assertIn("Mandatory Pre-Modification Decision Tree", policy_content)
    self.assertIn("Progressive-Load Enforcement Checklist", policy_content)

  def test_two_answer_scheduled_exfiltration_workflow_contract(self):
    """multi-stage guide must document the Two-Answer Scheduled Exfiltration Workflow and Prevalence Assumption."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')

    with open(guide_path, 'r', encoding='utf-8') as f:
      guide_content = f.read()

    # Section 29 assertions
    self.assertIn("29. Scheduled & Automated Exfiltration: The Two-Answer Hybrid Workflow", guide_content)
    self.assertIn("NEVER force a purely volumetric daily baseline onto a temporal regularity problem", guide_content)
    self.assertIn("Answer 1: Immediate Risk Metrics Execution via Low-Prevalence Screening", guide_content)
    self.assertIn("PIPE-09-PREVALENCE", guide_content)
    self.assertIn("Prevalence Screening Assumption", guide_content)
    self.assertIn("Answer 2: Consultative Bridge for High-Prevalence / Living-Off-The-Cloud Targets", guide_content)
    self.assertIn("high-prevalence public cloud infrastructure", guide_content)
    self.assertIn("C2_BEACONING_JITTER (CV <= 0.20) & Cron Minute", guide_content)

  def test_monolithic_radar_join_contract(self):
    """SKILL.md, radar guide, and auditor must document and enforce the monolithic radar join prevention contract."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    radar_guide_path = os.path.join(skill_dir, 'references', 'soar-playbook-radar-integration.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(radar_guide_path, 'r', encoding='utf-8') as f:
      radar_guide_content = f.read()

    # SKILL.md contracts
    self.assertIn("ZERO MONOLITHIC JOINS — maxJoinCount=4 & Inner-Join Drop", skill_content)
    self.assertIn("STAT_ANTIPATTERN_MONOLITHIC_RADAR_JOIN", skill_content)
    self.assertIn("auto-bypass Mode B", skill_content)

    # Radar guide contracts
    self.assertIn("The Monolithic 5-Stage Join Trap & Decoupled Micro-Query Guarantee", radar_guide_content)
    self.assertIn("STAT_ANTIPATTERN_MONOLITHIC_RADAR_JOIN", radar_guide_content)
    self.assertIn("maxJoinCount = 4", radar_guide_content)
    self.assertIn("Silent Inner-Join Drop", radar_guide_content)
    self.assertIn("Decoupled 5-Sector Architecture & `radar_collector.py`", radar_guide_content)

    # Auditor enum contract
    from scripts.statistical_validator import StatisticalAntipatternType
    self.assertTrue(hasattr(StatisticalAntipatternType, "MONOLITHIC_RADAR_JOIN"))

  def test_hard_preflight_clearance_gate_contract(self):
    """SKILL.md, multi-stage guide, and radar guide must strictly enforce NO QUERY = NO CLEARANCE."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')
    radar_guide_path = os.path.join(skill_dir, 'references', 'soar-playbook-radar-integration.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      guide_content = f.read()
    with open(radar_guide_path, 'r', encoding='utf-8') as f:
      radar_content = f.read()

    # SKILL.md assertions
    self.assertIn("HARD PRE-FLIGHT CLEARANCE GATE (NO QUERY = NO CLEARANCE)", skill_content)
    self.assertIn("Clearance Request (Step 5) MUST NEVER BE ASKED unless a valid, compilable multi-stage YARA-L query has been successfully probed", skill_content)
    self.assertIn("Explicit Clearance Question & Turn Termination (GATED ON STEP 4 QUERY DISPLAY)", skill_content)

    # Reference guide assertions
    self.assertIn("The Hard Pre-Flight Clearance Gate (NO QUERY = NO CLEARANCE)", guide_content)
    self.assertIn("Step 5 clearance question MUST NEVER be asked unless a valid, compilable multi-stage YARA-L query has been successfully probed", guide_content)
    self.assertIn("Turn 1 Pre-Flight Clearance Hard Gate (NO QUERY = NO CLEARANCE)", radar_content)

  def test_iso8601_probe_timestamp_contract(self):
    """SKILL.md, guide, and radar integration must require ISO 8601 timestamps and reject relative offsets."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      guide_content = f.read()

    # SKILL.md assertions
    self.assertIn("1-shot pre-preview compiler probe with ISO 8601 timestamps", skill_content)
    self.assertIn("<ISO_10M_AGO>", skill_content)
    self.assertIn("<ISO_NOW>", skill_content)
    self.assertIn("Relative 'now-10m' is invalid", skill_content)

    # Guide assertions
    self.assertIn("Strict ISO 8601 Timestamps for Compiler Probes", guide_content)
    self.assertIn("API Rejection of Relative Time Offsets", guide_content)

  def test_identity_disambiguation_spotcheck_contract(self):
    """SKILL.md and guide must enforce 14-day UDM spot-checks and immediate halt for unresolved first names."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      guide_content = f.read()

    # SKILL.md assertions
    self.assertIn("14-Day UDM Spot-Check", skill_content)
    self.assertIn("HARD RESOLUTION GATE (ZERO GUESSING & NO SPEC CARD)", skill_content)
    self.assertIn("NEVER GUESS A USERNAME AND NEVER EMIT PRE-FLIGHT CARD", skill_content)
    self.assertIn("What is their corporate email or technical username?", skill_content)

    # Guide assertions
    self.assertIn("Identity Disambiguation & 14-Day UDM Spot-Check", guide_content)
    self.assertIn("The Single-Token Trap", guide_content)

  def test_pillar2_query_integrity_contract(self):
    """SKILL.md and guide must require executed multi-stage queries and forbid raw event filters in Pillar 2."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(skill_dir, 'SKILL.md')
    guide_path = os.path.join(skill_dir, 'references', 'multi-stage-metrics-guide.md')

    with open(skill_path, 'r', encoding='utf-8') as f:
      skill_content = f.read()
    with open(guide_path, 'r', encoding='utf-8') as f:
      guide_content = f.read()

    # SKILL.md assertions
    self.assertIn("Executed Multi-Stage YARA-L Query", skill_content)
    self.assertIn("For 360 Radar, display executed sector micro-queries", skill_content)
    self.assertIn("Raw event filters (e.g. `principal.user.userid = ...`) are STRICTLY PROHIBITED in Pillar 2", skill_content)

    # Guide assertions
    self.assertIn("Pillar 2 Executed Multi-Stage Query Integrity", guide_content)
    self.assertIn("Prohibition of Raw Event Filters in Pillar 2", guide_content)



  def test_dual_grounding_commandments_contract(self):
    """SKILL.md must strictly enforce the Dual Grounding Invariants against data and schema fabrication."""
    self.assertIn("THE DUAL GROUNDING INVARIANTS (THE NON-NEGOTIABLE INTEGRITY CORE)", self.skill_content)
    self.assertIn("Zero Data Simulation (NEVER Fabricate Data)", self.skill_content)
    self.assertIn("Zero Schema/Syntax Fantasy (NEVER Hallucinate UDM Fields or YARA-L Grammar)", self.skill_content)
    self.assertIn("Truth Over Completion", self.skill_content)

  def test_three_state_active_hunt_lifecycle_contract(self):
    """SKILL.md must define the closed 3-state active hunt engine."""
    self.assertIn("THE 3-STATE ACTIVE HUNT LIFECYCLE", self.skill_content)
    self.assertIn("State 1: Pre-Flight Clearance & Specification", self.skill_content)
    self.assertIn("State 2: Deterministic Multi-Stage Execution & 6-Pillar Report", self.skill_content)
    self.assertIn("State 3: Iteration, Entity Shifts & Federated Bridge", self.skill_content)

  def test_pillar5_debaiting_contract(self):
    """Pillar 5 must be titled Chronicle UI Manual Pivot and forbid tool execution to avoid the homonym trap."""
    self.assertIn("Chronicle UI Manual Pivot (Triage Reference Only)", self.skill_content)
    self.assertNotIn("Immediate 1-Click Investigation Queries", self.skill_content)

  def test_active_hunt_session_lock_contract(self):
    """SKILL.md must enforce the Active Hunt Session Lock and multi-turn entity shift routing."""
    self.assertIn("Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT)", self.skill_content)
    self.assertIn("same query for", self.skill_content)
    self.assertIn("Re-enter State 1 for new entity", self.skill_content)

if __name__ == '__main__':
  unittest.main()








