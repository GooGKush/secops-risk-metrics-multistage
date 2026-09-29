# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unit tests for Dual-Plane Hybrid Metric & Raw Telemetry Enrichment pipeline."""

import re
import unittest

from scripts.preflight_validator import EntityType, MalachiteASTValidator, PipelineArchitecture
from scripts.statistical_validator import StatisticalAntipatternAuditor
from scripts.template_router import MultiStageTemplateRouter
from scripts.federated_handoff import (
    build_handoff_payload,
    dispatch_to_endpoint,
    format_handoff_card,
    SUPPORTED_INTENTS,
    SUPPORTED_PROTOCOL,
)


class TestHybridPipelines(unittest.TestCase):

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  def test_hybrid_template_rendering_default_network_bytes(self):
    query = self.router.build_hybrid_enrichment_query(
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
        anomaly_threshold=3.0,
        hypothesis_goal="Detect exfiltration bursts combined with scripted HTTP clients",
    )

    # 1. Methodology header
    self.assertIn("// Goal: Detect exfiltration bursts combined with scripted HTTP clients", query)

    # 2. Stage 1 Macro Baseline
    self.assertIn("stage stage1_macro_baseline {", query)
    self.assertIn('metadata.event_type = "NETWORK_CONNECTION"', query)
    self.assertIn("principal.asset.hostname = $entity", query)
    self.assertIn("metrics.network_bytes_outbound(", query)
    self.assertIn("$z_score = ($observed_val - $hist_mean) / if($hist_stddev > 0, $hist_stddev, 1.0)", query)

    # 3. Stage 2 Raw Telemetry Enrichment
    self.assertIn("stage stage2_raw_telemetry {", query)
    self.assertIn('metadata.event_type = "NETWORK_HTTP"', query)
    self.assertIn("count_distinct(network.http.user_agent)", query)
    self.assertIn("array_distinct(network.http.user_agent)", query)

    # 4. Root Stage Fusion
    self.assertIn("$entity = $stage1_macro_baseline.entity", query)
    self.assertIn("$entity = $stage2_raw_telemetry.entity", query)
    self.assertIn("match:\n  $entity by 1d", query)
    self.assertIn("$macro_z_score >= 3.0", query)
    self.assertIn("$signature_diversity <= 2", query)

    # 5. Common Compiler Syntax Invariant Audits
    self.assertNotIn("events:", query)
    self.assertNotIn("rule ", query)
    self.assertNotIn("math.max", query)
    self.assertFalse(re.search(r"(?<!math\.)\bsqrt\s*\(", query))
    self.assertNotIn("^", query)

    # Compiler AST & Statistical Antipattern verification
    ast_errors = MalachiteASTValidator.validate_query(query)
    self.assertEqual(ast_errors, [])
    stat_violations = StatisticalAntipatternAuditor.audit_query(query)
    self.assertEqual(stat_violations, [])

  def test_archetype1_entropy_concentration_rendering_and_ast(self):
    """Archetype 1: Entropy & Concentration (Diversity Deficit & Elephant Flow)."""
    query = self.router.build_hybrid_entropy_concentration_query(
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
        anomaly_threshold=3.0,
        hypothesis_goal="Detect automated single-destination bulk exfiltration",
    )

    self.assertIn("// Goal: Detect automated single-destination bulk exfiltration", query)
    self.assertIn("stage stage1_macro_baseline {", query)
    self.assertIn("stage stage2_micro_forensics {", query)
    self.assertIn("$diversity_ratio = $vocab_cardinality / ($raw_events + 1.0)", query)
    self.assertIn("$concentration_ratio = $peak_transfer / ($sum_transfers + 1.0)", query)
    self.assertIn("$threat_score = $macro_z * (1.0 + $concentration_ratio)", query)
    self.assertIn("$is_skewed = if($diversity_ratio", query)
    self.assertIn("and $is_skewed = 1", query)
    self.assertIn("match:\n  $entity by 1d", query)
    self.assertIn("order:\n  $threat_score desc", query)

    # Common Compiler Invariants
    self.assertNotIn("events:", query)
    self.assertNotIn("rule ", query)
    self.assertFalse(re.search(r"(?<!math\.)\bsqrt\s*\(", query))
    self.assertNotIn("^", query)

    ast_errors = MalachiteASTValidator.validate_query(query)
    self.assertEqual(ast_errors, [])
    stat_violations = StatisticalAntipatternAuditor.audit_query(query)
    self.assertEqual(stat_violations, [])

  def test_archetype2_orthogonal_threat_space_rendering_and_ast(self):
    """Archetype 2: Orthogonal Threat Space (Joint Odds, Hurdle, Euclidean Distance)."""
    query = self.router.build_hybrid_orthogonal_space_query(
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
        anomaly_threshold=3.0,
        hypothesis_goal="Multi-dimensional threat distance and dormant awakening",
    )

    self.assertIn("// Goal: Multi-dimensional threat distance and dormant awakening", query)
    self.assertIn("stage stage1_macro_intensity {", query)
    self.assertIn("stage stage2_micro_breadth {", query)
    self.assertIn("$threat_distance_sq = $intensity_sq + $breadth_sq", query)
    self.assertIn("$joint_odds_score = (0.6 * $z_intensity) + (0.4 * $z_breadth)", query)
    self.assertIn("$threat_distance_sq >= 16.0", query)
    self.assertIn("$hist_days <= 2", query)
    self.assertIn("order:\n  $threat_distance_sq desc", query)

    # Common Compiler Invariants
    self.assertNotIn("events:", query)
    self.assertNotIn("rule ", query)
    self.assertFalse(re.search(r"(?<!math\.)\bsqrt\s*\(", query))
    self.assertNotIn("^", query)

    ast_errors = MalachiteASTValidator.validate_query(query)
    self.assertEqual(ast_errors, [])
    stat_violations = StatisticalAntipatternAuditor.audit_query(query)
    self.assertEqual(stat_violations, [])

  def test_archetype3_fleet_prevalence_rendering_and_ast(self):
    """Archetype 3: Fleet Prevalence Normalization (Patch Tuesday Shield)."""
    query = self.router.build_hybrid_fleet_prevalence_query(
        target_metric="file_executions_total",
        entity_type=EntityType.ASSET,
        anomaly_threshold=3.0,
        hypothesis_goal="Normalize process execution surges against fleet rollout",
    )

    self.assertIn("// Goal: Normalize process execution surges against fleet rollout", query)
    self.assertIn("stage stage1_personal_surge {", query)
    self.assertIn("stage stage2_fleet_prevalence {", query)
    self.assertIn("match:\n    $token by 1d", query)
    self.assertIn("$prevalence_dampener = 1.0 / ($fleet_adopters + 1.0)", query)
    self.assertIn("$normalized_odds_score = $personal_z * $prevalence_dampener", query)
    self.assertIn("match:\n  $token by 1d", query)
    self.assertIn("order:\n  $normalized_odds_score desc", query)

    # Common Compiler Invariants
    self.assertNotIn("events:", query)
    self.assertNotIn("rule ", query)
    self.assertFalse(re.search(r"(?<!math\.)\bsqrt\s*\(", query))
    self.assertNotIn("^", query)

    ast_errors = MalachiteASTValidator.validate_query(query)
    self.assertEqual(ast_errors, [])
    stat_violations = StatisticalAntipatternAuditor.audit_query(query)
    self.assertEqual(stat_violations, [])

  def test_hybrid_pipeline_join_count_safety(self):
    queries = [
        self.router.build_hybrid_enrichment_query(),
        self.router.build_hybrid_entropy_concentration_query(),
        self.router.build_hybrid_orthogonal_space_query(),
        self.router.build_hybrid_fleet_prevalence_query(),
    ]

    for q in queries:
      # Join 1: metrics.* function call
      metrics_calls = re.findall(r"\bmetrics\.[a-zA-Z0-9_]+\(", q)
      self.assertGreaterEqual(len(metrics_calls), 1)

      # Stage joins in Root: 2 stages joined = 1 inter-stage join
      # Total joins: 1 metric table join + 1 stage join = 2 joins (Ceiling is <= 4)
      stages = re.findall(r"stage\s+([a-zA-Z0-9_]+)\s*\{", q)
      self.assertEqual(len(stages), 2)

  def test_federated_handoff_payload_raw_telemetry_enrichment(self):
    payload = build_handoff_payload(
        intent="RAW_TELEMETRY_ENRICHMENT",
        entity_type="HOSTNAME",
        entity_value="site-rev-proxy.lan",
        lookback="24h",
        parameters={
            "enrichment_vector": "NETWORK_HTTP_USER_AGENT",
            "max_signature_diversity": 2,
            "target_entities": ["site-rev-proxy.lan", "ws-finance-04"],
        },
    )

    self.assertEqual(payload["protocol"], "secops-threat-hunt-handoff-v1")
    self.assertEqual(payload["intent"], "RAW_TELEMETRY_ENRICHMENT")
    self.assertEqual(payload["target_skill"], "secops-statistical-hunter")
    self.assertEqual(payload["statistical_model"]["parameters"]["enrichment_vector"], "NETWORK_HTTP_USER_AGENT")
    self.assertEqual(payload["statistical_model"]["parameters"]["max_signature_diversity"], 2)

    card = format_handoff_card(payload)
    self.assertIn("secops-threat-hunt-handoff-v1", card)
    self.assertIn("site-rev-proxy.lan", card)
    self.assertIn("RAW_TELEMETRY_ENRICHMENT", card)

  def test_federated_handoff_payloads_for_hybrid_models(self):
    """Verifies that all 6 hybrid mathematical models generate conforming handoff payloads and receive ACKs."""
    intents = [
        "DIVERSITY_DEFICIT",
        "ELEPHANT_FLOW_CONCENTRATION",
        "ORTHOGONAL_THREAT_SPACE",
        "BAYESIAN_JOINT_ODDS",
        "TWO_PART_HURDLE",
        "FLEET_PREVALENCE_NORMALIZATION",
    ]

    for intent in intents:
      self.assertIn(intent, SUPPORTED_INTENTS)
      payload = build_handoff_payload(
          intent=intent,
          entity_type="HOSTNAME",
          entity_value="ws-dev-42",
          lookback="24h",
      )
      self.assertEqual(payload["protocol"], SUPPORTED_PROTOCOL)
      self.assertEqual(payload["intent"], intent)
      self.assertEqual(payload["target_skill"], "secops-statistical-hunter")
      self.assertIsNotNone(payload.get("justification"))
      self.assertIn("parameters", payload["statistical_model"])

      # Dispatch to endpoint in secops-statistical-hunter
      ack = dispatch_to_endpoint(payload)
      self.assertEqual(
          ack.get("status"),
          "HANDOFF_ACK_ACCEPTED",
          f"Handoff dispatch failed for intent {intent}: {ack}",
      )
      self.assertEqual(ack.get("action"), "STEP_OUT_CONFIRMED")
      self.assertTrue(len(ack.get("compiled_query", "")) > 0)

  def test_hybrid_derived_file_prevalence_rendering_and_ast(self):
    """Verifies Derived Context File Prevalence pipeline AST and invariants."""
    query = self.router.build_hybrid_derived_file_prevalence_query(
        target_metric="file_executions_total",
        entity_type=EntityType.ASSET,
        anomaly_threshold=3.0,
        hypothesis_goal="Isolate rare binary execution bursts and filter software rollouts",
    )
    self.assertIn("stage stage1_process_baseline {", query)
    self.assertIn("metrics.file_executions_total(", query)
    self.assertIn("stage stage2_file_derived_context {", query)
    self.assertIn('$file.graph.metadata.source_type = "DERIVED_CONTEXT"', query)
    self.assertIn('$file.graph.metadata.entity_type = "FILE"', query)
    self.assertIn("$file.graph.entity.file.prevalence.day_count = 10", query)
    self.assertIn("$file.graph.entity.file.prevalence.rolling_max <= 3", query)
    self.assertIn("$file.graph.entity.file.prevalence.rolling_max > 0", query)
    self.assertIn("$sha256 = $stage2_file_derived_context.sha256", query)
    self.assertIn("$obs_ts = max($stage1_process_baseline.event_timestamp)", query)
    self.assertIn("$binary_age_days = ($obs_ts - $first_seen) / 86400.0", query)
    self.assertIn("$is_novel_binary = if($binary_age_days <= 7.0 and $binary_age_days >= 0.0, 1.0, 0.0)", query)
    self.assertIn("order:\n  $threat_score desc", query)

    # Compiler AST verification
    ast_errors = MalachiteASTValidator.validate_query(query)
    self.assertEqual(ast_errors, [])

  def test_hybrid_derived_domain_prevalence_rendering_and_ast(self):
    """Verifies Derived Context Domain Prevalence pipeline AST and invariants."""
    query = self.router.build_hybrid_derived_domain_prevalence_query(
        target_metric="http_queries_total",
        entity_type=EntityType.ASSET,
        anomaly_threshold=3.0,
        hypothesis_goal="Detect web query surges to rare enterprise destinations",
    )
    self.assertIn("stage stage1_query_baseline {", query)
    self.assertIn("metrics.http_queries_total(", query)
    self.assertIn("stage stage2_domain_derived_context {", query)
    self.assertIn('$dom.graph.metadata.source_type = "DERIVED_CONTEXT"', query)
    self.assertIn('$dom.graph.metadata.entity_type = "DOMAIN_NAME"', query)
    self.assertIn("$dom.graph.entity.domain.prevalence.day_count = 10", query)
    self.assertIn("$domain = $stage2_domain_derived_context.domain", query)
    self.assertIn("$obs_ts = max($stage1_query_baseline.event_timestamp)", query)
    self.assertIn("$domain_age_days = ($obs_ts - $first_seen) / 86400.0", query)
    self.assertIn("order:\n  $threat_score desc", query)

    ast_errors = MalachiteASTValidator.validate_query(query)
    self.assertEqual(ast_errors, [])

  def test_hybrid_whois_domain_lifecycle_rendering_and_ast(self):
    """Verifies WHOIS Domain Lifecycle pipeline (NRD age & expiration) AST and invariants."""
    query = self.router.build_hybrid_whois_domain_lifecycle_query(
        target_metric="http_queries_total",
        entity_type=EntityType.ASSET,
        anomaly_threshold=3.0,
        hypothesis_goal="Detect egress departures targeting newly registered or expired domains",
    )
    self.assertIn("stage stage1_egress_baseline {", query)
    self.assertIn("stage stage2_whois_lifecycle {", query)
    self.assertIn('$whois.graph.metadata.source_type = "GLOBAL_CONTEXT"', query)
    self.assertIn('$whois.graph.metadata.vendor_name = "WHOIS"', query)
    self.assertIn('$whois.graph.metadata.entity_type = "DOMAIN_NAME"', query)
    self.assertIn("$creation_ts = max($whois.graph.entity.domain.creation_time.seconds)", query)
    self.assertIn("$expiration_ts = min($whois.graph.entity.domain.expiration_time.seconds)", query)
    self.assertIn("$obs_ts = max($stage1_egress_baseline.event_timestamp)", query)
    self.assertIn("$domain_age_days = ($obs_ts - $created) / 86400.0", query)
    self.assertIn("$is_nrd = if($domain_age_days <= 30.0 and $domain_age_days >= 0.0, 1.0, 0.0)", query)
    self.assertIn("$is_expired = if($expires <= $obs_ts and $expires > 0, 1.0, 0.0)", query)
    self.assertIn("$days_to_expiration = ($expires - $obs_ts) / 86400.0", query)
    self.assertIn("order:\n  $fused_threat_score desc", query)

    ast_errors = MalachiteASTValidator.validate_query(query)
    self.assertEqual(ast_errors, [])

  def test_hybrid_derived_asset_age_rendering_and_ast(self):
    """Verifies Derived Context Infant Asset Age pipeline AST and invariants."""
    query = self.router.build_hybrid_derived_asset_age_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.ASSET,
        anomaly_threshold=3.0,
        hypothesis_goal="Detect abnormal activity on infant assets first seen within 7 days",
    )
    self.assertIn("stage stage1_asset_baseline {", query)
    self.assertIn("metrics.auth_attempts_total(", query)
    self.assertIn("stage stage2_asset_derived_context {", query)
    self.assertIn('$asset.graph.metadata.source_type = "DERIVED_CONTEXT"', query)
    self.assertIn('$asset.graph.metadata.entity_type = "ASSET"', query)
    self.assertIn("$host = $stage2_asset_derived_context.host", query)
    self.assertIn("$obs_ts = max($stage1_asset_baseline.event_timestamp)", query)
    self.assertIn("$asset_age_days = ($obs_ts - $first_seen) / 86400.0", query)
    self.assertIn("$is_infant_asset = if($asset_age_days <= 7.0 and $asset_age_days >= 0.0, 1.0, 0.0)", query)
    self.assertIn("order:\n  $threat_score desc", query)

    ast_errors = MalachiteASTValidator.validate_query(query)
    self.assertEqual(ast_errors, [])

  def test_hybrid_derived_domain_prevalence_dns_queries_ast(self):
    """Verifies DNS queries use network.dns_domain companion dimension, avoiding network.dns.questions.name."""
    query = self.router.build_hybrid_derived_domain_prevalence_query(
        target_metric="dns_queries_total",
        entity_type=EntityType.ASSET,
        anomaly_threshold=3.0,
        hypothesis_goal="Detect anomalous volume of DNS resolutions targeting rare domains",
    )
    self.assertIn("stage stage1_query_baseline {", query)
    self.assertIn("metrics.dns_queries_total(", query)
    self.assertIn("network.dns_domain: $domain", query)
    self.assertIn("network.dns_domain = $domain", query)
    self.assertNotIn("network.dns.questions.name", query)
    stage1_code = query[query.index("stage stage1_query_baseline"):]
    self.assertNotIn("target.hostname", stage1_code)
    self.assertIn("stage stage2_domain_derived_context {", query)
    self.assertIn('$dom.graph.metadata.source_type = "DERIVED_CONTEXT"', query)
    self.assertIn('$dom.graph.metadata.entity_type = "DOMAIN_NAME"', query)
    self.assertIn("$domain = $stage2_domain_derived_context.domain", query)

    ast_errors = MalachiteASTValidator.validate_query(query)
    self.assertEqual(ast_errors, [])

  def test_hybrid_whois_domain_lifecycle_dns_queries_ast(self):
    """Verifies DNS queries in WHOIS lifecycle pipeline use network.dns_domain, avoiding network.dns.questions.name."""
    query = self.router.build_hybrid_whois_domain_lifecycle_query(
        target_metric="dns_queries_total",
        entity_type=EntityType.ASSET,
        anomaly_threshold=3.0,
        hypothesis_goal="Detect anomalous DNS query departures to newly registered or expired domains",
    )
    self.assertIn("stage stage1_egress_baseline {", query)
    self.assertIn("metrics.dns_queries_total(", query)
    self.assertIn("network.dns_domain: $domain", query)
    self.assertIn("network.dns_domain = $domain", query)
    self.assertNotIn("network.dns.questions.name", query)
    stage1_code = query[query.index("stage stage1_egress_baseline"):]
    self.assertNotIn("target.hostname", stage1_code)
    self.assertIn("stage stage2_whois_lifecycle {", query)
    self.assertIn('$whois.graph.metadata.source_type = "GLOBAL_CONTEXT"', query)
    self.assertIn('$whois.graph.metadata.vendor_name = "WHOIS"', query)

    ast_errors = MalachiteASTValidator.validate_query(query)
    self.assertEqual(ast_errors, [])


if __name__ == "__main__":
  unittest.main()
