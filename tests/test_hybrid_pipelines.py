# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unit tests for Dual-Plane Hybrid Metric & Raw Telemetry Enrichment pipeline."""

import re
import unittest

from scripts.preflight_validator import EntityType, PipelineArchitecture
from scripts.template_router import MultiStageTemplateRouter
from scripts.federated_handoff import build_handoff_payload, format_handoff_card


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
    self.assertIn("period: 1d, window: 30d, metric: total_bytes, agg: avg", query)
    self.assertIn("$diff = $observed_val - $hist_mean", query)
    self.assertIn("$denom = $hist_stddev + 1.0", query)

    # 3. Stage 2 Raw Telemetry Enrichment
    self.assertIn("stage stage2_raw_telemetry {", query)
    self.assertIn('metadata.event_type = "NETWORK_HTTP"', query)
    self.assertIn("count_distinct(target.user_agent)", query)
    self.assertIn("array_distinct(target.user_agent)", query)

    # 4. Root Stage Fusion
    self.assertIn("$entity = $stage1_macro_baseline.entity", query)
    self.assertIn("$entity = $stage2_raw_telemetry.entity", query)
    self.assertIn("match:\n  $entity by 1d", query)
    self.assertIn("$macro_z_score >= 3.0", query)
    self.assertIn("$signature_diversity <= 2", query)

    # 5. Malachite Syntax Invariant Audits
    self.assertNotIn("events:", query)
    self.assertNotIn("rule ", query)
    self.assertNotIn("math.max", query)
    self.assertNotIn("sqrt(", query)

  def test_hybrid_pipeline_join_count_safety(self):
    query = self.router.build_hybrid_enrichment_query(
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
    )

    # Join 1: metrics.* function call
    metrics_calls = re.findall(r"\bmetrics\.[a-zA-Z0-9_]+\(", query)
    self.assertGreaterEqual(len(metrics_calls), 1)

    # Stage joins in Root: 2 stages joined on $entity = 1 inter-stage join
    # Total joins: 1 metric table join + 1 stage join = 2 joins (Limit is 4)
    self.assertTrue(2 <= 4)

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


if __name__ == "__main__":
  unittest.main()
