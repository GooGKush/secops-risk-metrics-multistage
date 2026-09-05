# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unit tests for federated handoff protocol in secops-risk-metrics-multistage."""

import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.federated_handoff import (
    build_handoff_payload,
    format_handoff_card,
    dispatch_to_endpoint,
    SUPPORTED_PROTOCOL,
)


class TestFederatedHandoff(unittest.TestCase):

  def test_build_handoff_payload_scheduled_exfiltration(self):
    """Payload must conform strictly to secops-threat-hunt-handoff-v1."""
    payload = build_handoff_payload(
        intent="SCHEDULED_EXFILTRATION_TIMING",
        entity_type="HOSTNAME",
        entity_value="site-rev-proxy.lan",
        lookback="24h",
        sensitivity="BALANCED",
    )
    self.assertEqual(payload["protocol"], SUPPORTED_PROTOCOL)
    self.assertEqual(payload["source_skill"], "secops-risk-metrics-multistage")
    self.assertEqual(payload["target_skill"], "secops-statistical-hunter")
    self.assertEqual(payload["intent"], "SCHEDULED_EXFILTRATION_TIMING")
    self.assertEqual(payload["target_entity"], {"type": "HOSTNAME", "value": "site-rev-proxy.lan"})
    self.assertEqual(payload["search_window"], {"lookback": "24h"})
    self.assertEqual(payload["statistical_model"], {
        "name": "SCHEDULED_EXFILTRATION_TIMING",
        "sensitivity": "BALANCED",
        "parameters": {"max_cv": 0.20, "min_observations": 10},
    })
    self.assertEqual(payload["status"], "PENDING_DISPATCH")

  def test_format_handoff_card_renders_fenced_json(self):
    """Handoff card must contain fenced JSON payload with protocol header."""
    payload = build_handoff_payload(
        intent="C2_BEACONING_JITTER",
        entity_type="HOSTNAME",
        entity_value="dc-corp-01",
        lookback="12h",
    )
    card = format_handoff_card(payload)
    self.assertIn("### 🔄 Federated Skill Handoff: Consultative Demarcation", card)
    self.assertIn("```json:secops-threat-hunt-handoff-v1", card)
    self.assertIn('"target_skill": "secops-statistical-hunter"', card)
    self.assertIn("Step-Out Directive", card)

  def test_format_handoff_card_with_ack(self):
    """Handoff card with ACK must render ACK status and target query."""
    payload = build_handoff_payload(
        intent="SCHEDULED_EXFILTRATION_TIMING",
        entity_type="HOSTNAME",
        entity_value="site-rev-proxy",
        lookback="24h",
    )
    ack = {
        "status": "HANDOFF_ACK_ACCEPTED",
        "action": "STEP_OUT_CONFIRMED",
        "model_routed": "C2_BEACONING_JITTER",
        "compiled_query": "stage host_intervals { ... }",
    }
    card = format_handoff_card(payload, ack)
    self.assertIn("Endpoint ACK**: `HANDOFF_ACK_ACCEPTED`", card)
    self.assertIn("Model Routed**: `C2_BEACONING_JITTER`", card)
    self.assertIn("stage host_intervals", card)

  def test_dispatch_to_endpoint_receives_ack(self):
    """Dispatching to secops-statistical-hunter must receive HANDOFF_ACK_ACCEPTED and STEP_OUT_CONFIRMED."""
    payload = build_handoff_payload(
        intent="SCHEDULED_EXFILTRATION_TIMING",
        entity_type="HOSTNAME",
        entity_value="site-rev-proxy",
        lookback="24h",
    )
    ack = dispatch_to_endpoint(payload)
    self.assertEqual(ack.get("status"), "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(ack.get("action"), "STEP_OUT_CONFIRMED")
    self.assertEqual(ack.get("model_routed"), "C2_BEACONING_JITTER")
    self.assertIn("stage host_intervals", ack.get("compiled_query", ""))
    self.assertIn("SOURCE_SKILL_STEP_OUT_CONFIRMED", ack.get("step_out_directive", ""))


if __name__ == "__main__":
  unittest.main()
