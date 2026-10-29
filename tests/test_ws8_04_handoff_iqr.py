# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""WS8-04: Regression tests for EXFILTRATION_IQR_OUTLIER handoff routing and parameters.

Verifies that EXFILTRATION_IQR_OUTLIER (and IQR_TUKEY_SKEW_FENCES) are first-class
supported intents in scripts/federated_handoff.py and are never coerced to C2
beaconing jitter (max_cv / min_observations / micro-timing justification).
"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.federated_handoff import (
    HandoffReason,
    SUPPORTED_INTENTS,
    SUPPORTED_PROTOCOL,
    _inprocess_fallback_ack,
    build_handoff_payload,
    dispatch_to_endpoint,
)
from scripts.preflight_validator import MalachiteASTValidator


class TestWS804HandoffIQR(unittest.TestCase):
  """Tests EXFILTRATION_IQR_OUTLIER and micro-model handoff routing without C2 coercion."""

  def test_handoff_reason_and_supported_intents_include_iqr_and_micro_models(self):
    expected_new_intents = (
        "EXFILTRATION_IQR_OUTLIER",
        "IQR_TUKEY_SKEW_FENCES",
        "SHANNON_ENTROPY_CHARACTER",
        "MARKOV_2GRAM_TRANSITION_RARITY",
        "ZIPFIAN_PROCESS_RARITY",
        "EWMA_BURST_VELOCITY",
    )
    enum_values = {member.value for member in HandoffReason}
    for intent in expected_new_intents:
      with self.subTest(intent=intent):
        self.assertIn(intent, enum_values)
        self.assertIn(intent, SUPPORTED_INTENTS)

  def test_exfiltration_iqr_outlier_payload_is_not_coerced_to_c2_jitter(self):
    for intent in ("EXFILTRATION_IQR_OUTLIER", "IQR_TUKEY_SKEW_FENCES"):
      with self.subTest(intent=intent):
        payload = build_handoff_payload(
            intent=intent,
            entity_type="HOSTNAME",
            entity_value="srv-db-export-01.corp",
            lookback="24h",
            sensitivity="BALANCED",
        )
        self.assertEqual(payload["protocol"], SUPPORTED_PROTOCOL)
        self.assertEqual(payload["intent"], intent)
        self.assertEqual(payload["statistical_model"]["name"], "IQR_TUKEY_SKEW_FENCES")

        params = payload["statistical_model"]["parameters"]
        self.assertEqual(params.get("fence_z"), 3.5)
        self.assertEqual(params.get("min_iqr"), 10.0)
        self.assertNotIn("max_cv", params)
        self.assertNotIn("min_observations", params)

        just_lower = payload["justification"].lower()
        self.assertTrue(
            "iqr" in just_lower or "tukey" in just_lower,
            f"Expected IQR/Tukey justification, got: {payload['justification']}",
        )
        self.assertNotIn("sub-second interval regularity", just_lower)
        self.assertNotIn("micro-timing variance", just_lower)

  def test_data_exfiltration_spike_vs_scheduled_exfiltration_timing_separation(self):
    spike_payload = build_handoff_payload(
        intent="DATA_EXFILTRATION_SPIKE",
        entity_type="HOSTNAME",
        entity_value="wkst-09.corp",
        lookback="24h",
    )
    spike_params = spike_payload["statistical_model"]["parameters"]
    self.assertEqual(spike_params.get("m_z"), 3.5)
    self.assertNotIn("max_cv", spike_params)
    self.assertNotIn("sub-second interval regularity", spike_payload["justification"].lower())

    timing_payload = build_handoff_payload(
        intent="SCHEDULED_EXFILTRATION_TIMING",
        entity_type="HOSTNAME",
        entity_value="wkst-09.corp",
        lookback="24h",
    )
    timing_params = timing_payload["statistical_model"]["parameters"]
    self.assertEqual(timing_params.get("max_cv"), 0.20)
    self.assertEqual(timing_params.get("min_observations"), 10)

  def test_shannon_entropy_payload_not_shadowed_by_diversity_deficit(self):
    shannon_payload = build_handoff_payload(
        intent="SHANNON_ENTROPY_CHARACTER",
        entity_type="HOSTNAME",
        entity_value="dns-client-07.corp",
        lookback="6h",
    )
    shannon_params = shannon_payload["statistical_model"]["parameters"]
    self.assertNotIn("max_diversity_ratio", shannon_params)
    self.assertIn("min_entropy", shannon_params)

  def test_inprocess_fallback_routes_iqr_and_binds_entity_across_all_branches(self):
    for intent in ("EXFILTRATION_IQR_OUTLIER", "IQR_TUKEY_SKEW_FENCES", "TUKEY_IQR_OUTLIER"):
      with self.subTest(intent=intent):
        payload = build_handoff_payload(
            intent=intent,
            entity_type="HOSTNAME",
            entity_value="srv-db-export-01.corp",
            lookback="24h",
        )
        ack = _inprocess_fallback_ack(payload)
        self.assertEqual(ack["status"], "HANDOFF_ACK_ACCEPTED")
        self.assertEqual(ack["action"], "STEP_OUT_CONFIRMED")
        self.assertEqual(ack["model_routed"], "IQR_TUKEY_SKEW_FENCES")
        query = ack["compiled_query"]
        self.assertIn('"srv-db-export-01.corp"', query)
        self.assertEqual(MalachiteASTValidator.validate_query(query), [])

    # Verify every fallback branch binds non-fleet entity_value in the query body
    branch_cases = [
        ("SCHEDULED_EXFILTRATION_TIMING", "HOSTNAME", "proxy-alpha.corp"),
        ("PRIVILEGED_LATERAL_EXPANSION", "USER", "svc_backup_admin"),
        ("HOUR_OF_DAY_PROFILE", "USER", "jdoe_ops"),
        ("SHANNON_ENTROPY_CHARACTER", "HOSTNAME", "wkst-dga-02.corp"),
    ]
    for intent, ent_type, ent_val in branch_cases:
      with self.subTest(fallback_branch=intent):
        payload = build_handoff_payload(
            intent=intent,
            entity_type=ent_type,
            entity_value=ent_val,
            lookback="24h",
        )
        ack = _inprocess_fallback_ack(payload)
        query_non_comment = "\n".join(
            line for line in ack["compiled_query"].splitlines()
            if not line.strip().startswith("//")
        )
        self.assertIn(f'"{ent_val}"', query_non_comment)
        self.assertEqual(MalachiteASTValidator.validate_query(ack["compiled_query"]), [])

  def test_dispatch_to_endpoint_accepts_exfiltration_iqr_outlier(self):
    payload = build_handoff_payload(
        intent="EXFILTRATION_IQR_OUTLIER",
        entity_type="HOSTNAME",
        entity_value="srv-db-export-01.corp",
        lookback="24h",
    )
    ack = dispatch_to_endpoint(payload)
    self.assertEqual(ack.get("status"), "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(ack.get("action"), "STEP_OUT_CONFIRMED")
    self.assertEqual(ack.get("model_routed"), "IQR_TUKEY_SKEW_FENCES")


if __name__ == "__main__":
  unittest.main()
