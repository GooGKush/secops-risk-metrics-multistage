# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Regression test suite for Clean Hand-Off (CH) synthetic UDM ingestion in Google SecOps.

Validates:
1. Synthetic UDM event generation across all 9 canonical product event types.
2. Strict compliance with official Chronicle UDM specification (important-udm-fields).
3. Correlated multi-event batching with shared Hunt Campaign ID.
4. Rejection of invalid/obsolete schema constructs (e.g. integer resource_type).
5. Pre-ingestion clearance card formatting and affirmative workflow.
6. Ingestion payload serialization for Chronicle SIEM API / SecOps GUS MCP.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import unittest

# Ensure skill root is in path
SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT))

from scripts.clean_handoff import (
    CANONICAL_PRODUCT_EVENT_TYPES,
    CHRONICLE_INGESTION_LOG_TYPE,
    CATCHALL_RULE_NAME,
    build_synthetic_udm_event,
    build_multi_event_batch,
    validate_clean_handoff_udm,
    format_pre_ingestion_clearance_card,
    prepare_chronicle_import_logs_args,
    map_cri_to_severity,
)


class TestCleanHandoffRegression(unittest.TestCase):
  """Regression test suite asserting complete Clean Hand-Off compliance and Chronicle ingestion."""

  def setUp(self):
    self.customer_id = "8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5"
    self.project_id = "gus-sdl"
    self.region = "us"
    self.forwarder_id = "155c709b-37f1-46fc-be7e-5af35db0ea5c"

  def test_all_9_canonical_product_event_types_generate_valid_udm(self):
    """Every one of the 9 canonical product_event_type variants must pass strict UDM validation."""
    for pet in CANONICAL_PRODUCT_EVENT_TYPES:
      with self.subTest(product_event_type=pet):
        event = build_synthetic_udm_event(
            product_event_type=pet,
            entity_id="test-entity-01",
            entity_type="USER",
            statistical_model=pet.replace("_", " ").title(),
            z_score=3.85,
            cri_score=72,
            observed_value=15,
            historical_mean=1.2,
            historical_stddev=0.4,
            summary=f"Automated regression test event for {pet}",
            hunt_campaign_id="hunt-regression-test-01",
            event_timestamp="2026-09-10T20:00:00Z",
        )
        errors = validate_clean_handoff_udm(event)
        self.assertEqual(errors, [], f"Validation errors for {pet}: {errors}")

        udm = event["udm"]
        self.assertEqual(udm["metadata"]["product_event_type"], pet)
        self.assertEqual(udm["metadata"]["product_name"], "SecOps Risk Metrics Hunter")
        self.assertEqual(udm["metadata"]["vendor_name"], "Google SecOps")
        self.assertEqual(udm["metadata"]["event_type"], "GENERIC_EVENT")
        self.assertEqual(udm["observer"]["hostname"], "secops-risk-metrics-hunter")
        self.assertEqual(udm["observer"]["application"], "Google SecOps Multi-Stage Risk Analytics")
        self.assertEqual(udm["target"]["resource"]["resource_type"], "RESOURCE_TYPE_UNSPECIFIED")
        self.assertEqual(udm["security_result"][0]["threat_id_namespace"], "MITRE_ATTACK")
        self.assertEqual(udm["security_result"][0]["risk_score"], 72)
        self.assertEqual(udm["security_result"][0]["severity"], "HIGH")

  def test_rejection_of_unknown_product_event_type(self):
    """Building an event with an unknown product_event_type must raise ValueError."""
    with self.assertRaises(ValueError):
      build_synthetic_udm_event(
          product_event_type="UNREGISTERED_ANOMALY_TYPE",
          entity_id="user01",
          entity_type="USER",
          statistical_model="Z-Score",
          z_score=3.0,
          cri_score=50,
          observed_value=10,
          historical_mean=2.0,
          historical_stddev=1.0,
          summary="Test",
      )

  def test_validator_rejects_obsolete_integer_resource_type(self):
    """Validator must strictly reject obsolete 'resource_type: 0' integer."""
    event = build_synthetic_udm_event(
        product_event_type="VOLUMETRIC_BASELINE_ANOMALY",
        entity_id="user01",
        entity_type="USER",
        statistical_model="Standard Z-Score",
        z_score=3.5,
        cri_score=65,
        observed_value=20,
        historical_mean=2.0,
        historical_stddev=1.0,
        summary="Test",
    )
    # Tamper with resource_type
    event["udm"]["target"]["resource"]["resource_type"] = 0
    errors = validate_clean_handoff_udm(event)
    self.assertTrue(any("Obsolete integer 'resource_type: 0' is forbidden" in e for e in errors))

  def test_validator_enforces_iso8601_utc_timestamps(self):
    """Timestamps must end in Z and follow ISO 8601 formatting."""
    event = build_synthetic_udm_event(
        product_event_type="BURST_CLUSTER_ANOMALY",
        entity_id="host-01",
        entity_type="HOSTNAME",
        statistical_model="Poisson Dispersion",
        z_score=4.0,
        cri_score=75,
        observed_value=30,
        historical_mean=1.0,
        historical_stddev=0.5,
        summary="Test burst",
    )
    event["udm"]["metadata"]["event_timestamp"] = "2026-09-10 16:00:00"  # Missing T and Z
    errors = validate_clean_handoff_udm(event)
    self.assertTrue(any("must be ISO 8601 UTC string ending in 'Z'" in e for e in errors))

  def test_multi_event_batch_correlation_and_shared_campaign_id(self):
    """Multi-event batch must bind all distinct findings under a single shared Hunt Campaign ID."""
    findings = [
        {
            "product_event_type": "VOLUMETRIC_BASELINE_ANOMALY",
            "entity_id": "admin@demo.wsexample.org",
            "entity_type": "USER",
            "statistical_model": "Standard Z-Score",
            "z_score": 4.10,
            "cri_score": 73,
            "observed_value": "12 BigQuery Operations",
            "historical_mean": 0.4,
            "historical_stddev": 0.8,
            "summary": "12 BigQuery operations transferring table data to Google Drive (+4.10σ).",
            "threat_id": "T1567.002",
            "mitre_tactics": ["TA0010_EXFILTRATION"],
            "mitre_techniques": ["T1567.002"],
        },
        {
            "product_event_type": "BURST_CLUSTER_ANOMALY",
            "entity_id": "serhatg",
            "entity_type": "USER",
            "statistical_model": "Poisson Dispersion / Fano Factor",
            "z_score": 3.82,
            "cri_score": 68,
            "observed_value": "11 Failed Su Attempts",
            "historical_mean": 0.1,
            "historical_stddev": 0.3,
            "summary": "11 failed su attempts to root on prod-linux (+3.82σ above baseline).",
            "threat_id": "T1548.003",
            "mitre_tactics": ["TA0004_PRIVILEGE_ESCALATION"],
            "mitre_techniques": ["T1548.003"],
        },
    ]

    shared_campaign = "HUNT-CAMP-20260827-BURST"
    batch = build_multi_event_batch(findings, hunt_campaign_id=shared_campaign)

    self.assertEqual(len(batch), 2)

    for item in batch:
      errors = validate_clean_handoff_udm(item)
      self.assertEqual(errors, [])
      u = item["udm"]
      labels = {l["key"]: l["value"] for l in u["metadata"]["ingestion_labels"]}
      self.assertEqual(labels["hunt_campaign_id"], shared_campaign)
      resource_labels = {l["key"]: l["value"] for l in u["target"]["resource"]["attribute"]["labels"]}
      self.assertEqual(resource_labels["Hunt Campaign ID"], shared_campaign)

  def test_pre_ingestion_clearance_card_format(self):
    """Clearance card must include customer, project, campaign, and structured tabular preview."""
    findings = [{
        "product_event_type": "VOLUMETRIC_BASELINE_ANOMALY",
        "entity_id": "admin@demo.wsexample.org",
        "entity_type": "USER",
        "statistical_model": "Standard Z-Score",
        "z_score": 4.10,
        "cri_score": 73,
        "observed_value": 12,
        "historical_mean": 0.4,
        "historical_stddev": 0.8,
        "summary": "BigQuery exfiltration anomaly",
    }]
    batch = build_multi_event_batch(findings, hunt_campaign_id="hunt-card-test")
    card = format_pre_ingestion_clearance_card(
        batch=batch,
        customer_id=self.customer_id,
        project_id=self.project_id,
        campaign_id="hunt-card-test",
    )

    self.assertIn("PRE-INGESTION CLEARANCE SPECIFICATION", card)
    self.assertIn(self.customer_id, card)
    self.assertIn(self.project_id, card)
    self.assertIn("hunt-card-test", card)
    self.assertIn("admin@demo.wsexample.org", card)
    self.assertIn("VOLUMETRIC_BASELINE_ANOMALY", card)
    self.assertIn("Would you like me to ingest this Synthetic UDM Security Event batch", card)

  def test_chronicle_import_logs_payload_structure(self):
    """Chronicle import_logs args must default to CUSTOM_SECURITY_DATA_ANALYTICS logType."""
    findings = [{
        "product_event_type": "FLEET_NORMALIZED_DELTA_Z",
        "entity_id": "srv-app-04",
        "entity_type": "HOSTNAME",
        "statistical_model": "Fleet Normalized Delta Z",
        "z_score": 3.42,
        "cri_score": 64,
        "observed_value": 18,
        "historical_mean": 2.1,
        "historical_stddev": 0.9,
        "summary": "Host breakout above fleet cluster",
    }]
    batch = build_multi_event_batch(findings)
    args = prepare_chronicle_import_logs_args(
        batch=batch,
        customer_id=self.customer_id,
        project_id=self.project_id,
        region=self.region,
        forwarder_id=self.forwarder_id,
    )

    self.assertEqual(args["customerId"], self.customer_id)
    self.assertEqual(args["projectId"], self.project_id)
    self.assertEqual(args["region"], self.region)
    self.assertEqual(args["logType"], CHRONICLE_INGESTION_LOG_TYPE)
    self.assertEqual(args["forwarderId"], self.forwarder_id)
    self.assertEqual(len(args["logs"]), 1)

    # Verify log string deserializes to valid UDM dict
    parsed = json.loads(args["logs"][0])
    self.assertEqual(validate_clean_handoff_udm(parsed), [])

  def test_cri_to_severity_mapping(self):
    """CRI threshold mapping must adhere strictly to Chronicle severity bands."""
    self.assertEqual(map_cri_to_severity(85), "CRITICAL")
    self.assertEqual(map_cri_to_severity(70), "HIGH")
    self.assertEqual(map_cri_to_severity(50), "MEDIUM")
    self.assertEqual(map_cri_to_severity(25), "LOW")
    self.assertEqual(map_cri_to_severity(10), "INFORMATIONAL")


if __name__ == "__main__":
  unittest.main()
