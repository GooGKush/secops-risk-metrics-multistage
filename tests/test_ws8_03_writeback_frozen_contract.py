# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""WS8-03: Characterization tests pinning the frozen D7 write-back contract.

Per Decision D7, the SecOps Risk Metrics Hunter write-back path (chronicle_ingest.py,
references/clean-handoff-udm-schema.md, and SKILL.md Clean Hand-Off instructions)
is a frozen interface depended upon by downstream runbooks and catch-all detections.
"""

import base64
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.chronicle_ingest import (
    DEFAULT_API_VERSION,
    DEFAULT_FORWARDER_ID,
    REQUIRED_METADATA_FIELDS,
    SUPPORTED_API_VERSIONS,
    WRONG_METHOD_FIELDS,
    _load_events,
    build_import_events_body,
    build_import_events_url,
    build_import_logs_payload,
    generate_catchall_yaral_rule,
    validate_events,
)

EXPECTED_10_PRODUCT_EVENT_TYPES = (
    "VOLUMETRIC_BASELINE_ANOMALY",
    "BURST_CLUSTER_ANOMALY",
    "DISCRETE_RARITY_ANOMALY",
    "BAYESIAN_SHRINKAGE_ANOMALY",
    "PEER_COHORT_BREAKOUT_ANOMALY",
    "FLEET_NORMALIZED_DELTA_Z",
    "MULTI_SECTOR_THREAT_FUSION",
    "LONGITUDINAL_CUSUM_DRIFT",
    "ENTITY_GRAPH_RARITY_OUTLIER",
    "BEHAVIORAL_RISK_RADAR_360",
)


def _extract_canonical_schema_payloads() -> dict[str, dict]:
  """Extracts the 10 numbered canonical product_event_type JSON blocks from clean-handoff-udm-schema.md."""
  schema_doc = (REPO_ROOT / "references" / "clean-handoff-udm-schema.md").read_text(
      encoding="utf-8"
  )
  pattern = re.compile(
      r"###\s+\d+\.\s+`([A-Z0-9_]+)`[^\n]*\n(?:(?!```json).)*?```json\n(.*?)\n```",
      re.DOTALL,
  )
  extracted: dict[str, dict] = {}
  for match in pattern.finditer(schema_doc):
    event_type_key = match.group(1)
    parsed = json.loads(match.group(2))
    extracted[event_type_key] = parsed
  return extracted


class TestWS803WritebackFrozenContract(unittest.TestCase):
  """Pins the frozen D7 write-back payload schema, chronicle_ingest helpers, and SKILL.md handoff instructions."""

  def test_chronicle_ingest_frozen_constants_and_url_builders(self):
    self.assertEqual(DEFAULT_API_VERSION, "v1alpha")
    self.assertEqual(SUPPORTED_API_VERSIONS, ("v1alpha", "v1beta", "v1"))
    self.assertEqual(
        WRONG_METHOD_FIELDS,
        ("forwarderId", "forwarder_id", "logType", "log_type"),
    )
    self.assertEqual(
        REQUIRED_METADATA_FIELDS,
        (
            ("event_timestamp", "eventTimestamp"),
            ("event_type", "eventType"),
            ("vendor_name", "vendorName"),
            ("product_name", "productName"),
        ),
    )

    events_url = build_import_events_url(
        project_id="gus-sdl",
        region="us",
        customer_id="8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5",
    )
    self.assertEqual(
        events_url,
        "https://us-chronicle.googleapis.com/v1alpha/projects/gus-sdl/"
        "locations/us/instances/8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5/events:import",
    )

  def test_chronicle_ingest_body_and_udm_log_payload_builders(self):
    schemas = _extract_canonical_schema_payloads()
    radar_udm = schemas["BEHAVIORAL_RISK_RADAR_360"]["udm"]

    body = build_import_events_body([radar_udm])
    self.assertEqual(body, {"inlineSource": {"events": [{"udm": radar_udm}]}})

    # _load_events unwraps Clean Hand-Off {"udm": ...} envelopes cleanly
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8") as tmp:
      json.dump([{"udm": radar_udm}], tmp)
      tmp.flush()
      loaded = _load_events(tmp.name)
    self.assertEqual(loaded, [radar_udm])
    self.assertEqual(build_import_events_body(loaded), body)

    # Legacy logs:import payload defaults strictly to log_type="UDM"
    logs_payload = build_import_logs_payload([radar_udm])
    self.assertEqual(logs_payload["log_type"], "UDM")
    self.assertEqual(logs_payload["forwarder_id"], DEFAULT_FORWARDER_ID)
    self.assertIn("inline_source", logs_payload)
    self.assertEqual(logs_payload["inline_source"]["forwarder"], DEFAULT_FORWARDER_ID)
    encoded_data = logs_payload["inline_source"]["logs"][0]["data"]
    decoded_udm = json.loads(base64.b64decode(encoded_data).decode("utf-8"))
    self.assertEqual(decoded_udm["metadata"]["product_name"], "SecOps Risk Metrics Hunter")
    self.assertEqual(decoded_udm["metadata"]["product_event_type"], "BEHAVIORAL_RISK_RADAR_360")

  def test_catchall_yaral_rule_pins_vendor_product_and_risk_gate(self):
    rule_text = generate_catchall_yaral_rule()
    self.assertIn('$e.metadata.vendor_name = "Google SecOps"', rule_text)
    self.assertIn('$e.metadata.product_name = "SecOps Risk Metrics Hunter"', rule_text)
    self.assertIn("$e.security_result.risk_score >= 50", rule_text)
    self.assertIn("allow_zero_values = true", rule_text)

  def test_all_10_canonical_clean_handoff_udm_schemas_frozen(self):
    schemas = _extract_canonical_schema_payloads()
    self.assertEqual(tuple(schemas.keys()), EXPECTED_10_PRODUCT_EVENT_TYPES)

    for expected_pet in EXPECTED_10_PRODUCT_EVENT_TYPES:
      with self.subTest(product_event_type=expected_pet):
        envelope = schemas[expected_pet]
        self.assertIn("udm", envelope)
        udm = envelope["udm"]
        self.assertEqual(validate_events([udm]), [])

        meta = udm["metadata"]
        self.assertEqual(meta["product_name"], "SecOps Risk Metrics Hunter")
        self.assertEqual(meta["vendor_name"], "Google SecOps")
        self.assertEqual(meta["event_type"], "GENERIC_EVENT")
        self.assertEqual(meta["product_event_type"], expected_pet)
        self.assertIsInstance(meta["event_timestamp"], str)

        ingestion_labels = {
            item["key"]: item["value"] for item in meta.get("ingestion_labels", [])
        }
        self.assertIn("hunt_campaign_id", ingestion_labels)
        self.assertEqual(
            ingestion_labels.get("source_skill"), "secops-risk-metrics-multistage"
        )

        resource = udm["target"]["resource"]
        self.assertEqual(resource["name"], expected_pet)
        labels = resource["attribute"]["labels"]
        self.assertIsInstance(labels, list)
        self.assertGreater(len(labels), 0)
        label_keys = [entry["key"] for entry in labels]
        self.assertIn("Hunt Campaign ID", label_keys)
        for entry in labels:
          self.assertIsInstance(entry["key"], str)
          self.assertIsInstance(entry["value"], str)

        sec_results = udm["security_result"]
        self.assertIsInstance(sec_results, list)
        self.assertGreaterEqual(len(sec_results), 1)
        for sr in sec_results:
          self.assertIsInstance(sr["risk_score"], int)
          self.assertNotIsInstance(sr["risk_score"], bool)
          self.assertIsInstance(sr["severity"], str)
          self.assertIsInstance(sr["summary"], str)
          if "confidence_score" in sr:
            self.assertIsInstance(sr["confidence_score"], (int, float))
            self.assertNotIsInstance(sr["confidence_score"], bool)

  def test_volumetric_and_radar_360_specific_field_contracts(self):
    schemas = _extract_canonical_schema_payloads()

    # Schema 1: VOLUMETRIC_BASELINE_ANOMALY single-entry security_result
    vol_udm = schemas["VOLUMETRIC_BASELINE_ANOMALY"]["udm"]
    vol_labels = {
        item["key"]: item["value"]
        for item in vol_udm["target"]["resource"]["attribute"]["labels"]
    }
    for required_key in (
        "Hunt Campaign ID",
        "Statistical Model",
        "Observed Volume",
        "Historical 30d Mean",
        "Historical 30d StdDev",
        "Z-Score",
        "CRI Score",
        "Active Baseline Days",
    ):
      self.assertIn(required_key, vol_labels)
    vol_sr = vol_udm["security_result"][0]
    self.assertIsInstance(vol_sr["risk_score"], int)
    self.assertIsInstance(vol_sr["confidence_score"], float)

    # Schema 10: BEHAVIORAL_RISK_RADAR_360 multi-entry COMPOSITE_360 + SECTOR_VECTOR contract
    radar_udm = schemas["BEHAVIORAL_RISK_RADAR_360"]["udm"]
    self.assertNotIn("ingested_timestamp", radar_udm["metadata"])
    radar_label_keys = [
        item["key"]
        for item in radar_udm["target"]["resource"]["attribute"]["labels"]
    ]
    self.assertEqual(
        radar_label_keys,
        [
            "Hunt Campaign ID",
            "Evaluated Day",
            "Composite CRI",
            "Composite D",
            "Peak Vector",
            "Peak CRI",
            "Peak Z",
            "Breached Vectors",
        ],
    )

    radar_srs = radar_udm["security_result"]
    self.assertGreaterEqual(len(radar_srs), 2)
    composite_sr = radar_srs[0]
    self.assertEqual(composite_sr["rule_name"], "360 Behavioral Risk Radar")
    self.assertEqual(composite_sr["rule_type"], "COMPOSITE_360")
    self.assertNotIn("threat_name", composite_sr)
    self.assertNotIn("confidence_score", composite_sr)
    self.assertIsInstance(composite_sr["risk_score"], int)

    for vec_sr in radar_srs[1:]:
      self.assertEqual(vec_sr["rule_type"], "SECTOR_VECTOR")
      self.assertTrue(vec_sr["rule_name"].startswith("360 Vector: "))
      self.assertIsInstance(vec_sr["threat_name"], str)
      self.assertIsInstance(vec_sr["risk_score"], int)
      self.assertIsInstance(vec_sr["confidence_score"], float)
      self.assertIn(vec_sr["threat_status"], ("ACTIVE", "CLEARED"))

  def test_skill_md_clean_handoff_instructions_intact(self):
    skill_md = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    self.assertIn("references/clean-handoff-udm-schema.md", skill_md)
    self.assertIn("import_events", skill_md)
    self.assertIn("create_case_comment", skill_md)
    self.assertIn("CRITICAL PROCESS POLLUTION VIOLATION", skill_md)


if __name__ == "__main__":
  unittest.main()
