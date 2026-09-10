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

"""Clean Hand-Off (CH) protocol module for secops-risk-metrics-multistage.

Provides schema validation, synthetic UDM event construction, multi-event batching,
and Chronicle ingestion dispatch for promoting statistical threat hunt outliers into
security alerts and cases without polluting process spaces.
"""

from datetime import datetime, timezone
import json
import re
from typing import Any, Dict, List, Optional
import uuid

# Canonical 9 Product Event Types
CANONICAL_PRODUCT_EVENT_TYPES = [
    "VOLUMETRIC_BASELINE_ANOMALY",
    "BURST_CLUSTER_ANOMALY",
    "DISCRETE_RARITY_ANOMALY",
    "BAYESIAN_SHRINKAGE_ANOMALY",
    "PEER_COHORT_BREAKOUT_ANOMALY",
    "FLEET_NORMALIZED_DELTA_Z",
    "MULTI_SECTOR_THREAT_FUSION",
    "LONGITUDINAL_CUSUM_DRIFT",
    "ENTITY_GRAPH_RARITY_OUTLIER",
]

# Primary Ingestion Log Type for Chronicle Ingestion Gateway
CHRONICLE_INGESTION_LOG_TYPE = "CUSTOM_SECURITY_DATA_ANALYTICS"

# Catch-All Rule Name
CATCHALL_RULE_NAME = "secops_risk_metrics_synthetic_alert_catchall"

# Valid Severities
VALID_SEVERITIES = {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def map_cri_to_severity(cri: float) -> str:
  """Maps Calibrated Risk Index (0-100) to standard Chronicle severity."""
  if cri >= 80:
    return "CRITICAL"
  if cri >= 60:
    return "HIGH"
  if cri >= 40:
    return "MEDIUM"
  if cri >= 20:
    return "LOW"
  return "INFORMATIONAL"


def build_synthetic_udm_event(
    product_event_type: str,
    entity_id: str,
    entity_type: str,  # "USER", "HOSTNAME", "SERVICE_ACCOUNT"
    statistical_model: str,
    z_score: float,
    cri_score: int,
    observed_value: Any,
    historical_mean: float,
    historical_stddev: float,
    summary: str,
    hunt_campaign_id: Optional[str] = None,
    event_timestamp: Optional[str] = None,
    threat_id: str = "T1078",
    mitre_tactics: Optional[List[str]] = None,
    mitre_techniques: Optional[List[str]] = None,
    extra_labels: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
  """Constructs an authentic, schema-validated synthetic UDM event dict conforming to official Chronicle standards."""
  if product_event_type not in CANONICAL_PRODUCT_EVENT_TYPES:
    raise ValueError(
        f"Invalid product_event_type: '{product_event_type}'. "
        f"Must be one of {CANONICAL_PRODUCT_EVENT_TYPES}"
    )

  campaign_id = hunt_campaign_id or f"hunt-{uuid.uuid4().hex[:8]}"
  now_iso = event_timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
  severity = map_cri_to_severity(cri_score)

  # Construct base metadata
  metadata: Dict[str, Any] = {
      "event_timestamp": now_iso,
      "ingested_timestamp": now_iso,
      "product_name": "SecOps Risk Metrics Hunter",
      "vendor_name": "Google SecOps",
      "event_type": "GENERIC_EVENT",
      "product_event_type": product_event_type,
      "description": f"Statistical Outlier ({product_event_type}): {entity_id} breached 30d baseline by {z_score:+.2f}σ (CRI: {cri_score})",
      "ingestion_labels": [
          {"key": "hunt_campaign_id", "value": campaign_id},
          {"key": "source_skill", "value": "secops-risk-metrics-multistage"},
          {"key": "statistical_model", "value": statistical_model},
      ],
  }

  observer = {
      "hostname": "secops-risk-metrics-hunter",
      "application": "Google SecOps Multi-Stage Risk Analytics",
  }

  principal: Dict[str, Any] = {}
  target: Dict[str, Any] = {}

  if entity_type.upper() in ("USER", "USER_ID", "SERVICE_ACCOUNT"):
    principal["user"] = {"userid": entity_id}
  elif entity_type.upper() in ("HOSTNAME", "HOST", "ASSET"):
    principal["hostname"] = entity_id
    principal["asset"] = {"hostname": entity_id}
  else:
    principal["user"] = {"userid": entity_id}

  # Build resource labels
  resource_labels = [
      {"key": "Hunt Campaign ID", "value": campaign_id},
      {"key": "Statistical Model", "value": statistical_model},
      {"key": "Observed Value", "value": str(observed_value)},
      {"key": "Historical 30d Mean", "value": f"{historical_mean:.2f}"},
      {"key": "Historical 30d StdDev", "value": f"{historical_stddev:.2f}"},
      {"key": "Z-Score", "value": f"{z_score:.2f}"},
      {"key": "CRI Score", "value": str(cri_score)},
      {"key": "Active Baseline Days", "value": "30"},
  ]

  if extra_labels:
    for k, v in extra_labels.items():
      resource_labels.append({"key": k, "value": str(v)})

  target["resource"] = {
      "name": product_event_type,
      "resource_type": "RESOURCE_TYPE_UNSPECIFIED",
      "attribute": {"labels": resource_labels},
  }

  detection_fields = [
      {"key": "source_skill", "value": "secops-risk-metrics-multistage"},
      {"key": "hunt_campaign_id", "value": campaign_id},
      {"key": "z_score", "value": f"{z_score:.2f}"},
      {"key": "cri_score", "value": str(cri_score)},
  ]
  if mitre_tactics:
    for t in mitre_tactics:
      detection_fields.append({"key": "mitre_tactics", "value": t})
  if mitre_techniques:
    for t in mitre_techniques:
      detection_fields.append({"key": "mitre_techniques", "value": t})

  security_result = [{
      "threat_name": f"Statistical Outlier: {statistical_model}",
      "threat_id": threat_id,
      "threat_id_namespace": "MITRE_ATTACK",
      "category": ["SUSPICIOUS_ACTIVITY"],
      "category_details": [product_event_type],
      "action": ["UNKNOWN_ACTION"],
      "risk_score": int(cri_score),
      "severity": severity,
      "summary": summary,
      "description": (
          f"Statistical baseline departure detected for {entity_id} using {statistical_model}. "
          f"Observed={observed_value} vs 30-day baseline μ={historical_mean:.2f}, σ={historical_stddev:.2f} "
          f"(Z={z_score:+.2f}σ, CRI={cri_score})."
      ),
      "detection_fields": detection_fields,
  }]

  return {
      "udm": {
          "metadata": metadata,
          "observer": observer,
          "principal": principal,
          "target": target,
          "security_result": security_result,
      }
  }


def build_multi_event_batch(
    findings: List[Dict[str, Any]],
    hunt_campaign_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
  """Builds a correlated array of synthetic UDM events bound by a shared Hunt Campaign ID."""
  shared_id = hunt_campaign_id or f"hunt-{uuid.uuid4().hex[:8]}"
  batch = []
  for f in findings:
    event = build_synthetic_udm_event(
        product_event_type=f["product_event_type"],
        entity_id=f["entity_id"],
        entity_type=f.get("entity_type", "USER"),
        statistical_model=f.get("statistical_model", "Standard Z-Score"),
        z_score=f["z_score"],
        cri_score=f["cri_score"],
        observed_value=f["observed_value"],
        historical_mean=f["historical_mean"],
        historical_stddev=f["historical_stddev"],
        summary=f["summary"],
        hunt_campaign_id=shared_id,
        event_timestamp=f.get("event_timestamp"),
        threat_id=f.get("threat_id", "T1078"),
        mitre_tactics=f.get("mitre_tactics"),
        mitre_techniques=f.get("mitre_techniques"),
        extra_labels=f.get("extra_labels"),
    )
    batch.append(event)
  return batch


def validate_clean_handoff_udm(payload: Dict[str, Any]) -> List[str]:
  """Validates that a synthetic UDM payload conforms strictly to Chronicle requirements.

  Returns a list of validation error strings (empty if valid).
  """
  errors = []

  if not isinstance(payload, dict):
    return ["Payload must be a dictionary"]

  if "udm" not in payload:
    return ["Payload must contain top-level 'udm' key"]

  udm = payload["udm"]

  # 1. Metadata Checks
  metadata = udm.get("metadata", {})
  if not metadata:
    errors.append("Missing 'metadata' block in UDM")
  else:
    for req in ("event_timestamp", "ingested_timestamp", "product_name", "vendor_name", "event_type", "product_event_type"):
      if req not in metadata or not metadata[req]:
        errors.append(f"Missing required metadata field: '{req}'")

    if metadata.get("product_event_type") not in CANONICAL_PRODUCT_EVENT_TYPES:
      errors.append(
          f"Invalid product_event_type '{metadata.get('product_event_type')}'. "
          f"Expected one of {CANONICAL_PRODUCT_EVENT_TYPES}"
      )

    for ts_field in ("event_timestamp", "ingested_timestamp"):
      ts = metadata.get(ts_field, "")
      if ts and not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$", ts):
        errors.append(f"Field '{ts_field}' must be ISO 8601 UTC string ending in 'Z': found '{ts}'")

  # 2. Observer Block
  observer = udm.get("observer", {})
  if not observer:
    errors.append("Missing 'observer' block in UDM")
  else:
    if not observer.get("hostname"):
      errors.append("Missing 'observer.hostname'")
    if not observer.get("application"):
      errors.append("Missing 'observer.application'")

  # 3. Principal / Target
  if not udm.get("principal"):
    errors.append("Missing 'principal' block in UDM")

  target = udm.get("target", {})
  if not target or not target.get("resource"):
    errors.append("Missing 'target.resource' in UDM")
  else:
    resource = target["resource"]
    # Check that resource_type is NOT obsolete integer 0
    if resource.get("resource_type") == 0:
      errors.append("Obsolete integer 'resource_type: 0' is forbidden; use 'RESOURCE_TYPE_UNSPECIFIED'")
    if resource.get("resource_type") != "RESOURCE_TYPE_UNSPECIFIED":
      errors.append("Expected resource_type 'RESOURCE_TYPE_UNSPECIFIED'")

  # 4. Security Result
  sec_results = udm.get("security_result", [])
  if not sec_results or not isinstance(sec_results, list):
    errors.append("Missing 'security_result' array in UDM")
  else:
    sr = sec_results[0]
    if not sr.get("threat_name"):
      errors.append("Missing 'security_result.threat_name'")
    if not sr.get("threat_id"):
      errors.append("Missing 'security_result.threat_id'")
    if sr.get("threat_id_namespace") != "MITRE_ATTACK":
      errors.append("Expected 'security_result.threat_id_namespace' to be 'MITRE_ATTACK'")

    risk = sr.get("risk_score")
    if risk is None or not isinstance(risk, int) or not (0 <= risk <= 100):
      errors.append(f"Invalid 'security_result.risk_score': {risk}. Must be integer 0-100")

    severity = sr.get("severity")
    if severity not in VALID_SEVERITIES:
      errors.append(f"Invalid 'security_result.severity': {severity}. Expected one of {VALID_SEVERITIES}")

    if not sr.get("summary"):
      errors.append("Missing 'security_result.summary'")

  return errors


def format_pre_ingestion_clearance_card(
    batch: List[Dict[str, Any]],
    customer_id: str,
    project_id: str,
    campaign_id: str,
) -> str:
  """Formats the required Turn-yielding pre-ingestion authorization preview card."""
  card_lines = [
      "### 📋 PRE-INGESTION CLEARANCE SPECIFICATION (CLEAN HAND-OFF)",
      f"• **Target Project / Customer**: `{project_id}` / `{customer_id}`",
      f"• **Hunt Campaign ID**: `{campaign_id}`",
      f"• **Catch-All Alert Rule**: `{CATCHALL_RULE_NAME}`",
      f"• **Batch Size**: {len(batch)} Outlier Event(s)",
      "",
      "| # | Entity | Product Event Type | Model | Z-Score | CRI | Severity |",
      "|---|---|---|---|---|---|---|",
  ]

  for i, item in enumerate(batch, 1):
    u = item["udm"]
    entity = u.get("principal", {}).get("user", {}).get("userid") or u.get("principal", {}).get("hostname", "Unknown")
    pet = u.get("metadata", {}).get("product_event_type", "")
    sr = u.get("security_result", [{}])[0]
    model = "Statistical Model"
    labels = u.get("metadata", {}).get("ingestion_labels", [])
    for l in labels:
      if l.get("key") == "statistical_model":
        model = l.get("value")
        break
    z = "N/A"
    for df in sr.get("detection_fields", []):
      if df.get("key") == "z_score":
        z = df.get("value")
        break
    cri = sr.get("risk_score", 0)
    sev = sr.get("severity", "MEDIUM")
    card_lines.append(f"| {i} | `{entity}` | `{pet}` | {model} | {z}σ | {cri} | **{sev}** |")

  card_lines.append("")
  card_lines.append("> *Would you like me to ingest this Synthetic UDM Security Event batch into Google SecOps (`gus-sdl`) to trigger the Catch-All Alert Rule and spawn a Case?*")
  return "\n".join(card_lines)


def prepare_chronicle_import_logs_args(
    batch: List[Dict[str, Any]],
    customer_id: str,
    project_id: str,
    region: str,
    forwarder_id: Optional[str] = None,
    log_type: Optional[str] = None,
) -> Dict[str, Any]:
  """Prepares the arguments dict for calling secops-gus:import_logs."""
  payload_strings = [json.dumps(event) for event in batch]
  effective_log_type = log_type or CHRONICLE_INGESTION_LOG_TYPE

  args: Dict[str, Any] = {
      "customerId": customer_id,
      "projectId": project_id,
      "region": region,
      "logType": effective_log_type,
      "logs": payload_strings,
  }

  if forwarder_id:
    args["forwarderId"] = forwarder_id

  return args
