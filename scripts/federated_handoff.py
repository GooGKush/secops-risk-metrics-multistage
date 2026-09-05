# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Federated Handoff Protocol Dispatcher for secops-risk-metrics-multistage.

Generates machine-readable handoff payloads conforming to secops-threat-hunt-handoff-v1
and coordinates cross-skill execution handshakes with secops-statistical-hunter.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
from typing import Any, Dict, Optional

SUPPORTED_PROTOCOL = "secops-threat-hunt-handoff-v1"

SUPPORTED_INTENTS = [
    "SCHEDULED_EXFILTRATION_TIMING",
    "C2_BEACONING_JITTER",
    "POISSON_BURST_CLUSTERING",
    "POISSON_RARE_SURGE",
    "ZSCORE_PROCESS_SURGE",
    "DATA_EXFILTRATION_SPIKE",
    "DUAL_BASELINE_DELTA_Z",
    "RAW_TELEMETRY_ENRICHMENT",
    "DIVERSITY_DEFICIT",
    "ELEPHANT_FLOW_CONCENTRATION",
    "ORTHOGONAL_THREAT_SPACE",
    "BAYESIAN_JOINT_ODDS",
    "TWO_PART_HURDLE",
    "FLEET_PREVALENCE_NORMALIZATION",
]


def build_handoff_payload(
    intent: str,
    entity_type: str,
    entity_value: str,
    lookback: str = "24h",
    sensitivity: str = "BALANCED",
    justification: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
  """Constructs a strictly-typed federated handoff payload."""
  if not request_id:
    request_id = f"req-{uuid.uuid4().hex[:8]}"

  model_params = parameters or {}
  intent_upper = intent.upper()
  if not justification:
    if any(kw in intent_upper for kw in ["DIVERSITY", "ENTROPY"]):
      justification = (
          "Macro 30-day baseline flagged volumetric anomaly; delegating to micro-entropy / "
          "lexical diversity probe to detect scripted target concentration (Diversity Deficit)."
      )
    elif any(kw in intent_upper for kw in ["CONCENTRATION", "ELEPHANT"]):
      justification = (
          "Macro 30-day baseline flagged bulk transfer; delegating to micro-concentration "
          "ratio analysis to detect single-destination Elephant Flows."
      )
    elif any(kw in intent_upper for kw in ["ORTHOGONAL", "DISTANCE", "EUCLIDEAN", "JOINT_ODDS"]):
      justification = (
          "Macro 30-day baseline intensity requires orthogonal coordinate projection with "
          "contemporary micro-breadth hits in a dual-plane threat space."
      )
    elif any(kw in intent_upper for kw in ["HURDLE", "DORMANT"]):
      justification = (
          "Dormant entity awakening flagged; delegating to two-part hurdle model to evaluate "
          "zero-state cold start combined with immediate high-impact activity."
      )
    elif any(kw in intent_upper for kw in ["FLEET_PREVALENCE", "PATCH_TUESDAY"]):
      justification = (
          "Macro surge detected for token/binary; delegating to fleet-wide prevalence probe "
          "to normalize against enterprise-wide administrative rollouts."
      )
    elif any(kw in intent_upper for kw in ["ENRICHMENT", "RAW_TELEMETRY", "DUAL_PLANE"]):
      justification = (
          "Macro 30-day baseline flagged a statistically significant volume outlier; "
          "delegating to targeted raw telemetry probe for micro-forensic signature enrichment."
      )
    else:
      justification = (
          "Volumetric 30-day baseline cannot detect sub-second interval regularity "
          "or scheduled cron exfiltration; delegating to micro-timing variance analysis."
      )

  if any(kw in intent_upper for kw in ["C2", "EXFIL", "TIMING", "JITTER"]):
    if "max_cv" not in model_params:
      model_params["max_cv"] = 0.20
    if "min_observations" not in model_params:
      model_params["min_observations"] = 10
  elif any(kw in intent_upper for kw in ["DIVERSITY", "ENTROPY"]):
    if "max_diversity_ratio" not in model_params:
      model_params["max_diversity_ratio"] = 0.10
    if "raw_vocab_field" not in model_params:
      model_params["raw_vocab_field"] = "target.url"
  elif any(kw in intent_upper for kw in ["CONCENTRATION", "ELEPHANT"]):
    if "min_concentration_ratio" not in model_params:
      model_params["min_concentration_ratio"] = 0.75
  elif any(kw in intent_upper for kw in ["ORTHOGONAL", "DISTANCE", "EUCLIDEAN"]):
    if "min_threat_distance_sq" not in model_params:
      model_params["min_threat_distance_sq"] = 16.0
  elif any(kw in intent_upper for kw in ["JOINT_ODDS", "BAYESIAN_ODDS"]):
    if "min_joint_odds" not in model_params:
      model_params["min_joint_odds"] = 2.5
  elif any(kw in intent_upper for kw in ["HURDLE", "DORMANT"]):
    if "max_dormant_days" not in model_params:
      model_params["max_dormant_days"] = 2
  elif any(kw in intent_upper for kw in ["FLEET_PREVALENCE", "PATCH_TUESDAY"]):
    if "max_fleet_adopters" not in model_params:
      model_params["max_fleet_adopters"] = 3
  elif any(kw in intent_upper for kw in ["ENRICHMENT", "RAW_TELEMETRY", "DUAL_PLANE"]):
    if "enrichment_vector" not in model_params:
      model_params["enrichment_vector"] = "NETWORK_HTTP_USER_AGENT"
    if "max_signature_diversity" not in model_params:
      model_params["max_signature_diversity"] = 2

  payload = {
      "protocol": SUPPORTED_PROTOCOL,
      "request_id": request_id,
      "source_skill": "secops-risk-metrics-multistage",
      "target_skill": "secops-statistical-hunter",
      "intent": intent.upper().replace("-", "_").strip(),
      "target_entity": {
          "type": entity_type.upper(),
          "value": entity_value.strip(),
      },
      "search_window": {
          "lookback": lookback.strip(),
      },
      "statistical_model": {
          "name": intent.upper().replace("-", "_").strip(),
          "sensitivity": sensitivity.upper(),
          "parameters": model_params,
      },
      "justification": justification,
      "status": "PENDING_DISPATCH",
  }
  return payload


def format_handoff_card(
    payload: Dict[str, Any],
    ack: Optional[Dict[str, Any]] = None,
) -> str:
  """Renders the user-facing consultative handoff card containing the typed JSON payload and optional ACK."""
  lines = [
      "### 🔄 Federated Skill Handoff: Consultative Demarcation",
      "",
      "> [!NOTE]",
      "> **Architectural Boundary Demarcation: Macro-Analysis ──► Micro-Analysis**",
      f"> • **Reason**: {payload.get('justification', 'Micro-statistical variance required.')}",
      f"> • **Target Entity**: `{payload['target_entity']['value']}` ({payload['target_entity']['type']})",
      f"> • **Delegated Model**: `{payload['statistical_model']['name']}` (Sensitivity: `{payload['statistical_model']['sensitivity']}`)",
      f"> • **Protocol**: `{payload['protocol']}` (Request ID: `{payload['request_id']}`)",
  ]

  if ack:
    lines.extend([
        f"> • **Endpoint ACK**: `{ack.get('status', 'UNKNOWN')}` (`{ack.get('action', 'NONE')}`)",
        f"> • **Model Routed**: `{ack.get('model_routed', 'UNKNOWN')}`",
    ])

  lines.extend([
      "",
      "```json:secops-threat-hunt-handoff-v1",
      json.dumps(payload, indent=2),
      "```",
      "",
  ])

  if ack and "compiled_query" in ack:
    lines.extend([
        "#### 🎯 Target Execution Pipeline (`secops-statistical-hunter`)",
        "```yara",
        ack["compiled_query"].strip(),
        "```",
        "",
    ])

  lines.extend([
      "> [!IMPORTANT]",
      "> **Step-Out Directive**: `secops-risk-metrics-multistage` yields ownership of this micro-timing vector.",
      "> Hand-off dispatched to `secops-statistical-hunter` for deterministic query compilation and execution.",
      ""
  ])
  return "\n".join(lines)


def dispatch_to_endpoint(
    payload: Dict[str, Any],
    stats_hunter_dir: Optional[Path] = None,
) -> Dict[str, Any]:
  """Dispatches the payload directly to the secops-statistical-hunter ingestion endpoint."""
  if stats_hunter_dir is None:
    stats_hunter_dir = Path(__file__).resolve().parent.parent.parent / "secops-statistical-hunter"

  builder_script = stats_hunter_dir / "scripts" / "multistage_query_builder.py"
  if not builder_script.exists():
    raise FileNotFoundError(f"Endpoint script not found: {builder_script}")

  cmd = [
      sys.executable,
      str(builder_script),
      "--ingest_handoff",
      json.dumps(payload),
  ]

  res = subprocess.run(cmd, capture_output=True, text=True)
  try:
    ack_data = json.loads(res.stdout)
    return ack_data
  except Exception:
    return {
        "status": "HANDOFF_ACK_REJECTED",
        "action": "ENDPOINT_CRASH",
        "stdout": res.stdout,
        "stderr": res.stderr,
        "returncode": res.returncode,
    }


def main():
  parser = argparse.ArgumentParser(
      description="Federated Handoff Protocol Dispatcher (secops-risk-metrics-multistage)"
  )
  parser.add_argument("--intent", default="SCHEDULED_EXFILTRATION_TIMING", help="Handoff intent")
  parser.add_argument("--entity_type", default="HOSTNAME", help="Target entity type (HOSTNAME, USER, IP)")
  parser.add_argument("--entity", required=True, help="Target entity value (e.g. site-rev-proxy)")
  parser.add_argument("--lookback", default="24h", help="Search window lookback")
  parser.add_argument("--sensitivity", default="BALANCED", help="Sensitivity tier")
  parser.add_argument("--justification", help="Handoff justification text")
  parser.add_argument("--dispatch", action="store_true", help="Immediately dispatch to secops-statistical-hunter endpoint")
  parser.add_argument("--card", action="store_true", help="Print user-facing markdown card with fenced JSON")

  args = parser.parse_args()

  payload = build_handoff_payload(
      intent=args.intent,
      entity_type=args.entity_type,
      entity_value=args.entity,
      lookback=args.lookback,
      sensitivity=args.sensitivity,
      justification=args.justification,
  )

  if args.dispatch:
    ack = dispatch_to_endpoint(payload)
    print(json.dumps(ack, indent=2))
    sys.exit(0 if ack.get("status") == "HANDOFF_ACK_ACCEPTED" else 1)

  if args.card:
    print(format_handoff_card(payload))
  else:
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
  main()
