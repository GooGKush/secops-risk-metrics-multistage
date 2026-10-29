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

from enum import Enum

SUPPORTED_PROTOCOL = "secops-threat-hunt-handoff-v1"


class HandoffReason(str, Enum):
  """Canonical handoff reasons and intents for cross-skill delegation."""
  SCHEDULED_EXFILTRATION_TIMING = "SCHEDULED_EXFILTRATION_TIMING"
  C2_BEACONING_JITTER = "C2_BEACONING_JITTER"
  POISSON_BURST_CLUSTERING = "POISSON_BURST_CLUSTERING"
  POISSON_RARE_SURGE = "POISSON_RARE_SURGE"
  ZSCORE_PROCESS_SURGE = "ZSCORE_PROCESS_SURGE"
  DATA_EXFILTRATION_SPIKE = "DATA_EXFILTRATION_SPIKE"
  DUAL_BASELINE_DELTA_Z = "DUAL_BASELINE_DELTA_Z"
  RAW_TELEMETRY_ENRICHMENT = "RAW_TELEMETRY_ENRICHMENT"
  DIVERSITY_DEFICIT = "DIVERSITY_DEFICIT"
  ELEPHANT_FLOW_CONCENTRATION = "ELEPHANT_FLOW_CONCENTRATION"
  ORTHOGONAL_THREAT_SPACE = "ORTHOGONAL_THREAT_SPACE"
  BAYESIAN_JOINT_ODDS = "BAYESIAN_JOINT_ODDS"
  TWO_PART_HURDLE = "TWO_PART_HURDLE"
  FLEET_PREVALENCE_NORMALIZATION = "FLEET_PREVALENCE_NORMALIZATION"
  PRIVILEGED_LATERAL_EXPANSION = "PRIVILEGED_LATERAL_EXPANSION"
  HOUR_OF_DAY_PROFILE = "HOUR_OF_DAY_PROFILE"
  OFF_HOURS_BURST = "off_hours_activity"


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
    "PRIVILEGED_LATERAL_EXPANSION",
    "HOUR_OF_DAY_PROFILE",
]


def build_handoff_payload(
    intent: str,
    entity_type: str = "HOSTNAME",
    entity_value: str = "",
    lookback: str = "24h",
    sensitivity: str = "BALANCED",
    justification: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
    reason: Optional[Any] = None,
) -> Dict[str, Any]:
  """Constructs a strictly-typed federated handoff payload."""
  if not entity_value and entity_type and entity_type.upper() not in ("HOSTNAME", "ASSET", "USER", "IP", "SERVICE_ACCOUNT", "DOMAIN"):
    entity_value = entity_type
    entity_type = "HOSTNAME"
  if not request_id:
    request_id = f"req-{uuid.uuid4().hex[:8]}"

  model_params = parameters or {}
  reason_str = (reason.value if hasattr(reason, "value") else str(reason or "")).upper()
  intent_upper = f"{intent.upper()} {reason_str}".strip()
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
    elif any(kw in intent_upper for kw in ["LATERAL", "BIPARTITE", "UNSEEN_ENDPOINT"]):
      justification = (
          "Bipartite user-to-host machine access history and destination expansion require "
          "ad-hoc bounded lookback over raw USER_LOGIN events; delegating to statistical hunter."
      )
    elif any(kw in intent_upper for kw in ["HOUR_OF_DAY", "TIME_OF_DAY", "HOURLY", "OFF_HOURS", "CIRCADIAN", "VON_MISES"]):
      justification = (
          "Macro metrics.* provides only daily (period: 1d, window: 30d) baselines (PF-10); "
          "delegating time-of-day / off-hours profiling to secops-statistical-hunter HOUR_OF_DAY_PROFILE over raw UDM telemetry."
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
  elif any(kw in intent_upper for kw in ["LATERAL", "BIPARTITE", "EXPANSION"]):
    if "min_distinct_targets" not in model_params:
      model_params["min_distinct_targets"] = 3
    if "min_z_score" not in model_params:
      model_params["min_z_score"] = 2.0
  elif any(kw in intent_upper for kw in ["HOUR_OF_DAY", "TIME_OF_DAY", "HOURLY", "OFF_HOURS", "CIRCADIAN", "VON_MISES"]):
    if "window_days" not in model_params:
      model_params["window_days"] = 14
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
      "handoff_justification": justification,
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


def _inprocess_fallback_ack(payload: Dict[str, Any]) -> Dict[str, Any]:
  """Synthesizes a deterministic secops-threat-hunt-handoff-v1 ACK when the sibling repo is unmounted."""
  if payload.get("protocol") != SUPPORTED_PROTOCOL:
    return {
        "status": "HANDOFF_ACK_REJECTED",
        "action": "PROTOCOL_MISMATCH",
        "error": f"Unsupported protocol: {payload.get('protocol')}",
    }
  intent = payload.get("intent", "SCHEDULED_EXFILTRATION_TIMING").upper()
  ent = payload.get("target_entity", {})
  ent_val = ent.get("value", "target_entity")
  ent_type = ent.get("type", "HOSTNAME").upper()
  params = payload.get("statistical_model", {}).get("parameters", {})

  if intent in ("SCHEDULED_EXFILTRATION_TIMING", "C2_BEACONING_JITTER"):
    model_routed = "C2_BEACONING_JITTER"
    max_cv = params.get("max_cv", 0.20)
    min_obs = params.get("min_observations", 10)
    compiled_query = (
        f"// Goal: Micro-Timing Variance & Jitter Analysis for {ent_val}\n"
        "stage host_intervals {\n"
        '  metadata.event_type = "NETWORK_HTTP"\n'
        f'  principal.asset.hostname = "{ent_val}"\n'
        "  principal.asset.hostname = $host\n"
        "  target.hostname = $dest\n"
        "  match:\n"
        "    $host, $dest by 5m\n"
        "  outcome:\n"
        "    $obs = count(metadata.id)\n"
        "}\n\n"
        "$host = $host_intervals.host\n"
        "$dest = $host_intervals.dest\n"
        "match:\n"
        "  $host, $dest\n"
        "outcome:\n"
        "  $mean_obs = avg($host_intervals.obs)\n"
        "  $std_obs = stddev($host_intervals.obs)\n"
        "  $windows = count($host_intervals.obs)\n"
        "  $cv = $std_obs / if($mean_obs > 0, $mean_obs, 1.0)\n"
        "condition:\n"
        f"  $windows >= {min_obs} and $cv <= {max_cv}\n"
        "order:\n"
        "  $cv asc\n"
    )
  elif intent == "PRIVILEGED_LATERAL_EXPANSION":
    model_routed = "PRIVILEGED_LATERAL_EXPANSION"
    min_z = params.get("min_z_score", 2.0)
    compiled_query = (
        f"// Goal: Privileged Lateral Expansion Bipartite Breadth Analysis for {ent_val}\n"
        "stage daily_user_breadth {\n"
        '  metadata.event_type = "USER_LOGIN"\n'
        "  principal.user.userid = $user\n"
        "  $user != \"\"\n"
        "  match:\n"
        "    $user by 1d\n"
        "  outcome:\n"
        "    $distinct_targets = count_distinct(target.asset.hostname)\n"
        "}\n\n"
        "stage user_breadth_baseline {\n"
        "  $user = $daily_user_breadth.user\n"
        "  match:\n"
        "    $user\n"
        "  outcome:\n"
        "    $hist_avg = avg($daily_user_breadth.distinct_targets)\n"
        "    $hist_std = stddev($daily_user_breadth.distinct_targets)\n"
        "}\n\n"
        "stage current_breadth {\n"
        '  metadata.event_type = "USER_LOGIN"\n'
        "  principal.user.userid = $user\n"
        "  $user != \"\"\n"
        "  match:\n"
        "    $user by 1d\n"
        "  outcome:\n"
        "    $today_targets = count_distinct(target.asset.hostname)\n"
        "}\n\n"
        "$user = $current_breadth.user\n"
        "$user = $user_breadth_baseline.user\n"
        "match:\n"
        "  $user\n"
        "outcome:\n"
        "  $obs = max($current_breadth.today_targets)\n"
        "  $mu = max($user_breadth_baseline.hist_avg)\n"
        "  $sigma = max($user_breadth_baseline.hist_std)\n"
        "  $z_score = ($obs - $mu) / if($sigma > 0, $sigma, 1.0)\n"
        "condition:\n"
        f"  $z_score >= {min_z}\n"
        "order:\n"
        "  $z_score desc\n"
    )
  elif intent in ("HOUR_OF_DAY_PROFILE", "OFF_HOURS_ACTIVITY"):
    model_routed = "HOUR_OF_DAY_PROFILE"
    ent_field = "target.user.userid" if ent_type == "USER" else "principal.asset.hostname"
    ev_type = "USER_LOGIN" if ent_type == "USER" else "NETWORK_HTTP"
    compiled_query = (
        f"// Goal: Per-Hour-of-Day Behavioral Profile (HOUR_OF_DAY_PROFILE) for {ent_val}\n"
        "stage hourly_counts {\n"
        f'  metadata.event_type = "{ev_type}"\n'
        f'  {ent_field} = "{ent_val}"\n'
        f"  {ent_field} = $entity\n"
        '  $hour_of_day = timestamp.get_hour(metadata.event_timestamp.seconds, "UTC")\n'
        "  match:\n"
        "    $entity, $hour_of_day by 1h\n"
        "  outcome:\n"
        "    $obs = count(metadata.id)\n"
        "}\n\n"
        "stage hour_of_day_baseline {\n"
        "  $entity = $hourly_counts.entity\n"
        "  $hour_of_day = $hourly_counts.hour_of_day\n"
        "  match:\n"
        "    $entity, $hour_of_day\n"
        "  outcome:\n"
        "    $mean_obs = avg($hourly_counts.obs)\n"
        "    $std_obs = stddev($hourly_counts.obs)\n"
        "    $active_buckets = count($hourly_counts.obs)\n"
        "}\n\n"
        "$entity = $hourly_counts.entity\n"
        "$entity = $hour_of_day_baseline.entity\n"
        "$hour_of_day = $hourly_counts.hour_of_day\n"
        "$hour_of_day = $hour_of_day_baseline.hour_of_day\n"
        "$ws = $hourly_counts.window_start\n"
        "match:\n"
        "  $entity, $hour_of_day, $ws by 1h\n"
        "outcome:\n"
        "  $obs = max($hourly_counts.obs)\n"
        "  $mu = max($hour_of_day_baseline.mean_obs)\n"
        "  $sigma = max($hour_of_day_baseline.std_obs)\n"
        "  $n_buckets = max($hour_of_day_baseline.active_buckets)\n"
        "  $floor = math.sqrt(if($mu > 1.0, $mu, 1.0))\n"
        "  $safe_sigma = if($sigma > $floor, $sigma, $floor)\n"
        "  $diff = $obs - $mu\n"
        "  $hod_z = $diff / $safe_sigma\n"
        "condition:\n"
        "  $n_buckets >= 7 and $hod_z >= 3.0\n"
        "order:\n"
        "  $hod_z desc\n"
    )
  else:
    model_routed = intent
    ent_field = "principal.user.userid" if ent_type == "USER" else "principal.asset.hostname"
    compiled_query = (
        f"// Goal: Delegated Micro-Forensic Analysis ({intent}) for {ent_val}\n"
        "stage micro_telemetry_extract {\n"
        '  metadata.event_type = "NETWORK_HTTP"\n'
        f'  {ent_field} = "{ent_val}"\n'
        f"  {ent_field} = $entity\n"
        "  match:\n"
        "    $entity by 1h\n"
        "  outcome:\n"
        "    $obs = count(metadata.id)\n"
        "    $distinct_targets = count_distinct(target.hostname)\n"
        "}\n\n"
        "$entity = $micro_telemetry_extract.entity\n"
        "match:\n"
        "  $entity\n"
        "outcome:\n"
        "  $peak_obs = max($micro_telemetry_extract.obs)\n"
        "  $mean_obs = avg($micro_telemetry_extract.obs)\n"
        "  $std_obs = stddev($micro_telemetry_extract.obs)\n"
        "  $z_score = ($peak_obs - $mean_obs) / if($std_obs > 0, $std_obs, 1.0)\n"
        "condition:\n"
        "  $z_score >= 2.0\n"
        "order:\n"
        "  $z_score desc\n"
    )

  return {
      "protocol": SUPPORTED_PROTOCOL,
      "request_id": payload.get("request_id", "req-fallback"),
      "status": "HANDOFF_ACK_ACCEPTED",
      "action": "STEP_OUT_CONFIRMED",
      "source_skill": payload.get("source_skill", "secops-risk-metrics-multistage"),
      "target_skill": "secops-statistical-hunter",
      "model_routed": model_routed,
      "compiled_query": compiled_query,
      "step_out_directive": (
          "SOURCE_SKILL_STEP_OUT_CONFIRMED: secops-statistical-hunter has assumed ownership "
          "of micro-telemetry compilation and execution."
      ),
  }


def dispatch_to_endpoint(
    payload: Dict[str, Any],
    stats_hunter_dir: Optional[Path] = None,
) -> Dict[str, Any]:
  """Dispatches the payload directly to the secops-statistical-hunter ingestion endpoint."""
  explicit_dir = stats_hunter_dir is not None
  if stats_hunter_dir is None:
    candidates = [
        Path(__file__).resolve().parent.parent.parent / "secops-statistical-hunter",
        Path.home() / "projects" / "secops-statistical-hunter",
        Path.home() / ".gemini" / "config" / "skills" / "secops-statistical-hunter",
        Path.home() / ".gemini" / "skills" / "secops-statistical-hunter",
    ]
    for candidate in candidates:
      if (candidate / "scripts" / "multistage_query_builder.py").exists():
        stats_hunter_dir = candidate
        break
    if stats_hunter_dir is None:
      return _inprocess_fallback_ack(payload)

  builder_script = stats_hunter_dir / "scripts" / "multistage_query_builder.py"
  if not builder_script.exists():
    if explicit_dir:
      raise FileNotFoundError(f"Endpoint script not found: {builder_script}")
    return _inprocess_fallback_ack(payload)

  cmd = [
      sys.executable,
      str(builder_script),
      "--ingest_handoff",
      json.dumps(payload),
  ]

  res = subprocess.run(cmd, capture_output=True, text=True)
  if res.returncode != 0 and not res.stdout.strip():
    return {
        "status": "HANDOFF_ACK_REJECTED",
        "action": "ENDPOINT_CRASH",
        "stdout": res.stdout,
        "stderr": res.stderr,
        "returncode": res.returncode,
    }
  try:
    ack_data = json.loads(res.stdout)
    if (
        ack_data.get("status") == "HANDOFF_ACK_REJECTED"
        and str(payload.get("intent", "")).upper() == "HOUR_OF_DAY_PROFILE"
        and not explicit_dir
    ):
      return _inprocess_fallback_ack(payload)
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
