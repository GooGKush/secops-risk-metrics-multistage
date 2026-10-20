#!/usr/bin/env python3
# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unified Python Hybrid Engine for secops-risk-metrics-multistage.

Orchestrates deterministic multi-stage YARA-L 2.0 query compilation across all
38 pre-computed Risk Analytics (`metrics.*`) baselines, Dual-Plane Hybrid
(Metric + Raw / Entity Context Graph) pipelines, Federated Cross-Skill Handoffs
(`secops-threat-hunt-handoff-v1`) to `secops-statistical-hunter`, and 6-Pillar
Forensic Dossier + SVG/HTML visual rendering.

Composable API surface:
  1. compile_hunt_pipeline(...) -> dict
  2. dispatch_hybrid_handoff(...) -> dict
  3. render_forensic_dossier(...) -> dict
  4. get_metric_catalog_summary(...) -> dict

CLI subcommands:
  python3 -m scripts.ueba_hybrid_engine compile ...
  python3 -m scripts.ueba_hybrid_engine handoff ...
  python3 -m scripts.ueba_hybrid_engine render ...
  python3 -m scripts.ueba_hybrid_engine catalog ...
"""

import argparse
import datetime
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

# Ensure package-root import resolution works both as `scripts.ueba_hybrid_engine`
# and when invoked directly as `python3 scripts/ueba_hybrid_engine.py`.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
  sys.path.insert(0, str(_REPO_ROOT))

from scripts import malachite_catalog as mc
from scripts.chart_generator import RiskMetricsChartGenerator
from scripts.federated_handoff import (
    SUPPORTED_INTENTS,
    SUPPORTED_PROTOCOL,
    build_handoff_payload,
    dispatch_to_endpoint,
    format_handoff_card,
)
from scripts.preflight_validator import (
    DEFAULT_SIGNIFICANCE_GATES,
    EntityType,
    KillChainArchetype,
    METRIC_CATALOG,
    MalachiteASTValidator,
    MatchMode,
    PipelineArchitecture,
    PostFlightExecutionAuditor,
    PreFlightValidator,
    StatisticalModel,
    default_significance_threshold,
)
from scripts.radar_collector import EntityRadarCollector, MetricSpoke
from scripts.statistical_validator import StatisticalAntipatternAuditor
from scripts.template_router import ChainedHuntRouter, MultiStageTemplateRouter
from scripts.timeline_assembler import TimelineAssembler, cri_from_score, parse_stats_payload
from scripts.triage_formatter import CommonMarkTriageFormatter


# ---------------------------------------------------------------------------
# Sensitivity, Model, and Architecture Resolution Maps
# ---------------------------------------------------------------------------

SENSITIVITY_THRESHOLD_MAP: Dict[str, Dict[str, float]] = {
    "HIGH_RECALL": {
        "anomaly_threshold": 2.0,
        "fold_change_threshold": 1.5,
        "fusion_threshold_sq": 6.25,
        "robust_threshold": 2.5,
    },
    "BALANCED": {
        "anomaly_threshold": 3.0,
        "fold_change_threshold": 2.0,
        "fusion_threshold_sq": 12.25,
        "robust_threshold": 3.5,
    },
    "HIGH_PRECISION": {
        "anomaly_threshold": 4.0,
        "fold_change_threshold": 3.0,
        "fusion_threshold_sq": 20.25,
        "robust_threshold": 4.5,
    },
}

SENSITIVITY_ALIASES: Dict[str, str] = {
    "HIGH_RECALL": "HIGH_RECALL",
    "LOW": "HIGH_RECALL",
    "BROAD": "HIGH_RECALL",
    "SENSITIVE": "HIGH_RECALL",
    "BALANCED": "BALANCED",
    "MEDIUM": "BALANCED",
    "DEFAULT": "BALANCED",
    "STANDARD": "BALANCED",
    "HIGH_PRECISION": "HIGH_PRECISION",
    "HIGH": "HIGH_PRECISION",
    "STRICT": "HIGH_PRECISION",
    "CONSERVATIVE": "HIGH_PRECISION",
}

MODEL_ALIAS_MAP: Dict[str, StatisticalModel] = {
    # 1. Standard Z-Score
    "ZSCORE": StatisticalModel.STANDARD_Z_SCORE,
    "Z_SCORE": StatisticalModel.STANDARD_Z_SCORE,
    "STANDARD_Z_SCORE": StatisticalModel.STANDARD_Z_SCORE,
    "STANDARD_Z": StatisticalModel.STANDARD_Z_SCORE,
    "LINEAR_Z": StatisticalModel.STANDARD_Z_SCORE,
    "Z": StatisticalModel.STANDARD_Z_SCORE,
    # 2. Median Absolute Deviation (MAD)
    "MAD": StatisticalModel.MAD,
    "MEDIAN_ABSOLUTE_DEVIATION": StatisticalModel.MAD,
    "IGLEWICZ_HOAGLIN": StatisticalModel.MAD,
    "ROBUST_Z": StatisticalModel.MAD,
    "MODIFIED_Z": StatisticalModel.MAD,
    # 3. Relative Deviation / Fold Change
    "RELATIVE_DEVIATION": StatisticalModel.RELATIVE_DEVIATION,
    "REL_DEV": StatisticalModel.RELATIVE_DEVIATION,
    "FOLD_CHANGE": StatisticalModel.RELATIVE_DEVIATION,
    "ROLLING_RATIO": StatisticalModel.RELATIVE_DEVIATION,
    # 4. Variance / Fano Factor
    "VARIANCE": StatisticalModel.VARIANCE,
    "FANO": StatisticalModel.VARIANCE,
    "FANO_FACTOR": StatisticalModel.VARIANCE,
    "VARIANCE_FANO": StatisticalModel.VARIANCE,
    "INDEX_OF_DISPERSION": StatisticalModel.VARIANCE,
    # 5. Discrete Poisson Rarity
    "POISSON": StatisticalModel.POISSON,
    "POISSON_RARITY": StatisticalModel.POISSON,
    "RARE_EVENT": StatisticalModel.POISSON,
    "ANSCOMBE": StatisticalModel.POISSON,
    # 6. Coefficient of Variation (CV)
    "CV": StatisticalModel.COEFFICIENT_OF_VARIATION,
    "COEFFICIENT_OF_VARIATION": StatisticalModel.COEFFICIENT_OF_VARIATION,
    "BEACON_REGULARITY": StatisticalModel.COEFFICIENT_OF_VARIATION,
    "JITTER": StatisticalModel.COEFFICIENT_OF_VARIATION,
    # 7. Hourly Temporal Z-Score
    "HOURLY_TEMPORAL_ZSCORE": StatisticalModel.HOURLY_TEMPORAL_ZSCORE,
    "HOURLY_ZSCORE": StatisticalModel.HOURLY_TEMPORAL_ZSCORE,
    "TEMPORAL_ZSCORE": StatisticalModel.HOURLY_TEMPORAL_ZSCORE,
    "INTRADAY_Z": StatisticalModel.HOURLY_TEMPORAL_ZSCORE,
    # 8. Bayesian Gamma-Poisson Shrinkage
    "BAYESIAN_GAMMA": StatisticalModel.BAYESIAN_GAMMA,
    "POISSON_GAMMA": StatisticalModel.BAYESIAN_GAMMA,
    "GAMMA_POISSON": StatisticalModel.BAYESIAN_GAMMA,
    "EMPIRICAL_BAYES_GAMMA": StatisticalModel.BAYESIAN_GAMMA,
    # 9. Bayesian Beta-Binomial Proportion Shrinkage
    "BAYESIAN_BETA_BINOMIAL": StatisticalModel.BAYESIAN_BETA_BINOMIAL,
    "BETA_BINOMIAL": StatisticalModel.BAYESIAN_BETA_BINOMIAL,
    "FAILURE_RATE_SHRINKAGE": StatisticalModel.BAYESIAN_BETA_BINOMIAL,
    # 10. Longitudinal CUSUM Drift
    "LONGITUDINAL_CUSUM": StatisticalModel.LONGITUDINAL_CUSUM,
    "CUSUM": StatisticalModel.LONGITUDINAL_CUSUM,
    "CUSUM_DRIFT": StatisticalModel.LONGITUDINAL_CUSUM,
    "LOW_AND_SLOW": StatisticalModel.LONGITUDINAL_CUSUM,
    # 11. Two-Part Hurdle (Dormant Awakening)
    "TWO_PART_HURDLE": StatisticalModel.TWO_PART_HURDLE,
    "HURDLE": StatisticalModel.TWO_PART_HURDLE,
    "DORMANT_AWAKENING": StatisticalModel.TWO_PART_HURDLE,
    "COLD_START": StatisticalModel.TWO_PART_HURDLE,
    # 12. Asymmetric Directional Z (Silence / Drop-out)
    "ASYMMETRIC_DIRECTIONAL_Z": StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z,
    "ASYMMETRIC_Z": StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z,
    "DIRECTIONAL_Z": StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z,
    "SILENCE_DETECTION": StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z,
    "DROP_OUT": StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z,
    # 13. Piecewise Sigmoid CRI
    "PIECEWISE_CRI": StatisticalModel.PIECEWISE_CRI,
    "CRI": StatisticalModel.PIECEWISE_CRI,
    "CALIBRATED_RISK_INDEX": StatisticalModel.PIECEWISE_CRI,
    "SIGMOID_CRI": StatisticalModel.PIECEWISE_CRI,
    # 14. Fleet Prevalence Shield
    "FLEET_PREVALENCE_SHIELD": StatisticalModel.FLEET_PREVALENCE_SHIELD,
    "PATCH_TUESDAY_SHIELD": StatisticalModel.FLEET_PREVALENCE_SHIELD,
    "PREVALENCE_SHIELD": StatisticalModel.FLEET_PREVALENCE_SHIELD,
    # 15. Adaptive Context Threshold
    "ADAPTIVE_CONTEXT_THRESHOLD": StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD,
    "ADAPTIVE_THRESHOLD": StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD,
    "DYNAMIC_THRESHOLD": StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD,
    # 16. MACD Momentum Velocity
    "MACD_MOMENTUM_VELOCITY": StatisticalModel.MACD_MOMENTUM_VELOCITY,
    "MACD": StatisticalModel.MACD_MOMENTUM_VELOCITY,
    "MOMENTUM_VELOCITY": StatisticalModel.MACD_MOMENTUM_VELOCITY,
    "EWMA_BURST": StatisticalModel.MACD_MOMENTUM_VELOCITY,
    # 17. Circadian von Mises
    "CIRCADIAN_VON_MISES": StatisticalModel.CIRCADIAN_VON_MISES,
    "CIRCADIAN": StatisticalModel.CIRCADIAN_VON_MISES,
    "VON_MISES": StatisticalModel.CIRCADIAN_VON_MISES,
    "OFF_HOURS": StatisticalModel.CIRCADIAN_VON_MISES,
}

# Models that automatically imply an advanced multi-stage pipeline architecture
# when architecture is left as "single_metric".
MODEL_IMPLIED_ARCHITECTURE: Dict[str, str] = {
    "DUAL_BASELINE_DELTA_Z": "dual_baseline",
    "DELTA_Z": "dual_baseline",
    "DUAL_BASELINE": "dual_baseline",
    "EMPIRICAL_BAYES": "empirical_bayes",
    "HIERARCHICAL_EMPIRICAL_BAYES": "empirical_bayes",
    "JAMES_STEIN": "empirical_bayes",
    "MULTI_SECTOR_FUSION": "sector_fusion",
    "SECTOR_FUSION": "sector_fusion",
    "DUAL_SECTOR_FUSION": "sector_fusion",
    "PART_OF_THE_WHOLE": "multilevel",
    "PEER_COHORT": "multilevel",
    "TRIAD": "triad",
    "360_RADAR": "360_radar",
    "RADAR_360": "360_radar",
    "DIVERSITY_DEFICIT": "hybrid_entropy_concentration",
    "ELEPHANT_FLOW": "hybrid_entropy_concentration",
    "ELEPHANT_FLOW_CONCENTRATION": "hybrid_entropy_concentration",
    "ORTHOGONAL_THREAT_SPACE": "hybrid_orthogonal_space",
    "BAYESIAN_JOINT_ODDS": "hybrid_orthogonal_space",
    "FLEET_PREVALENCE_NORMALIZATION": "hybrid_fleet_prevalence",
}


def resolve_sensitivity(sensitivity: str) -> Tuple[str, Dict[str, float]]:
  """Resolves a sensitivity tier string to its canonical tier name and thresholds."""
  key = (sensitivity or "BALANCED").strip().upper().replace("-", "_")
  tier = SENSITIVITY_ALIASES.get(key, "BALANCED")
  return tier, dict(SENSITIVITY_THRESHOLD_MAP[tier])


def resolve_entity_type(entity_type: Union[str, EntityType]) -> EntityType:
  """Resolves a string or EntityType into a canonical EntityType enum."""
  if isinstance(entity_type, EntityType):
    return entity_type
  key = (entity_type or "USER").strip().upper().replace("-", "_")
  if key in ("USER", "PRINCIPAL_USER", "TARGET_USER", "ACCOUNT", "USERID", "EMAIL"):
    return EntityType.USER
  if key in (
      "ASSET",
      "HOST",
      "HOSTNAME",
      "DEVICE",
      "PRINCIPAL_ASSET",
      "TARGET_ASSET",
      "ENDPOINT",
      "MACHINE",
      "IP",
  ):
    return EntityType.ASSET
  if key in ("RESOURCE", "CLOUD_RESOURCE", "REPOSITORY"):
    return EntityType.RESOURCE
  return EntityType.USER


def resolve_statistical_model(model: Union[str, StatisticalModel]) -> StatisticalModel:
  """Resolves a model alias or enum value to a canonical StatisticalModel."""
  if isinstance(model, StatisticalModel):
    return model
  raw = (model or "STANDARD_Z_SCORE").strip().upper().replace("-", "_").replace(" ", "_")
  if raw in MODEL_ALIAS_MAP:
    return MODEL_ALIAS_MAP[raw]
  for member in StatisticalModel:
    if raw in (member.name.upper(), member.value.upper()):
      return member
  return StatisticalModel.STANDARD_Z_SCORE


def normalize_metrics_list(
    metrics: Optional[Union[str, Sequence[str]]],
    entity_type: EntityType,
    architecture: str,
) -> List[str]:
  """Normalizes metric input into a clean list of catalog metric names."""
  if metrics is None:
    arch = (architecture or "single_metric").strip().lower()
    if arch in ("sector_fusion", "dual_sector_fusion_3stage", "multi_sector_fusion_4stage", "fusion_3stage", "fusion_4stage"):
      return ["auth_attempts_fail", "network_bytes_outbound"]
    if arch in ("triad", "part_of_the_whole_triad_multilevel"):
      if entity_type == EntityType.USER:
        return ["auth_attempts_total", "auth_attempts_fail", "auth_attempts_success"]
      return ["network_bytes_outbound", "network_bytes_inbound", "network_bytes_total"]
    if arch in ("fusion_rare_destination", "fusion_rare_destination_3stage"):
      if entity_type == EntityType.ASSET:
        return ["auth_attempts_total", "http_queries_total"]
      return ["workspace_total_download_actions", "http_queries_total"]
    if arch in ("cloud_scope", "cloud_repository_scope_dual_branch"):
      return ["resource_read_total"]
    if arch in (
        "hybrid_fleet_prevalence",
        "hybrid_metric_fleet_prevalence_2stage",
        "hybrid_derived_file_prevalence",
        "hybrid_metric_derived_file_prevalence_2stage",
    ):
      return ["file_executions_total"]
    if arch in (
        "hybrid_derived_domain_prevalence",
        "hybrid_metric_derived_domain_prevalence_2stage",
        "hybrid_whois_domain_lifecycle",
        "hybrid_metric_whois_domain_lifecycle_2stage",
        "hybrid_http_ua_prevalence",
        "hybrid_metric_http_ua_prevalence_2stage",
    ):
      return ["http_queries_total"]
    if arch in ("failure_ratio", "http_error_ratio_surge_2stage"):
      return ["http_queries_fail"]
    if arch == "c2_beacon_flow":
      return ["network_flows_outbound"]
    if arch == "alert_surge":
      return ["alert_event_name_count"]
    return ["auth_attempts_total"] if entity_type == EntityType.USER else ["network_bytes_outbound"]

  if isinstance(metrics, str):
    items = [m.strip() for m in metrics.split(",") if m.strip()]
  else:
    items = [str(m).strip() for m in metrics if str(m).strip()]

  cleaned = []
  for item in items:
    if item.startswith("metrics."):
      item = item[len("metrics."):]
    cleaned.append(item)
  return cleaned or (["auth_attempts_total"] if entity_type == EntityType.USER else ["network_bytes_outbound"])


def _inject_stage1_filters(
    query: str,
    entity_value: Optional[str] = None,
    custom_filter: Optional[Union[str, Sequence[str]]] = None,
) -> str:
  """Safely injects an entity_value constraint and/or custom UDM filters into Stage 1 extractor(s).

  Preserves all MalachiteASTValidator invariants:
  - Binds to the stage's existing entity placeholder variable ($user, $host, $entity, $sa)
    so no duplicate UDM event source alias is introduced.
  - Strips any leading `$e.` alias from custom_filter lines so unprefixed UDM stages remain 1 source.
  """
  filter_lines: List[str] = []
  if custom_filter:
    if isinstance(custom_filter, str):
      raw_lines = [ln.strip() for ln in custom_filter.splitlines() if ln.strip()]
    else:
      raw_lines = [str(ln).strip() for ln in custom_filter if str(ln).strip()]
    for ln in raw_lines:
      # Normalize `$e.field` -> `field` to prevent multi-source UDM alias violation
      normalized = re.sub(r"^\$[a-zA-Z0-9_]+\.(?=(?:metadata|principal|target|src|observer|network|security_result|additional|extensions)\.)", "", ln)
      filter_lines.append(normalized)

  clean_entity = (entity_value or "").strip()
  has_specific_entity = bool(
      clean_entity
      and clean_entity.lower() not in ("fleet", "fleet-wide", "all", "*", "unknown", "none")
      and f'"{clean_entity}"' not in query
  )

  if not has_specific_entity and not filter_lines:
    return query

  # Inject into the first stage block (before `match:`)
  stage_match = re.search(
      r"(stage\s+[a-zA-Z0-9_]+\s*\{)(.*?)(\n[ \t]*match:\s*\n)",
      query,
      flags=re.DOTALL,
  )
  if not stage_match:
    return query

  stage_open, stage_events, match_header = stage_match.group(1), stage_match.group(2), stage_match.group(3)
  extra_predicates: List[str] = []

  if has_specific_entity:
    # Identify the primary entity placeholder bound in stage_events ($user, $host, $entity, $sa)
    var_match = re.search(r"(\$[a-zA-Z0-9_]+)\s*!=\s*\"\"", stage_events)
    if not var_match:
      var_match = re.search(
          r"(?:principal|target)\.(?:user|asset)\.[a-zA-Z0-9_.]+\s*=\s*(\$[a-zA-Z0-9_]+)",
          stage_events,
      )
    if var_match:
      ent_var = var_match.group(1)
      extra_predicates.append(f'    {ent_var} = "{clean_entity}"')

  for fl in filter_lines:
    if fl not in stage_events:
      extra_predicates.append(f"    {fl}")

  if not extra_predicates:
    return query

  injected_events = stage_events.rstrip() + "\n" + "\n".join(extra_predicates) + "\n"
  return query[:stage_match.start()] + stage_open + injected_events + match_header + query[stage_match.end():]


def _compute_execution_windows(
    compiled_query: str,
    mode: str = "A",
    window_days: int = 1,
    statistical_model: Optional[StatisticalModel] = None,
    reference_time: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
  """Computes UTC ISO-8601 execution windows, baseline horizon dates, and Mode C shards."""
  now = reference_time or datetime.datetime.now(datetime.timezone.utc)
  if now.tzinfo is None:
    now = now.replace(tzinfo=datetime.timezone.utc)
  today_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
  end_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

  probe_start_iso = (now - datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
  probe_end_iso = end_iso

  mode_clean = (mode or "A").strip().upper()
  if mode_clean.startswith("MODE"):
    mode_clean = mode_clean.replace("MODE", "").strip()
  if mode_clean not in ("A", "B", "C", "D"):
    mode_clean = "A"

  has_ecg = bool(re.search(r"\bgraph\.(?:entity|metadata|relations)\b", compiled_query))
  ecg_72h_anchor_applied = False

  if mode_clean == "A":
    eff_days = 1
    if statistical_model == StatisticalModel.MAD:
      # MAD requires 30d raw search window for window.median(...) while $in_scoring_window gates to today
      start_dt = today_midnight - datetime.timedelta(days=29)
    elif has_ecg:
      # ECG snapshot freshness requires UTC date -2d at 00:00:00Z while event stage filters to today
      start_dt = today_midnight - datetime.timedelta(days=2)
      ecg_72h_anchor_applied = True
    else:
      start_dt = today_midnight
    start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    baseline_start = (today_midnight - datetime.timedelta(days=30)).strftime("%Y-%m-%d")
    baseline_end = (today_midnight - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    eval_label = "Mode A: Today (Default)"
    shards = [{
        "day": today_midnight.strftime("%Y-%m-%d"),
        "start_time": start_iso,
        "end_time": end_iso,
        "baseline_window": f"[{baseline_start}, {today_midnight.strftime('%Y-%m-%d')})",
        "query": compiled_query,
    }]

  elif mode_clean == "B":
    eff_days = max(window_days if window_days > 1 else 7, 2)
    if statistical_model == StatisticalModel.MAD:
      start_dt = today_midnight - datetime.timedelta(days=max(29, eff_days - 1))
    else:
      start_dt = today_midnight - datetime.timedelta(days=eff_days - 1)
    start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    anchor_day = today_midnight - datetime.timedelta(days=eff_days - 1)
    baseline_start = (anchor_day - datetime.timedelta(days=30)).strftime("%Y-%m-%d")
    baseline_end = (anchor_day - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    eval_label = f"Mode B: {eff_days}d Fixed-Baseline ({baseline_start}..{baseline_end})"
    shards = [{
        "day": f"{anchor_day.strftime('%Y-%m-%d')}..{today_midnight.strftime('%Y-%m-%d')}",
        "start_time": start_iso,
        "end_time": end_iso,
        "baseline_window": f"[{baseline_start}, {anchor_day.strftime('%Y-%m-%d')})",
        "query": compiled_query,
    }]

  elif mode_clean == "C":
    eff_days = min(max(window_days if window_days > 1 else 7, 2), 7)
    first_day = today_midnight - datetime.timedelta(days=eff_days - 1)
    start_iso = first_day.strftime("%Y-%m-%dT%H:%M:%SZ")
    baseline_start = (first_day - datetime.timedelta(days=30)).strftime("%Y-%m-%d")
    baseline_end = (today_midnight - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    eval_label = f"Mode C: {eff_days}d Rolling Per-Day Shards"
    shards = []
    today_str = today_midnight.strftime("%Y-%m-%d")
    for offset in range(eff_days - 1, -1, -1):
      day_dt = today_midnight - datetime.timedelta(days=offset)
      day_str = day_dt.strftime("%Y-%m-%d")
      shard_start = f"{day_str}T00:00:00Z"
      shard_end = end_iso if offset == 0 else f"{day_str}T23:59:59Z"
      b_start = (day_dt - datetime.timedelta(days=30)).strftime("%Y-%m-%d")
      shard_query = compiled_query.replace(f'"{today_str}"', f'"{day_str}"')
      shards.append({
          "day": day_str,
          "start_time": shard_start,
          "end_time": shard_end,
          "baseline_window": f"[{b_start}, {day_str})",
          "query": shard_query,
      })

  else:  # Mode D: Fleet Rollup Horizon
    eff_days = max(window_days, 1)
    start_dt = today_midnight - datetime.timedelta(days=eff_days - 1)
    start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    baseline_start = (start_dt - datetime.timedelta(days=30)).strftime("%Y-%m-%d")
    baseline_end = (start_dt - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    eval_label = f"Mode D: Fleet Rollup ({eff_days}d)"
    shards = [{
        "day": today_midnight.strftime("%Y-%m-%d"),
        "start_time": start_iso,
        "end_time": end_iso,
        "baseline_window": f"[{baseline_start}, {start_dt.strftime('%Y-%m-%d')})",
        "query": compiled_query,
    }]

  return {
      "mode": mode_clean,
      "window_days": eff_days,
      "evaluation_mode_label": eval_label,
      "start_time": start_iso,
      "end_time": end_iso,
      "probe_start_time": probe_start_iso,
      "probe_end_time": probe_end_iso,
      "baseline_start_date": baseline_start,
      "baseline_end_date": baseline_end,
      "ecg_72h_anchor_applied": ecg_72h_anchor_applied,
      "shards": shards,
  }


def _build_micro_raw_query(
    statistical_model: str,
    entity_type: EntityType,
    entity_value: Optional[str],
    anomaly_threshold: float,
    custom_filter: Optional[Union[str, Sequence[str]]] = None,
    hypothesis_goal: Optional[str] = None,
) -> str:
  """Compiles a raw UDM multi-stage YARA-L 2.0 query for the MICRO_RAW plane."""
  ent_field = "principal.user.userid" if entity_type == EntityType.USER else "principal.asset.hostname"
  ent_var = "$user" if entity_type == EntityType.USER else "$host"
  ent_name = ent_var.lstrip("$")
  model_upper = (statistical_model or "ZSCORE").strip().upper().replace("-", "_")
  goal = hypothesis_goal or f"Micro-Raw Statistical Outlier Hunt ({model_upper})"

  ent_filter_line = ""
  if entity_value and entity_value.lower() not in ("fleet", "fleet-wide", "all", "*"):
    ent_filter_line = f'    {ent_var} = "{entity_value}"\n'

  extra_lines = ""
  if custom_filter:
    lines = [custom_filter] if isinstance(custom_filter, str) else list(custom_filter)
    for ln in lines:
      if ln.strip():
        extra_lines += f"    {ln.strip()}\n"

  if "CV" in model_upper or "JITTER" in model_upper or "BEACON" in model_upper:
    return (
        f"// Goal: {goal}\n"
        "// Plane: MICRO_RAW (Sub-Hour Coefficient of Variation / Jitter)\n"
        "stage stage1_micro_buckets {\n"
        '    metadata.event_type = "NETWORK_HTTP"\n'
        f"    {ent_field} = {ent_var}\n"
        f"    {ent_var} != \"\"\n"
        f"{ent_filter_line}{extra_lines}\n"
        "  match:\n"
        f"    {ent_var} by 5m\n\n"
        "  outcome:\n"
        "    $bucket_obs = count(metadata.id)\n"
        "}\n\n"
        f"{ent_var} = $stage1_micro_buckets.{ent_name}\n\n"
        "match:\n"
        f"  {ent_var}\n\n"
        "outcome:\n"
        "  $mean_obs = avg($stage1_micro_buckets.bucket_obs)\n"
        "  $std_obs = stddev($stage1_micro_buckets.bucket_obs)\n"
        "  $active_windows = count($stage1_micro_buckets.bucket_obs)\n"
        "  $cv = $std_obs / if($mean_obs > 0, $mean_obs, 1.0)\n\n"
        "condition:\n"
        "  $active_windows >= 6 and $cv <= 0.25\n\n"
        "order:\n"
        "  $cv asc\n"
    )

  if "FANO" in model_upper or "VARIANCE" in model_upper:
    return (
        f"// Goal: {goal}\n"
        "// Plane: MICRO_RAW (Poisson Dispersion / Fano Factor Burst)\n"
        "stage stage1_micro_buckets {\n"
        '    metadata.event_type = "USER_LOGIN"\n'
        f"    {ent_field} = {ent_var}\n"
        f"    {ent_var} != \"\"\n"
        f"{ent_filter_line}{extra_lines}\n"
        "  match:\n"
        f"    {ent_var} by 1h\n\n"
        "  outcome:\n"
        "    $bucket_obs = count(metadata.id)\n"
        "}\n\n"
        f"{ent_var} = $stage1_micro_buckets.{ent_name}\n\n"
        "match:\n"
        f"  {ent_var}\n\n"
        "outcome:\n"
        "  $mean_obs = avg($stage1_micro_buckets.bucket_obs)\n"
        "  $std_obs = stddev($stage1_micro_buckets.bucket_obs)\n"
        "  $fano_factor = ($std_obs * $std_obs) / if($mean_obs > 0, $mean_obs, 1.0)\n\n"
        "condition:\n"
        f"  $fano_factor >= {anomaly_threshold}\n\n"
        "order:\n"
        "  $fano_factor desc\n"
    )

  return (
      f"// Goal: {goal}\n"
      f"// Plane: MICRO_RAW ({model_upper})\n"
      "stage stage1_micro_buckets {\n"
      '    metadata.event_type = "NETWORK_CONNECTION"\n'
      f"    {ent_field} = {ent_var}\n"
      f"    {ent_var} != \"\"\n"
      f"{ent_filter_line}{extra_lines}\n"
      "  match:\n"
      f"    {ent_var} by 1h\n\n"
      "  outcome:\n"
      "    $bucket_obs = count(metadata.id)\n"
      "}\n\n"
      f"{ent_var} = $stage1_micro_buckets.{ent_name}\n\n"
      "match:\n"
      f"  {ent_var}\n\n"
      "outcome:\n"
      "  $observed_val = max($stage1_micro_buckets.bucket_obs)\n"
      "  $historical_avg = avg($stage1_micro_buckets.bucket_obs)\n"
      "  $historical_stddev = stddev($stage1_micro_buckets.bucket_obs)\n"
      "  $z_score = ($observed_val - $historical_avg) / if($historical_stddev > 0, $historical_stddev, 1.0)\n\n"
      "condition:\n"
      f"  $z_score >= {anomaly_threshold}\n\n"
      "order:\n"
      "  $z_score desc\n"
  )


# ---------------------------------------------------------------------------
# Core Composable Function 1: compile_hunt_pipeline
# ---------------------------------------------------------------------------


def compile_hunt_pipeline(
    statistical_model: Union[str, StatisticalModel] = "STANDARD_Z_SCORE",
    metrics: Optional[Union[str, Sequence[str]]] = None,
    architecture: str = "single_metric",
    plane: str = "MACRO_METRICS",
    entity_type: Union[str, EntityType] = "USER",
    entity_value: Optional[str] = None,
    custom_filter: Optional[Union[str, Sequence[str]]] = None,
    mode: str = "A",
    window_days: int = 1,
    sensitivity: str = "BALANCED",
    anomaly_threshold: Optional[float] = None,
    min_baseline_days: Optional[int] = None,
    hypothesis_goal: Optional[str] = None,
    identifier_field: Optional[str] = None,
    cohort_entities: Optional[List[str]] = None,
    service_account: Optional[str] = None,
    killchain_archetype: Optional[str] = None,
    chained_path: Optional[str] = None,
    min_threshold: Optional[float] = None,
    max_threshold: Optional[float] = None,
    condition_expression: Optional[str] = None,
    fold_change_threshold: Optional[float] = None,
    fusion_threshold_sq: Optional[float] = None,
    robust_threshold: Optional[float] = None,
    scoring_days: Optional[int] = None,
    scoring_end_date: Optional[str] = None,
    reference_time: Optional[datetime.datetime] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
  """Compiles a multi-stage YARA-L 2.0 hunt pipeline, pre-flight specification card, and time windows.

  Supports all 38 metrics in malachite_catalog, all 17 StatisticalModel variants,
  all PipelineArchitecture DAGs (2-stage, 3-stage, 4-stage, Dual-Plane Hybrid,
  ECG Rarity, Cloud Scope, 360° Radar, MITRE Kill-Chain, and Two-Phase Chained Hunts),
  and Evaluation Modes A, B, C, and D.
  """
  del kwargs  # absorb any extra caller kwargs cleanly

  sens_tier, sens_defaults = resolve_sensitivity(sensitivity)
  eff_anomaly = anomaly_threshold if anomaly_threshold is not None else sens_defaults["anomaly_threshold"]
  eff_fold = fold_change_threshold if fold_change_threshold is not None else sens_defaults["fold_change_threshold"]
  eff_fusion_sq = fusion_threshold_sq if fusion_threshold_sq is not None else sens_defaults["fusion_threshold_sq"]
  eff_robust = robust_threshold if robust_threshold is not None else sens_defaults["robust_threshold"]

  ent_enum = resolve_entity_type(entity_type)
  plane_upper = (plane or "MACRO_METRICS").strip().upper().replace("-", "_")
  arch_raw = (architecture or "single_metric").strip()
  arch_key = arch_raw.lower().replace("-", "_")

  model_str_upper = (
      statistical_model.value
      if isinstance(statistical_model, StatisticalModel)
      else str(statistical_model or "STANDARD_Z_SCORE").strip().upper().replace("-", "_")
  )
  if arch_key in ("single_metric", "local_2stage", "2stage") and model_str_upper in MODEL_IMPLIED_ARCHITECTURE:
    arch_key = MODEL_IMPLIED_ARCHITECTURE[model_str_upper]

  if plane_upper == "HYBRID" and arch_key in ("single_metric", "local_2stage", "2stage"):
    arch_key = "hybrid_enrichment"

  stat_model_enum = resolve_statistical_model(statistical_model)
  metric_list = normalize_metrics_list(metrics, ent_enum, arch_key)
  primary_metric = metric_list[0]

  router = MultiStageTemplateRouter()
  sector_queries: Optional[Dict[str, str]] = None
  chained_plan: Optional[Dict[str, Any]] = None
  entity_graph_dim = "N/A"
  match_mode = MatchMode.FLEET_ROLLUP if (mode or "A").strip().upper().endswith("D") else MatchMode.TIMELINE_BREAKDOWN

  # 1. Compile the query according to plane and architecture
  if plane_upper == "MICRO_RAW":
    compiled_query = _build_micro_raw_query(
        statistical_model=model_str_upper,
        entity_type=ent_enum,
        entity_value=entity_value,
        anomaly_threshold=eff_anomaly,
        custom_filter=custom_filter,
        hypothesis_goal=hypothesis_goal,
    )
    audit_info = {
        "status": "VALID",
        "metric_id": 0,
        "metric_name": primary_metric,
        "required_event_type": "NETWORK_CONNECTION",
        "event_filter": ['metadata.event_type = "NETWORK_CONNECTION"'],
        "event_label": "Raw UDM Telemetry",
        "observed_agg": "count(metadata.id)",
        "metric_arg": "event_count_sum",
        "target_field": "principal.user.userid" if ent_enum == EntityType.USER else "principal.asset.hostname",
        "min_baseline_days": min_baseline_days or 7,
        "match_mode": match_mode.value,
        "math_guardrails": ["$historical_stddev > 0"],
        "sparse_callout": None,
    }
    canonical_arch = "MICRO_RAW_2STAGE"

  elif chained_path or arch_key in ("chained_killchain", "cross_entity") or arch_raw.upper() in ChainedHuntRouter.CROSS_ENTITY_PATHS:
    path_name = (chained_path or (arch_raw if arch_raw.upper() in ChainedHuntRouter.CROSS_ENTITY_PATHS else "USER_CREDENTIAL_TO_HOST_EXECUTION")).upper()
    chained_plan = ChainedHuntRouter.build_cross_entity_killchain_plan(
        path_name=path_name,
        bridge_entity=entity_value,
        anomaly_threshold=eff_anomaly,
    )
    compiled_query = _inject_stage1_filters(
        chained_plan["phase1_query"],
        entity_value=entity_value,
        custom_filter=custom_filter,
    )
    audit_info = PreFlightValidator.audit(
        target_metric=primary_metric if primary_metric in METRIC_CATALOG else "auth_attempts_fail",
        entity_type=ent_enum if ent_enum in METRIC_CATALOG.get(primary_metric, METRIC_CATALOG["auth_attempts_fail"]).supported_entity_types else EntityType.USER,
        min_baseline_days=min_baseline_days,
    )
    canonical_arch = f"CHAINED_{path_name}"

  elif killchain_archetype or arch_key in ("killchain", "mitre_killchain") or arch_raw.upper() in KillChainArchetype.__members__:
    kc_name = (killchain_archetype or (arch_raw if arch_raw.upper() in KillChainArchetype.__members__ else "EXECUTION_TO_EXFILTRATION")).upper()
    kc_enum = KillChainArchetype(kc_name)
    kc_spec = router.KILLCHAIN_CATALOG[kc_enum]
    kc_entity = ent_enum if ent_enum in kc_spec["supported_entities"] else kc_spec["supported_entities"][0]
    compiled_query = router.build_killchain_hunt_query(
        archetype=kc_enum,
        entity_type=kc_entity,
        min_baseline_days=min_baseline_days or 7,
        fusion_threshold_sq=eff_fusion_sq,
        hypothesis_goal=hypothesis_goal,
        identifier_field=identifier_field,
    )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=entity_value, custom_filter=custom_filter)
    metric_list = [kc_spec["sector_a"], kc_spec["sector_b"]]
    primary_metric = metric_list[0]
    ent_enum = kc_entity
    audit_info = PreFlightValidator.audit(target_metric=primary_metric, entity_type=ent_enum, min_baseline_days=min_baseline_days)
    canonical_arch = f"KILLCHAIN_{kc_enum.value}"

  elif arch_key in ("360_radar", "radar_360", "radar_360_decoupled_sector", "radar_360_sector_web_http", "radar_360_sector_alert"):
    if ent_enum == EntityType.USER:
      sector_map = {
          "auth": ("auth_attempts_total", EntityType.USER),
          "cloud": ("resource_read_total", EntityType.USER),
          "workspace": ("workspace_total_download_actions", EntityType.USER),
          "network": ("network_bytes_outbound", EntityType.USER),
          "dns": ("dns_queries_total", EntityType.USER),
          "web": ("http_queries_total", EntityType.USER),
      }
    else:
      sector_map = {
          "auth": ("auth_attempts_total", EntityType.ASSET),
          "alerts": ("alert_event_name_count", EntityType.ASSET),
          "endpoint": ("file_executions_total", EntityType.ASSET),
          "network": ("network_bytes_outbound", EntityType.ASSET),
          "dns": ("dns_queries_total", EntityType.ASSET),
          "web": ("http_queries_total", EntityType.ASSET),
      }
    sector_queries = {}
    for sec_name, (sec_metric, sec_ent) in sector_map.items():
      if sec_metric == "alert_event_name_count":
        sq = router.build_alert_surge_query(entity_type=sec_ent, anomaly_threshold=eff_anomaly)
      elif sec_metric.startswith("resource_"):
        sq = router.build_cloud_repository_scope_query(
            service_account=service_account or entity_value,
            anomaly_threshold=eff_anomaly,
            target_metric=sec_metric,
        )
      else:
        sq = router.build_query(
            target_metric=sec_metric,
            entity_type=sec_ent,
            statistical_model=StatisticalModel.STANDARD_Z_SCORE,
            anomaly_threshold=eff_anomaly,
            min_baseline_days=min_baseline_days,
            match_mode=match_mode,
        )
      sector_queries[sec_name] = _inject_stage1_filters(sq, entity_value=entity_value, custom_filter=custom_filter)

    if arch_key == "radar_360_sector_web_http":
      compiled_query = router.build_pipeline_query(PipelineArchitecture.RADAR_360_SECTOR_WEB_HTTP)
    elif arch_key == "radar_360_sector_alert":
      compiled_query = router.build_pipeline_query(PipelineArchitecture.RADAR_360_SECTOR_ALERT)
    else:
      compiled_query = router.build_pipeline_query(PipelineArchitecture.RADAR_360_DECOUPLED_SECTOR)
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=entity_value, custom_filter=custom_filter)
    audit_info = PreFlightValidator.audit(target_metric="auth_attempts_total", entity_type=ent_enum, min_baseline_days=min_baseline_days)
    canonical_arch = PipelineArchitecture.RADAR_360_DECOUPLED_SECTOR.value

  elif arch_key in ("dual_baseline", "dual_baseline_3stage", "delta_z"):
    if ent_enum not in METRIC_CATALOG[primary_metric].supported_entity_types:
      ent_enum = METRIC_CATALOG[primary_metric].supported_entity_types[0]
    compiled_query = router.build_pipeline_query(
        PipelineArchitecture.DUAL_BASELINE_3STAGE,
        target_metric=primary_metric,
        entity_type=ent_enum,
        anomaly_threshold=eff_anomaly,
        min_baseline_days=min_baseline_days,
        hypothesis_goal=hypothesis_goal,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        identifier_field=identifier_field,
    )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=entity_value, custom_filter=custom_filter)
    audit_info = PreFlightValidator.audit(target_metric=primary_metric, entity_type=ent_enum, min_baseline_days=min_baseline_days, identifier_field=identifier_field)
    canonical_arch = PipelineArchitecture.DUAL_BASELINE_3STAGE.value

  elif arch_key in ("empirical_bayes", "empirical_bayes_3stage", "hierarchical_bayes"):
    if ent_enum not in METRIC_CATALOG[primary_metric].supported_entity_types:
      ent_enum = METRIC_CATALOG[primary_metric].supported_entity_types[0]
    compiled_query = router.build_pipeline_query(
        PipelineArchitecture.EMPIRICAL_BAYES_3STAGE,
        target_metric=primary_metric,
        entity_type=ent_enum,
        anomaly_threshold=eff_anomaly,
        min_baseline_days=min_baseline_days,
        hypothesis_goal=hypothesis_goal,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        identifier_field=identifier_field,
    )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=entity_value, custom_filter=custom_filter)
    audit_info = PreFlightValidator.audit(target_metric=primary_metric, entity_type=ent_enum, min_baseline_days=min_baseline_days, identifier_field=identifier_field)
    canonical_arch = PipelineArchitecture.EMPIRICAL_BAYES_3STAGE.value

  elif arch_key in ("sector_fusion", "dual_sector_fusion_3stage", "fusion_3stage", "multi_sector_fusion_4stage", "fusion_4stage", "rollup_sector_fusion"):
    is_four_stage = arch_key in ("multi_sector_fusion_4stage", "fusion_4stage", "rollup_sector_fusion")
    pipe_enum = PipelineArchitecture.MULTI_SECTOR_FUSION_4STAGE if is_four_stage else PipelineArchitecture.DUAL_SECTOR_FUSION_3STAGE
    if len(metric_list) < 2:
      second = "network_bytes_outbound" if primary_metric != "network_bytes_outbound" else "auth_attempts_fail"
      metric_list = [primary_metric, second]
    for m in metric_list[:2]:
      if ent_enum not in METRIC_CATALOG[m].supported_entity_types:
        ent_enum = EntityType.ASSET
    compiled_query = router.build_pipeline_query(
        pipe_enum,
        target_metrics=metric_list[:2],
        entity_type=ent_enum,
        anomaly_threshold=eff_anomaly,
        min_baseline_days=min_baseline_days,
        hypothesis_goal=hypothesis_goal,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        identifier_field=identifier_field,
        fusion_threshold_sq=eff_fusion_sq,
    )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=entity_value, custom_filter=custom_filter)
    audit_info = PreFlightValidator.audit(target_metric=metric_list[0], entity_type=ent_enum, min_baseline_days=min_baseline_days)
    canonical_arch = pipe_enum.value

  elif arch_key in ("triad", "part_of_the_whole_triad_multilevel", "part_of_the_whole_triad"):
    compiled_query = router.build_pipeline_query(
        PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
        target_metrics=metric_list[:3],
        entity_type=ent_enum,
        anomaly_threshold=eff_anomaly,
        min_baseline_days=min_baseline_days,
        hypothesis_goal=hypothesis_goal,
        cohort_entities=cohort_entities,
        target_entity=entity_value,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        identifier_field=identifier_field,
        fusion_threshold_sq=eff_fusion_sq,
    )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=None, custom_filter=custom_filter)
    audit_info = PreFlightValidator.audit(target_metric=metric_list[0], entity_type=ent_enum, min_baseline_days=min_baseline_days)
    canonical_arch = PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL.value

  elif arch_key in ("multilevel", "part_of_the_whole_multilevel", "part_of_the_whole", "peer_cohort"):
    if ent_enum not in METRIC_CATALOG[primary_metric].supported_entity_types:
      ent_enum = METRIC_CATALOG[primary_metric].supported_entity_types[0]
    compiled_query = router.build_pipeline_query(
        PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL,
        target_metric=primary_metric,
        entity_type=ent_enum,
        anomaly_threshold=eff_anomaly,
        min_baseline_days=min_baseline_days,
        hypothesis_goal=hypothesis_goal,
        cohort_entities=cohort_entities,
        target_entity=entity_value,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        identifier_field=identifier_field,
    )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=None, custom_filter=custom_filter)
    audit_info = PreFlightValidator.audit(target_metric=primary_metric, entity_type=ent_enum, min_baseline_days=min_baseline_days, identifier_field=identifier_field)
    canonical_arch = PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL.value

  elif arch_key in ("cloud_scope", "cloud_repository_scope_dual_branch", "cloud_repository_scope"):
    sa_val = service_account or (entity_value if entity_value and entity_value.lower() not in ("fleet", "all", "*") else None)
    compiled_query = router.build_cloud_repository_scope_query(
        service_account=sa_val,
        anomaly_threshold=eff_anomaly,
        hypothesis_goal=hypothesis_goal,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        target_metric=primary_metric if primary_metric.startswith("resource_") else "resource_read_total",
    )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=None, custom_filter=custom_filter)
    ent_enum = EntityType.USER
    primary_metric = primary_metric if primary_metric.startswith("resource_") else "resource_read_total"
    audit_info = PreFlightValidator.audit(target_metric=primary_metric, entity_type=ent_enum, min_baseline_days=min_baseline_days)
    canonical_arch = PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH.value

  elif arch_key in ("rare_destination", "rare_destination_ecg_3stage"):
    ent_enum = EntityType.ASSET
    if ent_enum not in METRIC_CATALOG[primary_metric].supported_entity_types:
      primary_metric = "network_bytes_outbound"
    compiled_query = router.build_rare_destination_ecg_query(
        target_metric=primary_metric,
        entity_type=ent_enum,
        anomaly_threshold=eff_anomaly,
        hypothesis_goal=hypothesis_goal,
    )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=entity_value, custom_filter=custom_filter)
    audit_info = PreFlightValidator.audit(target_metric=primary_metric, entity_type=ent_enum, min_baseline_days=min_baseline_days)
    entity_graph_dim = "DERIVED_CONTEXT Domain Prevalence (rolling_max <= 3, day_count = 10)"
    canonical_arch = PipelineArchitecture.RARE_DESTINATION_ECG_3STAGE.value

  elif arch_key in ("fusion_rare_destination", "fusion_rare_destination_3stage"):
    compiled_query = router.build_fusion_rare_destination_query(
        target_metrics=metric_list[:2] if len(metric_list) >= 2 else None,
        entity_type=ent_enum,
        fusion_threshold_sq=eff_fusion_sq,
        hypothesis_goal=hypothesis_goal,
    )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=entity_value, custom_filter=custom_filter)
    audit_info = PreFlightValidator.audit(target_metric=metric_list[0], entity_type=ent_enum, min_baseline_days=min_baseline_days)
    entity_graph_dim = "DERIVED_CONTEXT Domain Prevalence (rolling_max <= 3, day_count = 10)"
    canonical_arch = PipelineArchitecture.FUSION_RARE_DESTINATION_3STAGE.value

  elif arch_key in ("failure_ratio", "http_error_ratio_surge_2stage"):
    fail_m = primary_metric if primary_metric.endswith("_fail") else "http_queries_fail"
    if ent_enum not in METRIC_CATALOG[fail_m].supported_entity_types:
      ent_enum = METRIC_CATALOG[fail_m].supported_entity_types[0]
    compiled_query = router.build_failure_ratio_surge_query(
        fail_metric=fail_m,
        entity_type=ent_enum,
        anomaly_threshold=eff_anomaly,
        hypothesis_goal=hypothesis_goal,
        identifier_field=identifier_field,
    )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=entity_value, custom_filter=custom_filter)
    primary_metric = fail_m
    audit_info = PreFlightValidator.audit(target_metric=primary_metric, entity_type=ent_enum, min_baseline_days=min_baseline_days)
    canonical_arch = PipelineArchitecture.HTTP_ERROR_RATIO_SURGE_2STAGE.value

  elif arch_key == "c2_beacon_flow":
    flow_m = primary_metric if primary_metric.startswith("network_flows_") else "network_flows_outbound"
    ent_enum = EntityType.ASSET
    compiled_query = router.build_c2_beacon_flow_query(
        target_metric=flow_m,
        entity_type=ent_enum,
        anomaly_threshold=eff_anomaly,
        min_baseline_days=min_baseline_days or 7,
        hypothesis_goal=hypothesis_goal,
        identifier_field=identifier_field,
    )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=entity_value, custom_filter=custom_filter)
    primary_metric = flow_m
    audit_info = PreFlightValidator.audit(target_metric=primary_metric, entity_type=ent_enum, min_baseline_days=min_baseline_days)
    canonical_arch = "C2_BEACON_FLOW_2STAGE"

  elif arch_key == "alert_surge":
    primary_metric = "alert_event_name_count"
    compiled_query = router.build_alert_surge_query(
        entity_type=ent_enum,
        anomaly_threshold=eff_anomaly,
        hypothesis_goal=hypothesis_goal,
    )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=entity_value, custom_filter=custom_filter)
    audit_info = {
        "status": "VALID",
        "metric_id": METRIC_CATALOG[primary_metric].metric_id,
        "metric_name": primary_metric,
        "required_event_type": "ALERT",
        "event_filter": list(mc.baseline_semantics(primary_metric).observed_filter),
        "event_label": mc.baseline_semantics(primary_metric).event_label,
        "observed_agg": "count(metadata.id)",
        "metric_arg": "event_count_sum",
        "target_field": "principal.user.userid" if ent_enum == EntityType.USER else "principal.asset.hostname",
        "min_baseline_days": min_baseline_days or 7,
        "match_mode": match_mode.value,
        "math_guardrails": ["$d_sigma > 0"],
        "sparse_callout": None,
    }
    canonical_arch = "ALERT_SURGE_2STAGE"

  elif arch_key in (
      "hybrid_enrichment",
      "hybrid_metric_raw_enrichment_2stage",
      "hybrid_entropy_concentration",
      "hybrid_metric_entropy_concentration_2stage",
      "hybrid_orthogonal_space",
      "hybrid_metric_orthogonal_space_2stage",
      "hybrid_fleet_prevalence",
      "hybrid_metric_fleet_prevalence_2stage",
      "hybrid_http_ua_prevalence",
      "hybrid_metric_http_ua_prevalence_2stage",
      "hybrid_derived_file_prevalence",
      "hybrid_metric_derived_file_prevalence_2stage",
      "hybrid_derived_domain_prevalence",
      "hybrid_metric_derived_domain_prevalence_2stage",
      "hybrid_whois_domain_lifecycle",
      "hybrid_metric_whois_domain_lifecycle_2stage",
      "hybrid_derived_asset_age",
      "hybrid_metric_derived_asset_age_2stage",
      "http_target_surge_2stage",
      "macd_momentum_velocity_2stage",
      "circadian_von_mises_2stage",
  ):
    hybrid_arch_map = {
        "hybrid_enrichment": PipelineArchitecture.HYBRID_METRIC_RAW_ENRICHMENT_2STAGE,
        "hybrid_metric_raw_enrichment_2stage": PipelineArchitecture.HYBRID_METRIC_RAW_ENRICHMENT_2STAGE,
        "hybrid_entropy_concentration": PipelineArchitecture.HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE,
        "hybrid_metric_entropy_concentration_2stage": PipelineArchitecture.HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE,
        "hybrid_orthogonal_space": PipelineArchitecture.HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE,
        "hybrid_metric_orthogonal_space_2stage": PipelineArchitecture.HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE,
        "hybrid_fleet_prevalence": PipelineArchitecture.HYBRID_METRIC_FLEET_PREVALENCE_2STAGE,
        "hybrid_metric_fleet_prevalence_2stage": PipelineArchitecture.HYBRID_METRIC_FLEET_PREVALENCE_2STAGE,
        "hybrid_http_ua_prevalence": PipelineArchitecture.HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE,
        "hybrid_metric_http_ua_prevalence_2stage": PipelineArchitecture.HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE,
        "hybrid_derived_file_prevalence": PipelineArchitecture.HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE,
        "hybrid_metric_derived_file_prevalence_2stage": PipelineArchitecture.HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE,
        "hybrid_derived_domain_prevalence": PipelineArchitecture.HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE,
        "hybrid_metric_derived_domain_prevalence_2stage": PipelineArchitecture.HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE,
        "hybrid_whois_domain_lifecycle": PipelineArchitecture.HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE,
        "hybrid_metric_whois_domain_lifecycle_2stage": PipelineArchitecture.HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE,
        "hybrid_derived_asset_age": PipelineArchitecture.HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE,
        "hybrid_metric_derived_asset_age_2stage": PipelineArchitecture.HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE,
        "http_target_surge_2stage": PipelineArchitecture.HTTP_TARGET_SURGE_2STAGE,
        "macd_momentum_velocity_2stage": PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE,
        "circadian_von_mises_2stage": PipelineArchitecture.CIRCADIAN_VON_MISES_2STAGE,
    }
    pipe_enum = hybrid_arch_map[arch_key]
    plane_upper = "HYBRID" if "HYBRID" in pipe_enum.value else plane_upper
    if ent_enum not in METRIC_CATALOG[primary_metric].supported_entity_types:
      ent_enum = METRIC_CATALOG[primary_metric].supported_entity_types[0]
    compiled_query = router.build_pipeline_query(
        pipe_enum,
        target_metric=primary_metric,
        entity_type=ent_enum,
        anomaly_threshold=eff_anomaly,
        min_baseline_days=min_baseline_days,
        hypothesis_goal=hypothesis_goal,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        identifier_field=identifier_field,
    )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=entity_value, custom_filter=custom_filter)
    audit_info = PreFlightValidator.audit(target_metric=primary_metric, entity_type=ent_enum, min_baseline_days=min_baseline_days)
    if "DERIVED" in pipe_enum.value:
      entity_graph_dim = "DERIVED_CONTEXT Prevalence / Asset Age (rolling_max <= 3, day_count = 10)"
    elif "WHOIS" in pipe_enum.value:
      entity_graph_dim = "GLOBAL_CONTEXT WHOIS Domain Registration Lifecycle (NRD <= 30d)"
    canonical_arch = pipe_enum.value

  else:
    # Default: 2-Stage Single Metric + Stage 2 Mathematical Model (or auto-routed composite/cloud scope)
    if primary_metric == "alert_event_name_count":
      compiled_query = router.build_alert_surge_query(
          entity_type=ent_enum,
          anomaly_threshold=eff_anomaly,
          hypothesis_goal=hypothesis_goal,
      )
      audit_info = {
          "status": "VALID",
          "metric_id": METRIC_CATALOG[primary_metric].metric_id,
          "metric_name": primary_metric,
          "required_event_type": "ALERT",
          "event_filter": list(mc.baseline_semantics(primary_metric).observed_filter),
          "event_label": mc.baseline_semantics(primary_metric).event_label,
          "observed_agg": "count(metadata.id)",
          "metric_arg": "event_count_sum",
          "target_field": "principal.user.userid" if ent_enum == EntityType.USER else "principal.asset.hostname",
          "min_baseline_days": min_baseline_days or 7,
          "match_mode": match_mode.value,
          "math_guardrails": ["$d_sigma > 0"],
          "sparse_callout": None,
      }
      canonical_arch = "ALERT_SURGE_2STAGE"
    else:
      if ent_enum not in METRIC_CATALOG[primary_metric].supported_entity_types:
        ent_enum = METRIC_CATALOG[primary_metric].supported_entity_types[0]
      compiled_query = router.build_query(
          target_metric=primary_metric,
          entity_type=ent_enum,
          statistical_model=stat_model_enum,
          anomaly_threshold=eff_anomaly,
          min_baseline_days=min_baseline_days,
          match_mode=match_mode,
          hypothesis_goal=hypothesis_goal,
          min_threshold=min_threshold,
          max_threshold=max_threshold,
          condition_expression=condition_expression,
          identifier_field=identifier_field,
          scoring_days=scoring_days,
          scoring_end_date=scoring_end_date,
          fold_change_threshold=eff_fold,
          robust_threshold=eff_robust,
      )
      audit_info = PreFlightValidator.audit(
          target_metric=primary_metric,
          entity_type=ent_enum,
          min_baseline_days=min_baseline_days,
          match_mode=match_mode,
          identifier_field=identifier_field,
      )
      canonical_arch = (
          PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH.value
          if (primary_metric.startswith("resource_") and ent_enum == EntityType.USER and stat_model_enum != StatisticalModel.MAD)
          else PipelineArchitecture.LOCAL_2STAGE.value
      )
    compiled_query = _inject_stage1_filters(compiled_query, entity_value=entity_value, custom_filter=custom_filter)

  # 2. Validate AST and Statistical Antipatterns
  ast_errors = MalachiteASTValidator.validate_query(compiled_query)
  stat_violations = [
      f"[{sv.antipattern.value}] stage '{sv.stage_name}': {sv.description}"
      for sv in StatisticalAntipatternAuditor.audit_query(compiled_query)
  ]

  # 3. Compute Execution Windows & Turn-1 10-Minute Probe Query
  window_spec = _compute_execution_windows(
      compiled_query=compiled_query,
      mode=mode,
      window_days=window_days,
      statistical_model=stat_model_enum if plane_upper != "MICRO_RAW" else None,
      reference_time=reference_time,
  )

  probe_filter_lines = list(audit_info.get("event_filter", ['metadata.event_type = "USER_LOGIN"']))
  probe_query = " AND ".join(probe_filter_lines)

  # 4. Render Pre-Flight Specification Card + Candidate Query Preview + Clearance Question
  target_scope_label = entity_value if (entity_value and entity_value.lower() not in ("fleet", "all", "*")) else f"Fleet-Wide ({ent_enum.value})"
  peer_cohort_label = (
      f"Named Cohort ({', '.join(cohort_entities)})"
      if cohort_entities
      else f"Enterprise {ent_enum.value.title()} Population"
  )
  root_gate = MultiStageTemplateRouter.root_condition(compiled_query)
  sig_label = root_gate or default_significance_threshold(stat_model_enum.value) or f"Z >= {eff_anomaly}σ (CRI >= 50)"

  preflight_card = PreFlightValidator.render_preflight_card(
      target_scope=target_scope_label,
      peer_cohort=peer_cohort_label,
      statistical_model=f"{stat_model_enum.value} ({canonical_arch})",
      entity_graph_dimension=entity_graph_dim,
      evaluation_mode=window_spec["evaluation_mode_label"],
      significance_threshold=sig_label,
      min_baseline_days=audit_info.get("min_baseline_days", 7),
  )

  clearance_question = (
      "Would you like me to proceed with **Mode A (Today vs 30-Day Baseline)**, "
      "**Mode B (2–7 Day Fixed-Baseline Timeline)**, or **Mode C (Per-Day Baseline Shards)**? "
      "(Thresholds can be tuned first.)"
  )

  md_parts = [preflight_card]
  if chained_plan:
    bridge_keys = ", ".join(chained_plan.get("bridge_contract", ("$host", "$user", "$timestamp")))
    tactics = " -> ".join(chained_plan.get("mitre_tactics", ("Phase 1", "Phase 2")))
    md_parts.append(
        f"**Two-Phase Chained Hunt Specification ({tactics})**:\n"
        f"- **Phase 1**: Execute primary UEBA baseline query below and extract bridge keys.\n"
        f"- **Bridge Contract**: `{bridge_keys}`\n"
        f"- **Phase 2**: Pivot into the secondary entity plane using the extracted bridge keys or Chronicle Data Table column syntax (`in %ueba_hunt_bridge.entity`)."
    )
  md_parts.extend([
      "#### 💻 Candidate Multi-Stage YARA-L 2.0 Query Preview\n\n```yara\n" + compiled_query.strip() + "\n```",
      clearance_question,
  ])
  preflight_card_markdown = "\n\n".join(md_parts)

  return {
      "status": "COMPILED" if not ast_errors else "VALIDATION_FAILED",
      "plane": plane_upper,
      "architecture": canonical_arch,
      "statistical_model": stat_model_enum.value if plane_upper != "MICRO_RAW" else model_str_upper,
      "metrics": metric_list,
      "primary_metric": primary_metric,
      "entity_type": ent_enum.value,
      "entity_value": entity_value or "Fleet-Wide",
      "target_field": audit_info.get("target_field", ""),
      "mode": window_spec["mode"],
      "window_days": window_spec["window_days"],
      "evaluation_mode_label": window_spec["evaluation_mode_label"],
      "sensitivity": sens_tier,
      "anomaly_threshold": eff_anomaly,
      "min_baseline_days": audit_info.get("min_baseline_days", 7),
      "compiled_query": compiled_query,
      "query": compiled_query,
      "probe_query": probe_query,
      "probe_start_time": window_spec["probe_start_time"],
      "probe_end_time": window_spec["probe_end_time"],
      "start_time": window_spec["start_time"],
      "end_time": window_spec["end_time"],
      "search_window": {
          "start_time": window_spec["start_time"],
          "end_time": window_spec["end_time"],
          "mode": window_spec["mode"],
          "window_days": window_spec["window_days"],
          "baseline_start_date": window_spec["baseline_start_date"],
          "baseline_end_date": window_spec["baseline_end_date"],
          "ecg_72h_anchor_applied": window_spec["ecg_72h_anchor_applied"],
      },
      "shards": window_spec["shards"],
      "sector_queries": sector_queries,
      "chained_plan": chained_plan,
      "ast_valid": len(ast_errors) == 0,
      "ast_errors": ast_errors,
      "statistical_violations": stat_violations,
      "audit": audit_info,
      "preflight_card": preflight_card,
      "preflight_card_markdown": preflight_card_markdown,
  }


# ---------------------------------------------------------------------------
# Core Composable Function 2: dispatch_hybrid_handoff
# ---------------------------------------------------------------------------


def dispatch_hybrid_handoff(
    intent: str = "SCHEDULED_EXFILTRATION_TIMING",
    entity_value: str = "unknown_entity",
    entity_type: str = "HOSTNAME",
    lookback: str = "24h",
    sensitivity: str = "BALANCED",
    justification: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    macro_context: Optional[Dict[str, Any]] = None,
    turn1_demarcation_only: bool = False,
    stats_hunter_dir: Optional[Path] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
  """Builds and dispatches a federated handoff payload (`secops-threat-hunt-handoff-v1`) to `secops-statistical-hunter`.

  Supports both:
  - Turn 1 Consultative Demarcation (`turn1_demarcation_only=True`): emits the conceptual
    handoff card with `json:secops-threat-hunt-handoff-v1` and ZERO YARA-L code blocks
    (enforcing the Zero-Code Handoff Invariant).
  - Phase 2 Macro-to-Micro Handoff (`turn1_demarcation_only=False`): enriches parameters
    with Phase 1 `macro_context` (metric, Z-score, CRI, observed/baseline stats), dispatches
    to `secops-statistical-hunter`, and returns the ACK + compiled micro-telemetry query.
  """
  merged_params: Dict[str, Any] = dict(parameters or {})
  if macro_context:
    merged_params["macro_context"] = dict(macro_context)
    if not justification:
      m_name = macro_context.get("metric", "metrics.*")
      m_z = macro_context.get("z_score", macro_context.get("score", "N/A"))
      m_cri = macro_context.get("cri", "N/A")
      justification = (
          f"Macro 30-day baseline ({m_name}) flagged entity '{entity_value}' "
          f"(Z={m_z}, CRI={m_cri}); delegating to secops-statistical-hunter "
          f"for micro-telemetry analysis ({intent})."
      )

  payload = build_handoff_payload(
      intent=intent,
      entity_type=entity_type,
      entity_value=entity_value,
      lookback=lookback,
      sensitivity=sensitivity,
      justification=justification,
      parameters=merged_params,
      request_id=request_id,
  )

  demarcation_card = format_handoff_card(payload, ack=None)
  if turn1_demarcation_only:
    return {
        "status": "PENDING_DISPATCH",
        "action": "CONSULTATIVE_DEMARCATION",
        "protocol": SUPPORTED_PROTOCOL,
        "request_id": payload["request_id"],
        "intent": payload["intent"],
        "model_routed": payload["statistical_model"]["name"],
        "payload": payload,
        "ack": None,
        "compiled_query": "",
        "handoff_card_markdown": demarcation_card,
        "demarcation_card_markdown": demarcation_card,
    }

  ack = dispatch_to_endpoint(payload, stats_hunter_dir=stats_hunter_dir)
  full_card = format_handoff_card(payload, ack=ack)

  return {
      "status": ack.get("status", "HANDOFF_ACK_ACCEPTED"),
      "action": ack.get("action", "STEP_OUT_CONFIRMED"),
      "protocol": SUPPORTED_PROTOCOL,
      "request_id": payload["request_id"],
      "intent": payload["intent"],
      "model_routed": ack.get("model_routed", payload["statistical_model"]["name"]),
      "payload": payload,
      "ack": ack,
      "compiled_query": ack.get("compiled_query", ""),
      "handoff_card_markdown": full_card,
      "demarcation_card_markdown": demarcation_card,
  }


# ---------------------------------------------------------------------------
# Core Composable Function 3: render_forensic_dossier
# ---------------------------------------------------------------------------


def _cri_band_metadata(cri: int) -> Tuple[str, str, str]:
  """Returns (short_badge, full_band_label, unicode_bar) for a CRI [0..100] score."""
  blocks = max(0, min(8, int(round((cri / 100.0) * 8))))
  bar = ("█" * blocks) + ("░" * (8 - blocks))
  if cri >= 90:
    return "CRITICAL", "🚨 Critical Outlier", bar
  if cri >= 70:
    return "HIGH", "🔴 High Threat", bar
  if cri >= 46:
    return "MEDIUM", "🟠 Medium Outlier", bar
  if cri >= 26:
    return "LOW", "🟡 Low Drift", bar
  return "INFORMATIONAL", "🟢 Nominal", bar


def _normalize_single_row(raw_row: Dict[str, Any]) -> Dict[str, Any]:
  """Normalizes an arbitrary Chronicle stats row or flat dict into canonical outlier fields."""
  row: Dict[str, Any] = {}
  for k, v in raw_row.items():
    clean_k = k.lstrip("$") if isinstance(k, str) else k
    row[clean_k] = v

  # Resolve entity identifier
  entity = None
  for k in (
      "entity",
      "user",
      "host",
      "sa",
      "hostname",
      "userid",
      "token",
      "domain",
      "resource",
      "principal.user.userid",
      "principal.asset.hostname",
      "target.user.userid",
      "target.asset.hostname",
  ):
    if row.get(k) not in (None, ""):
      entity = str(row[k])
      break
  if not entity:
    entity = "unknown_entity"

  def _first_float(keys: Sequence[str], default: Optional[float] = None) -> Optional[float]:
    for k in keys:
      if k in row and row[k] is not None and row[k] != "-":
        val = row[k]
        if isinstance(val, list) and val:
          val = val[0]
        try:
          return float(val)
        except (TypeError, ValueError):
          continue
    return default

  observed = _first_float((
      "observed",
      "observed_val",
      "observed_24h",
      "obs",
      "today_val",
      "total_obs",
      "observed_flows",
      "total_alerts",
      "observed_launches",
      "failed_obs",
      "observed_fails",
      "m1_obs",
      "sector_a_obs",
  ), 0.0)

  hist_avg = _first_float((
      "hist_avg",
      "historical_avg",
      "avg_30d",
      "mu",
      "hist_mean",
      "baseline_mean",
      "historical_mean",
      "historical_flow_avg",
      "hist_fail_avg",
      "median_30d",
      "d_mu",
      "m1_avg",
  ), 0.0)

  hist_stddev = _first_float((
      "hist_stddev",
      "historical_stddev",
      "stddev_30d",
      "sigma",
      "hist_std",
      "baseline_stddev",
      "historical_flow_stddev",
      "hist_fail_stddev",
      "robust_scale",
      "safe_robust_scale",
      "d_sigma",
  ), 1.0)

  active_days = _first_float((
      "active_days",
      "hist_active_days",
      "historical_active_days",
      "active_baseline_days",
      "hist_days",
      "d_days",
      "hist_flow_active_days",
      "hist_fail_active_days",
      "baseline_days",
  ), 30.0)

  score = _first_float((
      "z_score",
      "personal_z",
      "anomaly_score",
      "delta_z",
      "eb_z_score",
      "modified_z",
      "poisson_z",
      "cusum_s",
      "hurdle_z",
      "asymmetric_z",
      "macd_z",
      "circadian_z",
      "composite_risk",
      "threat_distance",
      "threat_norm",
      "threat_score",
      "normalized_odds_score",
      "recon_score",
      "beacon_score",
      "alert_z",
      "process_z",
      "fail_z",
      "flow_z",
      "macro_z_score",
      "macro_z",
      "z_vs_enterprise",
      "z_vs_team",
      "z",
  ))

  if score is None:
    sq_val = _first_float(("threat_distance_sq", "d_vs_fleet_sq", "d_vs_team_sq", "norm_sq"))
    if sq_val is not None:
      score = math.sqrt(max(0.0, sq_val))
    elif observed is not None and hist_avg is not None:
      denom = hist_stddev if (hist_stddev and hist_stddev > 0) else 1.0
      score = (observed - hist_avg) / denom
    else:
      score = 0.0

  explicit_cri = _first_float(("cri", "cri_score"))
  cri_int = int(round(explicit_cri)) if explicit_cri is not None else cri_from_score(score)
  cri_int = max(0, min(100, cri_int))
  short_badge, full_band, bar = _cri_band_metadata(cri_int)

  normalized = dict(row)
  normalized.update({
      "entity": entity,
      "observed": round(observed, 2) if observed is not None else 0.0,
      "observed_val": round(observed, 2) if observed is not None else 0.0,
      "hist_avg": round(hist_avg, 2) if hist_avg is not None else 0.0,
      "historical_avg": round(hist_avg, 2) if hist_avg is not None else 0.0,
      "hist_stddev": round(hist_stddev, 2) if hist_stddev is not None else 1.0,
      "historical_stddev": round(hist_stddev, 2) if hist_stddev is not None else 1.0,
      "active_days": int(round(active_days)) if active_days is not None else 30,
      "z_score": round(score, 2),
      "anomaly_score": round(score, 2),
      "cri": cri_int,
      "cri_score": cri_int,
      "cri_badge": short_badge,
      "cri_band_label": full_band,
      "visual_bar": bar,
  })
  return normalized


def _extract_and_normalize_rows(
    rows_input: Union[None, str, List[Dict[str, Any]], Dict[str, Any], Sequence[Tuple[str, Any]]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
  """Parses arbitrary rows/stats input into normalized outlier dicts and a raw API response envelope."""
  if rows_input is None or rows_input == "" or rows_input == [] or rows_input == {}:
    return [], {"stats": {"results": []}}

  # Check if Mode C shards: sequence of (day_str, payload) tuples
  if (
      isinstance(rows_input, (list, tuple))
      and rows_input
      and isinstance(rows_input[0], (list, tuple))
      and len(rows_input[0]) == 2
      and isinstance(rows_input[0][0], str)
  ):
    combined: List[Dict[str, Any]] = []
    for day_str, shard_payload in rows_input:
      shard_rows, _ = _extract_and_normalize_rows(shard_payload)
      for r in shard_rows:
        r_copy = dict(r)
        r_copy.setdefault("day", day_str)
        combined.append(_normalize_single_row(r_copy))
    combined.sort(key=lambda x: x.get("z_score", 0.0), reverse=True)
    return combined, {"stats": {"results": combined}}

  if isinstance(rows_input, str):
    text = rows_input.strip()
    if not text:
      return [], {"stats": {"results": []}}
    try:
      loaded = json.loads(text)
      return _extract_and_normalize_rows(loaded)
    except json.JSONDecodeError:
      return [], {"stats": {"results": []}}

  if isinstance(rows_input, dict):
    if "events" in rows_input and "stats" not in rows_input and "results" not in rows_input and "top_outliers" not in rows_input:
      return [], rows_input
    if "top_outliers" in rows_input and isinstance(rows_input["top_outliers"], list):
      normalized = [_normalize_single_row(r) for r in rows_input["top_outliers"]]
      normalized.sort(key=lambda x: x.get("z_score", 0.0), reverse=True)
      return normalized, {"stats": {"results": normalized}}
    if "results" in rows_input and "stats" not in rows_input and isinstance(rows_input["results"], list):
      return _extract_and_normalize_rows(rows_input["results"])
    parsed = parse_stats_payload(rows_input)
    normalized = [_normalize_single_row(r) for r in parsed]
    normalized.sort(key=lambda x: x.get("z_score", 0.0), reverse=True)
    return normalized, rows_input

  if isinstance(rows_input, (list, tuple)):
    # Could be a list of flat dicts or Chronicle columnar buckets
    if rows_input and isinstance(rows_input[0], dict) and "column" in rows_input[0] and "values" in rows_input[0]:
      parsed = parse_stats_payload({"stats": {"results": list(rows_input)}})
      normalized = [_normalize_single_row(r) for r in parsed]
    else:
      normalized = [_normalize_single_row(r) for r in rows_input if isinstance(r, dict)]
    normalized.sort(key=lambda x: x.get("z_score", 0.0), reverse=True)
    return normalized, {"stats": {"results": normalized}}

  return [], {"stats": {"results": []}}


def render_forensic_dossier(
    rows: Union[None, str, List[Dict[str, Any]], Dict[str, Any], Sequence[Tuple[str, Any]]],
    executed_query: str,
    statistical_model: str = "STANDARD_Z_SCORE",
    metric_name: str = "auth_attempts_total",
    entity_type: str = "USER",
    mode: str = "A",
    window_days: int = 14,
    anomaly_threshold: float = 3.0,
    output_html_path: Optional[Union[str, Path]] = None,
    radar_scores: Optional[Union[str, Dict[str, float]]] = None,
    baseline_dates: Optional[Tuple[str, str]] = None,
    skip_postflight_audit: bool = False,
    **kwargs: Any,
) -> Dict[str, Any]:
  """Renders a 6-Section CommonMark Forensic Triage Dossier with CRI scoring, SVG/HTML charts, and next steps.

  Handles:
  - Post-Flight Execution Auditing (blocking raw event log dumps or uncompiled queries)
  - Zero-Row Recovery (`CLEAN_OR_SUBTHRESHOLD` Nominal Baseline report when `rows` is empty)
  - Outcome Classification (`ACUTE_OUTLIER`, `FLEET_WAVE`, `SPARSE_BASELINE`, `CLEAN_OR_SUBTHRESHOLD`)
  - Mode B / Mode C Multi-Day Timeline Collation (`TimelineAssembler`)
  - 360° Entity Behavioral Radar (`EntityRadarCollector`)
  - Self-contained HTML + SVG Chart Generation (`RiskMetricsChartGenerator` & `EntityRadarCollector`)
  """
  del kwargs

  clean_metric = (metric_name or "auth_attempts_total").strip()
  if clean_metric.startswith("metrics."):
    clean_metric = clean_metric[len("metrics."):]
  ent_enum = resolve_entity_type(entity_type)
  stat_model_enum = resolve_statistical_model(statistical_model)
  model_label = stat_model_enum.value

  outliers, raw_envelope = _extract_and_normalize_rows(rows)
  mode_clean = (mode or "A").strip().upper().replace("MODE", "").strip() or "A"

  # 1. Post-Flight Execution Audit
  audit_result = None
  if not skip_postflight_audit and "metrics." in (executed_query or ""):
    audit_result = PostFlightExecutionAuditor.audit_execution(
        executed_query=executed_query,
        api_response=raw_envelope,
        target_metric=clean_metric if clean_metric in METRIC_CATALOG else None,
        entity_type=ent_enum,
        statistical_model=stat_model_enum,
        anomaly_threshold=anomaly_threshold,
    )
    if not audit_result.is_valid and "RAW_LOG_DUMP_DETECTED" in " ".join(audit_result.errors):
      blocked_md = CommonMarkTriageFormatter.format_report(
          reduced_data={"outlier_count": 0, "top_outliers": []},
          target_metric=clean_metric,
          statistical_model=model_label,
          anomaly_threshold=anomaly_threshold,
          executed_query=executed_query,
          audit_result=audit_result,
      )
      return {
          "status": "POSTFLIGHT_AUDIT_BLOCKED",
          "is_zero_row": True,
          "outcome_classification": "AUDIT_BLOCKED",
          "outlier_count": 0,
          "outliers": [],
          "dossier_markdown": blocked_md,
          "markdown": blocked_md,
          "clean_hunt_markdown": blocked_md,
          "chart_svg": "",
          "chart_html": "",
          "vega_lite_spec": {},
          "embed_tag": "",
          "output_html_path": None,
          "audit_result": audit_result,
      }

  reduced_data: Dict[str, Any] = {
      "outlier_count": len(outliers),
      "top_outliers": outliers,
      "primary_score_metric": "z_score",
      "fleet_wave": len(outliers) >= 10,
  }

  outcome_class = CommonMarkTriageFormatter.classify_hunt_outcome(reduced_data, anomaly_threshold)
  next_steps_md = CommonMarkTriageFormatter.build_agentic_next_steps(
      reduced_data=reduced_data,
      target_metric=clean_metric,
      statistical_model=model_label,
      anomaly_threshold=anomaly_threshold,
  )

  # 2. Optional 360° Radar Payload
  radar_payload: Optional[Dict[str, Any]] = None
  if radar_scores is not None:
    collector = EntityRadarCollector()
    if isinstance(radar_scores, str):
      normalized_scores_str = radar_scores.replace(":", "=")
      spokes = EntityRadarCollector.parse_scores_argument(normalized_scores_str, entity_type=ent_enum.value)
    else:
      pairs_str = ",".join(f"{k}={v}" for k, v in radar_scores.items())
      spokes = EntityRadarCollector.parse_scores_argument(pairs_str, entity_type=ent_enum.value)
    target_ent = outliers[0]["entity"] if outliers else "target_entity"
    radar_payload = collector.build_radar_payload(
        entity_id=target_ent,
        entity_type=ent_enum.value,
        spokes=spokes,
    )
    radar_payload["composite_risk_distance"] = radar_payload["composite_distance_d"]
    radar_payload["composite_cri"] = radar_payload["calibrated_risk_index"]
    radar_payload["severity_band"] = _cri_band_metadata(radar_payload["calibrated_risk_index"])[0]

  # 3. Optional Mode B / Mode C Timeline Assembly
  timeline_markdown = ""
  has_timeline_rows = any(r.get("day") or r.get("ws") or r.get("window_start") for r in outliers)
  if mode_clean in ("B", "C") or has_timeline_rows:
    assembler = TimelineAssembler(entity_field="entity", score_field="z_score")
    if mode_clean == "C" and isinstance(rows, (list, tuple)) and rows and isinstance(rows[0], (list, tuple)):
      for day_str, shard_payload in rows:
        shard_rows, _ = _extract_and_normalize_rows(shard_payload)
        assembler.add_shard(day_str, shard_rows)
      summary = assembler.build()
      timeline_markdown = TimelineAssembler.render_markdown(summary)
    elif outliers:
      by_day: Dict[str, List[Dict[str, Any]]] = {}
      base_day = datetime.date.today()
      for idx, r in enumerate(outliers):
        d_str = str(r.get("day") or (base_day - datetime.timedelta(days=idx)).isoformat())
        by_day.setdefault(d_str, []).append(r)
      for d_str, d_rows in sorted(by_day.items()):
        try:
          assembler.add_shard(d_str, d_rows)
        except ValueError:
          pass
      if assembler.shards:
        summary = assembler.build()
        timeline_markdown = TimelineAssembler.render_markdown(summary)

  # 4. Generate Charts (SVG, Vega-Lite Spec, Self-Contained Interactive HTML)
  ranked_entities_for_chart = [
      {
          "entity": r["entity"],
          "threat_distance_d": r["z_score"],
          "z_score": r["z_score"],
          "cri": r["cri"],
          "observed": r["observed"],
          "baseline_mean": r["hist_avg"],
          "status": r["cri_badge"],
      }
      for r in outliers[:15]
  ]
  if outliers:
    vega_spec = RiskMetricsChartGenerator.generate_dual_y_outlier_chart(
        outlier_records=ranked_entities_for_chart,
        target_metric=f"metrics.{clean_metric}",
        score_field="z_score",
        threshold_val=anomaly_threshold,
        title=f"Ranked Behavioral Outliers: {clean_metric} ({model_label})",
    )
    chart_html = EntityRadarCollector.generate_ranked_fleet_html(
        ranked_entities=ranked_entities_for_chart,
        title=f"Statistical Outlier Report: {clean_metric} ({model_label})",
        threshold_sigma=anomaly_threshold,
    )
  else:
    vega_spec = RiskMetricsChartGenerator.generate_ranked_fleet_outlier_chart(
        ranked_records=[],
        score_field="threat_distance_d",
        threshold_val=anomaly_threshold,
        title=f"Nominal Baseline: {clean_metric} (0 Outliers)",
    )
    chart_html = EntityRadarCollector.generate_ranked_fleet_html(
        ranked_entities=[],
        title=f"Nominal Baseline: {clean_metric} (0 Outliers)",
        threshold_sigma=anomaly_threshold,
    )
  svg_match = re.search(r"(<svg\b.*?</svg>)", chart_html, flags=re.DOTALL)
  chart_svg = svg_match.group(1) if svg_match else "<svg></svg>"

  embed_tag = ""
  resolved_html_path: Optional[str] = None
  if output_html_path:
    out_path = Path(output_html_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(chart_html, encoding="utf-8")
    svg_companion = out_path.with_suffix(".svg")
    svg_companion.write_text(chart_svg, encoding="utf-8")
    resolved_html_path = str(out_path)
    embed_tag = f'<agent-embed src="file://{resolved_html_path}"></agent-embed>'

  # 5. Handle Zero-Row Clean Hunt vs Populated 6-Section Dossier
  eval_mode_str = f"Mode {mode_clean}"
  clean_hunt_md = CommonMarkTriageFormatter.format_clean_hunt_report(
      target_metric=clean_metric,
      statistical_model=model_label,
      executed_query=executed_query,
      anomaly_threshold=anomaly_threshold,
      evaluation_mode=eval_mode_str,
  )

  # Resolve UDM pivot filter for Pillar 5
  if clean_metric in METRIC_CATALOG:
    sem = mc.baseline_semantics(clean_metric)
    pivot_filters = list(sem.observed_filter)
    target_field = METRIC_CATALOG[clean_metric].dimension_fields.get(
        ent_enum,
        "principal.user.userid" if ent_enum == EntityType.USER else "principal.asset.hostname",
    )
  else:
    pivot_filters = ['metadata.event_type = "USER_LOGIN"']
    target_field = "principal.user.userid" if ent_enum == EntityType.USER else "principal.asset.hostname"

  top_entity = outliers[0]["entity"] if outliers else ("target_user" if ent_enum == EntityType.USER else "target_host")
  ui_pivot_query = " AND ".join(pivot_filters + [f'{target_field} = "{top_entity}"'])
  bridge_pivot_query = f'{target_field} in %ueba_hunt_bridge.entity'
  mitre_recon_note = (
      " (MITRE TA0043 Reconnaissance / T1595 Active Scanning & Directory Probing)"
      if clean_metric in ("http_queries_fail", "dns_queries_fail")
      else ""
  )

  if not outliers and radar_payload is None:
    # Build 6-section zero-row dossier that preserves both Clean Hunt markers and all 6 section headers
    dossier_lines = [
        f"#### 1. Statistical Outlier Report: `{clean_metric}` ({model_label}){mitre_recon_note} (Nominal Baseline)",
        "",
        f"* **Result**: **0 observed events** (**0 ranked outlier entities**) exceeded the `{anomaly_threshold}σ` significance gate under **{eval_mode_str}** ($Z = 0.00\\sigma, D = 0.00\\sigma, \\text{{CRI}} = 0$, 🟢 **Nominal Fleet Baseline**).",
        "* **Baseline Horizon**: 30-Day Pre-Computed Behavioral Tables (`window: 30d`).",
        "* **Outcome Classification**: `CLEAN_OR_SUBTHRESHOLD`",
    ]
    if embed_tag:
      dossier_lines.extend(["", embed_tag])
    dossier_lines.extend([
        "",
        "---",
        "",
        "#### 2. Ranked Outlier Summary & Provenance Stamp",
        "",
        "* **Execution Provenance**: 0 outlier rows returned above significance threshold; 30-day `metrics.*` baseline evaluated cleanly.",
        "",
        "| Entity | Observed | 30d Mean (μ) | 30d StdDev (σ) | Z-Score | CRI Score (0–100) | Visual Magnitude |",
        "| :----- | :------- | :----------- | :------------- | :------ | :---------------- | :--------------- |",
        "| *(None — Nominal Baseline)* | `0` | `0.00` | `1.00` | `+0.00σ` | **`0`** (INFORMATIONAL) | `░░░░░░░░` |",
        "",
        "---",
        "",
        "#### 3. Forensic Vector Breakdown & Impact Analysis",
        "",
        "> [!IMPORTANT]",
        f"> **Nominal Baseline Verification: `{clean_metric}` ({model_label}){mitre_recon_note}**",
        f"> * **The Core Finding**: No entities breached the `{anomaly_threshold}σ` gate during the active evaluation window.",
        next_steps_md,
        "",
        "---",
        "",
        "#### 4. Chronicle UI Manual Pivot (Triage Reference Only)",
        "",
        "> [!NOTE]",
        "> **Manual Chronicle UI Web Pivot** (Enable **Case Sensitivity On** when running `metrics.*` queries in Chronicle Search UI):",
        f"> `{ui_pivot_query}`",
        f"> **Cross-Stage Data Table Bridge Filter**: `{bridge_pivot_query}`",
        "",
        "---",
        "",
        "#### 5. Collapsible Technical Appendix (Statistical & Mathematical Appendix)",
        "<details open>",
        "<summary>🔬 <b>Statistical & Mathematical Appendix (Technical Details)</b></summary>",
        "",
        f"* **Model Formulation**: `{model_label}` over 30-day behavioral baseline (`period: 1d, window: 30d`).",
        "* **Degrees of Freedom ($N$)**: 30 daily observation buckets.",
        "",
        "$$",
        r"\text{CRI}(S) = \text{clamp}\left(\text{round}\left(\frac{100}{1 + \exp(-0.6 \cdot (S - 3.0))}\right),\, 0,\, 100\right)",
        "$$",
        "",
        "</details>",
    ])
    dossier_md = "\n".join(dossier_lines)
    return {
        "status": "RENDERED",
        "is_zero_row": True,
        "outcome_classification": outcome_class,
        "outlier_count": 0,
        "outliers": [],
        "dossier_markdown": dossier_md,
        "markdown": dossier_md,
        "clean_hunt_markdown": clean_hunt_md,
        "timeline_markdown": timeline_markdown,
        "radar_payload": radar_payload,
        "chart_svg": chart_svg,
        "chart_html": chart_html,
        "vega_lite_spec": vega_spec,
        "embed_tag": embed_tag,
        "output_html_path": resolved_html_path,
        "audit_result": audit_result,
    }

  # 6. Populated 5-Section Dossier
  sparse_callout = None
  min_days_seen = min((r.get("active_days", 30) for r in outliers), default=30)
  if min_days_seen < 7:
    sparse_callout = (
        "> [!WARNING]\n"
        f"> **⚠️ Sparse Baseline Caution (Minimum Active Days $N = {min_days_seen} < 7$)**:\n"
        "> One or more ranked entities have fewer than 7 active baseline days in the 30-day window. "
        "Consider Empirical Bayes shrinkage (`EMPIRICAL_BAYES_3STAGE`) or `TWO_PART_HURDLE`."
    )

  table_lines = [
      "| Entity | Observed | 30d Mean (μ) | 30d StdDev (σ) | Z-Score | CRI Score (0–100) | Visual Magnitude |",
      "| :----- | :------- | :----------- | :------------- | :------ | :---------------- | :--------------- |",
  ]
  for r in outliers:
    table_lines.append(
        f"| `{r['entity']}` | `{r['observed']}` | `{r['hist_avg']}` | `{r['hist_stddev']}` | "
        f"`+{r['z_score']:.2f}σ` | **`{r['cri']}`** ({r['cri_badge']}) | `{r['visual_bar']}` |"
    )

  projected_cols = sorted(list(outliers[0].keys())) if outliers else []
  provenance_line = (
      f"* **Execution Provenance**: `{len(outliers)}` ranked outlier record(s) | "
      f"Evaluation Mode: `{eval_mode_str}` | Outcome Class: `{outcome_class}` | "
      f"Projected Schema Columns: `{', '.join(projected_cols[:8])}`"
  )

  dossier_sections = [
      f"#### 1. Statistical Outlier Report: `{clean_metric}` ({model_label})",
      "",
      "> [!NOTE]",
      "> **📊 Engine: Google SecOps UEBA & Risk Analytics (`window: 30d`)**",
      f"> • **Outcome Classification**: `{outcome_class}` ({len(outliers)} entity/entities exceeded `{anomaly_threshold}σ`)",
      f"> • **Evaluation Mode**: `{eval_mode_str}`",
      "> • **Baseline Horizon**: 30-Day Pre-Computed Behavioral Tables (`period: 1d, window: 30d`)",
  ]
  if sparse_callout:
    dossier_sections.extend(["", sparse_callout])
  if embed_tag:
    dossier_sections.extend(["", embed_tag])

  dossier_sections.extend([
      "",
      "---",
      "",
      "#### 2. Ranked Outlier Summary & Provenance Stamp",
      "",
      provenance_line,
      "",
      *table_lines,
      "",
      "> [!TIP]",
      "> **🎯 Calibrated Risk Index (CRI, 0–100 Scale) Interpretation Guide**:",
      "> • **CRI 90–100 (🚨 Critical Outlier / `CRITICAL`)**: Extreme surge ($S \\ge 6.7\\sigma$). Immediate IR escalation.",
      "> • **CRI 70–89 (🔴 High Threat / `HIGH`)**: Severe multi-sigma breakout ($4.4\\sigma \\le S < 6.7\\sigma$). Prioritize SOC triage.",
      "> • **CRI 46–69 (🟠 Medium Outlier / `MEDIUM`)**: Statistical anomaly spanning the $3.0\\sigma$ anchor ($\\text{CRI}(3.0\\sigma) = 50$).",
      "> • **CRI 26–45 (🟡 Low Drift / `LOW`)**: Moderate elevation ($1.2\\sigma \\le S < 2.7\\sigma$). Track via Longitudinal CUSUM.",
      "> • **CRI 0–25 (🟢 Nominal / `INFORMATIONAL`)**: Expected baseline variance ($S < 1.2\\sigma$).",
  ])

  if timeline_markdown:
    dossier_sections.extend(["", "##### 📅 Multi-Day Timeline Breakdown", "", timeline_markdown])

  if radar_payload:
    dossier_sections.extend([
        "",
        "##### 🕸️ 360° Multi-Sector Behavioral Risk Radar Summary",
        "",
        f"* **Composite Multi-Sector Threat Distance ($D$)**: `{radar_payload['composite_risk_distance']}σ` "
        f"(CRI: **`{radar_payload['composite_cri']}`** — `{radar_payload['severity_band']}`)",
    ])

  dossier_sections.extend([
      "",
      "---",
      "",
      "#### 3. Forensic Vector Breakdown & Impact Analysis",
      "",
      "> [!IMPORTANT]",
      f"> **Threat Translation & Attack Scenarios: `{clean_metric}` ({model_label}){mitre_recon_note}**",
      f"> * **The Core Finding**: Top entity `{top_entity}` registered `+{outliers[0]['z_score']:.2f}σ` (`CRI = {outliers[0]['cri']}`, {outliers[0]['cri_band_label']}) against its 30-day behavioral baseline (`μ = {outliers[0]['hist_avg']}`, `σ = {outliers[0]['hist_stddev']}`).",
      "> * **Security Significance**: Statistically significant departure from historical entity behavior indicating potential credential compromise, automated staging, or anomalous data movement.",
      "> * **Potential Attack Scenarios**: Credential stuffing, lateral expansion, living-off-the-land execution, or staged exfiltration.",
      "> * **Legitimate False Positives**: Scheduled enterprise backups, administrative batch jobs, or fleet patch rollouts.",
      "> * **SOC Action Playbook**: 1. Verify entity identity & change tickets, 2. Inspect companion process/network stages, 3. Pivot via Agentic Next Steps below.",
      next_steps_md,
      "",
      "---",
      "",
      "#### 4. Chronicle UI Manual Pivot (Triage Reference Only)",
      "",
      "> [!NOTE]",
      "> **Manual Chronicle UI Web Pivot** (Copy & paste into Chronicle Search UI for raw event timeline inspection; enable **Case Sensitivity On** when running `metrics.*` queries):",
      f"> `{ui_pivot_query}`",
      f"> **Cross-Stage Data Table Bridge Filter**: `{bridge_pivot_query}`",
      "",
      "---",
      "",
      "#### 5. Collapsible Technical Appendix (Statistical & Mathematical Appendix)",
      "<details open>",
      "<summary>🔬 <b>Statistical & Mathematical Appendix (Technical Details)</b></summary>",
      "",
      "##### 📐 Mathematical Formulations & Parameter Derivations",
      f"* **Model Formulation**: `{model_label}`",
      "* **Degrees of Freedom ($N$)**: 30 daily observation periods (`period: 1d, window: 30d`).",
      "* **Multi-Sector Rectified Threat Norm ($D$)**:",
      "",
      "$$",
      r"D = \sqrt{\sum_{i=1}^{K} \max(0, Z_i)^2}",
      "$$",
      "",
      "* **Calibrated Risk Index (Piecewise Sigmoid Mapping)**:",
      "",
      "$$",
      r"\text{CRI}(S) = \text{clamp}\left(\text{round}\left(\frac{100}{1 + \exp(-0.6 \cdot (S - 3.0))}\right),\, 0,\, 100\right)",
      "$$",
      "",
      "</details>",
  ])

  dossier_md = "\n".join(dossier_sections)
  legacy_report_md = CommonMarkTriageFormatter.format_report(
      reduced_data=reduced_data,
      target_metric=clean_metric,
      statistical_model=model_label,
      anomaly_threshold=anomaly_threshold,
      executed_query=executed_query,
      audit_result=audit_result,
      sparse_callout=sparse_callout,
  )

  return {
      "status": "RENDERED",
      "is_zero_row": False,
      "outcome_classification": outcome_class,
      "outlier_count": len(outliers),
      "outliers": outliers,
      "dossier_markdown": dossier_md,
      "markdown": dossier_md,
      "triage_report_markdown": legacy_report_md,
      "clean_hunt_markdown": clean_hunt_md,
      "timeline_markdown": timeline_markdown,
      "radar_payload": radar_payload,
      "chart_svg": chart_svg,
      "chart_html": chart_html,
      "vega_lite_spec": vega_spec,
      "embed_tag": embed_tag,
      "output_html_path": resolved_html_path,
      "audit_result": audit_result,
  }


# ---------------------------------------------------------------------------
# Catalog Inspection Helper: get_metric_catalog_summary
# ---------------------------------------------------------------------------


def get_metric_catalog_summary(
    sector: Optional[str] = None,
    entity_type: Optional[str] = None,
) -> Dict[str, Any]:
  """Returns a structured dictionary of all 38 Malachite UEBA metrics, triads, models, and intents."""
  ent_filter = resolve_entity_type(entity_type) if entity_type else None
  sector_filter = (sector or "").strip().lower()

  metrics_out: Dict[str, Any] = {}
  for m_name in sorted(METRIC_CATALOG.keys()):
    m_def = METRIC_CATALOG[m_name]
    if ent_filter and ent_filter not in m_def.supported_entity_types:
      continue
    if sector_filter and sector_filter not in m_name.lower() and sector_filter not in m_def.event_type.lower():
      continue
    sem = mc.baseline_semantics(m_name)
    metrics_out[m_name] = {
        "metric_id": m_def.metric_id,
        "metric_name": m_name,
        "event_type": m_def.event_type,
        "event_label": sem.event_label,
        "observed_filter": list(sem.observed_filter),
        "observed_agg": sem.observed_agg,
        "metric_arg": sem.metric_arg,
        "supported_entity_types": [e.value for e in m_def.supported_entity_types],
        "dimension_fields": {e.value: f for e, f in m_def.dimension_fields.items()},
        "is_composite_only": mc.is_composite_only(m_name),
        "default_floor_days": m_def.default_floor_days,
        "description": m_def.description,
    }

  return {
      "total_metrics": len(metrics_out),
      "metrics": metrics_out,
      "canonical_triads": {k: list(v) for k, v in mc.CANONICAL_TRIADS},
      "statistical_models": [m.value for m in StatisticalModel],
      "pipeline_architectures": [p.value for p in PipelineArchitecture],
      "killchain_archetypes": [k.value for k in KillChainArchetype],
      "chained_hunt_paths": list(ChainedHuntRouter.CROSS_ENTITY_PATHS),
      "handoff_intents": list(SUPPORTED_INTENTS),
  }


# ---------------------------------------------------------------------------
# Object-Oriented Wrapper: UEBAHybridEngine
# ---------------------------------------------------------------------------


class UEBAHybridEngine:
  """Object-oriented facade over compile_hunt_pipeline, dispatch_hybrid_handoff, and render_forensic_dossier."""

  compile_hunt_pipeline = staticmethod(compile_hunt_pipeline)
  dispatch_hybrid_handoff = staticmethod(dispatch_hybrid_handoff)
  render_forensic_dossier = staticmethod(render_forensic_dossier)
  get_metric_catalog_summary = staticmethod(get_metric_catalog_summary)


# ---------------------------------------------------------------------------
# Command-Line Interface (CLI)
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
      prog="ueba_hybrid_engine",
      description="Unified Python Hybrid Engine for Google SecOps Multi-Stage UEBA & Statistical Threat Hunting",
  )
  subparsers = parser.add_subparsers(dest="subcommand", required=True)

  # 1. compile subcommand
  p_compile = subparsers.add_parser("compile", help="Compile a multi-stage YARA-L 2.0 hunt pipeline")
  p_compile.add_argument("--model", "--statistical-model", dest="statistical_model", default="STANDARD_Z_SCORE")
  p_compile.add_argument("--metrics", "--metric", dest="metrics", default=None, help="Comma-separated metric name(s)")
  p_compile.add_argument("--architecture", default="single_metric")
  p_compile.add_argument("--plane", default="MACRO_METRICS", choices=["MACRO_METRICS", "MICRO_RAW", "HYBRID"])
  p_compile.add_argument("--entity-type", dest="entity_type", default="USER")
  p_compile.add_argument("--entity-value", "--entity", dest="entity_value", default=None)
  p_compile.add_argument("--custom-filter", dest="custom_filter", default=None)
  p_compile.add_argument("--mode", default="A", choices=["A", "B", "C", "D"])
  p_compile.add_argument("--window-days", dest="window_days", type=int, default=1)
  p_compile.add_argument("--sensitivity", default="BALANCED")
  p_compile.add_argument("--threshold", dest="anomaly_threshold", type=float, default=None)
  p_compile.add_argument("--min-baseline-days", dest="min_baseline_days", type=int, default=None)
  p_compile.add_argument("--goal", dest="hypothesis_goal", default=None)
  p_compile.add_argument("--identifier-field", dest="identifier_field", default=None)
  p_compile.add_argument("--cohort", dest="cohort_entities", default=None, help="Comma-separated cohort entity IDs")
  p_compile.add_argument("--service-account", dest="service_account", default=None)
  p_compile.add_argument("--killchain", dest="killchain_archetype", default=None)
  p_compile.add_argument("--chained-path", dest="chained_path", default=None)
  p_compile.add_argument("--format", choices=["json", "query", "markdown"], default="json")

  # 2. handoff subcommand
  p_handoff = subparsers.add_parser("handoff", help="Dispatch a federated handoff to secops-statistical-hunter")
  p_handoff.add_argument("--intent", default="SCHEDULED_EXFILTRATION_TIMING")
  p_handoff.add_argument("--entity-value", "--entity", dest="entity_value", required=True)
  p_handoff.add_argument("--entity-type", dest="entity_type", default="HOSTNAME")
  p_handoff.add_argument("--lookback", default="24h")
  p_handoff.add_argument("--sensitivity", default="BALANCED")
  p_handoff.add_argument("--justification", default=None)
  p_handoff.add_argument("--macro-context", dest="macro_context", default=None, help="JSON string of Phase 1 macro context")
  p_handoff.add_argument("--turn1-only", dest="turn1_demarcation_only", action="store_true")
  p_handoff.add_argument("--format", choices=["json", "card", "query"], default="json")

  # 3. render subcommand
  p_render = subparsers.add_parser("render", help="Render a 6-Pillar Forensic Triage Dossier and SVG/HTML chart")
  p_render.add_argument("--rows", default="[]", help="JSON string or path to JSON file containing stats rows")
  p_render.add_argument("--query", "--executed-query", dest="executed_query", default=None)
  p_render.add_argument("--model", "--statistical-model", dest="statistical_model", default="STANDARD_Z_SCORE")
  p_render.add_argument("--metric", "--metric-name", dest="metric_name", default="auth_attempts_total")
  p_render.add_argument("--entity-type", dest="entity_type", default="USER")
  p_render.add_argument("--mode", default="A")
  p_render.add_argument("--window-days", dest="window_days", type=int, default=14)
  p_render.add_argument("--threshold", dest="anomaly_threshold", type=float, default=3.0)
  p_render.add_argument("--output-html", dest="output_html_path", default=None)
  p_render.add_argument("--radar-scores", dest="radar_scores", default=None)
  p_render.add_argument("--format", choices=["markdown", "json"], default="markdown")

  # 4. catalog subcommand
  p_catalog = subparsers.add_parser("catalog", help="Inspect the 38-metric Malachite UEBA catalog and models")
  p_catalog.add_argument("--sector", default=None)
  p_catalog.add_argument("--entity-type", dest="entity_type", default=None)

  return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
  parser = _build_arg_parser()
  args = parser.parse_args(argv)

  if args.subcommand == "compile":
    cohort = [c.strip() for c in args.cohort_entities.split(",") if c.strip()] if args.cohort_entities else None
    res = compile_hunt_pipeline(
        statistical_model=args.statistical_model,
        metrics=args.metrics,
        architecture=args.architecture,
        plane=args.plane,
        entity_type=args.entity_type,
        entity_value=args.entity_value,
        custom_filter=args.custom_filter,
        mode=args.mode,
        window_days=args.window_days,
        sensitivity=args.sensitivity,
        anomaly_threshold=args.anomaly_threshold,
        min_baseline_days=args.min_baseline_days,
        hypothesis_goal=args.hypothesis_goal,
        identifier_field=args.identifier_field,
        cohort_entities=cohort,
        service_account=args.service_account,
        killchain_archetype=args.killchain_archetype,
        chained_path=args.chained_path,
    )
    if args.format == "query":
      print(res["compiled_query"])
    elif args.format == "markdown":
      print(res["preflight_card_markdown"])
    else:
      print(json.dumps(res, indent=2, default=str))
    return 0 if res["ast_valid"] else 1

  if args.subcommand == "handoff":
    macro_ctx = json.loads(args.macro_context) if args.macro_context else None
    res = dispatch_hybrid_handoff(
        intent=args.intent,
        entity_value=args.entity_value,
        entity_type=args.entity_type,
        lookback=args.lookback,
        sensitivity=args.sensitivity,
        justification=args.justification,
        macro_context=macro_ctx,
        turn1_demarcation_only=args.turn1_demarcation_only,
    )
    if args.format == "card":
      print(res["handoff_card_markdown"])
    elif args.format == "query":
      print(res["compiled_query"])
    else:
      print(json.dumps(res, indent=2, default=str))
    return 0

  if args.subcommand == "render":
    rows_arg = args.rows
    if rows_arg and Path(rows_arg).exists():
      rows_arg = Path(rows_arg).read_text(encoding="utf-8")
    exec_query = args.executed_query
    if not exec_query:
      compiled = compile_hunt_pipeline(
          statistical_model=args.statistical_model,
          metrics=args.metric_name,
          entity_type=args.entity_type,
          mode=args.mode,
          window_days=args.window_days,
      )
      exec_query = compiled["compiled_query"]

    res = render_forensic_dossier(
        rows=rows_arg,
        executed_query=exec_query,
        statistical_model=args.statistical_model,
        metric_name=args.metric_name,
        entity_type=args.entity_type,
        mode=args.mode,
        window_days=args.window_days,
        anomaly_threshold=args.anomaly_threshold,
        output_html_path=args.output_html_path,
        radar_scores=args.radar_scores,
    )
    if args.format == "markdown":
      print(res["dossier_markdown"])
    else:
      serializable = {k: v for k, v in res.items() if k != "audit_result"}
      print(json.dumps(serializable, indent=2, default=str))
    return 0

  if args.subcommand == "catalog":
    res = get_metric_catalog_summary(sector=args.sector, entity_type=args.entity_type)
    print(json.dumps(res, indent=2))
    return 0

  return 1


if __name__ == "__main__":
  sys.exit(main())
