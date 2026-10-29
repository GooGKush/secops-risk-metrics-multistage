"""360-Degree Entity Behavioral Risk Radar Collector & Visualizer for Google SecOps.

Author: Greg Kushmerek
Specification: 360 Entity Behavioral Risk Fingerprint & Playbook Hook
"""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
import hashlib
import html
import json
import math
import os
import sys
from typing import Any, Dict, List, Optional, Tuple


HELPER_VERSION = "2.3.0"


def _canonical_json_sha256(obj: Any) -> str:
  """Computes deterministic SHA-256 hex digest over canonical UTF-8 JSON."""
  canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
  return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _decode_chronicle_cell(cell: Any) -> Any:
  """Decodes a single Chronicle udm_search stats.results cell dict, failing closed on malformed cells."""
  if not isinstance(cell, dict):
    raise ValueError(
        "G1/G2 violation: malformed cell in udm_search stats.results; expected dict."
    )
  if not cell:
    return None
  if "value" not in cell or not isinstance(cell["value"], dict):
    raise ValueError(
        "G1/G2 violation: malformed cell in udm_search stats.results; expected {'value': {...}} envelope."
    )
  value = cell["value"]
  if not value:
    return None
  kind, raw = next(iter(value.items()))
  if kind in ("int64Val", "uint64Val"):
    return int(raw)
  if kind == "doubleVal":
    return float(raw)
  if kind == "boolVal":
    return bool(raw)
  if kind == "list" and isinstance(raw, dict):
    return [_decode_chronicle_cell({"value": v}) for v in raw.get("values", [])]
  return raw


def _parse_strict_udm_stats_payload(sector_key: str, raw_payload: Any) -> List[Dict[str, Any]]:
  """Strictly validates and parses a raw udm_search stats payload per D6 Guardrails G1 and G2."""
  if isinstance(raw_payload, bool) or not isinstance(raw_payload, dict):
    raise ValueError(
        "G1 violation: sector payload must be a raw udm_search response dict containing 'stats' "
        "(or empty {} for 0-row sector), not LLM-typed numbers."
    )
  if not raw_payload:
    return []
  if "events" in raw_payload and "stats" not in raw_payload:
    raise ValueError(
        f"G1 violation (RAW_LOG_DUMP_DETECTED): sector '{sector_key}' payload contains raw "
        "unaggregated 'events' without 'stats'."
    )
  if "stats" not in raw_payload:
    raise ValueError(
        "G1 violation: sector payload must be a raw udm_search response dict containing 'stats' "
        "(or empty {} for 0-row sector), not LLM-typed numbers or hand-typed dicts."
    )
  stats_obj = raw_payload["stats"]
  if stats_obj is None or stats_obj == {} or stats_obj == []:
    return []
  if not isinstance(stats_obj, dict):
    raise ValueError(
        f"G1/G2 violation: sector '{sector_key}' 'stats' must be a dict, got {type(stats_obj).__name__}."
    )
  if "results" not in stats_obj:
    raise ValueError(
        f"G1/G2 violation: sector '{sector_key}' non-empty 'stats' dict is missing 'results'."
    )
  results = stats_obj["results"]
  if results is None or results == []:
    return []
  if not isinstance(results, list):
    raise ValueError(
        f"G1/G2 violation: sector '{sector_key}' 'stats.results' must be a list."
    )
  columns: Dict[str, List[Any]] = {}
  for col in results:
    if (
        not isinstance(col, dict)
        or not isinstance(col.get("column"), str)
        or not col["column"].strip()
        or not isinstance(col.get("values"), list)
    ):
      raise ValueError(
          f"G1/G2 violation: malformed stats.results column entry in sector '{sector_key}'; "
          "expected Chronicle columnar {'column': str, 'values': [...]} structure."
      )
    col_name = col["column"].strip().lstrip("$")
    columns[col_name] = [_decode_chronicle_cell(cell) for cell in col["values"]]

  n_rows = max((len(vals) for vals in columns.values()), default=0)
  rows: List[Dict[str, Any]] = []
  for i in range(n_rows):
    rows.append({name: (vals[i] if i < len(vals) else None) for name, vals in columns.items()})
  return rows


def _extract_spoke_metrics_from_rows(
    sector_key: str,
    rows: List[Dict[str, Any]],
) -> Tuple[float, float, float, float]:
  """Extracts (observed, baseline_mean, baseline_stddev, z_score) from parsed stats.results rows."""
  primary_z_cols = (
      "personal_z",
      "z_score",
      "z",
      "alert_z",
      "z_alerts",
      "process_z",
      "fail_z",
      "flow_z",
      "macro_z_score",
      "macro_z",
  )
  excluded_z_suffixes = ("_sq", "_raw", "_pos", "_rw", "_cd", "_gap")
  prefix_aliases = {
      "download": ("dl", "download"),
      "change": ("ch", "change"),
      "outbound": ("out", "outbound"),
      "inbound": ("in", "inbound"),
      "egress": ("bytes", "egress"),
      "dns_fail": ("dns", "dns_fail"),
      "http": ("http", "web"),
      "alerts": ("alerts", "alert"),
  }

  def _as_float(val: Any) -> Optional[float]:
    if isinstance(val, list) and val:
      val = val[0]
    if val is None or isinstance(val, bool):
      return None
    try:
      return float(val)
    except (TypeError, ValueError):
      return None

  def _first_present(row: Dict[str, Any], candidates: Tuple[str, ...]) -> Optional[float]:
    for key in candidates:
      if key in row:
        num = _as_float(row[key])
        if num is not None:
          return num
    return None

  best_tuple: Optional[Tuple[float, float, float, float]] = None
  for row in rows:
    winning_prefix: Optional[str] = None
    z_val = _first_present(row, primary_z_cols)
    if z_val is None:
      z_candidates: List[Tuple[float, str]] = []
      for k, raw_v in row.items():
        kl = k.lower()
        if any(kl.endswith(sfx) for sfx in excluded_z_suffixes):
          continue
        if kl.startswith("z_"):
          fv = _as_float(raw_v)
          if fv is not None:
            z_candidates.append((fv, kl[2:]))
        elif kl.endswith("_z"):
          fv = _as_float(raw_v)
          if fv is not None:
            z_candidates.append((fv, kl[:-2]))
      if z_candidates:
        z_candidates.sort(key=lambda item: item[0], reverse=True)
        z_val, winning_prefix = z_candidates[0]

    pref_tokens: Tuple[str, ...] = ()
    if winning_prefix:
      pref_tokens = prefix_aliases.get(winning_prefix, (winning_prefix,))

    obs_candidates = (
        "observed",
        "observed_val",
        "observed_24h",
        "obs",
        "today_val",
        "total_obs",
        "alerts_obs",
    ) + tuple(f"{p}_obs" for p in pref_tokens)
    obs_val = _first_present(row, obs_candidates)
    if obs_val is None:
      for k, raw_v in row.items():
        if k.lower().endswith("_obs"):
          obs_val = _as_float(raw_v)
          if obs_val is not None:
            break

    avg_candidates = (
        "historical_avg",
        "hist_avg",
        "baseline",
        "baseline_mean",
        "avg_30d",
        "mu",
        "hist_mean",
        "historical_mean",
        "d_mu",
        "avg",
        "alerts_avg",
    ) + tuple(f"{p}_avg" for p in pref_tokens)
    avg_val = _first_present(row, avg_candidates)
    if avg_val is None:
      for k, raw_v in row.items():
        if k.lower().endswith(("_avg", "_mean")):
          avg_val = _as_float(raw_v)
          if avg_val is not None:
            break

    std_candidates = (
        "historical_stddev",
        "hist_stddev",
        "dispersion",
        "baseline_stddev",
        "stddev_30d",
        "sigma",
        "hist_std",
        "historical_std",
        "d_sigma",
        "stddev",
        "std",
        "alerts_std",
    ) + tuple(f"{p}_std" for p in pref_tokens) + tuple(f"{p}_stddev" for p in pref_tokens)
    std_val = _first_present(row, std_candidates)
    if std_val is None:
      for k, raw_v in row.items():
        if k.lower().endswith(("_std", "_stddev")):
          std_val = _as_float(raw_v)
          if std_val is not None:
            break

    if z_val is None:
      if obs_val is not None and avg_val is not None:
        denom = std_val if (std_val is not None and std_val > 0.0) else 1.0
        z_val = (obs_val - avg_val) / denom
      else:
        continue

    candidate = (
        obs_val if obs_val is not None else 0.0,
        avg_val if avg_val is not None else 0.0,
        std_val if std_val is not None else 0.0,
        z_val,
    )
    if best_tuple is None or candidate[3] > best_tuple[3]:
      best_tuple = candidate

  if best_tuple is None:
    raise ValueError(
        f"G2 violation: sector '{sector_key}' stats.results contains {len(rows)} row(s) "
        "but no recognized Z-score or baseline metric columns."
    )
  return best_tuple


@dataclass
class MetricSpoke:
  """Represents a single radial spoke in the 360-degree risk radar."""
  sector: str
  spoke_name: str
  metric_table: str
  observed: float
  baseline_mean: float
  baseline_stddev: float
  z_score: float
  unit: str = "events"
  cri_score: int = 0

  def __post_init__(self):
    if self.cri_score == 0 and self.z_score is not None:
      self.cri_score = round(100.0 / (1.0 + math.exp(-0.6 * (max(0.0, self.z_score) - 3.0))))

  def to_dict(self) -> Dict[str, Any]:
    return asdict(self)


class EntityRadarCollector:
  """Collects multi-sector behavioral metrics for an entity and renders radial risk fingerprints."""

  HELPER_VERSION = HELPER_VERSION

  USER_SECTOR_QUERIES = {
      "IAM & Authentication": """
// Sector: IAM & Authentication
stage s1 {
    metadata.event_type = "USER_LOGIN"
    not security_result.action = "ALLOW"
    target.user.userid = "%(entity_id)s"
    $user = target.user.userid
  match:
    $user by 1d
  outcome:
    $fail_obs = count(metadata.id)
    $fail_avg = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: target.user.userid))
    $fail_std = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: target.user.userid))
}
stage s2 {
    metadata.event_type = "USER_LOGIN"
    security_result.action = "ALLOW"
    target.user.userid = "%(entity_id)s"
    $user = target.user.userid
  match:
    $user by 1d
  outcome:
    $succ_obs = count(metadata.id)
    $succ_avg = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: target.user.userid))
    $succ_std = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: target.user.userid))
}
$user = $s1.user
$user = $s2.user
match: $user by 1d
outcome:
  $fail_std = max($s1.fail_std)
  $succ_std = max($s2.succ_std)
  $z_fail = (max($s1.fail_obs) - max($s1.fail_avg)) / if($fail_std > 0, $fail_std, 1.0)
  $z_succ = (max($s2.succ_obs) - max($s2.succ_avg)) / if($succ_std > 0, $succ_std, 1.0)
""",
      "Cloud Infrastructure": """
// Sector: Cloud Infrastructure CRUD
stage s1 {
    (
        metadata.event_type = "RESOURCE_READ" or
        metadata.event_type = "USER_RESOURCE_ACCESS" or
        metadata.event_type = "RESOURCE_WRITTEN" or
        metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT" or
        metadata.event_type = "RESOURCE_CREATION" or
        metadata.event_type = "USER_RESOURCE_CREATION" or
        metadata.event_type = "RESOURCE_DELETION" or
        metadata.event_type = "USER_RESOURCE_DELETION"
    )
    principal.user.userid = "%(entity_id)s"
    $user = principal.user.userid
    metadata.vendor_name = $v
    metadata.product_name = $p
  match:
    $user, $v, $p by 1d
  outcome:
    $read_obs = sum(if(metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS", 1, 0))
    $read_avg = max(metrics.resource_read_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: principal.user.userid, metadata.vendor_name: metadata.vendor_name, metadata.product_name: metadata.product_name))
    $read_std = max(metrics.resource_read_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: principal.user.userid, metadata.vendor_name: metadata.vendor_name, metadata.product_name: metadata.product_name))
    $write_obs = sum(if(metadata.event_type = "RESOURCE_WRITTEN" or metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT", 1, 0))
    $write_avg = max(metrics.resource_written_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: principal.user.userid, metadata.vendor_name: metadata.vendor_name, metadata.product_name: metadata.product_name))
    $write_std = max(metrics.resource_written_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: principal.user.userid, metadata.vendor_name: metadata.vendor_name, metadata.product_name: metadata.product_name))
    $create_obs = sum(if(metadata.event_type = "RESOURCE_CREATION" or metadata.event_type = "USER_RESOURCE_CREATION", 1, 0))
    $create_avg = max(metrics.resource_creation_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: principal.user.userid, metadata.vendor_name: metadata.vendor_name, metadata.product_name: metadata.product_name))
    $create_std = max(metrics.resource_creation_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: principal.user.userid, metadata.vendor_name: metadata.vendor_name, metadata.product_name: metadata.product_name))
    $delete_obs = sum(if(metadata.event_type = "RESOURCE_DELETION" or metadata.event_type = "USER_RESOURCE_DELETION", 1, 0))
    $delete_avg = max(metrics.resource_deletion_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: principal.user.userid, metadata.vendor_name: metadata.vendor_name, metadata.product_name: metadata.product_name))
    $delete_std = max(metrics.resource_deletion_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: principal.user.userid, metadata.vendor_name: metadata.vendor_name, metadata.product_name: metadata.product_name))
}
$user = $s1.user
match: $user by 1d
outcome:
  $read_std = max($s1.read_std)
  $write_std = max($s1.write_std)
  $create_std = max($s1.create_std)
  $delete_std = max($s1.delete_std)
  $z_read = (max($s1.read_obs) - max($s1.read_avg)) / if($read_std > 0, $read_std, 1000000.0)
  $z_write = (max($s1.write_obs) - max($s1.write_avg)) / if($write_std > 0, $write_std, 1000000.0)
  $z_create = (max($s1.create_obs) - max($s1.create_avg)) / if($create_std > 0, $create_std, 1000000.0)
  $z_delete = (max($s1.delete_obs) - max($s1.delete_avg)) / if($delete_std > 0, $delete_std, 1000000.0)
  $z_rw = if($z_read >= $z_write, $z_read, $z_write)
  $z_cd = if($z_create >= $z_delete, $z_create, $z_delete)
  $z = if($z_rw >= $z_cd, $z_rw, $z_cd)
""",
      "Workspace Data Hoarding": """
// Sector: Workspace & Drive Data
stage s1 {
    metadata.vendor_name = "Google Workspace"
    principal.user.userid = "%(entity_id)s"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $dl_obs = sum(if(metadata.product_event_type = "download", 1, 0))
    $ch_obs = count(metadata.id)
    $dl_avg = max(metrics.workspace_total_download_actions(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: principal.user.userid))
    $dl_std = max(metrics.workspace_total_download_actions(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: principal.user.userid))
    $ch_avg = max(metrics.workspace_total_change_actions(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: principal.user.userid))
    $ch_std = max(metrics.workspace_total_change_actions(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: principal.user.userid))
}
$user = $s1.user
match: $user by 1d
outcome:
  $dl_std = max($s1.dl_std)
  $ch_std = max($s1.ch_std)
  $z_download = (max($s1.dl_obs) - max($s1.dl_avg)) / if($dl_std > 0, $dl_std, 1.0)
  $z_change = (max($s1.ch_obs) - max($s1.ch_avg)) / if($ch_std > 0, $ch_std, 1.0)
""",
      "Network Egress & Web": """
// Sector: Network Egress Volume
stage s1 {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.user.userid = "%(entity_id)s"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $bytes_obs = sum(network.sent_bytes)
    $bytes_avg = max(metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: avg, principal.user.userid: principal.user.userid))
    $bytes_std = max(metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: stddev, principal.user.userid: principal.user.userid))
}
$user = $s1.user
match: $user by 1d
outcome:
  $bytes_std = max($s1.bytes_std)
  $z_egress = (max($s1.bytes_obs) - max($s1.bytes_avg)) / if($bytes_std > 0, $bytes_std, 1.0)
""",
      "DNS Resolution": """
// Sector: DNS Failures
stage s1 {
    (network.dns.questions.name != "" or network.dns.answers.name != "" or network.dns.id != 0)
    network.dns.response_code != 0
    principal.user.userid = "%(entity_id)s"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $dns_obs = count(metadata.id)
    $dns_avg = max(metrics.dns_queries_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: principal.user.userid))
    $dns_std = max(metrics.dns_queries_fail(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: principal.user.userid))
}
$user = $s1.user
match: $user by 1d
outcome:
  $dns_std = max($s1.dns_std)
  $z_dns_fail = (max($s1.dns_obs) - max($s1.dns_avg)) / if($dns_std > 0, $dns_std, 1.0)
""",
      "Web & Proxy Activity": """
// Sector: Web & Proxy Activity
stage s1 {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    principal.user.userid = "%(entity_id)s"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $http_obs = count(metadata.id)
    $http_avg = max(metrics.http_queries_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: principal.user.userid))
    $http_std = max(metrics.http_queries_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: principal.user.userid))
}
$user = $s1.user
match: $user by 1d
outcome:
  $http_std = max($s1.http_std)
  $z_http = (max($s1.http_obs) - max($s1.http_avg)) / if($http_std > 0, $http_std, 1.0)
""",
  }

  ASSET_SECTOR_QUERIES = {
      "Authentication & Access": """
// Sector: Asset Authentication
stage s1 {
    metadata.event_type = "USER_LOGIN"
    not security_result.action = "ALLOW"
    principal.asset.hostname = "%(entity_id)s"
    $asset = principal.asset.hostname
  match:
    $asset by 1d
  outcome:
    $fail_obs = count(metadata.id)
    $fail_avg = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.asset.hostname: principal.asset.hostname))
    $fail_std = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.asset.hostname: principal.asset.hostname))
}
$asset = $s1.asset
match: $asset by 1d
outcome:
  $fail_std = max($s1.fail_std)
  $z_fail = (max($s1.fail_obs) - max($s1.fail_avg)) / if($fail_std > 0, $fail_std, 1.0)
""",
      "Network Traffic Volume": """
// Sector: Network Inbound & Outbound
stage s1 {
    ((network.sent_bytes > 0 and network.sent_bytes < 1000000000000000) or (network.received_bytes > 0 and network.received_bytes < 1000000000000000))
    principal.asset.hostname = "%(entity_id)s"
    $asset = principal.asset.hostname
  match:
    $asset by 1d
  outcome:
    $out_obs = sum(network.sent_bytes)
    $out_avg = max(metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: avg, principal.asset.hostname: principal.asset.hostname))
    $out_std = max(metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: stddev, principal.asset.hostname: principal.asset.hostname))
    $in_obs = sum(network.received_bytes)
    $in_avg = max(metrics.network_bytes_inbound(period: 1d, window: 30d, metric: value_sum, agg: avg, principal.asset.hostname: principal.asset.hostname))
    $in_std = max(metrics.network_bytes_inbound(period: 1d, window: 30d, metric: value_sum, agg: stddev, principal.asset.hostname: principal.asset.hostname))
}
$asset = $s1.asset
match: $asset by 1d
outcome:
  $out_std = max($s1.out_std)
  $in_std = max($s1.in_std)
  $z_outbound = (max($s1.out_obs) - max($s1.out_avg)) / if($out_std > 0, $out_std, 1.0)
  $z_inbound = (max($s1.in_obs) - max($s1.in_avg)) / if($in_std > 0, $in_std, 1.0)
""",
      "DNS Resolution": """
// Sector: DNS Failures
stage s1 {
    (network.dns.questions.name != "" or network.dns.answers.name != "" or network.dns.id != 0)
    network.dns.response_code != 0
    principal.asset.hostname = "%(entity_id)s"
    $asset = principal.asset.hostname
  match:
    $asset by 1d
  outcome:
    $dns_obs = count(metadata.id)
    $dns_avg = max(metrics.dns_queries_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.asset.hostname: principal.asset.hostname))
    $dns_std = max(metrics.dns_queries_fail(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.asset.hostname: principal.asset.hostname))
}
$asset = $s1.asset
match: $asset by 1d
outcome:
  $dns_std = max($s1.dns_std)
  $z_dns_fail = (max($s1.dns_obs) - max($s1.dns_avg)) / if($dns_std > 0, $dns_std, 1.0)
""",
      "Web & Proxy Activity": """
// Sector: Web & Proxy Activity
stage s1 {
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    principal.asset.hostname = "%(entity_id)s"
    $asset = principal.asset.hostname
  match:
    $asset by 1d
  outcome:
    $http_obs = count(metadata.id)
    $http_avg = max(metrics.http_queries_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.asset.hostname: principal.asset.hostname))
    $http_std = max(metrics.http_queries_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.asset.hostname: principal.asset.hostname))
}
$asset = $s1.asset
match: $asset by 1d
outcome:
  $http_std = max($s1.http_std)
  $z_http = (max($s1.http_obs) - max($s1.http_avg)) / if($http_std > 0, $http_std, 1.0)
""",
      "Security & EDR Alerts": """
// Sector: Security & EDR Alerts
stage alerts_risk {
    (metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS")
    principal.asset.hostname = "%(entity_id)s"
    security_result.rule_name = $rule_name
    $asset = principal.asset.hostname
    $rule_name != ""
  match:
    $asset, $rule_name by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.alert_event_name_count(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.asset.hostname: principal.asset.hostname, security_result.rule_name: security_result.rule_name))
    $std = max(metrics.alert_event_name_count(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.asset.hostname: principal.asset.hostname, security_result.rule_name: security_result.rule_name))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}
$asset = $alerts_risk.asset
match: $asset by 1d
outcome:
  $alerts_std = max($alerts_risk.std)
  $z_alerts = max($alerts_risk.z)
  $alerts_obs = max($alerts_risk.obs)
  $alerts_avg = max($alerts_risk.avg)
""",
  }

  def __init__(self, secops_client: Optional[Any] = None):
    self.client = secops_client

  @staticmethod
  def get_canonical_nominal_spokes(entity_type: str = "USER") -> List[MetricSpoke]:
    """Returns the canonical nominal spokes (Z=0.00σ) when data is omitted or baseline is nominal."""
    if entity_type.upper() == "ASSET":
      return [
          MetricSpoke("Authentication", "Authentication & Access", "metrics.auth_attempts_fail", 0.0, 0.0, 0.0, 0.0, "logins", 0),
          MetricSpoke("Network", "Network Traffic Volume", "metrics.network_bytes_outbound", 0.0, 0.0, 0.0, 0.0, "bytes", 0),
          MetricSpoke("DNS", "DNS Resolution", "metrics.dns_queries_fail", 0.0, 0.0, 0.0, 0.0, "queries", 0),
          MetricSpoke("Web & Proxy", "Web & Proxy Requests", "metrics.http_queries_total", 0.0, 0.0, 0.0, 0.0, "requests", 0),
          MetricSpoke("Security & EDR Alerts", "Security & EDR Alerts", "metrics.alert_event_name_count", 0.0, 0.0, 0.0, 0.0, "alerts", 0),
          MetricSpoke("Endpoint", "Endpoint Process Activity", "metrics.file_executions_total", 0.0, 0.0, 0.0, 0.0, "events", 0),
      ]
    return [
        MetricSpoke("IAM & Authentication", "Authentication Attempts", "metrics.auth_attempts_fail", 0.0, 0.0, 0.0, 0.0, "logins", 0),
        MetricSpoke("Cloud Infrastructure", "Cloud Resource CRUD", "metrics.resource_creation_total", 0.0, 0.0, 0.0, 0.0, "events", 0),
        MetricSpoke("Workspace Data", "Workspace & SaaS Exfil", "metrics.workspace_total_download_actions", 0.0, 0.0, 0.0, 0.0, "actions", 0),
        MetricSpoke("Network Egress", "Network Egress", "metrics.network_bytes_outbound", 0.0, 0.0, 0.0, 0.0, "bytes", 0),
        MetricSpoke("DNS Resolution", "DNS Resolution", "metrics.dns_queries_fail", 0.0, 0.0, 0.0, 0.0, "queries", 0),
        MetricSpoke("Web & Proxy Activity", "Web & Proxy Requests", "metrics.http_queries_total", 0.0, 0.0, 0.0, 0.0, "requests", 0),
    ]

  @classmethod
  def _resolve_sector_index(cls, sector_key: str, entity_type: str = "USER") -> int:
    """Resolves a sector label or alias to its canonical 6-spoke index, failing closed on unknown keys."""
    if not isinstance(sector_key, str) or not sector_key.strip():
      raise ValueError("G2 violation: sector key must be a non-empty string.")
    clean = sector_key.strip().lower()
    is_asset = entity_type.upper() == "ASSET"

    user_exact = {
        "iam & authentication": 0,
        "authentication": 0,
        "authentication & access": 0,
        "authentication attempts": 0,
        "iam": 0,
        "auth": 0,
        "login": 0,
        "cloud infrastructure": 1,
        "cloud infrastructure & iam crud": 1,
        "cloud resource crud": 1,
        "cloud": 1,
        "crud": 1,
        "resource": 1,
        "workspace data": 2,
        "workspace data hoarding": 2,
        "workspace & saas exfil": 2,
        "workspace": 2,
        "saas": 2,
        "drive": 2,
        "doc": 2,
        "network egress": 3,
        "network egress & web": 3,
        "network traffic volume": 3,
        "network": 3,
        "net": 3,
        "egress": 3,
        "bytes": 3,
        "dns resolution": 4,
        "dns": 4,
        "web & proxy activity": 5,
        "web & proxy": 5,
        "web & proxy requests": 5,
        "web": 5,
        "http": 5,
        "proxy": 5,
    }
    asset_exact = {
        "authentication": 0,
        "authentication & access": 0,
        "iam & authentication": 0,
        "authentication attempts": 0,
        "auth": 0,
        "iam": 0,
        "login": 0,
        "access": 0,
        "network": 1,
        "network traffic volume": 1,
        "network egress": 1,
        "network egress & web": 1,
        "net": 1,
        "traffic": 1,
        "egress": 1,
        "bytes": 1,
        "dns": 2,
        "dns resolution": 2,
        "web & proxy": 3,
        "web & proxy activity": 3,
        "web & proxy requests": 3,
        "web": 3,
        "http": 3,
        "proxy": 3,
        "security & edr alerts": 4,
        "alerts": 4,
        "alert": 4,
        "edr": 4,
        "cloud": 4,
        "cloud infrastructure": 4,
        "endpoint": 5,
        "endpoint process activity": 5,
        "workspace / endpoint activity": 5,
        "proc": 5,
        "process": 5,
        "file_executions": 5,
    }
    exact_map = asset_exact if is_asset else user_exact
    if clean in exact_map:
      return exact_map[clean]

    prefix_rules = (
        [
            (("auth", "iam", "login", "access"), 0),
            (("net", "egress", "traffic", "byte"), 1),
            (("dns",), 2),
            (("web", "http", "proxy"), 3),
            (("alert", "edr", "cloud", "infra", "crud"), 4),
            (("endpoint", "proc", "process", "exec"), 5),
        ]
        if is_asset
        else [
            (("auth", "iam", "login"), 0),
            (("cloud", "crud", "resource"), 1),
            (("workspace", "saas", "drive", "doc"), 2),
            (("net", "egress", "byte"), 3),
            (("dns",), 4),
            (("web", "http", "proxy"), 5),
        ]
    )
    for tokens, idx in prefix_rules:
      if any(tok in clean for tok in tokens):
        return idx

    raise ValueError(
        f"G2 violation: unrecognized radar sector key '{sector_key}' for entity_type='{entity_type}'."
    )

  @classmethod
  def parse_raw_sector_payloads(
      cls,
      sector_payloads: Dict[str, Any],
      entity_type: str = "USER",
      query_texts: Optional[Dict[str, str]] = None,
  ) -> Tuple[List[MetricSpoke], Dict[str, Any]]:
    """Parses raw udm_search stats responses per sector into MetricSpokes + D6-G3 provenance.

    Enforces D6 Guardrails:
    - G1: Rejects LLM-typed numbers/strings, hand-typed dicts without 'stats', and raw 'events' dumps.
    - G2: Fails closed on missing, empty, unknown, duplicate, or malformed sector inputs.
    - G3: Returns helper_version, payload_sha256, and query_sha256 provenance metadata.
    """
    if isinstance(sector_payloads, bool) or not isinstance(sector_payloads, dict):
      raise ValueError(
          "G1 violation: sector payload must be a raw udm_search response dict containing 'stats' "
          "(or empty {} for 0-row sector), not LLM-typed numbers or strings."
      )
    if not sector_payloads:
      raise ValueError(
          "G2 violation: sector_payloads cannot be empty; provide raw udm_search response dicts per sector."
      )
    if query_texts is not None and not isinstance(query_texts, dict):
      raise ValueError(
          "G2 violation: query_texts must be a dict mapping sector keys to YARA-L query strings."
      )

    canonical = cls.get_canonical_nominal_spokes(entity_type)
    seen_indices: Dict[int, str] = {}
    sectors_with_telemetry = 0

    for sector_key, raw_payload in sector_payloads.items():
      idx = cls._resolve_sector_index(sector_key, entity_type)
      if idx in seen_indices:
        raise ValueError(
            f"G2 violation: duplicate radar sector mapping between '{seen_indices[idx]}' and '{sector_key}'."
        )
      seen_indices[idx] = sector_key

      rows = _parse_strict_udm_stats_payload(sector_key, raw_payload)
      if not rows:
        # Valid 0-row raw udm_search payload ({} or {"stats": {}}) -> deterministic nominal 0.0
        canonical[idx].observed = 0.0
        canonical[idx].baseline_mean = 0.0
        canonical[idx].baseline_stddev = 0.0
        canonical[idx].z_score = 0.0
        canonical[idx].cri_score = 0
        continue

      sectors_with_telemetry += 1
      obs_val, avg_val, std_val, z_val = _extract_spoke_metrics_from_rows(sector_key, rows)
      canonical[idx].observed = obs_val
      canonical[idx].baseline_mean = avg_val
      canonical[idx].baseline_stddev = std_val
      canonical[idx].z_score = z_val
      canonical[idx].cri_score = 0
      canonical[idx].__post_init__()

    payload_sha256 = _canonical_json_sha256(sector_payloads)
    query_sha256 = _canonical_json_sha256(query_texts) if query_texts else "N/A"
    provenance = {
        "helper_version": cls.HELPER_VERSION,
        "payload_sha256": payload_sha256,
        "query_sha256": query_sha256,
        "sectors_evaluated": len(canonical),
        "sectors_with_telemetry": sectors_with_telemetry,
    }
    return canonical, provenance

  @staticmethod
  def calculate_composite_risk(spokes: List[MetricSpoke]) -> Tuple[float, int]:
    """Calculates the Euclidean Composite Distance D and Calibrated Risk Index (CRI)."""
    if not spokes:
      return 0.0, 0

    sum_z_sq = sum(max(0.0, s.z_score) ** 2 for s in spokes)
    composite_d = math.sqrt(sum_z_sq)
    cri_score = round(100.0 / (1.0 + math.exp(-0.6 * (composite_d - 3.0))))
    return round(composite_d, 2), max(0, min(100, cri_score))

  def build_radar_payload(
      self,
      entity_id: str,
      entity_type: str,
      spokes: List[MetricSpoke],
      provenance: Optional[Dict[str, Any]] = None,
  ) -> Dict[str, Any]:
    """Assembles the full radar payload including statistics, provenance, SVG, Markdown, and Chart.js specs."""
    active_spokes = spokes if spokes else self.get_canonical_nominal_spokes(entity_type)
    sorted_spokes = sorted(active_spokes, key=lambda s: s.z_score, reverse=True)
    composite_d, cri = self.calculate_composite_risk(sorted_spokes)

    top_outlier = sorted_spokes[0] if sorted_spokes else None
    is_anomalous = composite_d >= 3.0
    effective_provenance = (
        dict(provenance)
        if provenance is not None
        else {
            "helper_version": self.HELPER_VERSION,
            "payload_sha256": "N/A",
            "query_sha256": "N/A",
        }
    )

    return {
        "entity_id": entity_id,
        "entity_type": entity_type.upper(),
        "composite_distance_d": composite_d,
        "calibrated_risk_index": cri,
        "is_anomalous": is_anomalous,
        "spoke_count": len(sorted_spokes),
        "top_outlier_spoke": top_outlier.spoke_name if top_outlier else "N/A",
        "top_outlier_z": top_outlier.z_score if top_outlier else 0.0,
        "provenance": effective_provenance,
        "spokes": [s.to_dict() for s in sorted_spokes],
        "svg_widget": self.generate_self_contained_svg(
            entity_id, sorted_spokes, composite_d, cri
        ),
        "html_widget": self.generate_html_widget(
            entity_id, sorted_spokes, composite_d, cri
        ),
        "data_uri_image": self.generate_data_uri_image(
            entity_id, sorted_spokes, composite_d, cri
        ),
        "dual_surface_embed": self.generate_dual_surface_embed(
            entity_id, sorted_spokes, composite_d, cri
        ),
        "ascii_chart": self.generate_ascii_chart(
            entity_id, sorted_spokes, composite_d, cri
        ),
        "markdown_table": self.generate_markdown_summary(
            entity_id, sorted_spokes, composite_d, cri, provenance=effective_provenance
        ),
        "chartjs_spec": self.generate_chartjs_spec(
            entity_id, sorted_spokes, composite_d, cri
        ),
    }

  @staticmethod
  def generate_self_contained_svg(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
      width: int = 620,
      height: int = 480,
      scale_mode: str = "zscore",
  ) -> str:
    """Renders a self-contained, crisp SVG radar chart with hover tooltips and 3-sigma perimeter."""
    active_spokes = spokes if spokes else EntityRadarCollector.get_canonical_nominal_spokes()
    spokes = active_spokes

    cx, cy = width / 2.0, height / 2.0 + 20
    max_radius = 125.0

    n = len(spokes)
    is_cri_mode = (scale_mode.lower() == "cri")
    display_cap = 100.0 if is_cri_mode else 4.0

    if composite_d >= 3.0:
      poly_fill, poly_stroke = "rgba(217, 48, 37, 0.25)", "#d93025"
      status_badge_bg, status_badge_fg, status_text = "#fce8e6", "#c5221f", "HIGH RISK ANOMALY"
    elif composite_d >= 2.0:
      poly_fill, poly_stroke = "rgba(249, 171, 0, 0.25)", "#f9ab00"
      status_badge_bg, status_badge_fg, status_text = "#fef7e0", "#b06000", "ELEVATED DEVIATION"
    else:
      poly_fill, poly_stroke = "rgba(26, 115, 232, 0.25)", "#1a73e8"
      status_badge_bg, status_badge_fg, status_text = "#e8f0fe", "#1967d2", "NOMINAL BASELINE"

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="{height}" style="font-family: Roboto, Arial, sans-serif; background: #ffffff; border-radius: 8px;">',
        '  <defs>',
        '    <filter id="shadow" x="-10%" y="-10%" width="120%" height="120%">',
        '      <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.1"/>',
        '    </filter>',
        '  </defs>',
        f'  <rect x="20" y="12" width="{width - 40}" height="46" rx="6" fill="{status_badge_bg}"/>',
        f'  <text x="32" y="30" font-size="12" font-weight="bold" fill="{status_badge_fg}">{entity_id} • 360° BEHAVIORAL RADAR</text>',
        f'  <text x="32" y="47" font-size="11" font-weight="500" fill="{status_badge_fg}">Multi-Sector Distance: D = {composite_d:.2f}σ  |  CRI: {cri}/100 ({status_text})</text>',
    ]

    if is_cri_mode:
      ring_values = [(25, False, "CRI 25"), (50, True, "50 (3.0σ Threshold)"), (75, False, "CRI 75"), (100, False, "CRI 100")]
    else:
      ring_values = [(1.0, False, "+1.0σ"), (2.0, False, "+2.0σ"), (3.0, True, "+3.0σ (Threshold)"), (4.0, False, "+4.0σ")]

    for val, is_threshold, ring_label in ring_values:
      r = (val / display_cap) * max_radius
      stroke_color = "#d93025" if is_threshold else "#e0e0e0"
      stroke_dash = 'stroke-dasharray="4,4"' if is_threshold else ""
      stroke_width = "1.5" if is_threshold else "1"

      svg_parts.append(f'  <circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="{stroke_color}" stroke-width="{stroke_width}" {stroke_dash}/>')
      label_color = "#d93025" if is_threshold else "#9e9e9e"
      svg_parts.append(f'  <text x="{cx + 4}" y="{cy - r + 10}" font-size="9" font-weight="bold" fill="{label_color}">{ring_label}</text>')

    spoke_coords = []
    polygon_points = []

    for i, s in enumerate(spokes):
      angle = -math.pi / 2.0 + (2.0 * math.pi * i / n)
      ax = cx + max_radius * math.cos(angle)
      ay = cy + max_radius * math.sin(angle)
      svg_parts.append(f'  <line x1="{cx}" y1="{cy}" x2="{ax:.1f}" y2="{ay:.1f}" stroke="#eeeeee" stroke-width="1"/>')

      if is_cri_mode:
        val_for_radius = min(max(0.0, float(s.cri_score)), 100.0)
        dr = (val_for_radius / 100.0) * max_radius
      else:
        raw_z = max(0.0, s.z_score)
        # Perimeter pinning: Clamp visual distance to display_cap (4.0σ), avoiding scale compression
        dr = (min(raw_z, display_cap) / display_cap) * max_radius

      px = cx + dr * math.cos(angle)
      py = cy + dr * math.sin(angle)
      polygon_points.append(f"{px:.1f},{py:.1f}")
      spoke_coords.append((px, py, s))

      label_r = max_radius + 20
      lx = cx + label_r * math.cos(angle)
      ly = cy + label_r * math.sin(angle)

      if abs(math.cos(angle)) < 0.2:
        text_anchor = "middle"
      elif math.cos(angle) > 0:
        text_anchor = "start"
      else:
        text_anchor = "end"

      spoke_highlight = "#c5221f" if s.z_score >= 3.0 else "#3c4043"
      outlier_tag = " 🚨" if s.z_score >= 4.0 else ""
      z_formatted = f"{s.z_score:+.1f}σ"

      if i == 0:  # Top spoke
        ly -= 6
      elif i in (1, n - 1):  # Upper side spokes
        ly -= 2

      if is_cri_mode:
        score_subtext = f"(CRI {s.cri_score} | {z_formatted}{outlier_tag})"
      else:
        score_subtext = f"({z_formatted}{outlier_tag})"

      svg_parts.append(
          f'  <text x="{lx:.1f}" y="{ly:.1f}" font-size="10" font-weight="bold" text-anchor="{text_anchor}" fill="{spoke_highlight}">'
          f'<tspan x="{lx:.1f}" dy="0">{s.spoke_name}</tspan>'
          f'<tspan x="{lx:.1f}" dy="13" font-size="9" font-weight="600" fill="{spoke_highlight}">{score_subtext}</tspan>'
          f'</text>'
      )

    poly_str = " ".join(polygon_points)
    svg_parts.append(f'  <polygon points="{poly_str}" fill="{poly_fill}" stroke="{poly_stroke}" stroke-width="2.5" filter="url(#shadow)"/>')

    for px, py, s in spoke_coords:
      pt_color = "#d93025" if s.z_score >= 3.0 else poly_stroke
      z_formatted_title = f"{s.z_score:+.2f}σ"
      svg_parts.append(f'  <circle cx="{px:.1f}" cy="{py:.1f}" r="4.5" fill="{pt_color}" stroke="#ffffff" stroke-width="1.5">')
      svg_parts.append(
          f'    <title>{s.spoke_name}\n• Observed: {s.observed} {s.unit}\n• 30d Baseline Mean: {s.baseline_mean:.1f}\n• 30d StdDev: {s.baseline_stddev:.1f}\n• Deviation: {z_formatted_title}</title>'
      )
      svg_parts.append('  </circle>')

    svg_parts.append('</svg>')
    return "\n".join(svg_parts)

  @staticmethod
  def generate_html_widget(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
      scale_mode: str = "zscore",
  ) -> str:
    """Wraps self-contained SVG into a Generative UI HTML artifact compatible with <agent-embed>."""
    svg = EntityRadarCollector.generate_self_contained_svg(
        entity_id, spokes, composite_d, cri, scale_mode=scale_mode
    )
    return (
        '<!DOCTYPE html>\n<html>\n<head>\n'
        '  <meta charset="utf-8">\n'
        '  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>\n'
        '</head>\n<body class="bg-transparent text-[var(--foreground)] antialiased p-2 flex justify-center">\n'
        '  <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-3 shadow-sm">\n'
        f'    {svg}\n'
        '  </div>\n</body>\n</html>\n'
    )

  @staticmethod
  def generate_data_uri_image(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
      scale_mode: str = "zscore",
  ) -> str:
    """Renders self-contained SVG wrapped in a Base64 Markdown image to prevent DOM sanitizers from collapsing text."""
    svg = EntityRadarCollector.generate_self_contained_svg(
        entity_id, spokes, composite_d, cri, scale_mode=scale_mode
    )
    b64_svg = base64.b64encode(svg.encode("utf-8")).decode("utf-8")
    return f"![360° Behavioral Risk Radar: {entity_id}](data:image/svg+xml;base64,{b64_svg})"

  @staticmethod
  def generate_dual_surface_embed(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
      artifact_path: Optional[str] = None,
      scale_mode: str = "zscore",
  ) -> str:
    """Renders the Jetski embed surface: <agent-embed> iframe plus a direct artifact link.

    Deliberately omits a base64 data-URI: Jetski's Markdown pipeline (rehype-sanitize)
    and CSP block `data:image/svg+xml;base64`, which renders as a broken image
    placeholder. SVG renders correctly inside the sandboxed <agent-embed> iframe.
    """
    src_path = artifact_path if artifact_path else f"radar_{entity_id}.html"
    file_uri = src_path if src_path.startswith("file://") else f"file://{src_path}"
    return (
        f'<agent-embed src="{file_uri}"></agent-embed>\n'
        f'[📊 Open 360° Risk Radar (SVG/HTML)]({file_uri})'
    )

  @staticmethod
  def generate_ascii_chart(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
      bar_width: int = 20,
  ) -> str:
    """Renders a clean, terminal-friendly ASCII horizontal bar chart for plain-text environments."""
    active_spokes = spokes if spokes else EntityRadarCollector.get_canonical_nominal_spokes()
    spokes = active_spokes

    is_anomalous = composite_d >= 3.0
    status_tag = "🚨 HIGH RISK ANOMALY" if is_anomalous else ("⚠️ ELEVATED" if composite_d >= 2.0 else "🟢 NOMINAL")
    header = f"360° BEHAVIORAL RISK RADAR: {entity_id} (D = {composite_d:.2f}σ | CRI {cri}/100 | {status_tag})"
    separator = "─" * max(len(header), 75)

    max_label_len = max(len(s.spoke_name) for s in spokes)
    lines = [header, separator]

    for s in spokes:
      z_val = max(0.0, s.z_score)
      capped_z = min(z_val, 4.0)
      filled = int(round((capped_z / 4.0) * bar_width))
      bar = "▰" * filled + "▱" * (bar_width - filled)
      outlier_icon = " 🚨" if s.z_score >= 3.0 else (" ⚠️" if s.z_score >= 2.0 else "   ")
      lines.append(
          f"{s.spoke_name:<{max_label_len}}  [{bar}]  +{s.z_score:>5.2f}σ  (CRI {s.cri_score:>3}/100){outlier_icon}"
      )

    lines.append(separator)
    lines.append(f"Perimeter Threshold: +3.00σ (CRI 50) | Monitored Sectors: {len(spokes)}")
    return "\n".join(lines)

  @staticmethod
  def generate_markdown_summary(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
      provenance: Optional[Dict[str, Any]] = None,
  ) -> str:
    """Generates CommonMark table with Unicode magnitude progress bars and D6-G3 provenance."""
    is_anomalous = composite_d >= 3.0
    status_icon = "🚨" if is_anomalous else "🟢"
    status_text = "HIGH RISK ANOMALOUS FOOTPRINT" if is_anomalous else "NOMINAL BEHAVIORAL BASELINE"

    lines = [
        f"### {status_icon} 360° Entity Behavioral Risk Radar: `{entity_id}`",
        f"**Composite Threat Distance**: `D = {composite_d:.2f}σ` | **Calibrated Risk Index**: `CRI = {cri}/100` (`{status_text}`)",
        "",
        "| Telemetry Sector Spoke | 24h Observed | 30d Baseline (μ ± σ) | Z-Score | Spoke CRI | Visual Spoke Magnitude | Status |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for s in spokes:
      z_val = max(0.0, s.z_score)
      bar_units = min(20, int(round(z_val / 0.2)))
      bar_str = "▰" * bar_units + "▱" * (20 - bar_units)

      status = "🚨 **Anomaly**" if s.z_score >= 3.0 else ("⚠️ Elevated" if s.z_score >= 2.0 else "🟢 Nominal")
      lines.append(
          f"| **{s.spoke_name}** ({s.sector}) | `{s.observed:,.0f} {s.unit}` | `{s.baseline_mean:,.1f} ± {s.baseline_stddev:,.1f}` | **`+{s.z_score:.2f}σ`** | `{s.cri_score}/100` | `{bar_str}` | {status} |"
      )

    lines.append("")
    lines.append("> [!NOTE]")
    lines.append(f"> Evaluated across **{len(spokes)} orthogonal telemetry sectors** using 30-day continuous Risk Analytics baselines (`period: 1d, window: 30d`).")
    lines.append("")
    lines.append("### 📐 Statistical & Mathematical Appendix (Step-by-Step Derivation)")
    lines.append("1. **Individual Spoke Z-Scores (Observed vs. 30-Day Historical Mean $\\pm$ StdDev)**:")
    lines.append("   $$Z_i = \\frac{\\text{Obs}_i - \\mu_{i, 30\\text{d}}}{\\max(\\sigma_{i, 30\\text{d}}, 1.0)}$$")
    lines.append("   *Universal dispersion floor ($+1.0$) prevents division-by-zero on quiet accounts while bounding variance.*")
    lines.append("")
    lines.append("2. **Euclidean Composite Threat Distance ($D$) Across All Orthogonal Spokes**:")
    sq_terms = [f"({max(0.0, s.z_score):.2f})^2" for s in spokes]
    sq_str = " + ".join(sq_terms)
    lines.append(f"   $$D = \\sqrt{{\\sum_{{i=1}}^{{K}} \\max(0, Z_i)^2}} = \\sqrt{{{sq_str}}} = \\mathbf{{{composite_d:.2f}\\sigma}}$$")
    lines.append("")
    lines.append("3. **Calibrated Risk Index (CRI: 0–100 Logistic Sigmoid Mapping)**:")
    lines.append("   $$\\text{CRI} = \\text{round}\\left(\\frac{100}{1 + \\exp(-0.6 \\cdot (D - 3.0))}\\right)$$")
    lines.append(f"   $$\\text{{CRI}}({composite_d:.2f}) = \\mathbf{{{cri} / 100}} \\quad ({status_text})$$")
    prov = provenance or {
        "helper_version": EntityRadarCollector.HELPER_VERSION,
        "payload_sha256": "N/A",
        "query_sha256": "N/A",
    }
    lines.append("")
    lines.append(
        f"* **D6-G3 Provenance**: `helper_version={prov.get('helper_version', EntityRadarCollector.HELPER_VERSION)}` | "
        f"`payload_sha256={prov.get('payload_sha256', 'N/A')}` | "
        f"`query_sha256={prov.get('query_sha256', 'N/A')}`"
    )
    return "\n".join(lines)

  @staticmethod
  def generate_chartjs_spec(
      entity_id: str,
      spokes: List[MetricSpoke],
      composite_d: float,
      cri: int,
  ) -> Dict[str, Any]:
    """Generates declarative Chart.js radar specification for web dashboards."""
    labels = [s.spoke_name for s in spokes]
    z_values = [max(0.0, s.z_score) for s in spokes]
    max_z = max(4.0, max(z_values) if z_values else 4.0)

    bg_color = "rgba(217, 48, 37, 0.25)" if composite_d >= 3.0 else ("rgba(249, 171, 0, 0.25)" if composite_d >= 2.0 else "rgba(26, 115, 232, 0.25)")
    border_color = "#d93025" if composite_d >= 3.0 else ("#f9ab00" if composite_d >= 2.0 else "#1a73e8")

    return {
        "type": "radar",
        "data": {
            "labels": labels,
            "datasets": [
                {
                    "label": f"{entity_id} (D = {composite_d:.2f}σ, CRI = {cri}/100)",
                    "data": z_values,
                    "backgroundColor": bg_color,
                    "borderColor": border_color,
                    "borderWidth": 2.5,
                    "pointBackgroundColor": border_color,
                    "pointRadius": 4,
                },
                {
                    "label": "Anomaly Boundary (+3.0σ)",
                    "data": [3.0] * len(labels),
                    "borderColor": "rgba(217, 48, 37, 0.6)",
                    "borderDash": [4, 4],
                    "borderWidth": 1.5,
                    "fill": False,
                    "pointRadius": 0,
                },
            ],
        },
        "options": {
            "responsive": True,
            "scales": {
                "r": {
                    "min": 0,
                    "max": math.ceil(max_z),
                    "ticks": {"stepSize": 1.0, "backdropColor": "transparent"},
                    "pointLabels": {"font": {"size": 11, "weight": "bold"}},
                }
            },
        },
    }

  @staticmethod
  def generate_ranked_fleet_html(
      ranked_entities: List[Dict[str, Any]],
      title: str = "360° Threat Fusion: Ranked Fleet Outliers",
      threshold_sigma: float = 3.0,
  ) -> str:
    """Renders a responsive standalone HTML/SVG ranked horizontal bar chart for fleet reviews."""
    row_height = 36
    header_height = 60
    svg_height = header_height + max(1, len(ranked_entities)) * row_height + 40
    svg_width = 760
    bar_start_x = 240
    max_bar_width = 380
    max_d = max([float(r.get("threat_distance_d", 0.0)) for r in ranked_entities] + [4.5])

    bars_svg = []
    # Anomaly reference line (+3.0 sigma)
    thresh_x = bar_start_x + (threshold_sigma / max_d) * max_bar_width
    bars_svg.append(
        f'<line x1="{thresh_x:.1f}" y1="50" x2="{thresh_x:.1f}" y2="{svg_height - 30}" '
        f'stroke="#d93025" stroke-width="1.5" stroke-dasharray="4,4"/>'
    )
    bars_svg.append(
        f'<text x="{thresh_x:.1f}" y="42" font-size="12" font-weight="600" fill="#d93025" text-anchor="middle">+3.0σ Anomaly</text>'
    )

    for i, ent in enumerate(ranked_entities):
      y = header_height + i * row_height
      d_val = float(ent.get("threat_distance_d", 0.0))
      cri_val = int(ent.get("cri", 0))
      entity_id = html.escape(str(ent.get("entity", f"Entity-{i+1}")))
      bar_w = max(4, (d_val / max_d) * max_bar_width)
      color = "#d93025" if d_val >= 3.0 else ("#f9ab00" if d_val >= 2.0 else "#1a73e8")

      bars_svg.append(
          f'<text x="{bar_start_x - 10}" y="{y + 18}" font-size="12" font-weight="500" fill="currentColor" text-anchor="end">{entity_id}</text>'
      )
      bars_svg.append(
          f'<rect x="{bar_start_x}" y="{y + 4}" width="{bar_w:.1f}" height="20" rx="4" fill="{color}" opacity="0.85"/>'
      )
      bars_svg.append(
          f'<text x="{bar_start_x + bar_w + 8:.1f}" y="{y + 18}" font-size="12" font-weight="600" fill="currentColor">'
          f'D={d_val:.2f}σ (CRI {cri_val})</text>'
      )

    bars_joined = "".join(bars_svg)
    return (
        f'<!DOCTYPE html>\n<html>\n<head>\n  <meta charset="utf-8">\n'
        f'  <title>{html.escape(title)}</title>\n  <style>\n'
        f'    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 16px; background: transparent; color: var(--foreground, #202124); display: flex; justify-content: center; }}\n'
        f'    .card {{ width: 100%; max-width: 780px; background: var(--card, #ffffff); color: var(--foreground, #202124); border: 1px solid var(--border, #e8eaed); border-radius: 12px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}\n'
        f'    h3 {{ margin: 0 0 4px 0; font-size: 16px; color: var(--foreground, #202124); }}\n'
        f'    p {{ margin: 0 0 16px 0; font-size: 12px; color: var(--muted-foreground, #5f6368); }}\n'
        f'  </style>\n</head>\n<body>\n  <div class="card">\n'
        f'    <h3>{html.escape(title)}</h3>\n'
        f'    <p>Ranked by Composite Threat Distance (D in σ) | Monitored Entities: {len(ranked_entities)}</p>\n'
        f'    <svg viewBox="0 0 {svg_width} {svg_height}" width="100%" height="{svg_height}">\n'
        f'      {bars_joined}\n    </svg>\n  </div>\n</body>\n</html>'
    )

  @staticmethod
  def generate_fleet_heatmap_html(
      fleet_matrix: List[Dict[str, Any]],
      title: str = "360° Multi-Sector Fleet Threat Matrix",
  ) -> str:
    """Renders a responsive standalone HTML 6-sector heatmap matrix for fleet reviews."""
    canonical_sectors = [
        "IAM & Authentication",
        "Cloud Infrastructure",
        "Workspace Data",
        "Network Egress",
        "DNS Resolution",
        "Web & Proxy Activity",
    ]
    rows = []
    for r in fleet_matrix:
      entity = r.get("entity", "Unknown")
      sec_dict = r.get("sectors", {})
      d_val = float(r.get("threat_distance_d", 0.0))
      cri_val = int(r.get("cri", 0))

      tds = [f'<td style="font-weight:600; padding:8px 12px; border-bottom:1px solid #e8eaed;">{entity}</td>']
      for s in canonical_sectors:
        z = float(sec_dict.get(s, 0.0))
        bg = "#fce8e6" if z >= 3.0 else ("#fef7e0" if z >= 2.0 else ("#e6f4ea" if z < 1.0 else "#ffffff"))
        text_color = "#c5221f" if z >= 3.0 else ("#b06000" if z >= 2.0 else "#137333")
        tds.append(
            f'<td style="text-align:center; background:{bg}; color:{text_color}; font-weight:600; padding:8px 12px; border-bottom:1px solid #e8eaed;">+{z:.2f}σ</td>'
        )
      badge_bg = "#fce8e6" if d_val >= 3.0 else ("#fef7e0" if d_val >= 2.0 else "#e6f4ea")
      badge_color = "#c5221f" if d_val >= 3.0 else ("#b06000" if d_val >= 2.0 else "#137333")
      tds.append(
          f'<td style="text-align:center; padding:8px 12px; border-bottom:1px solid #e8eaed;">'
          f'<span style="display:inline-block; padding:3px 8px; border-radius:10px; background:{badge_bg}; color:{badge_color}; font-weight:700;">'
          f'D={d_val:.2f}σ ({cri_val}/100)</span></td>'
      )
      tds_joined = "".join(tds)
      rows.append(f'<tr>{tds_joined}</tr>')

    th_sectors = "".join(f'<th style="padding:10px 12px; font-size:11px; text-align:center; background:#f8f9fa; border-bottom:2px solid #dadce0;">{html.escape(s)}</th>' for s in canonical_sectors)
    rows_joined = "".join(rows)
    return (
        f'<!DOCTYPE html>\n<html>\n<head>\n  <meta charset="utf-8">\n'
        f'  <title>{title}</title>\n  <style>\n'
        f'    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 16px; background: #fafafa; display: flex; justify-content: center; }}\n'
        f'    .card {{ width: 100%; max-width: 960px; background: #ffffff; border: 1px solid #e8eaed; border-radius: 12px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); overflow-x: auto; }}\n'
        f'    h3 {{ margin: 0 0 4px 0; font-size: 16px; color: #202124; }}\n'
        f'    p {{ margin: 0 0 16px 0; font-size: 12px; color: #5f6368; }}\n'
        f'    table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}\n'
        f'  </style>\n</head>\n<body>\n  <div class="card">\n'
        f'    <h3>{title}</h3>\n'
        f'    <p>Multi-Sector Behavioral Deviations across Fleet Entities</p>\n'
        f'    <table>\n      <thead>\n        <tr>\n'
        f'          <th style="padding:10px 12px; font-size:11px; text-align:left; background:#f8f9fa; border-bottom:2px solid #dadce0;">Entity</th>\n'
        f'          {th_sectors}\n'
        f'          <th style="padding:10px 12px; font-size:11px; text-align:center; background:#f8f9fa; border-bottom:2px solid #dadce0;">Composite Risk</th>\n'
        f'        </tr>\n      </thead>\n      <tbody>\n'
        f'        {rows_joined}\n      </tbody>\n    </table>\n  </div>\n</body>\n</html>'
    )

  @staticmethod
  def generate_fleet_heatmap_svg(
      fleet_matrix: List[Dict[str, Any]],
      title: str = "360° Multi-Sector Fleet Threat Matrix",
  ) -> str:
    """Renders a standalone pure SVG multi-sector heatmap matrix for fleet reviews."""
    canonical_sectors = [
        "IAM & Authentication",
        "Cloud Infrastructure",
        "Workspace Data",
        "Network Egress",
        "DNS Resolution",
        "Web & Proxy Activity",
    ]
    col_x = {
        "entity": 20,
        "IAM & Authentication": 160,
        "Cloud Infrastructure": 260,
        "Workspace Data": 360,
        "Network Egress": 460,
        "DNS Resolution": 560,
        "Web & Proxy Activity": 660,
        "composite": 770,
    }
    cell_w = 92
    cell_h = 28
    row_h = 36
    header_h = 75
    svg_w = 885
    svg_h = header_h + max(1, len(fleet_matrix)) * row_h + 20

    elements = []
    elements.append(f'<text x="20" y="28" font-size="16" font-weight="700" fill="#202124">{html.escape(title)}</text>')
    elements.append('<text x="20" y="46" font-size="12" fill="#5f6368">Multi-Sector Behavioral Deviations across Fleet Entities</text>')

    elements.append('<text x="20" y="68" font-size="11" font-weight="600" fill="#5f6368" text-anchor="start">Entity</text>')
    for s in canonical_sectors:
      cx = col_x[s] + cell_w / 2
      s_short = s.replace(" & ", "/").replace(" Infrastructure", "").replace(" Activity", "")
      elements.append(f'<text x="{cx:.1f}" y="68" font-size="11" font-weight="600" fill="#5f6368" text-anchor="middle">{html.escape(s_short)}</text>')
    elements.append(f'<text x="{col_x["composite"] + 47.5}" y="68" font-size="11" font-weight="600" fill="#5f6368" text-anchor="middle">Composite</text>')
    elements.append(f'<line x1="20" y1="74" x2="{svg_w - 20}" y2="74" stroke="#dadce0" stroke-width="1.5"/>')

    for i, r in enumerate(fleet_matrix):
      y = header_h + i * row_h
      entity = str(r.get("entity", f"Entity-{i+1}"))
      sec_dict = r.get("sectors", {})
      d_val = float(r.get("threat_distance_d", 0.0))
      cri_val = int(r.get("cri", 0))

      elements.append(f'<text x="20" y="{y + 19}" font-size="12" font-weight="500" fill="#202124">{html.escape(entity)}</text>')

      for s in canonical_sectors:
        z = float(sec_dict.get(s, 0.0))
        bg = "#fce8e6" if z >= 3.0 else ("#fef7e0" if z >= 2.0 else ("#e6f4ea" if z < 1.0 else "#f1f3f4"))
        border = "#fad2cf" if z >= 3.0 else ("#feefc3" if z >= 2.0 else ("#ceead6" if z < 1.0 else "#dadce0"))
        txt_c = "#c5221f" if z >= 3.0 else ("#b06000" if z >= 2.0 else ("#137333" if z < 1.0 else "#5f6368"))
        bx = col_x[s]
        by = y + 2
        elements.append(f'<rect x="{bx}" y="{by}" width="{cell_w}" height="{cell_h}" rx="4" fill="{bg}" stroke="{border}" stroke-width="1"/>')
        elements.append(f'<text x="{bx + cell_w/2:.1f}" y="{by + 18}" font-size="11" font-weight="600" fill="{txt_c}" text-anchor="middle">+{z:.2f}σ</text>')

      badge_bg = "#fce8e6" if d_val >= 3.0 else ("#fef7e0" if d_val >= 2.0 else "#e6f4ea")
      badge_border = "#fad2cf" if d_val >= 3.0 else ("#feefc3" if d_val >= 2.0 else "#ceead6")
      badge_c = "#c5221f" if d_val >= 3.0 else ("#b06000" if d_val >= 2.0 else "#137333")
      cmpx = col_x["composite"]
      elements.append(f'<rect x="{cmpx}" y="{y + 2}" width="95" height="{cell_h}" rx="14" fill="{badge_bg}" stroke="{badge_border}" stroke-width="1"/>')
      elements.append(f'<text x="{cmpx + 47.5:.1f}" y="{y + 20}" font-size="10" font-weight="700" fill="{badge_c}" text-anchor="middle">D={d_val:.2f}σ ({cri_val})</text>')

    content = "\n    ".join(elements)
    return f'<svg viewBox="0 0 {svg_w} {svg_h}" width="100%" height="{svg_h}" xmlns="http://www.w3.org/2000/svg">\n    {content}\n</svg>'

  @staticmethod
  def generate_dualy_timeline_svg(
      timeline_points: List[Dict[str, Any]],
      title: str = "Longitudinal Horizon Timeline: Observed Volume vs. Z-Score Drift",
      entity: str = "Entity",
      threshold_sigma: float = 3.0,
  ) -> str:
    """Renders a standalone pure SVG dual-Y axis chart (volume bars + Z-score path)."""
    svg_w = 760
    svg_h = 360
    plot_x0 = 70
    plot_x1 = 680
    plot_y0 = 60
    plot_y1 = 280
    plot_w = plot_x1 - plot_x0
    plot_h = plot_y1 - plot_y0

    n_points = max(1, len(timeline_points))
    raw_max_vol = max([float(p.get("volume", 0.0)) for p in timeline_points] + [10.0])
    max_vol = raw_max_vol * 1.2
    raw_max_z = max([float(p.get("z_score", 0.0)) for p in timeline_points] + [threshold_sigma + 0.5, 4.5])
    max_z = math.ceil(raw_max_z)

    elements = []
    elements.append(f'<text x="20" y="28" font-size="15" font-weight="700" fill="#202124">{html.escape(title)}</text>')
    elements.append(f'<text x="20" y="46" font-size="12" fill="#5f6368">Entity: {html.escape(entity)} | Mode B ({n_points}-Day Timeline) | Threshold: +{threshold_sigma:.1f}σ</text>')

    # Grid & Left Y-Axis (Volume)
    for step in [0.0, 0.25, 0.5, 0.75, 1.0]:
      y_pos = plot_y1 - step * plot_h
      val_vol = int(step * max_vol)
      elements.append(f'<line x1="{plot_x0}" y1="{y_pos:.1f}" x2="{plot_x1}" y2="{y_pos:.1f}" stroke="#f1f3f4" stroke-width="1"/>')
      elements.append(f'<text x="{plot_x0 - 8}" y="{y_pos + 4:.1f}" font-size="10" fill="#5f6368" text-anchor="end">{val_vol:,}</text>')

    elements.append(f'<text x="18" y="{plot_y0 + plot_h/2}" font-size="11" font-weight="600" fill="#1a73e8" transform="rotate(-90 18 {plot_y0 + plot_h/2})" text-anchor="middle">Observed Volume</text>')

    # Right Y-Axis (Z-Score)
    for z_val in range(0, int(max_z) + 1):
      y_pos = plot_y1 - (z_val / max_z) * plot_h
      elements.append(f'<text x="{plot_x1 + 8}" y="{y_pos + 4:.1f}" font-size="10" fill="#d93025" font-weight="600" text-anchor="start">+{z_val}.0σ</text>')

    elements.append(f'<text x="{svg_w - 14}" y="{plot_y0 + plot_h/2}" font-size="11" font-weight="600" fill="#d93025" transform="rotate(90 {svg_w - 14} {plot_y0 + plot_h/2})" text-anchor="middle">Z-Score Deviation (σ)</text>')

    # Anomaly Threshold Line (+3.0 sigma)
    thresh_y = plot_y1 - (threshold_sigma / max_z) * plot_h
    elements.append(f'<line x1="{plot_x0}" y1="{thresh_y:.1f}" x2="{plot_x1}" y2="{thresh_y:.1f}" stroke="#d93025" stroke-width="1.5" stroke-dasharray="4,4"/>')
    elements.append(f'<text x="{plot_x1 - 6}" y="{thresh_y - 6:.1f}" font-size="10" font-weight="700" fill="#d93025" text-anchor="end">+{threshold_sigma:.1f}σ Anomaly Ceiling</text>')

    # Volume Bars & Trajectory Points
    step_w = plot_w / n_points
    bar_w = max(4.0, step_w * 0.55)
    z_coords = []

    for i, p in enumerate(timeline_points):
      cx = plot_x0 + (i + 0.5) * step_w
      vol = float(p.get("volume", 0.0))
      z = float(p.get("z_score", 0.0))
      dt_label = str(p.get("date", f"D{i+1}"))[-5:]

      bar_h = (vol / max_vol) * plot_h
      bar_y = plot_y1 - bar_h
      bar_color = "#fce8e6" if z >= threshold_sigma else "#e8f0fe"
      bar_border = "#fad2cf" if z >= threshold_sigma else "#1a73e8"
      elements.append(f'<rect x="{cx - bar_w/2:.1f}" y="{bar_y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" rx="2" fill="{bar_color}" stroke="{bar_border}" stroke-width="1" opacity="0.85"/>')

      zy = plot_y1 - (max(0.0, z) / max_z) * plot_h
      z_coords.append((cx, zy, z))

      elements.append(f'<text x="{cx:.1f}" y="{plot_y1 + 18}" font-size="10" fill="#5f6368" text-anchor="middle">{html.escape(dt_label)}</text>')

    # Draw Z-Score Line Path
    if z_coords:
      path_d = f"M {z_coords[0][0]:.1f} {z_coords[0][1]:.1f} " + " ".join(f"L {x:.1f} {y:.1f}" for x, y, _ in z_coords[1:])
      elements.append(f'<path d="{path_d}" fill="none" stroke="#d93025" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>')

      for x, y, z in z_coords:
        pt_color = "#d93025" if z >= threshold_sigma else "#1a73e8"
        elements.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{pt_color}" stroke="#ffffff" stroke-width="1.5"/>')
        if z >= threshold_sigma:
          elements.append(f'<text x="{x:.1f}" y="{y - 9:.1f}" font-size="10" font-weight="700" fill="#d93025" text-anchor="middle">+{z:.1f}σ</text>')

    elements.append(f'<line x1="{plot_x0}" y1="{plot_y1}" x2="{plot_x1}" y2="{plot_y1}" stroke="#bdc1c6" stroke-width="1"/>')
    elements.append(f'<line x1="{plot_x0}" y1="{plot_y0}" x2="{plot_x0}" y2="{plot_y1}" stroke="#bdc1c6" stroke-width="1"/>')
    elements.append(f'<line x1="{plot_x1}" y1="{plot_y0}" x2="{plot_x1}" y2="{plot_y1}" stroke="#bdc1c6" stroke-width="1"/>')

    # Legend
    elements.append(
        f'<g transform="translate({plot_x0}, {plot_y1 + 35})">'
        f'<rect x="0" y="0" width="12" height="12" rx="2" fill="#e8f0fe" stroke="#1a73e8"/>'
        f'<text x="18" y="10" font-size="11" fill="#3c4043">Observed Volume</text>'
        f'<line x1="140" y1="6" x2="165" y2="6" stroke="#d93025" stroke-width="2.5"/>'
        f'<circle cx="152.5" cy="6" r="3.5" fill="#d93025"/>'
        f'<text x="172" y="10" font-size="11" fill="#3c4043">Z-Score Deviation</text>'
        f'<line x1="310" y1="6" x2="335" y2="6" stroke="#d93025" stroke-width="1.5" stroke-dasharray="3,3"/>'
        f'<text x="342" y="10" font-size="11" fill="#d93025">+{threshold_sigma:.1f}σ Threshold</text>'
        f'</g>'
    )

    content = "\n    ".join(elements)
    return f'<svg viewBox="0 0 {svg_w} {svg_h}" width="100%" height="{svg_h}" xmlns="http://www.w3.org/2000/svg">\n    {content}\n</svg>'

  @staticmethod
  def generate_dualy_timeline_html(
      timeline_points: List[Dict[str, Any]],
      title: str = "Longitudinal Horizon Timeline: Observed Volume vs. Z-Score Drift",
      entity: str = "Entity",
      threshold_sigma: float = 3.0,
  ) -> str:
    """Renders a responsive standalone HTML card wrapping the pure SVG dual-Y timeline."""
    svg_chart = EntityRadarCollector.generate_dualy_timeline_svg(
        timeline_points=timeline_points, title=title, entity=entity, threshold_sigma=threshold_sigma
    )
    return (
        f'<!DOCTYPE html>\n<html>\n<head>\n  <meta charset="utf-8">\n'
        f'  <title>{html.escape(title)}</title>\n  <style>\n'
        f'    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 16px; background: #fafafa; display: flex; justify-content: center; }}\n'
        f'    .card {{ width: 100%; max-width: 800px; background: #ffffff; border: 1px solid #e8eaed; border-radius: 12px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}\n'
        f'  </style>\n</head>\n<body>\n  <div class="card">\n'
        f'    {svg_chart}\n'
        f'  </div>\n</body>\n</html>'
    )

  @staticmethod
  def generate_prevalence_quadrant_svg(
      findings: List[Dict[str, Any]],
      title: str = "Prevalence vs. Anomaly Quadrant (Patch Tuesday Shield)",
      prevalence_threshold: int = 5,
      sigma_threshold: float = 3.0,
  ) -> str:
    """Renders a standalone pure SVG 2D quadrant scatter for prevalence discounting."""
    svg_w = 740
    svg_h = 420
    plot_x0 = 80
    plot_x1 = 680
    plot_y0 = 60
    plot_y1 = 340
    plot_w = plot_x1 - plot_x0
    plot_h = plot_y1 - plot_y0

    max_prev = max([float(f.get("fleet_adopters", 1)) for f in findings] + [50.0])
    max_z = max([float(f.get("personal_z", 0.0)) for f in findings] + [sigma_threshold + 1.0, 5.0])
    log_max_prev = math.log10(max(10.0, max_prev))

    def x_coord(prev_val: float) -> float:
      p = max(1.0, prev_val)
      ratio = math.log10(p) / log_max_prev
      return plot_x0 + ratio * plot_w

    def y_coord(z_val: float) -> float:
      z = max(0.0, z_val)
      ratio = z / max_z
      return plot_y1 - ratio * plot_h

    split_x = x_coord(prevalence_threshold)
    split_y = y_coord(sigma_threshold)

    elements = []
    elements.append(f'<text x="20" y="28" font-size="15" font-weight="700" fill="#202124">{html.escape(title)}</text>')
    elements.append(f'<text x="20" y="46" font-size="12" fill="#5f6368">Fleet Adopters vs. Personal Z-Score Deviation | Shield Hurdle: &le;{prevalence_threshold} hosts</text>')

    # Shaded Quadrants
    elements.append(f'<rect x="{plot_x0}" y="{plot_y0}" width="{split_x - plot_x0:.1f}" height="{split_y - plot_y0:.1f}" fill="#fce8e6" opacity="0.6"/>')
    elements.append(f'<text x="{plot_x0 + 12}" y="{plot_y0 + 20}" font-size="11" font-weight="700" fill="#c5221f">🚨 ACUTE TARGETED INTRUSION</text>')
    elements.append(f'<text x="{plot_x0 + 12}" y="{plot_y0 + 34}" font-size="9" fill="#c5221f">High Surge on Isolated Host</text>')

    elements.append(f'<rect x="{split_x}" y="{plot_y0}" width="{plot_x1 - split_x:.1f}" height="{split_y - plot_y0:.1f}" fill="#fef7e0" opacity="0.6"/>')
    elements.append(f'<text x="{split_x + 12:.1f}" y="{plot_y0 + 20}" font-size="11" font-weight="700" fill="#b06000">🛡️ CORPORATE ROLLOUT / PATCH TUESDAY</text>')
    elements.append(f'<text x="{split_x + 12:.1f}" y="{plot_y0 + 34}" font-size="9" fill="#b06000">Concurrent Fleet Adoption (Suppressed)</text>')

    elements.append(f'<rect x="{plot_x0}" y="{split_y}" width="{plot_w:.1f}" height="{plot_y1 - split_y:.1f}" fill="#f1f3f4" opacity="0.5"/>')
    elements.append(f'<text x="{plot_x0 + 12}" y="{plot_y1 - 12}" font-size="10" font-weight="600" fill="#5f6368">🟢 Nominal Operational Baseline (Z &lt; {sigma_threshold:.1f}σ)</text>')

    # Threshold Divider Lines
    elements.append(f'<line x1="{split_x:.1f}" y1="{plot_y0}" x2="{split_x:.1f}" y2="{plot_y1}" stroke="#5f6368" stroke-width="1.5" stroke-dasharray="4,4"/>')
    elements.append(f'<line x1="{plot_x0}" y1="{split_y:.1f}" x2="{plot_x1}" y2="{split_y:.1f}" stroke="#d93025" stroke-width="1.5" stroke-dasharray="4,4"/>')
    elements.append(f'<text x="{plot_x1 - 6}" y="{split_y - 6:.1f}" font-size="10" font-weight="700" fill="#d93025" text-anchor="end">+{sigma_threshold:.1f}σ Anomaly Ceiling</text>')

    # Axes
    elements.append(f'<line x1="{plot_x0}" y1="{plot_y1}" x2="{plot_x1}" y2="{plot_y1}" stroke="#202124" stroke-width="1.5"/>')
    elements.append(f'<line x1="{plot_x0}" y1="{plot_y0}" x2="{plot_x0}" y2="{plot_y1}" stroke="#202124" stroke-width="1.5"/>')

    for tick in [1, 2, 5, 10, 25, 50, 100, 250, 500]:
      if tick <= max_prev * 1.1:
        tx = x_coord(tick)
        elements.append(f'<line x1="{tx:.1f}" y1="{plot_y1}" x2="{tx:.1f}" y2="{plot_y1 + 4}" stroke="#5f6368"/>')
        elements.append(f'<text x="{tx:.1f}" y="{plot_y1 + 16}" font-size="10" fill="#5f6368" text-anchor="middle">{tick}</text>')

    elements.append(f'<text x="{plot_x0 + plot_w/2}" y="{plot_y1 + 32}" font-size="11" font-weight="600" fill="#202124" text-anchor="middle">Fleet Prevalence (Host Adopter Count - Log Scale)</text>')

    for z in range(0, int(max_z) + 1):
      ty = y_coord(z)
      elements.append(f'<line x1="{plot_x0 - 4}" y1="{ty:.1f}" x2="{plot_x0}" y2="{ty:.1f}" stroke="#5f6368"/>')
      elements.append(f'<text x="{plot_x0 - 8}" y="{ty + 4:.1f}" font-size="10" fill="#202124" font-weight="600" text-anchor="end">+{z}.0σ</text>')

    elements.append(f'<text x="24" y="{plot_y0 + plot_h/2}" font-size="11" font-weight="600" fill="#202124" transform="rotate(-90 24 {plot_y0 + plot_h/2})" text-anchor="middle">Personal Z-Score Deviation</text>')

    # Plot Findings Points
    for f in findings:
      k_prev = float(f.get("fleet_adopters", 1))
      z_val = float(f.get("personal_z", 0.0))
      label = str(f.get("token", f.get("entity", "Entity")))
      if len(label) > 16:
        label = label[:14] + "..."

      px = x_coord(k_prev)
      py = y_coord(z_val)
      is_targeted = (z_val >= sigma_threshold and k_prev <= prevalence_threshold)
      is_rollout = (z_val >= sigma_threshold and k_prev > prevalence_threshold)

      pt_c = "#d93025" if is_targeted else ("#f9ab00" if is_rollout else "#1a73e8")
      pt_r = 6 if (is_targeted or is_rollout) else 4

      elements.append(f'<circle cx="{px:.1f}" cy="{py:.1f}" r="{pt_r}" fill="{pt_c}" stroke="#ffffff" stroke-width="1.5"/>')
      text_color = "#c5221f" if is_targeted else ("#b06000" if is_rollout else "#3c4043")
      elements.append(f'<text x="{px + 8:.1f}" y="{py + 4:.1f}" font-size="10" font-weight="600" fill="{text_color}">{html.escape(label)} (+{z_val:.1f}σ, {int(k_prev)}h)</text>')

    content = "\n    ".join(elements)
    return f'<svg viewBox="0 0 {svg_w} {svg_h}" width="100%" height="{svg_h}" xmlns="http://www.w3.org/2000/svg">\n    {content}\n</svg>'

  @staticmethod
  def generate_prevalence_quadrant_html(
      findings: List[Dict[str, Any]],
      title: str = "Prevalence vs. Anomaly Quadrant (Patch Tuesday Shield)",
      prevalence_threshold: int = 5,
      sigma_threshold: float = 3.0,
  ) -> str:
    """Renders a responsive standalone HTML card wrapping the pure SVG prevalence quadrant."""
    svg_chart = EntityRadarCollector.generate_prevalence_quadrant_svg(
        findings=findings, title=title, prevalence_threshold=prevalence_threshold, sigma_threshold=sigma_threshold
    )
    return (
        f'<!DOCTYPE html>\n<html>\n<head>\n  <meta charset="utf-8">\n'
        f'  <title>{html.escape(title)}</title>\n  <style>\n'
        f'    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 16px; background: #fafafa; display: flex; justify-content: center; }}\n'
        f'    .card {{ width: 100%; max-width: 780px; background: #ffffff; border: 1px solid #e8eaed; border-radius: 12px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}\n'
        f'  </style>\n</head>\n<body>\n  <div class="card">\n'
        f'    {svg_chart}\n'
        f'  </div>\n</body>\n</html>'
    )



def _load_json_arg(arg_val: str, flag_name: str) -> Any:
  """Loads JSON from an inline string or existing file path, failing closed per D6-G2."""
  raw = arg_val.strip()
  if not raw:
    raise ValueError(f"G2 violation: empty JSON input provided to {flag_name}.")
  if raw.startswith("{") or raw.startswith("["):
    try:
      return json.loads(raw)
    except json.JSONDecodeError as exc:
      raise ValueError(f"G2 violation: malformed JSON in {flag_name}: {exc}") from exc
  if os.path.exists(raw):
    with open(raw, "r", encoding="utf-8") as f:
      text = f.read().strip()
    if not text:
      raise ValueError(f"G2 violation: empty JSON file provided to {flag_name}: '{raw}'.")
    try:
      return json.loads(text)
    except json.JSONDecodeError as exc:
      raise ValueError(f"G2 violation: malformed JSON in file '{raw}' ({flag_name}): {exc}") from exc
  try:
    return json.loads(raw)
  except json.JSONDecodeError as exc:
    raise ValueError(
        f"G2 violation: {flag_name} must be valid JSON or an existing file path, got '{raw}' ({exc})."
    ) from exc


def main(argv: Optional[List[str]] = None) -> int:
  """CLI entry point for deterministic visual generation and post-search collation."""
  parser = argparse.ArgumentParser(description="360° Entity Behavioral Risk Radar Generator")
  parser.add_argument("--entity", required=True, help="Entity identifier (user or hostname)")
  parser.add_argument(
      "--entity-type",
      default="USER",
      choices=["USER", "ASSET"],
      help="Entity type: USER or ASSET",
  )
  parser.add_argument(
      "--scores",
      default=None,
      help="REMOVED (D6-G1): LLM-typed scores are prohibited; raises an error.",
  )
  parser.add_argument(
      "--raw-payload",
      "--data",
      dest="raw_payload",
      default=None,
      help="JSON string or file path mapping sector names to raw udm_search stats payloads",
  )
  parser.add_argument(
      "--queries",
      "--query-texts",
      dest="query_texts",
      default=None,
      help="Optional JSON string or file path mapping sector names to executed YARA-L query texts",
  )
  parser.add_argument(
      "--format",
      choices=["html", "svg", "data-uri", "dual", "embed", "ascii", "markdown", "json"],
      default="html",
      help="Output format: html (generative-ui embed), svg, data-uri (markdown image), dual (cross-client embed+data-uri), embed (agent-embed snippet), ascii (terminal), markdown (table), json",
  )
  parser.add_argument("--scale-mode", choices=["zscore", "cri"], default="zscore", help="Radar scale mode")
  parser.add_argument("--output", help="Optional output file path")
  parser.add_argument(
      "--execute",
      action="store_true",
      help=(
          "Emit decoupled sector micro-queries for execution. Note: udm_search is invoked via the "
          "SecOps MCP tool by the agent rather than running an HTTP request directly."
      ),
  )
  args = parser.parse_args(argv)

  if args.scores is not None:
    raise ValueError(
        "G1 violation: --scores has been removed (D6-G1). "
        "Pass raw udm_search sector payloads JSON via --raw-payload or --data."
    )

  if args.execute:
    queries = (
        EntityRadarCollector.USER_SECTOR_QUERIES
        if args.entity_type.upper() == "USER"
        else EntityRadarCollector.ASSET_SECTOR_QUERIES
    )
    print(
        "# NOTE: udm_search is invoked via the SecOps MCP tool by the agent "
        "rather than running an HTTP request directly from this script.\n"
    )
    for sector_name, tpl in queries.items():
      print(f"// === Sector: {sector_name} ===")
      print((tpl % {"entity_id": args.entity}).strip())
      print()
    return 0

  if not args.raw_payload or not args.raw_payload.strip():
    raise ValueError(
        "G2 violation: missing required --raw-payload / --data argument; "
        "raw udm_search sector payloads JSON is required when --execute is not set."
    )

  parsed_payloads = _load_json_arg(args.raw_payload, "--raw-payload/--data")
  loaded_queries = (
      _load_json_arg(args.query_texts, "--queries") if args.query_texts else None
  )
  spokes, provenance = EntityRadarCollector.parse_raw_sector_payloads(
      parsed_payloads,
      entity_type=args.entity_type,
      query_texts=loaded_queries,
  )

  collector = EntityRadarCollector()
  payload = collector.build_radar_payload(
      args.entity,
      args.entity_type,
      spokes,
      provenance=provenance,
  )

  if args.format == "html":
    out_str = payload["html_widget"]
  elif args.format == "svg":
    out_str = payload["svg_widget"]
  elif args.format == "data-uri":
    out_str = payload["data_uri_image"]
  elif args.format == "dual":
    out_str = EntityRadarCollector.generate_dual_surface_embed(
        args.entity, spokes, payload["composite_distance_d"], payload["calibrated_risk_index"], artifact_path=args.output
    )
  elif args.format == "embed":
    src_path = args.output if args.output else f"radar_{args.entity}.html"
    file_uri = src_path if src_path.startswith("file://") else f"file://{src_path}"
    out_str = (
        f'<agent-embed src="{file_uri}"></agent-embed>\n'
        f'[📊 Open 360° Risk Radar (SVG/HTML)]({file_uri})'
    )
  elif args.format == "ascii":
    out_str = payload["ascii_chart"]
  elif args.format == "markdown":
    out_str = payload["markdown_table"]
  elif args.format == "json":
    out_str = json.dumps(payload, indent=2)
  else:
    out_str = payload["html_widget"]

  if args.output:
    file_content = payload["html_widget"] if args.format in ("dual", "embed") else out_str
    with open(args.output, "w", encoding="utf-8") as f:
      f.write(file_content)

    # Automatically generate companion file for seamless multi-surface rendering (.html <-> .svg)
    if args.output.endswith(".html"):
      companion_path = args.output[:-5] + ".svg"
      with open(companion_path, "w", encoding="utf-8") as f:
        f.write(payload["svg_widget"])
    elif args.output.endswith(".svg"):
      companion_path = args.output[:-4] + ".html"
      with open(companion_path, "w", encoding="utf-8") as f:
        f.write(payload["html_widget"])

  print(out_str)
  return 0


if __name__ == "__main__":
  sys.exit(main())
