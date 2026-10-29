"""Vetted Page One-Sided CUSUM Helper for Google SecOps Macro Baselines (WS6-01 / D6 G1-G5).

Evaluates Page's sequential cumulative sum recursion:
  S_0 = 0,  S_t = max(0.0, S_{t-1} + z_t - k)   (default slack k = 0.5)

Supports two deterministic execution modes over raw Chronicle udm_search JSON outputs:
  1. <= 14-Day Start-Anchored Series Mode (--payload-file):
     Consumes raw udm_search output from templates/pipelines/longitudinal_cusum_series_3stage.yl2,
     reconstructs every quiet 0-event UTC calendar day in [start_day, end_day] (inclusive) with
     observed = 0.0 and z_t = (0.0 - baseline_mean) / safe_sigma < 0 so quiet days decay S_t,
     enforces the D8 maturity gate (active_days >= min_baseline_days, routing immature entities
     to FIRST_SEEN_NOVELTY), and maps S_t to Z-equivalent and canonical [0..100] CRI.
  2. > 14-Day Multi-Shard Fixed-Reference Mode (--shard YYYY-MM-DD=path.json):
     Consumes ungated Mode C daily shard files scoped to candidate entities, reconstructs a
     fixed pre-window calendar-day reference (mu_cal_ref, safe_sd_cal_ref) from Shard 1 via
     rebuild_calendar_day_stats (WS1-05), re-standardizes every calendar day (including quiet
     0-event days) against that fixed reference without trailing-baseline fade, and supports
     explicit reference resets (--reset-on, --reset-after-alarm, --reset-every-days).
"""

import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:
  from .template_router import resolve_byte_dispersion_floor
  from .timeline_assembler import (
      TimelinePoint,
      calculate_page_cusum_series,
      rebuild_calendar_day_stats,
  )
  from .ueba_constants import (
      DEFAULT_MIN_BASELINE_DAYS,
      MAX_CUSUM_MODE_B_DAYS_MACRO,
      cri_from_model_score,
      format_cri,
      score_to_z_equivalent,
  )
except ImportError:
  try:
    from scripts.template_router import resolve_byte_dispersion_floor
    from scripts.timeline_assembler import (
        TimelinePoint,
        calculate_page_cusum_series,
        rebuild_calendar_day_stats,
    )
    from scripts.ueba_constants import (
        DEFAULT_MIN_BASELINE_DAYS,
        MAX_CUSUM_MODE_B_DAYS_MACRO,
        cri_from_model_score,
        format_cri,
        score_to_z_equivalent,
    )
  except ImportError:
    from template_router import resolve_byte_dispersion_floor  # type: ignore[no-redef]
    from timeline_assembler import (  # type: ignore[no-redef]
        TimelinePoint,
        calculate_page_cusum_series,
        rebuild_calendar_day_stats,
    )
    from ueba_constants import (  # type: ignore[no-redef]
        DEFAULT_MIN_BASELINE_DAYS,
        MAX_CUSUM_MODE_B_DAYS_MACRO,
        cri_from_model_score,
        format_cri,
        score_to_z_equivalent,
    )


HELPER_VERSION = "2.3.0"
DEFAULT_SLACK_K = 0.5
SIEGMUND_OVERSHOOT = 1.166

CUSUM_TIER_THRESHOLDS: Dict[str, float] = {
    "HIGH_RECALL": 3.0,
    "BALANCED": 4.0,
    "HIGH_PRECISION": 5.0,
}

DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

ENTITY_COLUMN_CANDIDATES: Tuple[str, ...] = (
    "entity",
    "user",
    "userid",
    "host",
    "hostname",
    "asset",
    "ip",
    "resource",
    "service_account",
    "principal",
    "target",
)

BUCKET_COLUMN_CANDIDATES: Tuple[str, ...] = (
    "ws",
    "window_start",
    "TIME_BUCKET",
    "day",
    "date",
)

OBSERVED_COLUMN_CANDIDATES: Tuple[str, ...] = (
    "observed_val",
    "observed",
    "obs",
    "today_val",
    "total_obs",
)

MEAN_COLUMN_CANDIDATES: Tuple[str, ...] = (
    "baseline_mean",
    "historical_avg",
    "hist_avg",
    "baseline",
    "mu",
    "avg",
)

STDDEV_COLUMN_CANDIDATES: Tuple[str, ...] = (
    "baseline_stddev",
    "historical_stddev",
    "hist_stddev",
    "dispersion",
    "sigma",
    "stddev",
    "std",
)

ACTIVE_DAYS_COLUMN_CANDIDATES: Tuple[str, ...] = (
    "active_days",
    "historical_active_days",
    "hist_active_days",
    "active_baseline_days",
)

HIST_SUM_COLUMN_CANDIDATES: Tuple[str, ...] = (
    "historical_sum",
    "hist_sum",
)


def assert_local_execution_available(local_execution_available: bool = True) -> None:
  """Enforces D6 Guardrail G5: never silently substitute Windowed Slack Sum when local scripts cannot run."""
  if not local_execution_available:
    raise ValueError(
        "G5 violation: Page CUSUM (LONGITUDINAL_CUSUM) cannot run statelessly in YARA-L alone — "
        "this model needs a client that can run local scripts (scripts/cusum_helper.py). "
        "Request statistical_model='WINDOWED_SLACK_SUM' explicitly if you want the stateless "
        "Windowed Slack Sum prefilter."
    )


def siegmund_arl(h: float, slack_k: float = DEFAULT_SLACK_K, shift_sigma: float = 0.0) -> float:
  """Computes Siegmund's Gaussian ARL approximation with overshoot correction b = h + 1.166."""
  if isinstance(h, bool) or isinstance(slack_k, bool) or isinstance(shift_sigma, bool):
    raise ValueError("G2 violation: ARL parameters must be finite numbers, not booleans.")
  h_val = float(h)
  k_val = float(slack_k)
  mu_val = float(shift_sigma)
  if not (math.isfinite(h_val) and math.isfinite(k_val) and math.isfinite(mu_val)):
    raise ValueError("G2 violation: ARL parameters must be finite.")
  if h_val <= 0.0 or k_val <= 0.0:
    raise ValueError("G2 violation: threshold h and slack k must be strictly positive (> 0).")
  b = h_val + SIEGMUND_OVERSHOOT
  delta = mu_val - k_val
  if abs(delta) < 1e-9:
    return b * b
  exponent = -2.0 * delta * b
  if exponent > 700.0:
    return float("inf")
  return (math.exp(exponent) - 1.0 + 2.0 * delta * b) / (2.0 * delta * delta)


CUSUM_ARL_CALIBRATION: Dict[str, Dict[str, float]] = {
    tier: {
        "threshold_h": h_val,
        "slack_k": DEFAULT_SLACK_K,
        "arl0_in_control": round(siegmund_arl(h_val, DEFAULT_SLACK_K, 0.0), 1),
        "arl1_plus_1sigma": round(siegmund_arl(h_val, DEFAULT_SLACK_K, 1.0), 2),
    }
    for tier, h_val in CUSUM_TIER_THRESHOLDS.items()
}


def resolve_cusum_threshold(
    tier: str = "BALANCED",
    threshold_h: Optional[float] = None,
) -> Tuple[str, float]:
  """Resolves sensitivity tier or explicit --threshold-h override into (label, h)."""
  if threshold_h is not None:
    if isinstance(threshold_h, bool):
      raise ValueError("G2 violation: threshold_h must be a positive finite float, got bool.")
    h_val = float(threshold_h)
    if not math.isfinite(h_val) or h_val <= 0.0:
      raise ValueError(f"G2 violation: threshold_h must be > 0 and finite, got {threshold_h!r}.")
    return ("CUSTOM", h_val)
  tier_norm = (tier or "BALANCED").strip().upper().replace("-", "_").replace(" ", "_")
  if tier_norm not in CUSUM_TIER_THRESHOLDS:
    raise ValueError(
        f"G2 violation: unknown sensitivity tier {tier!r}; expected one of {sorted(CUSUM_TIER_THRESHOLDS)}."
    )
  return (tier_norm, CUSUM_TIER_THRESHOLDS[tier_norm])


def _validate_positive_slack(slack_k: float) -> float:
  if isinstance(slack_k, bool):
    raise ValueError("G2 violation: slack_k must be a positive finite float, got bool.")
  k_val = float(slack_k)
  if not math.isfinite(k_val) or k_val <= 0.0:
    raise ValueError(f"G2 violation: slack_k must be > 0 and finite, got {slack_k!r}.")
  return k_val


def _parse_utc_day(day_str: str, label: str = "day") -> datetime.date:
  if not isinstance(day_str, str) or not DAY_RE.match(day_str.strip()):
    raise ValueError(f"G2 violation: {label} must be YYYY-MM-DD, got {day_str!r}.")
  try:
    return datetime.date.fromisoformat(day_str.strip())
  except ValueError as exc:
    raise ValueError(f"G2 violation: invalid calendar {label} {day_str!r}: {exc}") from exc


def _enumerate_calendar_days(
    start_day: str,
    end_day: str,
    *,
    enforce_single_query_14d_cap: bool = False,
) -> List[str]:
  """Enumerates inclusive UTC calendar days [start_day, end_day] and enforces Mode A & 14d caps."""
  start_dt = _parse_utc_day(start_day, "start_day")
  end_dt = _parse_utc_day(end_day, "end_day")
  if end_dt < start_dt:
    raise ValueError(
        f"G2 violation: end_day ({end_day}) precedes start_day ({start_day})."
    )
  span_days = (end_dt - start_dt).days + 1
  if span_days <= 1:
    raise ValueError(
        "LONGITUDINAL_CUSUM cannot run in single-day Mode A; "
        "sequential drift requires a multi-day window (>= 2 UTC calendar days)."
    )
  if enforce_single_query_14d_cap and span_days > MAX_CUSUM_MODE_B_DAYS_MACRO:
    raise ValueError(
        f"G2 violation: single-payload start-anchored CUSUM series mode supports at most "
        f"{MAX_CUSUM_MODE_B_DAYS_MACRO} UTC calendar days (PF-1), got {span_days} days "
        f"({start_day}..{end_day}); use --shard YYYY-MM-DD=<path> multi-shard fixed-reference mode."
    )
  return [
      (start_dt + datetime.timedelta(days=offset)).isoformat()
      for offset in range(span_days)
  ]


def _reject_inline_cli_value(raw_path: str, flag_name: str) -> str:
  if not isinstance(raw_path, str) or not raw_path.strip():
    raise ValueError(f"G2 violation: empty path provided to {flag_name}.")
  cleaned = raw_path.strip()
  if cleaned.startswith("{") or cleaned.startswith("["):
    raise ValueError(
        f"G1 violation: {flag_name} accepts only a file path on disk, never inline JSON strings."
    )
  return cleaned


def _read_required_file_bytes(raw_path: str, flag_name: str) -> Tuple[bytes, str]:
  cleaned = _reject_inline_cli_value(raw_path, flag_name)
  if not os.path.exists(cleaned) or not os.path.isfile(cleaned):
    raise ValueError(f"G2 violation: {flag_name} file does not exist: '{cleaned}'.")
  with open(cleaned, "rb") as f:
    raw_bytes = f.read()
  if not raw_bytes or not raw_bytes.strip():
    raise ValueError(f"G2 violation: {flag_name} file is empty: '{cleaned}'.")
  return raw_bytes, hashlib.sha256(raw_bytes).hexdigest()


def _decode_chronicle_cell_strict(cell: Any) -> Any:
  """Strictly decodes a Chronicle udm_search stats.results cell, rejecting NaN/Infinity."""
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
  val_obj = cell["value"]
  if not val_obj:
    return None
  kind, raw = next(iter(val_obj.items()))
  if kind in ("int64Val", "uint64Val"):
    try:
      return int(raw)
    except (TypeError, ValueError) as exc:
      raise ValueError(f"G2 violation: invalid integer cell {raw!r}: {exc}") from exc
  if kind == "doubleVal":
    if isinstance(raw, bool):
      raise ValueError("G2 violation: boolean found in doubleVal cell.")
    try:
      fval = float(raw)
    except (TypeError, ValueError) as exc:
      raise ValueError(f"G2 violation: invalid float cell {raw!r}: {exc}") from exc
    if not math.isfinite(fval):
      raise ValueError(f"G2 violation: non-finite float {raw!r} in stats.results.")
    return fval
  if kind == "boolVal":
    if not isinstance(raw, bool):
      raise ValueError(f"G2 violation: invalid boolVal cell {raw!r}.")
    return raw
  if kind == "stringVal":
    return str(raw)
  if kind == "list" and isinstance(raw, dict):
    return [_decode_chronicle_cell_strict({"value": v}) for v in raw.get("values", [])]
  return raw


def parse_strict_stats_payload(raw_payload: Any, source_label: str = "payload") -> List[Dict[str, Any]]:
  """Validates and parses a raw Chronicle udm_search stats payload per D6 Guardrails G1 and G2."""
  if isinstance(raw_payload, bool) or not isinstance(raw_payload, dict):
    raise ValueError(
        f"G1 violation: {source_label} must be a raw udm_search JSON object containing 'stats' "
        "(or empty {} for 0-row results), not hand-typed numbers or arrays."
    )
  if not raw_payload:
    return []
  if "events" in raw_payload and "stats" not in raw_payload:
    raise ValueError(
        f"G1 violation (RAW_LOG_DUMP_DETECTED): {source_label} contains raw unaggregated "
        "'events' without 'stats'."
    )
  if "stats" not in raw_payload:
    raise ValueError(
        f"G1 violation: {source_label} is missing 'stats' envelope; pass raw udm_search output."
    )
  stats_obj = raw_payload["stats"]
  if stats_obj is None or stats_obj == {} or stats_obj == []:
    return []
  if not isinstance(stats_obj, dict):
    raise ValueError(
        f"G1/G2 violation: {source_label} 'stats' must be a dict, got {type(stats_obj).__name__}."
    )
  if "results" not in stats_obj:
    raise ValueError(f"G1/G2 violation: {source_label} non-empty 'stats' dict is missing 'results'.")
  results = stats_obj["results"]
  if results is None or results == []:
    return []
  if not isinstance(results, list):
    raise ValueError(f"G1/G2 violation: {source_label} 'stats.results' must be a list.")

  columns: Dict[str, List[Any]] = {}
  for col in results:
    if not isinstance(col, dict) or not isinstance(col.get("column"), str) or not col["column"].strip():
      raise ValueError(
          f"G1/G2 violation: malformed column entry in {source_label} 'stats.results'."
      )
    values = col.get("values")
    if values is None:
      columns[col["column"].strip().lstrip("$")] = []
      continue
    if not isinstance(values, list):
      raise ValueError(
          f"G1/G2 violation: column '{col['column']}' 'values' in {source_label} must be a list."
      )
    col_name = col["column"].strip().lstrip("$")
    columns[col_name] = [_decode_chronicle_cell_strict(cell) for cell in values]

  n_rows = max((len(vals) for vals in columns.values()), default=0)
  if n_rows == 0:
    return []
  for col_name, vals in columns.items():
    if vals and len(vals) != n_rows:
      raise ValueError(
          f"G2 violation:ragged column '{col_name}' length ({len(vals)}) != {n_rows} in {source_label}."
      )
  rows: List[Dict[str, Any]] = []
  for idx in range(n_rows):
    rows.append({name: (vals[idx] if idx < len(vals) else None) for name, vals in columns.items()})
  return rows


def _load_payload_rows_from_file(path: str, flag_name: str) -> Tuple[List[Dict[str, Any]], str]:
  raw_bytes, sha256_hex = _read_required_file_bytes(path, flag_name)
  try:
    text = raw_bytes.decode("utf-8")
  except UnicodeDecodeError as exc:
    raise ValueError(f"G2 violation: {flag_name} is not valid UTF-8: {exc}") from exc

  def _reject_nan_constant(const_str: str) -> Any:
    raise ValueError(f"G2 violation: non-finite JSON constant '{const_str}' in {flag_name}.")

  try:
    parsed = json.loads(text, parse_constant=_reject_nan_constant)
  except json.JSONDecodeError as exc:
    raise ValueError(f"G2 violation: malformed JSON in {flag_name} ('{path}'): {exc}") from exc
  rows = parse_strict_stats_payload(parsed, source_label=flag_name)
  return rows, sha256_hex


def _resolve_column(row: Mapping[str, Any], candidates: Sequence[str], required_label: str) -> str:
  lower_map = {k.lower(): k for k in row.keys()}
  for cand in candidates:
    if cand in row:
      return cand
    if cand.lower() in lower_map:
      return lower_map[cand.lower()]
  raise ValueError(
      f"G2 violation: missing required '{required_label}' column in stats.results "
      f"(expected one of {list(candidates)}, got {sorted(row.keys())})."
  )


def _resolve_optional_column(row: Mapping[str, Any], candidates: Sequence[str]) -> Optional[str]:
  lower_map = {k.lower(): k for k in row.keys()}
  for cand in candidates:
    if cand in row:
      return cand
    if cand.lower() in lower_map:
      return lower_map[cand.lower()]
  return None


def _require_finite_float(val: Any, col_name: str, entity: str) -> float:
  if isinstance(val, list) and len(val) == 1:
    val = val[0]
  if val is None or isinstance(val, bool):
    raise ValueError(f"G2 violation: null or boolean value in required numeric column '{col_name}' for '{entity}'.")
  try:
    fval = float(val)
  except (TypeError, ValueError) as exc:
    raise ValueError(
        f"G2 violation: non-numeric value {val!r} in column '{col_name}' for '{entity}'."
    ) from exc
  if not math.isfinite(fval):
    raise ValueError(f"G2 violation: non-finite float {val!r} in column '{col_name}' for '{entity}'.")
  return fval


def _normalize_bucket_to_utc_day(val: Any, entity: str) -> str:
  if isinstance(val, list) and len(val) == 1:
    val = val[0]
  if val is None or isinstance(val, bool):
    raise ValueError(f"G2 violation: missing day bucket value for entity '{entity}'.")
  if isinstance(val, (int, float)):
    if not math.isfinite(float(val)) or float(val) <= 0.0:
      raise ValueError(f"G2 violation: invalid epoch timestamp {val!r} for entity '{entity}'.")
    return datetime.datetime.fromtimestamp(float(val), tz=datetime.timezone.utc).strftime("%Y-%m-%d")
  s = str(val).strip()
  if re.fullmatch(r"\d+(?:\.\d+)?", s):
    epoch = float(s)
    if epoch <= 0.0:
      raise ValueError(f"G2 violation: invalid epoch timestamp {val!r} for entity '{entity}'.")
    return datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).strftime("%Y-%m-%d")
  if len(s) >= 10 and DAY_RE.match(s[:10]):
    _parse_utc_day(s[:10], "bucket_day")
    return s[:10]
  raise ValueError(f"G2 violation: unrecognized day bucket value {val!r} for entity '{entity}'.")


def _compute_safe_sigma(
    baseline_mean: float,
    baseline_stddev: float,
    metric_name: Optional[str] = None,
    byte_dispersion_floor: Optional[float] = None,
) -> Tuple[float, float]:
  """Computes D8 domain-aware dispersion floor and safe_sigma = max(stddev, floor)."""
  byte_floor = resolve_byte_dispersion_floor(metric_name, byte_dispersion_floor)
  if byte_floor is None and metric_name and "byte" in metric_name.lower():
    byte_floor = 1048576.0
  if byte_floor is not None:
    disp_floor = float(byte_floor)
  else:
    disp_floor = math.sqrt(max(float(baseline_mean), 1.0))
  safe_sigma = max(float(baseline_stddev), disp_floor)
  return disp_floor, safe_sigma


def evaluate_start_anchored_cusum(
    payload_file: str,
    query_file: str,
    start_day: str,
    end_day: str,
    *,
    tier: str = "BALANCED",
    slack_k: float = DEFAULT_SLACK_K,
    threshold_h: Optional[float] = None,
    min_baseline_days: int = DEFAULT_MIN_BASELINE_DAYS,
    metric_name: Optional[str] = None,
    byte_dispersion_floor: Optional[float] = None,
    local_execution_available: bool = True,
) -> Dict[str, Any]:
  """Evaluates <= 14d start-anchored Page CUSUM over raw output from longitudinal_cusum_series_3stage.yl2."""
  assert_local_execution_available(local_execution_available)
  eff_k = _validate_positive_slack(slack_k)
  tier_label, eff_h = resolve_cusum_threshold(tier=tier, threshold_h=threshold_h)
  if int(min_baseline_days) < 1:
    raise ValueError(f"G2 violation: min_baseline_days must be >= 1, got {min_baseline_days}.")
  eff_min_days = int(min_baseline_days)

  calendar_days = _enumerate_calendar_days(
      start_day, end_day, enforce_single_query_14d_cap=True
  )
  calendar_day_set = set(calendar_days)

  _, query_sha256 = _read_required_file_bytes(query_file, "--query-file")
  rows, payload_sha256 = _load_payload_rows_from_file(payload_file, "--payload-file")

  provenance = {
      "helper_version": HELPER_VERSION,
      "mode": "START_ANCHORED_SERIES_LE_14D",
      "query_sha256": query_sha256,
      "payload_sha256": payload_sha256,
  }

  if not rows:
    return {
        "mode": "START_ANCHORED_SERIES_LE_14D",
        "start_day": calendar_days[0],
        "end_day": calendar_days[-1],
        "window_days": len(calendar_days),
        "tier": tier_label,
        "slack_k": eff_k,
        "threshold_h": eff_h,
        "arl_calibration": {
            "arl0_in_control": round(siegmund_arl(eff_h, eff_k, 0.0), 1),
            "arl1_plus_1sigma": round(siegmund_arl(eff_h, eff_k, 1.0), 2),
        },
        "min_baseline_days": eff_min_days,
        "entities": {},
        "alarms": [],
        "immature_entities": [],
        "provenance": provenance,
    }

  sample = rows[0]
  ent_col = _resolve_column(sample, ENTITY_COLUMN_CANDIDATES, "entity")
  ws_col = _resolve_column(sample, BUCKET_COLUMN_CANDIDATES, "day_bucket")
  obs_col = _resolve_column(sample, OBSERVED_COLUMN_CANDIDATES, "observed_val")
  mean_col = _resolve_column(sample, MEAN_COLUMN_CANDIDATES, "baseline_mean")
  std_col = _resolve_column(sample, STDDEV_COLUMN_CANDIDATES, "baseline_stddev")
  days_col = _resolve_column(sample, ACTIVE_DAYS_COLUMN_CANDIDATES, "active_days")
  slack_col = _resolve_optional_column(sample, ("windowed_slack_sum", "cusum_drift_score"))

  grouped: Dict[str, Dict[str, Any]] = {}
  for row in rows:
    raw_ent = row.get(ent_col)
    if isinstance(raw_ent, list) and raw_ent:
      raw_ent = raw_ent[0]
    if raw_ent is None or not str(raw_ent).strip():
      raise ValueError("G2 violation: empty entity identifier in stats.results.")
    ent = str(raw_ent).strip()
    day_str = _normalize_bucket_to_utc_day(row.get(ws_col), ent)
    if day_str not in calendar_day_set:
      raise ValueError(
          f"G2 violation: payload row day '{day_str}' for entity '{ent}' falls outside "
          f"declared window [{calendar_days[0]}..{calendar_days[-1]}]."
      )
    obs_val = _require_finite_float(row.get(obs_col), obs_col, ent)
    mean_val = _require_finite_float(row.get(mean_col), mean_col, ent)
    std_val = _require_finite_float(row.get(std_col), std_col, ent)
    act_days = _require_finite_float(row.get(days_col), days_col, ent)
    w_val = (
        _require_finite_float(row.get(slack_col), slack_col, ent)
        if slack_col and row.get(slack_col) is not None
        else None
    )

    rec = grouped.setdefault(
        ent,
        {
            "baseline_mean": mean_val,
            "baseline_stddev": std_val,
            "active_days": act_days,
            "windowed_slack_sum": w_val,
            "obs_by_day": {},
        },
    )
    rec["active_days"] = max(rec["active_days"], act_days)
    if w_val is not None:
      rec["windowed_slack_sum"] = max(rec["windowed_slack_sum"] or 0.0, w_val)
    # Sum or max duplicate day rows? In match: $entity, $ws by 1d each (entity, day) is unique; guard duplicates:
    if day_str in rec["obs_by_day"]:
      raise ValueError(
          f"G2 violation: duplicate row for entity '{ent}' on UTC day '{day_str}' in start-anchored series."
      )
    rec["obs_by_day"][day_str] = obs_val

  entities_out: Dict[str, Any] = {}
  immature_out: List[Dict[str, Any]] = []

  for ent in sorted(grouped.keys()):
    info = grouped[ent]
    act_days = float(info["active_days"])
    if act_days < float(eff_min_days):
      immature_out.append({
          "entity": ent,
          "active_days": int(act_days),
          "min_baseline_days": eff_min_days,
          "routed_to": "FIRST_SEEN_NOVELTY",
          "reason": (
              f"Active baseline days ({int(act_days)}) < min_baseline_days ({eff_min_days}); "
              "excluded from Page CUSUM and routed to FIRST_SEEN_NOVELTY."
          ),
      })
      continue

    mean_val = float(info["baseline_mean"])
    std_val = float(info["baseline_stddev"])
    disp_floor, safe_sigma = _compute_safe_sigma(
        mean_val, std_val, metric_name=metric_name, byte_dispersion_floor=byte_dispersion_floor
    )

    raw_points: List[TimelinePoint] = []
    for d_str in calendar_days:
      is_quiet = d_str not in info["obs_by_day"]
      obs_d = 0.0 if is_quiet else float(info["obs_by_day"][d_str])
      z_d = (obs_d - mean_val) / safe_sigma
      raw_points.append(
          TimelinePoint(
              day=d_str,
              z_score=round(z_d, 6),
              observed=obs_d,
              baseline_mean=mean_val,
              baseline_stddev=safe_sigma,
          )
      )

    evaluated_pts = calculate_page_cusum_series(raw_points, slack_k=eff_k)
    peak_s = 0.0
    peak_day = calendar_days[0]
    alarm_days: List[str] = []
    series_dicts: List[Dict[str, Any]] = []
    computed_w = 0.0

    for pt in evaluated_pts:
      s_val = float(pt.cusum_pos)
      z_val = float(pt.z_score)
      if pt.day in info["obs_by_day"] and z_val - eff_k > 0.0:
        computed_w += (z_val - eff_k)
      if s_val > peak_s:
        peak_s = s_val
        peak_day = pt.day
      if s_val >= eff_h:
        alarm_days.append(pt.day)
      series_dicts.append({
          "day": pt.day,
          "observed": round(float(pt.observed), 4),
          "reconstructed_zero_day": pt.day not in info["obs_by_day"],
          "z_score": round(z_val, 4),
          "cusum_s_t": round(s_val, 4),
          "z_equivalent": round(
              float(score_to_z_equivalent("cusum_s", s_val, threshold_override=eff_h) or 0.0), 4
          ),
          "cri": int(cri_from_model_score("cusum_s", s_val, threshold_override=eff_h) or 0),
      })

    final_s = float(evaluated_pts[-1].cusum_pos) if evaluated_pts else 0.0
    z_equiv = round(
        float(score_to_z_equivalent("cusum_s", peak_s, threshold_override=eff_h) or 0.0), 4
    )
    cri_score = int(cri_from_model_score("cusum_s", peak_s, threshold_override=eff_h) or 0)
    final_z_equiv = round(
        float(score_to_z_equivalent("cusum_s", final_s, threshold_override=eff_h) or 0.0), 4
    )
    final_cri = int(cri_from_model_score("cusum_s", final_s, threshold_override=eff_h) or 0)

    entities_out[ent] = {
        "entity": ent,
        "active_days": int(act_days),
        "baseline_mean": round(mean_val, 4),
        "baseline_stddev": round(std_val, 4),
        "dispersion_floor": round(disp_floor, 4),
        "safe_sigma": round(safe_sigma, 4),
        "windowed_slack_sum": round(
            info["windowed_slack_sum"] if info["windowed_slack_sum"] is not None else computed_w, 4
        ),
        "peak_s_t": round(peak_s, 4),
        "peak_day": peak_day,
        "final_s_t": round(final_s, 4),
        "alarm": bool(peak_s >= eff_h),
        "onset_day": alarm_days[0] if alarm_days else None,
        "alarm_days": alarm_days,
        "z_equivalent": z_equiv,
        "cri": cri_score,
        "final_z_equivalent": final_z_equiv,
        "final_cri": final_cri,
        "series": series_dicts,
    }

  alarms = sorted(
      (v for v in entities_out.values() if v["alarm"]),
      key=lambda item: (item["peak_s_t"], item["final_s_t"]),
      reverse=True,
  )

  return {
      "mode": "START_ANCHORED_SERIES_LE_14D",
      "start_day": calendar_days[0],
      "end_day": calendar_days[-1],
      "window_days": len(calendar_days),
      "tier": tier_label,
      "slack_k": eff_k,
      "threshold_h": eff_h,
      "arl_calibration": {
          "arl0_in_control": round(siegmund_arl(eff_h, eff_k, 0.0), 1),
          "arl1_plus_1sigma": round(siegmund_arl(eff_h, eff_k, 1.0), 2),
      },
      "min_baseline_days": eff_min_days,
      "entities": entities_out,
      "alarms": alarms,
      "immature_entities": immature_out,
      "provenance": provenance,
  }


def evaluate_multishard_cusum(
    shard_files: Mapping[str, str],
    query_file: str,
    *,
    start_day: Optional[str] = None,
    end_day: Optional[str] = None,
    tier: str = "BALANCED",
    slack_k: float = DEFAULT_SLACK_K,
    threshold_h: Optional[float] = None,
    min_baseline_days: int = DEFAULT_MIN_BASELINE_DAYS,
    metric_name: Optional[str] = None,
    byte_dispersion_floor: Optional[float] = None,
    reset_on: Optional[Sequence[str]] = None,
    reset_after_alarm: bool = False,
    reset_every_days: Optional[int] = None,
    local_execution_available: bool = True,
) -> Dict[str, Any]:
  """Evaluates multi-day (> 14d capable) fixed-reference Page CUSUM across ungated Mode C shards."""
  assert_local_execution_available(local_execution_available)
  eff_k = _validate_positive_slack(slack_k)
  tier_label, eff_h = resolve_cusum_threshold(tier=tier, threshold_h=threshold_h)
  if int(min_baseline_days) < 1:
    raise ValueError(f"G2 violation: min_baseline_days must be >= 1, got {min_baseline_days}.")
  eff_min_days = int(min_baseline_days)

  if reset_every_days is not None and int(reset_every_days) < 1:
    raise ValueError(f"G2 violation: reset_every_days must be >= 1, got {reset_every_days}.")
  eff_reset_every = int(reset_every_days) if reset_every_days is not None else None

  reset_on_set = set()
  for r_day in reset_on or ():
    _parse_utc_day(r_day, "reset_on")
    reset_on_set.add(r_day.strip())

  if not shard_files:
    raise ValueError("G2 violation: at least two daily shards are required for multi-shard CUSUM.")

  _, query_sha256 = _read_required_file_bytes(query_file, "--query-file")

  parsed_shards: Dict[str, List[Dict[str, Any]]] = {}
  shard_hashes: Dict[str, str] = {}
  for day_key, file_path in sorted(shard_files.items()):
    _parse_utc_day(day_key, "shard_day")
    clean_day = day_key.strip()
    rows, s_hash = _load_payload_rows_from_file(file_path, f"--shard {clean_day}")
    parsed_shards[clean_day] = rows
    shard_hashes[clean_day] = s_hash

  sorted_shard_days = sorted(parsed_shards.keys())
  eff_start = start_day.strip() if start_day else sorted_shard_days[0]
  eff_end = end_day.strip() if end_day else sorted_shard_days[-1]
  calendar_days = _enumerate_calendar_days(
      eff_start, eff_end, enforce_single_query_14d_cap=False
  )

  manifest_str = "\n".join(f"{d}:{shard_hashes[d]}" for d in sorted(shard_hashes))
  payload_sha256 = hashlib.sha256(manifest_str.encode("utf-8")).hexdigest()

  provenance = {
      "helper_version": HELPER_VERSION,
      "mode": "MULTISHARD_FIXED_REFERENCE",
      "query_sha256": query_sha256,
      "payload_sha256": payload_sha256,
      "shard_sha256": shard_hashes,
  }

  # Collect per-(entity, day) records across all supplied shards within [eff_start, eff_end]
  calendar_day_set = set(calendar_days)
  per_entity_days: Dict[str, Dict[str, Dict[str, Any]]] = {}

  for s_day, rows in sorted(parsed_shards.items()):
    if s_day not in calendar_day_set or not rows:
      continue
    sample = rows[0]
    ent_col = _resolve_column(sample, ENTITY_COLUMN_CANDIDATES, "entity")
    obs_col = _resolve_column(sample, OBSERVED_COLUMN_CANDIDATES, "observed_val")
    mean_col = _resolve_column(sample, MEAN_COLUMN_CANDIDATES, "baseline_mean")
    std_col = _resolve_column(sample, STDDEV_COLUMN_CANDIDATES, "baseline_stddev")
    days_col = _resolve_column(sample, ACTIVE_DAYS_COLUMN_CANDIDATES, "active_days")
    sum_col = _resolve_optional_column(sample, HIST_SUM_COLUMN_CANDIDATES)

    for row in rows:
      raw_ent = row.get(ent_col)
      if isinstance(raw_ent, list) and raw_ent:
        raw_ent = raw_ent[0]
      if raw_ent is None or not str(raw_ent).strip():
        raise ValueError(f"G2 violation: empty entity identifier in shard {s_day}.")
      ent = str(raw_ent).strip()
      obs_val = _require_finite_float(row.get(obs_col), obs_col, ent)
      mean_val = _require_finite_float(row.get(mean_col), mean_col, ent)
      std_val = _require_finite_float(row.get(std_col), std_col, ent)
      act_days = _require_finite_float(row.get(days_col), days_col, ent)
      h_sum = (
          _require_finite_float(row.get(sum_col), sum_col, ent)
          if sum_col and row.get(sum_col) is not None
          else None
      )
      ent_map = per_entity_days.setdefault(ent, {})
      if s_day in ent_map:
        raise ValueError(f"G2 violation: duplicate entity '{ent}' row in shard {s_day}.")
      ent_map[s_day] = {
          "observed": obs_val,
          "active_avg": mean_val,
          "active_sd": std_val,
          "active_days": act_days,
          "historical_sum": h_sum,
      }

  entities_out: Dict[str, Any] = {}
  immature_out: List[Dict[str, Any]] = []

  def _calendar_ref_from_rec(rec: Mapping[str, Any]) -> Tuple[float, float, float]:
    cal_stats = rebuild_calendar_day_stats(
        active_days=float(rec["active_days"]),
        active_avg=float(rec["active_avg"]),
        active_sd=float(rec["active_sd"]),
        historical_sum=rec.get("historical_sum"),
        window_days=30.0,
    )
    cal_mu = float(cal_stats["mu_cal"])
    cal_sd = float(cal_stats["sd_cal"])
    _, safe_sd = _compute_safe_sigma(
        cal_mu, cal_sd, metric_name=metric_name, byte_dispersion_floor=byte_dispersion_floor
    )
    return cal_mu, cal_sd, safe_sd

  for ent in sorted(per_entity_days.keys()):
    day_records = per_entity_days[ent]
    earliest_day = sorted(day_records.keys())[0]
    anchor_rec = day_records[earliest_day]
    anchor_active_days = float(anchor_rec["active_days"])
    if anchor_active_days < float(eff_min_days):
      immature_out.append({
          "entity": ent,
          "anchor_day": earliest_day,
          "active_days": int(anchor_active_days),
          "min_baseline_days": eff_min_days,
          "routed_to": "FIRST_SEEN_NOVELTY",
          "reason": (
              f"Anchor shard {earliest_day} active_days ({int(anchor_active_days)}) < "
              f"min_baseline_days ({eff_min_days}); excluded from Page CUSUM."
          ),
      })
      continue

    ref_day = earliest_day
    mu_cal_ref, sd_cal_ref, safe_sd_cal_ref = _calendar_ref_from_rec(anchor_rec)

    s_t = 0.0
    peak_s = 0.0
    peak_day = calendar_days[0]
    alarm_days: List[str] = []
    resets_applied: List[Dict[str, Any]] = []
    series_dicts: List[Dict[str, Any]] = []
    prev_day_alarmed = False

    for idx, d_str in enumerate(calendar_days):
      reset_reasons: List[str] = []
      if idx > 0 and d_str in reset_on_set:
        reset_reasons.append("scheduled_date")
      if idx > 0 and eff_reset_every is not None and (idx % eff_reset_every == 0):
        reset_reasons.append(f"periodic_{eff_reset_every}d")
      if idx > 0 and reset_after_alarm and prev_day_alarmed:
        reset_reasons.append("post_alarm")

      if reset_reasons:
        s_t = 0.0
        refreshed = False
        if d_str in day_records and float(day_records[d_str]["active_days"]) >= float(eff_min_days):
          mu_cal_ref, sd_cal_ref, safe_sd_cal_ref = _calendar_ref_from_rec(day_records[d_str])
          ref_day = d_str
          refreshed = True
        resets_applied.append({
            "day": d_str,
            "reasons": reset_reasons,
            "reference_refreshed": refreshed,
            "reference_anchor_day": ref_day,
            "mu_cal_ref": round(mu_cal_ref, 4),
            "safe_sd_cal_ref": round(safe_sd_cal_ref, 4),
        })

      is_quiet = d_str not in day_records
      obs_d = 0.0 if is_quiet else float(day_records[d_str]["observed"])
      z_d = (obs_d - mu_cal_ref) / safe_sd_cal_ref
      s_t = max(0.0, s_t + z_d - eff_k)

      if s_t > peak_s:
        peak_s = s_t
        peak_day = d_str
      day_alarm = s_t >= eff_h
      if day_alarm:
        alarm_days.append(d_str)
      prev_day_alarmed = day_alarm

      series_dicts.append({
          "day": d_str,
          "observed": round(obs_d, 4),
          "reconstructed_zero_day": is_quiet,
          "reference_anchor_day": ref_day,
          "mu_cal_ref": round(mu_cal_ref, 4),
          "safe_sd_cal_ref": round(safe_sd_cal_ref, 4),
          "z_score": round(z_d, 4),
          "cusum_s_t": round(s_t, 4),
          "z_equivalent": round(
              float(score_to_z_equivalent("cusum_s", s_t, threshold_override=eff_h) or 0.0), 4
          ),
          "cri": int(cri_from_model_score("cusum_s", s_t, threshold_override=eff_h) or 0),
      })

    z_equiv = round(
        float(score_to_z_equivalent("cusum_s", peak_s, threshold_override=eff_h) or 0.0), 4
    )
    cri_score = int(cri_from_model_score("cusum_s", peak_s, threshold_override=eff_h) or 0)
    final_z_equiv = round(
        float(score_to_z_equivalent("cusum_s", s_t, threshold_override=eff_h) or 0.0), 4
    )
    final_cri = int(cri_from_model_score("cusum_s", s_t, threshold_override=eff_h) or 0)

    entities_out[ent] = {
        "entity": ent,
        "initial_reference_day": earliest_day,
        "final_reference_day": ref_day,
        "active_days": int(anchor_active_days),
        "mu_cal_ref": round(mu_cal_ref, 4),
        "sd_cal_ref": round(sd_cal_ref, 4),
        "safe_sd_cal_ref": round(safe_sd_cal_ref, 4),
        "peak_s_t": round(peak_s, 4),
        "peak_day": peak_day,
        "final_s_t": round(s_t, 4),
        "alarm": bool(peak_s >= eff_h),
        "onset_day": alarm_days[0] if alarm_days else None,
        "alarm_days": alarm_days,
        "resets_applied": resets_applied,
        "z_equivalent": z_equiv,
        "cri": cri_score,
        "final_z_equivalent": final_z_equiv,
        "final_cri": final_cri,
        "series": series_dicts,
    }

  alarms = sorted(
      (v for v in entities_out.values() if v["alarm"]),
      key=lambda item: (item["peak_s_t"], item["final_s_t"]),
      reverse=True,
  )

  return {
      "mode": "MULTISHARD_FIXED_REFERENCE",
      "start_day": calendar_days[0],
      "end_day": calendar_days[-1],
      "window_days": len(calendar_days),
      "shards_supplied": len(parsed_shards),
      "tier": tier_label,
      "slack_k": eff_k,
      "threshold_h": eff_h,
      "arl_calibration": {
          "arl0_in_control": round(siegmund_arl(eff_h, eff_k, 0.0), 1),
          "arl1_plus_1sigma": round(siegmund_arl(eff_h, eff_k, 1.0), 2),
      },
      "min_baseline_days": eff_min_days,
      "entities": entities_out,
      "alarms": alarms,
      "immature_entities": immature_out,
      "provenance": provenance,
  }


def render_cusum_markdown(report: Mapping[str, Any]) -> str:
  """Renders a deterministic Markdown report including the D6-G3 Provenance Appendix."""
  arl = report.get("arl_calibration", {})
  lines = [
      f"### Page One-Sided CUSUM Sequential Drift Report (`{report['start_day']}` → `{report['end_day']}`, `{report['window_days']}d`)",
      "",
      f"* **Execution Mode**: `{report['mode']}`",
      f"* **Sensitivity & ARL Calibration**: `{report['tier']}` (`k = {report['slack_k']}`, `h = {report['threshold_h']}`, "
      f"`ARL0 ≈ {arl.get('arl0_in_control', 'N/A')}d`, `ARL1(+1σ) ≈ {arl.get('arl1_plus_1sigma', 'N/A')}d`)",
      f"* **Maturity Gate**: `active_days >= {report['min_baseline_days']}` (immature entities routed to `FIRST_SEEN_NOVELTY`)",
      "",
  ]

  entities = report.get("entities", {})
  if not entities:
    lines.append("*(Nominal — zero mature prefilter-surviving entities in window.)*")
    lines.append("")
  else:
    lines.extend([
        "| Entity | Status | Peak S_t | Peak Day | Final S_t | Onset Day | Z-Equiv | CRI (0-100) |",
        "| :--- | :--- | ---: | :--- | ---: | :--- | ---: | ---: |",
    ])
    ranked = sorted(
        entities.values(),
        key=lambda e: (1 if e["alarm"] else 0, e["peak_s_t"], e["final_s_t"]),
        reverse=True,
    )
    for ent in ranked:
      status = "ALARM" if ent["alarm"] else "BELOW_H"
      onset = ent["onset_day"] or "—"
      cri_str = format_cri(ent["cri"])
      lines.append(
          f"| `{ent['entity']}` | **{status}** | `{ent['peak_s_t']:.2f}` | `{ent['peak_day']}` | "
          f"`{ent['final_s_t']:.2f}` | `{onset}` | `{ent['z_equivalent']:.2f}` | **`{cri_str}`** |"
      )
    lines.append("")

  immature = report.get("immature_entities", [])
  if immature:
    lines.append("#### Immature Baseline Entities (Excluded from CUSUM → `FIRST_SEEN_NOVELTY`)")
    lines.append("")
    for item in immature:
      lines.append(
          f"* `{item['entity']}` (`active_days = {item['active_days']} < {item['min_baseline_days']}`) → `{item['routed_to']}`"
      )
    lines.append("")

  prov = report.get("provenance", {})
  lines.extend([
      "### Provenance Appendix",
      "",
      f"* `helper_version`: `{prov.get('helper_version', HELPER_VERSION)}`",
      f"* `query_sha256`: `{prov.get('query_sha256', 'N/A')}`",
      f"* `payload_sha256`: `{prov.get('payload_sha256', 'N/A')}`",
  ])
  if "shard_sha256" in prov and isinstance(prov["shard_sha256"], Mapping):
    lines.append(f"* `shard_count`: `{len(prov['shard_sha256'])}`")
  return "\n".join(lines) + "\n"


def _execute_live_udm_search_to_file(
    query_file: str,
    start_day: str,
    end_day: str,
    output_payload_path: str,
    *,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    project_id: Optional[str] = None,
    credentials_file: Optional[str] = None,
) -> None:
  """Executes --query-file via Google SecOps REST udmSearch using service-account credentials."""
  raw_q, _ = _read_required_file_bytes(query_file, "--query-file")
  query_text = raw_q.decode("utf-8")
  calendar_days = _enumerate_calendar_days(start_day, end_day, enforce_single_query_14d_cap=True)
  start_iso = f"{calendar_days[0]}T00:00:00Z"
  end_dt = _parse_utc_day(calendar_days[-1], "end_day") + datetime.timedelta(days=1)
  end_iso = f"{end_dt.isoformat()}T00:00:00Z"

  eff_creds = credentials_file or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
  eff_customer = customer_id or os.environ.get("CHRONICLE_CUSTOMER_ID") or os.environ.get("SECOPS_CUSTOMER_ID")
  eff_project = project_id or os.environ.get("CHRONICLE_PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT")
  eff_region = (region or os.environ.get("CHRONICLE_REGION") or "us").strip()

  if not eff_creds or not os.path.isfile(eff_creds):
    raise ValueError(
        "G2 violation: --run-query requires service-account credentials via --credentials-file or "
        "GOOGLE_APPLICATION_CREDENTIALS."
    )
  if not eff_customer or not eff_project:
    raise ValueError(
        "G2 violation: --run-query requires --customer-id and --project-id (or CHRONICLE_CUSTOMER_ID / "
        "CHRONICLE_PROJECT_ID)."
    )

  from google.auth.transport.requests import AuthorizedSession  # type: ignore[import-not-found]
  from google.oauth2 import service_account  # type: ignore[import-not-found]

  creds = service_account.Credentials.from_service_account_file(
      eff_creds, scopes=["https://www.googleapis.com/auth/cloud-platform"]
  )
  session = AuthorizedSession(creds)
  host = f"{eff_region}-chronicle.googleapis.com"
  url = (
      f"https://{host}/v1alpha/projects/{eff_project}/locations/{eff_region}/"
      f"instances/{eff_customer}:udmSearch"
  )
  resp = session.get(
      url,
      params={
          "query": query_text,
          "timeRange.startTime": start_iso,
          "timeRange.endTime": end_iso,
      },
      timeout=120,
  )
  if resp.status_code != 200:
    raise ValueError(f"G2 violation: live udmSearch failed ({resp.status_code}): {resp.text[:300]}")
  Path(output_payload_path).write_bytes(resp.content)


def _parse_shard_cli_spec(spec: str) -> Tuple[str, str]:
  if "=" not in spec:
    raise ValueError(f"G2 violation: --shard must be YYYY-MM-DD=<file_path>, got {spec!r}.")
  day_part, _, path_part = spec.partition("=")
  clean_day = day_part.strip()
  _parse_utc_day(clean_day, "--shard day")
  clean_path = _reject_inline_cli_value(path_part, f"--shard {clean_day}")
  return clean_day, clean_path


def main(argv: Optional[Sequence[str]] = None) -> int:
  parser = argparse.ArgumentParser(
      description="Vetted Page One-Sided CUSUM Helper over raw Chronicle udm_search JSON payloads (WS6-01)."
  )
  parser.add_argument("--payload-file", help="Path to raw udm_search JSON payload (<= 14d series mode)")
  parser.add_argument(
      "--shard",
      action="append",
      default=[],
      help="YYYY-MM-DD=<path> raw udm_search JSON shard file (repeatable; > 14d fixed-reference mode)",
  )
  parser.add_argument("--query-file", help="Path to the executed YARA-L query file (required per D6-G2/G3)")
  parser.add_argument("--start-day", help="Inclusive UTC start day YYYY-MM-DD")
  parser.add_argument("--end-day", help="Inclusive UTC end day YYYY-MM-DD")
  parser.add_argument(
      "--tier",
      default="BALANCED",
      choices=["HIGH_RECALL", "BALANCED", "HIGH_PRECISION"],
      help="ARL-calibrated sensitivity tier (HIGH_RECALL=3.0, BALANCED=4.0, HIGH_PRECISION=5.0)",
  )
  parser.add_argument("--slack-k", type=float, default=DEFAULT_SLACK_K, help="Page CUSUM slack k (default 0.5)")
  parser.add_argument("--threshold-h", type=float, default=None, help="Explicit alarm threshold h override")
  parser.add_argument(
      "--min-baseline-days",
      type=int,
      default=DEFAULT_MIN_BASELINE_DAYS,
      help="Minimum active baseline days required for maturity (default 7)",
  )
  parser.add_argument("--metric", default=None, help="Optional metric name for byte dispersion floor")
  parser.add_argument(
      "--reset-on",
      action="append",
      default=[],
      help="UTC day YYYY-MM-DD on which to reset S_t and refresh reference (repeatable; multi-shard mode)",
  )
  parser.add_argument(
      "--reset-after-alarm",
      action="store_true",
      help="Reset S_t (and refresh reference if mature) on the day following an alarm (multi-shard mode)",
  )
  parser.add_argument(
      "--reset-every-days",
      type=int,
      default=None,
      help="Periodic reference reset interval in days (multi-shard mode)",
  )
  parser.add_argument("--run-query", action="store_true", help="Execute --query-file via Chronicle REST API")
  parser.add_argument("--customer-id", default=None, help="Chronicle customer ID (for --run-query)")
  parser.add_argument("--project-id", default=None, help="GCP project ID (for --run-query)")
  parser.add_argument("--region", default=None, help="Chronicle region (for --run-query)")
  parser.add_argument("--credentials-file", default=None, help="Service-account JSON file (for --run-query)")
  parser.add_argument(
      "--scores",
      default=None,
      help="PROHIBITED (D6-G1): raw CLI scores are rejected.",
  )
  parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
  parser.add_argument("--output", default=None, help="Optional output file path")

  args = parser.parse_args(list(argv) if argv is not None else None)

  try:
    if args.scores is not None:
      raise ValueError(
          "G1 violation: --scores / hand-typed numbers are prohibited; pass --payload-file or --shard."
      )
    if not args.query_file or not args.query_file.strip():
      raise ValueError("G2 violation: --query-file is required for provenance and input validation.")
    if args.payload_file and args.shard:
      raise ValueError("G2 violation: pass either --payload-file (<= 14d) or --shard (multi-shard), not both.")
    if not args.payload_file and not args.shard and not args.run_query:
      raise ValueError("G2 violation: either --payload-file or --shard is required.")

    if args.run_query:
      if not args.start_day or not args.end_day:
        raise ValueError("G2 violation: --start-day and --end-day are required with --run-query.")
      target_payload = args.payload_file or os.path.join(
          os.path.dirname(os.path.abspath(args.query_file)), "cusum_live_payload.json"
      )
      _execute_live_udm_search_to_file(
          query_file=args.query_file,
          start_day=args.start_day,
          end_day=args.end_day,
          output_payload_path=target_payload,
          customer_id=args.customer_id,
          region=args.region,
          project_id=args.project_id,
          credentials_file=args.credentials_file,
      )
      args.payload_file = target_payload

    if args.payload_file:
      if not args.start_day or not args.end_day:
        raise ValueError(
            "G2 violation: --start-day and --end-day are required in --payload-file series mode."
        )
      report = evaluate_start_anchored_cusum(
          payload_file=args.payload_file,
          query_file=args.query_file,
          start_day=args.start_day,
          end_day=args.end_day,
          tier=args.tier,
          slack_k=args.slack_k,
          threshold_h=args.threshold_h,
          min_baseline_days=args.min_baseline_days,
          metric_name=args.metric,
      )
    else:
      shard_map: Dict[str, str] = {}
      for spec in args.shard:
        d_str, p_str = _parse_shard_cli_spec(spec)
        if d_str in shard_map:
          raise ValueError(f"G2 violation: duplicate --shard day '{d_str}'.")
        shard_map[d_str] = p_str
      report = evaluate_multishard_cusum(
          shard_files=shard_map,
          query_file=args.query_file,
          start_day=args.start_day,
          end_day=args.end_day,
          tier=args.tier,
          slack_k=args.slack_k,
          threshold_h=args.threshold_h,
          min_baseline_days=args.min_baseline_days,
          metric_name=args.metric,
          reset_on=args.reset_on,
          reset_after_alarm=args.reset_after_alarm,
          reset_every_days=args.reset_every_days,
      )
  except (ValueError, OSError) as exc:
    print(f"ERROR: {exc}", file=sys.stderr)
    return 2

  rendered = json.dumps(report, indent=2) if args.format == "json" else render_cusum_markdown(report)
  if args.output:
    with open(args.output, "w", encoding="utf-8") as f:
      f.write(rendered)
  print(rendered, end="" if rendered.endswith("\n") else "\n")
  return 0


if __name__ == "__main__":
  sys.exit(main())
