# Template Router for Multi-Stage YARA-L Queries (.yl2)

__author__ = "Greg Kushmerek"
__version__ = "2.3.0"

import datetime
import math
from pathlib import Path
import re
import statistics
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from . import malachite_catalog as mc
from .preflight_validator import (
    KillChainArchetype,
    METRIC_CATALOG,
    EntityType,
    MalachiteASTValidator,
    MatchMode,
    PF10_SUPPORTED_HOURLY_TODAY_METRICS,
    PF11_POPULATED_FIRST_SEEN_METRICS,
    PipelineArchitecture,
    PreFlightValidator,
    RETIRED_PIPELINE_ARCHITECTURES,
    RETIRED_STATISTICAL_MODELS,
    StatisticalModel,
)
from .ueba_constants import (
    DEFAULT_ANOMALY_THRESHOLD,
    DEFAULT_FOLD_CHANGE_THRESHOLD,
    DEFAULT_FUSION_THRESHOLD_SQ,
    DEFAULT_MIN_BASELINE_DAYS,
    DEFAULT_ROBUST_THRESHOLD,
)

DEFAULT_TUKEY_EXCESS_THRESHOLD = 1.0
DEFAULT_GAMMA_PRIOR_ALPHA0 = 0.5
DEFAULT_GAMMA_PRIOR_BETA0 = 0.1
DEFAULT_BETA_PRIOR_ALPHA0 = 1.0
DEFAULT_BETA_PRIOR_BETA0 = 19.0
DEFAULT_MIN_AWAKENING_VOLUME = 25
DEFAULT_TENANT_TZ = "UTC"
DEFAULT_BIZ_START_HOUR = 8
DEFAULT_BIZ_END_HOUR = 18


def normalize_learned_active_hours(learned_active_hours: Optional[Any]) -> Optional[Tuple[List[int], bool]]:
  """Normalizes optional WS5-HOD (HOUR_OF_DAY_PROFILE) learned active-hour schedules (0..23)."""
  if learned_active_hours is None:
    return None
  weekdays_only = False
  raw_items: Any = learned_active_hours
  if isinstance(learned_active_hours, dict):
    weekdays_only = bool(learned_active_hours.get("weekdays_only", False))
    if "active_hours" in learned_active_hours:
      raw_items = learned_active_hours["active_hours"]
    elif "learned_active_hours" in learned_active_hours:
      raw_items = learned_active_hours["learned_active_hours"]
    else:
      raw_items = [
          k for k, v in learned_active_hours.items()
          if k != "weekdays_only" and float(v) > 0.0
      ]
  hours: List[int] = []
  for item in raw_items:
    if isinstance(item, bool):
      raise ValueError(f"Invalid hour '{item}' in learned_active_hours; expected int in 0..23.")
    h = int(item)
    if h < 0 or h > 23:
      raise ValueError(f"learned_active_hours entry {h} out of valid 0..23 range.")
    hours.append(h)
  return (sorted(set(hours)), weekdays_only)


def _compact_hour_runs(hours: Sequence[int]) -> List[Tuple[int, int]]:
  """Compacts sorted unique integer hours (0..23) into inclusive (lo, hi) contiguous runs."""
  if not hours:
    return []
  runs: List[Tuple[int, int]] = []
  lo = hi = int(hours[0])
  for h_raw in hours[1:]:
    h = int(h_raw)
    if h == hi + 1:
      hi = h
    else:
      runs.append((lo, hi))
      lo = hi = h
  runs.append((lo, hi))
  return runs


def _build_in_schedule_condition(
    biz_start_hour: int,
    biz_end_hour: int,
    learned_active_hours: Optional[Any],
) -> Optional[str]:
  """Builds the Stage-1 YARA-L boolean condition for in-schedule events (or None / 'ALL_ACTIVE')."""
  if learned_active_hours is not None:
    norm = normalize_learned_active_hours(learned_active_hours)
    assert norm is not None
    hrs, weekdays_only = norm
    if not hrs:
      return None
    if len(hrs) == 24:
      return "$dow >= 2 and $dow <= 6" if weekdays_only else "ALL_ACTIVE"
    runs = _compact_hour_runs(hrs)
    parts: List[str] = []
    for lo, hi in runs:
      if lo == hi:
        parts.append(f"$hour = {lo}")
      elif len(runs) == 1 and not weekdays_only:
        parts.append(f"$hour >= {lo} and $hour <= {hi}")
      else:
        parts.append(f"($hour >= {lo} and $hour <= {hi})")
    if len(parts) == 1:
      hr_expr = parts[0]
    else:
      hr_expr = "(" + " or ".join(parts) + ")"
    if weekdays_only:
      return f"$dow >= 2 and $dow <= 6 and {hr_expr}"
    return hr_expr

  if isinstance(biz_start_hour, bool) or isinstance(biz_end_hour, bool):
    raise ValueError("biz_start_hour and biz_end_hour must be integers.")
  s = int(biz_start_hour)
  e = int(biz_end_hour)
  if s < 0 or s > 23 or e < 0 or e > 24:
    raise ValueError(
        f"Business hours out of bounds: biz_start_hour={s} (expected 0..23), biz_end_hour={e} (expected 0..24)."
    )
  if s == e:
    return None
  if s == 0 and e == 24:
    return "$dow >= 2 and $dow <= 6"
  if s < e:
    return f"$dow >= 2 and $dow <= 6 and $hour >= {s} and $hour < {e}"
  return f"$dow >= 2 and $dow <= 6 and ($hour >= {s} or $hour < {e})"


def resolve_beta_binomial_pair(metric_name: str) -> Tuple[str, str]:
  """Resolves a paired `(*_fail, *_total)` count family for BAYESIAN_BETA_BINOMIAL or raises ValueError."""
  if metric_name in METRIC_CATALOG and metric_name.endswith(("_fail", "_total", "_success")):
    prefix = metric_name.rsplit("_", 1)[0]
    fail_m = f"{prefix}_fail"
    total_m = f"{prefix}_total"
    if fail_m in METRIC_CATALOG and total_m in METRIC_CATALOG:
      return (fail_m, total_m)
  raise ValueError(
      f"Statistical model 'BAYESIAN_BETA_BINOMIAL' applies only to paired *_fail / *_total count "
      f"families (auth_attempts_*, dns_queries_*, http_queries_*, file_executions_*, resource_*); "
      f"'{metric_name}' is unpaired."
  )


def _iter_payload_rows(payload: Any) -> List[Dict[str, Any]]:
  """Extracts flat row dicts from either a list of dicts or a Chronicle udm_search stats envelope."""
  if isinstance(payload, list):
    return [r for r in payload if isinstance(r, dict)]
  if isinstance(payload, dict):
    if isinstance(payload.get("rows"), list):
      return [r for r in payload["rows"] if isinstance(r, dict)]
    results = payload.get("stats", {}).get("results")
    if isinstance(results, list) and results:
      cols: Dict[str, List[Any]] = {}
      max_len = 0
      for col in results:
        if not isinstance(col, dict):
          continue
        cname = str(col.get("column", "")).lstrip("$")
        vals = []
        for cell in col.get("values", []) or []:
          vdict = cell.get("value", cell) if isinstance(cell, dict) else cell
          if isinstance(vdict, dict):
            val = next(iter(vdict.values()), None) if vdict else None
          else:
            val = vdict
          vals.append(val)
        cols[cname] = vals
        max_len = max(max_len, len(vals))
      out: List[Dict[str, Any]] = []
      for idx in range(max_len):
        out.append({k: (v[idx] if idx < len(v) else None) for k, v in cols.items()})
      return out
  return []


def fit_gamma_prior_from_fleet(
    payload: Any,
    default_alpha0: float = DEFAULT_GAMMA_PRIOR_ALPHA0,
    default_beta0: float = DEFAULT_GAMMA_PRIOR_BETA0,
) -> Tuple[float, float]:
  """Fits Empirical Bayes Gamma(alpha0, beta0) hyperparameters to fleet entity daily rates (S / 30)."""
  rows = _iter_payload_rows(payload)
  rates: List[float] = []
  for row in rows:
    rate: Optional[float] = None
    for sum_key in ("hist_sum", "historical_sum", "sum_30d", "s"):
      if row.get(sum_key) is not None:
        try:
          rate = float(row[sum_key]) / 30.0
          break
        except (TypeError, ValueError):
          pass
    if rate is None:
      for rate_key in ("mu_cal", "rate", "daily_rate"):
        if row.get(rate_key) is not None:
          try:
            rate = float(row[rate_key])
            break
          except (TypeError, ValueError):
            pass
    if rate is None and row.get("active_days") is not None and row.get("hist_avg") is not None:
      try:
        rate = (float(row["active_days"]) * float(row["hist_avg"])) / 30.0
      except (TypeError, ValueError):
        pass
    if rate is not None and math.isfinite(rate) and rate >= 0.0:
      rates.append(rate)
  if len(rates) < 2:
    return (float(default_alpha0), float(default_beta0))
  mean_r = statistics.mean(rates)
  var_r = statistics.variance(rates)
  if mean_r <= 0.0 or var_r <= 0.0 or not math.isfinite(var_r):
    return (float(default_alpha0), float(default_beta0))
  beta0 = max(round(mean_r / var_r, 6), 0.01)
  alpha0 = max(round(mean_r * beta0, 6), 0.01)
  return (alpha0, beta0)


def fit_beta_prior_from_fleet(
    payload: Any,
    default_alpha0: float = DEFAULT_BETA_PRIOR_ALPHA0,
    default_beta0: float = DEFAULT_BETA_PRIOR_BETA0,
) -> Tuple[float, float]:
  """Fits Empirical Bayes Beta(alpha0, beta0) hyperparameters to fleet entity failure proportions."""
  rows = _iter_payload_rows(payload)
  props: List[float] = []
  if not rows and isinstance(payload, (list, tuple)):
    for item in payload:
      try:
        val = float(item)
        if math.isfinite(val) and 0.0 <= val <= 1.0:
          props.append(val)
      except (TypeError, ValueError):
        pass
  for row in rows:
    fail_v: Optional[float] = None
    total_v: Optional[float] = None
    for fk in ("hist_fail_sum", "fail_sum", "historical_fail_sum", "failures", "obs_fail"):
      if row.get(fk) is not None:
        try:
          fail_v = float(row[fk])
          break
        except (TypeError, ValueError):
          pass
    for tk in ("hist_total_sum", "total_sum", "historical_total_sum", "attempts", "obs_total"):
      if row.get(tk) is not None:
        try:
          total_v = float(row[tk])
          break
        except (TypeError, ValueError):
          pass
    prop: Optional[float] = None
    if fail_v is not None and total_v is not None and total_v > 0.0:
      prop = min(1.0, max(0.0, fail_v / total_v))
    else:
      for rk in ("fail_rate", "prior_fail_rate", "p", "proportion"):
        if row.get(rk) is not None:
          try:
            cand = float(row[rk])
            if math.isfinite(cand) and 0.0 <= cand <= 1.0:
              prop = cand
              break
          except (TypeError, ValueError):
            pass
    if prop is not None and math.isfinite(prop):
      props.append(prop)
  if len(props) < 2:
    return (float(default_alpha0), float(default_beta0))
  mean_p = statistics.mean(props)
  if mean_p <= 0.0 or mean_p >= 1.0:
    return (float(default_alpha0), float(default_beta0))
  var_p = statistics.variance(props)
  bernoulli_var = mean_p * (1.0 - mean_p)
  if not math.isfinite(var_p) or var_p <= 1e-9 or var_p >= bernoulli_var:
    conc = 20.0
  else:
    conc = max(1.0, min(200.0, (bernoulli_var / var_p) - 1.0))
  alpha0 = max(round(mean_p * conc, 6), 0.1)
  beta0 = max(round((1.0 - mean_p) * conc, 6), 0.1)
  return (alpha0, beta0)

# D8 / WS1-04: Per-metric fleet byte dispersion floors (median mature-entity stddev in bytes).
DEFAULT_FLEET_BYTE_DISPERSION_FLOORS: Dict[str, float] = {
    "network_bytes_outbound": 44979.0,
    "dns_bytes_outbound": 50450.0,
    "network_bytes_total": 303176.0,
    "network_bytes_inbound": 28276845.0,
    "workspace_network_bytes_outbound": 10240.0,
    "workspace_network_bytes_total": 10240.0,
}


def resolve_byte_dispersion_floor(
    metric_name: Optional[str],
    byte_dispersion_floor: Optional[float] = None,
) -> Optional[float]:
  """Resolves the per-metric byte dispersion floor (or caller override) for value_sum metrics."""
  if byte_dispersion_floor is not None:
    return float(byte_dispersion_floor)
  if not metric_name:
    return None
  if metric_name in DEFAULT_FLEET_BYTE_DISPERSION_FLOORS:
    return DEFAULT_FLEET_BYTE_DISPERSION_FLOORS[metric_name]
  try:
    if mc.baseline_semantics(metric_name).metric_arg == "value_sum":
      return 10240.0
  except Exception:  # pylint: disable=broad-exception-caught
    pass
  return None


def _apply_byte_dispersion_floor(
    rendered: str,
    metric_name: Optional[str],
    byte_dispersion_floor: Optional[float] = None,
    floor_vars: Sequence[str] = ("$dispersion_floor", "$personal_floor"),
) -> str:
  """Replaces count sqrt(max(avg, 1.0)) dispersion floor assignments with the byte floor on byte metrics."""
  floor = resolve_byte_dispersion_floor(metric_name, byte_dispersion_floor)
  if floor is None:
    return rendered
  out = rendered
  for var in floor_vars:
    escaped = re.escape(var.lstrip("$"))
    out = re.sub(
        rf"(\${escaped}\s*=\s*)math\.sqrt\([^\n]+\)",
        rf"\g<1>{floor}",
        out,
    )
  return out


def build_byte_dispersion_floor_probe(
    metric_name: str,
    entity_type: EntityType = EntityType.ASSET,
    entity_field: Optional[str] = None,
    min_baseline_days: int = DEFAULT_MIN_BASELINE_DAYS,
) -> str:
  """Builds a read-only 2-stage YARA-L probe to measure the tenant fleet byte stddev distribution."""
  audit = PreFlightValidator.audit(
      target_metric=metric_name,
      entity_type=entity_type,
      min_baseline_days=min_baseline_days,
      identifier_field=entity_field,
  )
  target_field = audit["target_field"]
  metric_arg = audit["metric_arg"]
  filter_block = "\n    ".join(audit["event_filter"])
  return (
      f"// Goal: Fleet byte dispersion floor probe for {metric_name}\n"
      "stage stage1_probe {\n"
      f"    {filter_block}\n"
      f"    {target_field} = $entity\n"
      "    $entity != \"\"\n\n"
      "  match:\n"
      "    $entity by 1d\n\n"
      "  outcome:\n"
      f"    $hist_stddev = max(metrics.{metric_name}(\n"
      f"        period: 1d, window: 30d, metric: {metric_arg}, agg: stddev,\n"
      f"        {target_field}: {target_field}\n"
      "    ))\n"
      f"    $active_days = max(metrics.{metric_name}(\n"
      f"        period: 1d, window: 30d, metric: {metric_arg}, agg: num_metric_periods,\n"
      f"        {target_field}: {target_field}\n"
      "    ))\n"
      "}\n\n"
      "$entity = $stage1_probe.entity\n\n"
      "match:\n"
      "  $entity\n\n"
      "outcome:\n"
      "  $hist_stddev = max($stage1_probe.hist_stddev)\n"
      "  $active_days = max($stage1_probe.active_days)\n\n"
      "condition:\n"
      f"  $active_days >= {int(min_baseline_days)} and $hist_stddev > 0.0\n\n"
      "order:\n"
      "  $hist_stddev asc\n"
  )


def _extract_probe_rows(payload: Any) -> List[Dict[str, Any]]:
  """Extracts normalized row dicts from either a list of dicts or a SecOps stats.results payload."""
  if isinstance(payload, list):
    return [r for r in payload if isinstance(r, dict)]
  if not isinstance(payload, dict):
    return []
  cols = (payload.get("stats") or {}).get("results") or payload.get("results") or []
  if not isinstance(cols, list) or not cols:
    return []
  if all(isinstance(c, dict) and "column" not in c for c in cols):
    return cols
  col_values: Dict[str, List[Any]] = {}
  max_len = 0
  for col in cols:
    if not isinstance(col, dict) or "column" not in col:
      continue
    name = str(col["column"]).lstrip("$")
    vals: List[Any] = []
    for cell in col.get("values") or []:
      inner = cell.get("value", cell) if isinstance(cell, dict) else cell
      if isinstance(inner, dict):
        for k in ("doubleVal", "int64Val", "uint64Val", "stringVal", "boolVal"):
          if k in inner:
            vals.append(inner[k])
            break
        else:
          vals.append(None)
      else:
        vals.append(inner)
    col_values[name] = vals
    max_len = max(max_len, len(vals))
  rows: List[Dict[str, Any]] = []
  for idx in range(max_len):
    rows.append({k: (v[idx] if idx < len(v) else None) for k, v in col_values.items()})
  return rows


def parse_byte_dispersion_floor_probe(
    payload: Any,
    metric_name: Optional[str] = None,
    fallback: float = 10240.0,
    min_baseline_days: int = DEFAULT_MIN_BASELINE_DAYS,
) -> float:
  """Computes the median positive stddev across mature entities (active_days >= min_baseline_days)."""
  rows = _extract_probe_rows(payload)
  mature_sds: List[float] = []
  for row in rows:
    days_raw = None
    for dk in ("active_days", "hist_active_days", "historical_active_days", "active_baseline_days", "n"):
      if dk in row and row[dk] is not None:
        days_raw = row[dk]
        break
    if days_raw is not None:
      try:
        if float(days_raw) < float(min_baseline_days):
          continue
      except (TypeError, ValueError):
        continue
    sd_raw = None
    for sk in ("hist_stddev", "stddev", "baseline_stddev", "historical_stddev", "sd"):
      if sk in row and row[sk] is not None:
        sd_raw = row[sk]
        break
    if sd_raw is None:
      continue
    try:
      sd_val = float(sd_raw)
    except (TypeError, ValueError):
      continue
    if sd_val > 0.0:
      mature_sds.append(sd_val)
  if mature_sds:
    return float(statistics.median(mature_sds))
  if metric_name and metric_name in DEFAULT_FLEET_BYTE_DISPERSION_FLOORS:
    return DEFAULT_FLEET_BYTE_DISPERSION_FLOORS[metric_name]
  return float(fallback)


def build_identifier_coverage_probe(
    target_metric: str,
    entity_type: EntityType = EntityType.ASSET,
) -> str:
  """Builds a read-only single-stage YARA-L stats probe measuring hostname vs IP (or userid vs email) coverage (D4 / WS1-07)."""
  if target_metric not in METRIC_CATALOG:
    raise ValueError(f"Unknown risk metric: {target_metric}")
  sem = mc.baseline_semantics(target_metric)
  filter_block = "\n".join(sem.observed_filter)
  if entity_type == EntityType.USER:
    primary_field = PreFlightValidator.resolve_identifier_field(target_metric, EntityType.USER, "userid")
    alt_field = PreFlightValidator.resolve_identifier_field(target_metric, EntityType.USER, "email_addresses")
    return (
        f"// Goal: Per-tenant D4 identifier coverage probe for {target_metric} (userid vs email_addresses)\n"
        f"{filter_block}\n"
        "$event_type = metadata.event_type\n\n"
        "match:\n"
        "  $event_type\n\n"
        "outcome:\n"
        "  $total_events = count(metadata.id)\n"
        f'  $userid_events = sum(if({primary_field} != "", 1, 0))\n'
        f'  $email_events = sum(if({alt_field} != "", 1, 0))\n'
        f"  $distinct_userids = count_distinct({primary_field})\n"
        f"  $distinct_emails = count_distinct({alt_field})\n\n"
        "order:\n"
        "  $total_events desc\n"
    )

  primary_field = PreFlightValidator.resolve_identifier_field(target_metric, EntityType.ASSET, "hostname")
  alt_field = PreFlightValidator.resolve_identifier_field(target_metric, EntityType.ASSET, "ip")
  return (
      f"// Goal: Per-tenant D4 identifier coverage probe for {target_metric} (hostname vs IP)\n"
      f"{filter_block}\n"
      "$event_type = metadata.event_type\n\n"
      "match:\n"
      "  $event_type\n\n"
      "outcome:\n"
      "  $total_events = count(metadata.id)\n"
      f'  $hostname_events = sum(if({primary_field} != "", 1, 0))\n'
      f'  $ip_events = sum(if({alt_field} != "", 1, 0))\n'
      f"  $distinct_hostnames = count_distinct({primary_field})\n"
      f"  $distinct_ips = count_distinct({alt_field})\n\n"
      "order:\n"
      "  $total_events desc\n"
  )


def _udm_path_populated(obj: Any, dotted_path: str) -> bool:
  """Returns True if dotted_path resolves to a non-empty string or non-empty list inside a UDM dict."""
  cur = obj
  for part in dotted_path.split("."):
    if not isinstance(cur, dict) or part not in cur:
      return False
    cur = cur[part]
  if isinstance(cur, list):
    return any(isinstance(v, str) and bool(v.strip()) or (not isinstance(v, str) and v is not None) for v in cur)
  if isinstance(cur, str):
    return bool(cur.strip())
  return cur is not None


def select_identifier_from_coverage(
    coverage_payload: Any,
    target_metric: str,
    entity_type: EntityType = EntityType.ASSET,
    min_primary_ratio: float = 0.20,
) -> str:
  """Selects the populated identifier UDM path (hostname vs IP, or userid vs email_addresses) from a D4 probe."""
  import json as _json

  if isinstance(coverage_payload, Path):
    coverage_payload = _json.loads(coverage_payload.read_text(encoding="utf-8"))
  elif isinstance(coverage_payload, str):
    raw_str = coverage_payload.strip()
    if raw_str.startswith("{") or raw_str.startswith("["):
      coverage_payload = _json.loads(raw_str)
    elif Path(raw_str).exists():
      coverage_payload = _json.loads(Path(raw_str).read_text(encoding="utf-8"))

  if entity_type == EntityType.USER:
    primary = PreFlightValidator.resolve_identifier_field(target_metric, EntityType.USER, "userid")
    alternate = PreFlightValidator.resolve_identifier_field(target_metric, EntityType.USER, "email_addresses")
    ev_key, alt_ev_key, dp_key, da_key = "userid_events", "email_events", "distinct_userids", "distinct_emails"
  else:
    primary = PreFlightValidator.resolve_identifier_field(target_metric, EntityType.ASSET, "hostname")
    alternate = PreFlightValidator.resolve_identifier_field(target_metric, EntityType.ASSET, "ip")
    ev_key, alt_ev_key, dp_key, da_key = "hostname_events", "ip_events", "distinct_hostnames", "distinct_ips"

  rows = _extract_probe_rows(coverage_payload)
  if not rows and isinstance(coverage_payload, dict) and any(
      k in coverage_payload for k in ("total_events", ev_key, alt_ev_key, dp_key, da_key)
  ):
    rows = [coverage_payload]

  if rows:
    total_events = 0.0
    primary_events: Optional[float] = None
    alt_events: Optional[float] = None
    distinct_primary: Optional[float] = None
    distinct_alt: Optional[float] = None
    for row in rows:
      if row.get("total_events") is not None:
        total_events += float(row["total_events"])
      if row.get(ev_key) is not None:
        primary_events = (primary_events or 0.0) + float(row[ev_key])
      if row.get(alt_ev_key) is not None:
        alt_events = (alt_events or 0.0) + float(row[alt_ev_key])
      if row.get(dp_key) is not None:
        distinct_primary = max(distinct_primary or 0.0, float(row[dp_key]))
      if row.get(da_key) is not None:
        distinct_alt = max(distinct_alt or 0.0, float(row[da_key]))

    if total_events > 0.0 and primary_events is not None:
      ratio = primary_events / total_events
      if ratio < min_primary_ratio and (
          (alt_events is not None and alt_events > primary_events)
          or (distinct_alt is None or distinct_alt > (distinct_primary or 0.0))
      ):
        return alternate
      return primary
    if distinct_primary is not None or distinct_alt is not None:
      dp = distinct_primary or 0.0
      da = distinct_alt or 0.0
      if dp == 0.0 and da > 0.0:
        return alternate
      if da > 0.0 and (dp / max(dp + da, 1.0)) < min_primary_ratio:
        return alternate
      return primary

  if isinstance(coverage_payload, dict) and isinstance(coverage_payload.get("events"), list):
    events = [ev for ev in coverage_payload["events"] if isinstance(ev, dict)]
    if events:
      primary_hits = sum(1 for ev in events if _udm_path_populated(ev.get("udm", ev), primary))
      alt_hits = sum(1 for ev in events if _udm_path_populated(ev.get("udm", ev), alternate))
      if (primary_hits / float(len(events))) < min_primary_ratio and alt_hits > primary_hits:
        return alternate
      return primary

  return primary


def _fill_event_filter(rendered: str, slot: str, lines: Sequence[str], indent: str = "    ") -> str:
  """Fills a stand-alone filter slot line with one predicate per line (or drops the line)."""
  if lines:
    return rendered.replace(slot, ("\n" + indent).join(lines))
  return re.sub(r"^[ \t]*" + re.escape(slot) + r"[ \t]*\n", "", rendered, flags=re.M)


_TEAM_BLOCK_RE = re.compile(
    r"^[ \t]*// >>> TEAM COHORT[^\n]*\n(.*?)^[ \t]*// <<< TEAM COHORT[^\n]*\n([ \t]*\n)?", re.M | re.S)


def _apply_team_cohort_blocks(rendered: str, keep: bool) -> str:
  """Keeps (marker lines removed) or deletes the optional '// >>> TEAM COHORT' blocks."""
  return _TEAM_BLOCK_RE.sub((lambda m: m.group(1) + (m.group(2) or "")) if keep else "", rendered)


def samuelson_max_z(cohort_size: Union[int, float]) -> float:
  """Maximum sample-SD Z-score achievable when the subject is included in an N-member cohort (PF-2 / WS1-09).

  Chronicle's `stddev()` and `metrics.*(..., agg: stddev)` compute sample standard deviation
  with N - 1 degrees of freedom, bounding max |Z| <= (N - 1) / sqrt(N).
  """
  n = float(cohort_size)
  if n <= 1.0:
    return 0.0
  return (n - 1.0) / math.sqrt(n)


def samuelson_min_cohort_size(threshold_z: float) -> int:
  """Minimum cohort size N >= 2 needed for sample-SD Samuelson cap (N - 1)/sqrt(N) >= threshold_z."""
  t = float(threshold_z)
  if t <= 0.0:
    return 2
  n_est = max(2, int(math.ceil(((2.0 + t * t) + t * math.sqrt(t * t + 4.0)) / 2.0)))
  while samuelson_max_z(n_est) + 1e-12 < t:
    n_est += 1
  while n_est > 2 and samuelson_max_z(n_est - 1) >= t - 1e-12:
    n_est -= 1
  return n_est


def samuelson_triad_max_d_sq(cohort_size: Union[int, float]) -> float:
  """Maximum 3-metric squared composite distance D^2 <= 3 * (N - 1)^2 / N for an N-member cohort."""
  z_cap = samuelson_max_z(cohort_size)
  return 3.0 * z_cap * z_cap


def samuelson_triad_min_cohort_size(fusion_threshold_sq: float) -> int:
  """Minimum cohort size N >= 2 needed for triad sample-SD D^2 cap 3*(N-1)^2/N >= fusion_threshold_sq."""
  t_sq = float(fusion_threshold_sq)
  if t_sq <= 0.0:
    return 2
  return samuelson_min_cohort_size(math.sqrt(t_sq / 3.0))


def evaluate_samuelson_cohort_cap(
    cohort_size: int,
    *,
    threshold_z: float = DEFAULT_ANOMALY_THRESHOLD,
    is_triad: bool = False,
    fusion_threshold_sq: float = DEFAULT_FUSION_THRESHOLD_SQ,
) -> Dict[str, Any]:
  """Evaluates whether an N-member peer cohort can reach the configured significance gate (WS1-09)."""
  n = max(int(cohort_size), 0)
  max_z = samuelson_max_z(n)
  max_d_sq = samuelson_triad_max_d_sq(n) if is_triad else None
  if is_triad:
    req_n = samuelson_triad_min_cohort_size(fusion_threshold_sq)
    too_small = bool(max_d_sq is not None and max_d_sq < float(fusion_threshold_sq))
    warning = (
        f"Cohort too small (PF-2 / WS1-09): peer cohort size N = {n} caps 3-metric sample-SD "
        f"distance at D^2 <= 3*(N - 1)^2/N = {max_d_sq:.2f} (per-metric max Z = (N - 1)/sqrt(N) = "
        f"{max_z:.2f}σ), which is below the D^2 >= {float(fusion_threshold_sq):.2f} gate — this peer "
        f"query mathematically cannot alert until N >= {req_n} active peers (or lower fusion_threshold_sq / "
        "drop to fleet-only comparison)."
        if too_small
        else None
    )
  else:
    req_n = samuelson_min_cohort_size(threshold_z)
    too_small = bool(max_z < float(threshold_z))
    warning = (
        f"Cohort too small (PF-2 / WS1-09): peer cohort size N = {n} caps sample-SD Z-score at "
        f"(N - 1)/sqrt(N) = {max_z:.2f}σ, which is below the {float(threshold_z):.2f}σ significance "
        f"gate — this peer query mathematically cannot alert until N >= {req_n} active peers "
        "(or lower anomaly_threshold / drop to fleet-only comparison)."
        if too_small
        else None
    )
  return {
      "cohort_size": n,
      "samuelson_max_z": round(max_z, 4),
      "samuelson_max_d_sq": round(max_d_sq, 4) if max_d_sq is not None else None,
      "required_min_cohort_size": req_n,
      "cohort_too_small": too_small,
      "warning": warning,
  }


def extract_query_cohort_cap_info(
    query_text: Optional[str],
    default_anomaly_threshold: float = DEFAULT_ANOMALY_THRESHOLD,
    default_fusion_threshold_sq: float = DEFAULT_FUSION_THRESHOLD_SQ,
) -> Optional[Dict[str, Any]]:
  """Extracts team_cohort_stats roster size and root gate from a rendered YARA-L peer query (WS1-09)."""
  if not query_text or "stage team_cohort_stats" not in query_text:
    return None
  stage_m = re.search(r"stage\s+team_cohort_stats\s*\{(.*?)\}", query_text, flags=re.S)
  if not stage_m:
    return None
  members = set(re.findall(r'\$u\s*=\s*"((?:\\.|[^"\\])*)"', stage_m.group(1)))
  if not members:
    return None
  root_cond = MultiStageTemplateRouter.root_condition(query_text) or ""
  triad_m = re.search(r"\$d_vs_team_sq\s*>=\s*([0-9]+(?:\.[0-9]+)?)", root_cond)
  if triad_m:
    return evaluate_samuelson_cohort_cap(
        len(members),
        is_triad=True,
        fusion_threshold_sq=float(triad_m.group(1)),
    )
  if "$d_vs_team_sq" in query_text:
    return evaluate_samuelson_cohort_cap(
        len(members),
        is_triad=True,
        fusion_threshold_sq=default_fusion_threshold_sq,
    )
  team_m = re.search(r"\$z_vs_team\s*>=\s*([0-9]+(?:\.[0-9]+)?)", root_cond)
  eff_z = float(team_m.group(1)) if team_m else float(default_anomaly_threshold)
  return evaluate_samuelson_cohort_cap(len(members), threshold_z=eff_z, is_triad=False)


def _today_date() -> str:
  """Today's UTC date as YYYY-MM-DD (Entity Graph freshness: event stages stay on today).

  Rendered into timestamp.get_date(metadata.event_timestamp.seconds) = "<date>". A date string
  replaces the earlier epoch literal because agents writing the query by hand computed the
  epoch wrong (tomorrow's midnight, now - 48h) but write today's date reliably.
  """
  return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def _swap_identifier_leaf(field: str, target_field: str) -> str:
  """Applies target_field's identifier leaf (userid, email_addresses, ...) to a raw companion field."""
  leaf = target_field.rsplit(".", 1)[-1]
  candidate = field.rsplit(".", 1)[0] + "." + leaf
  try:
    mc.entity_binding_for_field(candidate)
  except ValueError:
    return field
  return candidate


class MultiStageTemplateRouter:
  """Assembles 2-Stage, 3-Stage, and 4-Stage YARA-L DAG queries."""

  def __init__(self, template_dir: Optional[Path] = None):
    if template_dir is None:
      self.template_dir = Path(__file__).resolve().parent.parent / "templates"
    else:
      self.template_dir = template_dir
    self.last_advisories: List[str] = []

  # Default sector pair when a fusion pipeline is requested without explicit metrics.
  DEFAULT_FUSION_METRICS = ("auth_attempts_fail", "network_bytes_outbound")

  STAGE2_TEMPLATES = {
      StatisticalModel.STANDARD_Z_SCORE: "standard_z_score.yl2",
      StatisticalModel.MAD: "mad.yl2",
      StatisticalModel.RELATIVE_DEVIATION: "relative_deviation.yl2",
      StatisticalModel.VARIANCE: "variance_fano.yl2",
      StatisticalModel.POISSON: "poisson_rarity.yl2",
      StatisticalModel.COEFFICIENT_OF_VARIATION: "coefficient_of_variation.yl2",
      StatisticalModel.BAYESIAN_GAMMA: "poisson_gamma_bayesian.yl2",
      StatisticalModel.BAYESIAN_BETA_BINOMIAL: "beta_binomial_bayesian.yl2",
      StatisticalModel.LONGITUDINAL_CUSUM: "longitudinal_cusum.yl2",
      StatisticalModel.TWO_PART_HURDLE: "two_part_hurdle.yl2",
      StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z: "standard_z_score.yl2",
      StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD: "adaptive_context_threshold.yl2",
      StatisticalModel.MACD_MOMENTUM_VELOCITY: "macd_momentum_velocity.yl2",
      StatisticalModel.QUANTILE_IQR_SKEW: "quantile_iqr_skew.yl2",
      StatisticalModel.FIRST_SEEN_NOVELTY: "first_seen_novelty.yl2",
      "macd_momentum": "macd_momentum_velocity.yl2",
      "macd_momentum_velocity": "macd_momentum_velocity.yl2",
      "longitudinal_cusum": "longitudinal_cusum.yl2",
      "first_seen_novelty": "first_seen_novelty.yl2",
  }

  STAGE2_FALLBACK_TEMPLATES: Dict[str, str] = {}

  MODEL_DESCRIPTIONS = {
      StatisticalModel.VARIANCE: "Baseline Dispersion Screen (30-Day Fano Factor)",
      "variance": "Baseline Dispersion Screen (30-Day Fano Factor)",
      StatisticalModel.BAYESIAN_GAMMA: "Empirical Bayes Poisson-Gamma (Fleet Prior & NB Predictive Residual Z)",
      "bayesian_gamma": "Empirical Bayes Poisson-Gamma (Fleet Prior & NB Predictive Residual Z)",
      StatisticalModel.BAYESIAN_BETA_BINOMIAL: "Empirical Bayes Paired Beta-Binomial Failure Rate (Predictive Z)",
      "bayesian_beta_binomial": "Empirical Bayes Paired Beta-Binomial Failure Rate (Predictive Z)",
      StatisticalModel.COEFFICIENT_OF_VARIATION: "Regular-Volume Surge (Low-CV Predictable Baseline)",
      "coefficient_of_variation": "Regular-Volume Surge (Low-CV Predictable Baseline)",
      StatisticalModel.LONGITUDINAL_CUSUM: "Multi-Day Cumulative Drift (Windowed Slack Sum)",
      "longitudinal_cusum": "Multi-Day Cumulative Drift (Windowed Slack Sum)",
      StatisticalModel.TWO_PART_HURDLE: "Two-Part Hurdle Model (Dormant Awakening Volume + Active Intensity)",
      "two_part_hurdle": "Two-Part Hurdle Model (Dormant Awakening Volume + Active Intensity)",
      StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD: "Off-Hours & Weekend Adaptive Context Threshold (1.75σ Off-Hours / 3.0σ In-Hours)",
      "adaptive_context_threshold": "Off-Hours & Weekend Adaptive Context Threshold (1.75σ Off-Hours / 3.0σ In-Hours)",
      StatisticalModel.MACD_MOMENTUM_VELOCITY: "Above-Historical-Max Z (Linear Peak Exceedance)",
      "macd_momentum": "Above-Historical-Max Z (Linear Peak Exceedance)",
      "macd_momentum_velocity": "Above-Historical-Max Z (Linear Peak Exceedance)",
      StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z: "Standard Z-Score (Merged from ASYMMETRIC_DIRECTIONAL_Z per D1)",
      StatisticalModel.FIRST_SEEN_NOVELTY: "First-Seen 30-Day Boolean Novelty Flag (metrics.* first_seen = 0; Never σ)",
      "first_seen_novelty": "First-Seen 30-Day Boolean Novelty Flag (metrics.* first_seen = 0; Never σ)",
      "diversity_deficit": "Lexical Diversity Deficit & Target Concentration",
      "diversity_deficit_entropy": "Lexical Diversity Deficit & Target Concentration",
  }

  @staticmethod
  def _escape_yaral_literal(val: str) -> str:
    """Escapes backslashes and double quotes in user-supplied YARA-L string literals."""
    return str(val).replace("\\", "\\\\").replace('"', '\\"')

  @staticmethod
  def validate_rendered_pipeline(query_text: str) -> List[str]:
    """Checks rendered YARA-L pipeline text for unresolved {{placeholders}} and AST errors."""
    from scripts.preflight_validator import MalachiteASTValidator
    errors: List[str] = []
    if not query_text or not query_text.strip():
      return ["EMPTY_QUERY: Rendered pipeline query is empty."]
    code_only = "\n".join(
        ln for ln in query_text.splitlines() if not ln.lstrip().startswith("//")
    )
    unresolved = re.findall(r"\{\{[^}]+\}\}", code_only)
    if unresolved:
      errors.append(
          f"UNRENDERED_PLACEHOLDERS: Unresolved template placeholders found: {sorted(set(unresolved))}"
      )
    ast_errors = MalachiteASTValidator.validate_query(query_text)
    errors.extend(ast_errors)
    return errors

  # ---------------------------------------------------------------------------
  # Entity binding helpers
  # ---------------------------------------------------------------------------

  @staticmethod
  def _sector_entity_field(metric: str, entity_type: EntityType, identifier_field: Optional[str]) -> str:
    """Entity key field for one fusion sector (validated), or the raw request for check_fusion_pair to reject."""
    if metric in METRIC_CATALOG and entity_type in METRIC_CATALOG[metric].supported_entity_types and not mc.is_composite_only(metric):
      return PreFlightValidator.resolve_identifier_field(metric, entity_type, identifier_field)
    if identifier_field and "." in identifier_field:
      return identifier_field
    return METRIC_CATALOG[metric].dimension_fields.get(entity_type, "") if metric in METRIC_CATALOG else ""

  @staticmethod
  def _strip_identifier_swap_note(stage1_content: str) -> str:
    """Drops the extractor's '// Identifier swap:' authoring note (and its continuation lines).

    The note tells an agent filling the template by hand which fields it may swap in. The router
    binds the field itself, so the note would only leave a stale "keys on <old field>" comment.
    """
    out, skipping = [], False
    for line in stage1_content.split("\n"):
      if line.startswith("// Identifier swap:"):
        skipping = True
        continue
      if skipping and line.startswith("//   "):
        continue
      skipping = False
      out.append(line)
    return "\n".join(out)

  @staticmethod
  def _rebind_entity_field(stage1_content: str, target_metric: str, target_field: str) -> str:
    """Rebinds a Stage 1 extractor from its default entity field to `target_field`.

    Swaps the event binding (`field = $var` or `$var = field`) and every metric filter
    (`field: $var`) for the extractor's primary match variable, then re-checks each
    metric call against the compiler's exact dimension-set rule.
    """
    match_var = re.search(r"match:\s+([$][a-zA-Z0-9_]+)", stage1_content)
    if not match_var:
      return stage1_content
    var = match_var.group(1)
    v = re.escape(var)
    m = re.search(r"^\s*([a-z][a-zA-Z0-9_.]*)\s*=\s*" + v + r"\s*$", stage1_content, re.M) or re.search(
        r"^\s*" + v + r"\s*=\s*([a-z][a-zA-Z0-9_.]*)\s*$", stage1_content, re.M
    )
    if not m:
      return stage1_content
    old_field = m.group(1)
    if old_field == target_field:
      return stage1_content
    if re.search(r"(?<![\w.])" + re.escape(target_field) + r"\s*(?:=|:)", stage1_content):
      # Composite extractor that already keys on target_field (e.g. target.resource.name next to the user).
      return stage1_content
    f = re.escape(old_field)
    out = re.sub(r"^(\s*)" + f + r"(\s*=\s*" + v + r"\s*)$", r"\g<1>" + target_field + r"\g<2>", stage1_content, flags=re.M)
    out = re.sub(r"^(\s*" + v + r"\s*=\s*)" + f + r"(\s*)$", r"\g<1>" + target_field + r"\g<2>", out, flags=re.M)
    out = re.sub(r"\b" + f + r"\s*:\s*(?:" + f + r"|" + v + r")\b", f"{target_field}: {target_field}", out)
    for metric, body in re.findall(r"metrics\.([a-zA-Z0-9_]+)\s*\(([^)]*)\)", out, re.S):
      fields = [x for x in re.findall(r"([a-zA-Z0-9_.]+)\s*:", body) if x not in ("period", "window", "metric", "agg")]
      err = mc.validate_filter_fields(metric, fields)
      if err:
        raise ValueError(f"Cannot key {target_metric} on {target_field}: {err}")
    return out

  @staticmethod
  def _triad_event_selection(metrics: Sequence[str]):
    """Shared stage filter + per-metric observed value; see malachite_catalog.triad_event_selection."""
    return mc.triad_event_selection(metrics)

  # ---------------------------------------------------------------------------
  # Root significance gate
  # ---------------------------------------------------------------------------

  # Gate placeholders a template's root `condition:` may carry, with their router defaults:
  #   {{anomaly_threshold}}     sigma-unit gate (Z, Poisson Z, shielded Z, ...), default 3.0
  #   {{fold_change_threshold}} fold-change gate for ratio models (Bayes Gamma, CV, ...), default 2.0
  #   {{fusion_threshold_sq}}   squared Euclidean distance D^2 for fusion / triads, default 12.25 (D >= 3.5)
  #   {{robust_threshold}}      MAD modified Z (Iglewicz-Hoaglin), default 3.5
  #   {{tukey_excess_threshold}} Quantile robust scale-excess above Bowley-adjusted Tukey fence, default 1.0
  GATE_PLACEHOLDERS = (
      "anomaly_threshold",
      "fold_change_threshold",
      "fusion_threshold_sq",
      "robust_threshold",
      "tukey_excess_threshold",
  )
  _GATE_CLAUSE_RE = re.compile(
      r"(\$[A-Za-z0-9_]+)\s*>=\s*\{\{(anomaly_threshold|fold_change_threshold|fusion_threshold_sq|robust_threshold|tukey_excess_threshold)\}\}")
  _ROOT_CONDITION_RE = re.compile(r"^condition:[ \t]*\n(.*?)(?=\n[ \t]*\n[ \t]*order:)", re.M | re.S)

  @classmethod
  def root_condition(cls, rendered: str) -> Optional[str]:
    """The root stage `condition:` expression (comments dropped, whitespace collapsed), or None."""
    m = cls._ROOT_CONDITION_RE.search(rendered)
    if not m:
      return None
    code = " ".join(re.sub(r"//[^\n]*", "", m.group(1)).split())
    return code or None

  @classmethod
  def _apply_significance_gate(
      cls,
      rendered: str,
      *,
      anomaly_threshold: float = DEFAULT_ANOMALY_THRESHOLD,
      fold_change_threshold: float = DEFAULT_FOLD_CHANGE_THRESHOLD,
      fusion_threshold_sq: float = DEFAULT_FUSION_THRESHOLD_SQ,
      robust_threshold: float = DEFAULT_ROBUST_THRESHOLD,
      tukey_excess_threshold: float = DEFAULT_TUKEY_EXCESS_THRESHOLD,
      min_threshold: Optional[float] = None,
      max_threshold: Optional[float] = None,
      condition_expression: Optional[str] = None,
      default_score: str = "$personal_z",
      only_if_template_gate: bool = False,
      include_significance_gate: bool = True,
  ) -> str:
    """Resolves the template's root significance gate and applies any analyst override.

    Every score-producing template ships a default root gate (`<gate var> >= {{<placeholder>}}`, see
    GATE_PLACEHOLDERS). An override (condition_expression, or min/max_threshold on the gate variable)
    REPLACES that default clause and keeps the template's other condition clauses (e.g. MAD's
    scoring-window and sample-size gates). When include_significance_gate is False (e.g. decoupled
    360° radar sector queries fused post-query), significance gating is omitted while structural
    scoring-window guards ($in_scoring_window = 1) are preserved.
    """
    if not include_significance_gate:
      cond = cls._ROOT_CONDITION_RE.search(rendered)
      if cond:
        body = cond.group(1)
        m = cls._GATE_CLAUSE_RE.search(body)
        if "$in_scoring_window" in body and m:
          stripped = re.sub(
              r"\s+(?:and|or)\s+" + re.escape(m.group(0)) + r"|" + re.escape(m.group(0)) + r"\s+(?:and|or)\s+",
              "",
              body,
              count=1,
          )
          rendered = rendered[:cond.start(1)] + stripped + rendered[cond.end(1):]
        else:
          rendered = re.sub(
              r"(?:^[ \t]*// Significance gate:[^\n]*\n)?^condition:[ \t]*\n.*?\n[ \t]*\n(?=[ \t]*order:)",
              "",
              rendered,
              flags=re.M | re.S,
          )
      values = {
          "anomaly_threshold": anomaly_threshold,
          "fold_change_threshold": fold_change_threshold,
          "fusion_threshold_sq": fusion_threshold_sq,
          "robust_threshold": robust_threshold,
          "tukey_excess_threshold": tukey_excess_threshold,
      }
      for name, value in values.items():
        rendered = rendered.replace("{{" + name + "}}", str(value))
      return rendered

    clause = None
    cond = cls._ROOT_CONDITION_RE.search(rendered)
    if cond:
      m = cls._GATE_CLAUSE_RE.search(cond.group(1))
      if m:
        clause = (
            cond.start(1) + m.start(),
            cond.start(1) + m.end(),
            m.group(1),
            cond.group(1).strip() == m.group(0),
            m.group(2),
        )

    if clause:
      gate_var = clause[2]
    else:
      order_match = re.search(r"^order:\s*\n\s*([$][a-zA-Z0-9_]+)", rendered, re.M)
      gate_var = order_match.group(1) if order_match else default_score

    is_sq_gate = (clause is not None and clause[4] == "fusion_threshold_sq") or gate_var.endswith("_sq")
    eff_min = (
        (round(float(min_threshold) ** 2, 6) if float(min_threshold) > 0 else 0.0)
        if (min_threshold is not None and is_sq_gate)
        else min_threshold
    )
    eff_max = (
        (round(float(max_threshold) ** 2, 6) if float(max_threshold) > 0 else 0.0)
        if (max_threshold is not None and is_sq_gate)
        else max_threshold
    )

    if condition_expression:
      if cond or not only_if_template_gate:
        rendered = cls._set_root_condition(rendered, condition_expression)
    else:
      override = None
      if eff_min is not None and eff_max is not None:
        override = f"{gate_var} >= {eff_min} and {gate_var} < {eff_max}"
      elif eff_min is not None:
        override = f"{gate_var} >= {eff_min}"
      elif eff_max is not None:
        override = f"{gate_var} <= {eff_max}"

      if override:
        if clause:
          start, end, _, is_whole, _ = clause
          compound = re.search(r"\s(?:and|or)\s", override) is not None
          replacement = override if (is_whole or not compound) else f"({override})"
          rendered = rendered[:start] + replacement + rendered[end:]
        elif not only_if_template_gate:
          rendered = cls._merge_root_condition(rendered, override)

    values = {
        "anomaly_threshold": anomaly_threshold,
        "fold_change_threshold": fold_change_threshold,
        "fusion_threshold_sq": fusion_threshold_sq,
        "robust_threshold": robust_threshold,
        "tukey_excess_threshold": tukey_excess_threshold,
    }
    for name, value in values.items():
      rendered = rendered.replace("{{" + name + "}}", str(value))
    return rendered

  # ---------------------------------------------------------------------------
  # Generic sector fusion
  # ---------------------------------------------------------------------------

  @staticmethod
  def _scalar_entity_expr(field: str) -> str:
    leaf = field.rsplit(".", 1)[-1]
    return f"{field}[0]" if leaf in mc.REPEATED_IDENTIFIER_LEAVES else field

  @classmethod
  def _sector_entity_union_binding(cls, field_a: str, field_b: str) -> str:
    if field_a == field_b:
      return f"{field_a} = $entity"
    # Order target.* before principal.* so USER_LOGIN events (which populate both) resolve target first,
    # while NETWORK_*/EMAIL_* events (where target.user.userid is empty) fall through to principal.
    ordered = sorted([field_a, field_b], key=lambda f: (0 if f.startswith("target.") else 1, f))
    return f"$entity = strings.coalesce({cls._scalar_entity_expr(ordered[0])}, {cls._scalar_entity_expr(ordered[1])})"

  @staticmethod
  def _conditional_sector_observed_agg(metric: str, pred: str) -> str:
    sem = mc.baseline_semantics(metric)
    obs = sem.observed_agg.strip()
    if obs == "count(metadata.id)":
      return f"sum(if({pred}, 1, 0))"
    m_single_byte = re.match(r"^sum\((network\.(?:sent|received)_bytes)\)$", obs)
    if m_single_byte:
      bf = m_single_byte.group(1)
      clamp = f"{bf} < 1000000000000000"
      eff_pred = pred if clamp in pred else f"{pred} and {clamp}"
      return f"sum(if({eff_pred}, 1.0, 0.0) * {bf})"
    m_clamped_single_byte = re.match(
        r"^sum\(if\((network\.(?:sent|received)_bytes) > 0 and \1 < 1000000000000000, 1\.0, 0\.0\) \* \1\)$",
        obs,
    )
    if m_clamped_single_byte:
      bf = m_clamped_single_byte.group(1)
      pos = f"{bf} > 0"
      clamp = f"{bf} < 1000000000000000"
      eff_pred = pred
      if pos not in eff_pred:
        eff_pred = f"{eff_pred} and {pos}"
      if clamp not in eff_pred:
        eff_pred = f"{eff_pred} and {clamp}"
      return f"sum(if({eff_pred}, 1.0, 0.0) * {bf})"
    if obs in (
        "sum(network.sent_bytes) + sum(network.received_bytes)",
        "sum(if(network.sent_bytes > 0 and network.sent_bytes < 1000000000000000, 1.0, 0.0) * network.sent_bytes) + sum(if(network.received_bytes > 0 and network.received_bytes < 1000000000000000, 1.0, 0.0) * network.received_bytes)",
    ):
      return (
          f"sum(if({pred} and network.sent_bytes > 0 and network.sent_bytes < 1000000000000000, 1.0, 0.0) * network.sent_bytes) + "
          f"sum(if({pred} and network.received_bytes > 0 and network.received_bytes < 1000000000000000, 1.0, 0.0) * network.received_bytes)"
      )
    raise ValueError(f"Unsupported conditional observed aggregation '{obs}' for metric '{metric}'")

  def build_sector_fusion_query(
      self,
      sector_a: "mc.SectorSpec",
      sector_b: "mc.SectorSpec",
      four_stage: bool = False,
      min_baseline_days: int = DEFAULT_MIN_BASELINE_DAYS,
      hypothesis_goal: Optional[str] = None,
      min_threshold: Optional[float] = None,
      max_threshold: Optional[float] = None,
      condition_expression: Optional[str] = None,
      fusion_threshold_sq: float = DEFAULT_FUSION_THRESHOLD_SQ,
      include_significance_gate: bool = True,
  ) -> str:
    """Renders a dual-sector (single-stage union + root) or multi-sector (union + mature fleet median norm + root)
    fusion for ANY two entity-keyed metrics. Pairing rules come from malachite_catalog.check_fusion_pair; advisories
    are emitted as '// ADVISORY:' lines and kept in self.last_advisories.

    If one sector is a composite-only metric (no entity-only baseline), it is rendered as a roll-up
    sector in slot A of rollup_sector_fusion_4stage.yl2 (or _5stage.yl2 when four_stage is set)."""
    if sector_b.is_rollup and not sector_a.is_rollup:
      sector_a, sector_b = sector_b, sector_a  # the roll-up template's slot A is the roll-up sector
    check = mc.check_fusion_pair(sector_a, sector_b)
    if not check.ok:
      raise ValueError("Invalid fusion pair: " + " ".join(check.errors))
    self.last_advisories = list(check.advisories)

    rollup = sector_a.is_rollup
    if rollup:
      name = "rollup_sector_fusion_5stage.yl2" if four_stage else "rollup_sector_fusion_4stage.yl2"
    else:
      name = "multi_sector_fusion_4stage.yl2" if four_stage else "dual_sector_fusion_3stage.yl2"
    pipeline_file = self.template_dir / "pipelines" / name
    if not pipeline_file.exists():
      raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
    rendered = pipeline_file.read_text().strip()

    comp_nonempty: List[str] = []
    if rollup:
      plan = sector_a.rollup()
      comp_bindings = [ln for ln in plan.companion_bindings() if "!=" not in ln]
      rendered = _fill_event_filter(rendered, "{{sector_a_companion_bindings}}", comp_bindings)
      comp_nonempty = [
          f'{fld} != ""'
          for dim, fld in zip(plan.companions, plan.companion_fields)
          if dim != "EVENT_TYPE"
      ]
      rendered = rendered.replace(
          "{{sector_a_companion_nonempty}}",
          (" and " + " and ".join(comp_nonempty)) if comp_nonempty else "",
      )
      rendered = rendered.replace("{{sector_a_match_keys}}", plan.match_keys())
      rendered = rendered.replace("{{sector_a_metric_filters}}", plan.metric_filters())
      rendered = rendered.replace("{{sector_a_detail_key}}", mc.companion_var(plan.detail_key_dimension).lstrip("$"))

    same_field = sector_a.entity_field == sector_b.entity_field
    rendered = rendered.replace(
        "{{sector_entity_binding}}",
        self._sector_entity_union_binding(sector_a.entity_field, sector_b.entity_field),
    )

    for tag, spec in (("a", sector_a), ("b", sector_b)):
      sem = mc.baseline_semantics(spec.metric)
      scalar_fld = self._scalar_entity_expr(spec.entity_field)
      ev_parts = list(sem.observed_filter) if same_field else [*sem.observed_filter, f'{scalar_fld} != ""']
      ev_expr = " and ".join(ev_parts)
      pred_parts = list(sem.observed_filter)
      if rollup and tag == "a" and comp_nonempty:
        pred_parts.extend(comp_nonempty)
      if not same_field:
        pred_parts.append(f"{scalar_fld} = $entity")

      rendered = rendered.replace(f"{{{{sector_{tag}_label}}}}", spec.label())
      rendered = rendered.replace(f"{{{{sector_{tag}_event_filter}}}}", ev_expr)
      rendered = rendered.replace(f"{{{{sector_{tag}_entity_field}}}}", spec.entity_field)
      rendered = rendered.replace(
          f"{{{{sector_{tag}_union_observed_agg}}}}",
          self._conditional_sector_observed_agg(spec.metric, " and ".join(pred_parts)),
      )
      rendered = rendered.replace(f"{{{{sector_{tag}_metric_arg}}}}", sem.metric_arg)
      rendered = rendered.replace(f"{{{{sector_{tag}_metric}}}}", spec.metric)
      floor_vars = ("$a_floor", "$d_floor") if tag == "a" else ("$b_floor",)
      rendered = _apply_byte_dispersion_floor(rendered, spec.metric, floor_vars=floor_vars)
    rendered = rendered.replace("{{min_baseline_days}}", str(min_baseline_days))
    # The template's slot guide is for agents filling slots by hand; it is noise once rendered.
    rendered = re.sub(r"^// SLOT FILLING:.*?(?=^// ====)", "", rendered, flags=re.M | re.S)

    rendered = self._apply_significance_gate(
        rendered,
        fusion_threshold_sq=fusion_threshold_sq,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        default_score="$composite_threat_norm_sq",
        include_significance_gate=include_significance_gate,
    )
    prefix = "".join(f"// ADVISORY: {a}\n" for a in check.advisories)
    if hypothesis_goal:
      prefix = f"// Goal: {hypothesis_goal}\n" + prefix
    rendered = prefix + rendered

    errors = MalachiteASTValidator.validate_query(rendered)
    if errors:
      raise ValueError("Rendered fusion query failed validation: " + " | ".join(errors))
    return rendered + "\n"

  @staticmethod
  def _set_root_condition(rendered: str, expression: str) -> str:
    """Replaces an existing root condition block with `expression`, or inserts one before `order:`."""
    cond_block = f"condition:\n  {expression}\n\n"
    if "\ncondition:\n" in rendered:
      return re.sub(r"\ncondition:\s*\n.*?\n(?=order:)", f"\n{cond_block}", rendered, flags=re.DOTALL)
    return re.sub(r"(\border:\s*)", f"{cond_block}\\1", rendered, count=1)

  @staticmethod
  def _merge_root_condition(rendered: str, expression: str) -> str:
    """Adds `expression` to the root condition, AND-ing it into an existing condition block if present.

    Templates such as stage2_math_models/mad.yl2 ship their own root `condition:` (scoring-day and
    sample-size gates); inserting a second `condition:` block would not compile.
    """
    existing = re.search(r'(\bcondition:\s*\n)(.*?)(\n\s*\n\s*order:)', rendered, re.S)
    if existing:
      merged = f"{existing.group(2).rstrip()} and {expression}"
      return rendered[:existing.start(2)] + merged + rendered[existing.end(2):]
    cond_block = f"condition:\n  {expression}\n\n"
    return re.sub(r'(\border:\s*)', f"{cond_block}\\1", rendered, count=1)

  _METRICS_OUTCOME_RE = re.compile(
      r'^[ \t]*\$([A-Za-z0-9_]+)[ \t]*=[ \t]*(?:max|min)\(metrics\.[A-Za-z0-9_]+\([^()]*\)\)[ \t]*\n', re.M)
  _METRICS_ALIAS_RE = re.compile(
      r'^[ \t]*\$([A-Za-z0-9_]+)[ \t]*=[ \t]*\$(historical_[A-Za-z0-9_]+)[ \t]*\n', re.M)

  _NOVELTY_SUBKEY_VARS: Dict[str, str] = {
      "target.application": "$app",
      "target.hostname": "$dest_host",
      "network.dns_domain": "$domain",
      "network.dns.questions.type": "$qtype",
      "target.resource.name": "$resource",
      "principal.process.file.sha256": "$sha256",
      "security_result.rule_name": "$rule_name",
      "principal.ip": "$src_ip",
      "target.ip": "$dest_ip",
      "target.asset.ip": "$dest_ip",
  }

  @classmethod
  def _inject_stage1_first_seen_novelty(
      cls,
      stage1_content: str,
      extractor_metric: str,
      metric_arg: str,
      novelty_subkey_field: Optional[str] = None,
  ) -> str:
    """Injects PF-11 first_seen/last_seen/period_start_for_max lookups and optional composite subkey."""
    out = stage1_content
    if novelty_subkey_field:
      sub_field = novelty_subkey_field.strip()
      already_present = bool(re.search(rf"(?<![\w.]){re.escape(sub_field)}\s*(?:=|:)", out))
      if not already_present:
        sub_var = cls._NOVELTY_SUBKEY_VARS.get(
            sub_field,
            f"$sub_{re.sub(r'[^a-zA-Z0-9_]', '_', sub_field.rsplit('.', 1)[-1])}",
        )
        if re.search(rf"{re.escape(sub_var)}\b", out):
          sub_var = f"{sub_var}_key"
        out = re.sub(
            r"(\n[ \t]*match:\s*\n)",
            f"\n    {sub_field} = {sub_var}\n    {sub_var} != \"\"\\1",
            out,
            count=1,
        )
        out = re.sub(
            r"(\bmatch:\s*\n[ \t]*[^\n]+?)(\s+by\s+\d+[dh])",
            rf"\1, {sub_var}\2",
            out,
            count=1,
        )
        call_re = re.compile(
            r"(metrics\." + re.escape(extractor_metric) + r"\(\s*[^)]+?)"
            r"(\n[ \t]*\)\))",
            re.S,
        )
        out = call_re.sub(rf"\1,\n        {sub_field}: {sub_field}\2", out)
        for m_name, body in re.findall(r"metrics\.([a-zA-Z0-9_]+)\s*\(([^)]*)\)", out, re.S):
          fields = [
              x for x in re.findall(r"([a-zA-Z0-9_.]+)\s*:", body)
              if x not in ("period", "window", "metric", "agg")
          ]
          err = mc.validate_filter_fields(m_name, fields)
          if err:
            raise ValueError(
                f"Cannot combine {extractor_metric} with novelty_subkey_field='{sub_field}': {err}"
            )

    active_re = re.compile(
        r"^[ \t]*\$historical_active_days\s*=\s*max\(metrics\."
        + re.escape(extractor_metric)
        + r"\(\s*period:\s*1d,\s*window:\s*30d,\s*metric:\s*[a-zA-Z0-9_]+,\s*agg:\s*num_metric_periods,\s*([^)]+?)\s*\)\)[ \t]*\n",
        re.M | re.S,
    )
    active_m = active_re.search(out)
    if not active_m:
      raise ValueError(f"Could not locate $historical_active_days metrics lookup in {extractor_metric}.yl2")
    dims_block = active_m.group(1).strip()
    novelty_lookups = (
        f"    $prior_first_seen = min(metrics.{extractor_metric}(\n"
        "        period: 1d, window: 30d, metric: first_seen, agg: min,\n"
        f"        {dims_block}\n"
        "    ))\n"
        f"    $prior_last_seen = max(metrics.{extractor_metric}(\n"
        "        period: 1d, window: 30d, metric: last_seen, agg: max,\n"
        f"        {dims_block}\n"
        "    ))\n"
        f"    $peak_period_start = max(metrics.{extractor_metric}(\n"
        f"        period: 1d, window: 30d, metric: {metric_arg}, agg: period_start_for_max,\n"
        f"        {dims_block}\n"
        "    ))\n"
    )
    return out[:active_m.end()] + novelty_lookups + out[active_m.end():]

  @classmethod
  def _inject_stage1_intraday_hourly(
      cls,
      stage1_content: str,
      extractor_metric: str,
      metric_arg: str,
      *,
      include_first_seen: bool = False,
      paired_beta_metrics: Optional[Tuple[str, str]] = None,
  ) -> str:
    """Injects WS1-13 / PF-10 `(period: 1h, window: today)` earlier-today lookups alongside 30d anchors (PF-10b)."""
    active_re = re.compile(
        r"^[ \t]*\$historical_active_days\s*=\s*max\(metrics\."
        + re.escape(extractor_metric)
        + r"\(\s*period:\s*1d,\s*window:\s*30d,\s*metric:\s*[a-zA-Z0-9_]+,\s*agg:\s*num_metric_periods,\s*([^)]+?)\s*\)\)[ \t]*\n",
        re.M | re.S,
    )
    active_m = active_re.search(stage1_content)
    if not active_m:
      raise ValueError(f"Could not locate $historical_active_days metrics lookup in {extractor_metric}.yl2")
    dims_block = active_m.group(1).strip()

    if paired_beta_metrics is not None:
      fail_m, total_m = paired_beta_metrics
      hourly_lookups = (
          f"    $earlier_today_sum = max(metrics.{fail_m}(\n"
          "        period: 1h, window: today, metric: event_count_sum, agg: sum,\n"
          f"        {dims_block}\n"
          "    ))\n"
          f"    $earlier_today_peak_hour = max(metrics.{fail_m}(\n"
          "        period: 1h, window: today, metric: event_count_sum, agg: max,\n"
          f"        {dims_block}\n"
          "    ))\n"
          f"    $earlier_today_active_hours = max(metrics.{fail_m}(\n"
          "        period: 1h, window: today, metric: event_count_sum, agg: num_metric_periods,\n"
          f"        {dims_block}\n"
          "    ))\n"
          f"    $earlier_today_total_sum = max(metrics.{total_m}(\n"
          "        period: 1h, window: today, metric: event_count_sum, agg: sum,\n"
          f"        {dims_block}\n"
          "    ))\n"
      )
    else:
      first_seen_lookup = (
          f"    $earlier_today_first_seen = min(metrics.{extractor_metric}(\n"
          "        period: 1h, window: today, metric: first_seen, agg: min,\n"
          f"        {dims_block}\n"
          "    ))\n"
          if include_first_seen
          else ""
      )
      hourly_lookups = (
          f"    $earlier_today_sum = max(metrics.{extractor_metric}(\n"
          f"        period: 1h, window: today, metric: {metric_arg}, agg: sum,\n"
          f"        {dims_block}\n"
          "    ))\n"
          f"    $earlier_today_peak_hour = max(metrics.{extractor_metric}(\n"
          f"        period: 1h, window: today, metric: {metric_arg}, agg: max,\n"
          f"        {dims_block}\n"
          "    ))\n"
          f"    $earlier_today_active_hours = max(metrics.{extractor_metric}(\n"
          f"        period: 1h, window: today, metric: {metric_arg}, agg: num_metric_periods,\n"
          f"        {dims_block}\n"
          "    ))\n"
          + first_seen_lookup
      )
    return stage1_content[:active_m.end()] + hourly_lookups + stage1_content[active_m.end():]

  @classmethod
  def _inject_root_intraday_hourly(
      cls,
      stage2_raw: str,
      statistical_model: StatisticalModel,
  ) -> str:
    """Stitches `$full_today_so_far = $earlier_today_sum + $observed` into Root `outcome:` (R4: never / 24)."""
    out = stage2_raw
    base_lines = (
        "  $earlier_today_sum = max($stage1_extract.earlier_today_sum)\n"
        "  $earlier_today_peak_hour = max($stage1_extract.earlier_today_peak_hour)\n"
        "  $earlier_today_active_hours = max($stage1_extract.earlier_today_active_hours)\n"
    )
    if statistical_model == StatisticalModel.POISSON:
      out = re.sub(
          r"(^[ \t]*\$k\s*=\s*max\(\$stage1_extract\.observed_val\)\n)",
          r"\1" + base_lines + "  $full_today_so_far = $earlier_today_sum + $k\n",
          out,
          count=1,
          flags=re.M,
      )
      out = out.replace("  $sum_x = $active_days * $hist_avg\n", "")
      out = out.replace("  $mu_cal = $sum_x / 30.0", "  $mu_cal = ($active_days * $hist_avg) / 30.0")
      out = out.replace(
          "  $sum_x2 = ($df_minus_one * $hist_stddev * $hist_stddev) + ($active_days * $hist_avg * $hist_avg)\n",
          "",
      )
      out = out.replace(
          "  $raw_var_cal = ($sum_x2 / 30.0) - ($mu_cal * $mu_cal)",
          "  $raw_var_cal = ((($df_minus_one * $hist_stddev * $hist_stddev) + ($active_days * $hist_avg * $hist_avg)) / 30.0) - ($mu_cal * $mu_cal)",
      )
      out = out.replace("  $sqrt_lambda = math.sqrt($safe_lambda)\n", "")
      out = out.replace("  $diff = $k - $lambda\n", "")
      out = out.replace(
          "  $poisson_z = $diff / $safe_poisson_sd",
          "  $poisson_z = ($full_today_so_far - $lambda) / $safe_poisson_sd",
      )
      return out

    if statistical_model == StatisticalModel.BAYESIAN_BETA_BINOMIAL:
      out = re.sub(
          r"(^[ \t]*\$observed\s*=\s*\$obs_fail\n)",
          r"\1"
          + base_lines
          + "  $earlier_today_total_sum = max($stage1_extract.earlier_today_total_sum)\n"
          + "  $full_today_so_far = $earlier_today_sum + $observed\n"
          + "  $full_today_total_so_far = $earlier_today_total_sum + $obs_total\n",
          out,
          count=1,
          flags=re.M,
      )
      out = out.replace("  $alpha_pre = {{prior_alpha0}} + $hist_fail_sum\n", "")
      out = out.replace("  $beta_pre = {{prior_beta0}} + $hist_succ_sum\n", "")
      out = out.replace(
          "  $ab = $alpha_pre + $beta_pre",
          "  $ab = ({{prior_alpha0}} + $hist_fail_sum) + ({{prior_beta0}} + $hist_succ_sum)",
      )
      out = out.replace(
          "  $prior_fail_rate = $alpha_pre / $ab",
          "  $prior_fail_rate = ({{prior_alpha0}} + $hist_fail_sum) / $ab",
      )
      out = out.replace(
          "  $posterior_fail_rate = ($alpha_pre + $obs_fail) / ($ab + $obs_total)",
          "  $posterior_fail_rate = (({{prior_alpha0}} + $hist_fail_sum) + $full_today_so_far) / ($ab + $full_today_total_so_far)",
      )
      out = out.replace("  $posterior_rate = $posterior_fail_rate\n", "")
      out = out.replace("  $pred_mean = $obs_total * $prior_fail_rate\n", "")
      out = out.replace(
          "  $pred_var = $obs_total * $prior_fail_rate * ($beta_pre / $ab) * (($ab + $obs_total) / ($ab + 1.0))",
          "  $pred_var = $full_today_total_so_far * $prior_fail_rate * (({{prior_beta0}} + $hist_succ_sum) / $ab) * (($ab + $full_today_total_so_far) / ($ab + 1.0))",
      )
      out = out.replace(
          "  $beta_binomial_z = ($obs_fail - $pred_mean) / $safe_pred_sd",
          "  $beta_binomial_z = ($full_today_so_far - ($full_today_total_so_far * $prior_fail_rate)) / $safe_pred_sd",
      )
      return out

    extra_first_seen = (
        "  $earlier_today_first_seen = min($stage1_extract.earlier_today_first_seen)\n"
        if statistical_model == StatisticalModel.FIRST_SEEN_NOVELTY
        else ""
    )
    out = re.sub(
        r"(^[ \t]*\$observed\s*=\s*max\(\$stage1_extract\.observed_val\)\n)",
        r"\1" + base_lines + extra_first_seen + "  $full_today_so_far = $earlier_today_sum + $observed\n",
        out,
        count=1,
        flags=re.M,
    )

    if statistical_model in (StatisticalModel.STANDARD_Z_SCORE, StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z):
      out = out.replace(
          "  $personal_diff = $observed - $hist_avg",
          "  $personal_diff = $full_today_so_far - $hist_avg",
      )
    elif statistical_model == StatisticalModel.MACD_MOMENTUM_VELOCITY:
      out = out.replace(
          "  $personal_diff = $observed - $hist_avg",
          "  $personal_diff = $full_today_so_far - $hist_avg",
      )
      out = out.replace(
          "  $exceed_raw = $observed - $hist_max",
          "  $exceed_raw = $full_today_so_far - $hist_max",
      )
    elif statistical_model == StatisticalModel.RELATIVE_DEVIATION:
      out = out.replace(
          "  $dev = $observed - $safe_hist_avg",
          "  $dev = $full_today_so_far - $safe_hist_avg",
      )
      out = out.replace(
          "  $fold_change = $observed / $safe_hist_avg",
          "  $fold_change = $full_today_so_far / $safe_hist_avg",
      )
    elif statistical_model == StatisticalModel.COEFFICIENT_OF_VARIATION:
      out = out.replace(
          "  $surge_ratio = $observed / $safe_hist_avg",
          "  $surge_ratio = $full_today_so_far / $safe_hist_avg",
      )
    elif statistical_model == StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD:
      out = out.replace(
          "  $raw_diff = $observed - $hist_avg",
          "  $raw_diff = $full_today_so_far - $hist_avg",
      )
    elif statistical_model == StatisticalModel.BAYESIAN_GAMMA:
      out = out.replace(
          "  $sum_x2 = ($df_minus_one * $hist_stddev * $hist_stddev) + ($active_days * $hist_avg * $hist_avg)\n",
          "",
      )
      out = out.replace(
          "  $raw_var_cal = ($sum_x2 / 30.0) - ($mu_cal * $mu_cal)",
          "  $raw_var_cal = ((($df_minus_one * $hist_stddev * $hist_stddev) + ($active_days * $hist_avg * $hist_avg)) / 30.0) - ($mu_cal * $mu_cal)",
      )
      out = out.replace("  $post_alpha_pre = {{prior_alpha0}} + $hist_sum\n", "")
      out = out.replace("  $post_beta_pre = {{prior_beta0}} + 30.0\n", "")
      out = out.replace(
          "  $posterior_rate = $post_alpha_pre / $post_beta_pre",
          "  $posterior_rate = ({{prior_alpha0}} + $hist_sum) / ({{prior_beta0}} + 30.0)",
      )
      out = out.replace(
          "  $post_rate_var = $post_alpha_pre / ($post_beta_pre * $post_beta_pre)",
          "  $post_rate_var = ({{prior_alpha0}} + $hist_sum) / (({{prior_beta0}} + 30.0) * ({{prior_beta0}} + 30.0))",
      )
      out = out.replace("  $cred_w = $active_days / ($active_days + {{prior_beta0}})\n", "")
      out = out.replace(
          "  $pred_var = $posterior_rate + $post_rate_var + ($cred_w * $excess_var)",
          "  $pred_var = $posterior_rate + $post_rate_var + (($active_days / ($active_days + {{prior_beta0}})) * $excess_var)",
      )
      out = out.replace(
          "  $bayesian_z = ($observed - $posterior_rate) / $safe_pred_sd",
          "  $bayesian_z = ($full_today_so_far - $posterior_rate) / $safe_pred_sd",
      )
    elif statistical_model == StatisticalModel.TWO_PART_HURDLE:
      out = out.replace("  $dormant_days = 30.0 - $active_days\n", "")
      out = out.replace("  $df_minus_one = if($active_days > 1, $active_days, 1) - 1\n", "")
      out = out.replace(
          "  $sum_x2 = ($df_minus_one * $hist_stddev * $hist_stddev) + ($active_days * $hist_avg * $hist_avg)\n",
          "",
      )
      out = out.replace("  $raw_var_cal = ($sum_x2 / 30.0) - ($mu_cal * $mu_cal)\n", "")
      out = out.replace("  $sd_cal = math.sqrt(if($raw_var_cal > 0.0, $raw_var_cal, 0.0))\n", "")
      out = out.replace(
          "  $is_dormant_awakening = if($active_days < {{min_baseline_days}} and $observed >= {{min_awakening_volume}} and $observed > $hist_max, 1.0, 0.0)",
          "  $is_dormant_awakening = if($active_days < {{min_baseline_days}} and $full_today_so_far >= {{min_awakening_volume}} and $full_today_so_far > $hist_max, 1.0, 0.0)",
      )
      out = out.replace(
          "  $awakening_ratio = $observed / if($hist_max > {{min_awakening_volume}}, $hist_max, {{min_awakening_volume}})",
          "  $awakening_ratio = $full_today_so_far / if($hist_max > {{min_awakening_volume}}, $hist_max, {{min_awakening_volume}})",
      )
      out = out.replace(
          "  $raw_z = ($observed - $hist_avg) / $safe_stddev",
          "  $raw_z = ($full_today_so_far - $hist_avg) / $safe_stddev",
      )
    elif statistical_model == StatisticalModel.FIRST_SEEN_NOVELTY:
      out = out.replace(
          "  $novelty_flag = if($prior_first_seen = 0 and $observed >= {{min_novelty_events}}, 1, 0)",
          "  $novelty_flag = if($prior_first_seen = 0 and $full_today_so_far >= {{min_novelty_events}}, 1, 0)",
      )
    return out

  @classmethod
  def _prune_unused_metrics_lookups(cls, stage1_content: str, downstream: str) -> str:
    """Removes stage1 `$var = max(metrics.*(...))` outcomes (and unused aliases) that nothing downstream reads.

    Each metrics.* outcome is a per-entity, per-day lookup. A lookup is kept if the downstream stages
    reference `$stage1_extract.<var>` or another stage1 line references `$<var>`.
    """
    def _keep_alias(m: "re.Match[str]") -> str:
      alias_var = m.group(1)
      if re.search(r'\bstage1_extract\.' + re.escape(alias_var) + r'\b', downstream):
        return m.group(0)
      rest = stage1_content[:m.start()] + stage1_content[m.end():]
      if re.search(r'\$' + re.escape(alias_var) + r'\b', rest):
        return m.group(0)
      return ""

    stage1_content = cls._METRICS_ALIAS_RE.sub(_keep_alias, stage1_content)

    def _keep(m: "re.Match[str]") -> str:
      var = m.group(1)
      if re.search(r'\bstage1_extract\.' + re.escape(var) + r'\b', downstream):
        return m.group(0)
      rest = stage1_content[:m.start()] + stage1_content[m.end():]
      if re.search(r'\$' + re.escape(var) + r'\b', rest):
        return m.group(0)
      return ""
    return cls._METRICS_OUTCOME_RE.sub(_keep, stage1_content)

  @staticmethod
  def _mad_group_keys(stage1_content: str):
    """Splits stage1's match variables into baseline grouping keys and keys to drop.

    A match variable is a baseline key when the UDM field it binds is a dimension argument of the
    stage1 metrics.* calls (the baseline's identity). Other match variables (e.g. `$ip` on resource_*)
    would split one baseline tuple into several thin series, so they are dropped. Returns (keys, dropped);
    the first key is always the primary match variable.
    """
    m = re.search(r'\bmatch:\s*\n\s*(.*?)\s+by\s+\d+[dh]', stage1_content)
    if not m:
      return [], []
    match_vars = [v.strip() for v in m.group(1).split(",") if v.strip()]
    dims = set(re.findall(r'\b([a-z][a-zA-Z0-9_.]*)\s*:\s*\1\b', stage1_content))
    keys, dropped = [], []
    for i, var in enumerate(match_vars):
      v = re.escape(var)
      b = re.search(r'^\s*([a-z][a-zA-Z0-9_.]*)\s*=\s*' + v + r'\s*$', stage1_content, re.M) or re.search(
          r'^\s*' + v + r'\s*=\s*([a-z][a-zA-Z0-9_.]*)\s*$', stage1_content, re.M)
      if i == 0 or (b and b.group(1) in dims):
        keys.append(var)
      else:
        dropped.append(var)
    return keys, dropped

  @staticmethod
  def _drop_stage1_match_keys(stage1_content: str, dropped: Sequence[str]) -> str:
    """Removes `dropped` match variables from stage1's match list and deletes their bindings/filters."""
    for var in dropped:
      v = re.escape(var)
      stage1_content = re.sub(r',\s*' + v + r'\b(?=[^\n]*\bby\b)', '', stage1_content)
      stage1_content = re.sub(r'^[^\n]*' + v + r'\b[^\n]*\n', '', stage1_content, flags=re.M)
    return stage1_content

  @staticmethod
  def _expand_mad_keys(stage2_raw: str, primary_var: str, extra_keys: Sequence[str]) -> str:
    """Adds the extra MAD grouping keys next to the primary key in every MAD stage's bindings and match."""
    if not extra_keys:
      return stage2_raw
    p = re.escape(primary_var)
    p_name = re.escape(primary_var.lstrip("$"))

    def _bind(m: "re.Match[str]") -> str:
      indent, stage = m.group(1), m.group(2)
      extra = "".join(f"\n{indent}{k} = ${stage}.{k.lstrip('$')}" for k in extra_keys)
      return m.group(0) + extra
    stage2_raw = re.sub(r'^([ \t]*)' + p + r' = \$([a-zA-Z0-9_]+)\.' + p_name + r'[ \t]*$', _bind, stage2_raw, flags=re.M)
    stage2_raw = re.sub(r'(\bmatch:\s*\n\s*)' + p + r'(?![\w])', lambda m: m.group(1) + ", ".join([primary_var, *extra_keys]),
                        stage2_raw)
    return stage2_raw

  @classmethod
  def _apply_composite_companions_to_entity_pipeline(
      cls,
      rendered: str,
      target_metric: str,
      entity_type: EntityType,
  ) -> str:
    """Injects Malachite-required composite companion bindings, dimensions, and match keys into $entity pipelines."""
    if target_metric.startswith("file_executions_"):
      extra_bindings = (
          "    principal.process.file.sha256 = $sha256\n"
          '    $sha256 != ""'
      )
      extra_dims = (
          ",\n        metadata.event_type: metadata.event_type,\n"
          "        principal.process.file.sha256: principal.process.file.sha256"
      )
      extra_keys = ["$sha256"]
    elif target_metric == "alert_event_name_count":
      extra_bindings = (
          "    security_result.rule_name = $rule_name\n"
          '    $rule_name != ""'
      )
      extra_dims = ",\n        security_result.rule_name: security_result.rule_name"
      extra_keys = ["$rule_name"]
    elif target_metric.startswith("resource_"):
      if entity_type == EntityType.RESOURCE:
        extra_bindings = (
            "    principal.user.userid = $sa\n"
            "    metadata.vendor_name = $vendor\n"
            "    metadata.product_name = $product\n"
            '    $sa != ""\n'
            '    $vendor != ""\n'
            '    $product != ""'
        )
        extra_dims = (
            ",\n        principal.user.userid: principal.user.userid,\n"
            "        metadata.vendor_name: metadata.vendor_name,\n"
            "        metadata.product_name: metadata.product_name"
        )
        extra_keys = ["$sa", "$vendor", "$product"]
      else:
        extra_bindings = (
            "    metadata.vendor_name = $vendor\n"
            "    metadata.product_name = $product\n"
            "    target.resource.name = $resource\n"
            '    $vendor != ""\n'
            '    $product != ""\n'
            '    $resource != ""'
        )
        extra_dims = (
            ",\n        metadata.vendor_name: metadata.vendor_name,\n"
            "        metadata.product_name: metadata.product_name,\n"
            "        target.resource.name: target.resource.name"
        )
        extra_keys = ["$vendor", "$product", "$resource"]
    else:
      return rendered.replace(" {{extra_dimensions}}", "").replace("{{extra_dimensions}}", "")

    out = rendered.replace('    $entity != ""', f'    $entity != ""\n{extra_bindings}', 1)
    out = out.replace(" {{extra_dimensions}}", extra_dims).replace("{{extra_dimensions}}", extra_dims)
    return cls._expand_mad_keys(out, "$entity", extra_keys)

  @classmethod
  def _inject_stage1_adaptive_schedule(
      cls,
      stage1_content: str,
      *,
      tenant_tz: str,
      biz_start_hour: int,
      biz_end_hour: int,
      learned_active_hours: Optional[Any],
  ) -> str:
    """Injects {{tenant_tz}} event-level hour/weekday extraction and $off_hours_obs into Stage 1 (WS3-ADAPTIVE / D1c)."""
    eff_tz = str(tenant_tz or "").strip()
    if not eff_tz:
      raise ValueError("tenant_tz must be a non-empty IANA time-zone string (e.g. 'UTC' or 'America/Los_Angeles').")
    in_sched = _build_in_schedule_condition(
        biz_start_hour=biz_start_hour,
        biz_end_hour=biz_end_hour,
        learned_active_hours=learned_active_hours,
    )
    tz_bindings = (
        '    $hour = timestamp.get_hour(metadata.event_timestamp.seconds, "{{tenant_tz}}")\n'
        '    $dow = timestamp.get_day_of_week(metadata.event_timestamp.seconds, "{{tenant_tz}}")\n'
    )
    stage1_out = re.sub(
        r"(\n[ \t]*match:\s*\n)",
        "\n" + tz_bindings + r"\1",
        stage1_content,
        count=1,
    ).replace("{{tenant_tz}}", cls._escape_yaral_literal(eff_tz))

    obs_m = re.search(r"^[ \t]*\$observed_val\s*=\s*([^\n]+)\n", stage1_out, flags=re.M)
    if not obs_m:
      raise ValueError("Stage 1 extractor missing $observed_val assignment for ADAPTIVE_CONTEXT_THRESHOLD.")
    rhs = obs_m.group(1).strip()

    if in_sched is None:
      off_lines = "    $off_hours_obs = $observed_val\n"
    elif in_sched == "ALL_ACTIVE":
      off_lines = "    $off_hours_obs = 0 * $observed_val\n"
    elif rhs == "count(metadata.id)":
      off_lines = f"    $off_hours_obs = sum(if({in_sched}, 0, 1))\n"
    elif rhs == "sum($sent)":
      off_lines = f"    $off_hours_obs = sum(if({in_sched}, 0, $sent))\n"
    elif rhs == "sum($received)":
      off_lines = f"    $off_hours_obs = sum(if({in_sched}, 0, $received))\n"
    elif rhs == "sum($sent) + sum($received)":
      off_lines = (
          f"    $off_hours_sent = sum(if({in_sched}, 0, $sent))\n"
          f"    $off_hours_rcvd = sum(if({in_sched}, 0, $received))\n"
          "    $off_hours_obs = $off_hours_sent + $off_hours_rcvd\n"
      )
    elif rhs == "sum(network.sent_bytes) + sum(network.received_bytes)":
      off_lines = (
          f"    $off_hours_sent = sum(if({in_sched}, 0, network.sent_bytes))\n"
          f"    $off_hours_rcvd = sum(if({in_sched}, 0, network.received_bytes))\n"
          "    $off_hours_obs = $off_hours_sent + $off_hours_rcvd\n"
      )
    elif (
        rhs
        == "sum(if(network.sent_bytes > 0 and network.sent_bytes < 1000000000000000, 1.0, 0.0) * network.sent_bytes)"
    ):
      off_lines = (
          f"    $off_hours_obs = sum(if({in_sched}, 0.0, if(network.sent_bytes > 0 and network.sent_bytes < 1000000000000000, 1.0, 0.0)) * network.sent_bytes)\n"
      )
    elif (
        rhs
        == "sum(if(network.sent_bytes > 0 and network.sent_bytes < 1000000000000000, 1.0, 0.0) * network.sent_bytes)"
        " + sum(if(network.received_bytes > 0 and network.received_bytes < 1000000000000000, 1.0, 0.0) * network.received_bytes)"
    ):
      off_lines = (
          f"    $off_hours_sent = sum(if({in_sched}, 0.0, if(network.sent_bytes > 0 and network.sent_bytes < 1000000000000000, 1.0, 0.0)) * network.sent_bytes)\n"
          f"    $off_hours_rcvd = sum(if({in_sched}, 0.0, if(network.received_bytes > 0 and network.received_bytes < 1000000000000000, 1.0, 0.0)) * network.received_bytes)\n"
          "    $off_hours_obs = $off_hours_sent + $off_hours_rcvd\n"
      )
    else:
      raise ValueError(f"Unsupported Stage 1 $observed_val expression '{rhs}' for ADAPTIVE_CONTEXT_THRESHOLD.")

    return stage1_out[:obs_m.end()] + off_lines + stage1_out[obs_m.end():]

  def build_query(
      self,
      target_metric: str,
      entity_type: EntityType,
      statistical_model: StatisticalModel,
      anomaly_threshold: float = DEFAULT_ANOMALY_THRESHOLD,
      min_baseline_days: Optional[int] = None,
      match_mode: MatchMode = MatchMode.TIMELINE_BREAKDOWN,
      hypothesis_goal: Optional[str] = None,
      min_threshold: Optional[float] = None,
      max_threshold: Optional[float] = None,
      condition_expression: Optional[str] = None,
      apply_threshold_condition: bool = False,
      identifier_field: Optional[str] = None,
      scoring_days: Optional[int] = None,
      scoring_end_date: Optional[str] = None,
      fold_change_threshold: float = DEFAULT_FOLD_CHANGE_THRESHOLD,
      robust_threshold: float = DEFAULT_ROBUST_THRESHOLD,
      tukey_excess_threshold: float = DEFAULT_TUKEY_EXCESS_THRESHOLD,
      include_significance_gate: bool = True,
      byte_dispersion_floor: Optional[float] = None,
      identifier_coverage_payload: Optional[Any] = None,
      prior_alpha0: Optional[float] = None,
      prior_beta0: Optional[float] = None,
      fleet_prior_payload: Optional[Any] = None,
      min_awakening_volume: int = DEFAULT_MIN_AWAKENING_VOLUME,
      tenant_tz: str = DEFAULT_TENANT_TZ,
      biz_start_hour: int = DEFAULT_BIZ_START_HOUR,
      biz_end_hour: int = DEFAULT_BIZ_END_HOUR,
      learned_active_hours: Optional[Any] = None,
      novelty_subkey_field: Optional[str] = None,
      min_novelty_events: int = 1,
      intraday_hourly: bool = False,
  ) -> str:
    """Renders stage1 extractor + stage2 math model.

    Significance gate: every stage2 model except the Fano factor ships a default root `condition:`
    (sigma models: `>= anomaly_threshold`; ratio models: `>= fold_change_threshold`; MAD:
    `$modified_z >= robust_threshold`). min_threshold / max_threshold / condition_expression replace
    that default gate. Pass include_significance_gate=False to emit an ungated query (e.g. 360° radar
    decoupled sectors fused post-query). apply_threshold_condition is retained for backward compatibility.

    scoring_days applies to StatisticalModel.MAD only: the raw search window is the robust baseline
    (~30d), so the number of most-recent days actually scored is set explicitly (Mode A: 1, Mode B
    default: 7), ending at scoring_end_date (UTC YYYY-MM-DD; default today). The gate is a date
    string rendered into stage1 ($in_scoring_window), never wall-clock time or an epoch literal.
    """
    self.last_advisories = []
    if identifier_field is None and identifier_coverage_payload is not None:
      identifier_field = select_identifier_from_coverage(
          identifier_coverage_payload,
          target_metric=target_metric,
          entity_type=entity_type,
      )
    audit = PreFlightValidator.audit(
        target_metric=target_metric,
        entity_type=entity_type,
        min_baseline_days=min_baseline_days,
        match_mode=match_mode,
        identifier_field=identifier_field,
    )

    if statistical_model is None or (isinstance(statistical_model, str) and not statistical_model.strip()):
      raise ValueError(f"Unknown statistical model: '{statistical_model}'")
    if isinstance(statistical_model, StatisticalModel) and statistical_model in RETIRED_STATISTICAL_MODELS:
      raise ValueError(RETIRED_STATISTICAL_MODELS[statistical_model])
    raw_model_arg = statistical_model
    if not isinstance(statistical_model, StatisticalModel):
      if str(raw_model_arg).strip().upper().replace("-", "_").replace(" ", "_") == "ASYMMETRIC_DIRECTIONAL_Z":
        self.last_advisories.append(
            "ASYMMETRIC_DIRECTIONAL_Z merged into STANDARD_Z_SCORE (D1): upper-tail positive Z >= threshold is identical to Standard Z."
        )
      from .ueba_hybrid_engine import resolve_statistical_model
      statistical_model = resolve_statistical_model(statistical_model)
    if statistical_model in RETIRED_STATISTICAL_MODELS:
      raise ValueError(RETIRED_STATISTICAL_MODELS[statistical_model])
    if statistical_model == StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z:
      self.last_advisories.append(
          "ASYMMETRIC_DIRECTIONAL_Z merged into STANDARD_Z_SCORE (D1): upper-tail positive Z >= threshold is identical to Standard Z."
      )
    if (
        statistical_model == StatisticalModel.POISSON
        and mc.baseline_semantics(target_metric).metric_arg == "value_sum"
    ):
      raise ValueError(
          f"Statistical model 'POISSON' applies only to discrete event_count_sum metrics; "
          f"'{target_metric}' is a byte-volume value_sum metric where variance scales quadratically. "
          "Use MAD, QUANTILE_IQR_SKEW, or STANDARD_Z_SCORE instead."
      )

    paired_beta_metrics: Optional[Tuple[str, str]] = None
    if statistical_model == StatisticalModel.BAYESIAN_BETA_BINOMIAL:
      paired_beta_metrics = resolve_beta_binomial_pair(target_metric)

    if intraday_hourly:
      if target_metric not in PF10_SUPPORTED_HOURLY_TODAY_METRICS:
        raise ValueError(
            f"R5 / PF-10 violation: intraday_hourly=True (period: 1h, window: today) is not supported "
            f"for metric '{target_metric}' (returned 0 rows in the empirical gus-sdl PF-10 probe). "
            f"Supported metrics ({len(PF10_SUPPORTED_HOURLY_TODAY_METRICS)}/38): "
            f"{sorted(PF10_SUPPORTED_HOURLY_TODAY_METRICS)}."
        )
      if paired_beta_metrics is not None:
        for pm in paired_beta_metrics:
          if pm not in PF10_SUPPORTED_HOURLY_TODAY_METRICS:
            raise ValueError(
                f"R5 / PF-10 violation: intraday_hourly=True requires both paired Beta-Binomial metrics "
                f"{paired_beta_metrics} to be in PF10_SUPPORTED_HOURLY_TODAY_METRICS; '{pm}' is unsupported."
            )
      if statistical_model in (
          StatisticalModel.MAD,
          StatisticalModel.QUANTILE_IQR_SKEW,
          StatisticalModel.LONGITUDINAL_CUSUM,
      ):
        raise ValueError(
            f"R3 / PF-10 violation: intraday_hourly=True (period: 1h, window: today) requires a single-UTC-day "
            f"raw window (<= 24h) and cannot be combined with multi-day raw-series model '{statistical_model.value}'."
        )

    # Enforce Local-Baseline Isolation: default STANDARD_Z_SCORE multi-database account queries
    # route to CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH; explicit non-Z models (or intraday_hourly) render directly.
    if (
        target_metric.startswith("resource_")
        and entity_type == EntityType.USER
        and statistical_model == StatisticalModel.STANDARD_Z_SCORE
        and not intraday_hourly
    ):
      return self.build_pipeline_query(
          PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH,
          target_metric=target_metric,
          entity_type=entity_type,
          anomaly_threshold=anomaly_threshold,
          min_baseline_days=min_baseline_days,
          hypothesis_goal=hypothesis_goal,
          min_threshold=min_threshold,
          max_threshold=max_threshold,
          condition_expression=condition_expression,
          identifier_field=identifier_field,
          include_significance_gate=include_significance_gate,
          identifier_coverage_payload=identifier_coverage_payload,
      )

    extractor_metric = paired_beta_metrics[1] if paired_beta_metrics is not None else target_metric
    if extractor_metric != target_metric:
      audit = PreFlightValidator.audit(
          target_metric=extractor_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          match_mode=match_mode,
          identifier_field=identifier_field,
      )
    stage1_path = self.template_dir / "stage1_extractors" / f"{extractor_metric}.yl2"
    if not stage1_path.exists():
      raise FileNotFoundError(f"Missing Stage 1 template: {stage1_path}")
    stage1_content = self._rebind_entity_field(
        self._strip_identifier_swap_note(stage1_path.read_text().strip()), extractor_metric, audit["target_field"])

    model_key = statistical_model
    stage2_file = self.STAGE2_TEMPLATES.get(statistical_model)
    if not stage2_file:
      raise ValueError(f"Unknown statistical model: '{statistical_model}'")
    stage2_path = self.template_dir / "stage2_math_models" / stage2_file
    if not stage2_path.exists():
      raise FileNotFoundError(f"Missing Stage 2 template: {stage2_path}")
    stage2_raw = stage2_path.read_text().strip()

    if statistical_model == StatisticalModel.FIRST_SEEN_NOVELTY:
      if int(min_novelty_events) < 1:
        raise ValueError(f"min_novelty_events must be >= 1, got {min_novelty_events}.")
      if target_metric not in PF11_POPULATED_FIRST_SEEN_METRICS:
        self.last_advisories.append(
            f"PF-11 coverage advisory: metrics.{target_metric}(..., metric: first_seen) returned 0 rows "
            "in the empirical gus-sdl baseline (17/38 unpopulated metrics); verify tenant population or "
            "pair with raw/ECG context if 0 rows return."
        )
      stage1_content = self._inject_stage1_first_seen_novelty(
          stage1_content,
          extractor_metric=extractor_metric,
          metric_arg=audit["metric_arg"],
          novelty_subkey_field=novelty_subkey_field,
      )

    # Multi-key extractors: determine the metric's full baseline tuple and drop non-dimension Stage 1 match keys.
    group_keys, dropped_keys = self._mad_group_keys(stage1_content)
    stage1_content = self._drop_stage1_match_keys(stage1_content, dropped_keys)

    if paired_beta_metrics is not None:
      fail_m, total_m = paired_beta_metrics
      _, obs_map = mc.triad_event_selection((total_m, fail_m))
      fail_agg = obs_map[fail_m]
      stage1_content = re.sub(
          r"^[ \t]*\$observed_val\s*=\s*[^\n]+\n",
          (
              "    $obs_total = count(metadata.id)\n"
              f"    $obs_fail = {fail_agg}\n"
              "    $observed_val = $obs_fail\n"
          ),
          stage1_content,
          count=1,
          flags=re.M,
      )
      sum_call_re = re.compile(
          r"^[ \t]*\$historical_sum\s*=\s*max\(metrics\."
          + re.escape(total_m)
          + r"\(\s*period:\s*1d,\s*window:\s*30d,\s*metric:\s*event_count_sum,\s*agg:\s*sum,\s*([^)]+?)\s*\)\)[ \t]*\n",
          re.M | re.S,
      )
      sum_match = sum_call_re.search(stage1_content)
      if not sum_match:
        raise ValueError(f"Could not extract historical_sum dimensions from {total_m}.yl2")
      dims_block = sum_match.group(1).strip()
      paired_sums = (
          f"    $hist_fail_sum = max(metrics.{fail_m}(\n"
          "        period: 1d, window: 30d, metric: event_count_sum, agg: sum,\n"
          f"        {dims_block}\n"
          "    ))\n"
          f"    $hist_total_sum = max(metrics.{total_m}(\n"
          "        period: 1d, window: 30d, metric: event_count_sum, agg: sum,\n"
          f"        {dims_block}\n"
          "    ))\n"
      )
      stage1_content = stage1_content[:sum_match.start()] + paired_sums + stage1_content[sum_match.end():]
      stage1_content = self._prune_unused_metrics_lookups(stage1_content, stage2_raw)
    elif statistical_model == StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD:
      stage1_content = self._inject_stage1_adaptive_schedule(
          stage1_content,
          tenant_tz=tenant_tz,
          biz_start_hour=biz_start_hour,
          biz_end_hour=biz_end_hour,
          learned_active_hours=learned_active_hours,
      )
      stage1_content = self._prune_unused_metrics_lookups(stage1_content, stage2_raw)
    elif statistical_model == StatisticalModel.FIRST_SEEN_NOVELTY:
      stage1_content = self._prune_unused_metrics_lookups(stage1_content, stage2_raw)

    if intraday_hourly:
      stage1_content = self._inject_stage1_intraday_hourly(
          stage1_content,
          extractor_metric=extractor_metric,
          metric_arg=audit["metric_arg"],
          include_first_seen=(statistical_model == StatisticalModel.FIRST_SEEN_NOVELTY),
          paired_beta_metrics=paired_beta_metrics,
      )
      stage2_raw = self._inject_root_intraday_hourly(stage2_raw, statistical_model)

    # Harmonize Stage 2 entity variable with Stage 1 match variable ($user, $host, $entity, $sa)
    match_var_match = re.search(r'match:\s+([$][a-zA-Z0-9_]+)', stage1_content)
    primary_var = match_var_match.group(1) if match_var_match else "$entity"
    entity_name = primary_var.lstrip("$")

    if primary_var != "$entity":
      stage2_raw = stage2_raw.replace("$entity = $stage1_extract.entity", f"{primary_var} = $stage1_extract.{entity_name}")
      stage2_raw = stage2_raw.replace("$entity", primary_var)
      # Multi-stage modules (e.g. MAD's mad_center / mad_spread) reference sibling stages' match field too.
      stage2_raw = re.sub(r'(\$[a-zA-Z0-9_]+)\.entity\b', rf'\1.{entity_name}', stage2_raw)

    if statistical_model in (StatisticalModel.MAD, StatisticalModel.QUANTILE_IQR_SKEW):
      # MAD needs the daily rows of the raw search window as its empirical series, so the root keeps
      # `$entity, $ws by 1d` in every mode; Mode A / Mode B differ only in how many recent days are scored.
      if scoring_days is None:
        scoring_days = 1 if match_mode == MatchMode.FLEET_ROLLUP else 7
      if scoring_days < 1:
        raise ValueError(f"scoring_days must be >= 1, got {scoring_days}")
      end = datetime.datetime.strptime(scoring_end_date, "%Y-%m-%d") if scoring_end_date else \
          datetime.datetime.now(datetime.timezone.utc)
      first_scored_date = (end - datetime.timedelta(days=scoring_days - 1)).strftime("%Y-%m-%d")
      if "$in_scoring_window" not in stage1_content:
        stage1_content = re.sub(
            r'(^[ \t]*\$observed_val\s*=\s*[^\n]+\n)',
            r'\1    $in_scoring_window = max(if(timestamp.get_date(metadata.event_timestamp.seconds) >= "{{first_scored_date}}", 1, 0))\n',
            stage1_content,
            count=1,
            flags=re.M,
        )
      if "$pre_obs" not in stage1_content:
        stage1_content = re.sub(
            r'(^[ \t]*\$in_scoring_window\s*=\s*[^\n]+\n)',
            (
                r'\1'
                r'    $obs_float = 1.0 * $observed_val\n'
                r'    $pre_obs = if($in_scoring_window = 0, $obs_float, 0.0)\n'
                r'    $pre_obs_sq = $pre_obs * $pre_obs\n'
                r'    $pre_day = if($in_scoring_window = 0, 1, 0)\n'
            ),
            stage1_content,
            count=1,
            flags=re.M,
        )
      stage1_content = stage1_content.replace("{{first_scored_date}}", first_scored_date)
      # Keep the module's one-line title; its long design notes stay in the template, not in every query.
      for stage_hdr in ("stage mad_center", "stage quantile_envelope"):
        if stage_hdr in stage2_raw:
          head, sep, tail = stage2_raw.partition(stage_hdr)
          head_lines = head.splitlines()
          stage2_raw = "\n".join(head_lines[:1]) + "\n" + sep + tail
          break
      stage2_raw = stage2_raw.replace("{{first_scored_date}}", first_scored_date)
      stage2_raw = self._expand_mad_keys(stage2_raw, primary_var, group_keys[1:])
      # MAD itself never reads metrics.*; keep only the lookups the root consumes (Z cross-check).
      stage1_content = self._prune_unused_metrics_lookups(stage1_content, stage2_raw)
    else:
      if match_mode == MatchMode.FLEET_ROLLUP:
        stage2_raw = stage2_raw.replace(f"match:\n  {primary_var}, $ws by 1d", f"match:\n  {primary_var}")
        stage2_raw = stage2_raw.replace(f"match:\n  {primary_var}, $ws by 1h", f"match:\n  {primary_var}")
        stage2_raw = stage2_raw.replace("$ws = $stage1_extract.window_start\n", "")
      stage2_raw = self._expand_mad_keys(stage2_raw, primary_var, group_keys[1:])

    stage2_rendered = stage2_raw.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
    if "{{min_novelty_events}}" in stage2_rendered:
      stage2_rendered = stage2_rendered.replace("{{min_novelty_events}}", str(max(1, int(min_novelty_events))))
    if "{{min_awakening_volume}}" in stage2_rendered:
      if int(min_awakening_volume) < 1:
        raise ValueError(f"min_awakening_volume must be >= 1, got {min_awakening_volume}.")
      stage2_rendered = stage2_rendered.replace("{{min_awakening_volume}}", str(int(min_awakening_volume)))
    if "{{prior_alpha0}}" in stage2_rendered or "{{prior_beta0}}" in stage2_rendered:
      is_beta_binom = statistical_model == StatisticalModel.BAYESIAN_BETA_BINOMIAL
      def_a0 = DEFAULT_BETA_PRIOR_ALPHA0 if is_beta_binom else DEFAULT_GAMMA_PRIOR_ALPHA0
      def_b0 = DEFAULT_BETA_PRIOR_BETA0 if is_beta_binom else DEFAULT_GAMMA_PRIOR_BETA0
      if prior_alpha0 is not None or prior_beta0 is not None:
        eff_a0 = float(prior_alpha0 if prior_alpha0 is not None else def_a0)
        eff_b0 = float(prior_beta0 if prior_beta0 is not None else def_b0)
        if eff_a0 <= 0.0 or eff_b0 <= 0.0:
          raise ValueError(f"Empirical Bayes prior hyperparameters must be positive, got ({eff_a0}, {eff_b0}).")
      elif fleet_prior_payload is not None:
        eff_a0, eff_b0 = (
            fit_beta_prior_from_fleet(fleet_prior_payload)
            if is_beta_binom
            else fit_gamma_prior_from_fleet(fleet_prior_payload)
        )
      else:
        eff_a0, eff_b0 = (def_a0, def_b0)
      stage2_rendered = stage2_rendered.replace("{{prior_alpha0}}", str(eff_a0))
      stage2_rendered = stage2_rendered.replace("{{prior_beta0}}", str(eff_b0))
    stage2_rendered = _apply_byte_dispersion_floor(
        stage2_rendered,
        target_metric,
        byte_dispersion_floor=byte_dispersion_floor,
    )

    # Noise Level & Significance Threshold Conditioning: resolve the model's default root gate and
    # apply any analyst override (replaces the default gate clause; other clauses are kept).
    del apply_threshold_condition  # retained for API compatibility; the default gate is always applied
    stage2_rendered = self._apply_significance_gate(
        stage2_rendered,
        anomaly_threshold=anomaly_threshold,
        fold_change_threshold=fold_change_threshold,
        robust_threshold=robust_threshold,
        tukey_excess_threshold=tukey_excess_threshold,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        include_significance_gate=include_significance_gate,
    )
    gate = self.root_condition(stage2_rendered)
    if not include_significance_gate:
      gate_label = (
          f"{gate} (NO-GATE significance threshold omitted for post-query Euclidean fusion)"
          if gate
          else "NONE (NO-GATE decoupled sector for post-query Euclidean fusion)"
      )
    else:
      gate_label = gate or "NONE (model has no significance threshold; see template NO-GATE note)"

    model_label = statistical_model.value if hasattr(statistical_model, "value") else str(statistical_model)
    model_desc = self.MODEL_DESCRIPTIONS.get(model_key) or self.MODEL_DESCRIPTIONS.get(statistical_model)
    desc_line = f"// Model Architecture: {model_desc}\n" if model_desc else ""
    header = (
        "// ============================================================================\n"
        "// METHODOLOGY & HUNTING GOAL\n"
        f"// Goal: {hypothesis_goal or ('Hunt for statistical outliers in ' + target_metric)}\n"
        f"// Target Telemetry: {audit['event_label']} (Dimensions: {audit['target_field']})\n"
        f"// Event Filter: {' AND '.join(audit['event_filter'])}\n"
        f"// Statistical Model: {model_label}\n"
        f"{desc_line}"
        f"// Significance Gate: {gate_label}\n"
        f"// Match Mode: {match_mode.value}\n"
        f"// Baseline Window: 30-Day Historical Pre-Computed Metrics (Min Active Days: {audit['min_baseline_days']})\n"
        "// ============================================================================\n\n"
    )

    return f"{header}{stage1_content}\n\n{stage2_rendered}\n"

  def build_pipeline_query(
      self,
      pipeline_type: PipelineArchitecture,
      target_metric: Optional[str] = None,
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = DEFAULT_ANOMALY_THRESHOLD,
      min_baseline_days: Optional[int] = None,
      hypothesis_goal: Optional[str] = None,
      service_account: Optional[str] = None,
      min_threshold: Optional[float] = None,
      max_threshold: Optional[float] = None,
      condition_expression: Optional[str] = None,
      cohort_entities: Optional[List[str]] = None,
      target_entity: Optional[str] = None,
      target_metrics: Optional[List[str]] = None,
      identifier_field: Optional[str] = None,
      fold_change_threshold: float = DEFAULT_FOLD_CHANGE_THRESHOLD,
      fusion_threshold_sq: float = DEFAULT_FUSION_THRESHOLD_SQ,
      tukey_excess_threshold: float = DEFAULT_TUKEY_EXCESS_THRESHOLD,
      include_significance_gate: bool = True,
      byte_dispersion_floor: Optional[float] = None,
      identifier_coverage_payload: Optional[Any] = None,
      prior_alpha0: Optional[float] = None,
      prior_beta0: Optional[float] = None,
      fleet_prior_payload: Optional[Any] = None,
      min_awakening_volume: int = DEFAULT_MIN_AWAKENING_VOLUME,
      min_active_days: Optional[int] = None,
      max_asset_age_days: float = 30.0,
      max_fleet_prevalence: Optional[int] = None,
      max_fleet_adopters: Optional[int] = None,
      max_diversity_ratio: float = 0.05,
      min_concentration_ratio: float = 0.85,
      min_raw_events: int = 25,
      novelty_subkey_field: Optional[str] = None,
      min_novelty_events: int = 1,
  ) -> str:
    """Renders 3-Stage and 4-Stage advanced DAG pipelines, then resolves the root significance gate.

    Pipelines whose template carries a default gate placeholder (see GATE_PLACEHOLDERS) get it filled
    here, and min_threshold / max_threshold / condition_expression replace that default gate.
    Renderers that resolve their own gate (sector fusion, the hybrid_metric_* family) are left as is.
    """
    if isinstance(pipeline_type, str) and not isinstance(pipeline_type, PipelineArchitecture):
      raw_pipe = pipeline_type.strip().upper().replace("-", "_").replace(" ", "_")
      if raw_pipe == "DESTINATION_DIVERSITY_CONCENTRATION":
        raw_pipe = "DESTINATION_DIVERSITY_CONCENTRATION_2STAGE"
      if raw_pipe in PipelineArchitecture.__members__:
        pipeline_type = PipelineArchitecture[raw_pipe]
    if pipeline_type in RETIRED_PIPELINE_ARCHITECTURES:
      raise ValueError(RETIRED_PIPELINE_ARCHITECTURES[pipeline_type])
    eff_min_baseline = min_active_days if min_active_days is not None else min_baseline_days
    rendered = self._render_pipeline(
        pipeline_type,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        min_baseline_days=eff_min_baseline,
        hypothesis_goal=hypothesis_goal,
        service_account=service_account,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        cohort_entities=cohort_entities,
        target_entity=target_entity,
        target_metrics=target_metrics,
        identifier_field=identifier_field,
        fusion_threshold_sq=fusion_threshold_sq,
        byte_dispersion_floor=byte_dispersion_floor,
        identifier_coverage_payload=identifier_coverage_payload,
        prior_alpha0=prior_alpha0,
        prior_beta0=prior_beta0,
        fleet_prior_payload=fleet_prior_payload,
        min_active_days=min_active_days,
        max_asset_age_days=max_asset_age_days,
        max_fleet_prevalence=max_fleet_prevalence,
        max_fleet_adopters=max_fleet_adopters,
        max_diversity_ratio=max_diversity_ratio,
        min_concentration_ratio=min_concentration_ratio,
        min_raw_events=min_raw_events,
        novelty_subkey_field=novelty_subkey_field,
        min_novelty_events=min_novelty_events,
    )
    out = self._apply_significance_gate(
        rendered,
        anomaly_threshold=anomaly_threshold,
        fold_change_threshold=fold_change_threshold,
        fusion_threshold_sq=fusion_threshold_sq,
        tukey_excess_threshold=tukey_excess_threshold,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        only_if_template_gate=True,
        include_significance_gate=include_significance_gate,
    )
    if not include_significance_gate and "// Significance Gate: NONE" not in out:
      out = "// Significance Gate: NONE (NO-GATE decoupled sector for post-query Euclidean fusion)\n" + out
    return out

  def _render_pipeline(
      self,
      pipeline_type: PipelineArchitecture,
      target_metric: Optional[str] = None,
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = DEFAULT_ANOMALY_THRESHOLD,
      min_baseline_days: Optional[int] = None,
      hypothesis_goal: Optional[str] = None,
      service_account: Optional[str] = None,
      min_threshold: Optional[float] = None,
      max_threshold: Optional[float] = None,
      condition_expression: Optional[str] = None,
      cohort_entities: Optional[List[str]] = None,
      target_entity: Optional[str] = None,
      target_metrics: Optional[List[str]] = None,
      identifier_field: Optional[str] = None,
      fusion_threshold_sq: float = DEFAULT_FUSION_THRESHOLD_SQ,
      byte_dispersion_floor: Optional[float] = None,
      identifier_coverage_payload: Optional[Any] = None,
      prior_alpha0: Optional[float] = None,
      prior_beta0: Optional[float] = None,
      fleet_prior_payload: Optional[Any] = None,
      min_active_days: Optional[int] = None,
      max_asset_age_days: float = 30.0,
      max_fleet_prevalence: Optional[int] = None,
      max_fleet_adopters: Optional[int] = None,
      max_diversity_ratio: float = 0.05,
      min_concentration_ratio: float = 0.85,
      min_raw_events: int = 25,
      novelty_subkey_field: Optional[str] = None,
      min_novelty_events: int = 1,
  ) -> str:
    """Renders 3-Stage and 4-Stage advanced DAG pipelines (gate placeholders left for build_pipeline_query)."""
    if identifier_field is None and identifier_coverage_payload is not None:
      probe_metric = target_metric or ((target_metrics or [None])[0]) or "http_queries_total"
      if probe_metric in METRIC_CATALOG and entity_type in METRIC_CATALOG[probe_metric].supported_entity_types:
        identifier_field = select_identifier_from_coverage(
            identifier_coverage_payload,
            target_metric=probe_metric,
            entity_type=entity_type,
        )
    if pipeline_type in (PipelineArchitecture.MULTI_SECTOR_FUSION_4STAGE, PipelineArchitecture.DUAL_SECTOR_FUSION_3STAGE):
      metrics = list(target_metrics or self.DEFAULT_FUSION_METRICS)
      if len(metrics) != 2:
        raise ValueError(f"Sector fusion takes exactly 2 metrics, got {len(metrics)}: {metrics}")
      sectors = [mc.SectorSpec(m, self._sector_entity_field(m, entity_type, identifier_field)) for m in metrics]
      return self.build_sector_fusion_query(
          sectors[0], sectors[1],
          four_stage=pipeline_type == PipelineArchitecture.MULTI_SECTOR_FUSION_4STAGE,
          min_baseline_days=min_baseline_days if min_baseline_days is not None else DEFAULT_MIN_BASELINE_DAYS,
          hypothesis_goal=hypothesis_goal,
          min_threshold=min_threshold,
          max_threshold=max_threshold,
          condition_expression=condition_expression,
          fusion_threshold_sq=fusion_threshold_sq,
      )

    elif pipeline_type == PipelineArchitecture.RADAR_360_DECOUPLED_SECTOR:
      pipeline_file = self.template_dir / "pipelines" / "radar_360_decoupled_sector.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      return pipeline_file.read_text().strip() + "\n"

    elif pipeline_type == PipelineArchitecture.RADAR_360_SECTOR_WEB_HTTP:
      pipeline_file = self.template_dir / "pipelines" / "radar_360_sector_web_http.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      return pipeline_file.read_text().strip() + "\n"

    elif pipeline_type == PipelineArchitecture.RADAR_360_SECTOR_ALERT:
      pipeline_file = self.template_dir / "pipelines" / "radar_360_sector_alert.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      return pipeline_file.read_text().strip() + "\n"

    elif pipeline_type == PipelineArchitecture.HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE:
      if entity_type == EntityType.RESOURCE:
        raise ValueError(
            "HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE supports EntityType.ASSET and EntityType.USER "
            "(metrics.http_queries_total does not support HTTP_USER_AGENT + TARGET_HOSTNAME without host/user)."
        )
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_http_ua_prevalence_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      if identifier_field or entity_type != EntityType.ASSET:
        ent_field = PreFlightValidator.resolve_identifier_field("http_queries_total", entity_type, identifier_field)
        if ent_field != "principal.asset.hostname":
          raw = raw.replace("principal.asset.hostname = $entity", f"{ent_field} = $entity")
          raw = raw.replace("principal.asset.hostname: principal.asset.hostname", f"{ent_field}: {ent_field}")
          raw = raw.replace("count_distinct(principal.asset.hostname)", f"count_distinct({ent_field})")
          raw = raw.replace("array_distinct(principal.asset.hostname)", f"array_distinct({ent_field})")
      eff_days = int(min_baseline_days if min_baseline_days is not None else DEFAULT_MIN_BASELINE_DAYS)
      eff_adopters = int(
          max_fleet_adopters
          if max_fleet_adopters is not None
          else (max_fleet_prevalence if max_fleet_prevalence is not None else 2)
      )
      raw = raw.replace("$active_baseline_days >= 7", f"$active_baseline_days >= {eff_days}")
      raw = raw.replace("and $personal_z >= 3.0", f"and $personal_z >= {anomaly_threshold}")
      raw = raw.replace("and $fleet_adopters <= 2", f"and $fleet_adopters <= {eff_adopters}")
      if hypothesis_goal:
        raw = f"// Goal: {hypothesis_goal}\n" + raw
      rendered = raw
      if condition_expression:
        rendered = self._set_root_condition(rendered, condition_expression)
      elif min_threshold is not None and max_threshold is not None:
        order_match = re.search(r'order:\s*\n\s*([$][a-zA-Z0-9_]+)', rendered)
        score_var = order_match.group(1) if order_match else "$normalized_odds_score"
        rendered = self._set_root_condition(rendered, f"{score_var} >= {min_threshold} and {score_var} < {max_threshold}")
      elif min_threshold is not None:
        order_match = re.search(r'order:\s*\n\s*([$][a-zA-Z0-9_]+)', rendered)
        score_var = order_match.group(1) if order_match else "$normalized_odds_score"
        rendered = self._set_root_condition(rendered, f"{score_var} >= {min_threshold}")
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.HTTP_ERROR_RATIO_SURGE_2STAGE:
      eff_fail_metric = target_metric or "http_queries_fail"
      if not (
          eff_fail_metric == "http_queries_fail"
          and entity_type == EntityType.ASSET
          and (not identifier_field or identifier_field == "principal.asset.hostname")
      ):
        return self.build_failure_ratio_surge_query(
            fail_metric=eff_fail_metric,
            entity_type=entity_type,
            anomaly_threshold=anomaly_threshold,
            hypothesis_goal=hypothesis_goal,
            identifier_field=identifier_field,
        )
      pipeline_file = self.template_dir / "pipelines" / "http_error_ratio_surge_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      if hypothesis_goal:
        raw = f"// Goal: {hypothesis_goal}\n" + raw
      return raw + "\n"

    elif pipeline_type == PipelineArchitecture.HTTP_TARGET_SURGE_2STAGE:
      pipeline_file = self.template_dir / "pipelines" / "http_target_surge_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      if identifier_field or entity_type == EntityType.USER:
        ent_field = PreFlightValidator.resolve_identifier_field("http_queries_total", entity_type, identifier_field)
        if ent_field != "principal.asset.hostname":
          raw = raw.replace("principal.asset.hostname = $host", f"{ent_field} = $host")
          raw = raw.replace("principal.asset.hostname: principal.asset.hostname", f"{ent_field}: {ent_field}")
          raw = raw.replace("count_distinct(principal.asset.hostname)", f"count_distinct({ent_field})")
      eff_days = int(min_baseline_days if min_baseline_days is not None else DEFAULT_MIN_BASELINE_DAYS)
      eff_hosts = int(
          max_fleet_prevalence
          if max_fleet_prevalence is not None
          else (max_fleet_adopters if max_fleet_adopters is not None else 2)
      )
      raw = raw.replace("$active_baseline_days >= 7", f"$active_baseline_days >= {eff_days}")
      raw = raw.replace("and $target_z >= 3.0", f"and $target_z >= {anomaly_threshold}")
      raw = raw.replace("and $connecting_fleet_hosts <= 2", f"and $connecting_fleet_hosts <= {eff_hosts}")
      if hypothesis_goal:
        raw = f"// Goal: {hypothesis_goal}\n" + raw
      return raw + "\n"

    elif pipeline_type == PipelineArchitecture.DUAL_BASELINE_3STAGE:
      if not target_metric:
        target_metric = "http_queries_total"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "dual_baseline_delta_z_3stage.yl2"
      raw = pipeline_file.read_text().strip()
      metric_type_arg = f"metric: {audit['metric_arg']}"

      rendered = _fill_event_filter(raw, "{{event_filter}}", audit["event_filter"])
      rendered = rendered.replace("{{entity_field}}", audit["target_field"])
      rendered = rendered.replace("{{observed_agg}}", audit["observed_agg"])
      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = _apply_byte_dispersion_floor(rendered, target_metric, byte_dispersion_floor=byte_dispersion_floor)
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.EMPIRICAL_BAYES_3STAGE:
      if not target_metric:
        target_metric = "http_queries_total"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "hierarchical_empirical_bayes_3stage.yl2"
      raw = pipeline_file.read_text().strip()
      metric_type_arg = f"metric: {audit['metric_arg']}"

      if prior_alpha0 is not None or prior_beta0 is not None:
        eff_a0 = float(prior_alpha0 if prior_alpha0 is not None else DEFAULT_GAMMA_PRIOR_ALPHA0)
        eff_b0 = float(prior_beta0 if prior_beta0 is not None else DEFAULT_GAMMA_PRIOR_BETA0)
        if eff_a0 <= 0.0 or eff_b0 <= 0.0:
          raise ValueError(f"Empirical Bayes prior hyperparameters must be positive, got ({eff_a0}, {eff_b0}).")
      elif fleet_prior_payload is not None:
        eff_a0, eff_b0 = fit_gamma_prior_from_fleet(fleet_prior_payload)
      else:
        eff_a0, eff_b0 = (DEFAULT_GAMMA_PRIOR_ALPHA0, DEFAULT_GAMMA_PRIOR_BETA0)

      rendered = _fill_event_filter(raw, "{{event_filter}}", audit["event_filter"])
      rendered = rendered.replace("{{entity_field}}", audit["target_field"])
      rendered = rendered.replace("{{observed_agg}}", audit["observed_agg"])
      rendered = rendered.replace(
          "{{target_metric_func_sum}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: sum, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = rendered.replace("{{prior_alpha0}}", str(eff_a0))
      rendered = rendered.replace("{{prior_beta0}}", str(eff_b0))
      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH:
      pipeline_file = self.template_dir / "pipelines" / "cloud_repository_scope_dual_branch.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      if target_metric and target_metric.endswith("_fail"):
        raw = raw.replace("    $sa = principal.user.userid", '    not security_result.action = "ALLOW"\n    $sa = principal.user.userid')
        for fam in ("resource_read", "resource_written", "resource_deletion", "resource_creation"):
          raw = raw.replace(f"metrics.{fam}_total(", f"metrics.{fam}_fail(")
      elif target_metric and target_metric.endswith("_success"):
        raw = raw.replace("    $sa = principal.user.userid", '    security_result.action = "ALLOW"\n    $sa = principal.user.userid')
        for fam in ("resource_read", "resource_written", "resource_deletion", "resource_creation"):
          raw = raw.replace(f"metrics.{fam}_total(", f"metrics.{fam}_success(")
      eff_id_field = identifier_field
      if eff_id_field is None and identifier_coverage_payload is not None:
        eff_id_field = select_identifier_from_coverage(
            identifier_coverage_payload,
            target_metric=target_metric or "resource_read_total",
            entity_type=EntityType.USER,
        )
      if eff_id_field:
        sa_audit = PreFlightValidator.audit(
            target_metric=target_metric or "resource_read_total",
            entity_type=EntityType.USER,
            min_baseline_days=min_baseline_days,
            identifier_field=eff_id_field,
        )
        user_field = sa_audit["target_field"]
        if user_field != "principal.user.userid":
          raw = raw.replace("$sa = principal.user.userid", f"$sa = {user_field}")
          raw = raw.replace("principal.user.userid: principal.user.userid", f"{user_field}: {user_field}")
          if not service_account and user_field not in ("principal.user.userid", "principal.user.email_addresses"):
            raw = re.sub(r"^[ \t]*\$sa\s*=\s*/@.*?nocase[ \t]*\n", "", raw, flags=re.M)
      if service_account:
        sa_regex_pattern = r"(?:\(\s*)?\$sa\s*=\s*/@.*?nocase(?:\s*\))?"
        sa_binding = f'    $sa = "{self._escape_yaral_literal(service_account)}"'
        raw = re.sub(sa_regex_pattern, sa_binding, raw, flags=re.DOTALL)
      if min_baseline_days is not None and int(min_baseline_days) != 7:
        raw = raw.replace(" >= 7 ", f" >= {int(min_baseline_days)} ")
      if hypothesis_goal:
        raw = f"// Goal: {hypothesis_goal}\n" + raw
      # Significance gate: the template's `$composite_risk >= {{anomaly_threshold}}` default (and any
      # min/max/condition override) is resolved by build_pipeline_query.
      return raw + "\n"

    elif pipeline_type == PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL:
      if not target_metric:
        target_metric = "auth_attempts_total"
        entity_type = EntityType.USER
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "part_of_the_whole_multilevel.yl2"
      raw = pipeline_file.read_text().strip()
      metric_type_arg = f"metric: {audit['metric_arg']}"
      obs_agg = audit["observed_agg"]

      entity_var = "$user" if entity_type == EntityType.USER else "$host"
      entity_name = entity_var.lstrip("$")
      effective_cohort = list(cohort_entities) if cohort_entities else []
      if effective_cohort and target_entity and target_entity not in effective_cohort:
        effective_cohort.append(target_entity)

      # WS4-RADAR-COHORT: Exclude Windows machine/system accounts from human USER cohorts unless
      # the analyst explicitly targets a system/machine account itself.
      sys_acct_py_re = re.compile(r"^(system|local service|network service|.*\$)$", re.I)
      guard_lines: List[str] = []
      if entity_type == EntityType.USER and not (target_entity and sys_acct_py_re.match(target_entity)):
        guard_lines = [f"not re.regex({entity_var}, `(?i)^(system|local service|network service|.*\\$$)`)"]

      # Peer group rule (template header): no named cohort -> drop the TEAM COHORT blocks
      # (fleet only, order by $z_vs_enterprise); named cohort -> keep them, order by $z_vs_team.
      rendered = _apply_team_cohort_blocks(raw, keep=bool(effective_cohort))
      if effective_cohort:
        if len(effective_cohort) > 1:
          cohort_filter = "(\n      " + " or\n      ".join(f'$u = "{self._escape_yaral_literal(c)}"' for c in effective_cohort) + "\n    )"
        else:
          cohort_filter = f'$u = "{self._escape_yaral_literal(effective_cohort[0])}"'
        rendered = rendered.replace("{{cohort_filter}}", cohort_filter)
        rendered = rendered.replace("order:\n  $z_vs_enterprise desc", "order:\n  $z_vs_team desc")
        rendered = rendered.replace("$z_vs_enterprise >= {{anomaly_threshold}}", "$z_vs_team >= {{anomaly_threshold}}")
      if min_threshold is not None:
        rendered = rendered.replace("< {{anomaly_threshold}},", f"< {min_threshold},")

      if target_entity:
        target_filter = f'{entity_var} = "{self._escape_yaral_literal(target_entity)}"'
      elif effective_cohort:
        if len(effective_cohort) > 1:
          target_filter = "(\n  " + " or\n  ".join(f'{entity_var} = "{self._escape_yaral_literal(c)}"' for c in effective_cohort) + "\n)"
        else:
          target_filter = f'{entity_var} = "{self._escape_yaral_literal(effective_cohort[0])}"'
      else:
        target_filter = f'{entity_var} != ""'

      b_floor = resolve_byte_dispersion_floor(target_metric, byte_dispersion_floor=byte_dispersion_floor)
      var_floor_str = f"{b_floor * b_floor:.1f}" if b_floor is not None else "1.0"

      rendered = _fill_event_filter(rendered, "{{event_filter}}", audit["event_filter"])
      rendered = _fill_event_filter(rendered, "{{cohort_population_guard}}", guard_lines)
      rendered = rendered.replace("{{var_floor}}", var_floor_str)
      rendered = rendered.replace("{{entity_field}}", audit["target_field"])
      rendered = rendered.replace("{{entity_var}}", entity_var)
      rendered = rendered.replace("{{entity_name}}", entity_name)
      rendered = rendered.replace("{{observation_agg}}", obs_agg)
      rendered = rendered.replace("{{target_entity_filter}}", target_filter)
      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = _apply_byte_dispersion_floor(rendered, target_metric, byte_dispersion_floor=byte_dispersion_floor)
      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL:
      if not target_metrics:
        if entity_type == EntityType.USER:
          target_metrics = ["auth_attempts_total", "auth_attempts_fail", "auth_attempts_success"]
        else:
          target_metrics = ["network_bytes_outbound", "network_bytes_inbound", "network_bytes_total"]

      triad_audit = PreFlightValidator.audit_triad(
          target_metrics=target_metrics,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      triad_filter, triad_obs = self._triad_event_selection(target_metrics[:3])
      pipeline_file = self.template_dir / "pipelines" / "part_of_the_whole_triad_multilevel.yl2"
      raw = pipeline_file.read_text().strip()

      entity_var = "$user" if entity_type == EntityType.USER else "$host"
      entity_name = entity_var.lstrip("$")
      effective_cohort = list(cohort_entities) if cohort_entities else []
      if effective_cohort and target_entity and target_entity not in effective_cohort:
        effective_cohort.append(target_entity)

      sys_acct_py_re = re.compile(r"^(system|local service|network service|.*\$)$", re.I)
      guard_lines = []
      if entity_type == EntityType.USER and not (target_entity and sys_acct_py_re.match(target_entity)):
        guard_lines = [f"not re.regex({entity_var}, `(?i)^(system|local service|network service|.*\\$$)`)"]

      if target_entity:
        target_filter = f'{entity_var} = "{self._escape_yaral_literal(target_entity)}"'
      elif effective_cohort:
        if len(effective_cohort) > 1:
          target_filter = "(\n  " + " or\n  ".join(f'{entity_var} = "{self._escape_yaral_literal(c)}"' for c in effective_cohort) + "\n)"
        else:
          target_filter = f'{entity_var} = "{self._escape_yaral_literal(effective_cohort[0])}"'
      else:
        target_filter = f'{entity_var} != ""'

      # Peer group rule (template header): with no named cohort the team stage would just
      # recompute the fleet, so the marked TEAM COHORT blocks are dropped (fleet only).
      rendered = _apply_team_cohort_blocks(raw, keep=bool(effective_cohort))
      if effective_cohort:
        if len(effective_cohort) > 1:
          cohort_filter = "(\n      " + " or\n      ".join(f'$u = "{self._escape_yaral_literal(c)}"' for c in effective_cohort) + "\n    )"
        else:
          cohort_filter = f'$u = "{self._escape_yaral_literal(effective_cohort[0])}"'
        rendered = rendered.replace("{{cohort_filter}}", cohort_filter)
        rendered = rendered.replace("order:\n  $d_vs_fleet_sq desc", "order:\n  $d_vs_team_sq desc")
        rendered = rendered.replace("$d_vs_fleet_sq >= {{fusion_threshold_sq}}", "$d_vs_team_sq >= {{fusion_threshold_sq}}")
      if min_threshold is not None:
        eff_min_sq = round(float(min_threshold) ** 2, 6) if float(min_threshold) > 0 else 0.0
        rendered = rendered.replace("< {{fusion_threshold_sq}},", f"< {eff_min_sq},")

      rendered = _fill_event_filter(rendered, "{{event_filter}}", triad_filter)
      rendered = _fill_event_filter(rendered, "{{cohort_population_guard}}", guard_lines)
      rendered = rendered.replace("{{entity_field}}", triad_audit["target_field"])
      rendered = rendered.replace("{{entity_var}}", entity_var)
      rendered = rendered.replace("{{entity_name}}", entity_name)
      rendered = rendered.replace("{{target_entity_filter}}", target_filter)

      for idx, m in enumerate(target_metrics[:3], 1):
        metric_type_arg = f"metric: {mc.baseline_semantics(m).metric_arg}"
        obs_agg = triad_obs[m]
        m_b_floor = resolve_byte_dispersion_floor(m, byte_dispersion_floor=byte_dispersion_floor)
        m_var_floor_str = f"{m_b_floor * m_b_floor:.1f}" if m_b_floor is not None else "1.0"
        rendered = rendered.replace(f"{{{{m{idx}_var_floor}}}}", m_var_floor_str)
        rendered = rendered.replace(f"{{{{m{idx}_observation_agg}}}}", obs_agg)
        rendered = rendered.replace(
            f"{{{{m{idx}_metric_func_avg}}}}",
            f"metrics.{m}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {triad_audit['target_field']}: {triad_audit['target_field']})"
        )
        rendered = rendered.replace(
            f"{{{{m{idx}_metric_func_stddev}}}}",
            f"metrics.{m}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {triad_audit['target_field']}: {triad_audit['target_field']})"
        )
        rendered = _apply_byte_dispersion_floor(rendered, m, floor_vars=(f"$m{idx}_floor",))

      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.HYBRID_METRIC_RAW_ENRICHMENT_2STAGE:
      if not target_metric:
        target_metric = "network_bytes_outbound"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_raw_enrichment_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      metric_type_arg = f"metric: {audit['metric_arg']}"

      macro_entity_field = audit["target_field"]
      macro_observed_agg = audit["observed_agg"]

      raw_event_type = "NETWORK_HTTP"
      raw_entity_field = _swap_identifier_leaf(
          "principal.asset.hostname" if entity_type == EntityType.ASSET else "principal.user.userid", audit["target_field"])
      raw_event_filter = ""
      raw_signature_field = "network.http.user_agent"
      max_signature_diversity = 2
      min_raw_events = 5

      rendered = raw.replace("{{macro_entity_field}}", macro_entity_field)
      rendered = _fill_event_filter(rendered, "{{macro_event_filter}}", audit["event_filter"])
      rendered = rendered.replace("{{macro_observed_agg}}", macro_observed_agg)

      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, {audit['target_field']}: {audit['target_field']})"
      )

      rendered = rendered.replace("{{raw_event_type}}", raw_event_type)
      rendered = rendered.replace("{{raw_entity_field}}", raw_entity_field)
      rendered = rendered.replace("{{raw_event_filter}}", raw_event_filter)
      rendered = rendered.replace("{{raw_signature_field}}", raw_signature_field)

      rendered = rendered.replace("{{anomaly_threshold}}", str(anomaly_threshold))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = rendered.replace("{{max_signature_diversity}}", str(max_signature_diversity))
      rendered = rendered.replace("{{min_raw_events}}", str(min_raw_events))
      rendered = _apply_byte_dispersion_floor(rendered, target_metric, byte_dispersion_floor=byte_dispersion_floor)

      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered

      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE:
      if not target_metric:
        target_metric = "network_bytes_outbound"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_entropy_concentration_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      metric_type_arg = f"metric: {audit['metric_arg']}"

      macro_entity_field = audit["target_field"]
      macro_observed_agg = audit["observed_agg"]

      raw_event_type = "NETWORK_HTTP"
      raw_entity_field = _swap_identifier_leaf(
          "principal.asset.hostname" if entity_type == EntityType.ASSET else "principal.user.userid", audit["target_field"])
      raw_event_filter = ""
      raw_vocab_field = "target.url"
      raw_intensity_field = "network.sent_bytes" if "outbound" in target_metric else "1"

      rendered = raw.replace("{{macro_entity_field}}", macro_entity_field)
      rendered = _fill_event_filter(rendered, "{{macro_event_filter}}", audit["event_filter"])
      rendered = rendered.replace("{{macro_observed_agg}}", macro_observed_agg)

      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, {audit['target_field']}: {audit['target_field']})"
      )

      rendered = rendered.replace("{{raw_event_type}}", raw_event_type)
      rendered = rendered.replace("{{raw_entity_field}}", raw_entity_field)
      rendered = rendered.replace("{{raw_event_filter}}", raw_event_filter)
      rendered = rendered.replace("{{raw_vocab_field}}", raw_vocab_field)
      rendered = rendered.replace("{{raw_intensity_field}}", raw_intensity_field)

      rendered = rendered.replace("{{anomaly_threshold}}", str(anomaly_threshold))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = rendered.replace("{{max_diversity_ratio}}", f"{float(max_diversity_ratio):.2f}")
      rendered = rendered.replace("{{min_concentration_ratio}}", f"{float(min_concentration_ratio):.2f}")
      rendered = rendered.replace("{{min_raw_events}}", str(int(min_raw_events)))
      rendered = _apply_byte_dispersion_floor(rendered, target_metric, byte_dispersion_floor=byte_dispersion_floor)

      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered

      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE:
      raise ValueError(RETIRED_PIPELINE_ARCHITECTURES[PipelineArchitecture.HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE])

    elif pipeline_type == PipelineArchitecture.HYBRID_METRIC_FLEET_PREVALENCE_2STAGE:
      if not target_metric:
        target_metric = "file_executions_total"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_fleet_prevalence_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      metric_type_arg = "metric: event_count_sum"

      macro_entity_field = audit["target_field"]
      macro_token_field = "principal.process.file.sha256"
      macro_observed_agg = audit["observed_agg"]

      raw_event_type = "PROCESS_LAUNCH"
      raw_token_field = "principal.process.file.sha256"
      raw_event_filter = ""
      fleet_entity_field = audit["target_field"] if entity_type == EntityType.ASSET else "principal.asset.hostname"

      rendered = raw.replace("{{macro_entity_field}}", macro_entity_field)
      rendered = rendered.replace("{{macro_token_field}}", macro_token_field)
      rendered = _fill_event_filter(rendered, "{{macro_event_filter}}", audit["event_filter"])
      rendered = rendered.replace("{{macro_observed_agg}}", macro_observed_agg)

      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, metadata.event_type: metadata.event_type, {macro_entity_field}: {macro_entity_field}, principal.process.file.sha256: principal.process.file.sha256)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, metadata.event_type: metadata.event_type, {macro_entity_field}: {macro_entity_field}, principal.process.file.sha256: principal.process.file.sha256)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, metadata.event_type: metadata.event_type, {macro_entity_field}: {macro_entity_field}, principal.process.file.sha256: principal.process.file.sha256)"
      )

      rendered = rendered.replace("{{raw_event_type}}", raw_event_type)
      rendered = rendered.replace("{{raw_token_field}}", raw_token_field)
      rendered = rendered.replace("{{raw_event_filter}}", raw_event_filter)
      rendered = rendered.replace("{{fleet_entity_field}}", fleet_entity_field)

      eff_prev = int(max_fleet_prevalence if max_fleet_prevalence is not None else 3)
      eff_adopters = int(max_fleet_adopters if max_fleet_adopters is not None else 3)
      rendered = rendered.replace("{{personal_threshold}}", str(anomaly_threshold))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = rendered.replace("{{max_fleet_prevalence}}", str(eff_prev))
      rendered = rendered.replace("{{max_fleet_adopters}}", str(eff_adopters))
      rendered = rendered.replace("{{today_date}}", _today_date())

      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered

      # Noise Level & Significance Threshold Conditioning
      if condition_expression:
        cond_block = f"condition:\n  {condition_expression}\n\n"
        if "\ncondition:\n" in rendered:
          rendered = re.sub(r'\ncondition:\s*\n.*?\n(?=order:)', f"\n{cond_block}", rendered, flags=re.DOTALL)
        else:
          rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", rendered, count=1)
      elif min_threshold is not None and max_threshold is not None:
        order_match = re.search(r'order:\s*\n\s*([$][a-zA-Z0-9_]+)', rendered)
        score_var = order_match.group(1) if order_match else "$composite_risk"
        cond_block = f"condition:\n  {score_var} >= {min_threshold} and {score_var} < {max_threshold}\n\n"
        if "\ncondition:\n" in rendered:
          rendered = re.sub(r'\ncondition:\s*\n.*?\n(?=order:)', f"\n{cond_block}", rendered, flags=re.DOTALL)
        else:
          rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", rendered, count=1)
      elif min_threshold is not None:
        order_match = re.search(r'order:\s*\n\s*([$][a-zA-Z0-9_]+)', rendered)
        score_var = order_match.group(1) if order_match else "$composite_risk"
        cond_block = f"condition:\n  {score_var} >= {min_threshold}\n\n"
        if "\ncondition:\n" in rendered:
          rendered = re.sub(r'\ncondition:\s*\n.*?\n(?=order:)', f"\n{cond_block}", rendered, flags=re.DOTALL)
        else:
          rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", rendered, count=1)
      elif max_threshold is not None:
        order_match = re.search(r'order:\s*\n\s*([$][a-zA-Z0-9_]+)', rendered)
        score_var = order_match.group(1) if order_match else "$composite_risk"
        cond_block = f"condition:\n  {score_var} <= {max_threshold}\n\n"
        if "\ncondition:\n" in rendered:
          rendered = re.sub(r'\ncondition:\s*\n.*?\n(?=order:)', f"\n{cond_block}", rendered, flags=re.DOTALL)
        else:
          rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", rendered, count=1)

      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE:
      if not target_metric:
        target_metric = "file_executions_total"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_derived_file_prevalence_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      extra_filters = [ln for ln in audit["event_filter"] if ln != 'metadata.event_type = "PROCESS_LAUNCH"']
      if extra_filters:
        extra_block = "\n    ".join(extra_filters)
        raw = raw.replace('    metadata.event_type = "PROCESS_LAUNCH"', f'    metadata.event_type = "PROCESS_LAUNCH"\n    {extra_block}')
      if target_metric != "file_executions_total":
        raw = raw.replace("metrics.file_executions_total(", f"metrics.{target_metric}(")
      if audit["target_field"] != "principal.asset.hostname":
        ent_var = "$user" if entity_type == EntityType.USER else "$host"
        ent_name = ent_var.lstrip("$")
        raw = raw.replace("principal.asset.hostname = $host", f"{audit['target_field']} = {ent_var}")
        raw = raw.replace("principal.asset.hostname: principal.asset.hostname", f"{audit['target_field']}: {audit['target_field']}")
        raw = raw.replace("    $host != \"\"", f"    {ent_var} != \"\"")
        raw = raw.replace("$host, $sha256 by 1d", f"{ent_var}, $sha256 by 1d")
        raw = raw.replace("$host = $stage1_process_baseline.host", f"{ent_var} = $stage1_process_baseline.{ent_name}")
      eff_prev = int(max_fleet_prevalence if max_fleet_prevalence is not None else 3)
      rendered = raw.replace("{{anomaly_threshold}}", str(anomaly_threshold))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = rendered.replace("{{max_fleet_prevalence}}", str(eff_prev))
      rendered = rendered.replace("{{today_date}}", _today_date())
      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE:
      if not target_metric:
        target_metric = "http_queries_total"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_derived_domain_prevalence_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      domain_field = "network.dns_domain" if "dns" in target_metric else "target.hostname"
      metric_type_arg = f"metric: {audit['metric_arg']}"
      rendered = _fill_event_filter(raw, "{{event_filter}}", audit["event_filter"])
      rendered = rendered.replace("{{domain_field}}", domain_field)
      if audit["target_field"] != "principal.asset.hostname":
        ent_var = "$user" if entity_type == EntityType.USER else "$host"
        ent_name = ent_var.lstrip("$")
        rendered = rendered.replace("principal.asset.hostname = $host", f"{audit['target_field']} = {ent_var}")
        rendered = rendered.replace("    $host != \"\"", f"    {ent_var} != \"\"")
        rendered = rendered.replace("$host, $domain by 1d", f"{ent_var}, $domain by 1d")
        rendered = rendered.replace("$host = $stage1_query_baseline.host", f"{ent_var} = $stage1_query_baseline.{ent_name}")
      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: {audit['target_field']}, {domain_field}: {domain_field})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: {audit['target_field']}, {domain_field}: {domain_field})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, {audit['target_field']}: {audit['target_field']}, {domain_field}: {domain_field})"
      )
      eff_prev = int(max_fleet_prevalence if max_fleet_prevalence is not None else 3)
      rendered = rendered.replace("{{anomaly_threshold}}", str(anomaly_threshold))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = rendered.replace("{{max_fleet_prevalence}}", str(eff_prev))
      rendered = rendered.replace("{{today_date}}", _today_date())
      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE:
      if not target_metric:
        target_metric = "http_queries_total"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_whois_domain_lifecycle_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      domain_field = "network.dns_domain" if "dns" in target_metric else "target.hostname"
      metric_type_arg = f"metric: {audit['metric_arg']}"
      rendered = _fill_event_filter(raw, "{{event_filter}}", audit["event_filter"])
      rendered = rendered.replace("{{domain_field}}", domain_field)
      if audit["target_field"] != "principal.asset.hostname":
        ent_var = "$user" if entity_type == EntityType.USER else "$host"
        ent_name = ent_var.lstrip("$")
        rendered = rendered.replace("principal.asset.hostname = $host", f"{audit['target_field']} = {ent_var}")
        rendered = rendered.replace("    $host != \"\"", f"    {ent_var} != \"\"")
        rendered = rendered.replace("$host, $domain by 1d", f"{ent_var}, $domain by 1d")
        rendered = rendered.replace("$host = $stage1_egress_baseline.host", f"{ent_var} = $stage1_egress_baseline.{ent_name}")
      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: {audit['target_field']}, {domain_field}: {domain_field})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: {audit['target_field']}, {domain_field}: {domain_field})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, {audit['target_field']}: {audit['target_field']}, {domain_field}: {domain_field})"
      )
      rendered = rendered.replace("{{anomaly_threshold}}", str(anomaly_threshold))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = rendered.replace("{{today_date}}", _today_date())
      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE:
      if not target_metric:
        target_metric = "auth_attempts_total"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_derived_asset_age_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      metric_type_arg = f"metric: {audit['metric_arg']}"
      observed_agg = audit["observed_agg"]
      rendered = _fill_event_filter(raw, "{{event_filter}}", audit["event_filter"])
      rendered = rendered.replace("{{observed_agg}}", observed_agg)
      if audit["target_field"] != "principal.asset.hostname":
        rendered = rendered.replace("principal.asset.hostname = $host", f"{audit['target_field']} = $host")
        if audit["target_field"].endswith(".ip"):
          rendered = rendered.replace("$asset.graph.entity.asset.hostname = $host", "$asset.graph.entity.asset.ip = $host")
      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: {audit['target_field']})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, {audit['target_field']}: {audit['target_field']})"
      )
      eff_min_active = int(min_active_days if min_active_days is not None else audit["min_baseline_days"])
      rendered = rendered.replace("{{min_active_days}}", str(eff_min_active))
      rendered = rendered.replace("{{min_baseline_days}}", str(eff_min_active))
      rendered = rendered.replace("{{max_asset_age_days}}", str(float(max_asset_age_days)))
      rendered = rendered.replace("{{today_date}}", _today_date())
      rendered = _apply_byte_dispersion_floor(rendered, target_metric, byte_dispersion_floor=byte_dispersion_floor)
      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE:
      if not target_metric:
        target_metric = "network_bytes_outbound"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "macd_momentum_velocity_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      metric_type_val = audit["metric_arg"]
      observed_agg = audit["observed_agg"]
      rendered = _fill_event_filter(raw, "{{event_filter}}", audit["event_filter"])
      rendered = rendered.replace("{{entity_field}}", audit["target_field"])
      rendered = rendered.replace("{{observed_aggregation}}", observed_agg)
      rendered = rendered.replace("{{target_metric_name}}", target_metric)
      rendered = rendered.replace("{{metric_type_val}}", metric_type_val)
      rendered = rendered.replace("{{dimension_key}}", audit["target_field"])
      rendered = self._apply_composite_companions_to_entity_pipeline(rendered, target_metric, entity_type)
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = _apply_byte_dispersion_floor(rendered, target_metric, byte_dispersion_floor=byte_dispersion_floor)
      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.RARE_DESTINATION_ECG_3STAGE:
      if not target_metric:
        target_metric = "network_bytes_outbound"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "rare_destination_ecg_3stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      host_field = audit["target_field"]
      metric_type_arg = f"metric: {audit['metric_arg']}"
      contact_filter = mc.baseline_semantics("http_queries_total").observed_filter
      dest_field = "target.hostname"
      rendered = _fill_event_filter(raw, "{{sector_filter}}", audit["event_filter"])
      rendered = _fill_event_filter(rendered, "{{contact_filter}}", contact_filter)
      rendered = rendered.replace("{{host_field}}", host_field)
      rendered = rendered.replace("{{dest_field}}", dest_field)
      rendered = rendered.replace("{{sector_observation_agg}}", audit["observed_agg"])
      rendered = rendered.replace(
          "{{sector_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {host_field}: {host_field})"
      )
      rendered = rendered.replace(
          "{{sector_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {host_field}: {host_field})"
      )
      rendered = rendered.replace(
          "{{sector_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, {host_field}: {host_field})"
      )
      eff_prev = int(max_fleet_prevalence if max_fleet_prevalence is not None else 3)
      rendered = rendered.replace("{{ecg_entity_type}}", '"DOMAIN_NAME"')
      rendered = rendered.replace("{{ecg_key_path}}", "entity.domain.name")
      rendered = rendered.replace("{{ecg_prevalence_path}}", "entity.domain.prevalence")
      rendered = rendered.replace("{{max_fleet_prevalence}}", str(eff_prev))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = rendered.replace("{{today_date}}", _today_date())
      rendered = _apply_byte_dispersion_floor(rendered, target_metric, byte_dispersion_floor=byte_dispersion_floor)
      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.FUSION_RARE_DESTINATION_3STAGE:
      default_pair = (
          ["auth_attempts_total", "http_queries_total"]
          if entity_type == EntityType.ASSET
          else ["workspace_total_download_actions", "http_queries_total"]
      )
      metrics = list(target_metrics or default_pair)
      if len(metrics) != 2:
        raise ValueError(f"Fusion rare destination takes 2 metrics, got {len(metrics)}: {metrics}")
      m_a, m_b = metrics[0], metrics[1]
      audit_a = PreFlightValidator.audit(
          target_metric=m_a,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      audit_b = PreFlightValidator.audit(
          target_metric=m_b,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "fusion_rare_destination_3stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      host_field = audit_a["target_field"]
      dest_field = "network.dns_domain" if "dns" in m_b else "target.hostname"
      rendered = _fill_event_filter(raw, "{{sector_a_filter}}", audit_a["event_filter"])
      rendered = _fill_event_filter(rendered, "{{sector_b_filter}}", audit_b["event_filter"])
      rendered = rendered.replace("{{host_field}}", host_field)
      rendered = rendered.replace("{{dest_field}}", dest_field)
      rendered = rendered.replace("{{sector_a_observation_agg}}", audit_a["observed_agg"])
      rendered = rendered.replace("{{sector_b_observation_agg}}", audit_b["observed_agg"])
      rendered = rendered.replace(
          "{{sector_a_metric_func_avg}}",
          f"metrics.{m_a}(period: 1d, window: 30d, metric: {audit_a['metric_arg']}, agg: avg, {host_field}: {host_field})"
      )
      rendered = rendered.replace(
          "{{sector_a_metric_func_stddev}}",
          f"metrics.{m_a}(period: 1d, window: 30d, metric: {audit_a['metric_arg']}, agg: stddev, {host_field}: {host_field})"
      )
      rendered = rendered.replace(
          "{{sector_a_metric_func_active_days}}",
          f"metrics.{m_a}(period: 1d, window: 30d, metric: {audit_a['metric_arg']}, agg: num_metric_periods, {host_field}: {host_field})"
      )
      rendered = rendered.replace(
          "{{sector_b_metric_func_avg}}",
          f"metrics.{m_b}(period: 1d, window: 30d, metric: {audit_b['metric_arg']}, agg: avg, {host_field}: {host_field}, {dest_field}: {dest_field})"
      )
      rendered = rendered.replace(
          "{{sector_b_metric_func_stddev}}",
          f"metrics.{m_b}(period: 1d, window: 30d, metric: {audit_b['metric_arg']}, agg: stddev, {host_field}: {host_field}, {dest_field}: {dest_field})"
      )
      rendered = rendered.replace(
          "{{sector_b_metric_func_active_days}}",
          f"metrics.{m_b}(period: 1d, window: 30d, metric: {audit_b['metric_arg']}, agg: num_metric_periods, {host_field}: {host_field}, {dest_field}: {dest_field})"
      )
      eff_prev = int(max_fleet_prevalence if max_fleet_prevalence is not None else 3)
      rendered = rendered.replace("{{ecg_entity_type}}", '"DOMAIN_NAME"')
      rendered = rendered.replace("{{ecg_key_path}}", "entity.domain.name")
      rendered = rendered.replace("{{ecg_prevalence_path}}", "entity.domain.prevalence")
      rendered = rendered.replace("{{max_fleet_prevalence}}", str(eff_prev))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit_a["min_baseline_days"]))
      rendered = rendered.replace("{{today_date}}", _today_date())
      rendered = _apply_byte_dispersion_floor(rendered, m_a, floor_vars=("$a_floor",))
      rendered = _apply_byte_dispersion_floor(rendered, m_b, floor_vars=("$b_floor",))
      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.FIRST_SEEN_NOVELTY_2STAGE:
      if target_metric:
        eff_metric = target_metric
      elif entity_type == EntityType.USER:
        eff_metric = "auth_attempts_total"
      elif entity_type == EntityType.RESOURCE:
        eff_metric = "resource_read_total"
      else:
        eff_metric = "http_queries_total"

      if novelty_subkey_field:
        eff_subkey: Optional[str] = novelty_subkey_field.strip()
      elif eff_metric.startswith("auth_attempts_") and entity_type == EntityType.USER:
        eff_subkey = "target.application"
      elif eff_metric.startswith("http_queries_"):
        eff_subkey = "target.hostname"
      elif eff_metric.startswith("dns_queries_"):
        eff_subkey = "network.dns_domain"
      else:
        eff_subkey = None

      if mc.is_composite_only(eff_metric) or eff_metric.startswith("resource_"):
        return self.build_query(
            target_metric=eff_metric,
            entity_type=entity_type,
            statistical_model=StatisticalModel.FIRST_SEEN_NOVELTY,
            min_baseline_days=min_baseline_days,
            hypothesis_goal=hypothesis_goal,
            min_threshold=min_threshold,
            max_threshold=max_threshold,
            condition_expression=condition_expression,
            identifier_field=identifier_field,
            identifier_coverage_payload=identifier_coverage_payload,
            novelty_subkey_field=eff_subkey,
            min_novelty_events=min_novelty_events,
        )

      self.last_advisories = []
      if eff_metric not in PF11_POPULATED_FIRST_SEEN_METRICS:
        self.last_advisories.append(
            f"PF-11 coverage advisory: metrics.{eff_metric}(..., metric: first_seen) returned 0 rows "
            "in the empirical gus-sdl baseline (17/38 unpopulated metrics); verify tenant population or "
            "pair with raw/ECG context if 0 rows return."
        )
      audit = PreFlightValidator.audit(
          target_metric=eff_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "first_seen_novelty_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text(encoding="utf-8").strip()
      ent_field = audit["target_field"]
      ent_var = "$user" if entity_type == EntityType.USER else ("$resource" if entity_type == EntityType.RESOURCE else "$host")
      ent_name = ent_var.lstrip("$")
      filter_dims = [ent_field]
      if eff_subkey:
        sub_var = self._NOVELTY_SUBKEY_VARS.get(
            eff_subkey,
            f"$sub_{re.sub(r'[^a-zA-Z0-9_]', '_', eff_subkey.rsplit('.', 1)[-1])}",
        )
        sub_name = sub_var.lstrip("$")
        subkey_binding_block = f"    {eff_subkey} = {sub_var}\n    {sub_var} != \"\"\n"
        match_keys = f"{ent_var}, {sub_var}"
        dims_block = f"{ent_field}: {ent_field},\n        {eff_subkey}: {eff_subkey}"
        root_bindings = f"{ent_var} = $stage1_extract.{ent_name}\n{sub_var} = $stage1_extract.{sub_name}"
        filter_dims.append(eff_subkey)
      else:
        subkey_binding_block = ""
        match_keys = ent_var
        dims_block = f"{ent_field}: {ent_field}"
        root_bindings = f"{ent_var} = $stage1_extract.{ent_name}"
      dim_err = mc.validate_filter_fields(eff_metric, filter_dims)
      if dim_err:
        raise ValueError(f"Invalid dimension set for {eff_metric}: {dim_err}")

      rendered = _fill_event_filter(raw, "{{event_filter}}", audit["event_filter"])
      rendered = rendered.replace("{{entity_field}}", ent_field)
      rendered = rendered.replace("{{entity_var}}", ent_var)
      rendered = rendered.replace("{{subkey_binding_block}}\n", subkey_binding_block)
      rendered = rendered.replace("{{match_keys}}", match_keys)
      rendered = rendered.replace("{{observed_aggregation}}", audit["observed_agg"])
      rendered = rendered.replace("{{target_metric_name}}", eff_metric)
      rendered = rendered.replace("{{metric_type_val}}", audit["metric_arg"])
      rendered = rendered.replace("{{dimensions_block}}", dims_block)
      rendered = rendered.replace("{{root_entity_bindings}}", root_bindings)
      rendered = rendered.replace("{{min_novelty_events}}", str(max(1, int(min_novelty_events))))
      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.LONGITUDINAL_CUSUM_SERIES_3STAGE:
      return self.build_longitudinal_cusum_series_query(
          target_metric=target_metric or "network_bytes_outbound",
          entity_type=entity_type,
          cusum_h_threshold=anomaly_threshold if anomaly_threshold != 3.0 else 4.0,
          min_baseline_days=min_baseline_days,
          hypothesis_goal=hypothesis_goal,
          identifier_field=identifier_field,
          byte_dispersion_floor=byte_dispersion_floor,
          min_threshold=min_threshold,
          max_threshold=max_threshold,
          condition_expression=condition_expression,
      )

    elif pipeline_type == PipelineArchitecture.LOCAL_2STAGE:
      return self.build_query(
          target_metric=target_metric or "network_bytes_outbound",
          entity_type=entity_type,
          statistical_model=StatisticalModel.STANDARD_Z_SCORE,
          anomaly_threshold=anomaly_threshold,
          min_baseline_days=min_baseline_days,
          hypothesis_goal=hypothesis_goal,
          min_threshold=min_threshold,
          max_threshold=max_threshold,
          condition_expression=condition_expression,
          identifier_field=identifier_field,
          byte_dispersion_floor=byte_dispersion_floor,
          identifier_coverage_payload=identifier_coverage_payload,
      )
    else:
      raise ValueError(f"Unsupported pipeline type: {pipeline_type}")

  def build_cloud_repository_scope_query(
      self,
      service_account: Optional[str] = None,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
      min_threshold: Optional[float] = None,
      max_threshold: Optional[float] = None,
      condition_expression: Optional[str] = None,
      target_metric: str = "resource_read_total",
      include_significance_gate: bool = True,
  ) -> str:
    """Builds a verified Cloud Repository Scope pipeline guaranteeing target.resource.name binding."""
    return self.build_pipeline_query(
        PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH,
        target_metric=target_metric,
        entity_type=EntityType.USER,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
        service_account=service_account,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        include_significance_gate=include_significance_gate,
    )

  def build_failure_ratio_surge_query(
      self,
      fail_metric: str = "http_queries_fail",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      min_fail_ratio: float = 0.40,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
  ) -> str:
    """Builds a generalized 2-Stage Failure-to-Total Ratio Surge pipeline for any *_fail metric."""
    valid_fail_metrics = {
        "http_queries_fail": "http_queries_total",
        "dns_queries_fail": "dns_queries_total",
        "auth_attempts_fail": "auth_attempts_total",
        "file_executions_fail": "file_executions_total",
        "resource_read_fail": "resource_read_total",
        "resource_written_fail": "resource_written_total",
        "resource_creation_fail": "resource_creation_total",
        "resource_deletion_fail": "resource_deletion_total",
    }
    if fail_metric not in valid_fail_metrics:
      raise ValueError(f"Unsupported fail_metric '{fail_metric}'. Must be one of {sorted(valid_fail_metrics)}")
    total_metric = valid_fail_metrics[fail_metric]
    audit = PreFlightValidator.audit(
        target_metric=fail_metric,
        entity_type=entity_type,
        identifier_field=identifier_field,
    )
    ent_field = audit["target_field"]
    ent_var = (
        "$user"
        if entity_type == EntityType.USER
        else ("$resource" if entity_type == EntityType.RESOURCE else "$host")
    )
    ent_name = ent_var.lstrip("$")
    fail_filter_lines = mc.baseline_semantics(fail_metric).observed_filter
    total_filter_lines = mc.baseline_semantics(total_metric).observed_filter
    fail_filter_block = "\n    ".join(fail_filter_lines)
    total_filter_block = "\n    ".join(total_filter_lines)

    if fail_metric == "file_executions_fail":
      extra_bindings = "    principal.process.file.sha256 = $sha256\n    $sha256 != \"\"\n"
      match_keys = f"{ent_var}, $sha256"
      root_joins = (
          f"{ent_var} = $stage1_http_failure_surge.{ent_name}\n"
          f"$sha256 = $stage1_http_failure_surge.sha256\n"
          f"{ent_var} = $stage2_total_traffic.{ent_name}\n"
          f"$sha256 = $stage2_total_traffic.sha256"
      )
      metric_args = (
          f"metadata.event_type: metadata.event_type,\n"
          f"        {ent_field}: {ent_field},\n"
          f"        principal.process.file.sha256: principal.process.file.sha256"
      )
    elif fail_metric.startswith("resource_"):
      if entity_type == EntityType.RESOURCE:
        extra_bindings = (
            "    principal.user.userid = $sa\n"
            "    metadata.vendor_name = $vendor\n"
            "    metadata.product_name = $product\n"
            "    $sa != \"\"\n"
            "    $vendor != \"\"\n"
            "    $product != \"\"\n"
        )
        match_keys = f"{ent_var}, $sa, $vendor, $product"
        root_joins = (
            f"{ent_var} = $stage1_http_failure_surge.{ent_name}\n"
            "$sa = $stage1_http_failure_surge.sa\n"
            "$vendor = $stage1_http_failure_surge.vendor\n"
            "$product = $stage1_http_failure_surge.product\n"
            f"{ent_var} = $stage2_total_traffic.{ent_name}\n"
            "$sa = $stage2_total_traffic.sa\n"
            "$vendor = $stage2_total_traffic.vendor\n"
            "$product = $stage2_total_traffic.product"
        )
        metric_args = (
            "principal.user.userid: principal.user.userid,\n"
            "        metadata.vendor_name: metadata.vendor_name,\n"
            "        metadata.product_name: metadata.product_name,\n"
            f"        {ent_field}: {ent_field}"
        )
      else:
        extra_bindings = (
            "    metadata.vendor_name = $vendor\n"
            "    metadata.product_name = $product\n"
            "    target.resource.name = $resource\n"
            "    $resource != \"\"\n"
        )
        match_keys = f"{ent_var}, $vendor, $product, $resource"
        root_joins = (
            f"{ent_var} = $stage1_http_failure_surge.{ent_name}\n"
            f"$vendor = $stage1_http_failure_surge.vendor\n"
            f"$product = $stage1_http_failure_surge.product\n"
            f"$resource = $stage1_http_failure_surge.resource\n"
            f"{ent_var} = $stage2_total_traffic.{ent_name}\n"
            f"$vendor = $stage2_total_traffic.vendor\n"
            f"$product = $stage2_total_traffic.product\n"
            f"$resource = $stage2_total_traffic.resource"
        )
        metric_args = (
            f"{ent_field}: {ent_field},\n"
            f"        metadata.vendor_name: metadata.vendor_name,\n"
            f"        metadata.product_name: metadata.product_name,\n"
            f"        target.resource.name: target.resource.name"
        )
    else:
      extra_bindings = ""
      match_keys = ent_var
      root_joins = (
          f"{ent_var} = $stage1_http_failure_surge.{ent_name}\n"
          f"{ent_var} = $stage2_total_traffic.{ent_name}"
      )
      metric_args = f"{ent_field}: {ent_field}"

    goal_line = f"// Goal: {hypothesis_goal}\n" if hypothesis_goal else ""
    return (
        f"{goal_line}// Purpose: Hunt for entities with anomalous failure-to-total ratios in {fail_metric} (MITRE TA0043 Reconnaissance / T1595 Active Scanning)\n"
        "// ============================================================================\n"
        "// ARCHITECTURE: 2-STAGE FAILURE RATIO & MITRE TA0043 RECONNAISSANCE SURGE PIPELINE\n"
        "// ============================================================================\n\n"
        "stage stage1_http_failure_surge {\n"
        f"    {fail_filter_block}\n"
        f"    {ent_field} = {ent_var}\n"
        f"    {ent_var} != \"\"\n"
        f"{extra_bindings}\n"
        "  match:\n"
        f"    {match_keys} by 1d\n\n"
        "  outcome:\n"
        "    $failed_obs = count(metadata.id)\n"
        f"    $hist_fail_avg = max(metrics.{fail_metric}(\n"
        "        period: 1d, window: 30d, metric: event_count_sum, agg: avg,\n"
        f"        {metric_args}\n"
        "    ))\n"
        f"    $hist_fail_stddev = max(metrics.{fail_metric}(\n"
        "        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,\n"
        f"        {metric_args}\n"
        "    ))\n"
        f"    $hist_fail_active_days = max(metrics.{fail_metric}(\n"
        "        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,\n"
        f"        {metric_args}\n"
        "    ))\n"
        "    $dispersion_floor = math.sqrt(if($hist_fail_avg > 1.0, $hist_fail_avg, 1.0))\n"
        "    $fail_z = ($failed_obs - $hist_fail_avg) / if($hist_fail_stddev > $dispersion_floor, $hist_fail_stddev, $dispersion_floor)\n"
        "}\n\n"
        "stage stage2_total_traffic {\n"
        f"    {total_filter_block}\n"
        f"    {ent_field} = {ent_var}\n"
        f"    {ent_var} != \"\"\n"
        f"{extra_bindings}\n"
        "  match:\n"
        f"    {match_keys} by 1d\n\n"
        "  outcome:\n"
        "    $total_obs = count(metadata.id)\n"
        "}\n\n"
        f"{root_joins}\n\n"
        "match:\n"
        f"  {match_keys} by 1d\n\n"
        "outcome:\n"
        "  $fail_z = max($stage1_http_failure_surge.fail_z)\n"
        "  $active_days = max($stage1_http_failure_surge.hist_fail_active_days)\n"
        "  $observed_fails = max($stage1_http_failure_surge.failed_obs)\n"
        "  $total_events = max($stage2_total_traffic.total_obs)\n"
        "  $fail_ratio = $observed_fails / ($total_events + 0.001)\n"
        "  $recon_score = $fail_z * $fail_ratio\n\n"
        "condition:\n"
        f"  $active_days >= {audit['min_baseline_days']}\n"
        f"  and $fail_z >= {anomaly_threshold}\n"
        f"  and $fail_ratio >= {min_fail_ratio}\n\n"
        "order:\n"
        "  $recon_score desc\n"
    )

  def build_outbound_flow_surge_query(
      self,
      target_metric: str = "network_flows_outbound",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      min_baseline_days: int = 7,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
  ) -> str:
    """Builds a 2-Stage Outbound Flow Surge pipeline (D1 / WS4-D1; sub-hour C2 jitter hands off to stats-hunter)."""
    valid_flow_metrics = ("network_flows_outbound", "network_flows_inbound", "network_flows_total")
    if target_metric not in valid_flow_metrics:
      raise ValueError(f"Unsupported flow metric '{target_metric}'. Must be one of {valid_flow_metrics}")
    audit = PreFlightValidator.audit(
        target_metric=target_metric,
        entity_type=entity_type,
        min_baseline_days=min_baseline_days,
        identifier_field=identifier_field,
    )
    ent_field = audit["target_field"]
    ent_var = "$user" if entity_type == EntityType.USER else "$host"
    ent_name = ent_var.lstrip("$")
    filter_block = "\n    ".join(audit["event_filter"])
    if target_metric == "network_flows_outbound":
      bytes_block = "    $observed_bytes = sum(network.sent_bytes)\n"
    elif target_metric == "network_flows_inbound":
      bytes_block = "    $observed_bytes = sum(network.received_bytes)\n"
    else:
      bytes_block = (
          "    $clamped_sent = sum(if(network.sent_bytes < 1000000000000000, network.sent_bytes, 0))\n"
          "    $clamped_rcvd = sum(if(network.received_bytes < 1000000000000000, network.received_bytes, 0))\n"
          "    $observed_bytes = $clamped_sent + $clamped_rcvd\n"
      )
    goal_line = f"// Goal: {hypothesis_goal}\n" if hypothesis_goal else ""
    return (
        f"{goal_line}// Purpose: Hunt for daily outbound network flow count surges in {target_metric} "
        "(sub-hour C2 periodicity/jitter hands off to secops-statistical-hunter C2_BEACONING_JITTER)\n"
        "// ============================================================================\n"
        "// ARCHITECTURE: 2-STAGE OUTBOUND FLOW SURGE PIPELINE\n"
        "// ============================================================================\n\n"
        "stage stage1_flow_surge {\n"
        f"    {filter_block}\n"
        f"    {ent_field} = {ent_var}\n"
        f"    {ent_var} != \"\"\n\n"
        "  match:\n"
        f"    {ent_var} by 1d\n\n"
        "  outcome:\n"
        "    $observed_flows = count(metadata.id)\n"
        f"{bytes_block}"
        "    $distinct_targets = count_distinct(target.ip)\n"
        "    $distinct_ports = count_distinct(target.port)\n"
        f"    $hist_flow_avg = max(metrics.{target_metric}(\n"
        "        period: 1d, window: 30d, metric: event_count_sum, agg: avg,\n"
        f"        {ent_field}: {ent_field}\n"
        "    ))\n"
        f"    $hist_flow_stddev = max(metrics.{target_metric}(\n"
        "        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,\n"
        f"        {ent_field}: {ent_field}\n"
        "    ))\n"
        f"    $hist_flow_active_days = max(metrics.{target_metric}(\n"
        "        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,\n"
        f"        {ent_field}: {ent_field}\n"
        "    ))\n"
        "    $dispersion_floor = math.sqrt(if($hist_flow_avg > 1.0, $hist_flow_avg, 1.0))\n"
        "    $flow_z = ($observed_flows - $hist_flow_avg) / if($hist_flow_stddev > $dispersion_floor, $hist_flow_stddev, $dispersion_floor)\n"
        "    $bytes_per_flow = (1.0 * $observed_bytes) / ($observed_flows + 0.001)\n"
        "}\n\n"
        f"{ent_var} = $stage1_flow_surge.{ent_name}\n\n"
        "match:\n"
        f"  {ent_var} by 1d\n\n"
        "outcome:\n"
        "  $flow_z = max($stage1_flow_surge.flow_z)\n"
        "  $flow_surge_score = $flow_z\n"
        "  $observed_flows = max($stage1_flow_surge.observed_flows)\n"
        "  $historical_flow_avg = max($stage1_flow_surge.hist_flow_avg)\n"
        "  $active_days = max($stage1_flow_surge.hist_flow_active_days)\n"
        "  $bytes_per_flow = min($stage1_flow_surge.bytes_per_flow)\n"
        "  $distinct_targets = max($stage1_flow_surge.distinct_targets)\n"
        "  $distinct_ports = max($stage1_flow_surge.distinct_ports)\n\n"
        "condition:\n"
        f"  $active_days >= {audit['min_baseline_days']}\n"
        f"  and $flow_z >= {anomaly_threshold}\n\n"
        "order:\n"
        "  $flow_surge_score desc\n"
    )

  def build_c2_beacon_flow_query(
      self,
      target_metric: str = "network_flows_outbound",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      min_baseline_days: int = 7,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
  ) -> str:
    """Backward-compatible alias for build_outbound_flow_surge_query (D1 / WS4-D1)."""
    return self.build_outbound_flow_surge_query(
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        min_baseline_days=min_baseline_days,
        hypothesis_goal=hypothesis_goal,
        identifier_field=identifier_field,
    )

  def build_longitudinal_cusum_pipeline_query(
      self,
      target_metric: str = "network_bytes_outbound",
      entity_type: EntityType = EntityType.ASSET,
      cusum_h_threshold: float = 4.0,
      min_baseline_days: Optional[int] = None,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
      include_significance_gate: bool = True,
      byte_dispersion_floor: Optional[float] = None,
  ) -> str:
    """Renders longitudinal_cusum_2stage.yl2 (Windowed Slack Sum) with domain-aware dispersion floor and NO-GATE option."""
    audit = PreFlightValidator.audit(
        target_metric=target_metric,
        entity_type=entity_type,
        min_baseline_days=min_baseline_days,
        identifier_field=identifier_field,
    )
    pipeline_file = self.template_dir / "pipelines" / "longitudinal_cusum_2stage.yl2"
    if not pipeline_file.exists():
      raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
    raw = pipeline_file.read_text(encoding="utf-8").strip()
    rendered = _fill_event_filter(raw, "{{event_filter}}", audit["event_filter"])
    rendered = rendered.replace("{{entity_field}}", audit["target_field"])
    rendered = rendered.replace("{{observed_aggregation}}", audit["observed_agg"])
    rendered = rendered.replace("{{target_metric_name}}", target_metric)
    rendered = rendered.replace("{{metric_type_val}}", audit["metric_arg"])
    rendered = rendered.replace("{{dimension_key}}", audit["target_field"])
    rendered = self._apply_composite_companions_to_entity_pipeline(rendered, target_metric, entity_type)
    rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
    rendered = _apply_byte_dispersion_floor(rendered, target_metric, byte_dispersion_floor=byte_dispersion_floor)
    if hypothesis_goal:
      rendered = f"// Goal: {hypothesis_goal}\n" + rendered
    out = self._apply_significance_gate(
        rendered + "\n",
        anomaly_threshold=cusum_h_threshold,
        include_significance_gate=include_significance_gate,
    )
    if not include_significance_gate and "// Significance Gate: NONE" not in out:
      out = "// Significance Gate: NONE (NO-GATE Windowed Slack Sum series prefilter)\n" + out
    return out

  def build_longitudinal_cusum_series_query(
      self,
      target_metric: str = "network_bytes_outbound",
      entity_type: EntityType = EntityType.ASSET,
      cusum_h_threshold: float = 4.0,
      min_baseline_days: Optional[int] = None,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
      include_significance_gate: bool = True,
      byte_dispersion_floor: Optional[float] = None,
      min_threshold: Optional[float] = None,
      max_threshold: Optional[float] = None,
      condition_expression: Optional[str] = None,
      local_execution_available: bool = True,
  ) -> str:
    """Renders longitudinal_cusum_series_3stage.yl2 (ungated active-day series for W >= h prefilter survivors)."""
    if not local_execution_available:
      raise ValueError(
          "G5 violation: Page CUSUM series extraction cannot complete in YARA-L alone — "
          "this model needs a client that can run local scripts (scripts/cusum_helper.py). "
          "Use build_longitudinal_cusum_pipeline_query for the stateless Windowed Slack Sum prefilter."
      )
    audit = PreFlightValidator.audit(
        target_metric=target_metric,
        entity_type=entity_type,
        min_baseline_days=min_baseline_days,
        identifier_field=identifier_field,
    )
    pipeline_file = self.template_dir / "pipelines" / "longitudinal_cusum_series_3stage.yl2"
    if not pipeline_file.exists():
      raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
    raw = pipeline_file.read_text(encoding="utf-8").strip()
    rendered = _fill_event_filter(raw, "{{event_filter}}", audit["event_filter"])
    rendered = rendered.replace("{{entity_field}}", audit["target_field"])
    rendered = rendered.replace("{{observed_aggregation}}", audit["observed_agg"])
    rendered = rendered.replace("{{target_metric_name}}", target_metric)
    rendered = rendered.replace("{{metric_type_val}}", audit["metric_arg"])
    rendered = rendered.replace("{{dimension_key}}", audit["target_field"])
    rendered = self._apply_composite_companions_to_entity_pipeline(rendered, target_metric, entity_type)
    rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
    rendered = rendered.replace("{{cusum_h}}", str(float(cusum_h_threshold)))
    rendered = _apply_byte_dispersion_floor(rendered, target_metric, byte_dispersion_floor=byte_dispersion_floor)
    if hypothesis_goal:
      rendered = f"// Goal: {hypothesis_goal}\n" + rendered
    out = self._apply_significance_gate(
        rendered + "\n",
        anomaly_threshold=cusum_h_threshold,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        include_significance_gate=include_significance_gate,
    )
    if not include_significance_gate and "// Significance Gate: NONE" not in out:
      out = "// Significance Gate: NONE (NO-GATE ungated CUSUM series extractor)\n" + out
    return out

  def build_alert_surge_query(
      self,
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
      include_significance_gate: bool = True,
  ) -> str:
    """Builds a 2-Stage Security & EDR Alert Surge pipeline for metrics.alert_event_name_count.

    Supports host-level roll-ups (PRINCIPAL_DEVICE + SECURITY_RESULT_RULE_NAME) and user+host+process
    compound attribution (PRINCIPAL_DEVICE + PRINCIPAL_USER + PRINCIPAL_PROCESS_FILE_HASH + SECURITY_RESULT_RULE_NAME).
    """
    metric_name = "alert_event_name_count"
    filter_block = "\n    ".join(mc.baseline_semantics(metric_name).observed_filter)
    goal_line = f"// Goal: {hypothesis_goal}\n" if hypothesis_goal else ""
    gate_header_line = (
        ""
        if include_significance_gate
        else "// Significance Gate: NONE (NO-GATE decoupled sector for post-query Euclidean fusion)\n"
    )
    condition_block = (
        f"condition:\n  $alert_z >= {anomaly_threshold}\n\n"
        if include_significance_gate
        else ""
    )
    if entity_type == EntityType.USER:
      return (
          f"{goal_line}{gate_header_line}// Purpose: Hunt for user-attributed EDR & security alert surges across host and process context\n"
          "// ============================================================================\n"
          "// ARCHITECTURE: 2-STAGE USER-ATTRIBUTED SECURITY & EDR ALERT SURGE PIPELINE\n"
          "// ============================================================================\n\n"
          "stage stage1_alert_detail {\n"
          f"    {filter_block}\n"
          "    principal.user.userid = $user\n"
          "    principal.asset.hostname = $host\n"
          "    principal.process.file.sha256 = $sha256\n"
          "    security_result.rule_name = $rule_name\n"
          "    $user != \"\"\n"
          "    $host != \"\"\n"
          "    $sha256 != \"\"\n"
          "    $rule_name != \"\"\n\n"
          "  match:\n"
          "    $user, $host, $sha256, $rule_name by 1d\n\n"
          "  outcome:\n"
          "    $d_obs = count(metadata.id)\n"
          f"    $d_mu = max(metrics.{metric_name}(\n"
          "        period: 1d, window: 30d, metric: event_count_sum, agg: avg,\n"
          "        principal.asset.hostname: principal.asset.hostname,\n"
          "        principal.user.userid: principal.user.userid,\n"
          "        principal.process.file.sha256: principal.process.file.sha256,\n"
          "        security_result.rule_name: security_result.rule_name\n"
          "    ))\n"
          f"    $d_sigma = max(metrics.{metric_name}(\n"
          "        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,\n"
          "        principal.asset.hostname: principal.asset.hostname,\n"
          "        principal.user.userid: principal.user.userid,\n"
          "        principal.process.file.sha256: principal.process.file.sha256,\n"
          "        security_result.rule_name: security_result.rule_name\n"
          "    ))\n"
          f"    $d_days = max(metrics.{metric_name}(\n"
          "        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,\n"
          "        principal.asset.hostname: principal.asset.hostname,\n"
          "        principal.user.userid: principal.user.userid,\n"
          "        principal.process.file.sha256: principal.process.file.sha256,\n"
          "        security_result.rule_name: security_result.rule_name\n"
          "    ))\n"
          "    $d_floor = math.sqrt(if($d_mu > 1.0, $d_mu, 1.0))\n"
          "    $d_raw_z = ($d_obs - $d_mu) / if($d_sigma > $d_floor, $d_sigma, $d_floor)\n"
          "    $d_z = if($d_days >= 7, $d_raw_z, 0.0)\n"
          "    $d_novel = if($d_days = 0, 1, 0)\n"
          "}\n\n"
          "$user = $stage1_alert_detail.user\n"
          "$host = $stage1_alert_detail.host\n\n"
          "match:\n"
          "  $user, $host by 1d\n\n"
          "outcome:\n"
          "  $alert_z = max($stage1_alert_detail.d_z)\n"
          "  $total_alerts = sum($stage1_alert_detail.d_obs)\n"
          "  $distinct_rules = count_distinct($stage1_alert_detail.rule_name)\n"
          "  $novel_rules = sum($stage1_alert_detail.d_novel)\n\n"
          f"{condition_block}"
          "order:\n"
          "  $alert_z desc\n"
      )
    return (
        f"{goal_line}{gate_header_line}// Purpose: Hunt for host-level EDR & security alert surges across distinct rule names\n"
        "// ============================================================================\n"
        "// ARCHITECTURE: 2-STAGE HOST SECURITY & EDR ALERT SURGE PIPELINE\n"
        "// ============================================================================\n\n"
        "stage stage1_alert_detail {\n"
        f"    {filter_block}\n"
        "    principal.asset.hostname = $host\n"
        "    security_result.rule_name = $rule_name\n"
        "    $host != \"\"\n"
        "    $rule_name != \"\"\n\n"
        "  match:\n"
        "    $host, $rule_name by 1d\n\n"
        "  outcome:\n"
        "    $d_obs = count(metadata.id)\n"
        f"    $d_mu = max(metrics.{metric_name}(\n"
        "        period: 1d, window: 30d, metric: event_count_sum, agg: avg,\n"
        "        principal.asset.hostname: principal.asset.hostname,\n"
        "        security_result.rule_name: security_result.rule_name\n"
        "    ))\n"
        f"    $d_sigma = max(metrics.{metric_name}(\n"
        "        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,\n"
        "        principal.asset.hostname: principal.asset.hostname,\n"
        "        security_result.rule_name: security_result.rule_name\n"
        "    ))\n"
        f"    $d_days = max(metrics.{metric_name}(\n"
        "        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,\n"
        "        principal.asset.hostname: principal.asset.hostname,\n"
        "        security_result.rule_name: security_result.rule_name\n"
        "    ))\n"
        "    $d_floor = math.sqrt(if($d_mu > 1.0, $d_mu, 1.0))\n"
        "    $d_raw_z = ($d_obs - $d_mu) / if($d_sigma > $d_floor, $d_sigma, $d_floor)\n"
        "    $d_z = if($d_days >= 7, $d_raw_z, 0.0)\n"
        "    $d_novel = if($d_days = 0, 1, 0)\n"
        "}\n\n"
        "$host = $stage1_alert_detail.host\n\n"
        "match:\n"
        "  $host by 1d\n\n"
        "outcome:\n"
        "  $alert_z = max($stage1_alert_detail.d_z)\n"
        "  $total_alerts = sum($stage1_alert_detail.d_obs)\n"
        "  $distinct_rules = count_distinct($stage1_alert_detail.rule_name)\n"
        "  $novel_rules = sum($stage1_alert_detail.d_novel)\n\n"
        f"{condition_block}"
        "order:\n"
        "  $alert_z desc\n"
    )

  def build_hybrid_enrichment_query(
      self,
      target_metric: str = "network_bytes_outbound",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
  ) -> str:
    """Builds a verified Dual-Plane Hybrid Metric & Raw Telemetry Enrichment pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_RAW_ENRICHMENT_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
    )

  def build_hybrid_entropy_concentration_query(
      self,
      target_metric: str = "network_bytes_outbound",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
      min_baseline_days: Optional[int] = None,
      max_diversity_ratio: float = 0.05,
      min_concentration_ratio: float = 0.85,
      min_raw_events: int = 25,
      novelty_subkey_field: Optional[str] = None,
      min_novelty_events: int = 1,
  ) -> str:
    """Builds a verified Dual-Plane Destination Diversity & Concentration Screen pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        min_baseline_days=min_baseline_days,
        hypothesis_goal=hypothesis_goal,
        max_diversity_ratio=max_diversity_ratio,
        min_concentration_ratio=min_concentration_ratio,
        min_raw_events=min_raw_events,
        novelty_subkey_field=novelty_subkey_field,
        min_novelty_events=min_novelty_events,
    )

  def build_destination_diversity_concentration_query(
      self,
      target_metric: str = "network_bytes_outbound",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
      min_baseline_days: Optional[int] = None,
      max_diversity_ratio: float = 0.05,
      min_concentration_ratio: float = 0.85,
      min_raw_events: int = 25,
      novelty_subkey_field: Optional[str] = None,
      min_novelty_events: int = 1,
  ) -> str:
    """Canonical WS4 builder for Destination Diversity & Concentration Screen."""
    return self.build_hybrid_entropy_concentration_query(
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
        min_baseline_days=min_baseline_days,
        max_diversity_ratio=max_diversity_ratio,
        min_concentration_ratio=min_concentration_ratio,
        min_raw_events=min_raw_events,
        novelty_subkey_field=novelty_subkey_field,
        min_novelty_events=min_novelty_events,
    )

  def build_hybrid_orthogonal_space_query(
      self,
      target_metric: str = "network_bytes_outbound",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
  ) -> str:
    """Builds a verified Dual-Plane Hybrid Orthogonal Space pipeline (2D Threat Space & Joint Odds)."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
    )

  def build_hybrid_fleet_prevalence_query(
      self,
      target_metric: str = "file_executions_total",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
      min_baseline_days: Optional[int] = None,
      max_fleet_prevalence: Optional[int] = None,
      max_fleet_adopters: Optional[int] = None,
  ) -> str:
    """Builds a verified Dual-Plane Hybrid Fleet Prevalence Normalization pipeline (Patch Tuesday Shield)."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_FLEET_PREVALENCE_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        min_baseline_days=min_baseline_days,
        hypothesis_goal=hypothesis_goal,
        max_fleet_prevalence=max_fleet_prevalence,
        max_fleet_adopters=max_fleet_adopters,
    )

  def build_hybrid_derived_file_prevalence_query(
      self,
      target_metric: str = "file_executions_total",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
      min_baseline_days: Optional[int] = None,
      max_fleet_prevalence: Optional[int] = None,
      identifier_field: Optional[str] = None,
  ) -> str:
    """Builds a verified 2-Stage Derived Context File Prevalence pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        min_baseline_days=min_baseline_days,
        hypothesis_goal=hypothesis_goal,
        max_fleet_prevalence=max_fleet_prevalence,
        identifier_field=identifier_field,
    )

  def build_hybrid_derived_domain_prevalence_query(
      self,
      target_metric: str = "http_queries_total",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
      identifier_coverage_payload: Optional[Any] = None,
      min_baseline_days: Optional[int] = None,
      max_fleet_prevalence: Optional[int] = None,
  ) -> str:
    """Builds a verified 2-Stage Derived Context Domain Prevalence pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        min_baseline_days=min_baseline_days,
        hypothesis_goal=hypothesis_goal,
        identifier_field=identifier_field,
        identifier_coverage_payload=identifier_coverage_payload,
        max_fleet_prevalence=max_fleet_prevalence,
    )

  def build_hybrid_whois_domain_lifecycle_query(
      self,
      target_metric: str = "http_queries_total",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
      identifier_coverage_payload: Optional[Any] = None,
  ) -> str:
    """Builds a verified 2-Stage WHOIS Domain Lifecycle pipeline (NRD age & expiration)."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
        identifier_field=identifier_field,
        identifier_coverage_payload=identifier_coverage_payload,
    )

  def build_hybrid_derived_asset_age_query(
      self,
      target_metric: str = "auth_attempts_total",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
      identifier_coverage_payload: Optional[Any] = None,
      min_active_days: int = DEFAULT_MIN_BASELINE_DAYS,
      max_asset_age_days: float = 30.0,
      byte_dispersion_floor: Optional[float] = None,
  ) -> str:
    """Builds a verified 2-Stage Derived Context Young Asset Age pipeline (`$active_days >= min_active_days`).

    Note (WS4-BAYES-ASSET / WS1-12): Parametric Z-scoring requires `>= 7` active baseline days plus a
    continuous count/byte dispersion floor so Z never collapses to the raw event count. Infant/Day-0
    assets with `< 7` active baseline days must route to the `WS1-12` `metrics.*` `first_seen` novelty
    path (`FIRST_SEEN_NOVELTY` / `first_seen_novelty_2stage.yl2`).
    """
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
        identifier_field=identifier_field,
        identifier_coverage_payload=identifier_coverage_payload,
        min_active_days=min_active_days,
        max_asset_age_days=max_asset_age_days,
        byte_dispersion_floor=byte_dispersion_floor,
    )

  def build_macd_momentum_velocity_query(
      self,
      target_metric: str = "network_bytes_outbound",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
  ) -> str:
    """Builds a verified 2-Stage MACD Dual-Spine Momentum Velocity pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
    )

  def build_circadian_von_mises_query(
      self,
      target_metric: str = "auth_attempts_total",
      entity_type: EntityType = EntityType.USER,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
  ) -> str:
    """Builds a verified 2-Stage Circadian von Mises Temporal Distance pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.CIRCADIAN_VON_MISES_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
    )

  def build_rare_destination_ecg_query(
      self,
      target_metric: str = "network_bytes_outbound",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
      identifier_coverage_payload: Optional[Any] = None,
      min_baseline_days: Optional[int] = None,
      max_fleet_prevalence: Optional[int] = None,
  ) -> str:
    """Builds a verified 3-Stage Rare Destination ECG Filter pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.RARE_DESTINATION_ECG_3STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        min_baseline_days=min_baseline_days,
        hypothesis_goal=hypothesis_goal,
        identifier_field=identifier_field,
        identifier_coverage_payload=identifier_coverage_payload,
        max_fleet_prevalence=max_fleet_prevalence,
    )

  def build_fusion_rare_destination_query(
      self,
      target_metrics: Optional[List[str]] = None,
      entity_type: EntityType = EntityType.ASSET,
      fusion_threshold_sq: float = 12.25,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
      identifier_coverage_payload: Optional[Any] = None,
      min_baseline_days: Optional[int] = None,
      max_fleet_prevalence: Optional[int] = None,
  ) -> str:
    """Builds a verified 3-Stage Sector Fusion + Rare Destination ECG Filter pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.FUSION_RARE_DESTINATION_3STAGE,
        target_metrics=target_metrics,
        entity_type=entity_type,
        fusion_threshold_sq=fusion_threshold_sq,
        min_baseline_days=min_baseline_days,
        hypothesis_goal=hypothesis_goal,
        identifier_field=identifier_field,
        identifier_coverage_payload=identifier_coverage_payload,
        max_fleet_prevalence=max_fleet_prevalence,
    )

  def build_bridged_host_ip_fusion_query(
      self,
      hostname_metric: str = "auth_attempts_total",
      ip_metric: str = "dns_queries_total",
      min_baseline_days: int = DEFAULT_MIN_BASELINE_DAYS,
      fusion_threshold_sq: float = DEFAULT_FUSION_THRESHOLD_SQ,
      hypothesis_goal: Optional[str] = None,
      analysis_date: Optional[str] = None,
  ) -> str:
    """Builds a 3-stage cross-identifier fusion query bridging hostname-keyed and IP-keyed sectors via ASSET ECG context (D4 / WS1-07)."""
    host_field = PreFlightValidator.resolve_identifier_field(hostname_metric, EntityType.ASSET, "hostname")
    ip_field = PreFlightValidator.resolve_identifier_field(ip_metric, EntityType.ASSET, "ip")
    sem_h = mc.baseline_semantics(hostname_metric)
    sem_i = mc.baseline_semantics(ip_metric)
    date_pin = analysis_date or _today_date()

    def _sector_block(stage_name: str, metric: str, ent_field: str, ent_var: str, sem: mc.MetricSemantics, floor_var: str) -> str:
      filter_lines = "\n    ".join(sem.observed_filter)
      if mc.is_composite_only(metric):
        plan = mc.rollup_plan(metric, ent_field)
        comp_lines = "\n    ".join(plan.companion_bindings())
        extra_events = f"\n    {comp_lines}" if comp_lines else ""
        match_keys = ", ".join([ent_var] + [mc.companion_var(d) for d in plan.companions])
        m_filters = plan.metric_filters()
      else:
        extra_events = ""
        match_keys = ent_var
        m_filters = f"{ent_field}: {ent_field}"
      block = (
          f"stage {stage_name} {{\n"
          f"    {filter_lines}\n"
          f'    timestamp.get_date(metadata.event_timestamp.seconds) = "{date_pin}"\n'
          f"    {ent_field} = {ent_var}\n"
          f'    {ent_var} != ""{extra_events}\n\n'
          "  match:\n"
          f"    {match_keys} by 1d\n\n"
          "  outcome:\n"
          f"    $obs = {sem.observed_agg}\n"
          f"    $avg = max(metrics.{metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: avg, {m_filters}))\n"
          f"    $std = max(metrics.{metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: stddev, {m_filters}))\n"
          f"    $days = max(metrics.{metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: num_metric_periods, {m_filters}))\n"
          f"    {floor_var} = math.sqrt(if($avg > 1.0, $avg, 1.0))\n"
          f"    $raw_z = ($obs - $avg) / if($std > {floor_var}, $std, {floor_var})\n"
          f"    $z = if($days >= {int(min_baseline_days)}, $raw_z, 0.0)\n"
          "}"
      )
      return _apply_byte_dispersion_floor(block, metric, floor_vars=(floor_var,))

    host_stage = _sector_block("sector_host", hostname_metric, host_field, "$host", sem_h, "$h_floor")
    ip_stage = _sector_block("sector_ip", ip_metric, ip_field, "$ip", sem_i, "$i_floor")
    goal_text = hypothesis_goal or f"Cross-identifier ASSET-bridged fusion ({hostname_metric} on hostname + {ip_metric} on IP)"
    rendered = (
        f"// Goal: {goal_text}\n"
        "// ARCHITECTURE: 3-STAGE ASSET-BRIDGED HOSTNAME-TO-IP SECTOR FUSION (D4 / WS1-07)\n\n"
        f"{host_stage}\n\n"
        f"{ip_stage}\n\n"
        "stage asset_bridge {\n"
        '    $asset.graph.metadata.source_type = "DERIVED_CONTEXT"\n'
        '    $asset.graph.metadata.entity_type = "ASSET"\n'
        "    $asset.graph.entity.asset.hostname = $host\n"
        "    $asset.graph.entity.asset.ip = $ip\n"
        '    $host != ""\n'
        '    $ip != ""\n\n'
        "  match:\n"
        "    $host, $ip\n\n"
        "  outcome:\n"
        "    $asset_records = count($asset.graph.metadata.entity_type)\n"
        "}\n\n"
        "$host = $sector_host.host\n"
        "$host = $asset_bridge.host\n"
        "$ip = $sector_ip.ip\n"
        "$ip = $asset_bridge.ip\n\n"
        "match:\n"
        "  $host by 1d\n\n"
        "outcome:\n"
        "  $host_observed = max($sector_host.obs)\n"
        "  $ip_observed = max($sector_ip.obs)\n"
        "  $bridged_ips = array_distinct($sector_ip.ip)\n"
        "  $z_host = max($sector_host.z)\n"
        "  $z_ip = max($sector_ip.z)\n"
        "  $z_host_pos = if($z_host > 0, $z_host, 0.0)\n"
        "  $z_ip_pos = if($z_ip > 0, $z_ip, 0.0)\n"
        "  $composite_threat_norm_sq = ($z_host_pos * $z_host_pos) + ($z_ip_pos * $z_ip_pos)\n\n"
        "condition:\n"
        f"  $composite_threat_norm_sq >= {fusion_threshold_sq}\n\n"
        "order:\n"
        "  $composite_threat_norm_sq desc\n"
    )
    errs = MalachiteASTValidator.validate_query(rendered)
    if errs:
      raise ValueError("Rendered bridged host-to-IP fusion query failed validation: " + " | ".join(errs))
    return rendered

  def build_day0_ecg_companion_query(
      self,
      target_metric: str = "file_executions_total",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      identifier_field: Optional[str] = None,
      max_fleet_prevalence: int = 3,
      byte_dispersion_floor: Optional[float] = None,
  ) -> str:
    """Builds an AST-valid Day-0 companion query without any graph.* inner join (PF-8 / WS1-08).

    DERIVED_CONTEXT daily records lag 24-48h and WHOIS has coverage gaps, so any
    newly observed Day-0 binary, domain, destination IP, or infant asset is dropped
    by an Entity Graph inner join. Run this companion query over the unshifted scored
    UTC day [D 00:00Z, end) to catch Day-0 unindexed artifacts via metrics.* history
    and live fleet footprint.
    """
    ent_field = PreFlightValidator.resolve_identifier_field(target_metric, entity_type, identifier_field)
    ent_var = "$user" if entity_type == EntityType.USER else ("$resource" if entity_type == EntityType.RESOURCE else "$host")
    ent_name = ent_var.lstrip("$")
    fleet_field = ent_field if entity_type == EntityType.ASSET else "principal.asset.hostname"
    sem = mc.baseline_semantics(target_metric)
    filter_lines = "\n    ".join(sem.observed_filter)

    if target_metric.startswith("file_executions_"):
      rendered = (
          f"// Goal: WS1-08 Day-0 Companion Query (no DERIVED_CONTEXT graph inner join) for {target_metric}\n"
          "stage stage1_day0_baseline {\n"
          f"    {filter_lines}\n"
          "    $event_type = metadata.event_type\n"
          f"    {ent_field} = {ent_var}\n"
          "    principal.process.file.sha256 = $sha256\n"
          f'    {ent_var} != ""\n'
          '    $sha256 != ""\n\n'
          "  match:\n"
          f"    {ent_var}, $sha256 by 1d\n\n"
          "  outcome:\n"
          f"    $obs = {sem.observed_agg}\n"
          f"    $avg = max(metrics.{target_metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: avg, metadata.event_type: metadata.event_type, {ent_field}: {ent_field}, principal.process.file.sha256: principal.process.file.sha256))\n"
          f"    $std = max(metrics.{target_metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: stddev, metadata.event_type: metadata.event_type, {ent_field}: {ent_field}, principal.process.file.sha256: principal.process.file.sha256))\n"
          f"    $days = max(metrics.{target_metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: num_metric_periods, metadata.event_type: metadata.event_type, {ent_field}: {ent_field}, principal.process.file.sha256: principal.process.file.sha256))\n"
          "}\n\n"
          "stage stage2_day0_fleet_scope {\n"
          '    metadata.event_type = "PROCESS_LAUNCH"\n'
          "    principal.process.file.sha256 = $sha256\n"
          f"    {fleet_field} = $fleet_host\n"
          '    $sha256 != ""\n'
          '    $fleet_host != ""\n\n'
          "  match:\n"
          "    $sha256\n\n"
          "  outcome:\n"
          "    $today_fleet_hosts = count_distinct($fleet_host)\n"
          "}\n\n"
          f"{ent_var} = $stage1_day0_baseline.{ent_name}\n"
          "$sha256 = $stage1_day0_baseline.sha256\n"
          "$sha256 = $stage2_day0_fleet_scope.sha256\n\n"
          "match:\n"
          f"  {ent_var}, $sha256 by 1d\n\n"
          "outcome:\n"
          "  $observed = max($stage1_day0_baseline.obs)\n"
          "  $hist_avg = max($stage1_day0_baseline.avg)\n"
          "  $hist_stddev = max($stage1_day0_baseline.std)\n"
          "  $active_baseline_days = max($stage1_day0_baseline.days)\n"
          "  $dispersion_floor = math.sqrt(if($hist_avg > 1.0, $hist_avg, 1.0))\n"
          "  $z_score = ($observed - $hist_avg) / if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)\n"
          "  $today_fleet_hosts = max($stage2_day0_fleet_scope.today_fleet_hosts)\n"
          "  $is_day0_unseen_pair = if($active_baseline_days = 0, 1.0, 0.0)\n\n"
          "condition:\n"
          f"  $today_fleet_hosts <= {int(max_fleet_prevalence)}\n"
          f"  and ($active_baseline_days = 0 or $z_score >= {anomaly_threshold})\n\n"
          "order:\n"
          "  $observed desc\n"
      )
    elif target_metric.startswith(("http_queries_", "dns_queries_")):
      domain_field = "network.dns_domain" if target_metric.startswith("dns_") else "target.hostname"
      rendered = (
          f"// Goal: WS1-08 Day-0 Companion Query (no ECG/WHOIS graph inner join) for {target_metric}\n"
          "stage stage1_day0_baseline {\n"
          f"    {filter_lines}\n"
          f"    {ent_field} = {ent_var}\n"
          f"    {domain_field} = $domain\n"
          f'    {ent_var} != ""\n'
          '    $domain != ""\n\n'
          "  match:\n"
          f"    {ent_var}, $domain by 1d\n\n"
          "  outcome:\n"
          f"    $obs = {sem.observed_agg}\n"
          f"    $avg = max(metrics.{target_metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: avg, {ent_field}: {ent_field}, {domain_field}: {domain_field}))\n"
          f"    $std = max(metrics.{target_metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: stddev, {ent_field}: {ent_field}, {domain_field}: {domain_field}))\n"
          f"    $days = max(metrics.{target_metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: num_metric_periods, {ent_field}: {ent_field}, {domain_field}: {domain_field}))\n"
          "}\n\n"
          "stage stage2_day0_fleet_scope {\n"
          f"    {filter_lines}\n"
          f"    {domain_field} = $domain\n"
          f"    {fleet_field} = $fleet_host\n"
          '    $domain != ""\n'
          '    $fleet_host != ""\n\n'
          "  match:\n"
          "    $domain\n\n"
          "  outcome:\n"
          "    $today_fleet_hosts = count_distinct($fleet_host)\n"
          "}\n\n"
          f"{ent_var} = $stage1_day0_baseline.{ent_name}\n"
          "$domain = $stage1_day0_baseline.domain\n"
          "$domain = $stage2_day0_fleet_scope.domain\n\n"
          "match:\n"
          f"  {ent_var}, $domain by 1d\n\n"
          "outcome:\n"
          "  $observed = max($stage1_day0_baseline.obs)\n"
          "  $hist_avg = max($stage1_day0_baseline.avg)\n"
          "  $hist_stddev = max($stage1_day0_baseline.std)\n"
          "  $active_baseline_days = max($stage1_day0_baseline.days)\n"
          "  $dispersion_floor = math.sqrt(if($hist_avg > 1.0, $hist_avg, 1.0))\n"
          "  $z_score = ($observed - $hist_avg) / if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)\n"
          "  $today_fleet_hosts = max($stage2_day0_fleet_scope.today_fleet_hosts)\n"
          "  $is_day0_unseen_pair = if($active_baseline_days = 0, 1.0, 0.0)\n\n"
          "condition:\n"
          f"  $today_fleet_hosts <= {int(max_fleet_prevalence)}\n"
          f"  and ($active_baseline_days = 0 or $z_score >= {anomaly_threshold})\n\n"
          "order:\n"
          "  $observed desc\n"
      )
    else:
      if mc.is_composite_only(target_metric):
        plan = mc.rollup_plan(target_metric, ent_field)
        comp_lines = "\n    ".join(plan.companion_bindings())
        extra_events = f"\n    {comp_lines}" if comp_lines else ""
        match_keys = ", ".join([ent_var] + [mc.companion_var(d) for d in plan.companions])
        m_filters = plan.metric_filters()
      else:
        extra_events = ""
        match_keys = ent_var
        m_filters = f"{ent_field}: {ent_field}"
      rendered = (
          f"// Goal: WS1-08 Day-0 Companion Query (no DERIVED_CONTEXT graph inner join) for {target_metric}\n"
          "stage stage1_day0_baseline {\n"
          f"    {filter_lines}\n"
          f"    {ent_field} = {ent_var}\n"
          f'    {ent_var} != ""{extra_events}\n\n'
          "  match:\n"
          f"    {match_keys} by 1d\n\n"
          "  outcome:\n"
          f"    $obs = {sem.observed_agg}\n"
          f"    $avg = max(metrics.{target_metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: avg, {m_filters}))\n"
          f"    $std = max(metrics.{target_metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: stddev, {m_filters}))\n"
          f"    $days = max(metrics.{target_metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: num_metric_periods, {m_filters}))\n"
          "}\n\n"
          f"{ent_var} = $stage1_day0_baseline.{ent_name}\n\n"
          "match:\n"
          f"  {ent_var} by 1d\n\n"
          "outcome:\n"
          "  $observed = max($stage1_day0_baseline.obs)\n"
          "  $hist_avg = max($stage1_day0_baseline.avg)\n"
          "  $hist_stddev = max($stage1_day0_baseline.std)\n"
          "  $active_baseline_days = max($stage1_day0_baseline.days)\n"
          "  $dispersion_floor = math.sqrt(if($hist_avg > 1.0, $hist_avg, 1.0))\n"
          "  $z_score = ($observed - $hist_avg) / if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)\n"
          "  $is_day0_unseen_entity = if($active_baseline_days = 0, 1.0, 0.0)\n\n"
          "condition:\n"
          f"  $active_baseline_days = 0 or $z_score >= {anomaly_threshold}\n\n"
          "order:\n"
          "  $observed desc\n"
      )
      rendered = _apply_byte_dispersion_floor(rendered, target_metric, byte_dispersion_floor=byte_dispersion_floor)

    errs = MalachiteASTValidator.validate_query(rendered)
    if errs:
      raise ValueError("Rendered Day-0 ECG companion query failed validation: " + " | ".join(errs))
    return rendered

  # Canonical MITRE ATT&CK Multi-Stage Kill-Chain Archetypes
  KILLCHAIN_CATALOG: Dict[KillChainArchetype, Dict[str, Any]] = {
      KillChainArchetype.RECON_ENUMERATION_TO_INITIAL_ACCESS: {
          "mitre_tactics": ("TA0043 Reconnaissance", "TA0001 Initial Access"),
          "sector_a": "http_queries_fail",
          "sector_b": "auth_attempts_success",
          "supported_entities": (EntityType.ASSET, EntityType.USER),
          "rare_destination": False,
          "description": "Web/API failure enumeration surge followed by successful authentication",
      },
      KillChainArchetype.RESOURCE_DEV_NRD_TO_C2_EGRESS: {
          "mitre_tactics": ("TA0042 Resource Development", "TA0011 Command and Control"),
          "sector_a": "file_executions_total",
          "sector_b": "http_queries_total",
          "supported_entities": (EntityType.ASSET, EntityType.USER),
          "rare_destination": False,
          "description": "Staged binary tooling execution paired with HTTP C2 communication surge",
      },
      KillChainArchetype.CREDENTIAL_ACCESS_TO_EXECUTION: {
          "mitre_tactics": ("TA0006 Credential Access", "TA0002 Execution"),
          "sector_a": "file_executions_total",
          "sector_b": "auth_attempts_fail",
          "supported_entities": (EntityType.ASSET, EntityType.USER),
          "rare_destination": False,
          "description": "Credential stuffing/brute-force followed by novel binary execution",
      },
      KillChainArchetype.INITIAL_ACCESS_TO_DISCOVERY: {
          "mitre_tactics": ("TA0001 Initial Access", "TA0007 Discovery"),
          "sector_a": "auth_attempts_success",
          "sector_b": "http_queries_fail",
          "supported_entities": (EntityType.ASSET, EntityType.USER),
          "rare_destination": False,
          "description": "Compromised account login followed by internal web/API error scanning",
      },
      KillChainArchetype.EXECUTION_TO_C2_DNS: {
          "mitre_tactics": ("TA0002 Execution", "TA0011 Command and Control"),
          "sector_a": "file_executions_total",
          "sector_b": "dns_queries_total",
          "supported_entities": (EntityType.ASSET, EntityType.USER),
          "rare_destination": False,
          "description": "Suspicious endpoint binary launch paired with DNS C2 resolution surge",
      },
      KillChainArchetype.EXECUTION_TO_EXFILTRATION: {
          "mitre_tactics": ("TA0002 Execution", "TA0010 Exfiltration"),
          "sector_a": "file_executions_total",
          "sector_b": "network_bytes_outbound",
          "supported_entities": (EntityType.ASSET, EntityType.USER),
          "rare_destination": False,
          "description": "Endpoint process staging followed by anomalous outbound data transfer",
      },
      KillChainArchetype.CREDENTIAL_ACCESS_TO_LATERAL_MOVEMENT: {
          "mitre_tactics": ("TA0006 Credential Access", "TA0008 Lateral Movement"),
          "sector_a": "auth_attempts_fail",
          "sector_b": "network_flows_total",
          "supported_entities": (EntityType.ASSET, EntityType.USER),
          "rare_destination": False,
          "description": "Failed login burst paired with anomalous lateral network connection flows",
      },
      KillChainArchetype.EAST_WEST_LATERAL_FANOUT: {
          "mitre_tactics": ("TA0008 Lateral Movement", "TA0002 Execution"),
          "sector_a": "network_flows_outbound",
          "sector_b": "auth_attempts_success",
          "supported_entities": (EntityType.ASSET, EntityType.USER),
          "rare_destination": False,
          "description": "Outbound lateral connection fan-out paired with anomalous authentication success",
      },
      KillChainArchetype.CLOUD_DISCOVERY_TO_COLLECTION: {
          "mitre_tactics": ("TA0007 Discovery", "TA0009 Collection"),
          "sector_a": "resource_read_total",
          "sector_b": "workspace_total_download_actions",
          "supported_entities": (EntityType.USER,),
          "rare_destination": False,
          "description": "Cloud resource enumeration paired with bulk Workspace download hoarding",
      },
      KillChainArchetype.DEFENSE_EVASION_ALERT_TO_EXFILTRATION: {
          "mitre_tactics": ("TA0005 Defense Evasion", "TA0010 Exfiltration"),
          "sector_a": "alert_event_name_count",
          "sector_b": "network_bytes_outbound",
          "supported_entities": (EntityType.ASSET,),
          "rare_destination": False,
          "description": "EDR alert accumulation paired with outbound network exfiltration",
      },
      KillChainArchetype.C2_BEACON_TO_RARE_DESTINATION_EXFIL: {
          "mitre_tactics": ("TA0011 Command and Control", "TA0010 Exfiltration"),
          "sector_a": "auth_attempts_total",
          "sector_b": "http_queries_total",
          "supported_entities": (EntityType.ASSET,),
          "rare_destination": True,
          "description": "Host authentication anomaly fused with HTTP surge to rare external destinations",
      },
  }

  def build_killchain_hunt_query(
      self,
      archetype: KillChainArchetype,
      entity_type: Optional[EntityType] = None,
      four_stage: bool = False,
      min_baseline_days: int = 7,
      fusion_threshold_sq: float = 12.25,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
  ) -> str:
    """Builds a verified multi-stage MITRE ATT&CK Kill-Chain Fusion query for any canonical archetype."""
    if isinstance(archetype, str) and not isinstance(archetype, KillChainArchetype):
      archetype = KillChainArchetype(archetype.strip().upper())
    if archetype not in self.KILLCHAIN_CATALOG:
      raise ValueError(f"Unsupported KillChainArchetype: {archetype}")
    spec = self.KILLCHAIN_CATALOG[archetype]
    supported = spec["supported_entities"]
    if entity_type is None:
      entity_type = supported[0]
    if entity_type not in supported:
      raise ValueError(
          f"Archetype {archetype.value} supports entity types {[e.value for e in supported]}, got {entity_type.value}"
      )
    tactic_a, tactic_b = spec["mitre_tactics"]
    goal = hypothesis_goal or f"MITRE Kill-Chain ({tactic_a} -> {tactic_b}): {spec['description']}"
    if spec.get("rare_destination"):
      q = self.build_fusion_rare_destination_query(
          target_metrics=[spec["sector_a"], spec["sector_b"]],
          entity_type=entity_type,
          fusion_threshold_sq=fusion_threshold_sq,
          hypothesis_goal=goal,
      )
    else:
      sec_a = mc.SectorSpec(spec["sector_a"], self._sector_entity_field(spec["sector_a"], entity_type, identifier_field))
      sec_b = mc.SectorSpec(spec["sector_b"], self._sector_entity_field(spec["sector_b"], entity_type, identifier_field))
      q = self.build_sector_fusion_query(
          sec_a,
          sec_b,
          four_stage=four_stage,
          min_baseline_days=min_baseline_days,
          hypothesis_goal=goal,
          fusion_threshold_sq=fusion_threshold_sq,
      )
    return f"// MITRE ATT&CK Kill-Chain: {tactic_a} -> {tactic_b} ({archetype.value})\n" + q


class ChainedHuntRouter:
  """Builds Two-Phase Chained Hunt query specifications across entity boundaries."""

  CROSS_ENTITY_PATHS: Tuple[str, ...] = (
      "USER_CREDENTIAL_TO_HOST_EXECUTION",
      "HOST_EXECUTION_TO_CLOUD_SA_ACCESS",
      "HOST_ALERT_TO_PROCESS_EXECUTION",
      "USER_WORKSPACE_HOARDING_TO_HOST_EGRESS",
  )

  @staticmethod
  def build_phase1_endpoint_query(entity_scope: str = "fleet", anomaly_threshold: float = 3.0) -> str:
    """Builds Phase 1 Endpoint Process Outlier YARA-L query."""
    host_filter = "" if entity_scope == "fleet" else f'  $proc.principal.asset.hostname = "{entity_scope}"\n'
    return (
        "// Goal: Phase 1 Endpoint Process Outlier Hunt\n"
        "// Architecture: Two-Phase Chained Pipeline\n"
        "stage stage1_process_outlier {\n"
        "  $proc.metadata.event_type = \"PROCESS_LAUNCH\"\n"
        f"{host_filter}"
        "  $host = $proc.principal.asset.hostname\n"
        "  $sha256 = $proc.principal.process.file.sha256\n"
        "\n"
        "  match:\n"
        "    $host, $sha256 by 1d\n"
        "\n"
        "  outcome:\n"
        "    $obs = count($proc.metadata.id)\n"
        "    $mu = max(metrics.file_executions_total(\n"
        "      period: 1d, window: 30d, metric: event_count_sum, agg: avg,\n"
        "      metadata.event_type: metadata.event_type,\n"
        "      principal.asset.hostname: principal.asset.hostname, principal.process.file.sha256: principal.process.file.sha256\n"
        "    ))\n"
        "    $sigma = max(metrics.file_executions_total(\n"
        "      period: 1d, window: 30d, metric: event_count_sum, agg: stddev,\n"
        "      metadata.event_type: metadata.event_type,\n"
        "      principal.asset.hostname: principal.asset.hostname, principal.process.file.sha256: principal.process.file.sha256\n"
        "    ))\n"
        "    $days = max(metrics.file_executions_total(\n"
        "      period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,\n"
        "      metadata.event_type: metadata.event_type,\n"
        "      principal.asset.hostname: principal.asset.hostname, principal.process.file.sha256: principal.process.file.sha256\n"
        "    ))\n"
        "    $dispersion_floor = math.sqrt(if($mu > 1.0, $mu, 1.0))\n"
        "    $z_score = ($obs - $mu) / if($sigma > $dispersion_floor, $sigma, $dispersion_floor)\n"
        "}\n"
        "\n"
        "$host = $stage1_process_outlier.host\n"
        "$sha256 = $stage1_process_outlier.sha256\n"
        "\n"
        "match:\n"
        "  $host, $sha256 by 1d\n"
        "\n"
        "outcome:\n"
        "  $process_z = max($stage1_process_outlier.z_score)\n"
        "  $active_days = max($stage1_process_outlier.days)\n"
        "  $observed_launches = max($stage1_process_outlier.obs)\n"
        "  $historical_mean = max($stage1_process_outlier.mu)\n"
        "\n"
        "condition:\n"
        f"  $active_days >= 7 and $process_z >= {anomaly_threshold}\n"
        "\n"
        "order:\n"
        "  $process_z desc\n"
    )

  @staticmethod
  def build_phase2_cloud_query(target_user: Optional[str] = None, caller_ip: Optional[str] = None) -> str:
    """Builds Phase 2 Targeted Cloud Audit UDM search query."""
    filters = ['metadata.vendor_name = "Google Cloud Platform"', 'metadata.event_type = "USER_RESOURCE_ACCESS"']
    if target_user and caller_ip:
      filters.append(f'(principal.user.userid = "{target_user}" or principal.ip = "{caller_ip}")')
    elif target_user:
      filters.append(f'principal.user.userid = "{target_user}"')
    elif caller_ip:
      filters.append(f'principal.ip = "{caller_ip}"')
    
    return " AND ".join(filters)

  @classmethod
  def build_data_table_bridge_query(
      cls,
      entity_type: EntityType = EntityType.ASSET,
      target_metric: str = "network_bytes_outbound",
      anomaly_threshold: float = 3.0,
      min_baseline_days: int = DEFAULT_MIN_BASELINE_DAYS,
      data_table_name: str = "ueba_hunt_bridge",
      data_table_column: str = "entity",
      identifier_field: Optional[str] = None,
      byte_dispersion_floor: Optional[float] = None,
  ) -> str:
    """Builds a canonical 2-Stage Data Table Bridge query (`%<table_name>.<column_name>`, default `%ueba_hunt_bridge.entity`)."""
    audit = PreFlightValidator.audit(
        target_metric=target_metric,
        entity_type=entity_type,
        min_baseline_days=min_baseline_days,
        identifier_field=identifier_field,
    )
    ent_field = audit["target_field"]
    filter_block = "\n    ".join(audit["event_filter"])
    b_floor = resolve_byte_dispersion_floor(target_metric, byte_dispersion_floor=byte_dispersion_floor)
    if b_floor is not None:
      floor_line = f"  $dispersion_floor = {b_floor:.1f}\n"
    else:
      floor_line = "  $dispersion_floor = math.sqrt(if($baseline_mean > 1.0, $baseline_mean, 1.0))\n"
    rendered = (
        f"// Goal: Score 30-day {target_metric} behavioral departures for bridged cohort in %{data_table_name}.{data_table_column}\n"
        "// Architecture: 2-Stage Hybrid Data Table Bridge (HYBRID_DATA_TABLE_BRIDGE_2STAGE)\n\n"
        "stage stage1_extract {\n"
        f"    {filter_block}\n"
        f"    {ent_field} in %{data_table_name}.{data_table_column}\n"
        f"    {ent_field} = $entity\n"
        '    $entity != ""\n\n'
        "  match:\n"
        "    $entity by 1d\n\n"
        "  outcome:\n"
        f"    $observed_val = {audit['observed_agg']}\n"
        f"    $historical_avg = max(metrics.{target_metric}(\n"
        f"        period: 1d, window: 30d, metric: {audit['metric_arg']}, agg: avg,\n"
        f"        {ent_field}: {ent_field}\n"
        "    ))\n"
        f"    $historical_stddev = max(metrics.{target_metric}(\n"
        f"        period: 1d, window: 30d, metric: {audit['metric_arg']}, agg: stddev,\n"
        f"        {ent_field}: {ent_field}\n"
        "    ))\n"
        f"    $active_baseline_days = max(metrics.{target_metric}(\n"
        f"        period: 1d, window: 30d, metric: {audit['metric_arg']}, agg: num_metric_periods,\n"
        f"        {ent_field}: {ent_field}\n"
        "    ))\n"
        "}\n\n"
        "$entity = $stage1_extract.entity\n\n"
        "match:\n"
        "  $entity by 1d\n\n"
        "outcome:\n"
        "  $observed_24h = max($stage1_extract.observed_val)\n"
        "  $baseline_mean = max($stage1_extract.historical_avg)\n"
        "  $baseline_stddev = max($stage1_extract.historical_stddev)\n"
        "  $active_days = max($stage1_extract.active_baseline_days)\n"
        f"{floor_line}"
        "  $safe_stddev = if($baseline_stddev > $dispersion_floor, $baseline_stddev, $dispersion_floor)\n"
        "  $personal_z = ($observed_24h - $baseline_mean) / $safe_stddev\n\n"
        "condition:\n"
        f"  $active_days >= {int(audit['min_baseline_days'])} and $personal_z >= {anomaly_threshold}\n\n"
        "order:\n"
        "  $personal_z desc\n"
    )
    errs = MalachiteASTValidator.validate_query(rendered)
    if errs:
      raise ValueError("Rendered Data Table bridge query failed validation: " + " | ".join(errs))
    return rendered

  @classmethod
  def build_cross_entity_killchain_plan(
      cls,
      path_name: str,
      bridge_entity: Optional[str] = None,
      anomaly_threshold: float = 3.0,
  ) -> Dict[str, Any]:
    """Builds a deterministic Two-Phase Cross-Entity or Dual-Composite Kill-Chain Bridge Plan."""
    router = MultiStageTemplateRouter()
    key = path_name.strip().upper()
    if key == "USER_CREDENTIAL_TO_HOST_EXECUTION":
      phase1 = router.build_query(
          target_metric="auth_attempts_fail",
          entity_type=EntityType.USER,
          statistical_model=StatisticalModel.STANDARD_Z_SCORE,
          anomaly_threshold=anomaly_threshold,
          hypothesis_goal="Phase 1 (TA0006 Credential Access): Identify user accounts with anomalous failed login surges",
      )
      phase2 = router.build_hybrid_derived_file_prevalence_query(
          target_metric="file_executions_total",
          entity_type=EntityType.ASSET,
          anomaly_threshold=anomaly_threshold,
          hypothesis_goal=f"Phase 2 (TA0002 Execution on bridged host {bridge_entity or '$host'}): Rare binary execution surge",
      )
      return {
          "path_name": key,
          "mitre_tactics": ("TA0006 Credential Access", "TA0002 Execution"),
          "bridge_contract": ("$user", "$host", "$timestamp"),
          "phase1_query": phase1,
          "phase2_query": phase2,
      }
    elif key == "HOST_EXECUTION_TO_CLOUD_SA_ACCESS":
      phase1 = router.build_hybrid_derived_file_prevalence_query(
          target_metric="file_executions_total",
          entity_type=EntityType.ASSET,
          anomaly_threshold=anomaly_threshold,
          hypothesis_goal="Phase 1 (TA0002 Execution): Identify endpoint rare binary execution outliers",
      )
      sa_arg = bridge_entity if (bridge_entity and ("@" in bridge_entity or "arn:aws:" in bridge_entity)) else None
      phase2 = router.build_cloud_repository_scope_query(
          service_account=sa_arg,
          anomaly_threshold=anomaly_threshold,
          hypothesis_goal="Phase 2 (TA0007/TA0009 Cloud Resource Access): Baseline 4 CRUD families and origin IP",
      )
      return {
          "path_name": key,
          "mitre_tactics": ("TA0002 Execution", "TA0007 Discovery / TA0009 Collection"),
          "bridge_contract": ("$host", "$user", "$caller_ip"),
          "phase1_query": phase1,
          "phase2_query": phase2,
      }
    elif key == "HOST_ALERT_TO_PROCESS_EXECUTION":
      phase1 = router.build_alert_surge_query(
          entity_type=EntityType.ASSET,
          anomaly_threshold=anomaly_threshold,
          hypothesis_goal="Phase 1 (TA0005 Defense Evasion): Identify hosts with novel or surging EDR rule alerts",
      )
      phase2 = router.build_hybrid_derived_file_prevalence_query(
          target_metric="file_executions_total",
          entity_type=EntityType.ASSET,
          anomaly_threshold=anomaly_threshold,
          hypothesis_goal=f"Phase 2 (TA0002 Execution on {bridge_entity or '$host'}): Verify enterprise binary rarity",
      )
      return {
          "path_name": key,
          "mitre_tactics": ("TA0005 Defense Evasion", "TA0002 Execution"),
          "bridge_contract": ("$host", "$sha256", "$rule_name"),
          "phase1_query": phase1,
          "phase2_query": phase2,
      }
    elif key == "USER_WORKSPACE_HOARDING_TO_HOST_EGRESS":
      phase1 = router.build_query(
          target_metric="workspace_total_download_actions",
          entity_type=EntityType.USER,
          statistical_model=StatisticalModel.STANDARD_Z_SCORE,
          anomaly_threshold=anomaly_threshold,
          hypothesis_goal="Phase 1 (TA0009 Collection): Identify users with bulk Workspace download hoarding",
      )
      phase2 = router.build_rare_destination_ecg_query(
          target_metric="network_bytes_outbound",
          entity_type=EntityType.ASSET,
          anomaly_threshold=anomaly_threshold,
          hypothesis_goal=f"Phase 2 (TA0010 Exfiltration from {bridge_entity or '$host'}): Outbound byte surge to rare destinations",
      )
      return {
          "path_name": key,
          "mitre_tactics": ("TA0009 Collection", "TA0010 Exfiltration"),
          "bridge_contract": ("$user", "$host", "$caller_ip"),
          "phase1_query": phase1,
          "phase2_query": phase2,
      }
    raise ValueError(f"Unsupported cross-entity kill-chain path '{path_name}'. Must be one of {cls.CROSS_ENTITY_PATHS}")


STAGE2_TEMPLATES = MultiStageTemplateRouter.STAGE2_TEMPLATES
MODEL_DESCRIPTIONS = MultiStageTemplateRouter.MODEL_DESCRIPTIONS
validate_rendered_pipeline = MultiStageTemplateRouter.validate_rendered_pipeline
