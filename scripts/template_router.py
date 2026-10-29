# Template Router for Multi-Stage YARA-L Queries (.yl2)

__author__ = "Greg Kushmerek"
__version__ = "2.1.1"

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
      "macd_momentum": "macd_momentum_velocity.yl2",
      "macd_momentum_velocity": "macd_momentum_velocity.yl2",
      "longitudinal_cusum": "longitudinal_cusum.yl2",
  }

  STAGE2_FALLBACK_TEMPLATES: Dict[str, str] = {}

  MODEL_DESCRIPTIONS = {
      StatisticalModel.COEFFICIENT_OF_VARIATION: "Regular-Volume Surge (Low-CV Predictable Baseline)",
      "coefficient_of_variation": "Regular-Volume Surge (Low-CV Predictable Baseline)",
      StatisticalModel.LONGITUDINAL_CUSUM: "Multi-Day Cumulative Drift (Windowed Slack Sum)",
      "longitudinal_cusum": "Multi-Day Cumulative Drift (Windowed Slack Sum)",
      StatisticalModel.MACD_MOMENTUM_VELOCITY: "Above-Historical-Max Z (Linear Peak Exceedance)",
      "macd_momentum": "Above-Historical-Max Z (Linear Peak Exceedance)",
      "macd_momentum_velocity": "Above-Historical-Max Z (Linear Peak Exceedance)",
      StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z: "Standard Z-Score (Merged from ASYMMETRIC_DIRECTIONAL_Z per D1)",
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
  GATE_PLACEHOLDERS = ("anomaly_threshold", "fold_change_threshold", "fusion_threshold_sq", "robust_threshold")
  _GATE_CLAUSE_RE = re.compile(
      r"(\$[A-Za-z0-9_]+)\s*>=\s*\{\{(anomaly_threshold|fold_change_threshold|fusion_threshold_sq|robust_threshold)\}\}")
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
      }
      for name, value in values.items():
        rendered = rendered.replace("{{" + name + "}}", str(value))
      return rendered

    clause = None
    cond = cls._ROOT_CONDITION_RE.search(rendered)
    if cond:
      m = cls._GATE_CLAUSE_RE.search(cond.group(1))
      if m:
        clause = (cond.start(1) + m.start(), cond.start(1) + m.end(), m.group(1), cond.group(1).strip() == m.group(0))

    if clause:
      gate_var = clause[2]
    else:
      order_match = re.search(r"^order:\s*\n\s*([$][a-zA-Z0-9_]+)", rendered, re.M)
      gate_var = order_match.group(1) if order_match else default_score

    if condition_expression:
      if cond or not only_if_template_gate:
        rendered = cls._set_root_condition(rendered, condition_expression)
    else:
      override = None
      if min_threshold is not None and max_threshold is not None:
        override = f"{gate_var} >= {min_threshold} and {gate_var} < {max_threshold}"
      elif min_threshold is not None:
        override = f"{gate_var} >= {min_threshold}"
      elif max_threshold is not None:
        override = f"{gate_var} <= {max_threshold}"

      if override:
        if clause:
          start, end, _, is_whole = clause
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
    }
    for name, value in values.items():
      rendered = rendered.replace("{{" + name + "}}", str(value))
    return rendered

  # ---------------------------------------------------------------------------
  # Generic sector fusion
  # ---------------------------------------------------------------------------

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
  ) -> str:
    """Renders a dual-sector (3-stage) or multi-sector (4-stage, fleet-normalized) fusion for ANY two
    entity-keyed metrics. Pairing rules come from malachite_catalog.check_fusion_pair; advisories are
    emitted as '// ADVISORY:' lines and kept in self.last_advisories.

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

    if rollup:
      plan = sector_a.rollup()
      rendered = _fill_event_filter(rendered, "{{sector_a_companion_bindings}}", plan.companion_bindings())
      rendered = rendered.replace("{{sector_a_match_keys}}", plan.match_keys())
      rendered = rendered.replace("{{sector_a_metric_filters}}", plan.metric_filters())
      rendered = rendered.replace("{{sector_a_detail_key}}", mc.companion_var(plan.detail_key_dimension).lstrip("$"))
    for tag, spec in (("a", sector_a), ("b", sector_b)):
      sem = mc.baseline_semantics(spec.metric)
      rendered = rendered.replace(f"{{{{sector_{tag}_label}}}}", spec.label())
      rendered = _fill_event_filter(rendered, f"{{{{sector_{tag}_event_filter}}}}", sem.observed_filter)
      rendered = rendered.replace(f"{{{{sector_{tag}_entity_field}}}}", spec.entity_field)
      rendered = rendered.replace(f"{{{{sector_{tag}_observed_agg}}}}", sem.observed_agg)
      rendered = rendered.replace(f"{{{{sector_{tag}_metric_arg}}}}", sem.metric_arg)
      rendered = rendered.replace(f"{{{{sector_{tag}_metric}}}}", spec.metric)
      rendered = _apply_byte_dispersion_floor(rendered, spec.metric, floor_vars=(f"${tag}_floor",))
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
      r'^[ \t]*\$([A-Za-z0-9_]+)[ \t]*=[ \t]*max\(metrics\.[A-Za-z0-9_]+\([^()]*\)\)[ \t]*\n', re.M)
  _METRICS_ALIAS_RE = re.compile(
      r'^[ \t]*\$([A-Za-z0-9_]+)[ \t]*=[ \t]*\$(historical_[A-Za-z0-9_]+)[ \t]*\n', re.M)

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
      include_significance_gate: bool = True,
      byte_dispersion_floor: Optional[float] = None,
      identifier_coverage_payload: Optional[Any] = None,
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

    # Enforce Local-Baseline Isolation: default STANDARD_Z_SCORE multi-database account queries
    # route to CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH; explicit non-Z models render directly.
    if (
        target_metric.startswith("resource_")
        and entity_type == EntityType.USER
        and statistical_model == StatisticalModel.STANDARD_Z_SCORE
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
          include_significance_gate=include_significance_gate,
      )

    stage1_path = self.template_dir / "stage1_extractors" / f"{target_metric}.yl2"
    if not stage1_path.exists():
      raise FileNotFoundError(f"Missing Stage 1 template: {stage1_path}")
    stage1_content = self._rebind_entity_field(
        self._strip_identifier_swap_note(stage1_path.read_text().strip()), target_metric, audit["target_field"])

    model_key = statistical_model
    stage2_file = self.STAGE2_TEMPLATES.get(statistical_model)
    if not stage2_file:
      raise ValueError(f"Unknown statistical model: '{statistical_model}'")
    stage2_path = self.template_dir / "stage2_math_models" / stage2_file
    if not stage2_path.exists():
      raise FileNotFoundError(f"Missing Stage 2 template: {stage2_path}")
    stage2_raw = stage2_path.read_text().strip()

    # Multi-key extractors: determine the metric's full baseline tuple and drop non-dimension Stage 1 match keys.
    group_keys, dropped_keys = self._mad_group_keys(stage1_content)
    stage1_content = self._drop_stage1_match_keys(stage1_content, dropped_keys)

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
      include_significance_gate: bool = True,
      byte_dispersion_floor: Optional[float] = None,
      identifier_coverage_payload: Optional[Any] = None,
  ) -> str:
    """Renders 3-Stage and 4-Stage advanced DAG pipelines, then resolves the root significance gate.

    Pipelines whose template carries a default gate placeholder (see GATE_PLACEHOLDERS) get it filled
    here, and min_threshold / max_threshold / condition_expression replace that default gate.
    Renderers that resolve their own gate (sector fusion, the hybrid_metric_* family) are left as is.
    """
    if isinstance(pipeline_type, str) and not isinstance(pipeline_type, PipelineArchitecture):
      raw_pipe = pipeline_type.strip().upper().replace("-", "_").replace(" ", "_")
      if raw_pipe in PipelineArchitecture.__members__:
        pipeline_type = PipelineArchitecture[raw_pipe]
    if pipeline_type in RETIRED_PIPELINE_ARCHITECTURES:
      raise ValueError(RETIRED_PIPELINE_ARCHITECTURES[pipeline_type])
    rendered = self._render_pipeline(
        pipeline_type,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        min_baseline_days=min_baseline_days,
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
    )
    out = self._apply_significance_gate(
        rendered,
        anomaly_threshold=anomaly_threshold,
        fold_change_threshold=fold_change_threshold,
        fusion_threshold_sq=fusion_threshold_sq,
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
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_http_ua_prevalence_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      if identifier_field:
        ent_field = PreFlightValidator.resolve_identifier_field("http_queries_total", entity_type, identifier_field)
        if ent_field != "principal.asset.hostname":
          raw = raw.replace("principal.asset.hostname = $entity", f"{ent_field} = $entity")
          raw = raw.replace("principal.asset.hostname: principal.asset.hostname", f"{ent_field}: {ent_field}")
          raw = raw.replace("count_distinct(principal.asset.hostname)", f"count_distinct({ent_field})")
          raw = raw.replace("array_distinct(principal.asset.hostname)", f"array_distinct({ent_field})")
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
      if (target_metric or identifier_field) and not (
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
      if identifier_field:
        ent_field = PreFlightValidator.resolve_identifier_field("http_queries_total", entity_type, identifier_field)
        if ent_field != "principal.asset.hostname":
          raw = raw.replace("principal.asset.hostname = $host", f"{ent_field} = $host")
          raw = raw.replace("principal.asset.hostname: principal.asset.hostname", f"{ent_field}: {ent_field}")
          raw = raw.replace("count_distinct(principal.asset.hostname)", f"count_distinct({ent_field})")
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
      if service_account:
        sa_regex_pattern = r"(?:\(\s*)?\$sa\s*=\s*/@.*?nocase(?:\s*\))?"
        sa_binding = f'    $sa = "{self._escape_yaral_literal(service_account)}"'
        raw = re.sub(sa_regex_pattern, sa_binding, raw, flags=re.DOTALL)
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

      # Peer group rule (template header): no named cohort -> drop the TEAM COHORT blocks
      # (fleet only, order by $z_vs_enterprise); named cohort -> keep them, order by $z_vs_team.
      rendered = _apply_team_cohort_blocks(raw, keep=bool(cohort_entities))
      if cohort_entities:
        if len(cohort_entities) > 1:
          cohort_filter = "(\n      " + " or\n      ".join(f'$u = "{self._escape_yaral_literal(c)}"' for c in cohort_entities) + "\n    )"
        else:
          cohort_filter = f'$u = "{self._escape_yaral_literal(cohort_entities[0])}"'
        rendered = rendered.replace("{{cohort_filter}}", cohort_filter)
        rendered = rendered.replace("order:\n  $z_vs_enterprise desc", "order:\n  $z_vs_team desc")
        rendered = rendered.replace("$z_vs_enterprise >= {{anomaly_threshold}}", "$z_vs_team >= {{anomaly_threshold}}")
      if min_threshold is not None:
        rendered = rendered.replace("< {{anomaly_threshold}},", f"< {min_threshold},")

      if target_entity:
        target_filter = f'{entity_var} = "{self._escape_yaral_literal(target_entity)}"'
      elif cohort_entities:
        if len(cohort_entities) > 1:
          target_filter = "(\n  " + " or\n  ".join(f'{entity_var} = "{self._escape_yaral_literal(c)}"' for c in cohort_entities) + "\n)"
        else:
          target_filter = f'{entity_var} = "{self._escape_yaral_literal(cohort_entities[0])}"'
      else:
        target_filter = f'{entity_var} != ""'

      rendered = _fill_event_filter(rendered, "{{event_filter}}", audit["event_filter"])
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

      if target_entity:
        target_filter = f'{entity_var} = "{self._escape_yaral_literal(target_entity)}"'
      elif cohort_entities:
        if len(cohort_entities) > 1:
          target_filter = "(\n  " + " or\n  ".join(f'{entity_var} = "{self._escape_yaral_literal(c)}"' for c in cohort_entities) + "\n)"
        else:
          target_filter = f'{entity_var} = "{self._escape_yaral_literal(cohort_entities[0])}"'
      else:
        target_filter = f'{entity_var} != ""'

      # Peer group rule (template header): with no named cohort the team stage would just
      # recompute the fleet, so the marked TEAM COHORT blocks are dropped (fleet only).
      rendered = _apply_team_cohort_blocks(raw, keep=bool(cohort_entities))
      if cohort_entities:
        if len(cohort_entities) > 1:
          cohort_filter = "(\n      " + " or\n      ".join(f'$u = "{self._escape_yaral_literal(c)}"' for c in cohort_entities) + "\n    )"
        else:
          cohort_filter = f'$u = "{self._escape_yaral_literal(cohort_entities[0])}"'
        rendered = rendered.replace("{{cohort_filter}}", cohort_filter)
        rendered = rendered.replace("order:\n  $d_vs_fleet_sq desc", "order:\n  $d_vs_team_sq desc")
        rendered = rendered.replace("$d_vs_fleet_sq >= {{fusion_threshold_sq}}", "$d_vs_team_sq >= {{fusion_threshold_sq}}")
      if min_threshold is not None:
        rendered = rendered.replace("< {{fusion_threshold_sq}},", f"< {min_threshold},")

      rendered = _fill_event_filter(rendered, "{{event_filter}}", triad_filter)
      rendered = rendered.replace("{{entity_field}}", triad_audit["target_field"])
      rendered = rendered.replace("{{entity_var}}", entity_var)
      rendered = rendered.replace("{{entity_name}}", entity_name)
      rendered = rendered.replace("{{target_entity_filter}}", target_filter)

      for idx, m in enumerate(target_metrics[:3], 1):
        metric_type_arg = f"metric: {mc.baseline_semantics(m).metric_arg}"
        obs_agg = triad_obs[m]
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
      rendered = rendered.replace("{{max_diversity_ratio}}", "0.10")
      rendered = rendered.replace("{{min_concentration_ratio}}", "0.75")
      rendered = rendered.replace("{{min_raw_events}}", "5")
      rendered = _apply_byte_dispersion_floor(rendered, target_metric, byte_dispersion_floor=byte_dispersion_floor)

      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered

      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE:
      if not target_metric:
        target_metric = "network_bytes_outbound"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_orthogonal_space_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      metric_type_arg = f"metric: {audit['metric_arg']}"

      macro_entity_field = audit["target_field"]
      macro_observed_agg = audit["observed_agg"]

      raw_event_type = "NETWORK_CONNECTION"
      raw_entity_field = _swap_identifier_leaf(
          "principal.asset.hostname" if entity_type == EntityType.ASSET else "principal.user.userid", audit["target_field"])
      raw_event_filter = ""
      raw_breadth_field = "target.ip"

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
      rendered = rendered.replace("{{raw_breadth_field}}", raw_breadth_field)

      rendered = rendered.replace("{{min_threat_distance_sq}}", "16.0")
      rendered = rendered.replace("{{min_joint_odds}}", "2.5")
      rendered = rendered.replace("{{min_raw_hits}}", "3")
      rendered = rendered.replace("{{max_dormant_days}}", "2")
      rendered = rendered.replace("{{min_breadth_count}}", "3")
      rendered = _apply_byte_dispersion_floor(rendered, target_metric, byte_dispersion_floor=byte_dispersion_floor)

      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered

      return rendered + "\n"

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

      rendered = rendered.replace("{{personal_threshold}}", str(anomaly_threshold))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = rendered.replace("{{max_fleet_adopters}}", "3")
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
      rendered = raw.replace("{{anomaly_threshold}}", str(anomaly_threshold))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = rendered.replace("{{max_fleet_prevalence}}", "3")
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
      rendered = rendered.replace("{{anomaly_threshold}}", str(anomaly_threshold))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = rendered.replace("{{max_fleet_prevalence}}", "3")
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
      rendered = rendered.replace("{{anomaly_threshold}}", str(anomaly_threshold))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = rendered.replace("{{max_asset_age_days}}", "7.0")
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
      rendered = rendered.replace("{{extra_dimensions}}", "")
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
      rendered = rendered.replace("{{ecg_entity_type}}", '"DOMAIN_NAME"')
      rendered = rendered.replace("{{ecg_key_path}}", "entity.domain.name")
      rendered = rendered.replace("{{ecg_prevalence_path}}", "entity.domain.prevalence")
      rendered = rendered.replace("{{max_fleet_prevalence}}", "3")
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
          "{{sector_b_metric_func_avg}}",
          f"metrics.{m_b}(period: 1d, window: 30d, metric: {audit_b['metric_arg']}, agg: avg, {host_field}: {host_field}, {dest_field}: {dest_field})"
      )
      rendered = rendered.replace(
          "{{sector_b_metric_func_stddev}}",
          f"metrics.{m_b}(period: 1d, window: 30d, metric: {audit_b['metric_arg']}, agg: stddev, {host_field}: {host_field}, {dest_field}: {dest_field})"
      )
      rendered = rendered.replace("{{ecg_entity_type}}", '"DOMAIN_NAME"')
      rendered = rendered.replace("{{ecg_key_path}}", "entity.domain.name")
      rendered = rendered.replace("{{ecg_prevalence_path}}", "entity.domain.prevalence")
      rendered = rendered.replace("{{max_fleet_prevalence}}", "3")
      rendered = rendered.replace("{{today_date}}", _today_date())
      rendered = _apply_byte_dispersion_floor(rendered, m_a, floor_vars=("$a_floor",))
      rendered = _apply_byte_dispersion_floor(rendered, m_b, floor_vars=("$b_floor",))
      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

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
    ent_var = "$user" if entity_type == EntityType.USER else "$host"
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

  def build_c2_beacon_flow_query(
      self,
      target_metric: str = "network_flows_outbound",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      min_baseline_days: int = 7,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
  ) -> str:
    """Builds a 2-Stage C2 Beacon Flow Frequency & Regularity pipeline for network_flows_* metrics."""
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
      bytes_expr = "sum(network.sent_bytes)"
    elif target_metric == "network_flows_inbound":
      bytes_expr = "sum(network.received_bytes)"
    else:
      bytes_expr = "sum(network.sent_bytes) + sum(network.received_bytes)"
    goal_line = f"// Goal: {hypothesis_goal}\n" if hypothesis_goal else ""
    return (
        f"{goal_line}// Purpose: Hunt for C2 beaconing flow frequency surge and timing regularity in {target_metric}\n"
        "// ============================================================================\n"
        "// ARCHITECTURE: 2-STAGE C2 BEACON FLOW FREQUENCY & REGULARITY PIPELINE\n"
        "// ============================================================================\n\n"
        "stage stage1_flow_frequency {\n"
        f"    {filter_block}\n"
        f"    {ent_field} = {ent_var}\n"
        f"    {ent_var} != \"\"\n\n"
        "  match:\n"
        f"    {ent_var} by 1d\n\n"
        "  outcome:\n"
        "    $observed_flows = count(metadata.id)\n"
        f"    $observed_bytes = {bytes_expr}\n"
        "    $distinct_targets = count_distinct(target.ip)\n"
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
        "    $flow_cv = $hist_flow_stddev / if($hist_flow_avg > 0, $hist_flow_avg, 1.0)\n"
        "    $bytes_per_flow = $observed_bytes / ($observed_flows + 0.001)\n"
        "}\n\n"
        f"{ent_var} = $stage1_flow_frequency.{ent_name}\n\n"
        "match:\n"
        f"  {ent_var} by 1d\n\n"
        "outcome:\n"
        "  $flow_z = max($stage1_flow_frequency.flow_z)\n"
        "  $flow_cv = min($stage1_flow_frequency.flow_cv)\n"
        "  $observed_flows = max($stage1_flow_frequency.observed_flows)\n"
        "  $historical_flow_avg = max($stage1_flow_frequency.hist_flow_avg)\n"
        "  $active_days = max($stage1_flow_frequency.hist_flow_active_days)\n"
        "  $bytes_per_flow = min($stage1_flow_frequency.bytes_per_flow)\n"
        "  $distinct_targets = max($stage1_flow_frequency.distinct_targets)\n"
        "  $beacon_score = $flow_z * (1.0 / ($flow_cv + 0.1))\n\n"
        "condition:\n"
        f"  $flow_z >= {anomaly_threshold}\n"
        f"  and $active_days >= {audit['min_baseline_days']}\n\n"
        "order:\n"
        "  $beacon_score desc\n"
    )

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
  ) -> str:
    """Builds a verified Dual-Plane Hybrid Entropy & Concentration pipeline (Diversity Deficit & Elephant Flow)."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
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
  ) -> str:
    """Builds a verified Dual-Plane Hybrid Fleet Prevalence Normalization pipeline (Patch Tuesday Shield)."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_FLEET_PREVALENCE_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
    )

  def build_hybrid_derived_file_prevalence_query(
      self,
      target_metric: str = "file_executions_total",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
  ) -> str:
    """Builds a verified 2-Stage Derived Context File Prevalence pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
    )

  def build_hybrid_derived_domain_prevalence_query(
      self,
      target_metric: str = "http_queries_total",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
      identifier_coverage_payload: Optional[Any] = None,
  ) -> str:
    """Builds a verified 2-Stage Derived Context Domain Prevalence pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
        identifier_field=identifier_field,
        identifier_coverage_payload=identifier_coverage_payload,
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
  ) -> str:
    """Builds a verified 2-Stage Derived Context Infant Asset Age pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
        identifier_field=identifier_field,
        identifier_coverage_payload=identifier_coverage_payload,
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
  ) -> str:
    """Builds a verified 3-Stage Rare Destination ECG Filter pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.RARE_DESTINATION_ECG_3STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
        identifier_field=identifier_field,
        identifier_coverage_payload=identifier_coverage_payload,
    )

  def build_fusion_rare_destination_query(
      self,
      target_metrics: Optional[List[str]] = None,
      entity_type: EntityType = EntityType.ASSET,
      fusion_threshold_sq: float = 12.25,
      hypothesis_goal: Optional[str] = None,
      identifier_field: Optional[str] = None,
      identifier_coverage_payload: Optional[Any] = None,
  ) -> str:
    """Builds a verified 3-Stage Sector Fusion + Rare Destination ECG Filter pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.FUSION_RARE_DESTINATION_3STAGE,
        target_metrics=target_metrics,
        entity_type=entity_type,
        fusion_threshold_sq=fusion_threshold_sq,
        hypothesis_goal=hypothesis_goal,
        identifier_field=identifier_field,
        identifier_coverage_payload=identifier_coverage_payload,
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
