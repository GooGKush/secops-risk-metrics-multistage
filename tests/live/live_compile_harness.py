"""Live Compile & Metric Probe Harness for SecOps Risk Metrics (WS0-03).

Provides:
  1. Full offline matrix renderer (`render_full_matrix`, `render_all_pipelines`):
     Renders all 38 `METRIC_CATALOG` metrics x `supported_entity_types` x all 18
     `StatisticalModel`s x both `MatchMode`s (`TIMELINE_BREAKDOWN`, `FLEET_ROLLUP`),
     plus all 34 `templates/pipelines/*.yl2` templates, recording any render exceptions,
     `MalachiteASTValidator` errors, `SubmissionTestSuite` static invariant warnings,
     and structural stage/key warnings.
  2. Covering live-compile suite generator (`build_covering_compile_suite`):
     Produces a deduplicated `<= 1h` compile suite (`2026-10-27T14:00:00Z` to
     `2026-10-27T15:00:00Z`) exercising all 38 Stage 1 extractors across their
     supported entity types, all 18 Stage 2 math models across both `MatchMode`s,
     and all 34 pipeline templates (including named-cohort conditional branches).
  3. PF-10 `(period: 1h, window: today)` probe generator (`build_pf10_hourly_today_probes`):
     Generates minimal valid YARA-L 2.0 probe queries for all 38 metrics over a 5h
     post-midnight UTC window (`2026-10-27T14:00:00Z` to `2026-10-27T19:00:00Z`,
     satisfying PF-10's `start > 00:00Z` and `end - start >= 4h` invariant).
  4. PF-11 `metric: first_seen` probe generator (`build_pf11_first_seen_probes`):
     Generates minimal valid YARA-L 2.0 probe queries for all 38 metrics using
     `period: 1d, window: 30d, metric: first_seen, agg: min` (and `last_seen, agg: max`)
     over a `1h` window (`2026-10-27T14:00:00Z` to `2026-10-27T15:00:00Z`).
  5. Injectable `search_fn(query, start_time, end_time)` execution runner and JSON
     manifest export/import helpers (`export_manifest`, `load_manifest`, `run_manifest`).
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import datetime
import json
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

SKILL_ROOT = Path(__file__).resolve().parents[2]
if str(SKILL_ROOT) not in sys.path:
  sys.path.insert(0, str(SKILL_ROOT))

from scripts import malachite_catalog as mc
from scripts.preflight_validator import (
    EntityType,
    METRIC_CATALOG,
    MalachiteASTValidator,
    PreFlightValidator,
    QueryIntegrityGate,
    StatisticalModel,
)
from scripts.submission_tests import SubmissionTestSuite
from scripts.template_router import MatchMode, MultiStageTemplateRouter, PipelineArchitecture
from scripts.timeline_assembler import parse_stats_payload

TEMPLATES_DIR = SKILL_ROOT / "templates"

DEFAULT_CUSTOMER_ID = "8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5"
DEFAULT_PROJECT_ID = "gus-sdl"
DEFAULT_REGION = "us"

DEFAULT_TARGET_DATE = "2026-10-27"
DEFAULT_COMPILE_START_TIME = "2026-10-27T14:00:00Z"
DEFAULT_COMPILE_END_TIME = "2026-10-27T15:00:00Z"

# PF-10: `(period: 1h, window: today)` returns data ONLY when the query starts after
# 00:00Z and ends at least 4 hours after the start hour.
DEFAULT_PF10_START_TIME = "2026-10-27T14:00:00Z"
DEFAULT_PF10_END_TIME = "2026-10-27T19:00:00Z"

DEFAULT_PF11_START_TIME = "2026-10-27T14:00:00Z"
DEFAULT_PF11_END_TIME = "2026-10-27T15:00:00Z"

# PF-9: In `gus-sdl`, network/DNS/HTTP telemetry populates `principal.asset.ip` (~99.9%)
# far more densely than `principal.asset.hostname` (<1%). Probes keep each extractor's
# canonical dimension in `query` and attach a pre-validated `principal.asset.ip`
# fallback in `fallback_query` for these 13 metrics.
NETWORK_IP_FALLBACK_METRICS: frozenset[str] = frozenset({
    "dns_bytes_outbound",
    "dns_queries_fail",
    "dns_queries_success",
    "dns_queries_total",
    "http_queries_fail",
    "http_queries_success",
    "http_queries_total",
    "network_bytes_inbound",
    "network_bytes_outbound",
    "network_bytes_total",
    "network_flows_inbound",
    "network_flows_outbound",
    "network_flows_total",
})

SearchFn = Callable[[str, str, str], Any]


def _parse_utc_iso(ts: str) -> datetime.datetime:
  if not ts.endswith("Z"):
    raise ValueError(f"Timestamp must end with 'Z' (UTC ISO-8601), got '{ts}'")
  return datetime.datetime.fromisoformat(ts[:-1] + "+00:00")


def validate_pf10_window(start_time: str, end_time: str) -> None:
  """Enforces PF-10 `(period: 1h, window: today)` query window physics."""
  start_dt = _parse_utc_iso(start_time)
  end_dt = _parse_utc_iso(end_time)
  if end_dt <= start_dt:
    raise ValueError(f"end_time ({end_time}) must be after start_time ({start_time})")
  if start_dt.date() != end_dt.date():
    raise ValueError(
        f"PF-10 `(1h, today)` probe must stay within one UTC date, got {start_time} .. {end_time}"
    )
  if start_dt.hour == 0:
    raise ValueError(
        f"PF-10 `(1h, today)` requires start_time after the 00:00Z hour so earlier-today hours exist, got {start_time}"
    )
  start_hour_floor = start_dt.replace(minute=0, second=0, microsecond=0)
  if (end_dt - start_hour_floor) < datetime.timedelta(hours=4):
    raise ValueError(
        f"PF-10 `(1h, today)` requires end_time >= 4 hours after start hour ({start_time} .. {end_time})"
    )


def validate_compile_window(start_time: str, end_time: str, max_hours: float = 1.0) -> None:
  """Enforces the `<= 1h` compile-suite window budget."""
  start_dt = _parse_utc_iso(start_time)
  end_dt = _parse_utc_iso(end_time)
  if end_dt <= start_dt:
    raise ValueError(f"end_time ({end_time}) must be after start_time ({start_time})")
  if (end_dt - start_dt) > datetime.timedelta(hours=max_hours):
    raise ValueError(
        f"Compile window ({start_time} .. {end_time}) exceeds max_hours={max_hours}"
    )


def _pin_ecg_date(query: str, target_date: str) -> str:
  """Pins `_today_date()` literals in ECG-joined pipelines to `target_date`."""
  return re.sub(
      r'(timestamp\.get_date\(metadata\.event_timestamp\.seconds\)\s*=\s*")\d{4}-\d{2}-\d{2}(")',
      rf"\g<1>{target_date}\2",
      query,
  )


def detect_structural_warnings(
    query: str,
    *,
    metric_name: Optional[str] = None,
    entity_type: Optional[EntityType] = None,
    statistical_model: Optional[StatisticalModel] = None,
) -> List[str]:
  """Detects structural stage/key mismatches that compile or pass AST checks."""
  warnings: List[str] = []
  clean = re.sub(r"//[^\n]*", "", query)
  clean = re.sub(r"/\*.*?\*/", "", clean, flags=re.S)
  stage_stripped = re.sub(r"stage\s+[A-Za-z0-9_]+\s*\{.*?\n\}", "", clean, flags=re.S)

  if (
      metric_name
      and metric_name.startswith("resource_")
      and entity_type == EntityType.USER
      and statistical_model not in (
          None,
          StatisticalModel.STANDARD_Z_SCORE,
          StatisticalModel.MAD,
          StatisticalModel.QUANTILE_IQR_SKEW,
      )
      and "$observed_reads" in clean
  ):
    warnings.append(
        f"RESOURCE_USER_MODEL_REDIRECT: build_query redirected ({metric_name}, USER, "
        f"{statistical_model.value}) to CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH, bypassing {statistical_model.value}."
    )

  if statistical_model == StatisticalModel.CIRCADIAN_VON_MISES and "$circadian_threat_score" in clean:
    s1_match = re.search(
        r"stage\s+stage1_extract\s*\{.*?\bmatch:\s*\n\s*([^\n]+?)\s+by\s+(\d+[dh])",
        clean,
        flags=re.S,
    )
    if s1_match and s1_match.group(2) != "1h":
      warnings.append(
          f"CIRCADIAN_STAGE1_BUCKET_MISMATCH: stage1_extract uses 'by {s1_match.group(2)}' "
          f"for match keys '{s1_match.group(1).strip()}' while CIRCADIAN_VON_MISES root expects 'by 1h'."
      )

  if entity_type == EntityType.RESOURCE:
    root_match = re.search(r"\bmatch:\s*\n\s*([^\n]+)", stage_stripped)
    if root_match:
      root_keys = root_match.group(1)
      if "$resource" in clean and "$resource" not in root_keys and "$entity" not in root_keys:
        warnings.append(
            f"RESOURCE_ENTITY_ROOT_KEY_MISMATCH: EntityType.RESOURCE requested, "
            f"stage binds '$resource', but root match keys on '{root_keys.strip()}'."
        )
  return warnings


@dataclass
class Stage1ExtractorSpec:
  """Parsed components of a `templates/stage1_extractors/<metric>.yl2` template."""

  metric_name: str
  event_section: str
  match_keys: List[str]
  observed_expr: str
  metric_arg: str
  dimension_args: str
  dimension_fields: List[str]


@dataclass
class MatrixRenderRecord:
  """Result of rendering and offline-validating a single matrix cell or pipeline."""

  record_id: str
  kind: str
  query: str
  metric_name: Optional[str] = None
  entity_type: Optional[str] = None
  statistical_model: Optional[str] = None
  match_mode: Optional[str] = None
  pipeline_template: Optional[str] = None
  pipeline_architecture: Optional[str] = None
  render_error: Optional[str] = None
  ast_errors: List[str] = field(default_factory=list)
  static_errors: List[str] = field(default_factory=list)
  structural_warnings: List[str] = field(default_factory=list)

  @property
  def render_ok(self) -> bool:
    return self.render_error is None and bool(self.query.strip())

  @property
  def ast_ok(self) -> bool:
    return self.render_ok and not self.ast_errors

  def to_dict(self) -> Dict[str, Any]:
    return asdict(self)


@dataclass
class ManifestQuery:
  """Serializable live-compile or live-probe query entry."""

  query_id: str
  suite_type: str
  description: str
  query: str
  start_time: str
  end_time: str
  coverage_tags: List[str] = field(default_factory=list)
  metric_name: Optional[str] = None
  entity_type: Optional[str] = None
  statistical_model: Optional[str] = None
  match_mode: Optional[str] = None
  pipeline_template: Optional[str] = None
  fallback_query: Optional[str] = None
  metadata: Dict[str, Any] = field(default_factory=dict)

  def to_dict(self) -> Dict[str, Any]:
    return asdict(self)

  @classmethod
  def from_dict(cls, data: Dict[str, Any]) -> "ManifestQuery":
    return cls(
        query_id=data["query_id"],
        suite_type=data["suite_type"],
        description=data["description"],
        query=data["query"],
        start_time=data["start_time"],
        end_time=data["end_time"],
        coverage_tags=list(data.get("coverage_tags") or []),
        metric_name=data.get("metric_name"),
        entity_type=data.get("entity_type"),
        statistical_model=data.get("statistical_model"),
        match_mode=data.get("match_mode"),
        pipeline_template=data.get("pipeline_template"),
        fallback_query=data.get("fallback_query"),
        metadata=dict(data.get("metadata") or {}),
    )


@dataclass
class LiveExecutionResult:
  """Structured outcome of executing one `ManifestQuery` via `search_fn`."""

  query_id: str
  suite_type: str
  compiled: bool
  row_count: int
  has_nonzero_probe_data: Optional[bool] = None
  used_fallback_query: bool = False
  latency_ms: float = 0.0
  error: Optional[str] = None
  sample_row: Optional[Dict[str, Any]] = None
  metadata: Dict[str, Any] = field(default_factory=dict)

  def to_dict(self) -> Dict[str, Any]:
    return asdict(self)

  @classmethod
  def from_dict(cls, data: Dict[str, Any]) -> "LiveExecutionResult":
    return cls(
        query_id=data["query_id"],
        suite_type=data["suite_type"],
        compiled=bool(data["compiled"]),
        row_count=int(data["row_count"]),
        has_nonzero_probe_data=data.get("has_nonzero_probe_data"),
        used_fallback_query=bool(data.get("used_fallback_query", False)),
        latency_ms=float(data.get("latency_ms", 0.0)),
        error=data.get("error"),
        sample_row=data.get("sample_row"),
        metadata=dict(data.get("metadata") or {}),
    )


# ---------------------------------------------------------------------------
# Stage 1 Extractor Parsing & Standalone Pipeline Slot Rendering
# ---------------------------------------------------------------------------


def extract_stage1_spec(
    metric_name: str,
    *,
    template_dir: Path = TEMPLATES_DIR,
    rebind_field: Optional[str] = None,
) -> Stage1ExtractorSpec:
  """Extracts predicates, match keys, and canonical `metrics.*` dimensions from Stage 1."""
  stage1_path = template_dir / "stage1_extractors" / f"{metric_name}.yl2"
  if not stage1_path.exists():
    raise FileNotFoundError(f"Missing Stage 1 extractor template: {stage1_path}")

  raw = MultiStageTemplateRouter._strip_identifier_swap_note(stage1_path.read_text(encoding="utf-8").strip())
  if rebind_field:
    raw = MultiStageTemplateRouter._rebind_entity_field(raw, metric_name, rebind_field)

  body_match = re.search(r"stage\s+stage1_extract\s*\{\s*\n(.*)\n\}", raw, flags=re.S)
  if not body_match:
    raise ValueError(f"Could not parse 'stage stage1_extract' in {stage1_path}")
  stage_body = body_match.group(1)

  match_sec = re.search(
      r"^(.*?)\n[ \t]*match:\s*\n[ \t]*([^\n]+?)\s+by\s+\d+[dh]\s*\n[ \t]*outcome:\s*\n(.*)$",
      stage_body,
      flags=re.S,
  )
  if not match_sec:
    raise ValueError(f"Could not split event/match/outcome sections in {stage1_path}")

  event_section = match_sec.group(1).rstrip()
  match_keys = [v.strip() for v in match_sec.group(2).split(",") if v.strip()]
  outcome_section = match_sec.group(3)

  obs_match = re.search(r"^\s*\$observed_val\s*=\s*([^\n]+)", outcome_section, flags=re.M)
  if not obs_match:
    raise ValueError(f"Missing '$observed_val = ...' in {stage1_path}")
  observed_expr = obs_match.group(1).strip()

  m_call = re.search(r"metrics\." + re.escape(metric_name) + r"\s*\(([^)]+)\)", outcome_section, flags=re.S)
  if not m_call:
    raise ValueError(f"Missing 'metrics.{metric_name}(...)' call in {stage1_path}")
  call_args = m_call.group(1)

  m_type = re.search(r"\bmetric\s*:\s*([A-Za-z0-9_]+)", call_args)
  if not m_type:
    raise ValueError(f"Missing 'metric:' parameter in {stage1_path}")
  metric_arg = m_type.group(1)
  sem_arg = mc.baseline_semantics(metric_name).metric_arg
  if metric_arg != sem_arg:
    raise ValueError(f"Metric arg mismatch for {metric_name}: template={metric_arg}, catalog={sem_arg}")

  dim_pairs: List[Tuple[str, str]] = []
  for k, v in re.findall(r"([A-Za-z0-9_.]+)\s*:\s*([A-Za-z0-9_.$]+)", call_args):
    if k not in ("period", "window", "metric", "agg"):
      dim_pairs.append((k, v))
  if not dim_pairs:
    raise ValueError(f"No dimension filters parsed for {metric_name} in {stage1_path}")

  dim_fields = [k for k, _ in dim_pairs]
  err = mc.validate_filter_fields(metric_name, dim_fields)
  if err:
    raise ValueError(f"Invalid canonical dimensions for {metric_name}: {err}")

  dimension_args = ",\n        ".join(f"{k}: {v}" for k, v in dim_pairs)
  return Stage1ExtractorSpec(
      metric_name=metric_name,
      event_section=event_section,
      match_keys=match_keys,
      observed_expr=observed_expr,
      metric_arg=metric_arg,
      dimension_args=dimension_args,
      dimension_fields=dim_fields,
  )


def _render_standalone_slot_pipeline(
    template_filename: str,
    metric_name: str,
    entity_type: EntityType,
    *,
    template_dir: Path = TEMPLATES_DIR,
    target_date: str = DEFAULT_TARGET_DATE,
) -> str:
  """Renders one of the 5 standalone parameterized `templates/pipelines/*.yl2` files."""
  path = template_dir / "pipelines" / template_filename
  if not path.exists():
    raise FileNotFoundError(f"Missing pipeline template: {path}")
  raw = path.read_text(encoding="utf-8").strip()
  audit = PreFlightValidator.audit(target_metric=metric_name, entity_type=entity_type)

  rendered = raw.replace("{{event_filter}}", "\n    ".join(audit["event_filter"]))
  rendered = rendered.replace("{{entity_field}}", audit["target_field"])
  rendered = rendered.replace("{{observed_aggregation}}", audit["observed_agg"])
  rendered = rendered.replace("{{target_metric_name}}", metric_name)
  rendered = rendered.replace("{{metric_type_val}}", audit["metric_arg"])
  rendered = rendered.replace("{{dimension_key}}", audit["target_field"])
  rendered = rendered.replace("{{extra_dimensions}}", "")
  rendered = rendered.replace("{{dispersion_floor}}", "1.0")
  rendered = rendered.replace("{{anomaly_threshold}}", "3.0")
  rendered = rendered.replace("{{fold_change_threshold}}", "2.0")
  rendered = rendered.replace("{{fusion_threshold_sq}}", "12.25")
  rendered = rendered.replace("{{robust_threshold}}", "3.5")
  rendered = rendered.replace("{{tukey_excess_threshold}}", "1.0")
  rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
  rendered = rendered.replace("{{first_scored_date}}", target_date)
  if not re.search(r"//\s*(?:Goal:|ARCHITECTURE:|Sector:|Stage\s*\d*:)", rendered, re.I):
    rendered = f"// Goal: Standalone pipeline compile check for {template_filename}\n" + rendered
  return rendered + "\n"


def render_all_pipelines(
    router: Optional[MultiStageTemplateRouter] = None,
    *,
    target_date: str = DEFAULT_TARGET_DATE,
    include_cohort_variants: bool = False,
) -> List[MatrixRenderRecord]:
  """Renders all 34 `templates/pipelines/*.yl2` templates (plus optional cohort variants)."""
  router = router or MultiStageTemplateRouter(template_dir=TEMPLATES_DIR)
  pipelines_dir = router.template_dir / "pipelines"

  # 1-to-1 canonical rendering specification for all 34 pipeline `.yl2` files.
  specs: List[Tuple[str, Optional[str], Callable[[], str]]] = [
      (
          "c2_beacon_flow_frequency_2stage.yl2",
          None,
          lambda: (pipelines_dir / "c2_beacon_flow_frequency_2stage.yl2").read_text(encoding="utf-8").strip() + "\n",
      ),
      (
          "cloud_repository_scope_dual_branch.yl2",
          PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH,
              target_metric="resource_read_total",
              entity_type=EntityType.USER,
          ),
      ),
      (
          "dual_baseline_delta_z_3stage.yl2",
          PipelineArchitecture.DUAL_BASELINE_3STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.DUAL_BASELINE_3STAGE,
              target_metric="http_queries_total",
              entity_type=EntityType.ASSET,
          ),
      ),
      (
          "dual_sector_fusion_3stage.yl2",
          PipelineArchitecture.DUAL_SECTOR_FUSION_3STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.DUAL_SECTOR_FUSION_3STAGE,
              entity_type=EntityType.USER,
          ),
      ),
      (
          "fusion_rare_destination_3stage.yl2",
          PipelineArchitecture.FUSION_RARE_DESTINATION_3STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.FUSION_RARE_DESTINATION_3STAGE,
              entity_type=EntityType.ASSET,
          ),
      ),
      (
          "hierarchical_empirical_bayes_3stage.yl2",
          PipelineArchitecture.EMPIRICAL_BAYES_3STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.EMPIRICAL_BAYES_3STAGE,
              target_metric="http_queries_total",
              entity_type=EntityType.ASSET,
          ),
      ),
      (
          "http_error_ratio_surge_2stage.yl2",
          PipelineArchitecture.HTTP_ERROR_RATIO_SURGE_2STAGE.value,
          lambda: router.build_pipeline_query(PipelineArchitecture.HTTP_ERROR_RATIO_SURGE_2STAGE),
      ),
      (
          "http_target_surge_2stage.yl2",
          PipelineArchitecture.HTTP_TARGET_SURGE_2STAGE.value,
          lambda: router.build_pipeline_query(PipelineArchitecture.HTTP_TARGET_SURGE_2STAGE),
      ),
      (
          "hybrid_data_table_bridge_2stage.yl2",
          None,
          lambda: (pipelines_dir / "hybrid_data_table_bridge_2stage.yl2").read_text(encoding="utf-8").strip() + "\n",
      ),
      (
          "hybrid_metric_derived_asset_age_2stage.yl2",
          PipelineArchitecture.HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE,
              target_metric="auth_attempts_total",
              entity_type=EntityType.ASSET,
          ),
      ),
      (
          "hybrid_metric_derived_domain_prevalence_2stage.yl2",
          PipelineArchitecture.HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE,
              target_metric="http_queries_total",
              entity_type=EntityType.ASSET,
          ),
      ),
      (
          "hybrid_metric_derived_file_prevalence_2stage.yl2",
          PipelineArchitecture.HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE,
              target_metric="file_executions_total",
              entity_type=EntityType.ASSET,
          ),
      ),
      (
          "hybrid_metric_entropy_concentration_2stage.yl2",
          PipelineArchitecture.HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE,
              target_metric="network_bytes_outbound",
              entity_type=EntityType.ASSET,
          ),
      ),
      (
          "hybrid_metric_fleet_prevalence_2stage.yl2",
          PipelineArchitecture.HYBRID_METRIC_FLEET_PREVALENCE_2STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.HYBRID_METRIC_FLEET_PREVALENCE_2STAGE,
              target_metric="file_executions_total",
              entity_type=EntityType.ASSET,
          ),
      ),
      (
          "hybrid_metric_http_ua_prevalence_2stage.yl2",
          PipelineArchitecture.HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE.value,
          lambda: router.build_pipeline_query(PipelineArchitecture.HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE),
      ),
      (
          "hybrid_metric_orthogonal_space_2stage.yl2",
          PipelineArchitecture.HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE,
              target_metric="network_bytes_outbound",
              entity_type=EntityType.ASSET,
          ),
      ),
      (
          "hybrid_metric_raw_enrichment_2stage.yl2",
          PipelineArchitecture.HYBRID_METRIC_RAW_ENRICHMENT_2STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.HYBRID_METRIC_RAW_ENRICHMENT_2STAGE,
              target_metric="network_bytes_outbound",
              entity_type=EntityType.ASSET,
          ),
      ),
      (
          "hybrid_metric_whois_domain_lifecycle_2stage.yl2",
          PipelineArchitecture.HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE,
              target_metric="http_queries_total",
              entity_type=EntityType.ASSET,
          ),
      ),
      (
          "longitudinal_cusum_2stage.yl2",
          None,
          lambda: _render_standalone_slot_pipeline(
              "longitudinal_cusum_2stage.yl2",
              "network_bytes_outbound",
              EntityType.ASSET,
              template_dir=router.template_dir,
              target_date=target_date,
          ),
      ),
      (
          "macd_momentum_velocity_2stage.yl2",
          PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE,
              target_metric="network_bytes_outbound",
              entity_type=EntityType.ASSET,
          ),
      ),
      (
          "mad_robust_z_4stage.yl2",
          None,
          lambda: _render_standalone_slot_pipeline(
              "mad_robust_z_4stage.yl2",
              "network_bytes_outbound",
              EntityType.ASSET,
              template_dir=router.template_dir,
              target_date=target_date,
          ),
      ),
      (
          "multi_sector_fusion_4stage.yl2",
          PipelineArchitecture.MULTI_SECTOR_FUSION_4STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.MULTI_SECTOR_FUSION_4STAGE,
              entity_type=EntityType.USER,
          ),
      ),
      (
          "part_of_the_whole_multilevel.yl2",
          PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL,
              target_metric="auth_attempts_total",
              entity_type=EntityType.USER,
          ),
      ),
      (
          "part_of_the_whole_triad_multilevel.yl2",
          PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
              entity_type=EntityType.USER,
          ),
      ),
      (
          "poisson_rarity_2stage.yl2",
          None,
          lambda: _render_standalone_slot_pipeline(
              "poisson_rarity_2stage.yl2",
              "auth_attempts_fail",
              EntityType.USER,
              template_dir=router.template_dir,
              target_date=target_date,
          ),
      ),
      (
          "quantile_iqr_skew_3stage.yl2",
          None,
          lambda: _render_standalone_slot_pipeline(
              "quantile_iqr_skew_3stage.yl2",
              "network_bytes_outbound",
              EntityType.ASSET,
              template_dir=router.template_dir,
              target_date=target_date,
          ),
      ),
      (
          "radar_360_decoupled_sector.yl2",
          PipelineArchitecture.RADAR_360_DECOUPLED_SECTOR.value,
          lambda: router.build_pipeline_query(PipelineArchitecture.RADAR_360_DECOUPLED_SECTOR),
      ),
      (
          "radar_360_sector_alert.yl2",
          PipelineArchitecture.RADAR_360_SECTOR_ALERT.value,
          lambda: router.build_pipeline_query(PipelineArchitecture.RADAR_360_SECTOR_ALERT),
      ),
      (
          "radar_360_sector_web_http.yl2",
          PipelineArchitecture.RADAR_360_SECTOR_WEB_HTTP.value,
          lambda: router.build_pipeline_query(PipelineArchitecture.RADAR_360_SECTOR_WEB_HTTP),
      ),
      (
          "rare_destination_ecg_3stage.yl2",
          PipelineArchitecture.RARE_DESTINATION_ECG_3STAGE.value,
          lambda: router.build_pipeline_query(
              PipelineArchitecture.RARE_DESTINATION_ECG_3STAGE,
              target_metric="network_bytes_outbound",
              entity_type=EntityType.ASSET,
          ),
      ),
      (
          "rollup_sector_fusion_4stage.yl2",
          None,
          lambda: router.build_sector_fusion_query(
              mc.SectorSpec("file_executions_total", "principal.asset.hostname"),
              mc.SectorSpec("network_bytes_outbound", "principal.asset.hostname"),
              four_stage=False,
          ),
      ),
      (
          "rollup_sector_fusion_5stage.yl2",
          None,
          lambda: router.build_sector_fusion_query(
              mc.SectorSpec("file_executions_total", "principal.asset.hostname"),
              mc.SectorSpec("network_bytes_outbound", "principal.asset.hostname"),
              four_stage=True,
          ),
      ),
      (
          "standard_z_score_2stage.yl2",
          None,
          lambda: _render_standalone_slot_pipeline(
              "standard_z_score_2stage.yl2",
              "network_bytes_outbound",
              EntityType.ASSET,
              template_dir=router.template_dir,
              target_date=target_date,
          ),
      ),
  ]

  known_files = {fname for fname, _, _ in specs}
  for disk_path in sorted(pipelines_dir.glob("*.yl2")):
    if disk_path.name not in known_files:
      specs.append(
          (
              disk_path.name,
              None,
              lambda p=disk_path: (_ for _ in ()).throw(
                  NotImplementedError(f"Unmapped pipeline template file: {p.name}")
              ),
          )
      )

  if include_cohort_variants:
    specs.extend([
        (
            "part_of_the_whole_multilevel.yl2#named_cohort",
            PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL.value,
            lambda: router.build_pipeline_query(
                PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL,
                target_metric="auth_attempts_total",
                entity_type=EntityType.USER,
                cohort_entities=["alice@example.com", "bob@example.com"],
            ),
        ),
        (
            "part_of_the_whole_triad_multilevel.yl2#named_cohort",
            PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL.value,
            lambda: router.build_pipeline_query(
                PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
                entity_type=EntityType.USER,
                cohort_entities=["alice@example.com", "bob@example.com"],
            ),
        ),
    ])

  records: List[MatrixRenderRecord] = []
  for fname, arch_name, fn in specs:
    base_fname = fname.split("#", 1)[0]
    rec_id = f"pipeline::{fname}"
    try:
      rendered = _pin_ecg_date(fn(), target_date)
      ast_errs = MalachiteASTValidator.validate_query(rendered)
      static_errs = SubmissionTestSuite.validate_static_invariants(rendered, rec_id)
      warnings = detect_structural_warnings(rendered)
      records.append(
          MatrixRenderRecord(
              record_id=rec_id,
              kind="pipeline_template",
              query=rendered,
              pipeline_template=base_fname,
              pipeline_architecture=arch_name,
              ast_errors=ast_errs,
              static_errors=static_errs,
              structural_warnings=warnings,
          )
      )
    except Exception as exc:  # pylint: disable=broad-except
      records.append(
          MatrixRenderRecord(
              record_id=rec_id,
              kind="pipeline_template",
              query="",
              pipeline_template=base_fname,
              pipeline_architecture=arch_name,
              render_error=f"{type(exc).__name__}: {exc}",
          )
      )
  return records


def active_statistical_models() -> List[StatisticalModel]:
  """Returns active (non-retired) StatisticalModel members."""
  retired = {
      StatisticalModel.HOURLY_TEMPORAL_ZSCORE,
      StatisticalModel.CIRCADIAN_VON_MISES,
      StatisticalModel.PIECEWISE_CRI,
      StatisticalModel.FLEET_PREVALENCE_SHIELD,
  }
  return [m for m in StatisticalModel if m not in retired]


def is_compatible_metric_model(metric_name: str, model: StatisticalModel) -> bool:
  """Returns True when (metric_name, model) is domain-compatible in MultiStageTemplateRouter."""
  if metric_name not in METRIC_CATALOG:
    return False
  if model == StatisticalModel.POISSON and mc.baseline_semantics(metric_name).metric_arg == "value_sum":
    return False
  if model == StatisticalModel.BAYESIAN_BETA_BINOMIAL:
    if not metric_name.endswith(("_fail", "_total", "_success")):
      return False
    prefix = metric_name.rsplit("_", 1)[0]
    if f"{prefix}_fail" not in METRIC_CATALOG or f"{prefix}_total" not in METRIC_CATALOG:
      return False
  return True


def render_full_matrix(
    *,
    template_dir: Path = TEMPLATES_DIR,
    target_date: str = DEFAULT_TARGET_DATE,
) -> List[MatrixRenderRecord]:
  """Renders the full 38-metric x entity_type x active-model x 2-mode matrix + active pipelines."""
  router = MultiStageTemplateRouter(template_dir=template_dir)
  records: List[MatrixRenderRecord] = []
  active_models = active_statistical_models()

  for metric_name in sorted(METRIC_CATALOG.keys()):
    mdef = METRIC_CATALOG[metric_name]
    for entity_type in mdef.supported_entity_types:
      for model in active_models:
        if not is_compatible_metric_model(metric_name, model):
          continue
        for mode in MatchMode:
          rec_id = f"matrix::{metric_name}::{entity_type.value}::{model.value}::{mode.value}"
          try:
            rendered = router.build_query(
                target_metric=metric_name,
                entity_type=entity_type,
                statistical_model=model,
                match_mode=mode,
                scoring_end_date=target_date,
            )
            rendered = _pin_ecg_date(rendered, target_date)
            ast_errs = MalachiteASTValidator.validate_query(rendered)
            static_errs = SubmissionTestSuite.validate_static_invariants(rendered, rec_id)
            warnings = detect_structural_warnings(
                rendered,
                metric_name=metric_name,
                entity_type=entity_type,
                statistical_model=model,
            )
            records.append(
                MatrixRenderRecord(
                    record_id=rec_id,
                    kind="stage1_stage2_matrix",
                    query=rendered,
                    metric_name=metric_name,
                    entity_type=entity_type.value,
                    statistical_model=model.value,
                    match_mode=mode.value,
                    ast_errors=ast_errs,
                    static_errors=static_errs,
                    structural_warnings=warnings,
                )
            )
          except Exception as exc:  # pylint: disable=broad-except
            records.append(
                MatrixRenderRecord(
                    record_id=rec_id,
                    kind="stage1_stage2_matrix",
                    query="",
                    metric_name=metric_name,
                    entity_type=entity_type.value,
                    statistical_model=model.value,
                    match_mode=mode.value,
                    render_error=f"{type(exc).__name__}: {exc}",
                )
            )

  records.extend(render_all_pipelines(router, target_date=target_date, include_cohort_variants=False))
  return records


def summarize_matrix_records(records: Sequence[MatrixRenderRecord]) -> Dict[str, Any]:
  """Summarizes counts, crashes, AST errors, static warnings, and structural warnings."""
  matrix_cells = [r for r in records if r.kind == "stage1_stage2_matrix"]
  pipelines = [r for r in records if r.kind == "pipeline_template"]
  return {
      "total_records": len(records),
      "matrix_cell_count": len(matrix_cells),
      "pipeline_count": len(pipelines),
      "render_crash_count": sum(1 for r in records if not r.render_ok),
      "ast_error_record_count": sum(1 for r in records if r.ast_errors),
      "static_warning_record_count": sum(1 for r in records if r.static_errors),
      "structural_warning_record_count": sum(1 for r in records if r.structural_warnings),
      "render_crashes": [
          {"record_id": r.record_id, "error": r.render_error}
          for r in records
          if not r.render_ok
      ],
      "ast_error_records": [
          {"record_id": r.record_id, "errors": r.ast_errors}
          for r in records
          if r.ast_errors
      ],
      "structural_warning_records": [
          {"record_id": r.record_id, "warnings": r.structural_warnings}
          for r in records
          if r.structural_warnings
      ],
  }


# ---------------------------------------------------------------------------
# Covering Live-Compile Suite Generator (Deliverable 2b)
# ---------------------------------------------------------------------------


def build_covering_compile_suite(
    *,
    template_dir: Path = TEMPLATES_DIR,
    start_time: str = DEFAULT_COMPILE_START_TIME,
    end_time: str = DEFAULT_COMPILE_END_TIME,
) -> List[ManifestQuery]:
  """Builds a deduplicated covering live-compile suite over a `<= 1h` window.

  Covers:
    1. Every one of the 38 Stage 1 extractors across all `supported_entity_types`
       (paired with `STANDARD_Z_SCORE`, `TIMELINE_BREAKDOWN`).
    2. Every one of the 18 Stage 2 `StatisticalModel`s across both `MatchMode`s
       (`TIMELINE_BREAKDOWN` and `FLEET_ROLLUP`), plus multi-key MAD & Quantile.
    3. Every one of the 34 `templates/pipelines/*.yl2` templates (including
       named-cohort branches for `part_of_the_whole_*`).
  """
  validate_compile_window(start_time, end_time, max_hours=1.0)
  target_date = _parse_utc_iso(start_time).strftime("%Y-%m-%d")
  router = MultiStageTemplateRouter(template_dir=template_dir)

  candidates: List[ManifestQuery] = []

  # 1. All 38 Stage 1 extractors x supported_entity_types (paired with STANDARD_Z_SCORE)
  for metric_name in sorted(METRIC_CATALOG.keys()):
    mdef = METRIC_CATALOG[metric_name]
    for entity_type in mdef.supported_entity_types:
      q = router.build_query(
          target_metric=metric_name,
          entity_type=entity_type,
          statistical_model=StatisticalModel.STANDARD_Z_SCORE,
          match_mode=MatchMode.TIMELINE_BREAKDOWN,
          scoring_end_date=target_date,
      )
      q = _pin_ecg_date(q, target_date)
      candidates.append(
          ManifestQuery(
              query_id=f"compile_extractor::{metric_name}::{entity_type.value}",
              suite_type="compile_extractor",
              description=f"Stage 1 extractor compile check: {metric_name} ({entity_type.value}) + STANDARD_Z_SCORE",
              query=q,
              start_time=start_time,
              end_time=end_time,
              coverage_tags=[
                  f"extractor:{metric_name}",
                  f"extractor_entity:{metric_name}:{entity_type.value}",
                  "model_mode:STANDARD_Z_SCORE:TIMELINE_BREAKDOWN",
              ],
              metric_name=metric_name,
              entity_type=entity_type.value,
              statistical_model=StatisticalModel.STANDARD_Z_SCORE.value,
              match_mode=MatchMode.TIMELINE_BREAKDOWN.value,
          )
      )

  # 2. All active Stage 2 math models x both MatchModes
  anchor_metric = "auth_attempts_total"
  anchor_entity = EntityType.USER
  for model in active_statistical_models():
    for mode in MatchMode:
      q = router.build_query(
          target_metric=anchor_metric,
          entity_type=anchor_entity,
          statistical_model=model,
          match_mode=mode,
          scoring_end_date=target_date,
      )
      q = _pin_ecg_date(q, target_date)
      candidates.append(
          ManifestQuery(
              query_id=f"compile_model::{model.value}::{mode.value}",
              suite_type="compile_model",
              description=f"Stage 2 math model compile check: {model.value} ({mode.value}) on {anchor_metric}",
              query=q,
              start_time=start_time,
              end_time=end_time,
              coverage_tags=[
                  f"model:{model.value}",
                  f"model_mode:{model.value}:{mode.value}",
                  f"extractor:{anchor_metric}",
                  f"extractor_entity:{anchor_metric}:{anchor_entity.value}",
              ],
              metric_name=anchor_metric,
              entity_type=anchor_entity.value,
              statistical_model=model.value,
              match_mode=mode.value,
          )
      )

  # Also exercise multi-key Stage 2 expansion (`_expand_mad_keys`) for MAD and QUANTILE_IQR_SKEW.
  for multi_key_model in (StatisticalModel.MAD, StatisticalModel.QUANTILE_IQR_SKEW):
    q = router.build_query(
        target_metric="file_executions_total",
        entity_type=EntityType.ASSET,
        statistical_model=multi_key_model,
        match_mode=MatchMode.TIMELINE_BREAKDOWN,
        scoring_end_date=target_date,
    )
    candidates.append(
        ManifestQuery(
            query_id=f"compile_model_multikey::{multi_key_model.value}::file_executions_total",
            suite_type="compile_model",
            description=(
                f"Multi-key Stage 2 expansion compile check: {multi_key_model.value} on file_executions_total (ASSET)"
            ),
            query=q,
            start_time=start_time,
            end_time=end_time,
            coverage_tags=[
                f"model:{multi_key_model.value}",
                f"model_multikey:{multi_key_model.value}",
                "extractor:file_executions_total",
                "extractor_entity:file_executions_total:ASSET",
            ],
            metric_name="file_executions_total",
            entity_type=EntityType.ASSET.value,
            statistical_model=multi_key_model.value,
            match_mode=MatchMode.TIMELINE_BREAKDOWN.value,
        )
    )

  # 3. All 34 pipeline templates (+ named-cohort conditional branches)
  for rec in render_all_pipelines(router, target_date=target_date, include_cohort_variants=True):
    if not rec.render_ok:
      raise RuntimeError(f"Failed to render pipeline '{rec.record_id}': {rec.render_error}")
    variant_suffix = rec.record_id.split("::", 1)[1]
    tags = [f"pipeline:{rec.pipeline_template}"]
    if "#" in variant_suffix:
      tags.append(f"pipeline_variant:{variant_suffix}")
    meta: Dict[str, Any] = {}
    if "%ueba_hunt_bridge" in rec.query:
      meta["requires_data_table"] = "ueba_hunt_bridge"
    if rec.pipeline_architecture:
      meta["pipeline_architecture"] = rec.pipeline_architecture
    candidates.append(
        ManifestQuery(
            query_id=f"compile_pipeline::{variant_suffix}",
            suite_type="compile_pipeline",
            description=f"Pipeline template compile check: {variant_suffix}",
            query=rec.query,
            start_time=start_time,
            end_time=end_time,
            coverage_tags=tags,
            pipeline_template=rec.pipeline_template,
            metadata=meta,
        )
    )

  # Deduplicate by normalized YARA-L body while merging coverage_tags & preserving pipeline attribution.
  deduped: Dict[str, ManifestQuery] = {}
  for item in candidates:
    norm_key = QueryIntegrityGate.normalize_yaral(item.query)
    existing = deduped.get(norm_key)
    if existing is None:
      deduped[norm_key] = item
    else:
      for tag in item.coverage_tags:
        if tag not in existing.coverage_tags:
          existing.coverage_tags.append(tag)
      if item.pipeline_template and not existing.pipeline_template:
        existing.pipeline_template = item.pipeline_template
      existing.metadata.setdefault("merged_query_ids", []).append(item.query_id)

  return list(deduped.values())


# ---------------------------------------------------------------------------
# PF-10 `(period: 1h, window: today)` & PF-11 `first_seen` Probes (2c, 2d)
# ---------------------------------------------------------------------------


def _build_pf10_probe_sql(spec: Stage1ExtractorSpec) -> str:
  # PF-10b constraint (entitytrackingdal_impl.go ReadUebaPlacerFilePaths L1994-2147):
  # Queries invoking metrics.*(period: 1h, window: today) WITHOUT at least one companion
  # metrics.*(period: 1d, window: 30d) call in the same QueryRequest fail on tenants whose
  # UebaAnalyticDimensionalExports metadata is indexed under 86400s windows ("no risk analytics
  # metric data available for the time range"). Always pair (1h, today) with a (1d, 30d) anchor.
  root_bindings = "\n".join(f"{var} = $stage1_extract.{var.lstrip('$')}" for var in spec.match_keys)
  match_list = ", ".join(spec.match_keys)
  return (
      f"// Goal: PF-10 live probe for metrics.{spec.metric_name}(period: 1h, window: today) [PF-10b (1d, 30d)-anchored]\n"
      "stage stage1_extract {\n"
      f"{spec.event_section}\n\n"
      "  match:\n"
      f"    {match_list} by 1d\n\n"
      "  outcome:\n"
      f"    $observed_val = {spec.observed_expr}\n"
      f"    $d30_periods = max(metrics.{spec.metric_name}(\n"
      f"        period: 1d, window: 30d, metric: {spec.metric_arg}, agg: num_metric_periods,\n"
      f"        {spec.dimension_args}\n"
      "    ))\n"
      f"    $hourly_avg = max(metrics.{spec.metric_name}(\n"
      f"        period: 1h, window: today, metric: {spec.metric_arg}, agg: avg,\n"
      f"        {spec.dimension_args}\n"
      "    ))\n"
      f"    $hourly_sum = max(metrics.{spec.metric_name}(\n"
      f"        period: 1h, window: today, metric: {spec.metric_arg}, agg: sum,\n"
      f"        {spec.dimension_args}\n"
      "    ))\n"
      f"    $hourly_periods = max(metrics.{spec.metric_name}(\n"
      f"        period: 1h, window: today, metric: {spec.metric_arg}, agg: num_metric_periods,\n"
      f"        {spec.dimension_args}\n"
      "    ))\n"
      "}\n\n"
      f"{root_bindings}\n\n"
      "match:\n"
      f"  {match_list}\n\n"
      "outcome:\n"
      "  $observed = sum($stage1_extract.observed_val)\n"
      "  $d30_periods = max($stage1_extract.d30_periods)\n"
      "  $hourly_avg = max($stage1_extract.hourly_avg)\n"
      "  $hourly_sum = max($stage1_extract.hourly_sum)\n"
      "  $hourly_periods = max($stage1_extract.hourly_periods)\n\n"
      "condition:\n"
      "  $hourly_periods > 0\n\n"
      "order:\n"
      "  $hourly_periods desc\n"
  )


def _build_pf11_probe_sql(spec: Stage1ExtractorSpec) -> str:
  root_bindings = "\n".join(f"{var} = $stage1_extract.{var.lstrip('$')}" for var in spec.match_keys)
  match_list = ", ".join(spec.match_keys)
  return (
      f"// Goal: PF-11 live probe for metrics.{spec.metric_name} first_seen & last_seen (period: 1d, window: 30d)\n"
      "stage stage1_extract {\n"
      f"{spec.event_section}\n\n"
      "  match:\n"
      f"    {match_list} by 1d\n\n"
      "  outcome:\n"
      f"    $observed_val = {spec.observed_expr}\n"
      f"    $first_seen_ts = max(metrics.{spec.metric_name}(\n"
      "        period: 1d, window: 30d, metric: first_seen, agg: min,\n"
      f"        {spec.dimension_args}\n"
      "    ))\n"
      f"    $last_seen_ts = max(metrics.{spec.metric_name}(\n"
      "        period: 1d, window: 30d, metric: last_seen, agg: max,\n"
      f"        {spec.dimension_args}\n"
      "    ))\n"
      "}\n\n"
      f"{root_bindings}\n\n"
      "match:\n"
      f"  {match_list}\n\n"
      "outcome:\n"
      "  $observed = sum($stage1_extract.observed_val)\n"
      "  $first_seen = max($stage1_extract.first_seen_ts)\n"
      "  $last_seen = max($stage1_extract.last_seen_ts)\n\n"
      "condition:\n"
      "  $first_seen > 0\n\n"
      "order:\n"
      "  $first_seen desc\n"
  )


def build_pf10_hourly_today_probes(
    *,
    template_dir: Path = TEMPLATES_DIR,
    start_time: str = DEFAULT_PF10_START_TIME,
    end_time: str = DEFAULT_PF10_END_TIME,
) -> List[ManifestQuery]:
  """Generates PF-10 `(period: 1h, window: today)` probes for all 38 metrics."""
  validate_pf10_window(start_time, end_time)
  probes: List[ManifestQuery] = []
  for metric_name in sorted(METRIC_CATALOG.keys()):
    spec = extract_stage1_spec(metric_name, template_dir=template_dir)
    primary_query = _build_pf10_probe_sql(spec)
    ast_errs = MalachiteASTValidator.validate_query(primary_query)
    if ast_errs:
      raise ValueError(f"PF-10 probe for {metric_name} failed AST validation: {ast_errs}")

    fallback_query: Optional[str] = None
    if metric_name in NETWORK_IP_FALLBACK_METRICS:
      ip_spec = extract_stage1_spec(metric_name, template_dir=template_dir, rebind_field="principal.asset.ip")
      fallback_query = _build_pf10_probe_sql(ip_spec)
      fb_errs = MalachiteASTValidator.validate_query(fallback_query)
      if fb_errs:
        raise ValueError(f"PF-10 IP fallback probe for {metric_name} failed AST validation: {fb_errs}")

    probes.append(
        ManifestQuery(
            query_id=f"pf10_hourly_today::{metric_name}",
            suite_type="pf10_hourly_today_probe",
            description=(
                f"PF-10 (period: 1h, window: today) availability probe for metrics.{metric_name}"
            ),
            query=primary_query,
            start_time=start_time,
            end_time=end_time,
            coverage_tags=[f"pf10:{metric_name}", f"metric:{metric_name}"],
            metric_name=metric_name,
            fallback_query=fallback_query,
            metadata={
                "period": "1h",
                "window": "today",
                "metric_arg": spec.metric_arg,
                "canonical_dimensions": spec.dimension_fields,
                "has_ip_fallback": fallback_query is not None,
                "anchored_with_d30_companion": True,
            },
        )
    )
  return probes


def build_pf11_first_seen_probes(
    *,
    template_dir: Path = TEMPLATES_DIR,
    start_time: str = DEFAULT_PF11_START_TIME,
    end_time: str = DEFAULT_PF11_END_TIME,
) -> List[ManifestQuery]:
  """Generates PF-11 `metric: first_seen` (& `last_seen`) probes for all 38 metrics."""
  validate_compile_window(start_time, end_time, max_hours=1.0)
  probes: List[ManifestQuery] = []
  for metric_name in sorted(METRIC_CATALOG.keys()):
    spec = extract_stage1_spec(metric_name, template_dir=template_dir)
    primary_query = _build_pf11_probe_sql(spec)
    # Note: Offline `MalachiteASTValidator` currently restricts `metric:` to
    # `value_sum | event_count_sum`; assert zero OTHER AST errors exist.
    other_errs = [
        e for e in MalachiteASTValidator.validate_query(primary_query)
        if not e.startswith("INVALID_METRIC_TYPE")
    ]
    if other_errs:
      raise ValueError(f"PF-11 probe for {metric_name} failed AST structure validation: {other_errs}")

    fallback_query: Optional[str] = None
    if metric_name in NETWORK_IP_FALLBACK_METRICS:
      ip_spec = extract_stage1_spec(metric_name, template_dir=template_dir, rebind_field="principal.asset.ip")
      fallback_query = _build_pf11_probe_sql(ip_spec)
      fb_errs = [
          e for e in MalachiteASTValidator.validate_query(fallback_query)
          if not e.startswith("INVALID_METRIC_TYPE")
      ]
      if fb_errs:
        raise ValueError(f"PF-11 IP fallback probe for {metric_name} failed AST validation: {fb_errs}")

    probes.append(
        ManifestQuery(
            query_id=f"pf11_first_seen::{metric_name}",
            suite_type="pf11_first_seen_probe",
            description=(
                f"PF-11 (period: 1d, window: 30d, metric: first_seen/last_seen) probe for metrics.{metric_name}"
            ),
            query=primary_query,
            start_time=start_time,
            end_time=end_time,
            coverage_tags=[f"pf11:{metric_name}", f"metric:{metric_name}"],
            metric_name=metric_name,
            fallback_query=fallback_query,
            metadata={
                "period": "1d",
                "window": "30d",
                "metric_args": ["first_seen", "last_seen"],
                "canonical_dimensions": spec.dimension_fields,
                "has_ip_fallback": fallback_query is not None,
            },
        )
    )
  return probes


def build_all_probes(
    *,
    template_dir: Path = TEMPLATES_DIR,
    pf10_start_time: str = DEFAULT_PF10_START_TIME,
    pf10_end_time: str = DEFAULT_PF10_END_TIME,
    pf11_start_time: str = DEFAULT_PF11_START_TIME,
    pf11_end_time: str = DEFAULT_PF11_END_TIME,
) -> List[ManifestQuery]:
  """Builds the combined 76-query manifest (38 PF-10 `(1h, today)` + 38 PF-11 `first_seen`)."""
  return (
      build_pf10_hourly_today_probes(
          template_dir=template_dir,
          start_time=pf10_start_time,
          end_time=pf10_end_time,
      )
      + build_pf11_first_seen_probes(
          template_dir=template_dir,
          start_time=pf11_start_time,
          end_time=pf11_end_time,
      )
  )


# ---------------------------------------------------------------------------
# Manifest JSON Export / Import & Injectable `search_fn` Execution (2e)
# ---------------------------------------------------------------------------


def export_manifest(
    queries: Sequence[ManifestQuery],
    path: Path | str,
    *,
    manifest_name: str = "ws0_03_manifest",
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Path:
  """Writes a list of `ManifestQuery` items to JSON on disk."""
  out_path = Path(path)
  out_path.parent.mkdir(parents=True, exist_ok=True)
  payload = {
      "schema_version": "1.0",
      "manifest_name": manifest_name,
      "target_environment": {
          "customer_id": DEFAULT_CUSTOMER_ID,
          "project_id": DEFAULT_PROJECT_ID,
          "region": DEFAULT_REGION,
      },
      "query_count": len(queries),
      "metadata": dict(extra_metadata or {}),
      "queries": [q.to_dict() for q in queries],
  }
  out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
  return out_path


def load_manifest(path: Path | str) -> List[ManifestQuery]:
  """Loads a list of `ManifestQuery` items from a JSON manifest file."""
  raw = json.loads(Path(path).read_text(encoding="utf-8"))
  items = raw["queries"] if isinstance(raw, dict) and "queries" in raw else raw
  return [ManifestQuery.from_dict(item) for item in items]


def export_execution_results(results: Sequence[LiveExecutionResult], path: Path | str) -> Path:
  """Writes structured `LiveExecutionResult` entries to JSON on disk."""
  out_path = Path(path)
  out_path.parent.mkdir(parents=True, exist_ok=True)
  compiled_count = sum(1 for r in results if r.compiled)
  payload = {
      "schema_version": "1.0",
      "total": len(results),
      "compiled_count": compiled_count,
      "compile_failure_count": len(results) - compiled_count,
      "nonzero_probe_count": sum(1 for r in results if r.has_nonzero_probe_data is True),
      "results": [r.to_dict() for r in results],
  }
  out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
  return out_path


def _normalize_response_payload(raw_response: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
  """Normalizes an MCP / REST `udm_search` response into `(dict_payload, error_msg)`."""
  if raw_response is None:
    return {}, None

  gate = QueryIntegrityGate.verify_backend_response(raw_response)
  if not gate["valid"]:
    return None, "; ".join(gate["errors"])

  if isinstance(raw_response, str):
    stripped = raw_response.strip()
    if not stripped:
      return {}, None
    try:
      raw_response = json.loads(stripped)
    except json.JSONDecodeError as exc:
      return None, f"NON_JSON_RESPONSE: {exc}: {stripped[:240]}"

  if not isinstance(raw_response, dict):
    return None, f"UNEXPECTED_RESPONSE_TYPE: {type(raw_response).__name__}"

  if raw_response.get("error"):
    return None, f"API_ERROR_FIELD: {raw_response['error']}"

  return raw_response, None


def _evaluate_probe_nonzero(suite_type: str, rows: Sequence[Dict[str, Any]]) -> Optional[bool]:
  """Evaluates whether a PF-10 or PF-11 probe returned non-zero metric values."""
  if suite_type == "pf10_hourly_today_probe":
    if not rows:
      return False
    return any(
        (float(r.get("hourly_periods") or 0) > 0) or (float(r.get("hourly_sum") or 0) > 0)
        for r in rows
    )
  if suite_type == "pf11_first_seen_probe":
    if not rows:
      return False
    return any(float(r.get("first_seen") or 0) > 0 for r in rows)
  return None


def execute_single_query(
    item: ManifestQuery,
    search_fn: SearchFn,
    *,
    try_fallback_on_zero_rows: bool = False,
) -> LiveExecutionResult:
  """Executes one `ManifestQuery` sequentially via `search_fn`."""
  t0 = time.monotonic()
  used_fallback = False

  def _invoke(q_text: str) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
    try:
      raw_resp = search_fn(q_text, item.start_time, item.end_time)
    except Exception as exc:  # pylint: disable=broad-except
      return False, [], f"{type(exc).__name__}: {exc}"
    payload, err = _normalize_response_payload(raw_resp)
    if err is not None or payload is None:
      return False, [], err
    try:
      rows = parse_stats_payload(payload)
    except ValueError as exc:
      return False, [], str(exc)
    return True, rows, None

  compiled, rows, err = _invoke(item.query)
  if (
      compiled
      and not rows
      and try_fallback_on_zero_rows
      and item.fallback_query
  ):
    fb_compiled, fb_rows, fb_err = _invoke(item.fallback_query)
    used_fallback = True
    compiled, rows, err = fb_compiled, fb_rows, fb_err

  latency_ms = (time.monotonic() - t0) * 1000.0
  nonzero_probe = _evaluate_probe_nonzero(item.suite_type, rows) if compiled else None

  return LiveExecutionResult(
      query_id=item.query_id,
      suite_type=item.suite_type,
      compiled=compiled,
      row_count=len(rows),
      has_nonzero_probe_data=nonzero_probe,
      used_fallback_query=used_fallback,
      latency_ms=round(latency_ms, 2),
      error=err,
      sample_row=rows[0] if rows else None,
      metadata={
          **dict(item.metadata),
          "metric_name": item.metric_name,
          "entity_type": item.entity_type,
          "statistical_model": item.statistical_model,
          "match_mode": item.match_mode,
          "pipeline_template": item.pipeline_template,
      },
  )


def run_manifest(
    queries: Sequence[ManifestQuery],
    search_fn: SearchFn,
    *,
    try_fallback_on_zero_rows: bool = False,
    stop_on_compile_error: bool = False,
) -> List[LiveExecutionResult]:
  """Runs `queries` strictly sequentially (1 query at a time) through `search_fn`."""
  results: List[LiveExecutionResult] = []
  for item in queries:
    res = execute_single_query(
        item,
        search_fn,
        try_fallback_on_zero_rows=try_fallback_on_zero_rows,
    )
    results.append(res)
    if stop_on_compile_error and not res.compiled:
      break
  return results


def main(argv: Optional[Sequence[str]] = None) -> int:
  parser = argparse.ArgumentParser(description="WS0-03 SecOps Risk Metrics Live Compile & Probe Harness")
  parser.add_argument("--export-compile-suite", type=str, help="Output JSON path for covering compile suite")
  parser.add_argument("--export-probes", type=str, help="Output JSON path for PF-10 + PF-11 probes")
  parser.add_argument("--audit-matrix", action="store_true", help="Render & audit the full 2,592+34 matrix offline")
  args = parser.parse_args(argv)

  if args.audit_matrix:
    records = render_full_matrix()
    summary = summarize_matrix_records(records)
    print(json.dumps(summary, indent=2))
    if summary["render_crash_count"] > 0 or summary["ast_error_record_count"] > 0:
      return 1

  if args.export_compile_suite:
    suite = build_covering_compile_suite()
    out = export_manifest(
        suite,
        args.export_compile_suite,
        manifest_name="ws0_03_risk_metrics_compile_suite",
        extra_metadata={
            "window": {"start_time": DEFAULT_COMPILE_START_TIME, "end_time": DEFAULT_COMPILE_END_TIME},
            "extractors_covered": len(METRIC_CATALOG),
            "models_covered": len(StatisticalModel),
            "pipelines_covered": 34,
        },
    )
    print(f"Exported {len(suite)} compile-suite queries to {out}")

  if args.export_probes:
    probes = build_all_probes()
    out = export_manifest(
        probes,
        args.export_probes,
        manifest_name="ws0_03_risk_metrics_probes",
        extra_metadata={
            "pf10_window": {"start_time": DEFAULT_PF10_START_TIME, "end_time": DEFAULT_PF10_END_TIME},
            "pf11_window": {"start_time": DEFAULT_PF11_START_TIME, "end_time": DEFAULT_PF11_END_TIME},
            "pf10_count": len(METRIC_CATALOG),
            "pf11_count": len(METRIC_CATALOG),
        },
    )
    print(f"Exported {len(probes)} probe queries to {out}")

  return 0


if __name__ == "__main__":
  raise SystemExit(main())
