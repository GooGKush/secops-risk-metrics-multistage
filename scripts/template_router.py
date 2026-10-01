# Template Router for Multi-Stage YARA-L Queries (.yl2)

__author__ = "Greg Kushmerek"
__version__ = "2.1.1"

import datetime
from pathlib import Path
import re
from typing import List, Optional, Sequence
from . import malachite_catalog as mc
from .preflight_validator import METRIC_CATALOG, EntityType, MalachiteASTValidator, MatchMode, PipelineArchitecture, PreFlightValidator, StatisticalModel


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
    out = re.sub(r"\b" + f + r"(\s*:\s*" + v + r"\b)", target_field + r"\g<1>", out)
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

  @staticmethod
  def _inject_condition(rendered: str, default_score: str, condition_expression: Optional[str],
                        min_threshold: Optional[float], max_threshold: Optional[float]) -> str:
    order_match = re.search(r"order:\s*\n\s*([$][a-zA-Z0-9_]+)", rendered)
    score_var = order_match.group(1) if order_match else default_score
    if condition_expression:
      cond = condition_expression
    elif min_threshold is not None and max_threshold is not None:
      cond = f"{score_var} >= {min_threshold} and {score_var} < {max_threshold}"
    elif min_threshold is not None:
      cond = f"{score_var} >= {min_threshold}"
    elif max_threshold is not None:
      cond = f"{score_var} <= {max_threshold}"
    else:
      return rendered
    return re.sub(r"(\border:\s*)", f"condition:\n  {cond}\n\n\\1", rendered, count=1)

  # ---------------------------------------------------------------------------
  # Generic sector fusion
  # ---------------------------------------------------------------------------

  def build_sector_fusion_query(
      self,
      sector_a: "mc.SectorSpec",
      sector_b: "mc.SectorSpec",
      four_stage: bool = False,
      min_baseline_days: int = 7,
      hypothesis_goal: Optional[str] = None,
      min_threshold: Optional[float] = None,
      max_threshold: Optional[float] = None,
      condition_expression: Optional[str] = None,
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
    rendered = rendered.replace("{{min_baseline_days}}", str(min_baseline_days))
    # The template's slot guide is for agents filling slots by hand; it is noise once rendered.
    rendered = re.sub(r"^// SLOT FILLING:.*?(?=^// ====)", "", rendered, flags=re.M | re.S)

    rendered = self._inject_condition(rendered, "$composite_threat_norm_sq", condition_expression, min_threshold, max_threshold)
    prefix = "".join(f"// ADVISORY: {a}\n" for a in check.advisories)
    if hypothesis_goal:
      prefix = f"// Goal: {hypothesis_goal}\n" + prefix
    rendered = prefix + rendered

    errors = MalachiteASTValidator.validate_query(rendered)
    if errors:
      raise ValueError("Rendered fusion query failed validation: " + " | ".join(errors))
    return rendered + "\n"

  def build_query(
      self,
      target_metric: str,
      entity_type: EntityType,
      statistical_model: StatisticalModel,
      anomaly_threshold: float = 3.0,
      min_baseline_days: Optional[int] = None,
      match_mode: MatchMode = MatchMode.TIMELINE_BREAKDOWN,
      hypothesis_goal: Optional[str] = None,
      min_threshold: Optional[float] = None,
      max_threshold: Optional[float] = None,
      condition_expression: Optional[str] = None,
      apply_threshold_condition: bool = False,
      identifier_field: Optional[str] = None,
  ) -> str:
    audit = PreFlightValidator.audit(
        target_metric=target_metric,
        entity_type=entity_type,
        min_baseline_days=min_baseline_days,
        match_mode=match_mode,
        identifier_field=identifier_field,
    )

    # Enforce Local-Baseline Isolation: multi-database account queries must route to CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH
    if target_metric in [
        "resource_read_total",
        "resource_written_total",
        "resource_written_success",
        "resource_written_fail",
    ] and entity_type == EntityType.USER:
      return self.build_pipeline_query(
          PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH,
          target_metric=target_metric,
          entity_type=entity_type,
          anomaly_threshold=anomaly_threshold,
          min_baseline_days=min_baseline_days,
          hypothesis_goal=hypothesis_goal,
      )

    stage1_path = self.template_dir / "stage1_extractors" / f"{target_metric}.yl2"
    if not stage1_path.exists():
      raise FileNotFoundError(f"Missing Stage 1 template: {stage1_path}")
    stage1_content = self._rebind_entity_field(
        self._strip_identifier_swap_note(stage1_path.read_text().strip()), target_metric, audit["target_field"])

    stage2_file_map = {
        StatisticalModel.STANDARD_Z_SCORE: "standard_z_score.yl2",
        StatisticalModel.MAD: "mad.yl2",
        StatisticalModel.VARIANCE: "variance_fano.yl2",
        StatisticalModel.POISSON: "poisson_rarity.yl2",
        StatisticalModel.COEFFICIENT_OF_VARIATION: "coefficient_of_variation.yl2",
        StatisticalModel.HOURLY_TEMPORAL_ZSCORE: "hourly_temporal_zscore.yl2",
        StatisticalModel.BAYESIAN_GAMMA: "poisson_gamma_bayesian.yl2",
        StatisticalModel.BAYESIAN_BETA_BINOMIAL: "beta_binomial_bayesian.yl2",
        StatisticalModel.LONGITUDINAL_CUSUM: "longitudinal_cusum.yl2",
        StatisticalModel.TWO_PART_HURDLE: "two_part_hurdle.yl2",
        StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z: "asymmetric_directional_z.yl2",
        StatisticalModel.PIECEWISE_CRI: "piecewise_cri.yl2",
        StatisticalModel.FLEET_PREVALENCE_SHIELD: "fleet_prevalence_shield.yl2",
        StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD: "adaptive_context_threshold.yl2",
        StatisticalModel.MACD_MOMENTUM_VELOCITY: "macd_momentum_velocity.yl2",
        StatisticalModel.CIRCADIAN_VON_MISES: "circadian_von_mises.yl2",
    }
    stage2_path = self.template_dir / "stage2_math_models" / stage2_file_map[statistical_model]
    if not stage2_path.exists():
      raise FileNotFoundError(f"Missing Stage 2 template: {stage2_path}")
    stage2_raw = stage2_path.read_text().strip()

    # Harmonize Stage 2 entity variable with Stage 1 match variable ($user, $host, $entity)
    match_var_match = re.search(r'match:\s+([$][a-zA-Z0-9_]+)', stage1_content)
    primary_var = match_var_match.group(1) if match_var_match else "$entity"
    entity_name = primary_var.lstrip("$")

    if primary_var != "$entity":
      stage2_raw = stage2_raw.replace("$entity = $stage1_extract.entity", f"{primary_var} = $stage1_extract.{entity_name}")
      stage2_raw = stage2_raw.replace("$entity", primary_var)

    if statistical_model == StatisticalModel.CIRCADIAN_VON_MISES:
      if "$event_hour" not in stage1_content:
        stage1_content = re.sub(
            r'(outcome:\s*\n)',
            r'\1    $event_hour = max(timestamp.get_hour(metadata.event_timestamp.seconds))\n',
            stage1_content,
            count=1,
        )
      stage1_content = re.sub(r'(\bmatch:\s*\n\s*[$][a-zA-Z0-9_]+\s+by)\s+1d', r'\1 1h', stage1_content)

    if match_mode == MatchMode.FLEET_ROLLUP:
      stage2_raw = stage2_raw.replace(f"match:\n  {primary_var}, $ws by 1d", f"match:\n  {primary_var}")
      stage2_raw = stage2_raw.replace(f"match:\n  {primary_var}, $ws by 1h", f"match:\n  {primary_var}")
      stage2_raw = stage2_raw.replace("$ws = $stage1_extract.window_start\n", "")

    stage2_rendered = stage2_raw.replace("{{anomaly_threshold}}", str(anomaly_threshold))
    stage2_rendered = stage2_rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))

    # Noise Level & Significance Threshold Conditioning
    if apply_threshold_condition and min_threshold is None and max_threshold is None:
      min_threshold = anomaly_threshold

    order_match = re.search(r'order:\s*\n\s*([$][a-zA-Z0-9_]+)', stage2_rendered)
    score_var = order_match.group(1) if order_match else "$personal_z"

    if condition_expression:
      cond_block = f"condition:\n  {condition_expression}\n\n"
      stage2_rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", stage2_rendered, count=1)
    elif min_threshold is not None and max_threshold is not None:
      cond_block = f"condition:\n  {score_var} >= {min_threshold} and {score_var} < {max_threshold}\n\n"
      stage2_rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", stage2_rendered, count=1)
    elif min_threshold is not None:
      cond_block = f"condition:\n  {score_var} >= {min_threshold}\n\n"
      stage2_rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", stage2_rendered, count=1)
    elif max_threshold is not None:
      cond_block = f"condition:\n  {score_var} <= {max_threshold}\n\n"
      stage2_rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", stage2_rendered, count=1)

    header = (
        "// ============================================================================\n"
        "// METHODOLOGY & HUNTING GOAL\n"
        f"// Goal: {hypothesis_goal or ('Hunt for statistical outliers in ' + target_metric)}\n"
        f"// Target Telemetry: {audit['event_label']} (Dimensions: {audit['target_field']})\n"
        f"// Event Filter: {' AND '.join(audit['event_filter'])}\n"
        f"// Statistical Model: {statistical_model.value} (Threshold >= {anomaly_threshold})\n"
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
      anomaly_threshold: float = 3.0,
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
  ) -> str:
    """Renders 3-Stage and 4-Stage advanced DAG pipelines."""
    if pipeline_type in (PipelineArchitecture.MULTI_SECTOR_FUSION_4STAGE, PipelineArchitecture.DUAL_SECTOR_FUSION_3STAGE):
      metrics = list(target_metrics or self.DEFAULT_FUSION_METRICS)
      if len(metrics) != 2:
        raise ValueError(f"Sector fusion takes exactly 2 metrics, got {len(metrics)}: {metrics}")
      sectors = [mc.SectorSpec(m, self._sector_entity_field(m, entity_type, identifier_field)) for m in metrics]
      return self.build_sector_fusion_query(
          sectors[0], sectors[1],
          four_stage=pipeline_type == PipelineArchitecture.MULTI_SECTOR_FUSION_4STAGE,
          min_baseline_days=min_baseline_days if min_baseline_days is not None else 7,
          hypothesis_goal=hypothesis_goal,
          min_threshold=min_threshold,
          max_threshold=max_threshold,
          condition_expression=condition_expression,
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
      if hypothesis_goal:
        raw = f"// Goal: {hypothesis_goal}\n" + raw
      rendered = raw
      if condition_expression:
        cond_block = f"condition:\n  {condition_expression}\n\n"
        rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", rendered, count=1)
      elif min_threshold is not None and max_threshold is not None:
        order_match = re.search(r'order:\s*\n\s*([$][a-zA-Z0-9_]+)', rendered)
        score_var = order_match.group(1) if order_match else "$normalized_odds_score"
        cond_block = f"condition:\n  {score_var} >= {min_threshold} and {score_var} < {max_threshold}\n\n"
        rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", rendered, count=1)
      elif min_threshold is not None:
        order_match = re.search(r'order:\s*\n\s*([$][a-zA-Z0-9_]+)', rendered)
        score_var = order_match.group(1) if order_match else "$normalized_odds_score"
        cond_block = f"condition:\n  {score_var} >= {min_threshold}\n\n"
        rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", rendered, count=1)
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.HTTP_ERROR_RATIO_SURGE_2STAGE:
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
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: $host)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: $host)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, {audit['target_field']}: $host)"
      )
      rendered = rendered.replace("{{anomaly_threshold}}", str(anomaly_threshold))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
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
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: $host)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: $host)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, {audit['target_field']}: $host)"
      )
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH:
      pipeline_file = self.template_dir / "pipelines" / "cloud_repository_scope_dual_branch.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      if service_account:
        sa_regex_pattern = r"(?:\(\s*)?\$sa\s*=\s*/@.*?nocase(?:\s*\))?"
        sa_binding = f'    $sa = "{service_account}"'
        raw = re.sub(sa_regex_pattern, sa_binding, raw, flags=re.DOTALL)
      if hypothesis_goal:
        raw = f"// Goal: {hypothesis_goal}\n" + raw
      rendered = raw

      # Noise Level & Significance Threshold Conditioning
      if condition_expression:
        cond_block = f"condition:\n  {condition_expression}\n\n"
        rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", rendered, count=1)
      elif min_threshold is not None and max_threshold is not None:
        order_match = re.search(r'order:\s*\n\s*([$][a-zA-Z0-9_]+)', rendered)
        score_var = order_match.group(1) if order_match else "$composite_risk"
        cond_block = f"condition:\n  {score_var} >= {min_threshold} and {score_var} < {max_threshold}\n\n"
        rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", rendered, count=1)
      elif min_threshold is not None:
        order_match = re.search(r'order:\s*\n\s*([$][a-zA-Z0-9_]+)', rendered)
        score_var = order_match.group(1) if order_match else "$composite_risk"
        cond_block = f"condition:\n  {score_var} >= {min_threshold}\n\n"
        rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", rendered, count=1)
      elif max_threshold is not None:
        order_match = re.search(r'order:\s*\n\s*([$][a-zA-Z0-9_]+)', rendered)
        score_var = order_match.group(1) if order_match else "$composite_risk"
        cond_block = f"condition:\n  {score_var} <= {max_threshold}\n\n"
        rendered = re.sub(r'(\border:\s*)', f"{cond_block}\\1", rendered, count=1)

      return rendered + "\n"

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
          cohort_filter = "(\n      " + " or\n      ".join(f'$u = "{c}"' for c in cohort_entities) + "\n    )"
        else:
          cohort_filter = f'$u = "{cohort_entities[0]}"'
        rendered = rendered.replace("{{cohort_filter}}", cohort_filter)
        rendered = rendered.replace("order:\n  $z_vs_enterprise desc", "order:\n  $z_vs_team desc")

      if target_entity:
        target_filter = f'{entity_var} = "{target_entity}"'
      elif cohort_entities:
        if len(cohort_entities) > 1:
          target_filter = "(\n  " + " or\n  ".join(f'{entity_var} = "{c}"' for c in cohort_entities) + "\n)"
        else:
          target_filter = f'{entity_var} = "{cohort_entities[0]}"'
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
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: {entity_var})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: {entity_var})"
      )
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
        target_filter = f'{entity_var} = "{target_entity}"'
      elif cohort_entities:
        if len(cohort_entities) > 1:
          target_filter = "(\n  " + " or\n  ".join(f'{entity_var} = "{c}"' for c in cohort_entities) + "\n)"
        else:
          target_filter = f'{entity_var} = "{cohort_entities[0]}"'
      else:
        target_filter = f'{entity_var} != ""'

      # Peer group rule (template header): with no named cohort the team stage would just
      # recompute the fleet, so the marked TEAM COHORT blocks are dropped (fleet only).
      rendered = _apply_team_cohort_blocks(raw, keep=bool(cohort_entities))
      if cohort_entities:
        if len(cohort_entities) > 1:
          cohort_filter = "(\n      " + " or\n      ".join(f'$u = "{c}"' for c in cohort_entities) + "\n    )"
        else:
          cohort_filter = f'$u = "{cohort_entities[0]}"'
        rendered = rendered.replace("{{cohort_filter}}", cohort_filter)
        rendered = rendered.replace("order:\n  $d_vs_fleet_sq desc", "order:\n  $d_vs_team_sq desc")

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
            f"metrics.{m}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {triad_audit['target_field']}: {entity_var})"
        )
        rendered = rendered.replace(
            f"{{{{m{idx}_metric_func_stddev}}}}",
            f"metrics.{m}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {triad_audit['target_field']}: {entity_var})"
        )

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
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: $entity)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: $entity)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, {audit['target_field']}: $entity)"
      )

      rendered = rendered.replace("{{raw_event_type}}", raw_event_type)
      rendered = rendered.replace("{{raw_entity_field}}", raw_entity_field)
      rendered = rendered.replace("{{raw_event_filter}}", raw_event_filter)
      rendered = rendered.replace("{{raw_signature_field}}", raw_signature_field)

      rendered = rendered.replace("{{anomaly_threshold}}", str(anomaly_threshold))
      rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
      rendered = rendered.replace("{{max_signature_diversity}}", str(max_signature_diversity))
      rendered = rendered.replace("{{min_raw_events}}", str(min_raw_events))

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
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: $entity)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: $entity)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, {audit['target_field']}: $entity)"
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
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, {audit['target_field']}: $entity)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, {audit['target_field']}: $entity)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, {audit['target_field']}: $entity)"
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

      macro_entity_field = "principal.asset.hostname" if entity_type == EntityType.ASSET else "principal.user.userid"
      macro_token_field = "principal.process.file.sha256"
      macro_observed_agg = audit["observed_agg"]

      raw_event_type = "PROCESS_LAUNCH"
      raw_token_field = "principal.process.file.sha256"
      raw_event_filter = ""
      fleet_entity_field = "principal.asset.hostname"

      rendered = raw.replace("{{macro_entity_field}}", macro_entity_field)
      rendered = rendered.replace("{{macro_token_field}}", macro_token_field)
      rendered = _fill_event_filter(rendered, "{{macro_event_filter}}", audit["event_filter"])
      rendered = rendered.replace("{{macro_observed_agg}}", macro_observed_agg)

      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, metadata.event_type: \"PROCESS_LAUNCH\", {macro_entity_field}: $entity, principal.process.file.sha256: $token)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, metadata.event_type: \"PROCESS_LAUNCH\", {macro_entity_field}: $entity, principal.process.file.sha256: $token)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, metadata.event_type: \"PROCESS_LAUNCH\", {macro_entity_field}: $entity, principal.process.file.sha256: $token)"
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
      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, principal.asset.hostname: $host, {domain_field}: $domain)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, principal.asset.hostname: $host, {domain_field}: $domain)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, principal.asset.hostname: $host, {domain_field}: $domain)"
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
      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, principal.asset.hostname: $host, {domain_field}: $domain)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, principal.asset.hostname: $host, {domain_field}: $domain)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, principal.asset.hostname: $host, {domain_field}: $domain)"
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
      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, principal.asset.hostname: $host)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, principal.asset.hostname: $host)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, principal.asset.hostname: $host)"
      )
      rendered = rendered.replace("{{anomaly_threshold}}", str(anomaly_threshold))
      rendered = rendered.replace("{{max_asset_age_days}}", "7.0")
      rendered = rendered.replace("{{today_date}}", _today_date())
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
      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

    elif pipeline_type == PipelineArchitecture.CIRCADIAN_VON_MISES_2STAGE:
      if not target_metric:
        target_metric = "auth_attempts_total"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
          identifier_field=identifier_field,
      )
      pipeline_file = self.template_dir / "pipelines" / "circadian_von_mises_2stage.yl2"
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
      if hypothesis_goal:
        rendered = f"// Goal: {hypothesis_goal}\n" + rendered
      return rendered + "\n"

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
  ) -> str:
    """Builds a verified Cloud Repository Scope pipeline guaranteeing target.resource.name binding."""
    return self.build_pipeline_query(
        PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH,
        target_metric="resource_read_total",
        entity_type=EntityType.USER,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
        service_account=service_account,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
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
  ) -> str:
    """Builds a verified 2-Stage Derived Context Domain Prevalence pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
    )

  def build_hybrid_whois_domain_lifecycle_query(
      self,
      target_metric: str = "http_queries_total",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
  ) -> str:
    """Builds a verified 2-Stage WHOIS Domain Lifecycle pipeline (NRD age & expiration)."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
    )

  def build_hybrid_derived_asset_age_query(
      self,
      target_metric: str = "auth_attempts_total",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
  ) -> str:
    """Builds a verified 2-Stage Derived Context Infant Asset Age pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
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

class ChainedHuntRouter:
  """Builds Two-Phase Chained Hunt query specifications across entity boundaries."""

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
        "      metadata.event_type: \"PROCESS_LAUNCH\",\n"
        "      principal.asset.hostname: $host, principal.process.file.sha256: $sha256\n"
        "    ))\n"
        "    $sigma = max(metrics.file_executions_total(\n"
        "      period: 1d, window: 30d, metric: event_count_sum, agg: stddev,\n"
        "      metadata.event_type: \"PROCESS_LAUNCH\",\n"
        "      principal.asset.hostname: $host, principal.process.file.sha256: $sha256\n"
        "    ))\n"
        "    $z_score = ($obs - $mu) / if($sigma > 0, $sigma, 1.0)\n"
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
        "  $observed_launches = max($stage1_process_outlier.obs)\n"
        "  $historical_mean = max($stage1_process_outlier.mu)\n"
        "\n"
        "condition:\n"
        f"  $process_z >= {anomaly_threshold}\n"
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
