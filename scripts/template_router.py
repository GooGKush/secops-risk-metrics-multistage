# Template Router for Multi-Stage YARA-L Queries (.yl2)

__author__ = "Greg Kushmerek"
__version__ = "2.1.1"

from pathlib import Path
import re
from typing import Optional
from .preflight_validator import EntityType, MatchMode, PipelineArchitecture, PreFlightValidator, StatisticalModel


class MultiStageTemplateRouter:
  """Assembles 2-Stage, 3-Stage, and 4-Stage YARA-L DAG queries."""

  def __init__(self, template_dir: Optional[Path] = None):
    if template_dir is None:
      self.template_dir = Path(__file__).resolve().parent.parent / "templates"
    else:
      self.template_dir = template_dir

  def build_query(
      self,
      target_metric: str,
      entity_type: EntityType,
      statistical_model: StatisticalModel,
      anomaly_threshold: float,
      min_baseline_days: Optional[int] = None,
      match_mode: MatchMode = MatchMode.TIMELINE_BREAKDOWN,
      hypothesis_goal: Optional[str] = None,
  ) -> str:
    audit = PreFlightValidator.audit(
        target_metric=target_metric,
        entity_type=entity_type,
        min_baseline_days=min_baseline_days,
        match_mode=match_mode,
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
    stage1_content = stage1_path.read_text().strip()

    stage2_file_map = {
        StatisticalModel.STANDARD_Z_SCORE: "standard_z_score.yl2",
        StatisticalModel.MAD: "mad.yl2",
        StatisticalModel.VARIANCE: "variance_fano.yl2",
        StatisticalModel.POISSON: "poisson_rarity.yl2",
        StatisticalModel.COEFFICIENT_OF_VARIATION: "coefficient_of_variation.yl2",
        StatisticalModel.HOURLY_TEMPORAL_ZSCORE: "hourly_temporal_zscore.yl2",
        StatisticalModel.BAYESIAN_GAMMA: "poisson_gamma_bayesian.yl2",
        StatisticalModel.BAYESIAN_BETA_BINOMIAL: "beta_binomial_bayesian.yl2",
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

    if match_mode == MatchMode.FLEET_ROLLUP:
      stage2_raw = stage2_raw.replace(f"match:\n  {primary_var}, $ws by 1d", f"match:\n  {primary_var}")
      stage2_raw = stage2_raw.replace("$ws = $stage1_extract.window_start\n", "")

    stage2_rendered = stage2_raw.replace("{{anomaly_threshold}}", str(anomaly_threshold))
    stage2_rendered = stage2_rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))

    header = (
        "// ============================================================================\n"
        "// METHODOLOGY & HUNTING GOAL\n"
        f"// Goal: {hypothesis_goal or ('Hunt for statistical outliers in ' + target_metric)}\n"
        f"// Target Telemetry: {audit['required_event_type']} (Dimensions: {audit['target_field']})\n"
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
  ) -> str:
    """Renders 3-Stage and 4-Stage advanced DAG pipelines."""
    if pipeline_type == PipelineArchitecture.MULTI_SECTOR_FUSION_4STAGE:
      pipeline_file = self.template_dir / "pipelines" / "multi_sector_fusion_4stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      return pipeline_file.read_text().strip() + "\n"

    elif pipeline_type == PipelineArchitecture.DUAL_BASELINE_3STAGE:
      if not target_metric:
        target_metric = "http_queries_total"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
      )
      pipeline_file = self.template_dir / "pipelines" / "dual_baseline_delta_z_3stage.yl2"
      raw = pipeline_file.read_text().strip()
      metric_type_arg = "metric: value_sum" if "bytes" in target_metric else "metric: event_count_sum"
      
      rendered = raw.replace("{{event_type}}", audit["required_event_type"])
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
      )
      pipeline_file = self.template_dir / "pipelines" / "hierarchical_empirical_bayes_3stage.yl2"
      raw = pipeline_file.read_text().strip()
      metric_type_arg = "metric: value_sum" if "bytes" in target_metric else "metric: event_count_sum"
      
      rendered = raw.replace("{{event_type}}", audit["required_event_type"])
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
        sa_regex_pattern = r"\(\s*\$sa\s*=\s*/@.*?nocase\s*\)"
        sa_binding = f'    $sa = "{service_account}"'
        raw = re.sub(sa_regex_pattern, sa_binding, raw, flags=re.DOTALL)
      if hypothesis_goal:
        raw = f"// Goal: {hypothesis_goal}\n" + raw
      return raw + "\n"

    elif pipeline_type == PipelineArchitecture.HYBRID_METRIC_RAW_ENRICHMENT_2STAGE:
      if not target_metric:
        target_metric = "network_bytes_outbound"
      audit = PreFlightValidator.audit(
          target_metric=target_metric,
          entity_type=entity_type,
          min_baseline_days=min_baseline_days,
      )
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_raw_enrichment_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      metric_type_arg = "metric: total_bytes" if "bytes" in target_metric else "metric: event_count_sum"

      macro_entity_field = audit["target_field"]
      macro_event_type = audit["required_event_type"]
      macro_observed_agg = "sum(network.sent_bytes)" if "outbound" in target_metric else ("sum(network.received_bytes)" if "inbound" in target_metric else "count(metadata.id)")
      macro_event_filter = ""

      raw_event_type = "NETWORK_HTTP"
      raw_entity_field = "principal.asset.hostname" if entity_type == EntityType.ASSET else "principal.user.userid"
      raw_event_filter = ""
      raw_signature_field = "target.user_agent"
      max_signature_diversity = 2
      min_raw_events = 5

      rendered = raw.replace("{{macro_event_type}}", macro_event_type)
      rendered = rendered.replace("{{macro_entity_field}}", macro_entity_field)
      rendered = rendered.replace("{{macro_event_filter}}", macro_event_filter)
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
      )
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_entropy_concentration_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      metric_type_arg = "metric: total_bytes" if "bytes" in target_metric else "metric: event_count_sum"

      macro_entity_field = audit["target_field"]
      macro_event_type = audit["required_event_type"]
      macro_observed_agg = "sum(network.sent_bytes)" if "outbound" in target_metric else ("sum(network.received_bytes)" if "inbound" in target_metric else "count(metadata.id)")
      macro_event_filter = ""

      raw_event_type = "NETWORK_HTTP"
      raw_entity_field = "principal.asset.hostname" if entity_type == EntityType.ASSET else "principal.user.userid"
      raw_event_filter = ""
      raw_vocab_field = "target.url"
      raw_intensity_field = "network.sent_bytes" if "outbound" in target_metric else "1"

      rendered = raw.replace("{{macro_event_type}}", macro_event_type)
      rendered = rendered.replace("{{macro_entity_field}}", macro_entity_field)
      rendered = rendered.replace("{{macro_event_filter}}", macro_event_filter)
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
      )
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_orthogonal_space_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      metric_type_arg = "metric: total_bytes" if "bytes" in target_metric else "metric: event_count_sum"

      macro_entity_field = audit["target_field"]
      macro_event_type = audit["required_event_type"]
      macro_observed_agg = "sum(network.sent_bytes)" if "outbound" in target_metric else "count(metadata.id)"
      macro_event_filter = ""

      raw_event_type = "NETWORK_CONNECTION"
      raw_entity_field = "principal.asset.hostname" if entity_type == EntityType.ASSET else "principal.user.userid"
      raw_event_filter = ""
      raw_breadth_field = "target.ip"

      rendered = raw.replace("{{macro_event_type}}", macro_event_type)
      rendered = rendered.replace("{{macro_entity_field}}", macro_entity_field)
      rendered = rendered.replace("{{macro_event_filter}}", macro_event_filter)
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
      )
      pipeline_file = self.template_dir / "pipelines" / "hybrid_metric_fleet_prevalence_2stage.yl2"
      if not pipeline_file.exists():
        raise FileNotFoundError(f"Missing pipeline template: {pipeline_file}")
      raw = pipeline_file.read_text().strip()
      metric_type_arg = "metric: event_count_sum"

      macro_entity_field = "principal.asset.hostname" if entity_type == EntityType.ASSET else "principal.user.userid"
      macro_event_type = audit["required_event_type"]
      macro_token_field = "principal.process.file.sha256"
      macro_observed_agg = "count(metadata.id)"
      macro_event_filter = ""

      raw_event_type = "PROCESS_LAUNCH"
      raw_token_field = "principal.process.file.sha256"
      raw_event_filter = ""
      fleet_entity_field = "principal.asset.hostname"

      rendered = raw.replace("{{macro_event_type}}", macro_event_type)
      rendered = rendered.replace("{{macro_entity_field}}", macro_entity_field)
      rendered = rendered.replace("{{macro_token_field}}", macro_token_field)
      rendered = rendered.replace("{{macro_event_filter}}", macro_event_filter)
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
  ) -> str:
    """Builds a verified Cloud Repository Scope pipeline guaranteeing target.resource.name binding."""
    return self.build_pipeline_query(
        PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH,
        target_metric="resource_read_total",
        entity_type=EntityType.USER,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
        service_account=service_account,
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
        "    $diff = $obs - $mu\n"
        "    $denom = $sigma + 1.0\n"
        "    $z_score = $diff / $denom\n"
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
