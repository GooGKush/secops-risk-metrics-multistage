# Template Router for Multi-Stage YARA-L Queries (.yl2)

__author__ = "Greg Kushmerek"
__version__ = "2.1.1"

import datetime
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple
from . import malachite_catalog as mc
from .preflight_validator import (
    KillChainArchetype,
    METRIC_CATALOG,
    EntityType,
    MalachiteASTValidator,
    MatchMode,
    PipelineArchitecture,
    PreFlightValidator,
    StatisticalModel,
)


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

  STAGE2_TEMPLATES = {
      StatisticalModel.STANDARD_Z_SCORE: "standard_z_score.yl2",
      StatisticalModel.MAD: "mad.yl2",
      StatisticalModel.RELATIVE_DEVIATION: "relative_deviation.yl2",
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
      StatisticalModel.QUANTILE_IQR_SKEW: "quantile_iqr_skew.yl2",
      "diversity_deficit": "diversity_deficit_entropy.yl2",
      "diversity_deficit_entropy": "diversity_deficit_entropy.yl2",
      "macd_momentum": "macd_momentum.yl2",
      "macd_momentum_velocity": "macd_momentum_velocity.yl2",
      "hourly_zscore": "hourly_temporal_zscore.yl2",
      "longitudinal_cusum": "longitudinal_cusum.yl2",
  }

  STAGE2_FALLBACK_TEMPLATES = {
      "diversity_deficit_entropy.yl2": "coefficient_of_variation.yl2",
      "macd_momentum.yl2": "macd_momentum_velocity.yl2",
  }

  MODEL_DESCRIPTIONS = {
      StatisticalModel.HOURLY_TEMPORAL_ZSCORE: "Macro-Day + Micro-Hour Burst Localization",
      "hourly_zscore": "Macro-Day + Micro-Hour Burst Localization",
      StatisticalModel.LONGITUDINAL_CUSUM: "Multi-Day Cumulative Drift (Windowed Slack Sum)",
      "longitudinal_cusum": "Multi-Day Cumulative Drift (Windowed Slack Sum)",
      StatisticalModel.MACD_MOMENTUM_VELOCITY: "MACD Multi-Horizon Momentum & Velocity Crossover",
      "macd_momentum": "MACD Multi-Horizon Momentum & Velocity Crossover",
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
      anomaly_threshold: float = 3.0,
      fold_change_threshold: float = 2.0,
      fusion_threshold_sq: float = 12.25,
      robust_threshold: float = 3.5,
      min_threshold: Optional[float] = None,
      max_threshold: Optional[float] = None,
      condition_expression: Optional[str] = None,
      default_score: str = "$personal_z",
      only_if_template_gate: bool = False,
  ) -> str:
    """Resolves the template's root significance gate and applies any analyst override.

    Every score-producing template ships a default root gate (`<gate var> >= {{<placeholder>}}`, see
    GATE_PLACEHOLDERS). An override (condition_expression, or min/max_threshold on the gate variable)
    REPLACES that default clause and keeps the template's other condition clauses (e.g. MAD's
    scoring-window and sample-size gates). When the template has no default gate clause the override
    is AND-ed into the root condition (or a new root condition is created), unless
    only_if_template_gate is set; renderers that already resolved their own gate use that flag so an
    override is never applied twice. Remaining placeholders are filled with their defaults.
    """
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

    override = None
    if condition_expression:
      override = condition_expression
    elif min_threshold is not None and max_threshold is not None:
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
      min_baseline_days: int = 7,
      hypothesis_goal: Optional[str] = None,
      min_threshold: Optional[float] = None,
      max_threshold: Optional[float] = None,
      condition_expression: Optional[str] = None,
      fusion_threshold_sq: float = 12.25,
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

  @classmethod
  def _prune_unused_metrics_lookups(cls, stage1_content: str, downstream: str) -> str:
    """Removes stage1 `$var = max(metrics.*(...))` outcomes that nothing downstream reads.

    Each metrics.* outcome is a per-entity, per-day lookup. A lookup is kept if the downstream stages
    reference `$stage1_extract.<var>` or another stage1 line references `$<var>`.
    """
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
    """Splits stage1's match variables into MAD grouping keys and keys to drop.

    A match variable is a MAD key when the UDM field it binds is a dimension argument of the stage1
    metrics.* calls (the baseline's identity). Other match variables (e.g. `$ip` on resource_*) would
    split one baseline tuple into several thin series, so they are dropped. Returns (keys, dropped);
    the first key is always the primary match variable.
    """
    m = re.search(r'\bmatch:\s*\n\s*(.*?)\s+by\s+\d+[dh]', stage1_content)
    if not m:
      return [], []
    match_vars = [v.strip() for v in m.group(1).split(",") if v.strip()]
    dims = set(re.findall(r'^\s*([a-z][a-zA-Z0-9_.]*)\s*:\s*\1\s*,?\s*$', stage1_content, re.M))
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
      anomaly_threshold: float = 3.0,
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
      fold_change_threshold: float = 2.0,
      robust_threshold: float = 3.5,
  ) -> str:
    """Renders stage1 extractor + stage2 math model.

    Significance gate: every stage2 model except the Fano factor ships a default root `condition:`
    (sigma models: `>= anomaly_threshold`; ratio models: `>= fold_change_threshold`; MAD:
    `$modified_z >= robust_threshold`). min_threshold / max_threshold / condition_expression replace
    that default gate. apply_threshold_condition is retained for backward compatibility and no longer
    changes the output: the default gate is always applied.

    scoring_days applies to StatisticalModel.MAD only: the raw search window is the robust baseline
    (~30d), so the number of most-recent days actually scored is set explicitly (Mode A: 1, Mode B
    default: 7), ending at scoring_end_date (UTC YYYY-MM-DD; default today). The gate is a date
    string rendered into stage1 ($in_scoring_window), never wall-clock time or an epoch literal.
    """
    audit = PreFlightValidator.audit(
        target_metric=target_metric,
        entity_type=entity_type,
        min_baseline_days=min_baseline_days,
        match_mode=match_mode,
        identifier_field=identifier_field,
    )

    if isinstance(statistical_model, str):
      norm_model = statistical_model.strip().upper().replace("-", "_").replace(" ", "_")
      if norm_model in ("SILENCE_DETECTION", "DROP_OUT", "SILENCE", "DROPOUT"):
        raise ValueError(
            f"Statistical model '{statistical_model}' (silence / drop-out detection) is not supported: "
            "metrics.* and match ... by 1d emit no zero-count buckets, so lower-tail silence "
            "detection is not supported until a zero-day-aware lower-tail detector exists."
        )
      if norm_model in ("BEACON_REGULARITY", "JITTER", "BEACON", "C2_BEACONING_JITTER", "C2_JITTER"):
        raise ValueError(
            f"Statistical model '{statistical_model}' requires sub-hour inter-arrival timing on raw UDM telemetry; "
            "hand off to 'secops-statistical-hunter' model 'C2_BEACONING_JITTER' instead of rendering "
            "daily COEFFICIENT_OF_VARIATION."
        )

    # Enforce Local-Baseline Isolation: multi-database account queries must route to CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH.
    # An explicit MAD request is exempt: MAD groups by the full (user, vendor, product, resource) baseline tuple,
    # which already isolates each repository's baseline.
    if target_metric.startswith("resource_") and entity_type == EntityType.USER and statistical_model not in (StatisticalModel.MAD, StatisticalModel.QUANTILE_IQR_SKEW):
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
      )

    stage1_path = self.template_dir / "stage1_extractors" / f"{target_metric}.yl2"
    if not stage1_path.exists():
      raise FileNotFoundError(f"Missing Stage 1 template: {stage1_path}")
    stage1_content = self._rebind_entity_field(
        self._strip_identifier_swap_note(stage1_path.read_text().strip()), target_metric, audit["target_field"])

    model_key = statistical_model
    if isinstance(statistical_model, str):
      raw_key = statistical_model.strip()
      lower_key = raw_key.lower()
      alias_enum_map = {
          "hourly_zscore": StatisticalModel.HOURLY_TEMPORAL_ZSCORE,
          "hourly_temporal_zscore": StatisticalModel.HOURLY_TEMPORAL_ZSCORE,
          "longitudinal_cusum": StatisticalModel.LONGITUDINAL_CUSUM,
          "macd_momentum": StatisticalModel.MACD_MOMENTUM_VELOCITY,
          "macd_momentum_velocity": StatisticalModel.MACD_MOMENTUM_VELOCITY,
          "standard_z_score": StatisticalModel.STANDARD_Z_SCORE,
          "mad": StatisticalModel.MAD,
          "poisson": StatisticalModel.POISSON,
          "variance": StatisticalModel.VARIANCE,
          "relative_deviation": StatisticalModel.RELATIVE_DEVIATION,
          "coefficient_of_variation": StatisticalModel.COEFFICIENT_OF_VARIATION,
          "bayesian_gamma": StatisticalModel.BAYESIAN_GAMMA,
          "bayesian_beta_binomial": StatisticalModel.BAYESIAN_BETA_BINOMIAL,
          "two_part_hurdle": StatisticalModel.TWO_PART_HURDLE,
          "asymmetric_directional_z": StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z,
          "piecewise_cri": StatisticalModel.PIECEWISE_CRI,
          "fleet_prevalence_shield": StatisticalModel.FLEET_PREVALENCE_SHIELD,
          "adaptive_context_threshold": StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD,
          "circadian_von_mises": StatisticalModel.CIRCADIAN_VON_MISES,
          "quantile_iqr_skew": StatisticalModel.QUANTILE_IQR_SKEW,
          "bowley_skew": StatisticalModel.QUANTILE_IQR_SKEW,
          "tukey_fence": StatisticalModel.QUANTILE_IQR_SKEW,
          "tukey_skew_fence": StatisticalModel.QUANTILE_IQR_SKEW,
      }
      if lower_key in alias_enum_map:
        statistical_model = alias_enum_map[lower_key]
        model_key = statistical_model
      else:
        for m_enum in StatisticalModel:
          if raw_key in (m_enum.name, m_enum.value) or lower_key == m_enum.name.lower():
            statistical_model = m_enum
            model_key = m_enum
            break
        else:
          model_key = lower_key

    stage2_file = self.STAGE2_TEMPLATES.get(model_key) or self.STAGE2_TEMPLATES.get(statistical_model)
    if not stage2_file:
      raise ValueError(f"Unsupported statistical model: {statistical_model}")
    stage2_path = self.template_dir / "stage2_math_models" / stage2_file
    if not stage2_path.exists() and stage2_file in self.STAGE2_FALLBACK_TEMPLATES:
      stage2_file = self.STAGE2_FALLBACK_TEMPLATES[stage2_file]
      stage2_path = self.template_dir / "stage2_math_models" / stage2_file
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
      # Multi-stage modules (e.g. MAD's mad_center / mad_spread) reference sibling stages' match field too.
      stage2_raw = re.sub(r'(\$[a-zA-Z0-9_]+)\.entity\b', rf'\1.{entity_name}', stage2_raw)

    if statistical_model == StatisticalModel.CIRCADIAN_VON_MISES:
      if "$event_hour" not in stage1_content:
        stage1_content = re.sub(
            r'(outcome:\s*\n)',
            r'\1    $event_hour = max(timestamp.get_hour(metadata.event_timestamp.seconds))\n',
            stage1_content,
            count=1,
        )
      stage1_content = re.sub(r'(\bmatch:\s*\n\s*[$][a-zA-Z0-9_]+\s+by)\s+1d', r'\1 1h', stage1_content)

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
            r'(outcome:\s*\n)',
            r'\1    $in_scoring_window = max(if(timestamp.get_date(metadata.event_timestamp.seconds) >= "{{first_scored_date}}", 1, 0))\n',
            stage1_content,
            count=1,
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
      # Multi-key extractors: group every MAD stage by the metric's full baseline tuple.
      mad_keys, dropped_keys = self._mad_group_keys(stage1_content)
      stage1_content = self._drop_stage1_match_keys(stage1_content, dropped_keys)
      stage2_raw = self._expand_mad_keys(stage2_raw, primary_var, mad_keys[1:])
      # MAD itself never reads metrics.*; keep only the lookups the root consumes (Z cross-check).
      stage1_content = self._prune_unused_metrics_lookups(stage1_content, stage2_raw)
    elif match_mode == MatchMode.FLEET_ROLLUP:
      stage2_raw = stage2_raw.replace(f"match:\n  {primary_var}, $ws by 1d", f"match:\n  {primary_var}")
      stage2_raw = stage2_raw.replace(f"match:\n  {primary_var}, $ws by 1h", f"match:\n  {primary_var}")
      stage2_raw = stage2_raw.replace("$ws = $stage1_extract.window_start\n", "")

    stage2_rendered = stage2_raw.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))

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
    )
    gate = self.root_condition(stage2_rendered)

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
        f"// Significance Gate: {gate or 'NONE (model has no significance threshold; see template NO-GATE note)'}\n"
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
      fold_change_threshold: float = 2.0,
      fusion_threshold_sq: float = 12.25,
  ) -> str:
    """Renders 3-Stage and 4-Stage advanced DAG pipelines, then resolves the root significance gate.

    Pipelines whose template carries a default gate placeholder (see GATE_PLACEHOLDERS) get it filled
    here, and min_threshold / max_threshold / condition_expression replace that default gate.
    Renderers that resolve their own gate (sector fusion, the hybrid_metric_* family) are left as is.
    """
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
    )
    return self._apply_significance_gate(
        rendered,
        anomaly_threshold=anomaly_threshold,
        fold_change_threshold=fold_change_threshold,
        fusion_threshold_sq=fusion_threshold_sq,
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        condition_expression=condition_expression,
        only_if_template_gate=True,
    )

  def _render_pipeline(
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
      fusion_threshold_sq: float = 12.25,
  ) -> str:
    """Renders 3-Stage and 4-Stage advanced DAG pipelines (gate placeholders left for build_pipeline_query)."""
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
      if target_metric and not (target_metric == "http_queries_fail" and entity_type == EntityType.ASSET and not identifier_field):
        return self.build_failure_ratio_surge_query(
            fail_metric=target_metric,
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
      rendered = rendered.replace(
          "{{target_metric_func_avg}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, principal.asset.hostname: principal.asset.hostname, {domain_field}: {domain_field})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, principal.asset.hostname: principal.asset.hostname, {domain_field}: {domain_field})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, principal.asset.hostname: principal.asset.hostname, {domain_field}: {domain_field})"
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
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, principal.asset.hostname: principal.asset.hostname, {domain_field}: {domain_field})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, principal.asset.hostname: principal.asset.hostname, {domain_field}: {domain_field})"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, principal.asset.hostname: principal.asset.hostname, {domain_field}: {domain_field})"
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
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: avg, principal.asset.hostname: principal.asset.hostname)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_stddev}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: stddev, principal.asset.hostname: principal.asset.hostname)"
      )
      rendered = rendered.replace(
          "{{target_metric_func_active_days}}",
          f"metrics.{target_metric}(period: 1d, window: 30d, {metric_type_arg}, agg: num_metric_periods, principal.asset.hostname: principal.asset.hostname)"
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
        "    $fail_z = ($failed_obs - $hist_fail_avg) / if($hist_fail_stddev > 0, $hist_fail_stddev, 1.0)\n"
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
        "  $observed_fails = max($stage1_http_failure_surge.failed_obs)\n"
        "  $total_events = max($stage2_total_traffic.total_obs)\n"
        "  $fail_ratio = $observed_fails / ($total_events + 0.001)\n"
        "  $recon_score = $fail_z * $fail_ratio\n\n"
        "condition:\n"
        f"  $fail_z >= {anomaly_threshold}\n"
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
        "    $flow_z = ($observed_flows - $hist_flow_avg) / if($hist_flow_stddev > 0, $hist_flow_stddev, 1.0)\n"
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
  ) -> str:
    """Builds a 2-Stage Security & EDR Alert Surge pipeline for metrics.alert_event_name_count.

    Supports host-level roll-ups (PRINCIPAL_DEVICE + SECURITY_RESULT_RULE_NAME) and user+host+process
    compound attribution (PRINCIPAL_DEVICE + PRINCIPAL_USER + PRINCIPAL_PROCESS_FILE_HASH + SECURITY_RESULT_RULE_NAME).
    """
    metric_name = "alert_event_name_count"
    filter_block = "\n    ".join(mc.baseline_semantics(metric_name).observed_filter)
    goal_line = f"// Goal: {hypothesis_goal}\n" if hypothesis_goal else ""
    if entity_type == EntityType.USER:
      return (
          f"{goal_line}// Purpose: Hunt for user-attributed EDR & security alert surges across host and process context\n"
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
          "    $d_z = ($d_obs - $d_mu) / if($d_sigma > 0, $d_sigma, 1.0)\n"
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
          "condition:\n"
          f"  $alert_z >= {anomaly_threshold}\n\n"
          "order:\n"
          "  $alert_z desc\n"
      )
    return (
        f"{goal_line}// Purpose: Hunt for host-level EDR & security alert surges across distinct rule names\n"
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
        "    $d_z = ($d_obs - $d_mu) / if($d_sigma > 0, $d_sigma, 1.0)\n"
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
        "condition:\n"
        f"  $alert_z >= {anomaly_threshold}\n\n"
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

  def build_rare_destination_ecg_query(
      self,
      target_metric: str = "network_bytes_outbound",
      entity_type: EntityType = EntityType.ASSET,
      anomaly_threshold: float = 3.0,
      hypothesis_goal: Optional[str] = None,
  ) -> str:
    """Builds a verified 3-Stage Rare Destination ECG Filter pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.RARE_DESTINATION_ECG_3STAGE,
        target_metric=target_metric,
        entity_type=entity_type,
        anomaly_threshold=anomaly_threshold,
        hypothesis_goal=hypothesis_goal,
    )

  def build_fusion_rare_destination_query(
      self,
      target_metrics: Optional[List[str]] = None,
      entity_type: EntityType = EntityType.ASSET,
      fusion_threshold_sq: float = 12.25,
      hypothesis_goal: Optional[str] = None,
  ) -> str:
    """Builds a verified 3-Stage Sector Fusion + Rare Destination ECG Filter pipeline."""
    return self.build_pipeline_query(
        PipelineArchitecture.FUSION_RARE_DESTINATION_3STAGE,
        target_metrics=target_metrics,
        entity_type=entity_type,
        fusion_threshold_sq=fusion_threshold_sq,
        hypothesis_goal=hypothesis_goal,
    )

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
          statistical_model=StatisticalModel.PIECEWISE_CRI,
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
