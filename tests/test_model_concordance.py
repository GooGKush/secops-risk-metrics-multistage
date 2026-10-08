"""Unit tests for Model Concordance Contracts and AST Signature Verification.

Ensures that all 14 Stage 2 statistical models enforce strict concordance between
the model declared in Phase 1B prose and the AST emitted in YARA-L queries.
"""

from pathlib import Path
import re
import unittest
from scripts.preflight_validator import EntityType, MatchMode, StatisticalModel
from scripts.template_router import MultiStageTemplateRouter

# Authoritative Contract Specification matching references/model-concordance-guide.md
MODEL_AST_CONTRACTS = {
    StatisticalModel.STANDARD_Z_SCORE: {
        "template": "standard_z_score.yl2",
        "mandatory_vars": ["$personal_diff", "$safe_stddev", "$personal_z"],
        "order_var": "$personal_z",
        "required_ops": ["$personal_diff = $observed - $hist_avg", "if($hist_stddev > 0"],
        "prohibited_substitutions": [],
    },
    StatisticalModel.MAD: {
        "template": "mad.yl2",
        "mandatory_vars": ["$median_val", "$mad", "$mean_abs_dev", "$robust_scale", "$safe_robust_scale",
                           "$modified_z", "$personal_z", "$z_gap", "$raw_active_days", "$in_scoring_window"],
        "order_var": "$modified_z",
        "required_ops": [
            "window.median($stage1_extract.observed_val, false)",
            "window.median(math.abs($stage1_extract.observed_val - $mad_center.median_val), false)",
            "$scale_from_mad = $mad / 0.6745",
            "$scale_from_meanad = $mean_abs_dev * 1.253314",
            "$modified_z = ($observed - $median_val) / $safe_robust_scale",
        ],
        "prohibited_substitutions": ["$personal_z", "$ratio"],
    },
    StatisticalModel.RELATIVE_DEVIATION: {
        "template": "relative_deviation.yl2",
        "mandatory_vars": ["$dev", "$safe_hist_avg", "$ratio"],
        "order_var": "$ratio",
        "required_ops": ["$dev = $observed - $hist_avg", "$ratio = $dev / $safe_hist_avg"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.VARIANCE: {
        "template": "variance_fano.yl2",
        "mandatory_vars": ["$variance", "$safe_lambda", "$fano_factor"],
        "order_var": "$fano_factor",
        "required_ops": ["$variance = math.pow($stddev, 2)", "$fano_factor = $variance / $safe_lambda"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.POISSON: {
        "template": "poisson_rarity.yl2",
        "mandatory_vars": ["$diff", "$safe_lambda", "$sqrt_lambda", "$poisson_z"],
        "order_var": "$poisson_z",
        "required_ops": ["math.sqrt($safe_lambda)", "$poisson_z = $diff / $sqrt_lambda"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.COEFFICIENT_OF_VARIATION: {
        "template": "coefficient_of_variation.yl2",
        "mandatory_vars": ["$safe_hist_avg", "$cv", "$surge_ratio"],
        "order_var": "$surge_ratio",
        "required_ops": ["$cv = $hist_stddev / $safe_hist_avg", "$surge_ratio = $observed / $safe_hist_avg"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.HOURLY_TEMPORAL_ZSCORE: {
        "template": "hourly_temporal_zscore.yl2",
        "mandatory_vars": ["$observed_hour", "$avg_hourly", "$hourly_diff", "$safe_stddev_hourly", "$hourly_z", "$hourly_surge_ratio"],
        "order_var": "$hourly_z",
        "required_ops": ["by 1h", "$hourly_diff = $observed_hour - $avg_hourly", "$hourly_z = $hourly_diff / $safe_stddev_hourly"],
        "prohibited_substitutions": [],
    },
    StatisticalModel.BAYESIAN_GAMMA: {
        "template": "poisson_gamma_bayesian.yl2",
        "mandatory_vars": ["$variance_raw", "$safe_variance", "$beta_prior", "$alpha_prior", "$alpha_post", "$beta_post", "$posterior_mean", "$bayes_shift_ratio"],
        "order_var": "$bayes_shift_ratio",
        "required_ops": ["$beta_prior = $avg_30d / $safe_variance", "$alpha_post = $alpha_prior + $observed_24h", "$posterior_mean = $alpha_post / $beta_post"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.BAYESIAN_BETA_BINOMIAL: {
        "template": "beta_binomial_bayesian.yl2",
        "mandatory_vars": ["$avg_fail_prob", "$safe_variance", "$one_minus_p", "$sample_factor", "$alpha_prior", "$beta_prior", "$alpha_post", "$beta_post", "$posterior_fail_prob"],
        "order_var": "$posterior_fail_prob",
        "required_ops": ["$sample_factor =", "$alpha_post = $alpha_prior + $observed_fails", "$posterior_fail_prob = $alpha_post / $safe_total_post"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.LONGITUDINAL_CUSUM: {
        "template": "longitudinal_cusum.yl2",
        "mandatory_vars": ["$raw_drift", "$safe_stddev", "$slack_allowance", "$slack_excess", "$cusum_drift_score"],
        "order_var": "$cusum_drift_score",
        "required_ops": ["0.5 * $safe_stddev", "$slack_excess = $raw_drift - $slack_allowance", "$cusum_drift_score = if($slack_excess > 0"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.TWO_PART_HURDLE: {
        "template": "two_part_hurdle.yl2",
        "mandatory_vars": ["$is_active_today", "$dormant_score", "$diff", "$safe_stddev", "$intensity_z", "$hurdle_threat_score"],
        "order_var": "$hurdle_threat_score",
        "required_ops": ["$is_active_today = if($observed > 0", "$dormant_score = $observed * 2.0", "$hurdle_threat_score = if($active_days <= 2"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z: {
        "template": "asymmetric_directional_z.yl2",
        "mandatory_vars": ["$diff", "$excess_surge", "$safe_stddev", "$upper_tail_z"],
        "order_var": "$upper_tail_z",
        "required_ops": ["$excess_surge = if($diff > 0, $diff, 0.0)", "$upper_tail_z = $excess_surge / $safe_stddev"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.PIECEWISE_CRI: {
        "template": "piecewise_cri.yl2",
        "mandatory_vars": ["$diff", "$safe_stddev", "$raw_z", "$clamped_low", "$clamped_z", "$cri_tier4", "$cri_tier3", "$cri_tier2", "$cri_score"],
        "order_var": "$cri_score",
        "required_ops": ["$clamped_low = if($raw_z < -4.0, -4.0, $raw_z)", "$cri_score = if($clamped_z >= 1.0"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.FLEET_PREVALENCE_SHIELD: {
        "template": "fleet_prevalence_shield.yl2",
        "mandatory_vars": ["$fleet_count", "$diff", "$safe_stddev", "$personal_z", "$prevalence_factor", "$shielded_z"],
        "order_var": "$shielded_z",
        "required_ops": ["$fleet_count = count(", "$prevalence_factor = if($fleet_count > 10, 0.15, 1.0)", "$shielded_z = $personal_z * $prevalence_factor"],
        "prohibited_substitutions": [],
    },
    StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD: {
        "template": "adaptive_context_threshold.yl2",
        "mandatory_vars": ["$diff", "$safe_stddev", "$personal_z", "$is_off_hours", "$dynamic_threshold", "$sensitivity_excess"],
        "order_var": "$sensitivity_excess",
        "required_ops": ["$is_off_hours = if($active_days <= 5", "$dynamic_threshold = if($is_off_hours > 0, 1.75, 3.00)", "$sensitivity_excess = $personal_z - $dynamic_threshold"],
        "prohibited_substitutions": [],
    },
    StatisticalModel.MACD_MOMENTUM_VELOCITY: {
        "template": "macd_momentum_velocity.yl2",
        "mandatory_vars": ["$fast_diff", "$safe_stddev", "$fast_z", "$slow_diff", "$slow_z", "$macd_diff", "$safe_max", "$velocity_ratio", "$scaled_diff", "$macd_momentum_score"],
        "order_var": "$macd_momentum_score",
        "required_ops": ["$fast_diff = $observed - $hist_avg", "$slow_diff = $hist_max - $hist_avg", "$macd_diff = $fast_z - $slow_z", "$macd_momentum_score = if($macd_diff > 0"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.CIRCADIAN_VON_MISES: {
        "template": "circadian_von_mises.yl2",
        "mandatory_vars": ["$hourly_diff", "$safe_stddev_hourly", "$hourly_z", "$event_hour", "$raw_diff", "$inverted_dist", "$circ_dist", "$von_mises_arc", "$temporal_penalty", "$temporal_multiplier", "$circadian_threat_score"],
        "order_var": "$circadian_threat_score",
        "required_ops": ["by 1h", "max($stage1_extract.event_hour)", "$circ_dist = if($raw_diff > 12", "math.pow($circ_dist, 2)", "$temporal_penalty = $von_mises_arc / 72.0"],
        "prohibited_substitutions": ["$personal_z"],
    },
}


class TestModelConcordance(unittest.TestCase):
  """Validates that all 16 models adhere to their AST concordance contracts."""

  def setUp(self):
    self.repo_root = Path(__file__).resolve().parent.parent
    self.templates_dir = self.repo_root / "templates" / "stage2_math_models"
    self.router = MultiStageTemplateRouter()

  def test_all_statistical_models_covered_in_contracts(self):
    """Every enum in StatisticalModel must have an explicit AST contract."""
    for model in StatisticalModel:
      self.assertIn(model, MODEL_AST_CONTRACTS, f"Model {model} missing from MODEL_AST_CONTRACTS")

  def test_templates_exist_and_match_contract_definitions(self):
    """Each template file must exist and satisfy all mandatory AST contract items."""
    for model, contract in MODEL_AST_CONTRACTS.items():
      template_file = self.templates_dir / contract["template"]
      self.assertTrue(template_file.exists(), f"Missing template file: {template_file}")
      content = template_file.read_text()

      # Verify mandatory outcome variables
      for var in contract["mandatory_vars"]:
        self.assertIn(var, content, f"Model {model.value} template missing mandatory variable {var}")

      # Verify order clause
      expected_order = "order:\n  " + contract["order_var"] + " desc"
      self.assertIn(expected_order, content, f"Model {model.value} missing correct order clause for {contract['order_var']}")

      # Verify required operations
      for op in contract["required_ops"]:
        self.assertIn(op, content, f"Model {model.value} missing required operation: {op}")

  def test_router_emits_concordant_ast_for_all_models(self):
    """Router build_query must emit concordant ASTs containing mandatory variables for all 14 models."""
    target_metric = "auth_attempts_success"
    entity_type = EntityType.USER

    for model, contract in MODEL_AST_CONTRACTS.items():
      query = self.router.build_query(
          target_metric=target_metric,
          entity_type=entity_type,
          statistical_model=model,
          anomaly_threshold=3.0,
      )

      # Assert mandatory variables exist in the emitted query
      for var in contract["mandatory_vars"]:
        self.assertIn(var, query, f"Emitted query for {model.value} does not contain {var}")

      # Assert order clause matches contract
      self.assertIn(f"{contract['order_var']} desc", query, f"Emitted query for {model.value} does not order by {contract['order_var']}")

      # Anti-Degradation check: non-standard models must not emit univariate standard Z fallback
      for prohibited in contract["prohibited_substitutions"]:
        prohibited_order = "order:\n  " + prohibited + " desc"
        self.assertNotIn(prohibited_order, query, f"Emitted query for {model.value} degraded to standard {prohibited} ordering")

  def test_mad_rebinds_every_stage_member_to_the_stage1_match_variable(self):
    """MAD's sibling stages must use .user/.host when stage1 matches on $user/$host (no stray .entity)."""
    router = MultiStageTemplateRouter()
    query = router.build_query("auth_attempts_total", EntityType.USER, StatisticalModel.MAD,
                               match_mode=MatchMode.FLEET_ROLLUP, scoring_end_date="2026-10-07")
    self.assertNotIn(".entity", query)
    self.assertIn("$user = $mad_center.user", query)
    self.assertIn("$user = $mad_spread.user", query)
    # Mode A keeps the daily root (median needs the daily series) and scores only the end date.
    self.assertIn("$user, $ws by 1d", query)
    self.assertIn('>= "2026-10-07", 1, 0))', query)
    self.assertIn("$in_scoring_window = 1", query)

  def test_mad_mode_b_scoring_window_and_condition_merge(self):
    router = MultiStageTemplateRouter()
    query = router.build_query("network_bytes_outbound", EntityType.ASSET, StatisticalModel.MAD,
                               match_mode=MatchMode.TIMELINE_BREAKDOWN, scoring_days=3,
                               scoring_end_date="2026-10-07", min_threshold=3.5)
    self.assertIn('>= "2026-10-05", 1, 0))', query)
    self.assertEqual(query.count("condition:"), 1, "threshold must be AND-ed into the module's own condition")
    self.assertIn("$in_scoring_window = 1 and $raw_active_days >= 7 and $modified_z >= 3.5", query)
    self.assertNotIn("timestamp.current_seconds()", query)

  def test_mad_renders_only_the_metrics_lookups_its_root_reads(self):
    """MAD scores from raw daily values; metrics.* only feeds the Z cross-check (avg, stddev, active days)."""
    router = MultiStageTemplateRouter()
    extractors = sorted((self.repo_root / "templates" / "stage1_extractors").glob("*.yl2"))
    self.assertTrue(extractors)
    rendered = 0
    for path in extractors:
      for mode in (MatchMode.FLEET_ROLLUP, MatchMode.TIMELINE_BREAKDOWN):
        query = None
        for entity in (EntityType.ASSET, EntityType.USER):
          try:
            query = router.build_query(path.stem, entity, StatisticalModel.MAD, match_mode=mode,
                                       scoring_end_date="2026-10-07")
            break
          except ValueError:
            continue
        self.assertIsNotNone(query, f"{path.stem}: no valid entity type")
        self.assertIn("stage mad_center", query, f"{path.stem}/{mode.value}")
        rendered += 1
        self.assertEqual(query.count("metrics."), 3, f"{path.stem}/{mode.value}")
        for kept in ("$historical_avg =", "$historical_stddev =", "$historical_active_days ="):
          self.assertIn(kept, query, f"{path.stem}/{mode.value}")
        for dropped in ("$historical_max =", "$historical_sum ="):
          self.assertNotIn(dropped, query, f"{path.stem}/{mode.value}")
    self.assertEqual(rendered, 2 * len(extractors))
    pipeline = (self.repo_root / "templates" / "pipelines" / "mad_robust_z_4stage.yl2").read_text()
    self.assertEqual(pipeline.count("metrics.{{target_metric_name}}("), 3)

  def test_mad_groups_every_stage_by_the_same_baseline_tuple(self):
    """stage1, mad_center, mad_spread and root must share one key list (root adds only $ws)."""
    router = MultiStageTemplateRouter()
    for path in sorted((self.repo_root / "templates" / "stage1_extractors").glob("*.yl2")):
      query = None
      for entity in (EntityType.ASSET, EntityType.USER):
        try:
          query = router.build_query(path.stem, entity, StatisticalModel.MAD, scoring_end_date="2026-10-07")
          break
        except ValueError:
          continue
      matches = [m.strip() for m in re.findall(r"\bmatch:\s*\n\s*([^\n]+)", query)]
      self.assertEqual(len(matches), 4, path.stem)
      stage1_keys = re.sub(r"\s+by\s+1d$", "", matches[0])
      self.assertEqual(matches[1], stage1_keys, path.stem)
      self.assertEqual(matches[2], stage1_keys, path.stem)
      self.assertEqual(matches[3], f"{stage1_keys}, $ws by 1d", path.stem)
      for key in stage1_keys.split(", "):
        name = key.lstrip("$")
        for stage in ("stage1_extract", "mad_center", "mad_spread"):
          self.assertIn(f"{key} = ${stage}.{name}", query, f"{path.stem}: {key} not joined to {stage}")

  def test_mad_multi_key_extractors_use_metric_dimensions_only(self):
    router = MultiStageTemplateRouter()
    expected = {
        ("resource_read_total", EntityType.USER): "$sa, $vendor, $product, $resource",
        ("resource_written_fail", EntityType.USER): "$sa, $vendor, $product, $resource",
        ("file_executions_total", EntityType.ASSET): "$host, $sha256",
        ("alert_event_name_count", EntityType.ASSET): "$host, $rule_name",
    }
    for (metric, entity), keys in expected.items():
      query = router.build_query(metric, entity, StatisticalModel.MAD, scoring_end_date="2026-10-07")
      self.assertIn(f"match:\n    {keys} by 1d", query, metric)
      self.assertIn(f"match:\n  {keys}, $ws by 1d", query, metric)
      # $ip is not a baseline dimension: it would split one baseline tuple into per-IP series.
      self.assertNotIn("$ip", query, metric)

  def test_cloud_repository_redirect_still_applies_to_non_mad_models(self):
    router = MultiStageTemplateRouter()
    query = router.build_query("resource_read_total", EntityType.USER, StatisticalModel.STANDARD_Z_SCORE)
    self.assertNotIn("mad_center", query)
    self.assertIn("DUAL-BRANCH CLOUD REPOSITORY SCOPE", query)

  def test_non_mad_models_keep_all_five_metrics_lookups(self):
    router = MultiStageTemplateRouter()
    query = router.build_query("network_bytes_outbound", EntityType.ASSET, StatisticalModel.STANDARD_Z_SCORE)
    self.assertEqual(query.count("metrics."), 5)

  def test_mad_never_ignores_zero_values(self):
    """window.median's 2nd arg is should_ignore_zero_values; `true` drops zero deviations and inflates MAD."""
    root = Path(__file__).resolve().parent.parent
    for rel in ("templates/stage2_math_models/mad.yl2", "templates/pipelines/mad_robust_z_4stage.yl2"):
      text = (root / rel).read_text()
      code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("//"))
      calls = re.findall(r"window\.median\((.*)\)", code)
      self.assertEqual(len(calls), 2, rel)
      for call in calls:
        self.assertTrue(call.rstrip().endswith("false"), f"{rel}: window.median must pass false: {call}")

  def test_guide_documents_all_14_models(self):
    """The references/model-concordance-guide.md must document all 14 models."""
    guide_path = self.repo_root / "references" / "model-concordance-guide.md"
    self.assertTrue(guide_path.exists(), "references/model-concordance-guide.md does not exist")
    content = guide_path.read_text()

    for model in StatisticalModel:
      self.assertIn(model.value, content, f"Guide missing coverage for {model.value}")


if __name__ == "__main__":
  unittest.main()
