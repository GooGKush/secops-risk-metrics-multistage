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
        "mandatory_vars": ["$personal_diff", "$dispersion_floor", "$safe_stddev", "$personal_z"],
        "order_var": "$personal_z",
        "required_ops": [
            "$personal_diff = $observed - $hist_avg",
            "$safe_stddev = if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)",
        ],
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
        "mandatory_vars": ["$safe_hist_avg", "$dev", "$ratio", "$fold_change", "$rel_dev_z_equiv"],
        "order_var": "$ratio",
        "required_ops": [
            "$safe_hist_avg = if($hist_avg > 1.0, $hist_avg, 1.0)",
            "$dev = $observed - $safe_hist_avg",
            "$ratio = $dev / $safe_hist_avg",
            "$fold_change = $observed / $safe_hist_avg",
            "$rel_dev_z_equiv = if($raw_z_equiv > 0.0, $raw_z_equiv, 0.0)",
        ],
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
        "mandatory_vars": ["$diff", "$safe_lambda", "$fano_cal", "$safe_poisson_sd", "$sqrt_lambda", "$poisson_z"],
        "order_var": "$poisson_z",
        "required_ops": [
            "$fano_cal = $var_cal / $safe_lambda",
            "$safe_poisson_sd = math.sqrt($eff_var)",
            "$poisson_z = $diff / $safe_poisson_sd",
        ],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.COEFFICIENT_OF_VARIATION: {
        "template": "coefficient_of_variation.yl2",
        "mandatory_vars": ["$safe_hist_avg", "$cv", "$surge_ratio"],
        "order_var": "$surge_ratio",
        "required_ops": ["$cv = $hist_stddev / $safe_hist_avg", "$surge_ratio = $observed / $safe_hist_avg"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.BAYESIAN_GAMMA: {
        "template": "poisson_gamma_bayesian.yl2",
        "mandatory_vars": [
            "$mu_cal",
            "$var_cal",
            "$excess_var",
            "$posterior_rate",
            "$post_rate_var",
            "$cred_w",
            "$pred_var",
            "$safe_pred_sd",
            "$bayesian_z",
        ],
        "order_var": "$bayesian_z",
        "required_ops": [
            "$posterior_rate = $post_alpha_pre / $post_beta_pre",
            "$pred_var = $posterior_rate + $post_rate_var + ($cred_w * $excess_var)",
            "$bayesian_z = ($observed - $posterior_rate) / $safe_pred_sd",
        ],
        "prohibited_substitutions": ["$personal_z", "$bayes_shift_ratio"],
    },
    StatisticalModel.BAYESIAN_BETA_BINOMIAL: {
        "template": "beta_binomial_bayesian.yl2",
        "mandatory_vars": [
            "$obs_fail",
            "$obs_total",
            "$hist_fail_sum",
            "$hist_total_sum",
            "$prior_fail_rate",
            "$posterior_fail_rate",
            "$posterior_rate",
            "$pred_mean",
            "$pred_var",
            "$safe_pred_sd",
            "$beta_binomial_z",
        ],
        "order_var": "$beta_binomial_z",
        "required_ops": [
            "$posterior_fail_rate = ($alpha_pre + $obs_fail) / ($ab + $obs_total)",
            "$beta_binomial_z = ($obs_fail - $pred_mean) / $safe_pred_sd",
        ],
        "prohibited_substitutions": ["$personal_z", "$posterior_lift"],
    },
    StatisticalModel.LONGITUDINAL_CUSUM: {
        "template": "longitudinal_cusum.yl2",
        "mandatory_vars": [
            "$raw_drift",
            "$safe_stddev",
            "$slack_allowance",
            "$slack_excess",
            "$daily_excess",
            "$cusum_drift",
            "$windowed_slack_sum",
            "$cusum_drift_score",
            "$drift_days",
        ],
        "order_var": "$cusum_drift_score",
        "required_ops": [
            "0.5 * $safe_stddev",
            "$slack_excess = $raw_drift - $slack_allowance",
            "$daily_excess = if($active_days >=",
            "$cusum_drift = sum($stage2_daily_drift.daily_excess)",
            "$windowed_slack_sum = $cusum_drift",
            "$cusum_drift_score = $cusum_drift",
        ],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.TWO_PART_HURDLE: {
        "template": "two_part_hurdle.yl2",
        "mandatory_vars": ["$is_dormant_awakening", "$raw_diff", "$safe_stddev", "$intensity_z", "$obs_plus_one", "$log_obs", "$dormant_score", "$hurdle_threat_score"],
        "order_var": "$hurdle_threat_score",
        "required_ops": ["$is_dormant_awakening = if($active_days <= 2 and $observed > 0", "$dormant_score = 10.0 + $log_obs", "$hurdle_threat_score = if($active_days <= 2"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z: {
        "template": "standard_z_score.yl2",
        "mandatory_vars": ["$personal_diff", "$safe_stddev", "$personal_z"],
        "order_var": "$personal_z",
        "required_ops": [
            "$personal_diff = $observed - $hist_avg",
            "$safe_stddev = if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)",
        ],
        "prohibited_substitutions": [],
    },
    StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD: {
        "template": "adaptive_context_threshold.yl2",
        "mandatory_vars": ["$raw_diff", "$safe_stddev", "$personal_z", "$sparse_threshold", "$mature_threshold", "$effective_threshold", "$sensitivity_excess"],
        "order_var": "$sensitivity_excess",
        "required_ops": ["$effective_threshold = if($active_days < 7, $sparse_threshold, $mature_threshold)", "$sensitivity_excess = $personal_z - $effective_threshold"],
        "prohibited_substitutions": [],
    },
    StatisticalModel.MACD_MOMENTUM_VELOCITY: {
        "template": "macd_momentum_velocity.yl2",
        "mandatory_vars": [
            "$personal_diff",
            "$safe_stddev",
            "$personal_z",
            "$exceed_raw",
            "$exceed_pos",
            "$above_max_z",
            "$macd_z",
            "$macd_momentum_score",
        ],
        "order_var": "$macd_z",
        "required_ops": [
            "$personal_diff = $observed - $hist_avg",
            "$exceed_raw = $observed - $hist_max",
            "$above_max_z = $exceed_pos / $safe_stddev",
            "$macd_z = $personal_z + $above_max_z",
        ],
        "prohibited_substitutions": ["$ratio"],
    },
    StatisticalModel.QUANTILE_IQR_SKEW: {
        "template": "quantile_iqr_skew.yl2",
        "mandatory_vars": [
            "$q25_val",
            "$q50_val",
            "$q75_val",
            "$iqr",
            "$safe_iqr",
            "$bowley_skew",
            "$tail_heaviness",
            "$adj_upper_fence",
            "$robust_scale",
            "$tukey_excess_z",
            "$personal_z",
            "$raw_active_days",
            "$in_scoring_window",
        ],
        "order_var": "$tukey_excess_z",
        "required_ops": [
            "window.percentile($stage1_extract.observed_val, 25)",
            "window.percentile($stage1_extract.observed_val, 50)",
            "window.percentile($stage1_extract.observed_val, 75)",
            "$bowley_skew = ($q75_val + $q25_val - (2.0 * $q50_val)) / $safe_iqr",
            "1.35 *",
            "$robust_scale = $safe_iqr / 1.349",
            "$tukey_excess_z = ($observed - $adj_upper_fence) / $robust_scale",
        ],
        "prohibited_substitutions": ["$personal_z", "$ratio"],
    },
}

RETIRED_MODEL_CONTRACTS = {
    StatisticalModel.HOURLY_TEMPORAL_ZSCORE: {
        "removed_template": "hourly_temporal_zscore.yl2",
        "replacement": "HOUR_OF_DAY_PROFILE",
    },
    StatisticalModel.CIRCADIAN_VON_MISES: {
        "removed_template": "circadian_von_mises.yl2",
        "replacement": "HOUR_OF_DAY_PROFILE",
    },
    StatisticalModel.PIECEWISE_CRI: {
        "removed_template": "piecewise_cri.yl2",
        "replacement": "ueba_constants.calculate_cri",
    },
    StatisticalModel.FLEET_PREVALENCE_SHIELD: {
        "removed_template": "fleet_prevalence_shield.yl2",
        "replacement": "hybrid_metric_fleet_prevalence_2stage.yl2",
    },
}


class TestModelConcordance(unittest.TestCase):
  """Validates that active models adhere to AST concordance contracts and retired models fail closed."""

  def setUp(self):
    self.repo_root = Path(__file__).resolve().parent.parent
    self.templates_dir = self.repo_root / "templates" / "stage2_math_models"
    self.router = MultiStageTemplateRouter()

  def test_all_statistical_models_covered_in_contracts(self):
    """Every enum in StatisticalModel must have an active or retired AST contract."""
    for model in StatisticalModel:
      self.assertTrue(
          model in MODEL_AST_CONTRACTS or model in RETIRED_MODEL_CONTRACTS,
          f"Model {model} missing from MODEL_AST_CONTRACTS / RETIRED_MODEL_CONTRACTS",
      )

  def test_retired_models_removed_from_disk_and_rejected_by_router_and_validator(self):
    """WS2-02 (D1): Retired Stage-2 templates must be removed and raise clear replacement errors."""
    from scripts.preflight_validator import MalachiteASTValidator

    for model, spec in RETIRED_MODEL_CONTRACTS.items():
      removed_path = self.templates_dir / spec["removed_template"]
      self.assertFalse(removed_path.exists(), f"Retired template still on disk: {removed_path}")
      with self.assertRaisesRegex(ValueError, rf"retired.*{spec['replacement']}"):
        self.router.build_query(
            target_metric="auth_attempts_total",
            entity_type=EntityType.USER,
            statistical_model=model,
        )
      errs = MalachiteASTValidator.validate_model_concordance("// dummy", model)
      self.assertTrue(
          any("RETIRED" in e.upper() and spec["replacement"] in e for e in errs),
          f"Expected RETIRED error mentioning {spec['replacement']} for {model.value}, got {errs}",
      )
    self.assertFalse(
        (self.repo_root / "templates" / "pipelines" / "circadian_von_mises_2stage.yl2").exists(),
        "Retired circadian_von_mises_2stage.yl2 still on disk",
    )
    self.assertFalse(
        (self.templates_dir / "asymmetric_directional_z.yl2").exists(),
        "Merged asymmetric_directional_z.yl2 must be removed from disk (D1 -> standard_z_score.yl2)",
    )

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
    """WS1-03: MAD/Quantile compute $personal_z from pre-scoring raw active days, keeping only 1 metrics.* lookup (num_metric_periods)."""
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
        self.assertEqual(query.count("metrics."), 1, f"{path.stem}/{mode.value}")
        self.assertIn("$historical_active_days =", query, f"{path.stem}/{mode.value}")
        for dropped in ("$historical_avg =", "$historical_stddev =", "$historical_max =", "$historical_sum ="):
          self.assertNotIn(dropped, query, f"{path.stem}/{mode.value}")
    self.assertEqual(rendered, 2 * len(extractors))
    for pipe_name in ("mad_robust_z_4stage.yl2", "quantile_iqr_skew_3stage.yl2"):
      pipeline = (self.repo_root / "templates" / "pipelines" / pipe_name).read_text()
      self.assertEqual(pipeline.count("metrics.{{target_metric_name}}("), 1, pipe_name)

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

  def test_ws2_07_router_output_passes_validate_model_concordance_for_all_models_and_modes(self):
    """WS2-07: Router build_query output must pass validate_model_concordance and PostFlightExecutionAuditor across all 18 models x modes."""
    from scripts.preflight_validator import MalachiteASTValidator, PostFlightExecutionAuditor

    representative_targets = [
        ("network_bytes_outbound", EntityType.ASSET),
        ("auth_attempts_total", EntityType.USER),
        ("file_executions_total", EntityType.ASSET),
        ("resource_read_total", EntityType.USER),
        ("resource_read_total", EntityType.RESOURCE),
    ]
    for metric, entity_type in representative_targets:
      for model in StatisticalModel:
        if model in RETIRED_MODEL_CONTRACTS:
          with self.assertRaisesRegex(ValueError, "retired"):
            self.router.build_query(
                target_metric=metric,
                entity_type=entity_type,
                statistical_model=model,
            )
          continue
        if model == StatisticalModel.POISSON and metric == "network_bytes_outbound":
          with self.assertRaisesRegex(ValueError, r"POISSON.*event_count_sum|value_sum|byte"):
            self.router.build_query(
                target_metric=metric,
                entity_type=entity_type,
                statistical_model=model,
            )
          continue
        if model == StatisticalModel.BAYESIAN_BETA_BINOMIAL and metric == "network_bytes_outbound":
          with self.assertRaisesRegex(ValueError, r"BAYESIAN_BETA_BINOMIAL.*paired|unpaired|_fail"):
            self.router.build_query(
                target_metric=metric,
                entity_type=entity_type,
                statistical_model=model,
            )
          continue
        for mode in (MatchMode.TIMELINE_BREAKDOWN, MatchMode.FLEET_ROLLUP):
          with self.subTest(metric=metric, entity_type=entity_type.value, model=model.value, mode=mode.value):
            query = self.router.build_query(
                target_metric=metric,
                entity_type=entity_type,
                statistical_model=model,
                match_mode=mode,
                scoring_end_date="2026-10-27",
            )
            concordance_errors = MalachiteASTValidator.validate_model_concordance(query, model)
            self.assertEqual(
                concordance_errors,
                [],
                f"Router output failed validate_model_concordance for {model.value}/{mode.value}: {concordance_errors}",
            )
            audit_res = PostFlightExecutionAuditor.audit_execution(
                executed_query=query,
                api_response={"stats": {"results": []}},
                target_metric=metric,
                entity_type=entity_type,
                statistical_model=model,
            )
            self.assertTrue(
                audit_res.is_valid,
                f"PostFlightExecutionAuditor rejected router output for {model.value}/{mode.value}: {audit_res.errors}",
            )

  def test_ws2_07_validate_model_concordance_flags_topology_and_quantile_formula_mismatches(self):
    """WS2-07: Dynamic template stage-topology check catches missing/extra stages and QUANTILE_IQR_SKEW formula drift."""
    from scripts.preflight_validator import MalachiteASTValidator

    z_query = self.router.build_query(
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
        statistical_model=StatisticalModel.STANDARD_Z_SCORE,
    )
    cusum_query = self.router.build_query(
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
        statistical_model=StatisticalModel.LONGITUDINAL_CUSUM,
    )

    # Multi-stage Stage-2 models must reject a 1-named-stage query
    for multi_stage_model in (
        StatisticalModel.LONGITUDINAL_CUSUM,
        StatisticalModel.QUANTILE_IQR_SKEW,
        StatisticalModel.MAD,
    ):
      with self.subTest(missing_stage_for=multi_stage_model.value):
        errs = MalachiteASTValidator.validate_model_concordance(z_query, multi_stage_model)
        self.assertTrue(
            any("STAGE_TOPOLOGY_MISMATCH" in e for e in errs),
            f"Expected STAGE_TOPOLOGY_MISMATCH for {multi_stage_model.value}, got {errs}",
        )

    # Single-stage Stage-2 models (including BAYESIAN_GAMMA / BAYESIAN_BETA_BINOMIAL) must reject extra stages
    for single_stage_model in (
        StatisticalModel.STANDARD_Z_SCORE,
        StatisticalModel.BAYESIAN_GAMMA,
        StatisticalModel.BAYESIAN_BETA_BINOMIAL,
    ):
      with self.subTest(extra_stage_for=single_stage_model.value):
        errs = MalachiteASTValidator.validate_model_concordance(cusum_query, single_stage_model)
        self.assertTrue(
            any("STAGE_TOPOLOGY_MISMATCH" in e for e in errs),
            f"Expected STAGE_TOPOLOGY_MISMATCH for {single_stage_model.value}, got {errs}",
        )

    # QUANTILE_IQR_SKEW without window.percentile(...) must trigger MODEL_FORMULA_MISMATCH
    q_query = self.router.build_query(
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
        statistical_model=StatisticalModel.QUANTILE_IQR_SKEW,
        scoring_end_date="2026-10-27",
    )
    broken_quantile = q_query.replace("window.percentile(", "max(")
    q_errs = MalachiteASTValidator.validate_model_concordance(broken_quantile, StatisticalModel.QUANTILE_IQR_SKEW)
    self.assertTrue(
        any("MODEL_FORMULA_MISMATCH" in e for e in q_errs),
        f"Expected MODEL_FORMULA_MISMATCH when window.percentile is missing, got {q_errs}",
    )


if __name__ == "__main__":
  unittest.main()
