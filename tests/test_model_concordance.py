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
        "mandatory_vars": ["$dev", "$safe_hist_avg", "$ratio"],
        "order_var": "$ratio",
        "required_ops": ["$dev = $observed - $hist_avg", "$ratio = $dev / $safe_hist_avg"],
        "prohibited_substitutions": ["$personal_z"],
    },
    StatisticalModel.VARIANCE: {
        "template": "variance_fano.yl2",
        "mandatory_vars": ["$variance", "$safe_lambda", "$fano_factor"],
        "order_var": "$fano_factor",
        "required_ops": ["$variance = $stddev * $stddev", "$fano_factor = $variance / $safe_lambda"],
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
}


class TestModelConcordance(unittest.TestCase):
  """Validates that all 14 models adhere to their AST concordance contracts."""

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

  def test_guide_documents_all_14_models(self):
    """The references/model-concordance-guide.md must document all 14 models."""
    guide_path = self.repo_root / "references" / "model-concordance-guide.md"
    self.assertTrue(guide_path.exists(), "references/model-concordance-guide.md does not exist")
    content = guide_path.read_text()

    for model in StatisticalModel:
      self.assertIn(model.value, content, f"Guide missing coverage for {model.value}")


if __name__ == "__main__":
  unittest.main()
