"""Root significance gate contract.

Every score-producing template must carry its model's significance gate as a root `condition:`
between `outcome:` and `order:`, so the Pre-Flight card's `Significance Threshold` is actually
enforced by the query. The only ungated templates are the Fano factor (its score does not depend on
the scored day) and the 360 radar sector micro-queries (every sector must be reported).
"""

from pathlib import Path
import re
import unittest

from scripts.preflight_validator import (
    DEFAULT_SIGNIFICANCE_GATES,
    EntityType,
    PipelineArchitecture,
    PreFlightValidator,
    StatisticalModel,
    default_significance_threshold,
)
from scripts.template_router import MultiStageTemplateRouter

SKILL_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = SKILL_ROOT / "templates"
ROOT_CONDITION = re.compile(r"^condition:[ \t]*\n(.+?)\n[ \t]*\n^order:", re.M | re.S)

NO_GATE_TEMPLATES = {
    "stage2_math_models/variance_fano.yl2",
    "pipelines/radar_360_decoupled_sector.yl2",
    "pipelines/radar_360_sector_alert.yl2",
    "pipelines/radar_360_sector_web_http.yl2",
}

RETIRED_GATE_MODELS = {
    StatisticalModel.HOURLY_TEMPORAL_ZSCORE: "HOUR_OF_DAY_PROFILE",
    StatisticalModel.CIRCADIAN_VON_MISES: "HOUR_OF_DAY_PROFILE",
    StatisticalModel.PIECEWISE_CRI: "ueba_constants.calculate_cri",
    StatisticalModel.FLEET_PREVALENCE_SHIELD: "hybrid_metric_fleet_prevalence_2stage.yl2",
}

RETIRED_GATE_PIPELINES = {
    PipelineArchitecture.CIRCADIAN_VON_MISES_2STAGE: "HOUR_OF_DAY_PROFILE",
}

# Default root gate each active model renders with router defaults (sigma 3.0, fold change 2.0, MAD 3.5).
EXPECTED_DEFAULT_GATES = {
    StatisticalModel.STANDARD_Z_SCORE: "$active_days >= 7 and $personal_z >= 3.0",
    StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z: "$active_days >= 7 and $personal_z >= 3.0",
    StatisticalModel.POISSON: "$poisson_z >= 3.0",
    StatisticalModel.MACD_MOMENTUM_VELOCITY: "$active_days >= 7 and $macd_z >= 3.0",
    StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD: "$active_days >= 7 and $sensitivity_excess >= 0.0",
    StatisticalModel.LONGITUDINAL_CUSUM: "$active_days >= 7 and $cusum_drift_score >= 3.0 and $drift_days >= 2",
    StatisticalModel.TWO_PART_HURDLE: "$active_days <= 2 or $intensity_z >= 3.0",
    StatisticalModel.BAYESIAN_GAMMA: "$bayesian_z >= 3.0",
    StatisticalModel.BAYESIAN_BETA_BINOMIAL: "$posterior_lift >= 2.0",
    StatisticalModel.COEFFICIENT_OF_VARIATION: "$active_days >= 7 and $surge_ratio >= 2.0 and $cv <= 0.5",
    StatisticalModel.RELATIVE_DEVIATION: "$fold_change >= 2.0",
    StatisticalModel.MAD: "$in_scoring_window = 1 and $raw_active_days >= 7 and $modified_z >= 3.5",
    StatisticalModel.QUANTILE_IQR_SKEW: "$in_scoring_window = 1 and $raw_active_days >= 7 and $tukey_excess_z >= 1.0",
    StatisticalModel.VARIANCE: None,
}


def _code(query: str) -> str:
  return "\n".join(ln for ln in query.splitlines() if not ln.lstrip().startswith("//"))


class TemplateGateContractTest(unittest.TestCase):

  def _templates(self):
    for sub in ("pipelines", "stage2_math_models"):
      for path in sorted((TEMPLATES / sub).glob("*.yl2")):
        yield f"{sub}/{path.name}", path.read_text(encoding="utf-8")

  def test_every_score_template_has_a_root_gate_or_a_justified_no_gate(self):
    missing, unexpected_no_gate = [], []
    for rel, text in self._templates():
      if "// NO-GATE:" in text:
        if rel not in NO_GATE_TEMPLATES:
          unexpected_no_gate.append(rel)
        continue
      if not ROOT_CONDITION.search(text):
        missing.append(rel)
    self.assertEqual(missing, [], f"Templates missing a root condition: gate: {missing}")
    self.assertEqual(unexpected_no_gate, [], f"New NO-GATE templates need review: {unexpected_no_gate}")

  def test_no_gate_templates_have_no_root_condition(self):
    for rel in NO_GATE_TEMPLATES:
      text = (TEMPLATES / rel).read_text(encoding="utf-8")
      self.assertIn("// NO-GATE:", text, rel)
      self.assertIsNone(re.search(r"^condition:", text, re.M), rel)

  def test_root_condition_is_single_and_precedes_order(self):
    for rel, text in self._templates():
      roots = re.findall(r"^condition:", text, re.M)
      self.assertLessEqual(len(roots), 1, f"{rel}: more than one root condition: block")
      if roots:
        self.assertLess(text.index("\ncondition:"), text.rindex("\norder:"), rel)


class RouterGateTest(unittest.TestCase):

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  def _q(self, model, **kw):
    if model == StatisticalModel.POISSON:
      return self.router.build_query(
          target_metric="auth_attempts_total",
          entity_type=EntityType.USER,
          statistical_model=model,
          **kw,
      )
    return self.router.build_query(target_metric="network_bytes_outbound", entity_type=EntityType.ASSET,
                                   statistical_model=model, **kw)

  def test_every_model_renders_its_default_gate(self):
    with self.assertRaisesRegex(ValueError, r"POISSON.*event_count_sum|value_sum|byte"):
      self.router.build_query(
          target_metric="network_bytes_outbound",
          entity_type=EntityType.ASSET,
          statistical_model=StatisticalModel.POISSON,
      )
    for model in StatisticalModel:
      with self.subTest(model=model.value):
        if model in RETIRED_GATE_MODELS:
          with self.assertRaisesRegex(ValueError, rf"retired.*{RETIRED_GATE_MODELS[model]}"):
            self._q(model)
          continue
        q = self._q(model)
        self.assertEqual(MultiStageTemplateRouter.root_condition(q), EXPECTED_DEFAULT_GATES[model])
        self.assertNotIn("{{", _code(q))
        self.assertLessEqual(q.count("\ncondition:"), 1)

  def test_header_reports_the_emitted_gate(self):
    q = self._q(StatisticalModel.POISSON, anomaly_threshold=3.5)
    self.assertIn("// Significance Gate: $poisson_z >= 3.5", q)
    self.assertNotIn("(Threshold >=", q)
    self.assertIn("// Significance Gate: NONE", self._q(StatisticalModel.VARIANCE))

  def test_threshold_override_replaces_the_default_gate(self):
    q = self._q(StatisticalModel.STANDARD_Z_SCORE, min_threshold=2.0, max_threshold=3.0)
    self.assertEqual(
        MultiStageTemplateRouter.root_condition(q),
        "$active_days >= 7 and ($personal_z >= 2.0 and $personal_z < 3.0)",
    )
    q = self._q(StatisticalModel.TWO_PART_HURDLE, min_threshold=2.0, max_threshold=3.0)
    self.assertEqual(MultiStageTemplateRouter.root_condition(q),
                     "$active_days <= 2 or ($intensity_z >= 2.0 and $intensity_z < 3.0)")

  def test_fold_change_override_uses_the_gate_variable(self):
    q = self._q(StatisticalModel.RELATIVE_DEVIATION, min_threshold=3.0)
    self.assertEqual(MultiStageTemplateRouter.root_condition(q), "$fold_change >= 3.0")
    q = self._q(StatisticalModel.COEFFICIENT_OF_VARIATION, fold_change_threshold=1.5)
    self.assertEqual(
        MultiStageTemplateRouter.root_condition(q),
        "$active_days >= 7 and $surge_ratio >= 1.5 and $cv <= 0.5",
    )
    q = self._q(StatisticalModel.BAYESIAN_GAMMA, anomaly_threshold=3.5)
    self.assertEqual(MultiStageTemplateRouter.root_condition(q), "$bayesian_z >= 3.5")

  def test_pipelines_resolve_every_gate_placeholder(self):
    for arch in PipelineArchitecture:
      if arch == PipelineArchitecture.LOCAL_2STAGE:
        continue  # rendered through build_query, not build_pipeline_query
      with self.subTest(pipeline=arch.value):
        if arch in RETIRED_GATE_PIPELINES:
          with self.assertRaisesRegex(ValueError, rf"retired.*{RETIRED_GATE_PIPELINES[arch]}"):
            self.router.build_pipeline_query(arch)
          continue
        q = self.router.build_pipeline_query(arch)
        self.assertNotIn("{{", _code(q))
        self.assertLessEqual(q.count("\ncondition:"), 1)

  def test_pipeline_override_replaces_template_gate(self):
    q = self.router.build_pipeline_query(PipelineArchitecture.DUAL_BASELINE_3STAGE, min_threshold=2.5)
    self.assertEqual(MultiStageTemplateRouter.root_condition(q), "$delta_z >= 2.5 and $active_days >= 7")
    q = self.router.build_pipeline_query(PipelineArchitecture.DUAL_SECTOR_FUSION_3STAGE, fusion_threshold_sq=16.0)
    self.assertEqual(MultiStageTemplateRouter.root_condition(q), "$composite_threat_norm_sq >= 16.0")

  def test_named_cohort_moves_the_gate_to_the_team_score(self):
    q = self.router.build_pipeline_query(PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL, cohort_entities=["a", "b"])
    self.assertEqual(MultiStageTemplateRouter.root_condition(q), "$z_vs_team >= 3.0")
    q = self.router.build_pipeline_query(PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
                                         entity_type=EntityType.USER, cohort_entities=["a", "b"])
    self.assertEqual(MultiStageTemplateRouter.root_condition(q), "$d_vs_team_sq >= 12.25")


class CardAndDocConcordanceTest(unittest.TestCase):

  def test_card_states_the_model_gate_by_default(self):
    for model in StatisticalModel:
      card = PreFlightValidator.render_preflight_card(target_scope="fleet", peer_cohort="N/A", statistical_model=model.value)
      self.assertIn(DEFAULT_SIGNIFICANCE_GATES[model], card, model.value)
    self.assertEqual(default_significance_threshold("Standard Z Score"), "Z >= 3.0σ")
    self.assertIsNone(default_significance_threshold("Some Free-Text Model"))

  def test_concordance_guide_table_lists_every_model_gate(self):
    guide = (SKILL_ROOT / "references" / "model-concordance-guide.md").read_text(encoding="utf-8")
    table = guide[guide.index("### 2.1 Default Root Significance Gate"):guide.index("\n## 3. ")]
    for model in StatisticalModel:
      row = next((ln for ln in table.splitlines() if ln.startswith(f"| `{model.value}`")), None)
      self.assertIsNotNone(row, f"§2.1 has no row for {model.value}")
      self.assertIn(DEFAULT_SIGNIFICANCE_GATES[model], row, model.value)
      if model in RETIRED_GATE_MODELS:
        self.assertIn("RETIRED", row.upper(), model.value)
        continue
      gate = EXPECTED_DEFAULT_GATES[model]
      if gate and model != StatisticalModel.MAD:
        self.assertIn(f"`{gate}", row, model.value)

  def test_concordance_ast_contracts_carry_the_gate(self):
    guide = (SKILL_ROOT / "references" / "model-concordance-guide.md").read_text(encoding="utf-8")
    contracts = guide[guide.index("\n## 3. "):guide.index("\n## 4. ")]
    for model, gate in EXPECTED_DEFAULT_GATES.items():
      if gate is None:
        self.assertIn("// NO-GATE", contracts)
      else:
        self.assertIn(f"condition:\n  {gate}\n", contracts, model.value)

  def test_docs_do_not_claim_or_is_rejected_in_root_condition(self):
    for rel in ("SKILL.md", "references/multi-stage-metrics-guide.md"):
      text = (SKILL_ROOT / rel).read_text(encoding="utf-8")
      self.assertNotRegex(text, r"`or` is rejected in root `condition:`", rel)

  def test_ws3_fano_baseline_dispersion_screen_no_spray_claims(self):
    from scripts.triage_formatter import CommonMarkTriageFormatter
    from scripts.ueba_hybrid_engine import render_forensic_dossier

    self.assertEqual(
        DEFAULT_SIGNIFICANCE_GATES[StatisticalModel.VARIANCE],
        "N/A (baseline dispersion screen)",
    )
    self.assertIn(
        "Baseline Dispersion Screen",
        MultiStageTemplateRouter.MODEL_DESCRIPTIONS.get(StatisticalModel.VARIANCE, ""),
    )

    router = MultiStageTemplateRouter()
    q = router.build_query(
        target_metric="auth_attempts_fail",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.VARIANCE,
    )
    self.assertIsNone(MultiStageTemplateRouter.root_condition(q))
    self.assertIn("Baseline Dispersion Screen", q)
    self.assertIn("$fano_factor = $variance / $safe_lambda", q)

    taxonomy = (SKILL_ROOT / "references" / "statistical-models-taxonomy.md").read_text(encoding="utf-8")
    self.assertIn("baseline dispersion screen", taxonomy.lower())
    self.assertIn("poisson_burst_clustering", taxonomy.lower())
    self.assertNotIn("automated script iteration", taxonomy.lower())
    self.assertNotIn("distinguishes automated credential sprays", taxonomy.lower())

    sample_rows = [
        {
            "entity": "alice",
            "observed": 4,
            "hist_avg": 10.0,
            "hist_stddev": 8.0,
            "active_days": 20,
            "fano_factor": 6.4,
        }
    ]
    triage_md = CommonMarkTriageFormatter.format_report(
        reduced_data={"outlier_count": 1, "top_outliers": sample_rows, "primary_score_metric": "fano_factor"},
        target_metric="auth_attempts_fail",
        statistical_model="VARIANCE",
        anomaly_threshold=3.0,
        executed_query=q,
    )
    self.assertIn("baseline dispersion screen", triage_md.lower())
    self.assertIn("poisson_burst_clustering", triage_md.lower())
    self.assertNotIn("automated script iteration", triage_md.lower())

    dossier = render_forensic_dossier(
        rows=sample_rows,
        target_metric="auth_attempts_fail",
        entity_type="USER",
        statistical_model="VARIANCE",
        executed_query=q,
        skip_postflight_audit=True,
    )
    self.assertIn("baseline dispersion screen", dossier["dossier_markdown"].lower())
    self.assertIn("poisson_burst_clustering", dossier["dossier_markdown"].lower())
    self.assertNotIn("automated script iteration", dossier["dossier_markdown"].lower())



if __name__ == "__main__":
  unittest.main()
