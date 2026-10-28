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

# Default root gate each model renders with router defaults (sigma 3.0, fold change 2.0, MAD 3.5).
EXPECTED_DEFAULT_GATES = {
    StatisticalModel.STANDARD_Z_SCORE: "$personal_z >= 3.0",
    StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z: "$upper_tail_z >= 3.0",
    StatisticalModel.POISSON: "$poisson_z >= 3.0",
    StatisticalModel.HOURLY_TEMPORAL_ZSCORE: "$hourly_z >= 3.0",
    StatisticalModel.CIRCADIAN_VON_MISES: "$circadian_threat_score >= 3.0",
    StatisticalModel.MACD_MOMENTUM_VELOCITY: "$fast_z >= 3.0",
    StatisticalModel.PIECEWISE_CRI: "$clamped_z >= 3.0",
    StatisticalModel.FLEET_PREVALENCE_SHIELD: "$shielded_z >= 3.0",
    StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD: "$sensitivity_excess >= 0.0",
    StatisticalModel.LONGITUDINAL_CUSUM: "$cusum_drift_score >= 3.0 and $drift_days >= 2",
    StatisticalModel.TWO_PART_HURDLE: "$active_days <= 2 or $intensity_z >= 3.0",
    StatisticalModel.BAYESIAN_GAMMA: "$bayes_shift_ratio >= 2.0",
    StatisticalModel.BAYESIAN_BETA_BINOMIAL: "$posterior_lift >= 2.0",
    StatisticalModel.COEFFICIENT_OF_VARIATION: "$surge_ratio >= 2.0 and $cv <= 0.5",
    StatisticalModel.RELATIVE_DEVIATION: "$fold_change >= 2.0",
    StatisticalModel.MAD: "$in_scoring_window = 1 and $raw_active_days >= 7 and $modified_z >= 3.5",
    StatisticalModel.QUANTILE_IQR_SKEW: "$in_scoring_window = 1 and $raw_active_days >= 7 and $tukey_fence_ratio >= 2.0",
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
    return self.router.build_query(target_metric="network_bytes_outbound", entity_type=EntityType.ASSET,
                                   statistical_model=model, **kw)

  def test_every_model_renders_its_default_gate(self):
    for model in StatisticalModel:
      with self.subTest(model=model.value):
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
    self.assertEqual(MultiStageTemplateRouter.root_condition(q), "$personal_z >= 2.0 and $personal_z < 3.0")
    q = self._q(StatisticalModel.TWO_PART_HURDLE, min_threshold=2.0, max_threshold=3.0)
    self.assertEqual(MultiStageTemplateRouter.root_condition(q),
                     "$active_days <= 2 or ($intensity_z >= 2.0 and $intensity_z < 3.0)")

  def test_fold_change_override_uses_the_gate_variable(self):
    q = self._q(StatisticalModel.RELATIVE_DEVIATION, min_threshold=3.0)
    self.assertEqual(MultiStageTemplateRouter.root_condition(q), "$fold_change >= 3.0")
    q = self._q(StatisticalModel.BAYESIAN_GAMMA, fold_change_threshold=1.5)
    self.assertEqual(MultiStageTemplateRouter.root_condition(q), "$bayes_shift_ratio >= 1.5")

  def test_pipelines_resolve_every_gate_placeholder(self):
    for arch in PipelineArchitecture:
      if arch == PipelineArchitecture.LOCAL_2STAGE:
        continue  # rendered through build_query, not build_pipeline_query
      with self.subTest(pipeline=arch.value):
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


if __name__ == "__main__":
  unittest.main()
