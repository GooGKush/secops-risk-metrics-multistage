"""WS1-09 (PF-2): Samuelson small-cohort sample-SD cap (N - 1) / sqrt(N) regression tests."""

import math
import re
import statistics
import unittest

from scripts import template_router as tr
from scripts import ueba_hybrid_engine as engine
from scripts.preflight_validator import (
    EntityType,
    MalachiteASTValidator,
    PipelineArchitecture,
)
from scripts.statistical_validator import StatisticalAntipatternAuditor
from scripts.template_router import MultiStageTemplateRouter


def _strip_comments(query: str) -> str:
  return "\n".join(
      ln for ln in query.splitlines() if not ln.lstrip().startswith("//")
  )


class TestWS109SamuelsonCohortCap(unittest.TestCase):
  """Verifies in-query (N - 1) / sqrt(N) cap and 'cohort too small' reporting (WS1-09)."""

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  def test_samuelson_sample_sd_formula_and_minimum_cohort_sizes(self):
    samuelson_max_z = getattr(tr, "samuelson_max_z", None)
    samuelson_min_cohort_size = getattr(tr, "samuelson_min_cohort_size", None)
    samuelson_triad_max_d_sq = getattr(tr, "samuelson_triad_max_d_sq", None)
    samuelson_triad_min_cohort_size = getattr(
        tr, "samuelson_triad_min_cohort_size", None
    )
    self.assertIsNotNone(samuelson_max_z, "samuelson_max_z missing in template_router")
    self.assertIsNotNone(
        samuelson_min_cohort_size,
        "samuelson_min_cohort_size missing in template_router",
    )
    self.assertIsNotNone(
        samuelson_triad_max_d_sq,
        "samuelson_triad_max_d_sq missing in template_router",
    )
    self.assertIsNotNone(
        samuelson_triad_min_cohort_size,
        "samuelson_triad_min_cohort_size missing in template_router",
    )
    self.assertIsNotNone(
        getattr(engine, "samuelson_max_z", None),
        "samuelson_max_z must also be re-exported on ueba_hybrid_engine",
    )

    self.assertEqual(samuelson_max_z(0), 0.0)
    self.assertEqual(samuelson_max_z(1), 0.0)

    # Empirical check against sample SD (N - 1 degrees of freedom, PF-2):
    # Extreme one-hot vector [1000, 0, ..., 0] achieves the exact Samuelson bound.
    for n in (2, 5, 7, 10, 11):
      sample = [1000.0] + [0.0] * (n - 1)
      mu = statistics.mean(sample)
      sd = statistics.stdev(sample)
      empirical_z = (sample[0] - mu) / sd
      expected_z = (n - 1.0) / math.sqrt(float(n))
      self.assertAlmostEqual(samuelson_max_z(n), expected_z, places=9)
      self.assertAlmostEqual(samuelson_max_z(n), empirical_z, places=9)

    # 7-sample gates that include the scored observation cap at 6/sqrt(7) ≈ 2.2678 < 3.0!
    self.assertLess(samuelson_max_z(7), 3.0)
    self.assertLess(samuelson_max_z(10), 3.0)
    self.assertGreaterEqual(samuelson_max_z(11), 3.0)

    self.assertEqual(samuelson_min_cohort_size(3.0), 11)
    self.assertEqual(samuelson_min_cohort_size(2.0), 6)

    self.assertAlmostEqual(samuelson_triad_max_d_sq(4), 6.75, places=9)
    self.assertAlmostEqual(samuelson_triad_max_d_sq(5), 9.60, places=9)
    self.assertAlmostEqual(samuelson_triad_max_d_sq(6), 12.50, places=9)
    self.assertEqual(samuelson_triad_min_cohort_size(12.25), 6)

  def test_part_of_the_whole_templates_compute_samuelson_cap_in_query(self):
    q_multi = self.router.build_pipeline_query(
        PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL,
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        cohort_entities=["u1", "u2", "u3", "u4", "u5"],
        target_entity="u1",
    )
    code_multi = _strip_comments(q_multi)
    self.assertNotIn("math.sqrt(N - 1)", q_multi)
    self.assertIn("(N - 1) / math.sqrt(N)", q_multi)
    self.assertIn(
        "$samuelson_max_z = ($team_size - 1.0) / math.sqrt(if($team_size > 1, $team_size, 1.0))",
        code_multi,
    )
    self.assertIn("$cohort_too_small = if($samuelson_max_z < 3.0, 1, 0)", code_multi)
    self.assertEqual(MultiStageTemplateRouter.root_condition(q_multi), "$z_vs_team >= 3.0")
    self.assertEqual(MalachiteASTValidator.validate_query(q_multi), [])
    self.assertEqual(StatisticalAntipatternAuditor.audit_query(q_multi), [])

    q_triad = self.router.build_pipeline_query(
        PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
        entity_type=EntityType.USER,
        target_metrics=[
            "auth_attempts_total",
            "auth_attempts_fail",
            "auth_attempts_success",
        ],
        cohort_entities=["u1", "u2", "u3", "u4"],
        target_entity="u1",
    )
    code_triad = _strip_comments(q_triad)
    self.assertNotIn("math.sqrt(N - 1)", q_triad)
    self.assertIn("(N - 1) / math.sqrt(N)", q_triad)
    self.assertIn(
        "$samuelson_max_z = ($team_size - 1.0) / math.sqrt(if($team_size > 1, $team_size, 1.0))",
        code_triad,
    )
    self.assertIn(
        "$samuelson_max_d_sq = 3.0 * $samuelson_max_z * $samuelson_max_z",
        code_triad,
    )
    self.assertIn(
        "$cohort_too_small = if($samuelson_max_d_sq < 12.25, 1, 0)",
        code_triad,
    )
    self.assertEqual(
        MultiStageTemplateRouter.root_condition(q_triad), "$d_vs_team_sq >= 12.25"
    )
    # Verify root outcome count stays <= 20 compiler ceiling
    root_section = code_triad.rsplit("outcome:", 1)[-1].split("condition:", 1)[0]
    root_outcomes = re.findall(r"\$([a-zA-Z0-9_]+)\s*=", root_section)
    self.assertLessEqual(len(root_outcomes), 20)
    self.assertEqual(MalachiteASTValidator.validate_query(q_triad), [])
    self.assertEqual(StatisticalAntipatternAuditor.audit_query(q_triad), [])

  def test_compile_hunt_pipeline_flags_small_peer_cohort_and_explains_non_alerting(self):
    res_small = engine.compile_hunt_pipeline(
        architecture="multilevel",
        metrics="auth_attempts_total",
        entity_type="USER",
        entity_value="u1",
        cohort_entities=["u1", "u2", "u3", "u4", "u5"],
        anomaly_threshold=3.0,
    )
    self.assertTrue(res_small["ast_valid"], res_small["ast_errors"])
    self.assertTrue(res_small.get("cohort_too_small"))
    self.assertEqual(res_small.get("cohort_size"), 5)
    self.assertAlmostEqual(
        res_small.get("samuelson_max_z", 0.0), 4.0 / math.sqrt(5.0), places=3
    )
    self.assertEqual(res_small.get("required_min_cohort_size"), 11)
    warning = res_small.get("cohort_cap_warning") or ""
    self.assertIn("cohort too small", warning.lower())
    self.assertIn("1.79", warning)
    self.assertIn("11", warning)
    self.assertIn("cohort too small", res_small["preflight_card_markdown"].lower())

    # Adequate cohort size (N = 11 >= 11 for 3.0 sigma) is NOT flagged as cohort_too_small
    peers_11 = [f"u{i}" for i in range(1, 12)]
    res_ok = engine.compile_hunt_pipeline(
        architecture="multilevel",
        metrics="auth_attempts_total",
        entity_type="USER",
        entity_value="u1",
        cohort_entities=peers_11,
        anomaly_threshold=3.0,
    )
    self.assertFalse(res_ok.get("cohort_too_small"))
    self.assertIsNone(res_ok.get("cohort_cap_warning"))

    # Triad with 4 peers (max D^2 = 6.75 < 12.25; needs N >= 6)
    res_triad_small = engine.compile_hunt_pipeline(
        architecture="triad",
        metrics=["auth_attempts_total", "auth_attempts_fail", "auth_attempts_success"],
        entity_type="USER",
        entity_value="u1",
        cohort_entities=["u1", "u2", "u3", "u4"],
    )
    self.assertTrue(res_triad_small["ast_valid"], res_triad_small["ast_errors"])
    self.assertTrue(res_triad_small.get("cohort_too_small"))
    self.assertAlmostEqual(res_triad_small.get("samuelson_max_d_sq", 0.0), 6.75, places=3)
    self.assertEqual(res_triad_small.get("required_min_cohort_size"), 6)
    self.assertIn("cohort too small", (res_triad_small.get("cohort_cap_warning") or "").lower())

  def test_render_forensic_dossier_explains_small_cohort_zero_row_and_populated_outcomes(self):
    compiled = engine.compile_hunt_pipeline(
        architecture="multilevel",
        metrics="auth_attempts_total",
        entity_type="USER",
        entity_value="u1",
        cohort_entities=["u1", "u2", "u3", "u4", "u5"],
        anomaly_threshold=3.0,
    )
    # 0 rows returned because max Z = 4/sqrt(5) = 1.79 < 3.0 gate
    zero_dossier = engine.render_forensic_dossier(
        rows=[],
        executed_query=compiled["compiled_query"],
        statistical_model="STANDARD_Z_SCORE",
        metric_name="auth_attempts_total",
        entity_type="USER",
        anomaly_threshold=3.0,
    )
    self.assertTrue(zero_dossier.get("cohort_too_small"))
    self.assertIn("cohort too small", zero_dossier["dossier_markdown"].lower())
    self.assertIn("cohort too small", zero_dossier["clean_hunt_markdown"].lower())
    self.assertIn("1.79", zero_dossier["dossier_markdown"])
    self.assertIn("11", zero_dossier["dossier_markdown"])

    # Populated row carrying explicit cohort_too_small / small team_size
    pop_dossier = engine.render_forensic_dossier(
        rows=[{
            "entity": "u1",
            "observed": 850,
            "hist_avg": 100.0,
            "hist_stddev": 20.0,
            "active_days": 20,
            "z_score": 1.78,
            "team_size": 5,
            "samuelson_max_z": 1.7889,
            "cohort_too_small": 1,
        }],
        executed_query=compiled["compiled_query"],
        statistical_model="STANDARD_Z_SCORE",
        metric_name="auth_attempts_total",
        entity_type="USER",
        anomaly_threshold=3.0,
    )
    self.assertTrue(pop_dossier.get("cohort_too_small"))
    self.assertIn("cohort too small", pop_dossier["dossier_markdown"].lower())


if __name__ == "__main__":
  unittest.main()
