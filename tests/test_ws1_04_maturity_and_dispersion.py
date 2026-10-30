"""Regression & unit tests for WS1-04 (D8): Maturity Gates, Dispersion Floors & Immature Routing."""

from __future__ import annotations

import math
import unittest

from scripts import template_router as tr
from scripts.preflight_validator import EntityType, MalachiteASTValidator, StatisticalModel
from scripts.radar_collector import EntityRadarCollector
from scripts.template_router import (
    ChainedHuntRouter,
    MultiStageTemplateRouter,
    PipelineArchitecture,
)
from scripts.timeline_assembler import TimelineAssembler
from scripts.ueba_constants import DEFAULT_MIN_BASELINE_DAYS
from scripts.ueba_hybrid_engine import UEBAHybridEngine


def _eval_count_z(obs: float, avg: float, sd: float, active_days: int, min_days: int = 7) -> float:
  """Evaluates D8 count Z-score with maturity gate and sqrt(max(avg, 1.0)) dispersion floor."""
  if active_days < min_days:
    return 0.0
  floor = math.sqrt(max(avg, 1.0))
  safe_sd = max(sd, floor)
  return (obs - avg) / safe_sd


class TestWS104MaturityAndDispersion(unittest.TestCase):
  """Verifies D8 maturity gate ($active_days >= 7), count/byte floors, and immature routing."""

  def setUp(self) -> None:
    self.router = MultiStageTemplateRouter()
    self.engine = UEBAHybridEngine()

  def test_frank_kolzig_zero_variance_count_floor_prevents_false_alarm(self) -> None:
    # V-live: frank.kolzig logs in 103 times every day for 30 days (avg=103, sd=0, n=30).
    # Under old fallback (1.0), obs=106 gave +3.0σ false alarm.
    # Under D8 count floor sqrt(max(103, 1)) = 10.1489:
    #   obs=106 -> (106 - 103) / 10.1489 = +0.2956σ (< 3.0σ, NOT flagged)
    #   obs=150 -> (150 - 103) / 10.1489 = +4.6310σ (>= 3.0σ, real surge IS flagged)
    q = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.STANDARD_Z_SCORE,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q), [])
    self.assertIn("$dispersion_floor = math.sqrt(if($hist_avg > 1.0, $hist_avg, 1.0))", q)
    self.assertIn("$safe_stddev = if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)", q)
    self.assertEqual(
        MultiStageTemplateRouter.root_condition(q),
        "$active_days >= 7 and $personal_z >= 3.0",
    )

    z_106 = _eval_count_z(obs=106.0, avg=103.0, sd=0.0, active_days=30)
    self.assertAlmostEqual(z_106, 3.0 / math.sqrt(103.0), places=6)
    self.assertLess(z_106, 3.0)

    z_150 = _eval_count_z(obs=150.0, avg=103.0, sd=0.0, active_days=30)
    self.assertGreater(z_150, 3.0)

  def test_charles_hardy_preserved_while_maya_goodman_and_site_dc_excluded_from_z(self) -> None:
    # V-live entities:
    #   charles.hardy: obs=785, avg=164.6, sd=114.49, n=10 -> +5.42σ (mature, sd > sqrt(164.6))
    #   maya.goodman:  obs=4,   avg=50.5,  sd=65.76,  n=2  -> immature (n < 7)
    #   SITE-DC$:      obs=70574.5, avg=0, sd=0,      n=0  -> immature (n < 7)
    z_charles = _eval_count_z(obs=785.0, avg=164.6, sd=114.49, active_days=10)
    self.assertAlmostEqual(z_charles, (785.0 - 164.6) / 114.49, places=4)
    self.assertAlmostEqual(z_charles, 5.4188, places=3)

    self.assertEqual(_eval_count_z(obs=4.0, avg=50.5, sd=65.76, active_days=2), 0.0)
    self.assertEqual(_eval_count_z(obs=70574.5, avg=0.0, sd=0.0, active_days=0), 0.0)

    # Engine dossier must exclude immature entities from Z-alerting `outliers`, place them in
    # `immature_entities`, and emit novelty / TWO_PART_HURDLE routing guidance.
    compiled = self.engine.compile_hunt_pipeline(
        intent="USER_AUTH_BRUTE_FORCE",
        statistical_model="STANDARD_Z_SCORE",
        timeline_mode="A",
    )
    mock_payload = {
        "stats": {
            "results": [
                {"column": "entity", "values": [
                    {"value": {"stringVal": "SITE-DC$"}},
                    {"value": {"stringVal": "maya.goodman"}},
                    {"value": {"stringVal": "charles.hardy"}},
                ]},
                {"column": "observed", "values": [
                    {"value": {"doubleVal": 70574.5}},
                    {"value": {"doubleVal": 250.0}},
                    {"value": {"doubleVal": 785.0}},
                ]},
                {"column": "hist_avg", "values": [
                    {"value": {"doubleVal": 0.0}},
                    {"value": {"doubleVal": 50.5}},
                    {"value": {"doubleVal": 164.6}},
                ]},
                {"column": "hist_stddev", "values": [
                    {"value": {"doubleVal": 0.0}},
                    {"value": {"doubleVal": 65.76}},
                    {"value": {"doubleVal": 114.49}},
                ]},
                {"column": "active_days", "values": [
                    {"value": {"int64Val": "0"}},
                    {"value": {"int64Val": "2"}},
                    {"value": {"int64Val": "10"}},
                ]},
                {"column": "personal_z", "values": [
                    {"value": {"doubleVal": 70574.5}},
                    {"value": {"doubleVal": 3.03}},
                    {"value": {"doubleVal": 5.4188}},
                ]},
            ]
        }
    }
    res = self.engine.render_forensic_dossier(
        rows=mock_payload,
        executed_query=compiled["compiled_query"],
        metric_name="auth_attempts_total",
        entity_type="USER",
        statistical_model="STANDARD_Z_SCORE",
    )
    outlier_entities = [o["entity"] for o in res["outliers"]]
    self.assertEqual(outlier_entities, ["charles.hardy"])
    immature_entities = [o["entity"] for o in res["immature_entities"]]
    self.assertCountEqual(immature_entities, ["SITE-DC$", "maya.goodman"])
    self.assertIn("TWO_PART_HURDLE", res["dossier_markdown"])
    self.assertIn("first_seen", res["dossier_markdown"])

  def test_byte_dispersion_floors_and_probe_helpers(self) -> None:
    expected_floors = {
        "network_bytes_outbound": 44979.0,
        "dns_bytes_outbound": 50450.0,
        "network_bytes_total": 303176.0,
        "network_bytes_inbound": 28276845.0,
        "workspace_network_bytes_outbound": 10240.0,
        "workspace_network_bytes_total": 10240.0,
    }
    for metric_name, expected in expected_floors.items():
      self.assertEqual(tr.DEFAULT_FLEET_BYTE_DISPERSION_FLOORS[metric_name], expected)
      self.assertEqual(tr.resolve_byte_dispersion_floor(metric_name), expected)
      q = self.router.build_query(
          target_metric=metric_name,
          entity_type=EntityType.ASSET if "workspace_" not in metric_name else EntityType.USER,
          statistical_model=StatisticalModel.STANDARD_Z_SCORE,
      )
      self.assertEqual(MalachiteASTValidator.validate_query(q), [], msg=metric_name)
      self.assertIn(f"$dispersion_floor = {expected}", q)
      self.assertIn("$safe_stddev = if($hist_stddev > $dispersion_floor, $hist_stddev, $dispersion_floor)", q)

    # Custom caller override
    q_custom = self.router.build_query(
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
        statistical_model=StatisticalModel.STANDARD_Z_SCORE,
        byte_dispersion_floor=131072.0,
    )
    self.assertIn("$dispersion_floor = 131072.0", q_custom)

    # Probe generator & parser
    probe_q = tr.build_byte_dispersion_floor_probe(
        "network_bytes_outbound",
        entity_type=EntityType.ASSET,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(probe_q), [])
    probe_payload = {
        "stats": {
            "results": [
                {"column": "entity", "values": [
                    {"value": {"stringVal": "h1"}},
                    {"value": {"stringVal": "h2"}},
                    {"value": {"stringVal": "h3"}},
                    {"value": {"stringVal": "immature-h4"}},
                ]},
                {"column": "hist_stddev", "values": [
                    {"value": {"doubleVal": 20000.0}},
                    {"value": {"doubleVal": 44979.0}},
                    {"value": {"doubleVal": 90000.0}},
                    {"value": {"doubleVal": 5.0}},
                ]},
                {"column": "active_days", "values": [
                    {"value": {"int64Val": "12"}},
                    {"value": {"int64Val": "20"}},
                    {"value": {"int64Val": "30"}},
                    {"value": {"int64Val": "2"}},
                ]},
            ]
        }
    }
    parsed_floor = tr.parse_byte_dispersion_floor_probe(
        probe_payload,
        metric_name="network_bytes_outbound",
    )
    self.assertAlmostEqual(parsed_floor, 44979.0, places=2)

  def test_pipelines_radar_and_timeline_assembler_enforce_maturity_and_floors(self) -> None:
    # 1. TimelineAssembler defaults min_baseline_days to 7 (D8)
    asm = TimelineAssembler()
    self.assertEqual(asm.min_baseline_days, DEFAULT_MIN_BASELINE_DAYS)
    self.assertEqual(asm.min_baseline_days, 7)

    # 2. hybrid_metric_derived_asset_age_2stage gates on $active_days >= 7 so Z never equals raw count
    q_age = self.router.build_pipeline_query(
        PipelineArchitecture.HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE,
        target_metric="auth_attempts_total",
        entity_type=EntityType.ASSET,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_age), [])
    self.assertIn("$active_days >= 7", MultiStageTemplateRouter.root_condition(q_age) or "")

    # 3. dual_baseline_delta_z_3stage gates maturity before fleet mean
    q_dz = self.router.build_pipeline_query(
        PipelineArchitecture.DUAL_BASELINE_3STAGE,
        target_metric="http_queries_total",
        entity_type=EntityType.ASSET,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_dz), [])
    stage2_slice = q_dz.split("stage fleet_stats")[1].split("}")[0]
    self.assertIn("active_days >=", stage2_slice)

    # 4. ChainedHuntRouter Phase 1 endpoint query enforces maturity & count dispersion floor
    q_p1 = ChainedHuntRouter.build_phase1_endpoint_query()
    self.assertEqual(MalachiteASTValidator.validate_query(q_p1), [])
    self.assertNotIn("if($sigma > 0, $sigma, 1.0)", q_p1)
    self.assertIn("$active_days >= 7", q_p1)

    # 5. EntityRadarCollector replaces 1,000,000 divisor in Cloud Infrastructure spoke
    cloud_q = EntityRadarCollector.USER_SECTOR_QUERIES["Cloud Infrastructure"].format(entity="alice")
    self.assertNotIn("1000000.0", cloud_q)
    self.assertEqual(MalachiteASTValidator.validate_query("// Goal: Cloud spoke check\n" + cloud_q), [])


if __name__ == "__main__":
  unittest.main()
