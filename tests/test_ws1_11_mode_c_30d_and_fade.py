"""WS1-11 (D9, D10) regression tests: Mode C 30-day cap with query pacing & sustained-attack fade caveat."""

import datetime
import os
import sys
import unittest

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_DIR not in sys.path:
  sys.path.insert(0, REPO_DIR)

from scripts import timeline_assembler as ta
from scripts.ueba_hybrid_engine import compile_hunt_pipeline, render_forensic_dossier


class TestWS111ModeC30dPacingAndFadeCaveat(unittest.TestCase):
  """Verifies WS1-11 (D9, D10) Mode C 14..30d execution, batch pacing, and sustained-attack fade caveat."""

  def setUp(self):
    self.ref_time = datetime.datetime(2026, 10, 28, 12, 0, 0, tzinfo=datetime.timezone.utc)

  def test_mode_c_supports_14d_and_30d_and_caps_above_30d_with_notice(self):
    """D9 / WS1-11: Mode C runs 14d and 30d uncapped, and caps >30d requests at 30d with an explicit notice."""
    res_14 = compile_hunt_pipeline(
        statistical_model="STANDARD_Z_SCORE",
        metrics="auth_attempts_total",
        entity_type="USER",
        mode="C",
        window_days=14,
        reference_time=self.ref_time,
    )
    self.assertEqual(res_14["mode"], "C")
    self.assertEqual(res_14["window_days"], 14)
    self.assertEqual(len(res_14["shards"]), 14)
    self.assertIsNone(res_14["capped_from_days"])
    self.assertEqual(res_14["shards"][0]["day"], "2026-10-15")
    self.assertEqual(res_14["shards"][-1]["day"], "2026-10-28")

    res_30 = compile_hunt_pipeline(
        statistical_model="STANDARD_Z_SCORE",
        metrics="auth_attempts_total",
        entity_type="USER",
        mode="C",
        window_days=30,
        reference_time=self.ref_time,
    )
    self.assertEqual(res_30["mode"], "C")
    self.assertEqual(res_30["window_days"], 30)
    self.assertEqual(len(res_30["shards"]), 30)
    self.assertIsNone(res_30["capped_from_days"])

    res_45 = compile_hunt_pipeline(
        statistical_model="STANDARD_Z_SCORE",
        metrics="auth_attempts_total",
        entity_type="USER",
        mode="C",
        window_days=45,
        reference_time=self.ref_time,
    )
    self.assertEqual(res_45["mode"], "C")
    self.assertEqual(res_45["window_days"], 30)
    self.assertEqual(len(res_45["shards"]), 30)
    self.assertEqual(res_45["capped_from_days"], 45)
    self.assertTrue(res_45["mode_notice"])
    self.assertIn("30", res_45["mode_notice"])
    self.assertIn("45", res_45["mode_notice"])
    self.assertIn("30", res_45["preflight_card_markdown"])

  def test_mode_c_emits_structured_shard_pacing_and_batch_indices(self):
    """D9 / WS1-11: Mode C emits structured batch pacing metadata (<=10 shards/batch, pause, retry, wall-time)."""
    res_14 = compile_hunt_pipeline(
        statistical_model="STANDARD_Z_SCORE",
        metrics="network_bytes_outbound",
        entity_type="ASSET",
        mode="C",
        window_days=14,
        reference_time=self.ref_time,
    )
    pacing = res_14.get("shard_pacing")
    self.assertIsInstance(pacing, dict)
    self.assertLessEqual(pacing["batch_size"], 10)
    self.assertGreaterEqual(pacing["batch_size"], 1)
    self.assertEqual(pacing["shard_count"], 14)
    self.assertEqual(pacing["batch_count"], 2)
    self.assertGreater(pacing["inter_batch_pause_seconds"], 0.0)
    self.assertEqual(pacing["max_retries_per_shard"], 1)
    self.assertIn("RESOURCE_EXHAUSTED", pacing["retry_on"])
    self.assertGreater(pacing["estimated_wall_minutes"], 0.0)

    # Shards 0..9 in batch 0; shards 10..13 in batch 1
    self.assertEqual([s.get("batch_index") for s in res_14["shards"][:10]], [0] * 10)
    self.assertEqual([s.get("batch_index") for s in res_14["shards"][10:]], [1] * 4)
    self.assertIn("Mode C Query Pacing", res_14["preflight_card_markdown"])

    # Mode A has no shard_pacing
    res_a = compile_hunt_pipeline(
        statistical_model="STANDARD_Z_SCORE",
        metrics="network_bytes_outbound",
        entity_type="ASSET",
        mode="A",
        reference_time=self.ref_time,
    )
    self.assertIsNone(res_a.get("shard_pacing"))

  def test_d10_sustained_attack_fade_caveat_in_docs_and_timeline_assembler(self):
    """D10 / WS1-11: Guide, SKILL.md, and TimelineAssembler document sustained-attack baseline absorption & fade."""
    with open(os.path.join(REPO_DIR, "references", "timeline-modes-guide.md"), encoding="utf-8") as f:
      guide_text = f.read()
    with open(os.path.join(REPO_DIR, "SKILL.md"), encoding="utf-8") as f:
      skill_text = f.read()

    for doc_name, text in (("timeline-modes-guide.md", guide_text), ("SKILL.md", skill_text)):
      with self.subTest(doc=doc_name):
        self.assertIn("2.5", text)
        self.assertIn("+6", text)
        self.assertIn("3 days", text)
        self.assertIn("attack stopped", text.lower())
        self.assertIn("CUSUM", text)

    # Simulate a sustained +6σ attack across 5 shards where trailing σ inflation fades Z below 3σ after ~3 days
    asm = ta.TimelineAssembler()
    asm.add_shard("2026-10-20", [{"entity": "charles.hardy", "personal_z": 6.0}])
    asm.add_shard("2026-10-21", [{"entity": "charles.hardy", "personal_z": 4.6}])
    asm.add_shard("2026-10-22", [{"entity": "charles.hardy", "personal_z": 3.4}])
    asm.add_shard("2026-10-23", [])  # faded below 3.0σ gate
    asm.add_shard("2026-10-24", [])  # faded below 3.0σ gate
    tl_md = ta.TimelineAssembler.render_markdown(asm.build())
    self.assertIn("2.5", tl_md)
    self.assertIn("attack stopped", tl_md.lower())
    self.assertIn("LONGITUDINAL_CUSUM", tl_md)

  def test_d10_sustained_attack_fade_caveat_in_pillar3_of_mode_c_dossiers(self):
    """D10 / WS1-11: Mode C Pillar 3 includes sustained-attack fade caveat (populated & zero-row), pointing to CUSUM."""
    compiled = compile_hunt_pipeline(
        statistical_model="STANDARD_Z_SCORE",
        metrics="auth_attempts_total",
        entity_type="USER",
        mode="C",
        window_days=14,
        reference_time=self.ref_time,
    )
    shards = [
        (
            "2026-10-20",
            {
                "stats": {
                    "results": [
                        {"column": "user", "values": [{"value": {"stringVal": "charles.hardy"}}]},
                        {"column": "observed", "values": [{"value": {"doubleVal": 850.0}}]},
                        {"column": "historical_avg", "values": [{"value": {"doubleVal": 164.6}}]},
                        {"column": "historical_stddev", "values": [{"value": {"doubleVal": 114.49}}]},
                        {"column": "active_days", "values": [{"value": {"int64Val": "15"}}]},
                        {"column": "personal_z", "values": [{"value": {"doubleVal": 5.99}}]},
                    ]
                }
            },
        ),
        (
            "2026-10-21",
            {
                "stats": {
                    "results": [
                        {"column": "user", "values": [{"value": {"stringVal": "charles.hardy"}}]},
                        {"column": "observed", "values": [{"value": {"doubleVal": 850.0}}]},
                        {"column": "historical_avg", "values": [{"value": {"doubleVal": 207.4}}]},
                        {"column": "historical_stddev", "values": [{"value": {"doubleVal": 198.1}}]},
                        {"column": "active_days", "values": [{"value": {"int64Val": "16"}}]},
                        {"column": "personal_z", "values": [{"value": {"doubleVal": 3.24}}]},
                    ]
                }
            },
        ),
        ("2026-10-22", {"stats": {"results": []}}),
    ]
    dossier_pop = render_forensic_dossier(
        rows=shards,
        executed_query=compiled["compiled_query"],
        metric_name="auth_attempts_total",
        statistical_model="STANDARD_Z_SCORE",
        entity_type="USER",
        mode="C",
    )
    self.assertFalse(dossier_pop["is_zero_row"])
    self.assertTrue(dossier_pop.get("mode_c_fade_caveat"))
    p3_start = dossier_pop["dossier_markdown"].index("#### 3. Forensic Vector Breakdown")
    p4_start = dossier_pop["dossier_markdown"].index("#### 4. Chronicle UI Manual Pivot")
    pillar3_pop = dossier_pop["dossier_markdown"][p3_start:p4_start]
    self.assertIn("2.5", pillar3_pop)
    self.assertIn("attack stopped", pillar3_pop.lower())
    self.assertIn("LONGITUDINAL_CUSUM", pillar3_pop)

    # Zero-row Mode C dossier must also carry the Pillar 3 fade caveat (empty shards may reflect post-onset fade)
    dossier_zero = render_forensic_dossier(
        rows=[],
        executed_query=compiled["compiled_query"],
        metric_name="auth_attempts_total",
        statistical_model="STANDARD_Z_SCORE",
        entity_type="USER",
        mode="C",
    )
    self.assertTrue(dossier_zero["is_zero_row"])
    self.assertTrue(dossier_zero.get("mode_c_fade_caveat"))
    z_p3_start = dossier_zero["dossier_markdown"].index("#### 3. Forensic Vector Breakdown")
    z_p4_start = dossier_zero["dossier_markdown"].index("#### 4. Chronicle UI Manual Pivot")
    pillar3_zero = dossier_zero["dossier_markdown"][z_p3_start:z_p4_start]
    self.assertIn("2.5", pillar3_zero)
    self.assertIn("attack stopped", pillar3_zero.lower())
    self.assertIn("LONGITUDINAL_CUSUM", pillar3_zero)

    # Single-day Mode A dossier does not emit mode_c_fade_caveat
    dossier_mode_a = render_forensic_dossier(
        rows=[],
        executed_query=compiled["compiled_query"],
        metric_name="auth_attempts_total",
        statistical_model="STANDARD_Z_SCORE",
        entity_type="USER",
        mode="A",
    )
    self.assertIsNone(dossier_mode_a.get("mode_c_fade_caveat"))


if __name__ == "__main__":
  unittest.main()
