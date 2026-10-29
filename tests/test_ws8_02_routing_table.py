# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""WS8-02 contract tests: Canonical Cross-Skill Routing Table & Zero Ping-Pong."""

import importlib.util
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent.parent

START_TAG = "<!-- CANONICAL_SKILL_ROUTING_TABLE_START -->"
END_TAG = "<!-- CANONICAL_SKILL_ROUTING_TABLE_END -->"

RETIRED_TEMPLATES = (
    "fleet_prevalence_shield",
    "piecewise_cri",
    "hybrid_metric_orthogonal_space_2stage",
    "impossible_travel_geo_velocity_2stage",
    "hourly_temporal_zscore",
    "circadian_von_mises",
    "asymmetric_directional_z",
)


def _find_peer_repo(base_name: str) -> Path | None:
  parent = HERE.parent
  for candidate in (parent / f"{base_name}-WS8", parent / base_name):
    if candidate.exists():
      return candidate
  return None


def _extract_canonical_table(md_text: str) -> str:
  pattern = re.compile(
      re.escape(START_TAG) + r".*?" + re.escape(END_TAG),
      re.DOTALL,
  )
  matches = pattern.findall(md_text)
  if len(matches) != 1:
    raise AssertionError(
        f"Expected exactly 1 canonical routing table block, found {len(matches)}"
    )
  return matches[0]


def _load_stats_hunter_builder(sh_root: Path):
  builder_path = sh_root / "scripts" / "multistage_query_builder.py"
  spec = importlib.util.spec_from_file_location(
      "ws8_stats_hunter_builder", str(builder_path)
  )
  assert spec is not None and spec.loader is not None
  mod = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(mod)
  return mod


class TestWS802CanonicalRoutingTable(unittest.TestCase):
  """Verifies byte-identical canonical routing table and zero B-E6 ping-pong."""

  def test_local_skill_md_has_canonical_routing_table_and_ceilings(self):
    skill_md = (HERE / "SKILL.md").read_text(encoding="utf-8")
    raw_bytes = len(skill_md.encode("utf-8"))
    line_count = len(skill_md.splitlines())
    self.assertLessEqual(
        raw_bytes,
        28672,
        f"risk-metrics SKILL.md exceeds 28,672-byte ceiling ({raw_bytes} bytes)",
    )
    self.assertLessEqual(
        line_count,
        275,
        f"risk-metrics SKILL.md exceeds 275-line ceiling ({line_count} lines)",
    )

    block = _extract_canonical_table(skill_md)
    idx_1 = block.find("1. `secops-statistical-hunter`")
    idx_2 = block.find("2. `secops-risk-metrics-multistage`")
    idx_3 = block.find("3. Bilateral Co-Execution")
    idx_4 = block.find("4. `secops-detection-engineering`")
    self.assertGreater(idx_1, 0, "Missing Precedence 1 row in canonical table")
    self.assertGreater(idx_2, idx_1, "Precedence 2 must follow Precedence 1")
    self.assertGreater(idx_3, idx_2, "Precedence 3 must follow Precedence 2")
    self.assertGreater(idx_4, idx_3, "Precedence 4 must follow Precedence 3")

    required_tokens = (
        "C2_BEACONING_JITTER",
        "FLOW_GAP_RATIO_SCREEN",
        "HOUR_OF_DAY_PROFILE",
        "SHANNON_ENTROPY_CHARACTER",
        "LONG_STRING_SCREEN",
        "EWMA_BURST_VELOCITY",
        "BURST_Z_SCREEN",
        "MARKOV_2GRAM_TRANSITION_RARITY",
        "ZIPFIAN_PROCESS_RARITY",
        "POISSON_BURST_CLUSTERING",
        "PRODUCER_CONSUMER_RATIO_INVERSION",
        "DNS query length MAD",
        "metrics.auth_attempts_*",
        "first_seen_novelty_2stage.yl2",
        "dual_baseline_delta_z_3stage.yl2",
        "radar_360_decoupled_sector.yl2",
        "longitudinal_cusum_series_3stage.yl2",
        "mad_robust_z_4stage.yl2",
        "quantile_iqr_skew_3stage.yl2",
        "hybrid_metric_fleet_prevalence_2stage.yl2",
        "PLAYBOOK_BEHAVIORAL_HUNT_MATCH",
        "create_rule",
        "validate_rule",
    )
    for token in required_tokens:
      self.assertIn(token, block, f"Canonical routing table missing '{token}'")

    for retired in RETIRED_TEMPLATES:
      self.assertNotIn(retired, block)

  def test_cross_skill_routing_table_byte_for_byte_parity(self):
    sh_root = _find_peer_repo("secops-statistical-hunter")
    if sh_root is None:
      self.skipTest("secops-statistical-hunter sibling repo not checked out")

    rm_block = _extract_canonical_table(
        (HERE / "SKILL.md").read_text(encoding="utf-8")
    )
    sh_skill_md = (sh_root / "SKILL.md").read_text(encoding="utf-8")
    sh_block = _extract_canonical_table(sh_skill_md)
    self.assertEqual(
        rm_block.encode("utf-8"),
        sh_block.encode("utf-8"),
        "Canonical routing table drifted between risk-metrics and statistical-hunter SKILL.md",
    )

    mod = _load_stats_hunter_builder(sh_root)
    self.assertTrue(
        hasattr(mod, "CANONICAL_ROUTING_TABLE_MD"),
        "multistage_query_builder missing CANONICAL_ROUTING_TABLE_MD",
    )
    self.assertEqual(
        rm_block.encode("utf-8"),
        mod.CANONICAL_ROUTING_TABLE_MD.encode("utf-8"),
        "CANONICAL_ROUTING_TABLE_MD drifted from SKILL.md block",
    )

  def test_zero_ping_pong_and_matrix_alignment_with_peer_builder(self):
    sh_root = _find_peer_repo("secops-statistical-hunter")
    if sh_root is None:
      self.skipTest("secops-statistical-hunter sibling repo not checked out")

    mod = _load_stats_hunter_builder(sh_root)
    self.assertTrue(hasattr(mod, "CANONICAL_ROUTING_MATRIX"))
    matrix = mod.CANONICAL_ROUTING_MATRIX
    self.assertEqual([entry["precedence"] for entry in matrix], [1, 2, 3, 4])

    rm_pipelines = {p.name for p in (HERE / "templates" / "pipelines").glob("*.yl2")}
    sh_pipelines = {p.name for p in (sh_root / "templates" / "pipelines").glob("*.yl2")}
    for entry in matrix:
      for tpl in entry.get("canonical_templates", ()):
        for retired in RETIRED_TEMPLATES:
          self.assertNotIn(retired, tpl)
        if entry["precedence"] == 1:
          self.assertIn(tpl, sh_pipelines)
        elif entry["precedence"] == 2:
          self.assertIn(tpl, rm_pipelines)

    check = mod.check_routing_recommendation
    micro_prompts = [
        "Use UEBA to detect C2 beaconing jitter",
        "Detect off-hours circadian login anomalies by hour of day using UEBA",
        "Run MAD on raw DNS query string length",
        "Detect obfuscated PowerShell command lines with Shannon character entropy",
        "Use UEBA to detect Markov 2-gram rare parent-child process transitions",
        "Hunt intraday EWMA burst velocity using UEBA",
    ]
    for prompt in micro_prompts:
      self.assertIsNone(
          check(prompt),
          f"Precedence 1 prompt must stay in statistical-hunter without ping-pong: {prompt}",
      )

    macro_expectations = [
        ("Run 30-day login baseline for charles.hardy", "metrics.auth_attempts_total", "standard_z_score_2stage.yl2"),
        ("Compare user against IT department peer cohort", "metrics.auth_attempts_total", "dual_baseline_delta_z_3stage.yl2"),
        ("Run 360 entity health check and risk score", "graph.risk_score", "radar_360_decoupled_sector.yl2"),
        ("Detect 14-day longitudinal CUSUM exfiltration drift", "metrics.network_bytes_outbound", "longitudinal_cusum_series_3stage.yl2"),
        ("Run 30-day MAD baseline on metrics.network_bytes_outbound", "metrics.network_bytes_outbound", "mad_robust_z_4stage.yl2"),
        ("Evaluate 30-day metrics.auth_attempts_total first_seen novelty", "metrics.auth_attempts_total", "first_seen_novelty_2stage.yl2"),
    ]
    for prompt, exp_metric, exp_pipeline in macro_expectations:
      rec = check(prompt)
      self.assertIsNotNone(rec, f"Expected macro delegation for: {prompt}")
      self.assertEqual(rec["target_skill"], "secops-risk-metrics-multistage")
      self.assertEqual(rec["recommended_metric"], exp_metric)
      self.assertEqual(rec["recommended_pipeline"], exp_pipeline)
      self.assertIn(rec["recommended_pipeline"], rm_pipelines)


if __name__ == "__main__":
  unittest.main()
