# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unit and contract tests for shared UEBA constants (WS2-08)."""

import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import preflight_validator, radar_collector, template_router, ueba_constants, ueba_hybrid_engine


class TestUEBAConstantsContract(unittest.TestCase):
  """Verifies centralized thresholds, tier resolution, and module wiring (WS2-08)."""

  def test_canonical_sensitivity_threshold_map_values(self):
    self.assertEqual(
        ueba_constants.SENSITIVITY_THRESHOLD_MAP,
        {
            "HIGH_RECALL": {
                "anomaly_threshold": 2.0,
                "fold_change_threshold": 1.5,
                "fusion_threshold_sq": 6.25,
                "robust_threshold": 2.5,
            },
            "BALANCED": {
                "anomaly_threshold": 3.0,
                "fold_change_threshold": 2.0,
                "fusion_threshold_sq": 12.25,
                "robust_threshold": 3.5,
            },
            "HIGH_PRECISION": {
                "anomaly_threshold": 4.0,
                "fold_change_threshold": 3.0,
                "fusion_threshold_sq": 20.25,
                "robust_threshold": 4.5,
            },
        },
    )

  def test_operational_threshold_constants(self):
    self.assertEqual(ueba_constants.DEFAULT_SENSITIVITY_TIER, "BALANCED")
    self.assertEqual(ueba_constants.DEFAULT_ANOMALY_THRESHOLD, 3.0)
    self.assertEqual(ueba_constants.DEFAULT_FOLD_CHANGE_THRESHOLD, 2.0)
    self.assertEqual(ueba_constants.DEFAULT_FUSION_THRESHOLD_SQ, 12.25)
    self.assertEqual(ueba_constants.DEFAULT_ROBUST_THRESHOLD, 3.5)
    self.assertEqual(ueba_constants.DEFAULT_MIN_BASELINE_DAYS, 7)
    self.assertEqual(ueba_constants.RADAR_FUSION_DISTANCE_THRESHOLD, 3.0)
    self.assertEqual(ueba_constants.WRITEBACK_CRI_THRESHOLD, 50)
    self.assertEqual(ueba_constants.LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD, 25.0)
    self.assertEqual(ueba_constants.LOOPBACK_MIN_DISTINCT_HITS, 2)
    self.assertEqual(ueba_constants.MAX_MODE_B_DAYS_MACRO, 3)
    self.assertEqual(ueba_constants.MAX_CUSUM_MODE_B_DAYS_MACRO, 14)
    self.assertEqual(ueba_constants.MAX_MODE_C_DAYS_MACRO, 30)
    self.assertEqual(ueba_constants.MAX_MODE_B_DAYS_MICRO, 14)

  def test_cross_skill_sensitivity_tier_resolution(self):
    for raw in ("HIGH_RECALL", "AGGRESSIVE", "LOW", "BROAD", "SENSITIVE", "high-recall", "aggressive"):
      self.assertEqual(ueba_constants.resolve_sensitivity_tier(raw, strict=True), "HIGH_RECALL")
      self.assertEqual(ueba_constants.resolve_micro_sensitivity_tier(raw, strict=True), "AGGRESSIVE")

    for raw in ("BALANCED", "MEDIUM", "DEFAULT", "STANDARD", "", None):
      if raw:
        self.assertEqual(ueba_constants.resolve_sensitivity_tier(raw, strict=True), "BALANCED")
      self.assertEqual(ueba_constants.resolve_sensitivity_tier(raw, strict=False), "BALANCED")
      self.assertEqual(ueba_constants.resolve_micro_sensitivity_tier(raw, strict=False), "BALANCED")

    for raw in ("HIGH_PRECISION", "CONSERVATIVE", "HIGH", "STRICT", "high-precision", "conservative"):
      self.assertEqual(ueba_constants.resolve_sensitivity_tier(raw, strict=True), "HIGH_PRECISION")
      self.assertEqual(ueba_constants.resolve_micro_sensitivity_tier(raw, strict=True), "CONSERVATIVE")

    with self.assertRaises(ValueError):
      ueba_constants.resolve_sensitivity_tier("NONEXISTENT_TIER", strict=True)
    with self.assertRaises(ValueError):
      ueba_constants.resolve_micro_sensitivity_tier("NONEXISTENT_TIER", strict=True)
    self.assertEqual(ueba_constants.resolve_sensitivity_tier("NONEXISTENT_TIER", strict=False), "BALANCED")

  def test_macro_modules_delegate_to_ueba_constants(self):
    self.assertIs(ueba_hybrid_engine.SENSITIVITY_THRESHOLD_MAP, ueba_constants.SENSITIVITY_THRESHOLD_MAP)
    self.assertIs(ueba_hybrid_engine.SENSITIVITY_ALIASES, ueba_constants.SENSITIVITY_ALIASES)
    self.assertEqual(ueba_hybrid_engine.MAX_MODE_B_DAYS, ueba_constants.MAX_MODE_B_DAYS_MACRO)
    self.assertEqual(ueba_hybrid_engine.MAX_CUSUM_MODE_B_DAYS, ueba_constants.MAX_CUSUM_MODE_B_DAYS_MACRO)
    self.assertEqual(ueba_hybrid_engine.MAX_MODE_C_DAYS, ueba_constants.MAX_MODE_C_DAYS_MACRO)
    self.assertEqual(radar_collector.RADAR_FUSION_DISTANCE_THRESHOLD, ueba_constants.RADAR_FUSION_DISTANCE_THRESHOLD)
    self.assertEqual(template_router.DEFAULT_ANOMALY_THRESHOLD, ueba_constants.DEFAULT_ANOMALY_THRESHOLD)
    self.assertEqual(template_router.DEFAULT_FOLD_CHANGE_THRESHOLD, ueba_constants.DEFAULT_FOLD_CHANGE_THRESHOLD)
    self.assertEqual(template_router.DEFAULT_FUSION_THRESHOLD_SQ, ueba_constants.DEFAULT_FUSION_THRESHOLD_SQ)
    self.assertEqual(template_router.DEFAULT_ROBUST_THRESHOLD, ueba_constants.DEFAULT_ROBUST_THRESHOLD)
    self.assertEqual(preflight_validator.DEFAULT_MIN_BASELINE_DAYS, ueba_constants.DEFAULT_MIN_BASELINE_DAYS)

  def test_sibling_skill_ueba_constants_identical_if_present(self):
    here = Path(__file__).resolve().parent.parent
    local_file = here / "scripts" / "ueba_constants.py"
    self.assertTrue(local_file.exists())

    # Check either sibling worktree (-WS2 / -WS7) or canonical sibling repo if present
    candidates = []
    if here.name.startswith("secops-risk-metrics-multistage-"):
      suffix = here.name.replace("secops-risk-metrics-multistage-", "")
      candidates.append(here.parent / f"secops-statistical-hunter-{suffix}" / "scripts" / "ueba_constants.py")
    candidates.append(here.parent / "secops-statistical-hunter" / "scripts" / "ueba_constants.py")

    sibling = next((p for p in candidates if p.exists()), None)
    if sibling is None:
      self.skipTest("Sibling ueba_constants.py not yet checked out next to this worktree")
    h1 = hashlib.sha256(local_file.read_bytes()).hexdigest()
    h2 = hashlib.sha256(sibling.read_bytes()).hexdigest()
    self.assertEqual(h1, h2, f"ueba_constants.py drifted between skills: {local_file} vs {sibling}")


if __name__ == "__main__":
  unittest.main()
