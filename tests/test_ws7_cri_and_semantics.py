# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Contract tests for WS7-01 (D5 canonical CRI) in secops-risk-metrics-multistage."""

import math
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
  sys.path.insert(0, str(REPO_ROOT))

from scripts import radar_collector
from scripts import timeline_assembler as ta
from scripts import triage_formatter as tf
from scripts import ueba_constants as uc
from scripts import ueba_hybrid_engine as engine


class TestWS701CanonicalCRI(unittest.TestCase):
  """WS7-01 / D5: One canonical CRI (0..100, 0 for Z<=0, 26/46/70/90 bands, N/A on missing/error)."""

  def test_canonical_cri_zero_floor_anchors_and_saturation(self) -> None:
    self.assertEqual(uc.calculate_cri(0.0), 0)
    self.assertEqual(uc.calculate_cri(-0.001), 0)
    self.assertEqual(uc.calculate_cri(-5.0), 0)
    self.assertEqual(uc.cri_from_score(0.0), 0)
    self.assertEqual(uc.cri_from_score(-2.5), 0)
    self.assertEqual(uc.calculate_cri(3.0), 50)
    self.assertEqual(uc.calculate_cri(6.0), 86)
    self.assertEqual(uc.calculate_cri(15.0), 100)
    self.assertEqual(uc.calculate_cri(3000.0), 100)

  def test_canonical_cri_missing_and_error_values_return_none_and_na(self) -> None:
    for bad_input in (
        None,
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        "N/A",
        "NaN",
        "-",
        "",
        "unparseable_error",
    ):
      with self.subTest(bad_input=bad_input):
        self.assertIsNone(uc.calculate_cri(bad_input))
        self.assertEqual(uc.format_cri(bad_input), "N/A")
        self.assertEqual(uc.get_cri_badge(bad_input), ("⚪ `[CRI: N/A]`", "N/A"))
        short_badge, full_band, bar = uc.get_cri_band_metadata(bad_input)
        self.assertEqual(short_badge, "N/A")
        self.assertEqual(full_band, "⚪ N/A")
        self.assertEqual(bar, "░░░░░░░░")

  def test_canonical_cri_exact_band_cutoffs_26_46_70_90(self) -> None:
    expected = (
        (0, "INFORMATIONAL", "Nominal", "🟢"),
        (25, "INFORMATIONAL", "Nominal", "🟢"),
        (26, "LOW", "Low Drift", "🟡"),
        (45, "LOW", "Low Drift", "🟡"),
        (46, "MEDIUM", "Medium Outlier", "🟠"),
        (69, "MEDIUM", "Medium Outlier", "🟠"),
        (70, "HIGH", "High Threat", "🔴"),
        (89, "HIGH", "High Threat", "🔴"),
        (90, "CRITICAL", "Critical Outlier", "🚨"),
        (100, "CRITICAL", "Critical Outlier", "🚨"),
    )
    for cri_val, code, label, emoji in expected:
      with self.subTest(cri=cri_val):
        self.assertEqual(uc.get_cri_band_info(cri_val), (code, label, emoji))
        self.assertEqual(uc.get_cri_badge(cri_val), (f"{emoji} `[CRI: {cri_val}]`", label))
        meta_code, meta_full, _ = uc.get_cri_band_metadata(cri_val)
        self.assertEqual(meta_code, code)
        self.assertEqual(meta_full, f"{emoji} {label}")

  def test_timeline_assembler_zero_floor_and_na_handling(self) -> None:
    self.assertEqual(ta.cri_from_score(0.0), 0)
    self.assertEqual(ta.cri_from_score(-3.2), 0)
    self.assertIsNone(ta.cri_from_score(None))
    self.assertIsNone(ta.cri_from_score(float("nan")))

    pt_neg = ta.TimelinePoint(day="2026-10-01", z_score=-1.5)
    self.assertEqual(pt_neg.cri, 0)

    pt_missing = ta.TimelinePoint(day="2026-10-02", z_score=None)
    self.assertIsNone(pt_missing.cri)
    md = ta.format_markdown_table([pt_neg, pt_missing])
    self.assertIn("**`0`**", md)
    self.assertIn("**`N/A`**", md)
    self.assertNotIn("**`14`**", md)

  def test_radar_collector_zero_floor_eliminates_cri_14(self) -> None:
    spokes = [
        radar_collector.MetricSpoke("IAM", "Auth", "metrics.auth_attempts_fail", 0.0, 5.0, 2.0, -2.5),
        radar_collector.MetricSpoke("Net", "Egress", "metrics.network_bytes_outbound", 10.0, 10.0, 2.0, 0.0),
    ]
    self.assertEqual(spokes[0].cri_score, 0)
    self.assertEqual(spokes[1].cri_score, 0)
    d_val, cri_val = radar_collector.EntityRadarCollector.calculate_composite_risk(spokes)
    self.assertEqual(d_val, 0.0)
    self.assertEqual(cri_val, 0)

  def test_engine_and_triage_formatter_missing_and_zero_floor_cri(self) -> None:
    norm_neg = engine._normalize_single_row({"entity": "u-neg", "z_score": -1.2, "observed": 1, "hist_avg": 5, "hist_stddev": 2})
    self.assertEqual(norm_neg["cri"], 0)
    self.assertEqual(norm_neg["cri_badge"], "INFORMATIONAL")

    for err_row in (
        {"entity": "u-missing"},
        {"entity": "u-nan", "z_score": float("nan"), "observed": 10, "hist_avg": 2},
        {"entity": "u-err", "z_score": "N/A", "observed": 10, "hist_avg": 2},
    ):
      with self.subTest(row=err_row):
        norm_err = engine._normalize_single_row(err_row)
        self.assertIsNone(norm_err["cri"])
        self.assertEqual(norm_err["cri_badge"], "N/A")
        self.assertEqual(norm_err["cri_band_label"], "⚪ N/A")

    dossier = engine.render_forensic_dossier(
        rows=[{"entity": "u-err", "z_score": "N/A", "observed": 10, "hist_avg": 2, "hist_stddev": 1}],
        executed_query="// Goal: test\n",
        skip_postflight_audit=True,
    )
    self.assertIn("**`N/A`** (N/A)", dossier["dossier_markdown"])

    fmt_report = tf.CommonMarkTriageFormatter.format_report(
        reduced_data={
            "outlier_count": 1,
            "primary_score_metric": "z_score",
            "top_outliers": [{"entity": "u-no-cri", "observed": 10, "hist_avg": 2, "hist_stddev": 1}],
        },
        target_metric="metrics.auth_attempts_fail",
        statistical_model="STANDARD_Z_SCORE",
        anomaly_threshold=3.0,
    )
    self.assertIn("**`N/A`** (N/A)", fmt_report)
    self.assertNotIn("floor is \\text{CRI} = 14", fmt_report)
    self.assertNotIn("CRI = 14", fmt_report)


if __name__ == "__main__":
  unittest.main()
