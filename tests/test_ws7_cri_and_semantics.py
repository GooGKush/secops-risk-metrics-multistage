# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Contract tests for WS7-01 (D5 canonical CRI) and WS7-02 (Z-equivalent registry & sigma units)."""

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


class TestWS702ScoreSemanticsRegistry(unittest.TestCase):
  """WS7-02: Z-equivalent registry mapping thresholds to 3.0, flipping inverted ratios, and restricting sigma unit."""

  def test_every_model_threshold_maps_to_z_equiv_3_0_and_cri_50(self) -> None:
    threshold_cases = (
        ("z_score", 3.0),
        ("personal_z", 3.0),
        ("modified_z", 3.5),
        ("m_z_score", 3.5),
        ("quantile_z", 3.5),
        ("fence_z", 3.5),
        ("fleet_z", 2.5),
        ("z_log", 2.5),
        ("fold_change", 2.0),
        ("surge_ratio", 2.0),
        ("tukey_fence_ratio", 2.0),
        ("bayes_shift_ratio", 2.0),
        ("posterior_lift", 2.0),
        ("ratio", 1.0),
        ("fano_factor", 4.0),
        ("cv", 0.20),
        ("diversity_z", -1.5),
        ("posterior_fail_prob", 0.50),
        ("regularized_failure_prob", 0.50),
        ("posterior_rate", 0.50),
        ("concentration_ratio", 0.65),
        ("producer_ratio", 0.70),
        ("sensitivity_excess", 0.0),
        ("composite_threat_norm_sq", 12.25),
        ("poisson_z_sq", 12.25),
        ("threat_vector_norm_sq", 9.0),
        ("shannon_entropy_score", 5.5),
        ("zipf_rarity_score", 2.5),
        ("velocity_score", 2.0),
        ("velocity_kmh", 900.0),
        ("cusum_drift_score", 3.0),
        ("hurdle_threat_score", 3.0),
        ("cri_score", 50.0),
    )
    for key, thresh_val in threshold_cases:
      with self.subTest(key=key, thresh=thresh_val):
        z_eq = uc.score_to_z_equivalent(key, thresh_val)
        self.assertAlmostEqual(z_eq, 3.0, places=4)
        self.assertEqual(uc.cri_from_model_score(key, thresh_val), 50)

  def test_nominal_baselines_and_inverted_scores_behave_monotonically(self) -> None:
    # Fold-change / Tukey / Fano nominal baselines <= 1.0 -> Z_equiv = 0.0 -> CRI = 0
    for key in ("fold_change", "surge_ratio", "tukey_fence_ratio", "bayes_shift_ratio", "fano_factor"):
      self.assertEqual(uc.score_to_z_equivalent(key, 1.0), 0.0)
      self.assertEqual(uc.cri_from_model_score(key, 1.0), 0)
      self.assertEqual(uc.cri_from_model_score(key, 0.5), 0)

    # Inverted CV: 0.0 is robotic zero-jitter maximum anomaly (Z_equiv=5.0, CRI=77); >=0.50 is nominal (0); <0 is invalid (None)
    self.assertAlmostEqual(uc.score_to_z_equivalent("cv", 0.0), 5.0)
    self.assertEqual(uc.cri_from_model_score("cv", 0.0), 77)
    self.assertEqual(uc.cri_from_model_score("cv", 0.50), 0)
    self.assertEqual(uc.cri_from_model_score("cv", 0.80), 0)
    self.assertIsNone(uc.score_to_z_equivalent("cv", -0.1))
    self.assertIsNone(uc.cri_from_model_score("cv", -0.1))

    # Inverted diversity_z: positive/zero is nominal (0); negative is anomalous
    self.assertEqual(uc.cri_from_model_score("diversity_z", 0.0), 0)
    self.assertEqual(uc.cri_from_model_score("diversity_z", 1.8), 0)
    self.assertEqual(uc.cri_from_model_score("diversity_z", -3.0), 86)

    # Precomputed cri_score preserves exact CRI rather than saturating sigmoid
    self.assertEqual(uc.cri_from_model_score("cri_score", 85), 85)
    self.assertEqual(uc.cri_from_model_score("cri_score", 0), 0)

  def test_sigma_unit_shown_only_for_true_sigma_keys(self) -> None:
    true_sigma = ("z_score", "personal_z", "modified_z", "m_z_score", "quantile_z", "poisson_z", "delta_z", "diversity_z", "z_auth")
    for k in true_sigma:
      self.assertTrue(uc.is_true_sigma_key(k), f"Expected {k} to be true sigma")
    self.assertEqual(uc.format_score_with_unit("z_score", 4.25), "+4.25σ")
    self.assertEqual(uc.format_score_with_unit("diversity_z", -1.5), "-1.50σ")

    non_sigma = (
        "fold_change",
        "tukey_fence_ratio",
        "surge_ratio",
        "fano_factor",
        "cv",
        "posterior_fail_prob",
        "cusum_drift_score",
        "hurdle_threat_score",
        "threat_distance",
        "composite_threat_norm_sq",
        "shannon_entropy_score",
        "zipf_rarity_score",
        "velocity_score",
        "velocity_kmh",
        "sensitivity_excess",
    )
    for k in non_sigma:
      self.assertFalse(uc.is_true_sigma_key(k), f"Expected {k} NOT to be true sigma")
      formatted = uc.format_score_with_unit(k, 2.5)
      self.assertNotIn("σ", formatted)
      self.assertEqual(formatted, "2.50")

  def test_engine_triage_formatter_and_timeline_apply_z_equiv_and_unit_labels(self) -> None:
    # 1. Engine _normalize_single_row + render_forensic_dossier on non-sigma fold_change=2.0 -> CRI=50, no sigma on cell
    norm_fc = engine._normalize_single_row({"entity": "srv-01", "fold_change": 2.0, "observed": 200, "hist_avg": 100, "hist_stddev": 20})
    self.assertEqual(norm_fc["cri"], 50)
    self.assertFalse(norm_fc["is_true_sigma"])
    self.assertEqual(norm_fc["score_display"], "2.00")

    dossier_fc = engine.render_forensic_dossier(
        rows=[{"entity": "srv-01", "fold_change": 2.0, "observed": 200, "hist_avg": 100, "hist_stddev": 20}],
        executed_query="// Goal: test\n",
        statistical_model="RELATIVE_DEVIATION",
        skip_postflight_audit=True,
    )
    table_part = dossier_fc["dossier_markdown"].split("#### 2. Ranked Outlier Summary")[1].split("> [!TIP]")[0]
    self.assertIn("`2.00`", table_part)
    self.assertNotIn("`+2.00σ`", table_part)
    self.assertNotIn("`+3.00σ`", table_part)
    self.assertIn("**`50`** (MEDIUM)", table_part)

    # 2. Engine inverted CV: cv=0.05 ranks above cv=0.45 and gets CRI=71
    dossier_cv = engine.render_forensic_dossier(
        rows=[
            {"entity": "human-host", "cv": 0.45, "observed": 30, "hist_avg": 25, "hist_stddev": 5},
            {"entity": "beacon-host", "cv": 0.05, "observed": 30, "hist_avg": 25, "hist_stddev": 5},
        ],
        executed_query="// Goal: cv test\n",
        statistical_model="COEFFICIENT_OF_VARIATION",
        skip_postflight_audit=True,
    )
    self.assertEqual(dossier_cv["outliers"][0]["entity"], "beacon-host")
    self.assertEqual(dossier_cv["outliers"][0]["cri"], 71)

    # 3. CommonMarkTriageFormatter omits sigma on fold_change and Threat Distance (D)
    fmt_fc = tf.CommonMarkTriageFormatter.format_report(
        reduced_data={
            "outlier_count": 1,
            "primary_score_metric": "fold_change",
            "top_outliers": [{"entity": "srv-backup-01", "observed": 200, "hist_avg": 100, "hist_stddev": 10, "fold_change": 2.0}],
        },
        target_metric="metrics.network_bytes_outbound",
        statistical_model="RELATIVE_DEVIATION",
        anomaly_threshold=2.0,
    )
    fmt_table = fmt_fc.split("#### 📊 Ranked Outlier Summary")[1].split("> [!TIP]")[0]
    self.assertIn("`2.00`", fmt_table)
    self.assertNotIn("2.0σ", fmt_table)
    self.assertIn("**`50`** (MEDIUM)", fmt_table)

    fmt_ms = tf.CommonMarkTriageFormatter.format_report(
        reduced_data={
            "outlier_count": 1,
            "top_outliers": [{"entity": "u-multi", "z_auth": 2.5, "z_proc": 2.0, "z_net": 1.5, "threat_distance": 3.54}],
        },
        target_metric="metrics.auth_attempts_fail",
        statistical_model="MULTI_SECTOR_FUSION",
        anomaly_threshold=3.5,
    )
    ms_table = fmt_ms.split("#### 📊 Ranked Outlier Summary")[1].split("> [!TIP]")[0]
    self.assertIn("`+2.5σ`", ms_table)
    self.assertIn("`3.54`", ms_table)
    self.assertNotIn("3.54σ", ms_table)

    # 4. TimelineAssembler maps tukey_fence_ratio=2.0 -> CRI=50, modified_z=3.5 -> CRI=50, cv=0.05 beats cv=0.40
    asm_tukey = ta.TimelineAssembler()
    asm_tukey.add_shard("2026-10-01", [{"entity": "u1", "tukey_fence_ratio": 2.0}])
    self.assertEqual(asm_tukey.build()["top"][0]["cri"], 50)

    asm_mad = ta.TimelineAssembler()
    asm_mad.add_shard("2026-10-01", [{"entity": "u1", "modified_z": 3.5}])
    self.assertEqual(asm_mad.build()["top"][0]["cri"], 50)

    asm_cv = ta.TimelineAssembler()
    asm_cv.add_shard("2026-10-01", [{"entity": "h-beacon", "cv": 0.05}, {"entity": "h-human", "cv": 0.40}])
    cv_summary = asm_cv.build()
    self.assertEqual(cv_summary["days"][0]["top_entity"], "h-beacon")
    self.assertEqual(cv_summary["entities"]["h-beacon"]["peak_cri"], 71)


if __name__ == "__main__":
  unittest.main()
