"""Unit tests for the 6-Pillar CommonMark Triage Formatter."""

import os
import sys
import unittest

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_DIR not in sys.path:
  sys.path.insert(0, REPO_DIR)

from scripts.triage_formatter import CommonMarkTriageFormatter


class TestTriageFormatter(unittest.TestCase):

  def setUp(self):
    self.sample_reduced_data = {
        "target_metric": "metrics.file_executions_total",
        "statistical_model": "PARAMETRIC_ZSCORE",
        "outlier_count": 1,
        "primary_score_metric": "z_score",
        "top_outliers": [
            {
                "entity": "dev-win10-14.site.lan",
                "observed": 288,
                "hist_avg": 137.46,
                "hist_stddev": 33.66,
                "z_score": 4.47,
                "cri": 71,
                "tier": "HIGH_THREAT"
            }
        ]
    }
    self.sample_query = (
        "stage host_hourly {\n"
        "  metadata.event_type = \"PROCESS_LAUNCH\"\n"
        "  principal.asset.hostname = $host\n"
        "  match: $host by 1h\n"
        "  outcome: $hourly_count = count(metadata.id)\n"
        "}\n"
    )

  def test_format_report_contains_all_six_sections(self):
    """Report must strictly contain all 6 numbered pillars."""
    report = CommonMarkTriageFormatter.format_report(
        reduced_data=self.sample_reduced_data,
        target_metric="metrics.file_executions_total",
        statistical_model="PARAMETRIC_ZSCORE",
        anomaly_threshold=2.0,
        executed_query=self.sample_query
    )

    # 1. Executive Headline
    self.assertIn("### ⚡ Statistical Outlier Report:", report)
    self.assertIn("Active Search Window", report)
    self.assertIn("Historical Baseline Horizon", report)

    # 2. Executed Multi-Stage YARA-L Query
    self.assertIn("#### 💻 Executed Multi-Stage YARA-L Query", report)
    self.assertIn("stage host_hourly", report)

    # 3. Ranked Outlier Summary Table
    self.assertIn("#### 📊 Ranked Outlier Summary", report)
    self.assertIn("dev-win10-14.site.lan", report)

    # 4. Forensic Vector Breakdown & Action Plan
    self.assertIn("#### 🔍 Forensic Vector Breakdown", report)
    self.assertIn("> [!IMPORTANT]", report)

    # 5. Chronicle UI Manual Pivot (Triage Reference Only)
    self.assertIn("#### 🎯 Chronicle UI Manual Pivot (Triage Reference Only)", report)
    self.assertIn("principal.user.userid = \"dev-win10-14.site.lan\"", report)

    # 6. Collapsible Technical Appendix
    self.assertIn("<details open>", report)
    self.assertIn("🔬 <b>Statistical & Mathematical Appendix (Technical Details)</b>", report)
    self.assertIn("</details>", report)

  def test_executed_query_is_preserved_verbatim(self):
    """Section 2 code block must contain the exact query string provided."""
    custom_query = "// LITERAL_EXECUTION_VERBATIM_CHECK\nmetadata.event_type = \"USER_LOGIN\"\n"
    report = CommonMarkTriageFormatter.format_report(
        reduced_data=self.sample_reduced_data,
        target_metric="metrics.auth_attempts_total",
        statistical_model="PARAMETRIC_ZSCORE",
        anomaly_threshold=3.0,
        executed_query=custom_query
    )
    self.assertIn("// LITERAL_EXECUTION_VERBATIM_CHECK", report)

  def test_classify_hunt_outcome_four_shapes(self):
    """classify_hunt_outcome must deterministically classify all 4 outcome shapes."""
    self.assertEqual(
        CommonMarkTriageFormatter.classify_hunt_outcome(self.sample_reduced_data, anomaly_threshold=3.0),
        "ACUTE_OUTLIER",
    )
    self.assertEqual(
        CommonMarkTriageFormatter.classify_hunt_outcome({"outlier_count": 0, "top_outliers": []}, anomaly_threshold=3.0),
        "CLEAN_OR_SUBTHRESHOLD",
    )
    subthreshold_data = {
        "outlier_count": 1,
        "primary_score_metric": "z_score",
        "top_outliers": [{"entity": "host-1", "z_score": 2.1}],
    }
    self.assertEqual(
        CommonMarkTriageFormatter.classify_hunt_outcome(subthreshold_data, anomaly_threshold=3.0),
        "CLEAN_OR_SUBTHRESHOLD",
    )
    fleet_wave_data = {
        "outlier_count": 12,
        "primary_score_metric": "z_score",
        "top_outliers": [{"entity": f"host-{i}", "z_score": 4.2} for i in range(12)],
    }
    self.assertEqual(
        CommonMarkTriageFormatter.classify_hunt_outcome(fleet_wave_data, anomaly_threshold=3.0),
        "FLEET_WAVE",
    )
    sparse_data = {
        "outlier_count": 1,
        "primary_score_metric": "z_score",
        "top_outliers": [{"entity": "dormant-sa", "z_score": 5.0, "active_days": 2}],
    }
    self.assertEqual(
        CommonMarkTriageFormatter.classify_hunt_outcome(sparse_data, anomaly_threshold=3.0),
        "SPARSE_BASELINE",
    )

  def test_pillar4_includes_agentic_next_steps_and_clean_hunt_report(self):
    """Pillar 4 must include outcome-driven Agentic Next Steps while Pillar 5 stays passive."""
    report = CommonMarkTriageFormatter.format_report(
        reduced_data=self.sample_reduced_data,
        target_metric="metrics.file_executions_total",
        statistical_model="PARAMETRIC_ZSCORE",
        anomaly_threshold=3.0,
        executed_query=self.sample_query,
    )
    self.assertIn("🧭 Agentic Next Steps (Outcome Classification: `ACUTE_OUTLIER` — State 3 → Phase 1B Pivot)", report)
    self.assertIn("[A] Cross-Sector Fusion / 360° Radar", report)
    self.assertIn("[B] Two-Phase Chained Entity Pivot", report)
    self.assertIn("[C] Novelty & Prevalence Verification / Alert Escalation", report)

    clean_report = CommonMarkTriageFormatter.format_clean_hunt_report(
        target_metric="metrics.network_bytes_outbound",
        statistical_model="STANDARD_Z_SCORE",
        executed_query=self.sample_query,
        anomaly_threshold=3.0,
    )
    self.assertIn("### 🟢 Clean Hunt Summary:", clean_report)
    self.assertIn("Outcome Classification: `CLEAN_OR_SUBTHRESHOLD`", clean_report)
    self.assertIn("LONGITUDINAL_CUSUM", clean_report)


if __name__ == '__main__':
  unittest.main()
