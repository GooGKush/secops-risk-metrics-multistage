"""Unit tests for UI Charting & Axis Isolation in SecOps Risk Metrics."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from scripts.chart_generator import RiskMetricsChartGenerator


class TestRiskMetricsChartSpecifications(unittest.TestCase):

  def setUp(self):
    self.sample_outliers = [
        {"entity": "srv-db-01.corp", "observed": 450, "baseline_mean": 50.0, "z_score": 8.4, "cri": 98},
        {"entity": "srv-app-04.corp", "observed": 280, "baseline_mean": 45.0, "z_score": 4.2, "cri": 68},
    ]
    self.sample_timeline = [
        {"date": "2026-08-01", "observed": 12, "baseline_mean": 10.5, "baseline_lower": 4.5, "baseline_upper": 16.5, "z_score": 0.5},
        {"date": "2026-08-26", "observed": 185, "baseline_mean": 10.5, "baseline_lower": 4.5, "baseline_upper": 16.5, "z_score": 15.2},
    ]

  def test_baseline_envelope_chart_structure(self):
    """Baseline envelope chart must contain Area envelope, Mean line, and Observed points."""
    spec = RiskMetricsChartGenerator.generate_baseline_envelope_chart(
        timeline_records=self.sample_timeline,
        entity_id="srv-app-04.corp",
        metric_name="metrics.file_executions_total",
    )
    self.assertEqual(len(spec["layer"]), 3)
    self.assertEqual(spec["layer"][0]["mark"]["type"], "area")
    self.assertEqual(spec["layer"][1]["mark"]["type"], "line")
    self.assertEqual(spec["layer"][2]["mark"]["type"], "line")

  def test_dual_y_outlier_chart_axis_isolation(self):
    """Dual-Y chart must resolve independent Y scales and orient statistical score on the right."""
    spec = RiskMetricsChartGenerator.generate_dual_y_outlier_chart(
        outlier_records=self.sample_outliers,
        target_metric="metrics.network_bytes_outbound",
    )
    self.assertEqual(spec["resolve"]["scale"]["y"], "independent")
    self.assertEqual(spec["layer"][1]["encoding"]["y"]["axis"]["orient"], "right")
    self.assertEqual(spec["layer"][0]["encoding"]["x"]["type"], "nominal")

  def test_chartjs_dual_y_structure(self):
    """Chart.js spec must have separate y and y1 linear scale axes."""
    spec = RiskMetricsChartGenerator.generate_chartjs_dual_y(
        outlier_records=self.sample_outliers,
        target_metric="metrics.auth_attempts_fail",
    )
    self.assertIn("y", spec["options"]["scales"])
    self.assertIn("y1", spec["options"]["scales"])
    self.assertEqual(spec["options"]["scales"]["y"]["position"], "left")
    self.assertEqual(spec["options"]["scales"]["y1"]["position"], "right")


if __name__ == '__main__':
  unittest.main()
