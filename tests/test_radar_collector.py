"""Unit Tests for 360-Degree Entity Behavioral Risk Radar Collector & Visualizer.

Author: Greg Kushmerek
"""

import math
import unittest
from scripts.preflight_validator import MalachiteASTValidator
from scripts.radar_collector import EntityRadarCollector, MetricSpoke


class TestRadarCollector(unittest.TestCase):
  """Tests mathematical normalization, composite threat calculation, and SVG/Markdown visualizers."""

  def setUp(self):
    self.collector = EntityRadarCollector()
    self.sample_spokes = [
        MetricSpoke(
            sector="Cloud Infrastructure",
            spoke_name="Cloud Deletions",
            metric_table="resource_deletion_total",
            observed=640.0,
            baseline_mean=21.3,
            baseline_stddev=2.1,
            z_score=3.80,
            unit="events",
        ),
        MetricSpoke(
            sector="Workspace Data",
            spoke_name="Drive Downloads",
            metric_table="workspace_total_download_actions",
            observed=142.0,
            baseline_mean=12.0,
            baseline_stddev=1.8,
            z_score=3.20,
            unit="events",
        ),
        MetricSpoke(
            sector="Network Egress",
            spoke_name="Outbound Bytes",
            metric_table="network_bytes_outbound",
            observed=1200000000.0,
            baseline_mean=900000000.0,
            baseline_stddev=150000000.0,
            z_score=0.80,
            unit="bytes",
        ),
        MetricSpoke(
            sector="IAM & Authentication",
            spoke_name="Auth Successes",
            metric_table="auth_attempts_success",
            observed=18.0,
            baseline_mean=14.0,
            baseline_stddev=2.5,
            z_score=0.50,
            unit="logins",
        ),
        MetricSpoke(
            sector="IAM & Authentication",
            spoke_name="Auth Failures",
            metric_table="auth_attempts_fail",
            observed=0.0,
            baseline_mean=1.0,
            baseline_stddev=0.5,
            z_score=0.00,
            unit="logins",
        ),
    ]

  def test_metric_spoke_serialization(self):
    """MetricSpoke dataclass must serialize cleanly to dict."""
    spoke = self.sample_spokes[0]
    data = spoke.to_dict()
    self.assertEqual(data["spoke_name"], "Cloud Deletions")
    self.assertEqual(data["z_score"], 3.80)
    self.assertEqual(data["sector"], "Cloud Infrastructure")

  def test_calculate_composite_risk_empty_spokes(self):
    """Empty spoke list must return D = 0.0 and CRI = 0."""
    d, cri = EntityRadarCollector.calculate_composite_risk([])
    self.assertEqual(d, 0.0)
    self.assertEqual(cri, 0)

  def test_calculate_composite_risk_nominal(self):
    """Nominal spokes (Z < 1.0) must yield low D and low CRI score."""
    nominal_spokes = [
        MetricSpoke("IAM", "Auth", "auth", 10, 10, 2, 0.0),
        MetricSpoke("Net", "Egress", "net", 50, 50, 5, 0.2),
        MetricSpoke("Cloud", "Create", "cloud", 2, 2, 1, 0.1),
    ]
    d, cri = EntityRadarCollector.calculate_composite_risk(nominal_spokes)
    self.assertLess(d, 1.0)
    self.assertLess(cri, 25)

  def test_calculate_composite_risk_anomalous_fusion(self):
    """Multi-sector outliers must calculate Euclidean norm D = sqrt(sum Z^2)."""
    # Z1 = 3.80, Z2 = 3.20, Z3 = 0.80, Z4 = 0.50, Z5 = 0.0
    # Expected D = sqrt(3.8^2 + 3.2^2 + 0.8^2 + 0.5^2) = sqrt(14.44 + 10.24 + 0.64 + 0.25) = sqrt(25.57) approx 5.06
    d, cri = EntityRadarCollector.calculate_composite_risk(self.sample_spokes)
    expected_d = round(math.sqrt(3.8**2 + 3.2**2 + 0.8**2 + 0.5**2), 2)
    self.assertEqual(d, expected_d)
    self.assertGreaterEqual(cri, 60)

  def test_build_radar_payload_structure(self):
    """build_radar_payload must assemble complete typed dictionary."""
    payload = self.collector.build_radar_payload(
        entity_id="tim.smith@altostrat.com",
        entity_type="USER",
        spokes=self.sample_spokes,
    )
    self.assertEqual(payload["entity_id"], "tim.smith@altostrat.com")
    self.assertEqual(payload["entity_type"], "USER")
    self.assertTrue(payload["is_anomalous"])
    self.assertEqual(payload["top_outlier_spoke"], "Cloud Deletions")
    self.assertEqual(payload["top_outlier_z"], 3.80)
    self.assertEqual(payload["spoke_count"], 5)
    self.assertIn("<svg", payload["svg_widget"])
    self.assertIn("360° Entity Behavioral Risk Radar", payload["markdown_table"])
    self.assertEqual(payload["chartjs_spec"]["type"], "radar")

  def test_generate_self_contained_svg(self):
    """Generated SVG must contain valid tags, concentric rings, and title tooltips."""
    svg = EntityRadarCollector.generate_self_contained_svg(
        entity_id="tim.smith@altostrat.com",
        spokes=self.sample_spokes,
        composite_d=5.06,
        cri=78,
    )
    self.assertIn("<svg", svg)
    self.assertIn("</svg>", svg)
    self.assertIn("<polygon", svg)
    self.assertIn("+3σ", svg)
    self.assertIn("+1σ", svg)
    self.assertIn("tim.smith@altostrat.com", svg)
    self.assertIn("Cloud Deletions", svg)
    self.assertIn("<title>", svg)
    self.assertIn("24h Observed: 640.0", svg)

  def test_generate_markdown_summary(self):
    """Markdown summary must include formatted table and visual magnitude bars."""
    md = EntityRadarCollector.generate_markdown_summary(
        entity_id="tim.smith@altostrat.com",
        spokes=self.sample_spokes,
        composite_d=5.06,
        cri=78,
    )
    self.assertIn("### 🚨 360° Entity Behavioral Risk Radar", md)
    self.assertIn("| Telemetry Sector Spoke |", md)
    self.assertIn("Cloud Deletions", md)
    self.assertIn("▰", md)
    self.assertIn("+3.80σ", md)
    self.assertIn("🚨 **Anomaly**", md)

  def test_generate_chartjs_spec(self):
    """Chart.js spec must define radar type, spoke labels, and +3.0σ boundary."""
    spec = EntityRadarCollector.generate_chartjs_spec(
        entity_id="tim.smith@altostrat.com",
        spokes=self.sample_spokes,
        composite_d=5.06,
        cri=78,
    )
    self.assertEqual(spec["type"], "radar")
    self.assertEqual(len(spec["data"]["labels"]), 5)
    self.assertEqual(len(spec["data"]["datasets"]), 2)
    self.assertEqual(spec["data"]["datasets"][1]["label"], "Anomaly Boundary (+3.0σ)")

  def test_user_sector_queries_are_compiler_valid(self):
    """All user sector query templates must pass MalachiteASTValidator with goal header."""
    for sector, query_tpl in EntityRadarCollector.USER_SECTOR_QUERIES.items():
      query = f"// Goal: Sector {sector}\n" + (query_tpl % {"entity_id": "test_user"})
      errors = MalachiteASTValidator.validate_query(query)
      self.assertEqual(
          errors,
          [],
          f"Sector query for '{sector}' produced AST validator errors: {errors}",
      )

  def test_asset_sector_queries_are_compiler_valid(self):
    """All asset sector query templates must pass MalachiteASTValidator with goal header."""
    for sector, query_tpl in EntityRadarCollector.ASSET_SECTOR_QUERIES.items():
      query = f"// Goal: Sector {sector}\n" + (query_tpl % {"entity_id": "test_asset"})
      errors = MalachiteASTValidator.validate_query(query)
      self.assertEqual(
          errors,
          [],
          f"Sector query for '{sector}' produced AST validator errors: {errors}",
      )


if __name__ == "__main__":
  unittest.main()
