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
    self.assertIn('viewBox="0 0 620 480"', svg)
    self.assertIn("<polygon", svg)
    self.assertIn("+3.0σ", svg)
    self.assertIn("+1.0σ", svg)
    self.assertIn("tim.smith@altostrat.com", svg)
    self.assertIn("Cloud Deletions", svg)
    self.assertIn("<tspan", svg)
    self.assertIn("<title>", svg)
    self.assertIn("24h Observed: 640.0", svg)

  def test_generate_self_contained_svg_negative_and_zero_deviations(self):
    """SVG must format negative and zero deviations cleanly without '+-' sign duplication or text truncation."""
    negative_spokes = [
        MetricSpoke("Cloud", "Cloud Deletions", "tbl1", 0.0, 10.0, 2.0, -5.0),
        MetricSpoke("IAM", "Auth Attempts", "tbl2", 5.0, 5.0, 1.0, 0.0),
    ]
    svg = EntityRadarCollector.generate_self_contained_svg(
        entity_id="frank.kolzig",
        spokes=negative_spokes,
        composite_d=0.0,
        cri=0,
    )
    self.assertNotIn("+-", svg)
    self.assertIn("(-5.0σ)", svg)
    self.assertIn("(+0.0σ)", svg)
    self.assertIn("frank.kolzig • 360° BEHAVIORAL RADAR", svg)
    self.assertIn("Multi-Sector Distance: D = 0.00σ", svg)

  def test_generate_self_contained_svg_cri_mode(self):
    """SVG in CRI mode must display 0-100 concentric rings and map 50 to 3.0-sigma threshold."""
    svg = EntityRadarCollector.generate_self_contained_svg(
        entity_id="tim.smith@altostrat.com",
        spokes=self.sample_spokes,
        composite_d=5.06,
        cri=78,
        scale_mode="cri",
    )
    self.assertIn("50 (3.0σ Threshold)", svg)
    self.assertIn("CRI 25", svg)
    self.assertIn("CRI 100", svg)

  def test_extreme_outlier_perimeter_pinning(self):
    """Extreme outliers (e.g. Z=300) must pin to outer perimeter with badge without compressing other spokes."""
    extreme_spokes = [
        MetricSpoke("Cloud", "Deletions", "tbl1", 10000.0, 2.0, 1.0, 300.0),
        MetricSpoke("IAM", "Logins", "tbl2", 2.0, 1.0, 0.5, 2.0),
    ]
    payload = self.collector.build_radar_payload("extreme.user@corp", "USER", extreme_spokes)
    self.assertAlmostEqual(payload["composite_distance_d"], 300.01, places=1)
    self.assertEqual(payload["calibrated_risk_index"], 100)
    self.assertIn("+300.0σ 🚨", payload["svg_widget"])
    self.assertIn("Spoke CRI", payload["markdown_table"])
    self.assertIn("100/100", payload["markdown_table"])

  def test_generate_markdown_summary(self):
    """Markdown summary must include formatted table, Spoke CRI column, visual magnitude bars, and Math Appendix."""
    md = EntityRadarCollector.generate_markdown_summary(
        entity_id="tim.smith@altostrat.com",
        spokes=self.sample_spokes,
        composite_d=5.06,
        cri=78,
    )
    self.assertIn("### 🚨 360° Entity Behavioral Risk Radar", md)
    self.assertIn("| Telemetry Sector Spoke |", md)
    self.assertIn("Spoke CRI", md)
    self.assertIn("Cloud Deletions", md)
    self.assertIn("▰", md)
    self.assertIn("+3.80σ", md)
    self.assertIn("🚨 **Anomaly**", md)
    self.assertIn("Statistical & Mathematical Appendix", md)
    self.assertIn(r"$$Z_i = \frac{\text{Obs}_i - \mu_{i, 30\text{d}}}{\sigma_{i, 30\text{d}} + 1.0}$$", md)
    self.assertIn(r"$$D = \sqrt{\sum_{i=1}^{K} \max(0, Z_i)^2}", md)

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



  def test_generate_data_uri_image(self):
    """Data-URI image must wrap SVG inside a markdown image tag with base64 encoding."""
    payload = self.collector.build_radar_payload("tim.smith@altostrat.com", "USER", self.sample_spokes)
    data_uri = payload["data_uri_image"]
    self.assertTrue(data_uri.startswith("![360° Behavioral Risk Radar: tim.smith@altostrat.com](data:image/svg+xml;base64,"))
    self.assertTrue(data_uri.endswith(")"))

  def test_generate_ascii_chart(self):
    """ASCII chart must render horizontal bars and status indicators for terminals."""
    payload = self.collector.build_radar_payload("tim.smith@altostrat.com", "USER", self.sample_spokes)
    ascii_chart = payload["ascii_chart"]
    self.assertIn("360° BEHAVIORAL RISK RADAR", ascii_chart)
    self.assertIn("tim.smith@altostrat.com", ascii_chart)
    self.assertIn("▰", ascii_chart)
    self.assertIn("Perimeter Threshold: +3.00σ", ascii_chart)


  def test_generate_html_widget(self):
    """HTML widget must wrap SVG inside a Generative UI template compatible with <agent-embed>."""
    payload = self.collector.build_radar_payload("tim.smith@altostrat.com", "USER", self.sample_spokes)
    html_widget = payload["html_widget"]
    self.assertIn('<svg xmlns="http://www.w3.org/2000/svg"', html_widget)
    self.assertIn("tailwindcss.min.js", html_widget)
    self.assertIn("tim.smith@altostrat.com", html_widget)

  def test_canonical_nominal_spokes(self):
    """Canonical nominal spokes must return 5 spokes at 0.00σ baseline for both USER and ASSET."""
    user_spokes = EntityRadarCollector.get_canonical_nominal_spokes("USER")
    self.assertEqual(len(user_spokes), 5)
    for s in user_spokes:
      self.assertEqual(s.z_score, 0.0)

    asset_spokes = EntityRadarCollector.get_canonical_nominal_spokes("ASSET")
    self.assertEqual(len(asset_spokes), 5)
    for s in asset_spokes:
      self.assertEqual(s.z_score, 0.0)

  def test_parse_scores_argument(self):
    """parse_scores_argument must parse key-value pairs into calibrated MetricSpoke instances."""
    spokes = EntityRadarCollector.parse_scores_argument("auth=0.0,cloud=3.8,workspace=3.2,net=0.8,dns=10.8", "USER")
    self.assertEqual(len(spokes), 5)
    spoke_map = {s.spoke_name: s.z_score for s in spokes}
    self.assertEqual(spoke_map["Authentication Attempts"], 0.0)
    self.assertEqual(spoke_map["Cloud Resource CRUD"], 3.8)
    self.assertEqual(spoke_map["Workspace & SaaS Exfil"], 3.2)
    self.assertEqual(spoke_map["Network Egress"], 0.8)
    self.assertEqual(spoke_map["DNS & Web Activity"], 10.8)

    # Backward-compatible proc/endpoint alias
    proc_spokes = EntityRadarCollector.parse_scores_argument("proc=5.5", "USER")
    self.assertEqual(proc_spokes[4].z_score, 5.5)

  def test_generate_dual_surface_embed(self):
    """Dual-surface embed must emit <agent-embed>, Base64 markdown image, and direct file link."""
    payload = self.collector.build_radar_payload("tim.smith@altostrat.com", "USER", self.sample_spokes)
    dual_embed = payload["dual_surface_embed"]
    self.assertIn("<agent-embed", dual_embed)
    self.assertIn("![360° Behavioral Risk Radar: tim.smith@altostrat.com](data:image/svg+xml;base64,", dual_embed)
    self.assertIn("[📊 Open 360° Risk Radar (SVG/HTML)](file://", dual_embed)

  def test_empty_spokes_handling(self):
    """Passing empty spoke list to visualizers must auto-populate nominal baseline without blackouts."""
    svg = EntityRadarCollector.generate_self_contained_svg("nominal_user", [], 0.0, 14)
    self.assertIn("nominal_user • 360° BEHAVIORAL RADAR", svg)
    self.assertIn("<polygon", svg)
    self.assertNotIn("No metric data available", svg)

    ascii_out = EntityRadarCollector.generate_ascii_chart("nominal_user", [], 0.0, 14)
    self.assertIn("360° BEHAVIORAL RISK RADAR", ascii_out)
    self.assertNotIn("No metric data available", ascii_out)

  def test_skill_md_dual_surface_radar_contract(self):
    """SKILL.md must specify Dual-Surface visualization: ASCII/Unicode in chat stream and SVG via agent-embed."""
    import os
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_path = os.path.join(repo_dir, "SKILL.md")
    with open(skill_path, "r", encoding="utf-8") as f:
      content = f.read()

    self.assertIn("Dual-Surface Context-Aware Architecture", content)
    self.assertIn("Unicode magnitude progress bars", content)
    self.assertIn('<svg xmlns="http://www.w3.org/2000/svg"', content)
    self.assertIn("Canonical 5-Spoke SVG Layout", content)
    self.assertIn("Center $(310, 260)$, max $r=125$", content)
    self.assertIn("viewBox=\"0 0 620 480\"", content)
    self.assertIn("CRITICAL VISUAL SPECIFICATION VIOLATION", content)
    self.assertIn("agent-embed", content)


if __name__ == "__main__":
  unittest.main()
