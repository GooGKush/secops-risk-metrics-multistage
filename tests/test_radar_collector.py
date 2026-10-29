"""Unit Tests for 360-Degree Entity Behavioral Risk Radar Collector & Visualizer.

Author: Greg Kushmerek
"""

import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import radar_collector
from scripts.preflight_validator import MalachiteASTValidator
from scripts.radar_collector import EntityRadarCollector, MetricSpoke


def _make_stats_payload(columns: dict) -> dict:
  """Builds a Chronicle udm_search stats.results columnar response dict."""
  results = []
  for col_name, cells in columns.items():
    results.append({
        "column": col_name,
        "values": [{"value": {kind: val}} for kind, val in cells],
    })
  return {"stats": {"results": results}}


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
    self.assertIn("Observed: 640.0", svg)

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
    self.assertIn(r"$$Z_i = \frac{\text{Obs}_i - \mu_{i, 30\text{d}}}{\max(\sigma_{i, 30\text{d}}, 1.0)}$$", md)
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
    """Canonical nominal spokes must return 6 spokes at 0.00σ baseline for both USER and ASSET (WS4 / D6-G1)."""
    user_spokes = EntityRadarCollector.get_canonical_nominal_spokes("USER")
    self.assertEqual(len(user_spokes), 6)
    for s in user_spokes:
      self.assertEqual(s.z_score, 0.0)

    asset_spokes = EntityRadarCollector.get_canonical_nominal_spokes("ASSET")
    self.assertEqual(len(asset_spokes), 6)
    for s in asset_spokes:
      self.assertEqual(s.z_score, 0.0)
    self.assertEqual(asset_spokes[4].sector, "Security & EDR Alerts")
    self.assertEqual(asset_spokes[4].metric_table, "metrics.alert_event_name_count")
    self.assertEqual(asset_spokes[5].metric_table, "metrics.file_executions_total")

    # WS4 / D6-G1: ASSET alerts & endpoint spokes must parse from raw udm_search stats payloads,
    # never from LLM-typed score strings with fabricated Z*10 / 5.0 / 2.0 values.
    raw_asset_payloads = {
        "alerts": _make_stats_payload({
            "asset": [("stringVal", "wrk-01")],
            "alerts_obs": [("int64Val", "19")],
            "alerts_avg": [("doubleVal", 5.5)],
            "alerts_std": [("doubleVal", 3.0)],
            "z_alerts": [("doubleVal", 4.5)],
        }),
        "endpoint": _make_stats_payload({
            "host": [("stringVal", "wrk-01")],
            "observed": [("int64Val", "84")],
            "historical_avg": [("doubleVal", 20.0)],
            "historical_stddev": [("doubleVal", 20.0)],
            "personal_z": [("doubleVal", 3.2)],
        }),
    }
    parsed_asset, _ = EntityRadarCollector.parse_raw_sector_payloads(
        raw_asset_payloads, entity_type="ASSET"
    )
    self.assertEqual(parsed_asset[4].z_score, 4.5)
    self.assertEqual(parsed_asset[4].observed, 19.0)
    self.assertEqual(parsed_asset[4].baseline_mean, 5.5)
    self.assertEqual(parsed_asset[4].baseline_stddev, 3.0)
    self.assertEqual(parsed_asset[5].z_score, 3.2)
    self.assertEqual(parsed_asset[5].observed, 84.0)
    self.assertEqual(parsed_asset[5].baseline_mean, 20.0)
    self.assertEqual(parsed_asset[5].baseline_stddev, 20.0)

  def test_parse_scores_argument_removed_and_cli_scores_rejected_g1(self):
    """WS4 / D6-G1: parse_scores_argument is removed and --scores on CLI fails closed with G1 error."""
    self.assertFalse(
        hasattr(EntityRadarCollector, "parse_scores_argument"),
        "G1 violation: EntityRadarCollector.parse_scores_argument must be removed.",
    )
    proc = subprocess.run(
        [
            sys.executable,
            radar_collector.__file__,
            "--entity",
            "alex.smith",
            "--scores",
            "auth=0.0,cloud=3.8,workspace=3.2,net=0.8,dns=10.8,web=4.2",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    self.assertNotEqual(proc.returncode, 0)
    self.assertIn("G1", proc.stderr + proc.stdout)

  def test_parse_raw_sector_payloads_real_stats_and_zero_row_sectors(self):
    """WS4 / D6-G1..G3: parse_raw_sector_payloads parses raw udm_search stats, preserves 0-row sectors, and emits SHA-256 provenance."""
    sector_payloads = {
        "IAM & Authentication": _make_stats_payload({
            "user": [("stringVal", "alex.smith")],
            "fail_obs": [("int64Val", "17")],
            "fail_avg": [("doubleVal", 2.0)],
            "fail_std": [("doubleVal", 3.0)],
            "z_fail": [("doubleVal", 5.0)],
            "z_succ": [("doubleVal", 0.4)],
        }),
        "cloud": _make_stats_payload({
            "user": [("stringVal", "alex.smith")],
            "observed": [("int64Val", "640")],
            "baseline": [("doubleVal", 21.3)],
            "dispersion": [("doubleVal", 2.1)],
            "z": [("doubleVal", 3.8)],
        }),
        "workspace": {},
        "network": {"stats": {}},
        "dns": _make_stats_payload({
            "user": [("stringVal", "alex.smith")],
            "dns_obs": [("int64Val", "124")],
            "dns_avg": [("doubleVal", 16.0)],
            "dns_std": [("doubleVal", 10.0)],
            "z_dns_fail": [("doubleVal", 10.8)],
        }),
        "web": _make_stats_payload({
            "user": [("stringVal", "alex.smith")],
            "observed": [("int64Val", "310")],
            "d_mu": [("doubleVal", 100.0)],
            "d_sigma": [("doubleVal", 50.0)],
            "personal_z": [("doubleVal", 4.2)],
        }),
    }
    query_texts = {
        "IAM & Authentication": EntityRadarCollector.USER_SECTOR_QUERIES["IAM & Authentication"] % {"entity_id": "alex.smith"},
        "cloud": EntityRadarCollector.USER_SECTOR_QUERIES["Cloud Infrastructure"] % {"entity_id": "alex.smith"},
    }

    spokes, provenance = EntityRadarCollector.parse_raw_sector_payloads(
        sector_payloads,
        entity_type="USER",
        query_texts=query_texts,
    )
    self.assertEqual(len(spokes), 6)
    by_name = {s.spoke_name: s for s in spokes}

    self.assertEqual(by_name["Authentication Attempts"].z_score, 5.0)
    self.assertEqual(by_name["Authentication Attempts"].observed, 17.0)
    self.assertEqual(by_name["Authentication Attempts"].baseline_mean, 2.0)
    self.assertEqual(by_name["Authentication Attempts"].baseline_stddev, 3.0)

    self.assertEqual(by_name["Cloud Resource CRUD"].z_score, 3.8)
    self.assertEqual(by_name["Cloud Resource CRUD"].observed, 640.0)
    self.assertEqual(by_name["Cloud Resource CRUD"].baseline_mean, 21.3)
    self.assertEqual(by_name["Cloud Resource CRUD"].baseline_stddev, 2.1)

    # Clean 0-row raw payloads ({} and {"stats": {}}) map to 0.0 nominal
    self.assertEqual(by_name["Workspace & SaaS Exfil"].z_score, 0.0)
    self.assertEqual(by_name["Workspace & SaaS Exfil"].observed, 0.0)
    self.assertEqual(by_name["Network Egress"].z_score, 0.0)
    self.assertEqual(by_name["Network Egress"].observed, 0.0)

    self.assertEqual(by_name["DNS Resolution"].z_score, 10.8)
    self.assertEqual(by_name["DNS Resolution"].observed, 124.0)
    self.assertEqual(by_name["Web & Proxy Requests"].z_score, 4.2)
    self.assertEqual(by_name["Web & Proxy Requests"].baseline_mean, 100.0)
    self.assertEqual(by_name["Web & Proxy Requests"].baseline_stddev, 50.0)

    # D6-G3 provenance checks
    expected_payload_hash = hashlib.sha256(
        json.dumps(sector_payloads, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    expected_query_hash = hashlib.sha256(
        json.dumps(query_texts, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    self.assertEqual(provenance["helper_version"], "2.3.0")
    self.assertEqual(provenance["payload_sha256"], expected_payload_hash)
    self.assertEqual(provenance["query_sha256"], expected_query_hash)

    _, prov_no_queries = EntityRadarCollector.parse_raw_sector_payloads(sector_payloads, entity_type="USER")
    self.assertEqual(prov_no_queries["query_sha256"], "N/A")

    built = self.collector.build_radar_payload(
        "alex.smith", "USER", spokes, provenance=provenance
    )
    self.assertEqual(built["provenance"], provenance)
    self.assertIn(expected_payload_hash, built["markdown_table"])
    self.assertIn(expected_query_hash, built["markdown_table"])
    self.assertIn("2.3.0", built["markdown_table"])

  def test_g1_rejects_typed_numbers_strings_and_raw_event_dumps(self):
    """WS4 / D6-G1: parse_raw_sector_payloads rejects LLM-typed numbers, hand-typed dicts, and raw event dumps."""
    for bad_payload in (
        {"auth": 3.8},
        {"auth": "3.8"},
        "auth=3.8,cloud=2.1",
        {"auth": {"z_score": 3.8, "observed": 38}},
        {"auth": {"stats": {"results": [{"z_score": 3.8}]}}},
    ):
      with self.assertRaises(ValueError) as ctx:
        EntityRadarCollector.parse_raw_sector_payloads(bad_payload, entity_type="USER")  # type: ignore[arg-type]
      self.assertIn("G1", str(ctx.exception))

    with self.assertRaises(ValueError) as raw_ctx:
      EntityRadarCollector.parse_raw_sector_payloads(
          {"auth": {"events": [{"metadata": {"id": "evt-1"}}]}},
          entity_type="USER",
      )
    self.assertIn("RAW_LOG_DUMP_DETECTED", str(raw_ctx.exception))

  def test_g2_cli_fails_closed_on_missing_or_malformed_payload_and_accepts_raw_payload(self):
    """WS4 / D6-G2: CLI fails closed when --raw-payload/--data is missing or malformed, and succeeds on raw udm_search JSON."""
    # 1. Missing --data / --raw-payload (without --execute) MUST fail closed
    proc_missing = subprocess.run(
        [sys.executable, radar_collector.__file__, "--entity", "alex.smith"],
        capture_output=True,
        text=True,
        check=False,
    )
    self.assertNotEqual(proc_missing.returncode, 0)
    self.assertIn("G2", proc_missing.stderr + proc_missing.stdout)

    # 2. Malformed JSON MUST fail closed
    proc_bad_json = subprocess.run(
        [sys.executable, radar_collector.__file__, "--entity", "alex.smith", "--data", "{not-json"],
        capture_output=True,
        text=True,
        check=False,
    )
    self.assertNotEqual(proc_bad_json.returncode, 0)
    self.assertIn("G2", proc_bad_json.stderr + proc_bad_json.stdout)

    # 3. Hand-typed Z-score dict without stats MUST fail closed under G1
    proc_typed = subprocess.run(
        [sys.executable, radar_collector.__file__, "--entity", "alex.smith", "--data", '{"auth": 3.8}'],
        capture_output=True,
        text=True,
        check=False,
    )
    self.assertNotEqual(proc_typed.returncode, 0)
    self.assertIn("G1", proc_typed.stderr + proc_typed.stdout)

    # 4. Valid raw udm_search payload file via --raw-payload succeeds and emits provenance
    raw_file_payload = {
        "auth": _make_stats_payload({
            "user": [("stringVal", "alex.smith")],
            "observed": [("int64Val", "42")],
            "baseline": [("doubleVal", 6.0)],
            "dispersion": [("doubleVal", 6.0)],
            "z": [("doubleVal", 6.0)],
        }),
        "cloud": {},
    }
    with tempfile.TemporaryDirectory() as tmpdir:
      payload_path = f"{tmpdir}/raw_sectors.json"
      with open(payload_path, "w", encoding="utf-8") as f:
        json.dump(raw_file_payload, f)
      proc_ok = subprocess.run(
          [
              sys.executable,
              radar_collector.__file__,
              "--entity",
              "alex.smith",
              "--raw-payload",
              payload_path,
              "--format",
              "json",
          ],
          capture_output=True,
          text=True,
          check=False,
      )
      self.assertEqual(proc_ok.returncode, 0, msg=proc_ok.stderr)
      out_json = json.loads(proc_ok.stdout)
      self.assertEqual(out_json["provenance"]["helper_version"], "2.3.0")
      self.assertEqual(len(out_json["provenance"]["payload_sha256"]), 64)
      self.assertEqual(out_json["top_outlier_z"], 6.0)

  def test_generate_dual_surface_embed(self):
    """Jetski embed must emit <agent-embed> and a direct file link, and must never emit a
    Base64 data-URI (blocked by rehype-sanitize + CSP; renders as a broken image)."""
    payload = self.collector.build_radar_payload("tim.smith@altostrat.com", "USER", self.sample_spokes)
    dual_embed = payload["dual_surface_embed"]
    self.assertIn("<agent-embed", dual_embed)
    self.assertNotIn("data:image/svg+xml;base64", dual_embed)
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

    self.assertIn("Single visual surface", content)
    self.assertIn("Unicode magnitude bars", content)
    self.assertIn("agent-embed", content)

  def test_reject_monolithic_radar_join_and_missing_root_stage(self):
    """AST validator must reject monolithic multi-stage radar queries lacking a root stage and having unbound match variables."""
    pseudo_query = '''
// Sector 1: Authentication Baseline & Anomaly Extraction
stage stage_auth {
  $e.metadata.event_type = "USER_LOGIN"
  $e.security_result.action = "ALLOW"
  $e.target.user.userid = "admin"
  match:
    $user by 1d
  outcome:
    $obs_auth = count_distinct($e.metadata.id)
    $avg_auth = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: $user))
    $std_auth = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: $user))
    $z_auth   = ($obs_auth - $avg_auth) / ($std_auth + 1.0)
}

// Sector 2: Cloud Admin & Resource Creation Baseline
stage stage_cloud {
  $e.metadata.event_type = "RESOURCE_CREATION"
  $e.principal.user.userid = "admin"
  match:
    $user by 1d
  outcome:
    $obs_cloud = count_distinct($e.metadata.id)
    $avg_cloud = max(metrics.resource_creation_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: $user, metadata.vendor_name: "Google Cloud Platform", metadata.product_name: "Compute Engine"))
    $std_cloud = max(metrics.resource_creation_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: $user, metadata.vendor_name: "Google Cloud Platform", metadata.product_name: "Compute Engine"))
    $z_cloud   = ($obs_cloud - $avg_cloud) / ($std_cloud + 1.0)
}

// Sector 3: Workspace Data Exfiltration Baseline
stage stage_workspace {
  $e.metadata.event_type = "USER_UNCATEGORIZED"
  $e.metadata.product_name = "Google Workspace"
  $e.principal.user.userid = "admin"
  match:
    $user by 1d
  outcome:
    $obs_ws = count_distinct($e.metadata.id)
    $avg_ws = max(metrics.workspace_total_download_actions(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: $user))
    $std_ws = max(metrics.workspace_total_download_actions(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: $user))
    $z_ws   = ($obs_ws - $avg_ws) / ($std_ws + 1.0)
}

// Sector 4: Network Egress Outbound Bytes Baseline
stage stage_net {
  $e.metadata.event_type = "NETWORK_CONNECTION"
  $e.principal.user.userid = "admin"
  match:
    $user by 1d
  outcome:
    $obs_net = sum($e.network.sent_bytes)
    $avg_net = max(metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: avg, principal.user.userid: $user))
    $std_net = max(metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: stddev, principal.user.userid: $user))
    $z_net   = ($obs_net - $avg_net) / ($std_net + 1.0)
}

// Sector 5: DNS Query Volume Baseline
stage stage_dns {
  $e.metadata.event_type = "NETWORK_DNS"
  $e.principal.user.userid = "admin"
  match:
    $user by 1d
  outcome:
    $obs_dns = count_distinct($e.metadata.id)
    $avg_dns = max(metrics.dns_queries_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: $user))
    $std_dns = max(metrics.dns_queries_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: $user))
    $z_dns   = ($obs_dns - $avg_dns) / ($std_dns + 1.0)
}
'''
    errors = MalachiteASTValidator.validate_query(pseudo_query)
    error_str = " ".join(errors)
    self.assertIn("STAGE_LIMIT_EXCEEDED", error_str)
    self.assertIn("UNBOUND_MATCH_VARIABLE", error_str)
    self.assertIn("MISSING_ROOT_STAGE", error_str)

  def test_generate_ranked_fleet_html(self):
    """Ranked fleet HTML must include horizontal bars and anomaly boundary."""
    ranked = [
        {"entity": "user-a", "threat_distance_d": 4.10, "cri": 82, "status": "Critical"},
        {"entity": "user-b", "threat_distance_d": 1.20, "cri": 22, "status": "Nominal"},
    ]
    html = EntityRadarCollector.generate_ranked_fleet_html(ranked)
    self.assertIn("360° Threat Fusion: Ranked Fleet Outliers", html)
    self.assertIn("+3.0σ Anomaly", html)
    self.assertIn("user-a", html)
    self.assertIn("D=4.10σ", html)

  def test_generate_fleet_heatmap_html(self):
    """Fleet heatmap HTML must render 5 canonical sectors and composite risk."""
    matrix = [
        {
            "entity": "user-a",
            "sectors": {"IAM & Authentication": 3.4, "Cloud Infrastructure": 0.5},
            "threat_distance_d": 3.45,
            "cri": 72,
        }
    ]
    html = EntityRadarCollector.generate_fleet_heatmap_html(matrix)
    self.assertIn("360° Multi-Sector Fleet Threat Matrix", html)
    self.assertIn("IAM &amp; Authentication", html)
    self.assertIn("+3.40σ", html)
    self.assertIn("D=3.45σ", html)

  def test_generate_fleet_heatmap_svg(self):
    """Pure SVG fleet heatmap must emit vector rects, column headers, and anomaly badges."""
    matrix = [
        {
            "entity": "WRK-SHASEK",
            "sectors": {"IAM & Authentication": 1.2, "Cloud Infrastructure": 0.8, "DNS Resolution": 4.10},
            "threat_distance_d": 4.10,
            "cri": 78,
        }
    ]
    svg = EntityRadarCollector.generate_fleet_heatmap_svg(matrix)
    self.assertIn("<svg", svg)
    self.assertIn("viewBox=", svg)
    self.assertIn("WRK-SHASEK", svg)
    self.assertIn("+4.10σ", svg)
    self.assertIn("D=4.10σ (78)", svg)
    self.assertIn("</svg>", svg)

  def test_generate_dualy_timeline_svg_and_html(self):
    """Dual-Y timeline must emit dual axes, volume bars, Z-score path, and +3.0σ threshold."""
    timeline = [
        {"date": "2026-08-26", "volume": 120, "z_score": 0.40},
        {"date": "2026-08-27", "volume": 850, "z_score": 4.10},
    ]
    svg = EntityRadarCollector.generate_dualy_timeline_svg(timeline, entity="WRK-SHASEK")
    self.assertIn("<svg", svg)
    self.assertIn("viewBox=", svg)
    self.assertIn("Observed Volume", svg)
    self.assertIn("Z-Score Deviation (σ)", svg)
    self.assertIn("+3.0σ Anomaly Ceiling", svg)
    self.assertIn("WRK-SHASEK", svg)
    self.assertIn("<path", svg)
    self.assertIn("</svg>", svg)

    html_widget = EntityRadarCollector.generate_dualy_timeline_html(timeline, entity="WRK-SHASEK")
    self.assertIn("<!DOCTYPE html>", html_widget)
    self.assertIn("<svg", html_widget)
    self.assertIn("WRK-SHASEK", html_widget)

  def test_generate_prevalence_quadrant_svg_and_html(self):
    """Prevalence quadrant scatter must render four shaded quadrants, threshold lines, and entity markers."""
    findings = [
        {"token": "malware.exe", "fleet_adopters": 1, "personal_z": 4.5},
        {"token": "update.exe", "fleet_adopters": 350, "personal_z": 5.2},
    ]
    svg = EntityRadarCollector.generate_prevalence_quadrant_svg(findings)
    self.assertIn("<svg", svg)
    self.assertIn("ACUTE TARGETED INTRUSION", svg)
    self.assertIn("CORPORATE ROLLOUT / PATCH TUESDAY", svg)
    self.assertIn("+3.0σ Anomaly Ceiling", svg)
    self.assertIn("malware.exe", svg)
    self.assertIn("update.exe", svg)
    self.assertIn("</svg>", svg)

    html_widget = EntityRadarCollector.generate_prevalence_quadrant_html(findings)
    self.assertIn("<!DOCTYPE html>", html_widget)
    self.assertIn("<svg", html_widget)
    self.assertIn("ACUTE TARGETED INTRUSION", html_widget)

  def test_cloud_radar_spoke_unifies_all_four_crud_families_and_field_self_binding(self):
    """Cloud radar spoke and 360 guide must evaluate all 4 CRUD families and use <field>: <field> in metrics.*()."""
    import os
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cloud_query = EntityRadarCollector.USER_SECTOR_QUERIES["Cloud Infrastructure"]
    for family in (
        "metrics.resource_read_total",
        "metrics.resource_written_total",
        "metrics.resource_creation_total",
        "metrics.resource_deletion_total",
    ):
      self.assertIn(family, cloud_query)
    self.assertIn("principal.user.userid: principal.user.userid", cloud_query)
    self.assertIn("metadata.vendor_name: metadata.vendor_name", cloud_query)
    self.assertIn("metadata.product_name: metadata.product_name", cloud_query)

    guide_path = os.path.join(repo_dir, "references", "360-behavioral-radar-guide.md")
    with open(guide_path, "r", encoding="utf-8") as f:
      guide_text = f.read()
    for family in (
        "metrics.resource_read_total",
        "metrics.resource_written_total",
        "metrics.resource_creation_total",
        "metrics.resource_deletion_total",
    ):
      self.assertIn(family, guide_text)
    self.assertNotIn('target.user.userid: "%(entity_id)s"', guide_text)
    self.assertNotIn('principal.user.userid: "%(entity_id)s"', guide_text)
    self.assertNotIn("metadata.vendor_name: $vendor", guide_text)
    self.assertNotIn("metadata.product_name: $product", guide_text)

  def test_identity_spotcheck_includes_email_addresses(self):
    """SKILL.md, lifecycle, multi-stage guide, and 360 guide must include email_addresses in identity spot-checks."""
    import os
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for rel in (
        "SKILL.md",
        os.path.join("references", "turn-execution-lifecycle.md"),
        os.path.join("references", "multi-stage-metrics-guide.md"),
        os.path.join("references", "360-behavioral-radar-guide.md"),
    ):
      with open(os.path.join(repo_dir, rel), "r", encoding="utf-8") as f:
        text = f.read()
      self.assertIn("target.user.email_addresses", text, f"Missing target.user.email_addresses in {rel}")
      self.assertIn("principal.user.email_addresses", text, f"Missing principal.user.email_addresses in {rel}")


  def test_parse_chronicle_row_supports_composite_risk_and_z(self):
    """EntityRadarCollector must unify all 4 Cloud CRUD Z-scores into $z and evaluate $z on Security & EDR Alerts."""
    cloud_query = EntityRadarCollector.USER_SECTOR_QUERIES["Cloud Infrastructure"]
    self.assertIn("$z_rw = if($z_read >= $z_write, $z_read, $z_write)", cloud_query)
    self.assertIn("$z_cd = if($z_create >= $z_delete, $z_create, $z_delete)", cloud_query)
    self.assertIn("$z = if($z_rw >= $z_cd, $z_rw, $z_cd)", cloud_query)
    alert_query = EntityRadarCollector.ASSET_SECTOR_QUERIES["Security & EDR Alerts"]
    self.assertIn("$z =", alert_query)

  def test_ws2_03_six_sectors_at_2_8_sigma_fuse_to_6_86(self):
    """WS2-03: 6 ungated sectors at +2.8 sigma fuse to Euclidean D = sqrt(6 * 2.8^2) = 6.86 (~6.9)."""
    collector = EntityRadarCollector()

    def _stats(z_col: str, obs_col: str = "observed"):
      return {
          "stats": {
              "results": [
                  {"column": obs_col, "values": [{"value": {"int64Val": "38"}}]},
                  {"column": "hist_avg", "values": [{"value": {"doubleVal": 10.0}}]},
                  {"column": "hist_stddev", "values": [{"value": {"doubleVal": 10.0}}]},
                  {"column": z_col, "values": [{"value": {"doubleVal": 2.8}}]},
              ]
          }
      }

    user_spokes, user_prov = collector.parse_raw_sector_payloads(
        {
            "auth": _stats("personal_z"),
            "cloud": _stats("dest_z", obs_col="obs"),
            "workspace": _stats("personal_z"),
            "network": _stats("personal_z"),
            "dns": _stats("personal_z"),
            "web": _stats("personal_z"),
        },
        entity_type="USER",
    )
    user_payload = collector.build_radar_payload("charles.hardy", "USER", user_spokes, provenance=user_prov)
    self.assertEqual(user_payload["composite_distance_d"], 6.86)
    self.assertTrue(user_payload["is_anomalous"])

    asset_spokes, asset_prov = collector.parse_raw_sector_payloads(
        {
            "auth": _stats("personal_z"),
            "alerts": _stats("alert_z", obs_col="total_alerts"),
            "endpoint": _stats("personal_z"),
            "network": _stats("personal_z"),
            "dns": _stats("personal_z"),
            "web": _stats("personal_z"),
        },
        entity_type="ASSET",
    )
    asset_payload = collector.build_radar_payload("wkst-fin-09", "ASSET", asset_spokes, provenance=asset_prov)
    self.assertEqual(asset_payload["composite_distance_d"], 6.86)
    self.assertTrue(asset_payload["is_anomalous"])


if __name__ == "__main__":

  unittest.main()

