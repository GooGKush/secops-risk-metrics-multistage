"""WS1-08 regression tests: ECG D-2 anchor, inner-join filter disclosure, Day-0 companion query, and first_seen_time = 0 novelty disabling."""

import datetime
import unittest

from scripts.preflight_validator import MalachiteASTValidator
from scripts.ueba_hybrid_engine import compile_hunt_pipeline, render_forensic_dossier


class TestWS108ECGFreshnessAndNovelty(unittest.TestCase):
  """Verifies PF-8 / WS1-08 Entity Context Graph freshness, filter disclosure, Day-0 companion, and first_seen = 0 handling."""

  def test_ecg_run_starting_today_matches_explicit_d_minus_2_run(self):
    """A run starting today must anchor DERIVED_CONTEXT at D-2 and produce the exact same query & window as an explicit D-2 run."""
    ref_time = datetime.datetime(2026, 10, 28, 14, 0, 0, tzinfo=datetime.timezone.utc)

    res_today_flag = compile_hunt_pipeline(
        architecture="hybrid_derived_file_prevalence",
        metrics="file_executions_total",
        entity_type="ASSET",
        mode="A",
        today_so_far=True,
        reference_time=ref_time,
    )
    res_today_explicit = compile_hunt_pipeline(
        architecture="hybrid_derived_file_prevalence",
        metrics="file_executions_total",
        entity_type="ASSET",
        mode="A",
        start_time="2026-10-28T00:00:00Z",
        end_time="2026-10-28T14:00:00Z",
        reference_time=ref_time,
    )
    res_d_minus_2_explicit = compile_hunt_pipeline(
        architecture="hybrid_derived_file_prevalence",
        metrics="file_executions_total",
        entity_type="ASSET",
        mode="A",
        start_time="2026-10-26T00:00:00Z",
        end_time="2026-10-28T14:00:00Z",
        target_date="2026-10-28",
        reference_time=ref_time,
    )

    for res in (res_today_flag, res_today_explicit, res_d_minus_2_explicit):
      self.assertEqual(res["start_time"], "2026-10-26T00:00:00Z")
      self.assertEqual(res["end_time"], "2026-10-28T14:00:00Z")
      self.assertTrue(res["search_window"]["ecg_72h_anchor_applied"])
      self.assertEqual(res["search_window"]["baseline_start_date"], "2026-09-26")
      self.assertEqual(res["search_window"]["baseline_end_date"], "2026-10-25")
      self.assertIn('timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-28"', res["compiled_query"])

    self.assertEqual(res_today_flag["compiled_query"], res_d_minus_2_explicit["compiled_query"])
    self.assertEqual(res_today_explicit["compiled_query"], res_d_minus_2_explicit["compiled_query"])

    # Mode C ECG shards must also anchor each day shard at day - 2d 00:00:00Z while pinning event stage to shard day
    res_c = compile_hunt_pipeline(
        architecture="hybrid_derived_file_prevalence",
        metrics="file_executions_total",
        entity_type="ASSET",
        mode="C",
        window_days=3,
        reference_time=ref_time,
    )
    self.assertTrue(res_c["search_window"]["ecg_72h_anchor_applied"])
    self.assertEqual(len(res_c["shards"]), 3)
    expected_shards = [
        ("2026-10-26", "2026-10-24T00:00:00Z"),
        ("2026-10-27", "2026-10-25T00:00:00Z"),
        ("2026-10-28", "2026-10-26T00:00:00Z"),
    ]
    for shard, (exp_day, exp_start) in zip(res_c["shards"], expected_shards):
      self.assertEqual(shard["day"], exp_day)
      self.assertEqual(shard["start_time"], exp_start)
      self.assertIn(f'timestamp.get_date(metadata.event_timestamp.seconds) = "{exp_day}"', shard["query"])

    # Mode B 2-day ECG timeline must anchor at <= D-2 and gate events to >= anchor_day ("2026-10-27")
    res_b = compile_hunt_pipeline(
        architecture="hybrid_derived_domain_prevalence",
        metrics="http_queries_total",
        entity_type="ASSET",
        mode="B",
        window_days=2,
        reference_time=ref_time,
    )
    self.assertTrue(res_b["search_window"]["ecg_72h_anchor_applied"])
    self.assertEqual(res_b["start_time"], "2026-10-26T00:00:00Z")
    self.assertIn('timestamp.get_date(metadata.event_timestamp.seconds) >= "2026-10-27"', res_b["compiled_query"])

  def test_ecg_inner_join_filter_disclosed_in_preflight_and_dossier(self):
    """ECG pipelines must explicitly disclose inner-join filtering in compile output, preflight card, and both 0-row & populated dossiers."""
    ref_time = datetime.datetime(2026, 10, 28, 14, 0, 0, tzinfo=datetime.timezone.utc)
    for arch, metric in (
        ("hybrid_derived_file_prevalence", "file_executions_total"),
        ("hybrid_derived_domain_prevalence", "http_queries_total"),
        ("hybrid_derived_asset_age", "auth_attempts_total"),
        ("hybrid_whois_domain_lifecycle", "http_queries_total"),
        ("rare_destination_ecg_3stage", "network_bytes_outbound"),
        ("fusion_rare_destination_3stage", "network_bytes_outbound"),
    ):
      with self.subTest(arch=arch):
        res = compile_hunt_pipeline(
            architecture=arch,
            metrics=metric,
            entity_type="ASSET",
            mode="A",
            reference_time=ref_time,
        )
        self.assertTrue(res.get("has_ecg_join"))
        disclosure = res.get("ecg_join_filter_disclosure") or ""
        self.assertIn("inner join", disclosure.lower())
        self.assertIn("inner join", res["preflight_card_markdown"].lower())
        self.assertIn("[D-32, D-2)", res["preflight_card_markdown"])

        zero_dossier = render_forensic_dossier(
            rows=[],
            executed_query=res["compiled_query"],
            statistical_model="STANDARD_Z_SCORE",
            metric_name=metric,
            entity_type="ASSET",
            mode="A",
            skip_postflight_audit=True,
        )
        self.assertTrue(zero_dossier.get("has_ecg_join"))
        self.assertIn("inner join", (zero_dossier.get("ecg_join_filter_disclosure") or "").lower())
        self.assertIn("inner join", zero_dossier["dossier_markdown"].lower())

        pop_dossier = render_forensic_dossier(
            rows=[{
                "host": "wks-01",
                "observed": 42,
                "hist_avg": 5.0,
                "hist_stddev": 2.5,
                "z_score": 14.8,
                "active_days": 15,
                "first_seen": 1761000000,
            }],
            executed_query=res["compiled_query"],
            statistical_model="STANDARD_Z_SCORE",
            metric_name=metric,
            entity_type="ASSET",
            mode="A",
            skip_postflight_audit=True,
        )
        self.assertTrue(pop_dossier.get("has_ecg_join"))
        self.assertIn("inner join", pop_dossier["dossier_markdown"].lower())
        self.assertIn("inner join", pop_dossier["triage_report_markdown"].lower())

  def test_day0_companion_query_emitted_and_ast_valid(self):
    """DERIVED_CONTEXT ECG pipelines must emit an AST-valid Day-0 companion query with no graph.* inner join."""
    ref_time = datetime.datetime(2026, 10, 28, 14, 0, 0, tzinfo=datetime.timezone.utc)
    for arch, metric in (
        ("hybrid_derived_file_prevalence", "file_executions_total"),
        ("hybrid_derived_domain_prevalence", "http_queries_total"),
        ("hybrid_derived_asset_age", "auth_attempts_total"),
        ("rare_destination_ecg_3stage", "network_bytes_outbound"),
        ("fusion_rare_destination_3stage", "network_bytes_outbound"),
    ):
      with self.subTest(arch=arch):
        res = compile_hunt_pipeline(
            architecture=arch,
            metrics=metric,
            entity_type="ASSET",
            mode="A",
            reference_time=ref_time,
        )
        companion_q = res.get("day0_companion_query") or ""
        companion_win = res.get("day0_companion_window") or {}
        self.assertTrue(companion_q.strip(), f"Missing day0_companion_query for {arch}")
        self.assertNotRegex(companion_q, r"\bgraph\.(?:entity|metadata|relations)\b")
        self.assertIn("metrics.", companion_q)
        self.assertEqual(MalachiteASTValidator.validate_query(companion_q), [])
        # Scored day for default Mode A at 2026-10-28 is 2026-10-27 [00:00Z, 2026-10-28T00:00Z)
        self.assertEqual(companion_win.get("start_time"), "2026-10-27T00:00:00Z")
        self.assertEqual(companion_win.get("end_time"), "2026-10-28T00:00:00Z")
        self.assertIn("Day-0", res["preflight_card_markdown"])

  def test_ecg_first_seen_zero_disables_7d_novelty_boost_and_points_to_metrics_first_seen(self):
    """When ECG first_seen_time = 0, <7d ECG novelty boost must be disabled and dossier must direct to metrics.* first_seen."""
    res = compile_hunt_pipeline(
        architecture="hybrid_derived_file_prevalence",
        metrics="file_executions_total",
        entity_type="ASSET",
        mode="A",
        reference_time=datetime.datetime(2026, 10, 28, 14, 0, 0, tzinfo=datetime.timezone.utc),
    )
    self.assertIn("$ecg_novelty_disabled = if($first_seen <= 0, 1.0, 0.0)", res["compiled_query"])

    # Simulate a returned row with first_seen = 0 and an artificially 2.5x-boosted threat_score = 10.0 on z_score = 4.0
    rows = [{
        "host": "wks-zero-fs",
        "sha256": "deadbeef" * 8,
        "observed_execs": 25,
        "mean_execs": 5.0,
        "stddev_execs": 5.0,
        "z_score": 4.0,
        "threat_score": 10.0,
        "fleet_prevalence": 2,
        "first_seen": 0,
        "active_baseline_days": 12,
    }]
    dossier = render_forensic_dossier(
        rows=rows,
        executed_query=res["compiled_query"],
        statistical_model="STANDARD_Z_SCORE",
        metric_name="file_executions_total",
        entity_type="ASSET",
        mode="A",
        skip_postflight_audit=True,
    )
    self.assertTrue(dossier.get("ecg_novelty_boost_disabled"))
    self.assertTrue(dossier["outliers"][0].get("ecg_novelty_boost_disabled"))
    # 2.5x <7d novelty boost (10.0) must be stripped when first_seen = 0
    self.assertLess(dossier["outliers"][0]["anomaly_score"], 10.0)
    notice = dossier.get("ecg_novelty_notice") or ""
    self.assertIn("first_seen_time = 0", notice)
    self.assertIn("metrics.*", notice)
    self.assertIn("first_seen", notice)
    self.assertIn("first_seen_time = 0", dossier["dossier_markdown"])
    self.assertIn("first_seen", dossier["dossier_markdown"])
    # Ensure zero extra ```yara code blocks were injected into Turn-2 dossier_markdown
    self.assertEqual(dossier["dossier_markdown"].count("```yara"), 0)


if __name__ == "__main__":
  unittest.main()
