"""WS6-01 unit tests for Page CUSUM helper, 3-stage series extractor, D6 G1-G5, and timeline cleanup."""

import contextlib
import hashlib
import io
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import unittest

REPO_DIR = Path(__file__).resolve().parent.parent
if str(REPO_DIR) not in sys.path:
  sys.path.insert(0, str(REPO_DIR))

from scripts import cusum_helper as ch
from scripts import timeline_assembler as ta
from scripts import ueba_constants as uc
from scripts.preflight_validator import (
    EntityType,
    MalachiteASTValidator,
    PipelineArchitecture,
    StatisticalModel,
)
from scripts.template_router import MultiStageTemplateRouter
from scripts.ueba_hybrid_engine import compile_hunt_pipeline


def _make_stats_payload(columns):
  """Builds a valid Chronicle udm_search columnar stats.results dict."""
  results = []
  for col_name, values in columns.items():
    cells = []
    for val in values:
      if val is None:
        cells.append({})
      elif isinstance(val, bool):
        cells.append({"value": {"boolVal": val}})
      elif isinstance(val, str):
        cells.append({"value": {"stringVal": val}})
      elif isinstance(val, int):
        cells.append({"value": {"int64Val": str(val)}})
      elif isinstance(val, float):
        cells.append({"value": {"doubleVal": val}})
      else:
        raise TypeError(f"Unsupported test cell value: {val!r}")
    results.append({"column": col_name, "values": cells})
  return {"stats": {"results": results}}


def _epoch_for_day(day_str: str) -> int:
  import datetime
  dt = datetime.datetime.strptime(day_str, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
  return int(dt.timestamp())


class TestWS601SeriesPipelineAndLosslessPrefilter(unittest.TestCase):
  """Tests templates/pipelines/longitudinal_cusum_series_3stage.yl2 and lossless W >= S_t invariant."""

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  def test_series_3stage_pipeline_renders_and_passes_ast_budget(self):
    pipeline_path = REPO_DIR / "templates" / "pipelines" / "longitudinal_cusum_series_3stage.yl2"
    self.assertTrue(pipeline_path.exists(), "Missing longitudinal_cusum_series_3stage.yl2")

    q_count = self.router.build_longitudinal_cusum_series_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        cusum_h_threshold=4.0,
        min_baseline_days=7,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_count), [])
    self.assertLessEqual(MalachiteASTValidator.count_query_joins(q_count), 4)
    self.assertEqual(MalachiteASTValidator.count_query_joins(q_count), 2)
    self.assertIn("stage stage1_extract", q_count)
    self.assertIn("stage stage2_prefilter", q_count)
    self.assertIn("$ws = $stage1_extract.window_start", q_count)
    self.assertIn("match:\n  $entity, $ws by 1d", q_count)
    self.assertIn("$windowed_slack_sum >= 4.0", q_count)
    self.assertIn("$drift_days >= 2", q_count)
    self.assertIn("$active_days >= 7", q_count)
    self.assertIn("math.sqrt(if($historical_avg > 1.0, $historical_avg, 1.0))", q_count)

    q_bytes = self.router.build_longitudinal_cusum_series_query(
        target_metric="network_bytes_outbound",
        entity_type=EntityType.ASSET,
        cusum_h_threshold=5.0,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_bytes), [])
    self.assertNotIn("math.sqrt(if($historical_avg > 1.0, $historical_avg, 1.0))", q_bytes)
    self.assertIn("$windowed_slack_sum >= 5.0", q_bytes)

    q_arch = self.router.build_pipeline_query(
        PipelineArchitecture.LONGITUDINAL_CUSUM_SERIES_3STAGE,
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        anomaly_threshold=4.0,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_arch), [])

  def test_engine_blocks_mode_a_and_exposes_series_query_in_mode_b(self):
    with self.assertRaisesRegex(ValueError, "LONGITUDINAL_CUSUM cannot run in single-day Mode A"):
      compile_hunt_pipeline(
          architecture="longitudinal_cusum_series_3stage",
          metrics="auth_attempts_total",
          entity_type="USER",
          mode="A",
      )

    res_series = compile_hunt_pipeline(
        architecture="longitudinal_cusum_series_3stage",
        metrics="auth_attempts_total",
        entity_type="USER",
        mode="B",
        window_days=10,
    )
    self.assertTrue(res_series["ast_valid"])
    self.assertEqual(res_series["window_days"], 10)
    self.assertEqual(res_series["helper_script"], "scripts/cusum_helper.py")
    self.assertIn("stage stage2_prefilter", res_series["compiled_query"])

    res_default = compile_hunt_pipeline(
        statistical_model="LONGITUDINAL_CUSUM",
        metrics="auth_attempts_total",
        entity_type="USER",
        mode="B",
        window_days=7,
    )
    self.assertEqual(res_default["helper_script"], "scripts/cusum_helper.py")
    self.assertIn("stage stage2_prefilter", res_default["cusum_series_query"])

  def test_windowed_slack_sum_is_lossless_upper_bound_on_page_cusum(self):
    slack_k = 0.5
    sequences = [
        [0.0, 0.0, 0.0, 0.0],
        [1.2, 1.4, 1.3, 1.5, 1.1],
        [2.6, -2.5, -2.5, 2.6, -2.5],
        [-1.8, 0.9, -0.4, 1.8, 2.2, -3.0, 1.6],
        [0.6, 0.6, 0.6, 0.6, 0.6, 0.6, 0.6, 0.6],
    ]
    for seq in sequences:
      w_active_only = sum(max(0.0, z - slack_k) for z in seq if z > 0.0)
      s_series = ta.calculate_page_cusum_series(seq, slack_k=slack_k)
      peak_s = max(s_series) if s_series else 0.0
      self.assertLessEqual(
          peak_s,
          round(w_active_only + 1e-9, 6),
          f"Page S_t ({peak_s}) exceeded Windowed Slack Sum W ({w_active_only}) on {seq}",
      )


class TestWS601ARLAndHelperModes(unittest.TestCase):
  """Tests ARL-calibrated thresholds, <=14d series reconstruction, >14d fixed-ref shards, and resets."""

  def test_arl_calibrated_thresholds_and_siegmund_approximation(self):
    self.assertEqual(ch.resolve_cusum_threshold("HIGH_RECALL"), ("HIGH_RECALL", 3.0))
    self.assertEqual(ch.resolve_cusum_threshold("BALANCED"), ("BALANCED", 4.0))
    self.assertEqual(ch.resolve_cusum_threshold("HIGH_PRECISION"), ("HIGH_PRECISION", 5.0))
    self.assertEqual(ch.resolve_cusum_threshold("BALANCED", threshold_h=4.5), ("CUSTOM", 4.5))

    arl0_bal = ch.siegmund_arl(4.0, slack_k=0.5, shift_sigma=0.0)
    arl1_bal = ch.siegmund_arl(4.0, slack_k=0.5, shift_sigma=1.0)
    self.assertTrue(330.0 <= arl0_bal <= 345.0, f"Unexpected ARL0(h=4.0): {arl0_bal}")
    self.assertTrue(8.0 <= arl1_bal <= 8.8, f"Unexpected ARL1(h=4.0, +1σ): {arl1_bal}")

    arl0_hp = ch.siegmund_arl(5.0, slack_k=0.5, shift_sigma=0.0)
    arl1_hp = ch.siegmund_arl(5.0, slack_k=0.5, shift_sigma=1.0)
    self.assertTrue(920.0 <= arl0_hp <= 950.0, f"Unexpected ARL0(h=5.0): {arl0_hp}")
    self.assertTrue(10.0 <= arl1_hp <= 10.8, f"Unexpected ARL1(h=5.0, +1σ): {arl1_hp}")

  def test_start_anchored_14d_reconstructs_quiet_days_and_gates_maturity(self):
    """Quiet 0-event days pull S_t down (filtering false W>=4 hits), sustained drift alarms, immature excluded."""
    # Window: 2026-10-20 .. 2026-10-26 (7 UTC days)
    # 1) user_sustained: mu=100, sd=20, active_days=20. Active on Oct 20..23 with obs=130 (z=+1.5 -> +1.0/day -> S_t=4.0 on Oct 23!)
    #    Quiet on Oct 24..26 (obs=0 -> z=-5.0 -> S_t decays to 0.0, but peak_s_t=4.0 == h -> alarm! Z_equiv=3.0, CRI=50).
    # 2) user_isolated_spikes: mu=100, sd=20, active_days=20. Active on Oct 20 (obs=152, z=+2.6, s=2.1) and Oct 26 (obs=152, z=+2.6).
    #    Windowed Slack Sum W = 2.1 + 2.1 = 4.2 >= 4.0 (passes SQL prefilter!),
    #    but Oct 21..25 are quiet 0-event days (z = -5.0 each), resetting S_t to 0.0 -> peak_s_t = 2.1 < 4.0 (NO alarm!).
    # 3) SITE-DC$: active_days=2 (< 7 maturity gate), obs=8000 -> excluded to immature_entities (FIRST_SEEN_NOVELTY).
    rows_entity = [
        "user_sustained", "user_sustained", "user_sustained", "user_sustained",
        "user_isolated_spikes", "user_isolated_spikes",
        "SITE-DC$", "SITE-DC$",
    ]
    rows_ws = [
        _epoch_for_day("2026-10-20"), _epoch_for_day("2026-10-21"),
        _epoch_for_day("2026-10-22"), _epoch_for_day("2026-10-23"),
        _epoch_for_day("2026-10-20"), _epoch_for_day("2026-10-26"),
        _epoch_for_day("2026-10-20"), _epoch_for_day("2026-10-21"),
    ]
    rows_obs = [130.0, 130.0, 130.0, 130.0, 152.0, 152.0, 8000.0, 8500.0]
    rows_avg = [100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 10.0, 10.0]
    rows_std = [20.0, 20.0, 20.0, 20.0, 20.0, 20.0, 0.0, 0.0]
    rows_days = [20, 20, 20, 20, 20, 20, 2, 2]
    rows_w = [4.0, 4.0, 4.0, 4.0, 4.2, 4.2, 500.0, 500.0]

    payload = _make_stats_payload({
        "entity": rows_entity,
        "ws": rows_ws,
        "observed_val": rows_obs,
        "baseline_mean": rows_avg,
        "baseline_stddev": rows_std,
        "active_days": rows_days,
        "windowed_slack_sum": rows_w,
    })

    with tempfile.TemporaryDirectory() as tmp:
      p_file = os.path.join(tmp, "payload.json")
      q_file = os.path.join(tmp, "query.yaral")
      with open(p_file, "w", encoding="utf-8") as f:
        json.dump(payload, f)
      with open(q_file, "w", encoding="utf-8") as f:
        f.write("// longitudinal_cusum_series_3stage\n")

      report = ch.evaluate_start_anchored_cusum(
          payload_file=p_file,
          query_file=q_file,
          start_day="2026-10-20",
          end_day="2026-10-26",
          tier="BALANCED",
          slack_k=0.5,
          min_baseline_days=7,
      )

    self.assertEqual(report["threshold_h"], 4.0)
    self.assertEqual(len(report["immature_entities"]), 1)
    self.assertEqual(report["immature_entities"][0]["entity"], "SITE-DC$")
    self.assertEqual(report["immature_entities"][0]["routed_to"], "FIRST_SEEN_NOVELTY")
    self.assertNotIn("SITE-DC$", report["entities"])

    sustained = report["entities"]["user_sustained"]
    self.assertTrue(sustained["alarm"])
    self.assertAlmostEqual(sustained["peak_s_t"], 4.0, places=4)
    self.assertAlmostEqual(sustained["final_s_t"], 0.0, places=4)
    self.assertEqual(sustained["onset_day"], "2026-10-23")
    self.assertAlmostEqual(sustained["z_equivalent"], 3.0, places=4)
    self.assertEqual(sustained["cri"], 50)
    self.assertEqual(len(sustained["series"]), 7)
    # Quiet day Oct 24 reconstructed with observed=0.0 and negative z_score=-5.0
    oct24 = [pt for pt in sustained["series"] if pt["day"] == "2026-10-24"][0]
    self.assertEqual(oct24["observed"], 0.0)
    self.assertAlmostEqual(oct24["z_score"], -5.0, places=4)

    isolated = report["entities"]["user_isolated_spikes"]
    self.assertFalse(isolated["alarm"])
    self.assertAlmostEqual(isolated["peak_s_t"], 2.1, places=4)
    self.assertLess(isolated["cri"], 50)

  def test_multishard_gt_14d_fixed_reference_and_resets(self):
    """Tests >14d (18-day) Mode C shards re-standardized against Shard 1 calendar-day reference + resets."""
    # Shard 1 (2026-10-01): active_days=30, historical_avg=100.0, historical_stddev=10.0, historical_sum=3000.0
    # -> calendar mu_cal=100.0, sd_cal=10.0 (floor sqrt(100)=10.0 -> safe_sd=10.0).
    # Even if later shards have trailing baseline_mean=115.0, baseline_stddev=25.0 (trailing fade!),
    # fixed-reference mode scores all 18 days against Shard 1 (mu=100, sd=10) unless reset!
    with tempfile.TemporaryDirectory() as tmp:
      q_file = os.path.join(tmp, "shard_query.yaral")
      with open(q_file, "w", encoding="utf-8") as f:
        f.write("// ungated Mode C shard query\n")

      shard_specs = []
      for idx in range(18):
        day = f"2026-10-{idx + 1:02d}"
        s_path = os.path.join(tmp, f"shard_{day}.json")
        if idx == 5:
          # Quiet missing-row day (0 events -> empty stats {})
          data = {}
        else:
          # Constant mild +1.5σ shift relative to Shard 1 (observed = 115.0),
          # while trailing baseline_mean creeps up to 114.0 on later shards!
          trailing_avg = 100.0 if idx == 0 else min(114.0, 100.0 + idx * 1.2)
          trailing_sd = 10.0 if idx == 0 else 22.0
          # On reset day 2026-10-10 (idx == 9), set a clean post-investigation reference (mu=115, sd=10)
          if day == "2026-10-10":
            trailing_avg = 115.0
            trailing_sd = 10.0
          data = _make_stats_payload({
              "entity": ["svc-exfil"],
              "observed_val": [115.0],
              "historical_avg": [trailing_avg],
              "historical_stddev": [trailing_sd],
              "historical_active_days": [30],
              "historical_sum": [trailing_avg * 30.0],
          })
        with open(s_path, "w", encoding="utf-8") as f:
          json.dump(data, f)
        shard_specs.append((day, s_path))

      # 1. Fixed reference without reset across 18 days (> 14d!)
      res_fixed = ch.evaluate_multishard_cusum(
          shard_files=dict(shard_specs),
          query_file=q_file,
          tier="BALANCED",
          slack_k=0.5,
      )
      ent_fixed = res_fixed["entities"]["svc-exfil"]
      self.assertEqual(res_fixed["window_days"], 18)
      self.assertTrue(ent_fixed["alarm"])
      # Days 1..5 give +1.0 each -> S_5 = 5.0 (alarms on 2026-10-04 at S_4 = 4.0).
      # Day 6 (2026-10-06) has 0 events -> z = (0 - 100)/10 = -10.0 -> S_6 = 0.0, then days 7..18 add 12 * 1.0 = 12.0!
      self.assertEqual(ent_fixed["onset_day"], "2026-10-04")
      self.assertAlmostEqual(ent_fixed["peak_s_t"], 12.0, places=3)
      self.assertAlmostEqual(ent_fixed["final_s_t"], 12.0, places=3)

      # 2. Scheduled reset on 2026-10-10 updates baseline to mu=115, sd=10 -> z=0 on days 10..18, S_t stays 0.0!
      res_sched = ch.evaluate_multishard_cusum(
          shard_files=dict(shard_specs),
          query_file=q_file,
          tier="BALANCED",
          slack_k=0.5,
          reset_on=["2026-10-10"],
      )
      ent_sched = res_sched["entities"]["svc-exfil"]
      self.assertIn("2026-10-10", [r["day"] for r in ent_sched["resets_applied"]])
      self.assertAlmostEqual(ent_sched["final_s_t"], 0.0, places=4)

      # 3. Reset after alarm (--reset-after-alarm) resets S_t on day after 2026-10-04 alarm
      res_after_alarm = ch.evaluate_multishard_cusum(
          shard_files=dict(shard_specs),
          query_file=q_file,
          tier="BALANCED",
          slack_k=0.5,
          reset_after_alarm=True,
      )
      ent_alarm_rst = res_after_alarm["entities"]["svc-exfil"]
      self.assertTrue(len(ent_alarm_rst["resets_applied"]) >= 1)
      self.assertEqual(ent_alarm_rst["resets_applied"][0]["day"], "2026-10-05")

      # 4. Periodic schedule reset (--reset-every-days 7)
      res_periodic = ch.evaluate_multishard_cusum(
          shard_files=dict(shard_specs),
          query_file=q_file,
          tier="BALANCED",
          slack_k=0.5,
          reset_every_days=7,
      )
      ent_per = res_periodic["entities"]["svc-exfil"]
      reset_days = [r["day"] for r in ent_per["resets_applied"]]
      self.assertEqual(reset_days, ["2026-10-08", "2026-10-15"])


class TestWS601GuardrailsG1ToG5AndTimelineCleanup(unittest.TestCase):
  """Tests D6 Guardrails G1-G5 and TimelineAssembler gated CUSUM removal."""

  def test_g1_and_g2_fail_closed_cli_and_parser(self):
    with tempfile.TemporaryDirectory() as tmp:
      q_file = os.path.join(tmp, "q.yaral")
      with open(q_file, "w", encoding="utf-8") as f:
        f.write("// valid query\n")

      valid_p = os.path.join(tmp, "valid.json")
      with open(valid_p, "w", encoding="utf-8") as f:
        json.dump({}, f)

      # G1: inline JSON string rejected on --payload-file and --shard
      err = io.StringIO()
      with contextlib.redirect_stderr(err):
        rc = ch.main(["--payload-file", '{"stats": {}}', "--query-file", q_file,
                      "--start-day", "2026-10-20", "--end-day", "2026-10-25"])
      self.assertEqual(rc, 2)
      self.assertIn("G1", err.getvalue())

      err = io.StringIO()
      with contextlib.redirect_stderr(err):
        rc = ch.main(["--shard", '2026-10-20={"stats": {}}', "--query-file", q_file])
      self.assertEqual(rc, 2)
      self.assertIn("G1", err.getvalue())

      # G1: raw events without stats rejected
      raw_ev_p = os.path.join(tmp, "raw_events.json")
      with open(raw_ev_p, "w", encoding="utf-8") as f:
        json.dump({"events": [{"metadata": {"id": "1"}}]}, f)
      with self.assertRaisesRegex(ValueError, "RAW_LOG_DUMP_DETECTED"):
        ch.evaluate_start_anchored_cusum(
            payload_file=raw_ev_p,
            query_file=q_file,
            start_day="2026-10-20",
            end_day="2026-10-25",
        )

      # G2: missing --query-file rejected with exit code 2
      err = io.StringIO()
      with contextlib.redirect_stderr(err):
        rc = ch.main(["--payload-file", valid_p, "--start-day", "2026-10-20", "--end-day", "2026-10-25"])
      self.assertEqual(rc, 2)

      # G2: Mode A (1-day window) rejected
      with self.assertRaisesRegex(ValueError, "Mode A"):
        ch.evaluate_start_anchored_cusum(
            payload_file=valid_p,
            query_file=q_file,
            start_day="2026-10-20",
            end_day="2026-10-20",
        )

      # G2: >14 days in single-payload start-anchored mode rejected
      with self.assertRaisesRegex(ValueError, "14"):
        ch.evaluate_start_anchored_cusum(
            payload_file=valid_p,
            query_file=q_file,
            start_day="2026-10-01",
            end_day="2026-10-20",
        )

      # G2: invalid k <= 0 or h <= 0 rejected
      with self.assertRaises(ValueError):
        ch.evaluate_start_anchored_cusum(
            payload_file=valid_p,
            query_file=q_file,
            start_day="2026-10-20",
            end_day="2026-10-25",
            slack_k=0.0,
        )
      with self.assertRaises(ValueError):
        ch.evaluate_start_anchored_cusum(
            payload_file=valid_p,
            query_file=q_file,
            start_day="2026-10-20",
            end_day="2026-10-25",
            threshold_h=-1.0,
        )

      # G2: missing required baseline column on non-empty payload rejected
      bad_cols_p = os.path.join(tmp, "bad_cols.json")
      with open(bad_cols_p, "w", encoding="utf-8") as f:
        json.dump(_make_stats_payload({"entity": ["u1"], "ws": [_epoch_for_day("2026-10-20")]}), f)
      with self.assertRaisesRegex(ValueError, "G2"):
        ch.evaluate_start_anchored_cusum(
            payload_file=bad_cols_p,
            query_file=q_file,
            start_day="2026-10-20",
            end_day="2026-10-25",
        )

      # G2: non-finite NaN value rejected
      nan_p = os.path.join(tmp, "nan.json")
      with open(nan_p, "w", encoding="utf-8") as f:
        f.write(
            '{"stats":{"results":['
            '{"column":"entity","values":[{"value":{"stringVal":"u1"}}]},'
            '{"column":"ws","values":[{"value":{"int64Val":"1792454400"}}]},'
            '{"column":"observed_val","values":[{"value":{"doubleVal":"NaN"}}]},'
            '{"column":"baseline_mean","values":[{"value":{"doubleVal":10.0}}]},'
            '{"column":"baseline_stddev","values":[{"value":{"doubleVal":2.0}}]},'
            '{"column":"active_days","values":[{"value":{"int64Val":"10"}}]}'
            ']}}'
        )
      with self.assertRaisesRegex(ValueError, "G2"):
        ch.evaluate_start_anchored_cusum(
            payload_file=nan_p,
            query_file=q_file,
            start_day="2026-10-20",
            end_day="2026-10-25",
        )

  def test_g3_provenance_appendix_in_dict_and_markdown(self):
    with tempfile.TemporaryDirectory() as tmp:
      p_file = os.path.join(tmp, "p.json")
      q_file = os.path.join(tmp, "q.yaral")
      p_bytes = b'{"stats": {"results": []}}\n'
      q_bytes = b"// query text for sha256 verification\n"
      with open(p_file, "wb") as f:
        f.write(p_bytes)
      with open(q_file, "wb") as f:
        f.write(q_bytes)

      expected_p_sha = hashlib.sha256(p_bytes).hexdigest()
      expected_q_sha = hashlib.sha256(q_bytes).hexdigest()

      out_buf = io.StringIO()
      with contextlib.redirect_stdout(out_buf):
        rc = ch.main([
            "--payload-file", p_file,
            "--query-file", q_file,
            "--start-day", "2026-10-20",
            "--end-day", "2026-10-25",
            "--format", "markdown",
        ])
      self.assertEqual(rc, 0)
      md = out_buf.getvalue()
      self.assertIn("Provenance Appendix", md)
      self.assertIn(ch.HELPER_VERSION, md)
      self.assertIn(expected_p_sha, md)
      self.assertIn(expected_q_sha, md)

      report = ch.evaluate_start_anchored_cusum(
          payload_file=p_file,
          query_file=q_file,
          start_day="2026-10-20",
          end_day="2026-10-25",
      )
      self.assertEqual(report["provenance"]["helper_version"], "2.3.0")
      self.assertEqual(report["provenance"]["payload_sha256"], expected_p_sha)
      self.assertEqual(report["provenance"]["query_sha256"], expected_q_sha)

  def test_g5_honest_fallback_refuses_silent_slack_sum_substitution(self):
    expected_phrase = "this model needs a client that can run local scripts"
    with self.assertRaisesRegex(ValueError, expected_phrase):
      compile_hunt_pipeline(
          statistical_model="LONGITUDINAL_CUSUM",
          metrics="auth_attempts_total",
          entity_type="USER",
          mode="B",
          window_days=7,
          local_execution_available=False,
      )
    with self.assertRaisesRegex(ValueError, expected_phrase):
      compile_hunt_pipeline(
          statistical_model="CUSUM",
          metrics="auth_attempts_total",
          entity_type="USER",
          mode="B",
          window_days=7,
          has_run_command=False,
      )
    with self.assertRaisesRegex(ValueError, expected_phrase):
      MultiStageTemplateRouter().build_longitudinal_cusum_series_query(
          target_metric="auth_attempts_total",
          entity_type=EntityType.USER,
          local_execution_available=False,
      )
    with self.assertRaisesRegex(ValueError, expected_phrase):
      ch.assert_local_execution_available(False)

    # Explicit stateless prefilter request ("WINDOWED_SLACK_SUM") works honestly without local execution
    res_slack = compile_hunt_pipeline(
        statistical_model="WINDOWED_SLACK_SUM",
        metrics="auth_attempts_total",
        entity_type="USER",
        mode="B",
        window_days=7,
        local_execution_available=False,
        has_run_command=False,
    )
    self.assertEqual(res_slack["status"], "COMPILED")
    self.assertIn("Windowed Slack Sum", res_slack["preflight_card_markdown"])
    self.assertNotIn("Page CUSUM+", res_slack["preflight_card_markdown"])

  def test_timeline_assembler_removes_gated_cusum_and_guards_markdown_label(self):
    asm = ta.TimelineAssembler()
    asm.add_shard("2026-10-01", [{"entity": "h1", "z": 3.5}])
    asm.add_shard("2026-10-02", [])
    asm.add_shard("2026-10-03", [{"entity": "h1", "z": 4.2}])
    summary = asm.build()
    ent = summary["entities"]["h1"]
    self.assertNotIn("cusum_pos", ent)
    self.assertNotIn("peak_cusum_pos", ent)
    self.assertIn("gated_slack_sum", ent)
    self.assertIn("peak_gated_slack_sum", ent)

    gated_md = ta.format_markdown_table(
        [{"day": "2026-10-01", "observed": 50.0, "z_score": 3.5}],
        gated=True,
    )
    self.assertNotIn("Page CUSUM+ (S_t)", gated_md)

    ungated_md = ta.format_markdown_table(
        [{"day": "2026-10-01", "observed": 50.0, "z_score": 1.5}],
        gated=False,
    )
    self.assertIn("Page CUSUM+ (S_t)", ungated_md)


if __name__ == "__main__":
  unittest.main()
