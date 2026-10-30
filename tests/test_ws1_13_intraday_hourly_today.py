"""Unit tests for WS1-13: Opt-In Intra-Day `(1h, today)` Context & `PF-10`/`PF-10b` Guardrails.

Covers:
1. `PF10_SUPPORTED_HOURLY_TODAY_METRICS` (exact 23/38 metrics returning non-zero `(1h, today)`
   data in `gus-sdl` per `tests/live/baseline_gus_sdl.json["pf10_pf11_probes"]`).
2. `PF-10b` (`MISSING_D30_COMPANION_FOR_HOURLY_TODAY`) in `MalachiteASTValidator.validate_query`:
   - Rejects any stage/query invoking `metrics.*(period: 1h, window: today)` without a companion
     `metrics.*(period: 1d, window: 30d)` call.
   - Accepts queries pairing `(period: 1h, window: today)` with `(period: 1d, window: 30d)`.
3. `validate_intraday_hourly_window` & Guardrails R1–R5:
   - R1/R3: Requires UTC hour-aligned `start_time` (`MM:SS = 00:00Z`); rejects non-hour-aligned
     timestamps (e.g., `14:30:00Z`) and cross-UTC-day windows. Flags `empty_earlier_today_interval`
     explicitly when `start_time` is `00:00:00Z`, and computes `earlier_today_hours = 14` on
     `2026-10-28T14:00:00Z` -> `2026-10-28T19:00:00Z`.
   - R2: Rejects raw windows `< 4h` unless `allow_short_window=True`, emitting materialization-lag
     warning when overridden.
   - R5: Rejects all 15/38 unsupported `PF-10` metrics (`workspace_*`, `resource_deletion_*`,
     `resource_written_*`, `resource_creation_fail`, `file_executions_success`,
     `alert_event_name_count`) when `intraday_hourly=True`; accepts all 23/38 supported metrics.
4. `MultiStageTemplateRouter.build_query(..., intraday_hourly=True)`, `compile_hunt_pipeline`,
   CLI `--intraday-hourly`, and R4 Non-Division-by-24 + Partial-Day Upper-Tail / Cannot-Clear
   Dossier Semantics (`charles.hardy` `339 + 120 = 459` golden test).
5. Documentation parity in `references/multi-stage-metrics-guide.md` (`§2` & `§3`).
"""

import datetime
import json
from pathlib import Path
import re
import unittest

from scripts.preflight_validator import (
    EntityType,
    METRIC_CATALOG,
    MalachiteASTValidator,
    MatchMode,
    PF10_SUPPORTED_HOURLY_TODAY_METRICS,
    PF11_POPULATED_FIRST_SEEN_METRICS,
    StatisticalModel,
    validate_intraday_hourly_window,
)
from scripts.template_router import MultiStageTemplateRouter
from scripts.ueba_hybrid_engine import (
    compile_hunt_pipeline,
    evaluate_intraday_today_so_far,
    main as engine_cli_main,
    render_forensic_dossier,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_JSON_PATH = REPO_ROOT / "tests" / "live" / "baseline_gus_sdl.json"
GUIDE_MD_PATH = REPO_ROOT / "references" / "multi-stage-metrics-guide.md"


class TestWS113PF10BaselineAndPF10bASTValidator(unittest.TestCase):
  """Tests PF-10 23/38 capability table parity and PF-10b AST companion enforcement."""

  def test_pf10_supported_set_matches_live_gus_sdl_baseline_exactly(self) -> None:
    baseline = json.loads(BASELINE_JSON_PATH.read_text(encoding="utf-8"))
    pf10_pf11 = baseline["pf10_pf11_probes"]
    live_supported = {
        entry["metric_name"]
        for entry in pf10_pf11["by_metric_summary"]
        if entry["pf10_hourly_today"]["has_nonzero_hourly_data"]
    }
    live_results_supported = {
        r["metadata"]["metric_name"]
        for r in pf10_pf11["results"]
        if r["suite_type"] == "pf10_hourly_today_probe" and r["row_count"] > 0
    }
    self.assertEqual(live_supported, live_results_supported)
    self.assertEqual(len(live_supported), 23)
    self.assertEqual(PF10_SUPPORTED_HOURLY_TODAY_METRICS, frozenset(live_supported))
    self.assertEqual(
        PF10_SUPPORTED_HOURLY_TODAY_METRICS - PF11_POPULATED_FIRST_SEEN_METRICS,
        frozenset({"resource_creation_success", "resource_creation_total"}),
    )

  def test_pf10b_rejects_unanchored_hourly_today_and_accepts_d30_anchored(self) -> None:
    unanchored = """// Goal: Standalone (1h, today) without (1d, 30d) anchor must fail PF-10b
stage stage1_extract {
    metadata.event_type = "USER_LOGIN"
    target.user.userid = $user
    $user != ""
  match:
    $user by 1d
  outcome:
    $obs = count(metadata.id)
    $earlier_sum = max(metrics.auth_attempts_total(
        period: 1h, window: today, metric: event_count_sum, agg: sum,
        target.user.userid: target.user.userid
    ))
}
$user = $stage1_extract.user
match:
  $user
outcome:
  $s = max($stage1_extract.earlier_sum)
"""
    errs = MalachiteASTValidator.validate_query(unanchored)
    self.assertTrue(
        any("MISSING_D30_COMPANION_FOR_HOURLY_TODAY" in e for e in errs),
        f"Expected MISSING_D30_COMPANION_FOR_HOURLY_TODAY, got {errs}",
    )

    anchored = unanchored.replace(
        "    $obs = count(metadata.id)\n",
        "    $obs = count(metadata.id)\n"
        "    $d30_days = max(metrics.auth_attempts_total(\n"
        "        period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,\n"
        "        target.user.userid: target.user.userid\n"
        "    ))\n",
    )
    self.assertEqual(MalachiteASTValidator.validate_query(anchored), [])


class TestWS113GuardrailsR1ThroughR5(unittest.TestCase):
  """Tests Guardrails R1-R5 on window physics, metric gating, and non-division-by-24."""

  def test_r1_r2_r3_window_validation_physics(self) -> None:
    # Canonical V-live charles.hardy window: 14:00Z -> 19:00Z (5h raw window, 14 earlier-today hours)
    meta = validate_intraday_hourly_window("2026-10-28T14:00:00Z", "2026-10-28T19:00:00Z")
    self.assertFalse(meta["empty_earlier_today_interval"])
    self.assertEqual(meta["earlier_today_hours"], 14)
    self.assertAlmostEqual(meta["raw_window_hours"], 5.0)
    self.assertEqual(meta["earlier_today_interval"], "[2026-10-28T00:00:00Z, 2026-10-28T14:00:00Z)")

    # R1/R3: 00:00:00Z -> 06:00:00Z is hour-aligned and >= 4h, but [00:00Z, startTime) is empty!
    meta_midnight = validate_intraday_hourly_window("2026-10-28T00:00:00Z", "2026-10-28T06:00:00Z")
    self.assertTrue(meta_midnight["empty_earlier_today_interval"])
    self.assertEqual(meta_midnight["earlier_today_hours"], 0)
    self.assertIn("00:00", meta_midnight["earlier_today_interval_note"])
    self.assertIn("0", meta_midnight["earlier_today_interval_note"])

    # R1: Non-hour-aligned start_time (14:30:00Z) must fail
    with self.assertRaisesRegex(ValueError, "hour-aligned|00:00"):
      validate_intraday_hourly_window("2026-10-28T14:30:00Z", "2026-10-28T19:30:00Z")

    # R2: Raw window < 4h must fail unless allow_short_window=True
    with self.assertRaisesRegex(ValueError, "4h|4 hours|lag"):
      validate_intraday_hourly_window("2026-10-28T14:00:00Z", "2026-10-28T16:00:00Z")
    short_ok = validate_intraday_hourly_window(
        "2026-10-28T14:00:00Z",
        "2026-10-28T16:00:00Z",
        allow_short_window=True,
    )
    self.assertIsNotNone(short_ok["short_window_warning"])
    self.assertIn("lag", short_ok["short_window_warning"].lower())

    # R3: Cross-UTC-day window past midnight must fail
    with self.assertRaisesRegex(ValueError, "single UTC|UTC date"):
      validate_intraday_hourly_window("2026-10-28T21:00:00Z", "2026-10-29T03:00:00Z")

  def test_r5_rejects_all_15_unsupported_metrics_and_accepts_all_23_supported_metrics(self) -> None:
    router = MultiStageTemplateRouter()
    unsupported = sorted(set(METRIC_CATALOG.keys()) - PF10_SUPPORTED_HOURLY_TODAY_METRICS)
    self.assertEqual(len(unsupported), 15)

    for m_name in unsupported:
      ent = METRIC_CATALOG[m_name].supported_entity_types[0]
      with self.assertRaisesRegex(ValueError, "PF-10|intraday_hourly", msg=m_name):
        router.build_query(
            target_metric=m_name,
            entity_type=ent,
            statistical_model=StatisticalModel.STANDARD_Z_SCORE,
            intraday_hourly=True,
        )

    for m_name in sorted(PF10_SUPPORTED_HOURLY_TODAY_METRICS):
      ent = METRIC_CATALOG[m_name].supported_entity_types[0]
      q = router.build_query(
          target_metric=m_name,
          entity_type=ent,
          statistical_model=StatisticalModel.STANDARD_Z_SCORE,
          intraday_hourly=True,
      )
      errs = MalachiteASTValidator.validate_query(q)
      self.assertEqual(errs, [], msg=f"{m_name}: {errs}")
      self.assertIn("period: 1h, window: today", q, m_name)
      self.assertIn("period: 1d, window: 30d", q, m_name)
      self.assertIn("$earlier_today_sum", q, m_name)
      self.assertIn("$earlier_today_peak_hour", q, m_name)
      self.assertIn("$earlier_today_active_hours", q, m_name)
      self.assertIn("$full_today_so_far", q, m_name)
      # R4 invariant: never divide 30d mean/SD by 24 or 4.898979
      self.assertNotIn("24.0", q, m_name)
      self.assertNotIn("/ 24", q, m_name)
      self.assertNotIn("4.898979", q, m_name)

  def test_default_intraday_hourly_false_leaves_queries_byte_identical(self) -> None:
    router = MultiStageTemplateRouter()
    q_default = router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.STANDARD_Z_SCORE,
    )
    q_explicit_false = router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.STANDARD_Z_SCORE,
        intraday_hourly=False,
    )
    self.assertEqual(q_default, q_explicit_false)
    self.assertNotIn("window: today", q_default)
    self.assertNotIn("$earlier_today_sum", q_default)

  def test_first_seen_novelty_with_intraday_hourly_includes_earlier_today_first_seen(self) -> None:
    router = MultiStageTemplateRouter()
    q = router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.FIRST_SEEN_NOVELTY,
        novelty_subkey_field="target.application",
        intraday_hourly=True,
        match_mode=MatchMode.FLEET_ROLLUP,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q), [])
    self.assertEqual(
        MalachiteASTValidator.validate_model_concordance(q, StatisticalModel.FIRST_SEEN_NOVELTY),
        [],
    )
    self.assertIn("period: 1h, window: today, metric: first_seen, agg: min", q)
    self.assertIn("$earlier_today_first_seen", q)
    self.assertIn("$full_today_so_far = $earlier_today_sum + $observed", q)


class TestWS113GoldenCharlesHardyEngineAndDossier(unittest.TestCase):
  """Tests charles.hardy golden V-live math (339 + 120 = 459), CLI --intraday-hourly, and R4 dossier labels."""

  def test_charles_hardy_golden_full_day_breach_and_cannot_clear_semantics(self) -> None:
    # 1. Breach case: earlier_today_sum = 339 ([00:00Z, 14:00Z)), raw observed = 120 ([14:00Z, 19:00Z))
    breach = evaluate_intraday_today_so_far(
        earlier_today_sum=339,
        raw_observed=120,
        hist_avg=100.0,
        hist_stddev=20.0,
        threshold_sigma=3.0,
    )
    self.assertEqual(breach["full_today_so_far"], 459.0)
    self.assertEqual(breach["upper_tail_cutoff"], 160.0)
    self.assertAlmostEqual(breach["z_today_so_far"], 17.95, places=2)
    self.assertTrue(breach["guaranteed_full_day_breach"])
    self.assertEqual(breach["verdict"], "GUARANTEED_FULL_DAY_BREACH")

    # 2. Sub-threshold case: full_today_so_far = 70 < 160.0 -> CANNOT CLEAR until 24h complete
    sub = evaluate_intraday_today_so_far(
        earlier_today_sum=40,
        raw_observed=30,
        hist_avg=100.0,
        hist_stddev=20.0,
        threshold_sigma=3.0,
    )
    self.assertEqual(sub["full_today_so_far"], 70.0)
    self.assertFalse(sub["guaranteed_full_day_breach"])
    self.assertEqual(sub["verdict"], "PARTIAL_UTC_DAY_CANNOT_CLEAR")
    self.assertIn(
        "today so far (partial UTC day) — cannot clear entity until 24h complete",
        sub["status_label"],
    )

  def test_engine_compile_cli_and_dossier_intraday_hourly_end_to_end(self) -> None:
    ref_now = datetime.datetime(2026, 10, 28, 19, 0, 0, tzinfo=datetime.timezone.utc)
    compiled = compile_hunt_pipeline(
        statistical_model="STANDARD_Z_SCORE",
        metrics="auth_attempts_total",
        entity_type="USER",
        entity_value="charles.hardy",
        intraday_hourly=True,
        start_time="2026-10-28T14:00:00Z",
        end_time="2026-10-28T19:00:00Z",
        reference_time=ref_now,
    )
    self.assertEqual(compiled["status"], "COMPILED")
    self.assertTrue(compiled["ast_valid"])
    self.assertTrue(compiled["intraday_hourly"])
    self.assertEqual(compiled["intraday_window_meta"]["earlier_today_hours"], 14)
    self.assertIn("$full_today_so_far = $earlier_today_sum + $observed", compiled["compiled_query"])
    self.assertIn("$personal_diff = $full_today_so_far - $hist_avg", compiled["compiled_query"])

    # Populated breach dossier for charles.hardy (339 + 120 = 459 vs mu=100, sd=20)
    breach_dossier = render_forensic_dossier(
        rows=[
            {
                "user": "charles.hardy",
                "observed": 120,
                "earlier_today_sum": 339,
                "earlier_today_peak_hour": 58,
                "earlier_today_active_hours": 14,
                "full_today_so_far": 459,
                "hist_avg": 100.0,
                "hist_stddev": 20.0,
                "active_days": 30,
                "personal_z": 17.95,
            }
        ],
        executed_query=compiled["compiled_query"],
        statistical_model="STANDARD_Z_SCORE",
        metric_name="auth_attempts_total",
        entity_type="USER",
        intraday_hourly=True,
    )
    self.assertEqual(breach_dossier["outcome_classification"], "ACUTE_OUTLIER")
    self.assertTrue(breach_dossier["outliers"][0]["guaranteed_full_day_breach"])
    self.assertEqual(breach_dossier["outliers"][0]["full_today_so_far"], 459.0)
    self.assertIn("459", breach_dossier["dossier_markdown"])

    # Zero-row sub-threshold dossier must state cannot-clear partial-day caveat
    zero_dossier = render_forensic_dossier(
        rows=[],
        executed_query=compiled["compiled_query"],
        statistical_model="STANDARD_Z_SCORE",
        metric_name="auth_attempts_total",
        entity_type="USER",
        intraday_hourly=True,
    )
    self.assertEqual(zero_dossier["outcome_classification"], "CLEAN_OR_SUBTHRESHOLD")
    self.assertIn(
        "today so far (partial UTC day) — cannot clear entity until 24h complete",
        zero_dossier["dossier_markdown"],
    )
    self.assertIn(
        "today so far (partial UTC day) — cannot clear entity until 24h complete",
        zero_dossier["clean_hunt_markdown"],
    )

    # CLI --intraday-hourly smoke check
    rc = engine_cli_main([
        "compile",
        "--model",
        "STANDARD_Z_SCORE",
        "--metrics",
        "auth_attempts_total",
        "--entity-type",
        "USER",
        "--intraday-hourly",
        "--start-time",
        "2026-10-28T14:00:00Z",
        "--end-time",
        "2026-10-28T19:00:00Z",
        "--format",
        "query",
    ])
    self.assertEqual(rc, 0)

  def test_render_forensic_dossier_midnight_00z_surfaces_empty_interval_note(self) -> None:
    """Verifies render_forensic_dossier surfaces earlier_today_interval_note when start_time is 00:00Z."""
    ref_now = datetime.datetime(2026, 10, 28, 6, 0, 0, tzinfo=datetime.timezone.utc)
    compiled_midnight = compile_hunt_pipeline(
        statistical_model="STANDARD_Z_SCORE",
        metrics="auth_attempts_total",
        entity_type="USER",
        entity_value="charles.hardy",
        intraday_hourly=True,
        start_time="2026-10-28T00:00:00Z",
        end_time="2026-10-28T06:00:00Z",
        reference_time=ref_now,
    )
    expected_midnight_meta = validate_intraday_hourly_window(
        "2026-10-28T00:00:00Z",
        "2026-10-28T06:00:00Z",
        allow_short_window=True,
    )
    self.assertTrue(expected_midnight_meta["empty_earlier_today_interval"])
    expected_note = expected_midnight_meta["earlier_today_interval_note"]

    # 1. Zero-row dossier at 00:00Z must surface earlier_today_interval_note in dossier_markdown & clean_hunt_markdown
    zero_midnight = render_forensic_dossier(
        rows=[],
        executed_query=compiled_midnight["compiled_query"],
        statistical_model="STANDARD_Z_SCORE",
        metric_name="auth_attempts_total",
        entity_type="USER",
        intraday_hourly=True,
        start_time="2026-10-28T00:00:00Z",
        end_time="2026-10-28T06:00:00Z",
    )
    self.assertIn(expected_note, zero_midnight["dossier_markdown"])
    self.assertIn(expected_note, zero_midnight["clean_hunt_markdown"])
    self.assertIn(expected_note, zero_midnight["partial_day_warning"])
    self.assertTrue(zero_midnight["intraday_window_meta"]["empty_earlier_today_interval"])

    # 2. Populated breach dossier at 00:00Z (earlier_today_sum = 0, raw observed = 180) must also surface note
    populated_midnight = render_forensic_dossier(
        rows=[
            {
                "user": "charles.hardy",
                "observed": 180,
                "earlier_today_sum": 0,
                "earlier_today_peak_hour": 0,
                "earlier_today_active_hours": 0,
                "full_today_so_far": 180,
                "hist_avg": 100.0,
                "hist_stddev": 20.0,
                "active_days": 30,
                "personal_z": 4.0,
            }
        ],
        executed_query=compiled_midnight["compiled_query"],
        statistical_model="STANDARD_Z_SCORE",
        metric_name="auth_attempts_total",
        entity_type="USER",
        intraday_hourly=True,
        start_time="2026-10-28T00:00:00Z",
        end_time="2026-10-28T06:00:00Z",
    )
    self.assertTrue(populated_midnight["intraday_window_meta"]["empty_earlier_today_interval"])
    self.assertIn(expected_note, populated_midnight["dossier_markdown"])

    # 3. Non-midnight window (14:00Z -> 19:00Z) surfaces 14 hourly bucket(s) stitching note
    non_midnight = render_forensic_dossier(
        rows=[],
        executed_query=compiled_midnight["compiled_query"],
        statistical_model="STANDARD_Z_SCORE",
        metric_name="auth_attempts_total",
        entity_type="USER",
        intraday_hourly=True,
        start_time="2026-10-28T14:00:00Z",
        end_time="2026-10-28T19:00:00Z",
    )
    self.assertFalse(non_midnight["intraday_window_meta"]["empty_earlier_today_interval"])
    self.assertIn("14 hourly bucket(s)", non_midnight["dossier_markdown"])


class TestWS113MultiStageGuideDocumentationParity(unittest.TestCase):
  """Verifies references/multi-stage-metrics-guide.md §2 & §3 retire stale claims and document PF-10/PF-10b/PF-11."""

  def test_guide_retires_stale_hourly_scaling_and_documents_pf10_pf10b_pf11(self) -> None:
    text = GUIDE_MD_PATH.read_text(encoding="utf-8")
    self.assertNotIn("hourly_z_score.yl2", text)
    self.assertNotIn("HOURLY_TEMPORAL_ZSCORE", text)
    self.assertNotIn("validatePeriodAndWindow", text)
    self.assertNotIn("4.898979", text)
    self.assertNotRegex(text, r"\\mu_\{1\\text\{h\}\}\s*=\s*\\mu_\{1\\text\{d\}\}\s*/\s*24")

    self.assertIn("period: 1h, window: today", text)
    self.assertIn("PF-10b", text)
    self.assertIn("23/38", text)
    self.assertIn("first_seen", text)
    self.assertIn("last_seen", text)
    self.assertIn("period_start_for_max", text)
    self.assertIn("num_unique_filter_values", text)


if __name__ == "__main__":
  unittest.main()
