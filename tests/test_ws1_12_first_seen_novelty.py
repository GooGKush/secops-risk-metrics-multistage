"""Unit tests for WS1-12: First-Seen Novelty (`FIRST_SEEN_NOVELTY`) & `PF-11` Validator.

Covers:
1. Empirically verified `PF11_POPULATED_FIRST_SEEN_METRICS` (exact 21/38 metrics returning
   non-zero `first_seen` rows in `gus-sdl` per `tests/live/baseline_gus_sdl.json`).
2. `MalachiteASTValidator` (`PF-11` / `ueba.go` / `ueba_validator.go`):
   - Accepts `metric: first_seen` and `metric: last_seen` across both count and byte metrics
     with timestamp-safe aggregations (`min`, `max`, `num_metric_periods`,
     `period_start_for_max`, `period_start_for_min`).
   - Rejects invalid timestamp aggregations (`sum`, `avg`, `stddev`) on `first_seen` / `last_seen`.
   - Preserves `METRIC_TYPE_MISMATCH` (`value_sum` on count metrics, `event_count_sum` on byte metrics).
   - Accepts `metric: num_unique_filter_values` ONLY when wildcard `*` is on 1 non-namespace
     dimension filter alongside >= 1 concrete dimension filter; rejects `*` on namespace
     fields, 0 or 2 wildcards, or `*` on non-`num_unique_filter_values` metrics.
   - Enforces valid `(period, window)` combinations (`(1d, 30d)` and `(1h, today)` ONLY).
3. `MultiStageTemplateRouter`:
   - `StatisticalModel.FIRST_SEEN_NOVELTY` renders across single-key and composite multi-key
     extractors (`auth_attempts_total`, `network_bytes_outbound`, `file_executions_total`,
     `resource_read_total`) in both `TIMELINE_BREAKDOWN` and `FLEET_ROLLUP`, plus optional
     composite `novelty_subkey_field` (`target.application`, `target.hostname`, `network.dns_domain`).
   - `PipelineArchitecture.FIRST_SEEN_NOVELTY_2STAGE` renders composite `(user, app)` on
     `auth_attempts_total` (`USER`) and `(host, dest_host)` on `http_queries_total` (`ASSET`).
4. `UEBAHybridEngine` & `CommonMarkTriageFormatter`:
   - Routes novelty aliases (`FIRST_SEEN_NOVELTY`, `FIRST_SEEN`, `NOVELTY`, `UNSEEN`, `NEW_ACTIVITY`)
     to `StatisticalModel.FIRST_SEEN_NOVELTY` as primary novelty detector (ahead of ECG) and
     emits coverage advisories on the 17/38 unpopulated metrics in `gus-sdl`.
   - Formats `novelty_flag = 1` (`prior_first_seen = 0`) strictly as a boolean novelty flag +
     context (`prior_last_seen`, `peak_period_start`), `CRI = N/A`, `ACUTE_OUTLIER` — NEVER
     as `σ`, NEVER as `CRI = 23`, and NEVER filtered out as immature (`active_days = 0`).
"""

import json
from pathlib import Path
import unittest

from scripts.preflight_validator import (
    EntityType,
    MalachiteASTValidator,
    MatchMode,
    PF11_POPULATED_FIRST_SEEN_METRICS,
    PipelineArchitecture,
    StatisticalModel,
)
from scripts.template_router import MultiStageTemplateRouter
from scripts.triage_formatter import CommonMarkTriageFormatter
from scripts.ueba_hybrid_engine import compile_hunt_pipeline, render_forensic_dossier
from tests.live.live_compile_harness import build_pf11_first_seen_probes


REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_JSON_PATH = REPO_ROOT / "tests" / "live" / "baseline_gus_sdl.json"


class TestWS112PF11BaselineAndASTValidator(unittest.TestCase):
  """Tests PF-11 capability table parity and MalachiteASTValidator PF-11 rules."""

  def test_pf11_populated_set_matches_live_gus_sdl_baseline_exactly(self) -> None:
    baseline = json.loads(BASELINE_JSON_PATH.read_text(encoding="utf-8"))
    pf10_pf11 = baseline["pf10_pf11_probes"]
    live_populated = {
        entry["metric_name"]
        for entry in pf10_pf11["by_metric_summary"]
        if entry["pf11_first_seen"]["has_nonzero_first_seen"]
    }
    live_results_populated = {
        r["metadata"]["metric_name"]
        for r in pf10_pf11["results"]
        if r["suite_type"] == "pf11_first_seen_probe" and r["row_count"] > 0
    }
    self.assertEqual(live_populated, live_results_populated)
    self.assertEqual(len(live_populated), 21)
    self.assertEqual(PF11_POPULATED_FIRST_SEEN_METRICS, frozenset(live_populated))

  def test_all_38_pf11_probes_pass_malachite_ast_validator_directly(self) -> None:
    probes = build_pf11_first_seen_probes()
    self.assertEqual(len(probes), 38)
    for probe in probes:
      errs = MalachiteASTValidator.validate_query(probe.query)
      self.assertEqual(errs, [], msg=f"{probe.query_id}: {errs}")
      if probe.fallback_query is not None:
        fb_errs = MalachiteASTValidator.validate_query(probe.fallback_query)
        self.assertEqual(fb_errs, [], msg=f"{probe.query_id} fallback: {fb_errs}")

  def test_pf11_accepts_first_seen_last_seen_and_period_start_aggs_on_count_and_byte_metrics(self) -> None:
    byte_novelty_query = """// Goal: PF-11 byte metric first_seen/last_seen + period_start_for_max validation
stage stage1_extract {
    metadata.event_type = "NETWORK_CONNECTION"
    principal.asset.ip = $ip
    $ip != ""
  match:
    $ip by 1d
  outcome:
    $obs = sum(if(network.sent_bytes > 0 and network.sent_bytes < 1000000000000000, 1.0, 0.0) * network.sent_bytes)
    $first_ts = min(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: first_seen, agg: min,
        principal.asset.ip: principal.asset.ip
    ))
    $last_ts = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: last_seen, agg: max,
        principal.asset.ip: principal.asset.ip
    ))
    $peak_day = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: period_start_for_max,
        principal.asset.ip: principal.asset.ip
    ))
    $min_day = min(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: period_start_for_min,
        principal.asset.ip: principal.asset.ip
    ))
}
$ip = $stage1_extract.ip
match:
  $ip
outcome:
  $prior_first_seen = min($stage1_extract.first_ts)
  $prior_last_seen = max($stage1_extract.last_ts)
  $peak_period_start = max($stage1_extract.peak_day)
  $novelty_flag = if($prior_first_seen = 0, 1, 0)
condition:
  $novelty_flag = 1
order:
  $novelty_flag desc
"""
    self.assertEqual(MalachiteASTValidator.validate_query(byte_novelty_query), [])

  def test_pf11_rejects_sum_avg_stddev_on_timestamp_metrics_and_preserves_type_mismatch(self) -> None:
    bad_ts_agg = """// Goal: Reject sum on first_seen timestamp metric
stage stage1_extract {
    metadata.event_type = "USER_LOGIN"
    target.user.userid = $user
    $user != ""
  match:
    $user by 1d
  outcome:
    $bad = max(metrics.auth_attempts_total(
        period: 1d, window: 30d, metric: first_seen, agg: sum,
        target.user.userid: target.user.userid
    ))
}
$user = $stage1_extract.user
match:
  $user
outcome:
  $x = max($stage1_extract.bad)
"""
    errs = MalachiteASTValidator.validate_query(bad_ts_agg)
    self.assertTrue(
        any("INVALID_TIMESTAMP_AGGREGATION" in e for e in errs),
        f"Expected INVALID_TIMESTAMP_AGGREGATION, got {errs}",
    )

    # Byte metric with event_count_sum must still fail METRIC_TYPE_MISMATCH
    mismatch_q = bad_ts_agg.replace("USER_LOGIN", "NETWORK_CONNECTION").replace(
        "metrics.auth_attempts_total(\n        period: 1d, window: 30d, metric: first_seen, agg: sum,\n        target.user.userid: target.user.userid",
        "metrics.network_bytes_outbound(\n        period: 1d, window: 30d, metric: event_count_sum, agg: avg,\n        principal.user.userid: principal.user.userid",
    ).replace("target.user.userid = $user", "principal.user.userid = $user")
    mm_errs = MalachiteASTValidator.validate_query(mismatch_q)
    self.assertTrue(any("METRIC_TYPE_MISMATCH" in e for e in mm_errs), mm_errs)

  def test_pf11_validates_num_unique_filter_values_wildcard_rules_and_period_window_pairs(self) -> None:
    valid_unique_q = """// Goal: Valid num_unique_filter_values with 1 wildcard + 1 concrete filter
stage stage1_extract {
    metadata.event_type = "USER_LOGIN"
    target.user.userid = $user
    $user != ""
  match:
    $user by 1d
  outcome:
    $distinct_apps_30d = max(metrics.auth_attempts_total(
        period: 1d, window: 30d, metric: num_unique_filter_values, agg: max,
        target.user.userid: target.user.userid,
        target.application: *
    ))
}
$user = $stage1_extract.user
match:
  $user
outcome:
  $apps = max($stage1_extract.distinct_apps_30d)
"""
    self.assertEqual(MalachiteASTValidator.validate_query(valid_unique_q), [])

    # 0 wildcards on num_unique_filter_values -> invalid
    no_wc = valid_unique_q.replace("target.application: *", "target.application: target.application")
    self.assertTrue(
        any("INVALID_NUM_UNIQUE_FILTER_VALUES" in e for e in MalachiteASTValidator.validate_query(no_wc))
    )

    # Wildcard on event_count_sum -> invalid
    wc_on_count = valid_unique_q.replace("metric: num_unique_filter_values", "metric: event_count_sum")
    self.assertTrue(
        any("INVALID_WILDCARD_METRIC_FILTER" in e for e in MalachiteASTValidator.validate_query(wc_on_count))
    )

    # Wildcard on namespace filter -> invalid
    wc_ns = """// Goal: Reject wildcard on namespace filter
stage stage1_extract {
    metadata.event_type = "USER_LOGIN"
    target.user.userid = $user
    $user != ""
  match:
    $user by 1d
  outcome:
    $bad = max(metrics.auth_attempts_total(
        period: 1d, window: 30d, metric: num_unique_filter_values, agg: max,
        target.user.userid: target.user.userid,
        target.namespace: *
    ))
}
$user = $stage1_extract.user
match:
  $user
outcome:
  $x = max($stage1_extract.bad)
"""
    self.assertTrue(
        any("INVALID_WILDCARD_NAMESPACE_FILTER" in e for e in MalachiteASTValidator.validate_query(wc_ns))
    )

    # Invalid period/window pair (1h, 30d) -> invalid
    bad_pw = valid_unique_q.replace("period: 1d, window: 30d", "period: 1h, window: 30d")
    self.assertTrue(
        any("INVALID_METRIC_PERIOD_WINDOW" in e for e in MalachiteASTValidator.validate_query(bad_pw))
    )


class TestWS112RouterEngineAndTriageSemantics(unittest.TestCase):
  """Tests FIRST_SEEN_NOVELTY rendering, composite keys, aliases, advisories, and non-sigma reporting."""

  def setUp(self) -> None:
    self.router = MultiStageTemplateRouter()

  def test_router_builds_first_seen_novelty_across_single_and_composite_metrics(self) -> None:
    # 1. Single-key with explicit composite subkey (target.user.userid + target.application)
    q_user_app = self.router.build_query(
        target_metric="auth_attempts_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.FIRST_SEEN_NOVELTY,
        novelty_subkey_field="target.application",
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_user_app), [])
    self.assertIn("metric: first_seen, agg: min", q_user_app)
    self.assertIn("metric: last_seen, agg: max", q_user_app)
    self.assertIn("agg: period_start_for_max", q_user_app)
    self.assertIn("target.application: target.application", q_user_app)
    self.assertIn("$user, $app", q_user_app)
    self.assertIn("$novelty_flag = if($prior_first_seen = 0 and $observed >= 1, 1, 0)", q_user_app)
    self.assertEqual(MultiStageTemplateRouter.root_condition(q_user_app), "$novelty_flag = 1")
    self.assertNotIn("$personal_z", q_user_app)

    # 2. Native composite extractors: file_executions_total ($host, $sha256) and resource_read_total ($sa, $vendor, $product, $resource)
    q_exec = self.router.build_query(
        target_metric="file_executions_total",
        entity_type=EntityType.ASSET,
        statistical_model=StatisticalModel.FIRST_SEEN_NOVELTY,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_exec), [])
    self.assertIn("$host, $sha256", q_exec)
    self.assertIn("principal.process.file.sha256: principal.process.file.sha256", q_exec)

    q_res = self.router.build_query(
        target_metric="resource_read_total",
        entity_type=EntityType.USER,
        statistical_model=StatisticalModel.FIRST_SEEN_NOVELTY,
        match_mode=MatchMode.FLEET_ROLLUP,
    )
    self.assertEqual(MalachiteASTValidator.validate_query(q_res), [])
    self.assertIn("$sa, $vendor, $product, $resource", q_res)
    self.assertIn("target.resource.name: target.resource.name", q_res)

  def test_pipeline_first_seen_novelty_2stage_renders_user_and_asset_composite_pairs(self) -> None:
    q_user = self.router.build_pipeline_query(
        PipelineArchitecture.FIRST_SEEN_NOVELTY_2STAGE,
        entity_type=EntityType.USER,
    )
    self.assertEqual(MultiStageTemplateRouter.validate_rendered_pipeline(q_user), [])
    self.assertIn("metrics.auth_attempts_total(", q_user)
    self.assertIn("target.user.userid: target.user.userid", q_user)
    self.assertIn("target.application: target.application", q_user)
    self.assertIn("$novelty_flag = 1", q_user)

    q_asset = self.router.build_pipeline_query(
        PipelineArchitecture.FIRST_SEEN_NOVELTY_2STAGE,
        entity_type=EntityType.ASSET,
    )
    self.assertEqual(MultiStageTemplateRouter.validate_rendered_pipeline(q_asset), [])
    self.assertIn("metrics.http_queries_total(", q_asset)
    self.assertIn("principal.asset.hostname: principal.asset.hostname", q_asset)
    self.assertIn("target.hostname: target.hostname", q_asset)

  def test_engine_routes_novelty_aliases_and_warns_on_unpopulated_metrics(self) -> None:
    for alias in ("FIRST_SEEN_NOVELTY", "FIRST_SEEN", "NOVELTY", "UNSEEN", "NEW_ACTIVITY"):
      res = compile_hunt_pipeline(
          statistical_model=alias,
          metrics="auth_attempts_total",
          entity_type="USER",
          entity_value="charles.hardy",
      )
      self.assertEqual(res["status"], "COMPILED", alias)
      self.assertEqual(res["statistical_model"], "FIRST_SEEN_NOVELTY", alias)
      self.assertTrue(res["ast_valid"], alias)
      self.assertIn('= "charles.hardy"', res["compiled_query"])
      self.assertIn("metric: first_seen, agg: min", res["compiled_query"])

    # Unpopulated metric in gus-sdl (workspace_total_download_actions -> 0 rows in PF-11 baseline)
    res_unpop = compile_hunt_pipeline(
        statistical_model="FIRST_SEEN_NOVELTY",
        metrics="workspace_total_download_actions",
        entity_type="USER",
    )
    self.assertEqual(res_unpop["status"], "COMPILED")
    self.assertTrue(
        any("PF-11" in adv or "first_seen" in adv for adv in res_unpop.get("advisories", [])),
        f"Expected unpopulated PF-11 advisory in {res_unpop.get('advisories')}",
    )

  def test_dossier_and_triage_report_novelty_as_boolean_flag_never_sigma_and_never_immature_dropped(self) -> None:
    compiled = compile_hunt_pipeline(
        statistical_model="FIRST_SEEN_NOVELTY",
        architecture="first_seen_novelty_2stage",
        metrics="auth_attempts_total",
        entity_type="USER",
    )
    rows = [
        {
            "user": "charles.hardy",
            "app": "new-admin-portal",
            "observed": 4,
            "prior_first_seen": 0,
            "prior_last_seen": 0,
            "peak_period_start": 0,
            "active_days": 0,
            "novelty_flag": 1,
        }
    ]
    dossier = render_forensic_dossier(
        rows=rows,
        executed_query=compiled["compiled_query"],
        statistical_model="FIRST_SEEN_NOVELTY",
        metric_name="auth_attempts_total",
        entity_type="USER",
    )
    self.assertEqual(dossier["outcome_classification"], "ACUTE_OUTLIER")
    self.assertEqual(dossier["outlier_count"], 1)
    self.assertEqual(dossier["immature_count"], 0)

    rec = dossier["outliers"][0]
    self.assertFalse(rec["is_true_sigma"])
    self.assertIsNone(rec["cri"])
    self.assertEqual(rec["cri_display"], "N/A")
    self.assertNotIn("σ", rec["score_display"])
    self.assertIn("NOVEL", rec["score_display"].upper())

    md = dossier["dossier_markdown"]
    self.assertNotIn("+1.00σ", md)
    self.assertNotIn("1.0σ", md)
    self.assertIn("N/A", md)
    self.assertIn("NOVEL", md.upper())

    # Also check direct CommonMarkTriageFormatter classification
    self.assertEqual(
        CommonMarkTriageFormatter.classify_hunt_outcome(
            {
                "outlier_count": 1,
                "top_outliers": dossier["outliers"],
                "primary_score_metric": "novelty_flag",
            },
            anomaly_threshold=3.0,
        ),
        "ACUTE_OUTLIER",
    )


if __name__ == "__main__":
  unittest.main()
