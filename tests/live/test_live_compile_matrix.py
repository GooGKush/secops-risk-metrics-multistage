"""Offline unit tests and opt-in live tests for WS0-03 Live Compile Harness."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Callable, Optional
import unittest

SKILL_ROOT = Path(__file__).resolve().parents[2]
if str(SKILL_ROOT) not in sys.path:
  sys.path.insert(0, str(SKILL_ROOT))

from scripts import malachite_catalog as mc
from scripts.preflight_validator import METRIC_CATALOG, MalachiteASTValidator, StatisticalModel
from scripts.template_router import MatchMode
from tests.live.live_compile_harness import (
    DEFAULT_COMPILE_END_TIME,
    DEFAULT_COMPILE_START_TIME,
    DEFAULT_PF10_END_TIME,
    DEFAULT_PF10_START_TIME,
    DEFAULT_PF11_END_TIME,
    DEFAULT_PF11_START_TIME,
    NETWORK_IP_FALLBACK_METRICS,
    TEMPLATES_DIR,
    LiveExecutionResult,
    active_statistical_models,
    build_all_probes,
    build_covering_compile_suite,
    build_pf10_hourly_today_probes,
    build_pf11_first_seen_probes,
    export_execution_results,
    export_manifest,
    load_manifest,
    render_all_pipelines,
    render_full_matrix,
    run_manifest,
    summarize_matrix_records,
    validate_compile_window,
    validate_pf10_window,
)


def _stats_payload(columns: dict[str, list[tuple[str, Any]]]) -> dict[str, Any]:
  """Builds a synthetic Chronicle `udm_search` stats response dictionary."""
  return {
      "stats": {
          "results": [
              {
                  "column": col_name,
                  "values": [{"value": {kind: val}} for kind, val in cells],
              }
              for col_name, cells in columns.items()
          ]
      }
  }


class TestOfflineFullMatrixRenderer(unittest.TestCase):
  """Verifies full offline rendering across 38 metrics x entity types x 18 models x 2 modes + 34 pipelines."""

  records = []
  summary = {}

  @classmethod
  def setUpClass(cls) -> None:
    super().setUpClass()
    cls.records = render_full_matrix()
    cls.summary = summarize_matrix_records(cls.records)

  def test_full_matrix_counts_and_zero_render_or_ast_crashes(self) -> None:
    expected_pairs = sum(len(m.supported_entity_types) for m in METRIC_CATALOG.values())
    active_models = active_statistical_models()
    expected_cells = expected_pairs * len(active_models) * len(MatchMode)
    disk_pipelines = sorted(p.name for p in (TEMPLATES_DIR / "pipelines").glob("*.yl2"))

    self.assertEqual(len(METRIC_CATALOG), 38)
    self.assertEqual(len(StatisticalModel), 18)
    self.assertEqual(len(active_models), 14)
    self.assertIn(StatisticalModel.QUANTILE_IQR_SKEW, set(active_models))
    self.assertIn(StatisticalModel.RELATIVE_DEVIATION, set(active_models))
    self.assertNotIn(StatisticalModel.PIECEWISE_CRI, set(active_models))
    self.assertNotIn(StatisticalModel.FLEET_PREVALENCE_SHIELD, set(active_models))
    self.assertEqual(len(disk_pipelines), 33)

    self.assertEqual(self.summary["matrix_cell_count"], expected_cells)
    self.assertEqual(self.summary["pipeline_count"], len(disk_pipelines))
    self.assertEqual(self.summary["render_crash_count"], 0, msg=f"Render crashes: {self.summary['render_crashes']}")
    self.assertEqual(
        self.summary["ast_error_record_count"],
        0,
        msg=f"AST failures: {self.summary['ast_error_records']}",
    )

  def test_every_pipeline_file_on_disk_is_rendered_with_zero_unresolved_slots(self) -> None:
    disk_pipelines = {p.name for p in (TEMPLATES_DIR / "pipelines").glob("*.yl2")}
    pipeline_records = [r for r in self.records if r.kind == "pipeline_template"]
    rendered_files = {r.pipeline_template for r in pipeline_records}
    self.assertEqual(rendered_files, disk_pipelines)
    for rec in pipeline_records:
      self.assertTrue(rec.render_ok, msg=rec.record_id)
      self.assertNotIn("{{", rec.query, msg=f"Unresolved placeholder in {rec.record_id}")
      self.assertEqual(rec.ast_errors, [], msg=f"AST errors in {rec.record_id}: {rec.ast_errors}")

    # Named-cohort variants for part_of_the_whole_* also render and pass AST validation.
    with_cohorts = render_all_pipelines(include_cohort_variants=True)
    self.assertEqual(len(with_cohorts), 35)
    cohort_recs = [r for r in with_cohorts if "#named_cohort" in r.record_id]
    self.assertEqual(len(cohort_recs), 2)
    for rec in cohort_recs:
      self.assertTrue(rec.ast_ok, msg=f"{rec.record_id}: {rec.ast_errors}")
      self.assertIn("team", rec.query.lower())

  def test_structural_warning_detector_flags_known_multikey_and_resource_quirks(self) -> None:
    circadian_warnings = [
        r for r in self.records
        if any("CIRCADIAN_STAGE1_BUCKET_MISMATCH" in w for w in r.structural_warnings)
    ]
    resource_warnings = [
        r for r in self.records
        if any("RESOURCE_ENTITY_ROOT_KEY_MISMATCH" in w for w in r.structural_warnings)
    ]
    redirect_warnings = [
        r for r in self.records
        if any("RESOURCE_USER_MODEL_REDIRECT" in w for w in r.structural_warnings)
    ]
    # WS2-01: Multi-key extractors now expand composite keys and rewrite CIRCADIAN_VON_MISES Stage 1 to `by 1h`.
    self.assertEqual(len(circadian_warnings), 0)
    # WS2-01: EntityType.RESOURCE across all 18 models and both modes now preserves $resource in Root match:.
    self.assertEqual(len(resource_warnings), 0)
    # WS2-06: build_query no longer redirects non-Z models on (resource_*, EntityType.USER) to CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH.
    self.assertEqual(len(redirect_warnings), 0)


class TestCoveringLiveCompileSuite(unittest.TestCase):
  """Verifies covering live-compile suite coverage, deduplication, and `<= 1h` window."""

  def test_covering_suite_covers_all_extractors_models_modes_and_pipelines(self) -> None:
    suite = build_covering_compile_suite()
    self.assertGreater(len(suite), 100)
    self.assertLess(len(suite), 200)

    all_tags: set[str] = set()
    for item in suite:
      all_tags.update(item.coverage_tags)
      self.assertEqual(item.start_time, DEFAULT_COMPILE_START_TIME)
      self.assertEqual(item.end_time, DEFAULT_COMPILE_END_TIME)
      self.assertNotIn("{{", item.query, msg=item.query_id)
      self.assertEqual(MalachiteASTValidator.validate_query(item.query), [], msg=item.query_id)

    for metric_name, mdef in METRIC_CATALOG.items():
      self.assertIn(f"extractor:{metric_name}", all_tags)
      for et in mdef.supported_entity_types:
        self.assertIn(f"extractor_entity:{metric_name}:{et.value}", all_tags)

    for model in active_statistical_models():
      self.assertIn(f"model:{model.value}", all_tags)
      for mode in MatchMode:
        self.assertIn(f"model_mode:{model.value}:{mode.value}", all_tags)

    for disk_path in (TEMPLATES_DIR / "pipelines").glob("*.yl2"):
      self.assertIn(f"pipeline:{disk_path.name}", all_tags)

    self.assertIn("pipeline_variant:part_of_the_whole_multilevel.yl2#named_cohort", all_tags)
    self.assertIn("pipeline_variant:part_of_the_whole_triad_multilevel.yl2#named_cohort", all_tags)

  def test_compile_window_validator_rejects_oversized_or_inverted_windows(self) -> None:
    validate_compile_window("2026-10-27T14:00:00Z", "2026-10-27T15:00:00Z")
    with self.assertRaises(ValueError):
      validate_compile_window("2026-10-27T14:00:00Z", "2026-10-27T16:00:00Z")
    with self.assertRaises(ValueError):
      validate_compile_window("2026-10-27T15:00:00Z", "2026-10-27T14:00:00Z")


class TestPF10AndPF11ProbeGenerators(unittest.TestCase):
  """Verifies PF-10 `(1h, today)` and PF-11 `first_seen` probe generation for all 38 metrics."""

  def test_pf10_hourly_today_probes_cover_all_38_metrics_and_validate(self) -> None:
    probes = build_pf10_hourly_today_probes()
    self.assertEqual(len(probes), 38)
    self.assertEqual({p.metric_name for p in probes}, set(METRIC_CATALOG.keys()))

    ip_fallback_count = 0
    for probe in probes:
      self.assertEqual(probe.start_time, DEFAULT_PF10_START_TIME)
      self.assertEqual(probe.end_time, DEFAULT_PF10_END_TIME)
      # PF-10b: every (1h, today) probe MUST include a companion (1d, 30d) anchor lookup.
      self.assertIs(probe.metadata.get("anchored_with_d30_companion"), True)
      self.assertIn("period: 1d, window: 30d", probe.query)
      self.assertIn("$d30_periods = max(metrics.", probe.query)
      self.assertIn("$d30_periods = max($stage1_extract.d30_periods)", probe.query)
      self.assertIn("period: 1h, window: today", probe.query)
      self.assertIn("agg: sum", probe.query)
      self.assertIn("agg: num_metric_periods", probe.query)
      expected_arg = mc.baseline_semantics(probe.metric_name).metric_arg
      self.assertIn(f"metric: {expected_arg}", probe.query)
      self.assertEqual(MalachiteASTValidator.validate_query(probe.query), [], msg=probe.query_id)
      if probe.fallback_query is not None:
        ip_fallback_count += 1
        self.assertIn("period: 1d, window: 30d", probe.fallback_query)
        self.assertIn("$d30_periods = max($stage1_extract.d30_periods)", probe.fallback_query)
        self.assertIn("principal.asset.ip: principal.asset.ip", probe.fallback_query)
        self.assertEqual(MalachiteASTValidator.validate_query(probe.fallback_query), [], msg=probe.query_id)

    self.assertEqual(ip_fallback_count, len(NETWORK_IP_FALLBACK_METRICS))

  def test_pf10_window_validator_enforces_post_midnight_and_4h_cap_rule(self) -> None:
    validate_pf10_window("2026-10-27T14:00:00Z", "2026-10-27T19:00:00Z")
    # Starts at 00:00Z -> no earlier-today hours exist -> must reject.
    with self.assertRaises(ValueError):
      validate_pf10_window("2026-10-27T00:00:00Z", "2026-10-27T06:00:00Z")
    # Less than 4 hours between start hour and end -> must reject.
    with self.assertRaises(ValueError):
      validate_pf10_window("2026-10-27T14:00:00Z", "2026-10-27T17:00:00Z")
    # Crosses UTC day boundary -> must reject.
    with self.assertRaises(ValueError):
      validate_pf10_window("2026-10-27T21:00:00Z", "2026-10-28T02:00:00Z")

  def test_pf11_first_seen_probes_cover_all_38_metrics(self) -> None:
    probes = build_pf11_first_seen_probes()
    self.assertEqual(len(probes), 38)
    self.assertEqual({p.metric_name for p in probes}, set(METRIC_CATALOG.keys()))

    ip_fallback_count = 0
    for probe in probes:
      self.assertEqual(probe.start_time, DEFAULT_PF11_START_TIME)
      self.assertEqual(probe.end_time, DEFAULT_PF11_END_TIME)
      self.assertIn("period: 1d, window: 30d, metric: first_seen, agg: min", probe.query)
      self.assertIn("period: 1d, window: 30d, metric: last_seen, agg: max", probe.query)
      if probe.fallback_query is not None:
        ip_fallback_count += 1
        self.assertIn("principal.asset.ip: principal.asset.ip", probe.fallback_query)

    self.assertEqual(ip_fallback_count, len(NETWORK_IP_FALLBACK_METRICS))

    combined = build_all_probes()
    self.assertEqual(len(combined), 76)


class TestManifestIOAndMockSearchExecution(unittest.TestCase):
  """Verifies JSON manifest round-trip and `run_manifest` execution with injectable `search_fn`."""

  def test_manifest_export_load_and_mock_search_execution(self) -> None:
    pf10 = build_pf10_hourly_today_probes()
    pf11 = build_pf11_first_seen_probes()
    sample = [
        next(p for p in pf10 if p.metric_name == "auth_attempts_total"),
        next(p for p in pf10 if p.metric_name == "dns_queries_total"),
        next(p for p in pf11 if p.metric_name == "auth_attempts_total"),
        build_covering_compile_suite()[0],
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
      manifest_path = Path(tmpdir) / "sample_manifest.json"
      export_manifest(sample, manifest_path, manifest_name="unit_test_manifest")
      loaded = load_manifest(manifest_path)
      self.assertEqual(len(loaded), 4)
      self.assertEqual([q.query_id for q in loaded], [q.query_id for q in sample])

      calls: list[tuple[str, str, str]] = []

      def mock_search(query: str, start_time: str, end_time: str) -> Any:
        calls.append((query, start_time, end_time))
        if "metrics.auth_attempts_total" in query and "window: today" in query:
          return _stats_payload({
              "entity": [("stringVal", "charles.hardy")],
              "hourly_periods": [("int64Val", "14")],
              "hourly_sum": [("doubleVal", 339.0)],
          })
        if "metrics.dns_queries_total" in query:
          # Simulate PF-9 on gus-sdl: hostname returns empty, IP fallback returns rows.
          if "principal.asset.hostname" in query:
            return {}
          return _stats_payload({
              "entity": [("stringVal", "10.1.2.3")],
              "hourly_periods": [("int64Val", "8")],
              "hourly_sum": [("doubleVal", 120.0)],
          })
        if "metric: first_seen" in query:
          return _stats_payload({
              "entity": [("stringVal", "charles.hardy")],
              "first_seen": [("int64Val", "1760000000")],
              "last_seen": [("int64Val", "1761500000")],
          })
        # Simulate compile failure on the 4th item.
        return {"error": "INVALID_ARGUMENT: parsing: syntax error near line 12"}

      results = run_manifest(loaded, mock_search, try_fallback_on_zero_rows=True)
      self.assertEqual(len(results), 4)
      # 5 calls total because dns_queries_total retried on principal.asset.ip fallback.
      self.assertEqual(len(calls), 5)

      self.assertTrue(results[0].compiled)
      self.assertEqual(results[0].row_count, 1)
      self.assertIs(results[0].has_nonzero_probe_data, True)
      self.assertFalse(results[0].used_fallback_query)

      self.assertTrue(results[1].compiled)
      self.assertEqual(results[1].row_count, 1)
      self.assertIs(results[1].has_nonzero_probe_data, True)
      self.assertTrue(results[1].used_fallback_query)

      self.assertTrue(results[2].compiled)
      self.assertEqual(results[2].row_count, 1)
      self.assertIs(results[2].has_nonzero_probe_data, True)
      self.assertEqual(results[2].sample_row["first_seen"], 1760000000)

      self.assertFalse(results[3].compiled)
      self.assertIn("INVALID_ARGUMENT", results[3].error or "")

      results_path = Path(tmpdir) / "results.json"
      export_execution_results(results, results_path)
      self.assertTrue(results_path.exists())
      rehydrated = LiveExecutionResult.from_dict(results[0].to_dict())
      self.assertEqual(rehydrated.query_id, results[0].query_id)

  def test_raw_event_dump_is_flagged_as_non_stats_error(self) -> None:
    item = build_covering_compile_suite()[0]
    results = run_manifest(
        [item],
        lambda _q, _s, _e: {"events": [{"udm": {"metadata": {"id": "1"}}}]},
    )
    self.assertFalse(results[0].compiled)
    self.assertIn("RAW_LOG_DUMP_DETECTED", results[0].error or "")


class TestRecordedGusSdlBaselineArtifact(unittest.TestCase):
  """Verifies the recorded WS0-03 `baseline_gus_sdl.json` live baseline snapshot."""

  def test_baseline_gus_sdl_json_schema_and_coverage(self) -> None:
    baseline_path = Path(__file__).resolve().parent / "baseline_gus_sdl.json"
    self.assertTrue(baseline_path.exists(), msg=f"Missing baseline artifact: {baseline_path}")
    doc = json.loads(baseline_path.read_text(encoding="utf-8"))

    self.assertEqual(doc["metadata"]["item_id"], "WS0-03")
    self.assertEqual(doc["metadata"]["skill"], "secops-risk-metrics-multistage")
    self.assertEqual(doc["metadata"]["project_id"], "gus-sdl")
    self.assertEqual(doc["metadata"]["evidence_tag"], "V-live")

    # Offline matrix summary checks.
    matrix_sum = doc["offline_matrix_summary"]
    self.assertEqual(matrix_sum["matrix_cell_count"], 2592)
    self.assertEqual(matrix_sum["pipeline_count"], 34)
    self.assertEqual(matrix_sum["render_crash_count"], 0)
    self.assertEqual(matrix_sum["ast_error_record_count"], 0)

    # Covering live compile suite checks (134 queries: 133 compiled, 1 %ueba_hunt_bridge env prereq).
    comp = doc["covering_compile_suite"]
    self.assertEqual(comp["total_queries"], 134)
    self.assertEqual(comp["compile_ok_count"], 133)
    self.assertEqual(comp["unexpected_compile_failure_count"], 0)
    self.assertEqual(comp["env_prerequisite_failure_count"], 1)
    self.assertEqual(len(comp["results"]), 134)
    self.assertEqual(
        [f["query_id"] for f in comp["failed_queries"]],
        ["compile_pipeline::hybrid_data_table_bridge_2stage.yl2"],
    )

    # PF-10 & PF-11 live probes checks (76 probes: 38 PF-10 + 38 PF-11, 76/76 compiled).
    probes = doc["pf10_pf11_probes"]
    self.assertEqual(probes["summary_counts"]["total_manifest_probes"], 76)
    self.assertEqual(probes["summary_counts"]["compiled_count"], 76)
    self.assertEqual(probes["summary_counts"]["compile_failure_count"], 0)
    self.assertEqual(probes["pf10b_platform_constraint"]["id"], "PF-10b")
    self.assertEqual(len(probes["by_metric_summary"]), 38)
    self.assertEqual(len(probes["results"]), 76)

    # §8 macro baseline reproductions (8a, 8b, 8c).
    sec8 = doc["section_8_macro_baselines"]["summary"]
    self.assertTrue(sec8["case_8a_reproduced"])
    self.assertTrue(sec8["case_8b_reproduced"])
    self.assertTrue(sec8["case_8c_reproduced"])


@unittest.skipUnless(
    os.environ.get("SECOPS_LIVE_TESTS") == "1",
    "Opt-in live Chronicle compile tests require SECOPS_LIVE_TESTS=1",
)
class TestLiveChronicleCompileGate(unittest.TestCase):
  """Opt-in live execution harness (configure `LIVE_SEARCH_FN` before running)."""

  LIVE_SEARCH_FN: Optional[Callable[[str, str, str], Any]] = None

  def test_live_compile_and_probe_suites(self) -> None:
    if self.LIVE_SEARCH_FN is None:
      self.skipTest(
          "SECOPS_LIVE_TESTS=1 is set, but TestLiveChronicleCompileGate.LIVE_SEARCH_FN "
          "was not injected; supply a sequential udm_search callable to execute against gus-sdl."
      )
    has_bridge_table = os.environ.get("SECOPS_HAS_UEBA_HUNT_BRIDGE") == "1"
    suite = build_covering_compile_suite()
    compile_results = run_manifest(suite, self.LIVE_SEARCH_FN)
    unexpected_failures = [
        r
        for r in compile_results
        if not r.compiled and (has_bridge_table or not r.metadata.get("requires_data_table"))
    ]
    self.assertEqual(
        unexpected_failures,
        [],
        msg=f"Unexpected live compile failures: {[f.to_dict() for f in unexpected_failures]}",
    )

    probes = build_all_probes()
    probe_results = run_manifest(probes, self.LIVE_SEARCH_FN, try_fallback_on_zero_rows=True)
    probe_failures = [r for r in probe_results if not r.compiled]
    self.assertEqual(
        probe_failures,
        [],
        msg=f"Live PF-10/PF-11 probe compile failures: {[f.to_dict() for f in probe_failures]}",
    )


if __name__ == "__main__":
  unittest.main()
