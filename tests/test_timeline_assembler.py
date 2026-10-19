"""Unit tests for the Mode C per-day baseline timeline collator."""

import contextlib
import io
import json
import math
import os
import sys
import tempfile
import unittest

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_DIR not in sys.path:
  sys.path.insert(0, REPO_DIR)

from scripts import timeline_assembler as ta


def _stats(columns):
  """Builds a udm_search stats payload from {column: [python values]}."""
  results = []
  for name, values in columns.items():
    cells = []
    for v in values:
      if isinstance(v, str):
        cells.append({"value": {"stringVal": v}})
      elif isinstance(v, float):
        cells.append({"value": {"doubleVal": v}})
      else:
        cells.append({"value": {"int64Val": str(v)}})
    results.append({"column": name, "values": cells})
  return {"stats": {"results": results}}


def _fusion_rows(entity, norm_sq, z_a, z_b, a_obs=10, a_days=30.0):
  return {
      "entity": entity, "composite_threat_norm_sq": norm_sq, "z_a": z_a, "z_b": z_b,
      "z_a_sq": z_a * z_a, "dz_a_raw": 0.0, "a_observed": a_obs, "a_active_days": a_days,
  }


class TestParsing(unittest.TestCase):

  def test_empty_payloads_are_clean_shards(self):
    self.assertEqual([], ta.parse_stats_payload({}))
    self.assertEqual([], ta.parse_stats_payload({"stats": {}}))
    columns_only = {"stats": {"results": [{"column": "entity"}, {"column": "z"}], "hasJoin": True}}
    self.assertEqual([], ta.parse_stats_payload(columns_only))

  def test_raw_events_are_rejected(self):
    with self.assertRaisesRegex(ValueError, "RAW_LOG_DUMP_DETECTED"):
      ta.parse_stats_payload({"events": [{"name": "e1"}]})

  def test_value_types(self):
    payload = {"stats": {"results": [
        {"column": "entity", "values": [{"value": {"stringVal": "h1"}}]},
        {"column": "bytes", "values": [{"value": {"uint64Val": "42"}}]},
        {"column": "z", "values": [{"value": {"doubleVal": 3.5}}]},
    ]}}
    self.assertEqual([{"entity": "h1", "bytes": 42, "z": 3.5}], ta.parse_stats_payload(payload))

  def test_shard_spec_file_and_inline(self):
    payload = _stats({"entity": ["h1"], "z": [4.0]})
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
      json.dump(payload, f)
      path = f.name
    try:
      day, rows = ta.load_shard_spec(f"2026-10-01={path}")
      self.assertEqual(("2026-10-01", 1), (day, len(rows)))
      day, rows = ta.load_shard_spec("2026-10-02=" + json.dumps(payload))
      self.assertEqual(("2026-10-02", 1), (day, len(rows)))
    finally:
      os.unlink(path)

  def test_bad_day_rejected(self):
    with self.assertRaises(ValueError):
      ta.load_shard_spec("10/01/2026={}")


class TestAssembly(unittest.TestCase):

  def test_squared_norm_is_square_rooted(self):
    asm = ta.TimelineAssembler()
    asm.add_shard("2026-10-01", [_fusion_rows("h1", 157.93450932856814, 0.0, 9.39)])
    summary = asm.build()
    self.assertTrue(summary["meta"]["score_is_sqrt_of_field"])
    self.assertAlmostEqual(12.57, summary["top"][0]["score"], places=2)
    self.assertEqual(ta.cri_from_score(math.sqrt(157.93450932856814)), summary["top"][0]["cri"])

  def test_cri_anchor(self):
    self.assertEqual(50, ta.cri_from_score(3.0))
    self.assertEqual(ta.cri_from_score(0.0), ta.cri_from_score(-5.0))

  def test_persistence_onset_and_escalation(self):
    asm = ta.TimelineAssembler()
    asm.add_shard("2026-10-05", [{"entity": "svc", "z": 3.0, "z_a": 3.0}])
    asm.add_shard("2026-10-06", [{"entity": "svc", "z": 5.3, "z_a": 5.3}])
    asm.add_shard("2026-10-07", [{"entity": "svc", "z": 15.0, "z_a": 15.0}])
    asm.add_shard("2026-10-08", [{"entity": "svc", "z": 15.0, "z_a": 15.0}])
    e = asm.build()["entities"]["svc"]
    self.assertEqual(4, e["days_flagged"])
    self.assertEqual(4, e["longest_run"])
    self.assertTrue(e["escalating"])
    self.assertEqual("2026-10-07", e["peak_day"])
    self.assertEqual({"z_a": "2026-10-05"}, e["sector_onsets"])

  def test_gap_breaks_run_and_escalation(self):
    asm = ta.TimelineAssembler()
    asm.add_shard("2026-10-01", [{"entity": "h", "z": 3.0}])
    asm.add_shard("2026-10-02", [{"entity": "h", "z": 4.0}])
    asm.add_shard("2026-10-04", [{"entity": "h", "z": 5.0}])
    asm.add_shard("2026-10-03", [])
    e = asm.build()["entities"]["h"]
    self.assertEqual(2, e["longest_run"])
    self.assertFalse(e["escalating"])

  def test_failed_and_missing_days_are_reported_not_filled(self):
    asm = ta.TimelineAssembler()
    asm.add_shard("2026-10-01", [{"entity": "h", "z": 4.0}])
    asm.add_failed("2026-10-02", "RESOURCE_EXHAUSTED")
    asm.add_shard("2026-10-04", [])
    summary = asm.build()
    self.assertEqual(["2026-10-02"], summary["meta"]["failed_days"])
    self.assertEqual(["2026-10-03"], summary["meta"]["missing_days"])
    statuses = {d["day"]: d["status"] for d in summary["days"]}
    self.assertEqual({"2026-10-01": "ok", "2026-10-02": "failed", "2026-10-04": "empty"}, statuses)
    md = ta.TimelineAssembler.render_markdown(summary)
    self.assertIn("Failed shards (reported, not filled): 2026-10-02", md)
    self.assertIn("no shard supplied: 2026-10-03", md)

  def test_duplicate_day_rejected(self):
    asm = ta.TimelineAssembler()
    asm.add_shard("2026-10-01", [])
    with self.assertRaises(ValueError):
      asm.add_failed("2026-10-01")

  def test_peak_per_entity_day_when_rows_repeat(self):
    asm = ta.TimelineAssembler()
    asm.add_shard("2026-10-01", [{"entity": "h", "z": 4.0}, {"entity": "h", "z": 9.0}])
    summary = asm.build()
    self.assertEqual(1, summary["days"][0]["outliers"])
    self.assertEqual(9.0, summary["entities"]["h"]["peak_score"])

  def test_sparse_baseline_list(self):
    asm = ta.TimelineAssembler(min_baseline_days=5)
    asm.add_shard("2026-10-10", [
        _fusion_rows("new-host", 1000.0, 0.0, 30.0, a_obs=876, a_days=1.0),
        _fusion_rows("old-host", 1000.0, 9.4, 30.0, a_obs=267, a_days=29.0),
    ])
    sparse = asm.build()["sparse_baseline"]
    self.assertEqual(1, len(sparse))
    self.assertEqual(("new-host", "a", 876, 1), (
        sparse[0]["entity"], sparse[0]["sector"], sparse[0]["observed"], sparse[0]["baseline_days"]))

  def test_sector_fields_exclude_derived_columns(self):
    asm = ta.TimelineAssembler()
    asm.add_shard("2026-10-01", [_fusion_rows("h1", 100.0, 1.0, 9.0)])
    self.assertEqual(["z_a", "z_b"], asm.build()["meta"]["sector_fields"])

  def test_unresolvable_columns_raise(self):
    asm = ta.TimelineAssembler()
    asm.add_shard("2026-10-01", [{"count": 3}])
    with self.assertRaises(ValueError):
      asm.build()

  def test_all_empty_is_nominal(self):
    asm = ta.TimelineAssembler()
    asm.add_shard("2026-10-01", [])
    asm.add_shard("2026-10-02", [])
    md = ta.TimelineAssembler.render_markdown(asm.build())
    self.assertIn("No outliers in any completed shard", md)

  def test_auto_detects_template_score_columns(self):
    for col, val, is_sq, expected in (
        ("personal_z", 4.0, False, 4.0),
        ("beacon_score", 5.5, False, 5.5),
        ("shielded_z", 3.2, False, 3.2),
        ("threat_distance_sq", 25.0, True, 5.0),
        ("d_vs_fleet_sq", 16.0, True, 4.0),
    ):
      asm = ta.TimelineAssembler()
      asm.add_shard("2026-10-01", [{"host": "h1", col: val}])
      summary = asm.build()
      self.assertEqual(col, summary["meta"]["score_field"])
      self.assertEqual(is_sq, summary["meta"]["score_is_sqrt_of_field"])
      self.assertAlmostEqual(expected, summary["top"][0]["score"], places=2)

  def test_multi_sector_360_radar_shards_merge_into_euclidean_d(self):
    asm = ta.TimelineAssembler()
    # Day 1: Cloud CRUD spike (z=11.49) and minor Workspace activity (z=0.21); other 4 sectors skipped (0 events)
    asm.add_shard("2026-08-29:cloud", [{"user": "admin", "z": 11.49}])
    asm.add_shard("2026-08-29:workspace", [{"user": "admin", "z": 0.21}])
    # Day 2: Empty shard
    asm.add_shard("2026-08-30:cloud", [])
    summary = asm.build()
    expected_d = round(math.sqrt(11.49 ** 2 + 0.21 ** 2), 2)
    self.assertEqual(["z_cloud", "z_workspace"], summary["meta"]["sector_fields"])
    self.assertEqual(expected_d, summary["entities"]["admin"]["peak_score"])
    self.assertEqual("2026-08-29", summary["entities"]["admin"]["peak_day"])
    self.assertEqual({"z_cloud": "2026-08-29", "z_workspace": "2026-08-29"},
                     summary["entities"]["admin"]["sector_onsets"])
    statuses = {d["day"]: d["status"] for d in summary["days"]}
    self.assertEqual({"2026-08-29": "ok", "2026-08-30": "empty"}, statuses)

  def test_duplicate_sector_shard_rejected(self):
    asm = ta.TimelineAssembler()
    asm.add_shard("2026-08-29:cloud", [])
    with self.assertRaises(ValueError):
      asm.add_shard("2026-08-29:cloud", [])


class TestCli(unittest.TestCase):

  def test_cli_writes_outputs(self):
    payload = _stats({"entity": ["h1", "h2"], "composite_threat_norm_sq": [400.0, 16.0],
                      "z_a": [20.0, 0.0], "z_b": [0.0, 4.0]})
    with tempfile.TemporaryDirectory() as tmp:
      shard = os.path.join(tmp, "shard_2026-10-07.json")
      with open(shard, "w", encoding="utf-8") as f:
        json.dump(payload, f)
      md, js, html = (os.path.join(tmp, n) for n in ("t.md", "t.json", "t.html"))
      with contextlib.redirect_stdout(io.StringIO()):
        rc = ta.main(["--shard", f"2026-10-07={shard}", "--failed", "2026-10-08",
                      "--markdown-out", md, "--json-out", js, "--html-out", html])
      self.assertEqual(0, rc)
      with open(js, encoding="utf-8") as f:
        summary = json.load(f)
      self.assertEqual(20.0, summary["entities"]["h1"]["peak_score"])
      with open(html, encoding="utf-8") as f:
        html_text = f.read()
      self.assertIn("h1 (2026-10-07)", html_text)
      self.assertIn("2 days, 2026-10-07 → 2026-10-08", html_text)

  def test_cli_rejects_raw_events(self):
    with contextlib.redirect_stderr(io.StringIO()):
      rc = ta.main(["--shard", "2026-10-07=" + json.dumps({"events": [{"name": "x"}]})])
    self.assertEqual(2, rc)


if __name__ == "__main__":
  unittest.main()
