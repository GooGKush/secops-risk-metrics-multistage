"""WS9 Rule 10 tests verifying v2.3.0 release notes, version parity, and active README tree.

Verifies:
- `RELEASE_NOTES.md` and `README.md` both carry `v2.3.0` as the latest release.
- The `v2.3.0` section in `RELEASE_NOTES.md` documents the cross-review remediation
  items (`WS0`–`WS9` and `D1`, `D3`–`D10`), backward-compatible retired-model
  aliases, and frozen `D7` write-back interface.
- Active sections of `README.md` (before `## 📦 Recent Releases`) reference zero
  deleted/retired `.yl2` files and list `cusum_helper.py`, `ueba_constants.py`,
  `first_seen_novelty.yl2`, `first_seen_novelty_2stage.yl2`, and
  `longitudinal_cusum_series_3stage.yl2`.
"""

from pathlib import Path
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
RELEASE_NOTES = REPO_ROOT / "RELEASE_NOTES.md"
README_MD = REPO_ROOT / "README.md"


class TestWS9ReleaseNotesV230(unittest.TestCase):
  """Rule 10 release-notes and version-bump parity checks for v2.3.0."""

  def setUp(self) -> None:
    self.release_text = RELEASE_NOTES.read_text(encoding="utf-8")
    self.readme_text = README_MD.read_text(encoding="utf-8")

  def test_latest_version_is_v2_3_0_in_release_notes_and_readme(self) -> None:
    first_lines = "\n".join(self.release_text.splitlines()[:15])
    self.assertIn("(v2.3.0)", first_lines)
    self.assertIn("**Latest Version**: v2.3.0 (Major Point Release) — October 30, 2026", first_lines)
    self.assertIn("What's New in v2.3.0", self.release_text)
    self.assertIn("version-v2.3.0-blue.svg", self.readme_text)
    self.assertIn("unit%20tests-642%2F642%20passing", self.readme_text)
    self.assertIn("### v2.3.0", self.readme_text)
    from scripts import template_router
    self.assertEqual(template_router.__version__, "2.3.0")

  def test_v2_3_0_release_notes_cover_design_decisions_and_workstreams(self) -> None:
    # Slice the v2.3.0 section (before What's New in v2.2.0).
    v230_section = self.release_text.split("## 📢 What's New in v2.2.0", 1)[0]
    required_ids = (
        "D1",
        "D3",
        "D4",
        "D5",
        "D6",
        "D7",
        "D8",
        "D9",
        "D10",
        "WS1-01",
        "WS1-04",
        "WS1-05",
        "WS1-10",
        "WS1-11",
        "WS1-12",
        "WS1-13",
        "WS2-01",
        "WS6-01",
        "WS7-01",
        "WS7-02",
        "WS7-03",
        "WS8-02",
        "WS8-03",
        "WS9-01",
        "WS9-07",
    )
    for item_id in required_ids:
      with self.subTest(item_id=item_id):
        self.assertIn(item_id, v230_section, f"Missing {item_id} in v2.3.0 RELEASE_NOTES.md section")

  def test_v2_3_0_docs_match_d3_d8_d9_ws1_13_and_final_counts(self) -> None:
    v230_section = self.release_text.split("## 📢 What's New in v2.2.0", 1)[0]
    for forbidden in ("2–5 days", "Mode B `5d`", "Mode B 5d", "elapsed_hours / 24.0", "1048576.0", "634/634"):
      with self.subTest(forbidden=forbidden):
        self.assertNotIn(forbidden, v230_section, f"Stale claim {forbidden!r} in v2.3.0 RELEASE_NOTES.md")
    for required in ("642/642 offline unit tests", "54 test modules", "templates/radar_360/", "Scheduled Exfiltration", "04:00Z"):
      with self.subTest(required=required):
        self.assertIn(required, v230_section, f"Missing {required!r} in v2.3.0 RELEASE_NOTES.md")

    active_readme = self.readme_text.split("### v2.2.0", 1)[0]
    for forbidden in (
        "Mode B 5d cap",
        "Mode B `5d` Cap",
        "capped Mode B at 5 days",
        "2–5 days",
        "capped at 5 days",
        "elapsed-hours opt-in",
        "elapsed-hours-scaled",
        "impossible travel velocity",
        "math.geo_distance",
        "48 test modules",
        "37 Stage 1 extractor",
        "634/634",
        "634 / 634",
    ):
      with self.subTest(forbidden_readme=forbidden):
        self.assertNotIn(forbidden, active_readme, f"Stale claim {forbidden!r} in active/v2.3.0 README.md")

  def test_readme_directory_tree_matches_disk_artifacts(self) -> None:
    """Every active template, reference, script, and test module on disk is represented accurately in README.md tree."""
    import re
    tree_start = self.readme_text.index("```\nsecops-risk-metrics-multistage/")
    tree_end = self.readme_text.index("```", tree_start + 4)
    tree_block = self.readme_text[tree_start:tree_end]

    # Exact Stage 1 extractor count
    s1_files = sorted((REPO_ROOT / "templates" / "stage1_extractors").glob("*.yl2"))
    self.assertEqual(len(s1_files), 38)
    self.assertIn("38 Stage 1 extractor templates", tree_block)

    # Every pipeline (34), radar_360 (6), stage2_math_model (14), reference (25), script (18), and test module (54) + live/
    expected_basenames = []
    for sub in ("templates/pipelines", "templates/radar_360", "templates/stage2_math_models"):
      expected_basenames.extend(p.name for p in sorted((REPO_ROOT / sub).glob("*.yl2")))
    expected_basenames.extend(p.name for p in sorted((REPO_ROOT / "references").glob("*.md")))
    expected_basenames.extend(p.name for p in sorted((REPO_ROOT / "references" / "consultative").glob("*.md")))
    expected_basenames.extend(p.name for p in sorted((REPO_ROOT / "scripts").glob("*.py")))
    test_modules = sorted((REPO_ROOT / "tests").glob("test_*.py"))
    self.assertEqual(len(test_modules), 54)
    expected_basenames.extend(p.name for p in test_modules)
    expected_basenames.extend(["baseline_gus_sdl.json", "live_compile_harness.py", "test_live_compile_matrix.py"])

    for name in expected_basenames:
      with self.subTest(expected_in_tree=name):
        self.assertIn(name, tree_block, f"README.md directory tree missing {name}")

    # Verify llms.txt references only real pipeline files and current D3/D9 window defaults
    llms_txt = (REPO_ROOT / "llms.txt").read_text(encoding="utf-8")
    for tpl_rel in re.findall(r"templates/pipelines/[a-zA-Z0-9_]+\.yl2", llms_txt):
      self.assertTrue((REPO_ROOT / tpl_rel).exists(), f"llms.txt references missing {tpl_rel}")
    self.assertNotIn("Mode B 2–7d", llms_txt)
    self.assertNotIn("Fixed-Baseline Mode B (2–7d)", llms_txt)

  def test_active_readme_tree_and_tables_reflect_d1_and_new_artifacts(self) -> None:
    active_readme = self.readme_text.split("## 📦 Recent Releases", 1)[0]
    retired_files = (
        "asymmetric_directional_z.yl2",
        "circadian_von_mises.yl2",
        "circadian_von_mises_2stage.yl2",
        "fleet_prevalence_shield.yl2",
        "hourly_temporal_zscore.yl2",
        "piecewise_cri.yl2",
        "hybrid_metric_orthogonal_space_2stage.yl2",
        "IMPOSSIBLE_TRAVEL_GEO_VELOCITY",
    )
    for retired in retired_files:
      with self.subTest(retired=retired):
        self.assertNotIn(retired, active_readme, f"Active README.md still lists retired {retired}")

    new_artifacts = (
        "first_seen_novelty.yl2",
        "first_seen_novelty_2stage.yl2",
        "longitudinal_cusum_series_3stage.yl2",
        "cusum_helper.py",
        "ueba_constants.py",
    )
    for artifact in new_artifacts:
      with self.subTest(artifact=artifact):
        self.assertIn(artifact, active_readme, f"Active README.md missing {artifact}")


if __name__ == "__main__":
  unittest.main()
