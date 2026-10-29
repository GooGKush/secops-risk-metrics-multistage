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
    self.assertIn("**Latest Version**: v2.3.0", first_lines)
    self.assertIn("What's New in v2.3.0", self.release_text)
    self.assertIn("version-v2.3.0-blue.svg", self.readme_text)
    self.assertIn("### v2.3.0", self.readme_text)

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
