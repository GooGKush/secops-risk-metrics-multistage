# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""WS9-01: Concordance tests enforcing one unified Page CUSUM & Windowed Slack Sum story.

Verifies that SKILL.md, references/timeline-modes-guide.md, references/model-concordance-guide.md,
templates/pipelines/longitudinal_cusum_2stage.yl2, templates/pipelines/longitudinal_cusum_series_3stage.yl2,
and templates/stage2_math_models/longitudinal_cusum.yl2 all document the exact WS6-01 architecture:
  1. Mode A blocked (single-day CUSUM raises an error).
  2. Windowed Slack Sum W = sum(max(0, z_t - 0.5)) lossless prefilter (S_t <= W).
  3. <= 14 days: longitudinal_cusum_series_3stage.yl2 + scripts/cusum_helper.py
     (quiet-day 0-event reconstruction, ARL-calibrated h = 4.0 / 5.0 / 3.0).
  4. > 14 days: ungated candidate Mode C shards re-standardized against Shard 1's
     fixed calendar-day baseline (rebuild_calendar_day_stats) with reset controls.
"""

from pathlib import Path
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _header_comments(path: Path) -> str:
  lines = []
  for ln in path.read_text(encoding="utf-8").splitlines():
    stripped = ln.strip()
    if stripped.startswith("//") or stripped == "":
      lines.append(ln)
    else:
      break
  return "\n".join(lines)


class TestWS901UnifiedCusumStory(unittest.TestCase):
  """Asserts zero drift across all CUSUM documentation and template headers."""

  def test_skill_md_states_unified_cusum_architecture(self):
    skill_md = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    self.assertIn("Mode A blocked", skill_md)
    self.assertIn("Windowed Slack Sum", skill_md)
    self.assertIn("longitudinal_cusum_series_3stage.yl2", skill_md)
    self.assertIn("scripts/cusum_helper.py", skill_md)
    self.assertIn("Shard 1", skill_md)

  def test_timeline_modes_guide_distinguishes_le14d_vs_gt14d_cusum(self):
    guide = (REPO_ROOT / "references" / "timeline-modes-guide.md").read_text(
        encoding="utf-8"
    )
    self.assertNotIn("is never split into Mode C shards", guide)
    self.assertIn("Mode A", guide)
    self.assertIn("Windowed Slack Sum", guide)
    self.assertIn("longitudinal_cusum_series_3stage.yl2", guide)
    self.assertIn("scripts/cusum_helper.py", guide)
    self.assertIn("calculate_page_cusum_series", guide)
    self.assertIn("rebuild_calendar_day_stats", guide)
    self.assertIn("--reset-on", guide)
    self.assertIn("--reset-after-alarm", guide)
    self.assertIn("--reset-every-days", guide)
    self.assertIn("336", guide)
    self.assertIn("930", guide)

  def test_template_headers_point_to_cusum_helper_not_timeline_assembler(self):
    tpl_paths = [
        REPO_ROOT / "templates" / "pipelines" / "longitudinal_cusum_2stage.yl2",
        REPO_ROOT / "templates" / "pipelines" / "longitudinal_cusum_series_3stage.yl2",
        REPO_ROOT / "templates" / "stage2_math_models" / "longitudinal_cusum.yl2",
    ]
    for path in tpl_paths:
      with self.subTest(template=path.name):
        header = _header_comments(path)
        self.assertNotIn(
            "timeline_assembler.py",
            header,
            f"Stale timeline_assembler.py reference in {path.name} header",
        )
        self.assertIn("cusum_helper.py", header)
        self.assertIn("Windowed Slack Sum", header)
        self.assertIn("Mode A", header)
        self.assertIn("Shard 1", header)

  def test_model_concordance_guide_cusum_section_matches_ws6_01(self):
    guide = (REPO_ROOT / "references" / "model-concordance-guide.md").read_text(
        encoding="utf-8"
    )
    start = guide.index("### 9. `LONGITUDINAL_CUSUM`")
    end = guide.index("### 10. `TWO_PART_HURDLE`")
    section = guide[start:end]

    self.assertNotIn("timeline_assembler.py", section)
    self.assertIn("Mode A", section)
    self.assertIn("Windowed Slack Sum", section)
    self.assertIn("longitudinal_cusum_series_3stage.yl2", section)
    self.assertIn("scripts/cusum_helper.py", section)
    self.assertIn("calculate_page_cusum_series", section)
    self.assertIn("rebuild_calendar_day_stats", section)
    self.assertIn("--reset-on", section)
    self.assertIn("--reset-after-alarm", section)
    self.assertIn("--reset-every-days", section)
    self.assertIn("336", section)
    self.assertIn("930", section)


if __name__ == "__main__":
  unittest.main()
