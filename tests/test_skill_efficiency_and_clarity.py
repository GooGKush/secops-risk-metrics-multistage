"""Unit tests verifying structural clarity, token budget efficiency, and referential integrity of SKILL.md.

Author: Greg Kushmerek
"""

import os
import re
import unittest


class TestSkillEfficiencyAndClarity(unittest.TestCase):

  def setUp(self):
    self.skill_md_path = '/usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/SKILL.md'
    self.skill_dir = os.path.dirname(self.skill_md_path)
    self.assertTrue(os.path.exists(self.skill_md_path), "SKILL.md must exist")
    with open(self.skill_md_path, 'r', encoding='utf-8') as f:
      self.skill_content = f.read()
    self.lines = self.skill_content.splitlines()

  def test_token_budget_and_line_count_ceiling(self):
    """SKILL.md must remain lean (<= 250 lines and <= 20 KB) to prevent instruction bloat."""
    line_count = len(self.lines)
    file_size_kb = len(self.skill_content.encode('utf-8')) / 1024.0
    self.assertLessEqual(
        line_count, 250,
        f"SKILL.md exceeds the 250-line ceiling (found {line_count} lines). Move reference tables to references/."
    )
    self.assertLessEqual(
        file_size_kb, 20.0,
        f"SKILL.md exceeds the 20 KB ceiling (found {file_size_kb:.1f} KB)."
    )

  def test_referential_link_integrity(self):
    """Every reference document, template directory, and script referenced in SKILL.md must exist on disk."""
    file_links = re.findall(
        r'file:///usr/local/google/home/kushmerek/\.gemini/skills/secops-risk-metrics-multistage/([a-zA-Z0-9_\-\./]+)',
        self.skill_content
    )
    backtick_links = re.findall(
        r'`((?:references|templates|scripts)/[a-zA-Z0-9_\-\./]+)`',
        self.skill_content
    )
    all_links = set(file_links + backtick_links)
    self.assertGreater(len(all_links), 0, "SKILL.md must contain progressive disclosure references.")

    missing_paths = []
    for rel_path in all_links:
      clean = rel_path.rstrip('/')
      full_path = os.path.join(self.skill_dir, clean)
      if not os.path.exists(full_path):
        missing_paths.append(clean)

    self.assertEqual(
        len(missing_paths), 0,
        f"SKILL.md contains broken or missing referential paths: {missing_paths}"
    )

  def test_zero_contradiction_and_forbidden_phrases(self):
    """SKILL.md must contain zero ambiguous or forbidden simulation fallback phrases."""
    forbidden_phrases = [
        "fall back to python",
        "calculate locally in scratch",
        "simulate with python",
        "ad-hoc single-day moving average as ueba",
    ]
    content_lower = self.skill_content.lower()
    for phrase in forbidden_phrases:
      self.assertNotIn(
          phrase, content_lower,
          f"SKILL.md contains forbidden/contradictory phrase: '{phrase}'"
      )

  def test_step1_preflight_gate_hierarchy(self):
    """SKILL.md must define the essential sub-requirements of Step 1 Pre-Flight Gate."""
    self.assertIn("MANDATORY STEP 1: PRE-FLIGHT CLEARANCE", self.skill_content)
    self.assertIn("Turn 1 Tool Invariant", self.skill_content)
    self.assertIn("PRE-FLIGHT HUNTING SPECIFICATION", self.skill_content)
    self.assertIn("Explicit Clearance Question & Turn Termination", self.skill_content)

  def test_step2_six_pillars_hierarchy(self):
    """SKILL.md must define all 6 required pillars of the Step 2 triage report."""
    self.assertIn("MANDATORY STEP 2: PRESENT FULL 6-SECTION REPORT", self.skill_content)
    self.assertIn("Statistical Outlier Report", self.skill_content)
    self.assertIn("Executed Multi-Stage YARA-L Query", self.skill_content)
    self.assertIn("Ranked Outlier Summary", self.skill_content)
    self.assertIn("Forensic Vector Breakdown", self.skill_content)
    self.assertIn("Immediate 1-Click", self.skill_content)
    self.assertIn("Statistical & Mathematical Appendix", self.skill_content)


if __name__ == '__main__':
  unittest.main()
