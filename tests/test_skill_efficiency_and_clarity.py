"""Unit tests verifying structural clarity, token budget efficiency, and referential integrity of SKILL.md.

Author: Greg Kushmerek
"""

import os
import re
import unittest


class TestSkillEfficiencyAndClarity(unittest.TestCase):

  def setUp(self):
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    self.skill_md_path = os.path.join(repo_dir, "SKILL.md")
    self.skill_dir = repo_dir
    self.assertTrue(os.path.exists(self.skill_md_path), "SKILL.md must exist in repository")
    with open(self.skill_md_path, "r", encoding="utf-8") as f:
      self.skill_content = f.read()
    self.lines = self.skill_content.splitlines()

  def test_token_budget_and_line_count_ceiling(self):
    """SKILL.md must remain lean (<= 275 lines and <= 28.0 KB / 28,672 bytes) to prevent instruction bloat."""
    line_count = len(self.lines)
    raw_bytes = len(self.skill_content.encode("utf-8"))
    file_size_kb = raw_bytes / 1024.0
    self.assertLessEqual(
        line_count, 275,
        f"SKILL.md exceeds the 275-line ceiling (found {line_count} lines). Move reference tables to references/."
    )
    self.assertLessEqual(
        raw_bytes, 28672,
        f"SKILL.md exceeds the 28.0 KB (28,672 bytes) ceiling (found {raw_bytes} bytes / {file_size_kb:.1f} KB)."
    )
    self.assertLessEqual(
        file_size_kb, 28.0,
        f"SKILL.md exceeds the 28.0 KB ceiling (found {file_size_kb:.1f} KB)."
    )

  def test_frontmatter_description_length_and_triggers(self):
    """YAML frontmatter description must be <= 1,024 characters and contain key routing triggers."""
    m = re.match(r"^---\n(.*?)\n---", self.skill_content, re.DOTALL)
    self.assertIsNotNone(m, "SKILL.md must start with YAML frontmatter")
    fm = m.group(1)
    desc_match = re.search(r"^description:\s*(.+)$", fm, re.MULTILINE)
    self.assertIsNotNone(desc_match, "YAML frontmatter must include description")
    desc = desc_match.group(1).strip().strip("\"'")
    self.assertLessEqual(
        len(desc), 1024,
        f"Frontmatter description exceeds 1,024 character Agent Skills spec limit: {len(desc)}"
    )
    for trigger in (
        "peer cohort comparison",
        "360° entity health check",
        "CUSUM drift",
        "entity risk score",
        "30-day behavioral baseline",
        "30d-baseline MAD",
    ):
      self.assertIn(trigger, desc, f"Frontmatter description missing trigger: {trigger}")

  def test_referential_link_integrity(self):
    """Every reference document, template directory, and script referenced in SKILL.md must exist on disk."""
    file_links = re.findall(
        r"file:///[^`\s]+?/\.gemini/(?:config/)?skills/secops-risk-metrics-multistage/([a-zA-Z0-9_\-\./]+)",
        self.skill_content
    )
    backtick_links = re.findall(
        r"`((?:references|templates|scripts)/[a-zA-Z0-9_\-\./]+)`",
        self.skill_content
    )
    all_links = set(file_links + backtick_links)
    self.assertGreater(len(all_links), 0, "SKILL.md must contain progressive disclosure references.")

    missing_paths = []
    for rel_path in all_links:
      clean = rel_path.rstrip("/")
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
    self.assertTrue("MANDATORY STEP 1: PRE-FLIGHT CLEARANCE" in self.skill_content or "State 1: Pre-Flight Clearance" in self.skill_content)
    self.assertIn("Turn 1 Tool Invariant", self.skill_content)
    self.assertIn("PRE-FLIGHT HUNTING SPECIFICATION", self.skill_content)
    self.assertIn("Clearance Question (final sentence of Turn 1, then yield)", self.skill_content)

  def test_step2_six_pillars_hierarchy(self):
    """SKILL.md must define all 5 required pillars of the Step 2 triage report (without redundant Executed Query block)."""
    self.assertTrue("MANDATORY STEP 2: PRESENT FULL 5-SECTION REPORT" in self.skill_content or "State 2: Deterministic Multi-Stage Execution" in self.skill_content)
    self.assertIn("Statistical Outlier Report", self.skill_content)
    self.assertIn("Executive Summary & Calibrated Risk Index (CRI)", self.skill_content)
    self.assertNotIn("Executed Multi-Stage YARA-L Query", self.skill_content)
    self.assertIn("Ranked Outlier Summary", self.skill_content)
    self.assertIn("Forensic Vector Breakdown", self.skill_content)
    self.assertIn("Chronicle UI Manual Pivot", self.skill_content)
    self.assertIn("Statistical & Mathematical Appendix", self.skill_content)


if __name__ == "__main__":
  unittest.main()
