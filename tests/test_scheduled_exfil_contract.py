# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Contract tests for the Scheduled Exfiltration two-answer rule in SKILL.md (REG-P1-07)."""

from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestScheduledExfiltrationContract(unittest.TestCase):
  """Ensures SKILL.md defines a dedicated, non-contradictory Scheduled Exfiltration rule."""

  def setUp(self) -> None:
    super().setUp()
    self.skill_md = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    self.lines = self.skill_md.splitlines()

  def test_dedicated_scheduled_exfiltration_bullet_offers_two_answers_and_executes(self) -> None:
    sched_bullets = [
        ln for ln in self.lines if re.match(r"^\*\s+\*\*Scheduled Exfiltration\b", ln)
    ]
    self.assertEqual(
        len(sched_bullets),
        1,
        "SKILL.md must have a dedicated '* **Scheduled Exfiltration...' bullet near the routing table.",
    )
    bullet = sched_bullets[0]

    # (a) Zero-code Skill Handoff Card to secops-statistical-hunter for sub-day cron / jitter cadence
    self.assertIn("Skill Handoff Card", bullet)
    self.assertIn("secops-statistical-hunter", bullet)
    self.assertRegex(bullet, r"(?i)no query|zero-code")
    self.assertRegex(bullet, r"(?i)sub-day.*cron|cron.*jitter")

    # (b) In-skill Longitudinal CUSUM Drift pointing to series template + helper
    self.assertIn("Longitudinal CUSUM Drift", bullet)
    self.assertIn("templates/pipelines/longitudinal_cusum_series_3stage.yl2", bullet)
    self.assertIn("scripts/cusum_helper.py", bullet)

    # Executes (b) here on "run it" or clearance and renders the 5-section report
    self.assertRegex(bullet, r'(?i)"run it"|run it')
    self.assertIn("clearance", bullet.lower())
    self.assertIn("udm_search", bullet)
    self.assertRegex(bullet, r"#### 1\.|5-pillar|5-section")

  def test_routing_table_and_steering_mandate_cross_reference_scheduled_exfiltration(self) -> None:
    prec1_lines = [
        ln for ln in self.lines if "| **1. `secops-statistical-hunter`**" in ln
    ]
    self.assertEqual(len(prec1_lines), 1)
    prec1 = prec1_lines[0]
    self.assertNotIn(
        "sub-second/cron timing;",
        prec1,
        "Precedence 1 row must not route unqualified 'cron timing' to handoff-only.",
    )
    self.assertIn("sub-day cron", prec1)
    self.assertIn("Scheduled Exfiltration", prec1)

    steering_lines = [
        ln
        for ln in self.lines
        if ln.startswith("* **Non-Metrics Telemetry Steering Mandate")
    ]
    self.assertEqual(len(steering_lines), 1)
    steering = steering_lines[0]
    self.assertNotIn(
        "sub-second jitter, cron cadence)",
        steering,
        "Steering mandate must qualify sub-day cron cadence and cross-reference Scheduled Exfiltration.",
    )
    self.assertIn("sub-day cron", steering)
    self.assertIn("Scheduled Exfiltration", steering)


if __name__ == "__main__":
  unittest.main()
