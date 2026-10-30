"""WS9-04, WS9-05, and WS9-06 progressive-loading & platform-fact contract tests.

Verifies:
- WS9-04: SKILL.md allow-lists all vetted repository helpers (including
  `scripts/cusum_helper.py`) and states D6 guardrails G1-G5.
- WS9-05: SKILL.md states PF-1 (active-day `agg: avg` vs `/ 30` calendar-day rate),
  PF-2 (sample SD `N-1`, Samuelson `(N-1)/sqrt(N)`, `$active_days >= 7` + floors),
  and PF-10 (two valid `(period, window)` pairs `(1d, 30d)` and `(1h, today)`),
  and aligns D9 mode limits & D10 sustained-attack fade caveat with
  `references/timeline-modes-guide.md`.
- WS9-06: `references/multi-stage-metrics-guide.md` §3 documents the exact two valid
  `(period, window)` pairs, what `window: today` covers (`endTime - 4h` cap),
  cites `tests/live/baseline_gus_sdl.json` (`23/38` and `21/38`), documents
  `first_seen_novelty_2stage.yl2` + `first_seen`/`last_seen`/`period_start_for_max`/
  `period_start_for_min`/`num_unique_filter_values`, records the `(1h, today)`
  template decision, and omits `validatePeriodAndWindow`.
"""

from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_MD = REPO_ROOT / "SKILL.md"
TIMELINE_GUIDE = REPO_ROOT / "references" / "timeline-modes-guide.md"
METRICS_GUIDE = REPO_ROOT / "references" / "multi-stage-metrics-guide.md"


class TestWS904D6HelperAllowListAndGuardrails(unittest.TestCase):
  """WS9-04: SKILL.md Native Execution Guarantee includes full allow-list + G1-G5."""

  def setUp(self) -> None:
    self.skill_text = SKILL_MD.read_text(encoding="utf-8")

  def test_skill_md_allowlists_all_vetted_repository_helpers(self) -> None:
    expected_helpers = (
        "scripts/ueba_hybrid_engine.py",
        "scripts/radar_collector.py",
        "scripts/chart_generator.py",
        "scripts/triage_formatter.py",
        "scripts/timeline_assembler.py",
        "scripts/cusum_helper.py",
        "scripts/chronicle_ingest.py",
    )
    # Locate the Native Execution Guarantee bullet specifically.
    m = re.search(
        r"\*\s+\*\*Native Execution Guarantee.*?(?=\n\*\s+\*\*|\n###\s+|\Z)",
        self.skill_text,
        flags=re.DOTALL,
    )
    self.assertIsNotNone(m, "Native Execution Guarantee bullet missing from SKILL.md")
    bullet = m.group(0)
    for helper in expected_helpers:
      with self.subTest(helper=helper):
        self.assertIn(
            helper,
            bullet,
            f"Vetted helper {helper} missing from SKILL.md Native Execution Guarantee allow-list",
        )
        self.assertTrue((REPO_ROOT / helper).is_file(), f"Missing helper file {helper}")

  def test_skill_md_states_d6_guardrails_g1_through_g5(self) -> None:
    m = re.search(
        r"\*\s+\*\*Native Execution Guarantee.*?(?=\n\*\s+\*\*|\n###\s+|\Z)",
        self.skill_text,
        flags=re.DOTALL,
    )
    self.assertIsNotNone(m)
    bullet = m.group(0)
    for label in ("G1", "G2", "G3", "G4", "G5"):
      with self.subTest(guardrail=label):
        self.assertRegex(
            bullet,
            rf"\b{label}\b",
            f"D6 guardrail {label} missing from SKILL.md Native Execution Guarantee",
        )
    # G1: raw udm_search payload only, never LLM-typed numbers
    self.assertRegex(bullet, r"raw\s+`?udm_search`?")
    self.assertRegex(bullet, r"(?i)never.*typed\s+by\s+the\s+LLM|never.*LLM-typed")
    # G2: fail closed on missing/malformed input
    self.assertRegex(bullet, r"(?i)fail\s+closed")
    # G3: query/payload hash + helper version in appendix
    self.assertRegex(bullet, r"(?i)hash|SHA-256")
    self.assertRegex(bullet, r"(?i)helper\s+version|version")
    # G4: golden-tested offline
    self.assertRegex(bullet, r"(?i)offline")
    # G5: honest fallback phrasing without run_command
    self.assertIn("this model needs a client that can run local scripts", bullet)


class TestWS905PlatformFactsAndModeConcordance(unittest.TestCase):
  """WS9-05: SKILL.md states PF-1, PF-2, PF-10 and matches D9/D10 in timeline-modes-guide.md."""

  def setUp(self) -> None:
    self.skill_text = SKILL_MD.read_text(encoding="utf-8")
    self.modes_text = TIMELINE_GUIDE.read_text(encoding="utf-8")

  def test_skill_md_states_pf1_active_day_avg_vs_calendar_rate(self) -> None:
    self.assertIn("PF-1", self.skill_text)
    self.assertIn("num_metric_periods", self.skill_text)
    self.assertRegex(
        self.skill_text,
        r"historical_sum\s*/\s*30",
        "SKILL.md must state PF-1 calendar-day rate reconstruction via historical_sum / 30",
    )

  def test_skill_md_states_pf2_sample_sd_maturity_and_floors(self) -> None:
    self.assertIn("PF-2", self.skill_text)
    self.assertRegex(self.skill_text, r"sample\s+SD|\bN\s*[-−]\s*1\b")
    self.assertIn("$active_days >= 7", self.skill_text)
    self.assertRegex(self.skill_text, r"sqrt\(max\(avg,\s*1\)\)|math\.sqrt")

  def test_skill_md_states_pf10_two_valid_period_window_pairs(self) -> None:
    self.assertIn("PF-10", self.skill_text)
    self.assertRegex(self.skill_text, r"\(1d,\s*30d\)|period:\s*1d,\s*window:\s*30d")
    self.assertRegex(self.skill_text, r"\(1h,\s*today\)|period:\s*1h,\s*window:\s*today")
    self.assertIn("HOUR_OF_DAY_PROFILE", self.skill_text)

  def test_d9_and_d10_concordance_between_skill_md_and_timeline_guide(self) -> None:
    for doc_name, text in (("SKILL.md", self.skill_text), ("timeline-modes-guide.md", self.modes_text)):
      with self.subTest(doc=doc_name):
        # D9: Mode B capped at 3 days; Mode C up to 30 days paced in batches of <=10
        self.assertRegex(text, r"(?i)2[–-]3\s*days?")
        self.assertRegex(text, r"(?i)30\s*days?")
        self.assertRegex(text, r"10")
        # D10: sustained-attack fade (+3sigma -> ~2.5sigma day 2; +6sigma ~3 days; no guard band; CUSUM)
        self.assertRegex(text, r"2\.5\s*σ")
        self.assertRegex(text, r"(?i)no\s+guard\s+band")
        self.assertIn("LONGITUDINAL_CUSUM", text)


class TestWS906MultiStageMetricsGuidePF10PF11(unittest.TestCase):
  """WS9-06: multi-stage-metrics-guide.md §3 documents PF-10, PF-10b, PF-11, and baseline_gus_sdl.json."""

  def setUp(self) -> None:
    self.guide_text = METRICS_GUIDE.read_text(encoding="utf-8")

  def test_guide_documents_exact_two_pairs_today_bounds_and_live_table(self) -> None:
    self.assertNotIn("validatePeriodAndWindow", self.guide_text)
    self.assertRegex(
        self.guide_text,
        r"exactly\s+two\s+`?\(period,\s*window\)`?\s+pairs",
        "Guide §3 must explicitly state that Malachite accepts exactly two (period, window) pairs",
    )
    # Must describe what `window: today` covers: end of the 30d window to query start hour, capped 4h before endTime
    self.assertRegex(
        self.guide_text,
        r"end\s+of\s+the\s+30-day.*start.*hour|\[end_of_30d_window,\s*start_hour\)",
    )
    self.assertRegex(
        self.guide_text,
        r"4\s*hours?\s+before\s+`?endTime`?|endTime\s*[-−]\s*4h",
    )
    # Must cite WS0-03 live probe baseline artifact
    self.assertIn("tests/live/baseline_gus_sdl.json", self.guide_text)
    self.assertIn("23/38", self.guide_text)
    self.assertIn("21/38", self.guide_text)
    # Must document all PF-11 metrics/aggs + first_seen_novelty_2stage.yl2 + template decision
    for token in (
        "first_seen",
        "last_seen",
        "period_start_for_max",
        "period_start_for_min",
        "num_unique_filter_values",
        "first_seen_novelty_2stage.yl2",
        "--intraday-hourly",
    ):
      with self.subTest(token=token):
        self.assertIn(token, self.guide_text)


if __name__ == "__main__":
  unittest.main()
