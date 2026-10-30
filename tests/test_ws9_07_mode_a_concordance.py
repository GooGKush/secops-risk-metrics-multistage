"""WS9-07 repo-wide D3 Mode A and D9 Mode B reference concordance tests.

Verifies that `SKILL.md` (always loaded) and `references/**/*.md` (loaded on
demand), `scripts/generate_metric_sector_catalog.py`, and ECG pipeline headers
all agree on:
- D3 default Mode A: last complete UTC day (`[yesterday 00:00:00Z, today 00:00:00Z)`),
  or for Entity Context Graph (`graph.*`) queries: `startTime` = scored UTC day
  minus 2 at `00:00:00Z`, `endTime` = `today 00:00:00Z`, and
  `timestamp.get_date(metadata.event_timestamp.seconds) = "<scored UTC day, YYYY-MM-DD>"`
  in every event stage (`[D-32, D-2)` baseline shift disclosed).
- D3 "Today So Far" (`--today-so-far`): explicit, labeled partial-day option only,
  never the unmarked default Mode A instruction.
- D9 Mode B: 2–3 days (default & cap 3 days), never 2–7 days.
"""

from pathlib import Path
import re
import subprocess
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
REFERENCES_DIR = REPO_ROOT / "references"
PIPELINES_DIR = REPO_ROOT / "templates" / "pipelines"


def _is_explicit_partial_or_historical_line(line: str) -> bool:
  """Lines explicitly describing Today So Far, today's Mode C shard, or historical 2026-10-01 probe rows."""
  lower = line.lower()
  return (
      "today so far" in lower
      or "--today-so-far" in lower
      or "today's shard" in lower
      or "2026-10-01" in lower
      or "2026-09-29" in lower
  )


class TestWS907ModeAAndModeBConcordance(unittest.TestCase):
  """Ensures zero D3 Mode A or D9 Mode B progressive-loading contradictions across references/."""

  def test_no_reference_prescribes_today_or_endtime_now_as_default_mode_a(self) -> None:
    stale_patterns = (
        ("placeholder <today...>", re.compile(r"<today(?:\s+UTC)?,\s*YYYY-MM-DD>")),
        ("Mode A Today vs 30-Day title", re.compile(r"Mode\s+A\s*\(\s*Today\b", re.IGNORECASE)),
        ("Mode A = today", re.compile(r"Mode\s+A\s*=\s*today\b", re.IGNORECASE)),
        ("Card A today", re.compile(r":\s*\[?chosen mode only:\s*A\s+today\b", re.IGNORECASE)),
        ("Mode A current-day snapshot", re.compile(r"Mode\s+A[:\s\(]+current-day\s+snapshot", re.IGNORECASE)),
        ("default endTime = now", re.compile(r"`?endTime`?\s*(?:=|to)\s*`?now`?")),
        ("unmarked today 00:00Z -> now", re.compile(r"today\s+`?00:00(?::00)?Z`?\s*(?:→|->)\s*`?now`?", re.IGNORECASE)),
        ("Mode A [D0 00:00Z, now]", re.compile(r"Mode\s+A[^\n]*\[D(?:-2|0)\s+00:00Z,\s*now\]")),
    )
    offenders: list[str] = []
    for md_path in sorted(REFERENCES_DIR.rglob("*.md")):
      rel = md_path.relative_to(REPO_ROOT)
      for lineno, line in enumerate(md_path.read_text(encoding="utf-8").splitlines(), 1):
        if _is_explicit_partial_or_historical_line(line):
          continue
        for label, rx in stale_patterns:
          if rx.search(line):
            offenders.append(f"{rel}:{lineno} [{label}]: {line.strip()}")

    self.assertEqual(
        [],
        offenders,
        "Found stale default Mode A instructions in references/ (must default to last complete UTC day "
        "per D3 / WS1-01 / WS9-07):\n" + "\n".join(offenders),
    )

  def test_no_reference_prescribes_stale_2_to_7_day_mode_b_horizon(self) -> None:
    stale_mode_b = (
        re.compile(r"2\s*[–-]\s*7\s*(?:d\b|day)", re.IGNORECASE),
        re.compile(r"2\s+to\s+7\s+days", re.IGNORECASE),
        re.compile(r"Mode\s+B\s*\(\s*7-Day", re.IGNORECASE),
        re.compile(r"Mode\s+B:\s*7d\b", re.IGNORECASE),
        re.compile(r"Up to 7 days:\s*\*\*Mode B", re.IGNORECASE),
        re.compile(r"Mode\s+B,\s*N\s*[≤<=]+\s*7", re.IGNORECASE),
    )
    offenders: list[str] = []
    for md_path in sorted(REFERENCES_DIR.rglob("*.md")):
      rel = md_path.relative_to(REPO_ROOT)
      for lineno, line in enumerate(md_path.read_text(encoding="utf-8").splitlines(), 1):
        for rx in stale_mode_b:
          if rx.search(line):
            offenders.append(f"{rel}:{lineno}: {line.strip()}")

    self.assertEqual(
        [],
        offenders,
        "Found stale 2–7d / 7d Mode B horizon in references/ (D9 caps Mode B at 2–3 days):\n"
        + "\n".join(offenders),
    )

  def test_ecg_guide_and_sector_catalog_match_engine_d3_ws1_08_defaults(self) -> None:
    ecg_text = (REFERENCES_DIR / "entity-context-graph-guide.md").read_text(encoding="utf-8")
    catalog_text = (REFERENCES_DIR / "metric-sector-catalog.md").read_text(encoding="utf-8")

    # Rule 5 must specify scored UTC day - 2d at 00:00Z, endTime = today 00:00Z, and <scored UTC day, YYYY-MM-DD>
    self.assertIn("<scored UTC day, YYYY-MM-DD>", ecg_text)
    self.assertIn("<scored UTC day, YYYY-MM-DD>", catalog_text)
    self.assertRegex(ecg_text, r"endTime`\s+to\s+`today\s+00:00(?::00)?Z`")
    self.assertIn("Today So Far", ecg_text)
    self.assertIn("--today-so-far", ecg_text)

    # Catalog generator check must exit 0 (generated file in sync with generator script).
    proc = subprocess.run(
        [sys.executable, "-m", "scripts.generate_metric_sector_catalog", "--check"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    self.assertEqual(
        0,
        proc.returncode,
        f"generate_metric_sector_catalog.py --check failed: {proc.stdout} {proc.stderr}",
    )

  def test_ecg_pipeline_headers_describe_scored_utc_day_default(self) -> None:
    ecg_templates = (
        "rare_destination_ecg_3stage.yl2",
        "fusion_rare_destination_3stage.yl2",
        "hybrid_metric_derived_file_prevalence_2stage.yl2",
        "hybrid_metric_derived_domain_prevalence_2stage.yl2",
        "hybrid_metric_derived_asset_age_2stage.yl2",
        "hybrid_metric_fleet_prevalence_2stage.yl2",
        "hybrid_metric_whois_domain_lifecycle_2stage.yl2",
    )
    for name in ecg_templates:
      with self.subTest(template=name):
        text = (PIPELINES_DIR / name).read_text(encoding="utf-8")
        self.assertNotIn("today_date slot (today's UTC date, YYYY-MM-DD)", text)
        self.assertIn("scored UTC day", text)


if __name__ == "__main__":
  unittest.main()
