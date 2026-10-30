"""WS7-03 regression tests for multi-sector correlation disclosure and sqrt(2 ln N) labeling.

Verifies:
1. `SKILL.md`, `references/360-behavioral-radar-guide.md`,
   `references/multi-stage-metrics-guide.md`,
   `references/statistical-models-taxonomy.md`,
   `references/calibrated-risk-index-guide.md`, and
   `references/metric-sector-catalog.md` all disclose that multi-sector fusion
   false-positive rates depend on inter-sector correlation.
2. Fleet / multiplicity scaling `sqrt(2 ln N)` / `sqrt(2 * ln(K))` is explicitly
   labeled as an approximation of the expected maximum (Gaussian extreme value),
   NOT a Bonferroni correction, across `SKILL.md`, the fusion/taxonomy/CRI guides,
   and `rollup_sector_fusion_4stage.yl2` / `rollup_sector_fusion_5stage.yl2` headers.
3. No file in the repo mislabels `sqrt(2 ln N)` as a Bonferroni correction.
"""

from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestWS703FusionCorrelationAndExpectedMaxLabel(unittest.TestCase):
  """WS7-03 documentation and template header contract tests."""

  def test_fusion_docs_disclose_inter_sector_correlation_effect_on_fp_rate(self) -> None:
    targets = (
        REPO_ROOT / "SKILL.md",
        REPO_ROOT / "references" / "360-behavioral-radar-guide.md",
        REPO_ROOT / "references" / "multi-stage-metrics-guide.md",
        REPO_ROOT / "references" / "statistical-models-taxonomy.md",
        REPO_ROOT / "references" / "calibrated-risk-index-guide.md",
        REPO_ROOT / "references" / "metric-sector-catalog.md",
    )
    corr_rx = re.compile(r"(?i)(?:inter-sector|sector)s?.{0,40}?correlat|correlat.{0,40}?sectors?")
    fp_rx = re.compile(r"(?i)false[- ]positive|FP\s+rate|tail\s+(?:rate|probabilit)")
    for path in targets:
      rel = path.relative_to(REPO_ROOT)
      text = path.read_text(encoding="utf-8")
      with self.subTest(file=str(rel)):
        self.assertRegex(
            text,
            corr_rx,
            f"{rel} must state that fusion false-positive rates depend on sector correlation",
        )
        self.assertRegex(
            text,
            fp_rx,
            f"{rel} must link sector correlation to false-positive / tail rates",
        )

  def test_sqrt_2_ln_n_labeled_as_expected_maximum_not_bonferroni(self) -> None:
    targets = (
        REPO_ROOT / "SKILL.md",
        REPO_ROOT / "references" / "multi-stage-metrics-guide.md",
        REPO_ROOT / "references" / "statistical-models-taxonomy.md",
        REPO_ROOT / "references" / "calibrated-risk-index-guide.md",
        REPO_ROOT / "templates" / "pipelines" / "rollup_sector_fusion_4stage.yl2",
        REPO_ROOT / "templates" / "pipelines" / "rollup_sector_fusion_5stage.yl2",
    )
    expected_max_rx = re.compile(r"(?i)expected\s+max(?:imum)?")
    not_bonferroni_rx = re.compile(r"(?i)not\s+(?:a\s+)?bonferroni")
    for path in targets:
      rel = path.relative_to(REPO_ROOT)
      text = path.read_text(encoding="utf-8")
      with self.subTest(file=str(rel)):
        self.assertRegex(
            text,
            expected_max_rx,
            f"{rel} must label sqrt(2 ln N) / sqrt(2 ln K) as an approximation of the expected maximum",
        )
        self.assertRegex(
            text,
            not_bonferroni_rx,
            f"{rel} must clarify that sqrt(2 ln N) / sqrt(2 ln K) is not a Bonferroni correction",
        )

  def test_no_file_calls_sqrt_2_ln_a_bonferroni_correction(self) -> None:
    bad_rx = re.compile(
        r"(?i)bonferroni\s*(?:correction|threshold|offset|adjustment)?\s*(?:is|=|:|\()\s*[^\n]{0,30}?(?:sqrt|\\sqrt)\s*[\(\{]\s*2",
    )
    scan_paths = [REPO_ROOT / "SKILL.md", REPO_ROOT / "README.md"]
    scan_paths.extend(sorted((REPO_ROOT / "references").rglob("*.md")))
    scan_paths.extend(sorted((REPO_ROOT / "templates").rglob("*.yl2")))
    offenders: list[str] = []
    for path in scan_paths:
      rel = path.relative_to(REPO_ROOT)
      for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if bad_rx.search(line):
          offenders.append(f"{rel}:{lineno}: {line.strip()}")
    self.assertEqual([], offenders, f"Mislabeling sqrt(2 ln N) as Bonferroni found: {offenders}")


if __name__ == "__main__":
  unittest.main()
