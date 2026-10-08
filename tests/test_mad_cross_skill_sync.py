"""Cross-skill sync guard: the MAD math must stay identical in both skills.

secops-risk-metrics-multistage (templates/stage2_math_models/mad.yl2) uses MAD as a robustness
cross-check next to the 30d metrics.* baseline; secops-statistical-hunter
(templates/pipelines/mad_modified_z_4stage.yl2) runs standalone MAD on raw telemetry. Variable names
differ, the math must not. Skips when the sibling repo is not checked out next to this one.
"""

from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent.parent
PROJECTS = HERE.parent
MAD_TEMPLATES = {
    "secops-risk-metrics-multistage": "templates/stage2_math_models/mad.yl2",
    "secops-statistical-hunter": "templates/pipelines/mad_modified_z_4stage.yl2",
}


def _code(text: str) -> str:
  return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("//"))


def mad_signature(text: str) -> dict:
  """Name-independent fingerprint of the MAD computation."""
  code = _code(text)
  return {
      "median_calls_ignore_zero_false": [c.strip().endswith("false") for c in re.findall(r"window\.median\((.*)\)", code)],
      "mad_is_median_of_abs_dev": bool(re.search(r"window\.median\(math\.abs\([^)]*-[^)]*\),\s*false\)", code)),
      "mean_abs_dev_fallback": bool(re.search(r"avg\(math\.abs\([^)]*-[^)]*\)\)", code)),
      "scale_from_mad": bool(re.search(r"\$scale_from_mad = \$\w+ / 0\.6745", code)),
      "scale_from_meanad": bool(re.search(r"\$scale_from_meanad = \$\w+ \* 1\.253314", code)),
      "robust_scale_switch": bool(re.search(r"\$robust_scale = if\(\$\w+ > 0, \$scale_from_mad, \$scale_from_meanad\)", code)),
      "safe_scale_guard": bool(re.search(r"\$safe_robust_scale = if\(\$robust_scale > 0, \$robust_scale, ", code)),
      "modified_z_over_safe_scale": bool(re.search(r"= \(\$\w+ - \$\w+\) / \$safe_robust_scale", code)),
  }


class TestMadCrossSkillSync(unittest.TestCase):

  def test_mad_math_identical_across_skills(self):
    paths = {name: PROJECTS / name / rel for name, rel in MAD_TEMPLATES.items()}
    missing = [str(p) for p in paths.values() if not p.exists()]
    if missing:
      self.skipTest(f"sibling skill not checked out: {missing}")
    sigs = {name: mad_signature(p.read_text()) for name, p in paths.items()}
    for name, sig in sigs.items():
      self.assertEqual(sig["median_calls_ignore_zero_false"], [True, True], f"{name}: {sig}")
      for key, value in sig.items():
        if key != "median_calls_ignore_zero_false":
          self.assertTrue(value, f"{name}: MAD signature element '{key}' missing")
    a, b = sigs.values()
    self.assertEqual(a, b, "MAD math drifted between skills")


class MadRoutingInDescriptions(unittest.TestCase):
  """The skill-selection surface (frontmatter description) must state the MAD split for every user.

  risk-metrics: 30d-baseline MAD on metric-catalog vectors. statistical-hunter: standalone MAD over raw
  fields or custom windows. Each description names the other skill for the other half.
  """

  def _description(self, skill: str) -> str:
    path = PROJECTS / skill / "SKILL.md"
    if not path.exists():
      self.skipTest(f"{skill} not checked out next to this repo")
    import yaml  # pylint: disable=g-import-not-at-top
    front = path.read_text(encoding="utf-8").split("---")[1]
    return " ".join(str(yaml.safe_load(front)["description"]).split())

  def test_risk_metrics_description_claims_metrics_vector_mad(self):
    d = self._description("secops-risk-metrics-multistage")
    self.assertIn("MAD on metric-catalog vectors", d)
    self.assertIn("secops-statistical-hunter", d)

  def test_hunter_description_scopes_mad_to_raw_fields(self):
    d = self._description("secops-statistical-hunter")
    self.assertIn("standalone Median Absolute Deviation (MAD) over raw fields or custom windows", d)
    self.assertIn("secops-risk-metrics-multistage", d)


if __name__ == "__main__":
  unittest.main()
