"""Every YARA-L example in SKILL.md and references/ stays inside compiler limits.

Chronicle rejects a stage whose outcome: block defines more than 20 variables
("Request contains an invalid argument"). Agents copy these examples verbatim:
on 2026-10-29 the 360 radar guide's cloud_risk example carried 28 outcome
variables (4 CRUD families x 7) and both 360 regression tests (REG-P0-03,
REG-P1-12) failed live compilation with exactly those variable names.
"""

from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
MAX_OUTCOME_VARIABLES = 20

_FENCE = re.compile(r"```(?:yara|yara-l|yaral)?[^\n]*\n(.*?)```", re.DOTALL)
_OUTCOME = re.compile(r"\n\s*outcome:\s*\n")
_BLOCK_END = re.compile(r"\n\s*(?:condition|order|limit|options|match):|\n\s*\}")
_ASSIGNMENT = re.compile(r"^\s*\$\w+\s*=", re.MULTILINE)


def _doc_files():
  yield REPO_ROOT / "SKILL.md"
  yield from sorted((REPO_ROOT / "references").rglob("*.md"))


def outcome_block_sizes(markdown: str):
  """Yields (line_number, variable_count) for every outcome: block in YARA-L fences."""
  for fence in _FENCE.finditer(markdown):
    line = markdown[: fence.start()].count("\n") + 1
    for block in _OUTCOME.split(fence.group(1))[1:]:
      body = _BLOCK_END.split(block, maxsplit=1)[0]
      yield line, len(_ASSIGNMENT.findall(body))


class DocExampleOutcomeLimitTest(unittest.TestCase):

  def test_counter_sees_a_28_variable_block(self):
    body = "\n".join(f"    $v{i} = count(metadata.id)" for i in range(28))
    doc = f"```yara\nstage s {{\n  match:\n    $u by 1d\n  outcome:\n{body}\n}}\n```\n"
    self.assertEqual(list(outcome_block_sizes(doc)), [(1, 28)])

  def test_no_doc_example_exceeds_the_outcome_limit(self):
    breaches = [
        f"{path.relative_to(REPO_ROOT)}: fence at line {line} has {count} outcome variables"
        for path in _doc_files()
        for line, count in outcome_block_sizes(path.read_text(encoding="utf-8"))
        if count > MAX_OUTCOME_VARIABLES
    ]
    self.assertEqual(breaches, [], f"Chronicle allows at most {MAX_OUTCOME_VARIABLES} per stage")


if __name__ == "__main__":
  unittest.main()
