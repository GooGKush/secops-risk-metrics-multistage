"""Validates every YARA-L block in the documentation corpus against the AST validator.

The skill already validates queries it *generates* (MalachiteASTValidator, used by
the pre-flight path). Nothing validated the queries it *documents*. That gap is how
a rootless sector query survived in references/360-behavioral-radar-guide.md: the
agent mirrors documented query shapes, so a malformed example is a latent defect.

Two symmetric guards:

  1. Every unmarked ```yara block must be free of STRUCTURAL_CODES errors.
  2. Every block carrying a <!-- yara-fragment: ... --> marker must actually need
     it. This stops the marker from being used to silence a real defect.

Blocks that are intentionally partial (a single stage of a multi-stage example, a
root-stage AST contract excerpt, a deliberate anti-pattern demonstration, or a
continuous detection rule rather than an ad-hoc search) carry the marker
immediately above the fence:

    <!-- yara-fragment: stage 1 of 3; root stage shown in a later block -->
    ```yara
    ...
    ```

Author: Greg Kushmerek
"""

import os
import re
import sys
import unittest

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_DIR not in sys.path:
  sys.path.insert(0, REPO_DIR)

from scripts.preflight_validator import MalachiteASTValidator

FENCE_RE = re.compile(r"```yara\n(.*?)```", re.DOTALL)
FRAGMENT_MARKER = "yara-fragment"

# Error classes that indicate a query shape the compiler will reject. These are
# the regressions worth guarding in prose.
STRUCTURAL_CODES = (
    "MISSING_ROOT_STAGE",
    "INVALID_SQRT_FUNCTION",
    "INVALID_EXPONENT_OPERATOR",
    "STAGE_LIMIT_EXCEEDED",
    "INVALID_EVENTS_SECTION_IN_ROOT",
    "INVALID_DETECTION_RULE_SYNTAX",
    "UNBOUND_MATCH_VARIABLE",
)

# Deliberately NOT enforced over prose:
#   MISSING_GOAL_HEADER      - a generation-time style rule; no doc snippet
#                              carries the '// Goal:' banner and requiring it
#                              would add noise to every example.
#   INVALID_METRIC_FILTER    - illustrative snippets elide arguments as
#   MISSING_MANDATORY_FILTER   'metrics.foo(...)', which reads as a missing
#                              dimension but is just shorthand.


def _iter_doc_blocks():
  """Yields (relpath, fence_line_no, block_text, is_fragment) for the corpus."""
  paths = [os.path.join(REPO_DIR, "SKILL.md")]
  references = os.path.join(REPO_DIR, "references")
  for root, _, files in os.walk(references):
    for filename in sorted(files):
      if filename.endswith(".md"):
        paths.append(os.path.join(root, filename))

  for path in paths:
    with open(path, "r", encoding="utf-8") as f:
      content = f.read()
    for match in FENCE_RE.finditer(content):
      preceding = content[: match.start()].split("\n")
      line_no = len(preceding)
      prior_line = preceding[-2] if len(preceding) >= 2 else ""
      yield (
          os.path.relpath(path, REPO_DIR),
          line_no,
          match.group(1),
          FRAGMENT_MARKER in prior_line,
      )


def _structural_errors(block):
  return [
      e for e in MalachiteASTValidator.validate_query(block)
      if any(code in e for code in STRUCTURAL_CODES)
  ]


class TestDocumentationQueryCorpus(unittest.TestCase):

  def test_corpus_is_not_empty(self):
    """Guard against the extractor silently matching nothing."""
    blocks = list(_iter_doc_blocks())
    self.assertGreater(
        len(blocks), 20,
        "Expected the documentation corpus to contain many ```yara blocks; "
        "if this fails the fence regex has stopped matching."
    )

  def test_unmarked_doc_queries_are_structurally_valid(self):
    """Every complete documented query must survive the AST validator.

    This is the guard that would have caught the rootless 360 sector query.
    """
    failures = []
    for relpath, line_no, block, is_fragment in _iter_doc_blocks():
      if is_fragment:
        continue
      errors = _structural_errors(block)
      if errors:
        failures.append(f"{relpath}:{line_no}\n    " + "\n    ".join(errors))

    self.assertEqual(
        [], failures,
        "Documented YARA-L blocks failed structural validation. Either fix the "
        "block, or if it is intentionally partial, add a marker above the "
        "fence:\n    <!-- yara-fragment: why this block is partial -->\n\n"
        + "\n".join(failures)
    )

  def test_fragment_markers_are_load_bearing(self):
    """A fragment marker must be justified by an actual structural error.

    Without this, the marker becomes an easy way to silence a real defect.
    """
    unnecessary = []
    for relpath, line_no, block, is_fragment in _iter_doc_blocks():
      if not is_fragment:
        continue
      if not _structural_errors(block):
        unnecessary.append(f"{relpath}:{line_no}")

    self.assertEqual(
        [], unnecessary,
        "These blocks carry a <!-- yara-fragment --> marker but validate "
        "cleanly without it. Remove the marker so the block stays guarded: "
        + ", ".join(unnecessary)
    )

  def test_every_fragment_marker_precedes_a_fence(self):
    """A marker that drifts away from its fence silently stops working."""
    orphaned = []
    paths = [os.path.join(REPO_DIR, "SKILL.md")]
    for root, _, files in os.walk(os.path.join(REPO_DIR, "references")):
      paths.extend(
          os.path.join(root, f) for f in sorted(files) if f.endswith(".md")
      )

    for path in paths:
      with open(path, "r", encoding="utf-8") as f:
        lines = f.read().split("\n")
      for idx, line in enumerate(lines):
        if FRAGMENT_MARKER not in line:
          continue
        following = lines[idx + 1] if idx + 1 < len(lines) else ""
        if following.strip() != "```yara":
          orphaned.append(f"{os.path.relpath(path, REPO_DIR)}:{idx + 1}")

    self.assertEqual(
        [], orphaned,
        "These yara-fragment markers are not immediately followed by a "
        "```yara fence and are therefore inert: " + ", ".join(orphaned)
    )


if __name__ == "__main__":
  unittest.main()
