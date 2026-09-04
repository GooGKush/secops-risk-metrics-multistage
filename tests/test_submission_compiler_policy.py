#!/usr/bin/env python3
# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests validating the Pre-Submission Compiler Policy and Harness.

Ensures that all 20 canonical submission test cases pass static invariant validation,
the invariant validator accurately detects forbidden patterns, and documentation
stays synchronized.
"""

from pathlib import Path
import sys
import unittest

# Ensure skill root is in path
SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT))

from scripts.submission_tests import SubmissionTestSuite


class TestSubmissionCompilerPolicy(unittest.TestCase):
  """Validates the Pre-Submission Compiler Policy and invariant enforcement."""

  @classmethod
  def setUpClass(cls):
    cls.suite = SubmissionTestSuite(SKILL_ROOT)
    cls.matrix = cls.suite.build_canonical_test_matrix()

  def test_canonical_matrix_size(self):
    """Asserts that exactly 21 canonical test cases are defined."""
    self.assertEqual(len(self.matrix), 21)

  def test_all_canonical_cases_pass_static_validation(self):
    """Validates that all 21 canonical test cases produce clean YARA-L 2.0."""
    for tc in self.matrix:
      with self.subTest(test_id=tc.test_id, name=tc.name):
        query = tc.render()
        self.assertIsInstance(query, str)
        self.assertGreater(len(query), 50, f"Query for {tc.test_id} is unexpectedly short")
        errors = SubmissionTestSuite.validate_static_invariants(query, tc.test_id)
        self.assertEqual(
            errors,
            [],
            f"Test case {tc.test_id} failed invariant check with errors: {errors}",
        )

  def test_pipe_09_prevalence_compiler_invariants(self):
    """Asserts that PIPE-09-PREVALENCE passes AST validation and compiler invariants."""
    pipe_09 = next(tc for tc in self.matrix if tc.test_id == "PIPE-09-PREVALENCE")
    query = pipe_09.render()
    self.assertIn("stage host_egress", query)
    self.assertIn("stage destination_prevalence", query)
    self.assertIn("artifact.prevalence.day_count = 10", query)
    self.assertIn("artifact.prevalence.rolling_max <= 3", query)
    self.assertIn("metrics.network_bytes_outbound", query)
    errors = SubmissionTestSuite.validate_static_invariants(query, pipe_09.test_id)
    self.assertEqual(errors, [])

  def test_invariant_detects_forbidden_condition_block(self):
    """Ensures validator catches forbidden 'condition:' blocks in search queries."""
    bad_query = """
    stage s1 {
      metadata.event_type = "USER_LOGIN"
      principal.user.userid = $user
    match: $user by 1d
    outcome: $n = count(metadata.id)
    }
    order: $n desc
    condition: $n > 5
    """
    errors = SubmissionTestSuite.validate_static_invariants(bad_query, "TEST-BAD-COND")
    self.assertTrue(any("condition:" in e for e in errors))

  def test_invariant_detects_illegal_variance_function(self):
    """Ensures validator catches unsupported 'variance()' aggregate."""
    bad_query = """
    stage s1 {
      metadata.event_type = "USER_LOGIN"
      principal.user.userid = $user
    match: $user by 1d
    outcome: $v = variance(network.sent_bytes)
    }
    order: $v desc
    """
    errors = SubmissionTestSuite.validate_static_invariants(bad_query, "TEST-BAD-VAR")
    self.assertTrue(any("variance()" in e for e in errors))

  def test_invariant_detects_bare_math_round(self):
    """Ensures validator catches bare 'round()' without math. prefix."""
    bad_query = """
    stage s1 {
      metadata.event_type = "USER_LOGIN"
      principal.user.userid = $user
    match: $user by 1d
    outcome: $r = round(1.234)
    }
    order: $r desc
    """
    errors = SubmissionTestSuite.validate_static_invariants(bad_query, "TEST-BAD-ROUND")
    self.assertTrue(any("math.round()" in e for e in errors))

  def test_invariant_detects_math_exp(self):
    """Ensures validator catches unsupported 'math.exp()' call."""
    bad_query = """
    stage s1 {
      metadata.event_type = "USER_LOGIN"
      principal.user.userid = $user
    match: $user by 1d
    outcome: $e = math.exp(2.0)
    }
    order: $e desc
    """
    errors = SubmissionTestSuite.validate_static_invariants(bad_query, "TEST-BAD-EXP")
    self.assertTrue(any("math.exp()" in e for e in errors))

  def test_invariant_detects_dummy_bucket_variables(self):
    """Ensures validator catches forbidden $day_bucket or $hour_bucket."""
    bad_query = """
    stage s1 {
      metadata.event_type = "USER_LOGIN"
      principal.user.userid = $user
    match: $user, $day_bucket by 1d
    outcome: $c = count(metadata.id)
    }
    order: $c desc
    """
    errors = SubmissionTestSuite.validate_static_invariants(bad_query, "TEST-BAD-BUCKET")
    self.assertTrue(any("dummy bucket" in e.lower() for e in errors))

  def test_invariant_detects_stage_starting_with_dollar(self):
    """Ensures validator catches illegal 'stage $s1 {' syntax."""
    bad_query = """
    stage $s1 {
      metadata.event_type = "USER_LOGIN"
      principal.user.userid = $user
    match: $user by 1d
    outcome: $c = count(metadata.id)
    }
    order: $c desc
    """
    errors = SubmissionTestSuite.validate_static_invariants(bad_query, "TEST-BAD-STAGE")
    self.assertTrue(any("starting with '$'" in e for e in errors))

  def test_invariant_detects_unrendered_template_placeholders(self):
    """Ensures validator catches unrendered {{placeholder}} tokens."""
    bad_query = """
    stage s1 {
      metadata.event_type = "{{event_type}}"
      principal.user.userid = $user
    match: $user by 1d
    outcome: $c = count(metadata.id)
    }
    order: $c desc
    """
    errors = SubmissionTestSuite.validate_static_invariants(bad_query, "TEST-UNRENDERED")
    self.assertTrue(any("unrendered template placeholders" in e.lower() for e in errors))

  def test_invariant_detects_excessive_outcome_variables(self):
    """Ensures validator catches stages exceeding 20 outcome variables."""
    outcomes = "\n".join([f"    $var_{i} = count(metadata.id)" for i in range(25)])
    bad_query = f"""
    stage s1 {{
      metadata.event_type = "USER_LOGIN"
      principal.user.userid = $user
    match: $user by 1d
    outcome:
{outcomes}
    }}
    order: $var_0 desc
    """
    errors = SubmissionTestSuite.validate_static_invariants(bad_query, "TEST-MAX-OUTCOMES")
    self.assertTrue(any("exceeds SecOps limit of 20" in e for e in errors))

  def test_invariant_detects_excessive_raw_event_stages(self):
    """Ensures validator catches queries with >2 raw event extraction stages."""
    bad_query = """
    stage s1 {
      metadata.event_type = "USER_LOGIN"
      principal.user.userid = $user
    match: $user by 1d
    outcome: $c1 = count(metadata.id)
    }
    stage s2 {
      metadata.event_type = "NETWORK_CONNECTION"
      principal.user.userid = $user
    match: $user by 1d
    outcome: $c2 = count(metadata.id)
    }
    stage s3 {
      metadata.event_type = "PROCESS_LAUNCH"
      principal.user.userid = $user
    match: $user by 1d
    outcome: $c3 = count(metadata.id)
    }
    order: $c1 desc
    """
    errors = SubmissionTestSuite.validate_static_invariants(bad_query, "TEST-EXCESSIVE-JOINS")
    self.assertTrue(any("at most 2 raw event extraction stages" in e for e in errors))

  def test_policy_document_covers_all_test_case_ids(self):
    """Ensures compiler-submission-policy.md explicitly documents all 20 test IDs."""
    doc_path = SKILL_ROOT / "references" / "compiler-submission-policy.md"
    self.assertTrue(doc_path.exists(), "compiler-submission-policy.md is missing")
    content = doc_path.read_text(encoding="utf-8")
    for tc in self.matrix:
      self.assertIn(
          tc.test_id,
          content,
          f"Test ID {tc.test_id} not documented in references/compiler-submission-policy.md",
      )


if __name__ == "__main__":
  unittest.main()
