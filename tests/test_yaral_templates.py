"""Unit tests verifying all YARA-L 2.0 multi-stage templates comply with compiler rules."""

import glob
import re
import unittest


class TestYaraLTemplates(unittest.TestCase):

  def setUp(self):
    self.template_files = glob.glob(
        '/usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage/templates/**/*.yl2',
        recursive=True
    )
    self.assertGreater(len(self.template_files), 0, "Template directory must contain .yl2 files")

  def test_no_dollar_prefix_in_stage_names(self):
    """Stage identifiers must not have a '$' prefix (e.g. 'stage s1 {' NOT 'stage $s1 {')."""
    invalid_stage_pattern = re.compile(r'stage\s+\$[a-zA-Z0-9_]+\s*\{')
    for fpath in self.template_files:
      with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()
      matches = invalid_stage_pattern.findall(content)
      self.assertEqual(
          len(matches), 0,
          f"File {fpath} contains invalid stage definition with '$' prefix: {matches}"
      )

  def test_window_keyword_is_by_not_over(self):
    """Match window clause in multi-stage metrics queries must use 'by 1d' or 'by 1h'."""
    invalid_window_pattern = re.compile(r'match:\s*.*?\bover\s+[0-9]+[dhms]\b', re.DOTALL)
    for fpath in self.template_files:
      with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()
      # In multi-stage YARA-L, match windows must be 'by <duration>'
      self.assertNotIn("over 1d", content, f"File {fpath} uses deprecated 'over 1d' instead of 'by 1d'")

  def test_outcome_variable_limit(self):
    """Outcome sections must not exceed Google SecOps compiler limit of 20 variables."""
    outcome_var_pattern = re.compile(r'\$[a-zA-Z0-9_]+\s*=')
    for fpath in self.template_files:
      with open(fpath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
      
      in_outcome = False
      outcome_count = 0
      for line in lines:
        stripped = line.strip()
        if stripped.startswith("outcome:"):
          in_outcome = True
          outcome_count = 0
          continue
        elif in_outcome and (stripped.startswith("condition:") or stripped.startswith("order:") or stripped.startswith("stage ")):
          self.assertLessEqual(
              outcome_count, 20,
              f"File {fpath} exceeds OutcomeLimit of 20 variables (found {outcome_count})"
          )
          in_outcome = False
        elif in_outcome:
          if outcome_var_pattern.search(stripped) and not stripped.startswith("//"):
            outcome_count += 1

  def test_malachite_validator_flags_cramming_and_hallucination(self):
    """MalachiteASTValidator must detect single-stage multi-vector cramming and fake metric functions."""
    import sys
    sys.path.insert(0, '/usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage')
    from scripts.preflight_validator import MalachiteASTValidator

    bad_query = (
        "stage daily_entity_rollup {\n"
        "  (metadata.event_type = \"USER_LOGIN\" AND security_result.action = \"BLOCK\") OR\n"
        "  (metadata.event_type = \"SERVICE_STOP\" AND security_result.action = \"BLOCK\") OR\n"
        "  (metadata.event_type = \"NETWORK_CONNECTION\" AND network.direction = \"OUTBOUND\")\n"
        "  $host = principal.asset.hostname\n"
        "  match: $host by 1d\n"
        "  outcome:\n"
        "    $mu_auth = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.asset.hostname: $host))\n"
        "    $fake = max(metrics.service_stops(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.asset.hostname: $host))\n"
        "}\n"
    )

    errors = MalachiteASTValidator.validate_query(bad_query)
    self.assertTrue(any("ANTI-PATTERN 6" in e for e in errors), f"Expected Anti-Pattern 6 error, got {errors}")
    self.assertTrue(any("ANTI-PATTERN 7" in e for e in errors), f"Expected Anti-Pattern 7 error, got {errors}")

  def test_stage_count_contract_enforcement(self):
    """MalachiteASTValidator must enforce exact stage counts per architecture and stage parity per telemetry sector."""
    import sys
    sys.path.insert(0, '/usr/local/google/home/kushmerek/.gemini/skills/secops-risk-metrics-multistage')
    from scripts.preflight_validator import MalachiteASTValidator

    # Query claiming to be 4-stage Multi-Sector Fusion but only defining 1 named stage
    mismatched_query = (
        "// ARCHITECTURE: 4-STAGE MULTI-SECTOR THREAT FUSION\n"
        "stage single_extractor {\n"
        "  metadata.event_type = \"USER_LOGIN\"\n"
        "  principal.asset.hostname = $host\n"
        "  match: $host by 1d\n"
        "  outcome:\n"
        "    $mu_auth = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.asset.hostname: $host))\n"
        "    $mu_proc = max(metrics.file_executions_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.asset.hostname: $host))\n"
        "}\n"
    )
    errors = MalachiteASTValidator.validate_query(mismatched_query)
    self.assertTrue(any("PIPELINE ARCHITECTURE MISMATCH" in e for e in errors), f"Expected Architecture Mismatch, got {errors}")
    self.assertTrue(any("STAGE PARITY ERROR" in e for e in errors), f"Expected Stage Parity Error, got {errors}")


if __name__ == '__main__':
  unittest.main()


