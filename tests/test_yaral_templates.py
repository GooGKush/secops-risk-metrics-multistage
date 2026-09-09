"""Unit tests verifying all YARA-L 2.0 multi-stage templates comply with compiler rules."""

import glob
import re
import unittest


class TestYaraLTemplates(unittest.TestCase):

  def setUp(self):
    import os
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    templates_dir = os.path.join(repo_dir, 'templates')
    if not os.path.exists(templates_dir):
      templates_dir = os.path.expanduser('~/.gemini/skills/secops-risk-metrics-multistage/templates')
    self.template_files = glob.glob(
        os.path.join(templates_dir, '**/*.yl2'),
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
    import sys, os
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_dir not in sys.path:
      sys.path.insert(0, repo_dir)
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
    import sys, os
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_dir not in sys.path:
      sys.path.insert(0, repo_dir)
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

  def test_stage1_catalog_completeness_and_exact_38_match(self):
    """Ensures that all 38 active metrics in METRIC_CATALOG have a corresponding Stage 1 template."""
    import os, sys
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_dir not in sys.path:
      sys.path.insert(0, repo_dir)
    from scripts.preflight_validator import METRIC_CATALOG

    templates_dir = os.path.join(repo_dir, "templates", "stage1_extractors")
    self.assertEqual(len(METRIC_CATALOG), 38, "METRIC_CATALOG must contain exactly 38 metrics")

    disk_templates = set(os.listdir(templates_dir))
    for metric_name in METRIC_CATALOG:
      expected_file = f"{metric_name}.yl2"
      self.assertIn(
          expected_file,
          disk_templates,
          f"Missing Stage 1 extractor template for metric '{metric_name}' in {templates_dir}",
      )
    self.assertEqual(
        len([f for f in disk_templates if f.endswith(".yl2")]),
        38,
        "templates/stage1_extractors must contain exactly 38 .yl2 files",
    )

  def test_stage1_standardized_six_point_outcome_contract(self):
    """Guarantees every Stage 1 extractor emits the complete 6-variable outcome tuple for Stage 2 math."""
    import os, sys
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_dir not in sys.path:
      sys.path.insert(0, repo_dir)
    from scripts.preflight_validator import METRIC_CATALOG

    required_outcomes = [
        "$observed_val",
        "$historical_avg",
        "$historical_stddev",
        "$historical_active_days",
        "$historical_max",
        "$historical_sum",
    ]

    templates_dir = os.path.join(repo_dir, "templates", "stage1_extractors")
    for metric_name in METRIC_CATALOG:
      fpath = os.path.join(templates_dir, f"{metric_name}.yl2")
      with open(fpath, "r", encoding="utf-8") as f:
        content = f.read()

      # Extract outcome block up to stage closing brace
      outcome_match = re.search(r"outcome:\s*\n(.*?)\n\}", content, re.DOTALL)
      self.assertIsNotNone(outcome_match, f"[{metric_name}] Missing outcome block in {fpath}")
      outcome_text = outcome_match.group(1)

      assigned_vars = set(re.findall(r"^\s*(\$[a-zA-Z0-9_]+)\s*=", outcome_text, re.MULTILINE))
      for req_var in required_outcomes:
        self.assertIn(
            req_var,
            assigned_vars,
            f"[{metric_name}] Missing mandatory outcome variable '{req_var}' in {fpath}. Found: {assigned_vars}",
        )

  def test_stage1_aggregation_and_metric_type_invariants(self):
    """Validates compiler-required aggregation types and metric type arguments."""
    import os, sys
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_dir not in sys.path:
      sys.path.insert(0, repo_dir)
    from scripts.preflight_validator import METRIC_CATALOG

    templates_dir = os.path.join(repo_dir, "templates", "stage1_extractors")
    byte_metrics = {
        "network_bytes_inbound",
        "network_bytes_outbound",
        "network_bytes_total",
        "dns_bytes_outbound",
        "workspace_network_bytes_outbound",
        "workspace_network_bytes_total",
    }

    for metric_name in METRIC_CATALOG:
      fpath = os.path.join(templates_dir, f"{metric_name}.yl2")
      with open(fpath, "r", encoding="utf-8") as f:
        content = f.read()

      # 1. Prohibit unsupported agg: num_days (must be agg: num_metric_periods)
      self.assertNotIn("agg: num_days", content, f"[{metric_name}] Uses invalid agg: num_days in {fpath}")
      self.assertIn("agg: num_metric_periods", content, f"[{metric_name}] Missing required agg: num_metric_periods in {fpath}")

      # 2. Metric type invariants
      if metric_name in byte_metrics:
        self.assertIn("metric: value_sum", content, f"[{metric_name}] Byte volume metric must use 'metric: value_sum'")
      else:
        self.assertIn("metric: event_count_sum", content, f"[{metric_name}] Count metric must use 'metric: event_count_sum'")

  def test_stage1_cloud_crud_local_baseline_isolation(self):
    """Enforces Local-Baseline Isolation on all 12 cloud resource CRUD metric extractors."""
    import os, sys
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_dir not in sys.path:
      sys.path.insert(0, repo_dir)
    from scripts.preflight_validator import METRIC_CATALOG

    templates_dir = os.path.join(repo_dir, "templates", "stage1_extractors")
    cloud_metrics = [m for m in METRIC_CATALOG if m.startswith("resource_")]
    self.assertEqual(len(cloud_metrics), 12, "Must identify exactly 12 cloud resource CRUD metrics")

    for metric_name in cloud_metrics:
      fpath = os.path.join(templates_dir, f"{metric_name}.yl2")
      with open(fpath, "r", encoding="utf-8") as f:
        content = f.read()

      # Local-Baseline Isolation requires 5-tuple match: $sa, $vendor, $product, $resource, $ip by 1d
      self.assertIn(
          "match:\n    $sa, $vendor, $product, $resource, $ip by 1d",
          content,
          f"[{metric_name}] Cloud CRUD extractor must enforce 5-tuple Local-Baseline Isolation match clause",
      )
      self.assertIn("principal.user.userid: $sa", content)
      self.assertIn("metadata.vendor_name: $vendor", content)
      self.assertIn("metadata.product_name: $product", content)
      self.assertIn("target.resource.name: $resource", content)


if __name__ == '__main__':
  unittest.main()


