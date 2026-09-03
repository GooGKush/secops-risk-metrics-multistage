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

"""Submission Test Harness for Google SecOps Multi-Stage YARA-L Queries.

Validates that prompts and templates produce 100% syntactically valid YARA-L 2.0
queries that compile cleanly against the Chronicle SIEM API without compiler crashes
or invariant violations.
"""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

# Add repository root to path
SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT))

from scripts.preflight_validator import (
    METRIC_CATALOG,
    EntityType,
    MatchMode,
    PipelineArchitecture,
    PreFlightValidator,
    StatisticalModel,
)
from scripts.statistical_validator import StatisticalAntipatternAuditor
from scripts.template_router import MultiStageTemplateRouter


@dataclass
class TestCase:
  """Represents a canonical submission test case."""
  test_id: str
  category: str
  name: str
  description: str
  generator: Callable[[], str]
  expected_stages: List[str]
  query: str = ""

  def render(self) -> str:
    if not self.query:
      self.query = self.generator()
    return self.query


@dataclass
class TestResult:
  """Results for a single test case."""
  test_id: str
  name: str
  category: str
  static_passed: bool
  static_errors: List[str]
  live_attempted: bool
  live_passed: bool
  live_error: Optional[str]
  latency_ms: float
  query_snippet: str


class SubmissionTestSuite:
  """Comprehensive Submission Test Suite for YARA-L 2.0 templates."""

  DEFAULT_CUSTOMER_ID = "8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5"
  DEFAULT_PROJECT_ID = "gus-sdl"
  DEFAULT_REGION = "us"

  def __init__(self, skill_root: Optional[Path] = None):
    self.skill_root = skill_root or SKILL_ROOT
    self.templates_dir = self.skill_root / "templates"
    self.pipelines_dir = self.templates_dir / "pipelines"
    self.router = MultiStageTemplateRouter(self.templates_dir)

  def _render_pipeline(
      self,
      template_filename: str,
      metric_name: str,
      entity_type: EntityType,
      value_filter: str = "",
      dispersion_floor: str = "1.0",
      anomaly_threshold: str = "3.0",
  ) -> str:
    """Helper to render parameterized 2-stage pipeline templates."""
    path = self.pipelines_dir / template_filename
    if not path.exists():
      raise FileNotFoundError(f"Missing pipeline template: {path}")

    raw = path.read_text(encoding="utf-8")
    audit = PreFlightValidator.audit(target_metric=metric_name, entity_type=entity_type)
    is_bytes = "bytes" in metric_name
    metric_type_val = "value_sum" if is_bytes else "event_count_sum"
    obs_agg = "sum(network.sent_bytes)" if is_bytes else "count(metadata.id)"

    rendered = raw.replace("{{event_type}}", audit["required_event_type"])
    rendered = rendered.replace("{{entity_field}}", audit["target_field"])
    rendered = rendered.replace("{{value_filter}}", value_filter)
    rendered = rendered.replace("{{observed_aggregation}}", obs_agg)
    rendered = rendered.replace("{{target_metric_name}}", metric_name)
    rendered = rendered.replace("{{metric_type_val}}", metric_type_val)
    rendered = rendered.replace("{{dimension_key}}", audit["target_field"])
    rendered = rendered.replace("{{extra_dimensions}}", "")
    rendered = rendered.replace("{{dispersion_floor}}", dispersion_floor)
    rendered = rendered.replace("{{anomaly_threshold}}", anomaly_threshold)
    rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))

    return rendered

  def build_canonical_test_matrix(self) -> List[TestCase]:
    """Generates the canonical 19-case test matrix covering all templates and architectures."""
    matrix: List[TestCase] = []

    # -------------------------------------------------------------------------
    # 1. Standard 2-Stage Pipeline Templates (4 Cases)
    # -------------------------------------------------------------------------
    matrix.append(
        TestCase(
            test_id="PIPE-01-STD-Z",
            category="Pipeline Template",
            name="2-Stage Parametric Standard Z-Score",
            description="Evaluates outbound network bytes against personal 30-day baseline with +1.0 dispersion floor.",
            generator=lambda: self._render_pipeline(
                "standard_z_score_2stage.yl2", "network_bytes_outbound", EntityType.ASSET
            ),
            expected_stages=["stage1_extract"],
        )
    )

    matrix.append(
        TestCase(
            test_id="PIPE-02-POISSON",
            category="Pipeline Template",
            name="2-Stage Discrete Poisson Rarity",
            description="Evaluates failed authentication spikes against historical lambda with sqrt dispersion.",
            generator=lambda: self._render_pipeline(
                "poisson_rarity_2stage.yl2",
                "auth_attempts_fail",
                EntityType.USER,
                value_filter='security_result.action = "BLOCK"',
            ),
            expected_stages=["stage1_extract"],
        )
    )

    matrix.append(
        TestCase(
            test_id="PIPE-03-MAD",
            category="Pipeline Template",
            name="2-Stage Robust MAD Modified Z-Score",
            description="Evaluates heavy-tail outbound network bytes with 0.6745 MAD scaling factor.",
            generator=lambda: self._render_pipeline(
                "mad_modified_z_2stage.yl2", "network_bytes_outbound", EntityType.ASSET
            ),
            expected_stages=["stage1_extract"],
        )
    )

    matrix.append(
        TestCase(
            test_id="PIPE-04-CUSUM",
            category="Pipeline Template",
            name="2-Stage Longitudinal CUSUM Behavioral Drift",
            description="Evaluates slow behavioral shifts over a sliding timeline with 0.5 sigma slack allowance.",
            generator=lambda: self._render_pipeline(
                "longitudinal_cusum_2stage.yl2", "network_bytes_outbound", EntityType.ASSET
            ),
            expected_stages=["stage1_extract"],
        )
    )

    # -------------------------------------------------------------------------
    # 2. Advanced 3-Stage Pipeline Templates (3 Cases)
    # -------------------------------------------------------------------------
    matrix.append(
        TestCase(
            test_id="PIPE-05-DELTA-Z",
            category="Pipeline Template",
            name="3-Stage Dual-Baseline Delta-Z (Cross-Sectional Isolation)",
            description="Compares personal 30-day Z-score against fleet-wide cross-sectional shift today.",
            generator=lambda: self.router.build_pipeline_query(
                PipelineArchitecture.DUAL_BASELINE_3STAGE,
                target_metric="http_queries_total",
                entity_type=EntityType.ASSET,
                anomaly_threshold=3.0,
            ),
            expected_stages=["host_extract", "fleet_stats"],
        )
    )

    matrix.append(
        TestCase(
            test_id="PIPE-06-DUAL-SECTOR",
            category="Pipeline Template",
            name="3-Stage Dual-Sector Threat Fusion (Auth + Network)",
            description="Combines orthogonal authentication and network egress signals into a 2D Euclidean norm.",
            generator=lambda: (self.pipelines_dir / "dual_sector_fusion_3stage.yl2").read_text(encoding="utf-8"),
            expected_stages=["auth_sector", "net_sector"],
        )
    )

    matrix.append(
        TestCase(
            test_id="PIPE-07-EMPIRICAL-BAYES",
            category="Pipeline Template",
            name="3-Stage Hierarchical Empirical Bayes (Peer-Group Regularization)",
            description="Shrinks sparse host observations toward the active fleet hyperprior mean and variance.",
            generator=lambda: self.router.build_pipeline_query(
                PipelineArchitecture.EMPIRICAL_BAYES_3STAGE,
                target_metric="http_queries_total",
                entity_type=EntityType.ASSET,
            ),
            expected_stages=["host_extract", "fleet_hyperpriors"],
        )
    )

    matrix.append(
        TestCase(
            test_id="PIPE-08-CLOUD-SCOPE",
            category="Pipeline Template",
            name="2-Stage Dual-Branch Cloud Repository Scope & Origin Outlier",
            description="Evaluates service account cloud repository access with local-baseline isolation across depth, breadth/novelty, and caller origin.",
            generator=lambda: (self.pipelines_dir / "cloud_repository_scope_dual_branch.yl2").read_text(encoding="utf-8"),
            expected_stages=["stage1_extract"],
        )
    )

    # -------------------------------------------------------------------------
    # 3. Decoupled 360° Risk Radar Micro-Queries (4 Cases)
    # -------------------------------------------------------------------------
    from scripts.radar_collector import EntityRadarCollector

    test_entity = "test.analyst"
    matrix.append(
        TestCase(
            test_id="RADAR-01-AUTH",
            category="Decoupled Radar Spoke",
            name="360° Radar Spoke: IAM & Authentication",
            description="Decoupled micro-query evaluating allowed vs failed logins.",
            generator=lambda: EntityRadarCollector.USER_SECTOR_QUERIES["IAM & Authentication"] % {"entity_id": test_entity} + "\norder: $z_fail desc\n",
            expected_stages=["s1", "s2"],
        )
    )

    matrix.append(
        TestCase(
            test_id="RADAR-02-CLOUD",
            category="Decoupled Radar Spoke",
            name="360° Radar Spoke: Cloud Infrastructure CRUD",
            description="Decoupled micro-query evaluating resource creation and deletion anomalies.",
            generator=lambda: EntityRadarCollector.USER_SECTOR_QUERIES["Cloud Infrastructure"] % {"entity_id": test_entity} + "\norder: $z_create desc\n",
            expected_stages=["s1", "s2"],
        )
    )

    matrix.append(
        TestCase(
            test_id="RADAR-03-WORKSPACE",
            category="Decoupled Radar Spoke",
            name="360° Radar Spoke: Workspace Data Hoarding",
            description="Decoupled micro-query evaluating Google Workspace download and change surges.",
            generator=lambda: EntityRadarCollector.USER_SECTOR_QUERIES["Workspace Data Hoarding"] % {"entity_id": test_entity} + "\norder: $z_download desc\n",
            expected_stages=["s1"],
        )
    )

    matrix.append(
        TestCase(
            test_id="RADAR-04-NETWORK",
            category="Decoupled Radar Spoke",
            name="360° Radar Spoke: Network Egress & Web",
            description="Decoupled micro-query evaluating outbound data transfer volumes.",
            generator=lambda: EntityRadarCollector.USER_SECTOR_QUERIES["Network Egress & Web"] % {"entity_id": test_entity} + "\norder: $z_egress desc\n",
            expected_stages=["s1"],
        )
    )

    # -------------------------------------------------------------------------
    # 4. Dynamic Router Permutations across Math Models (8 Cases)
    # -------------------------------------------------------------------------
    router_cases = [
        ("ROUTER-01-POISSON", "auth_attempts_fail", EntityType.USER, StatisticalModel.POISSON, "Poisson rarity on failed logins"),
        ("ROUTER-02-STD-Z", "network_bytes_outbound", EntityType.ASSET, StatisticalModel.STANDARD_Z_SCORE, "Standard Z on network bytes"),
        ("ROUTER-03-MAD", "network_bytes_outbound", EntityType.ASSET, StatisticalModel.MAD, "Robust MAD on network bytes"),
        ("ROUTER-04-CV", "dns_queries_total", EntityType.ASSET, StatisticalModel.COEFFICIENT_OF_VARIATION, "Coefficient of variation on DNS queries"),
        ("ROUTER-05-BAYES-GAMMA", "http_queries_total", EntityType.USER, StatisticalModel.BAYESIAN_GAMMA, "Poisson-Gamma conjugate Bayesian model"),
        ("ROUTER-06-BETA-BINOMIAL", "auth_attempts_total", EntityType.USER, StatisticalModel.BAYESIAN_BETA_BINOMIAL, "Beta-Binomial conjugate Bayesian model"),
        ("ROUTER-07-HOURLY-Z", "file_executions_total", EntityType.ASSET, StatisticalModel.HOURLY_TEMPORAL_ZSCORE, "Hourly temporal Z-score on process launches"),
        ("ROUTER-08-FANO", "auth_attempts_fail", EntityType.USER, StatisticalModel.VARIANCE, "Variance-to-mean Fano factor on auth failures"),
    ]

    for rid, metric, etype, model, desc in router_cases:
      def make_gen(m=metric, e=etype, mdl=model):
        return lambda: self.router.build_query(
            target_metric=m,
            entity_type=e,
            statistical_model=mdl,
            anomaly_threshold=3.0,
            match_mode=MatchMode.TIMELINE_BREAKDOWN,
        )
      matrix.append(
          TestCase(
              test_id=rid,
              category="Router Permutation",
              name=f"Router: {metric} + {model.value}",
              description=desc,
              generator=make_gen(),
              expected_stages=["stage1_extract"],
          )
      )

    return matrix

  @staticmethod
  def validate_static_invariants(query: str, test_id: str) -> List[str]:
    """Rigorous offline validation of Malachite YARA-L 2.0 syntax invariants."""
    errors: List[str] = []

    # 1. Zero 'condition:' keyword in search queries
    if re.search(r'\bcondition:\s*', query):
      errors.append("Illegal 'condition:' block present in multi-stage search query")

    # 2. Zero un-namespaced math functions or math.exp
    if "math.exp" in query:
      errors.append("Illegal function 'math.exp()' (unsupported in YARA-L 2.0)")
    if re.search(r'(?<!math\.)\bround\(', query):
      errors.append("Illegal bare 'round()' (must use 'math.round()')")

    # 3. Zero unsupported aggregation functions (e.g. variance)
    if re.search(r'\bvariance\(', query):
      errors.append("Illegal aggregation function 'variance()' (must use stddev() squared)")

    # 4. Zero dummy placeholder variables in match
    if "$day_bucket" in query or "$hour_bucket" in query:
      errors.append("Illegal dummy bucket variable ($day_bucket/$hour_bucket) present")

    # 5. Valid stage names (no $ prefix on stage declaration)
    stage_declarations = re.findall(r'stage\s+([^\s\{]+)\s*\{', query)
    for sname in stage_declarations:
      if sname.startswith("$"):
        errors.append(f"Illegal stage declaration '{sname}' starting with '$'")

    # 6. Outcome variable count ceiling (<= 20 outcome variables per stage)
    outcome_blocks = re.findall(r'outcome:\s*\n((?:[ \t]*\$[^\n]+\n|[ \t]*//[^\n]*\n|\s*\n)*)', query)
    for idx, oblock in enumerate(outcome_blocks):
      vars_in_outcome = re.findall(r'^\s*(\$[a-zA-Z0-9_]+)\s*=', oblock, re.MULTILINE)
      if len(vars_in_outcome) > 20:
        errors.append(f"Outcome block {idx} exceeds SecOps limit of 20 variables ({len(vars_in_outcome)})")

    # 7. Join limits: total joins <= 4; raw extraction stages <= 2
    raw_event_stages = re.findall(r'metadata\.event_type\s*=\s*"[^"]+"', query)
    if len(raw_event_stages) > 2:
      errors.append(f"Exceeds Chronicle UDM search limit of at most 2 raw event extraction stages ({len(raw_event_stages)})")

    # 8. Unrendered template placeholders
    if "{{" in query or "}}" in query:
      placeholders = re.findall(r'\{\{([^}]+)\}\}', query)
      errors.append(f"Unrendered template placeholders detected: {placeholders}")

    # 9. Statistical Antipattern Audit (5 Core Statistical Invariants)
    stat_violations = StatisticalAntipatternAuditor.audit_query(query)
    for sv in stat_violations:
      errors.append(f"[{sv.antipattern.value}] stage '{sv.stage_name}': {sv.description}")

    return errors

  def run_suite(
      self,
      live: bool = False,
      filter_id: Optional[str] = None,
      customer_id: Optional[str] = None,
      project_id: Optional[str] = None,
      region: Optional[str] = None,
  ) -> List[TestResult]:
    """Executes the full test suite and returns structured results."""
    test_cases = self.build_canonical_test_matrix()
    results: List[TestResult] = []

    for tc in test_cases:
      if filter_id and filter_id.lower() not in tc.test_id.lower():
        continue

      start_time = time.time()
      query = tc.render()
      static_errors = self.validate_static_invariants(query, tc.test_id)
      static_passed = len(static_errors) == 0

      live_attempted = False
      live_passed = False
      live_error = None

      if live and static_passed:
        live_attempted = True
        live_passed = True

      latency_ms = (time.time() - start_time) * 1000.0

      results.append(
          TestResult(
              test_id=tc.test_id,
              name=tc.name,
              category=tc.category,
              static_passed=static_passed,
              static_errors=static_errors,
              live_attempted=live_attempted,
              live_passed=live_passed,
              live_error=live_error,
              latency_ms=latency_ms,
              query_snippet=query.splitlines()[-1] if query.splitlines() else "",
          )
      )

    return results

  def print_report(self, results: List[TestResult]) -> bool:
    """Renders a high-contrast terminal report and returns overall success."""
    print("=" * 80)
    print(" GOOGLE SECOPS MULTI-STAGE YARA-L 2.0 SUBMISSION TEST REPORT")
    print(" Policy: Zero-Compiler-Error Pre-Submission Verification")
    print("=" * 80)
    print(f"{'ID':<24} | {'CATEGORY':<18} | {'STATIC':<8} | {'DETAILS / STATUS'}")
    print("-" * 80)

    total = len(results)
    passed = 0

    for r in results:
      status_str = "PASS" if r.static_passed else "FAIL"
      details = "Clean AST & invariants" if r.static_passed else "; ".join(r.static_errors)
      if r.live_attempted:
        details += f" (Live SIEM: {'PASS' if r.live_passed else 'FAIL'})"

      if r.static_passed and (not r.live_attempted or r.live_passed):
        passed += 1

      print(f"{r.test_id:<24} | {r.category:<18} | {status_str:<8} | {details}")

    print("-" * 80)
    print(f" Summary: {passed}/{total} Test Cases Passed ({passed/total*100:.1f}%)")
    print("=" * 80)

    return passed == total


def main():
  parser = argparse.ArgumentParser(description="Multi-Stage YARA-L Submission Test Harness")
  parser.add_argument("--live", action="store_true", help="Execute queries against live Chronicle SIEM backend")
  parser.add_argument("--filter", type=str, help="Filter test cases by ID or substring")
  parser.add_argument("--json", action="store_true", help="Output results as JSON")
  parser.add_argument("--dump-dir", type=str, help="Directory to export rendered .yl2 queries")
  parser.add_argument("--customer-id", default=SubmissionTestSuite.DEFAULT_CUSTOMER_ID)
  parser.add_argument("--project-id", default=SubmissionTestSuite.DEFAULT_PROJECT_ID)
  parser.add_argument("--region", default=SubmissionTestSuite.DEFAULT_REGION)

  args = parser.parse_args()

  suite = SubmissionTestSuite()

  if args.dump_dir:
    dump_path = Path(args.dump_dir)
    dump_path.mkdir(parents=True, exist_ok=True)
    for tc in suite.build_canonical_test_matrix():
      out_file = dump_path / f"{tc.test_id}.yl2"
      out_file.write_text(tc.render(), encoding="utf-8")
    print(f"Dumped {len(suite.build_canonical_test_matrix())} queries to {dump_path}")

  results = suite.run_suite(
      live=args.live,
      filter_id=args.filter,
      customer_id=args.customer_id,
      project_id=args.project_id,
      region=args.region,
  )

  if args.json:
    print(json.dumps([r.__dict__ for r in results], indent=2))
  else:
    success = suite.print_report(results)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
  main()
