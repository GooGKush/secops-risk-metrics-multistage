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
import datetime
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
    MalachiteASTValidator,
    MatchMode,
    PipelineArchitecture,
    PreFlightValidator,
    StatisticalModel,
)
from scripts.statistical_validator import StatisticalAntipatternAuditor
from scripts.template_router import MultiStageTemplateRouter


def iter_if_calls(query: str):
  r"""Yields (call_text, [condition, then, else]) for every if(...) call, honoring nested parentheses.

  A naive `if\s*\(([^)]+)\)` regex truncates at the first ')' and misreads conditions that contain
  function calls, e.g. if(timestamp.get_date(metadata.event_timestamp.seconds) >= "2026-10-01", 1, 0).
  """
  query = re.sub(r"(^|\s)//[^\n]*", r"\1", query)  # ignore // comments (prose may mention if())
  for m in re.finditer(r"\bif\s*\(", query):
    depth, start, args, buf = 1, m.end(), [], []
    i = start
    in_str = False
    while i < len(query) and depth > 0:
      ch = query[i]
      if ch == '"' and (i == 0 or query[i - 1] != "\\"):
        in_str = not in_str
      if not in_str:
        if ch == "(":
          depth += 1
        elif ch == ")":
          depth -= 1
          if depth == 0:
            break
        elif ch == "," and depth == 1:
          args.append("".join(buf).strip())
          buf = []
          i += 1
          continue
      buf.append(ch)
      i += 1
    args.append("".join(buf).strip())
    yield query[m.start():i + 1], args


def if_branch_has_compound_arithmetic(branch: str) -> bool:
  """True when an if() branch is an arithmetic expression rather than a variable or literal.

  Verified live (gus-sdl, 2026-10-07): if($mad > 0, $mad / 0.6745, $m * 1.25) is rejected with
  'invalid argument'; precomputing each branch into its own outcome variable compiles.
  """
  return bool(re.search(r"[\+\-\*\/]", re.sub(r"^\s*[-+]\s*", "", branch)))


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



def _strip_comments(query: str) -> str:
  """Strips // line comments and /* */ block comments from YARA-L text."""
  no_block = re.sub(r"/\*.*?\*/", "", query, flags=re.DOTALL)
  return "\n".join(re.sub(r"//[^\n]*", "", ln) for ln in no_block.splitlines())


def _extract_named_stage_blocks(query: str) -> List[tuple]:
  """Extracts (stage_name, stage_body) tuples using balanced brace counting."""
  results = []
  for m in re.finditer(r"\bstage\s+([a-zA-Z0-9_$]+)\s*\{", query):
    stage_name = m.group(1)
    start_idx = m.end()
    depth = 1
    pos = start_idx
    while pos < len(query) and depth > 0:
      if query[pos] == "{":
        depth += 1
      elif query[pos] == "}":
        depth -= 1
      pos += 1
    if depth == 0:
      results.append((stage_name, query[start_idx : pos - 1]))
  return results


def check_stage_references(query: str) -> List[str]:
  """Validates that stage references ($stage.field) resolve against the union of all defined stages."""
  errors: List[str] = []
  clean = _strip_comments(query)
  clean_no_str = re.sub(r'"(?:\\.|[^"\\])*"', '""', clean)
  stage_blocks = _extract_named_stage_blocks(clean_no_str)
  defined_stages = {name for name, _ in stage_blocks}
  if not defined_stages:
    return errors

  udm_roots = {
      "metadata", "principal", "target", "src", "observer", "intermediary",
      "network", "security_result", "about", "additional", "extensions", "graph",
  }
  for m in re.finditer(r"\$([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)", clean_no_str):
    prefix, field = m.group(1), m.group(2)
    if prefix == "graph" or field in udm_roots:
      continue
    if prefix not in defined_stages:
      errors.append(
          f"UNDEFINED_STAGE_REFERENCE: Reference '${prefix}.{field}' does not match any defined stage in {sorted(defined_stages)}"
      )
  return errors


def check_root_match_stage_prefix(query: str) -> List[str]:
  """Inspects match: blocks across all stages (named and root) for illegal $stage.field prefixes."""
  errors: List[str] = []
  clean = _strip_comments(query)
  for m in re.finditer(
      r"(?:^|\n)\s*match\s*:\s*(.*?)(?=\n\s*(?:outcome|condition|order|limit)\s*:|\}|\Z)",
      clean,
      flags=re.DOTALL,
  ):
    match_body = m.group(1)
    for ref in re.finditer(r"\$([a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+)", match_body):
      errors.append(
          f"ILLEGAL_MATCH_STAGE_PREFIX: Stage-prefixed variable '${ref.group(1)}' in match: block (bind to a local variable before match:)"
      )
  return errors


def check_outcome_conditionals_and_divisions(query: str) -> List[str]:
  """Strips // comments before checking outcome: lines for illegal conditionals or literal / 0 divisions."""
  errors: List[str] = []
  clean = _strip_comments(query)
  clean_no_str = re.sub(r'"(?:\\.|[^"\\])*"', '""', clean)
  for m in re.finditer(
      r"(?:^|\n)\s*outcome\s*:\s*(.*?)(?=\n\s*(?:condition|order|limit|match)\s*:|\}|\Z)",
      clean_no_str,
      flags=re.DOTALL,
  ):
    outcome_body = m.group(1)
    for raw_line in outcome_body.splitlines():
      line = raw_line.strip()
      if not line:
        continue
      if re.search(r"/\s*0(?:\.0+)?(?![0-9.])", line):
        errors.append(f"DIVISION_BY_ZERO_LITERAL: Literal division by zero in outcome line: {line}")
      if "?" in line and ":" in line:
        errors.append(f"ILLEGAL_TERNARY_OPERATOR: Ternary '? :' is unsupported in outcome line: {line}")
  return errors


def check_Stage_1_zero_filters(query: str) -> List[str]:
  """Detects forbidden $var = 0 or 0 = $var equality filters on observed metric variables in Stage 1."""
  errors: List[str] = []
  clean = _strip_comments(query)
  stage_blocks = _extract_named_stage_blocks(clean)
  target_bodies = [stage_blocks[0][1]] if stage_blocks else [clean]
  for body in target_bodies:
    # Remove if(...) expressions so if(..., 1, 0) is never misflagged
    body_no_if = re.sub(r"\bif\s*\([^)]*\)", "", body)
    pattern = (
        r"(?<![!<>])(?:"
        r"\$(?:observed|observed_val|obs|daily_count|event_count|metric_val|count_val|bytes_val)[a-zA-Z0-9_]*\s*=\s*0(?:\.0+)?\b"
        r"|"
        r"\b0(?:\.0+)?\s*=\s*\$(?:observed|observed_val|obs|daily_count|event_count|metric_val|count_val|bytes_val)[a-zA-Z0-9_]*"
        r")(?![0-9.])"
    )
    for m in re.finditer(pattern, body_no_if):
      errors.append(
          f"STAGE1_ZERO_EQUALITY_FILTER: Forbidden Stage 1 zero equality filter '{m.group(0).strip()}' (raw UDM stages only emit rows for existing events)"
      )
  return errors


check_stage_1_zero_filters = check_Stage_1_zero_filters


def check_ecg_invariants(query: str) -> List[str]:
  """Enforces prevalence.day_count = 10 and rolling_max when DERIVED_CONTEXT prevalence is used."""
  errors: List[str] = []
  clean = _strip_comments(query)
  if "DERIVED_CONTEXT" in clean and ".prevalence." in clean:
    if not re.search(r"\.prevalence\.day_count\s*=\s*10\b", clean):
      errors.append(
          "ECG_PREVALENCE_INVARIANT: DERIVED_CONTEXT prevalence queries must anchor '.prevalence.day_count = 10'"
      )
    if "rolling_max" not in clean:
      errors.append(
          "ECG_PREVALENCE_INVARIANT: DERIVED_CONTEXT prevalence queries must constrain or project '.prevalence.rolling_max'"
      )
  return errors


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
      dispersion_floor: str = "1.0",
      anomaly_threshold: str = "3.0",
  ) -> str:
    """Helper to render parameterized 2-stage pipeline templates."""
    path = self.pipelines_dir / template_filename
    if not path.exists():
      raise FileNotFoundError(f"Missing pipeline template: {path}")

    raw = path.read_text(encoding="utf-8")
    audit = PreFlightValidator.audit(target_metric=metric_name, entity_type=entity_type)

    # Event selection, observed value and metric argument come from the vendored baseline semantics.
    rendered = raw.replace("{{event_filter}}", "\n    ".join(audit["event_filter"]))
    rendered = rendered.replace("{{entity_field}}", audit["target_field"])
    rendered = rendered.replace("{{observed_aggregation}}", audit["observed_agg"])
    rendered = rendered.replace("{{target_metric_name}}", metric_name)
    rendered = rendered.replace("{{metric_type_val}}", audit["metric_arg"])
    rendered = rendered.replace("{{dimension_key}}", audit["target_field"])
    rendered = rendered.replace("{{extra_dimensions}}", "")
    rendered = rendered.replace("{{dispersion_floor}}", dispersion_floor)
    rendered = rendered.replace("{{anomaly_threshold}}", anomaly_threshold)
    # Root significance gate placeholders for ratio, fusion and MAD templates (router defaults).
    rendered = rendered.replace("{{fold_change_threshold}}", "2.0")
    rendered = rendered.replace("{{fusion_threshold_sq}}", "12.25")
    rendered = rendered.replace("{{robust_threshold}}", "3.5")
    rendered = rendered.replace("{{min_baseline_days}}", str(audit["min_baseline_days"]))
    rendered = rendered.replace(
        "{{first_scored_date}}", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"))

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
            ),
            expected_stages=["stage1_extract"],
        )
    )

    matrix.append(
        TestCase(
            test_id="PIPE-03-MAD",
            category="Pipeline Template",
            name="4-Stage True MAD Modified Z-Score",
            description="Median/MAD over raw daily outbound bytes (window.median) with Iglewicz-Hoaglin MAD=0 fallback, next to the 30d metrics Z.",
            generator=lambda: self._render_pipeline(
                "mad_robust_z_4stage.yl2", "network_bytes_outbound", EntityType.ASSET
            ),
            expected_stages=["stage1_extract", "mad_center", "mad_spread"],
        )
    )

    matrix.append(
        TestCase(
            test_id="PIPE-04-CUSUM",
            category="Pipeline Template",
            name="2-Stage Longitudinal CUSUM Behavioral Drift",
            description="Evaluates slow behavioral shifts over a multi-day timeline (one fixed reference baseline) with 0.5 sigma slack allowance.",
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
            name="3-Stage Dual-Sector Threat Fusion (generic; default auth fail + network egress by userid)",
            description="Fuses two entity-keyed metric sectors into a 2D Euclidean norm, rendered from the generic template.",
            generator=lambda: self.router.build_pipeline_query(
                PipelineArchitecture.DUAL_SECTOR_FUSION_3STAGE,
                entity_type=EntityType.USER,
            ),
            expected_stages=["sector_a", "sector_b"],
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
            generator=lambda: (self.pipelines_dir / "cloud_repository_scope_dual_branch.yl2").read_text(
                encoding="utf-8").replace("{{anomaly_threshold}}", "3.0"),
            expected_stages=["stage1_extract"],
        )
    )

    matrix.append(
        TestCase(
            test_id="PIPE-09-PREVALENCE",
            category="Pipeline Template",
            name="2-Stage Entity Graph IP Prevalence & Egress Outlier",
            description="Evaluates outbound network connection volume against 30d baseline joined with Entity Graph external IP prevalence (<= 3 hosts).",
            generator=lambda: """// Stage 1: Measure outbound network connection activity and 30-day baseline per host and external IP
stage host_egress {
    $net.network.sent_bytes > 0
    $net.network.sent_bytes < 1000000000000000
    $net.principal.asset.hostname = $host
    $net.target.ip = $dst_ip

    // Exclude internal RFC 1918 traffic
    not net.ip_in_range_cidr($dst_ip, "10.0.0.0/8")
    not net.ip_in_range_cidr($dst_ip, "172.16.0.0/12")
    not net.ip_in_range_cidr($dst_ip, "192.168.0.0/16")

  match:
    $host, $dst_ip by 1d

  outcome:
    $observed_bytes = sum($net.network.sent_bytes)
    $hist_avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.asset.hostname: $host
    ))
    $hist_stddev = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.asset.hostname: $host
    ))
    $hist_active_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.hostname: $host
    ))
}

// Stage 2: Entity Graph Derived Context - External IP Prevalence (<= 3 internal hosts across 10d)
stage destination_prevalence {
    $graph.graph.metadata.entity_type = "IP_ADDRESS"
    $graph.graph.metadata.source_type = "DERIVED_CONTEXT"
    $graph.graph.entity.ip = $dst_ip
    $graph.graph.entity.artifact.prevalence.day_count = 10
    $graph.graph.entity.artifact.prevalence.rolling_max > 0
    $graph.graph.entity.artifact.prevalence.rolling_max <= 3

  match:
    $dst_ip by 1d

  outcome:
    $fleet_prevalence = max($graph.graph.entity.artifact.prevalence.rolling_max)
}

// Root Stage: Join host egress with destination rarity and evaluate statistical deviation
$host = $host_egress.host
$dst_ip = $host_egress.dst_ip
$dst_ip = $destination_prevalence.dst_ip

match:
  $host, $dst_ip by 1d

outcome:
  $actual_bytes = max($host_egress.observed_bytes)
  $historical_mean = max($host_egress.hist_avg)
  $historical_stddev = max($host_egress.hist_stddev)
  $baseline_active_days = max($host_egress.hist_active_days)
  $destination_prevalence_10d = max($destination_prevalence.fleet_prevalence)
  $z_score = ($actual_bytes - $historical_mean) / if($historical_stddev > 0, $historical_stddev, 1.0)

order:
  $z_score desc
""",
            expected_stages=["host_egress", "destination_prevalence"],
        )
    )

    matrix.append(
        TestCase(
            test_id="PIPE-10-MACD-MOMENTUM",
            category="Pipeline Template",
            name="2-Stage MACD Dual-Spine Momentum Velocity Pipeline",
            description="Evaluates outbound network bytes using short-term velocity divergence against historical baseline anchor.",
            generator=lambda: self.router.build_pipeline_query(
                PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE,
                target_metric="network_bytes_outbound",
                entity_type=EntityType.ASSET,
                anomaly_threshold=3.0,
            ),
            expected_stages=["stage1_extract"],
        )
    )

    matrix.append(
        TestCase(
            test_id="PIPE-11-CIRCADIAN-VON-MISES",
            category="Pipeline Template",
            name="2-Stage Circadian von Mises Temporal Distance Pipeline",
            description="Evaluates hourly authentication attempts against 24-hour circular clock penalizing off-hours deviation.",
            generator=lambda: self.router.build_pipeline_query(
                PipelineArchitecture.CIRCADIAN_VON_MISES_2STAGE,
                target_metric="auth_attempts_total",
                entity_type=EntityType.USER,
                anomaly_threshold=3.0,
            ),
            expected_stages=["stage1_extract"],
        )
    )

    matrix.append(
        TestCase(
            test_id="PIPE-12-MULTI-SECTOR-4STAGE",
            category="Pipeline Template",
            name="4-Stage Multi-Sector Threat Fusion with Fleet Normalization",
            description="Fuses two entity-keyed UDM sector stages (<= 2 UDM limit; default auth fail + network egress by userid) with Stage 3 cross-sectional fleet normalization into a 4-stage rectified norm.",
            generator=lambda: self.router.build_pipeline_query(
                PipelineArchitecture.MULTI_SECTOR_FUSION_4STAGE,
                entity_type=EntityType.USER,
            ),
            expected_stages=["sector_a", "sector_b", "fleet_sector_norm"],
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
            description="Decoupled micro-query evaluating resource read, write, creation, and deletion anomalies.",
            generator=lambda: EntityRadarCollector.USER_SECTOR_QUERIES["Cloud Infrastructure"] % {"entity_id": test_entity} + "\norder: $z desc\n",
            expected_stages=["s1"],
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
        ("ROUTER-09-CUSUM", "network_bytes_outbound", EntityType.ASSET, StatisticalModel.LONGITUDINAL_CUSUM, "Longitudinal CUSUM drift on egress bytes"),
        ("ROUTER-10-HURDLE", "auth_attempts_total", EntityType.USER, StatisticalModel.TWO_PART_HURDLE, "Two-part hurdle model for zero-inflated auth"),
        ("ROUTER-11-ASYMMETRIC-Z", "file_executions_total", EntityType.ASSET, StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z, "Asymmetric directional upper-tail surge on process executions"),
        ("ROUTER-12-PIECEWISE-CRI", "network_bytes_outbound", EntityType.ASSET, StatisticalModel.PIECEWISE_CRI, "Piecewise Winsorized Calibrated Risk Index"),
        ("ROUTER-13-FLEET-SHIELD", "network_bytes_outbound", EntityType.ASSET, StatisticalModel.FLEET_PREVALENCE_SHIELD, "Fleet prevalence concurrency discount shield"),
        ("ROUTER-14-ADAPTIVE-THRESH", "auth_attempts_total", EntityType.USER, StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD, "Adaptive context-modulated sensitivity tightening"),
        ("ROUTER-15-MACD-MOMENTUM", "network_bytes_outbound", EntityType.ASSET, StatisticalModel.MACD_MOMENTUM_VELOCITY, "MACD dual-spine momentum velocity on egress"),
        ("ROUTER-16-CIRCADIAN-VON-MISES", "auth_attempts_total", EntityType.USER, StatisticalModel.CIRCADIAN_VON_MISES, "Circadian von Mises temporal distance on auth"),
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
  def validate_static_invariants(query: str, test_id: str = "ADHOC") -> List[str]:
    """Rigorous offline validation of Malachite YARA-L 2.0 syntax invariants."""
    errors: List[str] = []
    clean_query = _strip_comments(query)

    # 1. Root stage condition blocks are valid in Malachite Common Compiler for hurdle models.
    # Validate section ordering: condition: must precede order:.
    if re.search(r'\border:\s*.*?\bcondition:\s*', clean_query, re.DOTALL):
      errors.append("Illegal section ordering: 'condition:' must precede 'order:' in YARA-L grammar")
    # Validate that outcome blocks do not contain illegal 'if(...)' with compound expressions or missing else.
    for call_text, args in iter_if_calls(clean_query):
      if len(args) < 3:
        errors.append(f"Illegal 'if(...)' expression in query: missing required 'else' clause: {call_text}")
      else:
        for label, branch in (("then", args[1]), ("else", args[2])):
          if if_branch_has_compound_arithmetic(branch):
            errors.append(f"Illegal 'if(...)' expression in query: compound arithmetic in '{label}' clause: {call_text}")

    # 1b. Zero illegal metric_value_sum parameter
    if "metric_value_sum" in clean_query:
      errors.append("Illegal metric type 'metric_value_sum' (must use 'value_sum' for volume metrics or 'event_count_sum' for count metrics)")

    # 2. Zero un-namespaced math functions or math.exp
    if "math.exp" in clean_query:
      errors.append("Illegal function 'math.exp()' (unsupported in YARA-L 2.0)")
    bare_math = re.search(r'(?<!math\.)\b(round|sqrt|pow|abs|log|floor|ceil)\(', clean_query)
    if bare_math:
      fn = bare_math.group(1)
      errors.append(f"Illegal bare '{fn}()' (must use 'math.{fn}()')")

    # 3. Zero unsupported aggregation functions (e.g. bare variance, count(if))
    if re.search(r'(?<!window\.)\bvariance\(', clean_query):
      errors.append("Illegal aggregation function 'variance()' (must use 'window.variance()' or stddev() squared)")
    if re.search(r'\bcount\s*\(\s*if\s*\(', clean_query, re.IGNORECASE):
      errors.append("Illegal aggregation function 'count(if(...))' (must use 'sum(if(condition, 1, 0))' for conditional counting)")
    if re.search(r'=\s*\/[^\/\n]+\/\s*\|\s*\/', clean_query):
      errors.append("Illegal regex alternation '|' outside regex literal delimiters (combine into single regex '/(p1|p2)/ nocase')")

    # 4. Zero dummy placeholder variables in match
    if "$day_bucket" in clean_query or "$hour_bucket" in clean_query:
      errors.append("Illegal dummy bucket variable ($day_bucket/$hour_bucket) present")

    # 5. Valid stage names (no $ prefix on stage declaration)
    stage_declarations = re.findall(r'stage\s+([^\s\{]+)\s*\{', clean_query)
    for sname in stage_declarations:
      if sname.startswith("$"):
        errors.append(f"Illegal stage declaration '{sname}' starting with '$'")

    # 6. Outcome variable count ceiling (<= 20 outcome variables per stage) and literal array rejection
    outcome_blocks = re.findall(r'outcome:\s*\n((?:[ \t]*\$[^\n]+\n|[ \t]*//[^\n]*\n|\s*\n)*)', query)
    for idx, oblock in enumerate(outcome_blocks):
      clean_oblock = re.sub(r"//[^\n]*", "", oblock)
      clean_oblock = re.sub(r"/\*.*?\*/", "", clean_oblock, flags=re.DOTALL)
      if re.search(r"\[\s*[^\]]*\s*\]", clean_oblock):
        errors.append(f"Outcome block {idx} contains illegal literal array notation '[...]' (unsupported in outcome expressions)")
      vars_in_outcome = re.findall(r'^\s*(\$[a-zA-Z0-9_]+)\s*=', oblock, re.MULTILINE)
      if len(vars_in_outcome) > 20:
        errors.append(f"Outcome block {idx} exceeds SecOps limit of 20 variables ({len(vars_in_outcome)})")

    # 7. Join limits: total joins <= 4; raw extraction stages <= 2
    extracted_stages = _extract_named_stage_blocks(query)
    stage_blocks = [sb for _, sb in extracted_stages]
    raw_event_stages = [sb for sb in stage_blocks if "metadata.event_type" in sb]
    if len(raw_event_stages) > 2:
      errors.append(f"Exceeds Chronicle UDM search limit of at most 2 raw event extraction stages ({len(raw_event_stages)})")

    # 8. Unrendered template placeholders
    if "{{" in query or "}}" in query:
      placeholders = re.findall(r'\{\{([^}]+)\}\}', query)
      errors.append(f"Unrendered template placeholders detected: {placeholders}")

    # 8b. Stage references, match stage prefixes, outcome conditionals/divisions, Stage 1 zero filters, ECG invariants
    errors.extend(check_stage_references(query))
    errors.extend(check_root_match_stage_prefix(query))
    errors.extend(check_outcome_conditionals_and_divisions(query))
    errors.extend(check_Stage_1_zero_filters(query))
    errors.extend(check_ecg_invariants(query))

    # 9. Statistical Antipattern Audit (Core Statistical Invariants)
    stat_violations = StatisticalAntipatternAuditor.audit_query(query)
    for sv in stat_violations:
      errors.append(f"[{sv.antipattern.value}] stage '{sv.stage_name}': {sv.description}")

    # 10. Malachite AST Invariants & Compiler Grammar
    ast_errors = MalachiteASTValidator.validate_query(query)
    for ae in ast_errors:
      if ae not in errors:
        errors.append(f"[MalachiteASTValidator] {ae}")

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

      # No Chronicle client here: never report a live result that was not run.
      live_attempted = False
      live_passed = False
      live_error = None

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

  check_stage_references = staticmethod(check_stage_references)
  check_root_match_stage_prefix = staticmethod(check_root_match_stage_prefix)
  check_outcome_conditionals_and_divisions = staticmethod(check_outcome_conditionals_and_divisions)
  check_Stage_1_zero_filters = staticmethod(check_Stage_1_zero_filters)
  check_stage_1_zero_filters = staticmethod(check_Stage_1_zero_filters)
  check_ecg_invariants = staticmethod(check_ecg_invariants)

  def validate_template_fragments(self) -> List[str]:
    """Validates templates/stage1_extractors/*.yl2 and templates/stage2_math_models/*.yl2 fragments."""
    frag_errors: List[str] = []
    s1_dir = self.skill_root / "templates" / "stage1_extractors"
    s2_dir = self.skill_root / "templates" / "stage2_math_models"
    allowed_s2_slots = {
        "min_baseline_days",
        "anomaly_threshold",
        "fold_change_threshold",
        "robust_threshold",
        "first_scored_date",
    }
    for p in sorted(s1_dir.glob("*.yl2")):
      raw = p.read_text(encoding="utf-8")
      if "stage stage1_extract" not in raw:
        frag_errors.append(f"{p.name}: missing stage stage1_extract declaration")
      frag_errors.extend(f"{p.name}: {e}" for e in check_root_match_stage_prefix(raw))
      frag_errors.extend(f"{p.name}: {e}" for e in check_outcome_conditionals_and_divisions(raw))
      frag_errors.extend(f"{p.name}: {e}" for e in check_Stage_1_zero_filters(raw))
    for p in sorted(s2_dir.glob("*.yl2")):
      raw = p.read_text(encoding="utf-8")
      clean = _strip_comments(raw)
      slots = set(re.findall(r"\{\{([^}]+)\}\}", clean))
      unexpected = slots - allowed_s2_slots
      if unexpected:
        frag_errors.append(f"{p.name}: unexpected template placeholders {sorted(unexpected)}")
      frag_errors.extend(f"{p.name}: {e}" for e in check_root_match_stage_prefix(raw))
      frag_errors.extend(f"{p.name}: {e}" for e in check_outcome_conditionals_and_divisions(raw))
    return frag_errors

  def run_all_tests(self) -> bool:
    """Runs all canonical matrix tests plus stage1/stage2 template fragment checks."""
    results = self.run_suite()
    frag_errors = self.validate_template_fragments()
    return all(r.static_passed for r in results) and len(frag_errors) == 0


def validate_template_fragments(skill_root: Optional[Path] = None) -> List[str]:
  """Module-level entry point to validate stage1 and stage2 template fragments."""
  suite = SubmissionTestSuite(skill_root=skill_root)
  return suite.validate_template_fragments()


def run_all_tests(skill_root: Optional[Path] = None) -> bool:
  """Module-level entry point to run all submission and template fragment tests."""
  suite = SubmissionTestSuite(skill_root=skill_root)
  return suite.run_all_tests()


def main():
  parser = argparse.ArgumentParser(description="Multi-Stage YARA-L Submission Test Harness")
  parser.add_argument(
      "--live", action="store_true",
      help="Not implemented: sends nothing to Chronicle; results are static only (use --dump-dir and udm_search)")
  parser.add_argument("--filter", type=str, help="Filter test cases by ID or substring")
  parser.add_argument("--json", action="store_true", help="Output results as JSON")
  parser.add_argument("--dump-dir", type=str, help="Directory to export rendered .yl2 queries")
  parser.add_argument("--customer-id", default=SubmissionTestSuite.DEFAULT_CUSTOMER_ID)
  parser.add_argument("--project-id", default=SubmissionTestSuite.DEFAULT_PROJECT_ID)
  parser.add_argument("--region", default=SubmissionTestSuite.DEFAULT_REGION)

  args = parser.parse_args()

  if args.live:
    print("NOTE: --live is not implemented; no query is sent to Chronicle. "
          "Export with --dump-dir and run the files through udm_search.", file=sys.stderr)

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

validate_static_invariants = SubmissionTestSuite.validate_static_invariants
