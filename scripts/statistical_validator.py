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

"""Statistical Antipattern Auditor for Google SecOps Multi-Stage Risk Metrics Queries.

Performs static AST inspection of YARA-L 2.0 queries to detect statistical antipatterns
against the pre-computed risk metrics library:
1. STAT_ANTIPATTERN_SCOPE_ASYMMETRY: Part-of-the-Whole fallacy (filtering observed events
   narrower than metric indexing dimensions, causing severe negative Z-score bias).
2. STAT_ANTIPATTERN_DYNAMIC_RANGE_MASKING: "Elephant and Mouse" aggregation across disparate
   destinations without local-baseline resource isolation.
3. STAT_ANTIPATTERN_ZERO_DISPERSION_HAZARD: Division by standard deviation or MAD without
   a non-zero dispersion floor or guard (e.g. if(sigma > 0, sigma, 1.0)).
4. STAT_ANTIPATTERN_DISTRIBUTION_MISMATCH: Evaluating discrete rare events with continuous
   Gaussian models without active baseline days gating (N >= 3) or Poisson rarity.
5. STAT_ANTIPATTERN_COLLINEAR_VECTOR_FUSION: Fusing collinear vectors from the same telemetry
   silo under orthogonal Euclidean threat distance norms (D = sqrt(sum max(0,Z)^2)).
"""

from dataclasses import dataclass
from enum import Enum
import re
from typing import Dict, List, Optional, Set, Tuple


class StatisticalAntipatternType(str, Enum):
  SCOPE_ASYMMETRY = "STAT_ANTIPATTERN_SCOPE_ASYMMETRY"
  DYNAMIC_RANGE_MASKING = "STAT_ANTIPATTERN_DYNAMIC_RANGE_MASKING"
  ZERO_DISPERSION_HAZARD = "STAT_ANTIPATTERN_ZERO_DISPERSION_HAZARD"
  DISTRIBUTION_MISMATCH = "STAT_ANTIPATTERN_DISTRIBUTION_MISMATCH"
  COLLINEAR_VECTOR_FUSION = "STAT_ANTIPATTERN_COLLINEAR_VECTOR_FUSION"
  UNPROFILED_SERVICE_ACCOUNT = "STAT_ANTIPATTERN_UNPROFILED_SERVICE_ACCOUNT"
  MONOLITHIC_RADAR_JOIN = "STAT_ANTIPATTERN_MONOLITHIC_RADAR_JOIN"
  WALL_CLOCK_TIME_DRIFT = "STAT_ANTIPATTERN_WALL_CLOCK_TIME_DRIFT"
  UNANCHORED_DERIVED_CONTEXT_PREVALENCE = "STAT_ANTIPATTERN_UNANCHORED_DERIVED_CONTEXT_PREVALENCE"
  UNRECTIFIED_SQUARED_Z_FUSION = "STAT_ANTIPATTERN_UNRECTIFIED_SQUARED_Z_FUSION"
  HARDCODED_DORMANT_Z_PROXY = "STAT_ANTIPATTERN_HARDCODED_DORMANT_Z_PROXY"


@dataclass
class StatisticalViolation:
  antipattern: StatisticalAntipatternType
  stage_name: str
  description: str
  remediation: str


class StatisticalAntipatternAuditor:
  """Inspects multi-stage YARA-L 2.0 queries for statistical antipatterns."""

  # Telemetry vector families for orthogonality checking in multi-sector fusion
  METRIC_FAMILIES: Dict[str, str] = {
      # Authentication & IAM
      "auth_attempts_success": "AUTH",
      "auth_attempts_fail": "AUTH",
      "auth_attempts_total": "AUTH",
      # Cloud CRUD
      "resource_creation_total": "CLOUD_CRUD",
      "resource_deletion_total": "CLOUD_CRUD",
      "resource_read_total": "CLOUD_CRUD",
      "resource_written_total": "CLOUD_CRUD",
      # Google Workspace & SaaS
      "workspace_emails_sent_total": "WORKSPACE",
      "workspace_network_bytes_outbound": "WORKSPACE",
      "workspace_network_bytes_total": "WORKSPACE",
      "workspace_total_change_actions": "WORKSPACE",
      "workspace_total_download_actions": "WORKSPACE",
      # Network Egress, Web & DNS (distinct sectors per metric-sector-catalog)
      "network_bytes_inbound": "NETWORK",
      "network_bytes_outbound": "NETWORK",
      "network_bytes_total": "NETWORK",
      "network_flows_inbound": "NETWORK",
      "network_flows_outbound": "NETWORK",
      "network_flows_total": "NETWORK",
      "http_queries_total": "WEB",
      "http_queries_success": "WEB",
      "http_queries_fail": "WEB",
      "dns_queries_total": "DNS",
      "dns_queries_success": "DNS",
      "dns_queries_fail": "DNS",
      "dns_bytes_outbound": "DNS",
      # Endpoint & Process
      "file_executions_total": "ENDPOINT",
  }

  # Discrete low-frequency count metrics that require Poisson rarity or sample-size gating
  DISCRETE_COUNT_METRICS: Set[str] = {
      "auth_attempts_fail",
      "resource_deletion_total",
  }

  @classmethod
  def _strip_comments(cls, query: str) -> str:
    """Strips /* ... */ block comments and // line comments from YARA-L text."""
    no_block = re.sub(r"/\*.*?\*/", "", query, flags=re.DOTALL)
    return "\n".join(re.sub(r"//[^\n]*", "", ln) for ln in no_block.splitlines())

  @classmethod
  def audit_query(cls, query_text: str) -> List[StatisticalViolation]:
    """Audits a multi-stage YARA-L 2.0 query for all statistical antipatterns."""
    violations: List[StatisticalViolation] = []
    clean_query = cls._strip_comments(query_text)

    # Parse stages using balanced brace counting
    stages = cls._extract_stages(clean_query)
    root_stage_body = cls._extract_root_stage(clean_query)

    # Check each named stage
    for stage_name, stage_body in stages.items():
      # 1. Scope Asymmetry (Part-of-the-Whole Fallacy)
      violations.extend(cls._check_scope_asymmetry(stage_name, stage_body))

      # 2. Dynamic Range Masking ("Elephant and Mouse")
      violations.extend(cls._check_dynamic_range_masking(stage_name, stage_body))

      # 3. Zero Dispersion Hazard
      violations.extend(cls._check_zero_dispersion_hazard(stage_name, stage_body))

      # 4. Distribution Domain Mismatch
      violations.extend(cls._check_distribution_mismatch(stage_name, stage_body))

      # 5. Unprofiled Service Account Identity Construction
      violations.extend(cls._check_unprofiled_service_account(stage_name, stage_body))

      # 6. Wall-Clock Time Drift (non-deterministic timestamp.current_seconds())
      violations.extend(cls._check_wall_clock_time_drift(stage_name, stage_body))

      # 7. Unanchored DERIVED_CONTEXT Prevalence
      violations.extend(cls._check_unanchored_derived_context_prevalence(stage_name, stage_body))

      # 8. Hardcoded 10.0 Dormant Z-Score Proxy
      violations.extend(cls._check_hardcoded_dormant_z_proxy(stage_name, stage_body))

    # Check Root Stage
    if root_stage_body:
      violations.extend(cls._check_zero_dispersion_hazard("root", root_stage_body))
      violations.extend(cls._check_collinear_vector_fusion(root_stage_body, stages))
      violations.extend(cls._check_monolithic_radar_join(root_stage_body, stages))
      violations.extend(cls._check_wall_clock_time_drift("root", root_stage_body))
      violations.extend(cls._check_unanchored_derived_context_prevalence("root", root_stage_body))
      violations.extend(cls._check_hardcoded_dormant_z_proxy("root", root_stage_body))
    elif len(stages) > 4:
      violations.extend(cls._check_monolithic_radar_join("", stages))

    violations.extend(cls._check_unrectified_squared_z_fusion(root_stage_body, stages, clean_query))
    return violations

  @classmethod
  def _extract_stages(cls, query: str) -> Dict[str, str]:
    stages: Dict[str, str] = {}
    for m in re.finditer(r"\bstage\s+([a-zA-Z0-9_]+)\s*\{", query):
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
        stages[stage_name] = query[start_idx : pos - 1]
    return stages

  @classmethod
  def _extract_root_stage(cls, query: str) -> str:
    last_stage_end = 0
    for m in re.finditer(r"\bstage\s+[a-zA-Z0-9_]+\s*\{", query):
      pos = m.end()
      depth = 1
      while pos < len(query) and depth > 0:
        if query[pos] == "{":
          depth += 1
        elif query[pos] == "}":
          depth -= 1
        pos += 1
      if depth == 0:
        last_stage_end = max(last_stage_end, pos)
    return query[last_stage_end:].strip()

  @classmethod
  def _check_scope_asymmetry(cls, stage_name: str, stage_body: str) -> List[StatisticalViolation]:
    """Detects filtering observed events narrower than the metric baseline indexing dimensions."""
    violations: List[StatisticalViolation] = []

    metrics_calls = re.findall(r"metrics\.([a-zA-Z0-9_]+)\s*\(([^)]+)\)", stage_body, re.DOTALL)
    if not metrics_calls:
      return violations

    # Check A: External threat context inside metrics stage (GLOBAL_CONTEXT / DERIVED_CONTEXT)
    if '"GLOBAL_CONTEXT"' in stage_body or '"DERIVED_CONTEXT"' in stage_body:
      violations.append(
          StatisticalViolation(
              antipattern=StatisticalAntipatternType.SCOPE_ASYMMETRY,
              stage_name=stage_name,
              description=(
                  f"Stage '{stage_name}' filters on external threat intelligence context (GLOBAL_CONTEXT/DERIVED_CONTEXT) "
                  "while evaluating universal metrics.* baselines. Observed volume (X_threat) will be smaller than "
                  "aggregate baseline mean (mu_total), producing severe negative Z-score bias."
              ),
              remediation=(
                  "Decouple into 2 stages: Stage 1 evaluates universal metrics.* baseline; Stage 2 evaluates external "
                  "threat context; Root stage joins on entity and multiplies score: Threat = Z_total * (N_threat + 1)."
              ),
          )
      )

    # Check B: Hardcoded product/vendor filter while metric does not bind product
    for metric_name, args_body in metrics_calls:
      if metric_name.startswith("workspace_"):
        continue
      product_filter_match = re.search(r"metadata\.product_name\s*==?\s*[\"']([^\"']+)[\"']", stage_body)
      if product_filter_match:
        hardcoded_product = product_filter_match.group(1)
        if f'metadata.product_name: "{hardcoded_product}"' not in args_body:
          if "metadata.product_name" not in args_body:
            violations.append(
                StatisticalViolation(
                    antipattern=StatisticalAntipatternType.SCOPE_ASYMMETRY,
                    stage_name=stage_name,
                    description=(
                        f"Stage '{stage_name}' filters observed events to specific product '{hardcoded_product}' "
                        f"but metric 'metrics.{metric_name}' is not scoped to that product. "
                        "Observed subset reads will be compared against aggregate baseline, causing false negatives."
                    ),
                    remediation=(
                        "Slice dynamically by ($sa, $vendor, $product, $resource by 1d) or ensure the metric function "
                        f"explicitly passes metadata.product_name: '{hardcoded_product}'."
                    ),
                )
            )

    return violations

  @classmethod
  def _check_dynamic_range_masking(cls, stage_name: str, stage_body: str) -> List[StatisticalViolation]:
    """Detects multi-resource access evaluated without local-baseline resource isolation."""
    violations: List[StatisticalViolation] = []

    resource_store_metrics = [
        "metrics.resource_read_total",
        "metrics.resource_written_total",
        "metrics.resource_written_success",
        "metrics.resource_written_fail",
    ]
    matched_metrics = [m for m in resource_store_metrics if m in stage_body]
    if not matched_metrics:
      has_legacy_metric = any(
          m in stage_body
          for m in ["metrics.resource_creation_total", "metrics.resource_deletion_total"]
      )
      if not has_legacy_metric:
        return violations

    match_block = re.search(r"\bmatch:\s*(.*?)(?=\b(?:outcome|condition|order)\s*:|\}|$|\Z)", stage_body, re.DOTALL)
    if not match_block:
      return violations

    match_content = match_block.group(1)
    event_section = stage_body[:match_block.start()]

    has_account_entity = any(
        term in match_content
        for term in ["$user", "$sa", "$account", "$principal", "principal.user.userid"]
    ) or any(
        re.search(rf"\b{re.escape(var)}\b", match_content)
        for var in re.findall(r"(\$[a-zA-Z0-9_]+)\s*=\s*principal\.user\.userid", event_section)
    )

    res_var_match = re.search(r"(\$[a-zA-Z0-9_]+)\s*=\s*target\.resource\.name", event_section)
    res_var = res_var_match.group(1) if res_var_match else "$resource"

    has_resource_in_match = res_var in match_content or "target.resource.name" in match_content
    is_unified_cloud_crud_radar_spoke = (
        "metrics.resource_creation_total" in stage_body
        and "metrics.resource_deletion_total" in stage_body
        and "target.resource.name" not in stage_body
    )

    if matched_metrics and has_account_entity and not has_resource_in_match and not is_unified_cloud_crud_radar_spoke:
      violations.append(
          StatisticalViolation(
              antipattern=StatisticalAntipatternType.DYNAMIC_RANGE_MASKING,
              stage_name=stage_name,
              description=(
                  f"Stage '{stage_name}' queries cloud data store metric '{matched_metrics[0]}' for an account, "
                  f"but match section '{match_content.strip()}' omits resource variable '{res_var}'. Aggregating "
                  "all repositories under an account-level baseline allows high-volume routine resources (the 'Elephant') "
                  "to mask acute exfiltration dumps on sensitive databases (the 'Mouse')."
              ),
              remediation=(
                  f"Bind '{res_var} = target.resource.name' and include in match: 'match: $sa, $vendor, $product, {res_var}, $ip by 1d' "
                  "to implement Local-Baseline Isolation (as implemented in templates/pipelines/cloud_repository_scope_dual_branch.yl2)."
              ),
          )
      )
    elif ("target.resource.name" in event_section or "$resource" in event_section) and not has_resource_in_match:
      violations.append(
          StatisticalViolation(
              antipattern=StatisticalAntipatternType.DYNAMIC_RANGE_MASKING,
              stage_name=stage_name,
              description=(
                  f"Stage '{stage_name}' queries multi-resource targets but match section '{match_content.strip()}' "
                  f"omits resource variable '{res_var}'. Aggregating all resources under an account-level baseline "
                  "allows high-volume routine resources (the 'Elephant') to mask acute exfiltration dumps on sensitive databases (the 'Mouse')."
              ),
              remediation=(
                  f"Include '{res_var}' in match key: 'match: $user, {res_var} by 1d' to implement Local-Baseline Isolation "
                  "(as implemented in templates/pipelines/cloud_repository_scope_dual_branch.yl2)."
              ),
          )
      )

    return violations

  @classmethod
  def _check_zero_dispersion_hazard(cls, stage_name: str, stage_body: str) -> List[StatisticalViolation]:
    """Detects division by standard deviation or MAD without an additive dispersion floor."""
    violations: List[StatisticalViolation] = []

    outcome_block = re.search(r"\boutcome:\s*(.*?)(?=\b(?:condition|order)\s*:|\}|$|\Z)", stage_body, re.DOTALL)
    if not outcome_block:
      return violations

    outcome_content = outcome_block.group(1)

    for raw_line in outcome_content.splitlines():
      assign_m = re.match(r"\s*(\$[a-zA-Z0-9_]+)\s*=\s*(.+)$", raw_line)
      if not assign_m:
        continue
      lhs_var = assign_m.group(1)
      rhs_expr = assign_m.group(2).strip()
      if "/" not in rhs_expr or lhs_var.lower().startswith("$beta"):
        continue

      # Inspect both the full denominator expression and every / $denom token on the line
      denom_candidates: List[str] = []
      first_slash = rhs_expr.find("/")
      if first_slash != -1:
        denom_candidates.append(rhs_expr[first_slash + 1 :].strip())
      for dm in re.finditer(r"/\s*(\$[a-zA-Z0-9_.]+|\([^)]+\)|if\s*\([^)]+\)|max\s*\([^)]+\))", rhs_expr):
        cand = dm.group(1).strip()
        if cand not in denom_candidates:
          denom_candidates.append(cand)

      is_z_or_score = any(kw in lhs_var.lower() for kw in ["z", "score", "rate", "outlier", "quotient"]) or any(
          kw in rhs_expr.lower() for kw in ["diff", "obs", "observed", "count"]
      )
      for denom in denom_candidates:
        is_dispersion_denom = any(kw in denom.lower() for kw in ["sigma", "std", "mad", "stddev", "$sd", "_sd"])
        if is_z_or_score and is_dispersion_denom:
          has_dispersion_floor = bool(
              re.search(r"if\s*\(", denom)
              or re.search(r"\+\s*(?:[1-9][0-9]*(?:\.[0-9]*)?|0\.[0-9]*[1-9][0-9]*)", denom)
              or re.search(r"max\s*\([^,]+,\s*(?:[1-9][0-9]*(?:\.[0-9]*)?|0\.[0-9]*[1-9][0-9]*)\)", denom)
              or "safe" in denom.lower()
              or re.search(rf"\${re.escape(denom.lstrip('$'))}\s*=\s*if\s*\(", stage_body)
          )
          if not has_dispersion_floor:
            violations.append(
                StatisticalViolation(
                    antipattern=StatisticalAntipatternType.ZERO_DISPERSION_HAZARD,
                    stage_name=stage_name,
                    description=(
                        f"Stage '{stage_name}' outcome variable '{lhs_var}' divides by dispersion denominator '{denom}' "
                        "without a non-zero dispersion floor or guard. On quiet accounts with zero historical variance (sigma = 0), "
                        "this triggers division by zero, yielding NaN, Infinity, or backend query abortion."
                    ),
                    remediation=f"Apply zero-variance protection: 'if({denom} > 0, {denom}, 1.0)' or an intermediate safe floor variable.",
                )
            )
            break

    return violations

  @classmethod
  def _check_distribution_mismatch(cls, stage_name: str, stage_body: str) -> List[StatisticalViolation]:
    """Detects applying continuous Gaussian models to discrete rare events without sample size gating."""
    violations: List[StatisticalViolation] = []

    discrete_metric_found = None
    for m in cls.DISCRETE_COUNT_METRICS:
      if f"metrics.{m}" in stage_body:
        discrete_metric_found = m
        break

    if not discrete_metric_found:
      return violations

    outcome_block = re.search(r"\boutcome:\s*(.*?)(?=\b(?:condition|order)\s*:|\}|$|\Z)", stage_body, re.DOTALL)
    if not outcome_block:
      return violations

    outcome_text = outcome_block.group(1)
    has_continuous_z = bool(re.search(r"(\$[a-zA-Z0-9_]*z[a-zA-Z0-9_]*)\s*=", outcome_text, re.IGNORECASE))

    if has_continuous_z:
      is_sibling_triad_with_poisson_floor = (
          "$m1_obs" in outcome_text
          and "$m2_obs" in outcome_text
          and "$m3_obs" in outcome_text
          and "math.sqrt(" in outcome_text
      )
      has_sample_gate = bool(
          "num_metric_periods" in stage_body or
          "min_baseline_days" in stage_body or
          "active_days" in stage_body or
          "poisson" in stage_body.lower() or
          "fano" in stage_body.lower() or
          "beta_binomial" in stage_body.lower() or
          is_sibling_triad_with_poisson_floor
      )
      if not has_sample_gate:
        violations.append(
            StatisticalViolation(
                antipattern=StatisticalAntipatternType.DISTRIBUTION_MISMATCH,
                stage_name=stage_name,
                description=(
                    f"Stage '{stage_name}' applies continuous Gaussian Z-score to discrete rare count metric "
                    f"'metrics.{discrete_metric_found}' without active baseline days gating (N >= 3) or Poisson rarity modeling. "
                    "Sparse accounts with mean << 1.0 will trigger severe false positives on single isolated events."
                ),
                remediation=(
                    "Gate on minimum active baseline days (num_metric_periods >= 3) or route discrete counts to "
                    "Poisson rarity model (templates/stage2_math_models/poisson_rarity.yl2)."
                ),
            )
        )

    return violations

  @classmethod
  def _check_collinear_vector_fusion(
      cls, root_body: str, stages: Dict[str, str]
  ) -> List[StatisticalViolation]:
    """Detects fusing collinear metrics from the same telemetry family under Euclidean distance norms."""
    violations: List[StatisticalViolation] = []

    fused_stages = set(re.findall(r"\$([a-zA-Z0-9_]+)\.[zZ][a-zA-Z0-9_]*", root_body))
    if len(fused_stages) < 2:
      return violations

    has_euclidean_fusion = bool(
        re.search(r"(\$[a-zA-Z0-9_]*norm[a-zA-Z0-9_]*|\$[a-zA-Z0-9_]*distance[a-zA-Z0-9_]*|\$[a-zA-Z0-9_]*d_sq|\$[a-zA-Z0-9_]*composite[a-zA-Z0-9_]*)\s*=", root_body, re.IGNORECASE)
    )
    if not has_euclidean_fusion:
      return violations

    stage_families: Dict[str, str] = {}
    for sname in fused_stages:
      if sname in stages:
        sbody = stages[sname]
        for m_name, fam in cls.METRIC_FAMILIES.items():
          if f"metrics.{m_name}" in sbody:
            stage_families[sname] = fam
            break

    family_counts: Dict[str, List[str]] = {}
    for sname, fam in stage_families.items():
      family_counts.setdefault(fam, []).append(sname)

    for fam, colliding_stages in family_counts.items():
      if len(colliding_stages) > 1:
        violations.append(
            StatisticalViolation(
                antipattern=StatisticalAntipatternType.COLLINEAR_VECTOR_FUSION,
                stage_name="root",
                description=(
                    f"Root stage fuses multiple stages ({colliding_stages}) belonging to the same telemetry family "
                    f"'{fam}' into an orthogonal Euclidean threat norm. Combining collinear vectors double-counts "
                    "variance and artificially inflates composite threat distance D by sqrt(2)."
                ),
                remediation=(
                    "Ensure Euclidean norm D fuses strictly orthogonal vectors (Auth + Cloud CRUD + Workspace + Network + Endpoint), "
                    "or combine intra-family metrics into a single sector score prior to multi-sector fusion."
                ),
            )
        )

    return violations

  @classmethod
  def _check_unprofiled_service_account(cls, stage_name: str, stage_body: str) -> List[StatisticalViolation]:
    """Detects service account querying without identity pattern profiling (allowing machine/OS accounts)."""
    violations: List[StatisticalViolation] = []

    # Check if this stage defines a service account variable
    sa_match = re.search(r"(?:\A|\s)(\$sa|\$service_account)\b\s*=\s*principal\.user\.userid\b", stage_body)
    if not sa_match:
      return violations

    sa_var = sa_match.group(1)

    # Check if the stage contains identity profiling (e.g. gserviceaccount, arn:aws, regex)
    has_identity_profile = any([
        "gserviceaccount" in stage_body,
        "arn:aws" in stage_body,
        "re.regex" in stage_body and sa_var in stage_body,
        "re.capture" in stage_body and sa_var in stage_body,
        bool(re.search(rf"{re.escape(sa_var)}\s*=\s*/[^/]+/", stage_body)),
        bool(re.search(rf"/{re.escape(sa_var)}/", stage_body)),
    ])

    if not has_identity_profile:
      violations.append(
          StatisticalViolation(
              antipattern=StatisticalAntipatternType.UNPROFILED_SERVICE_ACCOUNT,
              stage_name=stage_name,
              description=(
                  f"Stage '{stage_name}' binds service account variable '{sa_var}' but relies solely on null guards "
                  f"without identity pattern profiling. This allows Windows Active Directory computer accounts ($) "
                  "and local OS accounts (LOCAL SERVICE) to pollute cloud repository analytics."
              ),
              remediation=(
                  f"Enforce cloud service account identity construction: '({sa_var} = /@.*gserviceaccount\\.com$/ nocase "
                  f"or {sa_var} = /^arn:aws:(iam|sts)::/ nocase)'. "
                  "Profile what follows after the '@' symbol to anchor cloud domain and project boundaries."
              ),
          )
      )

    return violations

  @classmethod
  def _check_monolithic_radar_join(
      cls, root_body: str, stages: Dict[str, str]
  ) -> List[StatisticalViolation]:
    """Detects monolithic multi-sector inner joins (exceeding join limits or fusing >=3 disparate sectors)."""
    violations: List[StatisticalViolation] = []

    # Chronicle SIEM strictly enforces maxJoinCount = 4. More than 4 stages joined causes compiler error.
    if len(stages) > 4:
      violations.append(
          StatisticalViolation(
              antipattern=StatisticalAntipatternType.MONOLITHIC_RADAR_JOIN,
              stage_name="root",
              description=(
                  f"Query defines {len(stages)} stages in a single YARA-L rule. Chronicle SIEM enforces a hard limit "
                  "of maxJoinCount = 4 (maximum 4 joins across 4 stages). Queries with > 4 stages fail compilation."
              ),
              remediation=(
                  "Decouple 360° Risk Radar into independent sector micro-queries (<= 1 sector per query, or invoke "
                  "scripts/radar_collector.py). Evaluate sectors independently to prevent monolithic join compilation failures."
              ),
          )
      )
      return violations

    if not root_body:
      return violations

    # Check for joining >= 3 stages across disparate telemetry families in root
    joined_stages = set(re.findall(r"\$([a-zA-Z0-9_]+)\.[a-zA-Z0-9_]+", root_body))
    if len(joined_stages) < 3:
      return violations

    families: Set[str] = set()
    for sname in joined_stages:
      if sname in stages:
        sbody = stages[sname]
        for m_name, fam in cls.METRIC_FAMILIES.items():
          if f"metrics.{m_name}" in sbody:
            families.add(fam)
            break

    if len(families) >= 3:
      violations.append(
          StatisticalViolation(
              antipattern=StatisticalAntipatternType.MONOLITHIC_RADAR_JOIN,
              stage_name="root",
              description=(
                  f"Root stage joins stages across {len(families)} disparate telemetry families ({', '.join(sorted(families))}) "
                  "into a single inner join. In Chronicle SIEM, multi-stage joins are strict INNER JOINS. If the entity has zero "
                  "events in even one sector on the evaluation date, the entire join drops to 0 rows (Silent Inner-Join Drop)."
              ),
              remediation=(
                  "Decouple 360° Risk Radar into independent sector micro-queries (<= 1 sector per query, or invoke "
                  "scripts/radar_collector.py). Evaluate each sector independently with graceful nominal fallback (Z=0.00σ, CRI=0)."
              ),
          )
      )

    return violations

  @classmethod
  def _check_wall_clock_time_drift(cls, stage_name: str, stage_body: str) -> List[StatisticalViolation]:
    """Detects usage of timestamp.current_seconds() which produces non-deterministic execution drift."""
    violations: List[StatisticalViolation] = []
    clean_body = re.sub(r"//[^\n]*", "", stage_body)
    clean_body = re.sub(r"/\*.*?\*/", "", clean_body, flags=re.DOTALL)
    if "timestamp.current_seconds()" in clean_body:
      violations.append(
          StatisticalViolation(
              antipattern=StatisticalAntipatternType.WALL_CLOCK_TIME_DRIFT,
              stage_name=stage_name,
              description=(
                  f"Stage '{stage_name}' invokes 'timestamp.current_seconds()' to calculate delta time or age against historical data. "
                  "This introduces wall-clock execution time drift, producing non-deterministic outcomes across test replays or batch scans."
              ),
              remediation=(
                  "Anchor time calculations to observed event telemetry: extract '$event_timestamp = max(metadata.event_timestamp.seconds)' "
                  "in Stage 1 and compute recency via '($obs_ts - $reference_time) / 86400.0' in downstream stages."
              ),
          )
      )
    return violations


  @classmethod
  def _check_unanchored_derived_context_prevalence(
      cls, stage_name: str, stage_body: str
  ) -> List[StatisticalViolation]:
    """Detects DERIVED_CONTEXT prevalence usage without the mandatory day_count = 10 anchor."""
    violations: List[StatisticalViolation] = []
    if "DERIVED_CONTEXT" in stage_body and ".prevalence." in stage_body:
      if not re.search(r"\.prevalence\.day_count\s*=\s*10\b", stage_body):
        violations.append(
            StatisticalViolation(
                antipattern=StatisticalAntipatternType.UNANCHORED_DERIVED_CONTEXT_PREVALENCE,
                stage_name=stage_name,
                description=(
                    f"Stage '{stage_name}' queries DERIVED_CONTEXT prevalence without anchoring "
                    "'.prevalence.day_count = 10'. Chronicle SIEM only populates DERIVED_CONTEXT prevalence "
                    "buckets at day_count = 10; omitting or altering this filter yields 0 rows or multi-bucket duplication."
                ),
                remediation="Add explicit filter: '$graph.graph.entity.<type>.prevalence.day_count = 10'.",
            )
        )
    return violations

  @classmethod
  def _check_hardcoded_dormant_z_proxy(
      cls, stage_name: str, stage_body: str
  ) -> List[StatisticalViolation]:
    """Detects hardcoded 10.0 Z-score proxies for dormant/cold-start entities."""
    violations: List[StatisticalViolation] = []
    pattern = re.compile(
        r"if\s*\(\s*\$[a-zA-Z0-9_.]*(?:active_days|baseline_days|days|num_metric_periods|hist_avg|historical_avg|mean|stddev|sigma|sd)[a-zA-Z0-9_.]*\s*(?:=|==|<=|<)\s*[0-9.]+\s*,\s*10(?:\.0+)?\b",
        re.IGNORECASE,
    )
    if pattern.search(stage_body):
      violations.append(
          StatisticalViolation(
              antipattern=StatisticalAntipatternType.HARDCODED_DORMANT_Z_PROXY,
              stage_name=stage_name,
              description=(
                  f"Stage '{stage_name}' substitutes a hardcoded '10.0' Z-score proxy for dormant or zero-baseline entities. "
                  "Flat constant proxies destroy volume ranking among cold-start breakouts."
              ),
              remediation="Use the Two-Part Hurdle formulation ($dormant_score = $observed * 2.0 or 10.0 + math.log($observed + 1.0)).",
          )
      )
    return violations

  @classmethod
  def _check_unrectified_squared_z_fusion(
      cls, root_body: str, stages: Dict[str, str], full_query: str
  ) -> List[StatisticalViolation]:
    """Detects squaring unrectified Z-scores in multi-sector Euclidean threat fusion."""
    violations: List[StatisticalViolation] = []
    target_text = root_body if root_body else full_query
    has_fusion_norm = bool(
        re.search(
            r"\$(?:composite_threat_norm_sq|composite_threat_norm|threat_distance_sq|d_sq|threat_norm|threat_distance|norm)\s*=",
            target_text,
            re.IGNORECASE,
        )
    )
    if not has_fusion_norm:
      return violations
    has_squaring = bool(
        re.search(r"(\$[a-zA-Z0-9_]+)\s*\*\s*\1\b|math\.pow\s*\(\s*\$[a-zA-Z0-9_.]+\s*,\s*2\s*\)", target_text)
    )
    if not has_squaring:
      return violations
    has_rectification = bool(
        re.search(r"if\s*\([^,]+>\s*0(?:\.0+)?\s*,[^,]+,\s*0(?:\.0+)?\s*\)", full_query)
    )
    if not has_rectification:
      violations.append(
          StatisticalViolation(
              antipattern=StatisticalAntipatternType.UNRECTIFIED_SQUARED_Z_FUSION,
              stage_name="root",
              description=(
                  "Root stage squares Z-scores into a multi-sector Euclidean threat norm without half-rectification "
                  "max(0, Z). Squaring negative Z-scores (quiet sectors below baseline mean) turns inactivity into "
                  "positive threat distance."
              ),
              remediation="Half-rectify each sector Z-score prior to squaring: '$z_pos = if($z_raw > 0, $z_raw, 0.0)'.",
          )
      )
    return violations
