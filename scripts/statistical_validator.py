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
   an additive dispersion floor (+ 1.0).
4. STAT_ANTIPATTERN_DISTRIBUTION_MISMATCH: Evaluating discrete rare events with continuous
   Gaussian models without active baseline days gating (N >= 3) or Poisson rarity.
5. STAT_ANTIPATTERN_COLLINEAR_VECTOR_FUSION: Fusing collinear vectors from the same telemetry
   silo under orthogonal Euclidean threat distance norms (D = sqrt(sum Z^2)).
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
      # Network Egress & Web
      "network_bytes_inbound": "NETWORK",
      "network_bytes_outbound": "NETWORK",
      "network_bytes_total": "NETWORK",
      "http_queries_total": "NETWORK",
      "dns_queries_total": "NETWORK",
      # Endpoint & Process
      "file_executions_total": "ENDPOINT",
  }

  # Discrete low-frequency count metrics that require Poisson rarity or sample-size gating
  DISCRETE_COUNT_METRICS: Set[str] = {
      "auth_attempts_fail",
      "resource_deletion_total",
  }

  @classmethod
  def audit_query(cls, query_text: str) -> List[StatisticalViolation]:
    """Audits a multi-stage YARA-L 2.0 query for all statistical antipatterns."""
    violations: List[StatisticalViolation] = []

    # Parse stages
    stages = cls._extract_stages(query_text)
    root_stage_body = cls._extract_root_stage(query_text)

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

    # Check Root Stage
    if root_stage_body:
      violations.extend(cls._check_zero_dispersion_hazard("root", root_stage_body))
      violations.extend(cls._check_collinear_vector_fusion(root_stage_body, stages))
      violations.extend(cls._check_monolithic_radar_join(root_stage_body, stages))
    elif len(stages) > 4:
      violations.extend(cls._check_monolithic_radar_join("", stages))

    return violations

  @classmethod
  def _extract_stages(cls, query: str) -> Dict[str, str]:
    stages: Dict[str, str] = {}
    stage_matches = re.finditer(r"stage\s+([a-zA-Z0-9_]+)\s*\{([^}]*)\}", query, re.DOTALL)
    for m in stage_matches:
      stages[m.group(1)] = m.group(2)
    return stages

  @classmethod
  def _extract_root_stage(cls, query: str) -> str:
    last_stage_end = 0
    for match in re.finditer(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", query, re.DOTALL):
      last_stage_end = max(last_stage_end, match.end())
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

    if matched_metrics and has_account_entity and not has_resource_in_match:
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

    div_matches = re.finditer(r"(\$[a-zA-Z0-9_]+)\s*=\s*([^/\n]+)/\s*([^\n;]+)", outcome_content)
    for m in div_matches:
      lhs_var = m.group(1)
      numerator = m.group(2).strip()
      denom = m.group(3).strip()

      # Check if this division computes a standardized score, Z-score, or deviation quotient
      is_z_or_score = any(kw in lhs_var.lower() for kw in ["z", "score", "rate", "outlier", "quotient"]) or any(kw in numerator.lower() for kw in ["diff", "obs", "observed", "count"])
      is_dispersion_denom = any(kw in denom.lower() for kw in ["sigma", "std", "mad", "stddev"])

      # If dividing by standard deviation in Z-score or normalized anomaly metric
      if is_z_or_score and is_dispersion_denom and not lhs_var.lower().startswith("$beta"):
        has_dispersion_floor = bool(
            re.search(r"\+\s*(?:1(?:\.0*)?|0\.[0-9]+)", denom) or
            re.search(r"max\s*\([^,]+,\s*(?:1(?:\.0*)?|0\.[0-9]+)\)", denom)
        )
        if not has_dispersion_floor:
          violations.append(
              StatisticalViolation(
                  antipattern=StatisticalAntipatternType.ZERO_DISPERSION_HAZARD,
                  stage_name=stage_name,
                  description=(
                      f"Stage '{stage_name}' outcome variable '{lhs_var}' divides by dispersion denominator '{denom}' "
                      "without an additive constant floor (+ 1.0). On quiet accounts with zero historical variance (sigma = 0), "
                      "this triggers division by zero, yielding NaN, Infinity, or backend query abortion."
                  ),
                  remediation=f"Add universal dispersion floor to denominator: '({denom} + 1.0)'.",
              )
          )

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
      has_sample_gate = bool(
          "num_metric_periods" in stage_body or
          "min_baseline_days" in stage_body or
          "active_days" in stage_body or
          "poisson" in stage_body.lower() or
          "fano" in stage_body.lower() or
          "beta_binomial" in stage_body.lower()
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
                  f"or {sa_var} = /^arn:aws:(iam|sts)::.*:(role|assumed-role)\\// nocase)'. "
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
