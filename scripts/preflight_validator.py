"""Pre-Flight Validation & Ingestion Audit for Multi-Stage Risk Metrics.

Author: Greg Kushmerek
"""

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set


class EntityType(str, Enum):
  USER = "USER"
  ASSET = "ASSET"
  RESOURCE = "RESOURCE"
  LOG_TYPE = "LOG_TYPE"
  EMAIL = "EMAIL"


class MatchMode(str, Enum):
  TIMELINE_BREAKDOWN = "TIMELINE_BREAKDOWN"  # 1 row per active calendar day (match: $entity by 1d)
  FLEET_ROLLUP = "FLEET_ROLLUP"              # 1 summary row per entity across full search range (match: $entity)


class StatisticalModel(str, Enum):
  STANDARD_Z_SCORE = "STANDARD_Z_SCORE"
  MAD = "MAD"
  VARIANCE = "VARIANCE"
  POISSON = "POISSON"
  COEFFICIENT_OF_VARIATION = "COEFFICIENT_OF_VARIATION"
  HOURLY_TEMPORAL_ZSCORE = "HOURLY_TEMPORAL_ZSCORE"
  BAYESIAN_GAMMA = "BAYESIAN_GAMMA"
  BAYESIAN_BETA_BINOMIAL = "BAYESIAN_BETA_BINOMIAL"


class PipelineArchitecture(str, Enum):
  LOCAL_2STAGE = "LOCAL_2STAGE"
  DUAL_BASELINE_3STAGE = "DUAL_BASELINE_3STAGE"
  EMPIRICAL_BAYES_3STAGE = "EMPIRICAL_BAYES_3STAGE"
  MULTI_SECTOR_FUSION_4STAGE = "MULTI_SECTOR_FUSION_4STAGE"


@dataclass
class MetricDefinition:
  metric_id: int
  metric_name: str
  event_type: str
  supported_entity_types: List[EntityType]
  dimension_fields: Dict[EntityType, str]
  backing_log_types: List[str]
  is_vendor_scoped: bool
  default_floor_days: int
  description: str


# ALL 38 Pre-Computed Active Risk Metrics defined in entity.proto & config.textproto
METRIC_CATALOG: Dict[str, MetricDefinition] = {
    "network_bytes_inbound": MetricDefinition(
        metric_id=1,
        metric_name="network_bytes_inbound",
        event_type="NETWORK_CONNECTION",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["ZEEK", "PALO_ALTO_FIREWALL", "ZSCALER", "NETFLOW", "CISCO_ASA", "FORTINET_FIREWALL"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Total inbound network byte volume.",
    ),
    "network_bytes_outbound": MetricDefinition(
        metric_id=2,
        metric_name="network_bytes_outbound",
        event_type="NETWORK_CONNECTION",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["ZEEK", "PALO_ALTO_FIREWALL", "ZSCALER", "NETFLOW", "CISCO_ASA", "FORTINET_FIREWALL"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Total outbound network byte volume.",
    ),
    "network_bytes_total": MetricDefinition(
        metric_id=3,
        metric_name="network_bytes_total",
        event_type="NETWORK_CONNECTION",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["ZEEK", "PALO_ALTO_FIREWALL", "ZSCALER", "NETFLOW", "CISCO_ASA", "FORTINET_FIREWALL"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Total network byte volume (sent + received).",
    ),
    "auth_attempts_success": MetricDefinition(
        metric_id=4,
        metric_name="auth_attempts_success",
        event_type="USER_LOGIN",
        supported_entity_types=[EntityType.USER, EntityType.ASSET],
        dimension_fields={EntityType.USER: "target.user.userid", EntityType.ASSET: "principal.asset.hostname"},
        backing_log_types=["OKTA", "AZURE_AD", "GOOGLE_WORKSPACE", "WINEVTLOG", "ONEPASSWORD", "DUO"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Successful authentication attempts.",
    ),
    "auth_attempts_fail": MetricDefinition(
        metric_id=5,
        metric_name="auth_attempts_fail",
        event_type="USER_LOGIN",
        supported_entity_types=[EntityType.USER, EntityType.ASSET],
        dimension_fields={EntityType.USER: "target.user.userid", EntityType.ASSET: "principal.asset.hostname"},
        backing_log_types=["OKTA", "AZURE_AD", "GOOGLE_WORKSPACE", "WINEVTLOG", "ONEPASSWORD", "DUO"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Failed authentication attempts.",
    ),
    "auth_attempts_total": MetricDefinition(
        metric_id=6,
        metric_name="auth_attempts_total",
        event_type="USER_LOGIN",
        supported_entity_types=[EntityType.USER, EntityType.ASSET],
        dimension_fields={EntityType.USER: "target.user.userid", EntityType.ASSET: "principal.asset.hostname"},
        backing_log_types=["OKTA", "AZURE_AD", "GOOGLE_WORKSPACE", "WINEVTLOG", "ONEPASSWORD", "DUO"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Total authentication attempts.",
    ),
    "dns_bytes_outbound": MetricDefinition(
        metric_id=7,
        metric_name="dns_bytes_outbound",
        event_type="NETWORK_DNS",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["INFOBLOX_DNS", "WINDOWS_DNS", "BIND_DNS", "ZEEK_DNS"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Outbound DNS payload byte volume.",
    ),
    "network_flows_inbound": MetricDefinition(
        metric_id=8,
        metric_name="network_flows_inbound",
        event_type="NETWORK_CONNECTION",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["ZEEK", "PALO_ALTO_FIREWALL", "NETFLOW", "FORTINET_FIREWALL"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Total inbound network connection flow count.",
    ),
    "network_flows_outbound": MetricDefinition(
        metric_id=9,
        metric_name="network_flows_outbound",
        event_type="NETWORK_CONNECTION",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["ZEEK", "PALO_ALTO_FIREWALL", "NETFLOW", "FORTINET_FIREWALL"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Total outbound network connection flow count.",
    ),
    "network_flows_total": MetricDefinition(
        metric_id=10,
        metric_name="network_flows_total",
        event_type="NETWORK_CONNECTION",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["ZEEK", "PALO_ALTO_FIREWALL", "NETFLOW", "FORTINET_FIREWALL"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Total network connection flow count.",
    ),
    "dns_queries_success": MetricDefinition(
        metric_id=11,
        metric_name="dns_queries_success",
        event_type="NETWORK_DNS",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["INFOBLOX_DNS", "WINDOWS_DNS", "BIND_DNS", "ZEEK_DNS"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Successful DNS resolution queries.",
    ),
    "dns_queries_fail": MetricDefinition(
        metric_id=12,
        metric_name="dns_queries_fail",
        event_type="NETWORK_DNS",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["INFOBLOX_DNS", "WINDOWS_DNS", "BIND_DNS", "ZEEK_DNS"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Failed / NXDOMAIN DNS queries.",
    ),
    "dns_queries_total": MetricDefinition(
        metric_id=13,
        metric_name="dns_queries_total",
        event_type="NETWORK_DNS",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["INFOBLOX_DNS", "WINDOWS_DNS", "BIND_DNS", "ZEEK_DNS"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Total DNS query count.",
    ),
    "file_executions_success": MetricDefinition(
        metric_id=14,
        metric_name="file_executions_success",
        event_type="PROCESS_LAUNCH",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["CROWDSTRIKE", "SENTINEL_ONE", "MICROSOFT_DEFENDER_ATP", "SYSMON", "CARBON_BLACK"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Successful process executions.",
    ),
    "file_executions_fail": MetricDefinition(
        metric_id=15,
        metric_name="file_executions_fail",
        event_type="PROCESS_LAUNCH",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["CROWDSTRIKE", "SENTINEL_ONE", "MICROSOFT_DEFENDER_ATP", "SYSMON", "CARBON_BLACK"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Blocked / failed process executions.",
    ),
    "file_executions_total": MetricDefinition(
        metric_id=16,
        metric_name="file_executions_total",
        event_type="PROCESS_LAUNCH",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["CROWDSTRIKE", "SENTINEL_ONE", "MICROSOFT_DEFENDER_ATP", "SYSMON", "CARBON_BLACK"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Total process executions.",
    ),
    "http_queries_success": MetricDefinition(
        metric_id=17,
        metric_name="http_queries_success",
        event_type="NETWORK_HTTP",
        supported_entity_types=[EntityType.USER, EntityType.ASSET],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.ASSET: "principal.asset.hostname"},
        backing_log_types=["CHROME_MANAGEMENT", "ZSCALER", "SQUID_PROXY", "PALO_ALTO_FIREWALL", "BLUECOAT_PROXY"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Successful (2xx/3xx) HTTP web requests.",
    ),
    "http_queries_fail": MetricDefinition(
        metric_id=18,
        metric_name="http_queries_fail",
        event_type="NETWORK_HTTP",
        supported_entity_types=[EntityType.USER, EntityType.ASSET],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.ASSET: "principal.asset.hostname"},
        backing_log_types=["CHROME_MANAGEMENT", "ZSCALER", "SQUID_PROXY", "PALO_ALTO_FIREWALL", "BLUECOAT_PROXY"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Failed (4xx/5xx/Blocked) HTTP web requests.",
    ),
    "http_queries_total": MetricDefinition(
        metric_id=19,
        metric_name="http_queries_total",
        event_type="NETWORK_HTTP",
        supported_entity_types=[EntityType.USER, EntityType.ASSET],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.ASSET: "principal.asset.hostname"},
        backing_log_types=["CHROME_MANAGEMENT", "ZSCALER", "SQUID_PROXY", "PALO_ALTO_FIREWALL", "BLUECOAT_PROXY"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Total HTTP web requests.",
    ),
    "workspace_emails_sent_total": MetricDefinition(
        metric_id=20,
        metric_name="workspace_emails_sent_total",
        event_type="EMAIL_TRANSACTION",
        supported_entity_types=[EntityType.USER, EntityType.EMAIL],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.EMAIL: "network.email.from"},
        backing_log_types=["GOOGLE_WORKSPACE", "GMAIL"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Total outbound emails sent in Google Workspace.",
    ),
    "workspace_total_download_actions": MetricDefinition(
        metric_id=21,
        metric_name="workspace_total_download_actions",
        event_type="USER_RESOURCE_ACCESS",
        supported_entity_types=[EntityType.USER],
        dimension_fields={EntityType.USER: "principal.user.userid"},
        backing_log_types=["GOOGLE_WORKSPACE"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Total Google Workspace file downloads.",
    ),
    "workspace_total_change_actions": MetricDefinition(
        metric_id=22,
        metric_name="workspace_total_change_actions",
        event_type="USER_RESOURCE_ACCESS",
        supported_entity_types=[EntityType.USER],
        dimension_fields={EntityType.USER: "principal.user.userid"},
        backing_log_types=["GOOGLE_WORKSPACE"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Total administrative and settings changes in Workspace.",
    ),
    "workspace_auth_attempts_total": MetricDefinition(
        metric_id=23,
        metric_name="workspace_auth_attempts_total",
        event_type="USER_LOGIN",
        supported_entity_types=[EntityType.USER],
        dimension_fields={EntityType.USER: "target.user.userid"},
        backing_log_types=["GOOGLE_WORKSPACE"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Total Google Workspace authentication attempts.",
    ),
    "workspace_network_bytes_outbound": MetricDefinition(
        metric_id=24,
        metric_name="workspace_network_bytes_outbound",
        event_type="NETWORK_CONNECTION",
        supported_entity_types=[EntityType.USER],
        dimension_fields={EntityType.USER: "principal.user.userid"},
        backing_log_types=["GOOGLE_WORKSPACE"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Outbound network bytes from Google Workspace.",
    ),
    "workspace_network_bytes_total": MetricDefinition(
        metric_id=25,
        metric_name="workspace_network_bytes_total",
        event_type="NETWORK_CONNECTION",
        supported_entity_types=[EntityType.USER],
        dimension_fields={EntityType.USER: "principal.user.userid"},
        backing_log_types=["GOOGLE_WORKSPACE"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Total network bytes in Google Workspace.",
    ),
    "alert_event_name_count": MetricDefinition(
        metric_id=26,
        metric_name="alert_event_name_count",
        event_type="SCAN_VULNERABILITY",
        supported_entity_types=[EntityType.ASSET, EntityType.USER],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname", EntityType.USER: "principal.user.userid"},
        backing_log_types=["CB_EDR", "CS_EDR", "MICROSOFT_GRAPH_ALERT", "SENTINELONE_ALERTS"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Security rule and EDR alerts fired per entity.",
    ),
    "resource_creation_total": MetricDefinition(
        metric_id=27,
        metric_name="resource_creation_total",
        event_type="RESOURCE_CREATION",
        supported_entity_types=[EntityType.USER, EntityType.RESOURCE],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.RESOURCE: "target.resource.name"},
        backing_log_types=["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_ACTIVITY"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Total cloud resource creations (requires vendor_name & product_name).",
    ),
    "resource_creation_success": MetricDefinition(
        metric_id=28,
        metric_name="resource_creation_success",
        event_type="RESOURCE_CREATION",
        supported_entity_types=[EntityType.USER, EntityType.RESOURCE],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.RESOURCE: "target.resource.name"},
        backing_log_types=["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_ACTIVITY"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Successful cloud resource creations (requires vendor_name & product_name).",
    ),
    "resource_read_success": MetricDefinition(
        metric_id=29,
        metric_name="resource_read_success",
        event_type="RESOURCE_READ",
        supported_entity_types=[EntityType.USER, EntityType.RESOURCE],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.RESOURCE: "target.resource.name"},
        backing_log_types=["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_ACTIVITY"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Successful cloud resource reads (requires vendor_name & product_name).",
    ),
    "resource_read_fail": MetricDefinition(
        metric_id=30,
        metric_name="resource_read_fail",
        event_type="RESOURCE_READ",
        supported_entity_types=[EntityType.USER, EntityType.RESOURCE],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.RESOURCE: "target.resource.name"},
        backing_log_types=["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_ACTIVITY"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Failed cloud resource reads (requires vendor_name & product_name).",
    ),
    "resource_deletion_success": MetricDefinition(
        metric_id=31,
        metric_name="resource_deletion_success",
        event_type="RESOURCE_DELETION",
        supported_entity_types=[EntityType.USER, EntityType.RESOURCE],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.RESOURCE: "target.resource.name"},
        backing_log_types=["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_ACTIVITY"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Successful cloud resource deletions (requires vendor_name & product_name).",
    ),
    "resource_creation_fail": MetricDefinition(
        metric_id=32,
        metric_name="resource_creation_fail",
        event_type="RESOURCE_CREATION",
        supported_entity_types=[EntityType.USER, EntityType.RESOURCE],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.RESOURCE: "target.resource.name"},
        backing_log_types=["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_ACTIVITY"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Failed cloud resource creations (requires vendor_name & product_name).",
    ),
    "resource_deletion_fail": MetricDefinition(
        metric_id=33,
        metric_name="resource_deletion_fail",
        event_type="RESOURCE_DELETION",
        supported_entity_types=[EntityType.USER, EntityType.RESOURCE],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.RESOURCE: "target.resource.name"},
        backing_log_types=["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_ACTIVITY"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Failed cloud resource deletions (requires vendor_name & product_name).",
    ),
    "resource_deletion_total": MetricDefinition(
        metric_id=34,
        metric_name="resource_deletion_total",
        event_type="RESOURCE_DELETION",
        supported_entity_types=[EntityType.USER, EntityType.RESOURCE],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.RESOURCE: "target.resource.name"},
        backing_log_types=["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_ACTIVITY"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Total cloud resource deletions (requires vendor_name & product_name).",
    ),
    "resource_read_total": MetricDefinition(
        metric_id=35,
        metric_name="resource_read_total",
        event_type="RESOURCE_READ",
        supported_entity_types=[EntityType.USER, EntityType.RESOURCE],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.RESOURCE: "target.resource.name"},
        backing_log_types=["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_ACTIVITY"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Total cloud resource reads (requires vendor_name & product_name).",
    ),
    "resource_written_fail": MetricDefinition(
        metric_id=36,
        metric_name="resource_written_fail",
        event_type="RESOURCE_WRITTEN",
        supported_entity_types=[EntityType.USER, EntityType.RESOURCE],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.RESOURCE: "target.resource.name"},
        backing_log_types=["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_ACTIVITY"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Failed cloud resource writes/updates (requires vendor_name & product_name).",
    ),
    "resource_written_success": MetricDefinition(
        metric_id=37,
        metric_name="resource_written_success",
        event_type="RESOURCE_WRITTEN",
        supported_entity_types=[EntityType.USER, EntityType.RESOURCE],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.RESOURCE: "target.resource.name"},
        backing_log_types=["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_ACTIVITY"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Successful cloud resource writes/updates (requires vendor_name & product_name).",
    ),
    "resource_written_total": MetricDefinition(
        metric_id=38,
        metric_name="resource_written_total",
        event_type="RESOURCE_WRITTEN",
        supported_entity_types=[EntityType.USER, EntityType.RESOURCE],
        dimension_fields={EntityType.USER: "principal.user.userid", EntityType.RESOURCE: "target.resource.name"},
        backing_log_types=["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_ACTIVITY"],
        is_vendor_scoped=True,
        default_floor_days=7,
        description="Total cloud resource writes/updates (requires vendor_name & product_name).",
    ),
}



class PreFlightValidator:
  """Validates multi-stage parameters, prevents division-by-zero, and audits dimensions."""

  @classmethod
  def audit(
      cls,
      target_metric: str,
      entity_type: EntityType,
      min_baseline_days: Optional[int] = None,
      user_log_type_filter: Optional[str] = None,
      match_mode: MatchMode = MatchMode.TIMELINE_BREAKDOWN,
  ) -> Dict[str, Any]:
    if target_metric not in METRIC_CATALOG:
      raise ValueError(f"Unknown risk metric: {target_metric}")

    metric_def = METRIC_CATALOG[target_metric]

    if entity_type not in metric_def.supported_entity_types:
      raise ValueError(
          f"Entity type {entity_type} not supported for metric {target_metric}."
      )

    effective_floor_days = min_baseline_days if min_baseline_days is not None else metric_def.default_floor_days
    target_field = metric_def.dimension_fields[entity_type]

    # Mathematical Guardrail Verification
    math_guardrails = [
        "$hist_stddev > 0" if match_mode == MatchMode.TIMELINE_BREAKDOWN else "$sigma > 0",
        f"$hist_active_days >= {effective_floor_days}",
    ]

    # Sparse baseline callout generation (< 7 days)
    sparse_callout = None
    if effective_floor_days < 7:
      sparse_callout = (
          "> [!WARNING]\n"
          f"> **⚠️ Sparse Baseline Caution ({effective_floor_days} Days Requested)**:\n"
          f"> Evaluating entities with fewer than 7 active baseline days (N = {effective_floor_days}) reduces statistical "
          "degrees of freedom and inflates false-positive Z-scores. We enforce an active-day floor and recommend "
          "Empirical Bayes shrinkage to regularize sparse observations."
      )

    return {
        "status": "VALID",
        "metric_id": metric_def.metric_id,
        "metric_name": metric_def.metric_name,
        "required_event_type": metric_def.event_type,
        "target_field": target_field,
        "min_baseline_days": effective_floor_days,
        "match_mode": match_mode.value,
        "math_guardrails": math_guardrails,
        "sparse_callout": sparse_callout,
    }


# Canonical UDM Filter Fields per Metric from Malachite compiler source
# (googlex/security/malachite/analytics/configs/config.textproto & dimension_field_mapping.textproto)
MALACHITE_SUPPORTED_FILTERS: Dict[str, Set[str]] = {
    "alert_event_name_count": {
        "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip",
        "principal.asset.mac", "principal.asset.product_object_id", "principal.process.file.full_path",
        "principal.process.file.sha256", "principal.user.email_addresses", "principal.user.employee_id",
        "principal.user.product_object_id", "principal.user.userid", "principal.user.windows_sid",
        "security_result.rule_name"
    },
    "auth_attempts_fail": {
        "metadata.event_type", "network.http.user_agent", "network.tls.client.certificate.sha256",
        "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip", "principal.asset.mac",
        "principal.asset.product_object_id", "principal.ip_geo_artifact.location.country_or_region",
        "principal.ip_geo_artifact.network.organization_name", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.asset.asset_id", "target.asset.hostname",
        "target.asset.ip", "target.asset.mac", "target.asset.product_object_id", "target.user.email_addresses",
        "target.user.employee_id", "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "auth_attempts_success": {
        "metadata.event_type", "network.http.user_agent", "network.tls.client.certificate.sha256",
        "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip", "principal.asset.mac",
        "principal.asset.product_object_id", "principal.ip_geo_artifact.location.country_or_region",
        "principal.ip_geo_artifact.network.organization_name", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.asset.asset_id", "target.asset.hostname",
        "target.asset.ip", "target.asset.mac", "target.asset.product_object_id", "target.user.email_addresses",
        "target.user.employee_id", "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "auth_attempts_total": {
        "metadata.event_type", "network.http.user_agent", "network.tls.client.certificate.sha256",
        "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip", "principal.asset.mac",
        "principal.asset.product_object_id", "principal.ip_geo_artifact.location.country_or_region",
        "principal.ip_geo_artifact.network.organization_name", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.asset.asset_id", "target.asset.hostname",
        "target.asset.ip", "target.asset.mac", "target.asset.product_object_id", "target.user.email_addresses",
        "target.user.employee_id", "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "dns_bytes_outbound": {
        "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip", "principal.asset.mac",
        "principal.asset.product_object_id", "principal.user.email_addresses", "principal.user.employee_id",
        "principal.user.product_object_id", "principal.user.userid", "principal.user.windows_sid", "target.ip"
    },
    "dns_queries_fail": {
        "network.dns.questions.type", "network.dns_domain", "principal.asset.asset_id",
        "principal.asset.hostname", "principal.asset.ip", "principal.asset.mac", "principal.asset.product_object_id",
        "principal.user.email_addresses", "principal.user.employee_id", "principal.user.product_object_id",
        "principal.user.userid", "principal.user.windows_sid"
    },
    "dns_queries_success": {
        "network.dns.questions.type", "network.dns_domain", "principal.asset.asset_id",
        "principal.asset.hostname", "principal.asset.ip", "principal.asset.mac", "principal.asset.product_object_id",
        "principal.user.email_addresses", "principal.user.employee_id", "principal.user.product_object_id",
        "principal.user.userid", "principal.user.windows_sid"
    },
    "dns_queries_total": {
        "network.dns.questions.type", "network.dns_domain", "principal.asset.asset_id",
        "principal.asset.hostname", "principal.asset.ip", "principal.asset.mac", "principal.asset.product_object_id",
        "principal.user.email_addresses", "principal.user.employee_id", "principal.user.product_object_id",
        "principal.user.userid", "principal.user.windows_sid"
    },
    "file_executions_fail": {
        "metadata.event_type", "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip",
        "principal.asset.mac", "principal.asset.product_object_id", "principal.process.file.sha256",
        "principal.user.email_addresses", "principal.user.employee_id", "principal.user.product_object_id",
        "principal.user.userid", "principal.user.windows_sid"
    },
    "file_executions_success": {
        "metadata.event_type", "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip",
        "principal.asset.mac", "principal.asset.product_object_id", "principal.process.file.sha256",
        "principal.user.email_addresses", "principal.user.employee_id", "principal.user.product_object_id",
        "principal.user.userid", "principal.user.windows_sid"
    },
    "file_executions_total": {
        "metadata.event_type", "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip",
        "principal.asset.mac", "principal.asset.product_object_id", "principal.process.file.sha256",
        "principal.user.email_addresses", "principal.user.employee_id", "principal.user.product_object_id",
        "principal.user.userid", "principal.user.windows_sid"
    },
    "http_queries_fail": {
        "network.http.user_agent", "principal.asset.asset_id", "principal.asset.hostname",
        "principal.asset.ip", "principal.asset.mac", "principal.asset.product_object_id",
        "principal.user.email_addresses", "principal.user.employee_id", "principal.user.product_object_id",
        "principal.user.userid", "principal.user.windows_sid", "target.hostname"
    },
    "http_queries_success": {
        "network.http.user_agent", "principal.asset.asset_id", "principal.asset.hostname",
        "principal.asset.ip", "principal.asset.mac", "principal.asset.product_object_id",
        "principal.user.email_addresses", "principal.user.employee_id", "principal.user.product_object_id",
        "principal.user.userid", "principal.user.windows_sid", "target.hostname"
    },
    "http_queries_total": {
        "network.http.user_agent", "principal.asset.asset_id", "principal.asset.hostname",
        "principal.asset.ip", "principal.asset.mac", "principal.asset.product_object_id",
        "principal.user.email_addresses", "principal.user.employee_id", "principal.user.product_object_id",
        "principal.user.userid", "principal.user.windows_sid", "target.hostname"
    },
    "network_bytes_inbound": {
        "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip", "principal.asset.mac",
        "principal.asset.product_object_id", "principal.ip_geo_artifact.location.country_or_region",
        "principal.user.email_addresses", "principal.user.employee_id", "principal.user.product_object_id",
        "principal.user.userid", "principal.user.windows_sid", "security_result.category",
        "target.asset.asset_id", "target.asset.hostname", "target.asset.ip", "target.asset.mac",
        "target.asset.product_object_id", "target.ip_geo_artifact.network.organization_name"
    },
    "network_bytes_outbound": {
        "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip", "principal.asset.mac",
        "principal.asset.product_object_id", "principal.ip_geo_artifact.location.country_or_region",
        "principal.user.email_addresses", "principal.user.employee_id", "principal.user.product_object_id",
        "principal.user.userid", "principal.user.windows_sid", "security_result.category",
        "target.asset.asset_id", "target.asset.hostname", "target.asset.ip", "target.asset.mac",
        "target.asset.product_object_id", "target.ip_geo_artifact.network.organization_name"
    },
    "network_bytes_total": {
        "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip", "principal.asset.mac",
        "principal.asset.product_object_id", "principal.ip_geo_artifact.location.country_or_region",
        "principal.user.email_addresses", "principal.user.employee_id", "principal.user.product_object_id",
        "principal.user.userid", "principal.user.windows_sid", "security_result.category",
        "target.asset.asset_id", "target.asset.hostname", "target.asset.ip", "target.asset.mac",
        "target.asset.product_object_id", "target.ip_geo_artifact.network.organization_name"
    },
    "network_flows_inbound": {
        "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip", "principal.asset.mac",
        "principal.asset.product_object_id", "principal.user.email_addresses", "principal.user.employee_id",
        "principal.user.product_object_id", "principal.user.userid", "principal.user.windows_sid"
    },
    "network_flows_outbound": {
        "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip", "principal.asset.mac",
        "principal.asset.product_object_id", "principal.user.email_addresses", "principal.user.employee_id",
        "principal.user.product_object_id", "principal.user.userid", "principal.user.windows_sid"
    },
    "network_flows_total": {
        "principal.asset.asset_id", "principal.asset.hostname", "principal.asset.ip", "principal.asset.mac",
        "principal.asset.product_object_id", "principal.user.email_addresses", "principal.user.employee_id",
        "principal.user.product_object_id", "principal.user.userid", "principal.user.windows_sid"
    },
    "resource_creation_fail": {
        "metadata.product_name", "metadata.vendor_name", "principal.ip", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.location.name", "target.resource.name",
        "target.resource.resource_type", "target.user.email_addresses", "target.user.employee_id",
        "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "resource_creation_success": {
        "metadata.product_name", "metadata.vendor_name", "principal.ip", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.location.name", "target.resource.name",
        "target.resource.resource_type", "target.user.email_addresses", "target.user.employee_id",
        "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "resource_creation_total": {
        "metadata.product_name", "metadata.vendor_name", "principal.ip", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.location.name", "target.resource.name",
        "target.resource.resource_type", "target.user.email_addresses", "target.user.employee_id",
        "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "resource_deletion_fail": {
        "metadata.product_name", "metadata.vendor_name", "principal.ip", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.location.name", "target.resource.name",
        "target.resource.resource_type", "target.user.email_addresses", "target.user.employee_id",
        "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "resource_deletion_success": {
        "metadata.product_name", "metadata.vendor_name", "principal.ip", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.location.name", "target.resource.name",
        "target.resource.resource_type", "target.user.email_addresses", "target.user.employee_id",
        "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "resource_deletion_total": {
        "metadata.product_name", "metadata.vendor_name", "principal.ip", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.location.name", "target.resource.name",
        "target.resource.resource_type", "target.user.email_addresses", "target.user.employee_id",
        "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "resource_read_fail": {
        "metadata.product_name", "metadata.vendor_name", "principal.ip", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.location.name", "target.resource.name",
        "target.resource.resource_type", "target.user.email_addresses", "target.user.employee_id",
        "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "resource_read_success": {
        "metadata.product_name", "metadata.vendor_name", "principal.ip", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.location.name", "target.resource.name",
        "target.resource.resource_type", "target.user.email_addresses", "target.user.employee_id",
        "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "resource_read_total": {
        "metadata.product_name", "metadata.vendor_name", "principal.ip", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.location.name", "target.resource.name",
        "target.resource.resource_type", "target.user.email_addresses", "target.user.employee_id",
        "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "resource_written_fail": {
        "metadata.product_name", "metadata.vendor_name", "principal.ip", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.location.name", "target.resource.name",
        "target.resource.resource_type", "target.user.email_addresses", "target.user.employee_id",
        "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "resource_written_success": {
        "metadata.product_name", "metadata.vendor_name", "principal.ip", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.location.name", "target.resource.name",
        "target.resource.resource_type", "target.user.email_addresses", "target.user.employee_id",
        "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "resource_written_total": {
        "metadata.product_name", "metadata.vendor_name", "principal.ip", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "target.application", "target.location.name", "target.resource.name",
        "target.resource.resource_type", "target.user.email_addresses", "target.user.employee_id",
        "target.user.product_object_id", "target.user.userid", "target.user.windows_sid"
    },
    "workspace_auth_attempts_total": {
        "metadata.product_event_type", "principal.ip", "principal.ip_geo_artifact.location.country_or_region",
        "principal.user.email_addresses", "principal.user.employee_id", "principal.user.product_object_id",
        "principal.user.userid", "principal.user.windows_sid", "security_result.action", "target.application",
        "target.user.email_addresses", "target.user.employee_id", "target.user.product_object_id",
        "target.user.userid", "target.user.windows_sid"
    },
    "workspace_emails_sent_total": {
        "network.email.from", "network.email.mail_id", "network.email.to", "principal.application",
        "principal.ip", "principal.user.email_addresses", "principal.user.employee_id",
        "principal.user.product_object_id", "principal.user.userid", "principal.user.windows_sid",
        "security_result.rule_id", "target.ip"
    },
    "workspace_network_bytes_outbound": {
        "principal.ip_geo_artifact.location.country_or_region", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid"
    },
    "workspace_network_bytes_total": {
        "principal.ip_geo_artifact.location.country_or_region", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid"
    },
    "workspace_total_change_actions": {
        "metadata.product_event_type", "metadata.product_name", "principal.ip", "principal.user.email_addresses",
        "principal.user.employee_id", "principal.user.product_object_id", "principal.user.userid",
        "principal.user.windows_sid", "security_result.action", "target.resource.name",
        "target.user.email_addresses", "target.user.employee_id", "target.user.product_object_id",
        "target.user.userid", "target.user.windows_sid"
    },
    "workspace_total_download_actions": {
        "metadata.product_name", "principal.ip", "principal.user.email_addresses", "principal.user.employee_id",
        "principal.user.product_object_id", "principal.user.userid", "principal.user.windows_sid",
        "target.resource.name"
    },
}

MALACHITE_MANDATORY_FILTERS = {
    # All Cloud Resource Lifecycle (CRUD) metrics strictly require both metadata.vendor_name and metadata.product_name
    "resource_creation_fail": {"metadata.vendor_name", "metadata.product_name"},
    "resource_creation_success": {"metadata.vendor_name", "metadata.product_name"},
    "resource_creation_total": {"metadata.vendor_name", "metadata.product_name"},
    "resource_deletion_fail": {"metadata.vendor_name", "metadata.product_name"},
    "resource_deletion_success": {"metadata.vendor_name", "metadata.product_name"},
    "resource_deletion_total": {"metadata.vendor_name", "metadata.product_name"},
    "resource_read_fail": {"metadata.vendor_name", "metadata.product_name"},
    "resource_read_success": {"metadata.vendor_name", "metadata.product_name"},
    "resource_read_total": {"metadata.vendor_name", "metadata.product_name"},
    "resource_written_fail": {"metadata.vendor_name", "metadata.product_name"},
    "resource_written_success": {"metadata.vendor_name", "metadata.product_name"},
    "resource_written_total": {"metadata.vendor_name", "metadata.product_name"},
    # Process launch execution metrics require event_type and process sha256
    "file_executions_fail": {"metadata.event_type", "principal.process.file.sha256"},
    "file_executions_success": {"metadata.event_type", "principal.process.file.sha256"},
    "file_executions_total": {"metadata.event_type", "principal.process.file.sha256"},
}


class MalachiteASTValidator:
  """Enforces Google SecOps compiler rules and mathematical AST constraints on YARA-L 2.0 queries."""

  @staticmethod
  def validate_query(query_text: str) -> List[str]:
    errors = []

    # 1. Methodology & Goal Comment Header
    if not re.search(r"//\s*(?:Goal:|ARCHITECTURE:)", query_text, re.IGNORECASE):
      errors.append("MISSING_GOAL_HEADER: Query must start with a '// Goal:' or '// ARCHITECTURE:' methodology comment.")

    # 1B. Global Invalid Tokens & Math Functions
    if "^" in query_text:
      errors.append("INVALID_EXPONENT_OPERATOR: '^' is invalid in YARA-L. Use '$var * $var' for squared terms.")
    if re.search(r"\bif\s*\(", query_text):
      errors.append("INVALID_IF_CONDITIONAL: 'if(...)' is invalid in YARA-L outcome expressions.")
    if re.search(r"\bsqrt\s*\(", query_text):
      errors.append("INVALID_SQRT_FUNCTION: 'sqrt(...)' is invalid in YARA-L outcome expressions. Compute squared norm and order by '$norm_sq desc'.")
    if re.search(r"\b[a-zA-Z0-9_]+\.\$[a-zA-Z0-9_]+", query_text):
      errors.append("INVALID_STAGE_VARIABLE_SYNTAX: Multi-stage variable references must use '$stage.var', not 'stage.$var' (placing '$' after the dot causes an ANTLR syntax crash).")
    if re.search(r"^\s*rule\s+[a-zA-Z0-9_]+\s*\{", query_text, re.MULTILINE):
      errors.append(
          "INVALID_DETECTION_RULE_SYNTAX: Multi-stage threat hunting queries must be ad-hoc search queries ('stage name { ... }' + root stage), not continuous detection rules ('rule ... { ... }')."
      )

    # 2. Stage count & naming rules
    stage_blocks = re.findall(r"(?:stage\s+([a-zA-Z0-9_]+)\s*\{|\$(\w+)\s*=)", query_text)
    named_stages = [s[0] for s in stage_blocks if s[0]]

    for s_name in named_stages:
      if s_name.startswith("$"):
        errors.append(f"STAGE_NAME_PREFIX_ERROR: Stage '{s_name}' must not have a '$' prefix.")

    if len(named_stages) > 4:
      errors.append(f"STAGE_LIMIT_EXCEEDED: Query defines {len(named_stages)} stages (max allowed is 4).")

    # 3. Stage 1 Extraction Contracts
    stage1_matches = re.findall(r"stage\s+([a-zA-Z0-9_]+)\s*\{([^}]+)\}", query_text, re.DOTALL)
    for stage_name, stage_body in stage1_matches:
      # Check outcome count limit <= 20
      outcome_match = re.search(r"outcome:\s*(.*?)(?=\n\s*(?:condition|match|\}|$))", stage_body, re.DOTALL)
      if outcome_match:
        outcomes = re.findall(r"\$([a-zA-Z0-9_]+)\s*=", outcome_match.group(1))
        if len(outcomes) > 20:
          errors.append(f"OUTCOME_LIMIT_EXCEEDED in stage '{stage_name}': {len(outcomes)} variables (compiler limit is 20).")

      # Check window keyword: 'by 1d' not 'over 1d' or 'by 24h'
      if re.search(r"match:.*?over\s+1[dh]", stage_body, re.DOTALL):
        errors.append(f"WINDOW_SYNTAX_ERROR in stage '{stage_name}': Match window must use 'by 1d' or 'by 1h' (not 'over').")
      if re.search(r"match:.*?by\s+24h", stage_body, re.DOTALL):
        errors.append(f"INVALID_WINDOW_SYNTAX in stage '{stage_name}': 'by 24h' is invalid in YARA-L. Use 'by 1d' for daily matching.")

      # Check for invalid 'in ("A", "B")' literal tuple syntax
      if re.search(r"\bin\s*\([\"']", stage_body):
        errors.append(
            f"INVALID_IN_SYNTAX in stage '{stage_name}': 'in (...)' with literal string tuples is invalid in YARA-L. "
            "Use '(field = \"A\" or field = \"B\")' or regex."
        )

      # Check for invalid dot-notation metric properties (e.g. metrics.foo.mean)
      if re.search(r"metrics\.[a-zA-Z0-9_]+\.(?:mean|stddev|avg|sum|max|min|count)", stage_body):
        errors.append(
            f"INVALID_METRIC_DOT_NOTATION in stage '{stage_name}': Metric properties like 'metrics.foo.mean' are invalid. "
            "Use canonical function calls: 'max(metrics.foo(period: 1d, window: 30d, ...))'."
        )

      # Check for events: header inside stage
      if re.search(r"\bevents:\s*", stage_body):
        errors.append(
            f"INVALID_EVENTS_SECTION_IN_STAGE in stage '{stage_name}': Named stages must not contain an 'events:' header block."
        )

      # Check for stage in syntax ($var in stage_name)
      if re.search(r"\$[a-zA-Z0-9_]+\s+in\s+[a-zA-Z0-9_]+", stage_body):
        errors.append(
            f"INVALID_STAGE_IN_SYNTAX in stage '{stage_name}': '$var in stage_name' is invalid. "
            "Root stages join via '$user = $stage1.user' and '$stage1.outcome_var'."
        )

      # Check that placeholder variables in match section are defined in event section and no arithmetic above match
      match_block = re.search(r"\bmatch:\s*(.*?)(?=\b(?:outcome|condition|order)\s*:|\}|$|\Z)", stage_body, re.DOTALL)
      if match_block:
        event_part = stage_body[:match_block.start()]
        errors.extend(MalachiteASTValidator._check_arithmetic_in_event_section(stage_name, event_part))
        errors.extend(MalachiteASTValidator._check_match_placeholders_bound(stage_name, event_part, match_block.group(1)))
      else:
        # If no match section, check event section preceding outcome
        outcome_block = re.search(r"outcome:\s*", stage_body)
        if outcome_block:
          event_part = stage_body[:outcome_block.start()]
          errors.extend(MalachiteASTValidator._check_arithmetic_in_event_section(stage_name, event_part))

      # Anti-Pattern 6: Single-stage multi-vector cramming
      distinct_event_types = set(re.findall(r"metadata\.event_type\s*==?\s*[\"']([A-Z_]+)[\"']", stage_body))
      metrics_calls = re.findall(r"metrics\.([a-zA-Z0-9_]+)\s*\(", stage_body)
      if len(distinct_event_types) > 1 and metrics_calls:
        errors.append(
            f"ANTI-PATTERN 6 (Single-Stage Multi-Vector Cramming in stage '{stage_name}'): Stage contains multiple OR'd "
            f"event types {distinct_event_types} while evaluating metrics. Use independent DAG stages fused in Root stage."
        )

      # Anti-Pattern 6B: Multi-vector metric conflation within single stage
      metric_event_types = {METRIC_CATALOG[m].event_type for m in metrics_calls if m in METRIC_CATALOG}
      if len(metric_event_types) > 1:
        errors.append(
            f"MULTI_VECTOR_STAGE_CONFLATION in stage '{stage_name}': Stage attempts to evaluate metrics across different event types ({sorted(list(metric_event_types))}). "
            "Each telemetry vector must be evaluated in its own decoupled stage or micro-query."
        )

      # Anti-Pattern 7: Non-existent metric functions
      for metric_name in metrics_calls:
        if metric_name not in METRIC_CATALOG:
          errors.append(
              f"ANTI-PATTERN 7 (Non-Existent Metric Function in stage '{stage_name}'): 'metrics.{metric_name}' does not exist in METRIC_CATALOG."
          )

      # Metric Filter Validation against Malachite source definitions
      standard_params = {"period", "window", "metric", "agg", "filter"}
      metric_call_matches = re.findall(r"metrics\.([a-zA-Z0-9_]+)\s*\(([^)]+)\)", stage_body, re.DOTALL)
      for m_name, args_body in metric_call_matches:
        m_lower = m_name.lower()
        called_params = re.findall(r"([a-zA-Z0-9_.]+)\s*:", args_body)
        if m_lower in MALACHITE_SUPPORTED_FILTERS:
          valid_filters = MALACHITE_SUPPORTED_FILTERS[m_lower]
          for param in called_params:
            if param not in standard_params and param not in valid_filters:
              hint = ""
              if param == "principal.ip" and "principal.asset.ip" in valid_filters:
                hint = " (In Chronicle, device IP filtering requires 'principal.asset.ip' or 'principal.asset.hostname')"
              elif param == "target.ip" and "target.asset.ip" in valid_filters:
                hint = " (In Chronicle, device IP filtering requires 'target.asset.ip' or 'target.asset.hostname')"
              errors.append(
                  f"INVALID_METRIC_FILTER in stage '{stage_name}': '{param}' is not a supported filter for 'metrics.{m_name}'.{hint}"
              )

        # Check for mandatory companion dimensions
        if m_lower in MALACHITE_MANDATORY_FILTERS:
          required_dims = MALACHITE_MANDATORY_FILTERS[m_lower]
          called_filter_keys = set(called_params) - standard_params
          missing_dims = required_dims - called_filter_keys
          if missing_dims:
            hint = ""
            if "metadata.vendor_name" in missing_dims:
              hint = " In Chronicle Malachite, all Cloud CRUD metrics require both 'metadata.vendor_name' and 'metadata.product_name' when filtering by user/asset."
            elif "principal.process.file.sha256" in missing_dims:
              hint = " In Chronicle Malachite, process execution metrics require both 'metadata.event_type' and 'principal.process.file.sha256'."
            errors.append(
                f"MISSING_MANDATORY_FILTER in stage '{stage_name}': Metric 'metrics.{m_name}' is missing required companion dimension(s): {sorted(list(missing_dims))}.{hint}"
            )

      # Invariant: Maximum 1 ECG (Entity Context Graph) lookup per stage
      graph_aliases = set(re.findall(r"\$([a-zA-Z0-9_]+)\.graph\.", stage_body))
      if len(graph_aliases) > 1:
        errors.append(
            f"ECG_LIMIT_EXCEEDED in stage '{stage_name}': Number of ECG events exceeded max limit ({len(graph_aliases)} > 1). "
            "Place each Entity Context Graph lookup in its own dedicated stage."
        )

      # Anti-Pattern: Part-of-the-Whole (Subset vs. Universal Baseline Fallacy)
      # Evaluating metrics.* in a stage with GLOBAL_CONTEXT or DERIVED_CONTEXT filters causes negative Z-scores
      if metrics_calls and ('"GLOBAL_CONTEXT"' in stage_body or '"DERIVED_CONTEXT"' in stage_body):
        errors.append(
            f"ANTI-PATTERN (Part-of-the-Whole in stage '{stage_name}'): Evaluating metrics.* inside a stage that filters "
            "on external threat context (GLOBAL_CONTEXT / DERIVED_CONTEXT) skews Z-scores. Decouple baseline into Stage 1 "
            "(Universal Anomaly) and threat context into Stage 2 (Threat Hits)."
        )

    last_stage_end = 0
    for match in re.finditer(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", query_text, re.DOTALL):
      last_stage_end = max(last_stage_end, match.end())
    root_body = query_text[last_stage_end:]

    # Check root stage metric filter fields
    root_metric_calls = re.findall(r"metrics\.([a-zA-Z0-9_]+)\s*\(([^)]+)\)", root_body, re.DOTALL)
    for m_name, args_body in root_metric_calls:
      m_lower = m_name.lower()
      called_params = re.findall(r"([a-zA-Z0-9_.]+)\s*:", args_body)
      if m_lower in MALACHITE_SUPPORTED_FILTERS:
        valid_filters = MALACHITE_SUPPORTED_FILTERS[m_lower]
        for param in called_params:
          if param not in standard_params and param not in valid_filters:
            hint = ""
            if param == "principal.ip" and "principal.asset.ip" in valid_filters:
              hint = " (In Chronicle, device IP filtering requires 'principal.asset.ip' or 'principal.asset.hostname')"
            elif param == "target.ip" and "target.asset.ip" in valid_filters:
              hint = " (In Chronicle, device IP filtering requires 'target.asset.ip' or 'target.asset.hostname')"
            errors.append(
                f"INVALID_METRIC_FILTER in root stage: '{param}' is not a supported filter for 'metrics.{m_name}'.{hint}"
            )

      # Check for mandatory companion dimensions in root stage
      if m_lower in MALACHITE_MANDATORY_FILTERS:
        required_dims = MALACHITE_MANDATORY_FILTERS[m_lower]
        called_filter_keys = set(called_params) - standard_params
        missing_dims = required_dims - called_filter_keys
        if missing_dims:
          hint = ""
          if "metadata.vendor_name" in missing_dims:
            hint = " In Chronicle Malachite, all Cloud CRUD metrics require both 'metadata.vendor_name' and 'metadata.product_name' when filtering by user/asset."
          elif "principal.process.file.sha256" in missing_dims:
            hint = " In Chronicle Malachite, process execution metrics require both 'metadata.event_type' and 'principal.process.file.sha256'."
          errors.append(
              f"MISSING_MANDATORY_FILTER in root stage: Metric 'metrics.{m_name}' is missing required companion dimension(s): {sorted(list(missing_dims))}.{hint}"
          )

    # Check that placeholder variables in root stage match section are defined and no arithmetic above match
    root_match = re.search(r"\bmatch:\s*(.*?)(?=\b(?:outcome|condition|order)\s*:|\Z)", root_body, re.DOTALL)
    if root_match:
      root_event_part = root_body[:root_match.start()]
      errors.extend(MalachiteASTValidator._check_arithmetic_in_event_section("root stage", root_event_part))
      errors.extend(MalachiteASTValidator._check_match_placeholders_bound("root stage", root_event_part, root_match.group(1)))
    else:
      root_outcome = re.search(r"outcome:\s*", root_body)
      if root_outcome:
        root_event_part = root_body[:root_outcome.start()]
        errors.extend(MalachiteASTValidator._check_arithmetic_in_event_section("root stage", root_event_part))

    # 4. Multi-Sector Fusion Architecture Validation
    if "MULTI_SECTOR" in query_text.upper() or "MULTI-SECTOR" in query_text.upper():
      if len(named_stages) < 3:
        errors.append(f"PIPELINE ARCHITECTURE MISMATCH: Multi-Sector Threat Fusion requires 3 distinct extractor stages (found {len(named_stages)}).")
        errors.append(f"STAGE PARITY ERROR: Stage count ({len(named_stages)}) does not match required telemetry sectors (3).")

    return errors

  @staticmethod
  def _check_arithmetic_in_event_section(stage_name: str, event_part: str) -> List[str]:
    """Ensures no binary arithmetic is performed in event/stage join sections above match:."""
    errors = []
    lines = event_part.splitlines()
    for line in lines:
      clean = re.sub(r"//.*", "", line).strip()
      if not clean or "=" not in clean:
        continue
      parts = clean.split("=", 1)
      lhs = parts[0].strip()
      rhs = parts[1].strip()
      if re.match(r"^\$[a-zA-Z0-9_]+$", lhs):
        # Strip string literals and regex literals
        rhs_no_strings = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', rhs)
        rhs_no_strings = re.sub(r"'[^'\\]*(?:\\.[^'\\]*)*'", "''", rhs_no_strings)
        rhs_no_strings = re.sub(r'/[^/\\]*(?:\\.[^/\\]*)*/', '//', rhs_no_strings)
        # Check for binary arithmetic (+, -, *, /) between variables or numbers
        if re.search(r"(\$[a-zA-Z0-9_.]+|\d+(?:\.\d+)?)\s*[-+*/]\s*(\$[a-zA-Z0-9_.]+|\d+(?:\.\d+)?)", rhs_no_strings):
          errors.append(
              f"ARITHMETIC_IN_EVENT_SECTION in stage '{stage_name}': Variable arithmetic ('{clean}') is prohibited "
              "in event predicate blocks above match:. Under Google SecOps Common Compiler, placeholders in the events section "
              "must bind directly to event fields, stage fields, or scalar functions. "
              "Move arithmetic expressions into the outcome: section below match:."
          )
    return errors

  @staticmethod
  def _check_match_placeholders_bound(stage_name: str, event_part: str, match_part: str) -> List[str]:
    """Ensures every placeholder used in match: has an explicit binding in event_part."""
    errors = []
    match_vars = re.findall(r"\$([a-zA-Z0-9_]+)", match_part)
    for mv in match_vars:
      # Must be bound via $mv = ... or field = $mv
      is_bound = False
      for line in event_part.splitlines():
        clean = re.sub(r"//.*", "", line).strip()
        if not clean or "=" not in clean:
          continue
        parts = clean.split("=", 1)
        lhs = parts[0].strip()
        rhs = parts[1].strip()
        if lhs == f"${mv}" or re.search(rf"\${mv}\b", rhs):
          is_bound = True
          break
      if not is_bound:
        errors.append(
            f"UNBOUND_MATCH_VARIABLE in stage '{stage_name}': Match placeholder '${mv}' is not bound to any event field "
            "or stage field in the event section. Common Compiler requires all match variables to be explicitly assigned in events."
        )
    return errors

  @staticmethod
  def validate_model_concordance(query_text: str, model: StatisticalModel) -> List[str]:
    errors = []
    stage_blocks = re.findall(r"(?:stage\s+([a-zA-Z0-9_]+)\s*\{)", query_text)
    named_stages = [s for s in stage_blocks if s]

    # Stage count & topology validation
    if model in [StatisticalModel.STANDARD_Z_SCORE, StatisticalModel.MAD, StatisticalModel.POISSON,
                 StatisticalModel.VARIANCE, StatisticalModel.COEFFICIENT_OF_VARIATION]:
      if len(named_stages) != 1:
        errors.append(f"STAGE_TOPOLOGY_MISMATCH: Model {model.value} requires a 2-stage DAG (1 named extractor + root stage). Found {len(named_stages)} named stage(s).")
    elif "3STAGE" in model.value or model in [StatisticalModel.BAYESIAN_GAMMA, StatisticalModel.BAYESIAN_BETA_BINOMIAL]:
      pass

    # Mathematical formulation signature validation
    if model == StatisticalModel.MAD:
      if "0.6745" not in query_text and "mad" not in query_text.lower():
        errors.append("MODEL_FORMULA_MISMATCH: MAD model must include the 0.6745 median scaling factor and robust dispersion floor.")
    elif model == StatisticalModel.POISSON:
      if "sqrt" not in query_text.lower() and "poisson" not in query_text.lower():
        errors.append("MODEL_FORMULA_MISMATCH: Discrete Poisson model must calculate standard Poisson residual using sqrt(lambda).")
    elif model == StatisticalModel.STANDARD_Z_SCORE:
      if "+ 1.0" not in query_text and "stddev" not in query_text.lower():
        errors.append("MODEL_FORMULA_MISMATCH: Standard Z-Score must apply dispersion floor (+ 1.0) to denominator.")

    return errors


class AuditStatus(str, Enum):
  PASSED = "PASSED"
  RETRY_REQUIRED = "RETRY_REQUIRED"
  FAILED = "FAILED"


@dataclass
class PostFlightAuditResult:
  status: AuditStatus
  is_valid: bool
  errors: List[str]
  recommended_query: Optional[str] = None
  remediation_action: Optional[str] = None
  audit_summary: str = ""


class PostFlightExecutionAuditor:
  """Audits completed API executions, validates Risk Metrics provenance, and orchestrates auto-remediation."""

  @classmethod
  def audit_execution(
      cls,
      executed_query: Optional[str],
      api_response: Dict[str, Any],
      target_metric: Optional[str] = None,
      entity_type: Optional[EntityType] = None,
      statistical_model: Optional[StatisticalModel] = None,
      anomaly_threshold: float = 3.0,
  ) -> PostFlightAuditResult:
    errors = []

    # 1. Executed query presence and AST validation
    if not executed_query or not executed_query.strip():
      errors.append("MISSING_QUERY: No query string was recorded as executed against the SIEM API.")
    else:
      ast_errors = MalachiteASTValidator.validate_query(executed_query)
      errors.extend(ast_errors)

      metrics_calls = re.findall(r"metrics\.([a-zA-Z0-9_]+)\s*\(", executed_query)
      if not metrics_calls:
        errors.append(
            "NO_METRICS_FUNCTION: Query did not invoke native Google SecOps Risk Analytics (metrics.*). "
            "Raw UDM search filters cannot be used as a stand-in for 30-day UEBA baselines."
        )

      if statistical_model:
        model_errors = MalachiteASTValidator.validate_model_concordance(executed_query, statistical_model)
        errors.extend(model_errors)

    # 2. API Response Data Structure Verification
    if "events" in api_response and "stats" not in api_response and not api_response.get("results"):
      raw_events = api_response.get("events", [])
      if len(raw_events) > 0:
        errors.append(
            f"RAW_LOG_DUMP_DETECTED: API response contained {len(raw_events)} raw UDM events rather than a "
            "compiled multi-stage statistical aggregation. Local Python arithmetic cannot simulate SIEM baselines."
        )

    if not errors:
      return PostFlightAuditResult(
          status=AuditStatus.PASSED,
          is_valid=True,
          errors=[],
          audit_summary="🟢 Audit Passed: Native 30-day Risk Analytics query execution verified."
      )

    # 3. Auto-Correction / Remediation Generation (Self-Healing Loop)
    recommended_query = None
    remediation_action = None
    if target_metric and entity_type and statistical_model:
      try:
        from .template_router import MultiStageTemplateRouter
        router = MultiStageTemplateRouter()
        recommended_query = router.build_query(
            target_metric=target_metric,
            entity_type=entity_type,
            statistical_model=statistical_model,
            anomaly_threshold=anomaly_threshold,
            hypothesis_goal=f"Auto-corrected canonical hunt for {target_metric} using {statistical_model.value}"
        )
        remediation_action = "Auto-generated canonical YARA-L 2.0 multi-stage query from golden templates for retry."
      except Exception as e:
        remediation_action = f"Failed to auto-generate canonical query: {e}"

    return PostFlightAuditResult(
        status=AuditStatus.RETRY_REQUIRED if recommended_query else AuditStatus.FAILED,
        is_valid=False,
        errors=errors,
        recommended_query=recommended_query,
        remediation_action=remediation_action,
        audit_summary=f"❌ Audit Failed ({len(errors)} violation(s) detected). {remediation_action or ''}"
    )

