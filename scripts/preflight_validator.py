"""Pre-Flight Validation & Ingestion Audit for Multi-Stage Risk Metrics.

Author: Greg Kushmerek
"""

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set, Tuple

try:
  from . import malachite_catalog as _mc
except ImportError:  # imported as a top-level module
  import malachite_catalog as _mc  # type: ignore[no-redef]


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
  LONGITUDINAL_CUSUM = "LONGITUDINAL_CUSUM"
  TWO_PART_HURDLE = "TWO_PART_HURDLE"
  ASYMMETRIC_DIRECTIONAL_Z = "ASYMMETRIC_DIRECTIONAL_Z"
  PIECEWISE_CRI = "PIECEWISE_CRI"
  FLEET_PREVALENCE_SHIELD = "FLEET_PREVALENCE_SHIELD"
  ADAPTIVE_CONTEXT_THRESHOLD = "ADAPTIVE_CONTEXT_THRESHOLD"
  MACD_MOMENTUM_VELOCITY = "MACD_MOMENTUM_VELOCITY"
  CIRCADIAN_VON_MISES = "CIRCADIAN_VON_MISES"


class PipelineArchitecture(str, Enum):
  LOCAL_2STAGE = "LOCAL_2STAGE"
  DUAL_BASELINE_3STAGE = "DUAL_BASELINE_3STAGE"
  EMPIRICAL_BAYES_3STAGE = "EMPIRICAL_BAYES_3STAGE"
  MULTI_SECTOR_FUSION_4STAGE = "MULTI_SECTOR_FUSION_4STAGE"
  DUAL_SECTOR_FUSION_3STAGE = "DUAL_SECTOR_FUSION_3STAGE"
  RADAR_360_DECOUPLED_SECTOR = "RADAR_360_DECOUPLED_SECTOR"
  CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH = "CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH"
  HYBRID_METRIC_RAW_ENRICHMENT_2STAGE = "HYBRID_METRIC_RAW_ENRICHMENT_2STAGE"
  HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE = "HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE"
  HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE = "HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE"
  HYBRID_METRIC_FLEET_PREVALENCE_2STAGE = "HYBRID_METRIC_FLEET_PREVALENCE_2STAGE"
  PART_OF_THE_WHOLE_MULTILEVEL = "PART_OF_THE_WHOLE_MULTILEVEL"
  PART_OF_THE_WHOLE_TRIAD_MULTILEVEL = "PART_OF_THE_WHOLE_TRIAD_MULTILEVEL"
  HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE = "HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE"
  HTTP_ERROR_RATIO_SURGE_2STAGE = "HTTP_ERROR_RATIO_SURGE_2STAGE"
  HTTP_TARGET_SURGE_2STAGE = "HTTP_TARGET_SURGE_2STAGE"
  RADAR_360_SECTOR_WEB_HTTP = "RADAR_360_SECTOR_WEB_HTTP"
  RADAR_360_SECTOR_ALERT = "RADAR_360_SECTOR_ALERT"
  HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE = "HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE"
  HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE = "HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE"
  HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE = "HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE"
  HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE = "HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE"
  MACD_MOMENTUM_VELOCITY_2STAGE = "MACD_MOMENTUM_VELOCITY_2STAGE"
  CIRCADIAN_VON_MISES_2STAGE = "CIRCADIAN_VON_MISES_2STAGE"


@dataclass
class MetricDefinition:
  """Skill-level metadata for one metric.

  `event_type` is a nominal telemetry-vector label used for grouping (conflation
  checks, report headers). It is NOT the event filter: the events a baseline
  counts come from `malachite_catalog.baseline_semantics(metric).observed_filter`.
  `dimension_fields` are the default entity key per EntityType; each must be a
  field the compiler accepts for the metric (see malachite_catalog).
  """

  metric_id: int
  metric_name: str
  event_type: str
  supported_entity_types: List[EntityType]
  dimension_fields: Dict[EntityType, str]
  backing_log_types: List[str]
  is_vendor_scoped: bool
  default_floor_days: int
  description: str


# ALL 38 Pre-Computed Active Risk Metrics defined in Google SecOps YARA-L 2.0
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
        supported_entity_types=[EntityType.USER, EntityType.ASSET, EntityType.RESOURCE],
        dimension_fields={
            EntityType.USER: "principal.user.userid",
            EntityType.ASSET: "principal.asset.hostname",
            EntityType.RESOURCE: "target.hostname",
        },
        backing_log_types=["CHROME_MANAGEMENT", "ZSCALER", "SQUID_PROXY", "PALO_ALTO_FIREWALL", "BLUECOAT_PROXY"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Successful (2xx/3xx) HTTP web requests.",
    ),
    "http_queries_fail": MetricDefinition(
        metric_id=18,
        metric_name="http_queries_fail",
        event_type="NETWORK_HTTP",
        supported_entity_types=[EntityType.USER, EntityType.ASSET, EntityType.RESOURCE],
        dimension_fields={
            EntityType.USER: "principal.user.userid",
            EntityType.ASSET: "principal.asset.hostname",
            EntityType.RESOURCE: "target.hostname",
        },
        backing_log_types=["CHROME_MANAGEMENT", "ZSCALER", "SQUID_PROXY", "PALO_ALTO_FIREWALL", "BLUECOAT_PROXY"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Failed (4xx/5xx/Blocked) HTTP web requests.",
    ),
    "http_queries_total": MetricDefinition(
        metric_id=19,
        metric_name="http_queries_total",
        event_type="NETWORK_HTTP",
        supported_entity_types=[EntityType.USER, EntityType.ASSET, EntityType.RESOURCE],
        dimension_fields={
            EntityType.USER: "principal.user.userid",
            EntityType.ASSET: "principal.asset.hostname",
            EntityType.RESOURCE: "target.hostname",
        },
        backing_log_types=["CHROME_MANAGEMENT", "ZSCALER", "SQUID_PROXY", "PALO_ALTO_FIREWALL", "BLUECOAT_PROXY"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Total HTTP web requests.",
    ),
    "workspace_emails_sent_total": MetricDefinition(
        metric_id=20,
        metric_name="workspace_emails_sent_total",
        event_type="EMAIL_TRANSACTION",
        supported_entity_types=[EntityType.USER],
        dimension_fields={EntityType.USER: "principal.user.userid"},
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
        event_type="EDR_ALERT",
        supported_entity_types=[EntityType.ASSET],
        dimension_fields={EntityType.ASSET: "principal.asset.hostname"},
        backing_log_types=["CB_EDR", "CS_EDR", "MICROSOFT_GRAPH_ALERT", "SENTINELONE_ALERTS"],
        is_vendor_scoped=False,
        default_floor_days=7,
        description="Security rule and EDR alerts fired per entity (requires security_result.rule_name).",
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

  @staticmethod
  def resolve_identifier_field(target_metric: str, entity_type: EntityType, identifier_field: Optional[str]) -> str:
    """Returns the entity key field for `target_metric`, validated against config.textproto.

    `identifier_field` may be a full UDM path ('principal.user.email_addresses') or
    just an identifier leaf ('email_addresses'), which is applied to the metric's
    default field for `entity_type`.
    """
    metric_def = METRIC_CATALOG[target_metric]
    default_field = metric_def.dimension_fields[entity_type]
    if not identifier_field:
      return default_field
    field = identifier_field
    if "." not in identifier_field:
      field = _mc.with_identifier(default_field, identifier_field)
    expected_class = {EntityType.USER: "user", EntityType.ASSET: "device"}.get(entity_type)
    if expected_class:
      binding = _mc.entity_binding_for_field(field)
      if binding.entity_class != expected_class:
        raise ValueError(
            f"Identifier field '{field}' is a {binding.entity_class} field but entity_type is {entity_type.value}."
        )
    if _mc.is_composite_only(target_metric):
      dim = _mc.field_to_dimension().get(field)
      if not any(dim in s for s in _mc.metric_dimension_sets()[target_metric]):
        raise ValueError(
            f"'{field}' ({dim}) appears in no valid dimension set for {target_metric}: "
            f"{_mc.valid_dimension_sets_text(target_metric)}"
        )
    else:
      err = _mc.validate_filter_fields(target_metric, [field])
      if err:
        raise ValueError(err)
    return field

  @classmethod
  def audit(
      cls,
      target_metric: str,
      entity_type: EntityType,
      min_baseline_days: Optional[int] = None,
      user_log_type_filter: Optional[str] = None,
      match_mode: MatchMode = MatchMode.TIMELINE_BREAKDOWN,
      identifier_field: Optional[str] = None,
  ) -> Dict[str, Any]:
    if target_metric not in METRIC_CATALOG:
      raise ValueError(f"Unknown risk metric: {target_metric}")

    metric_def = METRIC_CATALOG[target_metric]

    if entity_type not in metric_def.supported_entity_types:
      raise ValueError(
          f"Entity type {entity_type} not supported for metric {target_metric}."
      )

    effective_floor_days = min_baseline_days if min_baseline_days is not None else metric_def.default_floor_days
    target_field = cls.resolve_identifier_field(target_metric, entity_type, identifier_field)
    semantics = _mc.baseline_semantics(target_metric)

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
        # Nominal vector label only; use event_filter for event selection.
        "required_event_type": metric_def.event_type,
        "event_filter": list(semantics.observed_filter),
        "event_label": semantics.event_label,
        "observed_agg": semantics.observed_agg,
        "metric_arg": semantics.metric_arg,
        "target_field": target_field,
        "min_baseline_days": effective_floor_days,
        "match_mode": match_mode.value,
        "math_guardrails": math_guardrails,
        "sparse_callout": sparse_callout,
    }

  @classmethod
  def audit_triad(
      cls,
      target_metrics: List[str],
      entity_type: EntityType,
      min_baseline_days: Optional[int] = None,
      identifier_field: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Audits 1 to 3 metrics for an atomic multilevel triad pipeline."""
    if not (1 <= len(target_metrics) <= 3):
      raise ValueError(f"Triad audit requires 1 to 3 metrics, got {len(target_metrics)}.")

    audits = [
        cls.audit(m, entity_type=entity_type, min_baseline_days=min_baseline_days, identifier_field=identifier_field)
        for m in target_metrics
    ]
    # Mixed metric families is the more fundamental error, so report it first.
    event_types = set(a["required_event_type"] for a in audits)
    if len(event_types) > 1:
      raise ValueError(
          f"Heterogeneous event types not permitted in atomic triad: {event_types}. "
          "All metrics must share identical event_type."
      )
    fields = {a["target_field"] for a in audits}
    if len(fields) > 1:
      raise ValueError(
          f"Triad metrics resolve to different entity fields {sorted(fields)}; one stage can bind only one. "
          "Pass identifier_field as a full UDM path valid for all three metrics."
      )
    return {
        "status": "VALID",
        "required_event_type": audits[0]["required_event_type"],
        "target_field": audits[0]["target_field"],
        "metrics": target_metrics,
        "audits": audits,
    }

  @classmethod
  def render_preflight_card(
      cls,
      target_scope: str,
      peer_cohort: str,
      statistical_model: str,
      entity_graph_dimension: str = "N/A",
      evaluation_mode: str = "Mode A: Today (Default)",
      significance_threshold: str = "Z >= 3.0σ (CRI >= 50)",
      active_days: Optional[int] = None,
      min_baseline_days: Optional[int] = None,
  ) -> str:
    """Renders the canonical PRE-FLIGHT HUNTING SPECIFICATION Card.

    Flags 'Sparse Baseline Caution' whenever active days or min_baseline_days N < 7.
    """
    effective_n = active_days if active_days is not None else min_baseline_days
    is_sparse = effective_n is not None and effective_n < 7

    spine_line = (
        f"• Baseline Horizon Spine: 30-Day Pre-Computed (period: 1d, 30d) [⚠️ Sparse Baseline Caution: N = {effective_n} < 7]"
        if is_sparse
        else "• Baseline Horizon Spine: 30-Day Pre-Computed (period: 1d, 30d)"
    )

    card = (
        "```markdown\n"
        "┌─────────────────────────────────────────────────────────────────┐\n"
        "│                PRE-FLIGHT HUNTING SPECIFICATION                 │\n"
        f"│ • Target Entity / Scope:  {target_scope:<38}│\n"
        f"│ {spine_line:<64}│\n"
        f"│ • Peer Cohort & Roster:   {peer_cohort:<38}│\n"
        f"│ • Entity Graph Dimension: {entity_graph_dimension:<38}│\n"
        f"│ • Evaluation Horizon Mode:{evaluation_mode:<38}│\n"
        f"│ • Statistical Model:      {statistical_model:<38}│\n"
        f"│ • Significance Threshold: {significance_threshold:<38}│\n"
        "└─────────────────────────────────────────────────────────────────┘\n"
        "```"
    )

    if is_sparse:
      callout = (
          "\n\n> [!WARNING]\n"
          f"> **⚠️ Sparse Baseline Caution (N = {effective_n} < 7 Active Days)**:\n"
          f"> Evaluating entities with fewer than 7 active baseline days reduces statistical "
          "degrees of freedom and inflates false-positive Z-scores. We enforce an active-day floor and recommend "
          "Empirical Bayes shrinkage to regularize sparse observations."
      )
      return card + callout

    return card


# UDM filter fields usable per metric (union over every valid dimension set), derived
# from the vendored compiler configuration (data/malachite/). A field listed here is
# necessary but not sufficient: the combination of filters in one metrics.*() call must
# also form exactly one valid dimension set (see UNSUPPORTED_DIMENSION_SET).
MALACHITE_SUPPORTED_FILTERS: Dict[str, Set[str]] = {
    m: _mc.supported_filter_fields(m) for m in sorted(_mc.known_metrics())
}

# Filters that appear in EVERY valid dimension set of the metric. Consistency with
# config.textproto is enforced by tests/test_malachite_catalog.py.
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
    # EDR and security rule alert metrics strictly require security_result.rule_name
    "alert_event_name_count": {"security_result.rule_name"},
}


class MalachiteASTValidator:
  """Enforces Google SecOps compiler rules and mathematical AST constraints on YARA-L 2.0 queries."""

  CLOUD_RESOURCE_EVENTS = frozenset({"RESOURCE_CREATION", "RESOURCE_READ", "RESOURCE_WRITTEN", "RESOURCE_DELETION"})
  STANDARD_METRIC_PARAMS = frozenset({"period", "window", "metric", "agg", "filter"})

  @staticmethod
  def _metric_filter_hint(m_lower: str, param: str, valid_filters: Set[str]) -> str:
    if param == "principal.ip" and "principal.asset.ip" in valid_filters:
      return " (In Chronicle, device IP filtering requires 'principal.asset.ip' or 'principal.asset.hostname')"
    if param == "target.ip" and "target.asset.ip" in valid_filters:
      return " (In Chronicle, device IP filtering requires 'target.asset.ip' or 'target.asset.hostname')"
    if m_lower.startswith("http_queries"):
      if param == "target.url":
        return " (In Chronicle Malachite, HTTP metrics only baseline 'target.hostname'. Full URL/URI analysis must be performed in raw event companion stages or via secops-statistical-hunter.)"
      if param in ("target.ip", "target.asset.ip"):
        return " (In Chronicle Malachite, HTTP metrics support 'target.hostname'. For IP destination baselines use 'metrics.dns_bytes_outbound' or secops-statistical-hunter.)"
      if param in ("network.http.response_code", "network.http.method"):
        return " (In Chronicle Malachite, HTTP methods/response codes are partitioned at ingest into 'metrics.http_queries_fail' and 'metrics.http_queries_success', not dynamic filters.)"
    if m_lower.startswith("dns_queries"):
      if param == "network.dns.questions.name":
        return " (In Chronicle Malachite, DNS query metrics baseline 'network.dns_domain' or 'network.dns.questions.type', not full question name 'network.dns.questions.name'.)"
      if param in ("target.hostname", "target.ip"):
        return " (In Chronicle Malachite, DNS query metrics baseline 'network.dns_domain', not target hostname or IP.)"
    return ""

  @staticmethod
  def _validate_metric_calls(location: str, body: str) -> List[str]:
    """Validates every metrics.*() call in `body` against the compiler configuration.

    `location` is "stage '<name>'" or "root stage" and prefixes each message.
    """
    errors: List[str] = []
    for m_name, args_body in re.findall(r"metrics\.([a-zA-Z0-9_]+)\s*\(([^)]+)\)", body, re.DOTALL):
      m_lower = m_name.lower()
      called_params = re.findall(r"([a-zA-Z0-9_.]+)\s*:", args_body)
      filter_keys = [p for p in called_params if p not in MalachiteASTValidator.STANDARD_METRIC_PARAMS]
      has_slots = "{{" in args_body

      unsupported = False
      if m_lower in MALACHITE_SUPPORTED_FILTERS:
        valid_filters = MALACHITE_SUPPORTED_FILTERS[m_lower]
        for param in filter_keys:
          if param not in valid_filters:
            unsupported = True
            hint = MalachiteASTValidator._metric_filter_hint(m_lower, param, valid_filters)
            errors.append(
                f"INVALID_METRIC_FILTER in {location}: '{param}' is not a supported filter for 'metrics.{m_name}'.{hint}"
            )

      missing_dims: Set[str] = set()
      if m_lower in MALACHITE_MANDATORY_FILTERS:
        missing_dims = MALACHITE_MANDATORY_FILTERS[m_lower] - set(filter_keys)
        if missing_dims and not has_slots:
          hint = ""
          if "metadata.vendor_name" in missing_dims:
            hint = " In Chronicle Malachite, all Cloud CRUD metrics require both 'metadata.vendor_name' and 'metadata.product_name' when filtering by user/asset."
          elif "principal.process.file.sha256" in missing_dims:
            hint = " In Chronicle Malachite, process execution metrics require both 'metadata.event_type' and 'principal.process.file.sha256'."
          elif "security_result.rule_name" in missing_dims:
            hint = " In Chronicle Malachite, 'metrics.alert_event_name_count' requires companion dimension 'security_result.rule_name'."
          errors.append(
              f"MISSING_MANDATORY_FILTER in {location}: Metric 'metrics.{m_name}' is missing required companion dimension(s): {sorted(list(missing_dims))}.{hint}"
          )

      # The compiler maps every filter to its dimension and requires the resulting SET to equal one of
      # the metric's valid dimension sets (ueba_validator.go). Individually valid filters can still fail.
      if m_lower in _mc.known_metrics() and not has_slots and not unsupported and not missing_dims:
        set_err = _mc.validate_filter_fields(m_lower, filter_keys)
        if set_err:
          errors.append(
              f"UNSUPPORTED_DIMENSION_SET in {location}: {set_err}. Valid sets: "
              f"{_mc.valid_dimension_sets_text(m_lower)}"
          )

      # Metric type parameter (value_sum vs event_count_sum)
      if "metric_value_sum" in args_body:
        errors.append(
            f"INVALID_METRIC_TYPE in {location}: 'metric_value_sum' is invalid in Google SecOps YARA-L 2.0. "
            "Use 'metric: value_sum' for volume metrics or 'metric: event_count_sum' for count metrics."
        )
      m_type_match = re.search(r"\bmetric\s*:\s*([a-zA-Z0-9_]+)", args_body)
      if m_type_match:
        m_type_val = m_type_match.group(1)
        if m_lower in _mc.known_metrics():
          expected = _mc.baseline_semantics(m_lower).metric_arg
        else:
          expected = "value_sum" if "bytes" in m_lower else "event_count_sum"
        if m_type_val not in ("value_sum", "event_count_sum"):
          errors.append(
              f"INVALID_METRIC_TYPE in {location}: Unsupported metric type '{m_type_val}' for 'metrics.{m_name}'. "
              "In Google SecOps YARA-L 2.0, metric baseline functions strictly accept 'value_sum' or 'event_count_sum'."
          )
        elif expected == "value_sum" and m_type_val != "value_sum":
          errors.append(
              f"METRIC_TYPE_MISMATCH in {location}: Byte-volume metric 'metrics.{m_name}' must use 'metric: value_sum', found '{m_type_val}'."
          )
        elif expected == "event_count_sum" and m_type_val == "value_sum":
          errors.append(
              f"METRIC_TYPE_MISMATCH in {location}: Count-based metric 'metrics.{m_name}' must use 'metric: event_count_sum', found '{m_type_val}'."
          )
    return errors


  @staticmethod
  def validate_query(query_text: str) -> List[str]:
    errors = []

    # 1. Methodology & Goal Comment Header
    if not re.search(r"//\s*(?:Goal:|ARCHITECTURE:|Sector:|Stage\s*\d*:)", query_text, re.IGNORECASE):
      errors.append("MISSING_GOAL_HEADER: Query must start with a '// Goal:' or '// ARCHITECTURE:' methodology comment.")

    # 1B. Global Invalid Tokens & Math Functions (checked on stripped code)
    clean_code = re.sub(r"//[^\n]*", "", query_text)
    clean_code = re.sub(r"/\*.*?\*/", "", clean_code, flags=re.DOTALL)

    code_no_literals = re.sub(r'"(?:\\.|[^"\\])*"', '""', clean_code)
    code_no_literals = re.sub(r'/(?:\\.|[^/\\])+/', '//', code_no_literals)
    if "^" in code_no_literals:
      errors.append("INVALID_EXPONENT_OPERATOR: '^' is invalid in YARA-L. Use 'math.pow($var, 2)' or '$var * $var' for squared terms.")
    for full_call, inner_content in MalachiteASTValidator._extract_if_invocations(clean_code):
      args = MalachiteASTValidator._split_top_level_csv(inner_content)
      if len(args) < 3:
        errors.append(f"INVALID_IF_CONDITIONAL: 'if(...)' is missing required else-clause: {full_call}")
      else:
        then_clause = re.sub(r"^\s*[-+]\s*", "", args[1])
        if re.search(r"[\+\-\*\/]", then_clause):
          errors.append(f"INVALID_IF_CONDITIONAL: 'if(...)' contains compound arithmetic in then-clause. Chronicle compiler only allows placeholders, fields, and constants in then clause: {full_call}")
    if re.search(r"\bcount\s*\(\s*if\s*\(", clean_code, re.IGNORECASE):
      errors.append("INVALID_AGGREGATE_FUNCTION: 'count(if(...))' is unsupported in YARA-L 2.0. Use 'sum(if(condition, 1, 0))' for conditional counting.")
    if re.search(r"=\s*\/[^\/\n]+\/\s*\|\s*\/", clean_code):
      errors.append("INVALID_REGEX_ALTERNATION: Alternation with '|' outside regex delimiters is invalid. Combine into a single regex literal (e.g. '/(pattern1|pattern2)/ nocase').")
    bare_math_match = re.search(r"(?<!math\.)\b(sqrt|pow|abs|log|floor|ceil|round)\s*\(", clean_code, re.IGNORECASE)
    if bare_math_match:
      fn_name = bare_math_match.group(1).lower()
      if fn_name == "sqrt":
        errors.append("INVALID_SQRT_FUNCTION: Bare 'sqrt(...)' is invalid in YARA-L outcome expressions. Use namespaced 'math.sqrt(...)', or compute squared norm and order by '$norm_sq desc'.")
      else:
        errors.append(f"INVALID_BARE_MATH_FUNCTION: Bare '{fn_name}(...)' is invalid in YARA-L. Use namespaced 'math.{fn_name}(...)'.")
    for m in re.finditer(r"math\.round\s*\(([^)]+)\)", clean_code):
      r_args = MalachiteASTValidator._split_top_level_csv(m.group(1))
      if len(r_args) < 1 or len(r_args) > 2:
        errors.append(f"INVALID_ROUND_ARITY: 'math.round(...)' expects 1 or 2 arguments, got {len(r_args)}: {m.group(0)}")
    outcome_blocks = re.findall(r"outcome:\s*(.*?)(?=\n\s*(?:condition|match|\}|$))", query_text, re.DOTALL)
    for ob in outcome_blocks:
      clean_ob = re.sub(r"//[^\n]*", "", ob)
      clean_ob = re.sub(r"/\*.*?\*/", "", clean_ob, flags=re.DOTALL)
      if re.search(r"\[\s*[^\]]*\s*\]", clean_ob):
        errors.append("INVALID_LITERAL_ARRAY_IN_OUTCOME: Literal array notation '[...]' is unsupported in outcome expressions under Malachite compiler.")
    if re.search(r"\b[a-zA-Z0-9_]+\.\$[a-zA-Z0-9_]+", clean_code):
      errors.append("INVALID_STAGE_VARIABLE_SYNTAX: Multi-stage variable references must use '$stage.var', not 'stage.$var' (placing '$' after the dot causes an ANTLR syntax crash).")
    if re.search(r"^\s*rule\s+[a-zA-Z0-9_]+\s*\{", clean_code, re.MULTILINE):
      errors.append(
          "INVALID_DETECTION_RULE_SYNTAX: Multi-stage threat hunting queries must be ad-hoc search queries ('stage name { ... }' + root stage), not continuous detection rules ('rule ... { ... }')."
      )

    # 2. Stage count & naming rules
    stage1_matches, root_body = MalachiteASTValidator._extract_stage_blocks(query_text)
    named_stages = [s[0] for s in stage1_matches]
    named_stage_set = {s.lstrip("$") for s in named_stages}

    for s_name in named_stages:
      if s_name.startswith("$"):
        errors.append(f"STAGE_NAME_PREFIX_ERROR: Stage '{s_name}' must not have a '$' prefix.")

    if len(named_stages) > 4:
      errors.append(f"STAGE_LIMIT_EXCEEDED: Query defines {len(named_stages)} stages (max allowed is 4).")

    # 2B. Multi-Stage Data Source Limits (get_structured_query_view_utils.cc:3040-3064)
    # Chronicle Search enforces hard caps across all stages combined:
    #   - source_count_limits["udm"] = 2 (FLAGS_malachite_search_join_query_max_event_tables_joined)
    #   - source_count_limits["entity"] = 1 (FLAGS_malachite_search_max_ecg_event_tables_in_event_ecg_join)
    total_udm_sources = 0
    total_ecg_sources = 0
    for _, s_body in stage1_matches:
      u_cnt, e_cnt = MalachiteASTValidator._count_stage_data_sources(s_body, named_stage_set)
      total_udm_sources += u_cnt
      total_ecg_sources += e_cnt
    if root_body.strip():
      u_cnt, e_cnt = MalachiteASTValidator._count_stage_data_sources(root_body, named_stage_set)
      total_udm_sources += u_cnt
      total_ecg_sources += e_cnt

    if total_udm_sources > 2:
      errors.append(
          f"UDM_SOURCE_LIMIT_EXCEEDED: Number of UDM events exceeded max limit: {total_udm_sources} > 2 "
          "(Chronicle Search caps total UDM event sources across all stages at 2; use at most 2 UDM stages per query "
          "or decouple into parallel 360° sector micro-queries)."
      )
    if total_ecg_sources > 1:
      errors.append(
          f"ECG_SOURCE_LIMIT_EXCEEDED: Number of ECG events exceeded max limit: {total_ecg_sources} > 1 "
          "(Chronicle Search caps total Entity Context Graph sources across all stages at 1)."
      )

    # 3. Stage 1 Extraction Contracts
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

      # Check for hallucinated user agent UDM paths in stage body
      if re.search(r"\b(?:target|principal)\.(?:http\.)?user_agent\b", stage_body) or re.search(r"(?<!network\.)\bhttp\.user_agent\b", stage_body):
        errors.append(
            f"INVALID_UDM_PATH in stage '{stage_name}': User-Agent string is located at 'network.http.user_agent' in UDM (udm.proto Line 3889), not 'target.user_agent'."
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

      # Anti-Pattern 6: Single-stage multi-vector cramming. OR'd event types are allowed only when they
      # all belong to the baselines of the metrics evaluated in the stage (e.g. resource_read_* counts
      # RESOURCE_READ and USER_RESOURCE_ACCESS).
      distinct_event_types = set(re.findall(r"metadata\.event_type\s*==?\s*[\"']([A-Z_]+)[\"']", stage_body))
      metrics_calls = re.findall(r"metrics\.([a-zA-Z0-9_]+)\s*\(", stage_body)
      allowed_event_types = set(MalachiteASTValidator.CLOUD_RESOURCE_EVENTS)
      for m in metrics_calls:
        if m in _mc.known_metrics():
          allowed_event_types |= set(_mc.baseline_semantics(m).event_types)
      if len(distinct_event_types) > 1 and metrics_calls and not (distinct_event_types <= allowed_event_types):
        errors.append(
            f"ANTI-PATTERN 6 (Single-Stage Multi-Vector Cramming in stage '{stage_name}'): Stage contains multiple OR'd "
            f"event types {distinct_event_types} while evaluating metrics. Use independent DAG stages fused in Root stage."
        )

      # Anti-Pattern 6B: Multi-vector metric conflation within single stage
      metric_event_types = {METRIC_CATALOG[m].event_type for m in metrics_calls if m in METRIC_CATALOG}
      if len(metric_event_types) > 1 and not (metric_event_types <= MalachiteASTValidator.CLOUD_RESOURCE_EVENTS):
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

      # Metric filter validation against the compiler configuration
      errors.extend(MalachiteASTValidator._validate_metric_calls(f"stage '{stage_name}'", stage_body))

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

    if stage1_matches:
      has_root_match = bool(re.search(r"\bmatch:\s*", root_body))
      has_root_outcome_or_cond = bool(re.search(r"\b(?:outcome|condition):\s*", root_body))
      if not (has_root_match and has_root_outcome_or_cond):
        errors.append(
            "MISSING_ROOT_STAGE: Multi-stage query defines named 'stage ... { }' blocks but lacks an unwrapped terminal root stage "
            "(with 'match:' and 'outcome:'/'condition:'). Named stages cannot execute without a terminal root stage."
        )

    # Check for hallucinated user agent UDM paths in root body
    if re.search(r"\b(?:target|principal)\.(?:http\.)?user_agent\b", root_body) or re.search(r"(?<!network\.)\bhttp\.user_agent\b", root_body):
      errors.append(
          "INVALID_UDM_PATH in root stage: User-Agent string is located at 'network.http.user_agent' in UDM (udm.proto Line 3889), not 'target.user_agent'."
      )

    # Check root stage metric calls
    errors.extend(MalachiteASTValidator._validate_metric_calls("root stage", root_body))

    # Check for events: header in root stage
    if re.search(r"^\s*events:\s*", root_body, re.MULTILINE):
      errors.append(
          "INVALID_EVENTS_SECTION_IN_ROOT: Root stage of a multi-stage query must not contain an 'events:' header block. "
          "Stage variable bindings (e.g. '$host = $stage1.host') must be declared directly at the root level before match:."
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
      min_required_stages = 3 if "4-STAGE" in query_text.upper() else 2
      if len(named_stages) < min_required_stages:
        errors.append(
            f"PIPELINE ARCHITECTURE MISMATCH: Multi-Sector Threat Fusion requires {min_required_stages} distinct extractor stages (found {len(named_stages)})."
        )
        errors.append(
            f"STAGE PARITY ERROR: Stage count ({len(named_stages)}) does not match required telemetry sectors ({min_required_stages})."
        )

    return errors

  @staticmethod
  def _extract_stage_blocks(query_text: str) -> Tuple[List[Tuple[str, str]], str]:
    """Extracts named stage blocks and the trailing root stage using balanced braces (ignoring {{...}} placeholders)."""
    masked = re.sub(r"\{\{[^}]*\}\}", lambda m: "_" * len(m.group(0)), query_text)
    stages: List[Tuple[str, str]] = []
    last_end = 0
    for m in re.finditer(r"\bstage\s+(\$?[a-zA-Z0-9_]+)\s*\{", masked):
      sname = m.group(1)
      start_brace = m.end() - 1
      depth = 0
      i = start_brace
      while i < len(masked):
        if masked[i] == "{":
          depth += 1
        elif masked[i] == "}":
          depth -= 1
          if depth == 0:
            stages.append((sname, query_text[start_brace + 1 : i]))
            last_end = max(last_end, i + 1)
            break
        i += 1
    return stages, query_text[last_end:]

  @staticmethod
  def _count_stage_data_sources(body: str, named_stage_set: Set[str]) -> Tuple[int, int]:
    """Counts distinct UDM event sources and ECG ('entity') sources within a single stage body."""
    clean = re.sub(r"//[^\n]*", "", body)
    clean = re.sub(r"/\*.*?\*/", "", clean, flags=re.DOTALL)
    clean = re.sub(r"\{\{[^}]*\}\}", "", clean)
    clean = re.sub(r'"(?:\\.|[^"\\])*"', '""', clean)
    clean = re.sub(r"/(?:\\.|[^/\\])+/", "//", clean)
    # Strip metrics.*(...) calls so dimension filter keys inside UEBA functions are not counted as UDM event sources
    no_metrics = re.sub(r"metrics\.[a-zA-Z0-9_]+\s*\([^)]*\)", "", clean, flags=re.DOTALL)

    ecg_aliases = set(re.findall(r"\$([a-zA-Z0-9_]+)\.graph\.", no_metrics)) - named_stage_set
    unprefixed_ecg = bool(re.search(r"(?<![a-zA-Z0-9_$.])\bgraph\.(?:entity|metadata|relations)\b", no_metrics))
    ecg_count = len(ecg_aliases) + (1 if unprefixed_ecg else 0)

    udm_roots = r"(?:metadata|principal|target|src|observer|intermediary|about|network|security_result|additional|extensions)"
    udm_aliases = set(re.findall(rf"\$([a-zA-Z0-9_]+)\.{udm_roots}\.", no_metrics)) - named_stage_set
    unprefixed_udm = bool(re.search(rf"(?<![a-zA-Z0-9_$.])\b{udm_roots}\.", no_metrics))
    udm_count = len(udm_aliases) + (1 if unprefixed_udm else 0)
    return udm_count, ecg_count

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
    # Check for member access or stage-scoped dot references in match: (e.g. $s1.host)
    if re.search(r"\$[a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+", match_part):
      errors.append(
          f"INVALID_MATCH_MEMBER_ACCESS in stage '{stage_name}': Match section cannot contain member access or "
          "stage-scoped dot references like '$s1.host'. In YARA-L, match variables must be simple identifiers ('$host'). "
          "Bind stage variables in events ('$host = $stage.host') before match:."
      )
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
  def _extract_if_invocations(text: str) -> List[Tuple[str, str]]:
    results = []
    for match in re.finditer(r"\bif\s*\(", text):
      start_pos = match.end() - 1
      depth = 0
      i = start_pos
      while i < len(text):
        if text[i] == '(':
          depth += 1
        elif text[i] == ')':
          depth -= 1
          if depth == 0:
            full_call = text[match.start():i+1]
            inner_content = text[start_pos+1:i]
            results.append((full_call, inner_content))
            break
        i += 1
    return results

  @staticmethod
  def _split_top_level_csv(inner: str) -> List[str]:
    args = []
    cur = []
    depth = 0
    for ch in inner:
      if ch in '([':
        depth += 1
        cur.append(ch)
      elif ch in ')]':
        depth -= 1
        cur.append(ch)
      elif ch == ',' and depth == 0:
        args.append(''.join(cur).strip())
        cur = []
      else:
        cur.append(ch)
    if cur:
      args.append(''.join(cur).strip())
    return args

  @staticmethod
  def validate_model_concordance(query_text: str, model: StatisticalModel) -> List[str]:
    errors = []
    stage_blocks = re.findall(r"(?:stage\s+([a-zA-Z0-9_]+)\s*\{)", query_text)
    named_stages = [s for s in stage_blocks if s]

    # Stage count & topology validation
    if model in [StatisticalModel.STANDARD_Z_SCORE, StatisticalModel.MAD, StatisticalModel.POISSON,
                 StatisticalModel.VARIANCE, StatisticalModel.COEFFICIENT_OF_VARIATION,
                 StatisticalModel.HOURLY_TEMPORAL_ZSCORE, StatisticalModel.LONGITUDINAL_CUSUM,
                 StatisticalModel.TWO_PART_HURDLE, StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z,
                 StatisticalModel.PIECEWISE_CRI, StatisticalModel.FLEET_PREVALENCE_SHIELD,
                 StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD, StatisticalModel.MACD_MOMENTUM_VELOCITY,
                 StatisticalModel.CIRCADIAN_VON_MISES]:
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
      if "+ 1.0" not in query_text and "if(" not in query_text and "stddev" not in query_text.lower():
        errors.append("MODEL_FORMULA_MISMATCH: Standard Z-Score must apply dispersion floor (+ 1.0) or nested logic if($std > 0, $std, 1.0) to denominator.")
    elif model == StatisticalModel.MACD_MOMENTUM_VELOCITY:
      if "macd" not in query_text.lower() and "slow_z" not in query_text:
        errors.append("MODEL_FORMULA_MISMATCH: MACD model must include dual-spine momentum differential ($macd_diff).")
    elif model == StatisticalModel.CIRCADIAN_VON_MISES:
      if "circ" not in query_text.lower() and "von_mises" not in query_text.lower():
        errors.append("MODEL_FORMULA_MISMATCH: Circadian von Mises model must compute circular distance on 24-hour clock.")

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

