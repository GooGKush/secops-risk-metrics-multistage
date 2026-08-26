# Google SecOps Risk Metrics Reference Catalog (38 Metrics)

This catalog details all 38 active pre-computed behavioral risk metrics available in Google SecOps UEBA &amp; Risk Analytics.

---

## 1. Authentication Attempts
* **Log Scope:** `metadata.event_type = "USER_LOGIN"`
* **Backing Log Types:** `OKTA`, `AZURE_AD`, `WINEVTLOG_SECURITY`, `WORKSPACE`, `PING_IDENTITY`, `DUO`

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.auth_attempts_total` | All login events (success & fail) | `principal.user.userid`, `target.user.userid`, `principal.asset.hostname`, `principal.asset.ip`, `target.asset.hostname`, `target.application`, `http_user_agent` |
| `metrics.auth_attempts_success` | Logins where `security_result.action = "ALLOW"` | Same as total |
| `metrics.auth_attempts_fail` | Logins where `security_result.action != "ALLOW"` | Same as total |
| `metrics.workspace_auth_attempts_total` | Google Workspace login events | `principal.user.userid`, `target.user.userid` |

---

## 2. Network Bytes & Volume
* **Log Scope:** `metadata.event_type = "NETWORK_CONNECTION"`
* **Backing Log Types:** `PALO_ALTO_FIREWALL`, `ZEEK`, `ZSCALER`, `NETFLOW`, `FORTINET_FIREWALL`, `CHECKPOINT_FIREWALL`

| Metric Function | Value Measured (`value_sum`) | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.network_bytes_outbound` | `network.sent_bytes` | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid`, `principal.ip_geo_artifact.location.country_or_region` |
| `metrics.network_bytes_inbound` | `network.received_bytes` | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid` |
| `metrics.network_bytes_total` | Inbound + Outbound bytes | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid` |

---

## 3. Network Flows & Connections
* **Log Scope:** `metadata.event_type = "NETWORK_CONNECTION"`
* **Backing Log Types:** NetFlow, VPC Flow Logs, Firewall connection sessions

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.network_flows_outbound` | Outbound flow count | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid` |
| `metrics.network_flows_inbound` | Inbound flow count | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid` |
| `metrics.network_flows_total` | Total connection flows | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid` |

---

## 4. DNS Queries & Egress Bytes
* **Log Scope:** `metadata.event_type = "NETWORK_DNS"`
* **Backing Log Types:** `INFOBLOX`, `BIND`, `COREDNS`, `WINDOWS_DNS`, `ZEEK_DNS`

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.dns_queries_total` | Total DNS queries | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid`, `network.dns_domain` |
| `metrics.dns_queries_success` | Response code 0 (NOERROR) | Same as total |
| `metrics.dns_queries_fail` | Response code > 0 (NXDOMAIN/SERVFAIL) | Same as total |
| `metrics.dns_bytes_outbound` | Bytes over port 53/3000 | `principal.asset.hostname`, `principal.asset.ip`, `target.ip` |

---

## 5. File & Process Executions
* **Log Scope:** `metadata.event_type = "PROCESS_LAUNCH"`
* **Backing Log Types:** `CROWDSTRIKE`, `SENTINELONE`, `MICROSOFT_DEFENDER`, `CARBON_BLACK`

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.file_executions_total` | Total process launches | `metadata.event_type` + `principal.process.file.sha256` + [`principal.asset.hostname` \| `principal.user.userid` \| `principal.asset.ip`] *(Note: `metadata.event_type` is mandatory)* |
| `metrics.file_executions_success` | Successful launches | Same as total |
| `metrics.file_executions_fail` | Blocked / failed executions | Same as total |
| `metrics.alert_event_name_count` | EDR alert counts | `principal.asset.hostname`, `security_result.rule_name`, `principal.user.userid` |

---

## 6. HTTP & Web Queries
* **Log Scope:** `metadata.event_type = "NETWORK_HTTP"`
* **Backing Log Types:** `ZSCALER`, `SQUID_PROXY`, `BLUECOAT_PROXY`, `NGINX`

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.http_queries_total` | Total HTTP requests | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid`, `http_user_agent` |
| `metrics.http_queries_success` | HTTP 2xx/3xx responses | Same as total |
| `metrics.http_queries_fail` | HTTP 4xx/5xx responses | Same as total |

---

## 7. Cloud Resource Lifecycle (CRUD)
* **Log Scope:** `metadata.event_type = "RESOURCE_CREATION" | "RESOURCE_DELETION" | "RESOURCE_READ" | "RESOURCE_WRITTEN"`
* **Backing Log Types:** `GCP_CLOUDAUDIT`, `AWS_CLOUDTRAIL`, `AZURE_ACTIVITY`

| Metric Function Family | Operations Covered | Supported Dimensions |
| :--- | :--- | :--- |
| `metrics.resource_creation_*` | `total`, `success`, `fail` | `principal.user.userid`, `target.resource.name`, `target.resource.resource_type` |
| `metrics.resource_deletion_*` | `total`, `success`, `fail` | `principal.user.userid`, `target.resource.name`, `target.resource.resource_type` |
| `metrics.resource_read_*` | `total`, `success`, `fail` | `principal.user.userid`, `target.resource.name`, `target.resource.resource_type` |
| `metrics.resource_written_*` | `total`, `success`, `fail` | `principal.user.userid`, `target.resource.name`, `target.resource.resource_type` |

---

## 8. Google Workspace Telemetry
* **Log Scope:** `metadata.event_type = "USER_UNCATEGORIZED" | "EMAIL_TRANSACTION"`
* **Backing Log Types:** `WORKSPACE_REPORTS`, `GMAIL`

| Metric Function | Description | Supported Dimensions |
| :--- | :--- | :--- |
| `metrics.workspace_emails_sent_total` | Outbound emails sent | `principal.user.userid` |
| `metrics.workspace_network_bytes_outbound` | Google Drive / Docs outbound bytes | `principal.user.userid` |
| `metrics.workspace_network_bytes_total` | Total Workspace byte volume | `principal.user.userid` |
| `metrics.workspace_total_change_actions` | File edit / permissions changes | `principal.user.userid` |
| `metrics.workspace_total_download_actions` | File export / download actions | `principal.user.userid` |
