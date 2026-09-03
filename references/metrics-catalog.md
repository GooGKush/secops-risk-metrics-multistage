# Google SecOps Risk Metrics Reference Catalog (38 Metrics)

This catalog details all 38 active pre-computed behavioral risk metrics available in Google SecOps UEBA & Risk Analytics.

> [!IMPORTANT]
> **Device IP Filtering Invariant (`principal.asset.ip` vs. `principal.ip`)**:
> In Google SecOps Chronicle Malachite, device IP filtering requires `principal.asset.ip` (mapping to the `PRINCIPAL_DEVICE` dimension) or `target.asset.ip` (mapping to `TARGET_DEVICE`).
> Passing `principal.ip` (which maps to the `PRINCIPAL_IP` dimension) to network, authentication, DNS, HTTP, or process execution metrics causes a fatal compile-time failure:  
> `compilation error: validating ueba functions: unsupported filters for metric ...`  
> The `principal.ip` filter is strictly supported **only** on Cloud Resource CRUD (`resource_*`) and Google Workspace metrics. For all network connections, firewalls, logins, and endpoint telemetry, always filter by `principal.asset.ip` or `principal.asset.hostname`.

> [!IMPORTANT]
> **Entity Dimension Roles: Principal vs. Target Semantics (`principal.user.userid` vs. `target.user.userid`)**:
> Chronicle UDM explicitly separates the actor initiating an action (`principal`) from the object being acted upon (`target`):
> 1. **User as Target (`target.user.userid`)**:
>    - **Authentication (`USER_LOGIN`)**: The user account being accessed is the target of the authentication attempt. In IdP logs (Okta, Azure AD, Windows 4624/4625), the account identity resides in `target.user.userid`. When profiling logins for a user, the event filter is `target.user.userid = "<id>"` and the metric filter is `target.user.userid: "<id>"` (or `$user`).
> 2. **User as Principal (`principal.user.userid`)**:
>    - **Cloud Resource CRUD (`RESOURCE_CREATION` / `DELETION`)**: The IAM identity or service account creating or deleting cloud infrastructure.
>    - **Google Workspace & SaaS (`USER_RESOURCE_ACCESS`)**: The user downloading, sharing, or editing Drive files.
>    - **Network Traffic (`NETWORK_CONNECTION`)**: The user initiating outbound flows.
>    - **Process Executions (`PROCESS_LAUNCH`)**: The user executing binaries or administrative tools.
>    - In all these sectors, the event filter is `principal.user.userid = "<id>"` and the metric filter is `principal.user.userid: "<id>"` (or `$user`). Passing `target.user.userid` to these metrics causes compiler rejection (`unsupported filters for metric`) or zero matches.
> 3. **Assets (`principal.asset.hostname` / `principal.asset.ip`)**:
>    - For asset profiling, host is `principal.asset.hostname` across network, endpoint, DNS, and login events.
>    - Device IP filtering strictly requires `principal.asset.ip` (mapping to `PRINCIPAL_DEVICE`), whereas `principal.ip` is rejected on network, auth, DNS, and endpoint metrics.
> 4. **User Display Names vs. Technical User IDs (`user.user_display_name` vs. `user.userid`)**:
>    - **Technical User ID Dimension**: All 38 UEBA pre-computed metric tables (`metrics.*`) are partitioned and indexed strictly by the technical logon account identifier (`sAMAccountName`, UPN, or email prefix, e.g. `jholden`, `james.holden`, `fkolzig`).
>    - **Human Display Names**: Human names containing spaces (e.g. `"James Holden"`, `"Frank Kolzig"`) are Display Names (`user.user_display_name`), NOT `user.userid`. Passing a display name directly to `target.user.userid = "James Holden"` or metric filters will match zero events and zero baseline rows in Chronicle.
>    - **Pre-Flight Identity Spot Check**: When an analyst specifies a human display name, the agent executes a single lightweight spot check query to resolve the corresponding technical `userid`:
>      ```udm
>      target.user.user_display_name = "<Display Name>" nocase or principal.user.user_display_name = "<Display Name>" nocase
>      ```
>    - **Confirmation Gate**: The resolved `userid` must be presented in the Pre-Flight Card (e.g. `• Target Entity / Scope: James Holden (Resolved User ID: jholden)`) and explicitly confirmed with the analyst before compiling hunting queries. If the display name is not found in the current tenant's logs/enrichments, the agent must prompt the analyst for the technical `userid`.

---

## 1. Authentication Attempts
* **Log Scope:** `metadata.event_type = "USER_LOGIN"`
* **Backing Log Types:** `OKTA`, `AZURE_AD`, `WINEVTLOG_SECURITY`, `WORKSPACE`, `PING_IDENTITY`, `DUO`
* **Device IP Filter Note:** Use `principal.asset.ip` (not `principal.ip`) for source device IP filtering.

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
* **Device IP Filter Note:** Use `principal.asset.ip` (not `principal.ip`) for source device IP filtering.

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

| Metric Function Family | Operations Covered | Supported Dimensions (Entity Types & Required Attributes) |
| :--- | :--- | :--- |
| `metrics.resource_creation_*` | `total`, `success`, `fail` | `principal.user.userid` (or `target.user.userid`) + `metadata.vendor_name` + `metadata.product_name` (+ optional `target.resource.name`) |
| `metrics.resource_deletion_*` | `total`, `success`, `fail` | `principal.user.userid` (or `target.user.userid`) + `metadata.vendor_name` + `metadata.product_name` (+ optional `target.resource.name`) |
| `metrics.resource_read_*` | `total`, `success`, `fail` | `principal.user.userid` (or `target.user.userid`) + `metadata.vendor_name` + `metadata.product_name` (+ optional `target.resource.name`) |
| `metrics.resource_written_*` | `total`, `success`, `fail` | `principal.user.userid` (or `target.user.userid`) + `metadata.vendor_name` + `metadata.product_name` (+ optional `target.resource.name`) |

> [!IMPORTANT]
> **Mandatory Vendor & Product Scoping Invariant for Cloud CRUD (`resource_*`)**:
> In Google SecOps Chronicle Malachite, all Cloud Resource Lifecycle metrics (`metrics.resource_creation_*`, `metrics.resource_deletion_*`, `metrics.resource_read_*`, `metrics.resource_written_*`) **strictly require** both `metadata.vendor_name` AND `metadata.product_name` when filtering by user (`principal.user.userid`) or device.
> Calling a Cloud CRUD metric with `principal.user.userid` alone causes a fatal compile-time failure:  
> `compilation error: validating ueba functions: unsupported filters for metric RESOURCE_*`  
> Always match `$v = metadata.vendor_name, $p = metadata.product_name` in the event/match section and pass `metadata.vendor_name: $v, metadata.product_name: $p` into the metric function call.

### Service Account Cloud Repository & Origin IP Monitoring
* **Actor & Principal Role**: Service accounts in cloud IAM (e.g. `*.iam.gserviceaccount.com`, AWS IAM Role ARN) are tracked via `principal.user.userid`.
* **Expected Host Origin Invariant (`principal.ip`)**: Cloud CRUD and Google Workspace are the **only** metric families in Chronicle allowing direct baseline filtering on `principal.ip` (the caller IP).
* **Data Repository Scope**: Cloud data repositories (GCS buckets, BigQuery datasets, AWS S3 buckets, Azure Blobs) are bound to `target.resource.name` with `metadata.product_name` (`"Cloud Storage"`, `"BigQuery"`, `"S3"`).
* **Anomaly Mechanics**:
  - **Origin IP Outlier**: If a service account calls a data repository from an IP with zero 30-day baseline history ($\mu = 0$), it represents an immediate acute origin deviation.
  - **Scope/Volume Outlier**: Read spikes (`metrics.resource_read_total`) or bulk writes (`metrics.resource_written_total`) exceeding $Z > 3.0\sigma$ against the account's 30-day baseline flag potential data hoarding or exfiltration.
* **Local-Baseline Isolation & Dynamic Range Masking ("Elephant and Mouse" Problem)**:
  - *The Antipattern*: Hardcoding a single product (e.g. BigQuery) or comparing resource-level activity against an account-level aggregate causes severe dynamic range masking. An account with 1,000,000 routine storage sync reads will completely mask 2,500 acute reads dumping a high-value database if baselined globally.
  - *The Mathematical Solution*: Slice dynamically by `($sa, $vendor, $product, $resource, $ip by 1d)` so each repository is evaluated strictly against its own local historical parameters $(\mu_r, \sigma_r)$. A universal dispersion floor (`+ 1.0`) naturally detects zero-baseline novelty dumps ($\mu = 0 \implies Z = \text{Obs}$) while standard $Z$-scores flag depth surges in routine destinations.
  - *Composite Outlier Scoring*: $Z_{\text{composite}} = Z_{\text{dest}} + Z_{\text{origin}}$.
  - *Reference Pipeline*: `templates/pipelines/cloud_repository_scope_dual_branch.yl2`.

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
