<!-- Generated file. Maintainers: edit scripts/preflight_validator.py (METRIC_CATALOG) and re-run scripts/generate_references.py. Do not hand-edit this file. -->
<!-- Agents at runtime: this catalog is the authoritative reference for metric names, dimensions, and entity types. It is complete; do not open the generator or the validator. -->

> ⚡ **JETSKI / WORKSPACE & MCP AGENT DIRECTIVE**:
> Query templates in `templates/pipelines/` and `templates/stage1_extractors/` provide pre-validated AST structures.
> Do NOT execute local Python scripts during hunting. Inspect templates and assemble queries natively via view_file.

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

> [!IMPORTANT]
> **Metric Aggregation & Aggregator Invariants (`metric:` and `agg:`)**:
> In Google SecOps YARA-L 2.0, metric baseline functions strictly accept two aggregation types:
> 1. `metric: value_sum`: Strictly required for byte/volume telemetry metrics (`metrics.network_bytes_*`, `metrics.dns_bytes_*`, `metrics.workspace_network_bytes_*`). Passing `metric_value_sum` causes fatal compiler failure (`unsupported metric type metric_value_sum`).
> 2. `metric: event_count_sum`: Required for all count-based telemetry metrics (`metrics.auth_attempts_*`, `metrics.resource_*`, `metrics.http_queries_*`, `metrics.file_executions_*`, `metrics.network_flows_*`, `metrics.dns_queries_*`, `metrics.workspace_total_*`, `metrics.alert_event_name_count`).
>
> **Statistical Aggregators (`agg:`)**:
> Metric functions strictly accept: `agg: avg`, `agg: stddev`, `agg: sum`, `agg: min`, `agg: max`, or `agg: num_metric_periods`.
> * To count active baseline periods over the window, use `agg: num_metric_periods` (e.g. `metrics.auth_attempts_total(..., metric: event_count_sum, agg: num_metric_periods)`). Passing hallucinated aggregators such as `num_days_active` causes compilation rejection (`Request contains an invalid argument`).

---

## 1. Authentication Attempts
* **Log Scope:** `metadata.event_type = "USER_LOGIN"`
* **Backing Log Types:** `OKTA`, `AZURE_AD`, `WINEVTLOG_SECURITY`, `WORKSPACE`, `PING_IDENTITY`, `DUO`
* **Device IP Filter Note:** Use `principal.asset.ip` (not `principal.ip`) for source device IP filtering.

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.auth_attempts_success` | Successful logins | `target.user.userid`, `principal.asset.hostname`, `principal.asset.ip` |
| `metrics.auth_attempts_fail` | Failed login attempts | `target.user.userid`, `principal.asset.hostname`, `principal.asset.ip` |
| `metrics.auth_attempts_total` | All login attempts | `target.user.userid`, `principal.asset.hostname`, `principal.asset.ip` |

---

## 2. Network Connections & Firewalls
* **Log Scope:** `metadata.event_type = "NETWORK_CONNECTION"`
* **Backing Log Types:** `ZEEK`, `PALO_ALTO_FIREWALL`, `CISCO_ASA`, `FORTINET_FIREWALL`, `CHECKPOINT`, `AWS_VPC_FLOW`, `GCP_VPC_FLOW`

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.network_bytes_inbound` | Inbound traffic volume (requires `metric: value_sum`) | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid` |
| `metrics.network_bytes_outbound` | Outbound traffic volume (requires `metric: value_sum`) | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid` |
| `metrics.network_bytes_total` | Total bidirectional volume (requires `metric: value_sum`) | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid` |
| `metrics.network_flows_inbound` | Inbound flow count (requires `metric: event_count_sum`) | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid` |
| `metrics.network_flows_outbound` | Outbound flow count (requires `metric: event_count_sum`) | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid` |
| `metrics.network_flows_total` | Total connection flows (requires `metric: event_count_sum`) | `principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid` |

### 2.1 When to Choose Bytes vs. Flows (Volumetric vs. Session Count)

A common detection blindspot is evaluating all network anomalies through byte volume. Malachite partitions network telemetry into two distinct pre-computed metric branches:

1. **`metrics.network_bytes_*` (Volumetric)**:
   * **Underlying Calculation**: Sums `network.sent_bytes` and/or `network.received_bytes` (`has_sum_measure: true`).
   * **Compiler Invariant**: Strictly requires `metric: value_sum`.
   * **Ideal Threat Vectors**: Bulk data exfiltration, database dumps, unauthorized backups, media/archive streaming.
   * **Blindspot**: Completely blind to low-payload, high-frequency activity (e.g. 5,000 beaconing pings transferring 64 bytes each produce only ~320 KB total, which registers as zero deviation against a typical host's daily megabyte/gigabyte baseline).

2. **`metrics.network_flows_*` (Session / Connection Frequency)**:
   * **Underlying Calculation**: Counts distinct connection/flow events with non-zero byte transfer (`1 AS total_events`).
   * **Compiler Invariant**: Strictly requires `metric: event_count_sum` (using `metric: value_sum` causes fatal compiler error `unsupported metric type`).
   * **Ideal Threat Vectors**:
     * **C2 Beaconing / Heartbeats**: Persistent scheduled or jittered connection bursts to external infrastructure.
     * **Port Scanning / Host Enumeration**: Rapid fan-out across multiple destination IPs/ports with minimal payload.
     * **Micro-Session Tunneling**: Fragmented low-and-slow command execution over many discrete short-lived connections.
     * **Connection Flood / DoS Exhaustion**: Surges in total concurrent or sequential session initiations.

### 2.2 Volumetric vs. Flow Selection Matrix

| Investigative Goal / Threat Vector | Primary Metric | Aggregation Type | Why this Metric is Required |
| :--- | :--- | :--- | :--- |
| **Detect C2 Beaconing / Heartbeats** | `metrics.network_flows_outbound` | `metric: event_count_sum` | Micro-payloads will not move the byte needle; session count surges immediately surface $Z \ge 3.0\sigma$. |
| **Detect Port / Host Sweep** | `metrics.network_flows_outbound` | `metric: event_count_sum` | Connection attempts fan out with minimal data exchange. |
| **Detect Massive Egress / Exfiltration** | `metrics.network_bytes_outbound` | `metric: value_sum` | Single-session or small-flow data dumps are missed by flow counts but trigger extreme byte deviations. |
| **Detect Ingress Flood / DDoS** | `metrics.network_flows_inbound` | `metric: event_count_sum` | Floods of incoming handshake/session packets. |
| **Payload Density / Elephant Flow Profiling** | **Dual Baseline** (`bytes` + `flows`) | Hybrid (`value_sum` & `event_count_sum`) | Ratio $\frac{\text{Bytes}}{\text{Flows}}$ isolates whether an anomaly is high-frequency chatter or concentrated exfiltration. |

---

## 3. DNS Queries
* **Log Scope:** `metadata.event_type = "NETWORK_DNS"`
* **Backing Log Types:** `INFOBLOX_DNS`, `BIND_DNS`, `WINDOWS_DNS`, `ZEEK_DNS`, `COREDNS`

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.dns_bytes_outbound` | Sent outbound DNS byte volume / bandwidth (use `metric: value_sum`) | `principal.asset.hostname`, `principal.user.userid` |
| `metrics.dns_queries_success` | Successful DNS resolution queries | `principal.asset.hostname`, `principal.user.userid` |
| `metrics.dns_queries_fail` | Failed / NXDOMAIN DNS queries | `principal.asset.hostname`, `principal.user.userid` |
| `metrics.dns_queries_total` | Total DNS query volume / query count (use `metric: event_count_sum`) | `principal.asset.hostname`, `principal.user.userid` |

---

## 4. Endpoint & Process Executions
* **Log Scope:** `metadata.event_type = "PROCESS_LAUNCH"`
* **Backing Log Types:** `CROWDSTRIKE`, `MICROSOFT_DEFENDER_ATF`, `SENTINELONE`, `CARBONBLACK`, `SYSMON`

> [!IMPORTANT]
> **Mandatory Companion Dimensions for Process Executions (`principal.process.file.sha256` & `metadata.event_type`)**:
> In Chronicle Malachite, all endpoint execution baseline tables (`file_executions_*`) require both `principal.process.file.sha256` AND `metadata.event_type` in the metric filter.
> Chronicle does not provide a raw host-level process launch count baseline (`process_launches_total` does not exist). Always profile executions by binary hash or aggregate raw process launches in Stage 1.

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.file_executions_total` | Total process executions for binary hash | `principal.asset.hostname`, `principal.user.userid` (requires sha256 + event_type) |
| `metrics.file_executions_success` | Successful process executions | `principal.asset.hostname`, `principal.user.userid` (requires sha256 + event_type) |
| `metrics.file_executions_fail` | Blocked / failed process executions | `principal.asset.hostname`, `principal.user.userid` (requires sha256 + event_type) |

---

## 5. Security & EDR Rule Alerts
* **Log Scope:** `metadata.event_type = "SCAN_UNCATEGORIZED"`
* **Backing Log Types:** `CB_EDR`, `CS_EDR`, `MICROSOFT_GRAPH_ALERT`, `SENTINELONE_ALERTS`

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.alert_event_name_count` | Security rule and EDR alerts fired per entity | `principal.asset.hostname`, `principal.user.userid` |

> [!NOTE]
> **Lateral Movement & Asset Concurrency Baselining**:
> Chronicle Malachite does not maintain a pre-computed distinct entity baseline (e.g. `metrics.user_distinct_assets` does not exist).
> To baseline and hunt for lateral movement, compute distinct asset counts in the observation window (`$distinct_assets = count_distinct(principal.asset.hostname)`) and correlate against the user's authentications baseline using canonical `metrics.auth_attempts_success` or `metrics.auth_attempts_total`.

---

## 6. HTTP & Web Queries
* **Log Scope:** `metadata.event_type = "NETWORK_HTTP"`
* **Backing Log Types:** `CHROME_MANAGEMENT`, `ZSCALER`, `SQUID_PROXY`, `PALO_ALTO_FIREWALL`, `BLUECOAT_PROXY`, `NGINX`
* **Underlying Pre-computed Metric Shards in Malachite:**
  - `metrics.http_queries_total`: Evaluates `network.http.method != ""` (Shard 9)
  - `metrics.http_queries_success`: Evaluates `network.http.response_code < 400` and `network.http.method != ""` (Shard 8)
  - `metrics.http_queries_fail`: Evaluates `(network.http.response_code >= 400 or network.http.response_code is null)` and `network.http.method != ""` (Shard 7)

### 6.1 The 9 Supported Dimension Configurations
Chronicle Malachite pre-computes 30-day baseline tables across nine distinct dimension combinations for each HTTP metric function:

| Dimension Index | Dimension Type | UDM Field Mapping in `metrics.*` | Use Case |
| :--- | :--- | :--- | :--- |
| **1. Host / Device** | Single Dimension | `principal.asset.hostname` (or `principal.asset.ip`) | Device-level HTTP browsing volume & anomalies |
| **2. User** | Single Dimension | `principal.user.userid` | User-centric web proxy activity & exfiltration |
| **3. Target Hostname** | Single Dimension | `target.hostname` | Inbound / target-centric web server or API hammering |
| **4. Host + User-Agent** | Compound Pair | `principal.asset.hostname`, `network.http.user_agent` | Host-level anomalous browser or tool adoption |
| **5. User + User-Agent** | Compound Pair | `principal.user.userid`, `network.http.user_agent` | User account switching to automated script/scraper |
| **6. Host + Target Host** | Compound Pair | `principal.asset.hostname`, `target.hostname` | Host-to-destination C2 beaconing or exfil target |
| **7. User + Target Host** | Compound Pair | `principal.user.userid`, `target.hostname` | User targeted data siphoning to specific SaaS/cloud |
| **8. Host + UA + Target** | Tri-Tuple | `principal.asset.hostname`, `network.http.user_agent`, `target.hostname` | High-precision host targeted web access profile |
| **9. User + UA + Target** | Tri-Tuple | `principal.user.userid`, `network.http.user_agent`, `target.hostname` | High-precision user targeted API transaction profile |

### 6.2 Canonical YARA-L 2.0 Syntax Signatures

```yara
// 1. Single Entity (Host or User)
$hist_avg = max(metrics.http_queries_total(
    period: 1d, window: 30d, metric: event_count_sum, agg: avg,
    principal.asset.hostname: $host
))

// 2. Target Hostname Baselining
$target_hist_avg = max(metrics.http_queries_total(
    period: 1d, window: 30d, metric: event_count_sum, agg: avg,
    target.hostname: $target_host
))

// 3. Compound Pair: Host + User-Agent Token
$ua_hist_avg = max(metrics.http_queries_total(
    period: 1d, window: 30d, metric: event_count_sum, agg: avg,
    principal.asset.hostname: $host,
    network.http.user_agent: $user_agent
))

// 4. Compound Pair: User + Target Hostname
$user_target_avg = max(metrics.http_queries_total(
    period: 1d, window: 30d, metric: event_count_sum, agg: avg,
    principal.user.userid: $user,
    target.hostname: $target_host
))

// 5. Tri-Tuple: Host + User-Agent + Target Hostname
$tri_avg = max(metrics.http_queries_total(
    period: 1d, window: 30d, metric: event_count_sum, agg: avg,
    principal.asset.hostname: $host,
    network.http.user_agent: $user_agent,
    target.hostname: $target_host
))
```

### 6.3 HTTP Error Ratio & Scanning Outlier Math
In web reconnaissance and API fuzzing hunts, compare failed HTTP queries (`4xx/5xx`) against total requests in Stage 1 to produce a baseline-normalized failure ratio:

```yara
$total_obs = count(metadata.id)
$fail_obs = count(if(network.http.response_code >= 400, metadata.id, 0))
$fail_ratio = $fail_obs / ($total_obs + 0.001)

$hist_fail_avg = max(metrics.http_queries_fail(
    period: 1d, window: 30d, metric: event_count_sum, agg: avg,
    principal.asset.hostname: $host
))
$hist_fail_std = max(metrics.http_queries_fail(
    period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
    principal.asset.hostname: $host
))
$fail_z = ($fail_obs - $hist_fail_avg) / ($hist_fail_std + 1.0)
```

### 6.4 Raw UDM Events Alignment & Consultative Pivot to Statistical Hunter
When constructing multi-stage YARA-L rules or companion raw stages for HTTP metrics:
* **Raw `events:` Filter Alignment**: Match `metadata.event_type = "NETWORK_HTTP"` and include `network.http.method != ""` to align 1:1 with Malachite's underlying SQL ingestion filter (`WHERE network.http.method IS NOT NULL`).
* **Forensic vs. Baseline Dimension Separation**:
  - `metrics.http_queries_*` accepts **only** the 9 pre-computed dimensions (`principal.asset.hostname`, `principal.asset.ip`, `principal.user.userid`, `target.hostname`, `network.http.user_agent`).
  - High-cardinality URI paths (`target.url`), referrers (`network.http.referral_url`), and raw status codes are captured in companion raw stages (`outcome: array_distinct(target.url)`).
* **When to Pivot to `secops-statistical-hunter`**:
  - When investigating URI path entropy, directory traversal scanning (`../`), query parameter fuzzing, or payload byte distributions, pivot directly to `secops-statistical-hunter` (Risk metrics baselines index target hostnames).

---

## 7. Cloud Resource Lifecycle & Cloud Audit Telemetry Spectrum
* **Backing Log Types:** `GCP_CLOUDAUDIT`, `AWS_CLOUDTRAIL`, `AZURE_ACTIVITY`
* **Pre-Computed Baseline Scope:** `metadata.event_type = "RESOURCE_CREATION" | "RESOURCE_DELETION" | "RESOURCE_READ" | "RESOURCE_WRITTEN"`

### 7.1 Pre-Computed UEBA Metric Functions
Chronicle Malachite maintains 30-day pre-computed baseline tables for 4 core infrastructure CRUD operations:

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

### 7.2 Full UDM Event Spectrum for Cloud Audit Logs (`GCP_CLOUDAUDIT`)
While pre-computed baselines cover high-volume CRUD, threat hunting and behavioral detections across cloud environments must NOT be artificially restricted to only 4 enums. Real-world cloud audit telemetry parsed into Chronicle UDM spans user-level actions, permissions tampering, credential modifications, and administrative operations.

The following empirical distribution reflects a 30-day telemetry profile from the live `gus-sdl` production tenant:

| UDM Event Type (`metadata.event_type`) | Observed 30d Volume | Operational Role | Threat Detection & Hunting Focus |
| :--- | :--- | :--- | :--- |
| `GENERIC_EVENT` | 30,999 | Control plane & routine cloud operations | Broad background automation, service-to-service calls |
| `RESOURCE_WRITTEN` | 2,575 | System/generic resource modifications | High-volume writes, data store ingestion surges |
| `RESOURCE_CREATION` | 980 | System/generic resource provisioning | VM deployment spikes, container spinning |
| `RESOURCE_DELETION` | 936 | System/generic resource teardown | Mass deletions, resource decommissioning |
| `USER_RESOURCE_UPDATE_CONTENT` | 559 | User modifying resource data/content | Direct object tampering, database/bucket overwrites |
| `USER_UNCATEGORIZED` | 537 | Uncategorized user-initiated audit activity | Non-standard API actions, unmapped cloud services |
| `USER_RESOURCE_UPDATE_PERMISSIONS` | 378 | User modifying resource-level IAM/ACL | Bucket IAM modification, Secret Manager access grant |
| `USER_CHANGE_PERMISSIONS` | 150 | User/IAM role binding changes | Project/folder/org-level IAM role escalation |
| `RESOURCE_READ` | 124 | System/generic resource reads | Data inspection, baseline read monitoring |
| `USER_LOGIN` | 96 | Cloud Console / OAuth session initiation | Anomalous console access, suspicious token creation |
| `STATUS_UNCATEGORIZED` | 64 | Uncategorized status changes | Status monitoring events |
| `USER_CREATION` | 62 | Service account or user creation | Rogue service account creation, backdoor identity |
| `USER_CHANGE_PASSWORD` | 60 | Credential / key creation or rotation | Service account key generation, credential access |
| `USER_RESOURCE_DELETION` | 60 | User deleting specific resources | Targeted sabotage, evidence wiping |
| `USER_RESOURCE_ACCESS` | 43 | User accessing/reading resources | Secret inspection, targeted object retrieval |
| `GROUP_MODIFICATION` | 32 | Cloud Identity / IAM group membership | Group-based privilege escalation |
| `USER_RESOURCE_CREATION` | 30 | User creating specific resources | Shadow infrastructure, rogue compute instances |

> [!WARNING]
> **Critical UDM Enum Naming Rule for Cloud & User Activity**:
> 1. **Resource Access / Read**: Use `RESOURCE_READ` (system/generic) or `USER_RESOURCE_ACCESS` (user-initiated).  
>    *`USER_RESOURCE_READ` is **NOT** a valid UDM enum*. In Chronicle UDM, user-initiated read operations are mapped to `USER_RESOURCE_ACCESS`. Guessing `USER_RESOURCE_READ` will cause immediate query validation failure.
> 2. **Resource Modification / Write**: Use `RESOURCE_WRITTEN` or `USER_RESOURCE_UPDATE_CONTENT`.
> 3. **Resource Provisioning**: Use `RESOURCE_CREATION` or `USER_RESOURCE_CREATION`.
> 4. **Resource Deletion**: Use `RESOURCE_DELETION` or `USER_RESOURCE_DELETION`.
> 5. **Permissions & Privilege Changes**: Use `USER_RESOURCE_UPDATE_PERMISSIONS` (resource-level ACLs) or `USER_CHANGE_PERMISSIONS` (project/org IAM bindings).
> 6. **Credential Lifecycle**: Use `USER_CHANGE_PASSWORD` (covers service account key creation/rotation).

### 7.3 Multi-Stage Correlation Across Cloud Telemetry
In multi-stage YARA-L threat hunting:
* **Stage 1 (Volumetric Anomaly Discovery)**: Evaluates pre-computed 30-day baseline tables (`metrics.resource_*`) to detect statistical volume outliers ($Z \ge 3.0\sigma$) across service accounts or users.
* **Stage 2 (Tactical Correlation & Behavioral Verification)**: Correlates identified outliers against specific, high-fidelity security events such as `USER_RESOURCE_UPDATE_PERMISSIONS` (privilege escalation), `USER_CHANGE_PASSWORD` (key generation), or `USER_RESOURCE_ACCESS` (secret exfiltration).

### 7.4 Service Account Cloud Repository & Origin IP Monitoring
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
