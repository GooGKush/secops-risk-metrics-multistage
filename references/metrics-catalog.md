<!-- Generated file. Maintainers: edit data/malachite/ (via scripts/sync_malachite_catalog.py), data/metric_baseline_semantics.json, or this generator, then re-run scripts/generate_references.py. Do not hand-edit this file. -->
<!-- Agents at runtime: this catalog is the authoritative reference for metric names, dimensions, and entity types. It is complete; do not open the generator or the validator. -->

> ⚡ **JETSKI / WORKSPACE & MCP AGENT DIRECTIVE**:
> Query templates in `templates/pipelines/` and `templates/stage1_extractors/` provide pre-validated AST structures.
> Do NOT execute local Python scripts during hunting. Inspect templates and assemble queries natively via view_file.
> For the exact per-metric observed event filter, observed value, `metric:` arg and entity identifier fields, read `references/metric-sector-catalog.md`. The dimension sets below are generated from the compiler config (`config.textproto`); a metric call's filter args must equal ONE valid set exactly.

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
>    - **Authentication (`USER_LOGIN`)**: The user account being accessed is the target of the authentication attempt. In IdP logs (Okta, Azure AD, Windows 4624/4625), the account identity resides in `target.user.userid`. When profiling logins for a user, the event filter is `target.user.userid = "<id>"` and the metric filter is `target.user.userid: "<id>"` (or `$user`). Auth also accepts `principal.user.*` alone.
> 2. **User as Principal (`principal.user.userid`)**:
>    - **Cloud Resource CRUD (`RESOURCE_*` / `USER_RESOURCE_*`)**: The IAM identity or service account acting on cloud infrastructure (`target.user.*` + vendor + product is also a valid set).
>    - **Google Workspace (`metadata.vendor_name = "Google Workspace"`)**: The user downloading, sharing, or editing Drive files.
>    - **Network Traffic (`network.sent_bytes` / `network.received_bytes` > 0)**: The user initiating flows. No event_type filter.
>    - **Process Executions (`PROCESS_LAUNCH`)**: The user executing binaries (only together with `metadata.event_type` + `principal.process.file.sha256`).
>    - In these sectors, the event filter is `principal.user.userid = "<id>"` and the metric filter is `principal.user.userid: "<id>"` (or `$user`). Passing `target.user.userid` to network, DNS, HTTP or process metrics causes compiler rejection (`unsupported filters for metric`).
> 3. **Assets (`principal.asset.hostname` / `principal.asset.ip`)**:
>    - For asset profiling, host is `principal.asset.hostname` across network, endpoint, DNS, HTTP, alert, and login events. Cloud CRUD and Workspace metrics have no host dimension.
>    - Device IP filtering strictly requires `principal.asset.ip` (mapping to `PRINCIPAL_DEVICE`), whereas `principal.ip` is rejected on network, auth, DNS, and endpoint metrics.
> 4. **User Display Names vs. Technical User IDs (`user.user_display_name` vs. `user.userid`)**:
>    - **Technical User ID Dimension**: User-keyed metric baselines are indexed by the technical identifiers of the `PRINCIPAL_USER` / `TARGET_USER` dimensions (`userid`, `email_addresses`, `windows_sid`, `employee_id`, `product_object_id`), e.g. `jholden`, `james.holden@corp.com`. Bind the same identifier field in the event filter and the metric call.
>    - **Human Display Names**: Human names containing spaces (e.g. `"James Holden"`, `"Frank Kolzig"`) are Display Names (`user.user_display_name`), NOT `user.userid`. Passing a display name directly to `target.user.userid = "James Holden"` or metric filters will match zero events and zero baseline rows in Chronicle.
>    - **Pre-Flight Identity Spot Check**: When an analyst specifies a human display name, the agent executes a single lightweight spot check query to resolve the corresponding technical `userid`:
>      ```udm
>      target.user.user_display_name = "<Display Name>" nocase or principal.user.user_display_name = "<Display Name>" nocase
>      ```
>    - **Confirmation Gate**: The resolved `userid` must be presented in the Pre-Flight Card (e.g. `• Target Entity / Scope: James Holden (Resolved User ID: jholden)`) and explicitly confirmed with the analyst before compiling hunting queries. If the display name is not found in the current tenant's logs/enrichments, the agent must prompt the analyst for the technical `userid`.

> [!IMPORTANT]
> **Metric Aggregation Type Invariant (`metric: value_sum` vs. `metric: event_count_sum`)**:
> In Google SecOps YARA-L 2.0, metric baseline functions strictly accept two aggregation types:
> 1. `metric: value_sum`: Strictly required for byte/volume telemetry metrics (`metrics.network_bytes_*`, `metrics.dns_bytes_*`, `metrics.workspace_network_bytes_*`). Passing `metric_value_sum` causes fatal compiler failure (`unsupported metric type metric_value_sum`).
> 2. `metric: event_count_sum`: Required for all count-based telemetry metrics (`metrics.auth_attempts_*`, `metrics.resource_*`, `metrics.http_queries_*`, `metrics.file_executions_*`, `metrics.network_flows_*`, `metrics.dns_queries_*`, `metrics.workspace_total_*`, `metrics.alert_event_name_count`).

> [!NOTE]
> **Reading the dimension cells**: `Entity alone` lists the user/device dimensions that are a complete valid set by themselves (usable as a fusion sector). `also` lists the other valid sets. `Composite-only` metrics have no entity-alone set. Dimension → UDM field mapping is in `references/metric-sector-catalog.md`.

---

## 1. Authentication Attempts
* **Log Scope (success):** `metadata.event_type = "USER_LOGIN"` + `security_result.action = "ALLOW"`
* **Log Scope (fail):** `metadata.event_type = "USER_LOGIN"` + `not security_result.action = "ALLOW"` (logins with no action value count as failures)
* **Log Scope (total):** `metadata.event_type = "USER_LOGIN"`
* **Backing Log Types:** `OKTA`, `AZURE_AD`, `WINEVTLOG_SECURITY`, `WORKSPACE`, `PING_IDENTITY`, `DUO`
* **Device IP Filter Note:** Use `principal.asset.ip` (not `principal.ip`) for source device IP filtering.

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.auth_attempts_success` | Successful logins | Entity alone: PRINCIPAL_DEVICE, PRINCIPAL_USER, TARGET_USER; also: TARGET_APPLICATION + TARGET_DEVICE; TARGET_APPLICATION + TARGET_USER; CLIENT_CERTIFICATE_HASH + TARGET_USER; PRINCIPAL_COUNTRY + TARGET_USER; PRINCIPAL_NETWORK_ORGANIZATION_NAME + TARGET_USER; PRINCIPAL_DEVICE + TARGET_USER; PRINCIPAL_USER + TARGET_USER; EVENT_TYPE + PRINCIPAL_DEVICE |
| `metrics.auth_attempts_fail` | Failed login attempts | Entity alone: PRINCIPAL_DEVICE, PRINCIPAL_USER, TARGET_USER; also: TARGET_APPLICATION + TARGET_DEVICE; TARGET_APPLICATION + TARGET_USER; CLIENT_CERTIFICATE_HASH + TARGET_USER; EVENT_TYPE + PRINCIPAL_DEVICE; PRINCIPAL_DEVICE + TARGET_USER; PRINCIPAL_USER + TARGET_USER; PRINCIPAL_COUNTRY + TARGET_USER; PRINCIPAL_NETWORK_ORGANIZATION_NAME + TARGET_USER |
| `metrics.auth_attempts_total` | All login attempts | Entity alone: PRINCIPAL_DEVICE, PRINCIPAL_USER, TARGET_USER; also: TARGET_APPLICATION + TARGET_USER; TARGET_APPLICATION + TARGET_DEVICE; CLIENT_CERTIFICATE_HASH + TARGET_USER; EVENT_TYPE + PRINCIPAL_DEVICE; PRINCIPAL_DEVICE + TARGET_USER; PRINCIPAL_USER + TARGET_USER; PRINCIPAL_COUNTRY + TARGET_USER; PRINCIPAL_NETWORK_ORGANIZATION_NAME + TARGET_USER |

---

## 2. Network Connections & Firewalls
* **Log Scope (outbound):** `network.sent_bytes > 0` + `network.sent_bytes < 1000000000000000`
* **Log Scope (inbound):** `network.received_bytes > 0` + `network.received_bytes < 1000000000000000`
* **Log Scope (total, flows):** `((network.sent_bytes > 0 and network.sent_bytes < 1000000000000000) or (network.received_bytes > 0 and network.received_bytes < 1000000000000000))`. The baseline has NO `metadata.event_type` filter; do not add `NETWORK_CONNECTION` to observed stages.
* **Backing Log Types:** `ZEEK`, `PALO_ALTO_FIREWALL`, `CISCO_ASA`, `FORTINET_FIREWALL`, `CHECKPOINT`, `AWS_VPC_FLOW`, `GCP_VPC_FLOW`

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.network_bytes_inbound` | Inbound traffic volume (requires `metric: value_sum`) | Entity alone: PRINCIPAL_DEVICE, PRINCIPAL_USER; also: PRINCIPAL_COUNTRY + PRINCIPAL_DEVICE; PRINCIPAL_COUNTRY + PRINCIPAL_USER; PRINCIPAL_DEVICE + SECURITY_CATEGORY; PRINCIPAL_USER + SECURITY_CATEGORY; PRINCIPAL_DEVICE + TARGET_NETWORK_ORGANIZATION_NAME; PRINCIPAL_USER + TARGET_NETWORK_ORGANIZATION_NAME; PRINCIPAL_DEVICE + TARGET_DEVICE; PRINCIPAL_USER + TARGET_DEVICE |
| `metrics.network_bytes_outbound` | Outbound traffic volume (requires `metric: value_sum`) | Entity alone: PRINCIPAL_DEVICE, PRINCIPAL_USER; also: PRINCIPAL_COUNTRY + PRINCIPAL_DEVICE; PRINCIPAL_COUNTRY + PRINCIPAL_USER; PRINCIPAL_DEVICE + SECURITY_CATEGORY; PRINCIPAL_USER + SECURITY_CATEGORY; PRINCIPAL_DEVICE + TARGET_NETWORK_ORGANIZATION_NAME; PRINCIPAL_USER + TARGET_NETWORK_ORGANIZATION_NAME; PRINCIPAL_DEVICE + TARGET_DEVICE; PRINCIPAL_USER + TARGET_DEVICE |
| `metrics.network_bytes_total` | Total bidirectional volume (requires `metric: value_sum`) | Entity alone: PRINCIPAL_DEVICE, PRINCIPAL_USER; also: PRINCIPAL_COUNTRY + PRINCIPAL_DEVICE; PRINCIPAL_COUNTRY + PRINCIPAL_USER; PRINCIPAL_DEVICE + SECURITY_CATEGORY; PRINCIPAL_USER + SECURITY_CATEGORY; PRINCIPAL_DEVICE + TARGET_NETWORK_ORGANIZATION_NAME; PRINCIPAL_USER + TARGET_NETWORK_ORGANIZATION_NAME; PRINCIPAL_DEVICE + TARGET_DEVICE; PRINCIPAL_USER + TARGET_DEVICE |
| `metrics.network_flows_inbound` | Inbound flow count (requires `metric: event_count_sum`) | Entity alone: PRINCIPAL_DEVICE, PRINCIPAL_USER |
| `metrics.network_flows_outbound` | Outbound flow count (requires `metric: event_count_sum`) | Entity alone: PRINCIPAL_DEVICE, PRINCIPAL_USER |
| `metrics.network_flows_total` | Total connection flows (requires `metric: event_count_sum`) | Entity alone: PRINCIPAL_DEVICE, PRINCIPAL_USER |

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
* **Log Scope (queries total):** `(network.dns.questions.name != "" or network.dns.answers.name != "" or network.dns.id != 0)`. No `metadata.event_type` filter in the baseline.
* **Log Scope (queries success):** `(network.dns.questions.name != "" or network.dns.answers.name != "" or network.dns.id != 0)` + `network.dns.response_code = 0`
* **Log Scope (queries fail):** `(network.dns.questions.name != "" or network.dns.answers.name != "" or network.dns.id != 0)` + `network.dns.response_code != 0`
* **Log Scope (bytes outbound):** `network.sent_bytes > 0` + `((network.ip_protocol = "UDP" and target.port = 53) or (network.ip_protocol = "TCP" and (target.port = 53 or target.port = 3000)))`
* **Backing Log Types:** `INFOBLOX_DNS`, `BIND_DNS`, `WINDOWS_DNS`, `ZEEK_DNS`, `COREDNS`

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.dns_bytes_outbound` | Sent outbound DNS byte volume / bandwidth (use `metric: value_sum`) | Entity alone: PRINCIPAL_DEVICE, PRINCIPAL_USER; also: PRINCIPAL_DEVICE + TARGET_IP; PRINCIPAL_USER + TARGET_IP |
| `metrics.dns_queries_success` | Successful DNS resolution queries | Entity alone: PRINCIPAL_DEVICE, PRINCIPAL_USER; also: DNS_QUERY_TYPE + PRINCIPAL_DEVICE; DNS_QUERY_TYPE + PRINCIPAL_USER; DNS_DOMAIN + PRINCIPAL_DEVICE; DNS_DOMAIN + PRINCIPAL_USER |
| `metrics.dns_queries_fail` | Failed / NXDOMAIN DNS queries | Entity alone: PRINCIPAL_DEVICE, PRINCIPAL_USER; also: DNS_QUERY_TYPE + PRINCIPAL_DEVICE; DNS_QUERY_TYPE + PRINCIPAL_USER; DNS_DOMAIN + PRINCIPAL_DEVICE; DNS_DOMAIN + PRINCIPAL_USER |
| `metrics.dns_queries_total` | Total DNS query volume / query count (use `metric: event_count_sum`) | Entity alone: PRINCIPAL_DEVICE, PRINCIPAL_USER; also: DNS_QUERY_TYPE + PRINCIPAL_DEVICE; DNS_QUERY_TYPE + PRINCIPAL_USER; DNS_DOMAIN + PRINCIPAL_DEVICE; DNS_DOMAIN + PRINCIPAL_USER |

> [!IMPORTANT]
> **Companion Dimensions and Filter Rules for DNS Queries (`network.dns_domain`)**:
> In Chronicle Malachite, DNS metric tables have specific indexing constraints:
> - **Query Metrics (`metrics.dns_queries_total`, `metrics.dns_queries_success`, `metrics.dns_queries_fail`)**:
>   - Primary entity match keys: any `PRINCIPAL_DEVICE` field (`principal.asset.hostname`, `principal.asset.ip`, `principal.asset.asset_id`, ...) or `PRINCIPAL_USER` field (`principal.user.userid`, `principal.user.email_addresses`, ...).
>   - Supported companion dimension: `network.dns_domain: $domain` (or `network.dns.questions.type`), each only together with one entity field.
>   - **Compiler Anti-Pattern Warning**: NEVER use `network.dns.questions.name` or `target.hostname` in `metrics.dns_queries_*`. Chronicle indexes the normalized apex/domain field (`network.dns_domain`) in baseline tables, NOT the raw question name. Passing `network.dns.questions.name: $domain` triggers `compilation error: unsupported filters for metric DNS_QUERIES_TOTAL`.
> - **Byte Metrics (`metrics.dns_bytes_outbound`)**:
>   - Supported companion dimension: `target.ip: $ip`. Does NOT support domain or question name filters.


---

## 4. Endpoint & Process Executions
* **Log Scope:** `metadata.event_type = "PROCESS_LAUNCH"`
* **Backing Log Types:** `CROWDSTRIKE`, `MICROSOFT_DEFENDER_ATF`, `SENTINELONE`, `CARBONBLACK`, `SYSMON`

> [!IMPORTANT]
> **Mandatory Companion Dimensions for Process Executions (`principal.process.file.sha256` & `metadata.event_type`)**:
> In Chronicle Malachite, all endpoint execution baseline tables (`file_executions_*`) require both `principal.process.file.sha256` AND `metadata.event_type` in the metric filter:
> - **Canonical Dimension Path**: `principal.process.file.sha256: $sha` (or `$token`).
> - **Compiler Anti-Pattern Warning**: NEVER use `target.process.file.sha256` or `principal.process.sha256`. Chronicle does not index `target.process` in pre-computed metric tables; passing it triggers an immediate compiler error (`Request contains an invalid argument`).
> - Chronicle does not provide a raw host-level process launch count baseline (`process_launches_total` does not exist). Always profile executions by binary hash or aggregate raw process launches in Stage 1.
> - Because every valid set needs the hash, `file_executions_*` is composite-only and has no host-total baseline. Process execution + DNS is still a valid fusion as a roll-up sector (`rollup_sector_fusion_4stage.yl2`): per-binary Z, rolled up to the host (see `references/metric-sector-catalog.md`).

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.file_executions_total` | Total process executions for binary hash | Composite-only: EVENT_TYPE + PRINCIPAL_PROCESS_FILE_HASH; EVENT_TYPE + PRINCIPAL_DEVICE + PRINCIPAL_PROCESS_FILE_HASH; EVENT_TYPE + PRINCIPAL_PROCESS_FILE_HASH + PRINCIPAL_USER |
| `metrics.file_executions_success` | Successful process executions | Composite-only: EVENT_TYPE + PRINCIPAL_PROCESS_FILE_HASH; EVENT_TYPE + PRINCIPAL_DEVICE + PRINCIPAL_PROCESS_FILE_HASH; EVENT_TYPE + PRINCIPAL_PROCESS_FILE_HASH + PRINCIPAL_USER |
| `metrics.file_executions_fail` | Blocked / failed process executions | Composite-only: EVENT_TYPE + PRINCIPAL_PROCESS_FILE_HASH; EVENT_TYPE + PRINCIPAL_DEVICE + PRINCIPAL_PROCESS_FILE_HASH; EVENT_TYPE + PRINCIPAL_PROCESS_FILE_HASH + PRINCIPAL_USER |

---

## 5. Security & EDR Rule Alerts
* **Log Scope:** `(metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS")`. The baseline selects by `metadata.log_type`, not by `metadata.event_type`.
* **Backing Log Types:** `CB_EDR`, `CS_EDR`, `MICROSOFT_GRAPH_ALERT`, `SENTINELONE_ALERTS`

| Metric Function | Description | Supported Dimensions (Entity Types) |
| :--- | :--- | :--- |
| `metrics.alert_event_name_count` | Security rule and EDR alerts fired per host and rule | Composite-only: PRINCIPAL_DEVICE + SECURITY_RESULT_RULE_NAME; PRINCIPAL_DEVICE + PRINCIPAL_PROCESS_FILE_PATH + SECURITY_RESULT_RULE_NAME; PRINCIPAL_DEVICE + PRINCIPAL_PROCESS_FILE_PATH + PRINCIPAL_USER + SECURITY_RESULT_RULE_NAME; PRINCIPAL_DEVICE + PRINCIPAL_PROCESS_FILE_HASH + PRINCIPAL_USER + SECURITY_RESULT_RULE_NAME |

> [!NOTE]
> **Compound Dimension Scope for `metrics.alert_event_name_count`**:
> In Chronicle SIEM (Malachite), `metrics.alert_event_name_count` is partitioned as a compound metric measuring alert volume for a specific security rule per host. Every valid set contains `PRINCIPAL_DEVICE` + `SECURITY_RESULT_RULE_NAME`; `principal.user.*` is valid only together with the process file path or hash. There is no user-only alert baseline.
> Formulate queries by binding both the host identifier and the rule name (`security_result.rule_name: $rule_name`) in the event filter, match section, and metric call:
> ```yara
> (metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS")
> principal.asset.hostname = $host
> security_result.rule_name = $rule_name
> match: $host, $rule_name by 1d
> outcome:
>   $avg = max(metrics.alert_event_name_count(
>       period: 1d, window: 30d, metric: event_count_sum, agg: avg,
>       principal.asset.hostname: $host,
>       security_result.rule_name: $rule_name
>   ))
> ```
> To evaluate aggregate host risk or fleet sweeps across hosts without per-rule scoping, deploy single-dimension host metrics (`metrics.auth_attempts_total`, `metrics.network_bytes_outbound`, `metrics.dns_queries_total`, `metrics.http_queries_total`).

> [!NOTE]
> **Lateral Movement & Asset Concurrency Baselining**:
> Chronicle Malachite does not maintain a pre-computed distinct entity baseline (e.g. `metrics.user_distinct_assets` does not exist).
> To baseline and hunt for lateral movement, compute distinct asset counts in the observation window (`$distinct_assets = count_distinct(principal.asset.hostname)`) and correlate against the user's authentications baseline using canonical `metrics.auth_attempts_success` or `metrics.auth_attempts_total`.

---

## 6. HTTP & Web Queries
* **Log Scope:** `(network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")` (HTTP message present). No `metadata.event_type` filter in the baseline.
* **Backing Log Types:** `CHROME_MANAGEMENT`, `ZSCALER`, `SQUID_PROXY`, `PALO_ALTO_FIREWALL`, `BLUECOAT_PROXY`, `NGINX`
* **Underlying Pre-computed Metric Shards in Malachite:**
  - `metrics.http_queries_total`: network.http message present (http.method is not null); no event_type filter
  - `metrics.http_queries_success`: network.http message present and response_code < 400 (unset response_code reads as 0 and counts as success)
  - `metrics.http_queries_fail`: network.http message present and (response_code >= 400 or response_code is null); the null branch cannot fire for a present proto3 message

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
$fail_obs = sum(if(network.http.response_code >= 400, 1, 0))
$fail_ratio = $fail_obs / ($total_obs + 0.001)

$hist_fail_avg = max(metrics.http_queries_fail(
    period: 1d, window: 30d, metric: event_count_sum, agg: avg,
    principal.asset.hostname: $host
))
$hist_fail_std = max(metrics.http_queries_fail(
    period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
    principal.asset.hostname: $host
))
$fail_z = ($fail_obs - $hist_fail_avg) / if($hist_fail_std > 0, $hist_fail_std, 1.0)
```

### 6.4 Raw UDM Events Alignment & Consultative Pivot to Statistical Hunter
When constructing multi-stage YARA-L rules or companion raw stages for HTTP metrics:
* **Raw `events:` Filter Alignment**: Use the HTTP-present line `(network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")` to align with Malachite's baseline (`network.http` message present). Do NOT use `metadata.event_type = "NETWORK_HTTP"` alone (it overcounts Zeek rows with no HTTP fields) or `network.http.method != ""` alone (it misses user-agent-only events).
* **Forensic vs. Baseline Dimension Separation**:
  - `metrics.http_queries_*` accepts **only** the 9 pre-computed dimension sets (any `PRINCIPAL_DEVICE` field such as `principal.asset.hostname` / `principal.asset.ip`, any `PRINCIPAL_USER` field such as `principal.user.userid` / `principal.user.email_addresses`, `target.hostname`, `network.http.user_agent`).
  - High-cardinality URI paths (`target.url`), referrers (`network.http.referral_url`), and raw status codes are captured in companion raw stages (`outcome: array_distinct(target.url)`).
* **When to Pivot to `secops-statistical-hunter`**:
  - When investigating URI path entropy, directory traversal scanning (`../`), query parameter fuzzing, or payload byte distributions, pivot directly to `secops-statistical-hunter` (Risk metrics baselines index target hostnames).

---

## 7. Cloud Resource Lifecycle & Cloud Audit Telemetry Spectrum
* **Backing Log Types:** `GCP_CLOUDAUDIT`, `AWS_CLOUDTRAIL`, `AZURE_ACTIVITY`
* **Pre-Computed Baseline Scope:** creation `(metadata.event_type = "RESOURCE_CREATION" or metadata.event_type = "USER_RESOURCE_CREATION")`; deletion `(metadata.event_type = "RESOURCE_DELETION" or metadata.event_type = "USER_RESOURCE_DELETION")`; read `(metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS")`; written `(metadata.event_type = "RESOURCE_WRITTEN" or metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT")`. `_success` adds `security_result.action = "ALLOW"`; see `references/metric-sector-catalog.md` for `_fail`.

### 7.1 Pre-Computed UEBA Metric Functions
Chronicle Malachite maintains 30-day pre-computed baseline tables for 4 core infrastructure CRUD operations:

| Metric Function Family | Operations Covered | Supported Dimensions (Entity Types & Required Attributes) |
| :--- | :--- | :--- |
| `metrics.resource_creation_*` | `total`, `success`, `fail` | Composite-only: PRODUCT_NAME + TARGET_USER + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + VENDOR_NAME; PRINCIPAL_IP + PRINCIPAL_USER + PRODUCT_NAME + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_APPLICATION + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_RESOURCE_NAME + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_RESOURCE_NAME + TARGET_RESOURCE_TYPE + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_APPLICATION + TARGET_LOCATION_NAME + VENDOR_NAME |
| `metrics.resource_deletion_*` | `total`, `success`, `fail` | Composite-only: PRODUCT_NAME + TARGET_USER + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + VENDOR_NAME; PRINCIPAL_IP + PRINCIPAL_USER + PRODUCT_NAME + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_APPLICATION + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_RESOURCE_NAME + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_RESOURCE_NAME + TARGET_RESOURCE_TYPE + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_APPLICATION + TARGET_LOCATION_NAME + VENDOR_NAME |
| `metrics.resource_read_*` | `total`, `success`, `fail` | Composite-only: PRODUCT_NAME + TARGET_USER + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + VENDOR_NAME; PRINCIPAL_IP + PRINCIPAL_USER + PRODUCT_NAME + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_APPLICATION + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_RESOURCE_NAME + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_RESOURCE_NAME + TARGET_RESOURCE_TYPE + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_APPLICATION + TARGET_LOCATION_NAME + VENDOR_NAME |
| `metrics.resource_written_*` | `total`, `success`, `fail` | Composite-only: PRODUCT_NAME + TARGET_USER + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + VENDOR_NAME; PRINCIPAL_IP + PRINCIPAL_USER + PRODUCT_NAME + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_APPLICATION + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_RESOURCE_NAME + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_RESOURCE_NAME + TARGET_RESOURCE_TYPE + VENDOR_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_APPLICATION + TARGET_LOCATION_NAME + VENDOR_NAME |

> [!IMPORTANT]
> **Mandatory Vendor & Product Scoping Invariant for Cloud CRUD (`resource_*`)**:
> In Google SecOps Chronicle Malachite, all Cloud Resource Lifecycle metrics (`metrics.resource_creation_*`, `metrics.resource_deletion_*`, `metrics.resource_read_*`, `metrics.resource_written_*`) **strictly require** both `metadata.vendor_name` AND `metadata.product_name` together with a user (`principal.user.*` or `target.user.*`). There is no host/device dimension for these metrics.
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
* **Log Scope:** per metric (no `metadata.event_type` filter in any Workspace baseline):
  - `metrics.workspace_auth_attempts_total`: `metadata.vendor_name = "Google Workspace"` + `(metadata.product_name = "login" or metadata.product_name = "saml" or metadata.product_name = "token")`
  - `metrics.workspace_emails_sent_total`: `(metadata.product_name = "GMAIL" or metadata.product_name = "gmail")`
  - `metrics.workspace_network_bytes_outbound`: `(metadata.product_name = "GMAIL" or metadata.product_name = "gmail")`
  - `metrics.workspace_network_bytes_total`: `(metadata.product_name = "GMAIL" or metadata.product_name = "gmail")`
  - `metrics.workspace_total_change_actions`: `metadata.vendor_name = "Google Workspace"`
  - `metrics.workspace_total_download_actions`: `metadata.vendor_name = "Google Workspace"` + `metadata.product_event_type = "download"`
* **Backing Log Types:** `WORKSPACE_REPORTS`, `GMAIL`
* **Case note:** the Gmail baselines match `product_name` in (`GMAIL`, `gmail`) case-sensitively; tenants that log `Gmail` have no Gmail baseline rows.

| Metric Function | Description | Supported Dimensions |
| :--- | :--- | :--- |
| `metrics.workspace_auth_attempts_total` | Workspace login / SAML / token events | Entity alone: PRINCIPAL_USER, TARGET_USER; also: PRODUCT_EVENT_TYPE + TARGET_USER; PRINCIPAL_IP + TARGET_USER; PRINCIPAL_IP + PRODUCT_EVENT_TYPE + TARGET_USER; PRINCIPAL_COUNTRY + TARGET_USER; PRINCIPAL_IP + PRODUCT_EVENT_TYPE; PRINCIPAL_USER + SECURITY_ACTION; PRINCIPAL_COUNTRY + PRINCIPAL_USER + TARGET_APPLICATION; PRINCIPAL_COUNTRY + PRINCIPAL_USER; PRINCIPAL_IP + PRINCIPAL_USER; PRINCIPAL_USER + PRODUCT_EVENT_TYPE; PRINCIPAL_USER + PRODUCT_EVENT_TYPE + SECURITY_ACTION |
| `metrics.workspace_emails_sent_total` | Outbound Gmail messages | Entity alone: PRINCIPAL_USER; also: PRINCIPAL_USER + SECURITY_RULE_ID; PRINCIPAL_APPLICATION + PRINCIPAL_IP + PRINCIPAL_USER; PRINCIPAL_IP + PRINCIPAL_USER; PRINCIPAL_IP + PRINCIPAL_USER + TARGET_IP; PRINCIPAL_USER + TARGET_IP; EMAIL_FROM_ADDRESS + EMAIL_TO_ADDRESS; MAIL_ID + PRINCIPAL_USER; PRINCIPAL_APPLICATION + PRINCIPAL_USER |
| `metrics.workspace_network_bytes_outbound` | Gmail sent bytes (use `metric: value_sum`) | Entity alone: PRINCIPAL_USER; also: PRINCIPAL_COUNTRY + PRINCIPAL_USER |
| `metrics.workspace_network_bytes_total` | Gmail sent + received bytes (use `metric: value_sum`) | Entity alone: PRINCIPAL_USER; also: PRINCIPAL_COUNTRY + PRINCIPAL_USER |
| `metrics.workspace_total_change_actions` | Every Google Workspace event (despite the name, not only change actions) | Entity alone: PRINCIPAL_USER, TARGET_USER; also: PRINCIPAL_USER + PRODUCT_EVENT_TYPE + SECURITY_ACTION; PRINCIPAL_IP + PRODUCT_EVENT_TYPE; PRINCIPAL_USER + PRODUCT_EVENT_TYPE + PRODUCT_NAME; PRINCIPAL_USER + TARGET_RESOURCE_NAME; PRINCIPAL_USER + PRODUCT_EVENT_TYPE + TARGET_RESOURCE_NAME; PRINCIPAL_IP + PRINCIPAL_USER |
| `metrics.workspace_total_download_actions` | Workspace download actions (`product_event_type = "download"`) | Entity alone: PRINCIPAL_USER; also: PRINCIPAL_USER + TARGET_RESOURCE_NAME; PRINCIPAL_USER + PRODUCT_NAME + TARGET_RESOURCE_NAME |
