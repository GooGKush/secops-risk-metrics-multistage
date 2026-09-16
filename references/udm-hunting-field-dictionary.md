# 📖 Canonical UDM Hunting Field Dictionary

This reference provides the authoritative, compiler-verified field paths from Google SecOps's core Unified Data Model (`//depot/google3/googlex/security/malachite/proto/external/udm.proto`).

Use this dictionary whenever instantiating multi-stage YARA-L templates, authoring raw telemetry companion stages (UDM_EVENTS), or constructing manual triage pivots.

---

## ⚡ The Top 6 Invariant Schema Rules & Anti-Hallucination Traps

| Telemetry Domain | Canonical UDM Protobuf Path | Prohibited / Common Hallucinations | `udm.proto` Anchor |
| :--- | :--- | :--- | :--- |
| **HTTP User-Agent** | `network.http.user_agent` | `target.user_agent`, `target.http.user_agent`, `http.user_agent` | Line 3889 |
| **HTTP Methods & Headers** | `network.http.method`<br>`network.http.referral_url`<br>`network.http.response_code` | `target.method`<br>`target.http.referral_url`<br>`network.response_code` | Lines 3878, 3881, 3893 |
| **Target URL & Hostname** | `target.url`<br>`target.hostname` | `network.http.url`<br>`network.url` | Lines 5698, 5773 |
| **Network Volumes** | `network.sent_bytes`<br>`network.received_bytes` | `network.bytes_sent`, `network.client_bytes`, `network.sentBytes`, `network.bytes` | Lines 836, 839 |
| **Network Protocols** | `network.ip_protocol` (L4: `"TCP"`, `"UDP"`)<br>`network.application_protocol` (L7: `"HTTP"`, `"DNS"`) | `network.protocol = "TCP"`<br>`network.transport_protocol` | Lines 921, 928 |
| **Process Executables** | `principal.process.file.full_path`<br>`principal.process.file.sha256`<br>`principal.process.file.md5` | `principal.process.path`, `target.process.path`, `principal.process.sha256` | Lines 2584, 2599 |
| **Process Invocation** | `principal.process.command_line`<br>`principal.process.pid` | `principal.process.cmdline`, `principal.command_line` | Lines 1734, 1748 |
| **Cloud Resource Access** | `target.resource.name`<br>`target.resource.resource_type` | `target.resource_name`, `target.cloud.resource`, `resource.name` | Line 5845 |

---

## 1. Web & HTTP Telemetry (`metadata.event_type = "NETWORK_HTTP"`)

In HTTP telemetry, requested destination endpoints and protocol transport headers are cleanly split across the `Noun` (`target`) and the `Network` (`network.http`) messages:

### Canonical Fields:
- **User-Agent String**: `network.http.user_agent`
- **HTTP Method**: `network.http.method` (`"GET"`, `"POST"`, `"PUT"`, `"DELETE"`)
- **HTTP Status Code**: `network.http.response_code` (`200`, `302`, `404`, `500`)
- **Referrer URL**: `network.http.referral_url`
- **Target URL**: `target.url` (e.g. `https://login.corp.com/api/v1/auth`)
- **Target Hostname**: `target.hostname` (e.g. `login.corp.com`)
- **Target Port**: `target.port` (`80`, `443`, `8080`)
- **Source IP / Asset**: `principal.ip` or `principal.asset.ip`
- **Source Client Hostname**: `principal.asset.hostname`

### Anti-Pattern Traps:
❌ **INVALID**: `target.user_agent = /Python-requests/` (Causes query compilation error `400 Invalid argument: target.user_agent is not a valid field`)  
✅ **VALID**: `network.http.user_agent = /Python-requests/`

❌ **INVALID**: `network.http.url = "..."`  
✅ **VALID**: `target.url = "..."`

---

## 2. Network Flow & Connection Telemetry (`NETWORK_FLOW`, `NETWORK_CONNECTION`)

Netflow, firewall sessions, and VPC flow logs represent transfer volume and layer-specific protocols under the `network` block:

### Canonical Fields:
- **Egress (Outbound) Bytes**: `network.sent_bytes` (`uint64`)
- **Ingress (Inbound) Bytes**: `network.received_bytes` (`uint64`)
- **Total Bytes**: `network.total_bytes` (`int64`)
- **Packets Sent / Received**: `network.sent_packets`, `network.received_packets`
- **Session Duration**: `network.session_duration.seconds` (`int64`)
- **Traffic Direction**: `network.direction` (`OUTBOUND`, `INBOUND`, `BROADCAST`, `UNKNOWN_DIRECTION`)
- **Transport Protocol (L4)**: `network.ip_protocol` (`"TCP"`, `"UDP"`, `"ICMP"`, `"GRE"`)
- **Application Protocol (L7)**: `network.application_protocol` (`"HTTP"`, `"DNS"`, `"SSH"`, `"FTP"`, `"SMTP"`)

### Anti-Pattern Traps:
❌ **INVALID**: `network.bytes > 1000000000` or `network.bytes_sent > 1000000`  
✅ **VALID**: `network.sent_bytes > 1000000000`

❌ **INVALID**: `network.protocol = "TCP"`  
✅ **VALID**: `network.ip_protocol = "TCP"`

---

## 3. Endpoint Process Telemetry (`PROCESS_LAUNCH`, `PROCESS_INJECTION`)

Process execution events model the binary image as a `File` sub-message within `Process`:

### Canonical Fields:
- **Executable Full Path**: `principal.process.file.full_path` (or `target.process.file.full_path`)
- **Executable Hash**: `principal.process.file.sha256`, `principal.process.file.md5`
- **Executable File Size**: `principal.process.file.size`
- **Command Line**: `principal.process.command_line`
- **Process ID**: `principal.process.pid`
- **Parent Process Command Line**: `principal.process.parent_process.command_line`
- **Parent Process Executable Path**: `principal.process.parent_process.file.full_path`
- **Executing User**: `principal.user.userid`
- **Executing Machine**: `principal.asset.hostname`

### Anti-Pattern Traps:
❌ **INVALID**: `principal.process.path = "/usr/bin/curl"`  
✅ **VALID**: `principal.process.file.full_path = "/usr/bin/curl"`

❌ **INVALID**: `principal.process.sha256 = "..."`  
✅ **VALID**: `principal.process.file.sha256 = "..."`

---

## 4. User Authentication Telemetry (`USER_LOGIN`, `USER_LOGOUT`)

Authentication logs must cleanly differentiate the client/source from the identity/target being authenticated:

### Canonical Fields:
- **Target User Account**: `target.user.userid` (the account authenticated into)
- **Target User Email**: `target.user.email_addresses`
- **Originating User**: `principal.user.userid` (often service/system or equal to target)
- **Source Hostname**: `principal.asset.hostname`
- **Source IP**: `principal.ip` or `principal.asset.ip`
- **Target Destination Host**: `target.asset.hostname` (the server/host receiving authentication)
- **Logon Type / Mechanism**: `extensions.auth.type` (e.g. `INTERACTIVE`, `REMOTE_INTERACTIVE`, `SERVICE`)
- **Authentication Result**: `security_result.action` (`ALLOW`, `BLOCK`)

---

## 5. Cloud Resource Operations (`USER_RESOURCE_CREATION`, `USER_RESOURCE_UPDATE_CONTENT`, etc.)

Cloud control plane operations (GCP Cloud Audit Logs, AWS CloudTrail, Azure Activity Logs) describe modified resources under `target.resource`:

### Canonical Fields:
- **Resource Identifier / URI**: `target.resource.name`
- **Resource Category**: `target.resource.resource_type` (e.g. `"storage.googleapis.com/Bucket"`, `"compute.googleapis.com/Instance"`)
- **Resource Sub-Type**: `target.resource.resource_subtype`
- **Acting Principal**: `principal.user.userid` or `principal.user.email_addresses`
- **Service Name**: `target.application` (e.g. `"storage.googleapis.com"`, `"bigquery.googleapis.com"`)
- **Vendor / Product**: `metadata.vendor_name`, `metadata.product_name`
