# 360° Entity Behavioral Risk Radar: Canonical Architecture & Execution Playbook

This guide is the definitive, authoritative reference for executing the **360° Entity Behavioral Risk Radar** across Google SecOps Chronicle SIEM, Chronicle SOAR, and conversational MCP agents.

---

## 🏛️ 1. Architecture & Execution Topology

### 1.1 The Operational Objective
The 360° Entity Behavioral Risk Radar profiles an entity across **all five canonical enterprise telemetry sectors** against 30-day pre-computed historical baselines (`metrics.*`) to detect coordinated multi-stage lateral movement, insider threat escalation, and anomalous baseline departures.

```
                         [ 1. IAM & Authentication ]
                                     ▲
                                     │
      [ 5. DNS & Web Activity ] ◄─── ┼ ───► [ 2. Cloud Infrastructure ]
                                   ╱   ╲
                                  ▼     ▼
             [ 4. Network Egress ]       [ 3. Workspace Data ]
```

### 1.2 The Decoupled Execution Mandate (Zero Monolithic Joins)
In Google SecOps Chronicle SIEM, attempting to join all 5 sectors into a single monolithic YARA-L 2.0 multi-stage query is an architectural anti-pattern:
1. **Join Depth Limit**: Chronicle limits queries to a maximum of 4 joins (`maxJoinCount = 4`). Fusing 5 orthogonal sectors into one query fails compilation immediately.
2. **Inner-Join Suppression**: Multi-stage YARA-L joins are strict conjunctions ($S_1 \land S_2 \land \dots \land S_5$). If an entity is elevated on 2 vectors but has zero activity on the other 3 within the match window, an inner join drops the entity entirely.
3. **Cross-Entity Boundary Incompatibility**: Cloud actions (`principal.user.userid`), Auth (`target.user.userid`), and Network/DNS (`principal.asset.hostname`) do not share identical primary keys.

**The Canonical Solution**:
Execute **five independent, decoupled sector queries**, retrieve the observed metrics per sector, and perform the **Euclidean Norm Join ($D = \sqrt{\sum Z_i^2}$)** client-side.

---

## 🖥️ 2. Adaptive Client Execution Tiers

Because MCP clients operate across varied environments (web browsers, IDEs, desktop apps, and headless terminals), the 360 Radar supports **three adaptive execution tiers**:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CLIENT ENVIRONMENT                            │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         ▼                           ▼                           ▼
┌──────────────────┐        ┌──────────────────┐        ┌──────────────────┐
│      TIER 1      │        │      TIER 2      │        │      TIER 3      │
│  Rich Web / UI   │        │  File-Enabled    │        │  Headless CLI /  │
│  (Claude, Web,   │        │  Terminal        │        │  Text Terminal   │
│   Electron)      │        │  (Jetski, IDE)   │        │  (direct-mcp)    │
├──────────────────┤        ├──────────────────┤        ├──────────────────┤
│ Browser V8 Engine│        │ Python collector │        │ Deterministic    │
│ executes math in │        │ writes HTML/SVG  │        │ 5-Sector Matrix  │
│ client JavaScript│        │ to disk; embeds  │        │ & Hurdle Score-  │
│ & renders canvas │        │ artifact link    │        │ card (Zero Math) │
└──────────────────┘        └──────────────────┘        └──────────────────┘
```

### Tier 1: Rich Web / Browser Client (Local JavaScript Execution)
* **Execution**: The agent emits a declarative JSON spoke payload. The browser's native JavaScript engine executes the Euclidean distance and CRI formulas locally, rendering the SVG radar dynamically.
* **Benefit**: **Zero arithmetic hallucination**. Floating-point square roots and sigmoids are computed with 100% precision by the browser.

### Tier 2: File-Enabled Terminal / Jetski Environment
* **Execution**: The agent invokes `python3 scripts/radar_collector.py` via local shell. The script writes `radar_<entity>.html` and companions, outputting `<agent-embed>` or file links.
* **Benefit**: Seamless artifact generation with persistent audit trails.

### Tier 3: Pure Headless / Command-Line Client (Zero-Math Scorecard)
* **Execution**: In a terminal that lacks webview and shell access, the agent **never attempts floating-point math**. Instead, it presents the **Deterministic 5-Sector Terminal Scorecard** evaluating discrete event counts and a **$k$-of-5 Sector Hurdle**.
* **Benefit**: Fully grounded, verifiable intelligence without fabricated standard deviations or Z-scores.

---

## 🚦 3. Phase 1: Pre-Flight Scoping & Identity Resolution

### 3.1 Technical Identity Resolution Protocol
Pre-computed metric tables (`metrics.*`) are indexed strictly by technical logon identifiers (`user.userid` or `asset.hostname`), never by user display names.

1. **Spot-Check Query**:
   ```sql
   (target.user.userid = "<InputName>" nocase or principal.user.userid = "<InputName>" nocase or target.user.user_display_name = "<InputName>" nocase or principal.user.user_display_name = "<InputName>" nocase)
   ```
   *Time range*: Last 14 days (`startTime: <ISO_14D_AGO>`, `endTime: <ISO_NOW>`, `maxEvents: 5`).
2. **Resolution Gate**: If matched, extract canonical `user.userid` (e.g., `"Frank Kolzig"` $\to$ `frank.kolzig`). If 0 events match, halt and request the user's technical username or email.

### 3.2 Standard Pre-Flight Specification Card
On Turn 1, emit the card and single-representative preview query, then yield the turn:

```markdown
PRE-FLIGHT HUNTING SPECIFICATION:
• Target Entity / Scope:  [Target User or Host, e.g. frank.kolzig (Frank Kolzig)]
• Baseline Horizon Spine: 30-Day Pre-Computed (period: 1d, 30d)
• Peer Cohort & Roster:   [Department / Peer Group, e.g. Information Technology]
• Entity Graph Dimension: N/A (360° Omnidirectional Behavioral Radar)
• Evaluation Horizon Mode:Mode A: 24h Snapshot OR Mode B: 14d Timeline
• Statistical Model:      360° Entity Behavioral Risk Radar (5-Sector Fusion)
• Significance Threshold: Z >= 3.0σ (CRI >= 50) / D >= 3.5σ
```

### 3.3 Single Representative Query Preview (IAM & Auth)
```yara
// Representative Sector Micro-Query: IAM & Authentication
// (Evaluated alongside Cloud, Workspace, Network, and DNS decoupled micro-queries)
stage auth_fail {
    metadata.event_type = "USER_LOGIN"
    security_result.action = "BLOCK"
    target.user.userid = "%(entity_id)s"
    $user = target.user.userid
  match:
    $user by 1d
  outcome:
    $fail_obs = count(metadata.id)
    $fail_avg = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: "%(entity_id)s"))
    $fail_std = max(metrics.auth_attempts_fail(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: "%(entity_id)s"))
}
stage auth_success {
    metadata.event_type = "USER_LOGIN"
    security_result.action = "ALLOW"
    target.user.userid = "%(entity_id)s"
    $user = target.user.userid
  match:
    $user by 1d
  outcome:
    $succ_obs = count(metadata.id)
    $succ_avg = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: "%(entity_id)s"))
    $succ_std = max(metrics.auth_attempts_success(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: "%(entity_id)s"))
}
$user = $auth_fail.user
$user = $auth_success.user
match: $user by 1d
outcome:
  $z_fail = (max($auth_fail.fail_obs) - max($auth_fail.fail_avg)) / (max($auth_fail.fail_std) + 1.0)
  $z_succ = (max($auth_success.succ_obs) - max($auth_success.succ_avg)) / (max($auth_success.succ_std) + 1.0)
```

*Yield Turn Prompt*:
> *"Would you like me to proceed with **Mode A (24-Hour Snapshot fleet ranking)** or **Mode B (14-Day Longitudinal Timeline)**?"*

---

## 🔍 4. Phase 2: The 5 Invariate Canonical Sector Queries

On clearance, the agent evaluates the target across all five orthogonal sectors.

### 4.1 USER Entity Sector Specifications

#### Sector 1: IAM & Authentication
* **Telemetry Filter**: `metadata.event_type = "USER_LOGIN" and (target.user.userid = "%(entity_id)s" or principal.user.userid = "%(entity_id)s")`
* **Metrics Functions**: `metrics.auth_attempts_fail`, `metrics.auth_attempts_success`, `metrics.auth_attempts_total`
* **Dimension Scope**: `target.user.userid`
* **Spoke Unit**: `logins`

#### Sector 2: Cloud Infrastructure & IAM CRUD
* **Telemetry Filter**: `(metadata.event_type = "RESOURCE_CREATION" or metadata.event_type = "RESOURCE_DELETION" or metadata.event_type = "RESOURCE_WRITTEN" or metadata.event_type = "RESOURCE_PERMISSIONS_CHANGE") and (principal.user.userid = "%(entity_id)s" or target.user.userid = "%(entity_id)s")`
* **Metrics Functions**: `metrics.resource_creation_total`, `metrics.resource_deletion_total`, `metrics.resource_written_total`
* **Dimension Scope**: `principal.user.userid`, `metadata.vendor_name`, `metadata.product_name`
* **Spoke Unit**: `actions`

#### Sector 3: Workspace Data Hoarding & Exfiltration
* **Telemetry Filter**: `metadata.event_type = "USER_RESOURCE_ACCESS" and (principal.user.userid = "%(entity_id)s" or target.user.userid = "%(entity_id)s")`
* **Metrics Functions**: `metrics.workspace_total_download_actions`, `metrics.workspace_total_change_actions`
* **Dimension Scope**: `principal.user.userid`
* **Spoke Unit**: `downloads`

#### Sector 4: Network Egress Volume
* **Telemetry Filter**: `metadata.event_type = "NETWORK_CONNECTION" and (principal.user.userid = "%(entity_id)s" or target.user.userid = "%(entity_id)s")`
* **Metrics Functions**: `metrics.network_bytes_outbound`, `metrics.network_flows_outbound`
* **Dimension Scope**: `principal.user.userid`
* **Spoke Unit**: `bytes` (or `MB`)

#### Sector 5: DNS & Web Activity
* **Telemetry Filter**: `(metadata.event_type = "NETWORK_DNS" or metadata.event_type = "NETWORK_HTTP") and (principal.user.userid = "%(entity_id)s" or target.user.userid = "%(entity_id)s")`
* **Metrics Functions**: `metrics.dns_queries_fail`, `metrics.http_queries_total`
* **Dimension Scope**: `principal.user.userid`
* **Spoke Unit**: `queries`

---

### 4.2 ASSET Entity Sector Specifications
When the entity is a Host (`ASSET`), telemetry scope maps as follows:

| Sector | Telemetry Filter | Metrics Table | Primary Dimension |
| :--- | :--- | :--- | :--- |
| **Authentication** | `metadata.event_type = "USER_LOGIN"` | `metrics.auth_attempts_fail` | `principal.asset.hostname` |
| **Network Egress** | `metadata.event_type = "NETWORK_CONNECTION"` | `metrics.network_bytes_outbound` | `principal.asset.hostname` |
| **DNS Resolution** | `metadata.event_type = "NETWORK_DNS"` | `metrics.dns_queries_fail` | `principal.asset.hostname` |
| **Cloud CRUD** | `metadata.event_type = "RESOURCE_CREATION"` | `metrics.resource_creation_total` | `principal.asset.hostname` |
| **Process Launches** | `metadata.event_type = "PROCESS_LAUNCH"` | `metrics.process_launches_total` | `principal.asset.hostname` |

---

## ⚖️ 5. Phase 3: Affirmative Data Harvesting Standards

To eliminate synthetic baseline invention without relying on negative rules, the skill establishes affirmative operational definitions:

### 5.1 Deterministic Nominal Baseline for Quiet Sectors
When a sector query returns **0 observed events** within the evaluation window:
* **Affirmative Rule**: A sector with zero observed activity operates at its **Nominal Baseline**.
* **Standardized Assignment**:
  $$\text{Observed} = 0, \quad \mu = 0.0, \quad \sigma = 0.0, \quad Z = 0.00\sigma, \quad \text{CRI} = 0, \quad \text{Status} = \text{🟢 Nominal Baseline}$$
* **Mathematical Rationale**: In a normalized Gaussian Euclidean space, an unbreached vector contributes $(0.00)^2 = 0$ to total distance $D$.

### 5.2 Active Sector Data Handling
When a sector query returns **$> 0$ events**:
* **Observed Count**: Extracted directly from the query event count or aggregated volume.
* **Standardized Formula**:
  $$Z_i = \frac{\text{Observed}_i - \mu_i}{\sigma_i + 1.0}$$
* **Baseline Retrieval**:
  * In YARA-L detection runs: $\mu$ and $\sigma$ are output directly by `metrics.*` outcome variables.
  * In empirical UDM search: $\mu$ and $\sigma$ reflect the entity's 30-day daily historical distribution. If historical baseline telemetry is absent, record $\mu = \text{Uncomputed}, \sigma = \text{Uncomputed}, Z = \text{Evaluated Count}$.

---

## 📐 6. Phase 4: Mathematical Join Engine & Local JS Implementation

### 6.1 The Mathematical Formulation
For $k = 5$ orthogonal sectors:

1. **Euclidean Threat Distance ($D$)**:
   $$D = \sqrt{\sum_{i=1}^{5} \max(0, Z_i)^2}$$
2. **Calibrated Risk Index (CRI $[0–100]$)**:
   $$\text{CRI} = \min\left(100, \max\left(0, \text{round}\left(\frac{100}{1 + e^{-0.6(D - 3.0)}}\right)\right)\right)$$
   * $D = 0.0\sigma \implies \text{CRI} \approx 14$
   * $D = 3.0\sigma \implies \text{CRI} = 50$ (Anomaly Boundary)
   * $D \ge 4.5\sigma \implies \text{CRI} \ge 70$ (Critical High Threat)

---

### 6.2 Browser-Side JavaScript Implementation (Tier 1 Webviews)
For web and Electron MCP clients, embed this self-contained script. The client browser executes the math and draws the SVG:

```html
<div id="radar-container" style="max-width: 620px; font-family: Roboto, Arial, sans-serif;">
  <svg id="radar-svg" viewBox="0 0 620 480" width="100%" height="480"></svg>
</div>

<script>
(function() {
  const spokesData = [
    { sector: "IAM & Authentication", spoke: "Logins", obs: 4, mu: 0.5, sigma: 0.8 },
    { sector: "Cloud Infrastructure", spoke: "CRUD",   obs: 14, mu: 2.0, sigma: 3.0 },
    { sector: "Workspace Data",       spoke: "Exfil",  obs: 0, mu: 0.0, sigma: 0.0 },
    { sector: "Network Egress",       spoke: "Egress", obs: 0, mu: 0.0, sigma: 0.0 },
    { sector: "DNS & Web Activity",   spoke: "DNS",    obs: 0, mu: 0.0, sigma: 0.0 }
  ];

  // 1. Compute exact Z-scores per spoke
  spokesData.forEach(s => {
    s.z = s.obs === 0 ? 0.0 : (s.obs - s.mu) / (s.sigma + 1.0);
  });

  // 2. Compute exact Euclidean distance D
  const sumSquares = spokesData.reduce((acc, s) => acc + Math.pow(Math.max(0, s.z), 2), 0);
  const D = Math.sqrt(sumSquares);

  // 3. Compute Sigmoid Calibrated Risk Index
  const CRI = Math.min(100, Math.max(0, Math.round(100 / (1 + Math.exp(-0.6 * (D - 3.0))))));

  // 4. Render Dynamic SVG Radar
  const svg = document.getElementById("radar-svg");
  const cx = 310, cy = 250, maxR = 125, n = spokesData.length;

  // Background Rings
  [1.0, 2.0, 3.0, 4.0].forEach(ringZ => {
    const r = (ringZ / 4.0) * maxR;
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", cx); circle.setAttribute("cy", cy); circle.setAttribute("r", r);
    circle.setAttribute("fill", "none");
    circle.setAttribute("stroke", ringZ === 3.0 ? "#d93025" : "#e0e0e0");
    circle.setAttribute("stroke-dasharray", ringZ === 3.0 ? "4,4" : "none");
    svg.appendChild(circle);
  });

  // Polygon Points
  const points = spokesData.map((s, i) => {
    const angle = -Math.PI / 2 + (2 * Math.PI * i / n);
    const clampedZ = Math.min(Math.max(0, s.z), 4.0);
    const r = (clampedZ / 4.0) * maxR;
    return `${cx + r * Math.cos(angle)},${cy + r * Math.sin(angle)}`;
  }).join(" ");

  const polygon = document.createElementNS("http://www.w3.org/2000/svg", "polygon");
  polygon.setAttribute("points", points);
  polygon.setAttribute("fill", D >= 3.0 ? "rgba(217,48,37,0.25)" : "rgba(26,115,232,0.25)");
  polygon.setAttribute("stroke", D >= 3.0 ? "#d93025" : "#1a73e8");
  polygon.setAttribute("stroke-width", "2");
  svg.appendChild(polygon);
})();
</script>
```

---

### 6.3 Python Collector Invocation (Tier 2 Environments)
In environments with local script execution, invoke `scripts/radar_collector.py`:

```bash
python3 scripts/radar_collector.py \
  --entity "frank.kolzig" \
  --entity-type USER \
  --data '[
    {"sector": "IAM & Authentication", "spoke_name": "Authentication Attempts", "metric_table": "metrics.auth_attempts_total", "observed": 6.0, "baseline_mean": 4.2, "baseline_stddev": 1.8, "z_score": 0.64, "unit": "logins"},
    {"sector": "Cloud Infrastructure", "spoke_name": "Cloud Resource CRUD", "metric_table": "metrics.resource_creation_total", "observed": 0.0, "baseline_mean": 0.0, "baseline_stddev": 0.0, "z_score": 0.0, "unit": "events"},
    {"sector": "Workspace Data", "spoke_name": "Workspace & SaaS Exfil", "metric_table": "metrics.workspace_total_download_actions", "observed": 0.0, "baseline_mean": 0.0, "baseline_stddev": 0.0, "z_score": 0.0, "unit": "actions"},
    {"sector": "Network Egress", "spoke_name": "Network Egress", "metric_table": "metrics.network_bytes_outbound", "observed": 0.0, "baseline_mean": 0.0, "baseline_stddev": 0.0, "z_score": 0.0, "unit": "bytes"},
    {"sector": "DNS & Web Activity", "spoke_name": "DNS & Web Activity", "metric_table": "metrics.dns_queries_fail", "observed": 4.0, "baseline_mean": 3.5, "baseline_stddev": 1.2, "z_score": 0.23, "unit": "queries"}
  ]' \
  --format embed \
  --output /path/to/artifacts/radar_frank_kolzig.html
```

---

## 📋 7. Complete Deterministic 6-Pillar Report Template

### 7.1 Tier 1 / Tier 2 Rich Report (Visual Radar)

````markdown
#### 1. Statistical Outlier Report: 360° Entity Behavioral Risk Radar (Multi-Sector Fusion) (window: 30d)

<agent-embed src="file:///path/to/artifacts/radar_frank_kolzig.html"></agent-embed>
[📊 Open 360° Risk Radar (SVG/HTML)](file:///path/to/artifacts/radar_frank_kolzig.html)

* **Target Entity**: `frank.kolzig` (Windows Administrator, Information Technology)
* **Composite Threat Distance**: $D = 0.68\sigma$
* **Calibrated Risk Index**: $\text{CRI} = 18 / 100$ (🟢 Nominal Volumetric Baseline)
* **Evaluated Horizon**: Mode A (24-Hour Snapshot vs. 30-Day Pre-Computed Baseline)

---

#### 2. Executed Multi-Stage YARA-L Query Architecture

*(The 360° evaluation architecture decouples orthogonal behavioral sectors into independent micro-queries against their respective 30-day pre-computed metric tables to prevent inner-join suppression.)*

```yara
// Sector 1: IAM & Authentication
stage auth_risk {
    metadata.event_type = "USER_LOGIN"
    target.user.userid = "frank.kolzig"
    $user = target.user.userid
  match: $user by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.auth_attempts_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: "frank.kolzig"))
    $std = max(metrics.auth_attempts_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: "frank.kolzig"))
    $z = ($obs - $avg) / ($std + 1.0)
}
// Sector 2: Cloud Infrastructure CRUD
stage cloud_risk {
    metadata.event_type = "RESOURCE_CREATION"
    principal.user.userid = "frank.kolzig"
    $user = principal.user.userid
    metadata.vendor_name = $v
    metadata.product_name = $p
  match: $user, $v, $p by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.resource_creation_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, principal.user.userid: "frank.kolzig", metadata.vendor_name: $v, metadata.product_name: $p))
    $std = max(metrics.resource_creation_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, principal.user.userid: "frank.kolzig", metadata.vendor_name: $v, metadata.product_name: $p))
    $z = ($obs - $avg) / ($std + 1.0)
}
// (Sectors 3, 4, and 5 evaluated via decoupled Workspace, Network, and DNS micro-queries)
```

---

#### 3. Ranked Outlier Summary & Provenance Stamp

| Sector / Spoke | 24h Observed | 30d Mean (μ) | 30d StdDev (σ) | Z-Score | CRI Score | Visual Magnitude | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **IAM & Authentication** | 6 logins | 4.2 logins | 1.8 logins | $+0.64\sigma$ | 19 | `▰▰▰▱▱▱▱▱▱▱▱▱▱▱▱` | 🟢 Nominal |
| **DNS & Web Activity** | 4 queries | 3.5 queries | 1.2 queries | $+0.23\sigma$ | 16 | `▰▱▱▱▱▱▱▱▱▱▱▱▱▱▱` | 🟢 Nominal |
| **Cloud Infrastructure** | 0 events | 0.0 events | 0.0 events | $+0.00\sigma$ | 14 | `▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱` | 🟢 Nominal |
| **Workspace Data** | 0 actions | 0.0 actions | 0.0 actions | $+0.00\sigma$ | 14 | `▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱` | 🟢 Nominal |
| **Network Egress** | 0 bytes | 0.0 bytes | 0.0 bytes | $+0.00\sigma$ | 14 | `▱▱▱▱▱▱▱▱▱▱▱▱▱▱▱` | 🟢 Nominal |
| **Composite Threat Distance** | — | — | — | $D = 0.68\sigma$ | **18 / 100** | `▰▰▰▱▱▱▱▱▱▱▱▱▱▱▱` | 🟢 **Nominal Baseline** |

```markdown
PROVENANCE STAMP:
• Telemetry Events Scanned:  100 events across 24h evaluation window
• Chronicle Target Customer: 8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5 (Region: us, Project: gus-sdl)
• Sector Join Runtime:       Client-Side Euclidean Join (radar_collector.py / browser V8)
• Output Dimensions:         [entity_id, observed, baseline_mean, baseline_stddev, z_score, D, CRI]
```

---

#### 4. Forensic Vector Breakdown

##### Behavioral Threat Translation
While macroscopic volumetric baselines across the cloud, network, and SaaS planes remain nominal ($D = 0.68\sigma$), raw endpoint logs reveal **active hostile administrative utilities executed under this credential context**:
* **Active Directory NTDS Staging**: `vssadmin create shadow /for=C:` and `cmd.exe /c copy x:\windows\ntds\ntds.dit c:\ntds.dit`
* **In-Memory Credential Dumping**: `mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit`

##### SOC Playbook & Immediate Remediation Recommendations
* **Account Containment**: Revoke all active Kerberos TGT sessions for `frank.kolzig` and force an administrative password reset.
* **Asset Isolation**: Isolate host `activedir.stackedpads.local` to preserve volatile memory.
* **Dual KRBTGT Reset**: Initiate domain-wide `krbtgt` password rotation.

---

#### 5. Chronicle UI Manual Pivot (Triage Reference Only)

```sql
(target.user.userid = "frank.kolzig" or principal.user.userid = "frank.kolzig") and metadata.event_type = "PROCESS_LAUNCH"
```

---

#### 6. Collapsible Technical Appendix (Statistical & Mathematical Appendix)

<details>
<summary>Click to view Mathematical & Statistical Formulation</summary>

##### 1. Multi-Sector Euclidean Threat Distance ($D$)
$$D = \sqrt{\sum_{i=1}^{k} \max(0, Z_i)^2} = \sqrt{(0.64)^2 + (0.23)^2 + 0^2 + 0^2 + 0^2} \approx 0.68\sigma$$

##### 2. Calibrated Risk Index (CRI)
$$\text{CRI} = \text{round}\left(\frac{100}{1 + e^{-0.6(0.68 - 3.0)}}\right) = \text{round}\left(\frac{100}{1 + e^{1.392}}\right) \approx 18$$

##### 3. Longitudinal Horizon Parameters
* Baseline Window: $N = 30\text{ days}$
* Aggregation Unit: $1\text{ day}$ rolling buckets (`period: 1d`)
* Dispersion Floor: $\sigma_{\text{floor}} = 1.0$ applied to prevent division-by-zero on low-entropy dimensions:
$$Z_i = \frac{\text{Obs}_i - \mu_i}{\sigma_i + 1.0}$$

</details>
````

---

### 7.2 Tier 3 Headless / Text CLI Report (Deterministic Scorecard)

When running in a pure command-line terminal without webview or shell calculation tools:

```markdown
### 🛡️ 360° Entity Behavioral Scorecard: `admin`
• Evaluation Horizon: 24h Snapshot (2026-09-05 to 2026-09-06)
• Historical Baseline: 30-Day Pre-Computed Metrics
• Multi-Sector Consensus: 🚨 2 of 5 Sectors Active (High Threat Fusion)

| Telemetry Sector | 24h Observed | Baseline Status | Vector State |
| :--- | :--- | :--- | :--- |
| **1. IAM & Authentication** | 4 failed challenges | Policy enforcement blocks | 🚨 **ELEVATED** |
| **2. Cloud Infrastructure** | 14 CRUD actions     | CloudRun/Build modifications | 🚨 **ELEVATED** |
| **3. Workspace Data**       | 0 downloads         | 30d Nominal Baseline         | 🟢 Nominal Baseline |
| **4. Network Egress**       | 0 MB                | 30d Nominal Baseline         | 🟢 Nominal Baseline |
| **5. DNS & Web Activity**   | 0 queries           | 30d Nominal Baseline         | 🟢 Nominal Baseline |

---

#### Forensic Findings Summary
* **Authentication**: 4 failed re-authentication challenges triggering `riskySensitiveActionBlocked` on backend `organizations/579698384403`.
* **Cloud Infrastructure**: CloudRun service modification on `secops-mcp-interface` and service account impersonation on `mcp-web-comms@chronicle-mps.iam.gserviceaccount.com`.
* **Quiet Sectors**: Zero data hoarding in Google Drive, zero abnormal network egress.
```
