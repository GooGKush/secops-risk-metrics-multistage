# 📖 SecOps Hunter's Field Manual: Enhancing & Narrowing Hunts with Entity Context Graph & WHOIS

This reference provides the operational tradecraft, consultative dialogue patterns, field catalog, and compiler invariants for integrating Chronicle's **Entity Context Graph (ECG)** — specifically `DERIVED_CONTEXT` (persistent enterprise prevalence, first seen, and last seen) and `GLOBAL_CONTEXT` (curated WHOIS domain lifecycle and threat intelligence) — into multi-stage risk metrics threat hunting.

---

## 🧭 1. The Hunter's Strategic Dilemma: Narrowing vs. Enhancing

When an analyst investigates anomalous activity (e.g. volumetric network egress, an execution spike, or off-hours authentications), raw 30-day baseline metrics (`metrics.*`) identify entities deviating from historical behavior. However, without external context, hunters face two opposing hazards:
1. **The Confounder Trap (False Positive Storm)**: High-volume legitimate operations (such as Patch Tuesday software updates, administrative bulk backups, or enterprise-wide browser updates) cause massive metric spikes that obscure true zero-day threats.
2. **The Inner-Join Blindspot (Over-Filtering)**: Filtering an initial search exclusively on known IOCs or threat feeds drops 100% of novel attacks and clean anomalies from the results table.

Chronicle Entity Context Graph solves this dilemma by providing two distinct operational pathways:

```
┌──────────────────────────────────────┬────────────────────────────────────────────────────────────────────────┐
│ Hunting Strategy                     │ Operational Security Mechanics & Outcome                              │
├──────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ 🎯 NARROW THE HUNT                   │ • Applies persistent graph rarity as an ACTIVE FILTER in Stage 2/Root. │
│ (The Sieve / Noise Reduction)        │ • Prunes common enterprise software (file rolling_max <= 3).           │
│                                      │ • Drops routine SaaS/CDN destinations (domain rolling_max <= 3).        │
│                                      │ • Isolates infant machines (asset first_seen_time < 7 days).           │
│                                      │ • Outcome: High-prevalence noise drops to 0 rows; only rare survive.   │
├──────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ 🔍 ENHANCE THE HUNT                  │ • Evaluates 100% of the fleet population against universal baselines.  │
│ (The Magnifier / Risk Weighting)     │ • Preserves all anomalous hosts/users in the ranked summary table.     │
│                                      │ • Scales the risk score via context multipliers:                       │
│                                      │   - 2.5x Multiplier for Newly Registered Domains (NRD <= 30 days).     │
│                                      │   - 3.0x Multiplier for Expired Domains or Lapsed Certificates.        │
│                                      │   - Hyperbolic dampening 1.0 / (k_fleet + 1.0) on common tokens.       │
│                                      │ • Outcome: Every outlier is visible, but threat context rises to top.  │
└──────────────────────────────────────┴────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 2. Graph Source Types & UDM Field Catalog

### A. `DERIVED_CONTEXT` (Chronicle Persistent Enterprise History & Prevalence)
Chronicle continuously pre-computes and maintains multi-year enterprise telemetry history across 4 primary entity types:

| Entity Type | Graph Filter & Match Keys | Key Fields Available | Operational Purpose |
| :--- | :--- | :--- | :--- |
| **`FILE`** | `$file.graph.metadata.source_type = "DERIVED_CONTEXT"`<br>`$file.graph.metadata.entity_type = "FILE"`<br>`$file.graph.entity.file.sha256 = $sha256` | `$file.graph.entity.file.prevalence.day_count = 10`<br>`$file.graph.entity.file.prevalence.rolling_max`<br>`$file.graph.entity.file.first_seen_time.seconds`<br>`$file.graph.entity.file.last_seen_time.seconds` | **Binary Rarity**: Sifts zero-day malware from enterprise rollouts.<br>**Binary Age**: Discovers newly introduced binaries across endpoints. |
| **`DOMAIN_NAME`** | `$dom.graph.metadata.source_type = "DERIVED_CONTEXT"`<br>`$dom.graph.metadata.entity_type = "DOMAIN_NAME"`<br>`$dom.graph.entity.domain.name = $domain` | `$dom.graph.entity.domain.prevalence.day_count = 10`<br>`$dom.graph.entity.domain.prevalence.rolling_max`<br>`$dom.graph.entity.domain.first_seen_time.seconds`<br>`$dom.graph.entity.domain.last_seen_time.seconds` | **Destination Rarity**: Discovers external hostnames contacted by $\le 3$ internal machines.<br>**Domain Novelty**: Identifies first-time outbound contacts. |
| **`ASSET`** | `$asset.graph.metadata.source_type = "DERIVED_CONTEXT"`<br>`$asset.graph.metadata.entity_type = "ASSET"`<br>`$asset.graph.entity.asset.hostname = $host` | `$asset.graph.entity.asset.first_seen_time.seconds` | **Infant Machine Discovery**: Flags devices onboarded within the last 7 days.<br>**Asset Age Scoping**: Isolates newly provisioned infrastructure. |
| **`USER`** | `$user.graph.metadata.source_type = "DERIVED_CONTEXT"`<br>`$user.graph.metadata.entity_type = "USER"`<br>`$user.graph.entity.user.userid = $user` | `$user.graph.entity.user.first_seen_time.seconds` | **New Account Activation**: Flags accounts active within 48h of creation.<br>**Novel Identity Scoping**: Surfaces recently created identities. |

### B. `GLOBAL_CONTEXT` (Curated Threat Intelligence & External Lifecycle)
Curated external intelligence continuously updated by Google Cloud and commercial registrars:

| Provider / Feed | Graph Filter & Match Keys | Key Fields Available | Operational Purpose |
| :--- | :--- | :--- | :--- |
| **WHOIS Domain Registration** | `$whois.graph.metadata.source_type = "GLOBAL_CONTEXT"`<br>`$whois.graph.metadata.vendor_name = "WHOIS"`<br>`$whois.graph.metadata.entity_type = "DOMAIN_NAME"`<br>`$whois.graph.entity.domain.name = $domain` | `$whois.graph.entity.domain.creation_time.seconds`<br>`$whois.graph.entity.domain.expiration_time.seconds`<br>`$whois.graph.entity.domain.name` | **Newly Registered Domains (NRD)**: Identifies domains registered $< 30$ days ago.<br>**Domain Hijacking**: Detects egress to expired domains.<br>**Lapsed Certs / Expiration**: Surfaces unrenewed domain infrastructure. |
| **GCTI Threat Intelligence** | `$gcti.graph.metadata.source_type = "GLOBAL_CONTEXT"`<br>`$gcti.graph.metadata.vendor_name = "Google Cloud Threat Intelligence"` | `$gcti.graph.metadata.threat.threat_feed_name`<br>`$gcti.graph.entity.hostname`, `$gcti.graph.entity.ip` | **Threat Feed Confirmation**: Cross-references against Tor Exit Nodes, RATs, and C2 servers. |
| **Google Safe Browsing** | `$sb.graph.metadata.source_type = "GLOBAL_CONTEXT"`<br>`$sb.graph.metadata.product_name = "Google Safe Browsing"` | `$sb.graph.entity.file.sha256`<br>`$sb.graph.entity.url` | **Known Malware Confirmation**: Flags confirmed malicious hashes and URLs. |

---

## 🎯 3. Hunter's Playbook: The 4 Canonical Use Cases

### Playbook 1: Pruning Corporate Rollouts with Derived File Prevalence
* **The Scenario**: An analyst hunts for Living-off-the-Land (LotL) execution spikes or dropper activity on endpoints. Standard metric baselines (`metrics.file_executions_total`) flag legitimate Microsoft Windows updates, Chrome upgrades, or internal IT packages as massive anomalies.
* **The Solution (Narrowing)**:
  - Stage 1 extracts individual host/hash execution volume against `metrics.file_executions_total`.
  - Stage 2 filters on `$file.graph.metadata.source_type = "DERIVED_CONTEXT"` with `prevalence.day_count = 10` and `prevalence.rolling_max <= 3`.
  - Root Stage joins `$sha256` and computes personal $Z$-score.
* **Operational Result**: If an update was pushed to 5,000 machines, its `rolling_max` is 5,000; Stage 2 drops it completely. Only binaries executing on $\le 3$ machines enterprise-wide reach the analyst's screen.
* **Template**: `templates/pipelines/hybrid_metric_derived_file_prevalence_2stage.yl2`

### Playbook 2: Throwaway C2 & Egress Staging with WHOIS Domain Age (NRDs)
* **The Scenario**: Threat actors frequently spin up brand-new domains 24–48 hours prior to launching an attack (e.g. spearphishing lures, Cobalt Strike beacons, or exfiltration staging).
* **The Solution (Enhancing)**:
  - Stage 1 evaluates outbound query volume or bytes (`metrics.http_queries_total`, `metrics.network_bytes_outbound`) per `$host, $domain by 1d`.
  - Stage 2 extracts `$whois.graph.entity.domain.creation_time.seconds` via `GLOBAL_CONTEXT` WHOIS.
  - Root Stage calculates `$domain_age_days = ($now - $creation_ts) / 86400.0`. If `$domain_age_days <= 30.0`, it applies a **2.5x threat score multiplier**.
* **Operational Result**: Benign enterprise CDNs and established SaaS partners maintain high age ($> 1,000$ days) and receive standard $Z$-scores; novel throwaway C2 domains breach the critical threat threshold immediately.
* **Template**: `templates/pipelines/hybrid_metric_whois_domain_lifecycle_2stage.yl2`

### Playbook 3: Domain Takeover & Lapsed Certs with WHOIS Expiration
* **The Scenario**: Attackers often hijack abandoned corporate subdomains or register lapsed domains that internal endpoints continue to query. Similarly, expired SSL certificates or unrenewed domains represent compromised or rogue communications.
* **The Solution (Enhancing & Flagging)**:
  - Stage 2 extracts `$whois.graph.entity.domain.expiration_time.seconds`.
  - In raw TLS companion stages, inspect `network.tls.server.certificate.not_after.seconds < timestamp.current_seconds()`.
  - Root Stage flags `$is_expired = if($expiration_ts <= $now and $expiration_ts > 0, 1.0, 0.0)` and applies a **3.0x risk multiplier**.
* **Operational Result**: Connects departing outbound traffic directly to expired infrastructure vulnerabilities.
* **Template**: `templates/pipelines/hybrid_metric_whois_domain_lifecycle_2stage.yl2`

### Playbook 4: Infant Endpoints & Rogue Hardware with Asset First-Seen Age
* **The Scenario**: Rogue laptops, compromised test VMs, or shadow-IT devices plugged into internal networks frequently exhibit high authentication failure rates or heavy initial egress before security agents are installed.
* **The Solution (Narrowing)**:
  - Stage 1 monitors host authentication attempts (`metrics.auth_attempts_total` or `auth_attempts_fail`).
  - Stage 2 checks `$asset.graph.metadata.source_type = "DERIVED_CONTEXT"` and extracts `entity.asset.first_seen_time.seconds`.
  - Root Stage restricts output to `$asset_age_days <= 7.0`.
* **Operational Result**: Mature domain controllers and established workstations are filtered out; only newly onboarded assets undergoing authentication storms are surfaced.
* **Template**: `templates/pipelines/hybrid_metric_derived_asset_age_2stage.yl2`

---

## ⚡ 4. Compiler & Memory Invariants for Entity Graph DAGs

When authoring multi-stage queries with Entity Context Graph joins, the following rules are strictly enforced by Chronicle's engine and `MalachiteASTValidator`:

### Rule 1: Maximum 1 ECG Alias Per Named Stage (`ECG_LIMIT = 1`)
Chronicle's F1 distributed memory engine isolates graph traversal. Declaring more than one graph alias (`$alias.graph.*`) inside a single stage block causes memory exhaustion.
* ❌ **Invalid (Multiple Graph Aliases in One Stage)**:
  <!-- yara-fragment: intentional invalid stage illustrating multiple ECG alias error -->
  ```yara
  stage bad_stage {
    $whois.graph.metadata.source_type = "GLOBAL_CONTEXT"
    $seen.graph.metadata.source_type = "DERIVED_CONTEXT" // FAILS: 2 ECG aliases in one stage
  }
  ```
* ✅ **Valid (Decoupled across DAG Stages)**:
  Place each graph lookup in its own named stage.

### Rule 2: Zero Event-Section Arithmetic Above `match:`
Graph timestamp calculations must **never** perform binary arithmetic (`-`, `+`, `/`) in the event filter section:
* ❌ **Invalid**:
  ```yara
  $age_days = (timestamp.current_seconds() - $whois.graph.entity.domain.creation_time.seconds) / 86400.0 // FAILS
  ```
* ✅ **Valid (Direct Placeholder Assignment & Outcome Calculation)**:
  ```yara
  // In Stage 2 outcome:
  $creation_ts = max($whois.graph.entity.domain.creation_time.seconds)

  // In Root outcome:
  $now = timestamp.current_seconds()
  $domain_age_days = ($now - $creation_ts) / 86400.0
  ```

### Rule 3: The 10-Day Prevalence Platform Invariant (`day_count = 10`)
* In Google SecOps Entity Graph, prevalence tables are indexed strictly on a **fixed 10-day rolling window**.
* The anchor `$graph.graph.entity.<type>.prevalence.day_count = 10` is a platform invariant. Attempting to change `day_count` to other values (e.g. `30`, `7`, `14`) will fail or return zero data.
* To hunt for longer-term novelty, combine `day_count = 10` with `first_seen_time < 30/60/90 days`.

### Rule 4: The Part-of-the-Whole Anti-Pattern (Decoupled Baseline Sieve)
Never evaluate `metrics.*` in the same stage that filters by external threat attributes (e.g. WHOIS, GCTI, or Safe Browsing). Stage 1 must measure the entity's universal 30-day baseline; Stage 2 evaluates the context; Root Stage performs the risk fusion.

---

## 🗣️ 5. Consultative Dialogue: Engaging Hunters in Phase 1A & Phase 5

When interacting with security analysts, the skill actively leads the conversation to determine whether to Narrow or Enhance:

### Phase 1A Discovery Script (Offering Context Options):
When an analyst initiates a hunt, present clear contextual options:
> *"We can evaluate 30-day behavioral baselines across your fleet. To maximize the value of this hunt, we can layer Chronicle's Entity Context Graph in one of two ways:*
> 1. ***Narrow the Hunt (The Noise Sieve)***: Filter on enterprise prevalence (`rolling_max <= 3`, `day_count = 10`) to automatically prune standard software rollouts or corporate SaaS destinations.
> 2. ***Enhance the Hunt (The Threat Magnifier)***: Keep your entire fleet visible, but apply a 2.5x–3.0x risk multiplier if the external destination is a Newly Registered Domain (< 30 days old) or has an expired domain/cert."*

### Phase 5 Triage Script (Next-Action Guidance):
If the initial hunt was executed as a broad fleet sweep without context, provide immediate drilldowns in Section 5:
> * **1-Click Drilldown A**: *"Would you like to narrow these results to binaries observed on $\le 3$ endpoints enterprise-wide to eliminate Patch Tuesday noise?"*
> * **1-Click Drilldown B**: *"Would you like to check the WHOIS registration age and expiration status for the top 5 destination domains?"*
> * **1-Click Drilldown C**: *"Would you like to isolate infant endpoints (first seen within the last 7 days) exhibiting these authentication spikes?"*
