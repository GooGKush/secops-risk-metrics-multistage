# Consultative Deep-Dive: Security & EDR Alert Accumulation (`metrics.alert_event_name_count`)

## 1. The Deterministic Rule Failure Mode
SOC alert queues treat EDR and security detections (`CB_EDR`, `CS_EDR`, `MICROSOFT_GRAPH_ALERT`, `SENTINELONE_ALERTS`) as isolated point-in-time events:
* High-severity alerts fire immediately, while `LOW` and `INFORMATIONAL` alerts are suppressed or auto-closed.
* Static threshold rules on alert counts ignore per-host or per-rule historical noise profiles, causing noisy developer workstations to drown out quiet production servers.

**Why Attackers Slip Past**:
1. **Alert Dilution & Low-Severity Creep**: Hands-on-keyboard adversaries trip multiple low-severity behavioral indicators (reconnaissance commands,Unsigned DLL loads, anomalous parent-child spawns) that individually sit below SOC escalation thresholds.
2. **Novel Rule First-Sighting**: A single firing of a rule that has `0` historical active days (`num_metric_periods = 0`) on a critical asset is far more significant than 50 firings of a routine policy rule.
3. **Cross-Entity Attribution Gaps**: An alert firing on a host is rarely correlated with the active user identity (`principal.user.userid`) and process hash (`principal.process.file.sha256`) that triggered it.

---

## 2. Valid Compiler Dimension Sets & Baseline Semantics
`metrics.alert_event_name_count` is a **composite-only** metric (`metric: event_count_sum`). Its baseline SQL counts events matching:
```text
(metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS")
```
Every stage that calls `metrics.alert_event_name_count` **must** include this exact log-type filter in its event section and pass one of the 3 compiler-valid dimension sets from `config.textproto`:

1. **Host + Rule Roll-Up (`PRINCIPAL_DEVICE + SECURITY_RESULT_RULE_NAME`)**:
   * **Filter Fields**: `principal.asset.hostname: principal.asset.hostname, security_result.rule_name: security_result.rule_name`
   * **Use Case**: Host-centric alert surge, novel rule detection (`$d_days = 0`), Host 360° Behavioral Radar Spoke 5 (`radar_360_sector_alert.yl2`), and roll-up sector fusion (`rollup_sector_fusion_4stage.yl2`).
2. **Host + User + Process Hash + Rule (`PRINCIPAL_DEVICE + PRINCIPAL_USER + PRINCIPAL_PROCESS_FILE_HASH + SECURITY_RESULT_RULE_NAME`)**:
   * **Filter Fields**: `principal.asset.hostname: principal.asset.hostname, principal.user.userid: principal.user.userid, principal.process.file.sha256: principal.process.file.sha256, security_result.rule_name: security_result.rule_name`
   * **Use Case**: User-attributed EDR alert surge (`MultiStageTemplateRouter.build_alert_surge_query(entity_type=EntityType.USER)`) tying an account and binary SHA256 directly to an alert breakout on a host.
3. **Host + User + Process Path + Rule (`PRINCIPAL_DEVICE + PRINCIPAL_USER + PRINCIPAL_PROCESS_FILE_PATH + SECURITY_RESULT_RULE_NAME`)**:
   * **Filter Fields**: `principal.asset.hostname: principal.asset.hostname, principal.user.userid: principal.user.userid, principal.process.file.full_path: principal.process.file.full_path, security_result.rule_name: security_result.rule_name`
   * **Use Case**: Path-scoped LotL alert attribution when binary hashes rotate or are unavailable.

---

## 3. The Behavioral Antidotes

### Strategy A: Host Alert Surge & Novel Rule Breakout
* **Target Metric**: `metrics.alert_event_name_count`
* **Router / Template**: `MultiStageTemplateRouter.build_alert_surge_query(entity_type=EntityType.ASSET)` or `templates/stage1_extractors/alert_event_name_count.yl2` + `poisson_rarity.yl2` / `two_part_hurdle.yl2`
* **How It Defeats the Blind Spot**: Scores each `(host, rule_name)` tuple against its 30-day baseline and rolls up peak rule Z-score (`$alert_z`), distinct rules triggered (`$distinct_rules`), and novel rules (`$novel_rules` where 30-day active days $= 0$).

### Strategy B: Stealth Alert Accumulation (Longitudinal CUSUM Drift)
* **Target Metric**: `metrics.alert_event_name_count`
* **Math Model**: `longitudinal_cusum.yl2`
* **How It Defeats the Blind Spot**: Accumulates sustained low-amplitude alert elevations over multiple days ($S_t = \max(0, S_{t-1} + Z_t - k)$), catching multi-day intrusion staging before any single day crosses $3.0\sigma$.

### Strategy C: Cross-Sector Alert + Network / Auth Roll-Up Fusion
* **Target Metric**: `metrics.alert_event_name_count` paired with `metrics.network_bytes_outbound`, `metrics.dns_queries_fail`, or `metrics.auth_attempts_fail`
* **Template**: `rollup_sector_fusion_4stage.yl2` (`rollup_sector_fusion_5stage.yl2` with fleet normalization)
* **How It Defeats the Blind Spot**: Rolls `alert_event_name_count` from `(host, rule_name)` up to `principal.asset.hostname` in Stage 1–2 and fuses it with host network egress or authentication failures in Stage 3.

---

## 4. Post-Execution Agentic Pivots (State 3 → Phase 1B)
* **Acute Host Alert Outlier (`ACUTE_OUTLIER`)**: Pivot the host and `$sha256` directly into `HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE` (`hybrid_metric_derived_file_prevalence_2stage.yl2`) to check whether the binary triggering the alert is rare enterprise-wide (`rolling_max <= 3`), or fuse with `network_bytes_outbound` via `rollup_sector_fusion_4stage.yl2`.
* **User-Attributed Alert Breakout**: Carry `$user` and `$host` into a Two-Phase Chained Hunt (`ChainedHuntRouter.build_phase2_cloud_query`) or `CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH` to check whether the user who triggered the endpoint alert also accessed sensitive cloud repositories.
