# Consultative Deep-Dive: Data Hoarding & Stealth Exfiltration

## 1. The Deterministic Rule Failure Mode
Static detection rules designed to detect data loss rely almost exclusively on hard volume limits:
* Example: `network.sent_bytes > 5242880000` (Alert on > 5 GB egress)
* Example: `count(file_downloads) > 50 in 1h`

**Why Attackers Slip Past**:
1. **The Trickle Technique (Threshold Evasion)**: An insider or compromised credential downloading 200 MB every 3 hours will never trigger an hourly or 5 GB threshold rule, yet extracts gigabytes over weeks.
2. **Volumetric Camouflage**: A static threshold of 5 GB set for an entire engineering organization ignores the fact that a financial analyst rarely transfers more than 15 MB in a typical week.
3. **Alternative Channels**: Attackers route data through secondary protocols (DNS TXT/payload queries) or internal SaaS collaboration tools where network firewalls do not inspect payloads.

---

## 2. The Behavioral Antidotes

### Strategy A: The Longitudinal Accumulator (Longitudinal CUSUM Drift)
* **Target Metric**: `metrics.network_bytes_outbound` or `metrics.workspace_total_download_actions`
* **Math Model**: `longitudinal_cusum.yl2`
* **How It Defeats the Blind Spot**: Accumulates deviations above a reference slack parameter ($k = 0.5\sigma$) across multiple consecutive days ($S_t^+ = \max(0, S_{t-1}^+ + Z_t - k)$). Even if daily transfers stay comfortably within nominal levels, sustained deviations cause $S_t^+$ to cross the alert boundary ($H \ge 4.0\sigma$).

### Strategy B: The Shock Absorber (Piecewise CRI)
* **Target Metric**: `metrics.workspace_total_download_actions`
* **Math Model**: `piecewise_cri.yl2`
* **How It Defeats the Blind Spot**: Standard linear Z-scores produce excessive false alarms on jumpy baselines. Piecewise CRI applies a 3-zone curve: Zone 1 ($Z < 2.0$) absorbs operational variance; Zone 2 ($2.0 \le Z < 4.0$) alerts the SOC; Zone 3 ($Z \ge 4.0$) applies an exponential penalty for massive exfiltration events.

### Strategy C: Covert Payload Detection (Poisson-Gamma Bayesian)
* **Target Metric**: `metrics.dns_bytes_outbound`
* **Math Model**: `poisson_gamma_bayesian.yl2`
* **How It Defeats the Blind Spot**: DNS traffic is inherently noisy. A conjugate Poisson-Gamma model updates prior historical byte rate expectations with observed payloads, flagging statistically impossible payload densities without relying on static query count thresholds.

---

## 3. Operational Triage SLA & Chronicle Pivot
When outliers are surfaced:
1. **Inspect Target Destinations**: Pivot to `network.sent_bytes` and `target.ip` / `target.hostname` in Chronicle UI to verify foreign cloud storage endpoints (MEGA, Wasabi, AWS S3).
2. **Examine Document Sensitivity**: For Workspace downloads, check `target.resource.name` for customer PII, trade secrets, or unreleased financials.
