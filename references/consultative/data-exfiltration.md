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

### Strategy D: Outbound Flow Surge (Daily Session-Count Baseline)
* **Target Metric**: `metrics.network_flows_outbound`
* **Math Model**: `c2_beacon_flow_frequency_2stage.yl2` (**Outbound Flow Surge**)
* **How It Defeats the Blind Spot**: Attackers exfiltrating small, serialized tokens keep byte footprints tiny (<1 KB/session). While `metrics.network_bytes_outbound` shows minimal byte deviation, baselining daily session count (`metrics.network_flows_outbound`) with `metric: event_count_sum` catches acute connection count departures ($Z_{\text{flows}} \ge 3.0\sigma$; sub-hour periodicity/jitter hands off to `secops-statistical-hunter` `C2_BEACONING_JITTER`).



### Strategy E: 1-Stage Non-Parametric Quantiles, Bowley Skewness & Skew-Adjusted Tukey Fence
* **Target Metric**: `metrics.network_bytes_outbound` or `metrics.dns_bytes_outbound`
* **Math Model**: `quantile_iqr_skew.yl2` (`quantile_iqr_skew_3stage.yl2`)
* **How It Defeats the Blind Spot**: Historic bulk backups inflate the 30-day arithmetic mean and standard deviation (`$personal_z` masking), while 2-stage `MAD` consumes all 4 stages. Computing `$p10, $q25, $q50, $q75, $p90` in 1 stage via `window.percentile` provides Bowley quartile skewness (`$bowley_skew`), Moors tail-heaviness ratio (`$tail_heaviness`), and the Hubert–Vandervieren Skewness-Adjusted Tukey Upper Fence in 3 stages—leaving a free stage to join `DERIVED_CONTEXT` rare destination prevalence (`rolling_max <= 3`). Furthermore, adding intra-bucket `window.percentile(network.sent_bytes, 50)` vs `window.percentile(network.sent_bytes, 90)` in `stage1_extract` exposes high-tail burst exfiltration (`$p90 / $p50 >= 10x`) even when daily total bytes appear nominal.

---

## 3. Operational Triage SLA & Chronicle Pivot
When outliers are surfaced:
1. **Inspect Target Destinations**: Pivot to `network.sent_bytes` and `target.ip` / `target.hostname` in Chronicle UI to verify foreign cloud storage endpoints (MEGA, Wasabi, AWS S3).
2. **Examine Document Sensitivity**: For Workspace downloads, check `target.resource.name` for customer PII, trade secrets, or unreleased financials.
