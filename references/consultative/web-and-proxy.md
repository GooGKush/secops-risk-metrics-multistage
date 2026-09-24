# Consultative Deep-Dive: Web, Proxy & Covert HTTP Channels

## 1. The Deterministic Rule Failure Mode
Web proxy, gateway, and HTTP firewall rules are predominantly binary and static:
* Example: `network.http.user_agent = "*sqlmap*"` or `network.http.user_agent = "*curl*"`
* Example: `network.http.response_code = 404` with static count threshold `count > 100`
* Example: `target.hostname in %malicious_domains%`

**Why Attackers Slip Past**:
1. **User-Agent Masquerading & Living-off-the-Browser**: Modern threat actors, commodity malware, and C2 frameworks (e.g. Cobalt Strike, Mythic, Sliver) routinely clone standard enterprise browser strings (Chrome, Edge, Safari) or use benign system agents (`Microsoft-CryptoAPI`, `Windows-Update-Agent`). Static blacklists only catch unsophisticated script-kiddie tools.
2. **Slow-and-Low API Enumeration & Fuzzing**: Attackers probe endpoints, cloud REST APIs, and administrative portals at low rates (1 request every 5–10 seconds) with intermittent $401, 403, 404$ responses, staying well below volumetric tripwires while still extracting sensitive schemas or brute-forcing endpoints.
3. **Targeted C2 via Trusted Cloud Providers**: Command-and-control and exfiltration channels increasingly route through legitimate SaaS endpoints (`api.github.com`, `storage.googleapis.com`, `discord.com`, `notion.so`). Domain-reputation blacklists cannot block the domain without severing legitimate business functions.
4. **Corporate Browser / Extension Rollout Noise**: When IT pushes a new browser update or security plugin, thousands of hosts simultaneously generate a new User-Agent token. Static rules detecting "new user-agent strings" flood the SOC with unmanageable false-positive storms.

---

## 2. The Behavioral Antidotes

### Strategy A: User-Agent Token Fleet Prevalence Shield
* **Target Metric**: `metrics.http_queries_total`
* **Math Model & Template**: `templates/pipelines/hybrid_metric_http_ua_prevalence_2stage.yl2`
* **How It Defeats the Blind Spot**: Operates a dual-plane match architecture. Stage 1 baselines the individual host's or user's daily HTTP query volume for a specific User-Agent token against their personal 30-day baseline (`principal.asset.hostname`, `network.http.user_agent`). Stage 2 counts the total number of enterprise fleet adopters for that token ($k_{\text{fleet}}$) and applies hyperbolic dampening:
  $$\text{Dampener} = \frac{1.0}{k_{\text{fleet}} + 1.0}, \quad Z_{\text{penalized}} = Z_{\text{personal}} \times \text{Dampener}$$
  If IT rolls out a new Edge update to 5,000 workstations ($k_{\text{fleet}} = 5000$), $Z_{\text{penalized}} \to 0$. If an attacker runs a customized Python exfiltration script on a single host ($k_{\text{fleet}} = 1$), the full anomaly score is preserved.

### Strategy B: Web Application / Proxy Error Ratio Surge
* **Target Metric**: `metrics.http_queries_fail`
* **Math Model & Template**: `templates/pipelines/http_error_ratio_surge_2stage.yl2`
* **How It Defeats the Blind Spot**: Fusing 30-day baseline expectations of HTTP failures ($4xx/5xx$) with in-stage error ratio calculation ($\text{Observed Failures} / \text{Observed Total}$). Detects abnormal spikes in web request failures caused by directory fuzzing, API brute-forcing, and broken C2 beacon loops even when total traffic volume remains low.

### Strategy C: Web Server & Cloud API Hammering (Target-Centric Surge)
* **Target Metric**: `metrics.http_queries_total`
* **Math Model & Template**: `templates/pipelines/http_target_surge_2stage.yl2`
* **How It Defeats the Blind Spot**: Instead of profiling the client, profiles the destination web server or API gateway (`target.hostname`). Identifies acute volumetric departures against the server's 30-day historical query baseline, exposing targeted denial-of-service, automated data scraping, or internal API enumeration.

### Strategy D: Part-of-the-Whole HTTP Multi-Level Triad
* **Target Metrics**: `http_queries_total`, `http_queries_success`, `http_queries_fail`
* **Math Model & Template**: `templates/pipelines/part_of_the_whole_triad_multilevel.yl2`
* **How It Defeats the Blind Spot**: Simultaneously evaluates Total, Success, and Fail web requests in an atomic triad. Separates high-volume legitimate web browsing (where Success and Total surge in tandem, with Error Ratio remaining near $0\%$) from malicious scanning or broken exfiltration channels (where Failures surge disproportionately against historical baseline).

### Strategy E: 360° Behavioral Radar Spoke (Web & Proxy Activity)
* **Target Metric**: `metrics.http_queries_total`
* **Math Model & Template**: `templates/pipelines/radar_360_sector_web_http.yl2`
* **How It Defeats the Blind Spot**: Feeds an independent, dedicated spoke in the 6-sector Euclidean Threat Fusion Radar ($D = \sqrt{\sum_{i=1}^6 \max(0, Z_i)^2}$). Prevents web exfiltration and proxy tunneling from hiding behind DNS or network flow totals, preserving distinct sector visibility.

---

## 3. Operational Triage SLA & Chronicle Pivot
When outliers are surfaced:
1. **User-Agent & Request URI**: Pivot to `network.http.user_agent`, `target.url`, and `network.http.method` in raw UDM search to inspect URI parameters and HTTP headers.
2. **Response Code Distribution**: Analyze `network.http.response_code` to differentiate authentication barriers ($401/403$), resource missing ($404$), or server errors ($500/502$).
3. **Target Reputation & Infrastructure**: Inspect `target.hostname` and `target.ip` against VirusTotal, Google Cloud Threat Intelligence (GCTI), and WHOIS domain creation age.
