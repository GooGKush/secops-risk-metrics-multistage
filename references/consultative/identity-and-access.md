# Consultative Deep-Dive: Identity, Credential Abuse & Privilege Drift

## 1. The Deterministic Rule Failure Mode
Traditional authentication alerting centers around account lockout rules:
* Example: `count(failed_logins) > 5 in 10m`
* Example: `user_login where location != "United States"`

**Why Attackers Slip Past**:
1. **Low-and-Slow Spraying**: Attackers spread authentication attempts across hundreds of accounts over days, attempting 1 password every 4 hours to avoid lockouts.
2. **Dormant Credential Resurrections**: A compromised service account or ex-employee identity that has been silent for 90 days suddenly logs in. A single login attempt does not violate any static frequency rule.
3. **Internal Spraying**: Legitimate SSO/IdP authentication logs mask unauthorized attempts on internal service endpoints.

---

## 2. The Behavioral Antidotes

### Strategy A: Discrete Rarity Profiling (Beta-Binomial Bayesian)
* **Target Metric**: `metrics.auth_attempts_fail`
* **Math Model**: `beta_binomial_bayesian.yl2`
* **How It Defeats the Blind Spot**: Models the ratio of failed logins to total attempts as a probability distribution. If an account historically succeeds 99.8% of the time, even 3 failures distributed across a day become statistically alarming, whereas a service account that naturally fails 15% of the time is not flagged.

### Strategy B: Dormancy Transition Modeling (Two-Part Hurdle Model)
* **Target Metric**: `metrics.auth_attempts_success` or `metrics.workspace_auth_attempts_total`
* **Math Model**: `two_part_hurdle.yl2`
* **How It Defeats the Blind Spot**: Decomposes the anomaly into two distinct stages: Stage 1 evaluates the binary transition ($0 	o \ge 1$ active days), immediately alerting on previously silent accounts without requiring high volume; Stage 2 scores volume intensity only if the account is normally active.

### Strategy C: Volatility Shift (Asymmetric Directional Z)
* **Target Metric**: `metrics.auth_attempts_total`
* **Math Model**: `asymmetric_directional_z.yl2`
* **How It Defeats the Blind Spot**: Applies an asymmetric ReLU function ($\max(0, Z)$) that focuses analytical attention exclusively on upward surges while ignoring drops in volume (such as weekends or vacations) that corrupt symmetrical baselines.

---

## 3. Operational Triage SLA & Chronicle Pivot
When outliers are surfaced:
1. **Source IP & ASN Discrepancy**: Review `principal.ip` and autonomous system numbers to check for residential proxies or VPS providers (DigitalOcean, Linode).
2. **User-Agent Fingerprinting**: Compare `network.http.user_agent` strings between the anomalous session and the user's historical 30-day baseline.
