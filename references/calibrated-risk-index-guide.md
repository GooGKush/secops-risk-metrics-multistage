# 🎚️ The Calibrated Risk Index (CRI) Reference Guide

The **Calibrated Risk Index (CRI)** is the standardized **[0–100] Threat Normalization Layer** for Google SecOps Multi-Stage Risk Analytics. It transforms raw statistical deviations ($Z$-scores, composite Euclidean distance norms $D$, and CUSUM drift scores $S^+$) into an intuitive, bounded, and cross-comparable threat scale.

---

## 1. ❓ Why CRI Exists: The Zero-Inflated Baseline Problem

In enterprise security telemetry, many high-risk behaviors (e.g. failed administrative logins, external DLP file shares, lateral Kerberos sweeps) are **Zero-Inflated**:
* 99% of days have exactly **0 occurrences** ($\mu = 0.0, \sigma = 0.0$).
* When a quiet user or machine suddenly generates 10 or 100 events, standard Gaussian normalization with $+0.1$ regularization produces extreme mathematical artifacts:
  $$Z = \frac{k - \mu}{\sigma + 0.1} = \frac{332 - 0}{0.1} = \mathbf{+3,320\sigma}$$
* While statistically accurate as an indicator of rarity, unbounded scores ranging from $-2.0$ to $+50,000$ create severe operational friction:
  1. **Cognitive Distortion**: Tier 1 SOC analysts struggle to prioritize a $+4.16\sigma$ auth surge against a $+3,320\sigma$ flow surge.
  2. **Cross-Sector Incomparability**: Network byte standard deviations cannot be directly combined with process execution counts without distortion.
  3. **UI Layout Breakage**: Unbounded floats break tabular dashboards and reporting scorecards.

**The Solution**: CRI maps all statistical indicators onto a monotonic, non-linear **[0–100] S-Curve**.

> [!IMPORTANT]
> **Post-Processing Transformation Layer (Never in YARA-L Queries)**:
> CRI is strictly a **post-query presentation and triage transformation** executed in Python reporting scripts (`scripts/radar_collector.py`), dashboards, and SOAR playbooks.
> - **YARA-L Responsibility**: Chronicle queries calculate raw statistical deviations ($Z$-score, $\text{MAD } Z$, Poisson $Z$, CUSUM drift, Euclidean distance norm $D^2$) and order results via `order: <score> desc`.
> - **Post-Processing Responsibility**: Python / reporting layers consume the raw $Z$-scores and apply the logistic sigmoid function to normalize scores into the [0–100] CRI range.
> - **Do NOT implement CRI in YARA-L**: Chronicle YARA-L does not support `math.exp()`, and computing non-linear sigmoid curves inside database queries is unnecessary and anti-idiomatic.

---

## 2. 🧮 Mathematical Formulation

The Calibrated Risk Index applies a logistic (Sigmoid) transformation calibrated to anchor the **3-Sigma Alertable Statistical Boundary ($Z = 3.0\sigma$) at exactly CRI = 50**:

$$\text{CRI}(Z) = \begin{cases} 
0 & \text{if } Z \le 0 \\
\text{round}\left( \frac{100}{1 + \exp\left(-\alpha \cdot (Z - Z_{\text{mid}})\right)} \right) & \text{if } Z > 0 
\end{cases}$$

### Calibration Parameters:
* **Inflection Point ($Z_{\text{mid}} = 3.0\sigma$)**: The statistical threshold for a "True Statistical Anomaly" (the 99.87th percentile tail under Gaussian assumptions).
* **Steepness Parameter ($\alpha = 0.6$)**: Calibrates the transition slope so that moderate drift ($Z = 2.0\sigma$) sits in the low 30s, while multi-sigma breakouts ($Z \ge 5.0\sigma$) enter high-severity tiers ($>75$).

---

## 3. 🎯 Calibration Values & Mapping Curve

| Raw $Z$-Score | Mathematical Derivation ($\frac{100}{1 + e^{-0.6(Z - 3.0)}}$) | CRI Score | Severity Tier | Visual Badge |
| :---: | :--- | :---: | :--- | :---: |
| $\le 0.0\sigma$ | $\frac{100}{1 + e^{1.8}} = \frac{100}{1 + 6.05} \to 0$ (clamped) | **0** | **Nominal** | 🟢 `[CRI: 0]` |
| $+1.0\sigma$ | $\frac{100}{1 + e^{1.2}} = \frac{100}{1 + 3.32} = 23.1$ | **23** | **Nominal** | 🟢 `[CRI: 23]` |
| $+1.5\sigma$ | $\frac{100}{1 + e^{0.9}} = \frac{100}{1 + 2.46} = 28.9$ | **29** | **Low Drift** | 🟡 `[CRI: 29]` |
| $+2.0\sigma$ | $\frac{100}{1 + e^{0.6}} = \frac{100}{1 + 1.82} = 35.4$ | **35** | **Low Drift** | 🟡 `[CRI: 35]` |
| $+2.5\sigma$ | $\frac{100}{1 + e^{0.3}} = \frac{100}{1 + 1.35} = 42.6$ | **43** | **Low Drift** | 🟡 `[CRI: 43]` |
| **$+3.0\sigma$** | $\frac{100}{1 + e^{0.0}} = \frac{100}{1 + 1.00} = 50.0$ | **50** | **Medium Outlier (Alertable Anchor)** | 🟠 `[CRI: 50]` |
| $+3.5\sigma$ | $\frac{100}{1 + e^{-0.3}} = \frac{100}{1 + 0.74} = 57.4$ | **57** | **Medium Outlier** | 🟠 `[CRI: 57]` |
| $+4.0\sigma$ | $\frac{100}{1 + e^{-0.6}} = \frac{100}{1 + 0.55} = 64.6$ | **65** | **Medium Outlier** | 🟠 `[CRI: 65]` |
| $+4.5\sigma$ | $\frac{100}{1 + e^{-0.9}} = \frac{100}{1 + 0.41} = 71.1$ | **71** | **High Threat** | 🔴 `[CRI: 71]` |
| $+5.0\sigma$ | $\frac{100}{1 + e^{-1.2}} = \frac{100}{1 + 0.30} = 76.9$ | **77** | **High Threat** | 🔴 `[CRI: 77]` |
| $+6.0\sigma$ | $\frac{100}{1 + e^{-1.8}} = \frac{100}{1 + 0.165} = 85.8$ | **86** | **High Threat** | 🔴 `[CRI: 86]` |
| $+7.0\sigma$ | $\frac{100}{1 + e^{-2.4}} = \frac{100}{1 + 0.091} = 91.7$ | **92** | **Critical Outlier** | 🚨 `[CRI: 92]` |
| $+10.0\sigma$| $\frac{100}{1 + e^{-4.2}} = \frac{100}{1 + 0.015} = 98.5$ | **99** | **Critical Outlier** | 🚨 `[CRI: 99]` |
| **$+3,320\sigma$**| $\frac{100}{1 + e^{-1990.2}} \approx 100.0$ | **100** | **Critical Outlier (Saturated Cap)** | 🚨 `[CRI: 100]` |

---

## 4. 🧭 How to Interpret CRI in SOC Operations

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        CRI OPERATIONAL TRIAGE ACTION TIERS                             │
│                                                                                        │
│  [ CRI: 0 – 25 ]   🟢 NOMINAL         • Expected day-to-day variance. Log only.        │
│  [ CRI: 26 – 45 ]  🟡 LOW DRIFT       • Minor elevation. Contextual review.            │
│  [ CRI: 46 – 69 ]  🟠 MEDIUM OUTLIER  • True Statistical Anomaly (Z >= 3.0σ). Triage.  │
│  [ CRI: 70 – 89 ]  🔴 HIGH THREAT     • Severe Multi-Sigma Breakout. Immediate SOC.    │
│  [ CRI: 90 – 100 ] 🚨 CRITICAL        • Extreme Surge or Zero-Baseline Breakout. Esc.  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Operational Guidance:
1. **Tier 1 (CRI 0–25) — Nominal Behavior**:
   * **Interpretation**: The observed activity is well within the entity baseline envelope or peer group norm.
   * **Action**: Suppress alert; no SOC investigation required.
2. **Tier 2 (CRI 26–45) — Low Drift / Early Warning**:
   * **Interpretation**: Moderate elevation above baseline ($1.5\sigma \le Z < 3.0\sigma$). Often represents normal operational spikes (e.g. end-of-quarter reporting, large downloads).
   * **Action**: Include in longitudinal CUSUM tracking; do not page analysts.
3. **Tier 3 (CRI 46–69) — Medium Outlier (Alertable)**:
   * **Interpretation**: **True Statistical Anomaly**. The probability that this activity occurred by random chance is $p < 0.0013$ ($Z \ge 3.0\sigma$).
   * **Action**: Create Tier 1 SOC investigation ticket. Cross-reference Active Directory peers and check for secondary tool execution.
4. **Tier 4 (CRI 70–89) — High Threat**:
   * **Interpretation**: Severe anomaly ($4.5\sigma \le Z < 7.0\sigma$). Strong multi-vector divergence from both personal history and direct peer group.
   * **Action**: Immediate analyst intervention. Inspect process execution lineage and network destinations.
5. **Tier 5 (CRI 90–100) — Critical Outlier**:
   * **Interpretation**: Massive breakout ($Z \ge 7.0\sigma$) or dormant zero-baseline awakening. The entity is exhibiting behavior completely alien to its historical profile.
   * **Action**: High-priority incident response escalation. Isolate host or suspend user credentials if paired with suspicious command-line artifacts.

---

## 5. 🔬 Dual-Indicator Reporting Standard

In all Multi-Stage Risk Analytics reports, always report the exact statistical metric alongside the normalized CRI badge:

```markdown
| Target Entity | Metric Dimension | Observed ($k$) | Baseline ($\mu$) | Raw Stat ($Z$) | Calibrated Risk Index | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `frank.kolzig` | Total Logins | 103 | 76.8 (IT Team) | $+4.16\sigma$ | 🟠 **CRI: 67** | **Medium Outlier** |
| `tim.smith` | Network Flows | 332 | 0.0 (Self 30d) | $+3,320\sigma$| 🚨 **CRI: 100**| **Critical Outlier** |
| `tim.smith_admin` | Network Flows | 13 | 18.4 (IT Team) | $-0.38\sigma$ | 🟢 **CRI: 0** | **Nominal** |
```
