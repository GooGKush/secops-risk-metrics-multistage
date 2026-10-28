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
> **Post-Processing Transformation Layer**:
> CRI is a **post-query presentation and triage transformation** executed in Python reporting scripts (`scripts/radar_collector.py`, `scripts/triage_formatter.py`), dashboards, and SOAR playbooks.
> - **YARA-L Responsibility**: Chronicle queries calculate raw statistical deviations ($Z$-score, $\text{MAD } Z$, Poisson $Z$, CUSUM drift, Euclidean distance norm $D^2$) and order results via `order: <score> desc`.
> - **Post-Processing Responsibility**: Python / reporting layers consume the raw $Z$-scores and apply the logistic sigmoid function to normalize scores into the [0–100] CRI range.
> - **Syntax Note (`math.pow` vs `math.exp`)**: The literal identifier `math.exp()` does not exist in Chronicle YARA-L (base-$e$ exponentiation in YARA-L is written `math.pow(2.718281828, $x)`). Because CRI is a monotonic transformation of the underlying score, YARA-L orders directly by the raw statistical score and leaves sigmoid CRI formatting to the post-processing layer.

---

## 2. 🧮 Mathematical Formulation

The Calibrated Risk Index applies a logistic (Sigmoid) transformation calibrated to anchor the **3-Sigma Alertable Statistical Boundary ($Z = 3.0\sigma$) at exactly CRI = 50**:

$$
\text{CRI}(Z) = \begin{cases}
0 & \text{if } Z \le 0 \\
\text{round}\left( \frac{100}{1 + \exp\left(-\alpha \cdot (Z - Z_{\text{mid}})\right)} \right) & \text{if } Z > 0
\end{cases}
$$

### Calibration Parameters:
* **Inflection Point ($Z_{\text{mid}} = 3.0\sigma$)**: The statistical threshold for a "True Statistical Anomaly" (the 99.87th percentile tail under Gaussian assumptions).
* **Steepness Parameter ($\alpha = 0.6$)**: Calibrates the transition slope so that moderate drift ($Z = 2.0\sigma$) sits in the low 30s, while multi-sigma breakouts ($Z \ge 5.0\sigma$) enter high-severity tiers ($>75$).

---

## 3. 🎯 Calibration Values & Mapping Curve

| Raw $Z$-Score | Mathematical Derivation ($\frac{100}{1 + e^{-0.6(Z - 3.0)}}$) | CRI Score | Severity Tier | Visual Badge |
| :---: | :--- | :---: | :--- | :---: |
| $\le 0.0\sigma$ | $\frac{100}{1 + e^{1.8}} = \frac{100}{1 + 6.05} = 14.2 \to 0$ (zero-floor for $Z \le 0$) | **0** | **Nominal** | 🟢 `[CRI: 0]` |
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
1. **Tier 1 (CRI 0–25) — Nominal Behavior ($Z < 1.2\sigma$; $\text{CRI} = 0$ for $Z \le 0$)**:
   * **Interpretation**: The observed activity is at or below baseline ($\text{CRI} = 0$) or within ordinary day-to-day fluctuation ($0 < Z < 1.2\sigma$).
   * **Action**: Suppress alert; no SOC investigation required.
2. **Tier 2 (CRI 26–45) — Low Drift / Early Warning ($1.2\sigma \le Z < 2.7\sigma$)**:
   * **Interpretation**: Moderate elevation above baseline. Often represents normal operational variance (e.g. end-of-quarter reporting, bulk transfers).
   * **Action**: Include in longitudinal CUSUM tracking; do not page analysts.
3. **Tier 3 (CRI 46–69) — Medium Outlier (Alertable, $2.7\sigma \le Z < 4.4\sigma$, with $3.0\sigma \mapsto \text{CRI } 50$)**:
   * **Interpretation**: **True Statistical Anomaly** centered on the $Z = 3.0\sigma$ ($\text{CRI} = 50$) alertable anchor.
   * **Action**: Create Tier 1 SOC investigation ticket. Cross-reference Active Directory peers and check for secondary tool execution.
4. **Tier 4 (CRI 70–89) — High Threat ($4.4\sigma \le Z < 6.7\sigma$)**:
   * **Interpretation**: Severe multi-sigma anomaly. Strong divergence from both personal history and direct peer group.
   * **Action**: Immediate analyst intervention. Inspect process execution lineage and network destinations.
5. **Tier 5 (CRI 90–100) — Critical Outlier ($Z \ge 6.7\sigma$)**:
   * **Interpretation**: Massive breakout or dormant zero-baseline awakening. The entity is exhibiting behavior completely alien to its historical profile.
   * **Action**: High-priority incident response escalation. Isolate host or suspend user credentials if paired with suspicious command-line artifacts.

> **In-Query Discrete Step Ladder (`templates/stage2_math_models/piecewise_cri.yl2`)**: When a query computes a discrete step-function approximation directly inside YARA-L (`$cri_score`), it maps the same 5 operational tiers onto representative midpoint scores: `95` (`CRITICAL`, $Z \ge 6.0$), `85` (`HIGH`, $4.5 \le Z < 6.0$), `65` (`MEDIUM`, $3.0 \le Z < 4.5$), `40` (`LOW`, $2.0 \le Z < 3.0$), `15` (`INFORMATIONAL`, $0.0 < Z < 2.0$), and `0` (`NOMINAL`, $Z \le 0.0$).

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
