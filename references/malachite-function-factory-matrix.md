# Malachite Function Factory Compiler Reference Matrix

**Skill:** `secops-risk-metrics-multistage`  
**Target:** Google SecOps Malachite Common Compiler (YARA-L 2.0 / Stats Search)

---

## 1. Overview & Compiler Governance

The Chronicle Malachite Common Compiler features a rich standard library ("Function Factory") of built-in scalar, mathematical, and window aggregation functions. Understanding the strict section boundaries (`events:` vs `outcome:`) and type signatures is essential for writing high-performance, valid multi-stage queries.

---

## 2. Function Support & Section Validity Matrix

| Function Namespace | Function Signature | Valid in `events:` | Valid in `outcome:` | Notes / Invariants |
| :--- | :--- | :---: | :---: | :--- |
| **`math.sqrt`** | `math.sqrt(number)` | ❌ | ✅ | Computes $\sqrt{x}$. Bare `sqrt()` is strictly rejected. |
| **`math.pow`** | `math.pow(base, exp)` | ❌ | ✅ | Native exponentiation ($x^y$), including base-$e$ exponentials via `math.pow(2.718281828, $x)` (use instead of `math.exp()`, which is not a valid function name). Replaces manual `$stddev * $stddev`. `^` operator is invalid. |
| **`math.abs`** | `math.abs(number)` | ❌ | ✅ | Computes absolute value $\|x\|$. Useful for symmetric distance and deviations. |
| **`math.log`** | `math.log(number)` | ❌ | ✅ | Computes natural logarithm $\ln(x)$. Requires $x > 0$. |
| **`math.floor`** | `math.floor(number)` | ❌ | ✅ | Floor function $\lfloor x \rfloor$. |
| **`math.ceil`** | `math.ceil(number)` | ❌ | ✅ | Ceiling function $\lceil x \rceil$. |
| **`math.round`** | `math.round(number, [scale])` | ❌ | ✅ | 1-arg rounds to integer; 2-arg rounds to specified decimal scale (e.g. `math.round($z, 2)`). |
| **`math.geo_distance`** | `math.geo_distance(lon1, lat1, lon2, lat2)` | ✅ | ✅ | Computes geodesic distance in meters between coordinate pairs. |
| **`math.exp / min / max`** | *(Unsupported)* | ❌ | ❌ | `math.exp()`, `math.min()`, and `math.max()` are **not** supported in Chronicle YARA-L 2.0. Use `math.pow(2.718281828, $x)` for $e^x$ and `if($a >= $b, $a, $b)` for pairwise max/min. |
| **`window.variance`**| `window.variance(event_field)` | ❌ | ✅ | Computes sample variance across matched window events. Bare `variance()` is rejected. |
| **`window.median`**  | `window.median(expr, bool)` | ❌ | ✅ | Computes empirical median ($P_{50}$). Pass `false` for `should_ignore_zero_values` so zero deviations are retained. |
| **`window.percentile`** | `window.percentile(expr, P)` | ❌ | ✅ | Computes empirical $P$-th percentile ($P \in [0, 100]$) across matched window events or stage rows in a single stage (`$p10, $q25, $q50, $q75, $p90`). |
| **`cast.as_int`** | `cast.as_int(number\|string)` | ✅ | ✅ | Casts numeric float or string timestamp to integer (e.g. `cast.as_int(ts / 86400)`). |
| **`cast.as_float`** | `cast.as_float(string)` | ✅ | ✅ | Parses string representation into float. Expects type `string` (fails if passed `int`). |
| **`re.regex`** | `re.regex(field, pattern)` | ✅ | ❌ | Regular expression match in `events:`. (`regex.match()` does not exist.) |
| **`arrays.max/min`**| `arrays.max(array)` | ❌ | ❌ (Literals) | Literal array notation `[...]` in `outcome:` causes compiler syntax error. |

---

## 3. Section Boundary Constraints

### A. The `events:` Section
* **Allowed**:
  * Scalar function evaluations bound to fields or scalar expressions:
    ```yara
    $day_id = cast.as_int(metadata.event_timestamp.seconds / 86400)
    ```
  * String & regex functions: `strings.to_lower()`, `strings.concat()`, `re.regex()`.
  * Spatial functions: `math.geo_distance()`.
* **Prohibited**:
  * Top-level binary arithmetic in placeholder assignments (`$x = $a - $b`, `$x = a / 86400`) above `match:` fails compilation (whereas scalar arithmetic nested inside a function call argument such as `$day_id = cast.as_int(metadata.event_timestamp.seconds / 86400)` compiles). Perform placeholder arithmetic in `outcome:`.
  * Aggregation functions (`count`, `max`, `sum`, `avg`, `window.variance`).

### B. The `outcome:` Section
* **Allowed**:
  * Full variable-to-variable arithmetic, subtraction, multiplication, and division.
  * Native Function Factory mathematical operations (`math.pow`, `math.sqrt`, `math.abs`, `math.log`, `math.floor`, `math.ceil`, `math.round`).
  * Window aggregations (`window.variance(field)`, `count(id)`, `sum(bytes)`).
  * Conditional assignments: `if(condition, then_val, else_val)`.
* **Prohibited**:
  * **Literal Array Notation**: `arrays.max([0.0, $val])` or any `[...]` literal syntax in `outcome:` fails compiler parsing.
  * **Compound Arithmetic in `if()` Branches**: Both the `then` and `else` clauses of `if(cond, then_val, else_val)` must be plain `$placeholder` variables, fields, or constants. Expressions like `if(cond, $a - $b, 0)` or `if(cond, 0, $a - $b)` fail compilation; bind `$diff = $a - $b` first and write `if(cond, $diff, 0)`.
  * **Unaggregated Event Attributes in Match Windows**: When a match window is declared (`by 1d`), all raw event attributes in `outcome:` must use an aggregation function (`max()`, `min()`, `array_distinct()`, `count()`).

---

## 4. The Data-Anchored Time Spine Standard

### Wall-Clock Time Drift Anti-Pattern
Using `timestamp.current_seconds()` inside historical baseline search queries or multi-stage DAGs introduces **wall-clock execution drift**:
* The query outcome changes depending on the exact second the query is executed.
* Historical retrohunts and test replays fail because `now - event_time` expands indefinitely into the past.

### The Canonical Event-Anchored Standard
1. **Extract Event Timestamp in Stage 1**:
   <!-- yara-fragment: illustrative stage 1 event timestamp extraction -->
   ```yara
   stage stage1_extract {
     metadata.event_type = "USER_LOGIN"
     $user = principal.user.userid
     match:
       $user by 1d
     outcome:
       $event_timestamp = max(metadata.event_timestamp.seconds)
   }
   ```
2. **Anchor Downstream Calculations to Observed Telemetry**:
   ```yara
   // Root Stage
   outcome:
     $obs_ts = max($stage1_extract.event_timestamp)
     $first_seen = min($stage2_graph.first_seen_ts)
     $asset_age_days = ($obs_ts - $first_seen) / 86400.0
   ```
3. **Daily Binned Spine (Active Dashboard Standard)**:
   ```yara
   $day_id = cast.as_int(metadata.event_timestamp.seconds / 86400)
   ```
   Downstream:
   ```yara
   $max_day = max($day_id)
   $delta_days = $max_day - $day_id
   ```
This guarantees 100% deterministic, reproducible scoring across live streaming, historical backtests, and regression CI harnesses.

---

## 5. Non-Parametric Quantiles, Bowley Skewness & The 1-Stage Stage-Budget Advantage (`window.percentile`)

### A. Why 1-Stage `window.percentile` Saves a Stage Over 2-Stage `MAD`
True Median Absolute Deviation (`MAD = median(|x - median(x)|)`) requires **two consecutive intermediate stages** (`mad_center` $\to$ `mad_spread`) because YARA-L 2.0 cannot nest a window aggregation inside another window aggregation in the same stage. Consequently, `mad_robust_z_4stage.yl2` consumes all **4 stages** (`stage1_extract` $\to$ `mad_center` $\to$ `mad_spread` $\to$ `root`).

By contrast, `window.percentile(expr, P)` computes all five order statistics ($P_{10}, Q_{25}, Q_{50}, Q_{75}, P_{90}$) in a **single intermediate stage** (`stage quantile_envelope`), completing the pipeline in **3 stages** (`quantile_iqr_skew_3stage.yl2`). That saves **1 full stage and 1 stage-to-stage join**, freeing Stage 3 to attach an Entity Context Graph lookup (`DERIVED_CONTEXT` / `GLOBAL_CONTEXT`) or a peer-cohort normalization stage!

### B. Canonical Non-Parametric Quantile & Skewness Formulations
Given `$p10`, `$q25`, `$q50`, `$q75`, `$p90` from `stage quantile_envelope`:
1. **Interquartile Range (IQR) & Flat-History Floor**:
   $$\text{IQR} = Q_{75} - Q_{25}, \quad \text{IQR}_{\text{safe}} = \max(\text{IQR}, 0.05 \cdot Q_{50} + 1.0)$$
2. **Bowley Quartile Skewness ($B_{\text{skew}} \in [-1, +1]$)**:
   $$B_{\text{skew}} = \frac{Q_{75} + Q_{25} - 2 Q_{50}}{\text{IQR}_{\text{safe}}}$$
   * $B_{\text{skew}} \approx 0$: Symmetric baseline.
   * $B_{\text{skew}} > +0.25$: Right-skewed baseline (historic bulk jobs inflate the upper quartile and distort parametric $\mu, \sigma$).
3. **Moors Interdecile-to-Interquartile Tail-Heaviness Ratio ($T_{\text{ratio}}$)**:
   $$T_{\text{ratio}} = \frac{P_{90} - P_{10}}{\text{IQR}_{\text{safe}}}$$
   * For a Gaussian baseline, $T_{\text{ratio}} \approx 1.90$. Values $T_{\text{ratio}} > 2.5$ prove heavy-tailed baseline distortion where parametric $Z$-scores suffer from masking.
4. **Hubert–Vandervieren Skewness-Adjusted Tukey Upper Fence**:
   $$\text{UpperFence}_{\text{adj}} = Q_{75} + 1.5 \cdot e^{3 \cdot \max(0, B_{\text{skew}})} \cdot \text{IQR}_{\text{safe}}$$
   $$\text{Tukey Fence Ratio} = \frac{x_{\text{observed}}}{\max(\text{UpperFence}_{\text{adj}}, 1.0)}$$
