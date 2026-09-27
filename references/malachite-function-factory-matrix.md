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
| **`math.pow`** | `math.pow(base, exp)` | ❌ | ✅ | Native exponentiation ($x^y$). Replaces manual `$stddev * $stddev`. `^` operator is invalid. |
| **`math.abs`** | `math.abs(number)` | ❌ | ✅ | Computes absolute value $\|x\|$. Useful for symmetric distance and deviations. |
| **`math.log`** | `math.log(number)` | ❌ | ✅ | Computes natural logarithm $\ln(x)$. Requires $x > 0$. |
| **`math.floor`** | `math.floor(number)` | ❌ | ✅ | Floor function $\lfloor x \rfloor$. |
| **`math.ceil`** | `math.ceil(number)` | ❌ | ✅ | Ceiling function $\lceil x \rceil$. |
| **`math.round`** | `math.round(number, [scale])` | ❌ | ✅ | 1-arg rounds to integer; 2-arg rounds to specified decimal scale (e.g. `math.round($z, 2)`). |
| **`window.variance`**| `window.variance(event_field)` | ❌ | ✅ | Computes sample variance across matched window events. Bare `variance()` is rejected. |
| **`cast.as_int`** | `cast.as_int(number\|string)` | ✅ | ✅ | Casts numeric float or string timestamp to integer (e.g. `cast.as_int(ts / 86400)`). |
| **`cast.as_float`** | `cast.as_float(string)` | ✅ | ✅ | Parses string representation into float. Expects type `string` (fails if passed `int`). |
| **`arrays.max/min`**| `arrays.max(array)` | ❌ | ❌ (Literals) | Literal array notation `[...]` in `outcome:` causes compiler syntax error. |

---

## 3. Section Boundary Constraints

### A. The `events:` Section
* **Allowed**:
  * Scalar function evaluations bound to fields or scalar expressions:
    ```yara
    $day_id = cast.as_int(metadata.event_timestamp.seconds / 86400)
    ```
  * String functions: `strings.to_lower()`, `strings.concat()`, `regex.match()`.
  * Spatial functions: `math.geo_distance()`.
* **Prohibited**:
  * Binary variable-to-variable arithmetic (`$a - $b`, `$a / $b`) above `match:`. All placeholder arithmetic must occur in `outcome:`.
  * Aggregation functions (`count`, `max`, `sum`, `avg`, `window.variance`).

### B. The `outcome:` Section
* **Allowed**:
  * Full variable-to-variable arithmetic, subtraction, multiplication, and division.
  * Native Function Factory mathematical operations (`math.pow`, `math.sqrt`, `math.abs`, `math.log`, `math.floor`, `math.ceil`, `math.round`).
  * Window aggregations (`window.variance(field)`, `count(id)`, `sum(bytes)`).
  * Conditional assignments: `if(condition, then_val, else_val)`.
* **Prohibited**:
  * **Literal Array Notation**: `arrays.max([0.0, $val])` or any `[...]` literal syntax in `outcome:` fails compiler parsing.
  * **Compound Arithmetic in `then` Clause**: `if(cond, $a - $b, 0)` is invalid; must compute `$diff = $a - $b` and use `if(cond, $diff, 0)`.
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
