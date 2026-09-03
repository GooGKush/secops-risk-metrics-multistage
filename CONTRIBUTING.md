# Contributing to SecOps Multi-Stage Risk Metrics Threat Hunter

Contributions to this skill package are highly welcome! Whether you are adding new behavioral metric extractors, mathematical models, or detection contracts, please adhere to the following guidelines.

---

## 🛠️ Contribution Workflow

1. **Stage 1 Extractor Templates (`templates/stage1_extractors/*.yl2`)**:
   * Must strictly adhere to the **Universal 6-Point Stage 1 Outcome Contract**:
     * `$observed_val`
     * `$historical_avg`
     * `$historical_stddev`
     * `$historical_active_days`
     * `$historical_max`
     * `$historical_sum`
   * Must enforce non-empty entity filters (e.g. `$host != ""`, `$user != ""`).
   * Must preserve 100% of fleet population without premature threat filtering.

2. **Stage 2+ Mathematical Models (`templates/stage2_math_models/*.yl2`)**:
   * Must apply the **Universal Dispersion Floor ($\sigma_{\text{floor}} = 1.0$)** in all $Z$-score denominators to prevent division-by-zero on quiet accounts:
     `$z_score = $diff / ($stddev + 1.0)`
   * Must maintain clean mathematical bounds and support Calibrated Risk Index ($\text{CRI} \in [0, 100]$) mapping.

3. **Multi-Stage DAG Pipelines (`templates/pipelines/*.yl2`)**:
   * Must isolate orthogonal event domains into dedicated stages before root-stage vector fusion to prevent Cartesian product joins.

4. **Reference Documentation (`references/*.md`)**:
   * Detail the mathematical derivations, cyber analogies, and operational threat translations for any new models added.

---

## 🧪 Testing & Validation Standards

Every contribution must strictly adhere to the **[Pre-Submission Compiler Policy](references/compiler-submission-policy.md)** and pass all automated verification suites before code submission or pull requests:

```bash
# 1. Run canonical submission test suite (19 pipeline, router, and radar cases)
python3 scripts/submission_tests.py

# 2. Run all unit tests (including compiler policy assertions)
python3 -m unittest discover -s tests -p "test_*.py"

# 3. Verify SKILL.md token and line budget (<= 250 lines, <= 20,480 bytes)
wc -l SKILL.md
wc -c SKILL.md
```

### Mandatory Quality & Compiler Gates:
* **Zero-Compiler-Error Policy**: All generated queries across pipeline templates, radar spokes, and dynamic router permutations must achieve a 100% pass rate against Malachite YARA-L 2.0 compiler invariants (`scripts/submission_tests.py`).
* **Unit Test Assertions**: Add corresponding syntax and parameter binding assertions in `tests/test_submission_compiler_policy.py`, `tests/test_complex_multistage_syntax.py`, or `tests/test_guardrail_contracts.py`.
* **Universal Dispersion Floor**: All $Z$-score denominators must enforce `($stddev + 1.0)`.
* **Universal 6-Point Contract**: All Stage 1 extractors must export the standard 6 outcome metrics.
* **Skill Budget Compliance**: `SKILL.md` must strictly remain within its budget of $\le 250$ lines and $\le 20,480$ bytes.

---

## 📜 License & Author Attribution

By contributing to this repository, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
