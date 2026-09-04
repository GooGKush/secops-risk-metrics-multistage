# Google SecOps Pre-Submission Compiler Policy & Malachite YARA-L 2.0 Invariants

**Document Version:** 1.0.0  
**Status:** Mandatory Engineering Standard  
**Target Platform:** Google SecOps Chronicle SIEM (Malachite Query Engine)  
**Author:** Greg Kushmerek  

---

## 1. Executive Summary & Policy Mandate

This policy defines the mandatory verification gates and syntax invariants required for all YARA-L 2.0 multi-stage behavioral queries, templates, dynamic routers, and radar collectors prior to code submission, pull requests, or release.

> [!IMPORTANT]
> **The Zero-Compiler-Error Invariant**:  
> No query template, pipeline DAG, dynamic router permutation, or decoupled radar spoke may be submitted or merged without achieving a **100% pass rate** across both:
> 1. The offline AST & static invariant verification test suite (`scripts/submission_tests.py`).
> 2. Live compilation verification against the Google SecOps Chronicle SIEM API (`secops-gus:udm_search` or `validate_rule`).

---

## 2. Chronicle Malachite YARA-L 2.0 Compiler Invariants

Extensive live compilation testing against Google SecOps customer instances has identified the following hard architectural constraints enforced by the Chronicle Malachite compiler. Violations cause immediate `INVALID_ARGUMENT` or `INTERNAL` compilation crashes.

### 2.1 Join and Stage Cardinality Limits
* **Maximum Raw Event Extraction Stages**: In UDM Search mode, Chronicle enforces a hard ceiling of `maxJoinCount = 4`. A search query permits **at most 2 raw event extraction stages** (stages querying `metadata.event_type = ...`).
* **Multi-Sector Fusion Architecture**:
  * Combining 2 orthogonal sectors (e.g., Auth + Network) in a monolithic 3-stage query (`stage auth_sector`, `stage net_sector`, and root stage) is valid and fully supported (`PIPE-06-DUAL-SECTOR`).
  * Combining $\ge 3$ raw event sectors (e.g., Auth + Cloud + Process + Network) in a single monolithic query causes `INVALID_ARGUMENT: maxJoinCount exceeded`.
  * **Resolution**: High-order multi-sector analysis (such as the 5-sector 360° Risk Radar) MUST use the **Decoupled Micro-Query Architecture** (`scripts/radar_collector.py`), where individual sector queries execute in parallel and correlate in memory.

### 2.2 Aggregation and Mathematical Function Syntax
* **No `variance()` Aggregate**: YARA-L 2.0 does **not** support `variance(...)`. The compiler accepts only:
  `avg()`, `stddev()`, `min()`, `max()`, `sum()`, `count()`, `count_distinct()`.
  * To calculate variance across entities or stages, extract `stddev(...)` in the intermediate stage and square it in the outcome block:
    ```yara
    $fleet_sigma = max($fleet_hyperpriors.fleet_std)
    $fleet_sigma_sq = $fleet_sigma * $fleet_sigma
    ```
* **Strict Math Function Namespacing**:
  * Bare functions like `round(...)` are illegal. Must strictly use `math.round(...)`.
  * Transcendental functions like `math.exp(...)` are unsupported in the native query compiler. Non-linear conversions (such as sigmoid Calibrated Risk Index $\text{CRI}$) must be computed in client post-processing (`scripts/triage_formatter.py`).

### 2.3 Universal Dispersion Floor ($\sigma_{\text{floor}} = 1.0$)
* In all $Z$-score, Delta-$Z$, and ratio denominators, a constant floor of `+ 1.0` MUST be added:
  ```yara
  $z_score = $diff / ($stddev + 1.0)
  ```
* **Rationale**: On quiet accounts with zero variance ($\sigma = 0$), omitted dispersion floors trigger divide-by-zero exceptions or NaN evaluations in Chronicle.

### 2.4 Metric Schema Dimensions & Types
* Pre-computed behavioral metrics (`metrics.*`) require exact field dimensions:
  * `metrics.network_bytes_outbound`: Metric argument MUST be `metric: value_sum` (NOT `sent_bytes_sum`).
  * Vendor-scoped CRUD metrics (`resource_read_total`, `resource_written_total`, `resource_creation_total`, `resource_deletion_total`): MUST include `metadata.vendor_name: $v` and `metadata.product_name: $p` dimensions in the function call.

### 2.5 Stage Output & Variable Binding Contracts
* **Universal 6-Point Stage 1 Outcome Contract**: Every Stage 1 extractor must export:
  1. `$observed_val`
  2. `$historical_avg`
  3. `$historical_stddev`
  4. `$historical_active_days`
  5. `$historical_max`
  6. `$historical_sum`
* **Downstream Reference Integrity**: Any variable referenced as `$stage_name.variable` in a downstream stage or root outcome MUST be explicitly exported in `$stage_name`'s `outcome:` block. Undeclared references produce immediate compiler failure.
* **Stage Name Grammar**: Stage identifiers must NOT begin with `$`. Use `stage stage1_extract`, never `stage $stage1_extract`.
* **Outcome Variable Ceiling**: A single stage outcome block may define at most **20 outcome variables**.
* **Search Query Structure**: Multi-stage search queries must terminate with `order: <var> [desc|asc]`. They must **NEVER** contain a `condition:` block (which is reserved exclusively for detection rules).

### 2.6 Statistical Invariant & Antipattern Auditing (`scripts/statistical_validator.py`)
In addition to compiler syntax, all queries submitted to Chronicle must satisfy the 6 Statistical Invariants:
1. **Scope Symmetry (Zero Part-of-the-Whole Bias)**: Stages filtering observed events to specific products or attributes must bind the identical dimensions in `metrics.*` or decouple into 2-stage context fusion.
2. **Dynamic Range Isolation ("Elephant and Mouse" Prevention)**: Multi-resource data access must slice dynamically by `($user, $resource by 1d)` to evaluate local-baseline isolation and prevent high-volume routine traffic from masking acute targeted exfiltration.
3. **Universal Dispersion Flooring**: All outcome divisions by standard deviation ($\sigma$) or MAD must incorporate an additive scalar floor (`+ 1.0`) to prevent division by zero or NaN on quiet accounts.
4. **Distribution Domain Integrity**: Discrete count metrics (e.g. `auth_attempts_fail`) evaluated with continuous Gaussian Z-scores require active baseline days gating ($N \ge 3$) or Poisson rarity modeling.
5. **Orthogonal Sector Fusion**: Multi-sector Euclidean threat norms ($D = \sqrt{\sum Z_i^2}$) must fuse strictly independent behavioral vector families (Auth, Cloud CRUD, Workspace, Network, Endpoint), never collinear intra-family metrics.
6. **Cloud Service Account Identity Profiling**: When querying service account scope (binding `$sa` or `$service_account`), queries must enforce cloud identity construction (`/@.*gserviceaccount\.com$/` or `arn:aws:iam`) rather than relying on null checks (`$sa != ""`), preventing Windows Active Directory computer accounts (`HOST$`) and local OS services (`LOCAL SERVICE`) from polluting cloud repository analytics.

---

## 3. Pre-Submission Test Harness (`scripts/submission_tests.py`)

The submission test harness automates compiler verification across 21 canonical test cases categorized into four operational suites:

| ID | Suite | Target Metric / Model | Key Compiler Check |
|:---|:------|:----------------------|:-------------------|
| `PIPE-01-STD-Z` | Pipeline Template | `network_bytes_outbound` (Asset) | Standard 2-stage AST & metrics binding |
| `PIPE-02-POISSON` | Pipeline Template | `auth_attempts_fail` (User) | Discrete Poisson rarity & security filter |
| `PIPE-03-MAD` | Pipeline Template | `network_bytes_outbound` (Asset) | Robust MAD 0.6745 scaling syntax |
| `PIPE-04-CUSUM` | Pipeline Template | `network_bytes_outbound` (Asset) | Longitudinal cumulative sum drift |
| `PIPE-05-DELTA-Z` | Pipeline Template | `http_queries_total` (Asset) | Cross-sectional 3-stage Delta-Z fusion |
| `PIPE-06-DUAL-SECTOR` | Pipeline Template | Auth + Network Egress | Orthogonal 2-sector Euclidean norm |
| `PIPE-07-EMPIRICAL-BAYES` | Pipeline Template | `http_queries_total` (Asset) | 3-stage hyperprior shrinkage (stddev²) |
| `PIPE-08-CLOUD-SCOPE` | Pipeline Template | `resource_read_total` | Dual-branch cloud repository scope & origin outlier |
| `PIPE-09-PREVALENCE` | Pipeline Template | `network_bytes_outbound` + Entity Graph | 2-stage IP prevalence ($\le 3$) & egress volume |
| `RADAR-01-AUTH` | Decoupled Radar Spoke | `auth_attempts_fail` | Allowed vs failed login micro-query |
| `RADAR-02-CLOUD` | Decoupled Radar Spoke | `resource_creation_total` | Multi-dimensional cloud CRUD tracking |
| `RADAR-03-WORKSPACE` | Decoupled Radar Spoke | `google_workspace_downloads` | High-frequency document hoarding query |
| `RADAR-04-NETWORK` | Decoupled Radar Spoke | `network_bytes_outbound` | Web/Egress surge tracking (`value_sum`) |
| `ROUTER-01-POISSON` | Dynamic Router | `auth_attempts_fail` + Poisson | Automated variable harmonization |
| `ROUTER-02-STD-Z` | Dynamic Router | `network_bytes_outbound` + Z-Score | Entity-type binding (`asset.ip`) |
| `ROUTER-03-MAD` | Dynamic Router | `network_bytes_outbound` + MAD | Median & MAD denominator binding |
| `ROUTER-04-CV` | Dynamic Router | `dns_queries_total` + CV | Relative volatility quotient |
| `ROUTER-05-BAYES-GAMMA`| Dynamic Router | `http_queries_total` + Gamma | Prior shape ($\alpha$) & rate ($\beta$) outcomes |
| `ROUTER-06-BETA-BINOMIAL`| Dynamic Router| `auth_attempts_total` + Beta | Success/failure conjugate updates |
| `ROUTER-07-HOURLY-Z` | Dynamic Router | `file_executions_total` + Hourly | Temporal process launch variation |
| `ROUTER-08-FANO` | Dynamic Router | `auth_attempts_fail` + Fano | Variance-to-mean dispersion ratio |

---

## 4. Verification Workflow for Contributors

Before committing changes, contributors must execute the following test commands:

```bash
# 1. Run canonical submission test suite (Static verification of 20 test cases)
python3 scripts/submission_tests.py

# 2. Run all unit tests (including compiler policy assertions)
python3 -m unittest discover -s tests -p "test_*.py"

# 3. Verify SKILL.md token and line limits (Budget: <= 250 lines, <= 20,480 bytes)
wc -l SKILL.md
wc -c SKILL.md
```

All commands must exit with return code `0` and 100% pass rates.

---

## 5. Skill Architecture & Progressive-Load First Policy

To prevent context bloat, preserve LLM reasoning capacity, and strictly maintain the $\le 20.0$ KB (20,480 bytes) ceiling on `SKILL.md`, all contributors and AI agents must adhere to the **Progressive-Load First Policy**.

### 5.1 Three-Tier Information Architecture
Skill components are structured into three distinct tiers based on load timing and lifecycle:

1. **Tier 1: Core Orchestrator (`SKILL.md`)**
   * **Role**: Lean gatekeeper, conversational contract enforcer, and router.
   * **Content Allowed**: Trigger keywords, Phase 1A/1B discovery and gating contracts, tool embargoes, pre-output clearance requirements, the 6-pillar reporting schema, and high-level routing pointers.
   * **Hard Constraints**: $\le 250$ lines and $\le 20,480$ bytes (enforced by `test_skill_efficiency_and_clarity.py`).
   * **Threshold for Modification**: **Highest**. Never modify `SKILL.md` without first proving that the requirement cannot be fulfilled in Tier 2 or Tier 3.

2. **Tier 2: Progressive Reference Documentation (`references/*.md`)**
   * **Role**: On-demand domain encyclopedias, implementation guides, and analytical frameworks.
   * **Content Allowed**: Complete metric catalogs, mathematical proofs, operational SOC playbooks, deep AST compiler invariants, and threat actor behavioral mapping.
   * **Load Mechanism**: Read on-demand by the agent only when deep domain context is required, keeping the initial system prompt compact.

3. **Tier 3: Grounded Executables & Templates (`scripts/`, `templates/`)**
   * **Role**: Deterministic automation, validation, and reusable AST logic.
   * **Content Allowed**: Pre-flight parameter validators, AST builders, radar collectors, triage formatters, and `.yl2` query snippets.
   * **Load Mechanism**: Executed or inspected programmatically, consuming zero prompt tokens during conversational turns.

### 5.2 Mandatory Pre-Modification Decision Tree
Whenever an audit finding, user request, or feature proposal suggests adding guidance to this skill:

```
                      [New Directive / Guidance Proposed]
                                       │
                                       ▼
             Does it alter a Turn-1 conversational gate or tool embargo?
                                ├─── YES ──► Does it require new wording in SKILL.md?
                                │             ├─── NO ──► Offload detail to references/
                                │             └─── YES ─► Add minimal pointer in SKILL.md
                                │                         AND offload equivalent prose
                                │                         to references/ to keep size safe
                                │
                                └─── NO ───► DIRECTIVE: DO NOT TOUCH SKILL.md
                                              │
                                              ├── Deterministic / programmatic? ──► scripts/
                                              ├── Reusable query syntax?       ──► templates/
                                              └── Explanatory / specification?  ──► references/
```

### 5.3 Progressive-Load Enforcement Checklist
Before submitting any pull request or updating this skill package:
- [ ] Confirmed that all new specifications, catalog entries, and playbooks are housed in `references/`.
- [ ] Confirmed that deterministic parameter checks and validations are codified in `scripts/`.
- [ ] Confirmed that `SKILL.md` was only edited if an essential top-level conversational invariant changed.
- [ ] Verified `python3 -m unittest tests/test_skill_efficiency_and_clarity.py` passes with zero budget violations.
