# Consultative Deep-Dive: Cloud Infrastructure Tampering & Sabotage

## 1. The Deterministic Rule Failure Mode
Cloud security monitoring typically relies on signature-based alerts for known risky API calls:
* Example: `event_type = "RESOURCE_DELETION" and resource_type = "storage.bucket"`
* Example: `protoPayload.methodName = "v1.compute.instances.insert"`

**Why Attackers Slip Past**:
1. **Admin Baseline Saturation**: High-privilege engineers and CI/CD pipelines trigger hundreds of legitimate resource creations and updates daily, rendering static alerts too noisy to enable.
2. **Local-Baseline Isolation Failure**: A rule alerting on BigQuery read queries misses an attacker reading sensitive HR tables if the service account routinely reads marketing tables.
3. **Rapid Sabotage Timing**: Ransomware attackers in the cloud (such as those wiping backups or terminating production clusters) execute actions in minutes; static batch rules fire too late.

---

## 2. The Behavioral Antidotes

### Strategy A: Local-Baseline Isolation (Cloud Repository Scope)
* **Target Metric**: `metrics.resource_read_total` or `metrics.resource_written_total`
* **Pipeline Template**: `templates/pipelines/cloud_repository_scope_dual_branch.yl2`
* **How It Defeats the Blind Spot**: Enforces a 5-tuple baseline isolation match (`$sa, $vendor, $product, $resource, $ip by 1d`). Evaluates whether the account has *ever accessed this specific product and resource*, preventing high overall volume in one area from masking unauthorized access to another.

### Strategy B: Dormant Infrastructure Wakeup (Two-Part Hurdle Model)
* **Target Metric**: `metrics.resource_creation_total`
* **Math Model**: `two_part_hurdle.yl2`
* **How It Defeats the Blind Spot**: Catches compromised third-party vendor integrations or backup accounts that have been dormant for weeks suddenly provisioning compute or IAM roles.

### Strategy C: Explosive Deletion Penalty (Asymmetric Directional Z)
* **Target Metric**: `metrics.resource_deletion_total`
* **Math Model**: `asymmetric_directional_z.yl2`
* **How It Defeats the Blind Spot**: Specifically isolates mass resource teardown events ($Z > 3.0\sigma$) while completely suppressing alerts when deletion volume is zero or nominal.

---

## 3. Operational Triage SLA & Chronicle Pivot
When outliers are surfaced:
1. **Caller Identity Verification**: Verify `principal.user.userid` and whether the action originated from a human console session or an automated service account key.
2. **Resource Scope Analysis**: Check `target.resource.name` to identify whether core infrastructure, databases, or logging sinks were modified.
