"""Direct Chronicle ImportEvents ingestion for Clean Hand-Off synthetic UDM events.

The MCP `import_events` tool is intermittently absent from client tool lists for
reasons unrelated to tenant IAM (see ingestion_tools.yaml -- the tool is
commented out pending an ADK schema-parsing fix). This module provides the
direct REST path to the same RPC so the skill's ingestion capability does not
depend on MCP surface availability.

Verified against google3:
  * RPC      google.cloud.chronicle.v1alpha.IngestionService.ImportEvents
  * HTTP     POST /{version}/{parent=projects/*/locations/*/instances/*}/events:import
             body: "*"                      (v1main/ingestion.proto:74-77)
  * Request  ImportEventsRequest{parent, inline_source{events}}
                                            (v1main/ingestion.proto:178-200)
  * Event    message Event { backstory.UDM udm = 2; }
                                            (v1main/event.proto:373-387)
  * Perm     chronicle.googleapis.com/events.import
  * Deadline 120s                           (v1main/ingestion.proto:73)

Neither `forwarderId` nor `logType` exists on this method. Events land stamped
`metadata.log_type = "UDM"`, bypassing parsing entirely.

IAM is the deploying environment's responsibility. This module surfaces auth
failures verbatim rather than attempting to resolve them.

Sanctioned under the Post-Search Execution Exemption
(references/chart-specifications-guide.md section B): invoked only after
`udm_search` has returned verified results and the analyst has cleared the
Pre-Ingestion Clearance Card. It is never invoked during an active hunt.
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Chronicle rejects the entire batch if any single event is malformed, so these
# are checked locally before the request is built.
# Note: id is server-assigned (bytes id = 15) and must not be supplied by client.
REQUIRED_METADATA_FIELDS = (
    ("event_timestamp", "eventTimestamp"),
    ("event_type", "eventType"),
    ("vendor_name", "vendorName"),
    ("product_name", "productName"),
)

# ImportEvents is restricted to v1alpha, v1beta, v1 (ingestion.proto:71).
SUPPORTED_API_VERSIONS = ("v1alpha", "v1beta", "v1")

DEFAULT_API_VERSION = "v1alpha"
DEFAULT_TIMEOUT_SECONDS = 120  # matches the RPC deadline

# Fields that exist on ImportLogs but NOT on ImportEvents. Their presence means
# the caller assembled the wrong method's arguments.
WRONG_METHOD_FIELDS = ("forwarderId", "forwarder_id", "logType", "log_type")


class IngestionError(RuntimeError):
  """Raised when the ingestion request cannot be built or is rejected."""


def build_parent(project_id: str, region: str, customer_id: str) -> str:
  """Builds the ImportEventsRequest.parent resource name."""
  return (f"projects/{project_id}/locations/{region}"
          f"/instances/{customer_id}")


def build_import_events_url(
    project_id: str,
    region: str,
    customer_id: str,
    api_version: str = DEFAULT_API_VERSION,
) -> str:
  """Builds the regional REST endpoint for ImportEvents."""
  if api_version not in SUPPORTED_API_VERSIONS:
    raise IngestionError(
        f"Unsupported API version {api_version!r}. "
        f"ImportEvents is restricted to {', '.join(SUPPORTED_API_VERSIONS)}.")
  parent = build_parent(project_id, region, customer_id)
  return (f"https://{region}-chronicle.googleapis.com"
          f"/{api_version}/{parent}/events:import")


def validate_events(udm_events: Sequence[Dict[str, Any]]) -> List[str]:
  """Returns a list of validation errors; empty means the batch is sendable.

  Chronicle rejects the whole request if one event is invalid, so a local
  pre-check converts an opaque 400 into an actionable per-event message.
  """
  errors: List[str] = []
  if not udm_events:
    errors.append("udm_events is empty; ImportEvents requires at least one event.")
    return errors

  for i, event in enumerate(udm_events):
    if not isinstance(event, dict):
      errors.append(f"event[{i}]: expected a UDM object, got {type(event).__name__}")
      continue

    for wrong in WRONG_METHOD_FIELDS:
      if wrong in event:
        errors.append(
            f"event[{i}]: {wrong!r} does not exist on ImportEvents -- this field "
            "belongs to ImportLogs. The wrong ingestion method was selected.")

    metadata = event.get("metadata")
    if not isinstance(metadata, dict):
      errors.append(f"event[{i}]: missing required 'metadata' object")
      continue
    for field_aliases in REQUIRED_METADATA_FIELDS:
      if not any(metadata.get(f) for f in field_aliases):
        errors.append(f"event[{i}]: missing required 'metadata.{field_aliases[0]}'")

  return errors


def build_import_events_body(
    udm_events: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
  """Wraps UDM events in the ImportEventsRequest inline source.

  `parent` is bound in the URL path, so the body carries only the source.
  """
  return {"inlineSource": {"events": [{"udm": e} for e in udm_events]}}


def resolve_access_token(explicit: Optional[str] = None) -> str:
  """Resolves an OAuth bearer token.

  Order: explicit argument, then CHRONICLE_ACCESS_TOKEN, then gcloud ADC.
  IAM provisioning belongs to the deploying environment; this only locates a
  credential that the environment has already granted.
  """
  if explicit:
    return explicit
  env_token = os.environ.get("CHRONICLE_ACCESS_TOKEN")
  if env_token:
    return env_token.strip()
  try:
    result = subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        capture_output=True, text=True, check=True, timeout=30,
    )
  except FileNotFoundError as exc:
    raise IngestionError(
        "No credential available: CHRONICLE_ACCESS_TOKEN is unset and gcloud "
        "is not on PATH.") from exc
  except subprocess.CalledProcessError as exc:
    raise IngestionError(
        f"gcloud auth print-access-token failed: {exc.stderr.strip()}") from exc
  except subprocess.TimeoutExpired as exc:
    raise IngestionError("gcloud auth print-access-token timed out.") from exc
  return result.stdout.strip()


def format_request_preview(
    url: str,
    body: Dict[str, Any],
    event_count: int,
) -> str:
  """Renders the exact request for the Pre-Ingestion Clearance Card.

  Shows the analyst what will be sent without sending it, and doubles as the
  copyable payload artifact when no credential is available.
  """
  lines = [
      "### 📤 DIRECT CHRONICLE IMPORTEVENTS REQUEST (PREVIEW)",
      "",
      f"* **Method**: `POST` `IngestionService.ImportEvents`",
      f"* **Endpoint**: `{url}`",
      f"* **Events in batch**: {event_count}",
      "* **Forwarder / Log Type**: none — not fields on this method.",
      "",
      "```json",
      json.dumps(body, indent=2),
      "```",
  ]
  return "\n".join(lines)


def import_events(
    udm_events: Sequence[Dict[str, Any]],
    project_id: str,
    region: str,
    customer_id: str,
    access_token: Optional[str] = None,
    api_version: str = DEFAULT_API_VERSION,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> Tuple[int, str]:
  """POSTs a UDM event batch to Chronicle. Returns (http_status, body).

  Raises IngestionError on local validation failure or transport failure.
  A successful ImportEvents returns HTTP 200 with an empty JSON object.
  """
  errors = validate_events(udm_events)
  if errors:
    raise IngestionError(
        "Refusing to send an invalid batch (Chronicle rejects the entire "
        "request if any event is malformed):\n  - " + "\n  - ".join(errors))

  url = build_import_events_url(project_id, region, customer_id, api_version)
  payload = json.dumps(build_import_events_body(udm_events)).encode("utf-8")
  request = urllib.request.Request(
      url,
      data=payload,
      method="POST",
      headers={
          "Authorization": f"Bearer {resolve_access_token(access_token)}",
          "Content-Type": "application/json",
      },
  )

  try:
    with urllib.request.urlopen(request, timeout=timeout) as response:
      return response.status, response.read().decode("utf-8")
  except urllib.error.HTTPError as exc:
    detail = exc.read().decode("utf-8", errors="replace")
    if exc.code in (401, 403):
      raise IngestionError(_explain_auth_failure(exc.code, detail)) from exc
    raise IngestionError(f"HTTP {exc.code} from Chronicle:\n{detail}") from exc
  except urllib.error.URLError as exc:
    raise IngestionError(f"Could not reach {url}: {exc.reason}") from exc


def _extract_error_reason(detail: str) -> str:
  """Pulls google.rpc.ErrorInfo.reason out of a Chronicle error body."""
  try:
    for item in json.loads(detail).get("error", {}).get("details", []):
      if item.get("reason"):
        return item["reason"]
  except (ValueError, AttributeError):
    pass
  return ""


def _explain_auth_failure(code: int, detail: str) -> str:
  """Turns a 401/403 into the specific remedy, which differs by cause.

  A wrong *type* of credential and a missing *permission* both surface as 401,
  but one is fixed by swapping the token source and the other by granting IAM.
  """
  reason = _extract_error_reason(detail)
  if reason == "ACCESS_TOKEN_TYPE_UNSUPPORTED":
    head = (
        f"HTTP {code}: the endpoint resolved and Chronicle identified the "
        "method, but rejected the credential TYPE. This is not a missing "
        "permission. End-user tokens (`gcloud auth print-access-token`) are "
        "refused here; supply a service-account credential via "
        "CHRONICLE_ACCESS_TOKEN. Credential provisioning belongs to the "
        "deploying environment, not to this skill.")
  elif code == 403:
    head = (
        f"HTTP {code}: the credential was accepted but lacks "
        "'chronicle.googleapis.com/events.import' on the target instance. "
        "Grant the permission in the deploying environment.")
  else:
    head = (
        f"HTTP {code} from Chronicle. The credential was not accepted. "
        "Verify CHRONICLE_ACCESS_TOKEN is set to a valid, unexpired token for "
        "an identity holding 'chronicle.googleapis.com/events.import'.")
  return f"{head}\n{detail}"


def _load_events(path: str) -> List[Dict[str, Any]]:
  """Loads a UDM event or batch from JSON, accepting several shapes."""
  with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

  if isinstance(data, dict):
    # A single bare UDM event, or one already wrapped as {"udm": {...}}.
    return [data["udm"]] if "udm" in data else [data]
  if isinstance(data, list):
    # A Clean Hand-Off batch: [{"udm": {...}}, ...] or [{...}, ...].
    return [e["udm"] if isinstance(e, dict) and "udm" in e else e for e in data]
  raise IngestionError(f"{path}: expected a JSON object or array.")


def main(argv: Optional[Sequence[str]] = None) -> int:
  parser = argparse.ArgumentParser(
      description="Ingest Clean Hand-Off synthetic UDM events via ImportEvents.")
  parser.add_argument("--events-file", required=True,
                      help="Path to the UDM event or batch JSON.")
  parser.add_argument("--project-id", required=True)
  parser.add_argument("--customer-id", required=True)
  parser.add_argument("--region", default="us")
  parser.add_argument("--api-version", default=DEFAULT_API_VERSION,
                      choices=SUPPORTED_API_VERSIONS)
  parser.add_argument("--dry-run", action="store_true",
                      help="Render the request for the clearance card; send nothing.")
  args = parser.parse_args(argv)

  try:
    events = _load_events(args.events_file)
    errors = validate_events(events)
    if errors:
      print("VALIDATION FAILED:", file=sys.stderr)
      for e in errors:
        print(f"  - {e}", file=sys.stderr)
      return 2

    url = build_import_events_url(
        args.project_id, args.region, args.customer_id, args.api_version)

    if args.dry_run:
      print(format_request_preview(url, build_import_events_body(events), len(events)))
      return 0

    status, body = import_events(
        events, args.project_id, args.region, args.customer_id,
        api_version=args.api_version)
  except IngestionError as exc:
    print(f"INGESTION FAILED: {exc}", file=sys.stderr)
    return 1

  print(f"INGESTED {len(events)} event(s) — HTTP {status}")
  if body.strip() not in ("", "{}"):
    print(body)
  return 0


if __name__ == "__main__":
  sys.exit(main())
