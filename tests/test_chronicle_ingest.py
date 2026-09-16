"""Tests for the direct Chronicle ImportEvents ingestion path.

These pin the request shape against the google3 proto contract. A drift in the
URL, the body envelope, or the wrong-method guard would silently send an
unacceptable request, and Chronicle rejects an entire batch if any one event is
malformed -- so local validation has to be exact.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.chronicle_ingest import (
    DEFAULT_API_VERSION,
    SUPPORTED_API_VERSIONS,
    IngestionError,
    _explain_auth_failure,
    _extract_error_reason,
    _load_events,
    build_import_events_body,
    build_import_events_url,
    build_parent,
    format_request_preview,
    validate_events,
)

PROJECT = "gus-sdl"
CUSTOMER = "8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5"
REGION = "us"


def _valid_event(**overrides):
  event = {
      "metadata": {
          "id": "evt-1",
          "eventTimestamp": "2026-09-12T00:00:00Z",
          "eventType": "GENERIC_EVENT",
          "vendorName": "Google SecOps",
          "productName": "SecOps Risk Metrics Hunter",
      },
      "principal": {"user": {"userid": "frank.kolzig"}},
  }
  event.update(overrides)
  return event


class TestRequestConstruction(unittest.TestCase):

  def test_parent_matches_proto_resource_pattern(self):
    """parent must match projects/*/locations/*/instances/* (ingestion.proto:75)."""
    self.assertEqual(
        build_parent(PROJECT, REGION, CUSTOMER),
        f"projects/{PROJECT}/locations/{REGION}/instances/{CUSTOMER}")

  def test_url_is_regional_and_ends_in_events_import(self):
    url = build_import_events_url(PROJECT, REGION, CUSTOMER)
    self.assertEqual(
        url,
        f"https://us-chronicle.googleapis.com/{DEFAULT_API_VERSION}"
        f"/projects/{PROJECT}/locations/{REGION}/instances/{CUSTOMER}"
        "/events:import")
    # Verified live: this URL resolves and Chronicle names the method in its
    # error metadata, so the binding is correct even without a credential.
    self.assertTrue(url.endswith("/events:import"))

  def test_all_declared_api_versions_are_accepted(self):
    """ImportEvents is restricted to v1alpha, v1beta, v1 (ingestion.proto:71)."""
    for version in SUPPORTED_API_VERSIONS:
      self.assertIn(f"/{version}/",
                    build_import_events_url(PROJECT, REGION, CUSTOMER, version))

  def test_unsupported_api_version_is_rejected(self):
    with self.assertRaises(IngestionError):
      build_import_events_url(PROJECT, REGION, CUSTOMER, "v2")

  def test_body_wraps_each_event_in_the_udm_field(self):
    """Event carries UDM in field `udm` (event.proto:373-387)."""
    body = build_import_events_body([_valid_event(), _valid_event()])
    self.assertEqual(list(body), ["inlineSource"])
    self.assertEqual(len(body["inlineSource"]["events"]), 2)
    for wrapped in body["inlineSource"]["events"]:
      self.assertEqual(list(wrapped), ["udm"])

  def test_body_omits_parent_because_it_is_path_bound(self):
    """The http rule binds parent in the URL, so it must not appear in the body."""
    body = build_import_events_body([_valid_event()])
    self.assertNotIn("parent", body)
    self.assertNotIn("parent", json.dumps(body))


class TestValidation(unittest.TestCase):

  def test_valid_event_produces_no_errors(self):
    self.assertEqual(validate_events([_valid_event()]), [])

  def test_empty_batch_is_rejected(self):
    self.assertTrue(validate_events([]))

  def test_each_required_metadata_field_is_enforced(self):
    for field in ("eventTimestamp", "eventType", "vendorName", "productName"):
      event = _valid_event()
      del event["metadata"][field]
      errors = validate_events([event])
      self.assertTrue(errors, f"missing metadata.{field} was not caught")

  def test_missing_metadata_object_is_caught(self):
    self.assertTrue(validate_events([{"principal": {}}]))

  def test_forwarder_and_log_type_are_rejected_as_wrong_method(self):
    """Neither field exists on ImportEvents; their presence means ImportLogs args."""
    for wrong in ("forwarderId", "forwarder_id", "logType", "log_type"):
      errors = validate_events([_valid_event(**{wrong: "x"})])
      self.assertTrue(errors, f"{wrong} was not rejected")
      self.assertIn("ImportLogs", " ".join(errors))

  def test_error_names_the_offending_event_index(self):
    """Chronicle rejects the whole batch, so the bad event must be identifiable."""
    errors = validate_events([_valid_event(), {"metadata": {}}])
    self.assertIn("event[1]", " ".join(errors))
    self.assertNotIn("event[0]", " ".join(errors))


class TestEventLoading(unittest.TestCase):

  def _write(self, payload):
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(payload, handle)
    handle.close()
    self.addCleanup(os.unlink, handle.name)
    return handle.name

  def test_accepts_a_bare_single_event(self):
    self.assertEqual(len(_load_events(self._write(_valid_event()))), 1)

  def test_accepts_a_single_wrapped_event(self):
    events = _load_events(self._write({"udm": _valid_event()}))
    self.assertEqual(events[0]["metadata"]["id"], "evt-1")

  def test_accepts_a_clean_handoff_wrapped_batch(self):
    """The batch standard is [{"udm": {...}}, ...]."""
    events = _load_events(self._write([{"udm": _valid_event()}, {"udm": _valid_event()}]))
    self.assertEqual(len(events), 2)
    self.assertEqual(validate_events(events), [])

  def test_accepts_a_bare_batch(self):
    events = _load_events(self._write([_valid_event(), _valid_event()]))
    self.assertEqual(validate_events(events), [])


class TestAuthDiagnosis(unittest.TestCase):

  # Verbatim from the live probe against gus-sdl.
  LIVE_401 = json.dumps({
      "error": {
          "code": 401,
          "status": "UNAUTHENTICATED",
          "details": [
              {"@type": "type.googleapis.com/google.rpc.DebugInfo",
               "detail": "The account was restricted due to a domain admin's policies."},
              {"@type": "type.googleapis.com/google.rpc.ErrorInfo",
               "reason": "ACCESS_TOKEN_TYPE_UNSUPPORTED",
               "metadata": {
                   "method": "google.cloud.chronicle.v1alpha.IngestionService.ImportEvents"}},
          ],
      }
  })

  def test_reason_is_extracted_from_structured_details(self):
    self.assertEqual(_extract_error_reason(self.LIVE_401),
                     "ACCESS_TOKEN_TYPE_UNSUPPORTED")

  def test_malformed_body_does_not_raise(self):
    self.assertEqual(_extract_error_reason("not json"), "")
    self.assertEqual(_extract_error_reason("[]"), "")

  def test_token_type_rejection_is_not_reported_as_missing_permission(self):
    """The two causes have different remedies and must not be conflated."""
    message = _explain_auth_failure(401, self.LIVE_401)
    self.assertIn("credential TYPE", message)
    self.assertIn("not a missing permission", message)
    self.assertIn("CHRONICLE_ACCESS_TOKEN", message)

  def test_403_is_reported_as_a_missing_permission(self):
    message = _explain_auth_failure(403, "{}")
    self.assertIn("events.import", message)


class TestClearanceCardPreview(unittest.TestCase):

  def test_preview_shows_endpoint_and_disclaims_forwarder(self):
    body = build_import_events_body([_valid_event()])
    url = build_import_events_url(PROJECT, REGION, CUSTOMER)
    preview = format_request_preview(url, body, 1)
    self.assertIn(url, preview)
    self.assertIn("IngestionService.ImportEvents", preview)
    self.assertIn("Forwarder / Log Type", preview)
    self.assertIn("none", preview)

  def test_preview_embeds_the_literal_payload(self):
    """The analyst must see what will actually be sent, not a summary."""
    body = build_import_events_body([_valid_event()])
    preview = format_request_preview("https://x/events:import", body, 1)
    self.assertIn("frank.kolzig", preview)
    self.assertIn("inlineSource", preview)


if __name__ == "__main__":
  unittest.main()
