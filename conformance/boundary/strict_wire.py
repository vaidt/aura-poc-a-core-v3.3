"""Strict BC-02.1 JSON receipt consumer (C6 experiment only).

This is a wire-envelope parser, not a protocol conformance engine. It rejects
duplicate keys, unknown keys, authority-bearing fields, nulls, non-canonical
integer forms/types and malformed Base64. Raw artifact octets remain opaque.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

SCHEMA_ID = "BC-02.1-COMMON-RECEIPT"
SCHEMA_VERSION = 1
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_KEYS = {
    "conformance_result", "conformance", "acceptance_state",
    "expected_acceptance", "digest_output_state", "expected_digest_output",
    "result", "verdict", "outcome", "pass", "fail",
}
TOP = {"schema_id", "schema_version", "fixture", "handoff", "received",
       "receiver", "adapter", "environment"}
FIELDS = {
    "fixture": {"fixture_id", "fixture_artifact_identity"},
    "handoff": {"status", "method"},
    "received": {"octet_length", "raw_octets", "recomputed_sha256"},
    "receiver": {"receiver_id", "implementation_id", "language",
                 "implementation_version", "source_commit"},
    "adapter": {"adapter_id", "adapter_version"},
    "environment": {"environment_id", "platform", "runtime"},
}
STATUSES = {"TRANSFERRED", "NOT_TRANSFERRED", "ERROR"}


class ReceiptWireError(ValueError):
    """Rejected BC-02.1 receipt transport; not a conformance result."""


@dataclass(frozen=True)
class ParsedReceipt:
    value: dict[str, Any]
    raw_octets: bytes


def _pairs_no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ReceiptWireError(f"duplicate-key:{key}")
        out[key] = value
    return out


def _reject_constant(value):
    raise ReceiptWireError(f"non-json-constant:{value}")


def _walk(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() in FORBIDDEN_KEYS:
                raise ReceiptWireError(f"forbidden-authority-key:{key}")
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)
    else:
        yield node


def parse_receipt_json(payload: bytes) -> ParsedReceipt:
    """Consume a complete BC-02.1 JSON envelope under the strict wire contract."""
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise ReceiptWireError("receipt-envelope-must-be-bytes")
    try:
        text = bytes(payload).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReceiptWireError("receipt-envelope-invalid-utf8") from exc
    try:
        value = json.loads(text, object_pairs_hook=_pairs_no_duplicates,
                           parse_constant=_reject_constant)
    except ReceiptWireError:
        raise
    except (json.JSONDecodeError, UnicodeError, TypeError, ValueError) as exc:
        raise ReceiptWireError("receipt-envelope-malformed-json") from exc
    if not isinstance(value, dict):
        raise ReceiptWireError("top-level-must-be-object")
    if set(value) != TOP:
        missing, extra = sorted(TOP - set(value)), sorted(set(value) - TOP)
        raise ReceiptWireError(f"top-level-field-set:missing={missing}:extra={extra}")
    if value["schema_id"] != SCHEMA_ID or type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise ReceiptWireError("schema-identity-or-version")
    for parent, names in FIELDS.items():
        child = value[parent]
        if not isinstance(child, dict):
            raise ReceiptWireError(f"{parent}-must-be-object")
        if set(child) != names:
            missing, extra = sorted(names - set(child)), sorted(set(child) - names)
            raise ReceiptWireError(f"{parent}-field-set:missing={missing}:extra={extra}")
    if any(v is None for v in _walk(value)):
        raise ReceiptWireError("null-prohibited")
    for parent, names in FIELDS.items():
        for name in names:
            if parent == "received" and name == "octet_length":
                continue
            if not isinstance(value[parent][name], str):
                raise ReceiptWireError(f"type:{parent}.{name}:string-required")
            if not value[parent][name]:
                raise ReceiptWireError(f"empty:{parent}.{name}")
    status = value["handoff"]["status"]
    if status not in STATUSES:
        raise ReceiptWireError("handoff-status-outside-closed-domain")
    length = value["received"]["octet_length"]
    if type(length) is not int or length < 0:
        raise ReceiptWireError("octet-length-must-be-nonnegative-integer")
    encoded = value["received"]["raw_octets"]
    try:
        encoded_bytes = encoded.encode("ascii")
        raw = base64.b64decode(encoded_bytes, validate=True)
    except (UnicodeEncodeError, ValueError, TypeError) as exc:
        raise ReceiptWireError("raw-octets-invalid-base64") from exc
    # Require canonical padded RFC 4648 standard alphabet encoding.
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise ReceiptWireError("raw-octets-noncanonical-base64")
    if len(raw) != length:
        raise ReceiptWireError("octet-length-mismatch")
    digest = value["received"]["recomputed_sha256"]
    if not HEX_SHA256.fullmatch(digest):
        raise ReceiptWireError("digest-format")
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ReceiptWireError("digest-mismatch")
    return ParsedReceipt(value=value, raw_octets=raw)
