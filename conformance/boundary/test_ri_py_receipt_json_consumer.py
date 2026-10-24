"""Strict BC-02.1 wire-consumer contract tests (synthetic receipt only)."""
import base64
import hashlib
import json
import unittest

from conformance.boundary.ri_py_receiver import (
    AdapterIdentity, BoundaryReceiver, EnvironmentIdentity, FixtureIdentity,
    HandoffStatus, ReceiverIdentity, ReceiptParseError, parse_receipt_json,
    serialize_receipt,
)

OCTETS = b"BC-02.1\x00\xfe\xff"


def wire():
    receipt = BoundaryReceiver(
        ReceiverIdentity("RI-PY", "aura-ri-py", "1.0.0", "c6-test-commit"),
        AdapterIdentity("c6-adapter", "1.0.0"),
        EnvironmentIdentity("c6-env", "linux", "python"),
    ).receive(FixtureIdentity("FIX-C6-SYNTHETIC", "synthetic.bin"), "in-memory", OCTETS)
    return serialize_receipt(receipt)


class StrictReceiptConsumerTests(unittest.TestCase):
    def assert_code(self, payload, code):
        with self.assertRaises(ReceiptParseError) as ctx:
            parse_receipt_json(payload)
        self.assertEqual(ctx.exception.code, code)

    def test_roundtrip_base64_and_raw_octets(self):
        parsed = parse_receipt_json(wire())
        self.assertEqual(parsed.received.raw_octets, OCTETS)
        self.assertEqual(parsed.received.octet_length, len(OCTETS))
        self.assertEqual(parsed.received.recomputed_sha256, hashlib.sha256(OCTETS).hexdigest())
        self.assertEqual(parsed.handoff.status, HandoffStatus.TRANSFERRED)

    def test_empty_raw_octets_are_valid_and_use_empty_base64(self):
        receipt = BoundaryReceiver(
            ReceiverIdentity("RI-PY", "aura-ri-py", "1.0.0", "c6-test-commit"),
            AdapterIdentity("c6-adapter", "1.0.0"),
            EnvironmentIdentity("c6-env", "linux", "python"),
        ).receive(FixtureIdentity("FIX-C6-EMPTY", "empty.bin"), "in-memory", b"")
        parsed = parse_receipt_json(serialize_receipt(receipt))
        self.assertEqual(parsed.received.raw_octets, b"")
        self.assertEqual(parsed.received.octet_length, 0)

    def test_requires_bytes_not_mapping(self):
        self.assert_code({"schema_id": "x"}, "TYPE_MISMATCH")

    def test_rejects_invalid_utf8_receipt_envelope(self):
        self.assert_code(b'{"schema_id":"\xff"}', "INVALID_UTF8")

    def test_rejects_malformed_json(self):
        self.assert_code(b'{"schema_id":', "INVALID_JSON")

    def test_rejects_duplicate_keys_at_any_depth(self):
        p = wire().decode()
        p = p.replace('"schema_id":"BC-02.1-COMMON-RECEIPT"', '"schema_id":"BC-02.1-COMMON-RECEIPT","schema_id":"BC-02.1-COMMON-RECEIPT"', 1)
        self.assert_code(p.encode(), "DUPLICATE_KEY")
        p = wire().decode().replace('"status":"TRANSFERRED"', '"status":"TRANSFERRED","status":"TRANSFERRED"', 1)
        self.assert_code(p.encode(), "DUPLICATE_KEY")

    def test_rejects_unknown_and_authority_fields_top_and_nested(self):
        d = json.loads(wire())
        d["conformance_result"] = "PASS"
        self.assert_code(json.dumps(d).encode(), "UNKNOWN_FIELD")
        d = json.loads(wire())
        d["received"]["unknown"] = "x"
        self.assert_code(json.dumps(d).encode(), "UNKNOWN_FIELD")

    def test_rejects_missing_and_null_fields(self):
        d = json.loads(wire())
        del d["receiver"]
        self.assert_code(json.dumps(d).encode(), "MISSING_FIELD")
        d = json.loads(wire())
        d["adapter"]["adapter_id"] = None
        self.assert_code(json.dumps(d).encode(), "NULL_NOT_ALLOWED")

    def test_rejects_bad_status_schema_and_types(self):
        d = json.loads(wire()); d["handoff"]["status"] = "PASS"
        self.assert_code(json.dumps(d).encode(), "INVALID_VALUE")
        d = json.loads(wire()); d["schema_id"] = "wrong"
        self.assert_code(json.dumps(d).encode(), "SCHEMA_ID_MISMATCH")
        d = json.loads(wire()); d["schema_version"] = True
        self.assert_code(json.dumps(d).encode(), "TYPE_MISMATCH")
        d = json.loads(wire()); d["received"]["octet_length"] = 1.5
        self.assert_code(json.dumps(d).encode(), "TYPE_MISMATCH")
        d = json.loads(wire()); d["received"]["octet_length"] = True
        self.assert_code(json.dumps(d).encode(), "TYPE_MISMATCH")
        d = json.loads(wire()); d["received"]["octet_length"] = -1
        self.assert_code(json.dumps(d).encode(), "INVALID_VALUE")


    def test_rejects_prohibited_result_values_in_semantic_fields(self):
        d = json.loads(wire()); d["fixture"]["fixture_id"] = "PASS"
        self.assert_code(json.dumps(d).encode(), "INVALID_VALUE")
        d = json.loads(wire()); d["environment"]["platform"] = "CONFORMANT"
        self.assert_code(json.dumps(d).encode(), "INVALID_VALUE")

    def test_rejects_aliased_receiver_implementation_and_adapter_identities(self):
        d = json.loads(wire()); d["receiver"]["implementation_id"] = d["receiver"]["receiver_id"]
        self.assert_code(json.dumps(d).encode(), "INVALID_VALUE")
        d = json.loads(wire()); d["adapter"]["adapter_id"] = d["receiver"]["implementation_id"]
        self.assert_code(json.dumps(d).encode(), "INVALID_VALUE")

    def test_rejects_base64_length_and_digest_mutations(self):
        d = json.loads(wire()); d["received"]["raw_octets"] = "a@@="
        self.assert_code(json.dumps(d).encode(), "INVALID_BASE64")
        d = json.loads(wire()); d["received"]["raw_octets"] = base64.b64encode(OCTETS).decode()
        d["received"]["octet_length"] += 1
        self.assert_code(json.dumps(d).encode(), "LENGTH_MISMATCH")
        d = json.loads(wire()); d["received"]["recomputed_sha256"] = "0" * 64
        self.assert_code(json.dumps(d).encode(), "DIGEST_MISMATCH")


if __name__ == "__main__":
    unittest.main()
