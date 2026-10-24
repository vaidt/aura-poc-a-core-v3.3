from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import unittest
from pathlib import Path

from conformance.boundary.ri_py_receiver import (
    AdapterIdentity,
    BoundaryReceiver,
    EnvironmentIdentity,
    FixtureIdentity,
    ReceiverIdentity,
    consume_receipt_json as parse_receipt_json,
    serialize_receipt,
)
from conformance.boundary.strict_wire import ReceiptWireError

CORPUS_PATH = Path(__file__).resolve().parents[1] / "STAGE-C-C6-BC02.1-WIRE-MUTATIONS-v0.1.json"


def apply_mutation(base: str, case: dict) -> bytes:
    kind = case["kind"]
    if kind == "replace":
        find = case["find"]
        count = base.count(find)
        if count != 1:
            raise AssertionError(f"{case['id']}: expected one replacement target, got {count}")
        return base.replace(find, case["replace"], 1).encode("utf-8")
    if kind == "literal":
        return case["wire"].encode("utf-8")
    if kind == "hex":
        return bytes.fromhex(case["wire_hex"])
    raise AssertionError(f"{case['id']}: unsupported mutation kind {kind!r}")


class PinnedRIPyStrictWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus_bytes = CORPUS_PATH.read_bytes()
        cls.corpus = json.loads(cls.corpus_bytes)
        if cls.corpus["schema"] != "AURA-STAGE-C6-BC02.1-WIRE-MUTATION-CORPUS/0.1":
            raise AssertionError("unexpected C6 shared corpus schema")
        cls.base = cls.corpus["valid_receipt_json"]

    def test_accepts_shared_valid_receipt_and_preserves_raw_octets(self):
        parsed = parse_receipt_json(self.base.encode("utf-8"))
        self.assertEqual(parsed.raw_octets.hex(), self.corpus["raw_octets_hex"])

    def test_receiver_generated_receipt_round_trips_with_pinned_provenance(self):
        source_commit = os.environ.get("AURA_SOURCE_COMMIT", "")
        self.assertRegex(source_commit, re.compile(r"^[0-9a-f]{40}$"), "CI must bind source_commit to the tested Git SHA")
        raw_octets = bytes.fromhex(self.corpus["raw_octets_hex"])
        receiver = BoundaryReceiver(
            ReceiverIdentity(
                receiver_id="RI-PY-C6",
                implementation_id="AURA-RI-PY",
                implementation_version="1.0.0",
                source_commit=source_commit,
            ),
            AdapterIdentity(adapter_id="BC02.2-PY-ADAPTER", adapter_version="1.0.0"),
            EnvironmentIdentity(
                environment_id="C6-CI-LINUX",
                platform="ubuntu-latest",
                runtime=f"CPython {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            ),
        )
        receipt = receiver.receive(
            FixtureIdentity(
                fixture_id="FIX-C6-RECEIVER-FLOW",
                fixture_artifact_identity="issued-fixture:FIX-C6-RECEIVER-FLOW",
            ),
            method="local-octet-transfer",
            octets=raw_octets,
        )
        wire = serialize_receipt(receipt)
        parsed = parse_receipt_json(wire)

        self.assertEqual(parsed.raw_octets, raw_octets)
        self.assertEqual(parsed.value["receiver"]["source_commit"], source_commit)
        self.assertEqual(parsed.value["receiver"]["receiver_id"], "RI-PY-C6")
        self.assertEqual(parsed.value["receiver"]["implementation_id"], "AURA-RI-PY")
        self.assertNotEqual(parsed.value["receiver"]["receiver_id"], parsed.value["receiver"]["implementation_id"])
        self.assertEqual(parsed.value["adapter"]["adapter_id"], "BC02.2-PY-ADAPTER")
        self.assertEqual(parsed.value["environment"]["environment_id"], "C6-CI-LINUX")
        self.assertEqual(parsed.value["received"]["recomputed_sha256"], hashlib.sha256(raw_octets).hexdigest())
        print(f"C6_RI_PY_SOURCE_COMMIT={source_commit}")

    def test_rejects_every_shared_mutation(self):
        for case in self.corpus["mutations"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(case["expected"], "REJECT", "unexpected non-negative corpus disposition")
                candidate = apply_mutation(self.base, case)
                with self.assertRaises(ReceiptWireError, msg=case["id"]):
                    parse_receipt_json(candidate)

    def test_corpus_hash_is_stable_and_recordable(self):
        digest = hashlib.sha256(self.corpus_bytes).hexdigest()
        print(f"C6_SHARED_CORPUS_SHA256={digest}")
        self.assertEqual(self.corpus["contract"], "BC-02.1-COMMON-RECEIPT")
        self.assertEqual(len(self.corpus["mutations"]), 18)


if __name__ == "__main__":
    unittest.main(verbosity=2)
