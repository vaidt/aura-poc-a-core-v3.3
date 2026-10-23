from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from conformance.boundary.strict_wire import parse_receipt_json, ReceiptWireError

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
