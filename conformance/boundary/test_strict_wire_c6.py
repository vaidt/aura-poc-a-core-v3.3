from __future__ import annotations
import base64, hashlib, json, unittest
from conformance.boundary.strict_wire import parse_receipt_json, ReceiptWireError

RAW=b"C6\x00\xfe\xff"
def good():
    return {"schema_id":"BC-02.1-COMMON-RECEIPT","schema_version":1,
      "fixture":{"fixture_id":"FIX-C6","fixture_artifact_identity":"fixture.bin"},
      "handoff":{"status":"TRANSFERRED","method":"local"},
      "received":{"octet_length":len(RAW),"raw_octets":base64.b64encode(RAW).decode(),
        "recomputed_sha256":hashlib.sha256(RAW).hexdigest()},
      "receiver":{"receiver_id":"RI-PY","implementation_id":"impl","language":"Python","implementation_version":"1","source_commit":"abc"},
      "adapter":{"adapter_id":"adapter","adapter_version":"1"},
      "environment":{"environment_id":"env","platform":"linux","runtime":"python"}}
def wire(v): return json.dumps(v,separators=(",",":"),ensure_ascii=False).encode()

class PinnedRIPyStrictWireTests(unittest.TestCase):
    def test_accepts_valid_and_preserves_opaque_octets(self):
        got=parse_receipt_json(wire(good()))
        self.assertEqual(got.raw_octets,RAW)
    def test_rejects_shared_negative_cases(self):
        base=good()
        cases=[]
        v=json.loads(json.dumps(base)); v["conformance_result"]="PASS"; cases.append(v)
        v=json.loads(json.dumps(base)); v["received"]["extension"]="x"; cases.append(v)
        v=json.loads(json.dumps(base)); v["handoff"]["status"]="PASS"; cases.append(v)
        v=json.loads(json.dumps(base)); v["received"]["octet_length"]=True; cases.append(v)
        v=json.loads(json.dumps(base)); v["received"]["octet_length"]=len(RAW)-1; cases.append(v)
        v=json.loads(json.dumps(base)); v["received"]["recomputed_sha256"]="0"*64; cases.append(v)
        v=json.loads(json.dumps(base)); v["received"]["raw_octets"]="%%%"; cases.append(v)
        for i,v in enumerate(cases):
            with self.subTest(case=i), self.assertRaises(ReceiptWireError): parse_receipt_json(wire(v))
    def test_rejects_duplicate_top_and_nested_keys(self):
        base=wire(good()).decode()
        for raw in (base.replace('"schema_id":"BC-02.1-COMMON-RECEIPT"','"schema_id":"bad","schema_id":"BC-02.1-COMMON-RECEIPT"'),
                    base.replace('"method":"local"','"method":"local","method":"other"')):
            with self.assertRaises(ReceiptWireError): parse_receipt_json(raw.encode())
    def test_rejects_bad_envelope_but_not_bad_octets(self):
        for raw in (b'\xff',b'{'):
            with self.assertRaises(ReceiptWireError): parse_receipt_json(raw)
        self.assertEqual(parse_receipt_json(wire(good())).raw_octets,RAW)

if __name__ == "__main__": unittest.main(verbosity=2)
