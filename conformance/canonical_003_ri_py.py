"""CANONICAL-003 diagnostic execution against the current AURA Core serializer.

This is an executable engineering test, not a normative protocol decision.
It checks whether the currently implemented Core JSON serialization path already
produces RFC 8785 JCS bytes. It does not add or silently substitute a JCS adapter.

Current path under test: core/merkle.py::MerkleAttestor.generate_leaf, which
currently hashes json.dumps(data, sort_keys=True).encode() using Python defaults.
The observed bytes are materialized separately only so byte-level comparisons and
both requested hash domains can be reported, then bound back to the actual Core
method by checking its returned hash against those same observed bytes.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.merkle import MerkleAttestor  # noqa: E402

SPECIFICATION_COMMIT = "b3a6e784d9a6ea2e0b554310e3de80e7d13de859"
FIXTURE_PATH = Path("fixtures/corpus/CANONICAL-003_jcs_full_discriminator.json")
EXPECTED_PATH = Path("fixtures/corpus/CANONICAL-003_jcs_full_discriminator.expected.jcs")

EXPECTED_FIXTURE_BYTES = 4230
EXPECTED_FIXTURE_SHA256 = (
    "1cde8282d6df99defc16b8652cb0f43a8f327c35b8f356a8612b835ed996ec73"
)
EXPECTED_CANONICAL_BYTES = 577
EXPECTED_CANONICAL_SHA256 = (
    "9fb648c388c4485575d25c1d6171ba691fec51c1b433b11f4d61197bbe2a5509"
)
EXPECTED_RFC6962_LEAF_SHA256 = (
    "38672ea2bd0ea87b2446efce8d4ba4adeb822e0baaecee4a54b73179198d2b3e"
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_check(
    checks: list[dict[str, Any]], check_id: str, expected: Any, actual: Any
) -> None:
    checks.append(
        {
            "check_id": check_id,
            "status": "PASS" if actual == expected else "FAIL",
            "expected": expected,
            "actual": actual,
        }
    )


def main() -> int:
    specification_root = Path(
        os.environ.get("AURA_SPECIFICATION_ROOT", "../aura-specification")
    ).resolve()
    fixture_file = specification_root / FIXTURE_PATH
    expected_file = specification_root / EXPECTED_PATH

    fixture_bytes = fixture_file.read_bytes()
    expected_bytes = expected_file.read_bytes()

    fixture_digest = sha256_hex(fixture_bytes)
    fixture_valid = (
        len(fixture_bytes) == EXPECTED_FIXTURE_BYTES
        and fixture_digest == EXPECTED_FIXTURE_SHA256
    )
    if not fixture_valid:
        raise SystemExit(
            "INPUT INTEGRITY ERROR: pinned CANONICAL-003 fixture differs from expected "
            f"bytes (length={len(fixture_bytes)}, sha256={fixture_digest})"
        )

    if len(expected_bytes) != EXPECTED_CANONICAL_BYTES:
        raise SystemExit(
            "ORACLE ARTIFACT ERROR: expected JCS artifact length is "
            f"{len(expected_bytes)}, expected {EXPECTED_CANONICAL_BYTES}"
        )
    if expected_bytes.endswith(b"\\n"):
        raise SystemExit("ORACLE ARTIFACT ERROR: expected JCS bytes have a trailing LF")
    if sha256_hex(expected_bytes) != EXPECTED_CANONICAL_SHA256:
        raise SystemExit("ORACLE ARTIFACT ERROR: expected JCS artifact SHA-256 mismatch")

    fixture = json.loads(fixture_bytes.decode("utf-8"))
    if not isinstance(fixture, dict) or "protocol_object" not in fixture:
        raise SystemExit("INPUT SHAPE ERROR: missing JSON Pointer /protocol_object")
    protocol_object = fixture["protocol_object"]

    # Observe the exact existing serializer expression used by
    # core/merkle.py::MerkleAttestor.generate_leaf; do not replace it with JCS.
    observed_bytes = json.dumps(protocol_object, sort_keys=True).encode("utf-8")
    observed_sha256 = sha256_hex(observed_bytes)
    core_generate_leaf = MerkleAttestor.generate_leaf(protocol_object)
    core_method_binding = core_generate_leaf == observed_sha256

    leaf_preimage = b"\\x00" + observed_bytes
    observed_leaf_sha256 = sha256_hex(leaf_preimage)

    checks: list[dict[str, Any]] = []
    record_check(
        checks,
        "INPUT-FIXTURE-SHA256",
        EXPECTED_FIXTURE_SHA256,
        fixture_digest,
    )
    record_check(
        checks,
        "INPUT-FIXTURE-BYTE-LENGTH",
        EXPECTED_FIXTURE_BYTES,
        len(fixture_bytes),
    )
    record_check(
        checks,
        "CORE-PREIMAGE-BINDING",
        True,
        core_method_binding,
    )
    record_check(
        checks,
        "JCS-CANONICAL-BYTE-LENGTH",
        EXPECTED_CANONICAL_BYTES,
        len(observed_bytes),
    )
    record_check(
        checks,
        "JCS-CANONICAL-BYTE-IDENTITY",
        expected_bytes.hex(),
        observed_bytes.hex(),
    )
    record_check(
        checks,
        "JCS-SHA256",
        EXPECTED_CANONICAL_SHA256,
        observed_sha256,
    )
    record_check(
        checks,
        "RFC6962-LEAF-SHA256",
        EXPECTED_RFC6962_LEAF_SHA256,
        observed_leaf_sha256,
    )
    record_check(
        checks,
        "CORE-MERKLE-LEAF-VS-JCS-SHA256",
        EXPECTED_CANONICAL_SHA256,
        core_generate_leaf,
    )

    result = "PASS" if all(item["status"] == "PASS" for item in checks) else "FAIL"
    report = {
        "report_id": "CANONICAL-003-RI-PY-EXECUTION",
        "report_schema": "AURA-RI-PY-CANONICAL-EXECUTION-REPORT-0.1",
        "result": result,
        "interpretation": (
            "PASS means the current Core serialization path matched the RFC 8785 "
            "Oracle bytes and requested hashes. FAIL means it did not; do not alter "
            "Oracle constants to obtain a pass."
        ),
        "normative_status": "ENGINEERING TEST EVIDENCE ONLY; NON-NORMATIVE",
        "implementation": "RI-PY",
        "core_source_commit": os.environ.get("GITHUB_SHA", "local-unpinned"),
        "python_runtime": sys.version,
        "platform": platform.platform(),
        "specification_repository": "vaidt/aura-specification",
        "specification_commit": SPECIFICATION_COMMIT,
        "input_fixture": {
            "path": str(FIXTURE_PATH),
            "byte_length": len(fixture_bytes),
            "sha256": fixture_digest,
            "expected_sha256": EXPECTED_FIXTURE_SHA256,
            "fixture_integrity": "PASS" if fixture_valid else "FAIL",
            "json_pointer": "/protocol_object",
        },
        "serializer_under_test": {
            "module": "core/merkle.py",
            "entrypoint": "MerkleAttestor.generate_leaf",
            "observed_expression": "json.dumps(data, sort_keys=True).encode()",
            "dedicated_rfc8785_jcs_adapter_found_in_reviewed_main_tree": False,
            "json_defaults": {
                "sort_keys": True,
                "separators": "Python defaults (whitespace retained)",
                "ensure_ascii": True,
                "allow_nan": True,
            },
            "production_merkle_leaf_domain": "SHA-256(serialized_json_bytes), no RFC 6962 0x00 prefix",
        },
        "oracle": {
            "expected_artifact": str(EXPECTED_PATH),
            "canonical_bytes_length": EXPECTED_CANONICAL_BYTES,
            "canonical_sha256": EXPECTED_CANONICAL_SHA256,
            "rfc6962_leaf_sha256": EXPECTED_RFC6962_LEAF_SHA256,
            "expected_artifact_has_trailing_lf": False,
        },
        "observed": {
            "serialized_bytes_length": len(observed_bytes),
            "serialized_sha256": observed_sha256,
            "rfc6962_leaf_sha256_from_observed_bytes": observed_leaf_sha256,
            "core_merkle_generate_leaf_sha256": core_generate_leaf,
            "core_method_binding_to_observed_preimage": core_method_binding,
            "serialized_utf8_replacement_view": observed_bytes.decode(
                "utf-8", errors="replace"
            ),
            "serialized_hex": observed_bytes.hex(),
        },
        "checks": checks,
    }

    artifacts = Path("artifacts/canonical-003-ri-py")
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "CANONICAL-003_ri_py_actual_serialization.bin").write_bytes(
        observed_bytes
    )
    report_path = artifacts / "CANONICAL-003_ri_py_execution_report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\\n",
        encoding="utf-8",
    )

    print("===== CANONICAL-003 RI-PY RAW EXECUTION REPORT =====")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("===== END CANONICAL-003 RI-PY RAW EXECUTION REPORT =====")
    print(f"Raw serialized bytes: {artifacts / 'CANONICAL-003_ri_py_actual_serialization.bin'}")
    print(f"Machine-readable report: {report_path}")
    return 0 if result == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
