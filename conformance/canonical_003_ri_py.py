"""CANONICAL-003 executable conformance check for AURA Core / RI-PY.

This test uses a pinned RFC 8785 implementation through the production
MerkleAttestor.generate_leaf path. It reports exact canonical bytes, SHA-256,
and RFC 6962 leaf digest. Expected Oracle values are never changed to accommodate
the implementation.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

import rfc8785

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
EXPECTED_ARTIFACT_SHA256 = EXPECTED_CANONICAL_SHA256


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check(
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
    fixture_path = specification_root / FIXTURE_PATH
    expected_path = specification_root / EXPECTED_PATH

    fixture_bytes = fixture_path.read_bytes()
    expected_bytes = expected_path.read_bytes()
    fixture_sha256 = sha256_hex(fixture_bytes)
    oracle_sha256 = sha256_hex(expected_bytes)

    if expected_bytes.endswith(b"\n"):
        raise SystemExit("ORACLE ARTIFACT ERROR: expected JCS has a trailing LF")
    if len(expected_bytes) != EXPECTED_CANONICAL_BYTES:
        raise SystemExit(
            f"ORACLE ARTIFACT ERROR: expected {EXPECTED_CANONICAL_BYTES} bytes, "
            f"found {len(expected_bytes)}"
        )
    if oracle_sha256 != EXPECTED_ARTIFACT_SHA256:
        raise SystemExit(
            "ORACLE ARTIFACT ERROR: expected JCS SHA-256 differs from pinned oracle "
            f"({oracle_sha256})"
        )

    fixture = json.loads(fixture_bytes.decode("utf-8"))
    if not isinstance(fixture, dict) or "protocol_object" not in fixture:
        raise SystemExit("INPUT SHAPE ERROR: missing JSON Pointer /protocol_object")
    protocol_object = fixture["protocol_object"]

    # The canonical bytes are produced by the selected RFC 8785 library.
    # core/merkle.py uses the same library entry point inside generate_leaf().
    canonical_bytes = rfc8785.dumps(protocol_object)
    canonical_sha256 = sha256_hex(canonical_bytes)

    # RFC 6962 leaf domain uses a raw 0x00 octet, not the text "0x00".
    leaf_preimage = b"\x00" + canonical_bytes
    leaf_sha256 = sha256_hex(leaf_preimage)

    # Bind the production method to the independently recomputed RFC 6962 digest.
    core_leaf_sha256 = MerkleAttestor.generate_leaf(protocol_object)
    core_method_binding = core_leaf_sha256 == leaf_sha256

    checks: list[dict[str, Any]] = []
    check(checks, "INPUT-FIXTURE-BYTE-LENGTH", EXPECTED_FIXTURE_BYTES, len(fixture_bytes))
    check(checks, "INPUT-FIXTURE-SHA256", EXPECTED_FIXTURE_SHA256, fixture_sha256)
    check(checks, "ORACLE-ARTIFACT-BYTE-LENGTH", EXPECTED_CANONICAL_BYTES, len(expected_bytes))
    check(checks, "ORACLE-ARTIFACT-SHA256", EXPECTED_ARTIFACT_SHA256, oracle_sha256)
    check(checks, "JCS-CANONICAL-BYTE-LENGTH", EXPECTED_CANONICAL_BYTES, len(canonical_bytes))
    check(checks, "JCS-CANONICAL-BYTE-IDENTITY", expected_bytes.hex(), canonical_bytes.hex())
    check(checks, "JCS-SHA256", EXPECTED_CANONICAL_SHA256, canonical_sha256)
    check(checks, "RFC6962-LEAF-SHA256", EXPECTED_RFC6962_LEAF_SHA256, leaf_sha256)
    check(
        checks,
        "CORE-GENERATE-LEAF-USES-RFC6962-DOMAIN",
        EXPECTED_RFC6962_LEAF_SHA256,
        core_leaf_sha256,
    )
    check(checks, "CORE-METHOD-BINDING", True, core_method_binding)

    result = "PASS" if all(item["status"] == "PASS" for item in checks) else "FAIL"
    report = {
        "report_id": "CANONICAL-003-RI-PY-EXECUTION",
        "report_schema": "AURA-RI-PY-CANONICAL-EXECUTION-REPORT-0.2",
        "result": result,
        "normative_status": "ENGINEERING TEST EVIDENCE ONLY; NON-NORMATIVE",
        "implementation": "RI-PY",
        "core_source_commit": os.environ.get("GITHUB_SHA", "local-unpinned"),
        "python_runtime": sys.version,
        "platform": platform.platform(),
        "canonicalizer": {
            "distribution": "rfc8785",
            "version": "0.1.4",
            "api": "rfc8785.dumps(value) -> UTF-8 bytes",
        },
        "specification_repository": "vaidt/aura-specification",
        "specification_commit": SPECIFICATION_COMMIT,
        "input_fixture": {
            "path": str(FIXTURE_PATH),
            "byte_length": len(fixture_bytes),
            "sha256": fixture_sha256,
            "expected_byte_length": EXPECTED_FIXTURE_BYTES,
            "expected_sha256": EXPECTED_FIXTURE_SHA256,
            "json_pointer": "/protocol_object",
        },
        "serializer_under_test": {
            "module": "core/merkle.py",
            "entrypoint": "MerkleAttestor.generate_leaf",
            "canonicalizer": "rfc8785.dumps(data)",
            "leaf_preimage": "raw 0x00 octet || exact RFC 8785 UTF-8 bytes",
            "leaf_hash": "SHA-256(0x00 || canonical_bytes)",
        },
        "oracle": {
            "expected_artifact": str(EXPECTED_PATH),
            "canonical_bytes_length": EXPECTED_CANONICAL_BYTES,
            "canonical_sha256": EXPECTED_CANONICAL_SHA256,
            "rfc6962_leaf_sha256": EXPECTED_RFC6962_LEAF_SHA256,
            "has_trailing_lf": False,
        },
        "observed": {
            "canonical_bytes_length": len(canonical_bytes),
            "canonical_sha256": canonical_sha256,
            "rfc6962_leaf_sha256": leaf_sha256,
            "core_merkle_generate_leaf_sha256": core_leaf_sha256,
            "core_method_binding": core_method_binding,
            "canonical_utf8": canonical_bytes.decode("utf-8"),
            "canonical_hex": canonical_bytes.hex(),
        },
        "checks": checks,
    }

    artifacts = Path("artifacts/canonical-003-ri-py")
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "CANONICAL-003_ri_py_actual_serialization.bin").write_bytes(
        canonical_bytes
    )
    report_path = artifacts / "CANONICAL-003_ri_py_execution_report.json"
    report_path.write_bytes(
        json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    )

    print("===== CANONICAL-003 RI-PY RAW EXECUTION REPORT =====")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("===== END CANONICAL-003 RI-PY RAW EXECUTION REPORT =====")
    print(f"Raw serialized bytes: {artifacts / 'CANONICAL-003_ri_py_actual_serialization.bin'}")
    print(f"Machine-readable report: {report_path}")
    return 0 if result == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
