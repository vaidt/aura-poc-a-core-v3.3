#!/usr/bin/env python3
"""CORE-003 native x86_64 / ARM64 ARI+drift evidence.

This is executable implementation evidence, not a normative protocol definition.
It runs the real PoCAEvaluator against the fixed RD-006 observation vectors on
native architecture runners, then compares the complete inputs and actual
outputs produced on both hosts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.evaluator import PoCAEvaluator  # noqa: E402
from core.test_ari_observability import (  # noqa: E402
    IMPLEMENTATION_DERIVED_NON_NORMATIVE,
    OBSERVATION_CASES,
    SCALE,
)

EXPECTED_CASE_IDS = ["OBS-1", "OBS-2", "OBS-3", "OBS-4", "OBS-5"]
MACHINE_ALIASES = {
    "x86_64": {"x86_64", "amd64"},
    "aarch64": {"aarch64", "arm64"},
}


def canonical_json_bytes(value: Any) -> bytes:
    """Stable JSON encoding for evidence input digests; contains no floats."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def write_json(path: str | Path, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def build_record(expected_machine: str, runner_label: str, revision: str) -> dict:
    actual_machine = platform.machine().lower()
    if expected_machine not in MACHINE_ALIASES:
        raise ValueError(f"Unsupported expected machine: {expected_machine}")
    if actual_machine not in MACHINE_ALIASES[expected_machine]:
        raise RuntimeError(
            f"Runner architecture mismatch: expected {expected_machine}, "
            f"observed platform.machine()={platform.machine()!r}"
        )
    if not revision:
        raise ValueError("A non-empty source revision is required")

    source_path = REPO_ROOT / "core" / "evaluator.py"
    source_sha256 = sha256_hex(source_path.read_bytes())
    observations = []

    for case in OBSERVATION_CASES:
        case_input = {
            "constitution": list(case["constitution"]),
            "vector": list(case["vector"]),
            "valid_schema": bool(case["valid_schema"]),
            "scaling_factor": SCALE,
        }
        input_digest = sha256_hex(canonical_json_bytes(case_input))
        evaluator = PoCAEvaluator(case_input["constitution"])
        try:
            result = evaluator.evaluate(
                agent_id=f"CORE-003-{case['id']}",
                vector=case_input["vector"],
                valid_schema=case_input["valid_schema"],
            )
            observed = {"ari": result["ari"], "drift": result["drift"]}
            if type(observed["ari"]) is not int or type(observed["drift"]) is not int:
                raise TypeError("ARI and drift outputs must be plain integers")
            if not 0 <= observed["ari"] <= SCALE:
                raise AssertionError(
                    f"{case['id']}: ARI outside [0, {SCALE}]: {observed['ari']}"
                )
            if not 0 <= observed["drift"] <= SCALE:
                raise AssertionError(
                    f"{case['id']}: drift outside [0, {SCALE}]: {observed['drift']}"
                )
            observations.append(
                {
                    "case_id": case["id"],
                    "input": case_input,
                    "input_sha256": input_digest,
                    "execution": "SUCCESS",
                    "observed": observed,
                    "error": None,
                }
            )
        except Exception as exc:
            observations.append(
                {
                    "case_id": case["id"],
                    "input": case_input,
                    "input_sha256": input_digest,
                    "execution": "FAILURE",
                    "observed": None,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    report = {
        "schema_version": "1.0",
        "evidence_type": "CORE-003 native cross-architecture ARI/drift execution",
        "technical_result": "OBSERVATIONS_RECORDED",
        "normative_effect": "NONE",
        "source_revision": revision,
        "evaluator_source_sha256": source_sha256,
        "runtime": {
            "system": platform.system(),
            "machine": platform.machine(),
            "expected_machine": expected_machine,
            "runner_label": runner_label,
            "architecture": platform.architecture()[0],
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
        },
        "observations": observations,
    }
    return report


def load_report(path: str | Path) -> dict:
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    if report.get("normative_effect") != "NONE":
        raise ValueError(f"{path}: missing normative_effect=NONE")
    if report.get("evidence_type") != "CORE-003 native cross-architecture ARI/drift execution":
        raise ValueError(f"{path}: unexpected evidence_type")
    return report


def validate_report(report: dict, expected_machine: str) -> None:
    runtime = report.get("runtime", {})
    actual_machine = str(runtime.get("machine", "")).lower()
    if runtime.get("expected_machine") != expected_machine:
        raise AssertionError(
            f"Expected-machine marker mismatch: {runtime.get('expected_machine')!r}"
        )
    if actual_machine not in MACHINE_ALIASES[expected_machine]:
        raise AssertionError(
            f"Expected native {expected_machine}, observed {runtime.get('machine')!r}"
        )
    if not report.get("source_revision"):
        raise AssertionError("Source revision is missing")
    if not report.get("evaluator_source_sha256"):
        raise AssertionError("Evaluator source digest is missing")

    observations = report.get("observations")
    if not isinstance(observations, list):
        raise AssertionError("Observations must be a list")
    ids = [item.get("case_id") for item in observations]
    if ids != EXPECTED_CASE_IDS:
        raise AssertionError(f"Observation order/coverage mismatch: {ids!r}")

    for item in observations:
        if item.get("execution") != "SUCCESS" or item.get("error") is not None:
            raise AssertionError(
                f"{item.get('case_id')}: evaluation failed: {item.get('error')}"
            )
        case_input = item.get("input")
        if not isinstance(case_input, dict):
            raise AssertionError(f"{item.get('case_id')}: full input is missing")
        actual_digest = sha256_hex(canonical_json_bytes(case_input))
        if item.get("input_sha256") != actual_digest:
            raise AssertionError(f"{item.get('case_id')}: input digest mismatch")

        observed = item.get("observed")
        if not isinstance(observed, dict) or set(observed) != {"ari", "drift"}:
            raise AssertionError(f"{item.get('case_id')}: invalid measurement payload")
        if type(observed["ari"]) is not int or type(observed["drift"]) is not int:
            raise AssertionError(f"{item.get('case_id')}: measurements are not integers")
        if not 0 <= observed["ari"] <= SCALE:
            raise AssertionError(f"{item.get('case_id')}: ARI is out of range")
        if not 0 <= observed["drift"] <= SCALE:
            raise AssertionError(f"{item.get('case_id')}: drift is out of range")

        # These expected values characterize the implementation only; they are
        # explicitly non-normative in core.test_ari_observability.
        expected = IMPLEMENTATION_DERIVED_NON_NORMATIVE[item["case_id"]]
        if observed != expected:
            raise AssertionError(
                f"{item['case_id']}: observed {observed!r} does not match the "
                f"implementation-derived regression record {expected!r}"
            )


def compare_reports(x86_path: str | Path, arm_path: str | Path) -> dict:
    x86 = load_report(x86_path)
    arm = load_report(arm_path)
    validate_report(x86, "x86_64")
    validate_report(arm, "aarch64")

    if x86["source_revision"] != arm["source_revision"]:
        raise AssertionError("Architecture reports were produced from different revisions")
    if x86["evaluator_source_sha256"] != arm["evaluator_source_sha256"]:
        raise AssertionError("PoCAEvaluator source differs between architecture runs")

    xrt = x86["runtime"]
    art = arm["runtime"]
    for key in ("system", "python_implementation", "python_version"):
        if xrt.get(key) != art.get(key):
            raise AssertionError(
                f"Runtime mismatch for {key}: x86_64={xrt.get(key)!r}, "
                f"ARM64={art.get(key)!r}"
            )

    x_cases = {item["case_id"]: item for item in x86["observations"]}
    a_cases = {item["case_id"]: item for item in arm["observations"]}
    if list(x_cases) != list(a_cases) or list(x_cases) != EXPECTED_CASE_IDS:
        raise AssertionError("Architecture observations do not cover the same ordered cases")

    comparisons = []
    for case_id in EXPECTED_CASE_IDS:
        left, right = x_cases[case_id], a_cases[case_id]
        if left["input"] != right["input"]:
            raise AssertionError(f"{case_id}: full fixed inputs differ between architectures")
        if left["input_sha256"] != right["input_sha256"]:
            raise AssertionError(f"{case_id}: input SHA-256 differs between architectures")
        if left["observed"] != right["observed"]:
            raise AssertionError(
                f"{case_id}: ARI/drift mismatch: x86_64={left['observed']!r}, "
                f"ARM64={right['observed']!r}"
            )
        comparisons.append(
            {
                "case_id": case_id,
                "input_sha256": left["input_sha256"],
                "x86_64": left["observed"],
                "arm64": right["observed"],
                "measurements_equal": True,
            }
        )

    return {
        "schema_version": "1.0",
        "evidence_type": "CORE-003 native cross-architecture ARI/drift comparison",
        "technical_result": "PASS",
        "normative_effect": "NONE",
        "source_revision": x86["source_revision"],
        "evaluator_source_sha256": x86["evaluator_source_sha256"],
        "runtimes": {
            "x86_64": xrt,
            "arm64": art,
        },
        "cases_compared": len(comparisons),
        "all_measurements_equal": True,
        "comparisons": comparisons,
        "conclusion": (
            "The production PoCAEvaluator executed on native x86_64 and ARM64 "
            "runners using identical complete inputs and produced identical "
            "integer ARI/drift outputs for every recorded case. This is technical "
            "implementation evidence only; normative_effect remains NONE."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record_parser = subparsers.add_parser("record", help="run evaluator on this native host")
    record_parser.add_argument("--expected-machine", required=True, choices=("x86_64", "aarch64"))
    record_parser.add_argument("--runner-label", required=True)
    record_parser.add_argument("--revision", required=True)
    record_parser.add_argument("--output", required=True)

    compare_parser = subparsers.add_parser("compare", help="compare x86_64 and ARM64 records")
    compare_parser.add_argument("--x86", required=True)
    compare_parser.add_argument("--arm", required=True)
    compare_parser.add_argument("--output", required=True)

    args = parser.parse_args()
    if args.command == "record":
        report = build_record(args.expected_machine, args.runner_label, args.revision)
        if any(item["execution"] != "SUCCESS" for item in report["observations"]):
            write_json(args.output, report)
            print(json.dumps({"technical_result": "FAIL", "output": args.output}, indent=2))
            return 1
        write_json(args.output, report)
        print(
            json.dumps(
                {
                    "technical_result": "OBSERVATIONS_RECORDED",
                    "normative_effect": "NONE",
                    "revision": args.revision,
                    "runtime": report["runtime"],
                    "observations": [
                        {
                            "case_id": item["case_id"],
                            "input_sha256": item["input_sha256"],
                            "observed": item["observed"],
                        }
                        for item in report["observations"]
                    ],
                    "output": args.output,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    comparison = compare_reports(args.x86, args.arm)
    write_json(args.output, comparison)
    print(json.dumps(comparison, indent=2, sort_keys=True))
    print(f"Comparison evidence written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
