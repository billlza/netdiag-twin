#!/usr/bin/env python3
"""Keep real-device pilot claims fail-closed until lab evidence exists."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any

from bounded_file import (
    normalized_relative_parts,
    read_regular_file,
    read_regular_file_beneath,
)
from strict_json import StrictJsonError, parse_json_bytes_strict


ROOT = Path(__file__).resolve().parents[1]
STATUS_PATH = ROOT / "docs" / "real-device-pilot-readiness.json"
STATUS_DOC = ROOT / "docs" / "real-device-pilot-readiness.md"
DOCS_WITH_STATUS = [
    ROOT / "README.md",
    ROOT / "docs" / "pilot-run-center.md",
    ROOT / "docs" / "quality-gates.md",
    ROOT / "docs" / "release-process.md",
]
FORBIDDEN_PENDING_CLAIMS = (
    "real-device validated",
    "real device validated",
    "real-device proof passed",
    "real device proof passed",
)
REAL_DEVICE_EVIDENCE_SCHEMA = "netdiag-real-device-evidence-manifest/v1"
REQUIRED_REAL_DEVICE_ARTIFACT_KINDS = {
    "pilot_preflight",
    "pilot_workflow",
    "connector_health",
    "evidence_bundle",
    "model_promotion_gate",
}
ARTIFACT_SCHEMAS = {
    "pilot_preflight": "netdiag-pilot-preflight/v1",
    "pilot_workflow": "netdiag-pilot-workflow/v1",
    "evidence_bundle": "netdiag-evidence-bundle/v1",
    "model_promotion_gate": "netdiag-model-promotion-gate/v1",
}
REQUIRED_WORKFLOW_PHASES = {
    "preflight",
    "collect",
    "diagnose",
    "evidence_bundle",
    "verify",
}
REQUIRED_PROMOTION_GATES = {
    "model_load",
    "benchmark_model_match",
    "calibration_model_match",
    "calibration_thresholds_integrated",
    "benchmark_report",
}
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def is_hex_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


def is_non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def is_non_negative_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def read_hashed_json_value(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    failures: list[str],
) -> tuple[Any | None, str | None]:
    try:
        body = read_regular_file(path, max_bytes, label)
    except (OSError, ValueError) as error:
        failures.append(f"{label} could not be read safely: {error}")
        return None, None
    return decode_hashed_json_value(body, label=label, failures=failures)


def read_hashed_json_value_beneath(
    root: Path,
    relative_path: str,
    *,
    label: str,
    max_bytes: int,
    failures: list[str],
) -> tuple[Any | None, str | None]:
    try:
        body = read_regular_file_beneath(
            root, relative_path, max_bytes, label
        )
    except (OSError, ValueError) as error:
        failures.append(f"{label} could not be read safely: {error}")
        return None, None
    return decode_hashed_json_value(body, label=label, failures=failures)


def decode_hashed_json_value(
    body: bytes, *, label: str, failures: list[str]
) -> tuple[Any | None, str]:
    digest = hashlib.sha256(body).hexdigest()
    try:
        return parse_json_bytes_strict(body, source=label), digest
    except StrictJsonError as error:
        failures.append(str(error))
        return None, digest


def validate_check_list(value: object, label: str, failures: list[str]) -> None:
    if not isinstance(value, list) or not value:
        failures.append(f"{label} checks must be a non-empty list")
        return
    for index, check in enumerate(value):
        if not isinstance(check, dict):
            failures.append(f"{label} check {index} must be an object")
            continue
        require(
            check.get("status") in {"ok", "degraded"},
            failures,
            f"{label} check {index} must have status ok or degraded",
        )


def validate_source_inventory(value: object, label: str, failures: list[str]) -> None:
    if not isinstance(value, list) or not value:
        failures.append(f"{label} source_inventory must be a non-empty list")
        return
    primary_count = 0
    for index, source in enumerate(value):
        if not isinstance(source, dict):
            failures.append(f"{label} source_inventory {index} must be an object")
            continue
        for field in ["name", "kind", "role", "endpoint"]:
            require(
                is_non_empty_string(source.get(field)),
                failures,
                f"{label} source_inventory {index} missing {field}",
            )
        if source.get("role") == "primary":
            primary_count += 1
    require(
        primary_count == 1,
        failures,
        f"{label} source_inventory must contain exactly one primary source",
    )


def validate_pilot_preflight(
    payload: object,
    *,
    pilot_id: str,
    failures: list[str],
    label: str = "pilot_preflight",
) -> None:
    if not isinstance(payload, dict):
        failures.append(f"{label} must be a JSON object")
        return
    require(
        payload.get("schema") == ARTIFACT_SCHEMAS["pilot_preflight"],
        failures,
        f"{label} schema must be {ARTIFACT_SCHEMAS['pilot_preflight']}",
    )
    require(payload.get("passed") is True, failures, f"{label} must set passed=true")
    require(
        payload.get("pilot_id") == pilot_id,
        failures,
        f"{label} pilot_id must match the evidence manifest",
    )
    validate_source_inventory(payload.get("source_inventory"), label, failures)
    validate_check_list(payload.get("checks"), label, failures)


def validate_connector_health(payload: object, label: str, failures: list[str]) -> None:
    if not isinstance(payload, list) or not payload:
        failures.append(
            f"{label} must use the non-empty ConnectorHealthSnapshot array schema"
        )
        return
    for index, item in enumerate(payload):
        item_label = f"{label} source {index}"
        if not isinstance(item, dict):
            failures.append(f"{item_label} must be an object")
            continue
        require(
            item.get("status") in {"ok", "degraded"},
            failures,
            f"{item_label} status must be ok or degraded",
        )
        for field in ["source_kind", "profile_name", "sample", "captured_at"]:
            require(
                is_non_empty_string(item.get(field)),
                failures,
                f"{item_label} missing {field}",
            )
        require(
            is_non_negative_integer(item.get("rows")) and item.get("rows", 0) > 0,
            failures,
            f"{item_label} rows must be a positive integer",
        )
        require(
            is_non_negative_integer(item.get("warning_count")),
            failures,
            f"{item_label} warning_count must be a non-negative integer",
        )
        require(
            isinstance(item.get("missing_metrics"), list),
            failures,
            f"{item_label} missing_metrics must be a list",
        )
        quality = item.get("quality")
        if not isinstance(quality, dict):
            failures.append(f"{item_label} quality must be an object")
        else:
            for field in ["measured", "estimated", "fallback", "missing"]:
                require(
                    is_non_negative_integer(quality.get(field)),
                    failures,
                    f"{item_label} quality.{field} must be a non-negative integer",
                )


def validate_evidence_bundle(
    payload: object,
    *,
    run_id: str,
    failures: list[str],
    label: str = "evidence_bundle",
) -> None:
    if not isinstance(payload, dict):
        failures.append(f"{label} must be a JSON object")
        return
    require(
        payload.get("schema") == ARTIFACT_SCHEMAS["evidence_bundle"],
        failures,
        f"{label} schema must be {ARTIFACT_SCHEMAS['evidence_bundle']}",
    )
    require(
        payload.get("run_id") == run_id,
        failures,
        f"{label} run_id must match the evidence manifest",
    )
    require(
        is_non_empty_string(payload.get("created_at")),
        failures,
        f"{label} missing created_at",
    )
    require(
        is_non_empty_string(payload.get("output")),
        failures,
        f"{label} missing output",
    )
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        failures.append(f"{label} files must be a non-empty list")
        return
    seen_keys: set[str] = set()
    seen_zip_paths: set[str] = set()
    for index, item in enumerate(files):
        item_label = f"{label} file {index}"
        if not isinstance(item, dict):
            failures.append(f"{item_label} must be an object")
            continue
        key = item.get("key")
        zip_path = item.get("zip_path")
        for field in ["key", "source_path", "zip_path"]:
            require(
                is_non_empty_string(item.get(field)),
                failures,
                f"{item_label} missing {field}",
            )
        if isinstance(key, str):
            require(key not in seen_keys, failures, f"{item_label} duplicates key {key!r}")
            seen_keys.add(key)
        if isinstance(zip_path, str):
            require(
                zip_path not in seen_zip_paths,
                failures,
                f"{item_label} duplicates zip_path {zip_path!r}",
            )
            seen_zip_paths.add(zip_path)
        require(
            is_non_negative_integer(item.get("bytes")) and item.get("bytes", 0) > 0,
            failures,
            f"{item_label} bytes must be a positive integer",
        )
        require(
            is_hex_sha256(item.get("sha256")),
            failures,
            f"{item_label} missing SHA-256",
        )


def validate_model_promotion_gate(
    payload: object,
    *,
    model_identity: object,
    failures: list[str],
) -> None:
    label = "model_promotion_gate"
    if not isinstance(payload, dict):
        failures.append(f"{label} must be a JSON object")
        return
    require(
        payload.get("schema") == ARTIFACT_SCHEMAS[label],
        failures,
        f"{label} schema must be {ARTIFACT_SCHEMAS[label]}",
    )
    require(payload.get("passed") is True, failures, f"{label} must set passed=true")
    for field in ["model_dir", "benchmark_report", "calibration_report"]:
        require(
            is_non_empty_string(payload.get(field)),
            failures,
            f"{label} missing {field}",
        )
    if not isinstance(model_identity, dict):
        failures.append("validated_evidence_manifest model_identity must be an object")
    else:
        for field in ["model_manifest_hash_sha256", "model_file_hash_sha256"]:
            expected = model_identity.get(field)
            require(
                is_hex_sha256(expected),
                failures,
                f"validated_evidence_manifest model_identity.{field} must be SHA-256",
            )
            require(
                isinstance(expected, str)
                and isinstance(payload.get(field), str)
                and hmac.compare_digest(payload[field].lower(), expected.lower()),
                failures,
                f"{label} {field} must match the evidence manifest model_identity",
            )
    gates = payload.get("gates")
    if not isinstance(gates, list) or not gates:
        failures.append(f"{label} gates must be a non-empty list")
        return
    names: set[str] = set()
    for index, gate in enumerate(gates):
        if not isinstance(gate, dict):
            failures.append(f"{label} gate {index} must be an object")
            continue
        name = gate.get("name")
        require(
            is_non_empty_string(name),
            failures,
            f"{label} gate {index} missing name",
        )
        if isinstance(name, str):
            require(
                name not in names,
                failures,
                f"{label} gate {index} duplicates name {name!r}",
            )
            names.add(name)
        require(
            gate.get("passed") is True,
            failures,
            f"{label} gate {index} must set passed=true",
        )
    missing = sorted(REQUIRED_PROMOTION_GATES - names)
    require(
        not missing,
        failures,
        f"{label} missing required gates: {', '.join(missing)}",
    )


def validate_pilot_run(
    pilot_run: object,
    *,
    run_id: str,
    pilot_id: str,
    failures: list[str],
) -> None:
    label = "pilot_workflow pilot_run"
    if not isinstance(pilot_run, dict):
        failures.append(f"{label} must be an object")
        return
    require(
        pilot_run.get("schema") == "netdiag-pilot-report/v1",
        failures,
        f"{label} schema must be netdiag-pilot-report/v1",
    )
    require(
        pilot_run.get("passed") is True,
        failures,
        f"{label} must set passed=true",
    )
    require(
        pilot_run.get("run_id") == run_id,
        failures,
        f"{label} run_id must match the evidence manifest",
    )
    require(
        pilot_run.get("pilot_id") == pilot_id,
        failures,
        f"{label} pilot_id must match the evidence manifest",
    )
    validate_source_inventory(pilot_run.get("source_inventory"), label, failures)
    validate_check_list(pilot_run.get("checks"), label, failures)
    validate_connector_health(
        pilot_run.get("connector_health"),
        f"{label} connector_health",
        failures,
    )
    validate_evidence_bundle(
        pilot_run.get("evidence_bundle"),
        run_id=run_id,
        failures=failures,
        label=f"{label} evidence_bundle",
    )


def validate_workflow_phases(phases: object, failures: list[str]) -> None:
    label = "pilot_workflow"
    phase_status: dict[str, object] = {}
    if not isinstance(phases, list) or not phases:
        failures.append(f"{label} phases must be a non-empty list")
    else:
        for index, phase in enumerate(phases):
            if not isinstance(phase, dict) or not is_non_empty_string(phase.get("name")):
                failures.append(f"{label} phase {index} must have a name")
                continue
            name = phase["name"]
            require(
                name not in phase_status,
                failures,
                f"{label} phase {index} duplicates name {name!r}",
            )
            phase_status[name] = phase.get("status")
        for name in sorted(REQUIRED_WORKFLOW_PHASES):
            require(
                phase_status.get(name) == "passed",
                failures,
                f"{label} phase {name!r} must be passed",
            )


def validate_workflow_verification(
    verification: object,
    *,
    run_id: str,
    failures: list[str],
) -> None:
    label = "pilot_workflow"
    if not isinstance(verification, dict):
        failures.append(f"{label} verification must be an object")
    else:
        require(
            verification.get("schema") == "netdiag-action-verification/v1",
            failures,
            f"{label} verification schema must be netdiag-action-verification/v1",
        )
        require(
            verification.get("before_run_id") == run_id,
            failures,
            f"{label} verification before_run_id must match the evidence manifest",
        )
        require(
            is_non_empty_string(verification.get("after_run_id"))
            and verification.get("after_run_id") != run_id,
            failures,
            f"{label} verification after_run_id must identify a distinct after-run",
        )
        require(
            verification.get("verdict") == "verified",
            failures,
            f"{label} verification verdict must be verified",
        )


def validate_pilot_workflow(
    payload: object,
    *,
    run_id: str,
    pilot_id: str,
    failures: list[str],
) -> None:
    label = "pilot_workflow"
    if not isinstance(payload, dict):
        failures.append(f"{label} must be a JSON object")
        return
    require(
        payload.get("schema") == ARTIFACT_SCHEMAS[label],
        failures,
        f"{label} schema must be {ARTIFACT_SCHEMAS[label]}",
    )
    require(payload.get("passed") is True, failures, f"{label} must set passed=true")
    require(
        payload.get("pilot_id") == pilot_id,
        failures,
        f"{label} pilot_id must match the evidence manifest",
    )
    validate_pilot_preflight(
        payload.get("preflight"),
        pilot_id=pilot_id,
        failures=failures,
        label="pilot_workflow.preflight",
    )
    validate_pilot_run(
        payload.get("pilot_run"),
        run_id=run_id,
        pilot_id=pilot_id,
        failures=failures,
    )
    validate_workflow_phases(payload.get("phases"), failures)
    validate_workflow_verification(
        payload.get("verification"),
        run_id=run_id,
        failures=failures,
    )


def validate_artifact_semantics(
    payloads: dict[str, object],
    *,
    run_id: str,
    pilot_id: str,
    model_identity: object,
    failures: list[str],
) -> None:
    preflight = payloads.get("pilot_preflight")
    workflow = payloads.get("pilot_workflow")
    connector_health = payloads.get("connector_health")
    evidence_bundle = payloads.get("evidence_bundle")

    validate_pilot_preflight(preflight, pilot_id=pilot_id, failures=failures)
    validate_pilot_workflow(
        workflow,
        run_id=run_id,
        pilot_id=pilot_id,
        failures=failures,
    )
    validate_connector_health(connector_health, "connector_health", failures)
    validate_evidence_bundle(evidence_bundle, run_id=run_id, failures=failures)
    validate_model_promotion_gate(
        payloads.get("model_promotion_gate"),
        model_identity=model_identity,
        failures=failures,
    )

    if isinstance(workflow, dict):
        require(
            workflow.get("preflight") == preflight,
            failures,
            "pilot_workflow preflight must match the reviewed pilot_preflight artifact",
        )
        pilot_run = workflow.get("pilot_run")
        if isinstance(pilot_run, dict):
            require(
                pilot_run.get("connector_health") == connector_health,
                failures,
                "pilot_workflow connector_health must match the reviewed connector_health artifact",
            )
            require(
                pilot_run.get("evidence_bundle") == evidence_bundle,
                failures,
                "pilot_workflow evidence_bundle must match the reviewed evidence_bundle artifact",
            )


def validate_real_device_evidence_manifest(
    manifest_relative_path: str,
    failures: list[str],
) -> None:
    root = ROOT.resolve()
    payload, _manifest_hash = read_hashed_json_value_beneath(
        root,
        manifest_relative_path,
        label="validated_evidence_manifest",
        max_bytes=MAX_MANIFEST_BYTES,
        failures=failures,
    )
    if not isinstance(payload, dict):
        if payload is not None:
            failures.append("validated_evidence_manifest must be a JSON object")
        return

    require(
        payload.get("schema") == REAL_DEVICE_EVIDENCE_SCHEMA,
        failures,
        f"validated_evidence_manifest schema must be {REAL_DEVICE_EVIDENCE_SCHEMA}",
    )
    require(
        payload.get("source_mode") == "real_device",
        failures,
        "validated_evidence_manifest must set source_mode=real_device",
    )
    require(
        payload.get("sample_only") is False,
        failures,
        "validated_evidence_manifest must set sample_only=false",
    )
    require(
        payload.get("collection_mode") == "live",
        failures,
        "validated_evidence_manifest must set collection_mode=live",
    )
    run_id_value = payload.get("run_id")
    pilot_id_value = payload.get("pilot_id")
    require(
        is_non_empty_string(run_id_value),
        failures,
        "validated_evidence_manifest must include run_id",
    )
    require(
        is_non_empty_string(pilot_id_value),
        failures,
        "validated_evidence_manifest must include pilot_id",
    )
    run_id = run_id_value.strip() if isinstance(run_id_value, str) else ""
    pilot_id = pilot_id_value.strip() if isinstance(pilot_id_value, str) else ""
    model_identity = payload.get("model_identity")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        failures.append("validated_evidence_manifest artifacts must be a list")
        return

    seen_kinds: set[str] = set()
    seen_paths: set[str] = set()
    artifact_payloads: dict[str, object] = {}
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            failures.append(f"validated_evidence_manifest artifact {index} must be an object")
            continue
        kind = artifact.get("kind")
        if isinstance(kind, str) and kind.strip():
            kind = kind.strip()
            if kind not in REQUIRED_REAL_DEVICE_ARTIFACT_KINDS:
                failures.append(
                    f"validated_evidence_manifest artifact {index} has unsupported kind {kind!r}"
                )
            if kind in seen_kinds:
                failures.append(
                    f"validated_evidence_manifest artifact {index} duplicates kind {kind!r}"
                )
            else:
                seen_kinds.add(kind)
        else:
            failures.append(f"validated_evidence_manifest artifact {index} missing kind")

        require(
            artifact.get("run_id") == run_id,
            failures,
            f"validated_evidence_manifest artifact {index} run_id must match the manifest",
        )

        artifact_path: str | None = None
        path_value = artifact.get("path")
        if not isinstance(path_value, str) or not path_value.strip():
            failures.append(f"validated_evidence_manifest artifact {index} missing path")
        else:
            artifact_path = path_value.strip()
            try:
                normalized_relative_parts(
                    artifact_path,
                    f"validated_evidence_manifest artifact {index} path",
                )
            except ValueError as error:
                failures.append(str(error))
                artifact_path = None
        if artifact_path is not None:
            if artifact_path in seen_paths:
                failures.append(
                    f"validated_evidence_manifest artifact {index} duplicates path {path_value!r}"
                )
            else:
                seen_paths.add(artifact_path)

        declared_sha256 = artifact.get("sha256")
        if not is_hex_sha256(declared_sha256):
            failures.append(f"validated_evidence_manifest artifact {index} missing SHA-256")

        if artifact_path is not None:
            artifact_payload, actual_sha256 = read_hashed_json_value_beneath(
                root,
                artifact_path,
                label=f"validated_evidence_manifest artifact {index} ({kind})",
                max_bytes=MAX_ARTIFACT_BYTES,
                failures=failures,
            )
            if (
                isinstance(declared_sha256, str)
                and actual_sha256 is not None
                and not hmac.compare_digest(declared_sha256.lower(), actual_sha256)
            ):
                failures.append(
                    f"validated_evidence_manifest artifact {index} SHA-256 does "
                    "not match file content"
                )
            if (
                artifact_payload is not None
                and isinstance(kind, str)
                and kind not in artifact_payloads
            ):
                artifact_payloads[kind] = artifact_payload

    missing = sorted(REQUIRED_REAL_DEVICE_ARTIFACT_KINDS - seen_kinds)
    require(
        not missing,
        failures,
        "validated_evidence_manifest missing required artifact kinds: "
        + ", ".join(missing),
    )
    if not missing:
        validate_artifact_semantics(
            artifact_payloads,
            run_id=run_id,
            pilot_id=pilot_id,
            model_identity=model_identity,
            failures=failures,
        )


def main() -> int:
    failures: list[str] = []
    status, _status_hash = read_hashed_json_value(
        STATUS_PATH,
        label="real-device readiness status",
        max_bytes=MAX_MANIFEST_BYTES,
        failures=failures,
    )
    if not isinstance(status, dict):
        if status is not None:
            failures.append("real-device readiness status must be a JSON object")
        for failure in failures:
            print(f"real-device readiness failed: {failure}")
        return 1

    require(
        status.get("schema") == "netdiag-real-device-pilot-readiness/v1",
        failures,
        "real-device readiness schema is missing or unsupported",
    )
    require(
        status.get("status") in {"pending_lab_access", "validated"},
        failures,
        "real-device readiness status must be pending_lab_access or validated",
    )

    if status.get("status") == "pending_lab_access":
        require(
            status.get("real_device_validation") == "not_validated",
            failures,
            "pending lab access must keep real_device_validation=not_validated",
        )
        require(
            status.get("real_device_release_claim_eligible") is False,
            failures,
            "pending lab access must keep real_device_release_claim_eligible=false",
        )
        require(
            bool(status.get("blocking_reason")),
            failures,
            "pending lab access must include a blocking_reason",
        )
        require(
            bool(status.get("required_evidence_before_claim")),
            failures,
            "pending lab access must list required evidence before any validation claim",
        )
        require(
            status.get("validated_evidence_manifest") is None,
            failures,
            "pending lab access must not point at a validated evidence manifest",
        )

        for path in [STATUS_DOC, *DOCS_WITH_STATUS]:
            body = path.read_text().lower()
            relative = path.relative_to(ROOT)
            require(
                "pending_lab_access" in body and "not_validated" in body,
                failures,
                f"{relative} must state pending_lab_access and not_validated",
            )
            for phrase in FORBIDDEN_PENDING_CLAIMS:
                require(
                    phrase not in body,
                    failures,
                    f"{relative} must not claim {phrase!r} while lab access is pending",
                )
    else:
        require(
            status.get("real_device_validation") == "validated",
            failures,
            "validated status must set real_device_validation=validated",
        )
        require(
            status.get("real_device_release_claim_eligible") is True,
            failures,
            "validated status must set real_device_release_claim_eligible=true",
        )
        manifest = status.get("validated_evidence_manifest")
        require(
            isinstance(manifest, str) and bool(manifest.strip()),
            failures,
            "validated status must include validated_evidence_manifest",
        )
        if isinstance(manifest, str) and manifest.strip():
            manifest = manifest.strip()
            try:
                normalized_relative_parts(manifest, "validated_evidence_manifest")
            except ValueError as error:
                failures.append(str(error))
            else:
                validate_real_device_evidence_manifest(manifest, failures)

        for path in [STATUS_DOC, *DOCS_WITH_STATUS]:
            body = path.read_text(encoding="utf-8").lower()
            relative = path.relative_to(ROOT)
            require(
                "validated" in body,
                failures,
                f"{relative} must state validated when real-device evidence is validated",
            )
            require(
                "pending_lab_access" not in body and "not_validated" not in body,
                failures,
                f"{relative} must not state pending_lab_access or not_validated "
                "when real-device evidence is validated",
            )

    if failures:
        for failure in failures:
            print(f"real-device readiness failed: {failure}")
        return 1
    print("real-device readiness passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
