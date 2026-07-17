#!/usr/bin/env python3
"""Guard release quality scripts against smoke-only shortcuts."""

from __future__ import annotations

import ast
import os
import re
import shlex
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
QUALITY_SCRIPT = ROOT / "scripts" / "check_rust_quality.sh"
PACKAGE_SCRIPT = ROOT / "scripts" / "package_macos_app.sh"
PERF_SCRIPT = ROOT / "scripts" / "check_perf_budget.sh"
BENCHMARK_SOURCE = ROOT / "crates" / "netdiag-core" / "src" / "benchmark.rs"
BENCHMARK_ADAPTER_VALIDATION_SOURCE = (
    ROOT / "crates" / "netdiag-core" / "src" / "benchmark" / "adapter_validation.rs"
)
BENCHMARK_ADAPTER_VALIDATION_ROOT = (
    ROOT / "crates" / "netdiag-core" / "src" / "benchmark" / "adapter_validation"
)
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
RELEASE_WORKFLOW = WORKFLOW_DIRECTORY / "release.yml"
CI_WORKFLOW = WORKFLOW_DIRECTORY / "ci.yml"
SCHEMA_REQUIREMENTS_INPUT = ROOT / "requirements-jsonschema.in"
SCHEMA_REQUIREMENTS_LOCK = ROOT / "requirements-jsonschema.lock"
ADAPTER_PROCESS_SOURCE = ROOT / "scripts" / "adapter_process.py"
BENCHMARK_REPORT_PUBLISHER_SOURCE = (
    ROOT / "scripts" / "publish_benchmark_report.py"
)
ADAPTER_VALIDATOR_SOURCES = (
    ROOT / "scripts" / "validate_adapter_samples.py",
    ROOT / "scripts" / "validate_adapter_contract.py",
)
IPERF_ADAPTER_SOURCE = (
    ROOT / "examples" / "adapters" / "iperf3-http-json" / "adapter.py"
)
TC_NETEM_ADAPTER_SOURCE = (
    ROOT / "examples" / "adapters" / "tc-netem-lab" / "adapter.py"
)
REAL_DEVICE_READINESS_SOURCE = ROOT / "scripts" / "check_real_device_readiness.py"
PATCH_PROVENANCE_SOURCE = ROOT / "scripts" / "patch_provenance.py"
SCHEMA_INSTALL_COMMAND = (
    ".venv-jsonschema/bin/python -m pip install --disable-pip-version-check "
    "--only-binary=:all: --require-hashes -r requirements-jsonschema.lock"
)
FORBIDDEN_COVERAGE_OPTIONS = (
    "--ignore-filename-regex",
    "--ignore-run-fail",
    "--no-cfg-coverage",
    "--no-cfg-coverage-nightly",
)
FORBIDDEN_COVERAGE_ENVIRONMENT = (
    "LLVM_COV_FLAGS",
    "CARGO_LLVM_COV_FLAGS",
)
RUSTFLAGS_ENVIRONMENT = (
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
)
DISABLED_COVERAGE_INSTRUMENTATION = re.compile(
    r"-C(?:\s+|=)?instrument-coverage\s*=\s*(?:0|false|no|off)\b",
    re.IGNORECASE,
)
EXPECTED_COVERAGE_PROFILE_FILE_NAME = (
    "LLVM_PROFILE_FILE_NAME=netdiag-%m-%p.profraw"
)
ACTION_USE = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)")
PINNED_ACTION_REF = re.compile(r"[0-9a-f]{40}")
SECRET_REFERENCE = re.compile(r"\$\{\{\s*secrets\.([A-Z][A-Z0-9_]*)\s*\}\}")
VARIABLE_REFERENCE = re.compile(r"\$\{\{\s*vars\.([A-Z][A-Z0-9_]*)\s*\}\}")


def strip_shell_comment(line: str) -> str:
    single_quoted = False
    double_quoted = False
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and not single_quoted:
            escaped = True
            continue
        if char == "'" and not double_quoted:
            single_quoted = not single_quoted
            continue
        if char == '"' and not single_quoted:
            double_quoted = not double_quoted
            continue
        if (
            char == "#"
            and not single_quoted
            and not double_quoted
            and (index == 0 or line[index - 1].isspace())
        ):
            return line[:index]
    return line


def begins_cargo_command(line: str) -> bool:
    try:
        parts = shlex.split(line, posix=True)
    except ValueError:
        return False
    index = 0
    while index < len(parts) and re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*=.*", parts[index]
    ):
        index += 1
    return index < len(parts) and parts[index] == "cargo"


def logical_cargo_commands(body: str) -> list[str]:
    commands: list[str] = []
    current: list[str] = []
    for raw_line in body.splitlines():
        line = strip_shell_comment(raw_line).strip()
        if not line:
            continue
        if current:
            continued = line.endswith("\\")
            current.append(line[:-1].strip() if continued else line)
            if not continued:
                commands.append(" ".join(current))
                current = []
            continue
        continued = line.endswith("\\")
        command_line = line[:-1].strip() if continued else line
        if not begins_cargo_command(command_line):
            continue
        current = [command_line]
        if not continued:
            commands.append(" ".join(current))
            current = []
    if current:
        commands.append(" ".join(current))
    return commands


def uncommented_body(body: str) -> str:
    return "\n".join(strip_shell_comment(line) for line in body.splitlines())


def validate_perf_script_body(body: str, failures: list[str]) -> None:
    active_body = uncommented_body(body)
    if re.search(r"(?m)^\s*(?:command\s+)?rm(?:\s|$)", active_body):
        failures.append(
            "check_perf_budget.sh must delegate artifact cleanup to the owned Rust lifecycle"
        )


def validate_perf_script_hygiene(failures: list[str]) -> None:
    validate_perf_script_body(PERF_SCRIPT.read_text(encoding="utf-8"), failures)


def shell_function_body(body: str, name: str) -> str | None:
    match = re.search(rf"(?m)^\s*{re.escape(name)}\s*\(\s*\)\s*\{{", body)
    if match is None:
        return None
    opening = body.find("{", match.start(), match.end())
    depth = 0
    single_quoted = False
    double_quoted = False
    escaped = False
    for index in range(opening, len(body)):
        char = body[index]
        if escaped:
            escaped = False
            continue
        if char == "\\" and not single_quoted:
            escaped = True
            continue
        if char == "'" and not double_quoted:
            single_quoted = not single_quoted
            continue
        if char == '"' and not single_quoted:
            double_quoted = not double_quoted
            continue
        if single_quoted or double_quoted:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return body[opening + 1 : index]
    return None


def yaml_run_bodies(body: str) -> list[str]:
    """Return literal and one-line run bodies without parsing arbitrary YAML."""

    lines = body.splitlines()
    bodies: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)run:\s*(.*)$", lines[index])
        if match is None:
            index += 1
            continue
        indentation = len(match.group(1))
        value = match.group(2).strip()
        if value not in ("|", ">", "|-", ">-"):
            bodies.append(value)
            index += 1
            continue
        index += 1
        block: list[str] = []
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= indentation:
                break
            block.append(line)
            index += 1
        bodies.append("\n".join(block))
    return bodies


def yaml_job_body(body: str, name: str) -> str | None:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\s*\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*\n|\Z)",
        body,
    )
    return None if match is None else match.group("body")


def validate_schema_requirements(failures: list[str]) -> None:
    expected_input = (
        "jsonschema[format-nongpl]==4.25.1\n"
        'typing-extensions==4.16.0; python_version < "3.13"\n'
    )
    if not SCHEMA_REQUIREMENTS_INPUT.is_file():
        failures.append("schema validator input requirements file is missing")
        return
    if SCHEMA_REQUIREMENTS_INPUT.read_text(encoding="utf-8") != expected_input:
        failures.append("schema validator input must pin the reviewed package and extra exactly")

    if not SCHEMA_REQUIREMENTS_LOCK.is_file():
        failures.append("schema validator hash lock is missing")
        return
    lock_body = SCHEMA_REQUIREMENTS_LOCK.read_text(encoding="utf-8")
    if not lock_body.startswith("# Python schema validation dependency lock.\n"):
        failures.append("schema validator lock must carry the reviewed lock-file header")
    if any(
        fragment in lock_body
        for fragment in ("--index-url", "--find-links", "git+", "http://", "https://")
    ):
        failures.append("schema validator lock must contain only registry names, versions, and hashes")

    pinned: dict[str, int] = {}
    current: str | None = None
    for line in lock_body.splitlines():
        match = re.fullmatch(
            r'([a-z0-9][a-z0-9_.-]*)==([^\\\s;]+)'
            r'( ; python_version < "3\.13")? \\',
            line,
        )
        if match is not None:
            if current is not None and pinned[current] == 0:
                failures.append(f"schema validator dependency {current} has no SHA-256 hash")
            current = match.group(1)
            if current in pinned:
                failures.append(f"schema validator dependency is duplicated: {current}")
            pinned[current] = 0
        elif current is not None and line.strip().startswith("--hash=sha256:"):
            pinned[current] += 1
    if current is not None and pinned[current] == 0:
        failures.append(f"schema validator dependency {current} has no SHA-256 hash")
    if pinned.get("jsonschema") is None or "jsonschema==4.25.1 \\" not in lock_body:
        failures.append("schema validator lock must pin jsonschema 4.25.1")
    if (
        pinned.get("typing-extensions") is None
        or 'typing-extensions==4.16.0 ; python_version < "3.13" \\'
        not in lock_body
    ):
        failures.append(
            "schema validator lock must pin the Python 3.12 typing-extensions dependency"
        )
    if not pinned:
        failures.append("schema validator lock contains no pinned dependencies")


def validate_adapter_process_hygiene(failures: list[str]) -> None:
    sources = (
        ADAPTER_PROCESS_SOURCE,
        *ADAPTER_VALIDATOR_SOURCES,
        IPERF_ADAPTER_SOURCE,
        TC_NETEM_ADAPTER_SOURCE,
    )
    for source in sources:
        body = source.read_text(encoding="utf-8")
        try:
            tree = ast.parse(body, filename=str(source))
        except SyntaxError as error:
            failures.append(f"adapter process source is not valid Python: {source}: {error}")
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            receiver = node.func.value
            if (
                isinstance(receiver, ast.Name)
                and receiver.id == "subprocess"
                and node.func.attr == "run"
            ):
                failures.append(
                    f"adapter process boundary must not use buffering subprocess.run: {source}"
                )
                break

    adapter_process_body = ADAPTER_PROCESS_SOURCE.read_text(encoding="utf-8")
    for fragment in (
        "def run_bounded(",
        "start_new_session=True",
        "stdin=subprocess.DEVNULL",
        "stdout_limit_bytes",
        "stderr_limit_bytes",
        "env=dict(environment)",
        "def validation_python_environment(",
        '[sys.executable, "-I", "-B", str(adapter_path), *args]',
        "def trusted_rust_ingest_validator(",
        'root / "target" / "adapter-validator" / "debug" / "netdiag-cli"',
        "def _directory_chain(",
        "metadata.st_uid not in trusted_owners",
        "Rust ingest validator directory chain must not be group- or world-writable",
        "def _validate_acl_boundary(",
        "os.listxattr(path, follow_symlinks=False)",
        '["/bin/ls", "-lde", *[str(path) for path in paths]]',
        "metadata.st_uid != os.geteuid()",
        "stat.S_IWGRP | stat.S_IWOTH",
        "def validate_rust_ingest(",
        "validator = trusted_rust_ingest_validator(validator, workspace_root)",
        '[str(validator), "validate-trace", str(sample_path)]',
        "environment={},",
        "os.killpg",
        "signal.SIGKILL",
        "payload.decode(\"utf-8\")",
    ):
        if fragment not in adapter_process_body:
            failures.append(
                f"adapter validator subprocess boundary is missing control: {fragment}"
            )
    for source in ADAPTER_VALIDATOR_SOURCES:
        body = source.read_text(encoding="utf-8")
        for fragment in (
            "--rust-validator",
            "trusted_rust_ingest_validator(args.rust_validator, ROOT)",
            "validate_rust_ingest(rust_validator, sample_path, ROOT)",
        ):
            if fragment not in body:
                failures.append(
                    f"adapter validator must use the explicit prebuilt Rust boundary: "
                    f"{source}: {fragment}"
                )
        for forbidden in ("shutil.which", '"cargo"', "'cargo'"):
            if forbidden in body:
                failures.append(
                    f"adapter validator must not invoke Cargo during sample validation: "
                    f"{source}: {forbidden}"
                )

    iperf_body = IPERF_ADAPTER_SOURCE.read_text(encoding="utf-8")
    for fragment in (
        "selectors.DefaultSelector()",
        "start_new_session=True",
        "IPERF_STDOUT_LIMIT_BYTES",
        "IPERF_STDERR_LIMIT_BYTES",
        "IPERF_INPUT_LIMIT_BYTES",
        "os.fstat(descriptor)",
        "object_pairs_hook=strict_json_object",
        "parse_constant=reject_json_constant",
        "def normalized_timestamp(",
        "record_from_iperf(payload, args.udp)",
        'env={"PATH": executable_directory, "LANG": "C", "LC_ALL": "C"}',
        'stderr_bytes = len(decoded["stderr"].encode("utf-8"))',
        "allow_nan=False",
        "_stop_process_group(process)",
        "payload.decode(\"utf-8\")",
    ):
        if fragment not in iperf_body:
            failures.append(f"live iperf subprocess boundary is missing control: {fragment}")

    tc_netem_body = TC_NETEM_ADAPTER_SOURCE.read_text(encoding="utf-8")
    for fragment in (
        "--apply is unavailable until qdisc identity, verification, and crash-safe rollback are implemented",
        '"status": "ok" if active_change_ok else "error"',
        '"applied": False',
    ):
        if fragment not in tc_netem_body:
            failures.append(
                f"tc/netem adapter is missing its fail-closed mutation control: {fragment}"
            )


def validate_benchmark_report_publisher_hygiene(failures: list[str]) -> None:
    if not BENCHMARK_REPORT_PUBLISHER_SOURCE.is_file():
        failures.append("benchmark report publisher source is missing")
        return
    body = BENCHMARK_REPORT_PUBLISHER_SOURCE.read_text(encoding="utf-8")
    for fragment in (
        "class BenchmarkReportPublicationError(RuntimeError)",
        'EXPECTED_REPORT_FILES = frozenset({"benchmark_report.json", "benchmark_report.md"})',
        "def publish_benchmark_report(source: Path, destination: Path) -> None:",
        "metadata.st_uid != os.geteuid()",
        "stat.S_IWGRP | stat.S_IWOTH",
        "refusing to replace an existing benchmark report archive entry",
        "os.rename(source, destination)",
        "published benchmark report identity changed during publication",
    ):
        if fragment not in body:
            failures.append(
                f"benchmark report publisher is missing fail-closed control: {fragment}"
            )


def validate_release_evidence_input_hygiene(failures: list[str]) -> None:
    readiness_body = REAL_DEVICE_READINESS_SOURCE.read_text(encoding="utf-8")
    for fragment in (
        "read_regular_file_beneath(",
        "normalized_relative_parts(",
        "parse_json_bytes_strict(",
    ):
        if fragment not in readiness_body:
            failures.append(
                f"real-device evidence validation is missing safe input control: {fragment}"
            )

    provenance_body = PATCH_PROVENANCE_SOURCE.read_text(encoding="utf-8")
    for fragment in (
        "read_regular_file(",
        "parse_json_bytes_strict(",
        'mode="r|gz"',
        "for member in bundle:",
        "entry_count > MAX_ARCHIVE_FILES",
    ):
        if fragment not in provenance_body:
            failures.append(
                f"patch provenance validation is missing safe input control: {fragment}"
            )
    if ".getmembers(" in provenance_body:
        failures.append(
            "patch provenance validation must stream archive headers before enforcing limits"
        )


def validate_workflow_hygiene(failures: list[str]) -> None:
    release_body = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    ci_body = CI_WORKFLOW.read_text(encoding="utf-8")
    platform_body = (WORKFLOW_DIRECTORY / "platform-security.yml").read_text(
        encoding="utf-8"
    )
    package_body = PACKAGE_SCRIPT.read_text(encoding="utf-8")
    benchmark_sources = [
        BENCHMARK_SOURCE,
        BENCHMARK_ADAPTER_VALIDATION_SOURCE,
        *sorted(BENCHMARK_ADAPTER_VALIDATION_ROOT.rglob("*.rs")),
    ]
    benchmark_body = "\n".join(
        source.read_text(encoding="utf-8") for source in benchmark_sources
    )

    for workflow in sorted(WORKFLOW_DIRECTORY.glob("*.yml")):
        body = workflow.read_text(encoding="utf-8")
        for target in ACTION_USE.findall(body):
            if target.startswith("./"):
                continue
            if "@" not in target:
                failures.append(
                    f"{workflow.name} action must use a full commit SHA: {target}"
                )
                continue
            _, reference = target.rsplit("@", 1)
            if PINNED_ACTION_REF.fullmatch(reference) is None:
                failures.append(
                    f"{workflow.name} action must use a full commit SHA: {target}"
                )

    for run_body in yaml_run_bodies(release_body):
        if "${{ secrets." in run_body:
            failures.append(
                "release workflow must inject secrets through step env, not run interpolation"
            )
            break

    required_release_fragments = (
        "release_preflight:",
        "group: release-${{ github.ref_name }}",
        "cancel-in-progress: false",
        "release workflow accepts tag push events only",
        "Refuse to rebuild an existing release",
        "Require protected release environments",
        ".can_admins_bypass",
        ".prevent_self_review == true",
        ".total_count == 1",
        '.type == "tag" and .name == "v*"',
        "Require release attestation verification support",
        "gh release verify --help",
        "gh release verify-asset --help",
        "release(tagName: \\$tag)",
        "uses: ./.github/workflows/platform-security.yml",
        "needs: release_preflight",
        "needs: [release_preflight, platform_security, macos_compile]",
        "name: release-signing",
        "name: release-publication",
        "name: release-homebrew",
        "name: github-pages",
        "checkout_ref: ${{ needs.release_preflight.outputs.release_sha }}",
        "ref: ${{ needs.release_preflight.outputs.release_sha }}",
        "Verify immutable release checkout",
        "NETDIAG_EXPECTED_BINARY_SHA256",
        "scripts/package_macos_app.sh release --no-build",
        "actions: read",
        "tag_object_type=",
        'refs/remotes/origin/main',
        'actions/workflows/ci.yml/runs',
        "-f branch=main",
        "-f event=push",
        '-f head_sha="$RELEASE_SHA"',
        "-f status=success",
        "umask 077",
        "-T /usr/bin/codesign",
        "Remove signing material",
        "cargo build --locked --release -p netdiag-app",
        "Refuse existing release immediately before publication",
        "Validate fixed release notes",
        "gh release create",
        "--verify-tag",
        '--notes-file "$notes_file"',
        "SHA256SUMS",
        "Verify release provenance before publication",
        "Verify release provenance after publication",
        "compare/$RELEASE_SHA...main",
        ".merge_base_commit.sha",
        "git/tags/$tag_object_sha",
        "Verify published release assets",
        "gh release download",
        "gh release verify \"$RELEASE_TAG\"",
        "gh release verify-asset \"$RELEASE_TAG\"",
        "published-release-notes.md",
        'jq -erj \'.body\'',
        'cmp -- "$SOURCE_DIR/.github/release-notes/$RELEASE_TAG.md" "$published_notes"',
        "verify_release:",
        "attestations: read",
        "--json tagName,isImmutable,isDraft,isPrerelease",
        "(.isImmutable | tostring)",
        '[[ "$is_immutable" == "true" ]]',
        "published release is not immutable",
        "if: ${{ always() && !cancelled() && needs.macos_build.result == 'success' && (needs.publish_release.result == 'success' || needs.publish_release.result == 'failure') }}",
        "needs: [macos_build, verify_release]",
    )
    for fragment in required_release_fragments:
        if fragment not in release_body:
            failures.append(
                f"release workflow is missing required fail-closed control: {fragment}"
            )
    if "workflow_dispatch:" in release_body:
        failures.append("release workflow must accept tag push events only")
    if "softprops/action-gh-release" in release_body:
        failures.append(
            "release workflow must use atomic gh release creation, not an asset-overwriting action"
        )
    if "--generate-notes" in release_body:
        failures.append(
            "release workflow must publish the reviewed fixed notes file"
        )
    if release_body.count("gh api graphql") < 2 or release_body.count(
        "release(tagName: \\$tag)"
    ) < 2:
        failures.append(
            "release workflow must query for an existing release both before build and immediately before publication"
        )
    if release_body.count("needs: [macos_build, verify_release]") < 2:
        failures.append(
            "Pages and Homebrew publication must both depend on read-only release verification"
        )
    verify_release_body = yaml_job_body(release_body, "verify_release")
    if verify_release_body is None:
        failures.append("release workflow must define a verify_release job")
    else:
        if "attestations: read" not in verify_release_body:
            failures.append(
                "verify_release must have read permission for release attestations"
            )
        for fragment in (
            "--json tagName,isImmutable,isDraft,isPrerelease",
            "(.isImmutable | tostring)",
            '[[ "$is_immutable" == "true" ]]',
            "published release is not immutable",
        ):
            if fragment not in verify_release_body:
                failures.append(
                    "verify_release must reject a published mutable release: "
                    f"{fragment}"
                )
    if yaml_job_body(release_body, "validate_secrets") is not None:
        failures.append(
            "release workflow must validate only the secrets required by each protected job"
        )
    macos_compile_body = yaml_job_body(release_body, "macos_compile")
    macos_build_body = yaml_job_body(release_body, "macos_build")
    for job_name, job_body in (
        ("macos_compile", macos_compile_body),
        ("macos_build", macos_build_body),
    ):
        if job_body is None:
            failures.append(f"release workflow must define a {job_name} job")
        elif job_body.count("actions/checkout@") != 1:
            failures.append(
                f"{job_name} must perform exactly one immutable release SHA checkout"
            )
        elif (
            job_body.count(
                "ref: ${{ needs.release_preflight.outputs.release_sha }}"
            )
            != 1
        ):
            failures.append(
                f"{job_name} must checkout the exact validated release SHA"
            )
    if macos_compile_body is not None and "${{ secrets." in macos_compile_body:
        failures.append("macos_compile must not receive release secrets")
    if macos_build_body is not None:
        if "environment:\n      name: release-signing" not in macos_build_body:
            failures.append("macos_build must use the release-signing environment")
        if any(
            logical_cargo_commands(uncommented_body(run_body))
            for run_body in yaml_run_bodies(macos_build_body)
        ):
            failures.append("macos_build signing job must not execute Cargo")
        if any(
            re.search(
                r"(?m)^\s*git\s+(?:checkout|switch|reset|restore|clean)\b",
                uncommented_body(run_body),
            )
            for run_body in yaml_run_bodies(macos_build_body)
        ):
            failures.append(
                "macos_build signing job must not mutate its immutable checkout"
            )
    publish_homebrew_body = yaml_job_body(release_body, "publish_homebrew")
    if publish_homebrew_body is None:
        failures.append("release workflow must define a publish_homebrew job")
    elif "environment:\n      name: release-homebrew" not in publish_homebrew_body:
        failures.append(
            "publish_homebrew must use the release-homebrew environment"
        )
    elif publish_homebrew_body.count(
        "${{ secrets.HOMEBREW_TAP_TOKEN }}"
    ) != 1:
        failures.append(
            "publish_homebrew must expose its PAT only to the final push step"
        )
    elif publish_homebrew_body.find(
        "${{ secrets.HOMEBREW_TAP_TOKEN }}"
    ) < publish_homebrew_body.find("Fast-forward the audited cask"):
        failures.append(
            "publish_homebrew must expose its PAT only to the final push step"
        )
    if publish_homebrew_body is not None:
        for fragment in (
            "Verify exact remote cask bytes without executing tap content",
            'bash "$SOURCE_DIR/scripts/render_homebrew_cask.sh"',
            'git -C "$TAP_DIR" read-tree "$TAP_PARENT_SHA"',
            'git -C "$TAP_DIR" hash-object -w "$candidate"',
            "git -C \"$TAP_DIR\" update-index --add",
            'git -C "$TAP_DIR" write-tree',
            'git -C "$TAP_DIR" commit-tree',
            'git -C "$TAP_DIR" ls-remote --exit-code origin',
            '[[ "$remote_sha" == "$EXPECTED_TAP_SHA" ]]',
            'git -C "$TAP_DIR" show "$EXPECTED_TAP_SHA:Casks/netdiag-twin.rb"',
            'cmp -- "$RUNNER_TEMP/netdiag-twin.rb" "$published"',
        ):
            if fragment not in publish_homebrew_body:
                failures.append(
                    "publish_homebrew must re-read and exactly verify the remote tap: "
                    f"{fragment}"
                )
        if re.search(
            r"(?m)^\s*(?:brew|ruby)\b",
            uncommented_body(publish_homebrew_body),
        ):
            failures.append(
                "publish_homebrew must not execute Homebrew tap content or Ruby"
            )
    publish_release_body = yaml_job_body(release_body, "publish_release")
    atomic_publish_body = None
    if publish_release_body is None:
        failures.append("release workflow must define a publish_release job")
    else:
        if "environment:\n      name: release-publication" not in publish_release_body:
            failures.append(
                "publish_release must use the release-publication environment"
            )
        atomic_publish_body = next(
            (
                run_body
                for run_body in yaml_run_bodies(publish_release_body)
                if "gh release create" in run_body
            ),
            None,
        )
    if atomic_publish_body is None:
        failures.append("publish_release must contain an atomic release creation command")
    else:
        for fragment in (
            "git/ref/tags/$RELEASE_TAG",
            "git/tags/$tag_object_sha",
            '[[ "$tag_target_sha" == "$RELEASE_SHA" ]]',
        ):
            if fragment not in atomic_publish_body:
                failures.append(
                    "atomic release creation must revalidate the annotated tag "
                    f"immediately before publication: {fragment}"
                )

    publish_pages_body = yaml_job_body(release_body, "publish_pages")
    if publish_pages_body is None:
        failures.append("release workflow must define a publish_pages job")
    else:
        for fragment in (
            "environment:\n      name: github-pages",
            "url: ${{ steps.deployment.outputs.page_url }}",
            "id: deployment",
            "for attempt in $(seq 1 30)",
            "?release=$cache_buster",
            "cmp -s -- target/release/appcast.xml",
            "cmp -- target/release/appcast.xml",
        ):
            if fragment not in publish_pages_body:
                failures.append(
                    "publish_pages must deploy and exactly verify the Pages artifact: "
                    f"{fragment}"
                )

    expected_job_secrets = {
        "macos_build": {
            "NETDIAG_CODESIGN_P12_BASE64",
            "NETDIAG_CODESIGN_P12_PASSWORD",
            "NETDIAG_NOTARY_KEY_P8_BASE64",
            "SPARKLE_PRIVATE_KEY",
        },
        "publish_homebrew": {"HOMEBREW_TAP_TOKEN"},
    }
    expected_job_variables = {
        "macos_build": {
            "CODESIGN_IDENTITY",
            "NETDIAG_NOTARY_ISSUER",
            "NETDIAG_NOTARY_KEY_ID",
            "NETDIAG_NOTARY_PROFILE",
            "NETDIAG_SPARKLE_PUBLIC_KEY",
        },
    }
    for job_name in re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", release_body):
        job_body = yaml_job_body(release_body, job_name)
        if job_body is None:
            continue
        actual_secrets = set(SECRET_REFERENCE.findall(job_body))
        expected_secrets = expected_job_secrets.get(job_name, set())
        if actual_secrets != expected_secrets:
            failures.append(
                f"{job_name} secret scope mismatch: "
                f"expected={sorted(expected_secrets)} actual={sorted(actual_secrets)}"
            )
        actual_variables = set(VARIABLE_REFERENCE.findall(job_body))
        expected_variables = expected_job_variables.get(job_name, set())
        if actual_variables != expected_variables:
            failures.append(
                f"{job_name} variable scope mismatch: "
                f"expected={sorted(expected_variables)} actual={sorted(actual_variables)}"
            )

    if "uses: ./.github/workflows/platform-security.yml" not in ci_body:
        failures.append("CI must call the reusable native platform security workflow")
    workflow_hygiene_body = yaml_job_body(ci_body, "workflow-hygiene") or ""
    required_workflow_hygiene_python = (
        "python3 -m venv --clear --copies .venv-jsonschema",
        SCHEMA_INSTALL_COMMAND,
        ".venv-jsonschema/bin/python -W error::ResourceWarning scripts/test_quality_guards.py",
    )
    for fragment in required_workflow_hygiene_python:
        if fragment not in workflow_hygiene_body:
            failures.append(
                f"workflow-hygiene must run quality guards with the locked schema environment: {fragment}"
            )
    if ci_body.count("python3 -m venv --clear --copies .venv-jsonschema") < 3:
        failures.append(
            "CI schema environments must use regular-file venv interpreter copies"
        )
    if ci_body.count(SCHEMA_INSTALL_COMMAND) != 3:
        failures.append(
            "CI schema environments must install the reviewed binary-only hash lock exactly"
        )
    adapter_schema_body = yaml_job_body(ci_body, "adapter-schema") or ""
    required_adapter_schema_fragments = (
        "CARGO_TARGET_DIR: ${{ github.workspace }}/target/adapter-validator",
        "cargo build --locked --quiet -p netdiag-cli --bin netdiag-cli",
        '.venv-jsonschema/bin/python scripts/validate_adapter_samples.py --rust-validator "$CARGO_TARGET_DIR/debug/netdiag-cli"',
        '.venv-jsonschema/bin/python scripts/validate_adapter_contract.py --rust-validator "$CARGO_TARGET_DIR/debug/netdiag-cli"',
    )
    for fragment in required_adapter_schema_fragments:
        if fragment not in adapter_schema_body:
            failures.append(
                f"adapter-schema must prebuild and reuse the trusted Rust validator: {fragment}"
            )
    if all(
        fragment in adapter_schema_body for fragment in required_adapter_schema_fragments
    ):
        adapter_schema_indexes = [
            adapter_schema_body.index(fragment)
            for fragment in required_adapter_schema_fragments
        ]
        if adapter_schema_indexes != sorted(adapter_schema_indexes):
            failures.append(
                "adapter-schema must build the trusted Rust validator before both validation passes"
            )
    rust_ci_body = yaml_job_body(ci_body, "rust") or ""
    strict_step = rust_ci_body.find("id: strict_quality")
    success_upload = rust_ci_body.find("- name: Upload successful benchmark report")
    failure_upload = rust_ci_body.find("- name: Upload failed benchmark diagnostics")
    if min(strict_step, success_upload, failure_upload) < 0 or not (
        strict_step < success_upload < failure_upload
    ):
        failures.append(
            "CI must order the strict gate before separate successful and failed benchmark uploads"
        )
    else:
        success_upload_body = rust_ci_body[success_upload:failure_upload]
        failure_upload_body = rust_ci_body[failure_upload:]
        for fragment in (
            "steps.strict_quality.outcome == 'success'",
            "path: target/benchmark-reports",
            "if-no-files-found: error",
        ):
            if fragment not in success_upload_body:
                failures.append(
                    f"CI successful benchmark upload is missing: {fragment}"
                )
        for fragment in (
            "steps.strict_quality.outcome == 'failure'",
            "target/pilot-smoke.*/benchmark-report",
            "target/benchmark-reports/pilot-smoke.*",
            "if-no-files-found: ignore",
        ):
            if fragment not in failure_upload_body:
                failures.append(
                    f"CI failed benchmark diagnostics upload is missing: {fragment}"
                )
    if "ref: ${{ inputs.checkout_ref || github.sha }}" not in platform_body:
        failures.append(
            "platform security workflow must checkout the immutable caller revision"
        )
    if "Verify immutable checkout" not in platform_body:
        failures.append(
            "platform security workflow must verify the immutable caller revision"
        )
    if "components: rustfmt, clippy" not in rust_ci_body:
        failures.append(
            "strict CI must install rustfmt and clippy before running the quality gate"
        )
    for fragment in (
        "mktemp -d /tmp/netdiag-platform-security.XXXXXX",
        'chmod 700 "$trusted_root"',
        'git clone --quiet --no-local "$GITHUB_WORKSPACE" "$trusted_root/repo"',
        '[[ "$actual_sha" == "$EXPECTED_SHA" ]]',
        'rm -rf -- "$trusted_root"',
        "cargo test --locked -p netdiag-platform -p netdiag-core -p netdiag-cli -p netdiag-app --all-targets --all-features",
    ):
        if fragment not in platform_body:
            failures.append(
                f"Linux platform tests are missing trusted-checkout control: {fragment}"
            )

    required_package_fragments = (
        'BUILD_MODE="${2:-build}"',
        'if [[ "$BUILD_MODE" == "--no-build" ]]',
        'EXPECTED_BINARY_SHA256="${NETDIAG_EXPECTED_BINARY_SHA256:-}"',
        "release binary checksum mismatch before packaging",
        "release binary checksum mismatch immediately before signing",
        'rm -rf "$SPARKLE_WORK"',
        'elif [[ "$PROFILE" == "release" ]]',
        "cargo build --locked --release -p netdiag-app",
    )
    for fragment in required_package_fragments:
        if fragment not in package_body:
            failures.append(
                f"macOS packaging script is missing sealed no-build control: {fragment}"
            )
    if 'if [[ ! -d "$SPARKLE_FRAMEWORK" ]]' in package_body:
        failures.append(
            "macOS packaging must always recreate Sparkle from the verified archive"
        )

    forbidden_python_fallbacks = (
        'PathBuf::from("python3")',
        'Command::new("python3")',
    )
    if any(fragment in benchmark_body for fragment in forbidden_python_fallbacks):
        failures.append(
            "benchmark validation must not execute a basename Python interpreter"
        )
    for fragment in (
        '.venv-jsonschema/bin/python',
        "resolve_trusted_python_runtime",
        'BoundedCommand::new(executable)',
        '.args(["-E", "-B", "-s"])',
        'RUST_VALIDATOR_RELATIVE_PATH: &str = "target/adapter-validator/debug/netdiag-cli"',
        ".canonicalize().with_path(&repository_path)?",
        '.arg("--rust-validator")',
        '("PATH", runtime_path)',
        '("PYTHONNOUSERSITE", "1")',
        '("PYTHONDONTWRITEBYTECODE", "1")',
    ):
        if fragment not in benchmark_body:
            failures.append(
                f"benchmark validation is missing trusted Python control: {fragment}"
            )
    if '.arg("--schema-only")' in benchmark_body:
        failures.append(
            "benchmark validation must not bypass Rust ingest with --schema-only"
        )

    ordered_steps = (
        "Validate release provenance",
        "Require successful CI for the exact main commit",
        "Prepare signing keychain",
        "Import code-signing identity",
        "Store notarization credentials",
        "Build DMG",
        "Validate notarized DMG",
        "Remove signing material",
        "Generate appcast",
        "Upload verified release artifact",
        "Refuse existing release immediately before publication",
        "Publish GitHub Release assets",
    )
    positions = [release_body.find(step) for step in ordered_steps]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        failures.append(
            "release workflow must clean signing material before artifact publication"
        )
    signing_window_start = release_body.find("Prepare signing keychain")
    signing_window_end = release_body.find("Remove signing material")
    if signing_window_start >= 0 and signing_window_end > signing_window_start:
        signing_window = release_body[signing_window_start:signing_window_end]
        forbidden_signing_tools = re.findall(
            r"(?m)^\s*(?:cargo|python[0-9.]*|go|brew)(?:\s|$)", signing_window
        )
        if forbidden_signing_tools:
            failures.append(
                "release signing window must not execute build or package-manager tools"
            )
        for unnecessary_acl in ("-T /usr/bin/productsign", "-T /usr/bin/xcrun"):
            if unnecessary_acl in signing_window:
                failures.append(
                    "release signing key ACL grants an unnecessary trusted application: "
                    f"{unnecessary_acl}"
                )


def main() -> int:
    body = QUALITY_SCRIPT.read_text()
    active_body = uncommented_body(body)
    smoke_body = shell_function_body(active_body, "run_pilot_smoke")
    strict_body = shell_function_body(active_body, "run_strict")
    schema_python_body = shell_function_body(active_body, "schema_python")
    adapter_contract_body = shell_function_body(active_body, "run_adapter_contracts")
    commands = logical_cargo_commands(smoke_body or "")
    calibrate_indexes = [
        index for index, command in enumerate(commands) if "lab calibrate" in command
    ]
    benchmark_indexes = [
        index for index, command in enumerate(commands) if "benchmark run" in command
    ]
    model_gate_indexes = [
        index for index, command in enumerate(commands) if "pilot model-gate" in command
    ]
    failures: list[str] = []
    validate_schema_requirements(failures)
    validate_adapter_process_hygiene(failures)
    validate_benchmark_report_publisher_hygiene(failures)
    validate_perf_script_hygiene(failures)
    validate_release_evidence_input_hygiene(failures)
    validate_workflow_hygiene(failures)
    if schema_python_body is None:
        failures.append("check_rust_quality.sh must define schema_python")
    else:
        for fragment in (
            '.venv-jsonschema/bin/python',
            '[[ ! -f "$interpreter" || -L "$interpreter" || ! -x "$interpreter" ]]',
        ):
            if fragment not in schema_python_body:
                failures.append(
                    f"check_rust_quality.sh schema_python is missing fail-closed control: {fragment}"
                )
        if re.search(r'(?m)^\s*(?:echo|printf)\s+["\']?python3\b', schema_python_body):
            failures.append(
                "check_rust_quality.sh schema_python must not fall back to basename python3"
            )
    if adapter_contract_body is None:
        failures.append("check_rust_quality.sh must define run_adapter_contracts")
    else:
        required_adapter_contract_fragments = (
            'validator_target_dir="$ROOT/target/adapter-validator"',
            'CARGO_TARGET_DIR="$validator_target_dir" cargo build --locked --quiet',
            "-p netdiag-cli --bin netdiag-cli",
            'scripts/validate_adapter_samples.py --rust-validator "$validator"',
            'scripts/validate_adapter_contract.py --rust-validator "$validator"',
        )
        for fragment in required_adapter_contract_fragments:
            if fragment not in adapter_contract_body:
                failures.append(
                    "check_rust_quality.sh run_adapter_contracts must prebuild and "
                    f"reuse the trusted Rust validator: {fragment}"
                )
        if adapter_contract_body.count("cargo build") != 1:
            failures.append(
                "check_rust_quality.sh run_adapter_contracts must build the Rust validator exactly once"
            )
        if all(
            fragment in adapter_contract_body
            for fragment in required_adapter_contract_fragments
        ):
            adapter_contract_indexes = [
                adapter_contract_body.index(fragment)
                for fragment in required_adapter_contract_fragments
            ]
            if adapter_contract_indexes != sorted(adapter_contract_indexes):
                failures.append(
                    "check_rust_quality.sh must build the Rust validator before both validation passes"
                )
    for variable in FORBIDDEN_COVERAGE_ENVIRONMENT:
        if os.environ.get(variable):
            failures.append(
                f"coverage environment override {variable} must be unset for the strict gate"
            )
    for variable in RUSTFLAGS_ENVIRONMENT:
        value = os.environ.get(variable, "").replace("\x1f", " ")
        if DISABLED_COVERAGE_INSTRUMENTATION.search(value):
            failures.append(
                f"coverage instrumentation must not be disabled through {variable}"
            )
    if DISABLED_COVERAGE_INSTRUMENTATION.search(active_body):
        failures.append(
            "check_rust_quality.sh must not disable rustc coverage instrumentation"
        )
    for command in logical_cargo_commands(active_body):
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError as exc:
            failures.append(f"could not parse cargo command for coverage hygiene: {exc}")
            continue
        try:
            cargo_index = tokens.index("cargo")
        except ValueError:
            continue
        if tokens[cargo_index + 1 : cargo_index + 3] != ["llvm-cov", "nextest"]:
            continue
        if EXPECTED_COVERAGE_PROFILE_FILE_NAME not in tokens[:cargo_index]:
            failures.append(
                "check_rust_quality.sh strict coverage must isolate raw profiles "
                "inside its owned coverage target directory"
            )
        for option in FORBIDDEN_COVERAGE_OPTIONS:
            if any(token == option or token.startswith(f"{option}=") for token in tokens):
                failures.append(
                    "check_rust_quality.sh strict coverage must not use "
                    f"report-suppressing option {option}"
                )
    if smoke_body is None:
        failures.append(
            "check_rust_quality.sh must define a parseable run_pilot_smoke function"
        )
    else:
        for fragment in (
            'benchmark_report_archive="$ROOT/target/benchmark-reports"',
            'published_benchmark_report="$benchmark_report_archive/${workspace##*/}"',
            "python3 scripts/publish_benchmark_report.py",
            '"$benchmark_report" "$published_benchmark_report"',
        ):
            if fragment not in smoke_body:
                failures.append(
                    f"check_rust_quality.sh pilot smoke report publication is missing: {fragment}"
                )
        model_gate_position = smoke_body.find("pilot model-gate")
        publication_position = smoke_body.find(
            "python3 scripts/publish_benchmark_report.py"
        )
        cleanup_position = smoke_body.rfind("\n  cleanup_pilot_smoke")
        if min(model_gate_position, publication_position, cleanup_position) < 0 or not (
            model_gate_position < publication_position < cleanup_position
        ):
            failures.append(
                "check_rust_quality.sh must publish the benchmark report after model-gate and before cleanup"
            )
    if strict_body is None:
        failures.append("check_rust_quality.sh must define a parseable run_strict function")
    else:
        adapter_contract_match = re.search(
            r"(?m)^\s*run_adapter_contracts(?:\s*(?:;|$))", strict_body
        )
        pilot_smoke_match = re.search(
            r"(?m)^\s*run_pilot_smoke(?:\s*(?:;|$))", strict_body
        )
        if pilot_smoke_match is None:
            failures.append(
                "check_rust_quality.sh run_strict must invoke run_pilot_smoke"
            )
        if adapter_contract_match is None:
            failures.append(
                "check_rust_quality.sh run_strict must build and validate the Rust adapter boundary"
            )
        elif pilot_smoke_match is not None and (
            adapter_contract_match.start() > pilot_smoke_match.start()
        ):
            failures.append(
                "check_rust_quality.sh run_strict must build the Rust adapter validator before pilot smoke"
            )
        strict_commands = logical_cargo_commands(strict_body)
        if not any(
            "cargo test --locked -p netdiag-core --bench perf_budget --all-features"
            in command
            for command in strict_commands
        ):
            failures.append(
                "check_rust_quality.sh strict must execute the performance benchmark target"
            )
        app_coverage_commands = []
        for command in strict_commands:
            try:
                tokens = shlex.split(command, posix=True)
                cargo_index = tokens.index("cargo")
            except (ValueError, IndexError):
                continue
            if tokens[cargo_index + 1 : cargo_index + 3] != ["llvm-cov", "nextest"]:
                continue
            if any(
                tokens[index : index + 2] == ["-p", "netdiag-app"]
                for index in range(len(tokens) - 1)
            ):
                app_coverage_commands.append(tokens[cargo_index + 3 :])
        if len(app_coverage_commands) != 1:
            failures.append(
                "check_rust_quality.sh strict must execute exactly one netdiag-app llvm-cov nextest command"
            )
        else:
            app_coverage = app_coverage_commands[0]
            for option in ("--locked", "--all-features", "--lib", "--bins", "--tests"):
                if option not in app_coverage:
                    failures.append(
                        "check_rust_quality.sh netdiag-app coverage command is missing "
                        f"{option}"
                    )
            if "--workspace" in app_coverage:
                failures.append(
                    "check_rust_quality.sh netdiag-app security coverage must remain an independent package gate"
                )
        if "python3 scripts/check_app_security_coverage.py" not in strict_body:
            failures.append(
                "check_rust_quality.sh strict must validate netdiag-app security coverage"
            )
    if '"schema": "netdiag-lab-calibration/' in active_body:
        failures.append(
            "check_rust_quality.sh must not handwrite lab_calibration_report.json"
        )
    if any("--allow-missing-evaluation" in command for command in commands):
        failures.append(
            "check_rust_quality.sh strict pilot smoke must not bypass evaluation gates"
        )
    for command in commands:
        try:
            tokens = shlex.split(command, posix=True)
            cargo_index = tokens.index("cargo")
        except (ValueError, IndexError):
            continue
        if cargo_index + 1 >= len(tokens) or tokens[cargo_index + 1] != "run":
            continue
        separator = tokens.index("--") if "--" in tokens else len(tokens)
        if "--locked" not in tokens[cargo_index + 2 : separator]:
            failures.append(
                "every cargo run in check_rust_quality.sh run_pilot_smoke must use --locked"
            )
            break
    if not calibrate_indexes:
        failures.append("check_rust_quality.sh strict pilot smoke must run lab calibrate")
    if not model_gate_indexes:
        failures.append("check_rust_quality.sh strict pilot smoke must run pilot model-gate")
    if not benchmark_indexes:
        failures.append("check_rust_quality.sh strict pilot smoke must run benchmark run")
    for index in benchmark_indexes:
        command = commands[index]
        if "--model-dir" not in command:
            failures.append(
                "check_rust_quality.sh strict benchmark run must use --model-dir"
            )
            break
    if calibrate_indexes and benchmark_indexes and model_gate_indexes:
        if not calibrate_indexes[0] < benchmark_indexes[0] < model_gate_indexes[0]:
            failures.append(
                "check_rust_quality.sh strict promotion flow must order lab calibrate "
                "before benchmark run before pilot model-gate"
            )

    if failures:
        for failure in failures:
            print(f"release gate hygiene failed: {failure}")
        return 1
    print("release gate hygiene passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
