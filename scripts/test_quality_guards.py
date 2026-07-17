#!/usr/bin/env python3
"""Unit tests for release hygiene guard scripts."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load script {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_module_path(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load module {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_main(module: ModuleType) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = module.main()
    return code, stdout.getvalue(), stderr.getvalue()


class StrictJsonBoundaryTests(unittest.TestCase):
    def test_strict_json_rejects_duplicate_non_finite_and_oversized_numbers(self) -> None:
        module = load_script("strict_json")
        sentinel = "sensitive-json-sentinel"
        invalid = (
            f'{{"{sentinel}": 1, "{sentinel}": 2}}',
            f'{{"value": NaN, "secret": "{sentinel}"}}',
            f'{{"value": Infinity, "secret": "{sentinel}"}}',
            f'{{"value": 1e400, "secret": "{sentinel}"}}',
            f'{{"value": -1e400, "secret": "{sentinel}"}}',
            '{"value": ' + "9" * (module.MAX_JSON_NUMBER_CHARACTERS + 1) + "}",
        )
        for document in invalid:
            with self.subTest(document=document[:32]):
                with self.assertRaises(module.StrictJsonError) as raised:
                    module.parse_json_strict(document, source="release evidence")
                self.assertNotIn(sentinel, str(raised.exception))

        maximum_integer = "9" * module.MAX_JSON_NUMBER_CHARACTERS
        parsed = module.parse_json_strict(
            '{"value": ' + maximum_integer + "}", source="release evidence"
        )
        self.assertEqual(parsed["value"], int(maximum_integer))

    def test_strict_json_bytes_reject_invalid_utf8_without_echoing_input(self) -> None:
        module = load_script("strict_json")
        with self.assertRaises(module.StrictJsonError) as raised:
            module.parse_json_bytes_strict(
                b'{"secret":"\xffsensitive-byte-sentinel"}',
                source="release evidence",
            )
        self.assertNotIn("sensitive-byte-sentinel", str(raised.exception))


class ReleaseGateHygieneTests(unittest.TestCase):
    def test_perf_script_hygiene_rejects_injectable_recursive_cleanup(self) -> None:
        module = load_script("check_release_gate_hygiene")
        dangerous = """\
ARTIFACTS="${NETDIAG_PERF_ARTIFACTS:-/tmp/perf-artifacts}"
rm -rf "$ARTIFACTS"
"""
        failures: list[str] = []

        module.validate_perf_script_body(dangerous, failures)

        self.assertEqual(len(failures), 1)
        self.assertIn("owned Rust lifecycle", failures[0])

    def test_perf_script_hygiene_accepts_rust_managed_artifacts(self) -> None:
        module = load_script("check_release_gate_hygiene")
        failures: list[str] = []

        module.validate_perf_script_hygiene(failures)

        self.assertEqual(failures, [])

    def test_workflow_hygiene_requires_locked_python_quality_environment(self) -> None:
        module = load_script("check_release_gate_hygiene")
        with tempfile.TemporaryDirectory() as tmp:
            workflow_directory = Path(tmp) / "workflows"
            workflow_directory.mkdir()
            for name in ("release.yml", "platform-security.yml"):
                (workflow_directory / name).write_text(
                    (REPO_ROOT / ".github/workflows" / name).read_text(
                        encoding="utf-8"
                    ),
                    encoding="utf-8",
                )
            ci_body = (REPO_ROOT / ".github/workflows/ci.yml").read_text(
                encoding="utf-8"
            )
            (workflow_directory / "ci.yml").write_text(
                ci_body.replace(
                    ".venv-jsonschema/bin/python -W error::ResourceWarning scripts/test_quality_guards.py",
                    "python3 scripts/test_quality_guards.py",
                    1,
                ),
                encoding="utf-8",
            )
            module.WORKFLOW_DIRECTORY = workflow_directory
            module.RELEASE_WORKFLOW = workflow_directory / "release.yml"
            module.CI_WORKFLOW = workflow_directory / "ci.yml"
            code, stdout, stderr = run_main(module)

        self.assertNotEqual(code, 0)
        self.assertIn("locked schema environment", stdout + stderr)

    def test_private_credential_file_patterns_are_ignored(self) -> None:
        required_patterns = ("*.p8", "*.pfx", "*.pem", "*.key")
        samples = (
            "release/AuthKey.p8",
            "release/signing.pfx",
            "release/private.pem",
            "release/signing.key",
        )
        ignore_body = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        configured_patterns = {
            line.strip()
            for line in ignore_body.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        for pattern in required_patterns:
            self.assertIn(pattern, configured_patterns)

        with tempfile.TemporaryDirectory() as tmp:
            repository = Path(tmp)
            (repository / ".gitignore").write_text(ignore_body, encoding="utf-8")
            subprocess.run(
                ["git", "init", "--quiet"],
                cwd=repository,
                check=True,
                capture_output=True,
                text=True,
            )
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    f"core.excludesFile={os.devnull}",
                    "check-ignore",
                    "--no-index",
                    "--stdin",
                ],
                cwd=repository,
                input="\n".join(samples) + "\n",
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(tuple(result.stdout.splitlines()), samples)

    def test_coverage_runtime_artifacts_are_ignored(self) -> None:
        ignore_body = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        configured_patterns = {
            line.strip()
            for line in ignore_body.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertTrue({"*.profraw", "*.profdata"} <= configured_patterns)

    def test_build_output_ignores_do_not_hide_source_modules(self) -> None:
        ignore_body = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        configured_patterns = {
            line.strip()
            for line in ignore_body.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertIn("/target/", configured_patterns)
        self.assertIn("/crates/*/target/", configured_patterns)
        self.assertNotIn("target/", configured_patterns)

        samples = (
            "target/debug/netdiag",
            "crates/netdiag-core/target/debug/netdiag",
            "crates/netdiag-core/src/storage/atomic_file/target/binding.rs",
        )
        with tempfile.TemporaryDirectory() as tmp:
            repository = Path(tmp)
            (repository / ".gitignore").write_text(ignore_body, encoding="utf-8")
            subprocess.run(
                ["git", "init", "--quiet"],
                cwd=repository,
                check=True,
                capture_output=True,
                text=True,
            )
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    f"core.excludesFile={os.devnull}",
                    "check-ignore",
                    "--no-index",
                    "--stdin",
                ],
                cwd=repository,
                input="\n".join(samples) + "\n",
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(tuple(result.stdout.splitlines()), samples[:2])

    def test_architecture_budgeted_sources_must_exist_in_the_git_index(self) -> None:
        guard_body = (REPO_ROOT / "scripts/check_architecture_guard.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'git -C "$ROOT" ls-files --error-unmatch -- "$path"', guard_body
        )
        self.assertIn(
            'architecture guard failed: $path is absent from the Git index', guard_body
        )

    def run_release_guard(self, body: str) -> tuple[int, str]:
        module = load_script("check_release_gate_hygiene")
        if "schema_python" not in body:
            body = (
                'schema_python() {\n'
                '  local interpreter=".venv-jsonschema/bin/python"\n'
                '  if [[ ! -f "$interpreter" || -L "$interpreter" || ! -x "$interpreter" ]]; then\n'
                "    return 2\n"
                "  fi\n"
                "  printf '%s\\n' \"$interpreter\"\n"
                "}\n"
                + body
            )
        if "run_adapter_contracts" not in body:
            body = (
                "run_adapter_contracts() {\n"
                "  local validator_target_dir\n"
                '  validator_target_dir="$ROOT/target/adapter-validator"\n'
                '  local validator="$validator_target_dir/debug/netdiag-cli"\n'
                '  CARGO_TARGET_DIR="$validator_target_dir" cargo build --locked --quiet \\\n'
                "    -p netdiag-cli --bin netdiag-cli\n"
                '  scripts/validate_adapter_samples.py --rust-validator "$validator"\n'
                '  scripts/validate_adapter_contract.py --rust-validator "$validator"\n'
                "}\n"
                + body
            )
        if "run_strict" not in body:
            body = (
                f"run_pilot_smoke() {{\n{body}\n"
                '  benchmark_report_archive="$ROOT/target/benchmark-reports"\n'
                '  published_benchmark_report="$benchmark_report_archive/${workspace##*/}"\n'
                "  python3 scripts/publish_benchmark_report.py \\\n"
                '    "$benchmark_report" "$published_benchmark_report"\n'
                "  cleanup_pilot_smoke\n"
                "}\n"
                "run_strict() {\n"
                "  cargo test --locked -p netdiag-core --bench perf_budget --all-features\n"
                '  LLVM_PROFILE_FILE_NAME="netdiag-%m-%p.profraw" cargo llvm-cov nextest --locked -p netdiag-app --all-features --lib --bins --tests\n'
                "  python3 scripts/check_app_security_coverage.py --summary app.json --dep-info-dir deps --aggregate-min 80 --file-min 50\n"
                "  run_adapter_contracts\n"
                "  run_pilot_smoke\n"
                "}\n"
            )
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "check_rust_quality.sh"
            script.write_text(body)
            module.QUALITY_SCRIPT = script
            code, stdout, stderr = run_main(module)
        return code, stdout + stderr

    def run_workflow_guard(
        self,
        transform: Callable[[str], str],
    ) -> tuple[int, str]:
        module = load_script("check_release_gate_hygiene")
        release_body = transform(
            (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflow_directory = Path(tmp) / "workflows"
            workflow_directory.mkdir()
            for name in ("ci.yml", "platform-security.yml"):
                (workflow_directory / name).write_text(
                    (REPO_ROOT / ".github/workflows" / name).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            release_workflow = workflow_directory / "release.yml"
            release_workflow.write_text(release_body, encoding="utf-8")
            module.WORKFLOW_DIRECTORY = workflow_directory
            module.RELEASE_WORKFLOW = release_workflow
            module.CI_WORKFLOW = workflow_directory / "ci.yml"
            code, stdout, stderr = run_main(module)
        return code, stdout + stderr

    def run_package_guard(
        self,
        transform: Callable[[str], str],
    ) -> tuple[int, str]:
        module = load_script("check_release_gate_hygiene")
        package_body = transform(
            (REPO_ROOT / "scripts/package_macos_app.sh").read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as tmp:
            package_script = Path(tmp) / "package_macos_app.sh"
            package_script.write_text(package_body, encoding="utf-8")
            module.PACKAGE_SCRIPT = package_script
            code, stdout, stderr = run_main(module)
        return code, stdout + stderr

    def run_benchmark_guard(
        self,
        transform: Callable[[str], str],
    ) -> tuple[int, str]:
        module = load_script("check_release_gate_hygiene")
        benchmark_body = transform(
            (REPO_ROOT / "crates/netdiag-core/src/benchmark.rs").read_text(
                encoding="utf-8"
            )
        )
        with tempfile.TemporaryDirectory() as tmp:
            benchmark_source = Path(tmp) / "benchmark.rs"
            benchmark_source.write_text(benchmark_body, encoding="utf-8")
            module.BENCHMARK_SOURCE = benchmark_source
            code, stdout, stderr = run_main(module)
        return code, stdout + stderr

    def run_schema_requirements_guard(
        self,
        input_body: str,
        lock_body: str,
    ) -> list[str]:
        module = load_script("check_release_gate_hygiene")
        with tempfile.TemporaryDirectory() as tmp:
            requirements_input = Path(tmp) / "requirements-jsonschema.in"
            requirements_lock = Path(tmp) / "requirements-jsonschema.lock"
            requirements_input.write_text(input_body, encoding="utf-8")
            requirements_lock.write_text(lock_body, encoding="utf-8")
            module.SCHEMA_REQUIREMENTS_INPUT = requirements_input
            module.SCHEMA_REQUIREMENTS_LOCK = requirements_lock
            failures: list[str] = []
            module.validate_schema_requirements(failures)
        return failures

    def test_release_workflows_accept_pinned_fail_closed_publication(self) -> None:
        code, output = self.run_workflow_guard(lambda body: body)
        self.assertEqual(code, 0, output)

    def test_release_workflows_reject_movable_action_tags(self) -> None:
        code, output = self.run_workflow_guard(
            lambda body: body.replace(
                "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
                "actions/checkout@v6",
                1,
            )
        )
        self.assertNotEqual(code, 0)
        self.assertIn("full commit SHA", output)

    def test_release_workflows_reject_secret_interpolation_in_run_blocks(self) -> None:
        code, output = self.run_workflow_guard(
            lambda body: body.replace(
                "run: git config --global init.defaultBranch main",
                'run: echo "${{ secrets.CODESIGN_IDENTITY }}"',
                1,
            )
        )
        self.assertNotEqual(code, 0)
        self.assertIn("inject secrets through step env", output)

    def test_release_workflows_reject_unnecessary_signing_key_acl_tools(self) -> None:
        code, output = self.run_workflow_guard(
            lambda body: body.replace(
                "            -T /usr/bin/codesign\n",
                "            -T /usr/bin/codesign \\\n"
                "            -T /usr/bin/xcrun\n",
                1,
            )
        )
        self.assertNotEqual(code, 0)
        self.assertIn("unnecessary trusted application", output)

    def test_strict_gate_requires_performance_benchmark_target(self) -> None:
        module = load_script("check_release_gate_hygiene")
        quality_body = (REPO_ROOT / "scripts/check_rust_quality.sh").read_text(
            encoding="utf-8"
        )
        with tempfile.TemporaryDirectory() as tmp:
            quality = Path(tmp) / "check_rust_quality.sh"
            quality.write_text(
                quality_body.replace(
                    "  cargo test --locked -p netdiag-core --bench perf_budget --all-features\n",
                    "",
                    1,
                ),
                encoding="utf-8",
            )
            module.QUALITY_SCRIPT = quality
            code, stdout, stderr = run_main(module)
        self.assertNotEqual(code, 0)
        self.assertIn("performance benchmark target", stdout + stderr)

    def test_strict_coverage_requires_owned_raw_profile_paths(self) -> None:
        module = load_script("check_release_gate_hygiene")
        quality_body = (REPO_ROOT / "scripts/check_rust_quality.sh").read_text(
            encoding="utf-8"
        )
        with tempfile.TemporaryDirectory() as tmp:
            quality = Path(tmp) / "check_rust_quality.sh"
            quality.write_text(
                quality_body.replace(
                    'LLVM_PROFILE_FILE_NAME="netdiag-%m-%p.profraw" ',
                    "",
                    1,
                ),
                encoding="utf-8",
            )
            module.QUALITY_SCRIPT = quality
            code, stdout, stderr = run_main(module)
        self.assertNotEqual(code, 0)
        self.assertIn("must isolate raw profiles", stdout + stderr)

    def test_ci_schema_virtual_environments_require_interpreter_copies(self) -> None:
        code, output = self.run_workflow_guard(
            lambda body: body,
        )
        self.assertEqual(code, 0, output)

        module = load_script("check_release_gate_hygiene")
        with tempfile.TemporaryDirectory() as tmp:
            workflow_directory = Path(tmp) / "workflows"
            workflow_directory.mkdir()
            for name in ("release.yml", "platform-security.yml"):
                (workflow_directory / name).write_text(
                    (REPO_ROOT / ".github/workflows" / name).read_text(
                        encoding="utf-8"
                    ),
                    encoding="utf-8",
                )
            ci_body = (REPO_ROOT / ".github/workflows/ci.yml").read_text(
                encoding="utf-8"
            )
            (workflow_directory / "ci.yml").write_text(
                ci_body.replace("venv --clear --copies", "venv --clear"),
                encoding="utf-8",
            )
            module.WORKFLOW_DIRECTORY = workflow_directory
            module.RELEASE_WORKFLOW = workflow_directory / "release.yml"
            module.CI_WORKFLOW = workflow_directory / "ci.yml"
            code, stdout, stderr = run_main(module)
        self.assertNotEqual(code, 0)
        self.assertIn("regular-file venv interpreter copies", stdout + stderr)

    def test_schema_requirements_lock_requires_exact_input_and_per_package_hashes(self) -> None:
        input_body = (REPO_ROOT / "requirements-jsonschema.in").read_text(
            encoding="utf-8"
        )
        lock_body = (REPO_ROOT / "requirements-jsonschema.lock").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            self.run_schema_requirements_guard(input_body, lock_body),
            [],
        )

        first_package_end = lock_body.index("\nattrs==")
        unhashed_first_package = "\n".join(
            line
            for line in lock_body[:first_package_end].splitlines()
            if "--hash=sha256:" not in line
        ) + lock_body[first_package_end:]
        failures = self.run_schema_requirements_guard(
            input_body,
            unhashed_first_package,
        )
        self.assertTrue(
            any("arrow has no SHA-256 hash" in failure for failure in failures),
            failures,
        )

        failures = self.run_schema_requirements_guard(
            "jsonschema[format-nongpl]==4.25.0\n",
            lock_body,
        )
        self.assertTrue(
            any("pin the reviewed package" in failure for failure in failures),
            failures,
        )

        failures = self.run_schema_requirements_guard(
            input_body,
            lock_body.replace(
                'typing-extensions==4.16.0 ; python_version < "3.13"',
                'typing-extensions==4.16.0 ; python_version < "3.12"',
            ),
        )
        self.assertTrue(
            any("Python 3.12 typing-extensions" in failure for failure in failures),
            failures,
        )

    def test_release_workflows_require_exact_sha_ci_and_early_key_cleanup(self) -> None:
        for fragment, expected in (
            ('-f head_sha="$RELEASE_SHA"', "head_sha"),
            ("Remove signing material", "clean signing material"),
        ):
            with self.subTest(fragment=fragment):
                code, output = self.run_workflow_guard(
                    lambda body, fragment=fragment: body.replace(fragment, "")
                )
                self.assertNotEqual(code, 0)
                self.assertIn(expected, output)

    def test_release_secrets_require_provenance_platform_and_environment_gates(
        self,
    ) -> None:
        for fragment in (
            "needs: [release_preflight, platform_security, macos_compile]",
            "name: release-signing",
            "name: release-publication",
            "name: release-homebrew",
        ):
            with self.subTest(fragment=fragment):
                code, output = self.run_workflow_guard(
                    lambda body, fragment=fragment: body.replace(fragment, "")
                )
                self.assertNotEqual(code, 0)
                self.assertIn(fragment, output)

    def test_release_requires_immutable_sha_checkouts_and_revalidation(self) -> None:
        for fragment in (
            "checkout_ref: ${{ needs.release_preflight.outputs.release_sha }}",
            "ref: ${{ needs.release_preflight.outputs.release_sha }}",
            "Verify release provenance before publication",
            "Verify release provenance after publication",
            "compare/$RELEASE_SHA...main",
            ".merge_base_commit.sha",
            "git/tags/$tag_object_sha",
        ):
            with self.subTest(fragment=fragment):
                code, output = self.run_workflow_guard(
                    lambda body, fragment=fragment: body.replace(fragment, "")
                )
                self.assertNotEqual(code, 0)
                self.assertIn(fragment, output)

    def test_release_serializes_versions_and_seals_the_prebuilt_binary(self) -> None:
        for fragment in (
            "group: release-${{ github.ref_name }}",
            "cancel-in-progress: false",
            "Refuse to rebuild an existing release",
            "Require protected release environments",
            ".can_admins_bypass",
            ".prevent_self_review == true",
            ".total_count == 1",
            "Require release attestation verification support",
            "Refuse existing release immediately before publication",
            "NETDIAG_EXPECTED_BINARY_SHA256",
            "scripts/package_macos_app.sh release --no-build",
            "gh release create",
            "--verify-tag",
            "Verify published release assets",
            "gh release verify \"$RELEASE_TAG\"",
            "gh release verify-asset \"$RELEASE_TAG\"",
            "verify_release:",
            "if: ${{ always() && !cancelled() && needs.macos_build.result == 'success' && (needs.publish_release.result == 'success' || needs.publish_release.result == 'failure') }}",
        ):
            with self.subTest(fragment=fragment):
                code, output = self.run_workflow_guard(
                    lambda body, fragment=fragment: body.replace(fragment, "")
                )
                self.assertNotEqual(code, 0)
                self.assertIn(fragment, output)

    def test_release_rechecks_existing_release_immediately_before_write(self) -> None:
        def remove_second_query(body: str) -> str:
            query = "gh api graphql"
            index = body.rfind(query)
            self.assertGreater(index, body.find(query))
            return body[:index] + body[index + len(query) :]

        code, output = self.run_workflow_guard(remove_second_query)
        self.assertNotEqual(code, 0)
        self.assertIn("both before build and immediately before publication", output)

    def test_release_verifier_requires_attestation_permission_and_immutable_state(self) -> None:
        for fragment, expected in (
            ("      attestations: read\n", "read permission for release attestations"),
            (
                '--json tagName,isImmutable,isDraft,isPrerelease',
                "published mutable release",
            ),
            ('(.isImmutable | tostring)', "published mutable release"),
            ('[[ "$is_immutable" == "true" ]]', "published mutable release"),
            ("published release is not immutable", "published mutable release"),
        ):
            with self.subTest(fragment=fragment):
                code, output = self.run_workflow_guard(
                    lambda body, fragment=fragment: body.replace(fragment, "", 1)
                )
                self.assertNotEqual(code, 0)
                self.assertIn(expected, output)

    def test_release_rejects_manual_dispatch_and_centralized_secret_loading(self) -> None:
        dispatch = (
            "  workflow_dispatch:\n"
            "    inputs:\n"
            "      release_tag:\n"
            "        required: true\n"
            "        type: string\n"
        )
        code, output = self.run_workflow_guard(
            lambda body: body.replace("on:\n", "on:\n" + dispatch, 1)
        )
        self.assertNotEqual(code, 0)
        self.assertIn("tag push events only", output)

        centralized_job = (
            "  validate_secrets:\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            "      - run: 'true'\n\n"
        )
        code, output = self.run_workflow_guard(
            lambda body: body.replace("jobs:\n", "jobs:\n" + centralized_job, 1)
        )
        self.assertNotEqual(code, 0)
        self.assertIn("only the secrets required by each protected job", output)

    def test_release_rejects_secret_references_outside_the_owning_job(self) -> None:
        def inject_secret(body: str) -> str:
            marker = "  release_preflight:\n"
            return body.replace(
                marker,
                marker
                + "    env:\n"
                + "      LEAK: ${{ secrets.HOMEBREW_TAP_TOKEN }}\n",
                1,
            )

        code, output = self.run_workflow_guard(inject_secret)
        self.assertNotEqual(code, 0)
        self.assertIn("release_preflight secret scope mismatch", output)

    def test_atomic_release_creation_revalidates_the_tag_target(self) -> None:
        fragment = '[[ "$tag_target_sha" == "$RELEASE_SHA" ]]'

        def remove_atomic_revalidation(body: str) -> str:
            publish_step = body.index("      - name: Publish GitHub Release assets\n")
            fragment_index = body.index(fragment, publish_step)
            return body[:fragment_index] + body[fragment_index + len(fragment) :]

        code, output = self.run_workflow_guard(remove_atomic_revalidation)
        self.assertNotEqual(code, 0)
        self.assertIn("immediately before publication", output)

    def test_release_build_rejects_an_extra_checkout(self) -> None:
        checkout = (
            "      - uses: "
            "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3\n"
        )

        def duplicate_macos_checkout(body: str) -> str:
            macos_build = body.index("  macos_build:\n")
            checkout_index = body.index(checkout, macos_build)
            return body[:checkout_index] + checkout + body[checkout_index:]

        code, output = self.run_workflow_guard(duplicate_macos_checkout)
        self.assertNotEqual(code, 0)
        self.assertIn("exactly one immutable release SHA checkout", output)

    def test_release_compile_cannot_receive_signing_secrets(self) -> None:
        def inject_secret(body: str) -> str:
            marker = "  macos_compile:\n"
            return body.replace(
                marker,
                marker + "    env:\n      LEAK: ${{ secrets.CODESIGN_IDENTITY }}\n",
                1,
            )

        code, output = self.run_workflow_guard(inject_secret)
        self.assertNotEqual(code, 0)
        self.assertIn("macos_compile must not receive release secrets", output)

    def test_release_signing_job_cannot_run_cargo(self) -> None:
        unsafe_step = (
            "      - name: Unsafe rebuild\n"
            "        run: cargo build --release -p netdiag-app\n"
        )

        def inject_cargo(body: str) -> str:
            marker = "      - name: Prepare signing keychain\n"
            macos_build = body.index("  macos_build:\n")
            marker_index = body.index(marker, macos_build)
            return body[:marker_index] + unsafe_step + body[marker_index:]

        code, output = self.run_workflow_guard(inject_cargo)
        self.assertNotEqual(code, 0)
        self.assertIn("signing job must not execute Cargo", output)

    def test_homebrew_pat_is_exposed_only_to_the_push_step(self) -> None:
        def inject_job_token(body: str) -> str:
            publish_homebrew = body.index("  publish_homebrew:\n")
            environment = "    environment:\n      name: release-homebrew\n"
            environment_index = body.index(environment, publish_homebrew)
            insertion = environment_index + len(environment)
            return (
                body[:insertion]
                + "    env:\n      LEAK: ${{ secrets.HOMEBREW_TAP_TOKEN }}\n"
                + body[insertion:]
            )

        code, output = self.run_workflow_guard(inject_job_token)
        self.assertNotEqual(code, 0)
        self.assertIn("PAT only to the final push step", output)

    def test_release_uses_reviewed_notes_and_verifies_published_bytes(self) -> None:
        for fragment in (
            '--notes-file "$notes_file"',
            'jq -erj \'.body\'',
            'cmp -- "$SOURCE_DIR/.github/release-notes/$RELEASE_TAG.md" "$published_notes"',
        ):
            with self.subTest(fragment=fragment):
                code, output = self.run_workflow_guard(
                    lambda body, fragment=fragment: body.replace(fragment, "", 1)
                )
                self.assertNotEqual(code, 0)
                self.assertIn(fragment, output)

        code, output = self.run_workflow_guard(
            lambda body: body.replace(
                '--notes-file "$notes_file"', "--generate-notes", 1
            )
        )
        self.assertNotEqual(code, 0)
        self.assertIn("reviewed fixed notes", output)

    def test_pages_requires_bounded_exact_appcast_convergence(self) -> None:
        def remove_from_pages(body: str, fragment: str) -> str:
            pages = body.index("  publish_pages:\n")
            position = body.index(fragment, pages)
            return body[:position] + body[position + len(fragment) :]

        for fragment in (
            "for attempt in $(seq 1 30)",
            "?release=$cache_buster",
            "cmp -s -- target/release/appcast.xml",
            "cmp -- target/release/appcast.xml",
        ):
            with self.subTest(fragment=fragment):
                code, output = self.run_workflow_guard(
                    lambda body, fragment=fragment: remove_from_pages(body, fragment)
                )
                self.assertNotEqual(code, 0)
                self.assertIn("exactly verify the Pages artifact", output)

    def test_homebrew_requires_remote_sha_and_content_verification(self) -> None:
        for fragment in (
            "Verify exact remote cask bytes without executing tap content",
            'git -C "$TAP_DIR" read-tree "$TAP_PARENT_SHA"',
            'git -C "$TAP_DIR" commit-tree',
            'git -C "$TAP_DIR" ls-remote --exit-code origin',
            '[[ "$remote_sha" == "$EXPECTED_TAP_SHA" ]]',
            'cmp -- "$RUNNER_TEMP/netdiag-twin.rb" "$published"',
        ):
            with self.subTest(fragment=fragment):
                code, output = self.run_workflow_guard(
                    lambda body, fragment=fragment: body.replace(fragment, "", 1)
                )
                self.assertNotEqual(code, 0)
                self.assertIn("exactly verify the remote tap", output)

    def test_homebrew_renderer_is_deterministic_and_rejects_unsafe_inputs(self) -> None:
        renderer = REPO_ROOT / "scripts/render_homebrew_cask.sh"
        digest = "a" * 64
        expected = (
            'cask "netdiag-twin" do\n'
            '  version "0.5.3"\n'
            f'  sha256 "{digest}"\n'
            "\n"
            '  url "https://github.com/billlza/netdiag-twin/releases/download/v#{version}/NetDiag-Twin-#{version}.dmg"\n'
            '  name "NetDiag Twin"\n'
            '  desc "Network diagnostics workstation"\n'
            '  homepage "https://github.com/billlza/netdiag-twin"\n'
            "\n"
            '  depends_on macos: ">= :ventura"\n'
            "\n"
            '  app "NetDiag Twin.app"\n'
            "end\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "netdiag-twin.rb"
            subprocess.run(
                ["bash", str(renderer), "0.5.3", digest, str(output)],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(output.read_text(encoding="utf-8"), expected)

            for version, sha256 in (
                ("v0.5.3", digest),
                ("0.5.3", "A" * 64),
                ("0.5.3; touch escaped", digest),
            ):
                with self.subTest(version=version, sha256=sha256[:8]):
                    result = subprocess.run(
                        ["bash", str(renderer), version, sha256, str(output)],
                        cwd=REPO_ROOT,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(output.read_text(encoding="utf-8"), expected)

    def test_packaging_always_recreates_verified_sparkle_tree(self) -> None:
        def restore_cache_shortcut(body: str) -> str:
            return body.replace(
                '  rm -rf "$SPARKLE_WORK"\n',
                '  if [[ ! -d "$SPARKLE_FRAMEWORK" ]]; then\n'
                '    rm -rf "$SPARKLE_WORK"\n'
                "  fi\n",
                1,
            )

        code, output = self.run_package_guard(restore_cache_shortcut)
        self.assertNotEqual(code, 0)
        self.assertIn("always recreate Sparkle", output)

    def test_benchmark_rejects_basename_python_fallback(self) -> None:
        code, output = self.run_benchmark_guard(
            lambda body: body + '\nconst LEGACY_PYTHON: &str = "python3";\n'
            + 'fn legacy_python() { let _ = PathBuf::from("python3"); }\n'
        )
        self.assertNotEqual(code, 0)
        self.assertIn("must not execute a basename Python interpreter", output)

    def test_quality_script_rejects_basename_python_fallback(self) -> None:
        quality_body = (REPO_ROOT / "scripts/check_rust_quality.sh").read_text(
            encoding="utf-8"
        )
        fallback_body = re.sub(
            r"(?ms)^schema_python\(\) \{.*?^\}",
            'schema_python() {\n  echo "python3"\n}',
            quality_body,
            count=1,
        )
        code, output = self.run_release_guard(fallback_body)
        self.assertNotEqual(code, 0)
        self.assertIn("must not fall back to basename python3", output)

    def test_rejects_handwritten_calibration_and_missing_evaluation_bypass(self) -> None:
        code, output = self.run_release_guard(
            """
            echo '{"schema": "netdiag-lab-calibration/v1"}'
            cargo run -- pilot model-gate --allow-missing-evaluation
            """
        )
        self.assertNotEqual(code, 0)
        self.assertIn("must not handwrite", output)
        self.assertIn("must not bypass evaluation", output)
        self.assertIn("must run lab calibrate", output)

    def test_rejects_missing_model_gate_and_benchmark_model_dir(self) -> None:
        code, output = self.run_release_guard(
            """
            cargo run -p netdiag-cli -- lab calibrate --artifacts target/pilot-artifacts
            cargo run -p netdiag-cli -- benchmark run --output target/benchmark-report
            """
        )
        self.assertNotEqual(code, 0)
        self.assertIn("must run pilot model-gate", output)
        self.assertIn("benchmark run must use --model-dir", output)

    def test_accepts_calibrate_benchmark_model_dir_and_model_gate_chain(self) -> None:
        code, output = self.run_release_guard(
            """
            cargo run --locked -p netdiag-cli -- lab calibrate --artifacts target/pilot-artifacts
            cargo run --locked -p netdiag-cli -- benchmark run --model-dir target/pilot-artifacts/model
            cargo run --locked -p netdiag-cli -- pilot model-gate --model-dir target/pilot-artifacts/model
            """
        )
        self.assertEqual(code, 0, output)

    def test_rejects_any_unlocked_cargo_run_in_pilot_smoke(self) -> None:
        code, output = self.run_release_guard(
            """
            cargo run --locked -p netdiag-cli -- lab calibrate --artifacts target/pilot-artifacts
            cargo run -p netdiag-cli -- benchmark run --model-dir target/pilot-artifacts/model
            cargo run --locked -p netdiag-cli -- pilot model-gate --model-dir target/pilot-artifacts/model
            """
        )
        self.assertNotEqual(code, 0)
        self.assertIn("every cargo run", output)
        self.assertIn("must use --locked", output)

    def test_commented_commands_do_not_satisfy_or_trigger_release_guards(self) -> None:
        code, output = self.run_release_guard(
            """
            # echo '{"schema": "netdiag-lab-calibration/v1"}'
            # cargo run -p netdiag-cli -- lab calibrate --artifacts target/pilot-artifacts
            # cargo run -p netdiag-cli -- benchmark run --model-dir target/pilot-artifacts/model
            # cargo run -p netdiag-cli -- pilot model-gate --allow-missing-evaluation
            """
        )
        self.assertNotEqual(code, 0)
        self.assertIn("must run lab calibrate", output)
        self.assertIn("must run benchmark run", output)
        self.assertIn("must run pilot model-gate", output)
        self.assertNotIn("must not handwrite", output)
        self.assertNotIn("must not bypass evaluation", output)

    def test_inline_comment_cannot_supply_benchmark_model_dir(self) -> None:
        code, output = self.run_release_guard(
            """
            cargo run -p netdiag-cli -- lab calibrate --artifacts target/pilot-artifacts
            cargo run -p netdiag-cli -- benchmark run # --model-dir target/pilot-artifacts/model
            cargo run -p netdiag-cli -- pilot model-gate --model-dir target/pilot-artifacts/model
            """
        )
        self.assertNotEqual(code, 0)
        self.assertIn("benchmark run must use --model-dir", output)

    def test_rejects_smoke_function_that_is_unreachable_from_strict(self) -> None:
        code, output = self.run_release_guard(
            """
            run_pilot_smoke() {
              cargo run -p netdiag-cli -- lab calibrate --artifacts target/pilot-artifacts
              cargo run -p netdiag-cli -- benchmark run --model-dir target/pilot-artifacts/model
              cargo run -p netdiag-cli -- pilot model-gate --model-dir target/pilot-artifacts/model
            }
            run_strict() {
              :
            }
            """
        )

        self.assertNotEqual(code, 0)
        self.assertIn("run_strict must invoke run_pilot_smoke", output)

    def test_rejects_adapter_validator_built_after_pilot_smoke(self) -> None:
        code, output = self.run_release_guard(
            """
            run_pilot_smoke() {
              cargo run --locked -p netdiag-cli -- lab calibrate --artifacts target/pilot-artifacts
              cargo run --locked -p netdiag-cli -- benchmark run --model-dir target/pilot-artifacts/model
              cargo run --locked -p netdiag-cli -- pilot model-gate --model-dir target/pilot-artifacts/model
            }
            run_strict() {
              cargo test --locked -p netdiag-core --bench perf_budget --all-features
              LLVM_PROFILE_FILE_NAME="netdiag-%m-%p.profraw" cargo llvm-cov nextest --locked -p netdiag-app --all-features --lib --bins --tests
              python3 scripts/check_app_security_coverage.py --summary app.json --dep-info-dir deps --aggregate-min 80 --file-min 50
              run_pilot_smoke
              run_adapter_contracts
            }
            """
        )

        self.assertNotEqual(code, 0)
        self.assertIn("must build the Rust adapter validator before pilot smoke", output)

    def test_commands_outside_smoke_cannot_satisfy_release_chain(self) -> None:
        code, output = self.run_release_guard(
            """
            run_pilot_smoke() {
              :
            }
            unrelated_helper() {
              cargo run -p netdiag-cli -- lab calibrate --artifacts target/pilot-artifacts
              cargo run -p netdiag-cli -- benchmark run --model-dir target/pilot-artifacts/model
              cargo run -p netdiag-cli -- pilot model-gate --model-dir target/pilot-artifacts/model
            }
            run_strict() {
              run_pilot_smoke
            }
            """
        )

        self.assertNotEqual(code, 0)
        self.assertIn("strict pilot smoke must run lab calibrate", output)
        self.assertIn("strict pilot smoke must run benchmark run", output)
        self.assertIn("strict pilot smoke must run pilot model-gate", output)

    def test_logical_cargo_commands_accept_quoted_environment_assignments(self) -> None:
        module = load_script("check_release_gate_hygiene")
        commands = module.logical_cargo_commands(
            'RUSTFLAGS="-D warnings" cargo nextest run --workspace --all-features\n'
        )
        self.assertEqual(
            commands,
            [
                'RUSTFLAGS="-D warnings" cargo nextest run '
                "--workspace --all-features"
            ],
        )

    def test_rejects_coverage_instrumentation_suppression(self) -> None:
        for command in (
            "cargo llvm-cov nextest --no-cfg-coverage",
            "cargo llvm-cov nextest --ignore-filename-regex crates/netdiag-core",
            'RUSTFLAGS="-C instrument-coverage=no" cargo llvm-cov nextest',
        ):
            with self.subTest(command=command):
                code, output = self.run_release_guard(
                    "cargo run -p netdiag-cli -- lab calibrate --artifacts artifacts\n"
                    "cargo run -p netdiag-cli -- benchmark run --model-dir model\n"
                    "cargo run -p netdiag-cli -- pilot model-gate --model-dir model\n"
                    f"{command}\n"
                )
                self.assertNotEqual(code, 0)
                self.assertIn("must not", output)

    def test_rejects_coverage_environment_overrides(self) -> None:
        for variable, value in (
            ("LLVM_COV_FLAGS", "--ignore-filename-regex=crates/netdiag-core"),
            ("CARGO_LLVM_COV_FLAGS", "--ignore-filename-regex=pilot"),
            ("RUSTFLAGS", "-C instrument-coverage=off"),
            ("CARGO_ENCODED_RUSTFLAGS", "-C\x1finstrument-coverage=off"),
            ("CARGO_BUILD_RUSTFLAGS", "-Cinstrument-coverage=off"),
        ):
            with self.subTest(variable=variable), mock.patch.dict(
                os.environ, {variable: value}, clear=False
            ):
                code, output = self.run_release_guard(
                    "cargo run -p netdiag-cli -- lab calibrate --artifacts artifacts\n"
                    "cargo run -p netdiag-cli -- benchmark run --model-dir model\n"
                    "cargo run -p netdiag-cli -- pilot model-gate --model-dir model\n"
                )
                self.assertNotEqual(code, 0)
                self.assertIn(variable, output)


class AdapterContractTests(unittest.TestCase):
    @staticmethod
    def create_rust_validator(workspace: Path, *, body: str = "validator") -> Path:
        validator = (
            workspace / "target" / "adapter-validator" / "debug" / "netdiag-cli"
        )
        validator.parent.mkdir(parents=True)
        validator.write_text(body, encoding="utf-8")
        validator.chmod(0o700)
        return validator

    def test_rust_ingest_uses_the_prebuilt_binary_with_an_empty_environment(self) -> None:
        module = load_script("adapter_process")
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp).resolve()
            validator = self.create_rust_validator(workspace)
            sample = workspace / "sample.json"
            sample.write_text("{}", encoding="utf-8")
            trusted = module.trusted_rust_ingest_validator(validator, workspace)
            completed = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            with mock.patch.object(
                module, "run_bounded", return_value=completed
            ) as bounded:
                module.validate_rust_ingest(trusted, sample, workspace)

        self.assertEqual(
            bounded.call_args.args[0],
            [str(validator), "validate-trace", str(sample)],
        )
        self.assertEqual(bounded.call_args.kwargs["cwd"], workspace)
        self.assertEqual(bounded.call_args.kwargs["environment"], {})
        self.assertEqual(
            bounded.call_args.kwargs["timeout_seconds"],
            module.RUST_VALIDATION_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            bounded.call_args.kwargs["stdout_limit_bytes"],
            module.RUST_VALIDATION_OUTPUT_LIMIT_BYTES,
        )
        self.assertEqual(
            bounded.call_args.kwargs["stderr_limit_bytes"],
            module.RUST_VALIDATION_OUTPUT_LIMIT_BYTES,
        )

    def test_rust_ingest_rejects_a_nonzero_validator_exit(self) -> None:
        module = load_script("adapter_process")
        completed = subprocess.CompletedProcess(
            args=[], returncode=7, stdout="less-specific stdout", stderr="invalid trace"
        )
        with mock.patch.object(
            module,
            "trusted_rust_ingest_validator",
            return_value=Path("/trusted/netdiag-cli"),
        ), mock.patch.object(module, "run_bounded", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "invalid trace"):
                module.validate_rust_ingest(
                    Path("/trusted/netdiag-cli"),
                    Path("/sample.json"),
                    Path("/workspace"),
                )

    def test_rust_ingest_rejects_stderr_from_a_successful_validator(self) -> None:
        module = load_script("adapter_process")
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="unexpected diagnostic"
        )
        with mock.patch.object(
            module,
            "trusted_rust_ingest_validator",
            return_value=Path("/trusted/netdiag-cli"),
        ), mock.patch.object(module, "run_bounded", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "non-empty stderr on success"):
                module.validate_rust_ingest(
                    Path("/trusted/netdiag-cli"),
                    Path("/sample.json"),
                    Path("/workspace"),
                )

    def test_rust_ingest_validator_rejects_untrusted_paths_and_modes(self) -> None:
        module = load_script("adapter_process")
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp).resolve()
            validator = self.create_rust_validator(workspace)
            cases = (
                (
                    Path("target/adapter-validator/debug/netdiag-cli"),
                    "normalized absolute path",
                ),
                (workspace / "outside" / "netdiag-cli", "trusted build location"),
                (
                    workspace
                    / "target"
                    / "adapter-validator"
                    / "debug"
                    / ".."
                    / "debug"
                    / "netdiag-cli",
                    "normalized absolute path",
                ),
            )
            for path, expected in cases:
                with self.subTest(path=path), self.assertRaisesRegex(
                    RuntimeError, expected
                ):
                    module.trusted_rust_ingest_validator(path, workspace)

            validator.chmod(0o720)
            with self.assertRaisesRegex(RuntimeError, "group- or world-writable"):
                module.trusted_rust_ingest_validator(validator, workspace)
            validator.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "must be executable"):
                module.trusted_rust_ingest_validator(validator, workspace)
            validator.chmod(0o700)
            metadata = validator.lstat()
            with mock.patch.object(
                module.os, "geteuid", return_value=metadata.st_uid + 1
            ), self.assertRaisesRegex(RuntimeError, "untrusted owner"):
                module.trusted_rust_ingest_validator(validator, workspace)

    def test_rust_ingest_validator_rejects_empty_directory_and_symlink_targets(self) -> None:
        module = load_script("adapter_process")
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp).resolve()
            validator = self.create_rust_validator(workspace, body="")
            with self.assertRaisesRegex(RuntimeError, "non-empty regular file"):
                module.trusted_rust_ingest_validator(validator, workspace)

            validator.unlink()
            validator.mkdir()
            with self.assertRaisesRegex(RuntimeError, "non-empty regular file"):
                module.trusted_rust_ingest_validator(validator, workspace)

            validator.rmdir()
            real = workspace / "real-validator"
            real.write_text("validator", encoding="utf-8")
            real.chmod(0o700)
            validator.symlink_to(real)
            with self.assertRaisesRegex(RuntimeError, "must not contain symlinks"):
                module.trusted_rust_ingest_validator(validator, workspace)

        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp).resolve()
            real_target = workspace / "real-target"
            validator = self.create_rust_validator(real_target)
            target_link = workspace / "target"
            target_link.symlink_to(real_target / "target", target_is_directory=True)
            linked_validator = (
                target_link / "adapter-validator" / "debug" / "netdiag-cli"
            )
            self.assertTrue(validator.is_file())
            with self.assertRaisesRegex(RuntimeError, "must not contain symlinks"):
                module.trusted_rust_ingest_validator(linked_validator, workspace)

    def test_rust_ingest_validator_rejects_writable_directory_chain(self) -> None:
        module = load_script("adapter_process")
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp).resolve()
            validator = self.create_rust_validator(workspace)
            for directory in (workspace, workspace / "target"):
                original_mode = stat.S_IMODE(directory.stat().st_mode)
                directory.chmod(0o770)
                try:
                    with self.subTest(directory=directory), self.assertRaisesRegex(
                        RuntimeError, "directory chain must not be group- or world-writable"
                    ):
                        module.trusted_rust_ingest_validator(validator, workspace)
                finally:
                    directory.chmod(original_mode)

    def test_rust_ingest_revalidates_a_replaced_validator_before_execution(self) -> None:
        module = load_script("adapter_process")
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp).resolve()
            validator = self.create_rust_validator(workspace)
            sample = workspace / "sample.json"
            sample.write_text("{}", encoding="utf-8")
            trusted = module.trusted_rust_ingest_validator(validator, workspace)
            replacement = workspace / "replacement"
            replacement.write_text("replacement", encoding="utf-8")
            replacement.chmod(0o700)
            validator.unlink()
            validator.symlink_to(replacement)

            with mock.patch.object(module, "run_bounded") as bounded:
                with self.assertRaisesRegex(RuntimeError, "must not contain symlinks"):
                    module.validate_rust_ingest(trusted, sample, workspace)
            bounded.assert_not_called()

    def test_rust_ingest_validator_rejects_linux_and_macos_acl_entries(self) -> None:
        module = load_script("adapter_process")
        path = Path("/trusted")
        with mock.patch.object(module.sys, "platform", "linux"), mock.patch.object(
            module.os,
            "listxattr",
            return_value=["system.posix_acl_access"],
            create=True,
        ), self.assertRaisesRegex(RuntimeError, "must not carry an extended ACL"):
            module._validate_acl_boundary((path,))

        acl_output = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="drwx------ 2 user staff 64 /trusted\n 0: group:staff allow write\n",
            stderr="",
        )
        with mock.patch.object(module.sys, "platform", "darwin"), mock.patch.object(
            module, "run_bounded", return_value=acl_output
        ), self.assertRaisesRegex(RuntimeError, "must not carry an extended ACL"):
            module._validate_acl_boundary((path,))

    def test_adapter_ingest_requires_an_explicit_validator_argument(self) -> None:
        for script in ("validate_adapter_samples", "validate_adapter_contract"):
            module = load_script(script)
            with self.subTest(script=script), mock.patch.object(
                sys, "argv", [script]
            ), redirect_stderr(io.StringIO()), self.assertRaisesRegex(SystemExit, "2"):
                module.main()
            with self.subTest(script=f"{script}-schema-only"), mock.patch.object(
                sys,
                "argv",
                [script, "--schema-only", "--rust-validator", "/tmp/validator"],
            ), redirect_stderr(io.StringIO()), self.assertRaisesRegex(SystemExit, "2"):
                module.main()

    def test_release_guard_rejects_buffering_adapter_subprocess(self) -> None:
        module = load_script("check_release_gate_hygiene")
        original = (SCRIPTS / "adapter_process.py").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "adapter_process.py"
            source.write_text(
                original + "\nsubprocess.run(['forbidden-buffering-boundary'])\n",
                encoding="utf-8",
            )
            module.ADAPTER_PROCESS_SOURCE = source
            code, stdout, stderr = run_main(module)

        self.assertNotEqual(code, 0)
        self.assertIn("must not use buffering subprocess.run", stdout + stderr)

    def test_release_guard_requires_tc_netem_to_remain_fail_closed(self) -> None:
        module = load_script("check_release_gate_hygiene")
        adapter = REPO_ROOT / "examples/adapters/tc-netem-lab/adapter.py"
        original = adapter.read_text(encoding="utf-8")
        weakened = original.replace(
            "--apply is unavailable until qdisc identity, verification, and crash-safe rollback are implemented",
            "--apply accepted",
        )
        self.assertNotEqual(weakened, original)
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "adapter.py"
            source.write_text(weakened, encoding="utf-8")
            module.TC_NETEM_ADAPTER_SOURCE = source
            code, stdout, stderr = run_main(module)

        self.assertNotEqual(code, 0)
        self.assertIn("missing its fail-closed mutation control", stdout + stderr)

    def test_release_guard_requires_streamed_archive_and_safe_evidence_reads(self) -> None:
        module = load_script("check_release_gate_hygiene")
        original = module.PATCH_PROVENANCE_SOURCE.read_text(encoding="utf-8")
        weakened = original.replace('mode="r|gz"', 'mode="r:gz"').replace(
            "for member in bundle:",
            "for member in bundle.getmembers():",
        )
        self.assertNotEqual(weakened, original)
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "patch_provenance.py"
            source.write_text(weakened, encoding="utf-8")
            module.PATCH_PROVENANCE_SOURCE = source
            failures: list[str] = []
            module.validate_release_evidence_input_hygiene(failures)

        output = "\n".join(failures)
        self.assertIn("missing safe input control", output)
        self.assertIn("must stream archive headers", output)

    def test_successful_adapter_must_not_emit_stderr(self) -> None:
        module = load_script("adapter_process")
        with tempfile.TemporaryDirectory() as tmp:
            adapter = Path(tmp) / "adapter.py"
            adapter.write_text(
                "import sys\n"
                "print('{}')\n"
                "print('warning: degraded dependency', file=sys.stderr)\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "non-empty stderr on success"):
                module.run_json(adapter, [])

    def test_contract_failure_check_is_isolated_and_does_not_echo_stderr(self) -> None:
        module = load_script("validate_adapter_contract")
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=2,
            stdout="",
            stderr="sensitive-source-stderr",
        )
        with mock.patch.object(module, "run_bounded", return_value=completed) as run:
            with self.assertRaisesRegex(RuntimeError, "exited 2") as raised:
                module.assert_command_fails(
                    REPO_ROOT / "examples/adapters/tc-netem-lab/adapter.py",
                    ["--collect"],
                    "expected-classification",
                )

        command = run.call_args.args[0]
        self.assertEqual(command[:3], [sys.executable, "-I", "-B"])
        self.assertNotIn("sensitive-source-stderr", str(raised.exception))
        self.assertIn("stderr bytes", str(raised.exception))

    def test_adapter_validation_does_not_inherit_parent_secrets_or_echo_stderr(self) -> None:
        module = load_script("adapter_process")
        with tempfile.TemporaryDirectory() as tmp:
            adapter = Path(tmp) / "adapter.py"
            adapter.write_text(
                "import json, os\n"
                "print(json.dumps({'secret': os.environ.get('VALIDATOR_SECRET')}))\n",
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"VALIDATOR_SECRET": "sensitive-env-value"}):
                self.assertEqual(module.run_json(adapter, []), {"secret": None})

            adapter.write_text(
                "import sys\n"
                "print('sensitive-stderr-value', file=sys.stderr)\n"
                "raise SystemExit(7)\n",
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError) as raised:
                module.run_json(adapter, [])
            self.assertIn("exited 7", str(raised.exception))
            self.assertNotIn("sensitive-stderr-value", str(raised.exception))

    def test_adapter_output_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        module = load_script("adapter_process")
        with tempfile.TemporaryDirectory() as tmp:
            adapter = Path(tmp) / "adapter.py"
            for output, expected in (
                ('{"record": 1, "record": 2}', "duplicate object key"),
                ('{"record": NaN}', "non-finite numeric constant"),
            ):
                with self.subTest(output=output):
                    adapter.write_text(f"print({output!r})\n", encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, expected):
                        module.run_json(adapter, [])

    def test_schema_errors_are_bounded_and_do_not_echo_instance_values(self) -> None:
        module = load_script("schema_validation")
        consumed = 0

        class FakeError:
            validator = "maximum"
            absolute_schema_path = ("properties", "records", "items", "maximum")
            message = "sensitive-instance-value"

        def errors():
            nonlocal consumed
            for _ in range(1_000):
                consumed += 1
                yield FakeError()

        details = module.bounded_validation_errors(errors(), detail_limit=10)
        self.assertEqual(consumed, 11)
        self.assertEqual(len(details), 11)
        self.assertIn("omitted after 10 details", details[-1])
        self.assertNotIn("sensitive-instance-value", "\n".join(details))

    def test_adapter_interrupt_always_reaps_the_spawned_process(self) -> None:
        module = load_script("adapter_process")
        real_popen = subprocess.Popen
        spawned: list[subprocess.Popen[bytes]] = []

        def capture_process(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = real_popen(*args, **kwargs)
            spawned.append(process)
            return process

        with mock.patch.object(module.subprocess, "Popen", side_effect=capture_process), mock.patch.object(
            module.time, "monotonic", side_effect=KeyboardInterrupt
        ):
            with self.assertRaises(KeyboardInterrupt):
                module.run_bounded(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    cwd=REPO_ROOT,
                    timeout_seconds=2.0,
                    stdout_limit_bytes=128,
                    stderr_limit_bytes=128,
                    environment=module.validation_python_environment(),
                )

        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].poll())

    def test_adapter_output_is_bounded_before_process_completion(self) -> None:
        module = load_script("adapter_process")
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            adapter = directory / "adapter.py"
            adapter.write_text("print('x' * 4096)\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "stdout exceeded 128 byte limit"):
                module.run_bounded(
                    [sys.executable, str(adapter)],
                    cwd=directory,
                    timeout_seconds=2.0,
                    stdout_limit_bytes=128,
                    stderr_limit_bytes=128,
                    environment=module.validation_python_environment(),
                )

    def test_adapter_deadline_terminates_the_process_group(self) -> None:
        module = load_script("adapter_process")
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            adapter = directory / "adapter.py"
            adapter.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")

            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, "exceeded 0.05s deadline"):
                module.run_bounded(
                    [sys.executable, str(adapter)],
                    cwd=directory,
                    timeout_seconds=0.05,
                    stdout_limit_bytes=128,
                    stderr_limit_bytes=128,
                    environment=module.validation_python_environment(),
                )
            self.assertLess(time.monotonic() - started, 2.0)

    def test_adapter_rejects_descendants_left_running_after_exit(self) -> None:
        module = load_script("adapter_process")
        child = (
            "import subprocess, sys; "
            "subprocess.Popen([sys.executable, '-c', "
            "'import os, time; os.close(1); os.close(2); time.sleep(30)'])"
        )

        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "left descendant processes running"):
            module.run_bounded(
                [sys.executable, "-c", child],
                cwd=REPO_ROOT,
                timeout_seconds=3.0,
                stdout_limit_bytes=128,
                stderr_limit_bytes=128,
                environment=module.validation_python_environment(),
            )
        self.assertLess(time.monotonic() - started, 2.0)

    def test_live_iperf_inner_process_output_is_bounded(self) -> None:
        module = load_module_path(
            "iperf_adapter",
            REPO_ROOT / "examples/adapters/iperf3-http-json/adapter.py",
        )
        command = [
            sys.executable,
            "-c",
            f"print('x' * {module.IPERF_STDOUT_LIMIT_BYTES})",
        ]

        with self.assertRaisesRegex(RuntimeError, "iperf3 stdout exceeded"):
            module.run_iperf(command, 2.0)

    def test_live_iperf_uses_minimal_environment_and_redacts_failure_stderr(self) -> None:
        module = load_module_path(
            "iperf_adapter_environment",
            REPO_ROOT / "examples/adapters/iperf3-http-json/adapter.py",
        )
        with mock.patch.dict(os.environ, {"IPERF_TEST_SECRET": "sensitive-env-value"}):
            output = module.run_iperf(
                [
                    sys.executable,
                    "-c",
                    "import os; print(os.environ.get('IPERF_TEST_SECRET'))",
                ],
                2.0,
            )
        self.assertEqual(output.strip(), "None")

        with self.assertRaises(RuntimeError) as raised:
            module.run_iperf(
                [
                    sys.executable,
                    "-c",
                    "import sys; print('sensitive-stderr', file=sys.stderr); raise SystemExit(3)",
                ],
                2.0,
            )
        self.assertIn("exit code 3", str(raised.exception))
        self.assertNotIn("sensitive-stderr", str(raised.exception))
        with self.assertRaisesRegex(ValueError, "finite and positive"):
            module.run_iperf([sys.executable, "-c", "pass"], float("nan"))

    def test_live_iperf_rejects_inherited_pipe_lifetime(self) -> None:
        module = load_module_path(
            "iperf_adapter_pipe_lifetime",
            REPO_ROOT / "examples/adapters/iperf3-http-json/adapter.py",
        )
        child = (
            "import subprocess, sys; "
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])"
        )

        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "kept output pipes open"):
            module.run_iperf([sys.executable, "-c", child], 3.0)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_live_iperf_interrupt_always_reaps_the_spawned_process(self) -> None:
        module = load_module_path(
            "iperf_adapter_interrupt",
            REPO_ROOT / "examples/adapters/iperf3-http-json/adapter.py",
        )
        real_popen = subprocess.Popen
        spawned: list[subprocess.Popen[bytes]] = []

        def capture_process(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = real_popen(*args, **kwargs)
            spawned.append(process)
            return process

        with mock.patch.object(module.subprocess, "Popen", side_effect=capture_process), mock.patch.object(
            module.time, "monotonic", side_effect=KeyboardInterrupt
        ):
            with self.assertRaises(KeyboardInterrupt):
                module.run_iperf(
                    [sys.executable, "-c", "import time; time.sleep(30)"], 2.0
                )

        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].poll())

    def test_iperf_json_file_input_is_regular_and_bounded(self) -> None:
        module = load_module_path(
            "iperf_adapter_file_boundary",
            REPO_ROOT / "examples/adapters/iperf3-http-json/adapter.py",
        )
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            valid = directory / "valid.json"
            valid.write_text('{"end": {}}', encoding="utf-8")
            self.assertEqual(module.read_iperf_json_file(valid), {"end": {}})

            oversized = directory / "oversized.json"
            with oversized.open("wb") as output:
                output.truncate(module.IPERF_INPUT_LIMIT_BYTES + 1)
            self.assertFalse(module.iperf_input_is_eligible(oversized))
            with self.assertRaisesRegex(RuntimeError, "input exceeds"):
                module.read_iperf_json_file(oversized)

            symlink = directory / "symlink.json"
            symlink.symlink_to(valid)
            self.assertFalse(module.iperf_input_is_eligible(symlink))
            with self.assertRaisesRegex(RuntimeError, "failed to open.*safely"):
                module.read_iperf_json_file(symlink)

    def test_iperf_json_is_strict_typed_and_uses_real_timestamp_shape(self) -> None:
        module = load_module_path(
            "iperf_adapter_typed_json",
            REPO_ROOT / "examples/adapters/iperf3-http-json/adapter.py",
        )
        with self.assertRaisesRegex(ValueError, "duplicate object key"):
            module.parse_iperf_json('{"end": {}, "end": {}}')
        with self.assertRaisesRegex(ValueError, "non-finite numeric"):
            module.parse_iperf_json('{"end": {"sum": NaN}}')

        payload = {
            "start": {
                "timestamp": {
                    "time": "Wed, 13 Apr 2022 16:47:50 GMT",
                    "timesecs": 1_649_868_470,
                }
            },
            "end": {
                "streams": [
                    {
                        "sender": {
                            "bits_per_second": 94_200_000.0,
                            "retransmits": 2,
                        }
                    }
                ],
                "sum_sent": {
                    "bits_per_second": 94_200_000.0,
                    "retransmits": 2,
                },
            },
        }
        record, flow_count = module.record_from_iperf(payload, False)
        self.assertEqual(record["timestamp"], "2022-04-13T16:47:50+00:00")
        self.assertEqual(record["retransmission_rate"], 0.0)
        self.assertEqual(record["retry_events"], 2.0)
        self.assertEqual(flow_count, 1)

        payload["end"]["streams"][0]["sender"]["retransmits"] = -1
        with self.assertRaisesRegex(ValueError, "between 0"):
            module.record_from_iperf(payload, False)

    def test_tc_netem_rejects_unsafe_or_false_active_parameters(self) -> None:
        module = load_script("adapter_process")
        adapter = REPO_ROOT / "examples/adapters/tc-netem-lab/adapter.py"
        cases = (
            (["--emit-sample", "--latency-ms", "nan"], "must be finite"),
            (["--emit-sample", "--loss-pct", "101"], "between 0 and 100"),
            (["--emit-sample", "--duration-secs", "0"], "must be between 1"),
            (["--emit-sample", "--apply"], "--apply is unavailable"),
            (["--collect", "--interface", "../../device"], "must contain 1..=15"),
            (["--apply", "--interface", "lo"], "--apply is unavailable"),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                completed = module.run_bounded(
                    [sys.executable, "-I", "-B", str(adapter), *args],
                    cwd=adapter.parent,
                    timeout_seconds=2.0,
                    stdout_limit_bytes=1024,
                    stderr_limit_bytes=4096,
                    environment=module.validation_python_environment(),
                )
                self.assertEqual(completed.returncode, 2)
                self.assertIn(expected, completed.stderr)

        preflight = module.run_json(
            adapter,
            ["--preflight", "--apply", "--interface", "lo"],
        )
        self.assertIs(preflight["passed"], False)
        self.assertEqual(preflight["health"]["status"], "error")
        self.assertEqual(preflight["checks"][-1]["status"], "error")


@unittest.skipUnless(os.name == "posix", "POSIX report publication contract")
class BenchmarkReportPublicationTests(unittest.TestCase):
    @staticmethod
    def create_report(root: Path, name: str = "report") -> Path:
        report = root / name
        report.mkdir(mode=0o700)
        for file_name in ("benchmark_report.json", "benchmark_report.md"):
            path = report / file_name
            path.write_text(f"non-empty {file_name}\n", encoding="utf-8")
            path.chmod(0o600)
        return report

    def test_publish_moves_the_exact_report_without_changing_identity(self) -> None:
        module = load_script("publish_benchmark_report")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = self.create_report(root)
            source_identity = (source.stat().st_dev, source.stat().st_ino)
            destination = root / "archive" / "pilot-smoke.verified"

            module.publish_benchmark_report(source, destination)

            self.assertFalse(source.exists())
            self.assertEqual(
                (destination.stat().st_dev, destination.stat().st_ino),
                source_identity,
            )
            self.assertEqual(
                {entry.name for entry in destination.iterdir()},
                module.EXPECTED_REPORT_FILES,
            )

    def test_publish_never_replaces_an_existing_destination(self) -> None:
        module = load_script("publish_benchmark_report")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = self.create_report(root)
            destination = root / "archive" / "pilot-smoke.existing"
            destination.mkdir(parents=True, mode=0o700)
            marker = destination / "existing"
            marker.write_text("keep", encoding="utf-8")

            with self.assertRaisesRegex(
                module.BenchmarkReportPublicationError,
                "refusing to replace",
            ):
                module.publish_benchmark_report(source, destination)

            self.assertTrue(source.is_dir())
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_publish_rejects_missing_extra_empty_and_symlink_files(self) -> None:
        module = load_script("publish_benchmark_report")
        cases = ("missing", "extra", "empty", "symlink")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                source = self.create_report(root)
                json_report = source / "benchmark_report.json"
                if case == "missing":
                    json_report.unlink()
                elif case == "extra":
                    (source / "unexpected.txt").write_text("unexpected")
                elif case == "empty":
                    json_report.write_text("")
                else:
                    json_report.unlink()
                    json_report.symlink_to(source / "benchmark_report.md")
                destination = root / "archive" / f"pilot-smoke.{case}"

                with self.assertRaises(module.BenchmarkReportPublicationError):
                    module.publish_benchmark_report(source, destination)
                self.assertTrue(source.is_dir())
                self.assertFalse(destination.exists())

    def test_publish_rejects_unsafe_source_file_archive_and_owner(self) -> None:
        module = load_script("publish_benchmark_report")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = self.create_report(root)
            source.chmod(0o770)
            with self.assertRaisesRegex(
                module.BenchmarkReportPublicationError,
                "source must not be group- or world-writable",
            ):
                module.publish_benchmark_report(
                    source, root / "archive-source" / "pilot-smoke.source"
                )

            source.chmod(0o700)
            report_file = source / "benchmark_report.json"
            report_file.chmod(0o660)
            with self.assertRaisesRegex(
                module.BenchmarkReportPublicationError,
                "must not be group- or world-writable",
            ):
                module.publish_benchmark_report(
                    source, root / "archive-file" / "pilot-smoke.file"
                )

            report_file.chmod(0o600)
            archive = root / "archive-mode"
            archive.mkdir()
            archive.chmod(0o770)
            with self.assertRaisesRegex(
                module.BenchmarkReportPublicationError,
                "archive must not be group- or world-writable",
            ):
                module.publish_benchmark_report(
                    source, archive / "pilot-smoke.archive"
                )

            archive.chmod(0o700)
            owner = source.stat().st_uid
            with mock.patch.object(module.os, "geteuid", return_value=owner + 1):
                with self.assertRaisesRegex(
                    module.BenchmarkReportPublicationError,
                    "source must be owned by the current user",
                ):
                    module.publish_benchmark_report(
                        source, root / "archive-owner" / "pilot-smoke.owner"
                    )

    def test_publish_rejects_symlink_directories_and_surfaces_rename_failure(self) -> None:
        module = load_script("publish_benchmark_report")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            real_source = self.create_report(root, "real-source")
            source_link = root / "source-link"
            source_link.symlink_to(real_source, target_is_directory=True)
            with self.assertRaisesRegex(
                module.BenchmarkReportPublicationError,
                "source must be a directory",
            ):
                module.publish_benchmark_report(
                    source_link, root / "archive-link" / "pilot-smoke.link"
                )

            archive_target = root / "archive-target"
            archive_target.mkdir(mode=0o700)
            archive_link = root / "archive-symlink"
            archive_link.symlink_to(archive_target, target_is_directory=True)
            with self.assertRaisesRegex(
                module.BenchmarkReportPublicationError,
                "archive must be a directory",
            ):
                module.publish_benchmark_report(
                    real_source, archive_link / "pilot-smoke.archive-link"
                )

            destination = root / "archive-rename" / "pilot-smoke.rename"
            with mock.patch.object(
                module.os, "rename", side_effect=OSError("controlled failure")
            ), self.assertRaisesRegex(
                module.BenchmarkReportPublicationError,
                "could not be published atomically",
            ):
                module.publish_benchmark_report(real_source, destination)
            self.assertTrue(real_source.is_dir())
            self.assertFalse(destination.exists())


class AdapterMeasurementQualityTests(unittest.TestCase):
    EXPECTED = {
        "dns-probe": {
            "latency_ms": "measured",
            "jitter_ms": "measured",
            "packet_loss_rate": "fallback",
            "retransmission_rate": "missing",
            "timeout_events": "measured",
            "retry_events": "missing",
            "throughput_mbps": "missing",
            "dns_failure_events": "measured",
            "tls_failure_events": "missing",
            "quic_blocked_ratio": "missing",
        },
        "frr-routing-state": {
            "latency_ms": "fallback",
            "jitter_ms": "fallback",
            "packet_loss_rate": "missing",
            "retransmission_rate": "missing",
            "timeout_events": "fallback",
            "retry_events": "fallback",
            "throughput_mbps": "fallback",
            "dns_failure_events": "missing",
            "tls_failure_events": "missing",
            "quic_blocked_ratio": "missing",
        },
        "http-json-python": {
            metric: "measured"
            for metric in (
                "latency_ms",
                "jitter_ms",
                "packet_loss_rate",
                "retransmission_rate",
                "timeout_events",
                "retry_events",
                "throughput_mbps",
                "dns_failure_events",
                "tls_failure_events",
                "quic_blocked_ratio",
            )
        },
        "iperf3-http-json": {
            "latency_ms": "missing",
            "jitter_ms": "missing",
            "packet_loss_rate": "missing",
            "retransmission_rate": "missing",
            "timeout_events": "missing",
            "retry_events": "estimated",
            "throughput_mbps": "measured",
            "dns_failure_events": "missing",
            "tls_failure_events": "missing",
            "quic_blocked_ratio": "missing",
        },
        "openconfig-gnmi": {
            "latency_ms": "measured",
            "jitter_ms": "measured",
            "packet_loss_rate": "fallback",
            "retransmission_rate": "fallback",
            "timeout_events": "missing",
            "retry_events": "fallback",
            "throughput_mbps": "measured",
            "dns_failure_events": "missing",
            "tls_failure_events": "missing",
            "quic_blocked_ratio": "missing",
        },
        "prometheus-exporter-python": {
            metric: "measured"
            for metric in (
                "latency_ms",
                "jitter_ms",
                "packet_loss_rate",
                "retransmission_rate",
                "timeout_events",
                "retry_events",
                "throughput_mbps",
                "dns_failure_events",
                "tls_failure_events",
                "quic_blocked_ratio",
            )
        },
        "quic-probe": {
            "latency_ms": "measured",
            "jitter_ms": "measured",
            "packet_loss_rate": "fallback",
            "retransmission_rate": "missing",
            "timeout_events": "measured",
            "retry_events": "missing",
            "throughput_mbps": "missing",
            "dns_failure_events": "measured",
            "tls_failure_events": "missing",
            "quic_blocked_ratio": "fallback",
        },
        "snmp-if-mib": {
            "latency_ms": "missing",
            "jitter_ms": "missing",
            "packet_loss_rate": "fallback",
            "retransmission_rate": "fallback",
            "timeout_events": "missing",
            "retry_events": "fallback",
            "throughput_mbps": "estimated",
            "dns_failure_events": "missing",
            "tls_failure_events": "missing",
            "quic_blocked_ratio": "missing",
        },
        "tc-netem-lab": {
            "latency_ms": "fallback",
            "jitter_ms": "fallback",
            "packet_loss_rate": "fallback",
            "retransmission_rate": "missing",
            "timeout_events": "missing",
            "retry_events": "missing",
            "throughput_mbps": "fallback",
            "dns_failure_events": "missing",
            "tls_failure_events": "missing",
            "quic_blocked_ratio": "missing",
        },
        "tls-probe": {
            "latency_ms": "measured",
            "jitter_ms": "measured",
            "packet_loss_rate": "fallback",
            "retransmission_rate": "missing",
            "timeout_events": "measured",
            "retry_events": "missing",
            "throughput_mbps": "missing",
            "dns_failure_events": "measured",
            "tls_failure_events": "measured",
            "quic_blocked_ratio": "missing",
        },
    }

    def sample_payload(self, name: str, *extra_arguments: str) -> dict:
        boundary = load_script("adapter_process")
        directory = REPO_ROOT / "examples/adapters" / name
        adapter = directory / (
            "exporter.py" if name == "prometheus-exporter-python" else "adapter.py"
        )
        return boundary.run_json(adapter, ["--emit-sample", *extra_arguments])

    def test_bundled_samples_emit_exact_v2_quality_mappings(self) -> None:
        quality_contract = load_script("adapter_quality")
        for name, expected in self.EXPECTED.items():
            with self.subTest(adapter=name):
                payload = self.sample_payload(name)
                self.assertEqual(payload["schema"], "netdiag-adapter-payload/v2")
                quality_contract.validate_declared_measurement_quality(payload)
                self.assertEqual(payload["measurement_quality"], expected)

        udp = self.sample_payload("iperf3-http-json", "--udp")
        self.assertEqual(
            udp["measurement_quality"],
            {
                **self.EXPECTED["iperf3-http-json"],
                "jitter_ms": "measured",
                "packet_loss_rate": "measured",
                "retry_events": "missing",
            },
        )

    def test_quality_guard_rejects_missing_unknown_and_invalid_declarations(self) -> None:
        quality_contract = load_script("adapter_quality")
        valid = self.sample_payload("iperf3-http-json")
        cases = []

        missing_object = dict(valid)
        del missing_object["measurement_quality"]
        cases.append((missing_object, "must declare"))

        missing_metric = json.loads(json.dumps(valid))
        del missing_metric["measurement_quality"]["latency_ms"]
        cases.append((missing_metric, "missing canonical metrics"))

        unknown_metric = json.loads(json.dumps(valid))
        unknown_metric["measurement_quality"]["source"] = "measured"
        cases.append((unknown_metric, "unknown metrics"))

        invalid_enum = json.loads(json.dumps(valid))
        invalid_enum["measurement_quality"]["latency_ms"] = "direct"
        cases.append((invalid_enum, "unsupported values"))

        free_text_object = json.loads(json.dumps(valid))
        free_text_object["measurement_quality"]["latency_ms"] = {
            "quality": "measured",
            "reason": "unbounded",
        }
        cases.append((free_text_object, "unsupported values"))

        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(RuntimeError, message):
                    quality_contract.validate_declared_measurement_quality(payload)

    def test_v2_schema_requires_closed_complete_quality_declaration(self) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError as error:
            self.skipTest(f"jsonschema is unavailable: {error}")

        schema = json.loads(
            (
                REPO_ROOT
                / "examples/adapters/schema/netdiag-adapter-payload.schema.json"
            ).read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(schema)
        valid = self.sample_payload("iperf3-http-json")
        self.assertEqual(list(validator.iter_errors(valid)), [])

        cases = []
        missing_object = json.loads(json.dumps(valid))
        del missing_object["measurement_quality"]
        cases.append((missing_object, "required"))
        missing_metric = json.loads(json.dumps(valid))
        del missing_metric["measurement_quality"]["latency_ms"]
        cases.append((missing_metric, "required"))
        unknown_metric = json.loads(json.dumps(valid))
        unknown_metric["measurement_quality"]["source"] = "measured"
        cases.append((unknown_metric, "additionalProperties"))
        invalid_enum = json.loads(json.dumps(valid))
        invalid_enum["measurement_quality"]["latency_ms"] = "direct"
        cases.append((invalid_enum, "enum"))

        for metric, invalid in (
            ("packet_loss_rate", 100.000001),
            ("retransmission_rate", 100.000001),
            ("quic_blocked_ratio", 1.000001),
        ):
            out_of_range = json.loads(json.dumps(valid))
            out_of_range["records"][0][metric] = invalid
            cases.append((out_of_range, "maximum"))

        boundary = json.loads(json.dumps(valid))
        boundary["records"][0]["packet_loss_rate"] = 100.0
        boundary["records"][0]["retransmission_rate"] = 100.0
        boundary["records"][0]["quic_blocked_ratio"] = 1.0
        self.assertEqual(list(validator.iter_errors(boundary)), [])

        for payload, keyword in cases:
            with self.subTest(keyword=keyword):
                self.assertTrue(
                    any(
                        error.validator == keyword
                        for error in validator.iter_errors(payload)
                    )
                )


class ProbeAdapterBoundaryTests(unittest.TestCase):
    ADAPTER_PATHS = {
        "dns": REPO_ROOT / "examples/adapters/dns-probe/adapter.py",
        "tls": REPO_ROOT / "examples/adapters/tls-probe/adapter.py",
        "quic": REPO_ROOT / "examples/adapters/quic-probe/adapter.py",
    }

    def run_adapter(self, name: str, arguments: list[str]):
        boundary = load_script("adapter_process")
        adapter = self.ADAPTER_PATHS[name]
        return boundary.run_bounded(
            [sys.executable, "-I", "-B", str(adapter), *arguments],
            cwd=adapter.parent,
            timeout_seconds=3.0,
            stdout_limit_bytes=64 * 1024,
            stderr_limit_bytes=8 * 1024,
            environment=boundary.validation_python_environment(),
        )

    def load_adapter(self, name: str) -> ModuleType:
        return load_module_path(f"probe_{name}_adapter", self.ADAPTER_PATHS[name])

    def test_probe_entrypoints_keep_isolated_python_compatibility(self) -> None:
        import ast

        for name, path in self.ADAPTER_PATHS.items():
            source = path.read_text(encoding="utf-8")
            with self.subTest(adapter=name):
                self.assertEqual(
                    source.splitlines()[1],
                    "from __future__ import annotations",
                )
                ast.parse(source, filename=str(path), feature_version=(3, 8))
                self.assertNotIn("socket.setdefaulttimeout", source)
                self.assertNotIn("max(args.count, 1)", source)

    def test_probe_sample_mode_rejects_invalid_resource_budgets_before_output(
        self,
    ) -> None:
        common_cases = (
            (["--count", "0"], "--count must be between 1 and 20"),
            (["--count", "-1"], "--count must be between 1 and 20"),
            (["--count", "21"], "--count must be between 1 and 20"),
            (["--timeout-secs", "nan"], "--timeout-secs must be finite"),
            (["--timeout-secs", "inf"], "--timeout-secs must be finite"),
            (
                ["--timeout-secs", "0.049"],
                "--timeout-secs must be between 0.05 and 10 seconds",
            ),
            (
                ["--timeout-secs", "10.01"],
                "--timeout-secs must be between 0.05 and 10 seconds",
            ),
            (
                ["--count", "20", "--timeout-secs", "3.01"],
                "--count * --timeout-secs must not exceed 60 seconds",
            ),
            (["--host="], "--host must contain 1..=253 ASCII bytes"),
            (
                ["--host", "bad host"],
                "--host must not contain whitespace or control characters",
            ),
            (
                ["--host", "tést.example"],
                "--host must contain only visible ASCII characters",
            ),
            (
                ["--host", "a" * 254],
                "--host must contain 1..=253 ASCII bytes",
            ),
        )
        for name in self.ADAPTER_PATHS:
            for arguments, expected_error in common_cases:
                with self.subTest(adapter=name, arguments=arguments):
                    completed = self.run_adapter(
                        name, ["--emit-sample", *arguments]
                    )
                    self.assertEqual(completed.returncode, 2)
                    self.assertEqual(completed.stdout, "")
                    self.assertIn(expected_error, completed.stderr)

        for name in ("tls", "quic"):
            for port in ("0", "65536"):
                with self.subTest(adapter=name, port=port):
                    completed = self.run_adapter(
                        name, ["--emit-sample", "--port", port]
                    )
                    self.assertEqual(completed.returncode, 2)
                    self.assertEqual(completed.stdout, "")
                    self.assertIn(
                        "--port must be between 1 and 65535", completed.stderr
                    )

    def test_probe_sample_mode_accepts_inclusive_boundaries(self) -> None:
        for name in self.ADAPTER_PATHS:
            arguments = [
                "--emit-sample",
                "--host",
                "example.test",
                "--count",
                "20",
                "--timeout-secs",
                "3",
            ]
            if name != "dns":
                arguments.extend(["--port", "65535"])
            with self.subTest(adapter=name):
                completed = self.run_adapter(name, arguments)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, "")
                payload = json.loads(completed.stdout)
                self.assertEqual(payload["collection_mode"], "sample")
                self.assertEqual(payload["flow_count"], 20)

        for name in self.ADAPTER_PATHS:
            arguments = [
                "--emit-sample",
                "--host",
                "example.test",
                "--count",
                "1",
                "--timeout-secs",
                "0.05",
            ]
            if name != "dns":
                arguments.extend(["--port", "1"])
            with self.subTest(adapter=name, boundary="minimum"):
                completed = self.run_adapter(name, arguments)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, "")

    def test_resolver_deadline_terminates_real_worker_processes(self) -> None:
        sleep_command = [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import time; time.sleep(30)",
        ]
        for name in self.ADAPTER_PATHS:
            module = self.load_adapter(name)
            started = time.monotonic()
            with mock.patch.object(
                module, "resolver_command", return_value=sleep_command
            ):
                outcome = module.bounded_resolve(
                    "example.test", 443, module.socket.SOCK_STREAM, 0.05
                )
            with self.subTest(adapter=name):
                self.assertEqual(outcome.failure, module.TIMEOUT_FAILURE)
                self.assertEqual(outcome.addresses, ())
                self.assertLess(time.monotonic() - started, 2.0)

    def test_resolver_worker_normal_path_returns_bounded_numeric_addresses(
        self,
    ) -> None:
        for name in self.ADAPTER_PATHS:
            module = self.load_adapter(name)
            socket_type = (
                module.socket.SOCK_DGRAM
                if name == "quic"
                else module.socket.SOCK_STREAM
            )
            outcome = module.bounded_resolve("localhost", 443, socket_type, 1.0)
            with self.subTest(adapter=name):
                self.assertIsNone(outcome.failure)
                self.assertGreaterEqual(outcome.elapsed_ms, 0.0)
                self.assertLessEqual(
                    len(outcome.addresses), module.MAX_RESOLVED_ADDRESSES
                )
                self.assertGreater(len(outcome.addresses), 0)
                self.assertTrue(
                    all(
                        family in {module.socket.AF_INET, module.socket.AF_INET6}
                        for family, _address in outcome.addresses
                    )
                )

    def test_resolver_protocol_failures_are_redacted_and_fail_closed(self) -> None:
        sensitive_output = "sensitive-resolver-detail"
        invalid_command = [
            sys.executable,
            "-I",
            "-B",
            "-c",
            f"print({sensitive_output!r})",
        ]
        for name in self.ADAPTER_PATHS:
            module = self.load_adapter(name)
            with mock.patch.object(
                module, "resolver_command", return_value=invalid_command
            ):
                with self.assertRaises(module.ProbeRuntimeError) as raised:
                    module.bounded_resolve(
                        "example.test", 443, module.socket.SOCK_STREAM, 0.5
                    )
            with self.subTest(adapter=name):
                message = str(raised.exception)
                self.assertIn("invalid response", message)
                self.assertNotIn(sensitive_output, message)

            for invalid_payload in (
                b'{"status":"resolution","status":"network","elapsed_ms":1}',
                b'{"status":"resolution","elapsed_ms":NaN}',
            ):
                with self.subTest(adapter=name, payload=invalid_payload):
                    with self.assertRaisesRegex(
                        module.ProbeRuntimeError, "invalid response"
                    ):
                        module.parse_resolution_output(invalid_payload)
            wrong_port_payload = json.dumps(
                {
                    "status": "ok",
                    "elapsed_ms": 1.0,
                    "addresses": [[module.socket.AF_INET, "127.0.0.1", 444]],
                }
            ).encode("ascii")
            with self.assertRaisesRegex(
                module.ProbeRuntimeError, "invalid response"
            ):
                module.parse_resolution_output(wrong_port_payload, expected_port=443)

    def test_resolver_errors_are_typed_without_exposing_error_text(self) -> None:
        sensitive_detail = "sensitive-resolver-detail"
        for name in self.ADAPTER_PATHS:
            module = self.load_adapter(name)
            with mock.patch.object(
                module.socket,
                "getaddrinfo",
                side_effect=module.socket.gaierror(-2, sensitive_detail),
            ):
                payload = module.resolver_worker_payload(
                    "example.test", 443, module.socket.SOCK_STREAM
                )
            with self.subTest(adapter=name):
                self.assertEqual(payload["status"], module.RESOLUTION_FAILURE)
                self.assertGreaterEqual(payload["elapsed_ms"], 0.0)
                self.assertNotIn(sensitive_detail, json.dumps(payload))

        dns_module = self.load_adapter("dns")
        with mock.patch.object(
            dns_module.socket,
            "getaddrinfo",
            side_effect=OSError(sensitive_detail),
        ):
            payload = dns_module.resolver_worker_payload(
                "example.test", 443, dns_module.socket.SOCK_STREAM
            )
        self.assertEqual(payload["status"], dns_module.NETWORK_FAILURE)
        self.assertGreaterEqual(payload["elapsed_ms"], 0.0)
        self.assertNotIn(sensitive_detail, json.dumps(payload))

    def test_tls_error_classes_remain_distinct(self) -> None:
        module = self.load_adapter("tls")
        cases = (
            (
                module.ssl.SSLCertVerificationError(1, "sensitive"),
                module.CERTIFICATE_FAILURE,
            ),
            (module.socket.timeout("sensitive"), module.TIMEOUT_FAILURE),
            (module.ssl.SSLError(1, "sensitive"), module.PROTOCOL_FAILURE),
            (OSError("sensitive"), module.NETWORK_FAILURE),
        )
        for error, expected in cases:
            with self.subTest(error=type(error).__name__):
                self.assertEqual(module.classify_tls_error(error), expected)

    def test_live_probe_payloads_preserve_failure_types_and_actual_windows(
        self,
    ) -> None:
        dns = self.load_adapter("dns")
        dns_args = dns.build_parser().parse_args(
            [
                "--host",
                "example.test",
                "--count",
                "4",
                "--timeout-secs",
                "0.1",
                "--fault-start",
                "caller-start",
                "--fault-end",
                "caller-end",
            ]
        )
        dns_attempts = [
            dns.ProbeAttempt(10.0, None),
            dns.ProbeAttempt(20.0, dns.TIMEOUT_FAILURE),
            dns.ProbeAttempt(5.0, dns.RESOLUTION_FAILURE),
            dns.ProbeAttempt(3.0, dns.NETWORK_FAILURE),
        ]
        with mock.patch.object(dns, "dns_attempt", side_effect=dns_attempts):
            dns_payload = dns.live_payload(dns_args, "example.test")
        dns_record = dns_payload["records"][0]
        self.assertEqual(dns_payload["probe_summary"]["successes"], 1)
        self.assertEqual(
            dns_payload["probe_summary"]["failure_counts"],
            {"timeout": 1, "resolution": 1, "network": 1},
        )
        self.assertEqual(dns_record["latency_ms"], 9.5)
        self.assertEqual(dns_record["packet_loss_rate"], 75.0)
        self.assertEqual(dns_record["dns_failure_events"], 3.0)

        tls = self.load_adapter("tls")
        tls_args = tls.build_parser().parse_args(
            ["--host", "example.test", "--count", "6", "--timeout-secs", "0.1"]
        )
        tls_attempts = [
            tls.ProbeAttempt(1.0, None),
            tls.ProbeAttempt(2.0, tls.TIMEOUT_FAILURE),
            tls.ProbeAttempt(3.0, tls.RESOLUTION_FAILURE),
            tls.ProbeAttempt(4.0, tls.CERTIFICATE_FAILURE),
            tls.ProbeAttempt(5.0, tls.NETWORK_FAILURE),
            tls.ProbeAttempt(6.0, tls.PROTOCOL_FAILURE),
        ]
        with mock.patch.object(tls, "tls_attempt", side_effect=tls_attempts):
            tls_payload = tls.live_payload(tls_args, "example.test")
        tls_record = tls_payload["records"][0]
        self.assertEqual(tls_payload["probe_summary"]["successes"], 1)
        self.assertEqual(tls_record["timeout_events"], 1.0)
        self.assertEqual(tls_record["dns_failure_events"], 1.0)
        self.assertEqual(tls_record["tls_failure_events"], 2.0)

        quic = self.load_adapter("quic")
        quic_args = quic.build_parser().parse_args(
            ["--host", "example.test", "--count", "4", "--timeout-secs", "0.1"]
        )
        quic_attempts = [
            quic.ProbeAttempt(1.0, None),
            quic.ProbeAttempt(2.0, quic.TIMEOUT_FAILURE),
            quic.ProbeAttempt(3.0, quic.RESOLUTION_FAILURE),
            quic.ProbeAttempt(4.0, quic.NETWORK_FAILURE),
        ]
        with mock.patch.object(quic, "udp_attempt", side_effect=quic_attempts):
            quic_payload = quic.live_payload(quic_args, "example.test")
        quic_record = quic_payload["records"][0]
        self.assertEqual(quic_payload["probe_summary"]["successes"], 1)
        self.assertEqual(quic_record["packet_loss_rate"], 75.0)
        self.assertEqual(quic_record["quic_blocked_ratio"], 0.25)

        for payload in (dns_payload, tls_payload, quic_payload):
            experiment = payload["experiment"]
            self.assertNotEqual(experiment["fault_start"], "caller-start")
            self.assertNotEqual(experiment["fault_end"], "caller-end")
            started = dns.datetime.fromisoformat(experiment["fault_start"])
            ended = dns.datetime.fromisoformat(experiment["fault_end"])
            self.assertLessEqual(started, ended)

    def test_tls_failure_metric_only_counts_certificate_and_protocol_failures(
        self,
    ) -> None:
        tls = self.load_adapter("tls")
        args = tls.build_parser().parse_args(
            ["--host", "example.test", "--count", "1", "--timeout-secs", "0.1"]
        )
        cases = (
            (tls.RESOLUTION_FAILURE, 0.0, 1.0, 0.0),
            (tls.TIMEOUT_FAILURE, 1.0, 0.0, 0.0),
            (tls.NETWORK_FAILURE, 0.0, 0.0, 0.0),
            (tls.CERTIFICATE_FAILURE, 0.0, 0.0, 1.0),
            (tls.PROTOCOL_FAILURE, 0.0, 0.0, 1.0),
        )
        for failure, expected_timeouts, expected_dns, expected_tls in cases:
            with self.subTest(failure=failure):
                with mock.patch.object(
                    tls, "tls_attempt", return_value=tls.ProbeAttempt(1.0, failure)
                ):
                    payload = tls.live_payload(args, "example.test")
                record = payload["records"][0]
                self.assertEqual(record["timeout_events"], expected_timeouts)
                self.assertEqual(record["dns_failure_events"], expected_dns)
                self.assertEqual(record["tls_failure_events"], expected_tls)


class PatchContractHygieneTests(unittest.TestCase):
    VALID_QUALITY_SCRIPT = """
    run_patch_contracts() {
      cargo metadata --locked --offline --no-deps --format-version 1 --manifest-path third_party/demo/Cargo.toml >/dev/null
      cargo test --locked -p netdiag-demo-patch-contract --all-targets --all-features
      cargo clippy --locked -p netdiag-demo-patch-contract --all-targets --all-features -- -D warnings
    }
    run_strict() {
      run_patch_contracts
    }
    """

    def run_patch_guard(
        self,
        quality_script: str = VALID_QUALITY_SCRIPT,
        *,
        exclude_patch: bool = True,
        contract_patch: str = "demo",
        preserve_upstream_tests: bool = False,
        untracked_patch_file: str | None = None,
    ) -> tuple[int, str]:
        module = load_script("check_patch_contract_hygiene")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            excluded = 'exclude = ["third_party/demo"]\n' if exclude_patch else ""
            (root / "Cargo.toml").write_text(
                "[workspace]\n"
                'members = ["tools/patch-contracts/demo"]\n'
                f"{excluded}"
                "[patch.crates-io]\n"
                'demo = { path = "third_party/demo" }\n',
                encoding="utf-8",
            )
            vendor = root / "third_party" / "demo"
            vendor.mkdir(parents=True)
            cargo_manifest = '[package]\nname = "demo"\nversion = "1.0.0"\n'
            patch_notes = "# demo patch\n"
            (vendor / "Cargo.toml").write_text(
                cargo_manifest,
                encoding="utf-8",
            )
            (vendor / "PATCH.md").write_text(patch_notes, encoding="utf-8")
            upstream_files = {
                "Cargo.toml": hashlib.sha256(
                    cargo_manifest.encode("utf-8")
                ).hexdigest()
            }
            preserved_test_directories: list[str] = []
            if preserve_upstream_tests:
                test_asset = "published fixture\n"
                test_path = vendor / "tests" / "fixture.txt"
                test_path.parent.mkdir()
                test_path.write_text(test_asset, encoding="utf-8")
                upstream_files["tests/fixture.txt"] = hashlib.sha256(
                    test_asset.encode("utf-8")
                ).hexdigest()
                preserved_test_directories.append("tests")
            (vendor / "PATCH_PROVENANCE.json").write_text(
                json.dumps(
                    {
                        "schema": "netdiag-local-patch-provenance/v1",
                        "crate": "demo",
                        "version": "1.0.0",
                        "archive": {
                            "file_name": "demo-1.0.0.crate",
                            "url": "https://static.crates.io/crates/demo/demo-1.0.0.crate",
                            "sha256": "0" * 64,
                        },
                        "upstream_files": upstream_files,
                        "allowed_diff": {
                            "modified": {},
                            "added": {
                                "PATCH.md": hashlib.sha256(
                                    patch_notes.encode("utf-8")
                                ).hexdigest()
                            },
                            "removed": [],
                        },
                        "preserved_test_directories": preserved_test_directories,
                    }
                ),
                encoding="utf-8",
            )
            contract = root / "tools" / "patch-contracts" / "demo"
            contract.mkdir(parents=True)
            (contract / "Cargo.toml").write_text(
                "[package]\n"
                'name = "netdiag-demo-patch-contract"\n'
                'version = "1.0.0"\n'
                "[package.metadata.netdiag-patch-contract]\n"
                f'patches = ["{contract_patch}"]\n',
                encoding="utf-8",
            )
            quality = root / "check_rust_quality.sh"
            quality.write_text(quality_script, encoding="utf-8")
            subprocess.run(
                ["git", "init", "--quiet"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "add", "--force", "."],
                cwd=root,
                check=True,
                capture_output=True,
            )
            if untracked_patch_file is not None:
                subprocess.run(
                    ["git", "rm", "--cached", "--quiet", "--", untracked_patch_file],
                    cwd=root,
                    check=True,
                    capture_output=True,
                )
            module.ROOT = root
            module.WORKSPACE_MANIFEST = root / "Cargo.toml"
            module.QUALITY_SCRIPT = quality
            code, stdout, stderr = run_main(module)
        return code, stdout + stderr

    def test_accepts_explicit_independent_patch_contracts(self) -> None:
        code, output = self.run_patch_guard()
        self.assertEqual(code, 0, output)

    def test_rejects_patch_file_present_only_in_the_worktree(self) -> None:
        code, output = self.run_patch_guard(
            untracked_patch_file="third_party/demo/Cargo.toml"
        )
        self.assertNotEqual(code, 0)
        self.assertIn("files absent from the Git index", output)
        self.assertIn("Cargo.toml", output)

    def test_rejects_contract_function_not_invoked_by_strict(self) -> None:
        body = self.VALID_QUALITY_SCRIPT.replace(
            "run_strict() {\n      run_patch_contracts\n    }",
            "run_strict() {\n      :\n    }",
        )
        code, output = self.run_patch_guard(body)
        self.assertNotEqual(code, 0)
        self.assertIn("run_strict must invoke run_patch_contracts", output)

    def test_rejects_contract_without_warning_denied_clippy(self) -> None:
        body = self.VALID_QUALITY_SCRIPT.replace(" -- -D warnings", "")
        code, output = self.run_patch_guard(body)
        self.assertNotEqual(code, 0)
        self.assertIn("must Clippy", output)

    def test_rejects_unlocked_patch_metadata(self) -> None:
        body = self.VALID_QUALITY_SCRIPT.replace(
            "cargo metadata --locked", "cargo metadata", 1
        )
        code, output = self.run_patch_guard(body)
        self.assertNotEqual(code, 0)
        self.assertIn("cargo metadata --locked", output)

    def test_rejects_unexcluded_or_mismatched_local_patch(self) -> None:
        code, output = self.run_patch_guard(
            exclude_patch=False,
            contract_patch="not-demo",
        )
        self.assertNotEqual(code, 0)
        self.assertIn("must be excluded", output)
        self.assertIn("unknown local patch", output)
        self.assertIn("has no workspace patch contract", output)

    def test_preserved_upstream_tests_require_direct_test_and_clippy_commands(self) -> None:
        code, output = self.run_patch_guard(preserve_upstream_tests=True)
        self.assertNotEqual(code, 0)
        self.assertIn("must execute preserved demo upstream tests", output)
        self.assertIn("must Clippy preserved demo upstream tests", output)

        library_only_script = self.VALID_QUALITY_SCRIPT.replace(
            "      cargo metadata",
            "      cargo test --locked --offline --manifest-path third_party/demo/Cargo.toml --lib\n"
            "      cargo clippy --locked --offline --manifest-path third_party/demo/Cargo.toml "
            "--lib --tests -- -D warnings\n"
            "      cargo metadata",
            1,
        )
        code, output = self.run_patch_guard(
            library_only_script,
            preserve_upstream_tests=True,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("--all-targets --all-features", output)

        quality_script = self.VALID_QUALITY_SCRIPT.replace(
            "      cargo metadata",
            "      cargo test --locked --offline --manifest-path third_party/demo/Cargo.toml "
            "--all-targets --all-features\n"
            "      cargo clippy --locked --offline --manifest-path third_party/demo/Cargo.toml "
            "--all-targets --all-features -- -D warnings\n"
            "      cargo metadata",
            1,
        )
        code, output = self.run_patch_guard(
            quality_script,
            preserve_upstream_tests=True,
        )
        self.assertEqual(code, 0, output)

    def test_patch_snapshot_rejects_mutation_extra_files_and_test_removal(self) -> None:
        import patch_provenance as module

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            patch = root / "third_party" / "demo"
            test_path = patch / "tests" / "fixture.txt"
            test_path.parent.mkdir(parents=True)
            cargo_manifest = '[package]\nname = "demo"\nversion = "1.0.0"\n'
            patch_notes = "# demo patch\n"
            test_asset = "published fixture\n"
            (patch / "Cargo.toml").write_text(cargo_manifest, encoding="utf-8")
            (patch / "PATCH.md").write_text(patch_notes, encoding="utf-8")
            test_path.write_text(test_asset, encoding="utf-8")
            provenance_path = patch / "PATCH_PROVENANCE.json"
            provenance = {
                "schema": "netdiag-local-patch-provenance/v1",
                "crate": "demo",
                "version": "1.0.0",
                "archive": {
                    "file_name": "demo-1.0.0.crate",
                    "url": "https://static.crates.io/crates/demo/demo-1.0.0.crate",
                    "sha256": "0" * 64,
                },
                "upstream_files": {
                    "Cargo.toml": hashlib.sha256(
                        cargo_manifest.encode("utf-8")
                    ).hexdigest(),
                    "tests/fixture.txt": hashlib.sha256(
                        test_asset.encode("utf-8")
                    ).hexdigest(),
                },
                "allowed_diff": {
                    "modified": {},
                    "added": {
                        "PATCH.md": hashlib.sha256(
                            patch_notes.encode("utf-8")
                        ).hexdigest()
                    },
                    "removed": [],
                },
                "preserved_test_directories": ["tests"],
            }
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")

            failures: list[str] = []
            module.validate_patch_provenance(
                root, {"demo": "third_party/demo"}, failures
            )
            self.assertEqual(failures, [])

            (patch / "Cargo.toml").write_text(cargo_manifest + "# drift\n")
            failures = []
            module.validate_patch_provenance(
                root, {"demo": "third_party/demo"}, failures
            )
            self.assertTrue(any("digest mismatch: Cargo.toml" in item for item in failures))
            (patch / "Cargo.toml").write_text(cargo_manifest, encoding="utf-8")

            (patch / "undeclared.txt").write_text("unexpected\n", encoding="utf-8")
            failures = []
            module.validate_patch_provenance(
                root, {"demo": "third_party/demo"}, failures
            )
            self.assertTrue(any("undeclared files" in item for item in failures))
            (patch / "undeclared.txt").unlink()

            test_path.unlink()
            provenance["allowed_diff"]["removed"] = ["tests/fixture.txt"]
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
            failures = []
            module.validate_patch_provenance(
                root, {"demo": "third_party/demo"}, failures
            )
            self.assertTrue(
                any("must remain byte-for-byte intact" in item for item in failures)
            )

    def test_local_patch_walk_is_bounded_before_unbounded_hashing(self) -> None:
        import patch_provenance as module

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("a", "b", "c"):
                (root / name).write_text(name, encoding="utf-8")
            failures: list[str] = []
            with mock.patch.object(module, "MAX_ARCHIVE_FILES", 2):
                digests = module.local_file_digests(root, failures)
            self.assertLessEqual(len(digests), 2)
            self.assertTrue(any("entry count" in item for item in failures))

            failures = []
            with mock.patch.object(module, "MAX_ARCHIVE_CONTENT_BYTES", 1):
                digests = module.local_file_digests(root, failures)
            self.assertLessEqual(len(digests), 1)
            self.assertTrue(any("aggregate byte" in item for item in failures))

    def test_patch_archive_verification_checks_raw_sha_and_inventory(self) -> None:
        import patch_provenance as module

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            patch = root / "third_party" / "demo"
            archive_directory = root / "archives"
            patch.mkdir(parents=True)
            archive_directory.mkdir()
            cargo_manifest = '[package]\nname = "demo"\nversion = "1.0.0"\n'
            patch_notes = "# demo patch\n"
            (patch / "Cargo.toml").write_text(cargo_manifest, encoding="utf-8")
            (patch / "PATCH.md").write_text(patch_notes, encoding="utf-8")
            archive_path = archive_directory / "demo-1.0.0.crate"
            with tarfile.open(archive_path, mode="w:gz") as archive:
                info = tarfile.TarInfo("demo-1.0.0/Cargo.toml")
                content = cargo_manifest.encode("utf-8")
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            archive_sha = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            (patch / "PATCH_PROVENANCE.json").write_text(
                json.dumps(
                    {
                        "schema": "netdiag-local-patch-provenance/v1",
                        "crate": "demo",
                        "version": "1.0.0",
                        "archive": {
                            "file_name": "demo-1.0.0.crate",
                            "url": "https://static.crates.io/crates/demo/demo-1.0.0.crate",
                            "sha256": archive_sha,
                        },
                        "upstream_files": {
                            "Cargo.toml": hashlib.sha256(content).hexdigest()
                        },
                        "allowed_diff": {
                            "modified": {},
                            "added": {
                                "PATCH.md": hashlib.sha256(
                                    patch_notes.encode("utf-8")
                                ).hexdigest()
                            },
                            "removed": [],
                        },
                        "preserved_test_directories": [],
                    }
                ),
                encoding="utf-8",
            )

            failures: list[str] = []
            with mock.patch.object(
                tarfile.TarFile,
                "getmembers",
                side_effect=AssertionError("archive inventory must stream"),
            ):
                module.validate_patch_provenance(
                    root,
                    {"demo": "third_party/demo"},
                    failures,
                    archive_directory,
                )
            self.assertEqual(failures, [])

            archive_path.write_bytes(archive_path.read_bytes() + b"drift")
            failures = []
            module.validate_patch_provenance(
                root,
                {"demo": "third_party/demo"},
                failures,
                archive_directory,
            )
            self.assertTrue(any("SHA-256 mismatch" in item for item in failures))


class CiPlatformGateTests(unittest.TestCase):
    def platform_job(self) -> str:
        ci_workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "uses: ./.github/workflows/platform-security.yml",
            ci_workflow,
        )
        return (
            REPO_ROOT / ".github" / "workflows" / "platform-security.yml"
        ).read_text(encoding="utf-8")

    def test_platform_matrix_matches_mutation_capabilities(self) -> None:
        job = self.platform_job()
        self.assertIn("os: [ubuntu-24.04, windows-2025]", job)
        clippy = next(
            line.strip()
            for line in job.splitlines()
            if line.strip().startswith("run: cargo clippy ")
        )
        linux_test = next(
            line.strip()
            for line in job.splitlines()
            if line.strip().startswith("run: cargo test ")
            and "-p netdiag-cli" in line
        )
        for command in [clippy, linux_test]:
            for package in [
                "netdiag-platform",
                "netdiag-core",
                "netdiag-cli",
                "netdiag-app",
            ]:
                self.assertIn(f"-p {package}", command)
            self.assertIn("--all-targets", command)
            self.assertIn("--all-features", command)
        self.assertIn("Test full platform and consumer layers on Linux", job)
        self.assertIn("Test Windows platform primitives with warnings denied", job)
        self.assertIn(
            "cargo test --locked -p netdiag-platform --all-targets --all-features",
            job,
        )
        self.assertIn("Test Windows fail-closed mutation contracts", job)
        self.assertIn(
            "cargo test --locked -p netdiag-core --test windows_mutation_contract --all-features",
            job,
        )
        self.assertIn(
            "rustup target add --toolchain 1.95.0 wasm32-wasip1",
            job,
        )
        self.assertIn(
            "cargo clippy --locked -p netdiag-platform --target wasm32-wasip1 --all-targets --all-features -- -D warnings",
            job,
        )

    def test_platform_warnings_and_native_dependencies_fail_closed(self) -> None:
        job = self.platform_job()
        self.assertIn('RUSTFLAGS: "-D warnings"', job)
        self.assertIn("acl libpcap-dev", job)
        clippy = next(
            line.strip()
            for line in job.splitlines()
            if line.strip().startswith("run: cargo clippy ")
        )
        self.assertTrue(clippy.endswith("-- -D warnings"))

    def test_windows_pcap_runtime_is_pinned_and_verified(self) -> None:
        job = self.platform_job()
        match = re.search(r'NETDIAG_VCPKG_COMMIT: "([0-9a-f]{40})"', job)
        self.assertIsNotNone(match)
        cache_path = "${{ runner.temp }}/netdiag-vcpkg-binary-cache"
        self.assertIn(f"path: {cache_path}", job)
        self.assertIn(f"VCPKG_DEFAULT_BINARY_CACHE: {cache_path}", job)
        self.assertLess(
            job.index("- name: Restore pinned Windows libpcap binary cache"),
            job.index("- name: Install pinned Windows libpcap test runtime"),
        )
        install_step = job.split(
            "- name: Install pinned Windows libpcap test runtime", 1
        )[1].split("\n      - name:", 1)[0]
        strict_mode = install_step.index("Set-StrictMode -Version Latest")
        terminating_errors = install_step.index('$ErrorActionPreference = "Stop"')
        native_errors = install_step.index(
            "$PSNativeCommandUseErrorActionPreference = $true"
        )
        cache_creation = install_step.index(
            "New-Item -ItemType Directory -Force -Path $env:VCPKG_DEFAULT_BINARY_CACHE"
        )
        cache_validation = install_step.index(
            "Test-Path -LiteralPath $env:VCPKG_DEFAULT_BINARY_CACHE -PathType Container"
        )
        install = install_step.index('install "libpcap:$triplet"')
        self.assertEqual(
            [
                strict_mode,
                terminating_errors,
                native_errors,
                cache_creation,
                cache_validation,
                install,
            ],
            sorted(
                [
                    strict_mode,
                    terminating_errors,
                    native_errors,
                    cache_creation,
                    cache_validation,
                    install,
                ]
            ),
        )
        self.assertIn('install "libpcap:$triplet"', job)
        self.assertIn("lib\\wpcap.lib", job)
        self.assertIn("bin\\wpcap.dll", job)
        self.assertGreaterEqual(job.count("throw \"vcpkg did not produce"), 2)


class HttpConnectorSecurityGateTests(unittest.TestCase):
    def source(self, relative: str) -> str:
        return (REPO_ROOT / relative).read_text(encoding="utf-8")

    def test_http_loaders_share_a_no_redirect_sensitive_auth_client(self) -> None:
        client = self.source("crates/netdiag-core/src/connectors/http_client.rs")
        authorization = self.source(
            "crates/netdiag-core/src/connectors/http_client/authorization.rs"
        )
        token = self.source(
            "crates/netdiag-core/src/connectors/authentication/token.rs"
        )
        self.assertIn(".redirect(Policy::none())", client)
        self.assertIn(".no_proxy()", client)
        self.assertIn("bearer_header(bearer_token, context)", client)
        self.assertIn("Option<&ValidatedBearerToken>", client)
        self.assertIn(".authorization_header()", authorization)
        self.assertNotIn("token.to_owned()", authorization)
        self.assertNotIn("into_inner", authorization)
        self.assertIn("value: Zeroizing<String>", token)
        self.assertIn("let value = Zeroizing::new(value);", token)
        self.assertNotIn("#[derive(Clone", token)
        self.assertNotIn("into_inner", token)
        self.assertIn("authorization.set_sensitive(true)", token)
        self.assertIn("require_bearer_transport(&self.endpoint)", client)
        authentication_tests = self.source(
            "crates/netdiag-core/src/connectors/authentication/tests.rs"
        )
        authorization_tests = authorization
        self.assertIn(
            "token_validation_rejects_header_injection_without_disclosing_input",
            authentication_tests,
        )
        self.assertIn("HTTP header injection must be rejected", authentication_tests)
        self.assertIn('header.to_str().expect("ASCII header")', authorization_tests)
        self.assertIn('"Bearer private-token"', authorization_tests)
        for relative in (
            "crates/netdiag-core/src/connectors/http_json.rs",
            "crates/netdiag-core/src/connectors/prometheus.rs",
        ):
            loader = self.source(relative)
            self.assertIn("ConnectorHttpClient", loader)
            self.assertNotIn(".bearer_auth(", loader)
            self.assertNotIn("Client::builder()", loader)

    def test_http_json_records_use_bounded_typed_decode_without_payload_dom_clones(self) -> None:
        loader = self.source("crates/netdiag-core/src/connectors/http_json.rs")
        decoder = self.source(
            "crates/netdiag-core/src/connectors/http_json/decode.rs"
        )
        envelope = self.source(
            "crates/netdiag-core/src/connectors/http_json/decode/envelope.rs"
        )
        pilot = self.source("crates/netdiag-core/src/pilot/pilot_sources.rs")
        self.assertIn("decode_response(&response_bytes)?", loader)
        self.assertIn("drop(response_bytes)", loader)
        self.assertNotIn("serde_json::from_value", loader)
        self.assertNotIn("value.clone()", loader)
        self.assertIn("BoundedRecords", decoder)
        self.assertIn("ResponseEnvelope", decoder)
        self.assertIn("records: OptionalValue<BoundedRecords>", envelope)
        self.assertNotIn("serde(flatten)", envelope)
        self.assertIn("loaded.payload.take()", pilot)

    def test_bearer_credentials_have_recoverable_scope_lifecycle_and_clear_ui_inputs(self) -> None:
        lifecycle = self.source(
            "crates/netdiag-app/src/credential_lifecycle.rs"
        )
        settings = self.source(
            "crates/netdiag-app/src/settings/bearer_credentials.rs"
        )
        main = self.source("crates/netdiag-app/src/main.rs")
        self.assertIn("BearerCredentialState::PendingDeletion", lifecycle)
        self.assertIn("failed to write the new scoped bearer credential", lifecycle)
        self.assertIn("failed to prepare the destination bearer credential registry", lifecycle)
        self.assertNotIn("prepared destination rollback also failed", lifecycle)
        self.assertIn(
            "retained for deterministic startup reconciliation", lifecycle
        )
        self.assertIn(
            "post_publication_activation_failure_never_rolls_back_the_new_secret",
            lifecycle,
        )
        self.assertIn("delete_legacy_live_api_token()", lifecycle)
        self.assertNotIn("get_legacy_live_api_token", main)
        self.assertIn("canonical_origin: String", settings)
        self.assertNotIn("token:", settings)
        self.assertGreaterEqual(main.count("token_input.zeroize();"), 4)
        self.assertNotIn("legacy_token_presence", main)

    def test_endpoint_and_settings_boundaries_share_sensitive_query_policy(self) -> None:
        endpoint = self.source(
            "crates/netdiag-core/src/connectors/http_endpoint.rs"
        )
        settings = self.source(
            "crates/netdiag-app/src/settings/validation/connectors/http_endpoint.rs"
        )
        self.assertIn("is_sensitive_parameter_key", endpoint)
        self.assertIn('host.parse::<IpAddr>()', endpoint)
        self.assertIn("validate_http_connector_endpoint(value)", settings)


class DocsWorkflowHygieneTests(unittest.TestCase):
    def run_docs_guard(self, readme: str, getting_started: str = "") -> tuple[int, str]:
        module = load_script("check_docs_workflow_hygiene")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            readme_path = root / "README.md"
            docs = root / "docs"
            docs.mkdir()
            getting_path = docs / "getting-started.md"
            readme_path.write_text(readme)
            getting_path.write_text(getting_started)
            module.ROOT = root
            module.DOCS = [readme_path, getting_path]
            code, stdout, stderr = run_main(module)
        return code, stdout + stderr

    def test_guard_covers_adapter_command_documents(self) -> None:
        module = load_script("check_docs_workflow_hygiene")
        covered = {path.relative_to(module.ROOT).as_posix() for path in module.DOCS}
        self.assertIn("docs/api-source.md", covered)
        self.assertIn("examples/adapters/README.md", covered)

    def test_rejects_adapter_validation_without_the_prebuilt_validator(self) -> None:
        code, output = self.run_docs_guard(
            """
            ```bash
            python3 scripts/validate_adapter_samples.py
            ```
            """
        )
        self.assertNotEqual(code, 0)
        self.assertIn("must pass the fixed Rust validator", output)
        self.assertIn("must follow a locked validator build", output)

    def test_accepts_explicit_adapter_validator_build_and_commands(self) -> None:
        code, output = self.run_docs_guard(
            """
            ```bash
            validator_target="$(pwd -P)/target/adapter-validator"
            CARGO_TARGET_DIR="$validator_target" cargo build --locked \\
              -p netdiag-cli --bin netdiag-cli
            .venv-jsonschema/bin/python scripts/validate_adapter_samples.py \\
              --rust-validator "$validator_target/debug/netdiag-cli"
            .venv-jsonschema/bin/python scripts/validate_adapter_contract.py \\
              --rust-validator "$validator_target/debug/netdiag-cli"
            ```
            """
        )
        self.assertEqual(code, 0, output)

    def test_rejects_lab_calibration_before_first_lab_run(self) -> None:
        code, output = self.run_docs_guard(
            """
            cargo run -p netdiag-cli -- lab calibrate --artifacts artifacts
            cargo run -p netdiag-cli -- lab run examples/scenarios/lab-congestion-001.yaml
            """
        )
        self.assertNotEqual(code, 0)
        self.assertIn("documents lab calibrate before the first lab run", output)

    def test_rejects_unscoped_90_percent_coverage_claims(self) -> None:
        code, output = self.run_docs_guard("The strict gate targets 90% coverage.")
        self.assertNotEqual(code, 0)
        self.assertIn("unscoped 90% coverage claim", output)

    def test_rejects_model_gate_example_without_calibration_report(self) -> None:
        code, output = self.run_docs_guard(
            """
            cargo run -p netdiag-cli -- pilot model-gate \\
              --model-dir artifacts/model \\
              --benchmark-report target/benchmark-report/benchmark_report.json
            """
        )
        self.assertNotEqual(code, 0)
        self.assertIn("model-gate example missing --calibration-report", output)

    def test_allows_bundled_benchmark_example_without_model_dir(self) -> None:
        code, output = self.run_docs_guard(
            """
            CARGO_TARGET_DIR="$PWD/target/adapter-validator" cargo build --locked -p netdiag-cli --bin netdiag-cli
            cargo run -p netdiag-cli -- benchmark run \\
              --artifacts target/benchmark-artifacts \\
              --output target/benchmark-report
            """
        )
        self.assertEqual(code, 0, output)

    def test_rejects_benchmark_example_without_validator_prebuild(self) -> None:
        code, output = self.run_docs_guard(
            """
            cargo run -p netdiag-cli -- benchmark run \\
              --artifacts target/benchmark-artifacts \\
              --output target/benchmark-report
            """
        )
        self.assertNotEqual(code, 0)
        self.assertIn("must prebuild the trusted Rust validator", output)

    def test_promotion_benchmark_requires_candidate_model_dir(self) -> None:
        code, output = self.run_docs_guard(
            """
            cargo run -p netdiag-cli -- lab run examples/scenarios/lab-congestion-001.yaml
            cargo run -p netdiag-cli -- lab calibrate --artifacts artifacts
            cargo run -p netdiag-cli -- benchmark run \\
              --output target/benchmark-report
            cargo run -p netdiag-cli -- pilot model-gate \\
              --model-dir artifacts/model \\
              --benchmark-report target/benchmark-report/benchmark_report.json \\
              --calibration-report artifacts/lab_calibration_report.json
            """
        )
        self.assertNotEqual(code, 0)
        self.assertIn("promotion benchmark example missing --model-dir", output)

    def test_rejects_promotion_commands_in_stale_hash_order(self) -> None:
        code, output = self.run_docs_guard(
            """
            cargo run -p netdiag-cli -- lab run examples/scenarios/lab-congestion-001.yaml
            cargo run -p netdiag-cli -- benchmark run --model-dir artifacts/model
            cargo run -p netdiag-cli -- lab calibrate --artifacts artifacts
            cargo run -p netdiag-cli -- pilot model-gate \\
              --model-dir artifacts/model \\
              --benchmark-report target/benchmark-report/benchmark_report.json \\
              --calibration-report artifacts/lab_calibration_report.json
            """
        )
        self.assertNotEqual(code, 0)
        self.assertIn("must order lab calibrate before benchmark run", output)

    def test_accepts_complete_promotion_command_order(self) -> None:
        code, output = self.run_docs_guard(
            """
            cargo run -p netdiag-cli -- lab run examples/scenarios/lab-congestion-001.yaml
            cargo run -p netdiag-cli -- lab calibrate --artifacts artifacts
            CARGO_TARGET_DIR="$PWD/target/adapter-validator" cargo build --locked -p netdiag-cli --bin netdiag-cli
            cargo run -p netdiag-cli -- benchmark run --model-dir artifacts/model
            cargo run -p netdiag-cli -- pilot model-gate \\
              --model-dir artifacts/model \\
              --benchmark-report target/benchmark-report/benchmark_report.json \\
              --calibration-report artifacts/lab_calibration_report.json
            """
        )
        self.assertEqual(code, 0, output)


class RealDeviceReadinessTests(unittest.TestCase):
    RUN_ID = "real-device-run-001"
    PILOT_ID = "real-device-pilot-001"
    MODEL_MANIFEST_HASH = "a" * 64
    MODEL_FILE_HASH = "b" * 64

    def test_sha256_contract_requires_canonical_lowercase_hex(self) -> None:
        module = load_script("check_real_device_readiness")
        self.assertTrue(module.is_hex_sha256("a" * 64))
        self.assertTrue(module.is_hex_sha256("0" * 64))
        self.assertFalse(module.is_hex_sha256("A" * 64))
        self.assertFalse(module.is_hex_sha256("g" * 64))

    def test_evidence_json_rejects_duplicate_keys_and_symlink_paths(self) -> None:
        module = load_script("check_real_device_readiness")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.json"
            target.write_text('{"status":"first","status":"second"}', encoding="utf-8")
            failures: list[str] = []
            payload, _digest = module.read_hashed_json_value(
                target,
                label="evidence",
                max_bytes=1024,
                failures=failures,
            )
            self.assertIsNone(payload)
            self.assertTrue(any("duplicate object key" in item for item in failures))

            link = root / "link.json"
            link.symlink_to(target)
            failures = []
            payload, digest = module.read_hashed_json_value(
                link,
                label="evidence",
                max_bytes=1024,
                failures=failures,
            )
            self.assertIsNone(payload)
            self.assertIsNone(digest)
            self.assertTrue(any("opened safely" in item for item in failures))

            outside = root / "outside"
            outside.mkdir()
            (outside / "artifact.json").write_text("{}", encoding="utf-8")
            (root / "artifacts").symlink_to(outside, target_is_directory=True)
            failures = []
            payload, digest = module.read_hashed_json_value_beneath(
                root,
                "artifacts/artifact.json",
                label="evidence artifact",
                max_bytes=1024,
                failures=failures,
            )
            self.assertIsNone(payload)
            self.assertIsNone(digest)
            self.assertTrue(any("opened safely" in item for item in failures))

    def run_readiness_guard(
        self,
        status: dict,
        *,
        docs_body: str = "pending_lab_access not_validated",
        manifest_body: dict | None = None,
        manifest_is_dir: bool = False,
        artifact_payloads: dict[str, object] | None = None,
        artifact_text_overrides: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        module = load_script("check_real_device_readiness")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            docs.mkdir()
            status_path = docs / "real-device-pilot-readiness.json"
            status_path.write_text(json.dumps(status))
            status_doc = docs / "real-device-pilot-readiness.md"
            status_doc.write_text(docs_body)
            readme = root / "README.md"
            readme.write_text(docs_body)
            pilot = docs / "pilot-run-center.md"
            pilot.write_text(docs_body)
            quality = docs / "quality-gates.md"
            quality.write_text(docs_body)
            release = docs / "release-process.md"
            release.write_text(docs_body)
            manifest = root / "artifacts" / "real-device-evidence.json"
            if manifest_is_dir:
                manifest.mkdir(parents=True)
            elif manifest_body is not None:
                manifest.parent.mkdir(parents=True)
                manifest.write_text(json.dumps(manifest_body))
                for artifact in manifest_body.get("artifacts", []):
                    if (
                        isinstance(artifact, dict)
                        and isinstance(artifact.get("path"), str)
                    ):
                        artifact_path = root / artifact["path"]
                        artifact_path.parent.mkdir(parents=True, exist_ok=True)
                        kind = artifact.get("kind")
                        if (
                            artifact_text_overrides is not None
                            and isinstance(kind, str)
                            and kind in artifact_text_overrides
                        ):
                            body = artifact_text_overrides[kind]
                        elif (
                            artifact_payloads is not None
                            and isinstance(kind, str)
                            and kind in artifact_payloads
                        ):
                            body = json.dumps(artifact_payloads[kind], sort_keys=True)
                        else:
                            body = "{}"
                        artifact_path.write_text(body)

            module.ROOT = root
            module.STATUS_PATH = status_path
            module.STATUS_DOC = status_doc
            module.DOCS_WITH_STATUS = [readme, pilot, quality, release]
            code, stdout, stderr = run_main(module)
        return code, stdout + stderr

    def pending_status(self) -> dict:
        return {
            "schema": "netdiag-real-device-pilot-readiness/v1",
            "status": "pending_lab_access",
            "real_device_validation": "not_validated",
            "real_device_release_claim_eligible": False,
            "blocking_reason": "lab_device_access_unavailable",
            "validated_evidence_manifest": None,
            "required_evidence_before_claim": ["pilot preflight report"],
        }

    def validated_status(self) -> dict:
        return {
            "schema": "netdiag-real-device-pilot-readiness/v1",
            "status": "validated",
            "real_device_validation": "validated",
            "real_device_release_claim_eligible": True,
            "blocking_reason": None,
            "validated_evidence_manifest": "artifacts/real-device-evidence.json",
            "required_evidence_before_claim": [],
        }

    def reviewed_artifacts(self) -> dict[str, object]:
        source_inventory = [
            {
                "name": "openconfig-primary",
                "kind": "adapter_sample",
                "role": "primary",
                "endpoint": "examples/adapters/openconfig-gnmi/adapter.py",
                "active": False,
                "metadata": {"adapter_contract": "netdiag-adapter/v1"},
            }
        ]
        connector_health = [
            {
                "status": "ok",
                "source_kind": "adapter_sample",
                "profile_name": "openconfig-primary",
                "sample": "real-device-sample-001",
                "rows": 12,
                "warning_count": 0,
                "missing_metrics": [],
                "quality": {
                    "measured": 84,
                    "estimated": 0,
                    "fallback": 0,
                    "missing": 0,
                },
                "captured_at": "2026-07-11T01:02:03Z",
            }
        ]
        evidence_bundle = {
            "schema": "netdiag-evidence-bundle/v1",
            "run_id": self.RUN_ID,
            "created_at": "2026-07-11T01:03:00Z",
            "output": f"artifacts/netdiag-evidence-{self.RUN_ID}.zip",
            "files": [
                {
                    "key": "report",
                    "source_path": f"artifacts/runs/{self.RUN_ID}/report.json",
                    "zip_path": "report.json",
                    "bytes": 1024,
                    "sha256": "c" * 64,
                },
                {
                    "key": "connector_health",
                    "source_path": "artifacts/connector_health.json",
                    "zip_path": "connector_health.json",
                    "bytes": 512,
                    "sha256": "d" * 64,
                },
            ],
        }
        preflight = {
            "schema": "netdiag-pilot-preflight/v1",
            "generated_at": "2026-07-11T01:00:00Z",
            "pilot_id": self.PILOT_ID,
            "passed": True,
            "source_inventory": source_inventory,
            "checks": [
                {
                    "name": "adapter preflight",
                    "status": "ok",
                    "message": "live adapter preflight passed",
                }
            ],
        }
        pilot_run = {
            "schema": "netdiag-pilot-report/v1",
            "generated_at": "2026-07-11T01:02:04Z",
            "pilot_id": self.PILOT_ID,
            "pilot_name": "Real device pilot",
            "read_only": True,
            "passed": True,
            "run_id": self.RUN_ID,
            "pilot_run_dir": "artifacts/pilot-runs/real-device-pilot-001",
            "source_inventory": source_inventory,
            "connector_health": connector_health,
            "diagnosis_summary": {
                "diagnosis_status": "known",
                "primary_label": "normal",
                "root_causes": [],
                "recommendation_count": 0,
            },
            "evidence_bundle": evidence_bundle,
            "checks": [
                {
                    "name": "artifact completeness",
                    "status": "ok",
                    "message": "required artifacts are present",
                }
            ],
        }
        workflow = {
            "schema": "netdiag-pilot-workflow/v1",
            "generated_at": "2026-07-11T01:04:00Z",
            "pilot_id": self.PILOT_ID,
            "passed": True,
            "phases": [
                {"name": name, "status": "passed", "message": "passed"}
                for name in [
                    "preflight",
                    "collect",
                    "diagnose",
                    "evidence_bundle",
                    "verify",
                ]
            ]
            + [{"name": "review", "status": "pending", "message": "reviewed"}],
            "preflight": preflight,
            "pilot_run": pilot_run,
            "verification": {
                "schema": "netdiag-action-verification/v1",
                "generated_at": "2026-07-11T01:04:00Z",
                "before_run_id": self.RUN_ID,
                "after_run_id": "real-device-after-run-001",
                "verdict": "verified",
                "reasons": [],
            },
        }
        promotion_gates = [
            "model_load",
            "benchmark_model_match",
            "calibration_model_match",
            "calibration_thresholds_integrated",
            "benchmark_report",
        ]
        model_promotion_gate = {
            "schema": "netdiag-model-promotion-gate/v1",
            "generated_at": "2026-07-11T00:55:00Z",
            "passed": True,
            "model_dir": "artifacts/model",
            "benchmark_report": "artifacts/benchmark_report.json",
            "calibration_report": "artifacts/lab_calibration_report.json",
            "model_manifest_hash_sha256": self.MODEL_MANIFEST_HASH,
            "model_file_hash_sha256": self.MODEL_FILE_HASH,
            "gates": [
                {"name": name, "passed": True, "message": "passed"}
                for name in promotion_gates
            ],
        }
        return {
            "pilot_preflight": preflight,
            "pilot_workflow": workflow,
            "connector_health": connector_health,
            "evidence_bundle": evidence_bundle,
            "model_promotion_gate": model_promotion_gate,
        }

    def clone_artifacts(self) -> dict[str, object]:
        return json.loads(json.dumps(self.reviewed_artifacts()))

    def reviewed_manifest(self, artifact_payloads: dict[str, object]) -> dict:
        return {
            "schema": "netdiag-real-device-evidence-manifest/v1",
            "source_mode": "real_device",
            "sample_only": False,
            "collection_mode": "live",
            "run_id": self.RUN_ID,
            "pilot_id": self.PILOT_ID,
            "model_identity": {
                "model_manifest_hash_sha256": self.MODEL_MANIFEST_HASH,
                "model_file_hash_sha256": self.MODEL_FILE_HASH,
            },
            "artifacts": [
                {
                    "kind": kind,
                    "path": f"artifacts/{kind}.json",
                    "run_id": self.RUN_ID,
                    "sha256": hashlib.sha256(
                        json.dumps(artifact_payloads[kind], sort_keys=True).encode()
                    ).hexdigest(),
                }
                for kind in [
                    "pilot_preflight",
                    "pilot_workflow",
                    "connector_health",
                    "evidence_bundle",
                    "model_promotion_gate",
                ]
            ],
        }

    def test_pending_status_rejects_validation_claims_and_evidence_manifest(self) -> None:
        status = self.pending_status()
        status["validated_evidence_manifest"] = "artifacts/real-device-evidence.json"
        code, output = self.run_readiness_guard(
            status,
            docs_body="pending_lab_access not_validated real-device validated",
        )
        self.assertNotEqual(code, 0)
        self.assertIn("must not claim", output)
        self.assertIn("must not point at a validated evidence manifest", output)

    def test_validated_status_rejects_directory_manifest(self) -> None:
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_is_dir=True,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("must be a file", output)

    def test_validated_status_rejects_bad_manifest_schema(self) -> None:
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_body={"schema": "wrong/v1", "artifacts": ["x"]},
        )
        self.assertNotEqual(code, 0)
        self.assertIn("schema", output)

    def test_validated_status_accepts_reviewed_evidence_manifest(self) -> None:
        artifacts = self.reviewed_artifacts()
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_body=self.reviewed_manifest(artifacts),
            artifact_payloads=artifacts,
        )
        self.assertEqual(code, 0, output)

    def test_validated_status_rejects_artifact_tampering(self) -> None:
        artifacts = self.reviewed_artifacts()
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_body=self.reviewed_manifest(artifacts),
            artifact_payloads=artifacts,
            artifact_text_overrides={"pilot_preflight": '{"tampered":true}'},
        )
        self.assertNotEqual(code, 0)
        self.assertIn("SHA-256 does not match file content", output)

    def test_validated_status_rejects_duplicate_artifact_kind(self) -> None:
        artifacts = self.reviewed_artifacts()
        manifest = self.reviewed_manifest(artifacts)
        manifest["artifacts"].append(
            {
                "kind": "pilot_preflight",
                "path": "artifacts/duplicate-preflight.json",
                "run_id": self.RUN_ID,
                "sha256": hashlib.sha256(
                    json.dumps(artifacts["pilot_preflight"], sort_keys=True).encode()
                ).hexdigest(),
            }
        )
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_body=manifest,
            artifact_payloads=artifacts,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("duplicates kind", output)

    def test_validated_status_rejects_duplicate_artifact_path(self) -> None:
        artifacts = self.reviewed_artifacts()
        manifest = self.reviewed_manifest(artifacts)
        manifest["artifacts"].append(
            {
                "kind": "model_promotion_gate",
                "path": "artifacts/pilot_preflight.json",
                "run_id": self.RUN_ID,
                "sha256": hashlib.sha256(
                    json.dumps(artifacts["pilot_preflight"], sort_keys=True).encode()
                ).hexdigest(),
            }
        )
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_body=manifest,
            artifact_payloads=artifacts,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("duplicates path", output)

    def test_validated_status_rejects_empty_json_for_every_required_artifact(self) -> None:
        for kind in self.reviewed_artifacts():
            with self.subTest(kind=kind):
                artifacts = self.clone_artifacts()
                artifacts[kind] = {}
                code, output = self.run_readiness_guard(
                    self.validated_status(),
                    docs_body="validated",
                    manifest_body=self.reviewed_manifest(artifacts),
                    artifact_payloads=artifacts,
                )
                self.assertNotEqual(code, 0)
                self.assertIn(kind, output)

    def test_validated_status_rejects_wrong_artifact_schemas(self) -> None:
        for kind in [
            "pilot_preflight",
            "pilot_workflow",
            "evidence_bundle",
            "model_promotion_gate",
        ]:
            with self.subTest(kind=kind):
                artifacts = self.clone_artifacts()
                artifact = artifacts[kind]
                self.assertIsInstance(artifact, dict)
                artifact["schema"] = "wrong/v1"
                code, output = self.run_readiness_guard(
                    self.validated_status(),
                    docs_body="validated",
                    manifest_body=self.reviewed_manifest(artifacts),
                    artifact_payloads=artifacts,
                )
                self.assertNotEqual(code, 0)
                self.assertIn(f"{kind} schema", output)

    def test_validated_status_rejects_failed_reports_and_connector_status(self) -> None:
        for kind in ["pilot_preflight", "pilot_workflow", "model_promotion_gate"]:
            with self.subTest(kind=kind):
                artifacts = self.clone_artifacts()
                artifact = artifacts[kind]
                self.assertIsInstance(artifact, dict)
                artifact["passed"] = False
                code, output = self.run_readiness_guard(
                    self.validated_status(),
                    docs_body="validated",
                    manifest_body=self.reviewed_manifest(artifacts),
                    artifact_payloads=artifacts,
                )
                self.assertNotEqual(code, 0)
                self.assertIn("passed=true", output)

        artifacts = self.clone_artifacts()
        connector_health = artifacts["connector_health"]
        self.assertIsInstance(connector_health, list)
        connector_health[0]["status"] = "error"
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_body=self.reviewed_manifest(artifacts),
            artifact_payloads=artifacts,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("status must be ok or degraded", output)

    def test_validated_status_rejects_sample_collection_provenance(self) -> None:
        artifacts = self.reviewed_artifacts()
        manifest = self.reviewed_manifest(artifacts)
        manifest["source_mode"] = "sample"
        manifest["sample_only"] = True
        manifest["collection_mode"] = "sample"
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_body=manifest,
            artifact_payloads=artifacts,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("source_mode=real_device", output)
        self.assertIn("sample_only=false", output)
        self.assertIn("collection_mode=live", output)

    def test_validated_status_rejects_failed_workflow_and_promotion_subgates(self) -> None:
        artifacts = self.clone_artifacts()
        workflow = artifacts["pilot_workflow"]
        self.assertIsInstance(workflow, dict)
        verify_phase = next(
            phase for phase in workflow["phases"] if phase["name"] == "verify"
        )
        verify_phase["status"] = "pending"
        workflow["verification"]["verdict"] = "not_verified"
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_body=self.reviewed_manifest(artifacts),
            artifact_payloads=artifacts,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("phase 'verify' must be passed", output)
        self.assertIn("verification verdict must be verified", output)

        artifacts = self.clone_artifacts()
        promotion = artifacts["model_promotion_gate"]
        self.assertIsInstance(promotion, dict)
        promotion["gates"][0]["passed"] = False
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_body=self.reviewed_manifest(artifacts),
            artifact_payloads=artifacts,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("model_promotion_gate gate 0 must set passed=true", output)

    def test_validated_status_rejects_run_and_pilot_identity_mismatches(self) -> None:
        artifacts = self.clone_artifacts()
        evidence_bundle = artifacts["evidence_bundle"]
        self.assertIsInstance(evidence_bundle, dict)
        evidence_bundle["run_id"] = "different-run"
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_body=self.reviewed_manifest(artifacts),
            artifact_payloads=artifacts,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("evidence_bundle run_id must match", output)

        artifacts = self.clone_artifacts()
        preflight = artifacts["pilot_preflight"]
        self.assertIsInstance(preflight, dict)
        preflight["pilot_id"] = "different-pilot"
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_body=self.reviewed_manifest(artifacts),
            artifact_payloads=artifacts,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("pilot_id must match", output)

        artifacts = self.reviewed_artifacts()
        manifest = self.reviewed_manifest(artifacts)
        manifest["artifacts"][0]["run_id"] = "different-run"
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_body=manifest,
            artifact_payloads=artifacts,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("artifact 0 run_id must match", output)

    def test_validated_status_rejects_model_identity_mismatch(self) -> None:
        artifacts = self.clone_artifacts()
        promotion = artifacts["model_promotion_gate"]
        self.assertIsInstance(promotion, dict)
        promotion["model_manifest_hash_sha256"] = "e" * 64
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated",
            manifest_body=self.reviewed_manifest(artifacts),
            artifact_payloads=artifacts,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("must match the evidence manifest model_identity", output)

    def test_validated_status_rejects_pending_claims_in_docs(self) -> None:
        artifacts = self.reviewed_artifacts()
        code, output = self.run_readiness_guard(
            self.validated_status(),
            docs_body="validated pending_lab_access not_validated",
            manifest_body=self.reviewed_manifest(artifacts),
            artifact_payloads=artifacts,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("must not state pending_lab_access or not_validated", output)


class AppSecurityCoverageTests(unittest.TestCase):
    def coverage_payload(self, covered: int = 90) -> dict:
        module = load_script("check_app_security_coverage")
        failures: list[str] = []
        library, binary = module.expected_security_file_sets(failures)
        self.assertEqual(failures, [])
        files = [
            {
                "filename": relative,
                "summary": {
                    "lines": {
                        "covered": covered,
                        "count": 100,
                        "percent": float(covered),
                    }
                },
            }
            for relative in sorted(library | binary)
        ]
        count = len(files) * 100
        covered_total = len(files) * covered
        return {
            "data": [
                {
                    "totals": {
                        "lines": {
                            "covered": covered_total,
                            "count": count,
                            "percent": covered_total * 100.0 / count,
                        }
                    },
                    "files": files,
                }
            ]
        }

    def run_app_coverage_guard(
        self,
        payload: dict,
        *,
        binary_target: bool = True,
        dep_info_omissions: frozenset[str] = frozenset(),
        source_overrides: dict[str, str] | None = None,
        extra_sources: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        module = load_script("check_app_security_coverage")
        old_argv = sys.argv
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            overrides = source_overrides or {}
            discovery_failures: list[str] = []
            library, binary = module.expected_security_file_sets(discovery_failures)
            self.assertEqual(discovery_failures, [])
            for relative in sorted(library | binary):
                source = root / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(
                    overrides.get(relative, "pub fn covered() {}\n"),
                    encoding="utf-8",
                )
            for relative, contents in (extra_sources or {}).items():
                source = root / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(contents, encoding="utf-8")
            main = root / "crates/netdiag-app/src/main.rs"
            main.write_text("fn main() {}\n", encoding="utf-8")
            module.ROOT = root
            discovery_failures = []
            library = module.discover_security_files(
                module.LIBRARY_SECURITY_ROOT_FILES,
                module.LIBRARY_SECURITY_SOURCE_DIRS,
                discovery_failures,
            )
            binary = module.discover_security_files(
                module.BINARY_SECURITY_ROOT_FILES,
                module.BINARY_SECURITY_SOURCE_DIRS,
                discovery_failures,
            )
            self.assertEqual(discovery_failures, [])
            dep_info = root / "dep-info"
            dep_info.mkdir()
            library_sources = [
                relative
                for relative in sorted(library)
                if relative not in dep_info_omissions
            ]
            binary_sources = [
                relative
                for relative in sorted(binary)
                if relative not in dep_info_omissions
            ]
            (dep_info / "netdiag_app-library.d").write_text(
                "target/libnetdiag_app-fixture.rlib: "
                + " ".join(library_sources)
                + "\n",
                encoding="utf-8",
            )
            if binary_target:
                (dep_info / "netdiag_app-binary.d").write_text(
                    "target/netdiag_app-fixture: crates/netdiag-app/src/main.rs "
                    + " ".join(binary_sources)
                    + "\n",
                    encoding="utf-8",
                )
            summary = root / "summary.json"
            summary.write_text(json.dumps(payload), encoding="utf-8")
            sys.argv = [
                "check_app_security_coverage.py",
                "--summary",
                str(summary),
                "--dep-info-dir",
                str(dep_info),
                "--aggregate-min",
                "80",
                "--file-min",
                "50",
            ]
            try:
                code, stdout, stderr = run_main(module)
            finally:
                sys.argv = old_argv
        return code, stdout + stderr

    def test_accepts_executable_library_and_binary_security_coverage(self) -> None:
        code, output = self.run_app_coverage_guard(self.coverage_payload())

        self.assertEqual(code, 0, output)
        self.assertIn("app security coverage: aggregate=90.00%", output)

    def test_rejects_missing_binary_target_or_dep_info_source(self) -> None:
        missing = "crates/netdiag-app/src/api_test.rs"
        code, output = self.run_app_coverage_guard(
            self.coverage_payload(),
            binary_target=False,
            dep_info_omissions=frozenset({missing}),
        )

        self.assertNotEqual(code, 0)
        self.assertIn("no netdiag-app binary test target", output)
        self.assertIn("absent from app build dep-info", output)

    def test_rejects_missing_or_undercovered_security_file(self) -> None:
        payload = self.coverage_payload()
        missing = payload["data"][0]["files"].pop()
        lines = missing["summary"]["lines"]
        totals = payload["data"][0]["totals"]["lines"]
        totals["covered"] -= lines["covered"]
        totals["count"] -= lines["count"]
        totals["percent"] = totals["covered"] * 100.0 / totals["count"]
        code, output = self.run_app_coverage_guard(payload)
        self.assertNotEqual(code, 0)
        self.assertIn("security coverage file is missing from summary", output)

        payload = self.coverage_payload()
        entry = payload["data"][0]["files"][0]
        totals = payload["data"][0]["totals"]["lines"]
        totals["covered"] -= entry["summary"]["lines"]["covered"] - 49
        totals["percent"] = totals["covered"] * 100.0 / totals["count"]
        entry["summary"]["lines"] = {"covered": 49, "count": 100, "percent": 49.0}
        code, output = self.run_app_coverage_guard(payload)
        self.assertNotEqual(code, 0)
        self.assertIn("is below required 50.00%", output)

    def test_rejects_coverage_suppression_in_security_source(self) -> None:
        relative = "crates/netdiag-app/src/secrets.rs"
        code, output = self.run_app_coverage_guard(
            self.coverage_payload(),
            source_overrides={relative: "#[coverage(off)]\npub fn hidden() {}\n"},
        )

        self.assertNotEqual(code, 0)
        self.assertIn("coverage suppression is forbidden", output)
        self.assertIn(relative, output)

    def test_new_security_submodule_is_automatically_required(self) -> None:
        relative = "crates/netdiag-app/src/secrets/keychain.rs"
        code, output = self.run_app_coverage_guard(
            self.coverage_payload(),
            extra_sources={relative: "pub fn rotate_key() {}\n"},
        )

        self.assertNotEqual(code, 0)
        self.assertIn(f"security coverage file is missing from summary: {relative}", output)


class CoverageSummaryTests(unittest.TestCase):
    def run_coverage_guard(
        self,
        payload: dict,
        *,
        critical_min: float = 90.0,
        workspace_min: float = 79.5,
        setup_source_tree: Callable[[Path], None] | None = None,
        dep_info_omissions: frozenset[str] = frozenset(),
        core_dep_info_is_rlib: bool = True,
    ) -> tuple[int, str]:
        module = load_script("check_coverage_summary")
        old_argv = sys.argv
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for relative in self.critical_paths():
                source = root / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("pub fn covered() {}\n", encoding="utf-8")
            fixture = root / "crates/netdiag-core/src/coverage_fixture.rs"
            fixture.write_text("pub fn covered() {}\n", encoding="utf-8")
            declaration = root / "crates/netdiag-core/src/pilot/declarations.rs"
            declaration.write_text(
                "pub struct CoverageDeclaration;\n",
                encoding="utf-8",
            )
            for relative_dir in module.CRITICAL_SOURCE_DIRS:
                (root / relative_dir).mkdir(parents=True, exist_ok=True)
            if setup_source_tree is not None:
                setup_source_tree(root)
            dep_info = root / "dep-info"
            dep_info.mkdir()
            sources = sorted(
                path.relative_to(root).as_posix()
                for relative_dir in module.WORKSPACE_SOURCE_DIRS
                for path in (root / relative_dir).rglob("*.rs")
                if module.is_production_rust_source(path.relative_to(root).as_posix())
            )
            for crate_stem, crate_path in (
                ("netdiag_core", "crates/netdiag-core/"),
                ("netdiag_cli", "crates/netdiag-cli/"),
                ("netdiag_platform", "crates/netdiag-platform/"),
            ):
                dependencies = [
                    path
                    for path in sources
                    if path.startswith(crate_path) and path not in dep_info_omissions
                ]
                if crate_stem == "netdiag_core" and not core_dep_info_is_rlib:
                    target = "target/netdiag_core"
                elif crate_stem in {"netdiag_core", "netdiag_platform"}:
                    target = f"target/lib{crate_stem}-fixture.rlib"
                else:
                    target = f"target/{crate_stem}"
                (dep_info / f"{crate_stem}-fixture.d").write_text(
                    f"{target}: {' '.join(dependencies)}\n",
                    encoding="utf-8",
                )
            module.ROOT = root
            summary = root / "summary.json"
            summary.write_text(json.dumps(payload))
            sys.argv = [
                "check_coverage_summary.py",
                "--summary",
                str(summary),
                "--dep-info-dir",
                str(dep_info),
                "--critical-min",
                str(critical_min),
                "--workspace-min",
                str(workspace_min),
            ]
            try:
                code, stdout, stderr = run_main(module)
            finally:
                sys.argv = old_argv
        return code, stdout + stderr

    def critical_paths(self) -> tuple[str, ...]:
        return (
            "crates/netdiag-core/src/managed_temp_directory.rs",
            "crates/netdiag-core/src/pilot.rs",
            "crates/netdiag-core/src/python_runtime.rs",
            "crates/netdiag-cli/src/commands/pilot.rs",
            "crates/netdiag-platform/src/system_temporary_root.rs",
            "crates/netdiag-core/src/pilot/promotion/gates.rs",
            "crates/netdiag-platform/src/trusted_directory.rs",
            "crates/netdiag-platform/src/trusted_directory/strict.rs",
            "crates/netdiag-platform/src/trusted_directory/unix.rs",
            "crates/netdiag-platform/src/trusted_temp_directory.rs",
            "crates/netdiag-platform/src/trusted_temp_directory/cleanup.rs",
            "crates/netdiag-platform/src/trusted_temp_directory/create.rs",
            "crates/netdiag-platform/src/trusted_temp_directory/create/name.rs",
            "crates/netdiag-platform/src/trusted_temp_directory/create/platform/unix.rs",
            "crates/netdiag-platform/src/trusted_temp_directory/finish.rs",
            "crates/netdiag-platform/src/trusted_temp_directory/identity/unix.rs",
            "crates/netdiag-platform/src/unix_acl.rs",
        )

    def fixture_workspace_line_count(self) -> int:
        return max(2000, len(self.critical_paths()) * 100 + 500)

    def test_strict_coverage_keeps_workspace_and_app_security_gates_independent(self) -> None:
        quality = (SCRIPTS / "check_rust_quality.sh").read_text(encoding="utf-8")
        release_guard = load_script("check_release_gate_hygiene")
        strict = release_guard.shell_function_body(quality, "run_strict")
        self.assertIsNotNone(strict)
        commands = [
            item
            for item in release_guard.logical_cargo_commands(strict)
            if "cargo llvm-cov nextest" in item
        ]
        self.assertEqual(len(commands), 2)
        workspace = next(item for item in commands if "-p netdiag-core" in item)
        app = next(item for item in commands if "-p netdiag-app" in item)
        self.assertIn("-p netdiag-cli", workspace)
        self.assertIn("-p netdiag-platform", workspace)
        self.assertNotIn("--workspace", workspace)
        self.assertNotIn("netdiag-app", workspace)
        self.assertNotIn("--workspace", app)
        for option in ("--locked", "--all-features", "--lib", "--bins", "--tests"):
            self.assertIn(option, app)
        for command in commands:
            self.assertIn(
                'LLVM_PROFILE_FILE_NAME="netdiag-%m-%p.profraw"',
                command,
            )
        self.assertIn("scripts/check_app_security_coverage.py", strict)
        self.assertIn("--aggregate-min", strict)
        self.assertIn("--file-min", strict)
        self.assertIn('mktemp -d "$ROOT/target/netdiag-llvm-cov.XXXXXX"', strict)
        self.assertIn('CARGO_TARGET_DIR="$coverage_target_dir"', strict)
        self.assertIn('"$coverage_target_dir/llvm-cov-target/debug/deps"', strict)
        self.assertIn("strict coverage artifacts preserved for diagnosis", strict)
        self.assertNotIn("target/llvm-cov-target", strict)

    def test_nextest_leaks_are_release_blocking_without_relaxing_detection(self) -> None:
        config = (REPO_ROOT / ".config" / "nextest.toml").read_text(encoding="utf-8")
        self.assertIn("[profile.default]", config)
        self.assertIn(
            'leak-timeout = { period = "200ms", result = "fail" }',
            config,
        )

    def test_pilot_smoke_uses_an_initialized_unique_workspace(self) -> None:
        quality = (SCRIPTS / "check_rust_quality.sh").read_text(encoding="utf-8")
        release_guard = load_script("check_release_gate_hygiene")
        smoke = release_guard.shell_function_body(quality, "run_pilot_smoke")
        self.assertIsNotNone(smoke)
        self.assertIn('mktemp -d "$ROOT/target/pilot-smoke.XXXXXX"', smoke)
        self.assertIn("artifact-root initialize", smoke)
        self.assertIn('training_dataset="$workspace/input/', smoke)
        self.assertIn('--model-dir "$artifacts/model"', smoke)
        self.assertIn(
            'benchmark_report_archive="$ROOT/target/benchmark-reports"', smoke
        )
        self.assertIn("python3 scripts/publish_benchmark_report.py", smoke)
        self.assertIn("failed pilot smoke workspace preserved for diagnosis", smoke)
        self.assertIn("refusing to clean an unverified pilot smoke workspace", smoke)
        self.assertRegex(smoke, r"(?m)^\s*cleanup_pilot_smoke\s*$")
        self.assertNotIn("target/pilot-artifacts", smoke)
        self.assertNotRegex(smoke, r"(?m)^\s*rm -rf\s+target/")

    def test_strict_workspace_commands_enable_all_features(self) -> None:
        quality = (SCRIPTS / "check_rust_quality.sh").read_text(encoding="utf-8")
        release_guard = load_script("check_release_gate_hygiene")
        strict = release_guard.shell_function_body(quality, "run_strict")
        self.assertIsNotNone(strict)
        commands = release_guard.logical_cargo_commands(strict)
        required = [
            command
            for command in commands
            if "cargo clippy --workspace" in command
            or ("cargo nextest run" in command and "--workspace" in command)
            or "cargo llvm-cov nextest" in command
        ]
        self.assertEqual(len(required), 4)
        self.assertEqual(
            sum("cargo nextest run --locked --workspace" in command for command in required),
            1,
        )
        for command in required:
            self.assertIn("--all-features", command)

    def coverage_payload(
        self,
        *,
        omit_file: str | None = None,
        workspace_percent: float = 80.0,
        reported_workspace_percent: float | None = None,
    ) -> dict:
        files = [
            {
                "filename": relative,
                "summary": {"lines": {"covered": 95, "count": 100, "percent": 95.0}},
            }
            for relative in self.critical_paths()
            if relative != omit_file
        ]
        workspace_count = self.fixture_workspace_line_count()
        workspace_covered = round(workspace_percent * workspace_count / 100)
        critical_covered = sum(
            entry["summary"]["lines"]["covered"] for entry in files
        )
        critical_count = sum(entry["summary"]["lines"]["count"] for entry in files)
        supplemental_count = workspace_count - critical_count
        supplemental_covered = workspace_covered - critical_covered
        if supplemental_count > 0 and 0 <= supplemental_covered <= supplemental_count:
            files.append(
                {
                    "filename": "crates/netdiag-core/src/coverage_fixture.rs",
                    "summary": {
                        "lines": {
                            "covered": supplemental_covered,
                            "count": supplemental_count,
                            "percent": supplemental_covered * 100.0 / supplemental_count,
                        }
                    },
                }
            )
        return {
            "data": [
                {
                    "totals": {
                        "lines": {
                            "covered": workspace_covered,
                            "count": workspace_count,
                            "percent": (
                                workspace_percent
                                if reported_workspace_percent is None
                                else reported_workspace_percent
                            ),
                        }
                    },
                    "files": files,
                }
            ]
        }

    def test_reports_measured_core_cli_platform_workspace_scope(self) -> None:
        code, output = self.run_coverage_guard(self.coverage_payload())
        self.assertEqual(code, 0, output)
        self.assertIn("measured_core_cli_platform_workspace", output)
        self.assertNotIn("coverage: workspace=", output)

    def test_compiled_declaration_only_module_need_not_have_coverage_mapping(self) -> None:
        code, output = self.run_coverage_guard(self.coverage_payload())

        self.assertEqual(code, 0, output)
        self.assertIn("compiled_zero_mapping_files=1", output)
        self.assertIn("coverage zero-mapping file", output)
        self.assertIn("declarations.rs", output)

    def test_rejects_coverage_off_attribute_in_production_source(self) -> None:
        for attribute in (
            "#[coverage(off)]",
            "#[cfg_attr(coverage, coverage(off))]",
        ):
            with self.subTest(attribute=attribute):
                suppressed = "crates/netdiag-core/src/pilot/suppressed.rs"

                def add_suppressed_source(root: Path) -> None:
                    path = root / suppressed
                    path.write_text(
                        f"{attribute}\npub fn hidden_logic() -> bool {{ true }}\n",
                        encoding="utf-8",
                    )

                code, output = self.run_coverage_guard(
                    self.coverage_payload(),
                    setup_source_tree=add_suppressed_source,
                )

                self.assertNotEqual(code, 0)
                self.assertIn("coverage suppression is forbidden", output)
                self.assertIn("suppressed.rs", output)

    def test_rejects_missing_critical_file(self) -> None:
        code, output = self.run_coverage_guard(
            self.coverage_payload(
                omit_file="crates/netdiag-cli/src/commands/pilot.rs"
            )
        )
        self.assertNotEqual(code, 0)
        self.assertIn("critical coverage file is missing", output)

    def test_enforces_reported_production_pilot_module(self) -> None:
        production_module = "crates/netdiag-core/src/pilot/promotion/gates.rs"
        payload = self.coverage_payload()
        entry = next(
            entry
            for entry in payload["data"][0]["files"]
            if entry["filename"] == production_module
        )
        entry["summary"]["lines"] = {
            "covered": 89,
            "count": 100,
            "percent": 89.0,
        }
        code, output = self.run_coverage_guard(payload)
        self.assertNotEqual(code, 0)
        self.assertIn(production_module, output)
        self.assertIn("below required 90.00%", output)

    def test_rejects_non_instrumented_pilot_source_that_is_absent(self) -> None:
        payload = self.coverage_payload()
        payload["data"][0]["files"] = [
            entry
            for entry in payload["data"][0]["files"]
            if entry["filename"]
            != "crates/netdiag-core/src/pilot/promotion/gates.rs"
        ]

        code, output = self.run_coverage_guard(payload)

        self.assertNotEqual(code, 0)
        self.assertIn("totals do not equal the sum of file line summaries", output)

    def test_rejects_critical_source_absent_from_coverage_build_graph(self) -> None:
        uncompiled = "crates/netdiag-core/src/pilot/uncompiled_logic.rs"

        def add_uncompiled_source(root: Path) -> None:
            path = root / uncompiled
            path.write_text("pub fn production_logic() -> bool { true }\n")

        code, output = self.run_coverage_guard(
            self.coverage_payload(),
            setup_source_tree=add_uncompiled_source,
            dep_info_omissions=frozenset({uncompiled}),
        )

        self.assertNotEqual(code, 0)
        self.assertIn("absent from the coverage build dep-info", output)
        self.assertIn("uncompiled_logic.rs", output)

    def test_core_test_target_cannot_replace_production_rlib_dep_info(self) -> None:
        code, output = self.run_coverage_guard(
            self.coverage_payload(),
            core_dep_info_is_rlib=False,
        )

        self.assertNotEqual(code, 0)
        self.assertIn("no eligible production rlib target for netdiag_core", output)

    def test_dep_info_rejects_external_source_with_workspace_suffix(self) -> None:
        module = load_script("check_coverage_summary")
        failures: list[str] = []
        with tempfile.TemporaryDirectory() as checkout_tmp, tempfile.TemporaryDirectory() as external_tmp:
            checkout = Path(checkout_tmp)
            external = Path(external_tmp) / "crates/netdiag-core/src/external.rs"
            external.parent.mkdir(parents=True)
            external.write_text("pub fn external() {}\n", encoding="utf-8")
            dep_info = checkout / "dep-info"
            dep_info.mkdir()
            (dep_info / "netdiag_core-fixture.d").write_text(
                f"target/libnetdiag_core-fixture.rlib: {external}\n",
                encoding="utf-8",
            )
            (dep_info / "netdiag_cli-fixture.d").write_text(
                "target/netdiag_cli:\n",
                encoding="utf-8",
            )
            module.ROOT = checkout
            module.compiled_workspace_files(
                dep_info,
                {"crates/netdiag-core/src/external.rs"},
                failures,
            )

        self.assertTrue(
            any("must resolve inside the checkout" in failure for failure in failures),
            failures,
        )

    def test_reported_child_is_included_in_aggregate(self) -> None:
        payload = self.coverage_payload()
        child = next(
            entry
            for entry in payload["data"][0]["files"]
            if entry["filename"]
            == "crates/netdiag-core/src/pilot/promotion/gates.rs"
        )
        child["summary"]["lines"] = {
            "covered": 0,
            "count": 100,
            "percent": 0.0,
        }
        code, output = self.run_coverage_guard(payload)
        self.assertNotEqual(code, 0)
        expected_percent = (len(self.critical_paths()) - 1) * 95 / len(
            self.critical_paths()
        )
        self.assertIn(
            f"release-critical coverage {expected_percent:.2f}%",
            output,
        )

    def test_ignores_test_only_pilot_modules(self) -> None:
        payload = self.coverage_payload()
        payload["data"][0]["files"].append(
            {
                "filename": "crates/netdiag-core/src/pilot/pilot_sources/tests/support.rs",
                "summary": {
                    "lines": {"covered": 0, "count": 100, "percent": 0.0}
                },
            }
        )
        payload["data"][0]["totals"]["lines"] = {
            "covered": payload["data"][0]["totals"]["lines"]["covered"],
            "count": payload["data"][0]["totals"]["lines"]["count"] + 100,
            "percent": payload["data"][0]["totals"]["lines"]["covered"]
            * 100.0
            / (payload["data"][0]["totals"]["lines"]["count"] + 100),
        }
        code, output = self.run_coverage_guard(payload)
        self.assertEqual(code, 0, output)
        self.assertNotIn("tests/support.rs", output)

    def test_normalizes_windows_absolute_paths(self) -> None:
        payload = self.coverage_payload()
        child = next(
            entry
            for entry in payload["data"][0]["files"]
            if entry["filename"]
            == "crates/netdiag-core/src/pilot/promotion/gates.rs"
        )
        child["filename"] = (
            r"C:\runner\repo\crates\netdiag-core\src\pilot\promotion\gates.rs"
        )
        code, output = self.run_coverage_guard(payload)
        self.assertEqual(code, 0, output)
        self.assertIn("crates/netdiag-core/src/pilot/promotion/gates.rs", output)

    def test_rejects_duplicate_critical_entries(self) -> None:
        payload = self.coverage_payload()
        payload["data"][0]["files"].append(
            dict(payload["data"][0]["files"][0])
        )
        code, output = self.run_coverage_guard(payload)
        self.assertNotEqual(code, 0)
        self.assertIn("appears more than once", output)

    def test_rejects_non_finite_and_out_of_range_thresholds(self) -> None:
        for invalid in [float("nan"), float("inf"), -0.1, 100.1]:
            with self.subTest(invalid=invalid):
                code, output = self.run_coverage_guard(
                    self.coverage_payload(),
                    critical_min=invalid,
                )
                self.assertNotEqual(code, 0)
                self.assertIn("must be a finite percentage between 0 and 100", output)

    def test_rejects_forged_workspace_percent(self) -> None:
        code, output = self.run_coverage_guard(
            self.coverage_payload(reported_workspace_percent=99.0)
        )
        self.assertNotEqual(code, 0)
        self.assertIn("does not match covered/count recomputation", output)

    def test_rejects_forged_critical_file_percent(self) -> None:
        payload = self.coverage_payload()
        payload["data"][0]["files"][0]["summary"]["lines"]["percent"] = 100.0
        code, output = self.run_coverage_guard(payload)
        self.assertNotEqual(code, 0)
        self.assertIn("does not match covered/count recomputation", output)

    def test_rejects_workspace_below_ratchet_floor(self) -> None:
        code, output = self.run_coverage_guard(self.coverage_payload(workspace_percent=79.0))
        self.assertNotEqual(code, 0)
        self.assertIn("measured core/CLI/platform workspace coverage", output)

    def test_high_coverage_app_crate_cannot_raise_release_workspace_measurement(self) -> None:
        payload = self.coverage_payload(workspace_percent=80.0)
        payload["data"][0]["files"].append(
            {
                "filename": "crates/netdiag-app/src/lib.rs",
                "summary": {
                    "lines": {"covered": 9000, "count": 9000, "percent": 100.0}
                },
            }
        )
        base_totals = payload["data"][0]["totals"]["lines"]
        combined_covered = base_totals["covered"] + 9000
        combined_count = base_totals["count"] + 9000
        payload["data"][0]["totals"]["lines"] = {
            "covered": combined_covered,
            "count": combined_count,
            "percent": combined_covered * 100.0 / combined_count,
        }

        code, output = self.run_coverage_guard(payload, workspace_min=90.0)

        self.assertNotEqual(code, 0)
        self.assertIn("measured_core_cli_platform_workspace=80.00%", output)
        self.assertIn("below ratchet floor 90.00%", output)

    def test_nonexistent_core_source_cannot_raise_workspace_measurement(self) -> None:
        payload = self.coverage_payload()
        payload["data"][0]["files"].append(
            {
                "filename": "crates/netdiag-core/src/not_in_checkout.rs",
                "summary": {
                    "lines": {"covered": 1000, "count": 1000, "percent": 100.0}
                },
            }
        )

        code, output = self.run_coverage_guard(payload)

        self.assertNotEqual(code, 0)
        self.assertIn("absent from the checkout", output)
        self.assertIn("not_in_checkout.rs", output)


class ArchitectureGuardTests(unittest.TestCase):
    def test_complexity_parser_finds_qualified_and_multiline_functions(self) -> None:
        module = load_script("check_complexity")
        source = (
            "pub unsafe extern \"C\" fn ffi_entry() { if true {} }\n"
            "pub\n"
            "async\n"
            "fn multiline(\n"
            "    value: usize,\n"
            ") -> usize {\n"
            "    // fn fake() { if while match }\n"
            "    let text = \"fn fake() { if while match }\";\n"
            "    value + text.len()\n"
            "}\n"
            "const fn constant() -> usize { 1 }\n"
        )

        spans = module.function_spans(source)

        self.assertEqual(len(spans), 3)
        self.assertEqual([span[0] for span in spans], [1, 2, 11])
        self.assertEqual(
            [len(module.BRANCH_RE.findall(span[3])) for span in spans],
            [1, 0, 0],
        )

    def test_external_test_module_declaration_does_not_truncate_production_lines(self) -> None:
        module = load_script("count_production_lines")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.rs"
            path.write_text("fn before() {}\n#[cfg(test)]\nmod tests;\nfn after() {}\n")
            self.assertEqual(module.count_production_lines(path), 2)

    def test_inline_test_module_is_skipped_without_truncating_following_production(
        self,
    ) -> None:
        module = load_script("count_production_lines")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.rs"
            path.write_text(
                "fn before() {}\n"
                "#[cfg(test)]\n"
                "mod tests {\n"
                "fn test_only() {}\n"
                "}\n"
                "fn after() {}\n"
            )
            self.assertEqual(module.count_production_lines(path), 2)

    def test_inline_test_module_ignores_nested_and_literal_braces(self) -> None:
        module = load_script("count_production_lines")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.rs"
            path.write_text(
                "fn before() {}\n"
                "#[cfg(test)]\n"
                "#[allow(dead_code)]\n"
                "mod tests {\n"
                "    fn nested() { if true { let _ = '}'; } }\n"
                '    const TEXT: &str = "}{";\n'
                '    const BYTES: &[u8] = b"}{";\n'
                '    const RAW: &str = r###"}{"###;\n'
                '    const RAW_BYTES: &[u8] = br##"}{"##;\n'
                "    const BYTE: u8 = b'{';\n"
                "    // } line-comment brace\n"
                "    /* { outer /* } nested */ } */\n"
                "}\n"
                "fn after() {}\n"
            )
            self.assertEqual(module.count_production_lines(path), 2)

    def test_inline_test_module_on_shared_line_preserves_production_code(self) -> None:
        module = load_script("count_production_lines")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.rs"
            path.write_text("#[cfg(test)] mod tests {} fn production() {}\n")
            self.assertEqual(module.count_production_lines(path), 1)

    def test_malformed_inline_test_module_fails_closed(self) -> None:
        module = load_script("count_production_lines")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.rs"
            path.write_text("fn before() {}\n#[cfg(test)]\nmod tests {\n")
            with self.assertRaisesRegex(ValueError, "unterminated inline"):
                module.count_production_lines(path)

            original_argv = sys.argv
            try:
                sys.argv = ["count_production_lines.py", str(path)]
                code, stdout, stderr = run_main(module)
            finally:
                sys.argv = original_argv
            self.assertNotEqual(code, 0)
            self.assertEqual(stdout, "")
            self.assertIn("production line count failed", stderr)

    def test_pilot_coverage_policy_allows_only_external_tests_module(self) -> None:
        module = load_script("check_architecture_guard_sanity")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.rs"
            path.write_text("fn production() {}\n#[cfg(test)]\nmod tests;\n")
            self.assertEqual(module.test_code_violations(path), [])

    def test_pilot_coverage_policy_rejects_inline_helpers_and_auxiliary_modules(self) -> None:
        module = load_script("check_architecture_guard_sanity")
        cases = [
            "#[cfg(test)]\nfn helper() {}\n",
            "#[cfg(test)]\nmod fault_injection;\n",
            "#[cfg(all(test, unix))]\nmod tests {\n}\n",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for index, contents in enumerate(cases):
                path = Path(tmp) / f"sample-{index}.rs"
                path.write_text(contents)
                self.assertEqual(module.test_code_violations(path), [1])

class WorkspacePublishPolicyTests(unittest.TestCase):
    def workspace_fixture(self, root: Path) -> None:
        (root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crates/one", "tools/two"]\n',
            encoding="utf-8",
        )
        for member in ("crates/one", "tools/two"):
            directory = root / member
            directory.mkdir(parents=True)
            (directory / "Cargo.toml").write_text(
                f'[package]\nname = "{Path(member).name}"\npublish = false\n',
                encoding="utf-8",
            )

    def test_all_workspace_packages_are_private(self) -> None:
        module = load_script("check_workspace_publish_policy")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.workspace_fixture(root)
            self.assertEqual(module.validate(root), [])

    def test_publishable_workspace_package_is_rejected(self) -> None:
        module = load_script("check_workspace_publish_policy")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.workspace_fixture(root)
            (root / "crates/one/Cargo.toml").write_text(
                '[package]\nname = "one"\npublish = true\n',
                encoding="utf-8",
            )
            failures = module.validate(root)
        self.assertEqual(len(failures), 1)
        self.assertIn("publish = false", failures[0])


class AdapterInputBoundaryTests(unittest.TestCase):
    JSON_ADAPTERS = (
        (
            "openconfig_input_boundary",
            "examples/adapters/openconfig-gnmi/adapter.py",
            "load_notifications",
            "sample_notification",
            "record_from_notification",
            "rtt_ms",
        ),
        (
            "snmp_input_boundary",
            "examples/adapters/snmp-if-mib/adapter.py",
            "load_interfaces",
            "sample_if_mib",
            "record_from_if_mib",
            "interval_seconds",
        ),
        (
            "frr_input_boundary",
            "examples/adapters/frr-routing-state/adapter.py",
            "load_routing_states",
            "sample_frr",
            "record_from_frr",
            "routes_changed",
        ),
    )
    CSV_EXPORTERS = (
        (
            "http_json_input_boundary",
            "examples/adapters/http-json-python/adapter.py",
            "load_records",
        ),
        (
            "prometheus_input_boundary",
            "examples/adapters/prometheus-exporter-python/exporter.py",
            "load_csv",
        ),
    )

    def load_adapter(self, name: str, relative_path: str) -> ModuleType:
        return load_module_path(name, REPO_ROOT / relative_path)

    def valid_csv(self, module: ModuleType, rows: int = 1) -> str:
        header = ",".join(module.REQUIRED_HEADERS)
        numeric_fields = (
            module.FIELDS if hasattr(module, "FIELDS") else module.NUMERIC_FIELDS
        )
        values = [
            "2026-05-07T09:00:00+00:00",
            *("1" for _ in numeric_fields),
        ]
        return header + "\n" + (",".join(values) + "\n") * rows

    def test_standalone_adapters_start_in_isolated_python_39(self) -> None:
        interpreter = Path("/usr/bin/python3")
        if not interpreter.is_file():
            interpreter = Path(sys.executable)
        adapter_paths = {
            relative_path
            for _, relative_path, *_ in self.JSON_ADAPTERS
        } | {relative_path for _, relative_path, _ in self.CSV_EXPORTERS}
        for relative_path in sorted(adapter_paths):
            source = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
            self.assertIn("from __future__ import annotations", source.splitlines()[:4])
            completed = subprocess.run(
                [
                    str(interpreter),
                    "-I",
                    str(REPO_ROOT / relative_path),
                    "--emit-sample",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            with self.subTest(adapter=relative_path):
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, "")
                self.assertIsInstance(json.loads(completed.stdout), dict)

    def test_json_inputs_reject_duplicate_and_non_finite_numbers(self) -> None:
        invalid_documents = (
            ('[{"timestamp":"a","timestamp":"b"}]', "duplicate key"),
            ('[{"value":NaN}]', "non-standard number"),
            ('[{"value":Infinity}]', "non-standard number"),
            ('[{"value":1e400}]', "non-finite number"),
            ('[{"value":' + "9" * 309 + "}]", "integer exceeds"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, relative_path, loader_name, *_ in self.JSON_ADAPTERS:
                module = self.load_adapter(name, relative_path)
                loader = getattr(module, loader_name)
                for index, (document, message) in enumerate(invalid_documents):
                    path = root / f"{name}-{index}.json"
                    path.write_text(document, encoding="utf-8")
                    with self.subTest(adapter=name, document=index):
                        with self.assertRaisesRegex(ValueError, message):
                            loader(path)

    def test_json_inputs_require_non_empty_object_rows_and_source_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for (
                name,
                relative_path,
                loader_name,
                sample_name,
                record_name,
                required_field,
            ) in self.JSON_ADAPTERS:
                module = self.load_adapter(name, relative_path)
                loader = getattr(module, loader_name)
                for index, document in enumerate(("[]", "[{}]", "[1]")):
                    path = root / f"{name}-row-{index}.json"
                    path.write_text(document, encoding="utf-8")
                    with self.subTest(adapter=name, document=document):
                        with self.assertRaises(ValueError):
                            loader(path)

                row = getattr(module, sample_name)()
                del row[required_field]
                with self.subTest(adapter=name, missing=required_field):
                    with self.assertRaisesRegex(
                        ValueError, "missing required numeric field"
                    ):
                        getattr(module, record_name)(row)
                path = root / f"{name}-missing-field.json"
                path.write_text(json.dumps([row]), encoding="utf-8")
                report = module.preflight_report(
                    module.argparse.Namespace(
                        emit_sample=False,
                        input_json=path,
                        sample="boundary-test",
                    )
                )
                self.assertFalse(report["passed"])
                self.assertIn(required_field, report["checks"][0]["message"])

    def test_json_records_reject_non_finite_negative_and_out_of_range_values(
        self,
    ) -> None:
        ratio_mutations = {
            "openconfig_input_boundary": {"in_errors_delta": 1_000_000},
            "snmp_input_boundary": {"if_in_errors_delta": 1_000_000},
        }
        for (
            name,
            relative_path,
            _,
            sample_name,
            record_name,
            required_field,
        ) in self.JSON_ADAPTERS:
            module = self.load_adapter(name, relative_path)
            record = getattr(module, record_name)
            for invalid in (-1, float("nan"), float("inf")):
                row = getattr(module, sample_name)()
                row[required_field] = invalid
                with self.subTest(adapter=name, invalid=invalid):
                    with self.assertRaisesRegex(
                        ValueError, "finite and non-negative"
                    ):
                        record(row)

            ratio_mutation = ratio_mutations.get(name)
            if ratio_mutation is not None:
                row = getattr(module, sample_name)()
                row.update(ratio_mutation)
                with self.subTest(adapter=name, invalid="ratio"):
                    with self.assertRaisesRegex(ValueError, "between 0 and 100"):
                        record(row)

            if name == "openconfig_input_boundary":
                row = getattr(module, sample_name)()
                for field in (
                    "in_packets_delta",
                    "out_packets_delta",
                    "in_discards_delta",
                    "out_discards_delta",
                ):
                    row[field] = 0
                row["in_errors_delta"] = 1
            elif name == "snmp_input_boundary":
                row = getattr(module, sample_name)()
                for field in (
                    "if_in_ucast_pkts_delta",
                    "if_out_ucast_pkts_delta",
                    "if_in_discards_delta",
                    "if_out_discards_delta",
                ):
                    row[field] = 0
                row["if_in_errors_delta"] = 1
            else:
                continue
            with self.subTest(adapter=name, invalid="zero-denominator"):
                with self.assertRaisesRegex(ValueError, "denominator cannot be zero"):
                    record(row)

    def test_json_inputs_reject_symlinks_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.json"
            target.write_text("[]", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            oversized = root / "oversized.json"
            with oversized.open("wb") as handle:
                handle.truncate(16 * 1024 * 1024 + 1)

            for name, relative_path, loader_name, *_ in self.JSON_ADAPTERS:
                module = self.load_adapter(name, relative_path)
                self.assertEqual(module.MAX_INPUT_BYTES, 16 * 1024 * 1024)
                flags = module.secure_open_flags()
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_CLOEXEC)
                self.assertTrue(flags & os.O_NONBLOCK)
                descriptor = module.open_bounded_regular_input(target)
                try:
                    self.assertTrue(
                        module.stat.S_ISREG(os.fstat(descriptor).st_mode)
                    )
                    self.assertFalse(os.get_inheritable(descriptor))
                    self.assertFalse(os.get_blocking(descriptor))
                finally:
                    os.close(descriptor)
                loader = getattr(module, loader_name)
                with self.subTest(adapter=name, boundary="symlink"):
                    with self.assertRaisesRegex(ValueError, "securely open"):
                        loader(link)
                    report = module.preflight_report(
                        module.argparse.Namespace(
                            emit_sample=False,
                            input_json=link,
                            sample="boundary-test",
                        )
                    )
                    self.assertFalse(report["passed"])
                    self.assertIn("securely open", report["checks"][0]["message"])
                with self.subTest(adapter=name, boundary="size"):
                    with self.assertRaisesRegex(ValueError, "exceeds"):
                        loader(oversized)

    def test_csv_inputs_reject_header_and_row_contract_violations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, relative_path, loader_name in self.CSV_EXPORTERS:
                module = self.load_adapter(name, relative_path)
                loader = getattr(module, loader_name)
                headers = list(module.REQUIRED_HEADERS)
                numeric_fields = (
                    module.FIELDS
                    if hasattr(module, "FIELDS")
                    else module.NUMERIC_FIELDS
                )
                valid_values = [
                    "2026-05-07T09:00:00+00:00",
                    *("1" for _ in numeric_fields),
                ]
                cases = {
                    "duplicate": (
                        headers + [headers[0]],
                        valid_values + [valid_values[0]],
                        "duplicate headers",
                    ),
                    "missing-header": (
                        headers[:-1],
                        valid_values[:-1],
                        "missing required headers",
                    ),
                    "missing-value": (
                        headers,
                        [*valid_values[:-1], ""],
                        "is missing",
                    ),
                }
                for case, (case_headers, case_values, message) in cases.items():
                    path = root / f"{name}-{case}.csv"
                    path.write_text(
                        ",".join(case_headers) + "\n" + ",".join(case_values) + "\n",
                        encoding="utf-8",
                    )
                    with self.subTest(exporter=name, case=case):
                        with self.assertRaisesRegex(ValueError, message):
                            loader(path)

    def test_csv_inputs_reject_invalid_numbers_ranges_and_row_overflow(self) -> None:
        invalid_values = (
            ("latency_ms", "NaN", "finite and non-negative"),
            ("jitter_ms", "-1", "finite and non-negative"),
            ("packet_loss_rate", "100.1", "between 0 and 100"),
            ("quic_blocked_ratio", "1.1", "between 0 and 1"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, relative_path, loader_name in self.CSV_EXPORTERS:
                module = self.load_adapter(name, relative_path)
                loader = getattr(module, loader_name)
                for field, invalid, message in invalid_values:
                    values = {
                        header: "1"
                        for header in module.REQUIRED_HEADERS
                        if header != "timestamp"
                    }
                    values["timestamp"] = "2026-05-07T09:00:00+00:00"
                    values[field] = invalid
                    path = root / f"{name}-{field}.csv"
                    path.write_text(
                        ",".join(module.REQUIRED_HEADERS)
                        + "\n"
                        + ",".join(values[header] for header in module.REQUIRED_HEADERS)
                        + "\n",
                        encoding="utf-8",
                    )
                    with self.subTest(exporter=name, field=field):
                        with self.assertRaisesRegex(ValueError, message):
                            loader(path)

                self.assertEqual(module.MAX_CSV_ROWS, 100_000)
                path = root / f"{name}-rows.csv"
                path.write_text(self.valid_csv(module, rows=3), encoding="utf-8")
                with mock.patch.object(module, "MAX_CSV_ROWS", 2):
                    with self.assertRaisesRegex(ValueError, "row limit"):
                        loader(path)

    def test_csv_inputs_reject_symlinks_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.csv"
            target.write_text("timestamp\n", encoding="utf-8")
            link = root / "link.csv"
            link.symlink_to(target)
            oversized = root / "oversized.csv"
            with oversized.open("wb") as handle:
                handle.truncate(16 * 1024 * 1024 + 1)

            for name, relative_path, loader_name in self.CSV_EXPORTERS:
                module = self.load_adapter(name, relative_path)
                self.assertEqual(module.MAX_INPUT_BYTES, 16 * 1024 * 1024)
                flags = module.secure_open_flags()
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_CLOEXEC)
                self.assertTrue(flags & os.O_NONBLOCK)
                descriptor = module.open_bounded_regular_input(target)
                try:
                    self.assertTrue(
                        module.stat.S_ISREG(os.fstat(descriptor).st_mode)
                    )
                    self.assertFalse(os.get_inheritable(descriptor))
                    self.assertFalse(os.get_blocking(descriptor))
                finally:
                    os.close(descriptor)
                loader = getattr(module, loader_name)
                with self.subTest(exporter=name, boundary="symlink"):
                    with self.assertRaisesRegex(ValueError, "securely open"):
                        loader(link)
                with self.subTest(exporter=name, boundary="size"):
                    with self.assertRaisesRegex(ValueError, "exceeds"):
                        loader(oversized)

    def test_prometheus_csv_builds_records_and_aggregates_in_one_pass(self) -> None:
        module = self.load_adapter(
            "prometheus_single_pass",
            "examples/adapters/prometheus-exporter-python/exporter.py",
        )
        headers = list(module.REQUIRED_HEADERS)
        first = ["2026-05-07T09:00:00+00:00", *("1" for _ in module.FIELDS)]
        second = ["2026-05-07T09:00:01+00:00", *("3" for _ in module.FIELDS)]
        second[headers.index("quic_blocked_ratio")] = "1"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.csv"
            path.write_text(
                ",".join(headers)
                + "\n"
                + ",".join(first)
                + "\n"
                + ",".join(second)
                + "\n",
                encoding="utf-8",
            )
            records, values = module.load_csv(path)
        self.assertEqual(len(records), 2)
        self.assertEqual(values["latency_ms"], 2.0)
        self.assertNotIn("load_values", vars(module))
        self.assertNotIn("load_records", vars(module))

    def test_http_handlers_serve_only_preencoded_bounded_bodies(self) -> None:
        import http.client
        import threading

        cases = (
            (
                "http_json_preencoded",
                "examples/adapters/http-json-python/adapter.py",
                (("/trace", "trace_body", b'{"trace":true}'),),
            ),
            (
                "prometheus_preencoded",
                "examples/adapters/prometheus-exporter-python/exporter.py",
                (
                    ("/trace", "trace_body", b'{"trace":true}'),
                    ("/metrics", "metrics_body", b"netdiag_latency_ms 1\n"),
                ),
            ),
        )
        for name, relative_path, endpoints in cases:
            module = self.load_adapter(name, relative_path)
            for mutable_state in ("records", "values", "experiment"):
                self.assertFalse(hasattr(module.Handler, mutable_state))
            with self.assertRaises(ValueError):
                module.encode_json_body({"invalid": float("nan")})
            with self.assertRaisesRegex(ValueError, "response exceeds"):
                module.bounded_http_body(
                    b"x" * (module.MAX_HTTP_BODY_BYTES + 1), "/trace"
                )
            with mock.patch.object(module, "MAX_HTTP_BODY_BYTES", 16):
                with self.assertRaisesRegex(ValueError, "response exceeds"):
                    module.encode_json_body({"value": "x" * 32})

            request = mock.Mock()
            request.makefile.return_value = io.BytesIO()
            handler = object.__new__(module.Handler)
            handler.request = request
            module.Handler.setup(handler)
            request.settimeout.assert_called_once_with(module.SOCKET_DEADLINE_SECONDS)

            for endpoint, attribute, expected in endpoints:
                setattr(module.Handler, attribute, expected)
                server = module.HTTPServer(("127.0.0.1", 0), module.Handler)
                worker = threading.Thread(target=server.handle_request)
                worker.start()
                try:
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", server.server_port, timeout=2
                    )
                    connection.request("GET", endpoint)
                    response = connection.getresponse()
                    body = response.read()
                    connection.close()
                finally:
                    server.server_close()
                    worker.join(timeout=2)
                with self.subTest(exporter=name, endpoint=endpoint):
                    self.assertEqual(response.status, 200)
                    self.assertEqual(body, expected)
                    self.assertFalse(worker.is_alive())


if __name__ == "__main__":
    unittest.main()
