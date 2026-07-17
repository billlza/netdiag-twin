#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RIPGREP_EXECUTABLE="$(command -v rg || true)"
if [[ -z "$RIPGREP_EXECUTABLE" || "$RIPGREP_EXECUTABLE" != /* || ! -f "$RIPGREP_EXECUTABLE" || ! -x "$RIPGREP_EXECUTABLE" ]]; then
  echo "architecture guard failed: an absolute executable ripgrep (rg) is required" >&2
  exit 2
fi
readonly RIPGREP_EXECUTABLE

rg_matches() {
  local status
  if "$RIPGREP_EXECUTABLE" "$@"; then
    return 0
  else
    status=$?
  fi
  if (( status == 1 )); then
    return 1
  fi
  echo "architecture guard failed: ripgrep scan failed with status $status" >&2
  exit 2
}

if ! rg_matches --quiet --fixed-strings \
  'netdiag-ripgrep-self-test' <<< 'netdiag-ripgrep-self-test'; then
  echo "architecture guard failed: ripgrep self-test did not match expected input" >&2
  exit 2
fi

PYTHON_EXECUTABLE="${NETDIAG_PYTHON_EXECUTABLE:-}"
if [[ -z "$PYTHON_EXECUTABLE" ]]; then
  PYTHON_EXECUTABLE="$(command -v python3 || true)"
fi
if [[ -z "$PYTHON_EXECUTABLE" || "$PYTHON_EXECUTABLE" != /* || ! -f "$PYTHON_EXECUTABLE" || ! -x "$PYTHON_EXECUTABLE" ]]; then
  echo "architecture guard failed: an absolute executable Python interpreter is required" >&2
  exit 1
fi

fail=0

check_lines() {
  local path="$1"
  local max_lines="$2"
  local lines
  if ! git -C "$ROOT" ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
    echo "architecture guard failed: $path is absent from the Git index" >&2
    fail=1
    return
  fi
  lines="$("$PYTHON_EXECUTABLE" -B "$ROOT/scripts/count_production_lines.py" "$ROOT/$path")"
  if (( lines > max_lines )); then
    echo "architecture guard failed: $path has $lines production lines, max $max_lines" >&2
    fail=1
  else
    echo "$path: $lines/$max_lines production lines"
  fi
}

# Grandfathered large files are fixed to the current production-line ratchet.
# Future work must split them before adding more behavior.
check_lines "crates/netdiag-core/src/lab.rs" 3177
check_lines "crates/netdiag-core/src/lab/source_signal_metrics.rs" 60
check_lines "crates/netdiag-core/src/connectors.rs" 1536
check_lines "crates/netdiag-core/src/connectors/http_json.rs" 90
check_lines "crates/netdiag-core/src/connectors/http_json/decode.rs" 110
check_lines "crates/netdiag-core/src/connectors/http_json/decode/bounded_sequence.rs" 85
check_lines "crates/netdiag-core/src/connectors/http_json/decode/envelope.rs" 175
check_lines "crates/netdiag-core/src/connectors/http_json/metadata.rs" 180
check_lines "crates/netdiag-core/src/metric_quality.rs" 20
check_lines "crates/netdiag-core/src/metric_quality/application.rs" 45
check_lines "crates/netdiag-core/src/metric_quality/declarations.rs" 135
check_lines "crates/netdiag-core/src/connectors/http_endpoint.rs" 100
check_lines "crates/netdiag-core/src/connectors/http_client.rs" 100
check_lines "crates/netdiag-core/src/connectors/http_client/authorization.rs" 25
check_lines "crates/netdiag-core/src/connectors/authentication.rs" 25
check_lines "crates/netdiag-core/src/connectors/authentication/origin.rs" 45
check_lines "crates/netdiag-core/src/connectors/authentication/token.rs" 65
check_lines "crates/netdiag-core/src/connectors/authentication/identity.rs" 140
check_lines "crates/netdiag-core/src/connectors/authentication/bindings.rs" 140
check_lines "crates/netdiag-core/src/pilot/bearer.rs" 80
check_lines "crates/netdiag-core/src/lab/bearer.rs" 80
check_lines "crates/netdiag-core/src/connectors/otlp.rs" 320
check_lines "crates/netdiag-core/src/connectors/otlp/buffer.rs" 80
check_lines "crates/netdiag-core/src/connectors/otlp/projection.rs" 470
check_lines "crates/netdiag-core/src/connectors/otlp/projection/budget.rs" 285
check_lines "crates/netdiag-core/src/connectors/otlp/projection/numeric.rs" 125
check_lines "crates/netdiag-core/src/connectors/otlp/server.rs" 165
check_lines "crates/netdiag-core/src/connectors/otlp/server/incoming.rs" 155
check_lines "crates/netdiag-core/src/connectors/otlp/server/runtime.rs" 100
check_lines "crates/netdiag-core/src/connectors/otlp/server/shutdown.rs" 265
check_lines "crates/netdiag-core/src/connectors/otlp/tests.rs" 230
check_lines "crates/netdiag-core/src/connectors/capture_deadline.rs" 70
check_lines "crates/netdiag-core/src/connectors/pcap_file.rs" 165
check_lines "crates/netdiag-core/src/connectors/pcap_file/tests.rs" 150
check_lines "crates/netdiag-core/src/connectors/pcap_read_error.rs" 20
check_lines "crates/netdiag-core/src/connectors/validation.rs" 18
check_lines "crates/netdiag-core/src/connectors/validation/capture.rs" 65
check_lines "crates/netdiag-core/src/connectors/pcap_validation.rs" 25
check_lines "crates/netdiag-core/src/connectors/probe.rs" 180
check_lines "crates/netdiag-core/src/connectors/probe/executor.rs" 200
check_lines "crates/netdiag-core/src/connectors/probe/measurement.rs" 70
check_lines "crates/netdiag-core/src/connectors/probe/output.rs" 160
check_lines "crates/netdiag-core/src/connectors/probe/target.rs" 100
check_lines "crates/netdiag-core/src/connectors/probe/tests.rs" 380
check_lines "crates/netdiag-core/src/connectors/prometheus.rs" 400
check_lines "crates/netdiag-core/src/connectors/prometheus_mapping.rs" 40
check_lines "crates/netdiag-core/src/connectors/prometheus_matrix.rs" 50
check_lines "crates/netdiag-core/src/connectors/resource_budget.rs" 210
check_lines "crates/netdiag-cli/src/main.rs" 930
check_lines "crates/netdiag-cli/src/commands/bearer_bindings.rs" 55
check_lines "crates/netdiag-cli/src/commands/bearer_source_kind.rs" 15
check_lines "crates/netdiag-cli/src/commands/artifact_root.rs" 45
check_lines "crates/netdiag-cli/src/commands/artifact_root/output.rs" 30
check_lines "crates/netdiag-cli/src/commands/collect.rs" 170
check_lines "crates/netdiag-cli/src/commands/collect/source.rs" 25
check_lines "crates/netdiag-cli/src/commands/collect_auth.rs" 20
check_lines "crates/netdiag-cli/src/commands/collect_auth/binding.rs" 30
check_lines "crates/netdiag-cli/src/commands/twin.rs" 85
check_lines "crates/netdiag-app/src/main.rs" 6300
check_lines "crates/netdiag-app/src/api_test.rs" 80
check_lines "crates/netdiag-app/src/api_test/status.rs" 70
check_lines "crates/netdiag-app/src/capture_session.rs" 130
check_lines "crates/netdiag-app/src/capture_session/cleanup.rs" 70
check_lines "crates/netdiag-app/src/confirmation.rs" 35
check_lines "crates/netdiag-app/src/connector_flow.rs" 170
check_lines "crates/netdiag-app/src/connector_auth.rs" 70
check_lines "crates/netdiag-app/src/credential_lifecycle.rs" 360
check_lines "crates/netdiag-app/src/credential_lifecycle/reconciliation.rs" 75
check_lines "crates/netdiag-app/src/credential_lifecycle/deletion.rs" 65
check_lines "crates/netdiag-app/src/credential_lifecycle/deletion/live_api.rs" 85
check_lines "crates/netdiag-app/src/credential_lifecycle/deletion/plan.rs" 60
check_lines "crates/netdiag-app/src/data_source.rs" 620
check_lines "crates/netdiag-app/src/data_source/debug.rs" 65
check_lines "crates/netdiag-app/src/data_source/flow_summary.rs" 180
check_lines "crates/netdiag-app/src/data_source/native_pcap.rs" 35
check_lines "crates/netdiag-app/src/lab_runtime.rs" 120
check_lines "crates/netdiag-app/src/model_cache.rs" 105
check_lines "crates/netdiag-app/src/run_history.rs" 20
check_lines "crates/netdiag-app/src/secrets.rs" 320
check_lines "crates/netdiag-app/src/secrets/presence.rs" 85
check_lines "crates/netdiag-app/src/settings_runtime.rs" 60
check_lines "crates/netdiag-app/src/translations.rs" 410
check_lines "crates/netdiag-app/src/source_selection.rs" 100
check_lines "crates/netdiag-app/src/topology_state.rs" 40

if rg_matches --line-number 'std::process::Command|Command::new|/usr/libexec/PlistBuddy' \
  "$ROOT/crates/netdiag-app/src/updater.rs"; then
  echo "architecture guard failed: updater metadata reads must stay in-process" >&2
  fail=1
fi

# New modules should stay narrow enough to remain reviewable.
check_lines "crates/netdiag-core/src/reliability.rs" 639
check_lines "crates/netdiag-core/src/reliability/diagnostics.rs" 100
check_lines "crates/netdiag-core/src/reliability/file_scan.rs" 310
check_lines "crates/netdiag-core/src/reliability/file_scan/access.rs" 90
check_lines "crates/netdiag-core/src/reliability/file_scan/budget.rs" 50
check_lines "crates/netdiag-core/src/reliability/file_scan/binding.rs" 10
check_lines "crates/netdiag-core/src/reliability/file_scan/binding/digest.rs" 55
check_lines "crates/netdiag-core/src/reliability/file_scan/binding/root.rs" 150
check_lines "crates/netdiag-core/src/reliability/file_scan/binding/file.rs" 145
check_lines "crates/netdiag-core/src/reliability/file_scan/binding/metadata.rs" 150
check_lines "crates/netdiag-core/src/reliability/file_scan/binding/validation.rs" 125
check_lines "crates/netdiag-core/src/reliability/file_scan/directory.rs" 55
check_lines "crates/netdiag-core/src/reliability/secrets.rs" 125
check_lines "crates/netdiag-core/src/reliability/secrets/key.rs" 125
check_lines "crates/netdiag-core/src/reliability/secrets/url.rs" 170
check_lines "crates/netdiag-core/src/error.rs" 290
check_lines "crates/netdiag-core/src/error/atomic_publish_phase.rs" 35
check_lines "crates/netdiag-core/src/models/topology.rs" 40
check_lines "crates/netdiag-core/src/pipeline.rs" 455
check_lines "crates/netdiag-core/src/pipeline/artifact.rs" 25
check_lines "crates/netdiag-core/src/pipeline/connector_health.rs" 35
check_lines "crates/netdiag-core/src/pipeline/execution.rs" 130
check_lines "crates/netdiag-core/src/pipeline/execution/result.rs" 25
check_lines "crates/netdiag-core/src/perf_budget.rs" 410
check_lines "crates/netdiag-core/src/perf_budget/measurements.rs" 230
check_lines "crates/netdiag-core/src/perf_budget/workspace.rs" 40
check_lines "crates/netdiag-core/benches/perf_budget.rs" 40
check_lines "crates/netdiag-core/src/pipeline/persist.rs" 145
check_lines "crates/netdiag-core/src/pipeline/publication.rs" 120
check_lines "crates/netdiag-core/src/artifact_root_migration.rs" 75
check_lines "crates/netdiag-core/src/artifact_root_migration/run_anchor.rs" 35
check_lines "crates/netdiag-core/src/storage/artifact_root.rs" 50
check_lines "crates/netdiag-core/src/storage/artifact_root/clear.rs" 560
check_lines "crates/netdiag-core/src/storage/artifact_root/clear/contract.rs" 110
check_lines "crates/netdiag-core/src/storage/artifact_root/clear/journal.rs" 100
check_lines "crates/netdiag-core/src/storage/artifact_root/clear/recovery.rs" 330
check_lines "crates/netdiag-core/src/storage/artifact_root/migration.rs" 75
check_lines "crates/netdiag-core/src/storage/artifact_root/ownership.rs" 440
check_lines "crates/netdiag-core/src/storage/artifact_root/path_validation.rs" 35
check_lines "crates/netdiag-core/src/storage/artifact_root/run_publication.rs" 100
check_lines "crates/netdiag-core/src/storage/artifact_root/run_publication/begin.rs" 60
check_lines "crates/netdiag-core/src/storage/artifact_root/run_publication/contract.rs" 125
check_lines "crates/netdiag-core/src/storage/artifact_root/run_publication/manifest.rs" 20
check_lines "crates/netdiag-core/src/storage/artifact_root/run_publication/index.rs" 40
check_lines "crates/netdiag-core/src/storage/artifact_root/run_publication/io.rs" 80
check_lines "crates/netdiag-core/src/storage/artifact_root/run_publication/recovery.rs" 115
check_lines "crates/netdiag-core/src/storage/artifact_root/staging.rs" 100
check_lines "crates/netdiag-core/src/storage/artifact_root/staging/lifecycle.rs" 70
check_lines "crates/netdiag-core/src/storage/atomic_directory.rs" 150
check_lines "crates/netdiag-core/src/storage/atomic_directory/cleanup.rs" 40
check_lines "crates/netdiag-core/src/storage/atomic_directory/cleanup/removal.rs" 30
check_lines "crates/netdiag-core/src/storage/atomic_directory/creation.rs" 80
check_lines "crates/netdiag-core/src/storage/atomic_directory/publication.rs" 110
check_lines "crates/netdiag-core/src/storage/atomic_file.rs" 20
check_lines "crates/netdiag-core/src/storage/atomic_file/durability.rs" 37
check_lines "crates/netdiag-core/src/storage/atomic_file/durability/cleanup.rs" 25
check_lines "crates/netdiag-core/src/storage/atomic_file/durability/remove.rs" 40
check_lines "crates/netdiag-core/src/storage/atomic_file/durability/remove/bound.rs" 55
check_lines "crates/netdiag-core/src/storage/atomic_file/publish.rs" 65
check_lines "crates/netdiag-core/src/storage/atomic_file/temporary.rs" 25
check_lines "crates/netdiag-core/src/storage/atomic_file/temporary/staged.rs" 105
check_lines "crates/netdiag-core/src/storage/atomic_file/temporary/staged/lifecycle.rs" 60
check_lines "crates/netdiag-core/src/storage/atomic_file/temporary/staged/publish.rs" 90
check_lines "crates/netdiag-core/src/storage/atomic_file/temporary/staged/publish/existing.rs" 50
check_lines "crates/netdiag-core/src/storage/atomic_file/target.rs" 85
check_lines "crates/netdiag-core/src/storage/atomic_file/target/binding.rs" 45
check_lines "crates/netdiag-core/src/storage/atomic_file/target/path.rs" 45
check_lines "crates/netdiag-core/src/storage/atomic_file/write.rs" 76
check_lines "crates/netdiag-core/src/storage/atomic_file/write/entry.rs" 65
check_lines "crates/netdiag-core/src/storage/atomic_file/write/execute.rs" 90
check_lines "crates/netdiag-core/src/storage/atomic_file/write/error.rs" 35
check_lines "crates/netdiag-core/src/storage/atomic_file/write/noclobber.rs" 22
check_lines "crates/netdiag-core/src/storage/atomic_file/write/noclobber/bound.rs" 37
check_lines "crates/netdiag-core/src/storage/file_lock.rs" 180
check_lines "crates/netdiag-core/src/storage/file_lock/completion.rs" 50
check_lines "crates/netdiag-core/src/storage/file_lock/errors.rs" 50
check_lines "crates/netdiag-core/src/storage/file_lock/errors/publication.rs" 55
check_lines "crates/netdiag-core/src/storage/file_lock/key.rs" 100
check_lines "crates/netdiag-core/src/storage/file_lock/parent_scope.rs" 125
check_lines "crates/netdiag-core/src/storage/file_lock/platform.rs" 55
check_lines "crates/netdiag-core/src/storage/file_lock/platform/unix.rs" 105
check_lines "crates/netdiag-core/src/storage/file_lock/platform/windows.rs" 40
check_lines "crates/netdiag-core/src/storage/file_lock/prepared.rs" 100
check_lines "crates/netdiag-core/src/storage/file_lock/prepared/namespace.rs" 25
check_lines "crates/netdiag-core/src/storage/file_lock/prepared/target_boundary.rs" 55
check_lines "crates/netdiag-core/src/storage/file_lock/prepared/validation.rs" 45
check_lines "crates/netdiag-core/src/storage/file_lock/prepared/view.rs" 40
check_lines "crates/netdiag-core/src/storage/file_lock/process.rs" 65
check_lines "crates/netdiag-core/src/storage/stable_read.rs" 130
check_lines "crates/netdiag-core/src/storage/stable_read/bound.rs" 50
check_lines "crates/netdiag-core/src/storage/stable_read/checkpoint.rs" 65
check_lines "crates/netdiag-core/src/storage/stable_read/digest.rs" 32
check_lines "crates/netdiag-core/src/storage/stable_read/digest/pass.rs" 36
check_lines "crates/netdiag-core/src/storage/stable_read/limit.rs" 7
check_lines "crates/netdiag-core/src/storage/stable_read/validation.rs" 46
check_lines "crates/netdiag-core/src/storage/typed_json.rs" 20
check_lines "crates/netdiag-core/src/storage/typed_json/limits.rs" 36
check_lines "crates/netdiag-core/src/storage/typed_json/preparation.rs" 53
check_lines "crates/netdiag-core/src/storage/typed_json/read.rs" 45
check_lines "crates/netdiag-core/src/storage/typed_json/read/required.rs" 40
check_lines "crates/netdiag-core/src/storage/typed_json/write.rs" 39
check_lines "crates/netdiag-core/src/storage/run_documents.rs" 85
check_lines "crates/netdiag-core/src/storage/run_snapshot_locks.rs" 115
check_lines "crates/netdiag-core/src/storage/run_snapshot_locks/location_identity.rs" 120
check_lines "crates/netdiag-core/src/storage/run_snapshot_locks/location_identity/path_identity.rs" 45
check_lines "crates/netdiag-core/src/storage/run_snapshot_locks/output_validation.rs" 160
check_lines "crates/netdiag-core/src/storage/run_snapshot_locks/output_validation/protected_scopes.rs" 75
check_lines "crates/netdiag-core/src/storage/run_snapshot_locks/target_path.rs" 90
check_lines "crates/netdiag-core/src/storage/run_snapshot_locks/target_set.rs" 90
check_lines "crates/netdiag-core/src/storage/run_snapshot_locks/target_set/protected.rs" 35
check_lines "crates/netdiag-core/src/storage/run_snapshot_locks/target_set/reserved.rs" 35
check_lines "crates/netdiag-core/src/storage/run_snapshot_locks/target_set/transaction.rs" 50
check_lines "crates/netdiag-platform/src/lib.rs" 25
check_lines "crates/netdiag-platform/src/atomic_directory.rs" 60
check_lines "crates/netdiag-platform/src/atomic_directory/unix.rs" 80
check_lines "crates/netdiag-platform/src/atomic_directory/unix/identity.rs" 35
check_lines "crates/netdiag-platform/src/atomic_directory/unix/removal.rs" 135
check_lines "crates/netdiag-platform/src/atomic_directory/unsupported.rs" 35
check_lines "crates/netdiag-platform/src/system_temporary_root.rs" 40
check_lines "crates/netdiag-platform/src/system_temporary_root/error.rs" 65
check_lines "crates/netdiag-platform/src/system_temporary_root/windows.rs" 90
check_lines "crates/netdiag-platform/src/atomic_file.rs" 63
check_lines "crates/netdiag-platform/src/atomic_file/error.rs" 60
check_lines "crates/netdiag-platform/src/atomic_file/error/classification.rs" 70
check_lines "crates/netdiag-platform/src/atomic_file/error/classification/display.rs" 40
check_lines "crates/netdiag-platform/src/atomic_file/error/construction.rs" 40
check_lines "crates/netdiag-platform/src/atomic_file/error/display.rs" 20
check_lines "crates/netdiag-platform/src/atomic_file/leaf.rs" 23
check_lines "crates/netdiag-platform/src/atomic_file/unix.rs" 45
check_lines "crates/netdiag-platform/src/atomic_file/unix/durability.rs" 6
check_lines "crates/netdiag-platform/src/atomic_file/unix/open.rs" 83
check_lines "crates/netdiag-platform/src/atomic_file/unsupported.rs" 32
check_lines "crates/netdiag-platform/src/atomic_file/unsupported/publication.rs" 19
check_lines "crates/netdiag-platform/src/atomic_file/windows.rs" 59
check_lines "crates/netdiag-platform/src/atomic_file/windows/open.rs" 29
check_lines "crates/netdiag-platform/src/atomic_file/windows/classification.rs" 85
check_lines "crates/netdiag-platform/src/atomic_file/windows/classification/observation.rs" 40
check_lines "crates/netdiag-platform/src/opened_file.rs" 120
check_lines "crates/netdiag-platform/src/private_file_creation_error.rs" 80
check_lines "crates/netdiag-platform/src/private_file_creation_error/display.rs" 30
check_lines "crates/netdiag-platform/src/windows.rs" 40
check_lines "crates/netdiag-platform/src/windows/atomic_replace.rs" 40
check_lines "crates/netdiag-platform/src/windows/atomic_replace/path.rs" 25
check_lines "crates/netdiag-platform/src/windows/coordination.rs" 45
check_lines "crates/netdiag-platform/src/windows/identity.rs" 35
check_lines "crates/netdiag-platform/src/windows/known_folder.rs" 90
check_lines "crates/netdiag-platform/src/windows/known_folder/error.rs" 40
check_lines "crates/netdiag-platform/src/windows/known_folder/error/display.rs" 50
check_lines "crates/netdiag-platform/src/windows/open.rs" 30
check_lines "crates/netdiag-platform/src/trusted_directory.rs" 140
check_lines "crates/netdiag-platform/src/trusted_directory/creation.rs" 50
check_lines "crates/netdiag-platform/src/trusted_directory/error.rs" 65
check_lines "crates/netdiag-platform/src/trusted_directory/error/persistence.rs" 20
check_lines "crates/netdiag-platform/src/trusted_directory/error/display.rs" 110
check_lines "crates/netdiag-platform/src/trusted_directory/strict.rs" 70
check_lines "crates/netdiag-platform/src/trusted_directory/unix.rs" 225
check_lines "crates/netdiag-platform/src/trusted_directory/unix/child.rs" 80
check_lines "crates/netdiag-platform/src/trusted_directory/unix/child/create.rs" 50
check_lines "crates/netdiag-platform/src/trusted_directory/unix/child/create/cleanup.rs" 30
check_lines "crates/netdiag-platform/src/trusted_directory/unix/child/create/cleanup/error.rs" 30
check_lines "crates/netdiag-platform/src/trusted_directory/unix/child/create/cleanup/tests.rs" 10
check_lines "crates/netdiag-platform/src/trusted_directory/unix/child/create/cleanup/tests/success.rs" 40
check_lines "crates/netdiag-platform/src/trusted_directory/unix/child/create/cleanup/tests/prepared_success.rs" 40
check_lines "crates/netdiag-platform/src/trusted_directory/unix/child/create/cleanup/tests/failure.rs" 55
check_lines "crates/netdiag-platform/src/trusted_directory/unix/components.rs" 35
check_lines "crates/netdiag-platform/src/trusted_directory/unix/durability.rs" 15
check_lines "crates/netdiag-platform/src/trusted_directory/unix/durability/error.rs" 20
check_lines "crates/netdiag-platform/src/trusted_directory/unix/durability/open.rs" 30
check_lines "crates/netdiag-platform/src/trusted_directory/unix/durability/entry.rs" 45
check_lines "crates/netdiag-platform/src/trusted_directory/unix/durability/entry/tests.rs" 70
check_lines "crates/netdiag-platform/src/trusted_directory/unix/durability/chain.rs" 55
check_lines "crates/netdiag-platform/src/trusted_directory/unix/durability/chain/tests.rs" 75
check_lines "crates/netdiag-platform/src/trusted_directory/unix/durability/chain/tests/success.rs" 70
check_lines "crates/netdiag-platform/src/trusted_directory/unix/durability/chain/tests/error_paths.rs" 10
check_lines "crates/netdiag-platform/src/trusted_directory/unix/durability/chain/tests/error_paths/leaf.rs" 45
check_lines "crates/netdiag-platform/src/trusted_directory/unix/durability/chain/tests/error_paths/ancestor.rs" 60
check_lines "crates/netdiag-platform/src/trusted_directory/unix/entry_error.rs" 50
check_lines "crates/netdiag-platform/src/trusted_directory/unix/identity.rs" 45
check_lines "crates/netdiag-platform/src/trusted_directory/unix/security.rs" 60
check_lines "crates/netdiag-platform/src/trusted_directory/unix/strict.rs" 155
check_lines "crates/netdiag-platform/src/trusted_directory/unix/symlink.rs" 45
check_lines "crates/netdiag-platform/src/trusted_temp_directory.rs" 80
check_lines "crates/netdiag-platform/src/trusted_temp_directory/error.rs" 55
check_lines "crates/netdiag-platform/src/trusted_temp_directory/error/display.rs" 105
check_lines "crates/netdiag-platform/src/trusted_temp_directory/finish.rs" 60
check_lines "crates/netdiag-platform/src/trusted_temp_directory/cleanup.rs" 35
check_lines "crates/netdiag-platform/src/trusted_temp_directory/create.rs" 95
check_lines "crates/netdiag-platform/src/trusted_temp_directory/create/name.rs" 55
check_lines "crates/netdiag-platform/src/trusted_temp_directory/create/platform.rs" 40
check_lines "crates/netdiag-platform/src/trusted_temp_directory/create/platform/unix.rs" 70
check_lines "crates/netdiag-platform/src/trusted_temp_directory/create/platform/windows.rs" 45
check_lines "crates/netdiag-platform/src/trusted_temp_directory/create/platform/unsupported.rs" 25
check_lines "crates/netdiag-platform/src/trusted_temp_directory/identity.rs" 20
check_lines "crates/netdiag-platform/src/trusted_temp_directory/identity/unix.rs" 90
check_lines "crates/netdiag-platform/src/trusted_temp_directory/identity/windows.rs" 65
check_lines "crates/netdiag-platform/src/trusted_temp_directory/identity/unsupported.rs" 25
check_lines "crates/netdiag-platform/src/trusted_directory/windows.rs" 107
check_lines "crates/netdiag-platform/src/trusted_directory/windows/child.rs" 11
check_lines "crates/netdiag-platform/src/trusted_directory/windows/handle.rs" 36
check_lines "crates/netdiag-platform/src/trusted_directory/windows/identity.rs" 45
check_lines "crates/netdiag-platform/src/trusted_directory/windows/validation.rs" 45
check_lines "crates/netdiag-platform/src/trusted_directory/windows/tests.rs" 50
check_lines "crates/netdiag-platform/tests/trusted_directory.rs" 10
check_lines "crates/netdiag-platform/tests/trusted_directory/contract.rs" 60
check_lines "crates/netdiag-platform/tests/trusted_directory/chain.rs" 35
check_lines "crates/netdiag-platform/tests/trusted_directory/error_paths.rs" 65
check_lines "crates/netdiag-platform/src/unix_acl.rs" 100
check_lines "crates/netdiag-platform/src/unix_acl/linux.rs" 110
check_lines "crates/netdiag-platform/src/unix_acl/macos.rs" 260
check_lines "crates/netdiag-platform/src/windows/security.rs" 40
check_lines "crates/netdiag-platform/src/windows/security/buffer.rs" 40
check_lines "crates/netdiag-platform/src/windows/security/cleanup.rs" 20
check_lines "crates/netdiag-platform/src/windows/security/create.rs" 75
check_lines "crates/netdiag-platform/src/windows/security/descriptor.rs" 125
check_lines "crates/netdiag-platform/src/windows/security/sid.rs" 180
check_lines "crates/netdiag-platform/src/windows/security/validation.rs" 155
check_lines "crates/netdiag-platform/src/windows/security/validation/acl.rs" 140
check_lines "crates/netdiag-core/src/benchmark.rs" 494
check_lines "crates/netdiag-core/src/benchmark/adapter_validation.rs" 120
check_lines "crates/netdiag-core/src/benchmark/adapter_validation/schema_validation.rs" 25
check_lines "crates/netdiag-core/src/benchmark/adapter_validation/unix.rs" 120
check_lines "crates/netdiag-core/src/benchmark/adapter_validation/unsupported.rs" 15
check_lines "crates/netdiag-core/src/benchmark/benchmark_model_identity.rs" 49
check_lines "crates/netdiag-core/src/benchmark/ood_scenarios.rs" 30
check_lines "crates/netdiag-core/src/ml.rs" 1585
check_lines "crates/netdiag-core/src/ml/feedback_export.rs" 110
check_lines "crates/netdiag-core/src/ml/feedback_export/publication.rs" 70
check_lines "crates/netdiag-core/src/ml/feedback_export/publication/digest_writer.rs" 45
check_lines "crates/netdiag-core/src/ml/feedback_export/snapshot.rs" 95
check_lines "crates/netdiag-core/src/ml/feedback_export/snapshot_contract.rs" 125
check_lines "crates/netdiag-core/src/ml/model_bundle.rs" 290
check_lines "crates/netdiag-core/src/ml/model_bundle/layout.rs" 150
check_lines "crates/netdiag-core/src/ml/model_bundle/layout/current.rs" 60
check_lines "crates/netdiag-core/src/ml/model_bundle/layout/resolution.rs" 140
check_lines "crates/netdiag-core/src/ml/model_bundle/loading.rs" 110
check_lines "crates/netdiag-core/src/ml/model_bundle/publication.rs" 220
check_lines "crates/netdiag-core/src/ml/model_bundle/publication/cleanup.rs" 100
check_lines "crates/netdiag-core/src/ml/model_bundle/publication/durability.rs" 90
check_lines "crates/netdiag-core/src/ml/model_bundle/publication/durability/parent.rs" 50
check_lines "crates/netdiag-core/src/ml/model_bundle/publication/manifest_update.rs" 50
check_lines "crates/netdiag-core/src/ml/model_bundle/trust.rs" 180
check_lines "crates/netdiag-core/src/ml/model_bundle/trust/durability.rs" 30
check_lines "crates/netdiag-core/src/ml/model_bundle/trust/security.rs" 45
check_lines "crates/netdiag-core/src/ml/model_bundle/migration.rs" 195
check_lines "crates/netdiag-core/src/dataset.rs" 800
check_lines "crates/netdiag-core/src/dataset/migration.rs" 210
check_lines "crates/netdiag-core/src/dataset/input_snapshot.rs" 60
check_lines "crates/netdiag-core/src/dataset/input_snapshot/capture.rs" 45
check_lines "crates/netdiag-core/src/dataset/limits.rs" 30
check_lines "crates/netdiag-core/src/dataset/row_reader.rs" 210
check_lines "crates/netdiag-core/src/dataset/rows.rs" 190
check_lines "crates/netdiag-core/src/dataset/rows/retained.rs" 65
check_lines "crates/netdiag-core/src/dataset/rows/validation.rs" 115
check_lines "crates/netdiag-core/src/dataset/rows/validation/input.rs" 20
check_lines "crates/netdiag-core/src/dataset/split_publication.rs" 180
check_lines "crates/netdiag-core/src/dataset/split_publication/plan.rs" 165
check_lines "crates/netdiag-core/src/dataset/split_publication/plan/receipt.rs" 90
check_lines "crates/netdiag-core/src/dataset/split_publication/plan/receipt/validation.rs" 120
check_lines "crates/netdiag-core/src/dataset/split_publication/recovery.rs" 160
check_lines "crates/netdiag-core/src/dataset/split_publication/recovery/claim.rs" 120
check_lines "crates/netdiag-core/src/dataset/split_publication/recovery/collision.rs" 70
check_lines "crates/netdiag-core/src/dataset/split_publication/recovery/partition.rs" 170
check_lines "crates/netdiag-core/src/dataset/split_publication/recovery/partition/publication.rs" 85
check_lines "crates/netdiag-core/src/dataset/split_publication/recovery/committed.rs" 70
check_lines "crates/netdiag-core/src/dataset/split_publication/recovery/committed/manifest.rs" 90
check_lines "crates/netdiag-core/src/dataset/split_publication/recovery/target.rs" 60
check_lines "crates/netdiag-core/src/dataset/training.rs" 130
check_lines "crates/netdiag-core/src/dataset/registration.rs" 145
check_lines "crates/netdiag-core/src/dataset/registration/transaction.rs" 145
check_lines "crates/netdiag-core/src/dataset/trusted_root.rs" 50
check_lines "crates/netdiag-core/src/dataset/trusted_root/errors.rs" 45
check_lines "crates/netdiag-core/src/dataset/trusted_root/open.rs" 40
check_lines "crates/netdiag-core/src/dataset/trusted_root/open/child.rs" 45
check_lines "crates/netdiag-core/src/dataset/trusted_root/open/directory.rs" 40
check_lines "crates/netdiag-core/src/dataset/trusted_root/open/path.rs" 15
check_lines "crates/netdiag-core/src/dataset/trusted_root/publication.rs" 75
check_lines "crates/netdiag-core/src/dataset/trusted_root/publication/confirmation.rs" 65
check_lines "crates/netdiag-core/src/dataset/trusted_root/publication/finish.rs" 50
check_lines "crates/netdiag-core/src/dataset/trusted_root/rollback.rs" 55
check_lines "crates/netdiag-core/src/dataset/trusted_root/rollback/removal.rs" 45
check_lines "crates/netdiag-core/src/dataset/trusted_root/target.rs" 55
check_lines "crates/netdiag-core/src/dataset/registration/manifest.rs" 10
check_lines "crates/netdiag-core/src/dataset/registration/manifest/existing.rs" 50
check_lines "crates/netdiag-core/src/dataset/registration/manifest/existing/decode.rs" 20
check_lines "crates/netdiag-core/src/dataset/registration/manifest/preparation.rs" 15
check_lines "crates/netdiag-core/src/dataset/registration/manifest/publication.rs" 20
check_lines "crates/netdiag-core/src/dataset/registration/registry_publish.rs" 60
check_lines "crates/netdiag-core/src/dataset/registration/registry_publish/io.rs" 30
check_lines "crates/netdiag-core/src/dataset/registration/registry_publish/preparation.rs" 35
check_lines "crates/netdiag-core/src/dataset/registration/registry_publish/validation.rs" 25
check_lines "crates/netdiag-core/src/dataset/registration_snapshot.rs" 55
check_lines "crates/netdiag-core/src/dataset/registration_snapshot/bounded_digest.rs" 75
check_lines "crates/netdiag-core/src/dataset/registration_snapshot/digest.rs" 35
check_lines "crates/netdiag-core/src/dataset/registration_snapshot/lifecycle.rs" 40
check_lines "crates/netdiag-core/src/dataset/registration_snapshot/publication.rs" 70
check_lines "crates/netdiag-core/src/dataset/registration_snapshot/source.rs" 155
check_lines "crates/netdiag-core/src/identifiers.rs" 28
check_lines "crates/netdiag-core/src/identifiers/portable_ascii.rs" 22
check_lines "crates/netdiag-core/src/identifiers/windows.rs" 10
check_lines "crates/netdiag-core/src/resource_limits.rs" 35
check_lines "crates/netdiag-core/src/feature_schema.rs" 20
check_lines "crates/netdiag-core/src/strict_json.rs" 20
check_lines "crates/netdiag-core/src/strict_json/error.rs" 20
check_lines "crates/netdiag-core/src/strict_json/typed.rs" 15
check_lines "crates/netdiag-core/src/strict_json/validation.rs" 90
check_lines "crates/netdiag-core/src/strict_json/value.rs" 100
check_lines "crates/netdiag-core/src/models/comparison.rs" 25
check_lines "crates/netdiag-core/src/evidence_bundle.rs" 326
check_lines "crates/netdiag-core/src/evidence_bundle/source.rs" 118
check_lines "crates/netdiag-core/src/evidence_bundle/source/override_source.rs" 60
check_lines "crates/netdiag-core/src/evidence_bundle/source/stable_file.rs" 80
check_lines "crates/netdiag-core/src/evidence_bundle/source/stable_file/file_type.rs" 30
check_lines "crates/netdiag-core/src/file_identity.rs" 25
check_lines "crates/netdiag-core/src/evidence_bundle/source/zip_path.rs" 40
check_lines "crates/netdiag-core/src/evidence_bundle/stream.rs" 146
check_lines "crates/netdiag-core/src/evidence_bundle/archive_sources.rs" 170
check_lines "crates/netdiag-core/src/evidence_bundle/export.rs" 170
check_lines "crates/netdiag-core/src/evidence_bundle/export/source_overrides.rs" 80
check_lines "crates/netdiag-core/src/evidence_bundle/export/staged_directory.rs" 45
check_lines "crates/netdiag-core/src/evidence_bundle/context.rs" 115
check_lines "crates/netdiag-core/src/evidence_bundle/prepared.rs" 190
check_lines "crates/netdiag-core/src/evidence_bundle/prepared/capture.rs" 60
check_lines "crates/netdiag-core/src/evidence_bundle/prepared/requested_extras.rs" 60
check_lines "crates/netdiag-core/src/evidence_bundle/snapshot.rs" 230
check_lines "crates/netdiag-core/src/evidence_bundle/snapshot/cleanup.rs" 20
check_lines "crates/netdiag-core/src/evidence_bundle/snapshot/digest.rs" 115
check_lines "crates/netdiag-core/src/evidence_bundle/snapshot/seal.rs" 20
check_lines "crates/netdiag-core/src/lab/calibration.rs" 550
check_lines "crates/netdiag-core/src/lab/calibration/evidence_identity.rs" 130
check_lines "crates/netdiag-core/src/lab/calibration/model_identity.rs" 129
check_lines "crates/netdiag-core/src/lab/calibration/report.rs" 44
check_lines "crates/netdiag-core/src/lab/calibration/rule_events.rs" 46
check_lines "crates/netdiag-core/src/lab/calibration/rule_events/read.rs" 40
check_lines "crates/netdiag-core/src/lab/calibration/rule_events/read/error.rs" 30
check_lines "crates/netdiag-core/src/lab/calibration/rule_events/validation.rs" 40
check_lines "crates/netdiag-core/src/lab/calibration/thresholds.rs" 79
check_lines "crates/netdiag-core/src/lab/action_verification_artifact.rs" 300
check_lines "crates/netdiag-core/src/lab/index_update.rs" 90
check_lines "crates/netdiag-core/src/lab/index_update/review.rs" 40
check_lines "crates/netdiag-core/src/lab/index_update/tests.rs" 10
check_lines "crates/netdiag-core/src/lab/index_update/tests/support.rs" 45
check_lines "crates/netdiag-core/src/lab/index_contract.rs" 20
check_lines "crates/netdiag-core/src/lab/index_validation.rs" 45
check_lines "crates/netdiag-core/src/lab/index_validation/artifacts.rs" 110
check_lines "crates/netdiag-core/src/lab/evidence_identity.rs" 80
check_lines "crates/netdiag-core/src/lab/index_path.rs" 45
check_lines "crates/netdiag-core/src/lab/review_sync.rs" 110
check_lines "crates/netdiag-core/src/lab/scenario_input.rs" 70
check_lines "crates/netdiag-core/src/lab/scenario_input/validation.rs" 250
check_lines "crates/netdiag-core/src/lab/summary.rs" 190
check_lines "crates/netdiag-core/src/lab/summary/read.rs" 20
check_lines "crates/netdiag-core/src/lab/verification_objective.rs" 60
check_lines "crates/netdiag-core/src/storage.rs" 820
check_lines "crates/netdiag-core/src/hil_review.rs" 400
check_lines "crates/netdiag-core/src/storage/hil_transaction/feedback.rs" 80
check_lines "crates/netdiag-core/src/hil_review/plan.rs" 125
check_lines "crates/netdiag-core/src/storage/hil_transaction.rs" 30
check_lines "crates/netdiag-core/src/storage/hil_transaction/durability.rs" 35
check_lines "crates/netdiag-core/src/storage/hil_transaction/durability/publication.rs" 130
check_lines "crates/netdiag-core/src/storage/hil_transaction/durability/platform.rs" 25
check_lines "crates/netdiag-core/src/storage/hil_transaction/journal.rs" 185
check_lines "crates/netdiag-core/src/storage/hil_transaction/journal/file.rs" 25
check_lines "crates/netdiag-core/src/storage/hil_transaction/journal/validation.rs" 100
check_lines "crates/netdiag-core/src/storage/hil_transaction/publisher.rs" 380
check_lines "crates/netdiag-core/src/pilot.rs" 417
check_lines "crates/netdiag-core/src/pilot/preflight.rs" 230
check_lines "crates/netdiag-core/src/pilot/evidence.rs" 130
check_lines "crates/netdiag-platform/src/unix_acl.rs" 100
check_lines "crates/netdiag-core/src/pilot/redaction.rs" 85
check_lines "crates/netdiag-core/src/pilot/redaction/adapter_arguments.rs" 50
check_lines "crates/netdiag-core/src/pilot/adapter_contract.rs" 14
check_lines "crates/netdiag-core/src/pilot/adapter_contract/declaration.rs" 129
check_lines "crates/netdiag-core/src/pilot/adapter_contract/declaration/options.rs" 155
check_lines "crates/netdiag-core/src/pilot/adapter_contract/declaration/options/environment.rs" 60
check_lines "crates/netdiag-core/src/pilot/adapter_contract/preflight.rs" 45
check_lines "crates/netdiag-core/src/pilot/adapter_contract/preflight/structure.rs" 90
check_lines "crates/netdiag-core/src/bounded_process.rs" 120
check_lines "crates/netdiag-core/src/bounded_process/capture.rs" 110
check_lines "crates/netdiag-core/src/bounded_process/capture/polling.rs" 85
check_lines "crates/netdiag-core/src/bounded_process/capture/stream.rs" 80
check_lines "crates/netdiag-core/src/bounded_process/termination.rs" 75
check_lines "crates/netdiag-core/src/bounded_process/unix.rs" 190
check_lines "crates/netdiag-core/src/connectors/system_counters_process.rs" 80
check_lines "crates/netdiag-core/src/pilot/adapter_contract/process.rs" 115
check_lines "crates/netdiag-core/src/pilot/adapter_contract/process/error.rs" 25
check_lines "crates/netdiag-core/src/python_runtime.rs" 130
check_lines "crates/netdiag-core/src/managed_temp_directory.rs" 60
check_lines "crates/netdiag-core/src/python_runtime/discovery.rs" 80
check_lines "crates/netdiag-core/src/python_runtime/path_entries.rs" 85
check_lines "crates/netdiag-core/src/python_runtime/path_entries/trust.rs" 45
check_lines "crates/netdiag-core/src/python_runtime/configured.rs" 55
check_lines "crates/netdiag-core/src/pilot/pilot_sources.rs" 415
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_args.rs" 3
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_args/invocation.rs" 54
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_boundary.rs" 155
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_boundary/staging.rs" 145
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_boundary/staging/stage.rs" 95
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_boundary/staging/copy.rs" 60
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_boundary/staging/copy/digest.rs" 65
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_boundary/staging/file_security.rs" 35
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_boundary/staging/source_validation.rs" 40
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_boundary/staging/source_validation/normalize.rs" 30
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_boundary/staging/trusted_root.rs" 100
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_boundary/staging/trusted_root/open.rs" 95
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_boundary/staging/trusted_root/open/error.rs" 25
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_environment.rs" 110
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_environment/lookup.rs" 105
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_environment/redaction.rs" 45
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_environment/redaction/argument.rs" 25
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_source.rs" 125
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_source/redaction.rs" 45
check_lines "crates/netdiag-core/src/pilot/pilot_sources/adapter_source/reporting.rs" 30
check_lines "crates/netdiag-core/src/pilot/pilot_sources/payload_contract.rs" 66
check_lines "crates/netdiag-core/src/pilot/pilot_sources/payload_contract/validation.rs" 30
check_lines "crates/netdiag-core/src/pilot/prepared.rs" 40
check_lines "crates/netdiag-core/src/pilot/prepared/manifest.rs" 50
check_lines "crates/netdiag-core/src/pilot/run_directory.rs" 25
check_lines "crates/netdiag-core/src/pilot/types.rs" 213
check_lines "crates/netdiag-core/src/pilot/types/collection.rs" 90
check_lines "crates/netdiag-core/src/pilot/types/source_options.rs" 71
check_lines "crates/netdiag-core/src/pilot/types/workflow.rs" 70
check_lines "crates/netdiag-core/src/pilot/validation.rs" 76
check_lines "crates/netdiag-core/src/pilot/validation/adapter_boundary.rs" 45
check_lines "crates/netdiag-core/src/pilot/validation/adapter_boundary/budget.rs" 30
check_lines "crates/netdiag-core/src/pilot/workflow.rs" 187
check_lines "crates/netdiag-core/src/pilot/workflow/persistence.rs" 20
check_lines "crates/netdiag-core/src/pilot/promotion.rs" 303
check_lines "crates/netdiag-core/src/pilot/promotion/snapshot.rs" 27
check_lines "crates/netdiag-core/src/pilot/promotion/input.rs" 60
check_lines "crates/netdiag-core/src/pilot/promotion/benchmark_identity.rs" 60
check_lines "crates/netdiag-core/src/pilot/promotion/model_state.rs" 60
check_lines "crates/netdiag-core/src/pilot/promotion/calibration.rs" 338
check_lines "crates/netdiag-core/src/pilot/promotion/calibration/schema.rs" 28
check_lines "crates/netdiag-core/src/pilot/promotion/gates.rs" 216
check_lines "crates/netdiag-app/src/pilot_run_center.rs" 281
check_lines "crates/netdiag-app/src/pilot_run_center/view.rs" 68
check_lines "crates/netdiag-app/src/pilot_run_center/view/controls.rs" 35
check_lines "crates/netdiag-app/src/pilot_run_center/view/verification.rs" 25
check_lines "crates/netdiag-app/src/settings.rs" 860
check_lines "crates/netdiag-app/src/settings/store.rs" 180
check_lines "crates/netdiag-app/src/settings/store/errors.rs" 75
check_lines "crates/netdiag-app/src/settings/store/revision.rs" 30
check_lines "crates/netdiag-app/src/settings/store/snapshot.rs" 45
check_lines "crates/netdiag-app/src/settings/store/transaction.rs" 220
check_lines "crates/netdiag-app/src/settings/bearer_credentials.rs" 60
check_lines "crates/netdiag-app/src/settings/credential_cleanup.rs" 20
check_lines "crates/netdiag-app/src/settings/debug.rs" 60
check_lines "crates/netdiag-app/src/settings/environment.rs" 30
check_lines "crates/netdiag-app/src/settings/otlp.rs" 45
check_lines "crates/netdiag-app/src/settings/validation.rs" 45
check_lines "crates/netdiag-app/src/settings/validation/budget.rs" 66
check_lines "crates/netdiag-app/src/settings/validation/bearer_credentials.rs" 75
check_lines "crates/netdiag-app/src/settings/validation/path.rs" 20
check_lines "crates/netdiag-app/src/settings/validation/connectors.rs" 90
check_lines "crates/netdiag-app/src/settings/validation/connectors/authentication.rs" 25
check_lines "crates/netdiag-app/src/settings/validation/connectors/http_endpoint.rs" 60
check_lines "crates/netdiag-app/src/settings/validation/connectors/mapping.rs" 50
check_lines "crates/netdiag-app/src/settings/validation/connectors/profile.rs" 50
check_lines "crates/netdiag-app/src/settings/validation/connectors/website.rs" 25
check_lines "crates/netdiag-app/src/settings/validation/serialized_size.rs" 56
check_lines "crates/netdiag-app/src/settings/validation/topology.rs" 52

pipeline_publication_paths=(
  "$ROOT/crates/netdiag-core/src/pipeline.rs"
  "$ROOT/crates/netdiag-core/src/pipeline/execution.rs"
  "$ROOT/crates/netdiag-core/src/pipeline/publication.rs"
)
if rg_matches --line-number \
  'create_dir_all|remove_dir_all|(std::)?fs::rename|path_status' \
  "${pipeline_publication_paths[@]}"; then
  echo "architecture guard failed: pipeline run publication reintroduced path-based directory mutation" >&2
  fail=1
fi

perf_lifecycle_paths=(
  "$ROOT/crates/netdiag-core/src/perf_budget.rs"
  "$ROOT/crates/netdiag-core/src/perf_budget/measurements.rs"
  "$ROOT/crates/netdiag-core/src/perf_budget/workspace.rs"
  "$ROOT/crates/netdiag-core/benches/perf_budget.rs"
)
if rg_matches --line-number \
  'remove_dir_all|create_dir_all|join\("current"\)|perf-bench-artifacts' \
  "${perf_lifecycle_paths[@]}"; then
  echo "architecture guard failed: performance measurements reintroduced path-based workspace reset" >&2
  fail=1
fi
if ! rg_matches --quiet 'create_root_bound_staged_directory' \
     "$ROOT/crates/netdiag-core/src/perf_budget/workspace.rs" || \
   ! rg_matches --quiet 'discard_root_bound_staged_directory' \
     "$ROOT/crates/netdiag-core/src/perf_budget/workspace.rs"; then
  echo "architecture guard failed: performance workspaces are no longer root-bound and disposable" >&2
  fail=1
fi
if ! rg_matches --quiet 'TrustedTempDirectory::create' \
     "$ROOT/crates/netdiag-core/benches/perf_budget.rs" || \
   ! rg_matches --quiet 'workspace\.finish\(operation\)' \
     "$ROOT/crates/netdiag-core/benches/perf_budget.rs"; then
  echo "architecture guard failed: the performance benchmark default workspace is no longer isolated and explicitly cleaned" >&2
  fail=1
fi

strict_json_boundary_paths=(
  "$ROOT/crates/netdiag-core/src/reliability.rs"
  "$ROOT/crates/netdiag-core/src/evidence_bundle/archive_sources.rs"
  "$ROOT/crates/netdiag-core/src/lab/action_verification_artifact.rs"
  "$ROOT/crates/netdiag-core/src/dataset/registration/manifest/existing/decode.rs"
  "$ROOT/crates/netdiag-core/src/lab/calibration/rule_events/read.rs"
  "$ROOT/crates/netdiag-core/src/storage/artifact_root/run_publication/manifest.rs"
  "$ROOT/crates/netdiag-core/src/storage/artifact_root/run_publication/io.rs"
  "$ROOT/crates/netdiag-core/src/storage/artifact_root/clear/journal.rs"
  "$ROOT/crates/netdiag-core/src/storage/artifact_root/ownership.rs"
  "$ROOT/crates/netdiag-core/src/ml/model_bundle/loading.rs"
  "$ROOT/crates/netdiag-core/src/ml/model_bundle/layout/current.rs"
  "$ROOT/crates/netdiag-core/src/storage/hil_transaction/journal/file.rs"
  "$ROOT/crates/netdiag-core/src/pilot/promotion/input.rs"
  "$ROOT/crates/netdiag-core/src/perf_budget.rs"
)
if rg_matches --line-number 'serde_json::from_(slice|str|reader)' "${strict_json_boundary_paths[@]}"; then
  echo "architecture guard failed: persisted semantic JSON bypasses duplicate-key validation" >&2
  fail=1
fi
for strict_json_boundary in "${strict_json_boundary_paths[@]}"; do
  if ! rg_matches --quiet 'strict_json::from_slice' "$strict_json_boundary"; then
    echo "architecture guard failed: persisted semantic JSON no longer uses the strict decoder: $strict_json_boundary" >&2
    fail=1
  fi
done

capability_lifecycle_paths=(
  "$ROOT/crates/netdiag-core/src/pipeline.rs"
  "$ROOT/crates/netdiag-core/src/pipeline/execution.rs"
  "$ROOT/crates/netdiag-core/src/lab.rs"
  "$ROOT/crates/netdiag-core/src/pilot.rs"
  "$ROOT/crates/netdiag-core/src/benchmark.rs"
)
if rg_matches --line-number \
  'capability:[[:space:]]*Option|Option<&[^>]*ArtifactRootCapability>|capability\.as_ref\(\)' \
  "${capability_lifecycle_paths[@]}"; then
  echo "architecture guard failed: artifact publication capability became optional" >&2
  fail=1
fi
if rg_matches --line-number '\bupdate_run_index\b' "${pipeline_publication_paths[@]}"; then
  echo "architecture guard failed: pipeline publication reintroduced a path-based run index update" >&2
  fail=1
fi
if ! rg_matches --quiet 'RunPublicationRoot::Owned' "$ROOT/crates/netdiag-core/src/pipeline.rs" || \
   ! rg_matches --quiet 'RunPublicationRoot::Nested' "$ROOT/crates/netdiag-core/src/pipeline.rs" || \
   ! rg_matches --quiet 'reconcile_nested_run_publication_index' "$ROOT/crates/netdiag-core/src/pipeline/execution.rs"; then
  echo "architecture guard failed: pipeline owned/nested publication roots are no longer explicit" >&2
  fail=1
fi
for capability_owner in \
  "$ROOT/crates/netdiag-core/src/lab.rs" \
  "$ROOT/crates/netdiag-core/src/pilot.rs" \
  "$ROOT/crates/netdiag-core/src/benchmark.rs"; do
  if ! rg_matches --quiet 'prepare_artifact_root' "$capability_owner"; then
    echo "architecture guard failed: top-level operation no longer retains an artifact-root capability: $capability_owner" >&2
    fail=1
  fi
done
if ! rg_matches --quiet 'create_root_bound_staged_directory' "$ROOT/crates/netdiag-core/src/lab.rs" || \
   ! rg_matches --quiet 'finish_root_bound_staged_directory' "$ROOT/crates/netdiag-core/src/lab.rs"; then
  echo "architecture guard failed: Lab outer run no longer uses the root-bound staged lifecycle" >&2
  fail=1
fi
if ! rg_matches --quiet 'create_staged_pilot_run' "$ROOT/crates/netdiag-core/src/pilot.rs" || \
   ! rg_matches --quiet 'finish_root_bound_staged_directory' "$ROOT/crates/netdiag-core/src/pilot.rs"; then
  echo "architecture guard failed: Pilot outer run no longer uses the root-bound staged lifecycle" >&2
  fail=1
fi
if rg_matches --multiline --line-number \
  'fs::write\([^;]{0,200}run_id\.txt' \
  "$ROOT/crates/netdiag-core/src/lab.rs"; then
  echo "architecture guard failed: Lab run_id.txt reintroduced a direct, non-durable write" >&2
  fail=1
fi
if rg_matches --line-number \
  'std::fs|fs::(create_dir|create_dir_all|rename|remove_dir_all)' \
  "$ROOT/crates/netdiag-core/src/pilot/run_directory.rs"; then
  echo "architecture guard failed: Pilot outer run creation bypasses staged atomic directories" >&2
  fail=1
fi

otlp_receiver_paths=(
  "$ROOT/crates/netdiag-core/src/connectors/otlp.rs"
  "$ROOT/crates/netdiag-core/src/connectors/otlp/buffer.rs"
  "$ROOT/crates/netdiag-core/src/connectors/otlp/projection.rs"
  "$ROOT/crates/netdiag-core/src/connectors/otlp/projection/budget.rs"
  "$ROOT/crates/netdiag-core/src/connectors/otlp/projection/numeric.rs"
  "$ROOT/crates/netdiag-core/src/connectors/otlp/server.rs"
  "$ROOT/crates/netdiag-core/src/connectors/otlp/server/incoming.rs"
  "$ROOT/crates/netdiag-core/src/connectors/otlp/server/runtime.rs"
  "$ROOT/crates/netdiag-core/src/connectors/otlp/server/shutdown.rs"
)
if rg_matches --line-number \
  'VecDeque<[^>]*ExportMetricsServiceRequest|request:[[:space:]]*ExportMetricsServiceRequest' \
  "${otlp_receiver_paths[@]}"; then
  echo "architecture guard failed: OTLP receiver reintroduced a raw request queue" >&2
  fail=1
fi
if ! rg_matches --quiet \
  '\.max_decoding_message_size\(MAX_DECODING_MESSAGE_BYTES\)' \
  "$ROOT/crates/netdiag-core/src/connectors/otlp.rs"; then
  echo "architecture guard failed: OTLP tonic decoding limit is not explicitly configured" >&2
  fail=1
fi
if ! rg_matches --quiet \
  'parse_loopback_bind_addr\(&config\.bind_addr\)' \
  "$ROOT/crates/netdiag-core/src/connectors/otlp.rs"; then
  echo "architecture guard failed: OTLP startup no longer enforces the loopback boundary" >&2
  fail=1
fi

"$PYTHON_EXECUTABLE" -B "$ROOT/scripts/check_architecture_dependencies.py" "$ROOT" || fail=1

exit "$fail"
