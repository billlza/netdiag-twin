#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOW_DIRTY=0

usage() {
  cat >&2 <<'EOF'
Usage: scripts/bump_version.sh [--allow-dirty] <semver>

Updates the workspace version and versioned documentation references. Run the
normal validation gates before tagging:

  cargo fmt --all -- --check
  cargo clippy --locked --workspace --all-targets -- -D warnings
  cargo test --locked --workspace
  RUSTFLAGS="-D warnings" cargo test --locked --workspace
  scripts/check_perf_budget.sh
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-dirty)
      ALLOW_DIRTY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

VERSION="$1"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
  echo "version must be SemVer without a leading v, got: $VERSION" >&2
  exit 2
fi

cd "$ROOT"

if [[ "$ALLOW_DIRTY" != "1" ]]; then
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    echo "working tree has uncommitted changes; rerun with --allow-dirty while preparing a release branch" >&2
    exit 2
  fi
fi

CURRENT="$(awk -F ' = ' '/^version =/ {gsub("\"", "", $2); print $2; exit}' Cargo.toml)"
if [[ -z "$CURRENT" ]]; then
  echo "could not read workspace version from Cargo.toml" >&2
  exit 2
fi

perl -0pi -e 's/(\[workspace\.package\][^\[]*?version = ")[^"]+(")/${1}'"$VERSION"'$2/s' Cargo.toml

for file in \
  README.md \
  docs/getting-started.md \
  docs/pilot-run-center.md \
  docs/real-device-pilot-readiness.md \
  docs/release-process.md \
  .github/workflows/release.yml; do
  [[ -f "$file" ]] || continue
  perl -pi -e 's/v\Q'"$CURRENT"'\E/v'"$VERSION"'/g; s/\Q'"$CURRENT"'\E/'"$VERSION"'/g' "$file"
done

cargo check --workspace --quiet
cargo metadata --locked --no-deps --format-version 1 >/dev/null

UPDATED="$(awk -F ' = ' '/^version =/ {gsub("\"", "", $2); print $2; exit}' Cargo.toml)"
if [[ "$UPDATED" != "$VERSION" ]]; then
  echo "version update failed: Cargo.toml is $UPDATED, expected $VERSION" >&2
  exit 2
fi

echo "updated NetDiag Twin from $CURRENT to $VERSION"
echo "next tag: v$VERSION"
