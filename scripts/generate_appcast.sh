#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPARKLE_VERSION="2.7.1"
SPARKLE_ARCHIVE="$ROOT/vendor/Sparkle/Sparkle-$SPARKLE_VERSION.tar.xz"
SPARKLE_WORK="$ROOT/target/sparkle-$SPARKLE_VERSION"
ARCHIVE_DIR="${1:-$ROOT/target/release}"

if [[ ! -x "$SPARKLE_WORK/bin/generate_appcast" ]]; then
  mkdir -p "$SPARKLE_WORK"
  tar -xf "$SPARKLE_ARCHIVE" -C "$SPARKLE_WORK"
fi

if [[ -z "${SPARKLE_PRIVATE_KEY:-}" ]]; then
  echo "appcast generation blocked: set SPARKLE_PRIVATE_KEY" >&2
  exit 2
fi

"$SPARKLE_WORK/bin/generate_appcast" "$ARCHIVE_DIR"
