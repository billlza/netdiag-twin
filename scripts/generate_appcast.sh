#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPARKLE_VERSION="2.7.1"
SPARKLE_ARCHIVE="$ROOT/vendor/Sparkle/Sparkle-$SPARKLE_VERSION.tar.xz"
SPARKLE_SHA256="f7385c3e8c70c37e5928939e6246ac9070757b4b37a5cb558afa1b0d5ef189de"
SPARKLE_WORK="$ROOT/target/sparkle-$SPARKLE_VERSION"
ARCHIVE_DIR="${1:-$ROOT/target/release}"

if [[ ! -x "$SPARKLE_WORK/bin/generate_appcast" ]]; then
  if [[ ! -f "$SPARKLE_ARCHIVE" ]]; then
    echo "Sparkle archive missing: $SPARKLE_ARCHIVE" >&2
    exit 2
  fi
  actual="$(shasum -a 256 "$SPARKLE_ARCHIVE" | awk '{print $1}')"
  if [[ "$actual" != "$SPARKLE_SHA256" ]]; then
    echo "Sparkle archive checksum mismatch" >&2
    exit 2
  fi
  mkdir -p "$SPARKLE_WORK"
  tar -xf "$SPARKLE_ARCHIVE" -C "$SPARKLE_WORK"
fi

if [[ -z "${SPARKLE_PRIVATE_KEY:-}" ]]; then
  echo "appcast generation blocked: set SPARKLE_PRIVATE_KEY" >&2
  exit 2
fi

rm -f "$ARCHIVE_DIR/appcast.xml"
"$SPARKLE_WORK/bin/generate_appcast" "$ARCHIVE_DIR"
