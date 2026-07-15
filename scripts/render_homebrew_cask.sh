#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: scripts/render_homebrew_cask.sh <version> <dmg-sha256> <output>" >&2
}

if [[ $# -ne 3 ]]; then
  usage
  exit 2
fi

VERSION="$1"
DMG_SHA256="$2"
OUTPUT="$3"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
  echo "Homebrew cask version must be SemVer without a leading v" >&2
  exit 2
fi
if [[ ! "$DMG_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Homebrew cask DMG digest must be lowercase SHA-256" >&2
  exit 2
fi
if [[ -z "$OUTPUT" || "$OUTPUT" == "-" ]]; then
  echo "Homebrew cask output must be a file path" >&2
  exit 2
fi

output_directory="$(dirname -- "$OUTPUT")"
if [[ ! -d "$output_directory" || -L "$output_directory" ]]; then
  echo "Homebrew cask output directory must be a real directory" >&2
  exit 2
fi
if [[ -e "$OUTPUT" && ( ! -f "$OUTPUT" || -L "$OUTPUT" ) ]]; then
  echo "Homebrew cask output must be absent or a regular file" >&2
  exit 2
fi

umask 022
temporary="$(mktemp "$output_directory/.netdiag-twin.rb.XXXXXX")"
cleanup() {
  rm -f -- "$temporary"
}
trap cleanup EXIT

cat > "$temporary" <<RUBY
cask "netdiag-twin" do
  version "$VERSION"
  sha256 "$DMG_SHA256"

  url "https://github.com/billlza/netdiag-twin/releases/download/v#{version}/NetDiag-Twin-#{version}.dmg"
  name "NetDiag Twin"
  desc "Network diagnostics workstation"
  homepage "https://github.com/billlza/netdiag-twin"

  depends_on macos: ">= :ventura"

  app "NetDiag Twin.app"
end
RUBY

chmod 0644 "$temporary"
mv -f -- "$temporary" "$OUTPUT"
trap - EXIT
