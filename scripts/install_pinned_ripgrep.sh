#!/usr/bin/env bash
set -euo pipefail

readonly RIPGREP_VERSION="15.2.0"

if (( $# != 1 )); then
  echo "usage: install_pinned_ripgrep.sh <absolute-install-root>" >&2
  exit 2
fi

ripgrep_root="$1"
if [[ -z "$ripgrep_root" || "$ripgrep_root" != /* || "$ripgrep_root" == *$'\n'* || "$ripgrep_root" == *$'\r'* ]]; then
  echo "ripgrep installation root must be an absolute single-line path" >&2
  exit 2
fi
if [[ -e "$ripgrep_root" || -L "$ripgrep_root" ]]; then
  echo "isolated ripgrep installation root already exists" >&2
  exit 2
fi

cargo install ripgrep --version "$RIPGREP_VERSION" --locked --quiet --root "$ripgrep_root"

ripgrep_bin_dir="$ripgrep_root/bin"
ripgrep_executable="$ripgrep_bin_dir/rg"
if [[ -z "$ripgrep_executable" || "$ripgrep_executable" != /* || -L "$ripgrep_executable" || ! -f "$ripgrep_executable" || ! -x "$ripgrep_executable" ]]; then
  echo "installed ripgrep is not an absolute regular executable" >&2
  exit 2
fi

installed_version_output="$("$ripgrep_executable" --version)"
if [[ "${installed_version_output%%$'\n'*}" != "ripgrep $RIPGREP_VERSION" ]]; then
  echo "installed ripgrep version does not match the pinned version" >&2
  exit 2
fi
