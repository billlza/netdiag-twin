#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${1:-debug}"
BUILD_MODE="${2:-build}"
APP_NAME="NetDiag Twin"
DMG_BASENAME="NetDiag-Twin"
BUNDLE_ID="com.netdiag.twin"
EXECUTABLE="netdiag-app"
ICON_SRC="$ROOT/crates/netdiag-app/assets/NetDiagTwin.icns"
VERSION="$(awk -F ' = ' '/^version =/ {gsub("\"", "", $2); print $2; exit}' "$ROOT/Cargo.toml")"
BUILD_NUMBER="${GITHUB_RUN_NUMBER:-$(date +%Y%m%d%H%M)}"
SPARKLE_VERSION="2.7.1"
SPARKLE_ARCHIVE="$ROOT/vendor/Sparkle/Sparkle-$SPARKLE_VERSION.tar.xz"
SPARKLE_SHA256="f7385c3e8c70c37e5928939e6246ac9070757b4b37a5cb558afa1b0d5ef189de"
SPARKLE_WORK="$ROOT/target/sparkle-$SPARKLE_VERSION"
SPARKLE_FRAMEWORK="$SPARKLE_WORK/Sparkle.framework"
SPARKLE_FEED_URL="${NETDIAG_SPARKLE_FEED_URL:-https://billlza.github.io/netdiag-twin/appcast.xml}"
SPARKLE_PUBLIC_KEY="${NETDIAG_SPARKLE_PUBLIC_KEY:-}"
SIGN_IDENTITY="${CODESIGN_IDENTITY:--}"
NOTARY_PROFILE="${NETDIAG_NOTARY_PROFILE:-${NOTARYTOOL_PROFILE:-}}"
NOTARY_KEYCHAIN="${NETDIAG_NOTARY_KEYCHAIN:-}"
NOTARIZE="${NETDIAG_NOTARIZE:-0}"

export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"

case "$BUILD_MODE" in
  build | --no-build) ;;
  *)
    echo "unsupported package build mode: $BUILD_MODE (expected build or --no-build)" >&2
    exit 2
    ;;
esac

if [[ "$PROFILE" != "debug" && "$PROFILE" != "release" ]]; then
  echo "unsupported package profile: $PROFILE (expected debug or release)" >&2
  exit 2
fi

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "package version is not a valid semantic version" >&2
  exit 2
fi
if [[ ! "$BUILD_NUMBER" =~ ^[0-9]+$ ]]; then
  echo "bundle build number must contain decimal digits only" >&2
  exit 2
fi
feed_url_bytes="$(printf '%s' "$SPARKLE_FEED_URL" | wc -c | tr -d '[:space:]')"
feed_url_pattern='^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~!$&()*+,;=:@%/-]*)?$'
if [[ "$feed_url_bytes" -gt 16384 || ! "$SPARKLE_FEED_URL" =~ $feed_url_pattern ]]; then
  echo "Sparkle feed URL must be a bounded HTTPS URL without query, fragment, user info, or whitespace" >&2
  exit 2
fi
feed_authority="${SPARKLE_FEED_URL#https://}"
feed_authority="${feed_authority%%/*}"
if [[ "$feed_authority" == *:* ]]; then
  feed_port="${feed_authority##*:}"
  if (( 10#$feed_port < 1 || 10#$feed_port > 65535 )); then
    echo "Sparkle feed URL port must be between 1 and 65535" >&2
    exit 2
  fi
fi

if [[ "$PROFILE" == "release" ]]; then
  if [[ -z "$SPARKLE_PUBLIC_KEY" || "$SPARKLE_PUBLIC_KEY" == PLACEHOLDER* ]]; then
    echo "release packaging blocked: set NETDIAG_SPARKLE_PUBLIC_KEY to the real Sparkle EdDSA public key" >&2
    exit 2
  fi
  if [[ ! "$SPARKLE_PUBLIC_KEY" =~ ^[A-Za-z0-9+/=_-]{32,}$ ]]; then
    echo "release packaging blocked: NETDIAG_SPARKLE_PUBLIC_KEY does not look like an EdDSA public key" >&2
    exit 2
  fi
fi

if [[ "$BUILD_MODE" == "--no-build" ]]; then
  if [[ "$PROFILE" == "release" ]]; then
    TARGET_DIR="$ROOT/target/release"
  else
    TARGET_DIR="$ROOT/target/debug"
  fi
  EXPECTED_BINARY_SHA256="${NETDIAG_EXPECTED_BINARY_SHA256:-}"
  if [[ ! "$EXPECTED_BINARY_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "no-build packaging requires NETDIAG_EXPECTED_BINARY_SHA256" >&2
    exit 2
  fi
  source_binary="$TARGET_DIR/$EXECUTABLE"
  if [[ ! -f "$source_binary" || -L "$source_binary" || ! -x "$source_binary" ]]; then
    echo "no-build packaging requires a regular, non-symlink executable: $source_binary" >&2
    exit 2
  fi
  actual_binary_sha256="$(shasum -a 256 "$source_binary" | awk '{print $1}')"
  if [[ "$actual_binary_sha256" != "$EXPECTED_BINARY_SHA256" ]]; then
    echo "release binary checksum mismatch before packaging" >&2
    exit 2
  fi
elif [[ "$PROFILE" == "release" ]]; then
  export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-D warnings"
  cargo build --locked --release -p netdiag-app
  TARGET_DIR="$ROOT/target/release"
else
  cargo build --locked -p netdiag-app
  TARGET_DIR="$ROOT/target/debug"
fi

APP_DIR="$TARGET_DIR/$APP_NAME.app"
CONTENTS="$APP_DIR/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
FRAMEWORKS="$CONTENTS/Frameworks"

rm -rf "$APP_DIR"
mkdir -p "$MACOS" "$RESOURCES" "$FRAMEWORKS"
cp "$TARGET_DIR/$EXECUTABLE" "$MACOS/$EXECUTABLE"
cp "$ICON_SRC" "$RESOURCES/NetDiagTwin.icns"
chmod +x "$MACOS/$EXECUTABLE"

if [[ "$BUILD_MODE" == "--no-build" ]]; then
  copied_binary_sha256="$(shasum -a 256 "$MACOS/$EXECUTABLE" | awk '{print $1}')"
  if [[ "$copied_binary_sha256" != "$EXPECTED_BINARY_SHA256" ]]; then
    echo "release binary checksum mismatch after copying into the app bundle" >&2
    exit 2
  fi
fi

prepare_sparkle() {
  if [[ ! -f "$SPARKLE_ARCHIVE" ]]; then
    echo "Sparkle archive missing: $SPARKLE_ARCHIVE" >&2
    echo "Download https://github.com/sparkle-project/Sparkle/releases/download/$SPARKLE_VERSION/Sparkle-$SPARKLE_VERSION.tar.xz" >&2
    exit 2
  fi
  local actual
  actual="$(shasum -a 256 "$SPARKLE_ARCHIVE" | awk '{print $1}')"
  if [[ "$actual" != "$SPARKLE_SHA256" ]]; then
    echo "Sparkle archive checksum mismatch" >&2
    exit 2
  fi
  rm -rf "$SPARKLE_WORK"
  mkdir -p "$SPARKLE_WORK"
  tar -xf "$SPARKLE_ARCHIVE" -C "$SPARKLE_WORK" --strip-components 0
  ditto "$SPARKLE_FRAMEWORK" "$FRAMEWORKS/Sparkle.framework"
}

sign_path() {
  local path="$1"
  if [[ "$SIGN_IDENTITY" == "-" ]]; then
    codesign --force --sign - "$path" >/dev/null
  else
    codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$path" >/dev/null
  fi
}

sign_dmg() {
  local path="$1"
  if [[ "$SIGN_IDENTITY" == "-" ]]; then
    codesign --force --sign - "$path" >/dev/null
  else
    codesign --force --timestamp --sign "$SIGN_IDENTITY" "$path" >/dev/null
  fi
}

verify_dmg() {
  local path="$1"
  local attempt
  sync
  for attempt in 1 2 3 4 5; do
    if hdiutil verify "$path" >/dev/null; then
      return 0
    fi
    if [[ "$attempt" == "5" ]]; then
      break
    fi
    sleep "$attempt"
  done
  hdiutil verify "$path"
}

prepare_sparkle

if [[ "$BUILD_MODE" == "--no-build" ]]; then
  final_source_sha256="$(shasum -a 256 "$TARGET_DIR/$EXECUTABLE" | awk '{print $1}')"
  if [[ "$final_source_sha256" != "$EXPECTED_BINARY_SHA256" ]]; then
    echo "release binary changed during package preparation" >&2
    exit 2
  fi
fi

INFO_PLIST="$CONTENTS/Info.plist"
cat > "$INFO_PLIST" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>NetDiag Twin</string>
  <key>CFBundleExecutable</key>
  <string>netdiag-app</string>
  <key>CFBundleIconFile</key>
  <string>NetDiagTwin</string>
  <key>CFBundleIdentifier</key>
  <string>com.netdiag.twin</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>NetDiag Twin</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.0.0</string>
  <key>CFBundleVersion</key>
  <string>0</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
  <key>NSSupportsAutomaticGraphicsSwitching</key>
  <true/>
  <key>SUEnableAutomaticChecks</key>
  <true/>
  <key>SUFeedURL</key>
  <string>https://invalid.example/appcast.xml</string>
  <key>SUPublicEDKey</key>
  <string>PLACEHOLDER</string>
  <key>SUScheduledCheckInterval</key>
  <integer>86400</integer>
</dict>
</plist>
PLIST

plutil -replace CFBundleShortVersionString -string "$VERSION" "$INFO_PLIST"
plutil -replace CFBundleVersion -string "$BUILD_NUMBER" "$INFO_PLIST"
plutil -replace CFBundleIdentifier -string "$BUNDLE_ID" "$INFO_PLIST"
plutil -replace SUFeedURL -string "$SPARKLE_FEED_URL" "$INFO_PLIST"
plutil -replace SUPublicEDKey -string "$SPARKLE_PUBLIC_KEY" "$INFO_PLIST"
plutil -lint "$INFO_PLIST" >/dev/null
if [[ "$(plutil -extract CFBundleShortVersionString raw -o - "$INFO_PLIST")" != "$VERSION" \
   || "$(plutil -extract CFBundleVersion raw -o - "$INFO_PLIST")" != "$BUILD_NUMBER" \
   || "$(plutil -extract CFBundleIdentifier raw -o - "$INFO_PLIST")" != "$BUNDLE_ID" \
   || "$(plutil -extract SUFeedURL raw -o - "$INFO_PLIST")" != "$SPARKLE_FEED_URL" \
   || "$(plutil -extract SUPublicEDKey raw -o - "$INFO_PLIST")" != "$SPARKLE_PUBLIC_KEY" ]]; then
  echo "Info.plist value round-trip verification failed" >&2
  exit 2
fi

if [[ "$BUILD_MODE" == "--no-build" ]]; then
  pre_sign_binary_sha256="$(shasum -a 256 "$MACOS/$EXECUTABLE" | awk '{print $1}')"
  if [[ "$pre_sign_binary_sha256" != "$EXPECTED_BINARY_SHA256" ]]; then
    echo "release binary checksum mismatch immediately before signing" >&2
    exit 2
  fi
fi

if command -v codesign >/dev/null 2>&1; then
  sign_path "$FRAMEWORKS/Sparkle.framework/Versions/B/Autoupdate"
  sign_path "$FRAMEWORKS/Sparkle.framework/Versions/B/XPCServices/Downloader.xpc"
  sign_path "$FRAMEWORKS/Sparkle.framework/Versions/B/XPCServices/Installer.xpc"
  sign_path "$FRAMEWORKS/Sparkle.framework/Versions/B/Updater.app"
  sign_path "$FRAMEWORKS/Sparkle.framework"
  sign_path "$APP_DIR"
fi

if [[ "$PROFILE" == "release" ]]; then
  DMG_PATH="$TARGET_DIR/$DMG_BASENAME-$VERSION.dmg"
  rm -f "$TARGET_DIR/$DMG_BASENAME-"*.dmg
  hdiutil create -volname "$APP_NAME" -srcfolder "$APP_DIR" -ov -format UDZO "$DMG_PATH" >/dev/null
  sign_dmg "$DMG_PATH"
  verify_dmg "$DMG_PATH"

  if [[ "$NOTARIZE" == "1" || -n "$NOTARY_PROFILE" ]]; then
    if [[ "$SIGN_IDENTITY" == "-" ]]; then
      echo "notarization blocked: set CODESIGN_IDENTITY to a Developer ID Application identity" >&2
      exit 2
    fi
    if [[ -z "$NOTARY_PROFILE" ]]; then
      echo "notarization blocked: set NETDIAG_NOTARY_PROFILE or NOTARYTOOL_PROFILE" >&2
      exit 2
    fi
    notary_args=(xcrun notarytool submit "$DMG_PATH" --keychain-profile "$NOTARY_PROFILE" --wait)
    if [[ -n "$NOTARY_KEYCHAIN" ]]; then
      notary_args+=(--keychain "$NOTARY_KEYCHAIN")
    fi
    "${notary_args[@]}"
    xcrun stapler staple "$DMG_PATH"
    xcrun stapler validate "$DMG_PATH"
  elif [[ "$SIGN_IDENTITY" == "-" ]]; then
    echo "notarization skipped: ad-hoc signed local DMG only; set CODESIGN_IDENTITY and NETDIAG_NOTARY_PROFILE to notarize" >&2
  else
    echo "notarization skipped: set NETDIAG_NOTARIZE=1 and NETDIAG_NOTARY_PROFILE to submit" >&2
  fi
  echo "$DMG_PATH"
else
  echo "$APP_DIR"
fi
