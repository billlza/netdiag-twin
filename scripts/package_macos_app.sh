#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${1:-debug}"
APP_NAME="NetDiag Twin"
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
NOTARIZE="${NETDIAG_NOTARIZE:-0}"

export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"

if [[ "$PROFILE" == "release" ]]; then
  cargo build --release -p netdiag-app
  TARGET_DIR="$ROOT/target/release"
else
  cargo build -p netdiag-app
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
  if [[ ! -d "$SPARKLE_FRAMEWORK" ]]; then
    rm -rf "$SPARKLE_WORK"
    mkdir -p "$SPARKLE_WORK"
    tar -xf "$SPARKLE_ARCHIVE" -C "$SPARKLE_WORK" --strip-components 0
  fi
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

prepare_sparkle

cat > "$CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>$APP_NAME</string>
  <key>CFBundleExecutable</key>
  <string>$EXECUTABLE</string>
  <key>CFBundleIconFile</key>
  <string>NetDiagTwin</string>
  <key>CFBundleIdentifier</key>
  <string>$BUNDLE_ID</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>$APP_NAME</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$VERSION</string>
  <key>CFBundleVersion</key>
  <string>$BUILD_NUMBER</string>
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
  <string>$SPARKLE_FEED_URL</string>
  <key>SUPublicEDKey</key>
  <string>$SPARKLE_PUBLIC_KEY</string>
  <key>SUScheduledCheckInterval</key>
  <integer>86400</integer>
</dict>
</plist>
PLIST

if command -v codesign >/dev/null 2>&1; then
  sign_path "$FRAMEWORKS/Sparkle.framework/Versions/B/Autoupdate"
  sign_path "$FRAMEWORKS/Sparkle.framework/Versions/B/XPCServices/Downloader.xpc"
  sign_path "$FRAMEWORKS/Sparkle.framework/Versions/B/XPCServices/Installer.xpc"
  sign_path "$FRAMEWORKS/Sparkle.framework/Versions/B/Updater.app"
  sign_path "$FRAMEWORKS/Sparkle.framework"
  sign_path "$APP_DIR"
fi

if [[ "$PROFILE" == "release" ]]; then
  DMG_PATH="$TARGET_DIR/$APP_NAME-$VERSION.dmg"
  rm -f "$DMG_PATH"
  hdiutil create -volname "$APP_NAME" -srcfolder "$APP_DIR" -ov -format UDZO "$DMG_PATH" >/dev/null
  hdiutil verify "$DMG_PATH" >/dev/null

  if [[ "$NOTARIZE" == "1" || -n "$NOTARY_PROFILE" ]]; then
    if [[ "$SIGN_IDENTITY" == "-" ]]; then
      echo "notarization blocked: set CODESIGN_IDENTITY to a Developer ID Application identity" >&2
      exit 2
    fi
    if [[ -z "$NOTARY_PROFILE" ]]; then
      echo "notarization blocked: set NETDIAG_NOTARY_PROFILE or NOTARYTOOL_PROFILE" >&2
      exit 2
    fi
    xcrun notarytool submit "$DMG_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
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
