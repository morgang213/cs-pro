#!/bin/bash

# CyberSec Terminal - macOS DMG Builder
# Creates a drag-and-drop installer image for CyberSec Terminal.app

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$PROJECT_DIR/dist"
MACOS_DIR="$DIST_DIR/macos"
APP_NAME="CyberSec Terminal"
APP_BUNDLE="$MACOS_DIR/${APP_NAME}.app"
APP_EXECUTABLE="CyberSecTerminal"
DMG_FILENAME="CyberSec-Terminal-macOS.dmg"
DMG_PATH="$DIST_DIR/$DMG_FILENAME"
DMG_ROOT="$MACOS_DIR/dmg-root"
VOLUME_NAME="CyberSec Terminal"

VERSION="2.0.0"
if [[ -f "$PROJECT_DIR/VERSION" ]]; then
    VERSION="$(tr -d '[:space:]' < "$PROJECT_DIR/VERSION")"
fi

CODESIGN_IDENTITY=""
NOTARIZE="false"
NOTARY_PROFILE=""
OPEN_DMG="false"

print_info() {
    echo "[INFO] $1"
}

print_success() {
    echo "[SUCCESS] $1"
}

print_warning() {
    echo "[WARNING] $1"
}

print_error() {
    echo "[ERROR] $1"
}

show_help() {
    cat <<'EOF'
CyberSec Terminal macOS DMG Builder

Usage:
  ./build_macos_dmg.sh [options]

Options:
  --codesign-identity "Developer ID Application: ..."
      Sign the app and DMG with the provided identity.

  --notarize --notary-profile <profile>
      Submit the DMG to Apple notarization using an existing
      notarytool keychain profile.

  --open
      Open the resulting DMG in Finder after build.

  --help
      Show this help message.

Examples:
  ./build_macos_dmg.sh
  ./build_macos_dmg.sh --codesign-identity "Developer ID Application: Example Co (TEAMID)"
  ./build_macos_dmg.sh --codesign-identity "Developer ID Application: Example Co (TEAMID)" --notarize --notary-profile "AC_PASSWORD_PROFILE"
EOF
}

require_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        print_error "Required command not found: $cmd"
        exit 1
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --codesign-identity)
                shift
                if [[ $# -eq 0 ]]; then
                    print_error "--codesign-identity requires a value"
                    exit 1
                fi
                CODESIGN_IDENTITY="$1"
                ;;
            --notarize)
                NOTARIZE="true"
                ;;
            --notary-profile)
                shift
                if [[ $# -eq 0 ]]; then
                    print_error "--notary-profile requires a value"
                    exit 1
                fi
                NOTARY_PROFILE="$1"
                ;;
            --open)
                OPEN_DMG="true"
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done

    if [[ "$NOTARIZE" == "true" && -z "$NOTARY_PROFILE" ]]; then
        print_error "--notarize requires --notary-profile"
        exit 1
    fi
}

write_info_plist() {
    cat > "$APP_BUNDLE/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>$APP_NAME</string>
    <key>CFBundleDisplayName</key>
    <string>$APP_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>com.cyberscanpro.cybersec-terminal</string>
    <key>CFBundleVersion</key>
    <string>$VERSION</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>CFBundleExecutable</key>
    <string>$APP_EXECUTABLE</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST
}

write_launcher() {
    cat > "$APP_BUNDLE/Contents/MacOS/$APP_EXECUTABLE" <<LAUNCHER
#!/bin/bash
PROJECT_DIR="$PROJECT_DIR"
VENV_PYTHON="\$PROJECT_DIR/venv/bin/python"

cd "\$PROJECT_DIR" || exit 1

if [ -x "\$VENV_PYTHON" ]; then
    exec "\$VENV_PYTHON" -m cybersec_terminal.web
fi

if command -v cybersec-web >/dev/null 2>&1; then
    exec cybersec-web
fi

exec /usr/bin/env python3 -m cybersec_terminal.web
LAUNCHER

    chmod +x "$APP_BUNDLE/Contents/MacOS/$APP_EXECUTABLE"
}

create_app_bundle() {
    print_info "Preparing app bundle..."
    mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"
    write_info_plist
    write_launcher
    print_success "App bundle prepared at $APP_BUNDLE"
}

codesign_if_configured() {
    if [[ -z "$CODESIGN_IDENTITY" ]]; then
        print_warning "Code signing skipped (no --codesign-identity provided)."
        return
    fi

    require_command codesign
    print_info "Code signing app with identity: $CODESIGN_IDENTITY"
    codesign --force --deep --options runtime --sign "$CODESIGN_IDENTITY" "$APP_BUNDLE"
    print_success "App code signing complete"
}

create_dmg() {
    print_info "Creating DMG..."
    mkdir -p "$DMG_ROOT"
    rm -rf "$DMG_ROOT/$APP_NAME.app"
    cp -R "$APP_BUNDLE" "$DMG_ROOT/"
    ln -snf /Applications "$DMG_ROOT/Applications"

    rm -f "$DMG_PATH"
    hdiutil create -volname "$VOLUME_NAME" -srcfolder "$DMG_ROOT" -ov -format UDZO "$DMG_PATH" >/dev/null

    if [[ -n "$CODESIGN_IDENTITY" ]]; then
        print_info "Code signing DMG..."
        codesign --force --sign "$CODESIGN_IDENTITY" "$DMG_PATH"
    fi

    print_success "DMG created at $DMG_PATH"
}

notarize_if_requested() {
    if [[ "$NOTARIZE" != "true" ]]; then
        print_warning "Notarization skipped (use --notarize --notary-profile <profile>)."
        return
    fi

    require_command xcrun
    print_info "Submitting DMG for notarization with profile: $NOTARY_PROFILE"
    xcrun notarytool submit "$DMG_PATH" --keychain-profile "$NOTARY_PROFILE" --wait

    print_info "Stapling notarization ticket to DMG..."
    xcrun stapler staple "$DMG_PATH"
    print_success "Notarization complete"
}

main() {
    parse_args "$@"

    require_command hdiutil
    mkdir -p "$DIST_DIR" "$MACOS_DIR"

    create_app_bundle
    codesign_if_configured
    create_dmg
    notarize_if_requested

    print_success "Done"
    print_info "Installer: $DMG_PATH"

    if [[ "$OPEN_DMG" == "true" ]]; then
        open "$DMG_PATH"
    fi
}

main "$@"
