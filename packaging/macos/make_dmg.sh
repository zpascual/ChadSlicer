#!/bin/bash
# Package a macOS build of ChadSlicer as ChadSlicer.app and a .dmg disk image.
#
# Usage: packaging/macos/make_dmg.sh <build_dir> <output_dir>
#   build_dir  CMake build directory containing src/PrusaSlicer and src/Info.plist
#   output_dir where ChadSlicer.app and ChadSlicer-<version>-macos-<arch>.dmg are written
#
# The app is signed ad hoc (no Apple developer certificate), macOS asks to confirm
# the first start: right click the app -> Open.
set -euo pipefail

BUILD_DIR=$(cd "$1" && pwd)
OUT_DIR=$2
SRC_DIR=$(cd "$(dirname "$0")/../.." && pwd)

VERSION=$(sed -n 's/^set(SLIC3R_VERSION "\(.*\)")/\1/p' "$SRC_DIR/version.inc")
ARCH=$(lipo -archs "$BUILD_DIR/src/PrusaSlicer" | tr ' ' '-')
APP="$OUT_DIR/ChadSlicer.app"
DMG="$OUT_DIR/ChadSlicer-$VERSION-macos-$ARCH.dmg"

mkdir -p "$OUT_DIR"
rm -rf "$APP" "$DMG"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# Binary, the G-code viewer is the same binary started under another name.
cp "$BUILD_DIR/src/PrusaSlicer" "$APP/Contents/MacOS/PrusaSlicer"
ln -s PrusaSlicer "$APP/Contents/MacOS/PrusaGCodeViewer"
cp "$BUILD_DIR/src/Info.plist" "$APP/Contents/Info.plist"

# Resources are looked up next to the binary in ../Resources, icons of the bundle in Resources.
rsync -a --exclude '.DS_Store' "$SRC_DIR/resources/" "$APP/Contents/Resources/"
cp "$SRC_DIR"/resources/icons/*.icns "$APP/Contents/Resources/"

codesign --force --deep --sign - \
    --entitlements "$SRC_DIR/src/platform/osx/entitlements.plist" "$APP"
codesign --verify --deep --strict "$APP"

# Disk image with the app and a link to /Applications for drag and drop installation.
STAGE=$(mktemp -d)
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "ChadSlicer $VERSION" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE"

echo "Created $APP"
echo "Created $DMG"
