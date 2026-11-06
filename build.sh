#!/bin/bash
set -euo pipefail

# Stamp the version from a git tag (e.g. v1.2.0) when one exists; otherwise
# the default in src/main.go is used. Override with VERSION=... ./build.sh
VERSION="${VERSION:-$(git describe --tags --dirty 2>/dev/null || true)}"
LDFLAGS="-extldflags '-z relro -z now -s -w' -w -s"
[ -n "$VERSION" ] && LDFLAGS="$LDFLAGS -X main.version=${VERSION#v}"
BUILD_DIR="build"

GOOS_=("darwin" "windows" "linux" "linux" "linux" "freebsd")
GOARCH_=("arm64" "amd64" "arm64" "386" "amd64" "amd64")

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

for i in "${!GOOS_[@]}"; do
    EXT=""
    [ "${GOOS_[i]}" = "windows" ] && EXT=".exe"
    TARGET_FILE="${BUILD_DIR}/stringx-${GOOS_[i]}-${GOARCH_[i]}${EXT}"
    GOOS=${GOOS_[i]} GOARCH=${GOARCH_[i]} go build -trimpath -mod=readonly -ldflags="$LDFLAGS" -o "$TARGET_FILE" ./src
    sha256sum "$TARGET_FILE" >> "${BUILD_DIR}/checksums.txt"
done
