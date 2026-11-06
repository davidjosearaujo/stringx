#!/bin/bash

LDFLAGS="-extldflags '-z relro -z now -s -w' -w -s"
BUILD_DIR="build"

GOOS_=("darwin" "windows" "linux" "linux" "linux" "freebsd")
GOARCH_=("arm64" "amd64" "arm64" "386" "amd64" "amd64")

rm -rf build
mkdir -p build

for i in ${!GOOS_[@]};
do
    TARGET_FILE=${BUILD_DIR}/stringx-${GOOS_[i]}-${GOARCH_[i]}
    GOOS=${GOOS_[i]} GOARCH=${GOARCH_[i]} go build -trimpath -mod=readonly -ldflags="$LDFLAGS" -o $TARGET_FILE src/main.go
    sha256sum $TARGET_FILE >> build/checksums.txt
done