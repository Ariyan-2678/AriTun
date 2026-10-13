#!/usr/bin/env bash
# Cross-compile AriTun client/server binaries.
#
#   ./build.sh              server (linux) + client (windows, linux)
#   ./build.sh all          every supported platform
#   ./build.sh linux/amd64  one target
set -euo pipefail
cd "$(dirname "$0")"

VERSION="$(cat VERSION 2>/dev/null || echo dev)"
LDFLAGS="-s -w -X main.version=${VERSION}"
ALL_TARGETS="linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64"
DEFAULT_TARGETS="linux/amd64 windows/amd64 linux/arm64"

out_for() {
  local bin=$1 goos=$2 goarch=$3
  if [ "$goos" = windows ]; then
    echo "dist/${bin}-windows-${goarch}.exe"
  else
    echo "dist/${bin}-${goos}-${goarch}"
  fi
}

build() {
  local bin=$1 target=$2
  local goos=${target%/*} goarch=${target#*/}
  local out
  out=$(out_for "$bin" "$goos" "$goarch")
  echo "→ $bin → $target ($out)"
  GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 \
    go build -trimpath -ldflags "$LDFLAGS" -o "$out" "./cmd/$bin"
}

if [ $# -gt 0 ] && [ "$1" != all ]; then
  TARGETS="$*"
elif [ "${1:-}" = all ]; then
  TARGETS="$ALL_TARGETS"
else
  TARGETS="$DEFAULT_TARGETS"
fi

mkdir -p dist
# Remove stale artifacts from the previous product name so dist/ only presents
# the AriTun binaries after a rename/build.
rm -f dist/tunnel dist/tunneld dist/tunnel-* dist/tunneld-* dist/tunnel.exe dist/tunneld.exe
for target in $TARGETS; do
  case "$target" in
    */*) build aritund "$target"; build aritun "$target" ;;
    *) echo "unknown target: $target" >&2; exit 1 ;;
  esac
done

echo
echo "done. artifacts in dist/"
ls -lh dist/
