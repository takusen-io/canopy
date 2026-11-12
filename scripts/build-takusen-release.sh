#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=${RELEASE_OUTPUT_DIR:-"$root/build/takusen-release"}
first=$(mktemp -d)
second=$(mktemp -d)
trap 'rm -rf "$first" "$second"' EXIT

"$root/scripts/verify-takusen-release-source.sh"

build_once() {
  local destination=$1
  mkdir -p "$destination"
  (
    cd "$root"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=true \
      -ldflags='-s -w' -o "$destination/canopy" ./cmd/main/...
  )
  (
    cd "$root/plugin/go"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
      -ldflags='-s -w' -o "$destination/takusen-canopy-plugin" .
  )
  (cd "$destination" && shasum -a 256 * | LC_ALL=C sort) >"$destination/SHA256SUMS"
}

build_once "$first"
build_once "$second"
diff -u "$first/SHA256SUMS" "$second/SHA256SUMS"

rm -rf "$output"
mkdir -p "$output"
cp "$first"/* "$output"/
commit=$(git -C "$root" rev-parse HEAD)
tree=$(git -C "$root" rev-parse HEAD^{tree})
toolchain=$(go version | sed 's/"/\\"/g')
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
{
  printf '{\n'
  printf '  "generatedAt": "%s",\n' "$generated_at"
  printf '  "goToolchain": "%s",\n' "$toolchain"
  printf '  "target": "linux/amd64",\n'
  printf '  "source": {"repository":"takusen-io/canopy","branch":"takusen-integration","commit":"%s","tree":"%s"},\n' "$commit" "$tree"
  printf '  "checksumsFile": "SHA256SUMS"\n'
  printf '}\n'
} >"$output/source-manifest.json"

echo "reproducible Native Chain release written to $output"
