#!/usr/bin/env bash
# Checks the installed kmipclient CMake package:
# 1. installs the given build tree into a scratch prefix, then configures,
#    builds and runs a consumer of find_package(kmipclient);
# 2. checks that a project vendoring this repository with add_subdirectory()
#    installs nothing (KMIPCLIENT_INSTALL defaults to OFF there).
# Extra arguments are passed to every cmake configure call.
set -euo pipefail

build="${1:?usage: check-install.sh <build-dir> [config] [cmake configure args...]}"
config="${2:-Release}"
shift $(($# < 2 ? $# : 2))

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cmake --install "$build" --config "$config" --prefix "$work/prefix"

cmake -S "$root/ci/install-test/consumer" -B "$work/consumer" \
  -DCMAKE_BUILD_TYPE="$config" -DCMAKE_PREFIX_PATH="$work/prefix" "$@"
cmake --build "$work/consumer" --config "$config"
for exe in use_kmiputil use_kmipcore; do
  # Multi-config generators (Visual Studio) put binaries in a <config>/ subdirectory.
  bin=$(find "$work/consumer" -type f \( -name "$exe" -o -name "$exe.exe" \) | head -n 1)
  "$bin"
done

cmake -S "$root/ci/install-test/vendor" -B "$work/vendor" \
  -DKMIPCLIENT_SOURCE_DIR="$root" "$@"
cmake --install "$work/vendor" --config "$config" --prefix "$work/vendor-prefix"
if [ -d "$work/vendor-prefix" ] && [ -n "$(find "$work/vendor-prefix" -type f)" ]; then
  echo "::error::installing a project that vendors kmipclient installed files:"
  find "$work/vendor-prefix" -type f
  exit 1
fi
echo "install check passed"
