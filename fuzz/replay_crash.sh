#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${1:?usage: replay_crash.sh <target> <crash_file> [binary_args...]}"
crash_file="${2:?usage: replay_crash.sh <target> <crash_file> [binary_args...]}"
shift 2

binary="${FUZZ_BINARY:-$repo_root/build-fuzz-clang/${target}_fuzz}"
if [[ ! -x "$binary" ]]; then
    echo "binary not found: $binary" >&2
    exit 1
fi

if [[ ! -f "$crash_file" ]]; then
    echo "crash file not found: $crash_file" >&2
    exit 1
fi

exec "$binary" "$crash_file" "$@"
