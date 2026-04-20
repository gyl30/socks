#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${BINARY:-$repo_root/build/udp_transparent_session_regression}"

if [[ ! -x "$binary" ]]; then
    echo "binary not found or not executable: $binary" >&2
    exit 1
fi

"$binary" route_blocked
