#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$repo_root/build-review/socks}"
extra_args=()
if [[ "${KEEP_TEST_ARTIFACTS:-0}" == "1" ]]; then
    extra_args+=("--keep-artifacts")
fi

exec python3 "$repo_root/scripts/socks5_resource_suite.py" --mode churn --binary "$binary" "${extra_args[@]}"
