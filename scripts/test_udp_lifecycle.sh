#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
udp_binary="${UDP_BINARY:-$repo_root/build/udp_transparent_session_regression}"
socks_binary="${SOCKS_BINARY:-$repo_root/build/socks}"

if [[ ! -x "$udp_binary" ]]; then
    echo "udp regression binary not found or not executable: $udp_binary" >&2
    exit 1
fi

if [[ ! -x "$socks_binary" ]]; then
    echo "socks binary not found or not executable: $socks_binary" >&2
    exit 1
fi

for scenario in closed_no_io stopped transport_error multi_outbound; do
    "$udp_binary" "$scenario"
done

python3 "$repo_root/scripts/test_reality_integration.py" --binary "$socks_binary"
