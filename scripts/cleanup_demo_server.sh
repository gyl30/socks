#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/cleanup_demo_server.sh

Environment:
  STATE_DIR      Runtime state dir. Default: .tmp-demo-stack
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
state_dir="${STATE_DIR:-$repo_root/.tmp-demo-stack}"
pid_file="$state_dir/server.pid"

if [[ ! -f "$pid_file" ]]; then
    echo "demo server pid file not found: $pid_file"
    exit 0
fi

server_pid="$(<"$pid_file")"
if [[ -n "$server_pid" ]] && kill -0 "$server_pid" >/dev/null 2>&1; then
    kill "$server_pid" >/dev/null 2>&1 || true
    deadline=$((SECONDS + 10))
    while (( SECONDS < deadline )); do
        if ! kill -0 "$server_pid" >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done
    if kill -0 "$server_pid" >/dev/null 2>&1; then
        kill -9 "$server_pid" >/dev/null 2>&1 || true
    fi
    wait "$server_pid" >/dev/null 2>&1 || true
fi

rm -f "$pid_file"
echo "demo server stopped"
