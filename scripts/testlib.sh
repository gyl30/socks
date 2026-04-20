#!/usr/bin/env bash

require_commands() {
    local cmd
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "missing dependency: $cmd" >&2
            return 1
        fi
    done
}

create_test_tmp_dir() {
    local repo_root="$1"
    local pattern="$2"
    mktemp -d "$repo_root/$pattern"
}

cleanup_managed_pids() {
    local -n managed_pids_ref="$1"
    local force_kill="${2:-0}"
    local pid

    for pid in "${managed_pids_ref[@]:-}"; do
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
        fi
    done

    if [[ "$force_kill" == "1" ]]; then
        sleep 0.2
        for pid in "${managed_pids_ref[@]:-}"; do
            if kill -0 "$pid" >/dev/null 2>&1; then
                kill -9 "$pid" >/dev/null 2>&1 || true
            fi
        done
    fi

    for pid in "${managed_pids_ref[@]:-}"; do
        if [[ -n "$pid" ]]; then
            wait "$pid" >/dev/null 2>&1 || true
        fi
    done
}

print_test_logs() {
    local tmp_dir="$1"
    local tail_lines="$2"
    shift 2

    local pattern
    local log_file
    for pattern in "$@"; do
        for log_file in "$tmp_dir"/$pattern; do
            if [[ -f "$log_file" ]]; then
                echo "===== $(basename "$log_file") =====" >&2
                tail -n "$tail_lines" "$log_file" >&2 || true
            fi
        done
    done
}

wait_for_tcp_port() {
    local host="$1"
    local port="$2"
    local name="$3"
    local timeout_sec="${4:-10}"
    shift 4

    python3 - "$host" "$port" "$name" "$timeout_sec" "$@" <<'PY'
import os
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
name = sys.argv[3]
deadline = time.time() + float(sys.argv[4])
owner_pids = [int(arg) for arg in sys.argv[5:] if arg]
last_error = None

while time.time() < deadline:
    for pid in owner_pids:
        try:
            os.kill(pid, 0)
        except OSError:
            print(f"{name} owner process exited early", file=sys.stderr)
            sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        sock.connect((host, port))
        sys.exit(0)
    except OSError as exc:
        last_error = exc
        time.sleep(0.1)
    finally:
        sock.close()

print(f"timeout waiting for {name} {host}:{port} last_error={last_error}", file=sys.stderr)
sys.exit(1)
PY
}
