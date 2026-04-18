#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/test_local_tun_https.sh

Environment:
  BINARY                   Path to socks binary. Default: ./build/socks
  SERVER_CONFIG            Server config path. Default: config/local-server.json
  CLIENT_CONFIG            Client config path. Default: config/local-client.json
  TUN_TEST_USER            User routed into tun. Default: tunuser
  REQUEST_COUNT            Requests per target. Default: 3
  CURL_MAX_TIME            Per-request curl timeout seconds. Default: 20
  TARGETS                  Space-separated HTTPS URLs. Default: "https://example.com https://example.net"
  KEEP_LOGS                Keep /tmp logs after exit when set to 1. Default: 0

This script:
  1. Starts the local server
  2. Starts the local client wrapper with tun routing for TUN_TEST_USER
  3. Runs curl as TUN_TEST_USER against each HTTPS target
  4. Prints a short summary
  5. Dumps log tails on failure
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
binary="${BINARY:-$repo_root/build/socks}"
server_config="${SERVER_CONFIG:-$repo_root/config/local-server.json}"
client_config="${CLIENT_CONFIG:-$repo_root/config/local-client.json}"
tun_test_user="${TUN_TEST_USER:-tunuser}"
request_count="${REQUEST_COUNT:-3}"
curl_max_time="${CURL_MAX_TIME:-20}"
targets_string="${TARGETS:-https://example.com https://example.net}"
keep_logs="${KEEP_LOGS:-0}"

for cmd in curl id mktemp pkill su tail; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing dependency: $cmd" >&2
        exit 1
    fi
done

if [[ ! -x "$binary" ]]; then
    echo "binary not found or not executable: $binary" >&2
    exit 1
fi

if [[ ! -f "$server_config" || ! -f "$client_config" ]]; then
    echo "config file not found" >&2
    exit 1
fi

id "$tun_test_user" >/dev/null 2>&1 || {
    echo "user not found: $tun_test_user" >&2
    exit 1
}

server_stdout_log="$(mktemp /tmp/socks-local-server.XXXXXX.log)"
client_stdout_log="$(mktemp /tmp/socks-local-client.XXXXXX.log)"
wrapper_log_glob="$repo_root/.tmp-local-client-wrapper"

declare -a curl_err_logs=()
declare -a curl_out_logs=()

server_pid=""
client_wrapper_pid=""
cleanup_done=0

cleanup() {
    if (( cleanup_done )); then
        return
    fi
    cleanup_done=1

    if [[ -n "$client_wrapper_pid" ]]; then
        kill -INT "$client_wrapper_pid" >/dev/null 2>&1 || true
        wait "$client_wrapper_pid" >/dev/null 2>&1 || true
    fi

    if [[ -n "$server_pid" ]]; then
        kill -INT "$server_pid" >/dev/null 2>&1 || true
        wait "$server_pid" >/dev/null 2>&1 || true
    fi

    pkill -INT -f "$repo_root/scripts/run_local_client.sh $client_config" >/dev/null 2>&1 || true
    pkill -INT -f "$binary -c $client_config" >/dev/null 2>&1 || true
    pkill -INT -f "$binary -c $server_config" >/dev/null 2>&1 || true
    sleep 1

    if [[ "$keep_logs" != "1" ]]; then
        rm -f "$server_stdout_log" "$client_stdout_log" "${curl_err_logs[@]:-}" "${curl_out_logs[@]:-}"
    fi
}

trap cleanup EXIT

rm -f "$repo_root"/config/local-client.log "$repo_root"/config/local-server.log
rm -f "$repo_root"/.tmp-local-client-wrapper.*.log

"$binary" -c "$server_config" >"$server_stdout_log" 2>&1 &
server_pid="$!"
sleep 1

TUN_TEST_USER="$tun_test_user" KEEP_WRAPPER_LOG=1 /usr/bin/bash "$repo_root/scripts/run_local_client.sh" "$client_config" >"$client_stdout_log" 2>&1 &
client_wrapper_pid="$!"
sleep 4

read -r -a targets <<<"$targets_string"
total=0
passed=0
failed=0

run_single_request() {
    local target_url="$1"
    local attempt="$2"
    local out_log err_log

    out_log="$(mktemp /tmp/socks-tun-curl-out.XXXXXX.log)"
    err_log="$(mktemp /tmp/socks-tun-curl-err.XXXXXX.log)"
    curl_out_logs+=("$out_log")
    curl_err_logs+=("$err_log")

    echo "=== request $attempt $target_url ==="
    if su -s /bin/bash -c "/usr/bin/curl '$target_url' -v --max-time '$curl_max_time'" "$tun_test_user" >"$out_log" 2>"$err_log"; then
        passed=$((passed + 1))
        echo "PASS $target_url"
    else
        failed=$((failed + 1))
        echo "FAIL $target_url"
        tail -n 40 "$err_log" || true
    fi
    total=$((total + 1))
}

attempt=0
for target in "${targets[@]}"; do
    for _ in $(seq 1 "$request_count"); do
        attempt=$((attempt + 1))
        run_single_request "$target" "$attempt"
        sleep 1
    done
done

echo
echo "summary: passed=$passed failed=$failed total=$total"

if (( failed > 0 )); then
    echo
    echo "server stdout tail:"
    tail -n 80 "$server_stdout_log" || true
    echo
    echo "client wrapper stdout tail:"
    tail -n 80 "$client_stdout_log" || true
    latest_wrapper_log="$(find "$repo_root" -maxdepth 1 -type f -name '.tmp-local-client-wrapper.*.log' | sort | tail -n 1)"
    if [[ -n "$latest_wrapper_log" ]]; then
        echo
        echo "client runtime tail:"
        tail -n 120 "$latest_wrapper_log" || true
    fi
    exit 1
fi
