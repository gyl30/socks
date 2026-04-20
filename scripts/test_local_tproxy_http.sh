#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/test_local_tproxy_http.sh

Environment:
  BINARY                   Path to socks binary. Default: ./build/socks
  SERVER_CONFIG            Server config path. Default: config/local-server.json
  CLIENT_CONFIG            Client config path. Default: config/local-client.json
  TEST_ID                  Optional test identifier forwarded to child scripts and log prefixes. Default: empty
  TPROXY_TEST_USER         User redirected into tproxy. Default: tpuser
  REQUEST_COUNT            Requests per target. Default: 3
  CURL_MAX_TIME            Per-request curl timeout seconds. Default: 20
  TARGETS                  Space-separated HTTP URLs. Default: "http://example.com http://example.net"
  TPROXY_TCP_PORTS         Destination TCP ports redirected into tproxy. Default: 80
  DRY_RUN                  Print planned commands and exit without changing system state. Default: 0
  KEEP_LOGS                Keep /tmp logs after exit when set to 1. Default: 0

This script:
  1. Starts the local server
  2. Starts the local client wrapper with user-based tproxy steering
  3. Runs curl as TPROXY_TEST_USER against each HTTP target
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
test_id="${TEST_ID:-}"
tproxy_test_user="${TPROXY_TEST_USER:-tpuser}"
request_count="${REQUEST_COUNT:-3}"
curl_max_time="${CURL_MAX_TIME:-20}"
targets_string="${TARGETS:-http://example.com http://example.net}"
tproxy_tcp_ports="${TPROXY_TCP_PORTS:-80}"
dry_run="${DRY_RUN:-0}"
keep_logs="${KEEP_LOGS:-0}"

for cmd in curl flock id mktemp su tail tr; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing dependency: $cmd" >&2
        exit 1
    fi
done

lock_file="/tmp/socks-local-stack.lock"
exec 9>"$lock_file"
if ! flock -n 9; then
    echo "another local stack test is already running: $lock_file" >&2
    exit 1
fi

if [[ ! -x "$binary" ]]; then
    echo "binary not found or not executable: $binary" >&2
    exit 1
fi

if [[ ! -f "$server_config" || ! -f "$client_config" ]]; then
    echo "config file not found" >&2
    exit 1
fi

id "$tproxy_test_user" >/dev/null 2>&1 || {
    echo "user not found: $tproxy_test_user" >&2
    exit 1
}

sanitize_test_id() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9'
}

test_id_slug=""
wrapper_log_pattern=".tmp-local-client-wrapper.*.log"
if [[ -n "$test_id" ]]; then
    test_id_slug="$(sanitize_test_id "$test_id")"
    if [[ -z "$test_id_slug" ]]; then
        echo "TEST_ID must contain at least one alphanumeric character" >&2
        exit 1
    fi
    wrapper_log_pattern=".tmp-local-client-wrapper.${test_id_slug}.*.log"
fi

server_stdout_log="$(mktemp /tmp/socks-local-server.XXXXXX.log)"
client_stdout_log="$(mktemp /tmp/socks-local-client.XXXXXX.log)"

declare -a curl_err_logs=()
declare -a curl_out_logs=()

server_pid=""
client_wrapper_pid=""
cleanup_done=0

stop_pid() {
    local pid="$1"
    local label="$2"
    local signal="${3:-INT}"
    local deadline=$((SECONDS + 5))

    [[ -n "$pid" ]] || return 0
    kill "-$signal" "$pid" >/dev/null 2>&1 || true
    while (( SECONDS < deadline )); do
        if ! kill -0 "$pid" >/dev/null 2>&1; then
            wait "$pid" >/dev/null 2>&1 || true
            return 0
        fi
        sleep 0.2
    done

    kill -TERM "$pid" >/dev/null 2>&1 || true
    sleep 1
    if kill -0 "$pid" >/dev/null 2>&1; then
        kill -KILL "$pid" >/dev/null 2>&1 || true
    fi
    wait "$pid" >/dev/null 2>&1 || true
}

print_cmd() {
    printf '  '
    printf '%q ' "$@"
    printf '\n'
}

cleanup() {
    if (( cleanup_done )); then
        return
    fi
    cleanup_done=1

    stop_pid "$client_wrapper_pid" "client_wrapper"
    stop_pid "$server_pid" "server"

    if [[ "$keep_logs" != "1" ]]; then
        rm -f "$server_stdout_log" "$client_stdout_log" "${curl_err_logs[@]:-}" "${curl_out_logs[@]:-}"
    fi
}

trap cleanup EXIT INT TERM

if [[ "$dry_run" == "1" ]]; then
    read -r -a targets <<<"$targets_string"
    echo "dry-run: no commands will be executed"
    echo "server command:"
    print_cmd "$binary" -c "$server_config"
    echo "client wrapper command:"
    if [[ -n "$test_id" ]]; then
        print_cmd env TEST_ID="$test_id" TPROXY_TEST_USER="$tproxy_test_user" TPROXY_TCP_PORTS="$tproxy_tcp_ports" DRY_RUN=1 KEEP_WRAPPER_LOG=1 \
            /usr/bin/bash "$repo_root/scripts/run_local_client.sh" "$client_config"
    else
        print_cmd env TPROXY_TEST_USER="$tproxy_test_user" TPROXY_TCP_PORTS="$tproxy_tcp_ports" DRY_RUN=1 KEEP_WRAPPER_LOG=1 \
            /usr/bin/bash "$repo_root/scripts/run_local_client.sh" "$client_config"
    fi
    echo "request commands:"
    for target in "${targets[@]}"; do
        print_cmd su -s /bin/bash -c "/usr/bin/curl '$target' -v --max-time '$curl_max_time'" "$tproxy_test_user"
    done
    exit 0
fi

rm -f "$repo_root"/config/local-client.log "$repo_root"/config/local-server.log
rm -f "$repo_root"/$wrapper_log_pattern
if [[ -n "$test_id_slug" ]]; then
    server_stdout_log="$(mktemp "/tmp/socks-local-server.${test_id_slug}.XXXXXX.log")"
    client_stdout_log="$(mktemp "/tmp/socks-local-client.${test_id_slug}.XXXXXX.log")"
    echo "test id: $test_id resource_suffix:$test_id_slug"
fi

"$binary" -c "$server_config" >"$server_stdout_log" 2>&1 &
server_pid="$!"
sleep 1

if [[ -n "$test_id" ]]; then
    TEST_ID="$test_id" \
    TPROXY_TEST_USER="$tproxy_test_user" \
    TPROXY_TCP_PORTS="$tproxy_tcp_ports" \
    KEEP_WRAPPER_LOG=1 \
    /usr/bin/bash "$repo_root/scripts/run_local_client.sh" "$client_config" >"$client_stdout_log" 2>&1 &
else
    TPROXY_TEST_USER="$tproxy_test_user" \
    TPROXY_TCP_PORTS="$tproxy_tcp_ports" \
    KEEP_WRAPPER_LOG=1 \
    /usr/bin/bash "$repo_root/scripts/run_local_client.sh" "$client_config" >"$client_stdout_log" 2>&1 &
fi
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

    if [[ -n "$test_id_slug" ]]; then
        out_log="$(mktemp "/tmp/socks-tproxy-curl-out.${test_id_slug}.XXXXXX.log")"
        err_log="$(mktemp "/tmp/socks-tproxy-curl-err.${test_id_slug}.XXXXXX.log")"
    else
        out_log="$(mktemp /tmp/socks-tproxy-curl-out.XXXXXX.log)"
        err_log="$(mktemp /tmp/socks-tproxy-curl-err.XXXXXX.log)"
    fi
    curl_out_logs+=("$out_log")
    curl_err_logs+=("$err_log")

    echo "=== request $attempt $target_url ==="
    if su -s /bin/bash -c "/usr/bin/curl '$target_url' -v --max-time '$curl_max_time'" "$tproxy_test_user" >"$out_log" 2>"$err_log"; then
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
    latest_wrapper_log="$(find "$repo_root" -maxdepth 1 -type f -name "$wrapper_log_pattern" | sort | tail -n 1)"
    if [[ -n "$latest_wrapper_log" ]]; then
        echo
        echo "client runtime tail:"
        tail -n 120 "$latest_wrapper_log" || true
    fi
    exit 1
fi
