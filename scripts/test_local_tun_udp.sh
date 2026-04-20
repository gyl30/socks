#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/test_local_tun_udp.sh

Environment:
  BINARY                   Path to socks binary. Default: ./build/socks
  SERVER_CONFIG            Server config path. Default: config/local-server.json
  CLIENT_CONFIG            Client config path. Default: config/local-client.json
  TEST_ID                  Optional test identifier forwarded to child scripts and log prefixes. Default: empty
  TUN_TEST_USER            User routed into tun. Default: tunuser
  REQUEST_COUNT            Requests per target. Default: 3
  UDP_TIMEOUT              Per-request UDP timeout seconds. Default: 5
  PROBE_RETRIES            Extra retries per request before marking failure. Default: 1
  DNS_NAME                 DNS name queried over UDP. Default: example.com
  TARGETS                  Space-separated host:port targets. Default: "1.1.1.1:53 8.8.8.8:53"
  DRY_RUN                  Print planned commands and exit without changing system state. Default: 0
  KEEP_LOGS                Keep /tmp logs after exit when set to 1. Default: 0
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
tun_test_user="${TUN_TEST_USER:-tunuser}"
request_count="${REQUEST_COUNT:-3}"
udp_timeout="${UDP_TIMEOUT:-5}"
probe_retries="${PROBE_RETRIES:-1}"
dns_name="${DNS_NAME:-example.com}"
targets_string="${TARGETS:-8.8.8.8:53}"
dry_run="${DRY_RUN:-0}"
keep_logs="${KEEP_LOGS:-0}"
probe_script="$repo_root/scripts/udp_dns_probe.py"
probe_runner=""

for cmd in flock id mktemp su tail python3 tr; do
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

if [[ ! -x "$binary" || ! -f "$server_config" || ! -f "$client_config" || ! -f "$probe_script" ]]; then
    echo "required file missing" >&2
    exit 1
fi

id "$tun_test_user" >/dev/null 2>&1 || {
    echo "user not found: $tun_test_user" >&2
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
declare -a probe_err_logs=()
declare -a probe_out_logs=()
server_pid=""
client_wrapper_pid=""
cleanup_done=0

stop_pid() {
    local pid="$1"
    local signal="${2:-INT}"
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
    stop_pid "$client_wrapper_pid"
    stop_pid "$server_pid"
    if [[ "$keep_logs" != "1" ]]; then
        rm -f "$server_stdout_log" "$client_stdout_log" "${probe_err_logs[@]:-}" "${probe_out_logs[@]:-}"
    fi
    rm -f "${probe_runner:-}"
}

trap cleanup EXIT INT TERM

if [[ "$dry_run" == "1" ]]; then
    read -r -a targets <<<"$targets_string"
    echo "dry-run: no commands will be executed"
    echo "server command:"
    print_cmd "$binary" -c "$server_config"
    echo "client wrapper command:"
    if [[ -n "$test_id" ]]; then
        print_cmd env TEST_ID="$test_id" TUN_TEST_USER="$tun_test_user" DRY_RUN=1 KEEP_WRAPPER_LOG=1 \
            /usr/bin/bash "$repo_root/scripts/run_local_client.sh" "$client_config"
    else
        print_cmd env TUN_TEST_USER="$tun_test_user" DRY_RUN=1 KEEP_WRAPPER_LOG=1 /usr/bin/bash "$repo_root/scripts/run_local_client.sh" \
            "$client_config"
    fi
    echo "probe commands:"
    for target in "${targets[@]}"; do
        host="${target%%:*}"
        port="${target##*:}"
        print_cmd su -s /bin/bash -c "/usr/bin/python3 '$probe_script' '$host' '$port' '$dns_name' '$udp_timeout'" "$tun_test_user"
    done
    exit 0
fi

rm -f "$repo_root"/config/local-client.log "$repo_root"/config/local-server.log
rm -f "$repo_root"/$wrapper_log_pattern
if [[ -n "$test_id_slug" ]]; then
    server_stdout_log="$(mktemp "/tmp/socks-local-server.${test_id_slug}.XXXXXX.log")"
    client_stdout_log="$(mktemp "/tmp/socks-local-client.${test_id_slug}.XXXXXX.log")"
    probe_runner="$(mktemp "/tmp/socks-udp-dns-probe.${test_id_slug}.XXXXXX.py")"
    echo "test id: $test_id resource_suffix:$test_id_slug"
else
    probe_runner="$(mktemp /tmp/socks-udp-dns-probe.XXXXXX.py)"
fi
cp "$probe_script" "$probe_runner"
chmod 755 "$probe_runner"

"$binary" -c "$server_config" >"$server_stdout_log" 2>&1 &
server_pid="$!"
sleep 1

if [[ -n "$test_id" ]]; then
    TEST_ID="$test_id" TUN_TEST_USER="$tun_test_user" KEEP_WRAPPER_LOG=1 /usr/bin/bash "$repo_root/scripts/run_local_client.sh" "$client_config" \
        >"$client_stdout_log" 2>&1 &
else
    TUN_TEST_USER="$tun_test_user" KEEP_WRAPPER_LOG=1 /usr/bin/bash "$repo_root/scripts/run_local_client.sh" "$client_config" >"$client_stdout_log" \
        2>&1 &
fi
client_wrapper_pid="$!"
sleep 4

read -r -a targets <<<"$targets_string"
total=0
passed=0
failed=0

run_single_probe() {
    local target="$1"
    local attempt="$2"
    local host="${target%%:*}"
    local port="${target##*:}"
    local out_log err_log

    if [[ -n "$test_id_slug" ]]; then
        out_log="$(mktemp "/tmp/socks-tun-udp-out.${test_id_slug}.XXXXXX.log")"
        err_log="$(mktemp "/tmp/socks-tun-udp-err.${test_id_slug}.XXXXXX.log")"
    else
        out_log="$(mktemp /tmp/socks-tun-udp-out.XXXXXX.log)"
        err_log="$(mktemp /tmp/socks-tun-udp-err.XXXXXX.log)"
    fi
    probe_out_logs+=("$out_log")
    probe_err_logs+=("$err_log")

    echo "=== probe $attempt $host:$port $dns_name ==="
    local try_count=0
    local max_tries=$((probe_retries + 1))
    local succeeded=0
    while (( try_count < max_tries )); do
        try_count=$((try_count + 1))
        if su -s /bin/bash -c "/usr/bin/python3 '$probe_runner' '$host' '$port' '$dns_name' '$udp_timeout'" "$tun_test_user" >"$out_log" 2>"$err_log"; then
            succeeded=1
            break
        fi
        if (( try_count < max_tries )); then
            echo "retry $try_count/$probe_retries for $host:$port"
            sleep 1
        fi
    done
    if (( succeeded )); then
        passed=$((passed + 1))
        echo "PASS $host:$port"
    else
        failed=$((failed + 1))
        echo "FAIL $host:$port"
        tail -n 40 "$err_log" || true
    fi
    total=$((total + 1))
}

attempt=0
for target in "${targets[@]}"; do
    for _ in $(seq 1 "$request_count"); do
        attempt=$((attempt + 1))
        run_single_probe "$target" "$attempt"
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
