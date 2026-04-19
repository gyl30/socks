#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/test_local_tproxy_udp.sh

Environment:
  BINARY                   Path to socks binary. Default: ./build/socks
  SERVER_CONFIG            Server config path. Default: config/local-server.json
  CLIENT_CONFIG            Client config path. Default: config/local-client.json
  REQUEST_COUNT            Requests per target. Default: 3
  UDP_TIMEOUT              Per-request UDP timeout seconds. Default: 5
  PROBE_RETRIES            Extra retries per request before marking failure. Default: 1
  DNS_NAME                 DNS name queried over UDP. Default: example.com
  TARGETS                  Space-separated host:port targets. Default: "8.8.8.8:53"
  TPROXY_UDP_PORT          Local client tproxy UDP port. Default: 23456
  TPROXY_UDP_PORTS         Destination UDP ports intercepted. Default: 53
  TPROXY_TABLE             Policy routing table for test traffic. Default: 233
  TPROXY_MARK_HEX          Mark used by TPROXY rules. Default: 0x233
  KEEP_LOGS                Keep /tmp logs after exit when set to 1. Default: 0

This script:
  1. Starts the local server
  2. Starts the local client directly
  3. Creates an isolated netns+veth pair
  4. Installs real mangle/TPROXY rules on the host-side veth
  5. Runs UDP DNS probes inside the namespace
  6. Prints a short summary and dumps logs on failure
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
request_count="${REQUEST_COUNT:-3}"
udp_timeout="${UDP_TIMEOUT:-5}"
probe_retries="${PROBE_RETRIES:-1}"
dns_name="${DNS_NAME:-example.com}"
targets_string="${TARGETS:-8.8.8.8:53}"
tproxy_udp_port="${TPROXY_UDP_PORT:-23456}"
tproxy_udp_ports="${TPROXY_UDP_PORTS:-53}"
tproxy_table="${TPROXY_TABLE:-233}"
tproxy_mark_hex="${TPROXY_MARK_HEX:-0x233}"
keep_logs="${KEEP_LOGS:-0}"
probe_script="$repo_root/scripts/udp_dns_probe.py"

for cmd in flock ip iptables mktemp pkill python3 ss tail; do
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

source "$repo_root/scripts/runtime_env.sh"
init_runtime_ld_library_path "$binary"

server_stdout_log="$(mktemp /tmp/socks-local-server.XXXXXX.log)"
client_stdout_log="$(mktemp /tmp/socks-local-client.XXXXXX.log)"
declare -a probe_err_logs=()
declare -a probe_out_logs=()
probe_runner=""
server_pid=""
client_pid=""
cleanup_done=0

ns_name="socks-tproxy-udp"
host_if="veth-tp-h"
ns_if="veth-tp-n"
host_ip="192.0.2.1"
ns_ip="192.0.2.2"
ns_cidr="${ns_ip}/24"
tproxy_chain="SOCKS_LOCAL_TPROXY_UDP_TEST"

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

wait_for_udp_listener() {
    local port="$1"
    local deadline=$((SECONDS + 15))
    while (( SECONDS < deadline )); do
        if ss -H -lun "sport = :$port" | grep -q .; then
            return 0
        fi
        if [[ -n "$client_pid" ]] && ! kill -0 "$client_pid" >/dev/null 2>&1; then
            wait "$client_pid"
            return 1
        fi
        sleep 0.2
    done
    echo "timeout waiting for UDP listener on :$port" >&2
    return 1
}

cleanup() {
    if (( cleanup_done )); then
        return
    fi
    cleanup_done=1

    iptables -t mangle -D PREROUTING -i "$host_if" -j "$tproxy_chain" >/dev/null 2>&1 || true
    iptables -t mangle -F "$tproxy_chain" >/dev/null 2>&1 || true
    iptables -t mangle -X "$tproxy_chain" >/dev/null 2>&1 || true
    ip rule del fwmark "$tproxy_mark_hex" lookup "$tproxy_table" >/dev/null 2>&1 || true
    ip route del local 0.0.0.0/0 dev lo table "$tproxy_table" >/dev/null 2>&1 || true
    ip link del "$host_if" >/dev/null 2>&1 || true
    ip netns del "$ns_name" >/dev/null 2>&1 || true

    stop_pid "$client_pid"
    stop_pid "$server_pid"

    pkill -INT -f "$binary -c $client_config" >/dev/null 2>&1 || true
    pkill -INT -f "$binary -c $server_config" >/dev/null 2>&1 || true
    sleep 1

    rm -f "${probe_runner:-}"
    if [[ "$keep_logs" != "1" ]]; then
        rm -f "$server_stdout_log" "$client_stdout_log" "${probe_err_logs[@]:-}" "${probe_out_logs[@]:-}"
    fi
}

trap cleanup EXIT

setup_namespace() {
    ip netns del "$ns_name" >/dev/null 2>&1 || true
    ip link del "$host_if" >/dev/null 2>&1 || true

    ip netns add "$ns_name"
    ip link add "$host_if" type veth peer name "$ns_if"
    ip link set "$ns_if" netns "$ns_name"

    ip addr add "${host_ip}/24" dev "$host_if"
    ip link set "$host_if" up

    ip netns exec "$ns_name" ip link set lo up
    ip netns exec "$ns_name" ip addr add "$ns_cidr" dev "$ns_if"
    ip netns exec "$ns_name" ip link set "$ns_if" up
    ip netns exec "$ns_name" ip route add default via "$host_ip" dev "$ns_if"
}

install_tproxy_rules() {
    local port
    local -a udp_ports=()
    IFS=',' read -r -a udp_ports <<<"$tproxy_udp_ports"

    iptables -t mangle -N "$tproxy_chain" >/dev/null 2>&1 || true
    iptables -t mangle -F "$tproxy_chain"
    for port in "${udp_ports[@]}"; do
        [[ -n "$port" ]] || continue
        iptables -t mangle -A "$tproxy_chain" -p udp --dport "$port" -j TPROXY --on-port "$tproxy_udp_port" --tproxy-mark "${tproxy_mark_hex}/${tproxy_mark_hex}"
    done
    iptables -t mangle -D PREROUTING -i "$host_if" -j "$tproxy_chain" >/dev/null 2>&1 || true
    iptables -t mangle -A PREROUTING -i "$host_if" -j "$tproxy_chain"

    ip rule del fwmark "$tproxy_mark_hex" lookup "$tproxy_table" >/dev/null 2>&1 || true
    ip route del local 0.0.0.0/0 dev lo table "$tproxy_table" >/dev/null 2>&1 || true
    ip rule add fwmark "$tproxy_mark_hex" lookup "$tproxy_table"
    ip route add local 0.0.0.0/0 dev lo table "$tproxy_table"
}

rm -f "$repo_root"/config/local-client.log "$repo_root"/config/local-server.log
probe_runner="$(mktemp /tmp/socks-udp-dns-probe.XXXXXX.py)"
cp "$probe_script" "$probe_runner"
chmod 755 "$probe_runner"

env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$server_config" >"$server_stdout_log" 2>&1 &
server_pid="$!"
sleep 1

env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$client_config" >"$client_stdout_log" 2>&1 &
client_pid="$!"
wait_for_udp_listener "$tproxy_udp_port"

setup_namespace
install_tproxy_rules

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

    out_log="$(mktemp /tmp/socks-tproxy-udp-out.XXXXXX.log)"
    err_log="$(mktemp /tmp/socks-tproxy-udp-err.XXXXXX.log)"
    probe_out_logs+=("$out_log")
    probe_err_logs+=("$err_log")

    echo "=== probe $attempt $host:$port $dns_name ==="
    local try_count=0
    local max_tries=$((probe_retries + 1))
    local succeeded=0
    while (( try_count < max_tries )); do
        try_count=$((try_count + 1))
        if ip netns exec "$ns_name" /usr/bin/python3 "$probe_runner" "$host" "$port" "$dns_name" "$udp_timeout" >"$out_log" 2>"$err_log"; then
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
    tail -n 120 "$server_stdout_log" || true
    echo
    echo "client stdout tail:"
    tail -n 120 "$client_stdout_log" || true
    exit 1
fi
