#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/run_local_client.sh [config_path]

Environment:
  BINARY                   Path to socks binary. Default: ./build/socks
  TUN_NAME                 TUN device name. Default: socks-test
  TUN_TEST_USER            Linux user whose traffic should go through TUN. Default: empty
  TUN_ROUTES               Comma-separated CIDRs routed into TUN for TUN_TEST_USER. Default: 0.0.0.0/1,128.0.0.0/1
  TUN_IPV6_ROUTES          Comma-separated IPv6 CIDRs routed into TUN. Default: empty
  TUN_TABLE                Policy routing table for TUN traffic. Default: 101
  TUN_PRIORITY             Priority for the TUN uidrange rule. Default: 90
  TPROXY_TEST_USER         Linux user whose traffic should be redirected to local tproxy inbound. Default: empty
  TPROXY_TCP_PORT          Local tproxy TCP port. Default: 23456
  TPROXY_UDP_PORT          Local tproxy UDP port. Default: 23456
  TPROXY_TCP_PORTS         Optional comma-separated destination TCP ports to redirect. Default: all
  TPROXY_UDP_PORTS         Optional comma-separated destination UDP ports to redirect. Default: all
  TPROXY_EXCLUDE_CIDRS     Extra comma-separated CIDRs bypassed from local tproxy redirection. Default: empty
  KEEP_WRAPPER_LOG         Set to 1 to keep the wrapper log file after exit. Default: 0

Examples:
  sudo TUN_TEST_USER=socks-test scripts/run_local_client.sh
  sudo TPROXY_TEST_USER=socks-test TPROXY_TCP_PORTS=80,443 TPROXY_UDP_PORTS=53 scripts/run_local_client.sh
  sudo TUN_TEST_USER=tunuser TPROXY_TEST_USER=tpuser scripts/run_local_client.sh
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
config_path="${1:-$repo_root/config/local-client.json}"
binary="${BINARY:-$repo_root/build/socks}"

for cmd in awk getent id ip iptables python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing dependency: $cmd" >&2
        exit 1
    fi
done

if [[ ! -x "$binary" ]]; then
    echo "binary not found or not executable: $binary" >&2
    exit 1
fi

if [[ ! -f "$config_path" ]]; then
    echo "config file not found: $config_path" >&2
    exit 1
fi

source "$repo_root/scripts/runtime_env.sh"
init_runtime_ld_library_path "$binary"

TUN_NAME="${TUN_NAME:-socks-test}"
TUN_TEST_USER="${TUN_TEST_USER:-}"
TUN_ROUTES="${TUN_ROUTES:-0.0.0.0/1,128.0.0.0/1}"
TUN_IPV6_ROUTES="${TUN_IPV6_ROUTES:-}"
TUN_TABLE="${TUN_TABLE:-101}"
TUN_PRIORITY="${TUN_PRIORITY:-90}"

TPROXY_TEST_USER="${TPROXY_TEST_USER:-}"
TPROXY_TCP_PORT="${TPROXY_TCP_PORT:-23456}"
TPROXY_UDP_PORT="${TPROXY_UDP_PORT:-23456}"
TPROXY_TCP_PORTS="${TPROXY_TCP_PORTS:-}"
TPROXY_UDP_PORTS="${TPROXY_UDP_PORTS:-}"
TPROXY_EXCLUDE_CIDRS="${TPROXY_EXCLUDE_CIDRS:-}"
TPROXY_NAT_CHAIN="SOCKS_LOCAL_TPROXY_NAT"
KEEP_WRAPPER_LOG="${KEEP_WRAPPER_LOG:-0}"

if [[ -z "$TUN_TEST_USER" && -z "$TPROXY_TEST_USER" ]]; then
    echo "set at least one of TUN_TEST_USER or TPROXY_TEST_USER" >&2
    exit 1
fi

wrapper_log="$(mktemp "$repo_root/.tmp-local-client-wrapper.XXXXXX.log")"
client_pid=""
cleanup_done=0
tun_uid=""
tproxy_uid=""
declare -a bypass_hosts=()
declare -a bypass_route_ips=()

split_csv() {
    local input="$1"
    local -n out_ref="$2"
    out_ref=()
    if [[ -z "$input" ]]; then
        return 0
    fi
    IFS=',' read -r -a out_ref <<<"$input"
}

resolve_uid() {
    local user_name="$1"
    id -u "$user_name"
}

run_client() {
    env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$config_path" >>"$wrapper_log" 2>&1 &
    client_pid="$!"
}

wait_for_tun_device() {
    local deadline=$((SECONDS + 15))
    while (( SECONDS < deadline )); do
        if ip link show dev "$TUN_NAME" >/dev/null 2>&1; then
            return 0
        fi
        if [[ -n "$client_pid" ]] && ! kill -0 "$client_pid" >/dev/null 2>&1; then
            wait "$client_pid"
            return 1
        fi
        sleep 0.2
    done
    echo "timeout waiting for tun device $TUN_NAME" >&2
    return 1
}

wait_for_tcp_listener() {
    local host="$1"
    local port="$2"
    local name="$3"
    HOST="$host" PORT="$port" NAME="$name" python3 - <<'PY'
import os
import socket
import sys
import time

host = os.environ["HOST"]
port = int(os.environ["PORT"])
name = os.environ["NAME"]
deadline = time.time() + 15.0
while time.time() < deadline:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        sock.connect((host, port))
        sys.exit(0)
    except OSError:
        time.sleep(0.1)
    finally:
        sock.close()
print(f"timeout waiting for {name} {host}:{port}", file=sys.stderr)
sys.exit(1)
PY
}

load_outbound_hosts() {
    local host
    while IFS= read -r host; do
        [[ -n "$host" ]] || continue
        bypass_hosts+=("$host")
    done < <(
        python3 - "$config_path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    cfg = json.load(fh)

for outbound in cfg.get("outbounds", []):
    settings = outbound.get("settings") or {}
    host = settings.get("host")
    if isinstance(host, str) and host:
        print(host)
PY
    )
}

install_bypass_route() {
    local host="$1"
    local ip_addr route_line route_via route_dev

    if [[ "$host" =~ : ]]; then
        return 0
    fi

    ip_addr="$(getent ahostsv4 "$host" | awk 'NR==1 {print $1}')"
    if [[ -z "$ip_addr" ]]; then
        return 0
    fi

    case "$ip_addr" in
        127.*|0.*)
            return 0
            ;;
    esac

    route_line="$(ip route get "$ip_addr" | head -n 1)"
    route_dev="$(awk '{for (i = 1; i <= NF; ++i) if ($i == "dev") {print $(i + 1); exit}}' <<<"$route_line")"
    route_via="$(awk '{for (i = 1; i <= NF; ++i) if ($i == "via") {print $(i + 1); exit}}' <<<"$route_line")"

    if [[ -z "$route_dev" ]]; then
        return 0
    fi

    if [[ -n "$route_via" ]]; then
        ip route replace "${ip_addr}/32" via "$route_via" dev "$route_dev"
    else
        ip route replace "${ip_addr}/32" dev "$route_dev"
    fi
    bypass_route_ips+=("$ip_addr")
}

remove_bypass_routes() {
    local ip_addr
    for ip_addr in "${bypass_route_ips[@]:-}"; do
        ip route del "${ip_addr}/32" >/dev/null 2>&1 || true
    done
}

install_tun_rules() {
    local -a tun_routes tun_ipv6_routes
    split_csv "$TUN_ROUTES" tun_routes
    split_csv "$TUN_IPV6_ROUTES" tun_ipv6_routes

    if [[ -z "$tun_uid" ]]; then
        return 0
    fi
    if (( ${#tun_routes[@]} == 0 && ${#tun_ipv6_routes[@]} == 0 )); then
        return 0
    fi

    /usr/bin/bash "$repo_root/scripts/tun_linux_route.sh" --table "$TUN_TABLE" up "$TUN_NAME" "${tun_routes[@]}" "${tun_ipv6_routes[@]}"
    ip rule del pref "$TUN_PRIORITY" uidrange "${tun_uid}-${tun_uid}" lookup "$TUN_TABLE" >/dev/null 2>&1 || true
    ip rule add pref "$TUN_PRIORITY" uidrange "${tun_uid}-${tun_uid}" lookup "$TUN_TABLE"
}

remove_tun_rules() {
    local -a tun_routes tun_ipv6_routes
    split_csv "$TUN_ROUTES" tun_routes
    split_csv "$TUN_IPV6_ROUTES" tun_ipv6_routes

    if [[ -z "$tun_uid" ]]; then
        return 0
    fi

    ip rule del pref "$TUN_PRIORITY" uidrange "${tun_uid}-${tun_uid}" lookup "$TUN_TABLE" >/dev/null 2>&1 || true
    if (( ${#tun_routes[@]} == 0 && ${#tun_ipv6_routes[@]} == 0 )); then
        return 0
    fi
    /usr/bin/bash "$repo_root/scripts/tun_linux_route.sh" --table "$TUN_TABLE" down "$TUN_NAME" "${tun_routes[@]}" "${tun_ipv6_routes[@]}" >/dev/null 2>&1 || true
}

install_tproxy_rules() {
    local cidr port bypass_ip
    local -a extra_excludes tcp_ports udp_ports

    if [[ -z "$tproxy_uid" ]]; then
        return 0
    fi

    split_csv "$TPROXY_EXCLUDE_CIDRS" extra_excludes
    split_csv "$TPROXY_TCP_PORTS" tcp_ports
    split_csv "$TPROXY_UDP_PORTS" udp_ports

    iptables -t nat -N "$TPROXY_NAT_CHAIN" >/dev/null 2>&1 || true
    iptables -t nat -F "$TPROXY_NAT_CHAIN"

    for cidr in \
        0.0.0.0/8 \
        10.0.0.0/8 \
        127.0.0.0/8 \
        169.254.0.0/16 \
        172.16.0.0/12 \
        192.168.0.0/16 \
        224.0.0.0/4 \
        240.0.0.0/4 \
        "${extra_excludes[@]}"; do
        [[ -n "$cidr" ]] || continue
        iptables -t nat -A "$TPROXY_NAT_CHAIN" -d "$cidr" -j RETURN
    done

    for host in "${bypass_hosts[@]}"; do
        bypass_ip="$(getent ahostsv4 "$host" | awk 'NR==1 {print $1}')"
        [[ -n "$bypass_ip" ]] || continue
        iptables -t nat -A "$TPROXY_NAT_CHAIN" -d "$bypass_ip/32" -j RETURN
    done

    if (( ${#tcp_ports[@]} == 0 )); then
        iptables -t nat -A "$TPROXY_NAT_CHAIN" -p tcp -j REDIRECT --to-ports "$TPROXY_TCP_PORT"
    else
        for port in "${tcp_ports[@]}"; do
            iptables -t nat -A "$TPROXY_NAT_CHAIN" -p tcp --dport "$port" -j REDIRECT --to-ports "$TPROXY_TCP_PORT"
        done
    fi

    if (( ${#udp_ports[@]} == 0 )); then
        iptables -t nat -A "$TPROXY_NAT_CHAIN" -p udp -j REDIRECT --to-ports "$TPROXY_UDP_PORT"
    else
        for port in "${udp_ports[@]}"; do
            iptables -t nat -A "$TPROXY_NAT_CHAIN" -p udp --dport "$port" -j REDIRECT --to-ports "$TPROXY_UDP_PORT"
        done
    fi

    iptables -t nat -D OUTPUT -m owner --uid-owner "$tproxy_uid" -j "$TPROXY_NAT_CHAIN" >/dev/null 2>&1 || true
    iptables -t nat -A OUTPUT -m owner --uid-owner "$tproxy_uid" -j "$TPROXY_NAT_CHAIN"
}

remove_tproxy_rules() {
    if [[ -z "$tproxy_uid" ]]; then
        return 0
    fi

    iptables -t nat -D OUTPUT -m owner --uid-owner "$tproxy_uid" -j "$TPROXY_NAT_CHAIN" >/dev/null 2>&1 || true
    iptables -t nat -F "$TPROXY_NAT_CHAIN" >/dev/null 2>&1 || true
    iptables -t nat -X "$TPROXY_NAT_CHAIN" >/dev/null 2>&1 || true
}

cleanup() {
    local exit_code=$?

    if (( cleanup_done == 1 )); then
        exit "$exit_code"
    fi
    cleanup_done=1
    trap - EXIT INT TERM

    set +e

    if [[ -n "$client_pid" ]] && kill -0 "$client_pid" >/dev/null 2>&1; then
        kill "$client_pid" >/dev/null 2>&1 || true
        wait "$client_pid" >/dev/null 2>&1 || true
    fi

    remove_tproxy_rules
    remove_tun_rules
    remove_bypass_routes

    if [[ "$KEEP_WRAPPER_LOG" == "1" || $exit_code -ne 0 ]]; then
        echo "wrapper log kept at $wrapper_log"
    else
        rm -f "$wrapper_log"
    fi

    exit "$exit_code"
}

trap cleanup EXIT INT TERM

if [[ -n "$TUN_TEST_USER" ]]; then
    tun_uid="$(resolve_uid "$TUN_TEST_USER")"
fi
if [[ -n "$TPROXY_TEST_USER" ]]; then
    tproxy_uid="$(resolve_uid "$TPROXY_TEST_USER")"
fi

echo "wrapper log: $wrapper_log"
load_outbound_hosts
for host in "${bypass_hosts[@]}"; do
    install_bypass_route "$host"
done

run_client
if [[ -n "$tun_uid" ]]; then
    wait_for_tun_device
fi
if [[ -n "$tproxy_uid" ]]; then
    wait_for_tcp_listener "127.0.0.1" "$TPROXY_TCP_PORT" "tproxy_tcp"
fi

install_tun_rules
install_tproxy_rules

echo "client started with user-based steering rules installed"
if [[ -n "$tun_uid" ]]; then
    echo "tun user: $TUN_TEST_USER uid:$tun_uid table:$TUN_TABLE device:$TUN_NAME"
fi
if [[ -n "$tproxy_uid" ]]; then
    echo "tproxy user: $TPROXY_TEST_USER uid:$tproxy_uid tcp:$TPROXY_TCP_PORT udp:$TPROXY_UDP_PORT"
fi

wait "$client_pid"
