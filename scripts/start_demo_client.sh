#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/start_demo_client.sh

Environment:
  BINARY                Path to socks binary. Default: ./build/socks
  CONFIG_PATH           Client config path. Default: config/all-features-client.json
  STATE_DIR             Runtime state dir. Default: .tmp-demo-stack
  TUN_TEST_USER         TUN 测试用户。默认: tunuser
  TPROXY_TEST_USER      TPROXY 测试用户。默认: tpuser
  TUN_ROUTES            TUN 路由。默认: 0.0.0.0/1,128.0.0.0/1
  TUN_IPV6_ROUTES       TUN IPv6 路由。默认: 空
  TUN_TABLE             TUN 路由表。默认: 101
  TUN_PRIORITY          TUN ip rule 优先级。默认: 90
  TPROXY_TCP_PORTS      重定向到 tproxy 的 TCP 目标端口。默认: 80,443
  TPROXY_UDP_PORTS      重定向到 tproxy 的 UDP 目标端口。默认: 53
  TPROXY_EXCLUDE_CIDRS  额外绕过的 CIDR。默认: 空
  TEST_ID               Optional test id forwarded to run_local_client.sh
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
config_path="${CONFIG_PATH:-$repo_root/config/all-features-client.json}"
state_dir="${STATE_DIR:-$repo_root/.tmp-demo-stack}"
pid_file="$state_dir/client-wrapper.pid"
env_file="$state_dir/client.env"
stdout_log="$state_dir/client-wrapper.stdout.log"

source "$repo_root/scripts/testlib.sh"
require_commands id python3 grep tr

if [[ ! -x "$binary" ]]; then
    echo "binary not found or not executable: $binary" >&2
    exit 1
fi
if [[ ! -f "$config_path" ]]; then
    echo "config file not found: $config_path" >&2
    exit 1
fi

tun_test_user="${TUN_TEST_USER:-tunuser}"
tproxy_test_user="${TPROXY_TEST_USER:-tpuser}"
tun_routes="${TUN_ROUTES:-0.0.0.0/1,128.0.0.0/1}"
tun_ipv6_routes="${TUN_IPV6_ROUTES:-}"
tun_table="${TUN_TABLE:-101}"
tun_priority="${TUN_PRIORITY:-90}"
tproxy_tcp_ports="${TPROXY_TCP_PORTS:-80,443}"
tproxy_udp_ports="${TPROXY_UDP_PORTS:-53}"
tproxy_exclude_cidrs="${TPROXY_EXCLUDE_CIDRS:-}"
test_id="${TEST_ID:-}"

sanitize_test_id() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9'
}

uppercase_text() {
    printf '%s' "$1" | tr '[:lower:]' '[:upper:]'
}

id "$tun_test_user" >/dev/null 2>&1 || {
    echo "user not found: $tun_test_user" >&2
    exit 1
}
id "$tproxy_test_user" >/dev/null 2>&1 || {
    echo "user not found: $tproxy_test_user" >&2
    exit 1
}

test_id_slug=""
if [[ -n "$test_id" ]]; then
    test_id_slug="$(sanitize_test_id "$test_id")"
    if [[ -z "$test_id_slug" ]]; then
        echo "TEST_ID must contain at least one alphanumeric character" >&2
        exit 1
    fi
fi

tproxy_nat_chain="${TPROXY_NAT_CHAIN:-}"
tproxy_rule_comment="${TPROXY_RULE_COMMENT:-}"
if [[ -z "$tproxy_nat_chain" ]]; then
    if [[ -n "$test_id_slug" ]]; then
        tproxy_nat_chain="SOCKS_LTP_$(uppercase_text "${test_id_slug:0:12}")"
    else
        tproxy_nat_chain="SOCKS_LOCAL_TPROXY_NAT"
    fi
fi
if [[ -z "$tproxy_rule_comment" ]]; then
    if [[ -n "$test_id_slug" ]]; then
        tproxy_rule_comment="socks-local-${test_id_slug:0:24}"
    else
        tproxy_rule_comment="socks-local-tproxy"
    fi
fi

mkdir -p "$state_dir"

if [[ -f "$pid_file" ]]; then
    existing_pid="$(<"$pid_file")"
    if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" >/dev/null 2>&1; then
        echo "demo client wrapper already running pid=$existing_pid" >&2
        exit 1
    fi
    rm -f "$pid_file"
fi

read -r socks_port tun_name tproxy_tcp_port tproxy_udp_port <<EOF
$(python3 - "$config_path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    cfg = json.load(handle)

socks_port = ""
tun_name = ""
tproxy_tcp_port = ""
tproxy_udp_port = ""
for inbound in cfg.get("inbounds", []):
    settings = inbound.get("settings") or {}
    inbound_type = inbound.get("type")
    if inbound_type == "socks" and not socks_port:
        socks_port = str(settings.get("port", ""))
    elif inbound_type == "tun" and not tun_name:
        tun_name = str(settings.get("name", ""))
    elif inbound_type == "tproxy" and not tproxy_tcp_port:
        tproxy_tcp_port = str(settings.get("tcp_port", ""))
        tproxy_udp_port = str(settings.get("udp_port", ""))

print(socks_port, tun_name, tproxy_tcp_port, tproxy_udp_port)
PY
)
EOF

cat >"$env_file" <<EOF
REPO_ROOT=$(printf '%q' "$repo_root")
BINARY=$(printf '%q' "$binary")
CONFIG_PATH=$(printf '%q' "$config_path")
STATE_DIR=$(printf '%q' "$state_dir")
TUN_TEST_USER=$(printf '%q' "$tun_test_user")
TPROXY_TEST_USER=$(printf '%q' "$tproxy_test_user")
TUN_NAME=$(printf '%q' "$tun_name")
TUN_ROUTES=$(printf '%q' "$tun_routes")
TUN_IPV6_ROUTES=$(printf '%q' "$tun_ipv6_routes")
TUN_TABLE=$(printf '%q' "$tun_table")
TUN_PRIORITY=$(printf '%q' "$tun_priority")
TPROXY_TCP_PORT=$(printf '%q' "$tproxy_tcp_port")
TPROXY_UDP_PORT=$(printf '%q' "$tproxy_udp_port")
TPROXY_TCP_PORTS=$(printf '%q' "$tproxy_tcp_ports")
TPROXY_UDP_PORTS=$(printf '%q' "$tproxy_udp_ports")
TPROXY_EXCLUDE_CIDRS=$(printf '%q' "$tproxy_exclude_cidrs")
TPROXY_NAT_CHAIN=$(printf '%q' "$tproxy_nat_chain")
TPROXY_RULE_COMMENT=$(printf '%q' "$tproxy_rule_comment")
TEST_ID=$(printf '%q' "$test_id")
EOF

(
    cd "$repo_root"
    env \
        BINARY="$binary" \
        TEST_ID="$test_id" \
        TUN_NAME="$tun_name" \
        TUN_TEST_USER="$tun_test_user" \
        TUN_ROUTES="$tun_routes" \
        TUN_IPV6_ROUTES="$tun_ipv6_routes" \
        TUN_TABLE="$tun_table" \
        TUN_PRIORITY="$tun_priority" \
        TPROXY_TEST_USER="$tproxy_test_user" \
        TPROXY_TCP_PORT="$tproxy_tcp_port" \
        TPROXY_UDP_PORT="$tproxy_udp_port" \
        TPROXY_TCP_PORTS="$tproxy_tcp_ports" \
        TPROXY_UDP_PORTS="$tproxy_udp_ports" \
        TPROXY_EXCLUDE_CIDRS="$tproxy_exclude_cidrs" \
        TPROXY_NAT_CHAIN="$tproxy_nat_chain" \
        TPROXY_RULE_COMMENT="$tproxy_rule_comment" \
        KEEP_WRAPPER_LOG=1 \
        /usr/bin/bash "$repo_root/scripts/run_local_client.sh" "$config_path" >"$stdout_log" 2>&1
) &
wrapper_pid="$!"
printf '%s\n' "$wrapper_pid" >"$pid_file"

if [[ -n "$socks_port" ]]; then
    wait_for_tcp_port 127.0.0.1 "$socks_port" "client_socks_in" 20 "$wrapper_pid"
fi

deadline=$((SECONDS + 20))
rules_ready=0
while (( SECONDS < deadline )); do
    if grep -q "client started with user-based steering rules installed" "$stdout_log" 2>/dev/null; then
        rules_ready=1
        break
    fi
    if ! kill -0 "$wrapper_pid" >/dev/null 2>&1; then
        wait "$wrapper_pid"
        exit 1
    fi
    sleep 0.2
done
if (( rules_ready == 0 )); then
    echo "timeout waiting for client wrapper to install user steering rules" >&2
    exit 1
fi

echo "demo client started"
echo "pid: $wrapper_pid"
echo "stdout log: $stdout_log"
echo "state dir: $state_dir"
echo
echo "manual test commands:"
echo "  curl --socks5-hostname 127.0.0.1:${socks_port} http://example.com"
echo "    socks-in -> reality-out -> server reality-in -> direct"
echo "  sudo -u ${tun_test_user} curl https://example.com -v --max-time 20"
echo "    tun-in -> direct"
echo "  sudo -u ${tproxy_test_user} curl http://example.net -v --max-time 20"
echo "    tproxy-in -> socks-out -> server socks-in -> direct"
echo "  sudo -u ${tun_test_user} python3 ${repo_root}/scripts/udp_dns_probe.py 8.8.8.8 53 example.com 5"
echo "  sudo -u ${tproxy_test_user} python3 ${repo_root}/scripts/udp_dns_probe.py 8.8.8.8 53 example.com 5"
echo "note:"
echo "  client reality-in is wired to block, reserved for block-path validation"
