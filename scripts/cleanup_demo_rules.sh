#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/cleanup_demo_rules.sh

Environment:
  CONFIG_PATH     Client config path. Default: config/all-features-client.json
  STATE_DIR       Runtime state dir. Default: .tmp-demo-stack
  TUN_TEST_USER   TUN 测试用户。默认: tunuser
  TPROXY_TEST_USER TPROXY 测试用户。默认: tpuser
  TUN_NAME        TUN 设备名。默认从 state/config 推导
  TUN_ROUTES      TUN 路由。默认: 0.0.0.0/1,128.0.0.0/1
  TUN_IPV6_ROUTES TUN IPv6 路由。默认: 空
  TUN_TABLE       TUN 路由表。默认: 101
  TUN_PRIORITY    TUN ip rule 优先级。默认: 90
  TPROXY_NAT_CHAIN TPROXY nat chain。默认: SOCKS_LOCAL_TPROXY_NAT
  TPROXY_RULE_COMMENT TPROXY 规则注释。默认: socks-local-tproxy
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
config_path="${CONFIG_PATH:-$repo_root/config/all-features-client.json}"
state_dir="${STATE_DIR:-$repo_root/.tmp-demo-stack}"
pid_file="$state_dir/client-wrapper.pid"
env_file="$state_dir/client.env"

source "$repo_root/scripts/testlib.sh"
require_commands getent id ip iptables python3 awk tr

if [[ -f "$env_file" ]]; then
    # shellcheck disable=SC1090
    source "$env_file"
    config_path="${CONFIG_PATH:-$config_path}"
    state_dir="${STATE_DIR:-$state_dir}"
    pid_file="$state_dir/client-wrapper.pid"
fi

tun_test_user="${TUN_TEST_USER:-tunuser}"
tproxy_test_user="${TPROXY_TEST_USER:-tpuser}"
tun_name="${TUN_NAME:-}"
tun_routes="${TUN_ROUTES:-0.0.0.0/1,128.0.0.0/1}"
tun_ipv6_routes="${TUN_IPV6_ROUTES:-}"
tun_table="${TUN_TABLE:-101}"
tun_priority="${TUN_PRIORITY:-90}"
tproxy_nat_chain="${TPROXY_NAT_CHAIN:-SOCKS_LOCAL_TPROXY_NAT}"
tproxy_rule_comment="${TPROXY_RULE_COMMENT:-socks-local-tproxy}"

if [[ -z "$tun_name" && -f "$config_path" ]]; then
    tun_name="$(python3 - "$config_path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    cfg = json.load(handle)

for inbound in cfg.get("inbounds", []):
    if inbound.get("type") == "tun":
        print((inbound.get("settings") or {}).get("name", ""))
        break
PY
)"
fi

if [[ -f "$pid_file" ]]; then
    wrapper_pid="$(<"$pid_file")"
    if [[ -n "$wrapper_pid" ]] && kill -0 "$wrapper_pid" >/dev/null 2>&1; then
        kill "$wrapper_pid" >/dev/null 2>&1 || true
        deadline=$((SECONDS + 10))
        while (( SECONDS < deadline )); do
            if ! kill -0 "$wrapper_pid" >/dev/null 2>&1; then
                break
            fi
            sleep 0.2
        done
        if kill -0 "$wrapper_pid" >/dev/null 2>&1; then
            kill -9 "$wrapper_pid" >/dev/null 2>&1 || true
        fi
        wait "$wrapper_pid" >/dev/null 2>&1 || true
    fi
    rm -f "$pid_file"
fi

tun_uid=""
tproxy_uid=""
if id "$tun_test_user" >/dev/null 2>&1; then
    tun_uid="$(id -u "$tun_test_user")"
fi
if id "$tproxy_test_user" >/dev/null 2>&1; then
    tproxy_uid="$(id -u "$tproxy_test_user")"
fi

if [[ -n "$tproxy_uid" ]]; then
    iptables -t nat -D OUTPUT -m owner --uid-owner "$tproxy_uid" -m comment --comment "$tproxy_rule_comment" -j "$tproxy_nat_chain" \
        >/dev/null 2>&1 || true
    iptables -t nat -F "$tproxy_nat_chain" >/dev/null 2>&1 || true
    iptables -t nat -X "$tproxy_nat_chain" >/dev/null 2>&1 || true
    echo "removed tproxy nat rules chain=$tproxy_nat_chain uid=$tproxy_uid"
fi

if [[ -n "$tun_uid" ]]; then
    ip rule del pref "$tun_priority" uidrange "${tun_uid}-${tun_uid}" lookup "$tun_table" >/dev/null 2>&1 || true
    if [[ -n "$tun_name" ]]; then
        read -r -a tun_route_items <<<"$(tr ',' ' ' <<<"$tun_routes")"
        read -r -a tun_ipv6_route_items <<<"$(tr ',' ' ' <<<"$tun_ipv6_routes")"
        if (( ${#tun_route_items[@]} > 0 || ${#tun_ipv6_route_items[@]} > 0 )); then
            /usr/bin/bash "$repo_root/scripts/tun_linux_route.sh" --table "$tun_table" down "$tun_name" \
                "${tun_route_items[@]}" "${tun_ipv6_route_items[@]}" >/dev/null 2>&1 || true
        fi
    fi
    echo "removed tun rules table=$tun_table priority=$tun_priority uid=$tun_uid"
fi

if [[ -f "$config_path" ]]; then
    while IFS= read -r host; do
        [[ -n "$host" ]] || continue
        if [[ "$host" == 127.* || "$host" == 0.* || "$host" == *:* ]]; then
            continue
        fi
        ip_addr="$(getent ahostsv4 "$host" | awk 'NR==1 {print $1}')"
        [[ -n "$ip_addr" ]] || continue
        ip route del "${ip_addr}/32" >/dev/null 2>&1 || true
    done < <(
        python3 - "$config_path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    cfg = json.load(handle)

for outbound in cfg.get("outbounds", []):
    settings = outbound.get("settings") or {}
    host = settings.get("host")
    if isinstance(host, str) and host:
        print(host)
PY
    )
fi

rm -f "$env_file"
echo "demo client rules cleaned"
