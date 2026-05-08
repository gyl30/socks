#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/start_demo_server.sh

Environment:
  BINARY         Path to socks binary. Default: ./build/socks
  CONFIG_PATH    Server config path. Default: config/all-features-server.json
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
binary="${BINARY:-$repo_root/build/socks}"
config_path="${CONFIG_PATH:-$repo_root/config/all-features-server.json}"
state_dir="${STATE_DIR:-$repo_root/.tmp-demo-stack}"
pid_file="$state_dir/server.pid"
stdout_log="$state_dir/server.stdout.log"

source "$repo_root/scripts/runtime_env.sh"
source "$repo_root/scripts/testlib.sh"
require_commands ip python3
init_runtime_ld_library_path "$binary"

if [[ ! -x "$binary" ]]; then
    echo "binary not found or not executable: $binary" >&2
    exit 1
fi
if [[ ! -f "$config_path" ]]; then
    echo "config file not found: $config_path" >&2
    exit 1
fi

mkdir -p "$state_dir"

if [[ -f "$pid_file" ]]; then
    existing_pid="$(<"$pid_file")"
    if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" >/dev/null 2>&1; then
        echo "demo server already running pid=$existing_pid" >&2
        exit 1
    fi
    rm -f "$pid_file"
fi

read -r reality_port socks_port tun_name <<EOF
$(python3 - "$config_path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    cfg = json.load(handle)

reality_port = ""
socks_port = ""
tun_name = ""
for inbound in cfg.get("inbounds", []):
    settings = inbound.get("settings") or {}
    inbound_type = inbound.get("type")
    if inbound_type == "reality" and not reality_port:
        reality_port = str(settings.get("port", ""))
    elif inbound_type == "socks" and not socks_port:
        socks_port = str(settings.get("port", ""))
    elif inbound_type == "tun" and not tun_name:
        tun_name = str(settings.get("name", ""))

print(reality_port, socks_port, tun_name)
PY
)
EOF

(
    cd "$repo_root"
    env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$config_path" >"$stdout_log" 2>&1
) &
server_pid="$!"
printf '%s\n' "$server_pid" >"$pid_file"

if [[ -n "$reality_port" ]]; then
    wait_for_tcp_port 127.0.0.1 "$reality_port" "server_reality_in" 20 "$server_pid"
fi
if [[ -n "$socks_port" ]]; then
    wait_for_tcp_port 127.0.0.1 "$socks_port" "server_socks_in" 20 "$server_pid"
fi
if [[ -n "$tun_name" ]]; then
    deadline=$((SECONDS + 20))
    tun_ready=0
    while (( SECONDS < deadline )); do
        if ip link show dev "$tun_name" >/dev/null 2>&1; then
            tun_ready=1
            break
        fi
        if ! kill -0 "$server_pid" >/dev/null 2>&1; then
            wait "$server_pid"
            exit 1
        fi
        sleep 0.2
    done
    if (( tun_ready == 0 )); then
        echo "timeout waiting for tun device $tun_name" >&2
        exit 1
    fi
fi

echo "demo server started"
echo "pid: $server_pid"
echo "log: $stdout_log"
echo "state dir: $state_dir"
