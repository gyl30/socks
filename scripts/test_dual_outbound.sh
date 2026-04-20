#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$repo_root/build/socks}"

if [[ ! -x "$binary" ]]; then
    echo "binary not found: $binary" >&2
    exit 1
fi

source "$repo_root/scripts/runtime_env.sh"
source "$repo_root/scripts/testlib.sh"
require_commands python3 curl
init_runtime_ld_library_path "$binary"

tmp_dir="$(create_test_tmp_dir "$repo_root" ".tmp-dual-outbound.XXXXXX")"
keep_artifacts="${KEEP_TEST_ARTIFACTS:-0}"
declare -a pids=()

cleanup() {
    local exit_code=$?
    trap - EXIT
    cleanup_managed_pids pids

    if [[ $exit_code -ne 0 ]]; then
        echo "test failed logs kept at $tmp_dir" >&2
        print_test_logs "$tmp_dir" 120 "*.log"
        exit "$exit_code"
    fi

    if [[ "$keep_artifacts" == "1" ]]; then
        echo "test artifacts kept at $tmp_dir"
    else
        rm -rf "$tmp_dir"
    fi
}

trap cleanup EXIT

read -r reality_port server_socks_port client_socks_port client_tproxy_tcp_port client_tproxy_udp_port < <(
    python3 - <<'PY'
import socket

holders = []
ports = []
for _ in range(5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    ports.append(sock.getsockname()[1])
    holders.append(sock)

print(*ports)

for sock in holders:
    sock.close()
PY
)

key_output="$(env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" x25519)"
private_key="$(awk '/private key:/{print $3}' <<<"$key_output")"
public_key="$(awk '/public key:/{print $3}' <<<"$key_output")"
short_id="0102030405060708"
sni="www.example.com"

cat >"$tmp_dir/server.json" <<EOF
{
  "workers": 1,
  "log": {
    "level": "debug",
    "file": "$tmp_dir/server.log"
  },
  "timeout": {
    "read": 10,
    "write": 10,
    "connect": 10,
    "idle": 60
  },
  "inbounds": [
    {
      "type": "reality",
      "tag": "reality-in",
      "settings": {
        "host": "127.0.0.1",
        "port": $reality_port,
        "sni": "$sni",
        "private_key": "$private_key",
        "public_key": "$public_key",
        "short_id": "$short_id",
        "replay_cache_max_entries": 100000
      }
    },
    {
      "type": "socks",
      "tag": "socks-in-server",
      "settings": {
        "host": "127.0.0.1",
        "port": $server_socks_port,
        "auth": false
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "socks",
      "tag": "socks-out",
      "settings": {
        "host": "127.0.0.1",
        "port": $client_socks_port,
        "auth": false
      }
    }
  ],
  "routing": [
    {
      "type": "inbound",
      "values": [
        "reality-in",
        "socks-in-server"
      ],
      "out": "direct"
    }
  ]
}
EOF

cat >"$tmp_dir/client.json" <<EOF
{
  "workers": 1,
  "log": {
    "level": "debug",
    "file": "$tmp_dir/client.log"
  },
  "timeout": {
    "read": 10,
    "write": 10,
    "connect": 10,
    "idle": 60
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "settings": {
        "host": "127.0.0.1",
        "port": $client_socks_port,
        "auth": false
      }
    },
    {
      "type": "tun",
      "tag": "tun-in",
      "settings": {
        "name": "socks-tun0",
        "mtu": 1500,
        "ipv4": "198.18.0.1",
        "ipv4_prefix": 24,
        "ipv6": "fd00::1",
        "ipv6_prefix": 64
      }
    },
    {
      "type": "tproxy",
      "tag": "tproxy-in",
      "mark": 17,
      "settings": {
        "listen_host": "::",
        "tcp_port": $client_tproxy_tcp_port,
        "udp_port": $client_tproxy_udp_port
      }
    }
  ],
  "outbounds": [
    {
      "type": "reality",
      "tag": "reality-out",
      "settings": {
        "host": "127.0.0.1",
        "port": $reality_port,
        "sni": "$sni",
        "fingerprint": "random",
        "public_key": "$public_key",
        "short_id": "$short_id",
        "max_handshake_records": 256
      }
    },
    {
      "type": "socks",
      "tag": "socks-out",
      "settings": {
        "host": "127.0.0.1",
        "port": $server_socks_port,
        "auth": false
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "routing": [
    {
      "type": "domain",
      "values": ["example.com", "www.example.com"],
      "out": "reality-out"
    },
    {
      "type": "domain",
      "values": ["example.net", "www.example.net"],
      "out": "socks-out"
    },
    {
      "type": "inbound",
      "values": ["socks-in", "tun-in", "tproxy-in"],
      "out": "direct"
    }
  ]
}
EOF

env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$tmp_dir/server.json" >"$tmp_dir/server.stdout.log" 2>&1 &
server_pid=$!
pids+=("$server_pid")

wait_for_tcp_port "127.0.0.1" "$reality_port" "reality_inbound" 20 "$server_pid"
wait_for_tcp_port "127.0.0.1" "$server_socks_port" "server_socks_inbound" 20 "$server_pid"

if [[ "$EUID" -eq 0 ]]; then
    env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$tmp_dir/client.json" >"$tmp_dir/client.stdout.log" 2>&1 &
else
    if sudo -n true >/dev/null 2>&1; then
        sudo -n env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$tmp_dir/client.json" >"$tmp_dir/client.stdout.log" 2>&1 &
    else
        echo "client config contains tun/tproxy and requires root; run script as root or allow passwordless sudo" >&2
        exit 1
    fi
fi
client_pid=$!
pids+=("$client_pid")

wait_for_tcp_port "127.0.0.1" "$client_socks_port" "client_socks_inbound" 20 "$client_pid"

curl --socks5-hostname "127.0.0.1:$client_socks_port" --max-time 25 -fsS "http://example.com" >"$tmp_dir/reality.out"
curl --socks5-hostname "127.0.0.1:$client_socks_port" --max-time 25 -fsS "http://example.net" >"$tmp_dir/socks.out"

sleep 1

rg -q "target_domain example.com .* out_tag reality-out" "$tmp_dir/client.stdout.log" \
    || { echo "missing reality-out route hit in client log" >&2; exit 1; }
rg -q "target_domain example.net .* out_tag socks-out" "$tmp_dir/client.stdout.log" \
    || { echo "missing socks-out route hit in client log" >&2; exit 1; }
rg -q "target example.com:80 route reality-out connected" "$tmp_dir/client.stdout.log" \
    || { echo "missing reality-out connected log" >&2; exit 1; }
rg -q "target example.net:80 route socks-out connected" "$tmp_dir/client.stdout.log" \
    || { echo "missing socks-out connected log" >&2; exit 1; }

echo "dual outbound integration ok"
