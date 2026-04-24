#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$repo_root/build-review/socks}"

if [[ ! -x "$binary" ]]; then
    echo "binary not found: $binary" >&2
    exit 1
fi

source "$repo_root/scripts/runtime_env.sh"
source "$repo_root/scripts/testlib.sh"
require_commands python3 curl
init_runtime_ld_library_path "$binary"

tmp_dir="$(create_test_tmp_dir "$repo_root" ".tmp-socks5-test.XXXXXX")"
keep_artifacts="${KEEP_TEST_ARTIFACTS:-0}"
declare -a pids=()

cleanup() {
    local exit_code=$?
    trap - EXIT
    cleanup_managed_pids pids

    if [[ $exit_code -ne 0 ]]; then
        echo "test failed logs kept at $tmp_dir" >&2
        print_test_logs "$tmp_dir" 80 "*.log"
        exit "$exit_code"
    fi

    if [[ "$keep_artifacts" == "1" ]]; then
        echo "test artifacts kept at $tmp_dir"
    else
        rm -rf "$tmp_dir"
    fi
}

trap cleanup EXIT

read -r server_port socks_port http_port web_port udp_port udp_a_port udp_b_port < <(
    python3 - <<'PY'
import socket

socks = []
tcp_ports = []
for _ in range(4):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    tcp_ports.append(sock.getsockname()[1])
    socks.append(sock)

udp_socks = []
udp_ports = []
for _ in range(3):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("127.0.0.1", 0))
    udp_ports.append(udp_sock.getsockname()[1])
    udp_socks.append(udp_sock)

print(*tcp_ports, *udp_ports)

for sock in socks:
    sock.close()
for sock in udp_socks:
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
  "inbounds": [
    {
      "type": "reality",
      "tag": "reality-in",
      "settings": {
        "host": "127.0.0.1",
        "port": $server_port,
        "sni": "$sni",
        "private_key": "$private_key",
        "public_key": "$public_key",
        "short_id": "$short_id",
        "replay_cache_max_entries": 100000
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
    }
  ],
  "routing": [
    {
      "type": "inbound",
      "values": ["reality-in"],
      "out": "direct"
    }
  ],
  "timeout": {
    "read": 5,
    "write": 5,
    "connect": 5,
    "idle": 30
  }
}
EOF

cat >"$tmp_dir/client.json" <<EOF
{
  "workers": 1,
  "log": {
    "level": "debug",
    "file": "$tmp_dir/client.log"
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "settings": {
        "host": "127.0.0.1",
        "port": $socks_port,
        "auth": false
      }
    }
  ],
  "outbounds": [
    {
      "type": "reality",
      "tag": "reality-out",
      "settings": {
        "host": "127.0.0.1",
        "port": $server_port,
        "sni": "$sni",
        "fingerprint": "random",
        "public_key": "$public_key",
        "short_id": "$short_id",
        "max_handshake_records": 256
      }
    },
    {
      "type": "reality",
      "tag": "reality-out-a",
      "settings": {
        "host": "127.0.0.1",
        "port": $server_port,
        "sni": "$sni",
        "fingerprint": "random",
        "public_key": "$public_key",
        "short_id": "$short_id",
        "max_handshake_records": 256
      }
    },
    {
      "type": "reality",
      "tag": "reality-out-b",
      "settings": {
        "host": "127.0.0.1",
        "port": $server_port,
        "sni": "$sni",
        "fingerprint": "random",
        "public_key": "$public_key",
        "short_id": "$short_id",
        "max_handshake_records": 256
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
      "type": "ip",
      "values": ["127.0.0.2/32"],
      "out": "reality-out-a"
    },
    {
      "type": "ip",
      "values": ["127.0.0.3/32"],
      "out": "reality-out-b"
    },
    {
      "type": "inbound",
      "values": ["socks-in"],
      "out": "reality-out"
    }
  ],
  "timeout": {
    "read": 5,
    "write": 5,
    "connect": 5,
    "idle": 30
  },
  "web": {
    "enabled": true,
    "host": "127.0.0.1",
    "port": $web_port
  }
}
EOF

mkdir -p "$tmp_dir/http"
printf 'ok-socks5\n' >"$tmp_dir/http/healthz.txt"

python3 -m http.server "$http_port" --bind 127.0.0.1 --directory "$tmp_dir/http" >"$tmp_dir/http.log" 2>&1 &
http_pid=$!
pids+=("$http_pid")

python3 "$repo_root/scripts/socks5_udp_echo_server.py" --host 127.0.0.1 --port "$udp_port" >"$tmp_dir/udp-echo.log" 2>&1 &
udp_echo_pid=$!
pids+=("$udp_echo_pid")

python3 "$repo_root/scripts/socks5_udp_echo_server.py" --host 127.0.0.2 --port "$udp_a_port" >"$tmp_dir/udp-echo-a.log" 2>&1 &
udp_echo_a_pid=$!
pids+=("$udp_echo_a_pid")

python3 "$repo_root/scripts/socks5_udp_echo_server.py" --host 127.0.0.3 --port "$udp_b_port" >"$tmp_dir/udp-echo-b.log" 2>&1 &
udp_echo_b_pid=$!
pids+=("$udp_echo_b_pid")

env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$tmp_dir/server.json" >"$tmp_dir/server.stdout.log" 2>&1 &
server_pid=$!
pids+=("$server_pid")

env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$tmp_dir/client.json" >"$tmp_dir/client.stdout.log" 2>&1 &
client_pid=$!
pids+=("$client_pid")

wait_for_tcp_port 127.0.0.1 "$server_port" "reality_server" 10 "$server_pid" "$client_pid"
wait_for_tcp_port 127.0.0.1 "$socks_port" "socks5_listener" 10 "$server_pid" "$client_pid"
wait_for_tcp_port 127.0.0.1 "$web_port" "trace_web" 10 "$server_pid" "$client_pid"

wait_for_proxy_ready() {
    local socks_port="$1"
    local target_url="$2"
    SOCKS_PORT="$socks_port" TARGET_URL="$target_url" SERVER_PID="$server_pid" CLIENT_PID="$client_pid" python3 - <<'PY'
import os
import subprocess
import sys
import time

deadline = time.time() + 20.0
socks_port = int(os.environ["SOCKS_PORT"])
target_url = os.environ["TARGET_URL"]
last_error = ""

while time.time() < deadline:
    for pid_env in ("SERVER_PID", "CLIENT_PID"):
        pid = int(os.environ[pid_env])
        try:
            os.kill(pid, 0)
        except OSError:
            print("proxy owner process exited early", file=sys.stderr)
            sys.exit(1)

    result = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "2",
            "--socks5-hostname",
            f"127.0.0.1:{socks_port}",
            target_url,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0 and result.stdout.strip() == "ok-socks5":
        sys.exit(0)

    last_error = (result.stderr or result.stdout or f"rc={result.returncode}").strip()
    time.sleep(0.2)

print(f"timeout waiting for socks5 proxy ready last_error={last_error}", file=sys.stderr)
sys.exit(1)
PY
}

wait_for_proxy_ready "$socks_port" "http://127.0.0.1:$http_port/healthz.txt"

tcp_payload="$(curl --silent --show-error --fail --socks5-hostname "127.0.0.1:$socks_port" "http://127.0.0.1:$http_port/healthz.txt")"
if [[ "$tcp_payload" != "ok-socks5" ]]; then
    echo "unexpected tcp payload: $tcp_payload" >&2
    exit 1
fi

parallel_dir="$tmp_dir/parallel"
mkdir -p "$parallel_dir"
request_pids=()
for index in 1 2 3 4; do
    curl --silent --show-error --fail \
        --socks5-hostname "127.0.0.1:$socks_port" \
        "http://127.0.0.1:$http_port/healthz.txt" >"$parallel_dir/$index.out" &
    request_pids+=("$!")
done
for request_pid in "${request_pids[@]}"; do
    wait "$request_pid"
done
for index in 1 2 3 4; do
    if [[ "$(tr -d '\r\n' <"$parallel_dir/$index.out")" != "ok-socks5" ]]; then
        echo "parallel request $index failed" >&2
        exit 1
    fi
done

udp_payload="$(python3 "$repo_root/scripts/socks5_udp_client.py" \
    --socks-host 127.0.0.1 \
    --socks-port "$socks_port" \
    --target-host 127.0.0.1 \
    --target-port "$udp_port" \
    --payload "udp-smoke")"
if [[ "$udp_payload" != "udp-smoke" ]]; then
    echo "unexpected udp payload: $udp_payload" >&2
    exit 1
fi

python3 "$repo_root/scripts/socks5_udp_multi_target.py" \
    --socks-host 127.0.0.1 \
    --socks-port "$socks_port" \
    --target-a-host 127.0.0.2 \
    --target-a-port "$udp_a_port" \
    --target-b-host 127.0.0.3 \
    --target-b-port "$udp_b_port"

python3 - "$web_port" <<'PY'
import json
import sys
import time
import urllib.request

web_port = int(sys.argv[1])
deadline = time.time() + 5.0
last_payload = None

while time.time() < deadline:
    with urllib.request.urlopen(f"http://127.0.0.1:{web_port}/api/traces/events?stage=route_decide_done&limit=100", timeout=2) as response:
        payload = json.load(response)
    last_payload = payload
    events = payload.get("items") or payload.get("events") or []
    socks_udp_events = [
        event
        for event in events
        if event.get("inbound_tag") == "socks-in"
        and event.get("target_host") in {"127.0.0.2", "127.0.0.3"}
    ]
    tags_by_target = {event.get("target_host"): event.get("outbound_tag") for event in socks_udp_events}
    if tags_by_target.get("127.0.0.2") == "reality-out-a" and tags_by_target.get("127.0.0.3") == "reality-out-b":
        sys.exit(0)
    time.sleep(0.1)

raise RuntimeError(f"missing socks udp multi outbound trace events: {last_payload}")
PY

echo "socks5 tcp smoke ok"
echo "socks5 parallel proxy ok"
echo "socks5 udp associate ok"
echo "socks5 udp multi outbound ok"

python3 "$repo_root/scripts/socks5_edge_cases.py" \
    --socks-host 127.0.0.1 \
    --socks-port "$socks_port"

python3 "$repo_root/scripts/socks5_udp_edge_cases.py" \
    --socks-host 127.0.0.1 \
    --socks-port "$socks_port" \
    --target-port "$udp_port"
