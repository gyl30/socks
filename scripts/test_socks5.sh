#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$repo_root/build-review/socks}"

if [[ ! -x "$binary" ]]; then
    echo "binary not found: $binary" >&2
    exit 1
fi

for cmd in python3 curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing dependency: $cmd" >&2
        exit 1
    fi
done

source "$repo_root/scripts/runtime_env.sh"
init_runtime_ld_library_path "$binary"

tmp_dir="$(mktemp -d "$repo_root/.tmp-socks5-test.XXXXXX")"
keep_artifacts="${KEEP_TEST_ARTIFACTS:-0}"
declare -a pids=()

cleanup() {
    local exit_code=$?
    trap - EXIT
    for pid in "${pids[@]:-}"; do
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
            wait "$pid" >/dev/null 2>&1 || true
        fi
    done

    if [[ $exit_code -ne 0 ]]; then
        echo "test failed logs kept at $tmp_dir" >&2
        for log_file in "$tmp_dir"/*.log; do
            if [[ -f "$log_file" ]]; then
                echo "===== $(basename "$log_file") =====" >&2
                tail -n 80 "$log_file" >&2 || true
            fi
        done
        exit "$exit_code"
    fi

    if [[ "$keep_artifacts" == "1" ]]; then
        echo "test artifacts kept at $tmp_dir"
    else
        rm -rf "$tmp_dir"
    fi
}

trap cleanup EXIT

read -r server_port socks_port http_port udp_port < <(
    python3 - <<'PY'
import socket

socks = []
tcp_ports = []
for _ in range(3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    tcp_ports.append(sock.getsockname()[1])
    socks.append(sock)

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.bind(("127.0.0.1", 0))
udp_port = udp_sock.getsockname()[1]

print(*tcp_ports, udp_port)

for sock in socks:
    sock.close()
udp_sock.close()
PY
)

key_output="$(env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" x25519)"
private_key="$(awk '/private key:/{print $3}' <<<"$key_output")"
public_key="$(awk '/public key:/{print $3}' <<<"$key_output")"
short_id="0102030405060708"
sni="www.example.com"

cat >"$tmp_dir/server.json" <<EOF
{
  "mode": "server",
  "workers": 1,
  "log": {
    "level": "debug",
    "file": "$tmp_dir/server.log"
  },
  "inbound": {
    "host": "127.0.0.1",
    "port": $server_port
  },
  "socks": {
    "enabled": false
  },
  "reality": {
    "sni": "$sni",
    "private_key": "$private_key",
    "public_key": "$public_key",
    "short_id": "$short_id"
  },
  "timeout": {
    "read": 5,
    "write": 5,
    "connect": 5,
    "idle": 30
  },
  "limits": {
    "max_connections": 64,
    "max_buffer": 10485760,
    "max_streams": 256,
    "max_handshake_records": 256
  }
}
EOF

cat >"$tmp_dir/client.json" <<EOF
{
  "mode": "client",
  "workers": 1,
  "log": {
    "level": "debug",
    "file": "$tmp_dir/client.log"
  },
  "socks": {
    "enabled": true,
    "host": "127.0.0.1",
    "port": $socks_port,
    "auth": false
  },
  "tproxy": {
    "enabled": false,
    "listen_host": "::",
    "tcp_port": 0,
    "udp_port": 0,
    "mark": 17
  },
  "outbound": {
    "host": "127.0.0.1",
    "port": $server_port
  },
  "reality": {
    "sni": "$sni",
    "fingerprint": "random",
    "public_key": "$public_key",
    "short_id": "$short_id"
  },
  "timeout": {
    "read": 5,
    "write": 5,
    "connect": 5,
    "idle": 30
  },
  "limits": {
    "max_connections": 4,
    "max_buffer": 10485760,
    "max_streams": 256,
    "max_handshake_records": 256
  },
  "heartbeat": {
    "min_interval": 15,
    "max_interval": 45,
    "min_padding": 32,
    "max_padding": 128
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

env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$tmp_dir/server.json" >"$tmp_dir/server.stdout.log" 2>&1 &
server_pid=$!
pids+=("$server_pid")

env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$tmp_dir/client.json" >"$tmp_dir/client.stdout.log" 2>&1 &
client_pid=$!
pids+=("$client_pid")

wait_for_port() {
    local host="$1"
    local port="$2"
    local name="$3"
    HOST="$host" PORT="$port" NAME="$name" SERVER_PID="$server_pid" CLIENT_PID="$client_pid" python3 - <<'PY'
import os
import socket
import sys
import time

host = os.environ["HOST"]
port = int(os.environ["PORT"])
name = os.environ["NAME"]
deadline = time.time() + 10.0
while time.time() < deadline:
    for pid_env in ("SERVER_PID", "CLIENT_PID"):
        pid = int(os.environ[pid_env])
        try:
            os.kill(pid, 0)
        except OSError:
            print(f"{name} owner process exited early", file=sys.stderr)
            sys.exit(1)
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

wait_for_port 127.0.0.1 "$server_port" "reality_server"
wait_for_port 127.0.0.1 "$socks_port" "socks5_listener"

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

echo "socks5 tcp smoke ok"
echo "socks5 mux parallel ok"
echo "socks5 udp associate ok"

python3 "$repo_root/scripts/socks5_edge_cases.py" \
    --socks-host 127.0.0.1 \
    --socks-port "$socks_port"

python3 "$repo_root/scripts/socks5_udp_edge_cases.py" \
    --socks-host 127.0.0.1 \
    --socks-port "$socks_port" \
    --target-port "$udp_port"
