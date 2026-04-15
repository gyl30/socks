#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$repo_root/build-review/socks}"

if [[ ! -x "$binary" ]]; then
    echo "binary not found: $binary" >&2
    exit 1
fi

for cmd in python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing dependency: $cmd" >&2
        exit 1
    fi
done

concurrency="${CONCURRENCY:-1}"
requests_per_worker="${REQUESTS_PER_WORKER:-1}"
bytes_per_response="${BYTES_PER_RESPONSE:-4194304}"
client_workers="${CLIENT_WORKERS:-2}"
server_workers="${SERVER_WORKERS:-2}"
read_timeout_sec="${READ_TIMEOUT_SEC:-10}"
write_timeout_sec="${WRITE_TIMEOUT_SEC:-10}"
connect_timeout_sec="${CONNECT_TIMEOUT_SEC:-5}"
idle_timeout_sec="${IDLE_TIMEOUT_SEC:-60}"
client_max_handshake_records="${CLIENT_MAX_HANDSHAKE_RECORDS:-256}"
server_max_handshake_records="${SERVER_MAX_HANDSHAKE_RECORDS:-256}"
monitor_interval_ms="${MONITOR_INTERVAL_MS:-100}"
keep_artifacts="${KEEP_TEST_ARTIFACTS:-0}"

tmp_dir="$(mktemp -d "$repo_root/.tmp-socks5-resource.XXXXXX")"
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
        echo "resource test failed logs kept at $tmp_dir" >&2
        for log_file in "$tmp_dir"/*.log; do
            if [[ -f "$log_file" ]]; then
                echo "===== $(basename "$log_file") =====" >&2
                tail -n 80 "$log_file" >&2 || true
            fi
        done
        exit "$exit_code"
    fi

    if [[ "$keep_artifacts" == "1" ]]; then
        echo "resource test artifacts kept at $tmp_dir"
    else
        rm -rf "$tmp_dir"
    fi
}

trap cleanup EXIT

read -r server_port socks_port http_port < <(
    python3 - <<'PY'
import socket

sockets = []
ports = []
for _ in range(3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    ports.append(sock.getsockname()[1])
    sockets.append(sock)
print(*ports)
for sock in sockets:
    sock.close()
PY
)

key_output="$("$binary" x25519)"
private_key="$(awk '/private key:/{print $3}' <<<"$key_output")"
public_key="$(awk '/public key:/{print $3}' <<<"$key_output")"
short_id="0102030405060708"
sni="www.example.com"

cat >"$tmp_dir/server.json" <<EOF
{
  "workers": $server_workers,
  "log": {
    "level": "info",
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
    "read": $read_timeout_sec,
    "write": $write_timeout_sec,
    "connect": $connect_timeout_sec,
    "idle": $idle_timeout_sec
  }
}
EOF

cat >"$tmp_dir/client.json" <<EOF
{
  "workers": $client_workers,
  "log": {
    "level": "info",
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
        "max_handshake_records": $client_max_handshake_records
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
      "type": "inbound",
      "values": ["socks-in"],
      "out": "reality-out"
    }
  ],
  "timeout": {
    "read": $read_timeout_sec,
    "write": $write_timeout_sec,
    "connect": $connect_timeout_sec,
    "idle": $idle_timeout_sec
  }
}
EOF

payload_path="$tmp_dir/http/payload.bin"
mkdir -p "$tmp_dir/http"
PAYLOAD_PATH="$payload_path" BYTES_PER_RESPONSE="$bytes_per_response" python3 - <<'PY'
import os

payload_path = os.environ["PAYLOAD_PATH"]
size = int(os.environ["BYTES_PER_RESPONSE"])
chunk = (b"socks5-resource-test-" * 2048)[:65536]
remaining = size
with open(payload_path, "wb") as handle:
    while remaining > 0:
        piece = chunk[: min(len(chunk), remaining)]
        handle.write(piece)
        remaining -= len(piece)
PY

wait_for_port() {
    local host="$1"
    local port="$2"
    local name="$3"
    shift 3
    local owner_pids=("$@")
    HOST="$host" PORT="$port" NAME="$name" OWNER_PIDS="${owner_pids[*]}" python3 - <<'PY'
import os
import sys
import time

host = os.environ["HOST"]
port = int(os.environ["PORT"])
name = os.environ["NAME"]
owner_pids = [int(pid) for pid in os.environ.get("OWNER_PIDS", "").split() if pid]


def port_is_listening(port):
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                next(handle, None)
                for line in handle:
                    fields = line.split()
                    if len(fields) < 4:
                        continue
                    local_address = fields[1]
                    state = fields[3]
                    if state != "0A":
                        continue
                    try:
                        _addr_hex, port_hex = local_address.rsplit(":", 1)
                    except ValueError:
                        continue
                    if int(port_hex, 16) == port:
                        return True
        except FileNotFoundError:
            continue
    return False


deadline = time.time() + 10.0
while time.time() < deadline:
    for pid in owner_pids:
        try:
            os.kill(pid, 0)
        except OSError:
            print(f"{name} owner process exited early", file=sys.stderr)
            sys.exit(1)
    if port_is_listening(port):
        sys.exit(0)
    time.sleep(0.1)
print(f"timeout waiting for {name} {host}:{port}", file=sys.stderr)
sys.exit(1)
PY
}

python3 -m http.server "$http_port" --bind 127.0.0.1 --directory "$tmp_dir/http" >"$tmp_dir/http.log" 2>&1 &
http_pid=$!
pids+=("$http_pid")

"$binary" -c "$tmp_dir/server.json" >"$tmp_dir/server.stdout.log" 2>&1 &
server_pid=$!
pids+=("$server_pid")

wait_for_port 127.0.0.1 "$server_port" "reality_server" "$server_pid"

"$binary" -c "$tmp_dir/client.json" >"$tmp_dir/client.stdout.log" 2>&1 &
client_pid=$!
pids+=("$client_pid")

wait_for_port 127.0.0.1 "$socks_port" "socks5_listener" "$server_pid" "$client_pid"

wait_for_proxy_ready() {
    local socks_port="$1"
    local target_port="$2"
    local target_path="$3"
    SOCKS_PORT="$socks_port" TARGET_PORT="$target_port" TARGET_PATH="$target_path" REPO_ROOT="$repo_root" SERVER_PID="$server_pid" CLIENT_PID="$client_pid" python3 - <<'PY'
import os
import subprocess
import sys
import time

deadline = time.time() + 20.0
repo_root = os.environ["REPO_ROOT"]
cmd = [
    sys.executable,
    f"{repo_root}/scripts/socks5_tcp_load.py",
    "--socks-host",
    "127.0.0.1",
    "--socks-port",
    os.environ["SOCKS_PORT"],
    "--target-host",
    "127.0.0.1",
    "--target-port",
    os.environ["TARGET_PORT"],
    "--path",
    os.environ["TARGET_PATH"],
    "--concurrency",
    "1",
    "--requests-per-worker",
    "1",
]
last_error = ""

while time.time() < deadline:
    for pid_env in ("SERVER_PID", "CLIENT_PID"):
        pid = int(os.environ[pid_env])
        try:
            os.kill(pid, 0)
        except OSError:
            print("proxy owner process exited early", file=sys.stderr)
            sys.exit(1)

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        sys.exit(0)

    last_error = (result.stderr or result.stdout or f"rc={result.returncode}").strip()
    time.sleep(0.2)

print(f"timeout waiting for socks5 proxy ready last_error={last_error}", file=sys.stderr)
sys.exit(1)
PY
}

wait_for_proxy_ready "$socks_port" "$http_port" "/payload.bin"

python3 "$repo_root/scripts/process_resource_monitor.py" \
    --pid "client:$client_pid" \
    --pid "server:$server_pid" \
    --interval-ms "$monitor_interval_ms" \
    --output "$tmp_dir/resource-summary.json" >"$tmp_dir/resource-monitor.log" 2>&1 &
monitor_pid=$!
pids+=("$monitor_pid")

python3 "$repo_root/scripts/socks5_tcp_load.py" \
    --socks-host 127.0.0.1 \
    --socks-port "$socks_port" \
    --target-host 127.0.0.1 \
    --target-port "$http_port" \
    --path /payload.bin \
    --concurrency "$concurrency" \
    --requests-per-worker "$requests_per_worker" | tee "$tmp_dir/load-summary.log"

kill "$monitor_pid" >/dev/null 2>&1 || true
wait "$monitor_pid" >/dev/null 2>&1 || true

SUMMARY_JSON="$tmp_dir/resource-summary.json" python3 - <<'PY'
import json
import os
import sys

summary_path = os.environ["SUMMARY_JSON"]
with open(summary_path, "r", encoding="utf-8") as handle:
    summary = json.load(handle)

for label in ("client", "server"):
    proc = summary["processes"][label]
    print(
        f"{label} peak_rss_kb={proc['peak_rss_kb']} "
        f"peak_fd_count={proc['peak_fd_count']} "
        f"peak_threads={proc['peak_threads']} "
        f"cpu_seconds_total={proc['cpu_seconds_total']:.3f}"
    )

thresholds = {
    "client": {
        "rss_kb": os.getenv("MAX_CLIENT_RSS_KB"),
        "fd_count": os.getenv("MAX_CLIENT_FD"),
    },
    "server": {
        "rss_kb": os.getenv("MAX_SERVER_RSS_KB"),
        "fd_count": os.getenv("MAX_SERVER_FD"),
    },
}
for label, values in thresholds.items():
    proc = summary["processes"][label]
    if values["rss_kb"] is not None and proc["peak_rss_kb"] > int(values["rss_kb"]):
        print(f"{label} peak rss exceeded threshold", file=sys.stderr)
        sys.exit(1)
    if values["fd_count"] is not None and proc["peak_fd_count"] > int(values["fd_count"]):
        print(f"{label} peak fd exceeded threshold", file=sys.stderr)
        sys.exit(1)
PY
