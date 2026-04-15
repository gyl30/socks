#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$repo_root/build/socks}"

if [[ ! -x "$binary" ]]; then
    echo "binary not found: $binary" >&2
    exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "this script must run as root or inside unshare -Urnm" >&2
    exit 1
fi

for cmd in ip python3 openssl awk; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing dependency: $cmd" >&2
        exit 1
    fi
done

source "$repo_root/scripts/runtime_env.sh"
init_runtime_ld_library_path "$binary"

tmp_dir="${ARTIFACT_DIR:-$(mktemp -d "$repo_root/.tmp-tun-bench.XXXXXX")}"
mkdir -p "$tmp_dir"

run_root="${BENCH_RUN_ROOT:-1}"
run_direct="${BENCH_RUN_DIRECT:-1}"
run_proxy="${BENCH_RUN_PROXY:-1}"
run_tcp_tests="${BENCH_RUN_TCP_TESTS:-1}"
run_udp_tests="${BENCH_RUN_UDP_TESTS:-1}"

tcp_concurrency="${BENCH_TCP_CONCURRENCY:-64}"
tcp_requests="${BENCH_TCP_REQUESTS:-1}"
tcp_body_bytes="${BENCH_TCP_BODY_BYTES:-2097152}"
tcp_chunk_size="${BENCH_TCP_CHUNK_SIZE:-65536}"

udp_workers="${BENCH_UDP_WORKERS:-16}"
udp_requests="${BENCH_UDP_REQUESTS:-500}"
udp_payload_small="${BENCH_UDP_PAYLOAD_SMALL:-64}"
udp_payload_large="${BENCH_UDP_PAYLOAD_LARGE:-1200}"

warmup_body_bytes="${BENCH_WARMUP_BODY_BYTES:-1024}"
warmup_chunk_size="${BENCH_WARMUP_CHUNK_SIZE:-1024}"

tcp_path="/fast-large?body_bytes=${tcp_body_bytes}&chunk_size=${tcp_chunk_size}&chunk_interval_ms=0"
warmup_path="/fast-large?body_bytes=${warmup_body_bytes}&chunk_size=${warmup_chunk_size}&chunk_interval_ms=0"

ip link set lo up
ensure_netns_mountpoint /run/netns

declare -a pids=()

cleanup() {
    local rc=$?
    trap - EXIT

    for pid in "${pids[@]:-}"; do
        kill "$pid" >/dev/null 2>&1 || true
    done

    sleep 0.2
    for pid in "${pids[@]:-}"; do
        kill -9 "$pid" >/dev/null 2>&1 || true
    done

    for pid in "${pids[@]:-}"; do
        wait "$pid" >/dev/null 2>&1 || true
    done

    ip netns delete "$ns_app" >/dev/null 2>&1 || true
    ip netns delete "$ns_client" >/dev/null 2>&1 || true
    ip netns delete "$ns_target" >/dev/null 2>&1 || true
    ip link delete "$host_if" >/dev/null 2>&1 || true
    ip link delete "$target_host_if" >/dev/null 2>&1 || true
    if [[ -w /proc/sys/net/ipv4/ip_forward ]]; then
        printf '%s\n' "$host_ip_forward_before" >/proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    fi

    exit "$rc"
}

trap cleanup EXIT

wait_for_port() {
    local host="$1"
    local port="$2"
    local label="$3"

    HOST="$host" PORT="$port" LABEL="$label" python3 - <<'PY'
import os
import socket
import sys
import time

host = os.environ["HOST"]
port = int(os.environ["PORT"])
label = os.environ["LABEL"]
deadline = time.time() + 20.0
last_error = None

while time.time() < deadline:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        sock.connect((host, port))
        sys.exit(0)
    except OSError as exc:
        last_error = exc
        time.sleep(0.1)
    finally:
        sock.close()

print(f"timeout waiting for {label} {host}:{port} last_error={last_error}", file=sys.stderr)
sys.exit(1)
PY
}

wait_for_log() {
    local file="$1"
    local needle="$2"
    local timeout_sec="${3:-20}"

    FILE="$file" NEEDLE="$needle" TIMEOUT_SEC="$timeout_sec" python3 - <<'PY'
import os
import pathlib
import sys
import time

path = pathlib.Path(os.environ["FILE"])
needle = os.environ["NEEDLE"]
deadline = time.time() + float(os.environ["TIMEOUT_SEC"])

while time.time() < deadline:
    if path.exists() and needle in path.read_text(encoding="utf-8", errors="replace"):
        sys.exit(0)
    time.sleep(0.2)

print(f"timeout waiting for {needle!r} in {path}", file=sys.stderr)
sys.exit(1)
PY
}

proc_jiffies() {
    python3 - "$1" <<'PY'
import sys

with open(f"/proc/{sys.argv[1]}/stat", "r", encoding="utf-8") as handle:
    fields = handle.read().split()
print(int(fields[13]) + int(fields[14]))
PY
}

clk_tck="$(getconf CLK_TCK)"

report_cpu() {
    local label="$1"
    local start_client="$2"
    local end_client="$3"
    local start_server="$4"
    local end_server="$5"

    python3 - "$label" "$start_client" "$end_client" "$start_server" "$end_server" "$clk_tck" <<'PY'
import sys

label = sys.argv[1]
start_client = int(sys.argv[2])
end_client = int(sys.argv[3])
start_server = int(sys.argv[4])
end_server = int(sys.argv[5])
clk_tck = int(sys.argv[6])

print(f"{label}_client_cpu_seconds={(end_client - start_client) / clk_tck:.3f}")
print(f"{label}_server_cpu_seconds={(end_server - start_server) / clk_tck:.3f}")
PY
}

run_tcp_bench() {
    python3 - "$1" "$2" "$3" "$4" "$5" <<'PY'
import asyncio
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
path = sys.argv[3]
concurrency = int(sys.argv[4])
requests = int(sys.argv[5])


async def read_http_response(reader):
    header = bytearray()
    while b"\r\n\r\n" not in header:
        chunk = await reader.read(4096)
        if not chunk:
            raise RuntimeError("unexpected eof before response header")
        header.extend(chunk)
        if len(header) > 65536:
            raise RuntimeError("response header too large")

    header_end = header.index(b"\r\n\r\n") + 4
    raw_header = bytes(header[:header_end])
    body = bytearray(header[header_end:])
    lines = raw_header.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split()
    if len(parts) < 2 or parts[1] != "200":
        raise RuntimeError(f"unexpected status line {lines[0]}")

    content_length = None
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.lower() == "content-length":
            content_length = int(value.strip())
            break
    if content_length is None:
        raise RuntimeError("missing content-length")

    while len(body) < content_length:
        chunk = await reader.read(content_length - len(body))
        if not chunk:
            raise RuntimeError("unexpected eof before response body")
        body.extend(chunk)

    return content_length


async def one_request():
    reader, writer = await asyncio.open_connection(host, port)
    try:
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Connection: close\r\n"
            "User-Agent: tun-bench\r\n"
            "\r\n"
        ).encode("ascii")
        writer.write(request)
        await writer.drain()
        return await read_http_response(reader)
    finally:
        writer.close()
        await writer.wait_closed()


async def worker():
    total = 0
    for _ in range(requests):
        total += await one_request()
    return total


async def main():
    started = time.perf_counter()
    results = await asyncio.gather(*[asyncio.create_task(worker()) for _ in range(concurrency)])
    duration = time.perf_counter() - started
    total_bytes = sum(results)
    mib = total_bytes / (1024.0 * 1024.0)
    throughput = mib / duration if duration > 0 else 0.0

    print(f"connections={concurrency * requests}")
    print(f"bytes={total_bytes}")
    print(f"duration_seconds={duration:.3f}")
    print(f"throughput_mib_per_s={throughput:.2f}")


asyncio.run(main())
PY
}

run_udp_bench() {
    python3 - "$1" "$2" "$3" "$4" "$5" <<'PY'
import concurrent.futures
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
payload_size = int(sys.argv[3])
workers = int(sys.argv[4])
requests = int(sys.argv[5])
payload = b"u" * payload_size

def worker():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    sock.bind(("0.0.0.0", 0))
    ok = 0
    fail = 0
    total = 0

    try:
        for _ in range(requests):
            try:
                sock.sendto(payload, (host, port))
                data, _peer = sock.recvfrom(65535)
            except Exception:
                fail += 1
                continue

            if data != payload:
                fail += 1
                continue

            ok += 1
            total += len(data)
    finally:
        sock.close()

    return ok, fail, total


def main():
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(lambda _index: worker(), range(workers)))
    duration = time.perf_counter() - started
    ok = sum(item[0] for item in results)
    fail = sum(item[1] for item in results)
    total = sum(item[2] for item in results)
    pps = ok / duration if duration > 0 else 0.0
    throughput = (total / (1024.0 * 1024.0)) / duration if duration > 0 else 0.0

    print(f"packets_ok={ok}")
    print(f"packets_fail={fail}")
    print(f"bytes={total}")
    print(f"duration_seconds={duration:.3f}")
    print(f"pps={pps:.0f}")
    print(f"throughput_mib_per_s={throughput:.2f}")


main()
PY
}

run_app_tcp() {
    ip netns exec "$ns_app" bash -lc "$(declare -f run_tcp_bench); run_tcp_bench '$1' '$2' '$3' '$4' '$5'"
}

run_app_udp() {
    ip netns exec "$ns_app" bash -lc "$(declare -f run_udp_bench); run_udp_bench '$1' '$2' '$3' '$4' '$5'"
}

tag="$(printf '%04x' "$(( $$ % 65536 ))")"
net_id="$(( (16#$tag % 200) + 20 ))"
ns_app="tunb_app_$tag"
ns_client="tunb_client_$tag"
ns_target="tunb_target_$tag"
host_if="bh$tag"
client_host_if="bc$tag"
client_app_if="bd$tag"
app_if="ba$tag"
host_ip="10.213.${net_id}.1"
client_host_ip="10.213.${net_id}.2"
client_app_ip="10.212.${net_id}.1"
app_ip="10.212.${net_id}.2"
app_cidr="$app_ip/32"
target_host_if="ch$tag"
target_if="ca$tag"
target_host_ip="10.214.${net_id}.1"
target_ip="10.214.${net_id}.2"
target_cidr="$target_ip/32"
tun_direct="td$tag"
tun_proxy="tp$tag"
host_ip_forward_before="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"

read -r server_port http_port udp_port < <(
    python3 - <<'PY'
import socket

ports = []
for _ in range(2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    ports.append(sock.getsockname()[1])
    sock.close()

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.bind(("127.0.0.1", 0))
udp_port = udp_sock.getsockname()[1]
udp_sock.close()

print(ports[0], ports[1], udp_port)
PY
)

mkdir -p "$tmp_dir/rules_direct" "$tmp_dir/rules_proxy"
for dir in "$tmp_dir/rules_direct" "$tmp_dir/rules_proxy"; do
    : >"$dir/block_ip.txt"
    : >"$dir/direct_domain.txt"
    : >"$dir/block_domain.txt"
    : >"$dir/proxy_domain.txt"
done
printf '%s/32\n' "$target_ip" >"$tmp_dir/rules_direct/direct_ip.txt"
: >"$tmp_dir/rules_proxy/direct_ip.txt"

key_output="$(env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" x25519)"
private_key="$(awk '/private key:/{print $3}' <<<"$key_output")"
public_key="$(awk '/public key:/{print $3}' <<<"$key_output")"
short_id="0102030405060708"
sni="localhost"

cat >"$tmp_dir/server.json" <<EOF
{
  "workers": 1,
  "log": {"level": "info", "file": "$tmp_dir/server.log"},
  "inbounds": [
    {
      "type": "reality",
      "tag": "reality-in",
      "settings": {
        "host": "$host_ip",
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
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ],
  "routing": [
    {"type": "inbound", "values": ["reality-in"], "out": "direct"}
  ],
  "timeout": {"read": 5, "write": 5, "connect": 5, "idle": 30}
}
EOF

cat >"$tmp_dir/client-direct.json" <<EOF
{
  "workers": 1,
  "log": {"level": "info", "file": "$tmp_dir/client-direct.log"},
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "settings": {
        "name": "$tun_direct",
        "mtu": 1400,
        "ipv4": "198.18.0.1",
        "ipv4_prefix": 32,
        "ipv6": "fd00::1",
        "ipv6_prefix": 128
      }
    }
  ],
  "outbounds": [
    {
      "type": "reality",
      "tag": "reality-out",
      "settings": {
        "host": "$host_ip",
        "port": $server_port,
        "sni": "$sni",
        "fingerprint": "random",
        "public_key": "$public_key",
        "short_id": "$short_id",
        "max_handshake_records": 256
      }
    },
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ],
  "routing": [
    {"type": "ip", "file": "$tmp_dir/rules_direct/direct_ip.txt", "out": "direct"},
    {"type": "inbound", "values": ["tun-in"], "out": "reality-out"}
  ],
  "timeout": {"read": 5, "write": 5, "connect": 5, "idle": 30}
}
EOF

cat >"$tmp_dir/client-proxy.json" <<EOF
{
  "workers": 1,
  "log": {"level": "info", "file": "$tmp_dir/client-proxy.log"},
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "settings": {
        "name": "$tun_proxy",
        "mtu": 1400,
        "ipv4": "198.18.0.1",
        "ipv4_prefix": 32,
        "ipv6": "fd00::1",
        "ipv6_prefix": 128
      }
    }
  ],
  "outbounds": [
    {
      "type": "reality",
      "tag": "reality-out",
      "settings": {
        "host": "$host_ip",
        "port": $server_port,
        "sni": "$sni",
        "fingerprint": "random",
        "public_key": "$public_key",
        "short_id": "$short_id",
        "max_handshake_records": 256
      }
    },
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ],
  "routing": [
    {"type": "inbound", "values": ["tun-in"], "out": "reality-out"}
  ],
  "timeout": {"read": 5, "write": 5, "connect": 5, "idle": 30}
}
EOF

ip netns add "$ns_app"
ip netns add "$ns_client"
ip netns add "$ns_target"

ip link add "$host_if" type veth peer name "$client_host_if"
ip link set "$client_host_if" netns "$ns_client"
ip addr add "$host_ip/24" dev "$host_if"
ip link set "$host_if" up
ip netns exec "$ns_client" ip link set lo up
ip netns exec "$ns_client" ip addr add "$client_host_ip/24" dev "$client_host_if"
ip netns exec "$ns_client" ip link set "$client_host_if" up
ip netns exec "$ns_client" ip route replace default via "$host_ip" dev "$client_host_if"

ip link add "$client_app_if" type veth peer name "$app_if"
ip link set "$client_app_if" netns "$ns_client"
ip link set "$app_if" netns "$ns_app"
ip netns exec "$ns_client" ip addr add "$client_app_ip/24" dev "$client_app_if"
ip netns exec "$ns_client" ip link set "$client_app_if" up
ip netns exec "$ns_app" ip link set lo up
ip netns exec "$ns_app" ip addr add "$app_ip/24" dev "$app_if"
ip netns exec "$ns_app" ip link set "$app_if" up
ip netns exec "$ns_app" ip route replace default via "$client_app_ip" dev "$app_if"

printf '1\n' >/proc/sys/net/ipv4/ip_forward
ip netns exec "$ns_client" sh -c 'printf "1\n" >/proc/sys/net/ipv4/ip_forward'

ip link add "$target_host_if" type veth peer name "$target_if"
ip link set "$target_if" netns "$ns_target"
ip addr add "$target_host_ip/24" dev "$target_host_if"
ip link set "$target_host_if" up
ip netns exec "$ns_target" ip link set lo up
ip netns exec "$ns_target" ip addr add "$target_ip/24" dev "$target_if"
ip netns exec "$ns_target" ip link set "$target_if" up
ip netns exec "$ns_target" ip route replace default via "$target_host_ip" dev "$target_if"

cat >"$tmp_dir/origin-openssl.cnf" <<'EOF'
[req]
distinguished_name=req_dn
x509_extensions=v3_req
prompt=no

[req_dn]
CN=localhost

[v3_req]
subjectAltName=@alt_names

[alt_names]
DNS.1=localhost
EOF

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$tmp_dir/origin.key" -out "$tmp_dir/origin.crt" -config "$tmp_dir/origin-openssl.cnf" -extensions v3_req >"$tmp_dir/openssl-req.log" 2>&1
openssl s_server -accept 127.0.0.1:443 -www -tls1_3 -cert "$tmp_dir/origin.crt" -key "$tmp_dir/origin.key" >"$tmp_dir/origin.log" 2>&1 &
pids+=("$!")
wait_for_port 127.0.0.1 443 origin_tls

ip netns exec "$ns_target" python3 "$repo_root/scripts/slow_http_server.py" --host "$target_ip" --port "$http_port" >"$tmp_dir/http.log" 2>&1 &
pids+=("$!")
ip netns exec "$ns_target" python3 "$repo_root/scripts/socks5_udp_echo_server.py" --host "$target_ip" --port "$udp_port" >"$tmp_dir/udp.log" 2>&1 &
pids+=("$!")
wait_for_port "$target_ip" "$http_port" target_http

env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$tmp_dir/server.json" >"$tmp_dir/server.stdout.log" 2>&1 &
server_pid=$!
pids+=("$server_pid")
wait_for_port "$host_ip" "$server_port" reality_server

if [[ "$run_root" == "1" ]]; then
    if [[ "$run_tcp_tests" == "1" ]]; then
        run_tcp_bench "$target_ip" "$http_port" "$tcp_path" "$tcp_concurrency" "$tcp_requests" >"$tmp_dir/root-tcp.txt"
    fi
    if [[ "$run_udp_tests" == "1" ]]; then
        run_udp_bench "$target_ip" "$udp_port" "$udp_payload_small" "$udp_workers" "$udp_requests" >"$tmp_dir/root-udp-${udp_payload_small}.txt"
        run_udp_bench "$target_ip" "$udp_port" "$udp_payload_large" "$udp_workers" "$udp_requests" >"$tmp_dir/root-udp-${udp_payload_large}.txt"
    fi
fi

if [[ "$run_direct" == "1" ]]; then
    ip netns exec "$ns_client" env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$tmp_dir/client-direct.json" >"$tmp_dir/client-direct.stdout.log" 2>&1 &
    client_direct_pid=$!
    pids+=("$client_direct_pid")
    wait_for_log "$tmp_dir/client-direct.log" "tun inbound started" 20
    ip netns exec "$ns_client" ip link show "$tun_direct" >/dev/null
    /usr/bin/bash "$repo_root/scripts/tun_linux_route.sh" --netns "$ns_client" --from "$app_cidr" --table 100 up "$tun_direct" "$target_cidr" >/dev/null
    ip netns exec "$ns_client" ip rule show >"$tmp_dir/client-direct.policy-rule.log" 2>&1 || true
    ip netns exec "$ns_client" ip route show table 100 >"$tmp_dir/client-direct.policy-route.log" 2>&1 || true
    if [[ "$run_tcp_tests" == "1" ]]; then
        ip netns exec "$ns_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" --host "$target_ip" --port "$http_port" --path "$warmup_path" --expect-substring "socks5-slow-http-server" >/dev/null
    fi
    if [[ "$run_udp_tests" == "1" ]]; then
        ip netns exec "$ns_app" python3 "$repo_root/scripts/tproxy_udp_client.py" --host "$target_ip" --port "$udp_port" --payload "warmup-direct" --expect-echo >/dev/null
    fi

    start_client_jiffies="$(proc_jiffies "$client_direct_pid")"
    start_server_jiffies="$(proc_jiffies "$server_pid")"
    if [[ "$run_tcp_tests" == "1" ]]; then
        run_app_tcp "$target_ip" "$http_port" "$tcp_path" "$tcp_concurrency" "$tcp_requests" >"$tmp_dir/tun-direct-tcp.txt"
    fi
    if [[ "$run_udp_tests" == "1" ]]; then
        run_app_udp "$target_ip" "$udp_port" "$udp_payload_small" "$udp_workers" "$udp_requests" >"$tmp_dir/tun-direct-udp-${udp_payload_small}.txt"
        run_app_udp "$target_ip" "$udp_port" "$udp_payload_large" "$udp_workers" "$udp_requests" >"$tmp_dir/tun-direct-udp-${udp_payload_large}.txt"
    fi
    end_client_jiffies="$(proc_jiffies "$client_direct_pid")"
    end_server_jiffies="$(proc_jiffies "$server_pid")"
    report_cpu tun_direct "$start_client_jiffies" "$end_client_jiffies" "$start_server_jiffies" "$end_server_jiffies" >"$tmp_dir/tun-direct-cpu.txt"

    kill "$client_direct_pid" >/dev/null 2>&1 || true
    wait "$client_direct_pid" >/dev/null 2>&1 || true
    sleep 1
fi

if [[ "$run_proxy" == "1" ]]; then
    ip netns exec "$ns_client" env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$tmp_dir/client-proxy.json" >"$tmp_dir/client-proxy.stdout.log" 2>&1 &
    client_proxy_pid=$!
    pids+=("$client_proxy_pid")
    wait_for_log "$tmp_dir/client-proxy.log" "tun inbound started" 20
    ip netns exec "$ns_client" ip link show "$tun_proxy" >/dev/null
    /usr/bin/bash "$repo_root/scripts/tun_linux_route.sh" --netns "$ns_client" --from "$app_cidr" --table 100 up "$tun_proxy" "$target_cidr" >/dev/null
    ip netns exec "$ns_client" ip rule show >"$tmp_dir/client-proxy.policy-rule.log" 2>&1 || true
    ip netns exec "$ns_client" ip route show table 100 >"$tmp_dir/client-proxy.policy-route.log" 2>&1 || true
    if [[ "$run_tcp_tests" == "1" ]]; then
        ip netns exec "$ns_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" --host "$target_ip" --port "$http_port" --path "$warmup_path" --expect-substring "socks5-slow-http-server" >/dev/null
    fi
    if [[ "$run_udp_tests" == "1" ]]; then
        ip netns exec "$ns_app" python3 "$repo_root/scripts/tproxy_udp_client.py" --host "$target_ip" --port "$udp_port" --payload "warmup-proxy" --expect-echo >/dev/null
    fi

    start_client_jiffies="$(proc_jiffies "$client_proxy_pid")"
    start_server_jiffies="$(proc_jiffies "$server_pid")"
    if [[ "$run_tcp_tests" == "1" ]]; then
        run_app_tcp "$target_ip" "$http_port" "$tcp_path" "$tcp_concurrency" "$tcp_requests" >"$tmp_dir/tun-proxy-tcp.txt"
    fi
    if [[ "$run_udp_tests" == "1" ]]; then
        run_app_udp "$target_ip" "$udp_port" "$udp_payload_small" "$udp_workers" "$udp_requests" >"$tmp_dir/tun-proxy-udp-${udp_payload_small}.txt"
        run_app_udp "$target_ip" "$udp_port" "$udp_payload_large" "$udp_workers" "$udp_requests" >"$tmp_dir/tun-proxy-udp-${udp_payload_large}.txt"
    fi
    end_client_jiffies="$(proc_jiffies "$client_proxy_pid")"
    end_server_jiffies="$(proc_jiffies "$server_pid")"
    report_cpu tun_proxy "$start_client_jiffies" "$end_client_jiffies" "$start_server_jiffies" "$end_server_jiffies" >"$tmp_dir/tun-proxy-cpu.txt"
fi

printf 'artifact_dir=%s\n' "$tmp_dir"
for file in \
    root-tcp.txt \
    "root-udp-${udp_payload_small}.txt" \
    "root-udp-${udp_payload_large}.txt" \
    tun-direct-tcp.txt \
    "tun-direct-udp-${udp_payload_small}.txt" \
    "tun-direct-udp-${udp_payload_large}.txt" \
    tun-direct-cpu.txt \
    tun-proxy-tcp.txt \
    "tun-proxy-udp-${udp_payload_small}.txt" \
    "tun-proxy-udp-${udp_payload_large}.txt" \
    tun-proxy-cpu.txt; do
    if [[ -f "$tmp_dir/$file" ]]; then
        echo "===== $file ====="
        cat "$tmp_dir/$file"
    fi
done
