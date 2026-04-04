#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$repo_root/build-tun/socks}"
trace_server="${2:-0}"
target_mode="${3:-${TARGET_MODE:-local}}"

if [[ ! -x "$binary" ]]; then
    echo "binary not found: $binary" >&2
    exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
fi

ip link set lo up
mkdir -p /run/netns
mount -t tmpfs tmpfs /run >/dev/null 2>&1 || true
mkdir -p /run/netns

for cmd in ip python3 curl awk openssl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing dependency: $cmd" >&2
        exit 1
    fi
done

for helper in /tmp/test_connect_wrapper /tmp/test_async_connect_wrapper; do
    if [[ -x "$helper" ]]; then
        continue
    fi
    echo "missing helper: $helper" >&2
    exit 1
done

cleanup_stale_tests() {
    while read -r stale_pid; do
        if [[ -n "$stale_pid" ]] && [[ "$stale_pid" != "$$" ]]; then
            kill "$stale_pid" >/dev/null 2>&1 || true
        fi
    done < <(ps -eo pid=,args= | awk -v root="$repo_root" '/\.tmp-tun-test\./ && index($0, root) > 0 {print $1}')

    sleep 0.2
    while read -r stale_pid; do
        if [[ -n "$stale_pid" ]] && [[ "$stale_pid" != "$$" ]] && kill -0 "$stale_pid" >/dev/null 2>&1; then
            kill -9 "$stale_pid" >/dev/null 2>&1 || true
        fi
    done < <(ps -eo pid=,args= | awk -v root="$repo_root" '/\.tmp-tun-test\./ && index($0, root) > 0 {print $1}')

    while read -r ns_name; do
        if [[ -z "$ns_name" ]]; then
            continue
        fi
        while read -r ns_pid; do
            if [[ -n "$ns_pid" ]] && kill -0 "$ns_pid" >/dev/null 2>&1; then
                kill "$ns_pid" >/dev/null 2>&1 || true
            fi
        done < <(ip netns pids "$ns_name" 2>/dev/null || true)
        ip netns delete "$ns_name" >/dev/null 2>&1 || true
    done < <(ip netns list | awk '/^socks_tun_(app|client|target)_/ {print $1}')

    while read -r link_name; do
        if [[ -n "$link_name" ]]; then
            ip link delete "$link_name" >/dev/null 2>&1 || true
        fi
    done < <(ip -o link show | awk -F': ' '{print $2}' | awk '/^(th|ta|xh|xt)[0-9a-f]{4}$/ {print $1}')

    while read -r dev_name dev_cidr; do
        if [[ -n "$dev_name" ]] && [[ -n "$dev_cidr" ]]; then
            ip addr del "$dev_cidr" dev "$dev_name" >/dev/null 2>&1 || true
        fi
    done < <(ip -o -4 addr show | awk '$4 ~ /^10\.(213|214)\.[0-9]+\.2\/[0-9]+$/ {print $2, $4}')
}

cleanup_stale_tests

source "$repo_root/scripts/runtime_env.sh"
init_runtime_ld_library_path "$binary"

tmp_dir="$(mktemp -d "$repo_root/.tmp-tun-test.XXXXXX")"
chmod 755 "$tmp_dir"
keep_artifacts="${KEEP_TEST_ARTIFACTS:-0}"
artifact_uid="${SUDO_UID:-$(stat -c '%u' "$repo_root")}"
artifact_gid="${SUDO_GID:-$(stat -c '%g' "$repo_root")}"
tag="$(printf '%04x' "$(( $$ % 65536 ))")"
net_id="$(( (16#$tag % 200) + 20 ))"
ns_app="socks_tun_app_${tag}"
ns_client="socks_tun_client_${tag}"
ns_target="socks_tun_target_${tag}"
host_if="th${tag}"
client_host_if="tc${tag}"
client_app_if="ca${tag}"
app_if="ta${tag}"
host_ip="10.213.${net_id}.1"
client_host_ip="10.213.${net_id}.2"
client_app_ip="10.212.${net_id}.1"
app_ip="10.212.${net_id}.2"
app_cidr="${app_ip}/32"
target_host_if="xh${tag}"
target_if="xt${tag}"
target_host_ip="10.214.${net_id}.1"
target_ip="10.214.${net_id}.2"
target_cidr="${target_ip}/32"
tun_name="tun${tag}"
host_ip_forward_before="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
declare -a pids=()

read -r server_port http_port udp_port < <(
    python3 - <<'PY'
import socket

socks = []
ports = []
for _ in range(2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    ports.append(sock.getsockname()[1])
    socks.append(sock)

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.bind(("127.0.0.1", 0))
udp_port = udp_sock.getsockname()[1]

print(*ports, udp_port)

for sock in socks:
    sock.close()
udp_sock.close()
PY
)

cleanup() {
    local exit_code=$?
    trap - EXIT

    for pid in "${pids[@]:-}"; do
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
        fi
    done

    sleep 0.2
    for pid in "${pids[@]:-}"; do
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill -9 "$pid" >/dev/null 2>&1 || true
        fi
    done

    for pid in "${pids[@]:-}"; do
        if [[ -n "$pid" ]]; then
            wait "$pid" >/dev/null 2>&1 || true
        fi
    done

    for ns_name in "$ns_app" "$ns_client" "$ns_target"; do
        if ip netns list | awk '{print $1}' | grep -Fxq "$ns_name"; then
            while read -r ns_pid; do
                if [[ -n "$ns_pid" ]] && kill -0 "$ns_pid" >/dev/null 2>&1; then
                    kill "$ns_pid" >/dev/null 2>&1 || true
                fi
            done < <(ip netns pids "$ns_name" 2>/dev/null || true)
            ip netns delete "$ns_name" >/dev/null 2>&1 || true
        fi
    done

    ip link delete "$host_if" >/dev/null 2>&1 || true
    ip link delete "$target_host_if" >/dev/null 2>&1 || true
    ip addr del "$target_ip/32" dev lo >/dev/null 2>&1 || true
    if [[ -w /proc/sys/net/ipv4/ip_forward ]]; then
        printf '%s\n' "$host_ip_forward_before" >/proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    fi

    if [[ -d "$tmp_dir" ]]; then
        chown -R "$artifact_uid:$artifact_gid" "$tmp_dir" >/dev/null 2>&1 || true
        chmod -R u+rwX,go+rX "$tmp_dir" >/dev/null 2>&1 || true
    fi

    if [[ $exit_code -ne 0 ]]; then
        echo "tun test failed logs kept at $tmp_dir" >&2
        for log_file in "$tmp_dir"/*.log "$tmp_dir"/*.strace*; do
            if [[ -f "$log_file" ]]; then
                echo "===== $(basename "$log_file") =====" >&2
                tail -n 120 "$log_file" >&2 || true
            fi
        done
        exit "$exit_code"
    fi

    if [[ "$keep_artifacts" == "1" ]]; then
        echo "tun test artifacts kept at $tmp_dir"
    else
        rm -rf "$tmp_dir"
    fi
}

trap cleanup EXIT

wait_for_port() {
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

print(f"timeout waiting for {name} on {host}:{port}", file=sys.stderr)
sys.exit(1)
PY
}

wait_for_log() {
    local file="$1"
    local pattern="$2"
    local timeout_sec="${3:-15}"
    python3 - "$file" "$pattern" "$timeout_sec" <<'PY'
import pathlib
import sys
import time

path = pathlib.Path(sys.argv[1])
pattern = sys.argv[2]
timeout_sec = float(sys.argv[3])
deadline = time.time() + timeout_sec

while time.time() < deadline:
    if path.exists():
        data = path.read_text(encoding="utf-8", errors="replace")
        if pattern in data:
            sys.exit(0)
    time.sleep(0.2)

print(f"timeout waiting for log pattern {pattern!r} in {path}", file=sys.stderr)
sys.exit(1)
PY
}

assert_target_route() {
    local mode="$1"
    local route_text
    local root_target_addrs
    route_text="$(ip -4 route get "$target_ip" 2>&1 || true)"
    printf '%s\n' "$route_text" >"$tmp_dir/target-route.log"
    root_target_addrs="$(ip -o -4 addr show | awk -v target="$target_ip" '$4 ~ ("^" target "/") {print $2, $4}')"
    printf '%s\n' "$root_target_addrs" >"$tmp_dir/root-target-addr.log"
    ip -o -4 addr show >"$tmp_dir/root-addr.log" 2>&1 || true
    ip -o link show >"$tmp_dir/root-link.log" 2>&1 || true

    if [[ "$mode" == "netns" ]]; then
        if [[ -n "$root_target_addrs" ]]; then
            echo "unexpected root target address ownership for netns target: $root_target_addrs" >&2
            exit 1
        fi
        if grep -Eq '(^| )local( |$)| dev lo( |$)' <<<"$route_text"; then
            echo "unexpected root local route for netns target: $route_text" >&2
            exit 1
        fi
        if ! grep -Fq "dev $target_host_if" <<<"$route_text"; then
            echo "unexpected root route device for netns target: $route_text" >&2
            exit 1
        fi
        return
    fi

    if ! grep -Eq '(^| )local( |$)| dev lo( |$)' <<<"$route_text"; then
        echo "unexpected root route for local target: $route_text" >&2
        exit 1
    fi
}

run_step() {
    local name="$1"
    shift
    echo "[case] $name"
    "$@"
    echo "[ok] $name"
}

mkdir -p "$tmp_dir/http" "$tmp_dir/rules"
printf 'ok-tun\n' >"$tmp_dir/http/healthz.txt"
: >"$tmp_dir/rules/direct_ip.txt"
: >"$tmp_dir/rules/block_ip.txt"
: >"$tmp_dir/rules/direct_domain.txt"
: >"$tmp_dir/rules/block_domain.txt"
: >"$tmp_dir/rules/proxy_domain.txt"

key_output="$(env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" x25519)"
private_key="$(awk '/private key:/{print $3}' <<<"$key_output")"
public_key="$(awk '/public key:/{print $3}' <<<"$key_output")"
short_id="0102030405060708"
sni="${REALITY_SNI:-localhost}"

cat >"$tmp_dir/server.json" <<EOF
{
  "mode": "server",
  "workers": 1,
  "log": {
    "level": "debug",
    "file": "$tmp_dir/server.log"
  },
  "inbound": {
    "host": "$host_ip",
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
    "enabled": false
  },
  "tproxy": {
    "enabled": false,
    "listen_host": "::",
    "tcp_port": 0,
    "udp_port": 0,
    "mark": 17
  },
  "tun": {
    "enabled": true,
    "name": "$tun_name",
    "mtu": 1400,
    "ipv4": "198.18.0.1",
    "ipv4_prefix": 32,
    "ipv6": "fd00::1",
    "ipv6_prefix": 128
  },
  "outbound": {
    "host": "$host_ip",
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
    "max_connections": 8,
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

ip netns add "$ns_app"
ip netns add "$ns_client"
ip link add "$host_if" type veth peer name "$client_host_if"
ip link set "$client_host_if" netns "$ns_client"
ip addr add "$host_ip/24" dev "$host_if"
ip link set "$host_if" up
ip netns exec "$ns_client" ip addr add "$client_host_ip/24" dev "$client_host_if"
ip netns exec "$ns_client" ip link set lo up
ip netns exec "$ns_client" ip link set "$client_host_if" up
ip netns exec "$ns_client" ip route replace default via "$host_ip" dev "$client_host_if"

ip link add "$client_app_if" type veth peer name "$app_if"
ip link set "$client_app_if" netns "$ns_client"
ip link set "$app_if" netns "$ns_app"
ip netns exec "$ns_client" ip addr add "$client_app_ip/24" dev "$client_app_if"
ip netns exec "$ns_client" ip link set "$client_app_if" up
ip netns exec "$ns_app" ip addr add "$app_ip/24" dev "$app_if"
ip netns exec "$ns_app" ip link set lo up
ip netns exec "$ns_app" ip link set "$app_if" up
ip netns exec "$ns_app" ip route replace default via "$client_app_ip" dev "$app_if"

printf '1\n' >/proc/sys/net/ipv4/ip_forward
ip netns exec "$ns_client" sh -c 'printf "1\n" >/proc/sys/net/ipv4/ip_forward'

if [[ "$target_mode" == "netns" ]]; then
    ip netns add "$ns_target"
    ip link add "$target_host_if" type veth peer name "$target_if"
    ip link set "$target_if" netns "$ns_target"
    ip addr add "$target_host_ip/24" dev "$target_host_if"
    ip link set "$target_host_if" up
    ip netns exec "$ns_target" ip addr add "$target_ip/24" dev "$target_if"
    ip netns exec "$ns_target" ip link set lo up
    ip netns exec "$ns_target" ip link set "$target_if" up
    ip netns exec "$ns_target" ip route replace default via "$target_host_ip" dev "$target_if"

    ip netns exec "$ns_target" \
        python3 "$repo_root/scripts/test_http_server.py" --host "$target_ip" --port "$http_port" --directory "$tmp_dir/http" >"$tmp_dir/http.log" 2>&1 &
    pids+=("$!")

    ip netns exec "$ns_target" \
        python3 "$repo_root/scripts/socks5_udp_echo_server.py" --host "$target_ip" --port "$udp_port" >"$tmp_dir/udp-echo.log" 2>&1 &
    pids+=("$!")

    ip netns exec "$ns_target" ip -o -4 addr show >"$tmp_dir/target-ns-addr.log" 2>&1 || true
    ip netns exec "$ns_target" ip -o link show >"$tmp_dir/target-ns-link.log" 2>&1 || true
else
    ip addr add "$target_ip/32" dev lo
    python3 "$repo_root/scripts/test_http_server.py" --host "$target_ip" --port "$http_port" --directory "$tmp_dir/http" >"$tmp_dir/http.log" 2>&1 &
    pids+=("$!")

    python3 "$repo_root/scripts/socks5_udp_echo_server.py" --host "$target_ip" --port "$udp_port" >"$tmp_dir/udp-echo.log" 2>&1 &
    pids+=("$!")
fi

if [[ "$sni" == "localhost" ]]; then
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
    wait_for_port 127.0.0.1 443 "origin_tls"
fi

assert_target_route "$target_mode"

wait_for_port "$target_ip" "$http_port" "http_target"

run_step "host tcp target ready" \
    python3 "$repo_root/scripts/tproxy_tcp_client.py" \
        --host "$target_ip" \
        --port "$http_port" \
        --path "/healthz.txt" \
        --expect-substring "ok-tun"

run_step "host udp target ready" \
    python3 "$repo_root/scripts/tproxy_udp_client.py" \
        --host "$target_ip" \
        --port "$udp_port" \
        --payload "host-udp-echo" \
        --expect-echo

if [[ "$trace_server" == "1" ]]; then
    strace -ff -s 128 -tt -e trace=socket,setsockopt,bind,connect,getsockname \
        -o "$tmp_dir/server.strace" \
        env LD_LIBRARY_PATH="$runtime_ld_library_path" SOCKS_CONFIG_DIR="$tmp_dir/rules" "$binary" -c "$tmp_dir/server.json" \
        >"$tmp_dir/server.stdout.log" 2>&1 &
    server_pid=$!
else
    env LD_LIBRARY_PATH="$runtime_ld_library_path" SOCKS_CONFIG_DIR="$tmp_dir/rules" "$binary" -c "$tmp_dir/server.json" >"$tmp_dir/server.stdout.log" 2>&1 &
    server_pid=$!
fi
pids+=("$server_pid")

ip netns exec "$ns_client" env LD_LIBRARY_PATH="$runtime_ld_library_path" SOCKS_CONFIG_DIR="$tmp_dir/rules" "$binary" -c "$tmp_dir/client.json" >"$tmp_dir/client.stdout.log" 2>&1 &
client_pid=$!
pids+=("$client_pid")

wait_for_port "$host_ip" "$server_port" "reality_server"
wait_for_log "$tmp_dir/client.log" "tun client started name $tun_name" 20
host_netns_id="$(readlink /proc/$$/ns/net)"
server_netns_id="$(readlink /proc/$server_pid/ns/net)"
if [[ "$host_netns_id" != "$server_netns_id" ]]; then
    echo "server netns mismatch: host=$host_netns_id server=$server_netns_id" >&2
    exit 1
fi
ip netns exec "$ns_client" ip link show "$tun_name" >/dev/null
/usr/bin/bash "$repo_root/scripts/tun_linux_route.sh" --netns "$ns_client" --from "$app_cidr" --table 100 up "$tun_name" "$target_cidr" >/dev/null
ip netns exec "$ns_client" ip rule show >"$tmp_dir/client-policy-rule.log" 2>&1 || true
ip netns exec "$ns_client" ip route show table 100 >"$tmp_dir/client-policy-route.log" 2>&1 || true

run_step "host tcp target ready after tunnel start" \
    python3 "$repo_root/scripts/tproxy_tcp_client.py" \
        --host "$target_ip" \
        --port "$http_port" \
        --path "/healthz.txt" \
        --expect-substring "ok-tun"

run_step "host udp target ready after tunnel start" \
    python3 "$repo_root/scripts/tproxy_udp_client.py" \
        --host "$target_ip" \
        --port "$udp_port" \
        --payload "host-udp-echo-after-start" \
        --expect-echo

run_step "host boost connect ready after tunnel start" \
    /tmp/test_connect_wrapper "$target_ip" "$http_port"

run_step "host async boost connect ready after tunnel start" \
    /tmp/test_async_connect_wrapper "$target_ip" "$http_port" 5

run_step "host socks binary connect ready after tunnel start" \
    env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" probe-connect "$target_ip" "$http_port" 5

run_step "host socks threaded connect ready after tunnel start" \
env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" probe-connect-thread "$target_ip" "$http_port" 5

timeout 5 tcpdump -nn -l -i any "host $target_ip and tcp port $http_port" >"$tmp_dir/target-tcpdump.log" 2>&1 &
pids+=("$!")

run_step "host tcp target ready under capture" \
    python3 "$repo_root/scripts/tproxy_tcp_client.py" \
        --host "$target_ip" \
        --port "$http_port" \
        --path "/healthz.txt" \
        --expect-substring "ok-tun"

run_step "tun tcp proxy smoke" \
    ip netns exec "$ns_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" \
        --host "$target_ip" \
        --port "$http_port" \
        --path "/healthz.txt" \
        --expect-substring "ok-tun"

run_step "tun udp proxy smoke" \
    ip netns exec "$ns_app" python3 "$repo_root/scripts/tproxy_udp_client.py" \
        --host "$target_ip" \
        --port "$udp_port" \
        --payload "tun-udp-echo" \
        --expect-echo

wait_for_log "$tmp_dir/client.log" "tun client started name $tun_name" 5

echo "tun tcp proxy smoke ok"
echo "tun udp proxy smoke ok"
