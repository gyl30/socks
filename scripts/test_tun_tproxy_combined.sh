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

source "$repo_root/scripts/runtime_env.sh"

ip link set lo up
ensure_netns_mountpoint /run/netns

for cmd in ip iptables python3 openssl awk; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing dependency: $cmd" >&2
        exit 1
    fi
done

init_runtime_ld_library_path "$binary"

tmp_dir="${ARTIFACT_DIR:-$(mktemp -d "$repo_root/.tmp-tun-tproxy.XXXXXX")}"
mkdir -p "$tmp_dir"

keep_artifacts="${KEEP_TEST_ARTIFACTS:-1}"
artifact_uid="${SUDO_UID:-$(stat -c '%u' "$repo_root")}"
artifact_gid="${SUDO_GID:-$(stat -c '%g' "$repo_root")}"
tag="$(printf '%04x' "$(( $$ % 65536 ))")"
net_id="$(( (16#$tag % 200) + 20 ))"

ns_tun_app="socks_combo_tun_${tag}"
ns_tp_app="socks_combo_tp_${tag}"
ns_client="socks_combo_client_${tag}"
ns_target="socks_combo_target_${tag}"

host_if="ch${tag}"
client_host_if="cc${tag}"
client_tun_if="ct${tag}"
tun_app_if="ta${tag}"
client_tp_if="cp${tag}"
tp_app_if="tp${tag}"
target_host_if="xh${tag}"
target_if="xt${tag}"

host_ip="10.213.${net_id}.1"
client_host_ip="10.213.${net_id}.2"
client_tun_ip="10.212.${net_id}.1"
tun_app_ip="10.212.${net_id}.2"
tun_app_cidr="${tun_app_ip}/32"
client_tp_ip="10.211.${net_id}.1"
tp_app_ip="10.211.${net_id}.2"
target_host_ip="10.214.${net_id}.1"
direct_ip="10.214.${net_id}.2"
proxy_ip="10.214.${net_id}.3"
target_cidrs=("${direct_ip}/32" "${proxy_ip}/32")
tun_name="tun${tag}"
tproxy_tcp_port=15080
tproxy_udp_port=15081

host_ip_forward_before="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
declare -a pids=()

read -r server_port http_port udp_port < <(
    python3 - <<'PY'
import socket

ports = []
sockets = []
for _ in range(2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    ports.append(sock.getsockname()[1])
    sockets.append(sock)

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.bind(("127.0.0.1", 0))
udp_port = udp_sock.getsockname()[1]

print(ports[0], ports[1], udp_port)

for sock in sockets:
    sock.close()
udp_sock.close()
PY
)

ns_exec() {
    local ns="$1"
    shift
    ip netns exec "$ns" "$@"
}

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

configure_namespace_sysctls() {
    local ns="$1"
    shift
    ns_exec "$ns" sysctl -q -w net.ipv4.ip_forward=1
    ns_exec "$ns" sysctl -q -w net.ipv4.conf.all.rp_filter=0
    ns_exec "$ns" sysctl -q -w net.ipv4.conf.default.rp_filter=0
    for iface in "$@"; do
        ns_exec "$ns" sysctl -q -w "net.ipv4.conf.${iface}.rp_filter=0"
    done
}

run_step() {
    local name="$1"
    shift
    echo "[case] $name"
    "$@"
    echo "[ok] $name"
}

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

    for ns_name in "$ns_tun_app" "$ns_tp_app" "$ns_client" "$ns_target"; do
        ip netns delete "$ns_name" >/dev/null 2>&1 || true
    done
    ip link delete "$host_if" >/dev/null 2>&1 || true
    ip link delete "$target_host_if" >/dev/null 2>&1 || true
    if [[ -w /proc/sys/net/ipv4/ip_forward ]]; then
        printf '%s\n' "$host_ip_forward_before" >/proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    fi

    if [[ -d "$tmp_dir" ]]; then
        chown -R "$artifact_uid:$artifact_gid" "$tmp_dir" >/dev/null 2>&1 || true
        chmod -R u+rwX,go+rX "$tmp_dir" >/dev/null 2>&1 || true
    fi

    if [[ $rc -ne 0 ]]; then
        echo "combined tun tproxy test failed logs kept at $tmp_dir" >&2
        for log_file in "$tmp_dir"/*.log "$tmp_dir"/*.txt; do
            if [[ -f "$log_file" ]]; then
                echo "===== $(basename "$log_file") =====" >&2
                tail -n 120 "$log_file" >&2 || true
            fi
        done
        exit "$rc"
    fi

    if [[ "$keep_artifacts" == "1" ]]; then
        echo "combined tun tproxy artifacts kept at $tmp_dir"
    else
        rm -rf "$tmp_dir"
    fi
}

trap cleanup EXIT

mkdir -p "$tmp_dir/http" "$tmp_dir/rules"
printf 'combo-ok\n' >"$tmp_dir/http/healthz.txt"
printf '%s/32\n' "$direct_ip" >"$tmp_dir/rules/direct_ip.txt"
: >"$tmp_dir/rules/block_ip.txt"
: >"$tmp_dir/rules/direct_domain.txt"
: >"$tmp_dir/rules/block_domain.txt"
: >"$tmp_dir/rules/proxy_domain.txt"

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

cat >"$tmp_dir/client.json" <<EOF
{
  "workers": 1,
  "log": {"level": "debug", "file": "$tmp_dir/client.log"},
  "inbounds": [
    {
      "type": "tproxy",
      "tag": "tproxy-in",
      "settings": {
        "listen_host": "0.0.0.0",
        "tcp_port": $tproxy_tcp_port,
        "udp_port": $tproxy_udp_port,
        "mark": 17
      }
    },
    {
      "type": "tun",
      "tag": "tun-in",
      "settings": {
        "name": "$tun_name",
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
    {"type": "ip", "file": "$tmp_dir/rules/direct_ip.txt", "out": "direct"},
    {"type": "inbound", "values": ["tun-in", "tproxy-in"], "out": "reality-out"}
  ],
  "timeout": {"read": 5, "write": 5, "connect": 5, "idle": 30}
}
EOF

ip netns add "$ns_tun_app"
ip netns add "$ns_tp_app"
ip netns add "$ns_client"
ip netns add "$ns_target"

ip link add "$host_if" type veth peer name "$client_host_if"
ip link set "$client_host_if" netns "$ns_client"
ip addr add "$host_ip/24" dev "$host_if"
ip link set "$host_if" up
ns_exec "$ns_client" ip link set lo up
ns_exec "$ns_client" ip addr add "$client_host_ip/24" dev "$client_host_if"
ns_exec "$ns_client" ip link set "$client_host_if" up
ns_exec "$ns_client" ip route replace default via "$host_ip" dev "$client_host_if"

ip link add "$client_tun_if" type veth peer name "$tun_app_if"
ip link set "$client_tun_if" netns "$ns_client"
ip link set "$tun_app_if" netns "$ns_tun_app"
ns_exec "$ns_client" ip addr add "$client_tun_ip/24" dev "$client_tun_if"
ns_exec "$ns_client" ip link set "$client_tun_if" up
ns_exec "$ns_tun_app" ip link set lo up
ns_exec "$ns_tun_app" ip addr add "$tun_app_ip/24" dev "$tun_app_if"
ns_exec "$ns_tun_app" ip link set "$tun_app_if" up
ns_exec "$ns_tun_app" ip route replace default via "$client_tun_ip" dev "$tun_app_if"

ip link add "$client_tp_if" type veth peer name "$tp_app_if"
ip link set "$client_tp_if" netns "$ns_client"
ip link set "$tp_app_if" netns "$ns_tp_app"
ns_exec "$ns_client" ip addr add "$client_tp_ip/24" dev "$client_tp_if"
ns_exec "$ns_client" ip link set "$client_tp_if" up
ns_exec "$ns_tp_app" ip link set lo up
ns_exec "$ns_tp_app" ip addr add "$tp_app_ip/24" dev "$tp_app_if"
ns_exec "$ns_tp_app" ip link set "$tp_app_if" up
ns_exec "$ns_tp_app" ip route replace default via "$client_tp_ip" dev "$tp_app_if"

ip link add "$target_host_if" type veth peer name "$target_if"
ip link set "$target_if" netns "$ns_target"
ip addr add "$target_host_ip/24" dev "$target_host_if"
ip link set "$target_host_if" up
ns_exec "$ns_target" ip link set lo up
ns_exec "$ns_target" ip addr add "${direct_ip}/24" dev "$target_if"
ns_exec "$ns_target" ip addr add "${proxy_ip}/24" dev "$target_if"
ns_exec "$ns_target" ip link set "$target_if" up
ns_exec "$ns_target" ip route replace default via "$target_host_ip" dev "$target_if"

printf '1\n' >/proc/sys/net/ipv4/ip_forward
configure_namespace_sysctls "$ns_client" "$client_host_if" "$client_tun_if" "$client_tp_if"

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

ns_exec "$ns_target" python3 "$repo_root/scripts/test_http_server.py" --host "$direct_ip" --port "$http_port" --directory "$tmp_dir/http" >"$tmp_dir/direct-http.log" 2>&1 &
pids+=("$!")
ns_exec "$ns_target" python3 "$repo_root/scripts/test_http_server.py" --host "$proxy_ip" --port "$http_port" --directory "$tmp_dir/http" >"$tmp_dir/proxy-http.log" 2>&1 &
pids+=("$!")
ns_exec "$ns_target" python3 "$repo_root/scripts/socks5_udp_echo_server.py" --host "$direct_ip" --port "$udp_port" >"$tmp_dir/direct-udp.log" 2>&1 &
pids+=("$!")
ns_exec "$ns_target" python3 "$repo_root/scripts/socks5_udp_echo_server.py" --host "$proxy_ip" --port "$udp_port" >"$tmp_dir/proxy-udp.log" 2>&1 &
pids+=("$!")

wait_for_port "$direct_ip" "$http_port" direct_http
wait_for_port "$proxy_ip" "$http_port" proxy_http

env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$tmp_dir/server.json" >"$tmp_dir/server.stdout.log" 2>&1 &
server_pid=$!
pids+=("$server_pid")
wait_for_port "$host_ip" "$server_port" reality_server

ns_exec "$ns_client" env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" -c "$tmp_dir/client.json" >"$tmp_dir/client.stdout.log" 2>&1 &
client_pid=$!
pids+=("$client_pid")

wait_for_log "$tmp_dir/client.log" "tun inbound started" 20
wait_for_log "$tmp_dir/client.log" "tproxy tcp listening on 0.0.0.0:$tproxy_tcp_port" 20
wait_for_log "$tmp_dir/client.log" "tproxy udp listening on 0.0.0.0:$tproxy_udp_port" 20

/usr/bin/bash "$repo_root/scripts/tun_linux_route.sh" --netns "$ns_client" --from "$tun_app_cidr" --table 101 --priority 90 up "$tun_name" "${target_cidrs[@]}" >/dev/null
ns_exec "$ns_client" ip rule show >"$tmp_dir/client-policy-rule.log" 2>&1 || true
ns_exec "$ns_client" ip route show table 101 >"$tmp_dir/client-policy-route.log" 2>&1 || true
ns_exec "$ns_client" ip rule add pref 100 fwmark 0x11 iif "$client_tp_if" lookup 100
ns_exec "$ns_client" ip route add local 0.0.0.0/0 dev lo table 100

for ip_addr in "$direct_ip" "$proxy_ip"; do
    ns_exec "$ns_client" iptables -t mangle -A PREROUTING -i "$client_tp_if" -p tcp -d "$ip_addr" --dport "$http_port" \
        -j TPROXY --on-ip "$client_tp_ip" --on-port "$tproxy_tcp_port" --tproxy-mark 0x11/0x11
    ns_exec "$ns_client" iptables -t mangle -A PREROUTING -i "$client_tp_if" -p udp -d "$ip_addr" --dport "$udp_port" \
        -j TPROXY --on-ip "$client_tp_ip" --on-port "$tproxy_udp_port" --tproxy-mark 0x11/0x11
done

run_step "tun tcp direct" \
    ns_exec "$ns_tun_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" \
        --host "$direct_ip" \
        --port "$http_port" \
        --path "/healthz.txt" \
        --expect-substring "combo-ok"

run_step "tun tcp proxy" \
    ns_exec "$ns_tun_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" \
        --host "$proxy_ip" \
        --port "$http_port" \
        --path "/healthz.txt" \
        --expect-substring "combo-ok"

run_step "tun udp direct" \
    ns_exec "$ns_tun_app" python3 "$repo_root/scripts/tproxy_udp_client.py" \
        --host "$direct_ip" \
        --port "$udp_port" \
        --payload "tun-direct" \
        --expect-echo

run_step "tun udp proxy" \
    ns_exec "$ns_tun_app" python3 "$repo_root/scripts/tproxy_udp_client.py" \
        --host "$proxy_ip" \
        --port "$udp_port" \
        --payload "tun-proxy" \
        --expect-echo

run_step "tproxy tcp direct" \
    ns_exec "$ns_tp_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" \
        --host "$direct_ip" \
        --port "$http_port" \
        --path "/healthz.txt" \
        --expect-substring "combo-ok"

run_step "tproxy tcp proxy" \
    ns_exec "$ns_tp_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" \
        --host "$proxy_ip" \
        --port "$http_port" \
        --path "/healthz.txt" \
        --expect-substring "combo-ok"

run_step "tproxy udp direct" \
    ns_exec "$ns_tp_app" python3 "$repo_root/scripts/tproxy_udp_client.py" \
        --host "$direct_ip" \
        --port "$udp_port" \
        --payload "tproxy-direct" \
        --expect-echo

run_step "tproxy udp proxy" \
    ns_exec "$ns_tp_app" python3 "$repo_root/scripts/tproxy_udp_client.py" \
        --host "$proxy_ip" \
        --port "$udp_port" \
        --payload "tproxy-proxy" \
        --expect-echo

wait_for_log "$tmp_dir/client.log" "target ${direct_ip}:${http_port} route direct" 5
wait_for_log "$tmp_dir/client.log" "target ${proxy_ip}:${http_port} route proxy" 5

echo "combined tun tproxy smoke ok"
