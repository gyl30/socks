#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$repo_root/build-review/socks}"

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

for cmd in awk ip iptables python3 openssl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing dependency: $cmd" >&2
        exit 1
    fi
done

tmp_dir="$(mktemp -d "$repo_root/.tmp-tproxy-test.XXXXXX")"
keep_artifacts="${KEEP_TEST_ARTIFACTS:-1}"
artifact_uid="${SUDO_UID:-$(stat -c '%u' "$repo_root")}"
artifact_gid="${SUDO_GID:-$(stat -c '%g' "$repo_root")}"
tag="$(printf '%04x' "$(( $$ % 65536 ))")"
sni="${REALITY_SNI:-localhost}"
uplink_if=""

source "$repo_root/scripts/runtime_env.sh"
init_runtime_ld_library_path "$binary"

resolv_source=""
if [[ "$sni" != "localhost" ]]; then
    uplink_if="${TPROXY_UPLINK_IF:-$(ip route show default 0.0.0.0/0 | awk '/default/ {print $5; exit}')}"
    if [[ -z "$uplink_if" ]]; then
        echo "failed to detect host uplink interface; set TPROXY_UPLINK_IF explicitly" >&2
        exit 1
    fi

    if grep -Eq '^[[:space:]]*nameserver[[:space:]]+(127\.0\.0\.(1|53)|::1)[[:space:]]*$' /etc/resolv.conf; then
        resolv_source="/run/systemd/resolve/resolv.conf"
    else
        resolv_source="/etc/resolv.conf"
    fi

    if [[ ! -f "$resolv_source" ]]; then
        echo "dns resolver source not found: $resolv_source" >&2
        exit 1
    fi

    if ! grep -Eq '^[[:space:]]*nameserver[[:space:]]+([^[:space:]]+)' "$resolv_source"; then
        echo "dns resolver source has no nameserver entries: $resolv_source" >&2
        exit 1
    fi
fi

host_ip_forward_before="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"

ns_app="socks_tp_app_${tag}"
ns_mid="socks_tp_mid_${tag}"
ns_wan="socks_tp_wan_${tag}"

app_if="ta${tag}"
mid_app_if="tma${tag}"
mid_wan_if="tmw${tag}"
wan_if="tw${tag}"
mid_host_if="tmh${tag}"
host_if="th${tag}"

app_ip="10.200.1.2"
mid_app_ip="10.200.1.1"
mid_wan_ip="10.200.2.1"
wan_ip="10.200.2.2"
mid_host_ip="10.200.3.2"
host_ip="10.200.3.1"
routed_subnet="10.200.0.0/16"

server_port=18443
tproxy_tcp_port=15080
tproxy_udp_port=15081

direct_tcp_ip="36.1.0.2"
direct_tcp_port=18080
direct_tcp_drop_ip="36.1.0.3"
direct_tcp_drop_port=18083
direct_udp_ip="36.1.0.2"
direct_udp_port=18081
direct_udp_blackhole_ip="36.1.0.4"
direct_udp_blackhole_port=18082

proxy_tcp_ip="9.9.9.2"
proxy_tcp_port=28080
proxy_tcp_drop_ip="9.9.9.3"
proxy_tcp_drop_port=28083
proxy_udp_ip="9.9.9.2"
proxy_udp_port=28081
proxy_udp_blackhole_ip="9.9.9.4"
proxy_udp_blackhole_port=28082

client_log="$tmp_dir/tproxy-client.log"
server_log="$tmp_dir/reality-server.log"

declare -a pids=()

ns_exists() {
    ip netns list | awk '{print $1}' | grep -Fxq "$1"
}

ns_exec() {
    local ns="$1"
    shift
    ip netns exec "$ns" "$@"
}

prepare_namespace_resolv_conf() {
    local ns="$1"
    local dir="/etc/netns/$ns"
    mkdir -p "$dir"
    {
        grep -E '^[[:space:]]*nameserver[[:space:]]+' "$resolv_source" | awk '$2 !~ /^127\./ && $2 != "::1" {print $0}'
        grep -E '^[[:space:]]*search[[:space:]]+' "$resolv_source" || true
        grep -E '^[[:space:]]*options[[:space:]]+' "$resolv_source" || true
    } >"$dir/resolv.conf"

    if ! grep -Eq '^[[:space:]]*nameserver[[:space:]]+' "$dir/resolv.conf"; then
        echo "no non-loopback nameserver available for namespace $ns from $resolv_source" >&2
        exit 1
    fi
}

verify_external_tls_reachability() {
    local ns="$1"
    local host="$2"
    ns_exec "$ns" python3 - "$host" <<'PY'
import socket
import sys

host = sys.argv[1]
port = 443

try:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
except OSError as exc:
    print(f"dns lookup failed for {host}: {exc}", file=sys.stderr)
    sys.exit(1)

last_error = None
for family, socktype, proto, _, sockaddr in infos:
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(5.0)
    try:
        sock.connect(sockaddr)
        sock.close()
        sys.exit(0)
    except OSError as exc:
        last_error = exc
    finally:
        sock.close()

print(f"tcp connect failed for {host}:{port}: {last_error}", file=sys.stderr)
sys.exit(1)
PY
}

cleanup() {
    local exit_code=$?
    trap - EXIT

    for pid in "${pids[@]:-}"; do
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
            wait "$pid" >/dev/null 2>&1 || true
        fi
    done

    if [[ -n "$uplink_if" ]]; then
        iptables -t nat -D POSTROUTING -s "$routed_subnet" -o "$uplink_if" -j MASQUERADE >/dev/null 2>&1 || true
        iptables -D FORWARD -i "$host_if" -o "$uplink_if" -j ACCEPT >/dev/null 2>&1 || true
        iptables -D FORWARD -i "$uplink_if" -o "$host_if" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || true
        ip route del "$routed_subnet" via "$mid_host_ip" dev "$host_if" >/dev/null 2>&1 || true
    fi
    ip link delete "$host_if" >/dev/null 2>&1 || true
    sysctl -q -w net.ipv4.ip_forward="$host_ip_forward_before" >/dev/null 2>&1 || true

    for ns in "$ns_app" "$ns_mid" "$ns_wan"; do
        if ns_exists "$ns"; then
            while read -r ns_pid; do
                if [[ -n "$ns_pid" ]] && kill -0 "$ns_pid" >/dev/null 2>&1; then
                    kill "$ns_pid" >/dev/null 2>&1 || true
                fi
            done < <(ip netns pids "$ns" 2>/dev/null || true)
            ip netns delete "$ns" >/dev/null 2>&1 || true
        fi
        rm -rf "/etc/netns/$ns" >/dev/null 2>&1 || true
    done

    if [[ -d "$tmp_dir" ]]; then
        chown -R "$artifact_uid:$artifact_gid" "$tmp_dir" >/dev/null 2>&1 || true
        chmod -R u+rwX,go+rX "$tmp_dir" >/dev/null 2>&1 || true
    fi

    if [[ $exit_code -ne 0 ]]; then
        echo "tproxy test failed logs kept at $tmp_dir" >&2
        for log_file in "$tmp_dir"/*.log; do
            if [[ -f "$log_file" ]]; then
                echo "===== $(basename "$log_file") =====" >&2
                tail -n 120 "$log_file" >&2 || true
            fi
        done
        exit "$exit_code"
    fi

    if [[ "$keep_artifacts" == "1" ]]; then
        echo "tproxy test artifacts kept at $tmp_dir"
    else
        rm -rf "$tmp_dir"
    fi
}

trap cleanup EXIT

run_step() {
    local name="$1"
    shift
    echo "[case] $name"
    "$@"
    echo "[ok] $name"
}

run_expect_failure() {
    local name="$1"
    shift
    echo "[case] $name"
    if "$@"; then
        echo "expected failure but command succeeded: $name" >&2
        exit 1
    fi
    echo "[ok] $name expected failure observed"
}

log_line_count() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        echo 0
        return
    fi
    wc -l <"$file"
}

wait_log_pattern_since() {
    local file="$1"
    local start_line="$2"
    local pattern="$3"
    local timeout_sec="$4"
    python3 - "$file" "$start_line" "$pattern" "$timeout_sec" <<'PY'
import pathlib
import sys
import time

file_path = pathlib.Path(sys.argv[1])
start_line = int(sys.argv[2])
pattern = sys.argv[3]
timeout_sec = float(sys.argv[4])
deadline = time.time() + timeout_sec

while time.time() < deadline:
    if file_path.exists():
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[start_line:]:
            if pattern in line:
                sys.exit(0)
    time.sleep(0.2)

sys.exit(1)
PY
}

wait_tunnel_pool_ready() {
    local timeout_sec="${1:-8}"
    local start_line
    start_line="$(log_line_count "$client_log")"
    wait_log_pattern_since "$client_log" "$start_line" "tunnel installed" "$timeout_sec"
}

print_log_count() {
    local label="$1"
    local file="$2"
    local pattern="$3"
    local count=0
    if [[ -f "$file" ]]; then
        count="$(grep -Fc "$pattern" "$file" || true)"
    fi
    echo "$label=$count"
}

wait_tcp_port() {
    local ns="$1"
    local host="$2"
    local port="$3"
    local name="$4"
    python3 - "$ns" "$host" "$port" "$name" <<'PY'
import subprocess
import sys
import time

ns = sys.argv[1]
host = sys.argv[2]
port = sys.argv[3]
name = sys.argv[4]
deadline = time.time() + 10.0

while time.time() < deadline:
    result = subprocess.run(
        ["ip", "netns", "exec", ns, "python3", "-c", (
            "import socket,sys;"
            f"s=socket.socket();"
            "s.settimeout(0.2);"
            f"s.connect(({host!r},{int(port)}));"
            "s.close()"
        )],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        sys.exit(0)
    time.sleep(0.2)

print(f"timeout waiting for {name} {host}:{port}", file=sys.stderr)
sys.exit(1)
PY
}

start_in_ns() {
    local ns="$1"
    local log_file="$2"
    shift 2
    ns_exec "$ns" "$@" >"$log_file" 2>&1 &
    local pid=$!
    pids+=("$pid")
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

echo "[setup] create isolated network namespaces"
ip netns add "$ns_app"
ip netns add "$ns_mid"
ip netns add "$ns_wan"

ip link add "$app_if" type veth peer name "$mid_app_if"
ip link add "$mid_wan_if" type veth peer name "$wan_if"
ip link add "$host_if" type veth peer name "$mid_host_if"

ip link set "$app_if" netns "$ns_app"
ip link set "$mid_app_if" netns "$ns_mid"
ip link set "$mid_wan_if" netns "$ns_mid"
ip link set "$wan_if" netns "$ns_wan"
ip link set "$mid_host_if" netns "$ns_mid"

if [[ "$sni" != "localhost" ]]; then
    prepare_namespace_resolv_conf "$ns_wan"
fi

ns_exec "$ns_app" ip link set lo up
ns_exec "$ns_app" ip addr add "${app_ip}/24" dev "$app_if"
ns_exec "$ns_app" ip link set "$app_if" up
ns_exec "$ns_app" ip route add default via "$mid_app_ip"

ip addr add "${host_ip}/24" dev "$host_if"
ip link set "$host_if" up
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w "net.ipv4.conf.${host_if}.rp_filter=0"
if [[ -n "$uplink_if" ]]; then
    echo "[setup] attach host uplink $uplink_if to isolated topology"
    ip route add "$routed_subnet" via "$mid_host_ip" dev "$host_if"
    iptables -A FORWARD -i "$host_if" -o "$uplink_if" -j ACCEPT
    iptables -A FORWARD -i "$uplink_if" -o "$host_if" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -A POSTROUTING -s "$routed_subnet" -o "$uplink_if" -j MASQUERADE
fi

ns_exec "$ns_mid" ip link set lo up
ns_exec "$ns_mid" ip addr add "${mid_app_ip}/24" dev "$mid_app_if"
ns_exec "$ns_mid" ip addr add "${mid_wan_ip}/24" dev "$mid_wan_if"
ns_exec "$ns_mid" ip addr add "${mid_host_ip}/24" dev "$mid_host_if"
ns_exec "$ns_mid" ip link set "$mid_app_if" up
ns_exec "$ns_mid" ip link set "$mid_wan_if" up
ns_exec "$ns_mid" ip link set "$mid_host_if" up
configure_namespace_sysctls "$ns_mid" "$mid_app_if" "$mid_wan_if" "$mid_host_if"
ns_exec "$ns_mid" ip route add "${direct_tcp_ip}/32" via "$wan_ip"
ns_exec "$ns_mid" ip route add "${direct_tcp_drop_ip}/32" via "$wan_ip"
ns_exec "$ns_mid" ip route add "${direct_udp_blackhole_ip}/32" via "$wan_ip"
ns_exec "$ns_mid" ip route add "${proxy_tcp_ip}/32" via "$wan_ip"
ns_exec "$ns_mid" ip route add "${proxy_tcp_drop_ip}/32" via "$wan_ip"
ns_exec "$ns_mid" ip route add "${proxy_udp_blackhole_ip}/32" via "$wan_ip"
if [[ -n "$uplink_if" ]]; then
    ns_exec "$ns_mid" ip route add default via "$host_ip"
fi
ns_exec "$ns_mid" ip rule add pref 100 fwmark 0x11 iif "$mid_app_if" lookup 100
ns_exec "$ns_mid" ip route add local 0.0.0.0/0 dev lo table 100

ns_exec "$ns_wan" ip link set lo up
ns_exec "$ns_wan" ip addr add "${wan_ip}/24" dev "$wan_if"
ns_exec "$ns_wan" ip link set "$wan_if" up
ns_exec "$ns_wan" ip addr add "${direct_tcp_ip}/32" dev lo
ns_exec "$ns_wan" ip addr add "${direct_tcp_drop_ip}/32" dev lo
ns_exec "$ns_wan" ip addr add "${direct_udp_blackhole_ip}/32" dev lo
ns_exec "$ns_wan" ip addr add "${proxy_tcp_ip}/32" dev lo
ns_exec "$ns_wan" ip addr add "${proxy_tcp_drop_ip}/32" dev lo
ns_exec "$ns_wan" ip addr add "${proxy_udp_blackhole_ip}/32" dev lo
ns_exec "$ns_wan" ip route add default via "$mid_wan_ip"

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
    start_in_ns "$ns_wan" "$tmp_dir/origin.stdout.log" openssl s_server -accept 127.0.0.1:443 -www -tls1_3 -cert "$tmp_dir/origin.crt" -key "$tmp_dir/origin.key"
    wait_tcp_port "$ns_wan" 127.0.0.1 443 "origin_tls"
fi

echo "[setup] verify tls reachability from $ns_wan to $sni:443"
verify_external_tls_reachability "$ns_wan" "$sni"

echo "[setup] install TPROXY rules inside $ns_mid"
for ip_port in \
    "${direct_tcp_ip}:${direct_tcp_port}" \
    "${direct_tcp_drop_ip}:${direct_tcp_drop_port}" \
    "${proxy_tcp_ip}:${proxy_tcp_port}" \
    "${proxy_tcp_drop_ip}:${proxy_tcp_drop_port}"
do
    ip_addr="${ip_port%:*}"
    ip_port_num="${ip_port#*:}"
    ns_exec "$ns_mid" iptables -t mangle -A PREROUTING -i "$mid_app_if" -p tcp -d "$ip_addr" --dport "$ip_port_num" \
        -j TPROXY --on-ip "$mid_app_ip" --on-port "$tproxy_tcp_port" --tproxy-mark 0x11/0x11
done

for ip_port in \
    "${direct_udp_ip}:${direct_udp_port}" \
    "${direct_udp_blackhole_ip}:${direct_udp_blackhole_port}" \
    "${proxy_udp_ip}:${proxy_udp_port}" \
    "${proxy_udp_blackhole_ip}:${proxy_udp_blackhole_port}"
do
    ip_addr="${ip_port%:*}"
    ip_port_num="${ip_port#*:}"
    ns_exec "$ns_mid" iptables -t mangle -A PREROUTING -i "$mid_app_if" -p udp -d "$ip_addr" --dport "$ip_port_num" \
        -j TPROXY --on-ip "$mid_app_ip" --on-port "$tproxy_udp_port" --tproxy-mark 0x11/0x11
done

echo "[setup] install timeout blackhole rules inside $ns_wan"
ns_exec "$ns_wan" iptables -A INPUT -d "$direct_tcp_drop_ip" -p tcp --dport "$direct_tcp_drop_port" -j DROP
ns_exec "$ns_wan" iptables -A OUTPUT -d "$proxy_tcp_drop_ip" -p tcp --dport "$proxy_tcp_drop_port" -j DROP
ns_exec "$ns_wan" iptables -A INPUT -d "$proxy_tcp_drop_ip" -p tcp --dport "$proxy_tcp_drop_port" -j DROP

key_output="$(env LD_LIBRARY_PATH="$runtime_ld_library_path" "$binary" x25519)"
private_key="$(awk '/private key:/{print $3}' <<<"$key_output")"
public_key="$(awk '/public key:/{print $3}' <<<"$key_output")"
short_id="0102030405060708"

cat >"$tmp_dir/server.json" <<EOF
{
  "mode": "server",
  "workers": 2,
  "log": {
    "level": "debug",
    "file": "$server_log"
  },
  "inbound": {
    "host": "$wan_ip",
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
    "read": 2,
    "write": 2,
    "connect": 2,
    "idle": 10
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
  "workers": 2,
  "log": {
    "level": "debug",
    "file": "$client_log"
  },
  "socks": {
    "enabled": false,
    "host": "127.0.0.1",
    "port": 0,
    "auth": false
  },
  "tproxy": {
    "enabled": true,
    "listen_host": "0.0.0.0",
    "tcp_port": $tproxy_tcp_port,
    "udp_port": $tproxy_udp_port,
    "mark": 17
  },
  "outbound": {
    "host": "$wan_ip",
    "port": $server_port
  },
  "reality": {
    "sni": "$sni",
    "fingerprint": "random",
    "public_key": "$public_key",
    "short_id": "$short_id"
  },
  "timeout": {
    "read": 2,
    "write": 2,
    "connect": 2,
    "idle": 4
  },
  "limits": {
    "max_connections": 4,
    "max_buffer": 10485760,
    "max_streams": 256,
    "max_handshake_records": 256
  },
  "heartbeat": {
    "enabled": true,
    "min_interval": 8,
    "max_interval": 12,
    "min_padding": 32,
    "max_padding": 64
  }
}
EOF

echo "[setup] start isolated target services"
start_in_ns "$ns_wan" "$tmp_dir/direct-http.log" python3 "$repo_root/scripts/slow_http_server.py" --host "$direct_tcp_ip" --port "$direct_tcp_port"
start_in_ns "$ns_wan" "$tmp_dir/proxy-http.log" python3 "$repo_root/scripts/slow_http_server.py" --host "$proxy_tcp_ip" --port "$proxy_tcp_port"
start_in_ns "$ns_wan" "$tmp_dir/direct-udp-echo.log" python3 "$repo_root/scripts/socks5_udp_echo_server.py" --host "$direct_udp_ip" --port "$direct_udp_port"
start_in_ns "$ns_wan" "$tmp_dir/proxy-udp-echo.log" python3 "$repo_root/scripts/socks5_udp_echo_server.py" --host "$proxy_udp_ip" --port "$proxy_udp_port"
start_in_ns "$ns_wan" "$tmp_dir/direct-udp-blackhole.log" python3 "$repo_root/scripts/udp_blackhole_server.py" --host "$direct_udp_blackhole_ip" --port "$direct_udp_blackhole_port"
start_in_ns "$ns_wan" "$tmp_dir/proxy-udp-blackhole.log" python3 "$repo_root/scripts/udp_blackhole_server.py" --host "$proxy_udp_blackhole_ip" --port "$proxy_udp_blackhole_port"
start_in_ns "$ns_wan" "$tmp_dir/reality-server.stdout.log" env LD_LIBRARY_PATH="$runtime_ld_library_path" SOCKS_CONFIG_DIR="$repo_root/config" "$binary" -c "$tmp_dir/server.json"

wait_tcp_port "$ns_wan" "$wan_ip" "$server_port" "reality_server"
wait_tcp_port "$ns_wan" "$direct_tcp_ip" "$direct_tcp_port" "direct_http_server"
wait_tcp_port "$ns_wan" "$proxy_tcp_ip" "$proxy_tcp_port" "proxy_http_server"

echo "[setup] start TPROXY client inside $ns_mid"
start_in_ns "$ns_mid" "$tmp_dir/tproxy-client.stdout.log" env LD_LIBRARY_PATH="$runtime_ld_library_path" SOCKS_CONFIG_DIR="$repo_root/config" "$binary" -c "$tmp_dir/client.json"

if ! wait_log_pattern_since "$client_log" 0 "tproxy tcp listening on 0.0.0.0:$tproxy_tcp_port" 10; then
    echo "tproxy tcp listener did not start" >&2
    exit 1
fi
if ! wait_log_pattern_since "$client_log" 0 "tproxy udp listening on 0.0.0.0:$tproxy_udp_port" 10; then
    echo "tproxy udp listener did not start" >&2
    exit 1
fi

echo "[test] tcp slow success under low rate and latency"
start_line="$(log_line_count "$client_log")"
run_step "tcp direct slow success" \
    ns_exec "$ns_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" \
    --host "$direct_tcp_ip" \
    --port "$direct_tcp_port" \
    --path "/slow-success?header_delay_ms=600&body_bytes=65536&chunk_size=4096&chunk_interval_ms=120" \
    --read-timeout 15 \
    --expect-substring "socks5-slow-http-server"
wait_log_pattern_since "$client_log" "$start_line" "target ${direct_tcp_ip}:${direct_tcp_port} route direct" 5 || {
    echo "missing direct route log for tcp direct slow success" >&2
    exit 1
}

start_line="$(log_line_count "$client_log")"
run_step "tcp proxy slow success" \
    ns_exec "$ns_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" \
    --host "$proxy_tcp_ip" \
    --port "$proxy_tcp_port" \
    --path "/slow-success?header_delay_ms=600&body_bytes=65536&chunk_size=4096&chunk_interval_ms=120" \
    --read-timeout 15 \
    --expect-substring "socks5-slow-http-server"
wait_log_pattern_since "$client_log" "$start_line" "target ${proxy_tcp_ip}:${proxy_tcp_port} route proxy" 5 || {
    echo "missing proxy route log for tcp proxy slow success" >&2
    exit 1
}

echo "[test] udp direct and proxy echo"
start_line="$(log_line_count "$client_log")"
run_step "udp direct echo" \
    ns_exec "$ns_app" python3 "$repo_root/scripts/tproxy_udp_client.py" \
    --host "$direct_udp_ip" \
    --port "$direct_udp_port" \
    --payload-size 1200 \
    --expect-echo
wait_log_pattern_since "$client_log" "$start_line" "opened direct udp socket" 5 || {
    echo "missing direct udp open log" >&2
    exit 1
}

start_line="$(log_line_count "$client_log")"
run_step "udp proxy echo" \
    ns_exec "$ns_app" python3 "$repo_root/scripts/tproxy_udp_client.py" \
    --host "$proxy_udp_ip" \
    --port "$proxy_udp_port" \
    --payload-size 1200 \
    --expect-echo
wait_log_pattern_since "$client_log" "$start_line" "opened proxy udp stream" 8 || {
    echo "missing proxy udp open log" >&2
    exit 1
}

echo "[test] tcp connect timeout"
start_line="$(log_line_count "$client_log")"
run_expect_failure "tcp direct connect timeout" \
    ns_exec "$ns_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" \
    --host "$direct_tcp_drop_ip" \
    --port "$direct_tcp_drop_port" \
    --path "/" \
    --read-timeout 8
wait_log_pattern_since "$client_log" "$start_line" "target ${direct_tcp_drop_ip}:${direct_tcp_drop_port} route direct connect failed" 8 || {
    echo "missing direct connect timeout log" >&2
    exit 1
}

start_line_client="$(log_line_count "$client_log")"
start_line_server="$(log_line_count "$server_log")"
run_expect_failure "tcp proxy connect timeout" \
    ns_exec "$ns_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" \
    --host "$proxy_tcp_drop_ip" \
    --port "$proxy_tcp_drop_port" \
    --path "/" \
    --read-timeout 8
if ! wait_log_pattern_since "$client_log" "$start_line_client" "target ${proxy_tcp_drop_ip}:${proxy_tcp_drop_port} route proxy connect failed" 8; then
    echo "missing proxy connect timeout log" >&2
    exit 1
fi

echo "[test] tcp idle timeout"
start_line="$(log_line_count "$client_log")"
run_expect_failure "tcp direct idle timeout" \
    ns_exec "$ns_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" \
    --host "$direct_tcp_ip" \
    --port "$direct_tcp_port" \
    --path "/stall-before-header?delay_ms=6500" \
    --read-timeout 8
wait_log_pattern_since "$client_log" "$start_line" "tcp session idle closing" 8 || {
    echo "missing tcp idle timeout log for direct case" >&2
    exit 1
}

start_line="$(log_line_count "$client_log")"
run_expect_failure "tcp proxy idle timeout" \
    ns_exec "$ns_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" \
    --host "$proxy_tcp_ip" \
    --port "$proxy_tcp_port" \
    --path "/stall-before-header?delay_ms=6500" \
    --read-timeout 8
if ! wait_log_pattern_since "$client_log" "$start_line" "tcp session idle closing" 8; then
    wait_log_pattern_since "$client_log" "$start_line" "target ${proxy_tcp_ip}:${proxy_tcp_port} tx_bytes" 8 || {
        echo "missing tcp idle timeout log for proxy case" >&2
        exit 1
    }
fi

echo "[test] tcp client no-read write timeout"
start_line="$(log_line_count "$client_log")"
run_step "tcp direct client no-read" \
    ns_exec "$ns_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" \
    --host "$direct_tcp_ip" \
    --port "$direct_tcp_port" \
    --mode hold-no-read \
    --path "/fast-large?body_bytes=67108864&chunk_size=65536&chunk_interval_ms=0" \
    --hold-seconds 5 \
    --recv-buffer 4096
wait_log_pattern_since "$client_log" "$start_line" "failed to write to client" 8 || {
    echo "missing client write timeout log for direct case" >&2
    exit 1
}

wait_tunnel_pool_ready 8 || {
    echo "tunnel pool did not recover before proxy client no-read case" >&2
    exit 1
}

start_line="$(log_line_count "$client_log")"
run_step "tcp proxy client no-read" \
    ns_exec "$ns_app" python3 "$repo_root/scripts/tproxy_tcp_client.py" \
    --host "$proxy_tcp_ip" \
    --port "$proxy_tcp_port" \
    --mode hold-no-read \
    --path "/fast-large?body_bytes=67108864&chunk_size=65536&chunk_interval_ms=0" \
    --hold-seconds 5 \
    --recv-buffer 4096
wait_log_pattern_since "$client_log" "$start_line" "failed to write to client" 8 || {
    echo "missing client write timeout log for proxy case" >&2
    exit 1
}

echo "[test] udp idle timeout"
start_line="$(log_line_count "$client_log")"
run_step "udp direct idle timeout" \
    ns_exec "$ns_app" python3 "$repo_root/scripts/tproxy_udp_client.py" \
    --host "$direct_udp_blackhole_ip" \
    --port "$direct_udp_blackhole_port" \
    --payload "direct-blackhole" \
    --timeout 1.5 \
    --expect-timeout
wait_log_pattern_since "$client_log" "$start_line" "udp session idle timeout" 8 || {
    echo "missing udp idle timeout log for direct case" >&2
    exit 1
}

start_line="$(log_line_count "$client_log")"
run_step "udp proxy idle timeout" \
    ns_exec "$ns_app" python3 "$repo_root/scripts/tproxy_udp_client.py" \
    --host "$proxy_udp_blackhole_ip" \
    --port "$proxy_udp_blackhole_port" \
    --payload "proxy-blackhole" \
    --timeout 1.5 \
    --expect-timeout
if ! wait_log_pattern_since "$client_log" "$start_line" "udp session idle timeout" 8; then
    wait_log_pattern_since "$client_log" "$start_line" "target ${proxy_udp_blackhole_ip}:${proxy_udp_blackhole_port} route proxy tx_bytes" 8 || {
        echo "missing udp idle timeout or proxy close log for proxy case" >&2
        exit 1
    }
fi

echo "[summary]"
if grep -Fq "original dst failed" "$client_log"; then
    echo "SO_ORIGINAL_DST failed; TPROXY not verified" >&2
    exit 1
fi
print_log_count "client_route_direct" "$client_log" " route direct"
print_log_count "client_route_proxy" "$client_log" " route proxy"
print_log_count "client_udp_direct_open" "$client_log" "opened direct udp socket"
print_log_count "client_udp_proxy_open" "$client_log" "opened proxy udp stream"
print_log_count "client_tcp_idle_timeout" "$client_log" "tcp session idle closing"
print_log_count "client_udp_idle_timeout" "$client_log" "udp session idle timeout"
print_log_count "client_write_timeout" "$client_log" "failed to write to client"
print_log_count "proxy_connect_failed" "$client_log" "target ${proxy_tcp_drop_ip}:${proxy_tcp_drop_port} route proxy connect failed"

echo "client_log=$client_log"
echo "server_log=$server_log"
echo "tmp_dir=$tmp_dir"
