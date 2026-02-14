#!/usr/bin/env bash
set -euo pipefail

FULL_CHAIN=${FULL_CHAIN:-0}
if [[ "${1:-}" == "--full" ]]; then
    FULL_CHAIN=1
    shift
fi

NS_CLIENT=${NS_CLIENT:-tpc}
NS_PROXY=${NS_PROXY:-tpp}
NS_SERVER=${NS_SERVER:-tps}
VETH_CLIENT_HOST=${VETH_CLIENT_HOST:-vethc0}
VETH_CLIENT_NS=${VETH_CLIENT_NS:-vethc1}
VETH_SERVER_HOST=${VETH_SERVER_HOST:-veths0}
VETH_SERVER_NS=${VETH_SERVER_NS:-veths1}
CLIENT_IP=${CLIENT_IP:-10.200.1.2}
PROXY_CLIENT_IP=${PROXY_CLIENT_IP:-10.200.1.1}
PROXY_SERVER_IP=${PROXY_SERVER_IP:-10.200.2.1}
SERVER_IP=${SERVER_IP:-10.200.2.2}
HOST_TCP_PORT=${HOST_TCP_PORT:-23456}
HOST_UDP_PORT=${HOST_UDP_PORT:-23457}
TPROXY_PORT=${TPROXY_PORT:-1081}
TPROXY_MARK=${TPROXY_MARK:-0x11}
OUTBOUND_MARK=${OUTBOUND_MARK:-18}
REMOTE_PORT=${REMOTE_PORT:-18444}
TLS_PORT=${TLS_PORT:-24443}
BIN=${BIN:-"$(pwd)/build/socks"}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1" >&2; exit 1; }
}

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "run as root or with CAP_NET_ADMIN" >&2
    exit 1
fi

require_cmd ip
require_cmd iptables
require_cmd python3
if [[ "${FULL_CHAIN}" == "1" ]]; then
    require_cmd openssl
fi

if [[ ! -x "$BIN" ]]; then
    echo "binary not found: $BIN" >&2
    echo "build it first: cmake --build build -j" >&2
    exit 1
fi

OUTBOUND_MARK_DEC=$OUTBOUND_MARK
if [[ "$OUTBOUND_MARK" == 0x* || "$OUTBOUND_MARK" == 0X* ]]; then
    OUTBOUND_MARK_DEC=$((OUTBOUND_MARK))
fi

TMPDIR=$(mktemp -d)
TPROXY_PID=""
ECHO_PID=""
SERVER_PID=""
TLS_PID=""
OUTBOUND_HOST="127.0.0.1"
OUTBOUND_PORT=1
REALITY_PUB="8d4e6ddf1479f2305b6645f045e02f9f5e400005884a8f1663ee9c51915bcc6d"

cleanup() {
    set +e
    if [[ -n "${TPROXY_PID}" ]]; then
        kill "${TPROXY_PID}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${SERVER_PID}" ]]; then
        kill "${SERVER_PID}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${TLS_PID}" ]]; then
        kill "${TLS_PID}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${ECHO_PID}" ]]; then
        kill "${ECHO_PID}" >/dev/null 2>&1 || true
    fi
    ip netns exec "${NS_PROXY}" iptables -t mangle -D PREROUTING -j TPROXY_MUX >/dev/null 2>&1 || true
    ip netns exec "${NS_PROXY}" iptables -t mangle -F TPROXY_MUX >/dev/null 2>&1 || true
    ip netns exec "${NS_PROXY}" iptables -t mangle -X TPROXY_MUX >/dev/null 2>&1 || true
    ip netns exec "${NS_PROXY}" ip rule del fwmark "${TPROXY_MARK}"/0xff lookup 100 >/dev/null 2>&1 || true
    ip netns exec "${NS_PROXY}" ip route del local 0.0.0.0/0 dev lo table 100 >/dev/null 2>&1 || true
    ip netns exec "${NS_PROXY}" ip -6 rule del fwmark "${TPROXY_MARK}"/0xff lookup 100 >/dev/null 2>&1 || true
    ip netns exec "${NS_PROXY}" ip -6 route del local ::/0 dev lo table 100 >/dev/null 2>&1 || true
    ip netns del "${NS_CLIENT}" >/dev/null 2>&1 || true
    ip netns del "${NS_PROXY}" >/dev/null 2>&1 || true
    ip netns del "${NS_SERVER}" >/dev/null 2>&1 || true
    ip link del "${VETH_CLIENT_HOST}" >/dev/null 2>&1 || true
    ip link del "${VETH_SERVER_HOST}" >/dev/null 2>&1 || true
    rm -rf "${TMPDIR}"
}

trap cleanup EXIT

ip netns del "${NS_CLIENT}" >/dev/null 2>&1 || true
ip netns del "${NS_PROXY}" >/dev/null 2>&1 || true
ip netns del "${NS_SERVER}" >/dev/null 2>&1 || true
ip link del "${VETH_CLIENT_HOST}" >/dev/null 2>&1 || true
ip link del "${VETH_SERVER_HOST}" >/dev/null 2>&1 || true

ip link add "${VETH_CLIENT_HOST}" type veth peer name "${VETH_CLIENT_NS}"
ip link add "${VETH_SERVER_HOST}" type veth peer name "${VETH_SERVER_NS}"

ip netns add "${NS_CLIENT}"
ip netns add "${NS_PROXY}"
ip netns add "${NS_SERVER}"

ip link set "${VETH_CLIENT_NS}" netns "${NS_CLIENT}"
ip link set "${VETH_CLIENT_HOST}" netns "${NS_PROXY}"
ip link set "${VETH_SERVER_HOST}" netns "${NS_PROXY}"
ip link set "${VETH_SERVER_NS}" netns "${NS_SERVER}"

ip netns exec "${NS_CLIENT}" ip addr add "${CLIENT_IP}/24" dev "${VETH_CLIENT_NS}"
ip netns exec "${NS_CLIENT}" ip link set "${VETH_CLIENT_NS}" up
ip netns exec "${NS_CLIENT}" ip link set lo up
ip netns exec "${NS_CLIENT}" ip route add default via "${PROXY_CLIENT_IP}" dev "${VETH_CLIENT_NS}"

ip netns exec "${NS_PROXY}" ip addr add "${PROXY_CLIENT_IP}/24" dev "${VETH_CLIENT_HOST}"
ip netns exec "${NS_PROXY}" ip addr add "${PROXY_SERVER_IP}/24" dev "${VETH_SERVER_HOST}"
ip netns exec "${NS_PROXY}" ip link set "${VETH_CLIENT_HOST}" up
ip netns exec "${NS_PROXY}" ip link set "${VETH_SERVER_HOST}" up
ip netns exec "${NS_PROXY}" ip link set lo up
ip netns exec "${NS_PROXY}" sysctl -w net.ipv4.ip_forward=1 >/dev/null

ip netns exec "${NS_SERVER}" ip addr add "${SERVER_IP}/24" dev "${VETH_SERVER_NS}"
ip netns exec "${NS_SERVER}" ip link set "${VETH_SERVER_NS}" up
ip netns exec "${NS_SERVER}" ip link set lo up
ip netns exec "${NS_SERVER}" ip route add default via "${PROXY_SERVER_IP}" dev "${VETH_SERVER_NS}"

ip netns exec "${NS_SERVER}" python3 -u - <<PY &
import socket
import threading

HOST_IP = "${SERVER_IP}"
TCP_PORT = int("${HOST_TCP_PORT}")
UDP_PORT = int("${HOST_UDP_PORT}")

def handle_tcp(conn):
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data)

def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST_IP, TCP_PORT))
    s.listen(5)
    while True:
        conn, _ = s.accept()
        t = threading.Thread(target=handle_tcp, args=(conn,), daemon=True)
        t.start()

def udp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST_IP, UDP_PORT))
    while True:
        data, addr = s.recvfrom(65535)
        if data:
            s.sendto(data, addr)

threading.Thread(target=tcp_server, daemon=True).start()
udp_server()
PY
ECHO_PID=$!

if [[ "${FULL_CHAIN}" == "1" ]]; then
    KEY_OUTPUT=$("${BIN}" x25519)
    PRIV_KEY=$(echo "${KEY_OUTPUT}" | awk '/private key/ {print $3}')
    PUB_KEY=$(echo "${KEY_OUTPUT}" | awk '/public key/ {print $3}')
    if [[ -z "${PRIV_KEY}" || -z "${PUB_KEY}" ]]; then
        echo "failed to generate reality keypair" >&2
        exit 1
    fi
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "${TMPDIR}/tls_key.pem" -out "${TMPDIR}/tls_cert.pem" -subj "/CN=example.com" -days 1 >/dev/null 2>&1
    ip netns exec "${NS_SERVER}" python3 -u - <<PY &
import ssl
import socket

HOST = "${SERVER_IP}"
PORT = int("${TLS_PORT}")
CERT = "${TMPDIR}/tls_cert.pem"
KEY = "${TMPDIR}/tls_key.pem"

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT, keyfile=KEY)
context.minimum_version = ssl.TLSVersion.TLSv1_2

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(5)

while True:
    conn, _ = s.accept()
    try:
        tls = context.wrap_socket(conn, server_side=True)
        tls.recv(1)
        tls.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
PY
    TLS_PID=$!
    cat >"${TMPDIR}/server.json" <<EOF
{
  "mode": "server",
  "log": { "level": "info", "file": "server_test.log" },
  "inbound": { "host": "${SERVER_IP}", "port": ${REMOTE_PORT} },
  "fallbacks": [
    { "sni": "example.com", "host": "${SERVER_IP}", "port": "${TLS_PORT}" }
  ],
  "reality": {
    "sni": "example.com",
    "private_key": "${PRIV_KEY}",
    "public_key": "${PUB_KEY}",
    "short_id": ""
  }
}
EOF
    OUTBOUND_HOST="${SERVER_IP}"
    OUTBOUND_PORT=${REMOTE_PORT}
    REALITY_PUB="${PUB_KEY}"
    ip netns exec "${NS_SERVER}" bash -lc "cd '${TMPDIR}' && '${BIN}' -c server.json" &
    SERVER_PID=$!
    ip netns exec "${NS_PROXY}" python3 - <<PY
import socket
import time

HOST_IP = "${SERVER_IP}"
REMOTE_PORT = int("${REMOTE_PORT}")

deadline = time.time() + 10.0
last_error = None
while time.time() < deadline:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect((HOST_IP, REMOTE_PORT))
        print("remote server ready")
        break
    except OSError as exc:
        last_error = exc
        time.sleep(0.1)
    finally:
        sock.close()
else:
    raise SystemExit(f"remote server not ready: {last_error}")
PY
fi

cat >"${TMPDIR}/config.json" <<EOF
{
  "mode": "client",
  "log": { "level": "info", "file": "tproxy_test.log" },
  "outbound": { "host": "${OUTBOUND_HOST}", "port": ${OUTBOUND_PORT} },
  "socks": { "enabled": false },
  "tproxy": {
    "enabled": true,
    "listen_host": "::",
    "tcp_port": ${TPROXY_PORT},
    "udp_port": 0,
    "mark": ${OUTBOUND_MARK_DEC}
  },
  "reality": {
    "sni": "example.com",
    "public_key": "${REALITY_PUB}",
    "short_id": "",
    "strict_cert_verify": false
  },
  "limits": { "max_connections": 1 },
  "timeout": { "idle": 5 }
}
EOF

if [[ "${FULL_CHAIN}" == "1" ]]; then
    : >"${TMPDIR}/direct_ip.txt"
else
    cat >"${TMPDIR}/direct_ip.txt" <<EOF
0.0.0.0/0
::/0
EOF
fi

touch "${TMPDIR}/block_ip.txt"
touch "${TMPDIR}/proxy_domain.txt"
touch "${TMPDIR}/block_domain.txt"
touch "${TMPDIR}/direct_domain.txt"

ip netns exec "${NS_PROXY}" ip rule add fwmark "${TPROXY_MARK}"/0xff lookup 100
ip netns exec "${NS_PROXY}" ip route add local 0.0.0.0/0 dev lo table 100
ip netns exec "${NS_PROXY}" ip -6 rule add fwmark "${TPROXY_MARK}"/0xff lookup 100 >/dev/null 2>&1 || true
ip netns exec "${NS_PROXY}" ip -6 route add local ::/0 dev lo table 100 >/dev/null 2>&1 || true
 
ip netns exec "${NS_PROXY}" iptables -t mangle -N TPROXY_MUX
ip netns exec "${NS_PROXY}" iptables -t mangle -F TPROXY_MUX
ip netns exec "${NS_PROXY}" iptables -t mangle -A PREROUTING -j TPROXY_MUX
ip netns exec "${NS_PROXY}" iptables -t mangle -A TPROXY_MUX -i "${VETH_CLIENT_HOST}" -m mark --mark "${TPROXY_MARK}"/0xff -j RETURN
ip netns exec "${NS_PROXY}" iptables -t mangle -A TPROXY_MUX -i "${VETH_CLIENT_HOST}" -p tcp -j TPROXY --on-port "${TPROXY_PORT}" --tproxy-mark "${TPROXY_MARK}"
ip netns exec "${NS_PROXY}" iptables -t mangle -A TPROXY_MUX -i "${VETH_CLIENT_HOST}" -p udp -j TPROXY --on-port "${TPROXY_PORT}" --tproxy-mark "${TPROXY_MARK}"

ip netns exec "${NS_PROXY}" bash -lc "cd '${TMPDIR}' && '${BIN}' -c config.json" &
TPROXY_PID=$!

sleep 1

ip netns exec "${NS_CLIENT}" python3 - <<PY
import socket
import time

HOST_IP = "${SERVER_IP}"
TCP_PORT = int("${HOST_TCP_PORT}")

msg = b"tproxy-tcp-test"
deadline = time.time() + 12.0
last_error = None
while time.time() < deadline:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((HOST_IP, TCP_PORT))
        sock.sendall(msg)
        data = sock.recv(4096)
        if data == msg:
            print("tcp ok")
            break
        last_error = f"tcp echo mismatch {data!r}"
    except OSError as exc:
        last_error = exc
    finally:
        sock.close()
    time.sleep(0.2)
else:
    raise SystemExit(f"tcp probe failed: {last_error}")
PY

ip netns exec "${NS_CLIENT}" python3 - <<PY
import socket
import time

HOST_IP = "${SERVER_IP}"
UDP_PORT = int("${HOST_UDP_PORT}")

msg = b"tproxy-udp-test"
deadline = time.time() + 10.0
last_error = None
while time.time() < deadline:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(msg, (HOST_IP, UDP_PORT))
        data, _ = sock.recvfrom(4096)
        if data == msg:
            print("udp ok")
            break
        last_error = f"udp echo mismatch {data!r}"
    except OSError as exc:
        last_error = exc
    finally:
        sock.close()
    time.sleep(0.2)
else:
    raise SystemExit(f"udp probe failed: {last_error}")
PY

sleep 6

ip netns exec "${NS_CLIENT}" python3 - <<PY
import socket
import time

HOST_IP = "${SERVER_IP}"
UDP_PORT = int("${HOST_UDP_PORT}")

msg = b"tproxy-udp-test-2"
deadline = time.time() + 10.0
last_error = None
while time.time() < deadline:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(msg, (HOST_IP, UDP_PORT))
        data, _ = sock.recvfrom(4096)
        if data == msg:
            print("udp ok after idle")
            break
        last_error = f"udp echo mismatch after idle {data!r}"
    except OSError as exc:
        last_error = exc
    finally:
        sock.close()
    time.sleep(0.2)
else:
    raise SystemExit(f"udp probe after idle failed: {last_error}")
PY

echo "tproxy ci test done"
