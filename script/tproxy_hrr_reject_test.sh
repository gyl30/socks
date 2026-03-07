#!/usr/bin/env bash
set -euo pipefail

NS_CLIENT=${NS_CLIENT:-thc}
NS_PROXY=${NS_PROXY:-thp}
NS_SERVER=${NS_SERVER:-ths}
VETH_CLIENT_HOST=${VETH_CLIENT_HOST:-vethhc0}
VETH_CLIENT_NS=${VETH_CLIENT_NS:-vethhc1}
VETH_SERVER_HOST=${VETH_SERVER_HOST:-vethhs0}
VETH_SERVER_NS=${VETH_SERVER_NS:-vethhs1}
CLIENT_IP=${CLIENT_IP:-10.210.1.2}
PROXY_CLIENT_IP=${PROXY_CLIENT_IP:-10.210.1.1}
PROXY_SERVER_IP=${PROXY_SERVER_IP:-10.210.2.1}
SERVER_IP=${SERVER_IP:-10.210.2.2}
HOST_TCP_PORT=${HOST_TCP_PORT:-24556}
TPROXY_PORT=${TPROXY_PORT:-1181}
TPROXY_MARK=${TPROXY_MARK:-0x21}
OUTBOUND_MARK=${OUTBOUND_MARK:-34}
REMOTE_PORT=${REMOTE_PORT:-19444}
BIN=${BIN:-"$(pwd)/build/socks"}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing command: $1" >&2
        exit 1
    }
}

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "run as root or with CAP_NET_ADMIN" >&2
    exit 1
fi

require_cmd ip
require_cmd iptables
require_cmd python3

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
HRR_PID=""
ECHO_PID=""

cleanup() {
    set +e
    if [[ -n "${TPROXY_PID}" ]]; then
        kill "${TPROXY_PID}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${HRR_PID}" ]]; then
        kill "${HRR_PID}" >/dev/null 2>&1 || true
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

KEY_OUTPUT=$("${BIN}" x25519)
PRIV_KEY=$(echo "${KEY_OUTPUT}" | awk '/private key/ {print $3}')
PUB_KEY=$(echo "${KEY_OUTPUT}" | awk '/public key/ {print $3}')
if [[ -z "${PRIV_KEY}" || -z "${PUB_KEY}" ]]; then
    echo "failed to generate x25519 keypair" >&2
    exit 1
fi

ip netns exec "${NS_SERVER}" python3 -u - <<PY &
import socket
import threading

HOST = "${SERVER_IP}"
PORT = int("${HOST_TCP_PORT}")

def handle(conn):
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(5)

while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY
ECHO_PID=$!

ip netns exec "${NS_SERVER}" python3 -u - <<PY &
import pathlib
import socket
import time

HOST = "${SERVER_IP}"
PORT = int("${REMOTE_PORT}")
LOG = pathlib.Path("${TMPDIR}/fake_hrr_server.log")
HRR_RANDOM = bytes([
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
])

def recv_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed early")
        data.extend(chunk)
    return bytes(data)

def parse_client_hello(record_body):
    if len(record_body) < 4 or record_body[0] != 0x01:
        raise ValueError("not client hello")
    msg_len = int.from_bytes(record_body[1:4], "big")
    body = record_body[4 : 4 + msg_len]
    pos = 0
    pos += 2
    pos += 32
    sid_len = body[pos]
    pos += 1
    session_id = body[pos : pos + sid_len]
    pos += sid_len
    cipher_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    cipher_suite = int.from_bytes(body[pos : pos + 2], "big")
    if cipher_len < 2:
        raise ValueError("bad cipher suite list")
    return session_id, cipher_suite

def build_hrr(session_id, cipher_suite):
    extensions = b"".join(
        [
            b"\\x00\\x2b\\x00\\x02\\x03\\x04",
            b"\\x00\\x33\\x00\\x02\\x00\\x1d",
        ]
    )
    body = bytearray()
    body.extend(b"\\x03\\x03")
    body.extend(HRR_RANDOM)
    body.append(len(session_id))
    body.extend(session_id)
    body.extend(cipher_suite.to_bytes(2, "big"))
    body.append(0x00)
    body.extend(len(extensions).to_bytes(2, "big"))
    body.extend(extensions)

    handshake = bytearray()
    handshake.append(0x02)
    handshake.extend(len(body).to_bytes(3, "big"))
    handshake.extend(body)

    record = bytearray()
    record.extend(b"\\x16\\x03\\x03")
    record.extend(len(handshake).to_bytes(2, "big"))
    record.extend(handshake)
    return bytes(record)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((HOST, PORT))
sock.listen(5)
LOG.write_text("ready\\n", encoding="utf-8")

while True:
    conn, addr = sock.accept()
    with conn:
        conn.settimeout(2)
        header = recv_exact(conn, 5)
        body_len = int.from_bytes(header[3:5], "big")
        body = recv_exact(conn, body_len)
        session_id, cipher_suite = parse_client_hello(body)
        conn.sendall(build_hrr(session_id, cipher_suite))
        with LOG.open("a", encoding="utf-8") as handle:
            handle.write(f"accepted {addr[0]}:{addr[1]}\\n")
        time.sleep(0.1)
PY
HRR_PID=$!

python3 - <<PY
import pathlib
import time

log_path = pathlib.Path("${TMPDIR}/fake_hrr_server.log")
deadline = time.time() + 5.0
while time.time() < deadline:
    if log_path.exists() and "ready" in log_path.read_text(encoding="utf-8"):
        raise SystemExit(0)
    time.sleep(0.1)
raise SystemExit("fake hrr server not ready")
PY

cat >"${TMPDIR}/config.json" <<EOF
{
  "mode": "client",
  "log": { "level": "info", "file": "tproxy_hrr_test.log" },
  "outbound": { "host": "${SERVER_IP}", "port": ${REMOTE_PORT} },
  "socks": { "enabled": false },
  "tproxy": {
    "enabled": true,
    "listen_host": "::",
    "tcp_port": ${TPROXY_PORT},
    "udp_port": ${TPROXY_PORT},
    "mark": ${OUTBOUND_MARK_DEC}
  },
  "reality": {
    "sni": "example.com",
    "public_key": "${PUB_KEY}",
    "short_id": ""
  },
  "limits": { "max_connections": 1, "max_handshake_records": 8 },
  "timeout": { "read": 5, "write": 5, "connect": 5, "idle": 5 },
  "monitor": { "enabled": false }
}
EOF

touch "${TMPDIR}/block_ip.txt"
touch "${TMPDIR}/direct_ip.txt"
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

python3 - <<PY
import pathlib
import time

log_path = pathlib.Path("${TMPDIR}/tproxy_hrr_test.log")
deadline = time.time() + 15.0
while time.time() < deadline:
    if log_path.exists():
        text = log_path.read_text(encoding="utf-8")
        if "hello retry request not supported" in text and "stage=handshake" in text and "Operation not supported" in text:
            raise SystemExit(0)
    time.sleep(0.2)
raise SystemExit("client log missing hrr reject marker")
PY

python3 - <<PY
from pathlib import Path

log_text = Path("${TMPDIR}/fake_hrr_server.log").read_text(encoding="utf-8")
accepted = [line for line in log_text.splitlines() if line.startswith("accepted ")]
if not accepted:
    raise SystemExit("fake hrr server did not receive any client hello")
print(f"hrr handshakes {len(accepted)}")
PY

ip netns exec "${NS_CLIENT}" python3 - <<PY
import socket

HOST = "${SERVER_IP}"
PORT = int("${HOST_TCP_PORT}")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(3)
try:
    sock.connect((HOST, PORT))
    sock.sendall(b"unexpected-success")
    data = sock.recv(1024)
    if data == b"unexpected-success":
        raise SystemExit("transparent tcp unexpectedly succeeded while hrr was rejected")
    raise SystemExit(0)
except (socket.timeout, ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
    print("tcp blocked after hrr reject")
finally:
    sock.close()
PY

echo "tproxy hrr reject test passed"
