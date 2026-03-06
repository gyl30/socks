#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="${1:-run}"

CLIENT_BIN="${CLIENT_BIN:-${ROOT_DIR}/build-review/socks}"
CLIENT_CFG="${CLIENT_CFG:-${ROOT_DIR}/config/local_client_127001_socks2080_tproxy3080.json}"
SERVER_CFG="${SERVER_CFG:-${ROOT_DIR}/config/local_server_127001_8443.json}"
RULE_SCRIPT="${RULE_SCRIPT:-${ROOT_DIR}/script/tproxy_local_127001.sh}"
CONFIG_DIR="${CONFIG_DIR:-${ROOT_DIR}/config}"
HTTP_PORT="${HTTP_PORT:-18080}"
STATE_DIR="${STATE_DIR:-/tmp/socks_tproxy_curl}"
HTTP_PID_FILE="${STATE_DIR}/http.pid"
SERVER_PID_FILE="${STATE_DIR}/server.pid"
CLIENT_PID_FILE="${STATE_DIR}/client.pid"
HTTP_LOG="${HTTP_LOG:-${STATE_DIR}/http.log}"
CLIENT_LOG="${CLIENT_LOG:-${ROOT_DIR}/client_127001.log}"
SERVER_LOG="${SERVER_LOG:-${ROOT_DIR}/server_8443.log}"
TPROXY_UID="${TPROXY_UID:-$(id -un)}"
STRICT_ISOLATION="${STRICT_ISOLATION:-0}"
MARK_UDP="${MARK_UDP:-0}"

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing command: $1"
        exit 1
    }
}

require_file() {
    if [[ ! -f "$1" ]]; then
        echo "missing file: $1"
        exit 1
    fi
}

ensure_state_dir() {
    mkdir -p "${STATE_DIR}"
}

resolve_host_ip() {
    local host_ip
    host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    if [[ -z "${host_ip}" || "${host_ip}" == 127.* ]]; then
        host_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i = 1; i <= NF; ++i) if ($i == "src") {print $(i + 1); exit}}')"
    fi
    if [[ -z "${host_ip}" || "${host_ip}" == 127.* ]]; then
        echo "failed to resolve non-loopback ipv4 address"
        exit 1
    fi
    printf '%s\n' "${host_ip}"
}

write_pid() {
    local pid_file="$1"
    local pid="$2"
    printf '%s\n' "${pid}" > "${pid_file}"
}

read_pid() {
    local pid_file="$1"
    if [[ ! -f "${pid_file}" ]]; then
        return 1
    fi
    cat "${pid_file}"
}

is_running() {
    local pid="$1"
    kill -0 "${pid}" 2>/dev/null
}

stop_pid_file() {
    local pid_file="$1"
    local use_sudo="$2"
    local pid
    if ! pid="$(read_pid "${pid_file}")"; then
        return 0
    fi
    if [[ -n "${pid}" ]] && is_running "${pid}"; then
        if [[ "${use_sudo}" == "1" ]]; then
            sudo kill "${pid}" 2>/dev/null || true
        else
            kill "${pid}" 2>/dev/null || true
        fi
        wait "${pid}" 2>/dev/null || true
    fi
    rm -f "${pid_file}"
}

wait_for_tcp_port() {
    local host="$1"
    local port="$2"
    python3 - "$host" "$port" <<'PY'
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
deadline = time.time() + 10.0
last_error = None
while time.time() < deadline:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect((host, port))
        sys.exit(0)
    except OSError as exc:
        last_error = exc
    finally:
        sock.close()
    time.sleep(0.2)
print(f"tcp port not ready {host}:{port} last_error={last_error}", file=sys.stderr)
sys.exit(1)
PY
}

start_http_server() {
    sudo python3 -m http.server "${HTTP_PORT}" --bind 0.0.0.0 > "${HTTP_LOG}" 2>&1 &
    write_pid "${HTTP_PID_FILE}" "$!"
}

start_server() {
    sudo env SOCKS_CONFIG_DIR="${CONFIG_DIR}" \
        "${CLIENT_BIN}" -c "${SERVER_CFG}" > "${SERVER_LOG}" 2>&1 &
    write_pid "${SERVER_PID_FILE}" "$!"
}

start_client() {
    env SOCKS_CONFIG_DIR="${CONFIG_DIR}" \
        "${CLIENT_BIN}" -c "${CLIENT_CFG}" > "${CLIENT_LOG}" 2>&1 &
    write_pid "${CLIENT_PID_FILE}" "$!"
}

apply_rules() {
    sudo TPROXY_UID="${TPROXY_UID}" STRICT_ISOLATION="${STRICT_ISOLATION}" MARK_UDP="${MARK_UDP}" \
        "${RULE_SCRIPT}" up
}

remove_rules() {
    sudo "${RULE_SCRIPT}" down
}

show_status() {
    local host_ip="$1"
    echo "host_ip=${host_ip}"
    echo "http_log=${HTTP_LOG}"
    echo "client_log=${CLIENT_LOG}"
    echo "server_log=${SERVER_LOG}"
    if [[ -f "${HTTP_PID_FILE}" ]]; then
        echo "http_pid=$(cat "${HTTP_PID_FILE}")"
    fi
    if [[ -f "${SERVER_PID_FILE}" ]]; then
        echo "server_pid=$(cat "${SERVER_PID_FILE}")"
    fi
    if [[ -f "${CLIENT_PID_FILE}" ]]; then
        echo "client_pid=$(cat "${CLIENT_PID_FILE}")"
    fi
}

run_curl() {
    local host_ip="$1"
    echo "curl target=http://${host_ip}:${HTTP_PORT}/"
    curl --noproxy "*" -v "http://${host_ip}:${HTTP_PORT}/"
}

down() {
    remove_rules || true
    stop_pid_file "${CLIENT_PID_FILE}" "0"
    stop_pid_file "${SERVER_PID_FILE}" "1"
    stop_pid_file "${HTTP_PID_FILE}" "1"
}

up() {
    local host_ip
    ensure_state_dir
    host_ip="$(resolve_host_ip)"
    start_http_server
    start_server
    start_client
    wait_for_tcp_port 127.0.0.1 8443
    wait_for_tcp_port 127.0.0.1 3080
    wait_for_tcp_port "${host_ip}" "${HTTP_PORT}"
    apply_rules
    show_status "${host_ip}"
}

run() {
    local host_ip
    down
    up
    host_ip="$(resolve_host_ip)"
    run_curl "${host_ip}"
}

usage() {
    cat <<EOF
usage: $0 run|up|curl|down|status

env:
  CLIENT_BIN         default ${CLIENT_BIN}
  CLIENT_CFG         default ${CLIENT_CFG}
  SERVER_CFG         default ${SERVER_CFG}
  HTTP_PORT          default ${HTTP_PORT}
  TPROXY_UID         default ${TPROXY_UID}
  STRICT_ISOLATION   default ${STRICT_ISOLATION}
  MARK_UDP           default ${MARK_UDP}
EOF
}

main() {
    require_cmd bash
    require_cmd curl
    require_cmd python3
    require_cmd sudo
    require_cmd hostname
    require_cmd ip
    require_file "${CLIENT_BIN}"
    require_file "${CLIENT_CFG}"
    require_file "${SERVER_CFG}"
    require_file "${RULE_SCRIPT}"

    case "${ACTION}" in
        run)
            run
            ;;
        up)
            up
            ;;
        curl)
            run_curl "$(resolve_host_ip)"
            ;;
        down)
            down
            ;;
        status)
            show_status "$(resolve_host_ip)"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main
