#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${BIN:-${ROOT_DIR}/build-review/socks}"
LOG_PATH="${LOG_PATH:-${ROOT_DIR}/ci_tproxy_burst_log.txt}"
OPENSSL_BIN_DIR="${OPENSSL_BIN_DIR:-/home/gyl/openssl/bin}"
OPENSSL_LIB_DIR="${OPENSSL_LIB_DIR:-/home/gyl/openssl/lib64}"
UDP_BURST_COUNT="${UDP_BURST_COUNT:-500}"
UDP_BURST_PAYLOAD_BYTES="${UDP_BURST_PAYLOAD_BYTES:-1024}"
UDP_BURST_TIMEOUT_MS="${UDP_BURST_TIMEOUT_MS:-1000}"

sudo env \
    BIN="${BIN}" \
    UDP_BURST_COUNT="${UDP_BURST_COUNT}" \
    UDP_BURST_PAYLOAD_BYTES="${UDP_BURST_PAYLOAD_BYTES}" \
    UDP_BURST_TIMEOUT_MS="${UDP_BURST_TIMEOUT_MS}" \
    PATH="${OPENSSL_BIN_DIR}:${PATH}" \
    LD_LIBRARY_PATH="${OPENSSL_LIB_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
    /usr/bin/bash "${ROOT_DIR}/script/ci_tproxy_test.sh" --full \
    >"${LOG_PATH}" 2>&1

tail -n 80 "${LOG_PATH}"
