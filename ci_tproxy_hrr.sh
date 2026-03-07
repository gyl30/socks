#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${BIN:-${ROOT_DIR}/build-review/socks}"
LOG_PATH="${LOG_PATH:-${ROOT_DIR}/ci_tproxy_hrr_test_log.txt}"

sudo env \
    BIN="${BIN}" \
    /usr/bin/bash "${ROOT_DIR}/script/tproxy_hrr_reject_test.sh" \
    >"${LOG_PATH}" 2>&1

tail -n 80 "${LOG_PATH}"
