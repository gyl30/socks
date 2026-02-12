#!/usr/bin/env bash
set -euo pipefail

AS_ROOT_MODE=0
if [[ "${1:-}" == "--as-root" ]]; then
    AS_ROOT_MODE=1
    shift
fi

if [[ -z "${BIN:-}" ]]; then
    echo "BIN is not set"
    exit 1
fi

if [[ ! -x "${BIN}" ]]; then
    echo "binary not found: ${BIN}"
    exit 1
fi

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT_PATH=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")

run_ci_test() {
    for cmd in ip iptables python3 openssl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "skip tproxy integration test (missing ${cmd})"
            exit 77
        fi
    done
    BIN="${BIN}" "${ROOT_DIR}/script/ci_tproxy_test.sh" --full
}

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    run_ci_test
    exit 0
fi

if [[ "${AS_ROOT_MODE}" -eq 1 ]]; then
    echo "skip tproxy integration test (need root privilege)"
    exit 77
fi

if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    BIN="${BIN}" exec sudo -n -E "$0" --as-root
fi

if command -v unshare >/dev/null 2>&1; then
    BIN="${BIN}" TEST_SCRIPT="${SCRIPT_PATH}" exec unshare -Urnm bash -lc 'set -e; mount -t tmpfs tmpfs /run; mkdir -p /run/netns; exec "${TEST_SCRIPT}" --as-root'
fi

echo "skip tproxy integration test (need root privilege)"
exit 77
