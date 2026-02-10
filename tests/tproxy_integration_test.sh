#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "skip tproxy integration test (need root)"
    exit 77
fi

for cmd in ip iptables python3 openssl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "skip tproxy integration test (missing ${cmd})"
        exit 77
    fi
done

if [[ -z "${BIN:-}" ]]; then
    echo "BIN is not set"
    exit 1
fi

if [[ ! -x "${BIN}" ]]; then
    echo "binary not found: ${BIN}"
    exit 1
fi

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
BIN="${BIN}" "${ROOT_DIR}/script/ci_tproxy_test.sh" --full
