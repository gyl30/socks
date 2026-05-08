#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/setup_demo_test_users.sh

Environment:
  TUN_TEST_USER      TUN 测试用户。默认: tunuser
  TPROXY_TEST_USER   TPROXY 测试用户。默认: tpuser
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/testlib.sh"
require_commands id useradd

ensure_user() {
    local user_name="$1"
    if id "$user_name" >/dev/null 2>&1; then
        echo "user exists: $user_name"
        return 0
    fi

    useradd -m -s /bin/bash "$user_name"
    echo "user created: $user_name"
}

ensure_user "${TUN_TEST_USER:-tunuser}"
ensure_user "${TPROXY_TEST_USER:-tpuser}"
