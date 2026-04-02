#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  tun_linux_route.sh [--netns <name>] up <device> <cidr> [cidr...]
  tun_linux_route.sh [--netns <name>] down <device> <cidr> [cidr...]

Examples:
  sudo scripts/tun_linux_route.sh up socks-tun 198.19.0.0/16
  sudo scripts/tun_linux_route.sh --netns appns up socks-tun 198.19.0.0/16 2001:db8::/32
EOF
}

if [[ $# -lt 3 ]]; then
    usage >&2
    exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
    echo "missing dependency: ip" >&2
    exit 1
fi

netns=""
if [[ "${1:-}" == "--netns" ]]; then
    if [[ $# -lt 5 ]]; then
        usage >&2
        exit 1
    fi
    netns="$2"
    shift 2
fi

action="$1"
device="$2"
shift 2

if [[ "$action" != "up" && "$action" != "down" ]]; then
    usage >&2
    exit 1
fi

if [[ $# -lt 1 ]]; then
    usage >&2
    exit 1
fi

run_ip() {
    if [[ -n "$netns" ]]; then
        ip netns exec "$netns" ip "$@"
    else
        ip "$@"
    fi
}

for cidr in "$@"; do
    if [[ "$cidr" == *:* ]]; then
        family=(-6)
    else
        family=()
    fi

    if [[ "$action" == "up" ]]; then
        run_ip "${family[@]}" route replace "$cidr" dev "$device"
        echo "route added device=$device cidr=$cidr${netns:+ netns=$netns}"
    else
        run_ip "${family[@]}" route del "$cidr" dev "$device" >/dev/null 2>&1 || true
        echo "route removed device=$device cidr=$cidr${netns:+ netns=$netns}"
    fi
done
