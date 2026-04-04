#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  tun_linux_route.sh [--netns <name>] [--table <id>] [--priority <id>] up <device> <cidr> [cidr...]
  tun_linux_route.sh [--netns <name>] [--table <id>] [--priority <id>] down <device> <cidr> [cidr...]
  tun_linux_route.sh [--netns <name>] --from <cidr> [--table <id>] [--priority <id>] up <device> <cidr> [cidr...]
  tun_linux_route.sh [--netns <name>] --from <cidr> [--table <id>] [--priority <id>] down <device> <cidr> [cidr...]

Examples:
  sudo scripts/tun_linux_route.sh up socks-tun 198.19.0.0/16
  sudo scripts/tun_linux_route.sh --netns appns up socks-tun 198.19.0.0/16 2001:db8::/32
  sudo scripts/tun_linux_route.sh --netns clientns --from 10.212.1.2/32 --table 100 up socks-tun 198.19.0.0/16
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
route_table=""
rule_priority="100"
source_cidr=""

while [[ $# -gt 0 ]]; do
    case "${1:-}" in
        --netns)
            if [[ $# -lt 3 ]]; then
                usage >&2
                exit 1
            fi
            netns="$2"
            shift 2
            ;;
        --table)
            if [[ $# -lt 3 ]]; then
                usage >&2
                exit 1
            fi
            route_table="$2"
            shift 2
            ;;
        --priority)
            if [[ $# -lt 3 ]]; then
                usage >&2
                exit 1
            fi
            rule_priority="$2"
            shift 2
            ;;
        --from)
            if [[ $# -lt 3 ]]; then
                usage >&2
                exit 1
            fi
            source_cidr="$2"
            shift 2
            ;;
        up|down)
            break
            ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
done

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

route_args=()
if [[ -n "$route_table" ]]; then
    route_args+=(table "$route_table")
fi

rule_args=()
if [[ -n "$source_cidr" ]]; then
    if [[ -z "$route_table" ]]; then
        echo "--from requires --table" >&2
        exit 1
    fi
    rule_args+=(pref "$rule_priority" from "$source_cidr" table "$route_table")
fi

if [[ "$action" == "up" && ${#rule_args[@]} -gt 0 ]]; then
    run_ip rule del "${rule_args[@]}" >/dev/null 2>&1 || true
    run_ip rule add "${rule_args[@]}"
    echo "rule added from=$source_cidr table=$route_table priority=$rule_priority${netns:+ netns=$netns}"
fi

for cidr in "$@"; do
    if [[ "$cidr" == *:* ]]; then
        family=(-6)
    else
        family=()
    fi

    if [[ "$action" == "up" ]]; then
        run_ip "${family[@]}" route replace "${route_args[@]}" "$cidr" dev "$device"
        echo "route added device=$device cidr=$cidr${route_table:+ table=$route_table}${netns:+ netns=$netns}"
    else
        run_ip "${family[@]}" route del "${route_args[@]}" "$cidr" dev "$device" >/dev/null 2>&1 || true
        echo "route removed device=$device cidr=$cidr${route_table:+ table=$route_table}${netns:+ netns=$netns}"
    fi
done

if [[ "$action" == "down" && ${#rule_args[@]} -gt 0 ]]; then
    run_ip rule del "${rule_args[@]}" >/dev/null 2>&1 || true
    echo "rule removed from=$source_cidr table=$route_table priority=$rule_priority${netns:+ netns=$netns}"
fi
