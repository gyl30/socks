#!/usr/bin/env bash

append_runtime_lib_dir() {
    local dir="$1"
    if [[ -z "$dir" ]] || [[ ! -d "$dir" ]]; then
        return
    fi
    case ":${runtime_ld_library_path:-}:" in
        *":$dir:"*) ;;
        *)
            if [[ -n "${runtime_ld_library_path:-}" ]]; then
                runtime_ld_library_path="$runtime_ld_library_path:$dir"
            else
                runtime_ld_library_path="$dir"
            fi
            ;;
    esac
}

append_runtime_lib_dirs() {
    local raw="$1"
    local dir
    if [[ -z "$raw" ]]; then
        return
    fi
    IFS=':' read -r -a _runtime_dirs <<< "$raw"
    for dir in "${_runtime_dirs[@]}"; do
        append_runtime_lib_dir "$dir"
    done
}

append_root_runtime_lib_dirs() {
    local root="$1"
    if [[ -z "$root" ]]; then
        return
    fi
    append_runtime_lib_dir "$root/lib64"
    append_runtime_lib_dir "$root/lib"
}

read_binary_runpath() {
    local binary="$1"
    if ! command -v readelf >/dev/null 2>&1; then
        return
    fi
    readelf -d "$binary" 2>/dev/null | awk -F'[][]' '/(RUNPATH|RPATH)/ {print $2; exit}'
}

is_mountpoint() {
    local target="$1"
    awk -v target="$target" '
        $5 == target { found = 1; exit }
        END { exit(found ? 0 : 1) }
    ' /proc/self/mountinfo
}

is_shared_mountpoint() {
    local target="$1"
    awk -v target="$target" '
        $5 == target {
            found = 1
            for (i = 7; i <= NF && $i != "-"; ++i) {
                if ($i ~ /^shared:/) {
                    shared = 1
                }
            }
            exit
        }
        END { exit(found && shared ? 0 : 1) }
    ' /proc/self/mountinfo
}

enter_private_run_mount_namespace() {
    if [[ "${SOCKS_PRIVATE_RUN_READY:-0}" != "1" ]]; then
        if ! command -v unshare >/dev/null 2>&1; then
            echo "missing dependency: unshare" >&2
            return 1
        fi

        exec unshare -m --propagation private env SOCKS_PRIVATE_RUN_READY=1 "${BASH:-bash}" "$0" "$@"
    fi

    if [[ "${SOCKS_PRIVATE_RUN_NETNS_TMPFS_READY:-0}" == "1" ]]; then
        return
    fi

    mkdir -p /run/netns
    mount -t tmpfs tmpfs /run/netns
    export SOCKS_PRIVATE_RUN_NETNS_TMPFS_READY=1
}

netns_mountpoint_owned_dir=""

ensure_netns_mountpoint() {
    local netns_dir="${1:-/run/netns}"

    mkdir -p "$netns_dir"

    if [[ "${netns_mountpoint_owned_dir:-}" == "$netns_dir" ]]; then
        return
    fi

    if is_mountpoint "$netns_dir" && is_shared_mountpoint "$netns_dir"; then
        return
    fi

    if ! mount --bind "$netns_dir" "$netns_dir"; then
        return 1
    fi
    netns_mountpoint_owned_dir="$netns_dir"

    if ! is_shared_mountpoint "$netns_dir"; then
        if ! mount --make-shared "$netns_dir"; then
            umount "$netns_dir" >/dev/null 2>&1 || true
            netns_mountpoint_owned_dir=""
            return 1
        fi
    fi
}

cleanup_netns_mountpoint() {
    local netns_dir="${1:-${netns_mountpoint_owned_dir:-}}"

    if [[ -z "${netns_mountpoint_owned_dir:-}" ]]; then
        return
    fi

    if [[ "$netns_mountpoint_owned_dir" != "$netns_dir" ]]; then
        return
    fi

    if is_mountpoint "$netns_dir"; then
        umount "$netns_dir" >/dev/null 2>&1 || true
    fi

    netns_mountpoint_owned_dir=""
}

init_runtime_ld_library_path() {
    local binary="$1"
    runtime_ld_library_path=""
    append_runtime_lib_dirs "${SOCKS_RUNTIME_LIB_DIRS:-}"
    append_root_runtime_lib_dirs "${OPENSSL_ROOT_DIR:-}"
    append_root_runtime_lib_dirs "${BROTLI_ROOT_DIR:-}"
    append_runtime_lib_dirs "$(read_binary_runpath "$binary")"
    append_runtime_lib_dirs "${LD_LIBRARY_PATH:-}"
}
