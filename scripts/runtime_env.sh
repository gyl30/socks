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

ensure_netns_mountpoint() {
    local netns_dir="${1:-/run/netns}"

    mkdir -p "$netns_dir"

    if ! is_mountpoint "$netns_dir"; then
        mount --bind "$netns_dir" "$netns_dir"
    fi

    if ! awk -v target="$netns_dir" '
        $5 == target {
            found = 1
            for (i = 7; i <= NF && $i != "-"; ++i) {
                if ($i ~ /^shared:/) {
                    shared = 1
                }
            }
        }
        END { exit(found && shared ? 0 : 1) }
    ' /proc/self/mountinfo; then
        mount --make-shared "$netns_dir"
    fi
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
