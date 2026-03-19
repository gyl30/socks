#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${1:?usage: merge_corpus.sh <target> [output_dir] [input_dir ...]}"
shift || true

binary="${FUZZ_BINARY:-$repo_root/build-fuzz-clang/${target}_fuzz}"
if [[ ! -x "$binary" ]]; then
    echo "binary not found: $binary" >&2
    exit 1
fi

output_dir="${1:-$repo_root/fuzz/corpus/${target}_merged}"
if [[ $# -gt 0 ]]; then
    shift
fi

inputs=("$@")
if [[ ${#inputs[@]} -eq 0 ]]; then
    inputs=("$repo_root/fuzz/corpus/$target")
fi

mkdir -p "$output_dir"

exec "$binary" -merge=1 "$output_dir" "${inputs[@]}"
