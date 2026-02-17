#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  bash script/clean_workspace_artifacts.sh [--dry-run]

Options:
  --dry-run   Show targets that would be removed, without deleting.
  -h, --help  Show this help message.
USAGE
}

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

dry_run=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

# Keep this list focused on deterministic local artifacts.
targets=(
  "app.log"
  "build_valgrind"
  "build_coverage_strict"
)

removed=0
for target in "${targets[@]}"; do
  if [[ ! -e "$target" ]]; then
    continue
  fi

  if [[ "$dry_run" -eq 1 ]]; then
    echo "[dry-run] remove $target"
    continue
  fi

  if [[ -d "$target" ]]; then
    find "$target" -type f -delete
    find "$target" -depth -type d -empty -delete
  else
    rm -f "$target"
  fi
  echo "[clean] removed $target"
  removed=1
done

if [[ "$dry_run" -eq 1 ]]; then
  echo "[dry-run] done"
  exit 0
fi

if [[ "$removed" -eq 0 ]]; then
  echo "[clean] no matching artifacts"
else
  echo "[clean] done"
fi
