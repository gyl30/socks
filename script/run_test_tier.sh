#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  script/run_test_tier.sh --tier <smoke|full|unit|integration> [--build-dir <dir>] [--jobs <n>]

Options:
  --tier         Test tier to run.
  --build-dir    CTest build directory (default: build).
  --jobs         Parallel jobs for ctest (default: TEST_JOBS or nproc).

Environment:
  SMOKE_TEST_REGEX         Override smoke tier regex.
  INTEGRATION_TEST_REGEX   Override integration tier regex.
  CTEST_OUTPUT_LOG         Optional ctest --output-log path.
EOF
}

tier=""
build_dir="build"

detect_jobs() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
    return
  fi
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.logicalcpu 2>/dev/null || true
    return
  fi
  echo 1
}

default_jobs="$(detect_jobs)"
if [[ -z "${default_jobs}" ]] || ! [[ "${default_jobs}" =~ ^[0-9]+$ ]] || [[ "${default_jobs}" -lt 1 ]]; then
  default_jobs=1
fi

jobs="${TEST_JOBS:-${default_jobs}}"
smoke_regex="${SMOKE_TEST_REGEX:-config_test|monitor_server_test|mux_codec_test|protocol_edge_test|socks_protocol_test|reality_auth_test|limits_test}"
integration_regex="${INTEGRATION_TEST_REGEX:-integration|tproxy_integration|udp_integration|mux_connection_integration_test}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier)
      tier="${2:-}"
      shift 2
      ;;
    --build-dir)
      build_dir="${2:-}"
      shift 2
      ;;
    --jobs)
      jobs="${2:-}"
      shift 2
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

if [[ -z "$tier" ]]; then
  echo "--tier is required" >&2
  usage
  exit 2
fi

if ! [[ "$jobs" =~ ^[0-9]+$ ]] || [[ "$jobs" -lt 1 ]]; then
  echo "--jobs must be a positive integer" >&2
  usage
  exit 2
fi

ctest_cmd=(ctest --test-dir "$build_dir" --output-on-failure --parallel "$jobs")
if [[ -n "${CTEST_OUTPUT_LOG:-}" ]]; then
  ctest_cmd+=(--output-log "$CTEST_OUTPUT_LOG")
fi

case "$tier" in
  smoke)
    ctest_cmd+=(-R "$smoke_regex")
    ;;
  full)
    ;;
  unit)
    ctest_cmd+=(-E "$integration_regex")
    ;;
  integration)
    ctest_cmd+=(-R "$integration_regex")
    ;;
  *)
    echo "Unsupported tier: $tier" >&2
    usage
    exit 2
    ;;
esac

echo "[test-tier] tier=$tier build_dir=$build_dir jobs=$jobs"
"${ctest_cmd[@]}"
