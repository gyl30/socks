#!/usr/bin/env bash
set -euo pipefail

OPENSSL_VERSION="${OPENSSL_VERSION:?OPENSSL_VERSION is required}"
OPENSSL_ARCHIVE="${OPENSSL_ARCHIVE:-openssl-${OPENSSL_VERSION}.tar.gz}"
OPENSSL_SRC_DIR="${OPENSSL_SRC_DIR:-openssl-${OPENSSL_VERSION}}"
OPENSSL_INSTALL_DIR="${OPENSSL_INSTALL_DIR:?OPENSSL_INSTALL_DIR is required}"
OPENSSL_CACHE_DIR="${OPENSSL_CACHE_DIR:-${HOME}/.cache/openssl}"
OPENSSL_DOWNLOAD_URL="${OPENSSL_DOWNLOAD_URL:-https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/${OPENSSL_ARCHIVE}}"
OPENSSL_CONFIG_TARGET="${OPENSSL_CONFIG_TARGET:-}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

archive_path="${OPENSSL_CACHE_DIR}/${OPENSSL_ARCHIVE}"
source_dir="${OPENSSL_CACHE_DIR}/${OPENSSL_SRC_DIR}"

installed_version_matches() {
    local version_header="${OPENSSL_INSTALL_DIR}/include/openssl/opensslv.h"
    [[ -f "${version_header}" ]] && grep -q "OPENSSL_VERSION_STR \"${OPENSSL_VERSION}\"" "${version_header}"
}

mkdir -p "${OPENSSL_CACHE_DIR}"

if installed_version_matches; then
    echo "openssl ${OPENSSL_VERSION} already installed at ${OPENSSL_INSTALL_DIR}"
    exit 0
fi

if [[ ! -f "${archive_path}" ]]; then
    wget -O "${archive_path}" "${OPENSSL_DOWNLOAD_URL}"
fi

rm -rf "${source_dir}" "${OPENSSL_INSTALL_DIR}"
tar xf "${archive_path}" -C "${OPENSSL_CACHE_DIR}"

cd "${source_dir}"

configure_cmd=(
    perl
    ./Configure
    --prefix="${OPENSSL_INSTALL_DIR}"
    --openssldir="${OPENSSL_INSTALL_DIR}/ssl"
    shared
)

if [[ -n "${OPENSSL_CONFIG_TARGET}" ]]; then
    configure_cmd=(
        perl
        ./Configure
        "${OPENSSL_CONFIG_TARGET}"
        --prefix="${OPENSSL_INSTALL_DIR}"
        --openssldir="${OPENSSL_INSTALL_DIR}/ssl"
        shared
    )
fi

"${configure_cmd[@]}"
make -j"${JOBS}"
make install_sw

grep -q "OPENSSL_VERSION_STR \"${OPENSSL_VERSION}\"" "${OPENSSL_INSTALL_DIR}/include/openssl/opensslv.h"
