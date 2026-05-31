#!/bin/sh
# kapsaro installer
# Usage: curl -fsSL https://raw.githubusercontent.com/ebisawa/kapsaro/main/install.sh | sh

set -eu

REPO="ebisawa/kapsaro"
BIN_NAME="kapsaro"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

compute_sha256() {
  file="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    hash="$(sha256sum "${file}" 2>/dev/null | awk '{print $1}')"
    if [ -n "${hash}" ]; then
      printf '%s\n' "${hash}"
      return 0
    fi
  fi

  if command -v shasum >/dev/null 2>&1; then
    hash="$(shasum -a 256 "${file}" 2>/dev/null | awk '{print $1}')"
    if [ -n "${hash}" ]; then
      printf '%s\n' "${hash}"
      return 0
    fi
  fi

  if command -v openssl >/dev/null 2>&1; then
    hash="$(openssl dgst -sha256 "${file}" 2>/dev/null | awk '{print $NF}')"
    if [ -n "${hash}" ]; then
      printf '%s\n' "${hash}"
      return 0
    fi
  fi

  return 1
}

# Detect OS
OS="$(uname -s)"
case "${OS}" in
  Linux)  OS="linux" ;;
  Darwin) OS="darwin" ;;
  *)
    echo "Unsupported OS: ${OS}" >&2
    exit 1
    ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64)        ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *)
    echo "Unsupported architecture: ${ARCH}" >&2
    exit 1
    ;;
esac

# Map to release target triple
if [ "${OS}" = "darwin" ] && [ "${ARCH}" = "x86_64" ]; then
  echo "macOS x86_64 (Intel) is no longer supported. Please use an Apple Silicon Mac." >&2
  exit 1
elif [ "${OS}" = "linux" ] && [ "${ARCH}" = "x86_64" ]; then
  TARGET="x86_64-unknown-linux-gnu"
elif [ "${OS}" = "linux" ] && [ "${ARCH}" = "aarch64" ]; then
  TARGET="aarch64-unknown-linux-gnu"
elif [ "${OS}" = "darwin" ] && [ "${ARCH}" = "aarch64" ]; then
  TARGET="aarch64-apple-darwin"
else
  echo "Unsupported platform: ${OS}/${ARCH}" >&2
  exit 1
fi

# Get latest version from GitHub API
echo "Fetching latest version..."
TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
if [ -z "${TAG}" ]; then
  echo "Failed to fetch latest version" >&2
  exit 1
fi
echo "Latest version: ${TAG}"

# Download and extract
ARCHIVE="${BIN_NAME}-${TAG}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${TAG}/SHA256SUMS"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "Downloading ${URL}..."
curl -fsSL "${URL}" -o "${TMP_DIR}/${ARCHIVE}"

echo "Downloading ${CHECKSUMS_URL}..."
curl -fsSL "${CHECKSUMS_URL}" -o "${TMP_DIR}/SHA256SUMS"

EXPECTED_SHA256="$(awk -v archive="${ARCHIVE}" '$2 == archive { print $1; exit }' "${TMP_DIR}/SHA256SUMS")"
if [ -z "${EXPECTED_SHA256}" ]; then
  echo "Checksum not found for ${ARCHIVE}" >&2
  exit 1
fi

if ! ACTUAL_SHA256="$(compute_sha256 "${TMP_DIR}/${ARCHIVE}")"; then
  echo "No SHA256 command found. Please install sha256sum, shasum, or openssl." >&2
  exit 1
fi

if [ "${ACTUAL_SHA256}" != "${EXPECTED_SHA256}" ]; then
  echo "SHA256 mismatch for ${ARCHIVE}" >&2
  echo "Expected: ${EXPECTED_SHA256}" >&2
  echo "Actual:   ${ACTUAL_SHA256}" >&2
  exit 1
fi

echo "SHA256 verified."
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}"

# Install binary
if [ -w "${INSTALL_DIR}" ]; then
  cp "${TMP_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
  chmod +x "${INSTALL_DIR}/${BIN_NAME}"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo cp "${TMP_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
  sudo chmod +x "${INSTALL_DIR}/${BIN_NAME}"
fi

echo ""
echo "kapsaro ${TAG} installed to ${INSTALL_DIR}/${BIN_NAME}"
echo "Run 'kapsaro --help' to get started."
