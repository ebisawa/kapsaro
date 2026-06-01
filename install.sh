#!/bin/sh
# kapsaro installer
# Usage: curl -fsSL https://raw.githubusercontent.com/ebisawa/kapsaro/main/install.sh | sh

set -eu

REPO="ebisawa/kapsaro"
BIN_NAME="kapsaro"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

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

# Download and verify
ARCHIVE="${BIN_NAME}-${TAG}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "Downloading ${URL}..."
curl -fsSL "${URL}" -o "${TMP_DIR}/${ARCHIVE}"

# Verify the archive's build provenance via GitHub Artifact Attestations.
# The attestation bundle is shipped with the release, so verification works
# offline and needs no gh authentication. Verification is required by default.
# Opt out of it only when gh is unavailable or when explicitly skipping, by
# setting KAPSARO_INSECURE=1.
if [ "${KAPSARO_INSECURE:-}" = "1" ]; then
  echo "WARNING: KAPSARO_INSECURE=1 set; installing without provenance verification." >&2
elif command -v gh >/dev/null 2>&1; then
  BUNDLE="${BIN_NAME}-${TAG}.sigstore.jsonl"
  BUNDLE_URL="https://github.com/${REPO}/releases/download/${TAG}/${BUNDLE}"
  echo "Downloading attestation bundle..."
  curl -fsSL "${BUNDLE_URL}" -o "${TMP_DIR}/${BUNDLE}"
  echo "Verifying build provenance..."
  if ! gh attestation verify "${TMP_DIR}/${ARCHIVE}" --bundle "${TMP_DIR}/${BUNDLE}" --repo "${REPO}"; then
    echo "Provenance verification failed for ${ARCHIVE}." >&2
    exit 1
  fi
  echo "Provenance verified."
else
  echo "GitHub CLI (gh) is required to verify build provenance but was not found." >&2
  echo "Install it from https://cli.github.com and retry," >&2
  echo "or set KAPSARO_INSECURE=1 to install without verification." >&2
  exit 1
fi

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
