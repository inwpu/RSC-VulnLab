#!/usr/bin/env bash

set -e

echo "============================================"
echo "[*] Official Nuclei Installer (Proxy Ready)"
echo "============================================"

NUCLEI_VERSION="v3.6.0"
NUCLEI_NAME="nuclei_3.6.0_linux_amd64.zip"
DOWNLOAD_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/${NUCLEI_NAME}"

WORKDIR="/tmp/nuclei-install"
BIN_PATH="/usr/local/bin/nuclei"

echo "[*] Version: ${NUCLEI_VERSION}"
echo "[*] Download URL:"
echo "    ${DOWNLOAD_URL}"
echo "[*] Working directory: ${WORKDIR}"
echo

mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

echo "[*] Downloading nuclei from official GitHub..."

if ! wget -O "${NUCLEI_NAME}" "${DOWNLOAD_URL}"; then
  echo
  echo "[!] Download failed!"
  echo "[!] Please verify:"
  echo "    1. Your proxy is working"
  echo "    2. GitHub is reachable"
  echo
  exit 1
fi

echo "[+] Download success!"

echo "[*] Installing unzip..."
sudo apt update -y
sudo apt install -y unzip

echo "[*] Unzipping nuclei..."
unzip -o "${NUCLEI_NAME}"

if [ ! -f "nuclei" ]; then
  echo "[!] ERROR: nuclei binary not found after unzip!"
  exit 1
fi

echo "[*] Installing nuclei to ${BIN_PATH} ..."
sudo mv nuclei "${BIN_PATH}"
sudo chmod +x "${BIN_PATH}"

echo "[*] Verifying installation..."
nuclei -version || {
  echo "[!] nuclei install failed!"
  exit 1
}

echo
echo "[+] nuclei installation completed successfully!"
echo "[+] Binary path: ${BIN_PATH}"
echo "[+] Version info:"
nuclei -version
echo "============================================"

