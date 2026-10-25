#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 CuteFish Universal Package contributors
# SPDX-License-Identifier: BSD-3-Clause
# Universal Linux Installer for CuteFish Universal Package (CUP v3.0)
# Supports Debian, Ubuntu, CutefishOS, Fedora, Arch Linux, openSUSE, Alpine, etc.
set -euo pipefail

PREFIX="${PREFIX:-/usr}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "${SCRIPT_DIR}/bin" ]; then
    SRC_DIR="${SCRIPT_DIR}"
else
    SRC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
fi
BIN_DIR="${PREFIX}/bin"
LIB_DIR="${PREFIX}/lib/x86_64-linux-gnu"
if [ ! -d "${PREFIX}/lib/x86_64-linux-gnu" ] && [ -d "${PREFIX}/lib64" ]; then
    LIB_DIR="${PREFIX}/lib64"
elif [ ! -d "${PREFIX}/lib/x86_64-linux-gnu" ]; then
    LIB_DIR="${PREFIX}/lib"
fi
INCLUDE_DIR="${PREFIX}/include/cup"
DATA_DIR="${PREFIX}/share"
BINFMT_DIR="${PREFIX}/lib/binfmt.d"
if [ ! -d "${BINFMT_DIR}" ] && [ -d "/etc/binfmt.d" ]; then
    BINFMT_DIR="/etc/binfmt.d"
fi

echo "============================================================"
echo " CuteFish Universal Package (CUP v3.0) Universal Installer"
echo " Target Prefix: ${PREFIX}"
echo "============================================================"

# Ensure root privileges if installing into system prefix
if [ "${PREFIX}" = "/usr" ] || [ "${PREFIX}" = "/usr/local" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        echo "Error: Installation to ${PREFIX} requires root privileges." >&2
        echo "Please re-run with: sudo $0" >&2
        exit 1
    fi
fi

echo "==> Creating directories..."
mkdir -p "${BIN_DIR}" "${LIB_DIR}" "${INCLUDE_DIR}" \
         "${DATA_DIR}/applications" \
         "${DATA_DIR}/mime/packages" \
         "${DATA_DIR}/icons/hicolor/scalable/apps" \
         "${DATA_DIR}/icons/hicolor/scalable/mimetypes" \
         "${BINFMT_DIR}" \
         "/var/lib/cup/apps"

echo "==> Installing binaries..."
cp -f "${SRC_DIR}/bin/cup" "${BIN_DIR}/cup"
cp -f "${SRC_DIR}/bin/cup-cli" "${BIN_DIR}/cup-cli"
cp -f "${SRC_DIR}/bin/cup-installer" "${BIN_DIR}/cup-installer"
cp -f "${SRC_DIR}/bin/cup-builder" "${BIN_DIR}/cup-builder"
cp -f "${SRC_DIR}/bin/cup-stub" "${BIN_DIR}/cup-stub"
if [ -f "${SRC_DIR}/gui/build/cup-gui-installer" ]; then
    cp -f "${SRC_DIR}/gui/build/cup-gui-installer" "${BIN_DIR}/cup-gui-installer"
elif [ -f "${SRC_DIR}/bin/cup-gui-installer" ]; then
    cp -f "${SRC_DIR}/bin/cup-gui-installer" "${BIN_DIR}/cup-gui-installer"
fi
chmod 755 "${BIN_DIR}/cup"*

echo "==> Installing libraries and headers..."
if [ -f "${SRC_DIR}/lib/libcup2.a" ]; then
    cp -f "${SRC_DIR}/lib/libcup2.a" "${LIB_DIR}/libcup2.a"
fi
if [ -f "${SRC_DIR}/lib/libcup2.so" ]; then
    cp -f "${SRC_DIR}/lib/libcup2.so" "${LIB_DIR}/libcup2.so.3.0.0"
    ln -sf "libcup2.so.3.0.0" "${LIB_DIR}/libcup2.so.3"
    ln -sf "libcup2.so.3" "${LIB_DIR}/libcup2.so"
fi
if [ -d "${SRC_DIR}/c_core" ]; then
    cp -f "${SRC_DIR}/c_core/libcup2.h" "${INCLUDE_DIR}/" 2>/dev/null || true
    cp -f "${SRC_DIR}/c_core/cup_abi_solver.hpp" "${INCLUDE_DIR}/" 2>/dev/null || true
fi

echo "==> Installing desktop, MIME, and icon resources..."
if [ -f "${SRC_DIR}/gui/cup-gui-installer.desktop" ]; then
    cp -f "${SRC_DIR}/gui/cup-gui-installer.desktop" "${DATA_DIR}/applications/"
fi
if [ -f "${SRC_DIR}/data/cup.xml" ]; then
    cp -f "${SRC_DIR}/data/cup.xml" "${DATA_DIR}/mime/packages/"
fi
if [ -f "${SRC_DIR}/data/cup.conf" ]; then
    cp -f "${SRC_DIR}/data/cup.conf" "${BINFMT_DIR}/cup.conf"
fi

if [ -f "${SRC_DIR}/gui/icons/cup-gui-installer.svg" ]; then
    cp -f "${SRC_DIR}/gui/icons/cup-gui-installer.svg" "${DATA_DIR}/icons/hicolor/scalable/apps/"
fi
if [ -f "${SRC_DIR}/gui/icons/application-x-cup.svg" ]; then
    cp -f "${SRC_DIR}/gui/icons/application-x-cup.svg" "${DATA_DIR}/icons/hicolor/scalable/mimetypes/"
    cp -f "${SRC_DIR}/gui/icons/application-x-cup.svg" "${DATA_DIR}/icons/hicolor/scalable/mimetypes/application-x-cup-package.svg"
fi
if [ -f "${SRC_DIR}/assets/cup_logo.svg" ]; then
    cp -f "${SRC_DIR}/assets/cup_logo.svg" "${DATA_DIR}/icons/hicolor/scalable/apps/cup.svg"
fi

echo "==> Updating desktop databases and icon caches..."
command -v update-mime-database >/dev/null 2>&1 && update-mime-database "${DATA_DIR}/mime" >/dev/null 2>&1 || true
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "${DATA_DIR}/applications" >/dev/null 2>&1 || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -f -t "${DATA_DIR}/icons/hicolor" >/dev/null 2>&1 || true
command -v ldconfig >/dev/null 2>&1 && ldconfig >/dev/null 2>&1 || true

# Register with active binfmt_misc if available
if [ -f /proc/sys/fs/binfmt_misc/register ] && [ -f "${BINFMT_DIR}/cup.conf" ]; then
    grep -v '^#' "${BINFMT_DIR}/cup.conf" | while read -r line; do
        if [ -n "$line" ]; then
            echo "$line" > /proc/sys/fs/binfmt_misc/register 2>/dev/null || true
        fi
    done
fi

echo "==> CuteFish Universal Package (CUP v3.0) successfully installed on this system!"
echo "    CLI Tool:        ${BIN_DIR}/cup"
echo "    GUI Installer:   ${BIN_DIR}/cup-gui-installer"
echo "    Package Builder: ${BIN_DIR}/cup-builder"
echo ""
echo "Try running: cup --help"
