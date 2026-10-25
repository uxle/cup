#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 CuteFish Universal Package contributors
# SPDX-License-Identifier: BSD-3-Clause
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

VERSION="3.0.0"
PKG_NAME="cup-package-manager"
PKG_DIR="${REPO_ROOT}/debian_pkg"
DEB_FILE="${REPO_ROOT}/${PKG_NAME}_${VERSION}_amd64.deb"

echo "==> 1. Building all CUP binaries, libraries, and GUI installer..."
make all
make gui

echo "==> 2. Preparing package filesystem tree..."
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}/DEBIAN" \
         "${PKG_DIR}/usr/bin" \
         "${PKG_DIR}/usr/lib/x86_64-linux-gnu" \
         "${PKG_DIR}/usr/include/cup" \
         "${PKG_DIR}/usr/share/applications" \
         "${PKG_DIR}/usr/share/mime/packages" \
         "${PKG_DIR}/usr/lib/binfmt.d" \
         "${PKG_DIR}/usr/share/icons/hicolor/scalable/apps" \
         "${PKG_DIR}/usr/share/icons/hicolor/scalable/mimetypes" \
         "${PKG_DIR}/usr/share/icons/Cutefish/apps/scalable" \
         "${PKG_DIR}/usr/share/icons/Cutefish/mimetypes/scalable" \
         "${PKG_DIR}/var/lib/cup/apps"

echo "==> 3. Installing binaries and libraries..."
cp -f bin/cup "${PKG_DIR}/usr/bin/cup"
cp -f bin/cup-cli "${PKG_DIR}/usr/bin/cup-cli"
cp -f bin/cup-installer "${PKG_DIR}/usr/bin/cup-installer"
cp -f bin/cup-builder "${PKG_DIR}/usr/bin/cup-builder"
cp -f bin/cup-stub "${PKG_DIR}/usr/bin/cup-stub"
cp -f gui/build/cup-gui-installer "${PKG_DIR}/usr/bin/cup-gui-installer"
chmod 755 "${PKG_DIR}/usr/bin/"*

cp -f lib/libcup2.a "${PKG_DIR}/usr/lib/x86_64-linux-gnu/libcup2.a"
cp -f lib/libcup2.so "${PKG_DIR}/usr/lib/x86_64-linux-gnu/libcup2.so.${VERSION}"
ln -sf "libcup2.so.${VERSION}" "${PKG_DIR}/usr/lib/x86_64-linux-gnu/libcup2.so.3"
ln -sf "libcup2.so.3" "${PKG_DIR}/usr/lib/x86_64-linux-gnu/libcup2.so"

cp -f c_core/libcup2.h "${PKG_DIR}/usr/include/cup/libcup2.h"
cp -f c_core/cup_abi_solver.hpp "${PKG_DIR}/usr/include/cup/cup_abi_solver.hpp"
cp -f c_core/cup_ui.hpp "${PKG_DIR}/usr/include/cup/cup_ui.hpp" 2>/dev/null || true

echo "==> 4. Installing desktop entries, MIME types, and binfmt configuration..."
cp -f gui/cup-gui-installer.desktop "${PKG_DIR}/usr/share/applications/cup-gui-installer.desktop"
cp -f data/cup.xml "${PKG_DIR}/usr/share/mime/packages/cup.xml"
cp -f data/cup.conf "${PKG_DIR}/usr/lib/binfmt.d/cup.conf"

echo "==> 5. Installing scalable and raster icons..."
# Scalable SVG icons
cp -f gui/icons/cup-gui-installer.svg "${PKG_DIR}/usr/share/icons/hicolor/scalable/apps/cup-gui-installer.svg"
cp -f gui/icons/cup-gui-installer.svg "${PKG_DIR}/usr/share/icons/Cutefish/apps/scalable/cup-gui-installer.svg"
cp -f assets/cup_logo.svg "${PKG_DIR}/usr/share/icons/hicolor/scalable/apps/cup.svg"
cp -f assets/cup_logo.svg "${PKG_DIR}/usr/share/icons/Cutefish/apps/scalable/cup.svg"

cp -f gui/icons/application-x-cup.svg "${PKG_DIR}/usr/share/icons/hicolor/scalable/mimetypes/application-x-cup.svg"
cp -f gui/icons/application-x-cup.svg "${PKG_DIR}/usr/share/icons/Cutefish/mimetypes/scalable/application-x-cup.svg"
cp -f gui/icons/application-x-cup.svg "${PKG_DIR}/usr/share/icons/hicolor/scalable/mimetypes/application-x-cup-package.svg"

# Multi-resolution raster icons (16, 24, 32, 48, 64, 128, 256, 512)
if command -v rsvg-convert >/dev/null 2>&1; then
    for s in 16 24 32 48 64 128 256 512; do
        mkdir -p "${PKG_DIR}/usr/share/icons/hicolor/${s}x${s}/apps" \
                 "${PKG_DIR}/usr/share/icons/hicolor/${s}x${s}/mimetypes"
        rsvg-convert -w "${s}" -h "${s}" gui/icons/cup-gui-installer.svg \
            -o "${PKG_DIR}/usr/share/icons/hicolor/${s}x${s}/apps/cup-gui-installer.png"
        rsvg-convert -w "${s}" -h "${s}" assets/cup_logo.svg \
            -o "${PKG_DIR}/usr/share/icons/hicolor/${s}x${s}/apps/cup.png"
        rsvg-convert -w "${s}" -h "${s}" gui/icons/application-x-cup.svg \
            -o "${PKG_DIR}/usr/share/icons/hicolor/${s}x${s}/mimetypes/application-x-cup.png"
    done
fi

echo "==> 6. Writing Debian control and maintainer scripts..."
cat << 'EOF' > "${PKG_DIR}/DEBIAN/control"
Package: cup-package-manager
Version: 3.0.0
Section: utils
Priority: optional
Architecture: amd64
Maintainer: CuteFish Universal Package Contributors <support@cutefish.org>
Depends: libc6 (>= 2.38), libstdc++6 (>= 14), libgcc-s1 (>= 3.0), libssl3t64 (>= 3.0) | libssl3 (>= 3.0), cutefish-toolkit (>= 1.0)
Provides: cup
Description: CuteFish Universal Package (CUP v3.0) Package Manager & Runtime
 CUP is a next-generation universal Linux packaging format and runtime
 featuring cryptographically sealed containers (Ed25519 + ML-DSA-65), FastCDC
 Merkle integrity trees, zero-copy EROFS mounts, atomic symlink rollbacks,
 direct kernel execution via binfmt_misc, and graphical installer.
EOF

cat << 'EOF' > "${PKG_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
    # Update shared MIME database
    if command -v update-mime-database >/dev/null 2>&1; then
        update-mime-database /usr/share/mime >/dev/null 2>&1 || true
    fi

    # Update desktop database
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
    fi

    # Update icon caches
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -f -t /usr/share/icons/hicolor >/dev/null 2>&1 || true
        if [ -d /usr/share/icons/Cutefish ]; then
            gtk-update-icon-cache -q -f -t /usr/share/icons/Cutefish >/dev/null 2>&1 || true
        fi
    fi

    # Reload shared libraries
    ldconfig >/dev/null 2>&1 || true

    # Register binfmt_misc if systemd-binfmt is active
    if [ -d /proc/sys/fs/binfmt_misc ] && [ -f /usr/lib/binfmt.d/cup.conf ]; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl restart systemd-binfmt.service >/dev/null 2>&1 || true
        fi
    fi
fi

exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

cat << 'EOF' > "${PKG_DIR}/DEBIAN/prerm"
#!/bin/sh
set -e
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/prerm"

cat << 'EOF' > "${PKG_DIR}/DEBIAN/postrm"
#!/bin/sh
set -e

if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    if command -v update-mime-database >/dev/null 2>&1; then
        update-mime-database /usr/share/mime >/dev/null 2>&1 || true
    fi
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -f -t /usr/share/icons/hicolor >/dev/null 2>&1 || true
    fi
    ldconfig >/dev/null 2>&1 || true
fi

exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postrm"

echo "==> 7. Building Debian package with dpkg-deb..."
dpkg-deb --build --root-owner-group "${PKG_DIR}" "${DEB_FILE}"

echo "==> 8. Verifying package metadata and contents:"
dpkg-deb -I "${DEB_FILE}"
echo ""
echo "==> Package built successfully: ${DEB_FILE}"
