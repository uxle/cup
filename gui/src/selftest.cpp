// SPDX-FileCopyrightText: 2026 CuteFish Universal Package contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "selftest.h"
#include "installer_window.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>
#include <filesystem>

namespace cup::gui {

namespace {

int s_passed = 0;
int s_failed = 0;

void check(bool condition, const std::string& desc) {
    if (condition) {
        std::cout << "  ok   " << desc << "\n";
        s_passed++;
    } else {
        std::cerr << "  FAIL " << desc << "\n";
        s_failed++;
    }
}

} // namespace

int runHeadlessSelftest(const std::string& packagePath) {
    s_passed = 0;
    s_failed = 0;

    std::cout << "== cup-gui-installer (Cutefish Toolkit) Headless Selftest ==\n";

    // 1. Byte formatting unit checks
    check(InstallerWindow::formatBytes(0) == "0 B", "formatBytes(0) == '0 B'");
    check(InstallerWindow::formatBytes(512) == "512 B", "formatBytes(512) == '512 B'");
    check(InstallerWindow::formatBytes(1024) == "1.0 KB", "formatBytes(1024) == '1.0 KB'");
    check(InstallerWindow::formatBytes(1536) == "1.5 KB", "formatBytes(1536) == '1.5 KB'");
    check(InstallerWindow::formatBytes(1024 * 1024) == "1.0 MB", "formatBytes(1 MiB) == '1.0 MB'");

    // 2. Window instantiation in headless mode
    InstallerWindow win(/*headless=*/true);
    check(win.currentPage() == Page::Home, "Initial page is Home");

    // 3. Reject non-existent file
    check(!win.loadPackage("/nonexistent/path.cup"), "Nonexistent file rejected");

    // 4. Test real package load if provided
    if (!packagePath.empty() && std::filesystem::exists(packagePath)) {
        bool ok = win.loadPackage(packagePath);
        check(ok, "Real package loaded successfully");
        check(win.currentPage() == Page::App, "Page transitioned to App on load");
        check(!win.packageInfo().appId.empty(), "appId extracted (" + win.packageInfo().appId + ")");
        check(!win.packageInfo().version.empty(), "version extracted (" + win.packageInfo().version + ")");
        check(!win.packageInfo().sizeStr.empty(), "size string generated (" + win.packageInfo().sizeStr + ")");
        check(win.packageInfo().formatStr == "CUP3" || win.packageInfo().formatStr == "CUP2", "format signature verified");

        // 5. Test install flow
        win.startInstall("/tmp/cuptest_install_root");
        check(win.currentPage() == Page::Install, "Page transitioned to Install");
        check(win.installState() == InstallState::Succeeded, "Installation state succeeded");

        // 6. Test tampered package fails closed
        std::string tmpTampered = "/tmp/tampered_test.cup";
        {
            std::ifstream in(packagePath, std::ios::binary);
            std::vector<char> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            if (buf.size() > 200) {
                buf[150] ^= 0x55; // corrupt section header
            }
            std::ofstream out(tmpTampered, std::ios::binary);
            out.write(buf.data(), buf.size());
        }

        InstallerWindow winTampered(/*headless=*/true);
        bool tamperOk = winTampered.loadPackage(tmpTampered);
        check(!tamperOk, "Tampered package rejected by gate 1 validation");
        std::filesystem::remove(tmpTampered);
    } else {
        std::cout << "  (Notice: Skipping real package checks as packagePath not given or found)\n";
    }

    std::cout << "== Selftest results: " << s_passed << " passed, " << s_failed << " failed ==\n";
    return s_failed == 0 ? 0 : 1;
}

} // namespace cup::gui
