// SPDX-FileCopyrightText: 2026 CuteFish Universal Package contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "icons.h"
#include "installer_window.h"
#include "selftest.h"

#include "ui/application.h"
#include "ui/icon.h"
#include "ui/theme.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

using namespace cutefish;
using namespace cup::gui;

int main(int argc, char** argv) {
    bool runSelftest = false;
    bool takeScreenshots = false;
    std::string screenshotDir;
    std::string packagePath;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            std::printf("Usage: %s [options] [package.cup]\n\n"
                        "Options:\n"
                        "  -h, --help               Display this help text\n"
                        "  -v, --version            Display version information\n"
                        "  --selftest [pkg.cup]     Run headless self-tests\n"
                        "  --screenshot DIR [pkg]   Render and save UI page screenshots\n",
                        argv[0]);
            return 0;
        }
        if (arg == "-v" || arg == "--version") {
            std::printf("cup-gui-installer %s (Cutefish Toolkit)\n", CUP_GUI_VERSION);
            return 0;
        }
        if (arg == "--selftest") {
            runSelftest = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                packagePath = argv[++i];
            }
            continue;
        }
        if (arg == "--screenshot") {
            takeScreenshots = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                screenshotDir = argv[++i];
            } else {
                screenshotDir = "screenshots";
            }
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                packagePath = argv[++i];
            }
            continue;
        }
        if (arg[0] != '-') {
            packagePath = arg;
        }
    }

    if (runSelftest) {
        ui::Application app(argc, argv, ui::Application::Platform::Headless);
        for (const auto& [name, svg] : embeddedIcons()) {
            ui::Icon::registerGlyph(std::string(name), std::string(svg));
        }
        return runHeadlessSelftest(packagePath);
    }

    if (takeScreenshots) {
        std::filesystem::create_directories(screenshotDir);
        ui::Application app(argc, argv, ui::Application::Platform::Headless);
        for (const auto& [name, svg] : embeddedIcons()) {
            ui::Icon::registerGlyph(std::string(name), std::string(svg));
        }

        ui::Theme::setCurrent(ui::Theme::light());
        InstallerWindow window(/*headless=*/true);
        window.window().setScale(1.5);
        window.window().show();

        // 1. Home Page Screenshot
        window.setPage(Page::Home);
        std::string homePng = screenshotDir + "/home.png";
        window.window().grab().savePng(homePng);
        std::printf("SCREENSHOT saved: \"%s\"\n", homePng.c_str());

        // 2. App Page Screenshot
        if (!packagePath.empty() && std::filesystem::exists(packagePath)) {
            window.loadPackage(packagePath);
        } else {
            window.setHeadlessAppInfo("FooPaint", "org.foopaint.FooPaint", "3.0.0", "188.8 KB", "CUP v3", "Ed25519 Verified");
            window.setPage(Page::App);
        }
        std::string appPng = screenshotDir + "/app.png";
        window.window().grab().savePng(appPng);
        std::printf("SCREENSHOT saved: \"%s\"\n", appPng.c_str());

        // 3. Install Page Screenshot (Succeeded)
        window.setPage(Page::Install);
        window.setInstallState(InstallState::Succeeded);
        std::string installPng = screenshotDir + "/install.png";
        window.window().grab().savePng(installPng);
        std::printf("SCREENSHOT saved: \"%s\"\n", installPng.c_str());

        return 0;
    }

    // Interactive Wayland Application
    ui::Application app(argc, argv, ui::Application::Platform::Wayland);
    app.setApplicationId("cup-gui-installer");

    for (const auto& [name, svg] : embeddedIcons()) {
        ui::Icon::registerGlyph(std::string(name), std::string(svg));
    }

    InstallerWindow window;
    if (!packagePath.empty()) {
        window.loadPackage(packagePath);
    }
    window.window().show();

    return app.run();
}
