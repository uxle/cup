// SPDX-FileCopyrightText: 2026 CuteFish Universal Package contributors
// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <string>
#include <memory>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>

#include "ui/window.h"
#include "ui/view.h"
#include "ui/window_header.h"
#include "ui/label.h"
#include "ui/button.h"
#include "ui/dialog_window.h"
#include "ui/progress_bar.h"
#include "ui/icon.h"
#include "ui/file_drop_area.h"
#include "ui/file_chooser.h"
#include "ui/theme.h"

namespace cup::gui {

enum class Page {
    Home = 0,
    App,
    Install
};

enum class InstallState {
    Idle = 0,
    Installing,
    Succeeded,
    Failed
};

struct PackageInfo {
    std::string path;
    std::string name;
    std::string appId;
    std::string version;
    std::string sizeStr;
    std::string formatStr;
    std::string verifyDetails;
    bool valid = false;
    bool verified = false;
    std::string error;
};

class InstallerWindow {
public:
    static constexpr double WindowWidth = 460;
    static constexpr double WindowHeight = 500;
    static constexpr double HeaderHeight = 40;

    explicit InstallerWindow(bool headless = false);
    ~InstallerWindow();

    cutefish::ui::Window& window() { return m_window; }

    bool loadPackage(const std::string& path);
    void startInstall(const std::string& root = "");
    void setPage(Page page);
    Page currentPage() const { return m_page; }

    const PackageInfo& packageInfo() const { return m_pkg; }
    InstallState installState() const { return m_installState; }
    void setInstallState(InstallState state);

    // Helpers for headless tests / screenshots
    void setHeadlessAppInfo(const std::string& name, const std::string& id, const std::string& version,
                            const std::string& size, const std::string& format, const std::string& verify);

    static std::string formatBytes(uint64_t bytes);

private:
    class RootView;
    class HomeView;
    class AppView;
    class InstallView;

    void updateViews();
    void openFileChooser();

    cutefish::ui::Window m_window;
    RootView* m_root = nullptr;
    HomeView* m_homeView = nullptr;
    AppView* m_appView = nullptr;
    InstallView* m_installView = nullptr;

    Page m_page = Page::Home;
    InstallState m_installState = InstallState::Idle;
    PackageInfo m_pkg;
    std::string m_installRoot;
    bool m_headless = false;

    std::unique_ptr<std::thread> m_workerThread;
    std::atomic<bool> m_isBusy{false};
};

} // namespace cup::gui
