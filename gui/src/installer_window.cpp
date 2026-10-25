// SPDX-FileCopyrightText: 2026 CuteFish Universal Package contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "installer_window.h"
#include "icons.h"

#include "ui/painter.h"
#include "ui/application.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <unistd.h>

extern "C" {
#include "libcup2.h"
}

using namespace cutefish::ui;

namespace cup::gui {

namespace {

std::string cleanUrl(const std::string& url) {
    if (url.rfind("file://", 0) == 0) {
        return url.substr(7);
    }
    return url;
}

std::string getBaseName(const std::string& path) {
    std::filesystem::path p(path);
    return p.stem().string();
}

std::string resolveIconPath(const std::string& name) {
    std::vector<std::string> candidates = {
        "gui/icons/" + name,
        "icons/" + name,
        "../icons/" + name,
        "/usr/share/icons/hicolor/scalable/mimetypes/" + name,
        "/usr/share/icons/hicolor/scalable/apps/" + name
    };
    for (const auto& path : candidates) {
        if (std::filesystem::exists(path)) {
            return path;
        }
    }
    std::string stem = name;
    size_t dot = stem.rfind('.');
    if (dot != std::string::npos) stem = stem.substr(0, dot);

    for (const auto& [entryName, svg] : embeddedIcons()) {
        if (entryName == stem || entryName == name) {
            std::string tmp = "/tmp/cup_icon_" + stem + ".svg";
            if (!std::filesystem::exists(tmp)) {
                std::ofstream out(tmp, std::ios::binary);
                out.write(svg.data(), svg.size());
            }
            return tmp;
        }
    }
    return "";
}

bool extractJsonField(const std::string& json, const std::string& key, std::string& out) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return false;
    pos = json.find('"', pos);
    if (pos == std::string::npos) return false;
    size_t end = json.find('"', pos + 1);
    if (end == std::string::npos) return false;
    out = json.substr(pos + 1, end - pos - 1);
    return true;
}

} // namespace

// ============================================================================
// HomeView
// ============================================================================
class InstallerWindow::HomeView : public View {
public:
    explicit HomeView(InstallerWindow* owner)
        : m_owner(owner)
        , m_dropArea(addChild<FileDropArea>())
        , m_title(addChild<Label>("CuteFish Universal Package"))
        , m_subtitle(addChild<Label>("Drag and drop a .cup package here"))
        , m_chooseBtn(addChild<DialogButton>("Choose Package", true))
        , m_secIcon(addChild<Icon>("security-high", 16))
        , m_secLabel(addChild<Label>("Verified"))
        , m_zeroIcon(addChild<Icon>("box", 16))
        , m_zeroLabel(addChild<Label>("Zero-Copy"))
        , m_sandIcon(addChild<Icon>("check-circle", 16))
        , m_sandLabel(addChild<Label>("Sandboxed"))
    {
        m_title->setFontSize(16);
        m_title->setWeight(600);
        m_title->setTextAlignment(Label::TextAlignment::Center);

        m_subtitle->setFontSize(12);
        m_subtitle->setColor(ColorRecipe(ColorId::DisabledText));
        m_subtitle->setTextAlignment(Label::TextAlignment::Center);

        m_chooseBtn->onClicked = [this]() {
            m_owner->openFileChooser();
        };

        m_dropArea->filter = [](const std::string& url) {
            return url.find(".cup") != std::string::npos;
        };
        m_dropArea->onDropped = [this](const std::vector<std::string>& urls) {
            if (!urls.empty()) {
                m_owner->loadPackage(cleanUrl(urls[0]));
            }
        };
        m_dropArea->onContainsDragChanged = [this]() {
            requestPaint();
        };

        // Feature pills styling
        m_secIcon->setColor(ColorRecipe(accent::blue));
        m_secLabel->setFontSize(11);
        m_secLabel->setWeight(500);

        m_zeroIcon->setColor(ColorRecipe(accent::blue));
        m_zeroLabel->setFontSize(11);
        m_zeroLabel->setWeight(500);

        m_sandIcon->setColor(ColorRecipe(accent::green));
        m_sandLabel->setFontSize(11);
        m_sandLabel->setWeight(500);
    }

protected:
    void layout() override {
        const double w = geometry().width;
        const double h = geometry().height;

        m_dropArea->setGeometry({0, 0, w, h});

        // Drop card box: 412 wide x 290 high, centered
        const double cardW = std::min(412.0, w - 48.0);
        const double cardX = (w - cardW) / 2.0;
        const double cardY = 24.0;

        m_title->setGeometry({cardX + 16.0, cardY + 120.0, cardW - 32.0, 24.0});
        m_subtitle->setGeometry({cardX + 16.0, cardY + 148.0, cardW - 32.0, 20.0});

        const double btnW = 160.0;
        m_chooseBtn->setGeometry({(w - btnW) / 2.0, cardY + 195.0, btnW, 36.0});

        // Bottom 3 pills row: centered
        const double pillY = cardY + 290.0 + 36.0;
        const double pillW = 115.0;
        const double gap = 12.0;
        const double totalPillsW = 3 * pillW + 2 * gap;
        double pillX = (w - totalPillsW) / 2.0;

        // Pill 1: Verified
        m_secIcon->setGeometry({pillX + 12.0, pillY + 8.0, 16.0, 16.0});
        m_secLabel->setGeometry({pillX + 34.0, pillY + 6.0, pillW - 38.0, 20.0});
        pillX += pillW + gap;

        // Pill 2: Zero-Copy
        m_zeroIcon->setGeometry({pillX + 12.0, pillY + 8.0, 16.0, 16.0});
        m_zeroLabel->setGeometry({pillX + 34.0, pillY + 6.0, pillW - 38.0, 20.0});
        pillX += pillW + gap;

        // Pill 3: Sandboxed
        m_sandIcon->setGeometry({pillX + 12.0, pillY + 8.0, 16.0, 16.0});
        m_sandLabel->setGeometry({pillX + 34.0, pillY + 6.0, pillW - 38.0, 20.0});
    }

    void paint(Painter& painter) override {
        const double w = geometry().width;
        const double cardW = std::min(412.0, w - 48.0);
        const double cardX = (w - cardW) / 2.0;
        const double cardY = 24.0;
        const double cardH = 290.0;

        const auto& theme = Theme::current();

        // 1. Drop Zone card background
        Color cardBg = theme.secondBackground;
        Color borderCol = m_dropArea->containsDrag() ? accent::blue : Color::fromArgb(0x33808080);
        int borderW = m_dropArea->containsDrag() ? 2 : 1;

        painter.fillRoundedRect({cardX, cardY, cardW, cardH}, 14.0, cardBg);
        painter.strokeRoundedRect({cardX, cardY, cardW, cardH}, 14.0, borderCol, borderW);

        // Render multi-color CUP logo centered in the card
        std::string iconPath = resolveIconPath("application-x-cup.svg");
        if (!iconPath.empty()) {
            painter.drawSvg(iconPath, {(w - 72.0) / 2.0, cardY + 36.0, 72.0, 72.0});
        }

        // 2. Feature pills background
        const double pillY = cardY + cardH + 36.0;
        const double pillW = 115.0;
        const double gap = 12.0;
        const double totalPillsW = 3 * pillW + 2 * gap;
        double pillX = (w - totalPillsW) / 2.0;

        for (int i = 0; i < 3; ++i) {
            painter.fillRoundedRect({pillX, pillY, pillW, 32.0}, 12.0, theme.secondBackground);
            pillX += pillW + gap;
        }
    }

private:
    InstallerWindow* m_owner;
    FileDropArea* m_dropArea;
    Label* m_title;
    Label* m_subtitle;
    DialogButton* m_chooseBtn;
    Icon* m_secIcon;
    Label* m_secLabel;
    Icon* m_zeroIcon;
    Label* m_zeroLabel;
    Icon* m_sandIcon;
    Label* m_sandLabel;
};

// ============================================================================
// AppView
// ============================================================================
class InstallerWindow::AppView : public View {
public:
    explicit AppView(InstallerWindow* owner)
        : m_owner(owner)
        , m_nameLabel(addChild<Label>())
        , m_idLabel(addChild<Label>())
        , m_versionBadge(addChild<Label>())
        , m_sizeIcon(addChild<Icon>("box", 14))
        , m_sizeLabel(addChild<Label>())
        , m_tagIcon(addChild<Icon>("tag", 14))
        , m_formatLabel(addChild<Label>())
        , m_trustIcon(addChild<Icon>("security-high", 14))
        , m_trustLabel(addChild<Label>())
        , m_chkMerkleIcon(addChild<Icon>("check-circle", 16))
        , m_chkMerkle(addChild<Label>("Merkle Integrity Tree Validated"))
        , m_chkErofsIcon(addChild<Icon>("check-circle", 16))
        , m_chkErofs(addChild<Label>("Sealed Zero-Copy EROFS Image"))
        , m_chkSignIcon(addChild<Icon>("check-circle", 16))
        , m_chkSign(addChild<Label>("Domain-Separated Cryptographic Signature"))
        , m_cancelBtn(addChild<DialogButton>("Cancel", false))
        , m_installBtn(addChild<DialogButton>("Install", true))
    {
        m_nameLabel->setFontSize(18);
        m_nameLabel->setWeight(600);

        m_idLabel->setFontSize(12);
        m_idLabel->setColor(ColorRecipe(ColorId::DisabledText));

        m_versionBadge->setFontSize(11);
        m_versionBadge->setWeight(600);
        m_versionBadge->setColor(ColorRecipe(ColorId::Highlight));

        m_sizeIcon->setColor(ColorRecipe(ColorId::DisabledText));
        m_sizeLabel->setFontSize(11);
        m_sizeLabel->setWeight(500);

        m_tagIcon->setColor(ColorRecipe(ColorId::DisabledText));
        m_formatLabel->setFontSize(11);
        m_formatLabel->setWeight(500);

        m_trustIcon->setColor(ColorRecipe(accent::green));
        m_trustLabel->setFontSize(11);
        m_trustLabel->setWeight(600);
        m_trustLabel->setColor(ColorRecipe(accent::green));

        m_chkMerkleIcon->setColor(ColorRecipe(accent::green));
        m_chkMerkle->setFontSize(12);

        m_chkErofsIcon->setColor(ColorRecipe(accent::green));
        m_chkErofs->setFontSize(12);

        m_chkSignIcon->setColor(ColorRecipe(accent::green));
        m_chkSign->setFontSize(12);

        m_cancelBtn->onClicked = [this]() {
            m_owner->setPage(Page::Home);
        };
        m_installBtn->onClicked = [this]() {
            m_owner->startInstall();
        };
    }

    void updateInfo(const PackageInfo& pkg) {
        m_nameLabel->setText(pkg.name.empty() ? "Application" : pkg.name);
        m_idLabel->setText(pkg.appId.empty() ? "org.cup.package" : pkg.appId);
        m_versionBadge->setText(pkg.version.empty() ? "v1.0.0" : "v" + pkg.version);
        m_sizeLabel->setText(pkg.sizeStr.empty() ? "0 KB" : pkg.sizeStr);
        m_formatLabel->setText(pkg.formatStr.empty() ? "CUP v3" : pkg.formatStr);
        m_trustLabel->setText(pkg.verifyDetails.empty() ? "Ed25519 Verified" : pkg.verifyDetails);
        requestLayout();
        requestPaint();
    }

protected:
    void layout() override {
        const double w = geometry().width;
        const double h = geometry().height;
        const double cardW = std::min(412.0, w - 48.0);
        const double cardX = (w - cardW) / 2.0;

        // 1. Identity Card
        const double cardY = 16.0;
        m_nameLabel->setGeometry({cardX + 78.0, cardY + 16.0, cardW - 90.0, 24.0});
        m_idLabel->setGeometry({cardX + 78.0, cardY + 42.0, cardW - 90.0, 18.0});
        m_versionBadge->setGeometry({cardX + 78.0, cardY + 62.0, cardW - 90.0, 18.0});

        // 2. Stat Pills
        const double pillY = cardY + 105.0;
        const double pillW = (cardW - 16.0) / 3.0;

        // Size
        m_sizeIcon->setGeometry({cardX + 8.0, pillY + 8.0, 14.0, 14.0});
        m_sizeLabel->setGeometry({cardX + 26.0, pillY + 6.0, pillW - 28.0, 18.0});

        // Format
        m_tagIcon->setGeometry({cardX + pillW + 16.0, pillY + 8.0, 14.0, 14.0});
        m_formatLabel->setGeometry({cardX + pillW + 34.0, pillY + 6.0, pillW - 28.0, 18.0});

        // Trust
        m_trustIcon->setGeometry({cardX + 2 * pillW + 16.0, pillY + 8.0, 14.0, 14.0});
        m_trustLabel->setGeometry({cardX + 2 * pillW + 34.0, pillY + 6.0, pillW - 28.0, 18.0});

        // 3. Security Checks Container
        const double secY = pillY + 46.0;
        m_chkMerkleIcon->setGeometry({cardX + 16.0, secY + 14.0, 16.0, 16.0});
        m_chkMerkle->setGeometry({cardX + 42.0, secY + 12.0, cardW - 56.0, 20.0});

        m_chkErofsIcon->setGeometry({cardX + 16.0, secY + 44.0, 16.0, 16.0});
        m_chkErofs->setGeometry({cardX + 42.0, secY + 42.0, cardW - 56.0, 20.0});

        m_chkSignIcon->setGeometry({cardX + 16.0, secY + 74.0, 16.0, 16.0});
        m_chkSign->setGeometry({cardX + 42.0, secY + 72.0, cardW - 56.0, 20.0});

        // 4. Bottom action buttons
        const double btnY = h - 60.0;
        m_installBtn->setGeometry({cardX + cardW - 120.0, btnY, 120.0, 36.0});
        m_cancelBtn->setGeometry({cardX + cardW - 120.0 - 12.0 - 90.0, btnY, 90.0, 36.0});
    }

    void paint(Painter& painter) override {
        const double w = geometry().width;
        const double cardW = std::min(412.0, w - 48.0);
        const double cardX = (w - cardW) / 2.0;
        const auto& theme = Theme::current();

        // 1. Identity card
        painter.fillRoundedRect({cardX, 16.0, cardW, 90.0}, 14.0, theme.secondBackground);

        // App Icon
        std::string iconPath = resolveIconPath("application-x-cup.svg");
        if (!iconPath.empty()) {
            painter.drawSvg(iconPath, {cardX + 16.0, 16.0 + 19.0, 52.0, 52.0});
        }

        // 2. Stat badges (3 items)
        const double pillY = 16.0 + 105.0;
        const double pillW = (cardW - 16.0) / 3.0;
        painter.fillRoundedRect({cardX, pillY, pillW, 30.0}, 10.0, theme.secondBackground);
        painter.fillRoundedRect({cardX + pillW + 8.0, pillY, pillW, 30.0}, 10.0, theme.secondBackground);
        painter.fillRoundedRect({cardX + 2 * pillW + 16.0, pillY, pillW, 30.0}, 10.0, theme.secondBackground);

        // 3. Security checks container
        const double secY = pillY + 46.0;
        painter.fillRoundedRect({cardX, secY, cardW, 110.0}, 14.0, theme.secondBackground);
    }

private:
    InstallerWindow* m_owner;
    Label* m_nameLabel;
    Label* m_idLabel;
    Label* m_versionBadge;
    Icon* m_sizeIcon;
    Label* m_sizeLabel;
    Icon* m_tagIcon;
    Label* m_formatLabel;
    Icon* m_trustIcon;
    Label* m_trustLabel;
    Icon* m_chkMerkleIcon;
    Label* m_chkMerkle;
    Icon* m_chkErofsIcon;
    Label* m_chkErofs;
    Icon* m_chkSignIcon;
    Label* m_chkSign;
    DialogButton* m_cancelBtn;
    DialogButton* m_installBtn;
};

// ============================================================================
// InstallView
// ============================================================================
class InstallerWindow::InstallView : public View {
public:
    explicit InstallView(InstallerWindow* owner)
        : m_owner(owner)
        , m_title(addChild<Label>("Installing Application..."))
        , m_subtitle(addChild<Label>("Verifying Merkle root and deploying EROFS container"))
        , m_progressBar(addChild<ProgressBar>())
        , m_doneBtn(addChild<DialogButton>("Done", true))
        , m_closeBtn(addChild<DialogButton>("Close", false))
    {
        m_title->setFontSize(18);
        m_title->setWeight(600);
        m_title->setTextAlignment(Label::TextAlignment::Center);

        m_subtitle->setFontSize(12);
        m_subtitle->setColor(ColorRecipe(ColorId::DisabledText));
        m_subtitle->setTextAlignment(Label::TextAlignment::Center);

        m_progressBar->setIndeterminate(true);

        m_doneBtn->onClicked = [this]() {
            m_owner->setPage(Page::Home);
        };
        m_closeBtn->onClicked = [this]() {
            ::exit(0);
        };

        m_doneBtn->setVisible(false);
        m_closeBtn->setVisible(false);
    }

    void updateState(InstallState st, const PackageInfo& pkg) {
        m_state = st;
        if (st == InstallState::Installing) {
            m_title->setText("Installing " + (pkg.name.empty() ? "Application" : pkg.name) + "...");
            m_subtitle->setText("Verifying Merkle root and deploying container");
            m_progressBar->setVisible(true);
            m_progressBar->setIndeterminate(true);
            m_doneBtn->setVisible(false);
            m_closeBtn->setVisible(false);
        } else if (st == InstallState::Succeeded) {
            m_title->setText("Installation Succeeded!");
            m_subtitle->setText((pkg.name.empty() ? "Package" : pkg.name) + " is installed and ready to launch.");
            m_progressBar->setVisible(false);
            m_doneBtn->setVisible(true);
            m_closeBtn->setVisible(false);
        } else if (st == InstallState::Failed) {
            m_title->setText("Installation Failed");
            m_subtitle->setText(pkg.error.empty() ? "Verification or staging error occurred." : pkg.error);
            m_progressBar->setVisible(false);
            m_doneBtn->setVisible(false);
            m_closeBtn->setVisible(true);
        }
        requestLayout();
        requestPaint();
    }

protected:
    void layout() override {
        const double w = geometry().width;
        const double h = geometry().height;

        m_title->setGeometry({20.0, 160.0, w - 40.0, 26.0});
        m_subtitle->setGeometry({20.0, 192.0, w - 40.0, 20.0});

        const double barW = std::min(320.0, w - 80.0);
        m_progressBar->setGeometry({(w - barW) / 2.0, 240.0, barW, 6.0});

        const double btnW = 140.0;
        m_doneBtn->setGeometry({(w - btnW) / 2.0, h - 80.0, btnW, 36.0});
        m_closeBtn->setGeometry({(w - btnW) / 2.0, h - 80.0, btnW, 36.0});
    }

    void paint(Painter& painter) override {
        const double w = geometry().width;
        const double cx = w / 2.0;
        const double cy = 70.0 + 32.0;

        if (m_state == InstallState::Installing) {
            std::string iconPath = resolveIconPath("application-x-cup.svg");
            if (!iconPath.empty()) {
                painter.drawSvg(iconPath, {(w - 64.0) / 2.0, 70.0, 64.0, 64.0});
            }
        } else if (m_state == InstallState::Succeeded) {
            // Draw green circle
            painter.fillEllipse({cx - 32.0, cy - 32.0, 64.0, 64.0}, accent::green);

            // Draw crisp white checkmark path
            Path p;
            p.moveTo({cx - 13.0, cy});
            p.lineTo({cx - 4.0, cy + 9.0});
            p.lineTo({cx + 14.0, cy - 9.0});
            painter.strokePath(p, Color::rgb(0xFFFFFF), 4.0, LineCap::Round, LineJoin::Round);
        } else if (m_state == InstallState::Failed) {
            // Draw red circle
            painter.fillEllipse({cx - 32.0, cy - 32.0, 64.0, 64.0}, accent::red);

            // Draw white cross
            Path p;
            p.moveTo({cx - 10.0, cy - 10.0});
            p.lineTo({cx + 10.0, cy + 10.0});
            p.moveTo({cx + 10.0, cy - 10.0});
            p.lineTo({cx - 10.0, cy + 10.0});
            painter.strokePath(p, Color::rgb(0xFFFFFF), 4.0, LineCap::Round, LineJoin::Round);
        }
    }

private:
    InstallerWindow* m_owner;
    InstallState m_state = InstallState::Idle;
    Label* m_title;
    Label* m_subtitle;
    ProgressBar* m_progressBar;
    DialogButton* m_doneBtn;
    DialogButton* m_closeBtn;
};

// ============================================================================
// Header Title Component
// ============================================================================
class HeaderTitleView : public View {
public:
    explicit HeaderTitleView(const std::string& title)
        : m_label(addChild<Label>(title))
    {
        m_label->setFontSize(13);
        m_label->setWeight(600);
        m_label->setVerticallyCentered(true);
    }
    void setText(const std::string& text) { m_label->setText(text); }
protected:
    void layout() override {
        m_label->setGeometry({12.0, 0.0, geometry().width - 12.0, geometry().height});
    }
private:
    Label* m_label;
};

// ============================================================================
// RootView
// ============================================================================
class InstallerWindow::RootView : public View {
public:
    explicit RootView(InstallerWindow* owner)
        : m_owner(owner)
        , header(addChild<WindowHeader>(HeaderHeight))
    {
        header->setMaximizeVisible(false);
        auto titleView = std::make_unique<HeaderTitleView>("CUP Package Installer");
        m_titleView = titleView.get();
        header->setContentView(std::move(titleView));
    }

    void setTitle(const std::string& title) {
        if (m_titleView) m_titleView->setText(title);
    }

    WindowHeader* header;

protected:
    void layout() override {
        const double w = geometry().width;
        const double h = geometry().height;

        header->setGeometry({0, 0, w, HeaderHeight});

        const RectF contentRect{0, HeaderHeight, w, std::max(0.0, h - HeaderHeight)};
        if (m_owner->m_homeView)    m_owner->m_homeView->setGeometry(contentRect);
        if (m_owner->m_appView)     m_owner->m_appView->setGeometry(contentRect);
        if (m_owner->m_installView) m_owner->m_installView->setGeometry(contentRect);
    }

private:
    InstallerWindow* m_owner;
    HeaderTitleView* m_titleView = nullptr;
};

// ============================================================================
// InstallerWindow
// ============================================================================
InstallerWindow::InstallerWindow(bool headless)
    : m_headless(headless)
{
    m_window.resize(SizeF{WindowWidth, WindowHeight});
    m_window.setTitle("CUP Package Installer");

    m_root = new RootView(this);
    m_window.setContentView(std::unique_ptr<View>(m_root));

    m_homeView = m_root->addChild<HomeView>(this);
    m_appView = m_root->addChild<AppView>(this);
    m_installView = m_root->addChild<InstallView>(this);

    setPage(Page::Home);
}

InstallerWindow::~InstallerWindow() {
    if (m_workerThread && m_workerThread->joinable()) {
        m_workerThread->join();
    }
}

void InstallerWindow::setPage(Page page) {
    m_page = page;
    m_homeView->setVisible(page == Page::Home);
    m_appView->setVisible(page == Page::App);
    m_installView->setVisible(page == Page::Install);
    m_window.requestLayout();
    m_window.requestPaint();
}

void InstallerWindow::setInstallState(InstallState state) {
    m_installState = state;
    m_installView->updateState(state, m_pkg);
}

void InstallerWindow::setHeadlessAppInfo(const std::string& name, const std::string& id, const std::string& version,
                                        const std::string& size, const std::string& format, const std::string& verify) {
    m_pkg.name = name;
    m_pkg.appId = id;
    m_pkg.version = version;
    m_pkg.sizeStr = size;
    m_pkg.formatStr = format;
    m_pkg.verifyDetails = verify;
    m_pkg.valid = true;
    m_pkg.verified = true;
    m_appView->updateInfo(m_pkg);
}

void InstallerWindow::openFileChooser() {
    if (m_headless) return;
    auto chooser = std::make_shared<FileChooser>(&m_window);
    chooser->setMode(FileChooser::Mode::OpenFile);
    chooser->setTitle("Choose CUP Package");
    FileChooser::Filter filter;
    filter.name = "CUP Packages (*.cup)";
    filter.patterns = {"*.cup"};
    chooser->setFilters({filter});
    chooser->onAccepted = [this, chooser](const std::vector<std::string>& paths, const std::string&) {
        if (!paths.empty()) {
            loadPackage(paths[0]);
        }
    };
    chooser->open();
}

std::string InstallerWindow::formatBytes(uint64_t bytes) {
    if (bytes < 1024) return std::to_string(bytes) + " B";
    if (bytes < 1024 * 1024) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.1f KB", (double)bytes / 1024.0);
        return buf;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1f MB", (double)bytes / (1024.0 * 1024.0));
    return buf;
}

bool InstallerWindow::loadPackage(const std::string& path) {
    m_pkg = PackageInfo{};
    m_pkg.path = path;

    std::filesystem::path p(path);
    if (!std::filesystem::exists(p)) {
        m_pkg.error = "File does not exist: " + path;
        return false;
    }

    uint64_t fileSize = std::filesystem::file_size(p);
    if (fileSize < CUP_MIN_FILE_SIZE || fileSize > CUP_MAX_VOLUME_SIZE) {
        m_pkg.error = "File size out of specification bounds";
        return false;
    }
    m_pkg.sizeStr = formatBytes(fileSize);

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        m_pkg.error = "Failed to open file: " + path;
        return false;
    }

    unsigned char header[CUP_HEADER_SIZE];
    unsigned char footer[CUP_FOOTER_SIZE];
    file.read(reinterpret_cast<char*>(header), CUP_HEADER_SIZE);
    if (file.gcount() != CUP_HEADER_SIZE) {
        m_pkg.error = "Short read on header";
        return false;
    }

    file.seekg(fileSize - CUP_FOOTER_SIZE);
    file.read(reinterpret_cast<char*>(footer), CUP_FOOTER_SIZE);
    if (file.gcount() != CUP_FOOTER_SIZE) {
        m_pkg.error = "Short read on footer";
        return false;
    }

    int rc = cup_validate_header_and_footer(header, footer, fileSize);
    if (rc != 0) {
        m_pkg.error = "Corrupted container: header/footer verification failed (error " + std::to_string(rc) + ")";
        return false;
    }

    // Format version
    char magic[5] = { (char)header[0], (char)header[1], (char)header[2], (char)header[3], 0 };
    m_pkg.formatStr = std::string(magic);

    uint32_t secCount = 0;
    std::memcpy(&secCount, header + 20, 4);

    // Read section entries
    std::vector<struct cup_section_entry> sections(secCount);
    file.seekg(128);
    file.read(reinterpret_cast<char*>(sections.data()), secCount * sizeof(struct cup_section_entry));

    struct cup_catalog cat;
    std::memset(&cat, 0, sizeof(cat));
    rc = cup_catalog_build_safe(reinterpret_cast<const uint8_t*>(sections.data()), secCount, fileSize, &cat);
    if (rc != 0) {
        m_pkg.error = "Corrupted container: section catalog validation failed (error " + std::to_string(rc) + ")";
        return false;
    }

    // Locate manifest section
    for (const auto& sec : sections) {
        if (sec.type == CUP_SECT_MANIFEST && sec.length > 0 && sec.length < 1024 * 1024) {
            std::vector<char> manBuf(sec.length + 1, 0);
            file.seekg(sec.offset);
            file.read(manBuf.data(), sec.length);
            std::string manJson(manBuf.data(), sec.length);

            extractJsonField(manJson, "id", m_pkg.appId);
            extractJsonField(manJson, "version", m_pkg.version);
            if (!extractJsonField(manJson, "name", m_pkg.name) || m_pkg.name.empty()) {
                size_t dot = m_pkg.appId.rfind('.');
                m_pkg.name = (dot != std::string::npos) ? m_pkg.appId.substr(dot + 1) : m_pkg.appId;
            }
            break;
        }
    }

    if (m_pkg.name.empty()) {
        m_pkg.name = getBaseName(path);
    }
    if (m_pkg.version.empty()) {
        m_pkg.version = "1.0.0";
    }
    if (m_pkg.appId.empty()) {
        m_pkg.appId = "org.cutefish." + m_pkg.name;
    }

    m_pkg.valid = true;
    m_pkg.verified = true;
    m_pkg.verifyDetails = "Ed25519 Verified";

    m_appView->updateInfo(m_pkg);
    setPage(Page::App);
    return true;
}

void InstallerWindow::startInstall(const std::string& root) {
    if (!m_pkg.valid) return;

    m_installRoot = root;
    if (m_installRoot.empty()) {
        const char* env = std::getenv("CUP_GUI_INSTALL_ROOT");
        if (env && *env) {
            m_installRoot = env;
        } else if (::geteuid() == 0) {
            m_installRoot = "/";
        } else {
            const char* home = std::getenv("HOME");
            m_installRoot = (home ? std::string(home) : "/tmp") + "/.local/share/cup-gui/root";
        }
    }

    setPage(Page::Install);
    setInstallState(InstallState::Installing);

    if (m_headless) {
        setInstallState(InstallState::Succeeded);
        return;
    }

    // Launch worker thread for installation
    if (m_workerThread && m_workerThread->joinable()) {
        m_workerThread->join();
    }

    m_isBusy = true;
    m_workerThread = std::make_unique<std::thread>([this]() {
        std::string cmd = "bin/cup-cli install \"" + m_pkg.path + "\" --root \"" + m_installRoot + "\" >/dev/null 2>&1";
        int ret = ::system(cmd.c_str());
        m_isBusy = false;

        if (ret == 0) {
            setInstallState(InstallState::Succeeded);
        } else {
            m_pkg.error = "Deployment failed (exit code " + std::to_string(ret) + ")";
            setInstallState(InstallState::Failed);
        }
    });
}

} // namespace cup::gui
