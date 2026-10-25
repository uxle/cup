/*
 * cupinstaller.cpp — see cupinstaller.h for the architecture rationale.
 *
 * Security notes (this file is part of the audited CUP suite surface):
 *   - No shell is ever involved: QProcess::start(program, argv-list).
 *   - The .cup path is normalised to an absolute path before use and is
 *     only ever passed as a single argv element.
 *   - Untrusted file bytes only ever feed display strings capped in length
 *     and rendered through QML text items (no markup evaluation: plain
 *     text, no rich-text on log/details labels).
 *   - The Install button requires signaturesValid, which can only become
 *     true after `cup-cli verify --strict` exits 0 on the SAME path.
 */
#include "cupinstaller.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QScopeGuard>
#include <QStandardPaths>
#include <QUrl>

#include <unistd.h>

extern "C" {
#include "libcup2.h"
}

namespace {

/* Little-endian scalar readers (same convention as the C core). */
inline quint32 readU32Le(const unsigned char *p)
{
    return quint32(p[0]) | (quint32(p[1]) << 8) | (quint32(p[2]) << 16) | (quint32(p[3]) << 24);
}

/* Header field offsets (normative layout, see spec section 5). */
constexpr int kHdrSectionCountOff = 20;
constexpr int kHdrAbiTagOff       = 64;
constexpr int kHdrAbiTagLen       = 16;

QString trimmedAscii(const unsigned char *p, int len)
{
    QByteArray raw;
    raw.setRawData(reinterpret_cast<const char *>(p), len);
    // Only keep printable ASCII; anything else collapses to spaces.
    QByteArray clean;
    clean.reserve(len);
    for (char c : raw) {
        unsigned char uc = static_cast<unsigned char>(c);
        clean.append(uc >= 0x20 && uc <= 0x7E ? c : ' ');
    }
    return QString::fromLatin1(clean).trimmed();
}

} // namespace

CupInstaller::CupInstaller(QObject *parent)
    : QObject(parent)
    , m_valid(false)
    , m_signaturesValid(false)
    , m_isInstalled(false)
    , m_status(Begin)
    , m_process(new QProcess(this))
    , m_processIsInstall(false)
    , m_verifyTimeoutMs(60 * 1000)
    , m_installTimeoutMs(300 * 1000)
{
    m_installRoot = defaultInstallRoot();
    m_backendPath = resolveBackendPath();

    m_process->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_process, &QProcess::readyReadStandardOutput,
            this, &CupInstaller::onReadyReadStandardOutput);
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this](int code, QProcess::ExitStatus st) {
                if (m_processIsInstall)
                    onInstallFinished(code, st);
                else
                    onVerifyFinished(code, st);
            });
    connect(m_process, &QProcess::errorOccurred,
            this, &CupInstaller::onProcessError);

    m_timeoutTimer.setSingleShot(true);
    connect(&m_timeoutTimer, &QTimer::timeout, this, &CupInstaller::onTimeout);
}

CupInstaller::~CupInstaller()
{
    killCurrentProcess();
}

// ---------------------------------------------------------------------------
// Property accessors
// ---------------------------------------------------------------------------

QString CupInstaller::fileName() const { return m_fileName; }
QString CupInstaller::packageName() const { return m_packageName; }
QString CupInstaller::version() const { return m_version; }
QString CupInstaller::uri() const { return m_uri; }
QString CupInstaller::fileSize() const { return m_fileSize; }
QString CupInstaller::sectionCount() const { return m_sectionCount; }
QString CupInstaller::abiTag() const { return m_abiTag; }
QString CupInstaller::installRoot() const { return m_installRoot; }
QString CupInstaller::backendPath() const { return m_backendPath; }

bool CupInstaller::isValid() const { return m_valid; }
bool CupInstaller::signaturesValid() const { return m_signaturesValid; }
bool CupInstaller::isInstalled() const { return m_isInstalled; }

bool CupInstaller::canInstall() const
{
    return m_valid && m_signaturesValid && !busy();
}

bool CupInstaller::busy() const
{
    return m_status == Verifying || m_status == Installing;
}

QString CupInstaller::statusMessage() const { return m_statusMessage; }
QString CupInstaller::statusDetails() const { return m_statusDetails; }
CupInstaller::Status CupInstaller::status() const { return m_status; }

// ---------------------------------------------------------------------------
// fileName (entry point from DropArea / FileDialog / CLI argument)
// ---------------------------------------------------------------------------

void CupInstaller::setFileName(const QString &fileName)
{
    if (busy()) {
        // Never swap the target while a backend operation is in flight.
        setStatusMessage(tr("Busy: please wait for the current operation to finish."));
        return;
    }

    QString path = fileName;
    if (path.startsWith(QStringLiteral("file://")))
        path = QUrl(path).toLocalFile();

    if (path == m_fileName && m_status != Begin && m_status != Error)
        return;

    // Reset all per-package state. Notification happens BEFORE any early
    // return so that the clear-file path (empty path) also updates the UI.
    m_fileName.clear();
    m_packageName.clear();
    m_version.clear();
    m_uri.clear();
    m_fileSize.clear();
    m_sectionCount.clear();
    m_abiTag.clear();
    m_statusDetails.clear();
    m_signaturesValid = false;
    m_valid = false;
    m_statusMessage.clear();
    setStatus(Begin);

    emit fileNameChanged();
    emit packageNameChanged();
    emit versionChanged();
    emit uriChanged();
    emit fileSizeChanged();
    emit sectionCountChanged();
    emit abiTagChanged();
    emit validChanged();
    emit signaturesValidChanged();
    emit canInstallChanged();
    emit statusDetailsChanged();
    emit statusMessageChanged();

    if (path.isEmpty())
        return;

    QFileInfo info(path);
    if (!info.exists() || !info.isFile()) {
        setStatusMessage(tr("File does not exist: %1").arg(path));
        emit fileNameChanged();
        return;
    }
    if (info.suffix().compare(QStringLiteral("cup"), Qt::CaseInsensitive) != 0) {
        setStatusMessage(tr("Not a CUP package (expected a .cup file): %1").arg(path));
        emit fileNameChanged();
        return;
    }

    m_fileName = info.absoluteFilePath();
    emit fileNameChanged();

    // Local, hardened, read-only metadata pass (libcup2, no process spawn).
    QString id, ver, abi, err;
    quint32 sections = 0;
    if (parsePackageMetadata(m_fileName, &id, &ver, &abi, &sections, &err)) {
        m_packageName = id;
        m_version = ver;
        m_abiTag = abi;
        m_sectionCount = QString::number(sections);
        m_fileSize = formatByteSize(static_cast<double>(info.size()));
        m_valid = true;
    } else {
        m_packageName = info.completeBaseName();
        m_statusMessage = tr("Rejected by header check: %1").arg(err);
    }

    refreshInstalledState();
    emit packageNameChanged();
    emit versionChanged();
    emit fileSizeChanged();
    emit sectionCountChanged();
    emit abiTagChanged();
    emit validChanged();
    emit signaturesValidChanged();
    emit canInstallChanged();
    emit isInstalledChanged();
    emit statusMessageChanged();

    if (m_valid) {
        reverify();
    }
}

void CupInstaller::reverify()
{
    if (m_fileName.isEmpty() || busy())
        return;

    killCurrentProcess();

    m_signaturesValid = false;
    m_uri.clear();
    emit signaturesValidChanged();
    emit uriChanged();
    emit canInstallChanged();

    appendLog(tr("$ %1 verify \"%2\" --strict")
                  .arg(QFileInfo(m_backendPath).fileName(), m_fileName));
    appendLog(tr("Backend: %1").arg(m_backendPath));

    if (!launchBackend({ QStringLiteral("verify"), m_fileName, QStringLiteral("--strict") }))
        return;

    m_processIsInstall = false;
    setStatus(Verifying);
    setStatusMessage(tr("Verifying package..."));
    m_timeoutTimer.start(m_verifyTimeoutMs);
}

// ---------------------------------------------------------------------------
// install / clear / reset
// ---------------------------------------------------------------------------

void CupInstaller::install()
{
    if (!canInstall())
        return;
    if (m_status != Ready && m_status != Succeeded && m_status != Error)
        return;

    killCurrentProcess();

    // Non-system roots are created on demand; the system root ("/") must
    // already exist (and normally requires the GUI itself to be privileged).
    if (m_installRoot != QStringLiteral("/")) {
        QDir rootDir(m_installRoot);
        if (!rootDir.exists() && !QDir::root().mkpath(m_installRoot)) {
            setStatus(Error);
            setStatusMessage(tr("Cannot create install root %1").arg(m_installRoot));
            return;
        }
    }

    appendLog(tr("$ %1 install \"%2\" --root \"%3\"")
                  .arg(QFileInfo(m_backendPath).fileName(), m_fileName, m_installRoot));

    if (!launchBackend({ QStringLiteral("install"), m_fileName,
                         QStringLiteral("--root"), m_installRoot }))
        return;

    m_processIsInstall = true;
    setStatus(Installing);
    m_timeoutTimer.start(m_installTimeoutMs);
}

void CupInstaller::clearFile()
{
    if (busy()) {
        setStatusMessage(tr("Busy: please wait for the current operation to finish."));
        return;
    }
    setFileName(QString());
}

void CupInstaller::resetToReady()
{
    if (m_status == Succeeded || m_status == Error) {
        m_statusDetails.clear();
        setStatus(Ready);
        emit statusDetailsChanged();
    }
}

void CupInstaller::openFilePicker()
{
    if (busy()) {
        setStatusMessage(tr("Busy: please wait for the current operation to finish."));
        return;
    }
    const QString path = QFileDialog::getOpenFileName(
        nullptr, tr("Select a CUP package"), QString(),
        tr("CUP packages (*.cup);;All files (*)"));
    if (!path.isEmpty())
        setFileName(path);
}

// ---------------------------------------------------------------------------
// Process plumbing
// ---------------------------------------------------------------------------

bool CupInstaller::launchBackend(const QStringList &args)
{
    QFileInfo backendInfo(m_backendPath);
    if (m_backendPath.isEmpty() || !backendInfo.isExecutable()) {
        setStatus(Error);
        setStatusMessage(tr("Backend cup-cli not found or not executable "
                            "(set CUP_GUI_BACKEND to override)."));
        appendLog(tr("! backend missing: %1").arg(m_backendPath));
        return false;
    }
    m_lineBuffer.clear();
    m_process->start(m_backendPath, args);
    if (!m_process->waitForStarted(5000)) {
        setStatus(Error);
        setStatusMessage(tr("Could not start backend: %1").arg(m_backendPath));
        return false;
    }
    return true;
}

void CupInstaller::onReadyReadStandardOutput()
{
    QByteArray chunk = m_process->readAllStandardOutput();
    m_lineBuffer.append(chunk);
    int nl;
    while ((nl = m_lineBuffer.indexOf('\n')) >= 0) {
        QByteArray line = m_lineBuffer.left(nl);
        m_lineBuffer.remove(0, nl + 1);
        appendLog(QString::fromUtf8(line));
    }
    // Cap buffered partial-line size for hostile backends.
    if (m_lineBuffer.size() > 64 * 1024) {
        appendLog(QString::fromUtf8(m_lineBuffer));
        m_lineBuffer.clear();
    }
}

void CupInstaller::onVerifyFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    m_timeoutTimer.stop();
    if (!m_lineBuffer.isEmpty()) {
        appendLog(QString::fromUtf8(m_lineBuffer));
        m_lineBuffer.clear();
    }

    if (exitStatus != QProcess::NormalExit) {
        setStatus(Error);
        setStatusMessage(tr("Backend crashed during verification."));
        emit verificationFinished(false);
        return;
    }

    if (exitCode == 0) {
        m_signaturesValid = true;
        // Surface the canonical URI the audited CLI verified ("VERIFIED OK:
        // cup://sha256/<hash>?id=<app-id>") — display only, never trusted.
        const int pos = m_statusDetails.lastIndexOf(QStringLiteral("VERIFIED OK: "));
        if (pos >= 0) {
            QString line = m_statusDetails.mid(pos + QStringLiteral("VERIFIED OK: ").size());
            const int nl = line.indexOf(QLatin1Char('\n'));
            if (nl >= 0)
                line.truncate(nl);
            line = line.trimmed();
            if (line.size() <= 512)
                m_uri = line;
            emit uriChanged();
        }
        setStatus(Ready);
        setStatusMessage(tr("Package verified. Ready to install into %1").arg(m_installRoot));
    } else {
        m_signaturesValid = false;
        setStatus(Ready);
        setStatusMessage(tr("Verification FAILED — the package is NOT trusted. "
                            "Installing is disabled."));
        appendLog(tr("! verify exit code: %1").arg(exitCode));
    }
    emit signaturesValidChanged();
    emit canInstallChanged();
    emit verificationFinished(m_signaturesValid);
}

void CupInstaller::onInstallFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    m_timeoutTimer.stop();
    if (!m_lineBuffer.isEmpty()) {
        appendLog(QString::fromUtf8(m_lineBuffer));
        m_lineBuffer.clear();
    }
    refreshInstalledState();

    if (exitStatus == QProcess::NormalExit && exitCode == 0) {
        setStatus(Succeeded);
        setStatusMessage(tr("Installed into %1").arg(m_installRoot));
        emit installationFinished(true);
    } else {
        setStatus(Error);
        setStatusMessage(exitStatus == QProcess::NormalExit
                             ? tr("Installation failed (exit code %1).").arg(exitCode)
                             : tr("Backend crashed during installation."));
        emit installationFinished(false);
    }
}

void CupInstaller::onProcessError(QProcess::ProcessError error)
{
    if (error == QProcess::FailedToStart || error == QProcess::Crashed) {
        m_timeoutTimer.stop();
        setStatus(Error);
        setStatusMessage(error == QProcess::FailedToStart
                             ? tr("Could not start backend: %1").arg(m_backendPath)
                             : tr("Backend process crashed."));
        if (m_processIsInstall)
            emit installationFinished(false);
        else
            emit verificationFinished(false);
    }
}

void CupInstaller::onTimeout()
{
    appendLog(tr("! operation timed out, terminating backend"));
    killCurrentProcess();
    setStatus(Error);
    setStatusMessage(tr("Operation timed out."));
    if (m_processIsInstall)
        emit installationFinished(false);
    else
        emit verificationFinished(false);
}

void CupInstaller::killCurrentProcess()
{
    if (m_process->state() != QProcess::NotRunning) {
        m_timeoutTimer.stop();
        m_process->kill();
        m_process->waitForFinished(2000);
    }
}

void CupInstaller::refreshInstalledState()
{
    bool installed = false;
    if (!m_fileName.isEmpty() && !m_installRoot.isEmpty()) {
        const QString marker =
            m_installRoot + QStringLiteral("/active/DEPLOYED_PACKAGE.txt");
        installed = QFileInfo::exists(marker);
    }
    if (installed != m_isInstalled) {
        m_isInstalled = installed;
        emit isInstalledChanged();
    }
}

void CupInstaller::setInstallRoot(const QString &root)
{
    if (root == m_installRoot)
        return;
    m_installRoot = root;
    refreshInstalledState();
    emit installRootChanged();
}

QString CupInstaller::defaultInstallRoot() const
{
    // Explicit override first.
    const QByteArray envRoot = qgetenv("CUP_GUI_INSTALL_ROOT");
    if (!envRoot.isEmpty())
        return QString::fromLocal8Bit(envRoot);

    // A privileged GUI installs into the real system root; an unprivileged
    // one installs into a per-user sandbox root (created on demand).
    if (::geteuid() == 0)
        return QStringLiteral("/");
    return QDir::home().absoluteFilePath(QStringLiteral(".local/share/cup-gui/root"));
}

// ---------------------------------------------------------------------------
// State mutation helpers
// ---------------------------------------------------------------------------

void CupInstaller::setStatus(Status status)
{
    if (m_status == status)
        return;
    m_status = status;
    emit statusChanged();
    emit busyChanged();
    emit canInstallChanged();
}

void CupInstaller::setStatusMessage(const QString &message)
{
    if (m_statusMessage == message)
        return;
    m_statusMessage = message;
    emit statusMessageChanged();
}

void CupInstaller::appendLog(const QString &chunk)
{
    m_statusDetails.append(chunk);
    m_statusDetails.append(QLatin1Char('\n'));

    // Hard cap so a hostile backend cannot exhaust memory through the log.
    if (m_statusDetails.size() > kMaxLogBytes) {
        m_statusDetails = m_statusDetails.right(kMaxLogBytes / 2);
        m_statusDetails.prepend(QStringLiteral("… log trimmed …\n"));
    }
    emit statusDetailsChanged();
}

void CupInstaller::setBackendOverrideForTesting(const QString &path)
{
    m_backendPath = path;
}

void CupInstaller::setVerifyTimeoutMs(int ms) { m_verifyTimeoutMs = ms; }
void CupInstaller::setInstallTimeoutMs(int ms) { m_installTimeoutMs = ms; }

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

QString CupInstaller::formatByteSize(double size, int precision)
{
    if (size < 0.0 || precision < 0)
        return QStringLiteral("—");
    static const char * const units[] = {
        "B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"
    };
    const int unitCount = int(sizeof(units) / sizeof(units[0]));
    int unit = 0;
    while (qAbs(size) >= 1024.0 && unit < unitCount - 1) {
        size /= 1024.0;
        ++unit;
    }
    if (unit == 0)
        precision = 0;
    return QStringLiteral("%1 %2").arg(QString::number(size, 'f', precision),
                                       QString::fromLatin1(units[unit]));
}

bool CupInstaller::extractJsonStringField(const QByteArray &json, const char *key,
                                          QString *outValue, int maxLen)
{
    if (outValue)
        outValue->clear();
    if (!key || json.isEmpty())
        return false;

    // Look for "key" : "value" with a bounded scan (no full JSON parser is
    // needed for the normative manifest shape; escapes terminate the value).
    const QByteArray needle = QByteArrayLiteral("\"") + key + QByteArrayLiteral("\":\"");
    const int keyPos = json.indexOf(needle);
    if (keyPos < 0)
        return false;
    const int valueStart = keyPos + needle.size();
    int valueEnd = valueStart;
    const int n = json.size();
    while (valueEnd < n) {
        const char c = json.at(valueEnd);
        if (c == '"' || c == '\\' || c == '\n' || c == '\r')
            break;
        ++valueEnd;
    }
    if (valueEnd >= n || json.at(valueEnd) != '"')
        return false; // unterminated value — reject rather than guess
    const int len = valueEnd - valueStart;
    if (len <= 0 || len > maxLen)
        return false;

    const QByteArray raw = json.mid(valueStart, len);
    // Manifest ids/versions are printable ASCII by spec; enforce it.
    for (char c : raw) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc > 0x7E)
            return false;
    }
    if (outValue)
        *outValue = QString::fromLatin1(raw);
    return true;
}

bool CupInstaller::extractUriFields(const QString &uri, QString *outId, QString *outVersion)
{
    if (outId)
        outId->clear();
    if (outVersion)
        outVersion->clear();
    const int q = uri.indexOf(QLatin1Char('?'));
    if (q < 0)
        return false;
    const QStringList parts = uri.mid(q + 1).split(QLatin1Char('&'));
    bool gotId = false;
    for (const QString &part : parts) {
        const int eq = part.indexOf(QLatin1Char('='));
        if (eq <= 0)
            continue;
        const QString key = part.left(eq);
        const QString value = part.mid(eq + 1);
        if (key == QStringLiteral("id") && value.size() <= 256) {
            if (outId)
                *outId = value;
            gotId = true;
        } else if (key == QStringLiteral("v") && value.size() <= 64) {
            if (outVersion)
                *outVersion = value;
        }
    }
    return gotId;
}

QString CupInstaller::resolveBackendPath()
{
    // 1. Explicit override (also used by the selftest).
    const QByteArray env = qgetenv("CUP_GUI_BACKEND");
    if (!env.isEmpty()) {
        const QString p = QString::fromLocal8Bit(env);
        if (QFileInfo(p).isExecutable())
            return QFileInfo(p).absoluteFilePath();
    }

    const QString appDir = QCoreApplication::applicationDirPath();
    const QStringList candidates = {
        appDir + QStringLiteral("/cup-cli"),
        appDir + QStringLiteral("/../bin/cup-cli"),
        appDir + QStringLiteral("/../../bin/cup-cli"),
    };
    for (const QString &c : candidates) {
        if (QFileInfo(c).isExecutable())
            return QFileInfo(c).absoluteFilePath();
    }

    // 2. PATH lookup.
    const QString onPath = QStandardPaths::findExecutable(QStringLiteral("cup-cli"));
    if (!onPath.isEmpty())
        return onPath;

    return QString();
}

bool CupInstaller::parsePackageMetadata(const QString &path,
                                        QString *outId, QString *outVersion,
                                        QString *outAbiTag, quint32 *outSectionCount,
                                        QString *errorMessage)
{
    if (outId) outId->clear();
    if (outVersion) outVersion->clear();
    if (outAbiTag) outAbiTag->clear();
    if (outSectionCount) *outSectionCount = 0;
    if (errorMessage) errorMessage->clear();

    QFileInfo info(path);
    if (!info.exists() || !info.isFile()) {
        if (errorMessage) *errorMessage = QStringLiteral("file does not exist");
        return false;
    }
    const quint64 fileLen = quint64(info.size());
    if (fileLen < CUP_MIN_FILE_SIZE || fileLen > CUP_MAX_VOLUME_SIZE) {
        if (errorMessage) *errorMessage = QStringLiteral("file length %1 out of spec").arg(fileLen);
        return false;
    }

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (errorMessage) *errorMessage = QStringLiteral("cannot open file");
        return false;
    }
    const auto closeFile = qScopeGuard([&file]() { file.close(); });
    Q_UNUSED(closeFile);

    // Header + footer first (Gate 1 geometry is enforced by libcup2).
    unsigned char header[CUP_HEADER_SIZE];
    unsigned char footer[CUP_FOOTER_SIZE];
    if (file.read(reinterpret_cast<char *>(header), CUP_HEADER_SIZE) != CUP_HEADER_SIZE) {
        if (errorMessage) *errorMessage = QStringLiteral("short read on header");
        return false;
    }
    if (!file.seek(qint64(fileLen) - CUP_FOOTER_SIZE) ||
        file.read(reinterpret_cast<char *>(footer), CUP_FOOTER_SIZE) != CUP_FOOTER_SIZE) {
        if (errorMessage) *errorMessage = QStringLiteral("short read on footer");
        return false;
    }

    const int rc = cup_validate_header_and_footer(header, footer, fileLen);
    if (rc != CUP_OK) {
        if (errorMessage)
            *errorMessage = QString::fromLatin1(cup_strerror(rc));
        return false;
    }

    // Section table -> hardened catalog build.
    const quint32 sectionCount = readU32Le(header + kHdrSectionCountOff);
    if (sectionCount == 0 || sectionCount > CUP_MAX_SECTIONS) {
        if (errorMessage) *errorMessage = QStringLiteral("section count out of range");
        return false;
    }
    const quint64 tableBytes = quint64(sectionCount) * CUP_SECTION_ENTRY_SIZE;
    if (quint64(CUP_HEADER_SIZE) + tableBytes + CUP_FOOTER_SIZE > fileLen) {
        if (errorMessage) *errorMessage = QStringLiteral("section table exceeds file");
        return false;
    }

    QByteArray table(tableBytes, Qt::Uninitialized);
    if (!file.seek(CUP_HEADER_SIZE) ||
        file.read(table.data(), tableBytes) != qint64(tableBytes)) {
        if (errorMessage) *errorMessage = QStringLiteral("short read on section table");
        return false;
    }

    cup_catalog catalog{};
    const int crc = cup_catalog_build_safe(
        reinterpret_cast<const unsigned char *>(table.constData()),
        static_cast<size_t>(sectionCount), fileLen, &catalog);
    if (crc != CUP_OK) {
        if (errorMessage) *errorMessage = QString::fromLatin1(cup_strerror(crc));
        return false;
    }

    const quint16 manIdx = catalog.first_idx_by_type[CUP_SECT_MANIFEST];
    if (manIdx >= catalog.total_entries) {
        if (errorMessage) *errorMessage = QStringLiteral("no manifest section");
        return false;
    }
    const cup_section_entry &man = catalog.entries[manIdx];

    // cup_catalog_build_safe already proves offset+length <= fileLen without
    // wrap-around; re-assert cheaply before the seek anyway (defense in depth).
    if (man.offset > fileLen || man.length > fileLen - man.offset ||
        man.length > static_cast<quint64>(16 * 1024 * 1024)) {
        if (errorMessage) *errorMessage = QStringLiteral("manifest geometry rejected");
        return false;
    }

    QByteArray manifest(int(man.length), Qt::Uninitialized);
    if (!file.seek(qint64(man.offset)) ||
        file.read(manifest.data(), int(man.length)) != qint64(man.length)) {
        if (errorMessage) *errorMessage = QStringLiteral("short read on manifest");
        return false;
    }

    QString id, version;
    const bool haveId = extractJsonStringField(manifest, "id", &id);
    const bool haveVersion = extractJsonStringField(manifest, "version", &version);
    if (!haveId) {
        if (errorMessage) *errorMessage = QStringLiteral("manifest id missing/invalid");
        return false;
    }

    if (outId) *outId = id;
    if (outVersion) *outVersion = haveVersion ? version : QStringLiteral("?");
    if (outAbiTag) *outAbiTag = trimmedAscii(header + kHdrAbiTagOff, kHdrAbiTagLen);
    if (outSectionCount) *outSectionCount = sectionCount;
    return true;
}
