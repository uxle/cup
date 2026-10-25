/*
 * cupinstaller.h — QML backend object for the CUP GUI Installer.
 *
 * Architecture (mirrors the Cutefish debinstaller, which wraps QApt/libapt):
 *   - Display metadata comes from a *local, read-only* parse of the .cup
 *     file performed through the hardened libcup2 C core
 *     (cup_validate_header_and_footer + cup_catalog_build_safe), so the
 *     GUI never re-implements package parsing.
 *   - Every privileged or cryptographic decision is delegated to the
 *     audited `cup-cli` binary via QProcess *argv arrays* (never a shell),
 *     so no command-injection surface exists.
 *   - The Install action is hard-gated on a successful full verification
 *     (canInstall == valid && signaturesValid && !busy).
 */
#ifndef CUPINSTALLER_H
#define CUPINSTALLER_H

#include <QObject>
#include <QProcess>
#include <QTimer>

class CupInstaller : public QObject
{
    Q_OBJECT

    Q_PROPERTY(QString fileName READ fileName WRITE setFileName NOTIFY fileNameChanged)
    Q_PROPERTY(QString packageName READ packageName NOTIFY packageNameChanged)
    Q_PROPERTY(QString version READ version NOTIFY versionChanged)
    Q_PROPERTY(QString uri READ uri NOTIFY uriChanged)
    Q_PROPERTY(QString fileSize READ fileSize NOTIFY fileSizeChanged)
    Q_PROPERTY(QString sectionCount READ sectionCount NOTIFY sectionCountChanged)
    Q_PROPERTY(QString abiTag READ abiTag NOTIFY abiTagChanged)
    Q_PROPERTY(QString installRoot READ installRoot WRITE setInstallRoot NOTIFY installRootChanged)
    Q_PROPERTY(QString backendPath READ backendPath CONSTANT)

    Q_PROPERTY(bool valid READ isValid NOTIFY validChanged)
    Q_PROPERTY(bool signaturesValid READ signaturesValid NOTIFY signaturesValidChanged)
    Q_PROPERTY(bool canInstall READ canInstall NOTIFY canInstallChanged)
    Q_PROPERTY(bool isInstalled READ isInstalled NOTIFY isInstalledChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)

    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY statusMessageChanged)
    Q_PROPERTY(QString statusDetails READ statusDetails NOTIFY statusDetailsChanged)
    Q_PROPERTY(Status status READ status NOTIFY statusChanged)

public:
    /*
     * Page-flow states, matching the debinstaller state machine
     * (Begin -> Verifying -> Ready -> Installing -> Succeeded/Error).
     */
    enum Status {
        Begin = 0,
        Verifying,
        Ready,
        Installing,
        Succeeded,
        Error,
    };
    Q_ENUM(Status)

    explicit CupInstaller(QObject *parent = nullptr);
    ~CupInstaller() override;

    // ---- Q_PROPERTY accessors -------------------------------------------------
    QString fileName() const;
    void setFileName(const QString &fileName);

    QString packageName() const;
    QString version() const;
    QString uri() const;
    QString fileSize() const;
    QString sectionCount() const;
    QString abiTag() const;

    QString installRoot() const;
    void setInstallRoot(const QString &root);

    QString backendPath() const;

    bool isValid() const;
    bool signaturesValid() const;
    bool canInstall() const;
    bool isInstalled() const;
    bool busy() const;

    QString statusMessage() const;
    QString statusDetails() const;
    Status status() const;

    // ---- QML invokables -------------------------------------------------------
    Q_INVOKABLE void install();
    Q_INVOKABLE void reverify();
    Q_INVOKABLE void clearFile();
    Q_INVOKABLE void resetToReady();
    // Native (QtWidgets) file picker; feeds setFileName().
    Q_INVOKABLE void openFilePicker();

    // ---- pure helpers, unit-tested headlessly by selftest.cpp -----------------
    static QString formatByteSize(double size, int precision = 1);
    static bool extractJsonStringField(const QByteArray &json, const char *key,
                                       QString *outValue, int maxLen = 256);
    static bool extractUriFields(const QString &uri, QString *outId, QString *outVersion);
    static QString resolveBackendPath();

    // Read-only local metadata pass through libcup2 (no process spawn).
    // Returns true and fills the out-params on success; returns false and
    // sets *errorMessage on rejection. Never throws, never trusts geometry.
    static bool parsePackageMetadata(const QString &path,
                                     QString *outId, QString *outVersion,
                                     QString *outAbiTag, quint32 *outSectionCount,
                                     QString *errorMessage);

    void setBackendOverrideForTesting(const QString &path);
    void setVerifyTimeoutMs(int ms);
    void setInstallTimeoutMs(int ms);

signals:
    void fileNameChanged();
    void packageNameChanged();
    void versionChanged();
    void uriChanged();
    void fileSizeChanged();
    void sectionCountChanged();
    void abiTagChanged();
    void installRootChanged();

    void validChanged();
    void signaturesValidChanged();
    void canInstallChanged();
    void isInstalledChanged();
    void busyChanged();

    void statusMessageChanged();
    void statusDetailsChanged();
    void statusChanged();

    // Emitted once the async verification finishes (ok == full Gate 1+2 pass).
    void verificationFinished(bool ok);
    // Emitted once the async installation finishes (ok == exit code 0).
    void installationFinished(bool ok);

private slots:
    void onReadyReadStandardOutput();
    void onVerifyFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onInstallFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProcessError(QProcess::ProcessError error);
    void onTimeout();

private:
    void setStatus(Status status);
    void setStatusMessage(const QString &message);
    void appendLog(const QString &chunk);
    void killCurrentProcess();
    bool launchBackend(const QStringList &args);
    void refreshInstalledState();
    QString defaultInstallRoot() const;

    QString m_fileName;

    QString m_packageName;
    QString m_version;
    QString m_uri;
    QString m_fileSize;
    QString m_sectionCount;
    QString m_abiTag;

    QString m_installRoot;
    QString m_backendPath;

    bool m_valid;
    bool m_signaturesValid;
    bool m_isInstalled;
    Status m_status;
    QString m_statusMessage;
    QString m_statusDetails;

    QProcess *m_process;
    QTimer m_timeoutTimer;
    bool m_processIsInstall;
    QByteArray m_lineBuffer;

    int m_verifyTimeoutMs;
    int m_installTimeoutMs;

    static const int kMaxLogBytes = 512 * 1024;
};

#endif // CUPINSTALLER_H
