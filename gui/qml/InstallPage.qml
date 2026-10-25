/*
 * InstallPage - Minimalist, Icon-First Installation & Celebration State
 */
import QtQuick 2.12
import QtQuick.Layouts 1.12
import QtQuick.Controls 2.12
import CupUI 1.0 as CupUI
import CUP.Gui 1.0

Item {
    id: root

    readonly property bool working: Installer.status === CupInstaller.Verifying
                                    || Installer.status === CupInstaller.Installing
    readonly property bool done: Installer.status === CupInstaller.Succeeded
    readonly property bool failed: Installer.status === CupInstaller.Error
    property bool showLog: false

    function shortName(fullId) {
        var parts = fullId.split(".")
        return parts[parts.length - 1]
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: CupUI.Units.largeSpacing * 1.5
        spacing: CupUI.Units.largeSpacing

        // Main Visual State Card
        CupUI.RoundedPanel {
            Layout.fillWidth: true
            Layout.fillHeight: !root.showLog
            Layout.preferredHeight: root.showLog ? 180 : -1
            radius: CupUI.Units.largeRadius
            color: CupUI.Theme.secondBackgroundColor

            ColumnLayout {
                anchors.centerIn: parent
                spacing: CupUI.Units.mediumSpacing

                // 1. Icon State
                Item {
                    Layout.preferredWidth: 72
                    Layout.preferredHeight: 72
                    Layout.alignment: Qt.AlignHCenter

                    BusyIndicator {
                        anchors.fill: parent
                        visible: root.working
                        running: visible
                    }

                    Image {
                        anchors.fill: parent
                        sourceSize: Qt.size(144, 144)
                        visible: root.done
                        source: "qrc:/icons/check-circle.svg"
                    }

                    Image {
                        anchors.fill: parent
                        sourceSize: Qt.size(144, 144)
                        visible: root.failed
                        source: "qrc:/icons/security-low.svg"
                    }
                }

                // 2. Status Heading
                Label {
                    text: {
                        if (Installer.status === CupInstaller.Verifying)
                            return qsTr("Verifying...")
                        if (Installer.status === CupInstaller.Installing)
                            return qsTr("Installing...")
                        if (root.done)
                            return qsTr("Ready to Use")
                        if (root.failed)
                            return qsTr("Installation Failed")
                        return ""
                    }
                    color: root.done ? CupUI.Theme.successColor
                           : (root.failed ? CupUI.Theme.errorColor : CupUI.Theme.textColor)
                    font.pointSize: CupUI.Units.fontXL + 2
                    font.bold: true
                    Layout.alignment: Qt.AlignHCenter
                }

                // 3. Subtitle / App Identifier
                Label {
                    text: root.failed ? (Installer.statusMessage || qsTr("An error occurred"))
                          : qsTr("%1 (v%2)").arg(root.shortName(Installer.packageName)).arg(Installer.version)
                    color: root.failed ? CupUI.Theme.errorColor : CupUI.Theme.disabledTextColor
                    font.pointSize: CupUI.Units.fontS
                    Layout.alignment: Qt.AlignHCenter
                }

                // 4. Progress bar during active installation
                ProgressBar {
                    Layout.preferredWidth: 220
                    Layout.preferredHeight: 6
                    Layout.alignment: Qt.AlignHCenter
                    visible: root.working
                    indeterminate: true
                }
            }
        }

        // Optional Collapsible Details
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            visible: true

            Label {
                text: root.showLog ? qsTr("Hide log ▲") : qsTr("Details ▼")
                color: CupUI.Theme.highlightColor
                font.pointSize: CupUI.Units.fontXS
                font.bold: true

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.showLog = !root.showLog
                }
            }
        }

        // Collapsible Log Container
        CupUI.RoundedPanel {
            Layout.fillWidth: true
            Layout.fillHeight: true
            visible: root.showLog
            color: CupUI.Theme.logBackgroundColor

            Flickable {
                anchors.fill: parent
                anchors.margins: CupUI.Units.mediumSpacing
                contentWidth: _logText.implicitWidth
                contentHeight: _logText.implicitHeight
                clip: true

                TextEdit {
                    id: _logText
                    text: Installer.statusDetails
                    readOnly: true
                    selectByMouse: true
                    font.family: "monospace"
                    font.pointSize: CupUI.Units.fontXS
                    color: CupUI.Theme.textColor
                }
            }
        }

        // Action Buttons
        RowLayout {
            Layout.fillWidth: true
            spacing: CupUI.Units.mediumSpacing

            CupUI.ActionButton {
                Layout.fillWidth: true
                Layout.preferredHeight: 40
                text: root.done ? qsTr("Close") : qsTr("Cancel")
                onClicked: Qt.quit()
            }

            CupUI.ActionButton {
                Layout.fillWidth: true
                Layout.preferredHeight: 40
                primary: true
                visible: root.done
                text: qsTr("Done")
                onClicked: Qt.quit()
            }
        }
    }
}
