/*
 * AppPage - Minimalist, Icon-Driven Package Card & Install Trigger
 */
import QtQuick 2.12
import QtQuick.Layouts 1.12
import QtQuick.Controls 2.12
import CupUI 1.0 as CupUI

Item {
    id: root

    readonly property bool verifying: Installer.busy && !Installer.signaturesValid
    readonly property bool verified: Installer.signaturesValid
    readonly property bool failed: !verifying && !verified

    function shortName(fullId) {
        var parts = fullId.split(".")
        return parts[parts.length - 1]
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: CupUI.Units.largeSpacing * 1.5
        spacing: CupUI.Units.largeSpacing

        // 1. App Identity Card
        CupUI.RoundedPanel {
            Layout.fillWidth: true
            Layout.preferredHeight: 110
            radius: CupUI.Units.largeRadius
            color: CupUI.Theme.secondBackgroundColor

            RowLayout {
                anchors.fill: parent
                anchors.margins: CupUI.Units.largeSpacing
                spacing: CupUI.Units.largeSpacing

                Image {
                    Layout.preferredWidth: 64
                    Layout.preferredHeight: 64
                    sourceSize: Qt.size(128, 128)
                    source: "qrc:/icons/application-x-cup.svg"
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 4

                    Label {
                        text: root.shortName(Installer.packageName)
                        color: CupUI.Theme.textColor
                        font.pointSize: CupUI.Units.fontXL + 1
                        font.bold: true
                        elide: Text.ElideRight
                    }

                    RowLayout {
                        spacing: 8
                        Rectangle {
                            height: 22
                            width: _verText.implicitWidth + 16
                            radius: 11
                            color: CupUI.Theme.tint(CupUI.Theme.highlightColor, 0.15)

                            RowLayout {
                                anchors.centerIn: parent
                                spacing: 4
                                Image {
                                    source: "qrc:/icons/tag.svg"
                                    Layout.preferredWidth: 12
                                    Layout.preferredHeight: 12
                                }
                                Label {
                                    id: _verText
                                    text: "v" + Installer.version
                                    color: CupUI.Theme.highlightColor
                                    font.pointSize: CupUI.Units.fontXS
                                    font.bold: true
                                }
                            }
                        }

                        Label {
                            visible: Installer.isInstalled
                            text: qsTr("• Installed")
                            color: CupUI.Theme.successColor
                            font.pointSize: CupUI.Units.fontXS
                            font.bold: true
                        }
                    }
                }
            }
        }

        // 2. Icon Stats Row (3 Pill Badges: Size, Identity, Verified)
        RowLayout {
            Layout.fillWidth: true
            spacing: CupUI.Units.mediumSpacing

            // Stat 1: Size
            CupUI.RoundedPanel {
                Layout.fillWidth: true
                Layout.preferredHeight: 60
                radius: CupUI.Units.mediumRadius
                color: CupUI.Theme.secondBackgroundColor

                RowLayout {
                    anchors.centerIn: parent
                    spacing: 8
                    Image {
                        source: "qrc:/icons/box.svg"
                        Layout.preferredWidth: 20
                        Layout.preferredHeight: 20
                    }
                    ColumnLayout {
                        spacing: 0
                        Label {
                            text: qsTr("Size")
                            color: CupUI.Theme.disabledTextColor
                            font.pointSize: CupUI.Units.fontXS
                        }
                        Label {
                            text: Installer.fileSize || "—"
                            color: CupUI.Theme.textColor
                            font.pointSize: CupUI.Units.fontM
                            font.bold: true
                        }
                    }
                }
            }

            // Stat 2: Security State
            CupUI.RoundedPanel {
                Layout.fillWidth: true
                Layout.preferredHeight: 60
                radius: CupUI.Units.mediumRadius
                color: root.verified ? CupUI.Theme.tint(CupUI.Theme.successColor, 0.1)
                                     : CupUI.Theme.secondBackgroundColor

                RowLayout {
                    anchors.centerIn: parent
                    spacing: 8
                    Image {
                        source: root.verified ? "qrc:/icons/check-circle.svg"
                               : (root.verifying ? "qrc:/icons/folder-open.svg" : "qrc:/icons/security-low.svg")
                        Layout.preferredWidth: 20
                        Layout.preferredHeight: 20
                    }
                    ColumnLayout {
                        spacing: 0
                        Label {
                            text: qsTr("Status")
                            color: CupUI.Theme.disabledTextColor
                            font.pointSize: CupUI.Units.fontXS
                        }
                        Label {
                            text: root.verifying ? qsTr("Checking")
                                  : (root.verified ? qsTr("Verified") : qsTr("Blocked"))
                            color: root.verified ? CupUI.Theme.successColor
                                   : (root.verifying ? CupUI.Theme.textColor : CupUI.Theme.errorColor)
                            font.pointSize: CupUI.Units.fontM
                            font.bold: true
                        }
                    }
                }
            }
        }

        // 3. Status Bar
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 38
            radius: CupUI.Units.mediumRadius
            color: root.verified ? CupUI.Theme.tint(CupUI.Theme.successColor, 0.12)
                   : (root.verifying ? CupUI.Theme.secondBackgroundColor
                                     : CupUI.Theme.tint(CupUI.Theme.errorColor, 0.12))
            border.width: 1
            border.color: root.verified ? CupUI.Theme.tint(CupUI.Theme.successColor, 0.4)
                          : (root.verifying ? CupUI.Theme.borderColor
                                            : CupUI.Theme.tint(CupUI.Theme.errorColor, 0.4))

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: CupUI.Units.mediumSpacing
                anchors.rightMargin: CupUI.Units.mediumSpacing
                spacing: 8

                Image {
                    source: root.verified ? "qrc:/icons/security-high.svg"
                                          : "qrc:/icons/security-low.svg"
                    Layout.preferredWidth: 18
                    Layout.preferredHeight: 18
                    visible: !root.verifying
                }

                BusyIndicator {
                    Layout.preferredWidth: 18
                    Layout.preferredHeight: 18
                    visible: root.verifying
                    running: visible
                }

                Label {
                    Layout.fillWidth: true
                    text: root.verifying ? qsTr("Verifying cryptographic signature...")
                          : (root.verified ? qsTr("Ed25519 signature & Merkle integrity valid")
                                           : qsTr("Untrusted or tampered container"))
                    color: root.verified ? CupUI.Theme.successColor
                           : (root.verifying ? CupUI.Theme.textColor : CupUI.Theme.errorColor)
                    font.pointSize: CupUI.Units.fontS
                    font.bold: true
                    elide: Text.ElideRight
                }
            }
        }

        Item { Layout.fillHeight: true }

        // 4. Action Buttons
        RowLayout {
            Layout.fillWidth: true
            spacing: CupUI.Units.mediumSpacing

            CupUI.ActionButton {
                Layout.fillWidth: true
                Layout.preferredHeight: 40
                text: qsTr("Cancel")
                onClicked: Qt.quit()
            }

            CupUI.ActionButton {
                Layout.fillWidth: true
                Layout.preferredHeight: 40
                primary: true
                text: Installer.isInstalled ? qsTr("Reinstall") : qsTr("Install Package")
                enabled: Installer.canInstall && !Installer.busy
                onClicked: Installer.install()
            }
        }
    }
}
