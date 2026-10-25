/*
 * HomePage - Minimalist, Icon-First Package Drop & Selector
 */
import QtQuick 2.12
import QtQuick.Layouts 1.12
import QtQuick.Controls 2.12
import CupUI 1.0 as CupUI

Item {
    id: root

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.min(parent.width - CupUI.Units.largeSpacing * 4, 380)
        spacing: CupUI.Units.largeSpacing

        // Main Drop & Pick Card
        CupUI.RoundedPanel {
            Layout.fillWidth: true
            Layout.preferredHeight: 250
            radius: CupUI.Units.largeRadius
            color: CupUI.Theme.secondBackgroundColor
            border.color: CupUI.Theme.highlightColor
            border.width: 1.5

            ColumnLayout {
                anchors.centerIn: parent
                spacing: CupUI.Units.mediumSpacing

                Image {
                    Layout.preferredWidth: 84
                    Layout.preferredHeight: 84
                    Layout.alignment: Qt.AlignHCenter
                    sourceSize: Qt.size(168, 168)
                    source: "qrc:/icons/cup-gui-installer.svg"
                }

                Label {
                    text: qsTr("CUP Installer")
                    color: CupUI.Theme.textColor
                    font.pointSize: CupUI.Units.fontXL
                    font.bold: true
                    Layout.alignment: Qt.AlignHCenter
                }

                Label {
                    text: qsTr("Drop package here or browse")
                    color: CupUI.Theme.disabledTextColor
                    font.pointSize: CupUI.Units.fontS
                    Layout.alignment: Qt.AlignHCenter
                }

                CupUI.ActionButton {
                    primary: true
                    text: qsTr("Choose .cup")
                    Layout.preferredWidth: 160
                    Layout.preferredHeight: 36
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: CupUI.Units.smallSpacing
                    onClicked: Installer.openFilePicker()
                }
            }
        }

        // Error message if any
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: _errText.implicitHeight + CupUI.Units.mediumSpacing * 2
            visible: Installer.statusMessage !== ""
            radius: CupUI.Units.mediumRadius
            color: CupUI.Theme.tint(CupUI.Theme.errorColor, 0.12)
            border.width: 1
            border.color: CupUI.Theme.tint(CupUI.Theme.errorColor, 0.5)

            Label {
                id: _errText
                anchors.fill: parent
                anchors.margins: CupUI.Units.mediumSpacing
                text: Installer.statusMessage
                color: CupUI.Theme.errorColor
                wrapMode: Text.Wrap
                maximumLineCount: 2
                elide: Text.ElideRight
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                font.pointSize: CupUI.Units.fontS
            }
        }

        // Clean 3-Icon Feature Bar
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: CupUI.Units.largeSpacing

            RowLayout {
                spacing: 6
                Image {
                    source: "qrc:/icons/security-high.svg"
                    Layout.preferredWidth: 16
                    Layout.preferredHeight: 16
                }
                Label {
                    text: qsTr("Verified")
                    color: CupUI.Theme.disabledTextColor
                    font.pointSize: CupUI.Units.fontXS
                    font.bold: true
                }
            }

            RowLayout {
                spacing: 6
                Image {
                    source: "qrc:/icons/box.svg"
                    Layout.preferredWidth: 16
                    Layout.preferredHeight: 16
                }
                Label {
                    text: qsTr("Zero-Copy")
                    color: CupUI.Theme.disabledTextColor
                    font.pointSize: CupUI.Units.fontXS
                    font.bold: true
                }
            }

            RowLayout {
                spacing: 6
                Image {
                    source: "qrc:/icons/check-circle.svg"
                    Layout.preferredWidth: 16
                    Layout.preferredHeight: 16
                }
                Label {
                    text: qsTr("Sandboxed")
                    color: CupUI.Theme.disabledTextColor
                    font.pointSize: CupUI.Units.fontXS
                    font.bold: true
                }
            }
        }
    }
}
