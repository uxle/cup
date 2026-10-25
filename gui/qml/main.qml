/*
 * CUP GUI Installer — main window.
 * Layout follows the Cutefish debinstaller: fixed-size window, drag&drop
 * area, StackView page flow Home -> App -> Install driven by the
 * CupInstaller backend object exposed as the `Installer` context property.
 */
import QtQuick 2.12
import QtQuick.Window 2.12
import QtQuick.Layouts 1.12
import QtQuick.Controls 2.12
import CupUI 1.0 as CupUI
import CUP.Gui 1.0

CupUI.Window {
    id: control
    width: 480
    height: 480
    minimumWidth: 480
    minimumHeight: 480
    maximumWidth: 480
    maximumHeight: 480
    title: qsTr("CUP Package Installer")
    visible: true

    headerItem: [
        Image {
            Layout.preferredWidth: 22
            Layout.preferredHeight: 22
            sourceSize: Qt.size(44, 44)
            source: "qrc:/icons/cup-gui-installer.svg"
        },
        Label {
            text: control.title
            color: CupUI.Theme.textColor
            font.pointSize: CupUI.Units.fontM
            font.bold: true
            Layout.fillWidth: true
        }
    ]

    DropArea {
        id: _dropArea
        anchors.fill: parent
        z: 100

        onDropped: {
            if (drop.hasUrls && drop.urls.length > 0)
                Installer.fileName = drop.urls[0].toString()
        }
    }

    // Drag-and-drop feedback: shown while a file is held over the window.
    Rectangle {
        id: _dropOverlay
        anchors.fill: parent
        anchors.margins: CupUI.Units.mediumSpacing
        z: 99
        radius: CupUI.Units.largeRadius
        color: CupUI.Theme.tint(CupUI.Theme.highlightColor, 0.10)
        border.width: 2
        border.color: CupUI.Theme.highlightColor
        opacity: _dropArea.containsDrag ? 1.0 : 0.0
        visible: opacity > 0.0

        Behavior on opacity { NumberAnimation { duration: 120 } }

        Label {
            anchors.centerIn: parent
            text: qsTr("Drop the .cup package to open it")
            color: CupUI.Theme.highlightColor
            font.pointSize: CupUI.Units.fontL
            font.bold: true
        }
    }

    Component {
        id: _homePage
        HomePage { }
    }

    Component {
        id: _appPage
        AppPage { }
    }

    Component {
        id: _installPage
        InstallPage { }
    }

    StackView {
        id: _stackView
        objectName: "stackView"
        anchors.fill: parent
        initialItem: _homePage
    }

    Connections {
        target: Installer

        function onValidChanged() {
            if (Installer.valid) {
                _stackView.push(_appPage)
            } else {
                // Pop back to the Home page (deterministic loop: pop() takes
                // an item instance, and initialItem is only a Component).
                while (_stackView.depth > 1)
                    _stackView.pop()
            }
        }

        function onStatusChanged() {
            if (Installer.status === CupInstaller.Installing) {
                if (_stackView.depth < 3)
                    _stackView.push(_installPage)
            } else if (Installer.status === CupInstaller.Ready
                       || Installer.status === CupInstaller.Begin) {
                // Verify runs silently on the App page; pop the Install page
                // when the backend returns to the Ready/Begin state.
                if (_stackView.depth > 2)
                    _stackView.pop()
            }
        }
    }
}
