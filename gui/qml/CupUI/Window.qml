/*
 * CupUI.Window — application window shell in the FishUI / cutefish-toolkit
 * style: a soft card with rounded corners, in-card header row and a themed
 * content area.
 *
 * This deliberately keeps the native window frame (works identically on
 * X11, Wayland and the offscreen CI platform) while painting the Cutefish
 * look inside the window.
 */
import QtQuick 2.12
import QtQuick.Window 2.12
import QtQuick.Layouts 1.12
import QtQuick.Controls 2.12
import CupUI 1.0 as CupUI

ApplicationWindow {
    id: control

    // Header contents (FishUI-compatible name; not an ApplicationWindow
    // property, so it does not clash with the FINAL `header`).
    property alias headerItem: _headerLayout.data

    Rectangle {
        id: _card
        anchors.fill: parent
        radius: CupUI.Units.largeRadius
        color: CupUI.Theme.secondBackgroundColor
        border.width: 1
        border.color: CupUI.Theme.borderColor

        Rectangle {
            // Header strip inside the card.
            id: _headerStrip
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            height: _headerLayout.implicitHeight + CupUI.Units.largeSpacing
            color: "transparent"

            RowLayout {
                id: _headerLayout
                anchors.fill: parent
                anchors.leftMargin: CupUI.Units.largeSpacing
                anchors.rightMargin: CupUI.Units.largeSpacing
                anchors.topMargin: CupUI.Units.largeSpacing / 2
                anchors.bottomMargin: CupUI.Units.largeSpacing / 2
            }

            Rectangle {
                anchors.bottom: parent.bottom
                width: parent.width
                height: 1
                color: CupUI.Theme.borderColor
                opacity: 0.6
            }
        }

        // Page content lives below the header strip; the default property
        // routes Window children here.
        Item {
            id: _contentArea
            anchors.top: _headerStrip.bottom
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            clip: true
        }
    }

    default property alias contentArea: _contentArea.data
}
