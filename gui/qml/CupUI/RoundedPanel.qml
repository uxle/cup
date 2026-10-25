/*
 * CupUI.RoundedPanel — the rounded info card used across Cutefish apps.
 */
import QtQuick 2.12
import CupUI 1.0 as CupUI

Rectangle {
    id: panel

    property alias content: _layout.data

    color: CupUI.Theme.backgroundColor
    radius: CupUI.Units.mediumRadius
    border.width: 1
    border.color: CupUI.Theme.borderColor

    default property alias dataArea: _layout.data

    Item {
        id: _layout
        anchors.fill: parent
    }
}
