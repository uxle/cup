/*
 * CupUI.ActionButton — one button style for the whole installer.
 * `primary: true` gives the filled accent button (the one thing the page
 * wants you to press); the default is a quiet outlined button.
 * Pure QtQuick.Controls 2 + customised background/contentItem, so it does
 * not depend on any native style.
 */
import QtQuick 2.12
import QtQuick.Controls 2.12
import CupUI 1.0 as CupUI

Button {
    id: control

    property bool primary: false
    property color accent: CupUI.Theme.highlightColor

    implicitHeight: 38
    implicitWidth: 120
    hoverEnabled: true
    font.pointSize: CupUI.Units.fontM
    font.bold: primary

    contentItem: Text {
        text: control.text
        font: control.font
        elide: Text.ElideRight
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        color: !control.enabled ? CupUI.Theme.disabledTextColor
                                : (control.primary ? CupUI.Theme.highlightedTextColor
                                                   : CupUI.Theme.textColor)
    }

    background: Rectangle {
        radius: CupUI.Units.mediumRadius
        color: control.primary
               ? (!control.enabled ? CupUI.Theme.thirdBackgroundColor
                  : (control.down ? Qt.darker(control.accent, 1.18)
                     : (control.hovered ? Qt.lighter(control.accent, 1.08) : control.accent)))
               : (control.down ? CupUI.Theme.pressedColor
                  : (control.hovered ? CupUI.Theme.thirdBackgroundColor : CupUI.Theme.buttonColor))
        border.width: control.visualFocus ? 2 : (control.primary ? 0 : 1)
        border.color: control.visualFocus ? CupUI.Theme.highlightColor : CupUI.Theme.borderColor
    }
}
