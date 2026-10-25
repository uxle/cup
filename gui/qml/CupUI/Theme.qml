/*
 * CupUI.Theme — colour singleton following the FishUI (cutefish-toolkit)
 * palette conventions used by the Cutefish debinstaller. Light and dark
 * variants are provided; the hosting window flips `Theme.dark` from C++
 * palette luminance so both system themes render correctly.
 */
pragma Singleton
import QtQuick 2.12

QtObject {
    id: theme

    property bool dark: false

    // Backgrounds (FishUI naming)
    readonly property color backgroundColor:        dark ? "#1B1B1B" : "#FFFFFF"
    readonly property color secondBackgroundColor:  dark ? "#252525" : "#F2F2F7"
    readonly property color thirdBackgroundColor:   dark ? "#323232" : "#E9E9EE"

    // Text
    readonly property color textColor:              dark ? "#FFFFFF" : "#252525"
    readonly property color disabledTextColor:      dark ? "#8A8A8E" : "#909095"
    readonly property color labelColor:             textColor

    // Accents
    readonly property color highlightColor:         dark ? "#3FB8F8" : "#2CA6E0"
    readonly property color highlightedTextColor:   "#FFFFFF"
    readonly property color successColor:           dark ? "#2ED573" : "#1FA955"
    readonly property color errorColor:             dark ? "#FF6B81" : "#F85879"
    readonly property color warningColor:           dark ? "#FFD166" : "#E9A700"

    // Lines & controls
    readonly property color borderColor:            dark ? "#3A3A3C" : "#DDE0E5"
    readonly property color buttonColor:            dark ? "#323232" : "#FFFFFF"
    readonly property color pressedColor:           dark ? "#414141" : "#E8F4FB"
    readonly property color logBackgroundColor:     dark ? "#111111" : "#1E2430"

    // Signature / verification badge colours
    readonly property color validColor:             successColor
    readonly property color invalidColor:           errorColor

    // Soft tinted fill for banners (same hue, low alpha) - readable in both themes.
    function tint(c, alpha) { return Qt.rgba(c.r, c.g, c.b, alpha) }
}
