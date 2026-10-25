/*
 * CupUI.Units — spacing / sizing singleton, FishUI compatible.
 */
pragma Singleton
import QtQuick 2.12

QtObject {
    readonly property int smallSpacing:  4
    readonly property int mediumSpacing: 8
    readonly property int largeSpacing:  16

    readonly property int smallRadius:   6
    readonly property int mediumRadius:  10
    readonly property int largeRadius:   14

    readonly property int fontXS: 10
    readonly property int fontS:  11
    readonly property int fontM:  12
    readonly property int fontL:  15
    readonly property int fontXL: 18
}
