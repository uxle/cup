# CUP GUI Installer — qmake project (the suite's sandbox build path).
# The canonical distro build is CMakeLists.txt (same sources); this .pro
# exists so `make gui` works with only qt5-qmake installed.
#
#   qmake gui/gui.pro && make -C gui       (or: make gui from the suite root)

TARGET   = cup-gui-installer
TEMPLATE = app
CONFIG  += c++17
CONFIG  += warn_on
QT      += core gui widgets quick

INCLUDEPATH += ../c_core

# Same hardening posture as the rest of the CUP suite.
QMAKE_CXXFLAGS += -Werror -Wshadow -Wformat=2 -Wpointer-arith -Wcast-qual
QMAKE_CXXFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2

# Optional sysroot for locally-extracted (non-system) Qt/GL toolchains, e.g.
# sandbox builds without root:  QT5_SYSROOT=/path/to/extracted/usr qmake ...
QT5_SYSROOT = $$(QT5_SYSROOT)
!isEmpty(QT5_SYSROOT) {
    message("Using sysroot: $$QT5_SYSROOT")
    INCLUDEPATH += $$QT5_SYSROOT/usr/include
    QMAKE_LIBDIR += $$QT5_SYSROOT/usr/lib/x86_64-linux-gnu
    LIBS += -L$$QT5_SYSROOT/usr/lib/x86_64-linux-gnu
}

# Link the audited C core for the read-only metadata pass.
LIBS += $$PWD/../lib/libcup2.a
LIBS += -lcrypto -lpthread

SOURCES += \
    src/main.cpp \
    src/cupinstaller.cpp \
    src/selftest.cpp

HEADERS += \
    src/cupinstaller.h \
    src/selftest.h

RESOURCES += qml.qrc

# Desktop entry + icon install hooks (no-op for the sandbox build).
desktopfiles.path  = /usr/share/applications
desktopfiles.files = cup-gui-installer.desktop
INSTALLS += desktopfiles
