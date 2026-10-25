cmake_minimum_required(VERSION 3.16)

# CuteFish Universal Package (CUP v3.0) GUI Installer
# Built with native Cutefish Toolkit (Skia + Wayland)

project(cup-gui-installer VERSION 3.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GNUInstallDirs)

find_package(CutefishToolkit REQUIRED)
find_package(Threads REQUIRED)

# Embed vector SVG glyphs into C++ source
file(GLOB CUP_ICONS CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/icons/*.svg)
set(CUP_EMBEDDED ${CMAKE_CURRENT_BINARY_DIR}/icons.cpp)
string(REPLACE ";" "|" CUP_ICON_LIST "${CUP_ICONS}")
add_custom_command(OUTPUT ${CUP_EMBEDDED}
    COMMAND ${CMAKE_COMMAND} -DOUTPUT=${CUP_EMBEDDED}
            -DFILES=${CUP_ICON_LIST} -P ${PROJECT_SOURCE_DIR}/cmake/EmbedIcons.cmake
    DEPENDS ${CUP_ICONS} ${PROJECT_SOURCE_DIR}/cmake/EmbedIcons.cmake
    VERBATIM)

set(CUP_CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../c_core)
set(CUP_LIB_DIR  ${CMAKE_CURRENT_SOURCE_DIR}/../lib)

add_library(cup2_core STATIC IMPORTED GLOBAL)
set_target_properties(cup2_core PROPERTIES
    IMPORTED_LOCATION ${CUP_LIB_DIR}/libcup2.a)
target_include_directories(cup2_core INTERFACE ${CUP_CORE_DIR})

set(PROJECT_SOURCES
    src/main.cpp
    src/installer_window.h
    src/installer_window.cpp
    src/selftest.h
    src/selftest.cpp
    ${CUP_EMBEDDED}
)

add_executable(cup-gui-installer ${PROJECT_SOURCES})
target_include_directories(cup-gui-installer PRIVATE src ${CUP_CORE_DIR})
target_compile_definitions(cup-gui-installer PRIVATE CUP_GUI_VERSION="${PROJECT_VERSION}")
target_link_libraries(cup-gui-installer
    PRIVATE
        Cutefish::Toolkit
        Cutefish::ToolkitBase
        cup2_core
        Threads::Threads
        crypto
)

install(TARGETS cup-gui-installer RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES cup-gui-installer.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
