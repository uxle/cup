# Makefile for CuteFish Universal Package Format (CUP v3.0 - RFC CUP-3.0)
CC      := gcc
CXX     := g++
AR      := ar
STRIP   := strip
CFLAGS  := -std=c2x -O3 -Wall -Wextra -Werror -Wshadow -Wformat=2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2
CXXFLAGS:= -std=c++20 -O3 -Wall -Wextra -Werror -Wshadow -Wno-volatile -Wno-type-limits -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS := -lcrypto
HARD_HOSTILE_CFLAGS := -std=c2x -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer

HDRS    := c_core/libcup2.h c_core/cup_ui.hpp c_core/cup_json.hpp c_core/cup_verify.hpp

.PHONY: all clean test lint rust packages security fuzz assets help gui gui-test gui-screenshots deb dist

all: lib/libcup2.a lib/libcup2.so bin/cup-stub bin/cup-installer bin/cup-cli bin/cup-builder bin/cup-conformance packages

lib/libcup2.o: c_core/libcup2.c c_core/libcup2.h
	@mkdir -p lib
	$(CC) $(CFLAGS) -c c_core/libcup2.c -o lib/libcup2.o

lib/cup_abi_solver.o: c_core/cup_abi_solver.cpp c_core/cup_abi_solver.hpp c_core/libcup2.h
	@mkdir -p lib
	$(CXX) $(CXXFLAGS) -c c_core/cup_abi_solver.cpp -o lib/cup_abi_solver.o

lib/libcup2.a: lib/libcup2.o lib/cup_abi_solver.o
	$(AR) rcs lib/libcup2.a lib/libcup2.o lib/cup_abi_solver.o

lib/libcup2.so: lib/libcup2.o lib/cup_abi_solver.o
	$(CXX) -shared -o lib/libcup2.so lib/libcup2.o lib/cup_abi_solver.o $(LDFLAGS)

bin/cup-stub: c_core/cup_stub.c
	@mkdir -p bin
	$(CC) -std=c2x -Os -nostdlib -static -Wl,--build-id=none c_core/cup_stub.c -o bin/cup-stub
	$(STRIP) --strip-all bin/cup-stub

bin/cup-installer: c_core/cup_installer_main.cpp $(HDRS) lib/libcup2.a
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) c_core/cup_installer_main.cpp lib/libcup2.a $(LDFLAGS) -o bin/cup-installer

bin/cup-cli: bin/cup-installer
	cp bin/cup-installer bin/cup-cli

bin/cup-builder: bin/cup-installer
	cp bin/cup-installer bin/cup-builder

bin/cup-conformance: c_core/cup_conformance_runner.cpp lib/libcup2.a
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) c_core/cup_conformance_runner.cpp lib/libcup2.a $(LDFLAGS) -o bin/cup-conformance

packages: bin/cup-builder bin/cup-stub
	@mkdir -p packages
	./bin/cup-builder build packages/foopaint-3.0.0-x86_64.cup --app-id org.foopaint.FooPaint --version 3.0.0 --v3
	./bin/cup-builder build packages/foopaint-2.0.0-x86_64.cup --app-id org.foopaint.FooPaint --version 2.0.0 --v2

# Adversarial security harness: rebuilds libcup2 under ASan+UBSan and runs the
# hostile-input PoC suite (integer-overflow ELF, allocation wraps, chain smash,
# watchdog spin, D-Bus 'g' jump, BLAKE3 KAT). Every attack must be survived.
bin/hostile_tests: tools/hostile_tests.c c_core/libcup2.c c_core/libcup2.h
	@mkdir -p bin
	$(CC) $(HARD_HOSTILE_CFLAGS) -I c_core tools/hostile_tests.c c_core/libcup2.c $(LDFLAGS) -o bin/hostile_tests

security: bin/hostile_tests
	ASAN_OPTIONS=detect_leaks=0 ./bin/hostile_tests

test: all security
	./bin/cup-conformance
	./bin/cup-installer verify packages/foopaint-3.0.0-x86_64.cup --strict
	./bin/cup-installer verify packages/foopaint-2.0.0-x86_64.cup --strict
	python3 python/pycup_ffi.py
	python3 python/blake3_crossval.py
	python3 tools/cup-spec-lint spec/RFC_CUP_3.0_Master_Spec.md
	python3 tests/cli_tests.py

help:
	@echo "make            build libraries, tools and demo packages"
	@echo "make test       conformance + hostile + strict verify + FFI + BLAKE3 + CLI tests"
	@echo "make fuzz       ASAN/UBSAN build + 17k-mutant adversarial sweep of the verifier"
	@echo "make security   ASAN/UBSAN hostile PoC harness (libcup2)"
	@echo "make rust       build and test the Rust workspace (run 'make' first)"
	@echo "make assets     re-render PNG logos from the SVG sources (needs Playwright)"
	@echo "make gui        build the Qt/QML installer (needs qmake + Qt5 dev packages)"
	@echo "make deb        package CUP as a Debian .deb package"
	@echo "make dist       build .deb package and universal tarball in dist/"

# Memory-safety sweep: sanitizer build, then every section byte flipped / re-sealed / truncated / structurally attacked.
fuzz: lib/libcup2.a
	@mkdir -p build_asan
	$(CC) -std=c2x -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fPIC -c c_core/libcup2.c -o build_asan/libcup2.o
	$(CXX) -std=c++20 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wno-volatile -c c_core/cup_abi_solver.cpp -o build_asan/solver.o
	$(CXX) -std=c++20 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wno-volatile c_core/cup_installer_main.cpp build_asan/libcup2.o build_asan/solver.o $(LDFLAGS) -o build_asan/cup-installer-asan
	python3 -I tests/attack.py build_asan/cup-installer-asan packages/foopaint-3.0.0-x86_64.cup

assets:
	python3 tools/render_assets.py

rust:
	cd rust_workspace && cargo build --release && cargo test

# --- GUI installer (Cutefish-debinstaller-style Qt5/QML front-end) ---------
# Builds gui/gui.pro with qmake. For a locally-extracted Qt toolchain pass:
#   make gui GUI_QMAKE=/path/to/qmake GUI_QMAKE_LIBDIR=/path/to/usr/lib/x86_64-linux-gnu
GUI_DIR   := gui
GUI_BUILD := gui/build
GUI_QMAKE       ?= qmake
GUI_QMAKE_LIBDIR ?=

GUI_ENV := QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software

gui: lib/libcup2.a bin/cup-cli
	@mkdir -p $(GUI_BUILD)
	cd $(GUI_BUILD) && $(GUI_QMAKE) ../gui.pro $(if $(GUI_QMAKE_LIBDIR),QMAKE_LIBDIR+=$(GUI_QMAKE_LIBDIR),) && $(MAKE) -j$$(nproc)

# Headless backend battery (52 checks) + offscreen UI flow test (7 checks).
gui-test: gui
	cd $(GUI_BUILD) && $(GUI_ENV) ./cup-gui-installer --selftest ../../packages/foopaint-3.0.0-x86_64.cup
	cd $(GUI_BUILD) && $(GUI_ENV) ./cup-gui-installer --smoke-qml ../../packages/foopaint-3.0.0-x86_64.cup

# Offscreen renders of the Home/App/Install pages for visual review.
gui-screenshots: gui
	@mkdir -p $(GUI_BUILD)/screenshots
	cd $(GUI_BUILD) && $(GUI_ENV) ./cup-gui-installer --screenshot screenshots ../../packages/foopaint-3.0.0-x86_64.cup

deb: gui
	./scripts/package-deb.sh

dist: deb
	@mkdir -p dist
	@mv -f cup-package-manager_*_amd64.deb dist/ 2>/dev/null || true
	@rm -rf /tmp/cup-dist-staging
	@mkdir -p /tmp/cup-dist-staging/bin /tmp/cup-dist-staging/lib /tmp/cup-dist-staging/c_core \
	         /tmp/cup-dist-staging/data /tmp/cup-dist-staging/gui/icons /tmp/cup-dist-staging/assets /tmp/cup-dist-staging/scripts
	@cp -a bin/* /tmp/cup-dist-staging/bin/
	@cp -f gui/build/cup-gui-installer /tmp/cup-dist-staging/bin/ 2>/dev/null || true
	@cp -a lib/* /tmp/cup-dist-staging/lib/
	@cp -f c_core/*.h c_core/*.hpp /tmp/cup-dist-staging/c_core/ 2>/dev/null || true
	@cp -a data/* /tmp/cup-dist-staging/data/
	@cp -f gui/cup-gui-installer.desktop /tmp/cup-dist-staging/gui/
	@cp -a gui/icons/* /tmp/cup-dist-staging/gui/icons/
	@cp -a assets/* /tmp/cup-dist-staging/assets/
	@cp -a scripts/* /tmp/cup-dist-staging/scripts/
	@cp -f scripts/install-cup.sh /tmp/cup-dist-staging/install.sh
	@chmod +x /tmp/cup-dist-staging/install.sh
	@cp -f README.md LICENSE CHANGELOG.md /tmp/cup-dist-staging/
	@tar -czf dist/cup-3.0.0-linux-x86_64.tar.gz -C /tmp/cup-dist-staging .
	@rm -rf /tmp/cup-dist-staging
	@echo "==> Distribution artifacts created in dist/:"
	@ls -lh dist/

clean:
	rm -rf lib/*.o lib/*.a lib/*.so bin/* packages/*.cup build_asan $(GUI_BUILD) debian_pkg dist *.deb
