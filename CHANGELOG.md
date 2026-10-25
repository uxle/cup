# Changelog

All notable changes to the CuteFish Universal Package (CUP) project will be documented in this file.

---

## [3.0.0] - 2026-10-25 (RFC CUP-3.0)

### Added
- **Unified `cup` CLI & Application Runner**: High-level commands for `run`, `install`, `list`, `uninstall`, `verify`, and `inspect`.
- **Kernel `binfmt_misc` Execution**: Support for executing `.cup` packages directly as native Linux binaries (`./myapp.cup`).
- **Minimalist Qt5/QML Graphical Installer**: Clean, icon-driven user interface replacing verbose terminal logs with visual cards and badges.
- **Native Debian Packaging**: Complete `.deb` package generation script (`scripts/package-deb.sh`) for Debian, Ubuntu, and CutefishOS.
- **Universal Multi-Distro Installer**: `scripts/install-cup.sh` and standalone distribution tarball for Fedora, Arch Linux, and openSUSE.
- **Brand Assets**: Custom Cup icon design with SVG vector assets and multi-resolution PNG sets (16px to 512px).
- **Freedesktop MIME Database Integration**: Registered `application/x-cup-package` and `application/x-cup`.

### Security Hardening
- Hardened container bounds checking to eliminate stack buffer overflows (CWE-121).
- Added integer overflow protection on 64-bit ELF section header parsing (CWE-190).
- Guarded verifier against file-size race conditions and memory exhaustion (CWE-770).
- Full 236-length cross-validated BLAKE3 tree hashing implementation.

---

## [2.0.0] - 2025-11-14

### Added
- Ed25519 digital signature chains with intermediate certificate authorities.
- Content-defined chunking (FastCDC) and Merkle tree integrity verification.
- Atomic symlink deployment and rollback support (`active` / `rollback`).

---

## [1.0.0] - 2024-08-10

### Added
- Initial CUP container format with static ELF header and embedded payload.
- Basic CLI tool for container inspection and extraction.
