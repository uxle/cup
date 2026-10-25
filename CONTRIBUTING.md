# Contributing to CuteFish Universal Package (CUP)

Thank you for your interest in contributing to CUP! We welcome contributions across the core C23 runtime, C++20 ABI solver, Rust workspace, and Qt5/QML GUI.

---

## Development Setup

### Prerequisites

- **Compilers**: GCC 14+ or Clang 18+ with C23 and C++20 support.
- **Build Tools**: Make, CMake 3.16+, qmake.
- **Libraries**: OpenSSL 3.0+ (`libssl-dev`), Qt5 Declarative (`qtdeclarative5-dev`).

### Building from Source

```bash
# Clone the repository
git clone https://github.com/cutefishos/cup.git
cd cup

# Build all core binaries and libraries
make all

# Build the Qt/QML graphical installer
make gui
```

---

## Testing & Quality Assurance

All contributions must pass the full automated quality battery:

```bash
# 1. Run 400 normative conformance checks and security PoCs
make test

# 2. Run GUI backend and UI flow smoke tests
make gui-test

# 3. Memory safety adversarial fuzzing under AddressSanitizer & UndefinedBehaviorSanitizer
make security
make fuzz
```

---

## Coding Standards

- **Core Runtime (`c_core/libcup2.c`)**:
  - Pure C23 standard (`-std=c2x`).
  - Zero heap allocation in performance-critical verification paths.
  - Fail-closed error handling: always check buffer bounds, lengths, and integer overflow before pointer arithmetic.
- **Graphical Frontend (`gui/`)**:
  - Keep interfaces clean, responsive, and minimalist.
  - Prioritize icons and visual state indicators over walls of text.
  - Offload cryptographic and privileged operations to `cup-cli` via `QProcess` argv arrays (never execute through a shell).

---

## Submitting Pull Requests

1. Fork the repository and create your feature branch:
   ```bash
   git checkout -b feature/my-enhancement
   ```
2. Commit your changes with clear, descriptive commit messages.
3. Verify all tests pass (`make test && make gui-test`).
4. Push to your branch and open a Pull Request on GitHub.
