# Security Policy & Invariants

CUP (CuteFish Universal Package) is designed around strict, fail-closed security invariants to protect Linux desktop users from malicious or corrupted applications.

---

## Core Security Invariants

1. **Gate 1: Container Geometry & Header Sealing**:
   - The primary 128-byte header is validated against a trailing cryptographic footer digest.
   - Any truncation, section overlap, or integer wrap-around causes immediate rejection before parsing payload contents.
2. **Gate 2: Content Hash & Merkle Tree Binding**:
   - Every 4 KiB block is hashed via BLAKE3 / FastCDC content-defined chunking.
   - Merkle root digests must match the signed manifest exactly.
3. **Gate 3: Cryptographic Signature Chain**:
   - Manifests are sealed with domain-separated Ed25519 signatures linked through an X.509-style certificate chain to a trusted distribution root anchor.
4. **Gate 4: Unprivileged Sandboxing**:
   - Sandboxing tiers restrict network access, device files, and filesystem visibility using Landlock LSM and Seccomp-BPF filters.

---

## Reporting Vulnerabilities

If you discover a security vulnerability or bypass within CUP:
- **Do not disclose publicly** through GitHub Issues or public pull requests.
- Please email our security team at **security@cutefish.org**.
- Include a minimal proof of concept (PoC) or reproducer script.
- We will acknowledge receipt within 48 hours and work with you on a coordinated disclosure timeline.
