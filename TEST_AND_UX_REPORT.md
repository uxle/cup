# CUP v3.0 - Test findings and UX/brand improvements

Target: `cup_v3_project_FIXED_1` (a hardened version of the original suite, plus the Qt/QML GUI). The result is this tree.

## 1. How it was tested
- Rebuilt everything with the project's `-Wall -Wextra -Werror -Wshadow` flags and under ASan+UBSan.
- Black-box **mutation sweep**: 17,571 mutants, covering raw and re-sealed byte flips, truncations, and targeted structural attacks. Re-sealing recomputes section digests and footer so only the signature/binding logic can catch a change.
- **Independent Python verifier/forger** (`tests/cup_ref.py`), written from the wire layout only, so disagreements with the C verifier are real findings.
- **CLI end-to-end tests** (`tests/cli_tests.py`, 57 tests): UX contract, build+verify, attacks, forgeries, deployment.
- Conformance runner (400), hostile harness (9), cup-spec-lint, Python FFI/BLAKE3 cross-checks, Rust build+tests, GUI `--selftest` (52 checks).

## 2. Findings (before my changes) and what was done

| # | Finding | Status |
|---|---|---|
| 1 | The signature covered only the manifest. Payload, EROFS, FSVERITY and stub bytes were **not bound** to it: a re-sealed package with swapped payload verified OK. | Fixed: INDEX chunks, leaf hashes, Merkle root, EROFS digest and FSVERITY are checked against signed manifest fields. |
| 2 | Header `flags` and `sig_alg` are outside the signed data. Stripping the PQ half (`sig_alg 3->1`) or clearing flags passed. | Fixed: both are now signed inside the manifest and must match the header. |
| 3 | The embedded stub (section 0x10) was unauthenticated. | Fixed: `stub_sha256` in the signed manifest; SELF_BOOTSTRAP requires the section. |
| 4 | Namespace confusion: the manifest `id` was found by substring search, so a decoy `"id"` in another field or a duplicate key could pass the namespace check. | Fixed: strict JSON parser (rejects duplicate keys, trailing data, control chars, deep nesting). |
| 5 | Signature section parsing relied on trailing-length slack (`chain[8]` overflow history). | Fixed: bounds-checked parse; `chain_length` 1..8, exact length, trailing bytes fail. |
| 6 | Gaps between sections, non-zero FSVERITY tail, non-zero reserved/compression/encryption flags were accepted. | Now hard failures. |
| 7 | The CLI could not honestly report why it failed. | Every failure has a spec reference and an actionable hint; exit codes are honest. |
| 8 | `run`/`convert` pretended to work. | Now exit 4 with a clear "unavailable" message. |

Result after the fixes: **0 of 17,571 mutants accepted, 0 crashes.**

## 3. Findings that cannot be fixed inside this suite
- **Demo keys come from public seeds** (`CUP-V3-ROOT-CA-SEED` ...). Anyone can mint a package the built-in root accepts. The CLI now warns on every verify; use `--trust-root/--tsa-key/--no-builtin-root` for real use.
- **The ML-DSA-65 slot is not FIPS 204.** It is an Ed25519 anchor plus a SHAKE256 tail, and the PQ public key is attacker-supplied and uncertified. The CLI warns; `--require-pq` fails. A real implementation needs OpenSSL >= 3.5 or liboqs (the sandbox has 3.0.13).
- **The header is unauthenticated by design.** Mitigated by signing flags/`sig_alg` in the manifest, but a spec change (signed header) would be cleaner.
- **The conformance runner is ~40 distinct assertions looped to reach 400**, and the CUP-CLI category does not exercise the CLI. It is a sanity check, not 400 independent tests.
- **`./app.cup` self-execution** conflicts with magic `CUP3` at offset 0; it needs `binfmt_misc`.
- The EROFS image and fs-verity digest are demo stand-ins (plain SHA-256, tiny fake image); the builder payload is synthetic; one install root holds one package id.
- Landlock/BPF claims on the old badge were marketing; the new badge only lists what is actually implemented.

## 4. CLI UX
Colour only on a TTY (`NO_COLOR`, `CLICOLOR_FORCE`, `TERM=dumb`, `--color=`); ASCII fallback when the terminal is not UTF-8; grouped verify output (Container / Authenticity / Content / Warnings); `inspect` with section table, chain and manifest; `--json` everywhere with no escape codes; `--dry-run`; atomic output files; `install` over an existing id behaves as an upgrade (what the GUI needs); downgrade refused unless `--allow-downgrade`; the GUI contract line `VERIFIED OK: <uri>` is unchanged.

## 5. Brand
New mark: a package cube that is also a fish. Three faces (teal/sky/indigo), a forked coral tail, an eye that doubles as a "verified" dot. It reads at 16 px, unlike the old cube + blob + rings + text. Files in `assets/`: app icon, transparent mark, single-colour mark, dark/light lockups (font-independent stroke wordmark), installer badge, favicon, `brand.html` brand sheet, PNG renders. `make assets` regenerates everything from one script. GUI icons in `gui/icons/` updated to match.

## 6. GUI UX (needs `make gui` to see)
- `AppPage`: single column layout, so the metadata card can no longer overlap the status text or clip on the right; clear Verified / Verifying / **Not verified - installation is blocked** banner; primary Install button.
- `InstallPage`: status block on top, log fills the rest (selectable, wraps, follows the newest line); the log is no longer cut off at the top.
- `HomePage`: larger icon, one primary action, rejection reason in an error card, trust note.
- Whole-window drag-and-drop highlight; new `CupUI.ActionButton` (primary/secondary); theme `tint()` helper.
- Only the existing `Installer` API is used.

**Not verified:** this sandbox has no Qt dev headers or QML modules, so the QML was only checked for syntax balance, not compiled or rendered. Please run `make gui && make gui-test && make gui-screenshots` and look at the screenshots. The old GUI binary passes 51 of 52 selftest checks against the new CLI; the one mismatch is a hard-coded "6 sections" (v3 packages now carry the stub = 7), fixed in `gui/src/selftest.cpp`.

## 7. Things you may notice
- Package digests/URIs differ from the original suite (the signed manifest gained fields).
- Packages from the old builder still verify, with a warning (`--strict` fails them).

## 8. Reproduce
```
make all && make test        # build, 400 conformance, 57 CLI tests, lint, FFI
make security                # ASan+UBSan hostile harness (9/9)
make fuzz                    # 17,571-mutant sweep
make rust                    # Rust workspace
make assets                  # regenerate logos
```
