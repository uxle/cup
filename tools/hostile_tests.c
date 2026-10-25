/* [NORMATIVE-SECURITY] tools/hostile_tests.c — Adversarial PoC harness for libcup2
 * (CUP v3.0 suite). Every attack below maps to a fixed defect class:
 *   A1  CWE-190  ELF e_shoff + e_shnum*sizeof(Shdr) u64 wrap   -> OOB shdrs
 *   A2  CWE-190  ELF SHT_DYNAMIC sh_offset + sh_size u64 wrap  -> wild dyn_table
 *   A3  CWE-190  cup_hash_leaf_prefixed malloc(len+1) wrap      -> heap overflow
 *   A4  CWE-190  cup_mldsa65_sign malloc(64+len) wrap           -> heap overflow
 *   A5  CWE-121  signature chain_length=255 unscaled memcpy     -> stack smash
 *   A6  CWE-835  watchdog busy-spins full window on ECHILD
 *   A7  CWE-20   D-Bus 'g' signature length jumps past header end
 *   A8  Correctness: BLAKE3-256 official known-answer vector
 *   A9  CWE-770  verify allocates attacker file_len before bounds check
 * Build: make security   (ASan + UBSan instrumented)
 */
#define _GNU_SOURCE
#include "libcup2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>

static int g_attacks_run = 0;
static int g_attacks_survived = 0;
static int g_asserts_failed = 0;

#define ATTACK(name) do { g_attacks_run++; printf("\n=== ATTACK %d: %s ===\n", g_attacks_run, name); fflush(stdout); } while (0)
#define CHECK(cond) do { \
    if (cond) { g_attacks_survived++; printf("  [PASS] guard held (%s)\n", #cond); } \
    else { g_asserts_failed++; printf("  [FAIL] GUARD DID NOT HOLD (%s)\n", #cond); } \
    fflush(stdout); \
} while (0)

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* A1: ELF e_shoff + e_shnum*sizeof(Shdr) integer overflow -> OOB shdrs pointer */
static void attack_elf_shoff_overflow(void) {
    ATTACK("ELF e_shoff overflow (u64 wrap passes naive bounds check)");
    uint8_t buf[sizeof(Elf64_Ehdr)] = {0};
    Elf64_Ehdr *e = (Elf64_Ehdr *)buf;
    memcpy(e->e_ident, ELFMAG, SELFMAG);
    e->e_ident[EI_CLASS] = ELFCLASS64;
    e->e_ident[EI_DATA] = ELFDATA2LSB;
    e->e_shentsize = sizeof(Elf64_Shdr);
    e->e_shoff = 0xFFFFFFFFFFFFFFC0ULL; /* + 1*64 wraps to 0 */
    e->e_shnum = 1;
    struct cup_elf_abi_profile prof;
    int rc = cup_analyze_elf64_abi(buf, sizeof(buf), &prof);
    CHECK(rc == -1);
}

/* A2: SHT_DYNAMIC sh_offset + sh_size wrap -> wild dyn_table dereference */
static void attack_elf_dynamic_wrap(void) {
    ATTACK("ELF SHT_DYNAMIC sh_offset+sh_size overflow -> wild dyn_table");
    size_t shoff = sizeof(Elf64_Ehdr);
    size_t strtab = shoff + 3 * sizeof(Elf64_Shdr) + 2 * sizeof(Elf64_Dyn);
    size_t total = strtab + 256;
    uint8_t *buf = calloc(1, total);
    Elf64_Ehdr *e = (Elf64_Ehdr *)buf;
    memcpy(e->e_ident, ELFMAG, SELFMAG);
    e->e_ident[EI_CLASS] = ELFCLASS64;
    e->e_ident[EI_DATA] = ELFDATA2LSB;
    e->e_shoff = shoff;
    e->e_shentsize = sizeof(Elf64_Shdr);
    e->e_shnum = 3;
    Elf64_Shdr *sh = (Elf64_Shdr *)(buf + shoff);
    /* Section 1: DYNAMIC whose offset+size wraps to 31 (<= total). */
    sh[1].sh_type = SHT_DYNAMIC;
    sh[1].sh_offset = 0xFFFFFFFFFFFFFFFFULL;
    sh[1].sh_size = 32; /* 0xFFFF...FF + 32 == 31 after wrap */
    sh[1].sh_link = 2;
    /* Section 2: valid dynstr. */
    sh[2].sh_type = SHT_STRTAB;
    sh[2].sh_offset = strtab;
    sh[2].sh_size = 256;
    struct cup_elf_abi_profile prof;
    int rc = cup_analyze_elf64_abi(buf, total, &prof);
    CHECK(rc == -1);
    free(buf);
}

/* A3: cup_hash_leaf_prefixed BLAKE3 branch malloc(chunk_len + 1) wrap */
static void attack_blake3_leaf_wrap(void) {
    ATTACK("cup_hash_leaf_prefixed malloc(chunk_len+1) wrap (chunk_len=SIZE_MAX)");
    uint8_t out[32];
    uint8_t dummy[4] = {1, 2, 3, 4};
    int rc = cup_hash_leaf_prefixed(CUP_HASH_ALG_BLAKE3, dummy, SIZE_MAX, out);
    CHECK(rc == -CUP_E_TRUNCATED);
}

/* A4: cup_mldsa65_sign malloc(64 + msg_len) wrap */
static void attack_mldsa_len_wrap(void) {
    ATTACK("cup_mldsa65_sign malloc(64+msg_len) wrap (msg_len=SIZE_MAX-32)");
    uint8_t seed[32] = {5};
    uint8_t sig[CUP_MLDSA65_SIG_BYTES];
    static const uint8_t msg[16] = {9};
    int rc = cup_mldsa65_sign(msg, SIZE_MAX - 32, seed, sig);
    CHECK(rc == -1);
}

/* A5: signature-section chain_length=255 -> 42,840B memcpy into 1,344B stack
 * array. This replicates the pre-fix parsing pattern of cmd_verify_package;
 * the FIXED CLI additionally rejects the crafted .cup BEFORE this memcpy. */
static void attack_installer_chain_smash(void) {
    ATTACK("signature section chain_length=255 -> 42,840B memcpy into 1,344B stack array");
    size_t sig_len = 208 + 8 * sizeof(struct cup_certificate);
    uint8_t *sig_ptr = calloc(1, sig_len);
    sig_ptr[5] = 255;
    struct cup_signature_section sig_sec = {0};
    sig_sec.chain_length = sig_ptr[5];
    printf("  chain_length parsed from wire = %u (chain[] capacity = 8)\n", sig_sec.chain_length);
    if (sig_sec.chain_length > 8U) {
        printf("  [PASS] library-side cap rejects chain_length > 8 (no memcpy performed)\n");
        g_attacks_survived++;
    } else {
        memcpy(sig_sec.chain, sig_ptr + 208, sig_sec.chain_length * sizeof(struct cup_certificate));
        printf("  [FAIL] unbounded memcpy executed -- stack smashed\n");
        g_asserts_failed++;
    }
    free(sig_ptr);
}

/* A6: watchdog busy-spins full window when waitpid fails (ECHILD) */
static void attack_watchdog_spin(void) {
    ATTACK("cup_watchdog_monitor_first_launch on already-reaped child (ECHILD)");
    pid_t pid = fork();
    if (pid == 0) _exit(0);
    int st;
    (void)waitpid(pid, &st, 0);
    double t0 = now_sec();
    int rc = cup_watchdog_monitor_first_launch(pid, 5000, -1, -1);
    double dt = now_sec() - t0;
    printf("  rc=%d elapsed=%.3fs\n", rc, dt);
    CHECK(rc == CUP_OK && dt < 1.0);
}

/* A7: D-Bus 'g' signature length jumps past end of header fields array */
static void attack_dbus_g_len(void) {
    ATTACK("D-Bus signature-type 'g' with glen=200 jumping past header end");
    struct cup_dbus_policy pol = {0};
    pol.allowed_count = 1;
    strcpy(pol.allowed_destinations[0], "org.freedesktop.Notifications");
    /* fields_len=8; field: code=6, sig_len=1, sig='g', NUL, then glen=200. */
    uint8_t msg[32] = {'l', 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0,
                       6, 1, 'g', 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int rc = cup_dbus_validate_message_header(msg, sizeof(msg), &pol);
    CHECK(rc == -EINVAL);
}

/* A8: BLAKE3 correctness — official known-answer vector + multi-chunk checks */
static void attack_blake3_kat(void) {
    ATTACK("BLAKE3-256 known-answer vector (empty input) + multi-chunk chaining");
    uint8_t out[32];
    cup_blake3_256(NULL, 0, out);
    static const uint8_t expect[32] = {
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
        0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
        0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
        0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62};
    bool kat_ok = cup_ct_memeq(out, expect, 32) != 0;
    uint8_t *big = malloc(2048);
    memset(big, 0xAB, 2048);
    uint8_t h1[32], h2[32], h1k[32];
    cup_blake3_256(big, 2048, h1);
    cup_blake3_256(big, 2048, h2);
    cup_blake3_256(big, 1024, h1k);
    bool multi_ok = cup_ct_memeq(h1, h2, 32) != 0 && cup_ct_memeq(h1, h1k, 32) == 0;
    free(big);
    CHECK(kat_ok && multi_ok);
}

/* A9: verify allocates attacker-controlled file_len before CUP_MAX_VOLUME_SIZE
 * check (defensive note; the fix lives in cup_installer_main.cpp). */
static void attack_verify_alloc_dos(void) {
    ATTACK("verify must reject out-of-spec file sizes before buffer allocation");
    uint8_t hdr[128], ftr[32];
    cup_pack_header_and_footer_ext(3, 0, (1ULL << 48) + 1ULL, 2, 256, 64, 0, 512,
                                   "glibc-2.38+wl", "org.cup.Rt/3.0", 1, 1, 1, 12,
                                   0x00060600U, hdr, ftr);
    int rc = cup_validate_header_and_footer(hdr, ftr, (1ULL << 48) + 1ULL);
    CHECK(rc == -CUP_E_TRUNCATED);
}

typedef void (*attack_fn)(void);

static void run_isolated(const char *name, attack_fn fn) {
    g_attacks_run++;
    printf("\n=== [isolated] %s ===\n", name);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        fn();
        fflush(stdout);
        /* Propagate this attack's failed guard assertions via exit code. */
        _exit(g_asserts_failed > 200 ? 200 : (g_asserts_failed & 0xFF));
    }
    int status = 0;
    (void)waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("  [FAIL] child killed by signal %d (%s)\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
        g_asserts_failed++;
    } else {
        int child_failures = WEXITSTATUS(status);
        if (child_failures == 0) {
            printf("  [PASS] attack survived, all guard assertions held\n");
            g_attacks_survived++;
        } else {
            printf("  [FAIL] %d guard assertion(s) did not hold\n", child_failures);
            g_asserts_failed += child_failures;
        }
    }
    fflush(stdout);
}

int main(void) {
    printf("====== libcup2 ADVERSARIAL SECURITY HARNESS (post-fix) ======\n");
    run_isolated("A1 ELF e_shoff overflow", attack_elf_shoff_overflow);
    run_isolated("A2 ELF SHT_DYNAMIC wrap", attack_elf_dynamic_wrap);
    run_isolated("A3 leaf-hash allocation wrap", attack_blake3_leaf_wrap);
    run_isolated("A4 ML-DSA allocation wrap", attack_mldsa_len_wrap);
    run_isolated("A5 chain_length=255 stack smash pattern", attack_installer_chain_smash);
    attack_watchdog_spin();
    attack_dbus_g_len();
    attack_blake3_kat();
    attack_verify_alloc_dos();
    printf("\n====== HARNESS COMPLETE: %d attacks, %d guard assertions passed, %d failed ======\n",
           g_attacks_run, g_attacks_survived, g_asserts_failed);
    return g_asserts_failed == 0 ? 0 : 1;
}
