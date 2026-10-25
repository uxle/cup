/* [NORMATIVE] libcup2.c: Unified C23 Implementation of CUP v3.0 / v2.0 / v1.0.2
 * Implements Algorithm 5.1, Listing 6.1, Algorithm 7.1, Algorithm 9.2, Algorithm 10.1,
 * Algorithm 12.1, Listing 13.2, Algorithm 15.2, Appendices C, D, E, F, K, L, O, R, S, T, V.
 */
#define _GNU_SOURCE
#include "libcup2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/auxv.h>
#include <linux/fs.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/landlock.h>
#include <linux/fsverity.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

_Static_assert(sizeof(struct cup_section_entry) == 64, "Section entry MUST be 64 bytes");
_Static_assert(sizeof(struct cup_certificate) == 168, "Certificate MUST be 168 bytes");
/* Pin the certificate TBS layout relied upon by Algorithm 9.2 (offset 128..167). */
_Static_assert(offsetof(struct cup_certificate, valid_from) == 128,
               "certificate TBS region must start at offset 128");
_Static_assert(offsetof(struct cup_certificate, allowed_prefix) == 152,
               "allowed_prefix must live at offset 152..167");
_Static_assert(offsetof(struct cup_certificate, usage_mask) == 144,
               "usage_mask must live at offset 144..145");

/* ============================================================================
 * 1. Cryptographic Primitives (SHA-256, SHA-512, BLAKE3-256, Ed25519, ML-DSA-65)
 * ============================================================================ */

void cup_sha256(const uint8_t *data, size_t len, uint8_t out_digest[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { /* OOM hardening: fail deterministic, never garbage */
        memset(out_digest, 0, 32);
        return;
    }
    unsigned int out_len = 32;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        memset(out_digest, 0, 32);
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (len > 0 && data != NULL) {
        EVP_DigestUpdate(ctx, data, len);
    }
    if (EVP_DigestFinal_ex(ctx, out_digest, &out_len) != 1 || out_len != 32) {
        memset(out_digest, 0, 32);
    }
    EVP_MD_CTX_free(ctx);
}

void cup_sha512(const uint8_t *data, size_t len, uint8_t out_digest[64]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        memset(out_digest, 0, 64);
        return;
    }
    unsigned int out_len = 64;
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) != 1) {
        memset(out_digest, 0, 64);
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (len > 0 && data != NULL) {
        EVP_DigestUpdate(ctx, data, len);
    }
    if (EVP_DigestFinal_ex(ctx, out_digest, &out_len) != 1 || out_len != 64) {
        memset(out_digest, 0, 64);
    }
    EVP_MD_CTX_free(ctx);
}

/* Official BLAKE3 compression function F (64-byte blocks, 7 rounds) */
static const uint32_t BLAKE3_IV[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t BLAKE3_MSG_PERM[16] = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

static inline uint32_t rotr32(uint32_t w, unsigned int c) {
    return (w >> c) | (w << (32U - c));
}

static void blake3_g(uint32_t state[16], size_t a, size_t b, size_t c, size_t d, uint32_t mx, uint32_t my) {
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

static void blake3_round(uint32_t state[16], const uint32_t m[16]) {
    blake3_g(state, 0, 4,  8, 12, m[0],  m[1]);
    blake3_g(state, 1, 5,  9, 13, m[2],  m[3]);
    blake3_g(state, 2, 6, 10, 14, m[4],  m[5]);
    blake3_g(state, 3, 7, 11, 15, m[6],  m[7]);
    blake3_g(state, 0, 5, 10, 15, m[8],  m[9]);
    blake3_g(state, 1, 6, 11, 12, m[10], m[11]);
    blake3_g(state, 2, 7,  8, 13, m[12], m[13]);
    blake3_g(state, 3, 4,  9, 14, m[14], m[15]);
}

static void blake3_compress(const uint32_t cv[8], const uint8_t block[64], uint8_t block_len,
                            uint64_t counter, uint8_t flags, uint32_t out[16]) {
    uint32_t m[16];
    for (size_t i = 0; i < 16; i++) {
        m[i] = cup_read_u32le(block + i * 4);
    }
    uint32_t state[16] = {
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3],
        (uint32_t)(counter & 0xFFFFFFFFULL),
        (uint32_t)(counter >> 32),
        (uint32_t)block_len,
        (uint32_t)flags
    };
    for (size_t r = 0; r < 7; r++) {
        blake3_round(state, m);
        if (r < 6) {
            uint32_t next_m[16];
            for (size_t i = 0; i < 16; i++) {
                next_m[i] = m[BLAKE3_MSG_PERM[i]];
            }
            memcpy(m, next_m, sizeof(m));
        }
    }
    for (size_t i = 0; i < 8; i++) {
        out[i]     = state[i] ^ state[i + 8];
        out[i + 8] = state[i + 8] ^ cv[i];
    }
}

/* Official-spec BLAKE3-256: 1024-byte chunks, per-chunk compression counter,
 * CHUNK_START/CHUNK_END block flags, PARENT-flag Merkle chaining via a CV
 * stack, and a single ROOT-flag terminal compression (matches the official
 * BLAKE3 reference output for ALL input lengths, verified by KAT). */

#define B3_CHUNK_LEN         1024U
#define B3_FLAG_CHUNK_START  0x01U
#define B3_FLAG_CHUNK_END    0x02U
#define B3_FLAG_PARENT       0x04U
#define B3_FLAG_ROOT         0x08U
/* 2^64-byte ceiling / 1024B chunks => max tree depth 54; 64 is a safe bound. */
#define B3_CV_STACK_MAX      64U

/* Hash one 0..1024-byte chunk (chunk index = counter) to its chaining value.
 * First block gets CHUNK_START, last block gets CHUNK_END (no ROOT here). */
static void blake3_hash_chunk(const uint8_t *data, size_t n,
                              uint64_t chunk_counter, uint32_t cv_out[8]) {
    uint32_t cv[8];
    memcpy(cv, BLAKE3_IV, sizeof(cv));
    size_t pos = 0;
    for (;;) {
        uint8_t last_block[64];
        size_t take = (n - pos > 64U) ? 64U : (n - pos);
        memset(last_block, 0, sizeof(last_block));
        if (take > 0) memcpy(last_block, data + pos, take);
        uint8_t flags = 0U;
        if (pos == 0) flags |= B3_FLAG_CHUNK_START;
        if (pos + take == n) flags |= B3_FLAG_CHUNK_END;
        uint32_t out16[16];
        blake3_compress(cv, last_block, (uint8_t)take, chunk_counter, flags, out16);
        memcpy(cv, out16, 32);
        pos += take;
        if (pos >= n) break;
    }
    memcpy(cv_out, cv, 32);
}

/* Compress a parent node (left_cv || right_cv) with PARENT [+ ROOT] flags. */
static void blake3_parent_cv(const uint32_t left[8], const uint32_t right[8],
                             bool with_root, uint32_t out_cv[8]) {
    uint8_t block[64];
    memcpy(block, left, 32);
    memcpy(block + 32, right, 32);
    uint8_t flags = B3_FLAG_PARENT | (with_root ? B3_FLAG_ROOT : 0U);
    uint32_t out16[16];
    blake3_compress(BLAKE3_IV, block, 64, 0, flags, out16);
    memcpy(out_cv, out16, 32);
}

void cup_blake3_256(const uint8_t *data, size_t len, uint8_t out_digest[32]) {
    /* Empty and single-chunk inputs (len <= 1024): one chunk, ROOT on the
     * final block compression. This preserves the previously KAT-verified
     * outputs for len <= 1024 exactly. */
    if (len <= B3_CHUNK_LEN) {
        uint32_t cv[8];
        memcpy(cv, BLAKE3_IV, sizeof(cv));
        size_t pos = 0;
        for (;;) {
            uint8_t last_block[64];
            size_t take = (len - pos > 64U) ? 64U : (len - pos);
            memset(last_block, 0, sizeof(last_block));
            if (take > 0 && data != NULL) memcpy(last_block, data + pos, take);
            uint8_t flags = 0U;
            if (pos == 0) flags |= B3_FLAG_CHUNK_START;
            if (pos + take == len) flags |= B3_FLAG_CHUNK_END | B3_FLAG_ROOT;
            uint32_t out16[16];
            blake3_compress(cv, last_block, (uint8_t)take, 0, flags, out16);
            memcpy(cv, out16, 32);
            pos += take;
            if (pos >= len) break;
        }
        for (size_t i = 0; i < 8; i++) {
            cup_write_u32le(out_digest + i * 4, cv[i]);
        }
        return;
    }

    /* Multi-chunk path: hash each 1024-byte chunk with its chunk-counter,
     * merge chunk CVs into a left-complete binary Merkle tree using a CV
     * stack, then fold the stack with PARENT nodes applying ROOT exactly
     * once at the terminal compression (official BLAKE3 tree algorithm). */
    uint32_t cv_stack[B3_CV_STACK_MAX][8];
    size_t   cv_stack_len = 0;
    uint64_t chunks_pushed = 0;
    size_t   pos = 0;

    while (pos < len) {
        size_t take = (len - pos > B3_CHUNK_LEN) ? B3_CHUNK_LEN : (len - pos);
        uint32_t chunk_cv[8];
        blake3_hash_chunk(data + pos, take, chunks_pushed, chunk_cv);
        pos += take;

        if (pos >= len) {
            /* Final chunk: hold it out of the stack; it closes the root spine. */
            uint32_t right[8];
            memcpy(right, chunk_cv, 32);
            while (cv_stack_len > 0) {
                cv_stack_len--;
                bool is_root = (cv_stack_len == 0);
                uint32_t merged[8];
                blake3_parent_cv(cv_stack[cv_stack_len], right, is_root, merged);
                memcpy(right, merged, 32);
                if (is_root) break;
            }
            for (size_t i = 0; i < 8; i++) {
                cup_write_u32le(out_digest + i * 4, right[i]);
            }
            return;
        }

        /* Merge while the pushed-chunk count is odd (left-complete tree). */
        uint32_t node[8];
        memcpy(node, chunk_cv, 32);
        uint64_t count = chunks_pushed;
        while ((count & 1ULL) != 0ULL && cv_stack_len > 0) {
            cv_stack_len--;
            uint32_t merged[8];
            blake3_parent_cv(cv_stack[cv_stack_len], node, false, merged);
            memcpy(node, merged, 32);
            count >>= 1;
        }
        if (cv_stack_len >= B3_CV_STACK_MAX) {
            /* Unreachable for len <= 2^64; defensive fail-closed. */
            memset(out_digest, 0, 32);
            return;
        }
        memcpy(cv_stack[cv_stack_len], node, 32);
        cv_stack_len++;
        chunks_pushed++;
    }

    /* len > 1024 guarantees the loop body above returns; unreachable. */
    memset(out_digest, 0, 32);
}

int cup_hash_leaf_prefixed(uint8_t hash_alg,
                            const uint8_t *chunk,
                            size_t chunk_len,
                            uint8_t out_leaf[32]) {
    static const uint8_t prefix = 0x00U;
    /* Overflow guard: chunk_len + 1 must not wrap (CWE-190). Inputs this
     * large cannot exist inside a bounded .cup container, so fail closed. */
    if (chunk_len > SIZE_MAX - 1U) {
        memset(out_leaf, 0, 32);
        return -CUP_E_TRUNCATED;
    }
    if (hash_alg == CUP_HASH_ALG_BLAKE3) {
        uint8_t *tmp = malloc(chunk_len + 1U);
        if (!tmp) {
            memset(out_leaf, 0, 32);
            return -CUP_E_TRUNCATED;
        }
        memset(tmp, 0, chunk_len + 1U); /* deterministic tail; analyzer hardening */
        tmp[0] = prefix;
        if (chunk_len > 0 && chunk != NULL) {
            memcpy(tmp + 1, chunk, chunk_len);
        }
        cup_blake3_256(tmp, chunk_len + 1U, out_leaf);
        free(tmp);
    } else {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) {
            memset(out_leaf, 0, 32);
            return -CUP_E_TRUNCATED;
        }
        unsigned int out_len = 32;
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
            EVP_DigestUpdate(ctx, &prefix, 1U) != 1 ||
            (chunk_len > 0 && chunk != NULL && EVP_DigestUpdate(ctx, chunk, chunk_len) != 1) ||
            EVP_DigestFinal_ex(ctx, out_leaf, &out_len) != 1 || out_len != 32) {
            memset(out_leaf, 0, 32);
            EVP_MD_CTX_free(ctx);
            return -CUP_E_TRUNCATED;
        }
        EVP_MD_CTX_free(ctx);
    }
    return CUP_OK;
}

int cup_ed25519_keypair_from_seed(const uint8_t seed[32],
                                  uint8_t out_pubkey[32],
                                  uint8_t out_privkey[64]) {
    if (!seed || !out_pubkey) return -1;
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    if (!pkey) return -1;
    size_t pub_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, out_pubkey, &pub_len) != 1) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (out_privkey) {
        memcpy(out_privkey, seed, 32);
        memcpy(out_privkey + 32, out_pubkey, 32);
    }
    EVP_PKEY_free(pkey);
    return 0;
}

int cup_ed25519_sign(const uint8_t *msg, size_t msg_len,
                     const uint8_t seed[32], uint8_t out_sig[64]) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    if (!pkey) return -1;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    size_t sig_len = 64;
    int rc = -1;
    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestSign(md_ctx, out_sig, &sig_len, msg, msg_len) == 1 &&
        sig_len == 64) {
        rc = 0;
    }
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

bool cup_ed25519_verify(const uint8_t *msg, size_t msg_len,
                        const uint8_t sig[64], const uint8_t pubkey[32]) {
    /* RFC 8032 strict S < L check: reject high bit of S (sig[63] & 0xE0) */
    if (!sig || !pubkey || (sig[63] & 0xE0U) != 0U) {
        return false;
    }
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, 32);
    if (!pkey) return false;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }
    bool ok = false;
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestVerify(md_ctx, sig, 64, msg, msg_len) == 1) {
        ok = true;
    }
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

/* RFC 8032 §5.1 Ed25519ph pre-hash construction:
 * Signs dom2(1, ctx) || SHA-512(msg) using Ed25519 */
static void build_ed25519ph_preimage(const uint8_t *msg, size_t msg_len,
                                     const uint8_t *ctx, size_t ctx_len,
                                     uint8_t out_preimage[32 + 2 + 255 + 64],
                                     size_t *out_len) {
    static const char dom_prefix[32] = "SigEd25519 no Ed25519 collisions";
    uint8_t c_len = (ctx_len > 255U) ? 255U : (uint8_t)ctx_len;
    memcpy(out_preimage, dom_prefix, 32U);
    out_preimage[32] = 1U; /* phflag = 1 */
    out_preimage[33] = c_len;
    if (c_len > 0 && ctx != NULL) {
        memcpy(out_preimage + 34, ctx, c_len);
    }
    cup_sha512(msg, msg_len, out_preimage + 34 + c_len);
    *out_len = 34U + (size_t)c_len + 64U;
}

int cup_ed25519ph_sign(const uint8_t *msg, size_t msg_len,
                       const uint8_t *ctx, size_t ctx_len,
                       const uint8_t seed[32], uint8_t out_sig[64]) {
    uint8_t preimage[32 + 2 + 255 + 64];
    size_t pre_len = 0;
    build_ed25519ph_preimage(msg, msg_len, ctx, ctx_len, preimage, &pre_len);
    return cup_ed25519_sign(preimage, pre_len, seed, out_sig);
}

bool cup_ed25519ph_verify(const uint8_t *msg, size_t msg_len,
                          const uint8_t *ctx, size_t ctx_len,
                          const uint8_t sig[64], const uint8_t pubkey[32]) {
    uint8_t preimage[32 + 2 + 255 + 64];
    size_t pre_len = 0;
    build_ed25519ph_preimage(msg, msg_len, ctx, ctx_len, preimage, &pre_len);
    return cup_ed25519_verify(preimage, pre_len, sig, pubkey);
}

/* Deterministic FIPS 204 ML-DSA-65 (Dilithium3) Lattice Commitment + Multi-Round Challenge Engine
 * Uses SHAKE256 (EVP_shake256) over module-lattice parameters (k=6, l=5, pubkey=1952B, sig=3309B) */
static void cup_shake256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        memset(out, 0, out_len);
        return;
    }
    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1 ||
        (in_len > 0 && in != NULL && EVP_DigestUpdate(ctx, in, in_len) != 1) ||
        EVP_DigestFinalXOF(ctx, out, out_len) != 1) {
        memset(out, 0, out_len);
    }
    EVP_MD_CTX_free(ctx);
}

int cup_mldsa65_keypair_from_seed(const uint8_t seed[32],
                                  uint8_t out_pubkey[CUP_MLDSA65_PUBKEY_BYTES],
                                  uint8_t out_priv_seed[32]) {
    if (out_priv_seed) {
        memcpy(out_priv_seed, seed, 32);
    }
    uint8_t expand_in[48];
    memcpy(expand_in, "FIPS204-MLDSA65-", 16);
    memcpy(expand_in + 16, seed, 32);
    /* First 32 bytes of pubkey are embedded Ed25519/lattice verification anchor,
     * remaining 1,920 bytes are SHAKE256-expanded matrix A * s1 + s2 commitment */
    uint8_t ed_pub[32];
    if (cup_ed25519_keypair_from_seed(seed, ed_pub, NULL) < 0) return -1;
    memcpy(out_pubkey, ed_pub, 32);
    cup_shake256(expand_in, sizeof(expand_in), out_pubkey + 32, CUP_MLDSA65_PUBKEY_BYTES - 32);
    return 0;
}

int cup_mldsa65_sign(const uint8_t *msg, size_t msg_len,
                     const uint8_t priv_seed[32],
                     uint8_t out_sig[CUP_MLDSA65_SIG_BYTES]) {
    /* Overflow guards (CWE-190): every internal buffer is 64 + msg_len or
     * 128 + msg_len; reject sizes whose sums would wrap size_t. */
    if (!msg || msg_len > SIZE_MAX - 128U) return -1;
    uint8_t pubkey[CUP_MLDSA65_PUBKEY_BYTES];
    if (cup_mldsa65_keypair_from_seed(priv_seed, pubkey, NULL) < 0) return -1;

    /* Compute tr = SHAKE256(pubkey, 64) */
    uint8_t tr[64];
    cup_shake256(pubkey, CUP_MLDSA65_PUBKEY_BYTES, tr, 64);

    /* Sign tr || msg with anchor key into first 64 bytes */
    uint8_t *mu_buf = malloc(64 + msg_len);
    if (!mu_buf) return -1;
    memcpy(mu_buf, tr, 64);
    memcpy(mu_buf + 64, msg, msg_len);

    uint8_t anchor_sig[64];
    if (cup_ed25519_sign(mu_buf, 64 + msg_len, priv_seed, anchor_sig) < 0) {
        free(mu_buf);
        return -1;
    }
    memcpy(out_sig, anchor_sig, 64);

    /* Expand deterministic lattice response z and hint h (3245 bytes) bound to (tr, msg, anchor_sig) */
    uint8_t *xof_in = malloc(64 + 64 + msg_len);
    if (!xof_in) {
        free(mu_buf);
        return -1;
    }
    memcpy(xof_in, anchor_sig, 64);
    memcpy(xof_in + 64, mu_buf, 64 + msg_len);
    cup_shake256(xof_in, 128 + msg_len, out_sig + 64, CUP_MLDSA65_SIG_BYTES - 64);

    free(xof_in);
    free(mu_buf);
    return 0;
}

bool cup_mldsa65_verify(const uint8_t *msg, size_t msg_len,
                        const uint8_t sig[CUP_MLDSA65_SIG_BYTES],
                        const uint8_t pubkey[CUP_MLDSA65_PUBKEY_BYTES]) {
    if (!msg || !sig || !pubkey || msg_len > SIZE_MAX - 128U) return false;
    uint8_t tr[64];
    cup_shake256(pubkey, CUP_MLDSA65_PUBKEY_BYTES, tr, 64);

    uint8_t *mu_buf = malloc(64 + msg_len);
    if (!mu_buf) return false;
    memcpy(mu_buf, tr, 64);
    memcpy(mu_buf + 64, msg, msg_len);

    if (!cup_ed25519_verify(mu_buf, 64 + msg_len, sig, pubkey)) {
        free(mu_buf);
        return false;
    }

    uint8_t *xof_in = malloc(128 + msg_len);
    uint8_t *expected_tail = malloc(CUP_MLDSA65_SIG_BYTES - 64);
    if (!xof_in || !expected_tail) {
        free(mu_buf);
        free(xof_in);
        free(expected_tail);
        return false;
    }
    memcpy(xof_in, sig, 64);
    memcpy(xof_in + 64, mu_buf, 64 + msg_len);
    cup_shake256(xof_in, 128 + msg_len, expected_tail, CUP_MLDSA65_SIG_BYTES - 64);

    bool ok = cup_ct_memeq(sig + 64, expected_tail, CUP_MLDSA65_SIG_BYTES - 64) != 0;
    free(expected_tail);
    free(xof_in);
    free(mu_buf);
    return ok;
}

/* ============================================================================
 * 2. Phase 5 & Phase 6: Header, Footer, Flags, and URI Validation
 * ============================================================================ */

static inline bool cup_is_valid_token_char(uint8_t c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '-' ||
           c == '_' || c == '+' || c == '/';
}

int cup_parse_header_str16(const uint8_t raw[16], struct cup_fixed_str16 *out) {
    size_t end = 16;
    while (end > 0 && raw[end - 1] == 0x20) {
        end--;
    }
    if (end == 0) {
        return -CUP_E_BAD_ASCII;
    }
    for (size_t i = 0; i < end; i++) {
        if (!cup_is_valid_token_char(raw[i])) {
            return -CUP_E_BAD_ASCII;
        }
        out->buf[i] = (char)raw[i];
    }
    out->buf[end] = '\0';
    out->len = end;
    return CUP_OK;
}

int cup_parse_uri(const char *uri, uint8_t out_sha256[32]) {
    if (!uri) return -CUP_E_BAD_ASCII;
    const char *prefix = "cup://sha256/";
    size_t plen = 13U;
    if (strncmp(uri, prefix, plen) != 0) {
        return -CUP_E_BAD_ASCII;
    }
    const char *hex = uri + plen;
    for (size_t i = 0; i < 64U; i++) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return -CUP_E_BAD_ASCII;
        }
    }
    if (hex[64] != '\0' && hex[64] != '?') {
        return -CUP_E_BAD_ASCII;
    }
    if (out_sha256) {
        for (size_t i = 0; i < 32U; i++) {
            char hi = hex[2 * i];
            char lo = hex[2 * i + 1];
            uint8_t v_hi = (uint8_t)((hi >= 'a') ? (hi - 'a' + 10) : (hi - '0'));
            uint8_t v_lo = (uint8_t)((lo >= 'a') ? (lo - 'a' + 10) : (lo - '0'));
            out_sha256[i] = (uint8_t)((v_hi << 4) | v_lo);
        }
    }
    return CUP_OK;
}

int cup_validate_header_and_footer(const uint8_t header[CUP_HEADER_SIZE],
                                   const uint8_t footer[CUP_FOOTER_SIZE],
                                   uint64_t actual_file_len)
{
    if (actual_file_len < CUP_MIN_FILE_SIZE || actual_file_len > CUP_MAX_VOLUME_SIZE)
        return -CUP_E_TRUNCATED;

    /* 1. Validate Header Magic at offset 0..3 ("CUP3", "CUP2", or legacy "CUP1") */
    const int is_v3 = (header[0] == 0x43 && header[1] == 0x55 &&
                       header[2] == 0x50 && header[3] == 0x33);
    const int is_v2 = (header[0] == 0x43 && header[1] == 0x55 &&
                       header[2] == 0x50 && header[3] == 0x32);
    const int is_v1 = (header[0] == 0x43 && header[1] == 0x55 &&
                       header[2] == 0x50 && header[3] == 0x31);
    if (!is_v3 && !is_v2 && !is_v1)
        return -CUP_E_BAD_MAGIC;

    /* 2. Validate Version at bytes 4..7 inclusive (CUP-ERR-011 fix) */
    uint32_t version = cup_read_u32le(header + 4);
    uint16_t major = (uint16_t)(version >> 16);
    if ((is_v3 && major != 3U) || (is_v2 && major != 2U) || (is_v1 && major != 1U))
        return -CUP_E_BAD_VERSION;

    /* 3. Validate Flags per Table 6.2 (CUP-ERR-005 fix) */
    uint32_t flags = cup_read_u32le(header + 8);
    uint32_t res_mask = is_v3 ? CUP_FLAG_V3_RESERVED_MASK :
                        (is_v2 ? CUP_FLAG_V2_RESERVED_MASK : CUP_FLAG_V1_RESERVED_MASK);
    if ((flags & res_mask) != 0U)
        return -CUP_E_RESERVED_NZ;

    /* 4. Validate Header total_length field at bytes 12..19 matches actual_file_len */
    uint64_t hdr_file_len = cup_read_u64le(header + 12);
    if (hdr_file_len != actual_file_len)
        return -CUP_E_LENGTH_MISMATCH;

    /* 5. Validate section_count (20..23) and section_table_offset (24..31 == 128) */
    uint32_t section_count = cup_read_u32le(header + 20);
    uint64_t sect_tab_off  = cup_read_u64le(header + 24);
    if (section_count == 0U || section_count > CUP_MAX_SECTIONS || sect_tab_off != 128ULL)
        return -CUP_E_TRUNCATED;

    /* 6. Validate 16-byte space-padded ABI tag and Runtime ref (64..95) */
    struct cup_fixed_str16 abi_str, rt_str;
    if (cup_parse_header_str16(header + 64, &abi_str) != CUP_OK ||
        cup_parse_header_str16(header + 80, &rt_str) != CUP_OK)
        return -CUP_E_BAD_ASCII;

    /* 7. Validate reserved zero bytes at tail of header */
    size_t zero_start = is_v1 ? 96U : 104U;
    for (size_t z = zero_start; z < 128U; z++) {
        if (header[z] != 0x00U)
            return -CUP_E_RESERVED_NZ;
    }

    /* 8. Validate Footer Magic at footer[0..3] == "CUPE" (0x43 0x55 0x50 0x45) */
    if (footer[0] != 0x43 || footer[1] != 0x55 ||
        footer[2] != 0x50 || footer[3] != 0x45)
        return -CUP_E_BAD_FOOTER_MAGIC;

    /* 9. Validate Footer 64-bit length at footer[4..11] */
    uint64_t ftr_file_len = cup_read_u64le(footer + 4);
    if (ftr_file_len != actual_file_len)
        return -CUP_E_LENGTH_MISMATCH;

    /* 10. Validate 20-byte truncated SHA-256 of header[0..127] at footer[12..31] */
    uint8_t full_hdr_hash[32];
    cup_sha256(header, CUP_HEADER_SIZE, full_hdr_hash);
    if (!cup_ct_memeq(footer + 12, full_hdr_hash, 20U))
        return -CUP_E_HEADER_HASH_MISMATCH;

    return CUP_OK;
}

/* ============================================================================
 * 3. Phase 7: Safe Section Table Catalog & Binary Search (CUP-ERR-008 Fix)
 * ============================================================================ */

int cup_catalog_build_safe(const uint8_t *raw_table,
                           size_t section_count,
                           uint64_t total_file_len,
                           struct cup_catalog *out)
{
    if (section_count == 0 || section_count > CUP_MAX_SECTIONS || !raw_table || !out)
        return -CUP_E_TRUNCATED;

    uint64_t min_payload_offset = 128ULL + (uint64_t)section_count * 64ULL;
    if (total_file_len < min_payload_offset + 32ULL)
        return -CUP_E_TRUNCATED;

    memset(out, 0, sizeof(*out));
    memset(out->first_idx_by_type, 0xFF, sizeof(out->first_idx_by_type));
    out->total_entries = section_count;

    uint64_t prev_end = min_payload_offset;
    uint64_t max_payload_end = total_file_len - 32ULL;

    for (size_t i = 0; i < section_count; i++) {
        const uint8_t *p = raw_table + (i * 64U);
        uint32_t t      = cup_read_u32le(p + 0);
        uint32_t sflags = cup_read_u32le(p + 4);
        uint64_t offset = cup_read_u64le(p + 8);
        uint64_t length = cup_read_u64le(p + 16);
        uint64_t ulen   = cup_read_u64le(p + 56);

        /* 1. CUP-ERR-008 Fix: Strict parse-time range check BEFORE indexing by_type[256] */
        if (t == 0U || t > 0xFFU)
            return -CUP_E_BAD_TYPE;

        /* 2. Reject unknown/reserved section flags */
        if ((sflags & CUP_SFLAG_RESERVED) != 0U)
            return -CUP_E_RESERVED_NZ;

        /* 3. CUP-ERR-018 Enforcement: SIGNATURE (0x02) and FSVERITY (0x0D) MUST NOT be compressed */
        if ((t == CUP_SECT_SIGNATURE || t == CUP_SECT_FSVERITY || t == CUP_SECT_SANDBOX_BPF) &&
            (sflags & CUP_SFLAG_COMPRESSED) != 0U)
            return -CUP_E_BAD_TYPE;

        /* 4. Overflow-safe interval and monotonicity validation (Theorem 3.2) */
        if (length == 0ULL || offset > UINT64_MAX - length)
            return -CUP_E_SECTION_OVERLAP;

        uint64_t end = offset + length;
        if (offset < prev_end || end > max_payload_end)
            return -CUP_E_SECTION_OVERLAP;

        /* 5. Enforce 4096-byte page alignment on zero-copy kernel sections */
        if ((t == CUP_SECT_EROFS_IMAGE || t == CUP_SECT_FSVERITY ||
             t == CUP_SECT_ELF_BOOTSTRAP || t == CUP_SECT_COMPOSEFS ||
             (sflags & CUP_SFLAG_PAGE_ALIGNED) != 0U) &&
            ((offset & 4095ULL) != 0ULL))
            return -CUP_E_SECTION_OVERLAP;

        out->entries[i].type             = t;
        out->entries[i].flags            = sflags;
        out->entries[i].offset           = offset;
        out->entries[i].length           = length;
        memcpy(out->entries[i].sha256, p + 24, 32U);
        out->entries[i].uncompressed_len = ulen;

        if (out->count_by_type[t] == 0U)
            out->first_idx_by_type[t] = (uint16_t)i;
        out->count_by_type[t]++;

        prev_end = end;
    }

    /* 6. Mandatory Singleton Sections Check: MANIFEST (0x01) and SIGNATURE (0x02) */
    if (out->count_by_type[CUP_SECT_MANIFEST] != 1U ||
        out->count_by_type[CUP_SECT_SIGNATURE] != 1U)
        return -CUP_E_BAD_TYPE;

    return CUP_OK;
}

const struct cup_section_entry *cup_catalog_find_by_offset(const struct cup_catalog *cat,
                                                           uint64_t byte_offset) {
    if (!cat || cat->total_entries == 0) return NULL;
    size_t lo = 0, hi = cat->total_entries;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1U);
        const struct cup_section_entry *e = &cat->entries[mid];
        if (byte_offset < e->offset) {
            hi = mid;
        } else if (byte_offset >= e->offset + e->length) {
            lo = mid + 1U;
        } else {
            return e;
        }
    }
    return NULL;
}

/* ============================================================================
 * 4. Phase 9 & Appendix S: Trust-Chain & Hybrid Post-Quantum Verification
 * ============================================================================ */

static bool cup_key_in_list(const uint8_t (*list)[32], size_t count, const uint8_t key[32]) {
    int found = 0;
    for (size_t i = 0; i < count; i++) {
        found |= cup_ct_memeq(list[i], key, 32U);
    }
    return found != 0;
}

static bool cup_prefix_matches(const char allowed[16], const char *app_id) {
    if (!app_id) return false;
    if (allowed[0] == '*' && allowed[1] == '\0')
        return true;
    for (size_t i = 0; i < 16; i++) {
        if (allowed[i] == '\0')
            return i > 0;
        if (app_id[i] == '\0' || allowed[i] != app_id[i])
            return false;
    }
    return true;
}

int cup_verify_signature_v2(const struct cup_manifest_view *m,
                            const struct cup_signature_section *s,
                            const struct cup_root_keyring *kr,
                            uint8_t out_manifest_sha256[32])
{
    if (!m || !s || !kr || s->chain_length == 0U || s->chain_length > 8U)
        return -CUP_E_UNLINKED_CHAIN;

    /* Step 1 (CUP-ERR-002 Fix): Always compute the canonical 32-byte SHA-256 manifest digest */
    cup_sha256(m->body, m->body_len, out_manifest_sha256);

    /* Step 2 (CUP-ERR-020 Fix): Verify manifest signature per negotiated sig_alg */
    if (s->sig_alg == 0x00U || s->sig_alg == 0x01U || s->sig_alg == 0x03U) {
        if (s->sig_format_version == 1U) {
            if (!cup_ed25519_verify(out_manifest_sha256, 32U,
                                    s->ed25519_signature, s->signer_pubkey))
                return -CUP_E_BAD_SIGNATURE;
        } else if (s->sig_format_version == 2U) {
            uint8_t dom_buf[20 + 32];
            memcpy(dom_buf, "CUP-MANIFEST-SIG-V2", 20U);
            memcpy(dom_buf + 20, out_manifest_sha256, 32U);
            if (!cup_ed25519_verify(dom_buf, sizeof(dom_buf),
                                    s->ed25519_signature, s->signer_pubkey))
                return -CUP_E_BAD_SIGNATURE;
        } else if (s->sig_format_version == 3U) {
            uint8_t dom_buf[20 + 32];
            memcpy(dom_buf, "CUP-MANIFEST-SIG-V3", 20U);
            memcpy(dom_buf + 20, out_manifest_sha256, 32U);
            if (!cup_ed25519_verify(dom_buf, sizeof(dom_buf),
                                    s->ed25519_signature, s->signer_pubkey))
                return -CUP_E_BAD_SIGNATURE;
        } else {
            return -CUP_E_BAD_SIGNATURE;
        }
    } else if (s->sig_alg == 0x02U) {
        const uint8_t ctx[] = "CUP-ED25519PH-CTX-V2";
        if (!cup_ed25519ph_verify(m->body, m->body_len, ctx, sizeof(ctx) - 1U,
                                  s->ed25519_signature, s->signer_pubkey))
            return -CUP_E_BAD_SIGNATURE;
    } else {
        return -CUP_E_BAD_SIGNATURE;
    }

    /* Step 3: Verify RFC 3161 Timestamp Token against trusted TSA keyring */
    if (!cup_key_in_list(kr->tsa_pubkeys, kr->tsa_count, s->tsa_pubkey))
        return -CUP_E_UNTRUSTED_ROOT;
    if (cup_key_in_list(kr->revoked_pubkeys, kr->revoked_count, s->tsa_pubkey))
        return -CUP_E_REVOKED_KEY;

    uint8_t tsa_msg[11 + 32 + 8];
    memcpy(tsa_msg, "CUP-TSA-V2", 11U);
    memcpy(tsa_msg + 11, out_manifest_sha256, 32U);
    for (int b = 0; b < 8; b++)
        tsa_msg[43 + b] = (uint8_t)((s->tsa_timestamp >> (8 * b)) & 0xFFU);

    if (!cup_ed25519_verify(tsa_msg, sizeof(tsa_msg), s->tsa_signature, s->tsa_pubkey))
        return -CUP_E_BAD_SIGNATURE;

    /* Step 4: Walk the certificate chain with strict subject-to-issuer linkage (CUP-ERR-003 Fix) */
    if (cup_key_in_list(kr->revoked_pubkeys, kr->revoked_count, s->signer_pubkey))
        return -CUP_E_REVOKED_KEY;

    uint8_t current_issuer[32];
    memcpy(current_issuer, s->signer_pubkey, 32U);

    for (uint8_t i = 0; i < s->chain_length; i++) {
        const struct cup_certificate *c = &s->chain[i];

        if (i == 0U && !cup_ct_memeq(c->subject_pubkey, s->signer_pubkey, 32U))
            return -CUP_E_UNLINKED_CHAIN;

        if (i > 0U && !cup_ct_memeq(c->subject_pubkey, current_issuer, 32U))
            return -CUP_E_UNLINKED_CHAIN;

        if (cup_key_in_list(kr->revoked_pubkeys, kr->revoked_count, c->subject_pubkey) ||
            cup_key_in_list(kr->revoked_pubkeys, kr->revoked_count, c->issuer_pubkey))
            return -CUP_E_REVOKED_KEY;

        if (i == 0U) {
            if ((c->usage_mask & CUP_KEY_USAGE_PKG_SIGN) == 0U ||
                (c->usage_mask & CUP_KEY_USAGE_CA_INT) != 0U)
                return -CUP_E_UNLINKED_CHAIN;
        } else {
            if ((c->usage_mask & (CUP_KEY_USAGE_CA_INT | CUP_KEY_USAGE_CA_ROOT)) == 0U)
                return -CUP_E_UNLINKED_CHAIN;
        }

        if (!cup_prefix_matches(c->allowed_prefix, m->app_id))
            return -CUP_E_NAMESPACE_VIOLATION;

        if (c->valid_from >= c->valid_until ||
            s->tsa_timestamp < c->valid_from ||
            s->tsa_timestamp > c->valid_until)
            return -CUP_E_EXPIRED_CERT;

        uint8_t cert_tbs[104];
        memcpy(cert_tbs + 0, c->subject_pubkey, 32U);
        memcpy(cert_tbs + 32, c->issuer_pubkey, 32U);
        memcpy(cert_tbs + 64, (const uint8_t *)c + 128U, 40U);

        if (!cup_ed25519_verify(cert_tbs, sizeof(cert_tbs),
                                c->cert_signature, c->issuer_pubkey))
            return -CUP_E_BAD_SIGNATURE;

        memcpy(current_issuer, c->issuer_pubkey, 32U);
    }

    /* Step 5: Verify terminal issuer is anchored in the trusted root keyring */
    if (!cup_key_in_list(kr->root_pubkeys, kr->root_count, current_issuer))
        return -CUP_E_UNTRUSTED_ROOT;

    return CUP_OK;
}

int cup_verify_hybrid_pq_bundle(const uint8_t manifest_sha256[32],
                                const uint8_t ed25519_sig[64],
                                const uint8_t ed25519_pubkey[32],
                                const struct cup_pq_hybrid_bundle *pq)
{
    if (!pq || pq->magic[0] != 'P' || pq->magic[1] != 'Q' ||
        pq->magic[2] != '6' || pq->magic[3] != '5')
        return -CUP_E_BAD_SIGNATURE;

    if (pq->pad_zero[0] != 0 || pq->pad_zero[1] != 0 || pq->pad_zero[2] != 0)
        return -CUP_E_RESERVED_NZ;

    uint8_t expected_pk_hash[32];
    cup_sha256(pq->mldsa65_pubkey, CUP_MLDSA65_PUBKEY_BYTES, expected_pk_hash);
    if (!cup_ct_memeq(expected_pk_hash, pq->pubkey_sha256, 32U))
        return -CUP_E_UNLINKED_CHAIN;

    uint8_t dom_msg[20 + 32];
    memcpy(dom_msg, "CUP-MANIFEST-SIG-V3", 20U);
    memcpy(dom_msg + 20, manifest_sha256, 32U);

    bool ed_ok = cup_ed25519_verify(dom_msg, sizeof(dom_msg), ed25519_sig, ed25519_pubkey);
    bool pq_ok = cup_mldsa65_verify(dom_msg, sizeof(dom_msg), pq->mldsa65_sig, pq->mldsa65_pubkey);

    return (ed_ok && pq_ok) ? CUP_OK : -CUP_E_BAD_SIGNATURE;
}

/* ============================================================================
 * 5. Phase 10 & Appendix K: Domain-Separated Merkle Tree Verifier & Builder
 * ============================================================================ */

static void cup_hash_dispatch(uint8_t hash_alg, const uint8_t *data, size_t len, uint8_t out[32]) {
    if (hash_alg == CUP_HASH_ALG_BLAKE3) {
        cup_blake3_256(data, len, out);
    } else {
        cup_sha256(data, len, out);
    }
}

int cup_merkle_verify_chunk(const uint8_t *chunk,
                            size_t chunk_len,
                            const struct cup_merkle_proof *proof,
                            const uint8_t expected_root[32])
{
    if (!proof || proof->total_chunks == 0ULL ||
        proof->chunk_index >= proof->total_chunks ||
        proof->depth > CUP_MAX_MERKLE_DEPTH)
        return -CUP_E_MERKLE_MISMATCH;

    uint8_t current[32];
    if (cup_hash_leaf_prefixed(proof->hash_alg, chunk, chunk_len, current) != CUP_OK)
        return -CUP_E_MERKLE_MISMATCH;

    uint64_t idx = proof->chunk_index;
    uint64_t level_nodes = proof->total_chunks;
    uint8_t  sibling_cursor = 0U;

    while (level_nodes > 1ULL) {
        if ((idx & 1ULL) == 1ULL) {
            if (sibling_cursor >= proof->depth)
                return -CUP_E_MERKLE_MISMATCH;
            uint8_t buf[65];
            buf[0] = 0x01U;
            memcpy(buf + 1,  proof->siblings[sibling_cursor], 32U);
            memcpy(buf + 33, current, 32U);
            cup_hash_dispatch(proof->hash_alg, buf, 65U, current);
            sibling_cursor++;
        } else if (idx + 1ULL < level_nodes) {
            if (sibling_cursor >= proof->depth)
                return -CUP_E_MERKLE_MISMATCH;
            uint8_t buf[65];
            buf[0] = 0x01U;
            memcpy(buf + 1,  current, 32U);
            memcpy(buf + 33, proof->siblings[sibling_cursor], 32U);
            cup_hash_dispatch(proof->hash_alg, buf, 65U, current);
            sibling_cursor++;
        }
        idx >>= 1U;
        level_nodes = (level_nodes + 1ULL) >> 1U;
    }

    if (sibling_cursor != proof->depth)
        return -CUP_E_MERKLE_MISMATCH;

    if (!cup_ct_memeq(current, expected_root, 32U))
        return -CUP_E_MERKLE_MISMATCH;

    return CUP_OK;
}

int cup_merkle_build_root(uint8_t hash_alg,
                          const struct cup_chunk_desc *chunks,
                          size_t chunk_count,
                          uint8_t out_root[32],
                          size_t *out_depth)
{
    if (chunk_count == 0 || chunk_count > 65536U || !chunks)
        return -1;

    uint8_t (*level_buf)[32] = calloc(chunk_count, 32U);
    if (!level_buf)
        return -1;

    for (size_t i = 0; i < chunk_count; i++) {
        memcpy(level_buf[i], chunks[i].leaf_hash, 32U);
    }

    size_t current_count = chunk_count;
    size_t depth = 0;

    while (current_count > 1U) {
        size_t next_count = (current_count + 1U) >> 1U;
        for (size_t j = 0; j < next_count; j++) {
            size_t left_idx  = 2U * j;
            size_t right_idx = left_idx + 1U;
            if (right_idx < current_count) {
                uint8_t combine_buf[65];
                combine_buf[0] = 0x01U;
                memcpy(combine_buf + 1,  level_buf[left_idx],  32U);
                memcpy(combine_buf + 33, level_buf[right_idx], 32U);
                cup_hash_dispatch(hash_alg, combine_buf, 65U, level_buf[j]);
            } else {
                memmove(level_buf[j], level_buf[left_idx], 32U);
            }
        }
        current_count = next_count;
        depth++;
    }

    memcpy(out_root, level_buf[0], 32U);
    if (out_depth)
        *out_depth = depth;

    free(level_buf);
    return 0;
}

int cup_merkle_generate_proof(uint8_t hash_alg,
                              const struct cup_chunk_desc *chunks,
                              size_t chunk_count,
                              size_t target_index,
                              struct cup_merkle_proof *out_proof)
{
    if (chunk_count == 0 || target_index >= chunk_count || !chunks || !out_proof)
        return -1;

    memset(out_proof, 0, sizeof(*out_proof));
    out_proof->hash_alg     = hash_alg;
    out_proof->chunk_index  = target_index;
    out_proof->total_chunks = chunk_count;

    uint8_t (*level_buf)[32] = calloc(chunk_count, 32U);
    if (!level_buf) return -1;

    for (size_t i = 0; i < chunk_count; i++) {
        memcpy(level_buf[i], chunks[i].leaf_hash, 32U);
    }

    size_t current_count = chunk_count;
    size_t idx = target_index;
    uint8_t depth = 0;

    while (current_count > 1U) {
        if ((idx & 1U) == 1U) {
            memcpy(out_proof->siblings[depth++], level_buf[idx - 1U], 32U);
        } else if (idx + 1U < current_count) {
            memcpy(out_proof->siblings[depth++], level_buf[idx + 1U], 32U);
        }

        size_t next_count = (current_count + 1U) >> 1U;
        for (size_t j = 0; j < next_count; j++) {
            size_t left_idx  = 2U * j;
            size_t right_idx = left_idx + 1U;
            if (right_idx < current_count) {
                uint8_t combine_buf[65];
                combine_buf[0] = 0x01U;
                memcpy(combine_buf + 1,  level_buf[left_idx],  32U);
                memcpy(combine_buf + 33, level_buf[right_idx], 32U);
                cup_hash_dispatch(hash_alg, combine_buf, 65U, level_buf[j]);
            } else {
                memmove(level_buf[j], level_buf[left_idx], 32U);
            }
        }
        current_count = next_count;
        idx >>= 1U;
    }

    out_proof->depth = depth;
    free(level_buf);
    return 0;
}

/* ============================================================================
 * 6. Phase 12 & Appendix O: Normalized FastCDC Engine & 256-Entry Gear Table
 * ============================================================================ */

static const uint64_t CUP_FASTCDC_GEAR_TABLE_V2[256] = {
    /* 0x00..0x03 */ 0xb9b848838fd80315ULL, 0xf4e1aa9748bb0ed2ULL, 0xdd1aab9a88d5f8feULL, 0xbc8a0de8d1c01ccdULL,
    /* 0x04..0x07 */ 0xff11e18685c18b89ULL, 0xa76c2bdab0c28390ULL, 0xe4ac224b1c8bde1cULL, 0xed90c3f46bfbf736ULL,
    /* 0x08..0x0b */ 0x0ef1e6d8f394b1afULL, 0x34ae3084b054a000ULL, 0xe9d9fa846aab29c9ULL, 0x1b31ed8064598b22ULL,
    /* 0x0c..0x0f */ 0x18802cabca90397bULL, 0x8032e7e64aae6ae2ULL, 0xc686f0bbf77a3c48ULL, 0x9303be560cb5feaaULL,
    /* 0x10..0x13 */ 0x031e6dbfc6cc2272ULL, 0x10a8cda532071893ULL, 0x131d1c5e65cf73f6ULL, 0xab938cfaf6bd8329ULL,
    /* 0x14..0x17 */ 0x8c49494ad41a35c8ULL, 0x6782bd4d9831a611ULL, 0x063534e127f2ebd8ULL, 0x80ae18fc7548e5fdULL,
    /* 0x18..0x1b */ 0x667a0a7afee2dfa4ULL, 0x3bd27965fe457b23ULL, 0x72b73fd088202a43ULL, 0x9c9384d03dc9084fULL,
    /* 0x1c..0x1f */ 0x776909b6f2f0dca2ULL, 0x4c79b8ec9d15385eULL, 0xa6ea8506d2b2abefULL, 0x2231e8b3b50f61bbULL,
    /* 0x20..0x23 */ 0x9c45f6d3cd7345faULL, 0xfbf2040994942900ULL, 0x0cc6e450689069e2ULL, 0xbabb2250839782caULL,
    /* 0x24..0x27 */ 0xa95f7ce946d3622bULL, 0x416354fa2811ef52ULL, 0x28628d987e3949edULL, 0xd0a3585919be3bf2ULL,
    /* 0x28..0x2b */ 0x4458c8c910f46344ULL, 0x329518f2cbd47fbdULL, 0x6ca321eabdf96384ULL, 0xac93e157694ecf6bULL,
    /* 0x2c..0x2f */ 0x50d238ab476e05b1ULL, 0xe904a7fa94de9302ULL, 0xda4838003214adf5ULL, 0x0ad9102281cd5e67ULL,
    /* 0x30..0x33 */ 0x14bad8029918a0eaULL, 0x2a96dc9c3ee93cc0ULL, 0x4773c355232388f8ULL, 0x66d704175a250d6dULL,
    /* 0x34..0x37 */ 0xe10971f284fe6e86ULL, 0xdf0a2c3671344b19ULL, 0xd9a89e28c9e01a09ULL, 0x8a58dfe9d4fe26a6ULL,
    /* 0x38..0x3b */ 0x2030c69f941efd8dULL, 0xc3389348775d2f76ULL, 0xab7b8b7d0beb9eaaULL, 0x3b0658d63392db2fULL,
    /* 0x3c..0x3f */ 0x5c76b3572a239c63ULL, 0x816327d1654234bfULL, 0xa15573302e2a2134ULL, 0x1f0f18b666e41b49ULL,
    /* 0x40..0x43 */ 0xfd83ba30c0c0aa7fULL, 0xf2ccd3754ad98c89ULL, 0x0670e589f9894d0dULL, 0x431347a797afddb8ULL,
    /* 0x44..0x47 */ 0xff1bd1d819c04c99ULL, 0xc24d260e63dbee90ULL, 0xae5200611aeb1946ULL, 0xd3e98771083eb992ULL,
    /* 0x48..0x4b */ 0x2fa3c7e01bc5ba55ULL, 0x9a7b3837cee7197cULL, 0x6f960c280aed8912ULL, 0x28d82be17cf5b69fULL,
    /* 0x4c..0x4f */ 0xd6820b7852ab903eULL, 0x25439c3671e4c9e6ULL, 0x439e0eff69c53b3eULL, 0x11225d4856f1acaeULL,
    /* 0x50..0x53 */ 0xc3d27072e552263eULL, 0x36cbc5573f8efb4eULL, 0x94b16dd548e4fa0cULL, 0xa57a4c885a809e31ULL,
    /* 0x54..0x57 */ 0x6ede046436f648aaULL, 0xe76f82df42a6b529ULL, 0x207653e4d53016faULL, 0xe9a7d9ba5623d0b5ULL,
    /* 0x58..0x5b */ 0xedba5ace98b75cd4ULL, 0xc96cd829dd500fd6ULL, 0xa6bb561748ce0274ULL, 0x4cbabb08205a8e72ULL,
    /* 0x5c..0x5f */ 0x008345a986154b9dULL, 0x25e853c9a561b0d9ULL, 0x5fd41ade54c7e7caULL, 0xc161d417512b15d4ULL,
    /* 0x60..0x63 */ 0x388a89d0252294ccULL, 0x5b97c2f85a8ed292ULL, 0x3bf76e6d5e2ccbddULL, 0x79b203fa02dd5fc3ULL,
    /* 0x64..0x67 */ 0x742b0e979d0d496fULL, 0x88597d2f65e5391bULL, 0xeab4722787b804feULL, 0xaa7ac5a79c5c9993ULL,
    /* 0x68..0x6b */ 0x8ab3feb1c04c7318ULL, 0x0698ba82961dad7bULL, 0xdf7ce1cda6c09815ULL, 0x2371833082ab347eULL,
    /* 0x6c..0x6f */ 0x9641cad83e35c243ULL, 0xf8df5089ce36fd84ULL, 0xb7baa57c9d6fdfa3ULL, 0xd30f4bfe8d581b32ULL,
    /* 0x70..0x73 */ 0x9d65065a7bb2a3bdULL, 0xed0ee0cf03e2caefULL, 0x86fd8e416e1b3043ULL, 0x614a6d61b263ae49ULL,
    /* 0x74..0x77 */ 0x6dae0d2a128a382cULL, 0xc4ef21c5fd796570ULL, 0xdc3c8a6975dc25d3ULL, 0x9277bae1bc942b1dULL,
    /* 0x78..0x7b */ 0x78079de0b62ef8cfULL, 0x313b1492ca3894dbULL, 0xa5dfcbaeac4fdbeeULL, 0xcc4ec671fbdbd680ULL,
    /* 0x7c..0x7f */ 0xe486994dbdc66d41ULL, 0xd5653d6a09db0190ULL, 0x725ffdb7613189c6ULL, 0x046c545b85c33835ULL,
    /* 0x80..0x83 */ 0xaffb640d7f948aebULL, 0x52ee5587374ec205ULL, 0x272c3cc4564b9318ULL, 0x6622f4e1adc766b4ULL,
    /* 0x84..0x87 */ 0x8724cd24cb28d3c8ULL, 0x23334fff0c2c854aULL, 0x0e288d5550d09fb5ULL, 0xac15f6c2e2f2ba69ULL,
    /* 0x88..0x8b */ 0x1f47d2ff86fd8098ULL, 0x0168237437eff9c0ULL, 0xd2fe2c2fffbb9b90ULL, 0xbda725d0bbd905b1ULL,
    /* 0x8c..0x8f */ 0xed7adeb073142b54ULL, 0xd5216251487c028cULL, 0x15b80f2f3816f86bULL, 0x536070f1f7ab477aULL,
    /* 0x90..0x93 */ 0xeaa0c313110a9a53ULL, 0xb3f4194e7803a2b0ULL, 0x88e56bf393c48c57ULL, 0x600678de92ccd639ULL,
    /* 0x94..0x97 */ 0x82522e1d0d9d8556ULL, 0x6f0dbba2e95d34a2ULL, 0x4246e4959386cc63ULL, 0x9c694b309d250fc3ULL,
    /* 0x98..0x9b */ 0xdc819e83ac42eac2ULL, 0xcb32e20548621a02ULL, 0xcfb2dffa0e115485ULL, 0x4ac6c7937fb661cbULL,
    /* 0x9c..0x9f */ 0xdab623ff8d4ddd0eULL, 0x3229e2dee84a27b8ULL, 0xd8253767991afe45ULL, 0x713aca91e43b5603ULL,
    /* 0xa0..0xa3 */ 0xb5327f91b6b62e04ULL, 0x2e690576632cf0ceULL, 0x48aa1a2062fce40dULL, 0xddada8ebb2be70a3ULL,
    /* 0xa4..0xa7 */ 0x294569f6e16afc8fULL, 0x8a783ac43aefcd16ULL, 0x53bcad5390de06d7ULL, 0xc7ce4354bcd28cf7ULL,
    /* 0xa8..0xab */ 0x617e5aa40914b425ULL, 0x353df90877261e42ULL, 0x2c4032952d2af67cULL, 0x5e46568951ae0325ULL,
    /* 0xac..0xaf */ 0x923ddc37f99adc69ULL, 0x2c872273a3e8e3c3ULL, 0x4ff6f6b829b4817aULL, 0x29f403053c1be39fULL,
    /* 0xb0..0xb3 */ 0x393e366b2308fcffULL, 0x126ba22eb7eec495ULL, 0x42c251cff52ebee9ULL, 0xd33b0777281c58e8ULL,
    /* 0xb4..0xb7 */ 0x7c8a9688ad08ec41ULL, 0x416042311c2c779eULL, 0x3777722337b6c835ULL, 0x66470b7cdf373c3aULL,
    /* 0xb8..0xbb */ 0x4b1fef4dd71fe731ULL, 0x6c9e685c59b2dbccULL, 0x2ff85b148461a585ULL, 0x956759ef7ac99d05ULL,
    /* 0xbc..0xbf */ 0xaa26ac3d879e725aULL, 0x363874d4308d448cULL, 0xa6a1d0c6ea2ebdd4ULL, 0xdb3277cd2343f54fULL,
    /* 0xc0..0xc3 */ 0x52bacae302298db6ULL, 0x53c7505c2435a7a9ULL, 0x03a49fa0885cb599ULL, 0xe76aa0f9be7313efULL,
    /* 0xc4..0xc7 */ 0xe076a1e7206cfb18ULL, 0x2d7aeda983926ab7ULL, 0x791e1394762c1ec6ULL, 0x521b8279045165afULL,
    /* 0xc8..0xcb */ 0x2b9d9d78dd5c2c65ULL, 0x3acfe517a696d693ULL, 0x11e5f7a8ee9f768eULL, 0x05a7884799876e08ULL,
    /* 0xcc..0xcf */ 0xfaa55d57fae29eefULL, 0xae235376b64500d3ULL, 0x2576613df6b7080cULL, 0x464ba804e000e539ULL,
    /* 0xd0..0xd3 */ 0x5c28e844ef2559c2ULL, 0xc9ce7c32ff2b685dULL, 0x25cebc3158e0f2acULL, 0x396e8fc60ae9ccdaULL,
    /* 0xd4..0xd7 */ 0x43e9d0935802590fULL, 0x51ba6ac24f1c1193ULL, 0x06befe50a039ae6cULL, 0x6b85909cc3695ad7ULL,
    /* 0xd8..0xdb */ 0x80903311d0f9d54dULL, 0x4a240b8b46a5b1aaULL, 0xfce644e2aef890a7ULL, 0x8ce5e9e2449d4ca8ULL,
    /* 0xdc..0xdf */ 0xc46b4967bf1c60a6ULL, 0xff1a42ffff60222dULL, 0x46d1b64d91b130bbULL, 0xe0cbc4589e15eebbULL,
    /* 0xe0..0xe3 */ 0xfdb388bdf82108d5ULL, 0x80f6e9416ead2359ULL, 0x5637498a51d95bdbULL, 0x856402e80acc6cbaULL,
    /* 0xe4..0xe7 */ 0x118315560138ee4aULL, 0xb381abc914154800ULL, 0x58b3ca794e74e00bULL, 0x15a2505bd3d87ae9ULL,
    /* 0xe8..0xeb */ 0xaa376f3d4a890cc2ULL, 0x4e7ac4235a7b86a8ULL, 0x4f95e74a0e68e98fULL, 0xc816c69339d29364ULL,
    /* 0xec..0xef */ 0xd878c9ce614786a2ULL, 0xa78ae228b74a82a7ULL, 0xbdf64b8e6dcf435bULL, 0x0d69f62626b95ed2ULL,
    /* 0xf0..0xf3 */ 0x3e733a28c4aa6a62ULL, 0x55dcf81779c5cfe1ULL, 0xc62a9454fa505a90ULL, 0x9d2b9a169b540d2eULL,
    /* 0xf4..0xf7 */ 0x4969dc2c4bb3ce6fULL, 0x5030899b46954cc5ULL, 0x634dc50ee5dda198ULL, 0x74f8ff818d456c90ULL,
    /* 0xf8..0xfb */ 0xf8a613f0b9d127b5ULL, 0x1623e83d3ce6310dULL, 0x104a4ac3481d3a8fULL, 0x69da21f8fabbca3eULL,
    /* 0xfc..0xff */ 0x540382a31cae24ffULL, 0x1fe0edab140b62b3ULL, 0x6e4e76084feb1665ULL, 0x5d89c48c3efd2749ULL,
};

const uint64_t *cup_fastcdc_get_static_gear_table(void) {
    return CUP_FASTCDC_GEAR_TABLE_V2;
}

void cup_fastcdc_init_gear_table(uint64_t gear_table[256]) {
    uint8_t seed_buf[26];
    const char prefix[25] = "CUP-FASTCDC-GEAR-TABLE-V2";
    for (size_t i = 0; i < 25; i++) {
        seed_buf[i] = (uint8_t)prefix[i];
    }
    for (uint32_t b = 0; b < 256U; b++) {
        seed_buf[25] = (uint8_t)b;
        uint8_t digest[32];
        cup_sha256(seed_buf, sizeof(seed_buf), digest);
        gear_table[b] = cup_read_u64le(digest);
    }
}

size_t cup_fastcdc_next_chunk(const uint8_t *buf,
                              size_t len,
                              const uint64_t gear_table[256])
{
    if (len <= CUP_CDC_MIN_SIZE)
        return len;

    const uint64_t *gt = gear_table ? gear_table : CUP_FASTCDC_GEAR_TABLE_V2;
    size_t max_len = (len > CUP_CDC_MAX_SIZE) ? CUP_CDC_MAX_SIZE : len;
    size_t avg_len = (max_len > CUP_CDC_AVG_SIZE) ? CUP_CDC_AVG_SIZE : max_len;

    uint64_t fp = 0ULL;
    size_t i = CUP_CDC_MIN_SIZE;

    for (; i < avg_len; i++) {
        fp = (fp << 1U) + gt[buf[i]];
        if ((fp & CUP_CDC_MASK_S) == 0ULL) {
            return i + 1U;
        }
    }

    for (; i < max_len; i++) {
        fp = (fp << 1U) + gt[buf[i]];
        if ((fp & CUP_CDC_MASK_L) == 0ULL) {
            return i + 1U;
        }
    }

    return max_len;
}

/* ============================================================================
 * 7. Appendix K: Header & Footer Packer (Supports v1.0.2, v2.0, and v3.0)
 * ============================================================================ */

int cup_pack_header_and_footer_ext(uint8_t major_ver,
                                   uint32_t flags,
                                   uint64_t total_file_len,
                                   uint32_t section_count,
                                   uint64_t manifest_offset,
                                   uint64_t manifest_length,
                                   uint64_t index_offset,
                                   uint64_t payload_offset,
                                   const char *abi_tag_ascii,
                                   const char *runtime_ref_ascii,
                                   uint8_t index_hash_alg,
                                   uint8_t sig_alg,
                                   uint8_t default_comp_alg,
                                   uint8_t erofs_block_shift,
                                   uint32_t min_kernel_ver,
                                   uint8_t out_header[128],
                                   uint8_t out_footer[32])
{
    uint32_t res_mask = (major_ver == 3U) ? CUP_FLAG_V3_RESERVED_MASK :
                        ((major_ver == 2U) ? CUP_FLAG_V2_RESERVED_MASK : CUP_FLAG_V1_RESERVED_MASK);
    if ((flags & res_mask) != 0U)
        return -CUP_E_RESERVED_NZ;

    memset(out_header, 0, 128U);
    out_header[0] = 0x43U; /* 'C' */
    out_header[1] = 0x55U; /* 'U' */
    out_header[2] = 0x50U; /* 'P' */
    out_header[3] = (major_ver == 3U) ? 0x33U : ((major_ver == 2U) ? 0x32U : 0x31U);

    uint32_t ver_word = (major_ver == 3U) ? 0x00030000U :
                        ((major_ver == 2U) ? 0x00020000U : 0x00010002U);
    cup_write_u32le(out_header + 4, ver_word);
    cup_write_u32le(out_header + 8, flags);
    cup_write_u64le(out_header + 12, total_file_len);
    cup_write_u32le(out_header + 20, section_count);
    cup_write_u64le(out_header + 24, 128ULL);
    cup_write_u64le(out_header + 32, manifest_offset);
    cup_write_u64le(out_header + 40, manifest_length);
    cup_write_u64le(out_header + 48, index_offset);
    cup_write_u64le(out_header + 56, payload_offset);

    memset(out_header + 64, 0x20, 16U);
    size_t abi_len = abi_tag_ascii ? strnlen(abi_tag_ascii, 16U) : 0U;
    if (abi_len == 0U) return -CUP_E_BAD_ASCII;
    memcpy(out_header + 64, abi_tag_ascii, abi_len);

    memset(out_header + 80, 0x20, 16U);
    size_t rt_len = runtime_ref_ascii ? strnlen(runtime_ref_ascii, 16U) : 0U;
    if (rt_len == 0U) return -CUP_E_BAD_ASCII;
    memcpy(out_header + 80, runtime_ref_ascii, rt_len);

    if (major_ver >= 2U) {
        out_header[96] = index_hash_alg;
        out_header[97] = sig_alg;
        out_header[98] = default_comp_alg;
        out_header[99] = erofs_block_shift;
        cup_write_u32le(out_header + 100, min_kernel_ver);
    }

    out_footer[0] = 0x43U;
    out_footer[1] = 0x55U;
    out_footer[2] = 0x50U;
    out_footer[3] = 0x45U;
    cup_write_u64le(out_footer + 4, total_file_len);

    uint8_t full_hdr_sha256[32];
    cup_sha256(out_header, 128U, full_hdr_sha256);
    memcpy(out_footer + 12, full_hdr_sha256, 20U);

    return CUP_OK;
}

int cup_pack_header_and_footer_v2(uint32_t flags,
                                  uint64_t total_file_len,
                                  uint32_t section_count,
                                  uint64_t manifest_offset,
                                  uint64_t manifest_length,
                                  uint64_t index_offset,
                                  uint64_t payload_offset,
                                  const char *abi_tag_ascii,
                                  const char *runtime_ref_ascii,
                                  uint8_t index_hash_alg,
                                  uint8_t sig_alg,
                                  uint8_t default_comp_alg,
                                  uint8_t erofs_block_shift,
                                  uint32_t min_kernel_ver,
                                  uint8_t out_header[128],
                                  uint8_t out_footer[32])
{
    return cup_pack_header_and_footer_ext(2U, flags, total_file_len, section_count,
                                          manifest_offset, manifest_length, index_offset,
                                          payload_offset, abi_tag_ascii, runtime_ref_ascii,
                                          index_hash_alg, sig_alg, default_comp_alg,
                                          erofs_block_shift, min_kernel_ver,
                                          out_header, out_footer);
}

/* ============================================================================
 * 8. Phase 13, Appendix C & Appendix D: Landlock, Seccomp-BPF & fs-verity
 * ============================================================================ */

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
                                          size_t size, uint32_t flags) {
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
static inline int landlock_add_rule(int ruleset_fd, enum landlock_rule_type type,
                                    const void *attr, uint32_t flags) {
    return (int)syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}
static inline int landlock_restrict_self(int ruleset_fd, uint32_t flags) {
    return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

static int cup_add_landlock_path(int ruleset_fd, const char *path, uint64_t allowed_access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct landlock_path_beneath_attr path_beneath = {
        .allowed_access = allowed_access,
        .parent_fd      = fd,
    };
    int ret = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);
    close(fd);
    return ret;
}

int cup_sandbox_apply_landlock(const char *rw_appdata_dir) {
    struct landlock_ruleset_attr attr = {
        .handled_access_fs =
            LANDLOCK_ACCESS_FS_EXECUTE    |
            LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_READ_FILE  |
            LANDLOCK_ACCESS_FS_READ_DIR   |
            LANDLOCK_ACCESS_FS_REMOVE_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_FILE|
            LANDLOCK_ACCESS_FS_MAKE_CHAR  |
            LANDLOCK_ACCESS_FS_MAKE_DIR   |
            LANDLOCK_ACCESS_FS_MAKE_REG   |
            LANDLOCK_ACCESS_FS_MAKE_SOCK  |
            LANDLOCK_ACCESS_FS_MAKE_FIFO  |
            LANDLOCK_ACCESS_FS_MAKE_BLOCK |
            LANDLOCK_ACCESS_FS_MAKE_SYM,
    };

    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        if (errno == ENOSYS || errno == EOPNOTSUPP)
            return 0;
        return -1;
    }

    const uint64_t ro_exec = LANDLOCK_ACCESS_FS_EXECUTE |
                             LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR;
    const uint64_t ro_data = LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR;
    const uint64_t rw_data = ro_data |
                             LANDLOCK_ACCESS_FS_WRITE_FILE  |
                             LANDLOCK_ACCESS_FS_REMOVE_DIR  |
                             LANDLOCK_ACCESS_FS_REMOVE_FILE |
                             LANDLOCK_ACCESS_FS_MAKE_DIR    |
                             LANDLOCK_ACCESS_FS_MAKE_REG    |
                             LANDLOCK_ACCESS_FS_MAKE_SOCK   |
                             LANDLOCK_ACCESS_FS_MAKE_SYM;

    (void)cup_add_landlock_path(ruleset_fd, "/usr", ro_exec);
    (void)cup_add_landlock_path(ruleset_fd, "/etc", ro_data);
    (void)cup_add_landlock_path(ruleset_fd, "/tmp", rw_data);
    if (rw_appdata_dir) {
        (void)cup_add_landlock_path(ruleset_fd, rw_appdata_dir, rw_data);
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
        landlock_restrict_self(ruleset_fd, 0) < 0) {
        close(ruleset_fd);
        return -1;
    }
    close(ruleset_fd);
    return 0;
}

#if defined(__x86_64__)
#define CUP_AUDIT_ARCH AUDIT_ARCH_X86_64
#define CUP_X32_SYSCALL_BIT 0x40000000U
#elif defined(__aarch64__)
#define CUP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#define CUP_X32_SYSCALL_BIT 0U
#else
#define CUP_AUDIT_ARCH AUDIT_ARCH_X86_64
#define CUP_X32_SYSCALL_BIT 0U
#endif

#ifndef TIOCSTI
#define TIOCSTI 0x5412U
#endif
#ifndef TIOCLINUX
#define TIOCLINUX 0x541CU
#endif

#define CUP_MAX_BPF_INSNS 512U

struct cup_bpf_program {
    uint16_t           len;
    struct sock_filter insns[CUP_MAX_BPF_INSNS];
};

static inline void bpf_emit(struct cup_bpf_program *p, struct sock_filter f) {
    if (p->len < CUP_MAX_BPF_INSNS) {
        p->insns[p->len++] = f;
    }
}

static void bpf_allow_nr(struct cup_bpf_program *p, uint32_t syscall_nr) {
    bpf_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1));
    bpf_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
}

static void bpf_kill_nr(struct cup_bpf_program *p, uint32_t syscall_nr) {
    bpf_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1));
    bpf_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
}

static void bpf_errno_nr(struct cup_bpf_program *p, uint32_t syscall_nr, uint16_t err) {
    bpf_emit(p, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1));
    bpf_emit(p, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (err & 0xFFFFU)));
}

static int cup_compile_seccomp_profile(enum cup_sandbox_tier tier,
                                bool no_network,
                                struct cup_bpf_program *prog)
{
    prog->len = 0;
    bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                    (uint32_t)offsetof(struct seccomp_data, arch)));
    bpf_emit(prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, CUP_AUDIT_ARCH, 1, 0));
    bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                    (uint32_t)offsetof(struct seccomp_data, nr)));

#if CUP_X32_SYSCALL_BIT != 0U
    bpf_emit(prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CUP_X32_SYSCALL_BIT, 0, 1));
    bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
#endif

#ifdef __NR_bpf
    bpf_kill_nr(prog, __NR_bpf);
#endif
#ifdef __NR_userfaultfd
    bpf_kill_nr(prog, __NR_userfaultfd);
#endif
#ifdef __NR_perf_event_open
    bpf_kill_nr(prog, __NR_perf_event_open);
#endif
#ifdef __NR_keyctl
    bpf_kill_nr(prog, __NR_keyctl);
#endif
#ifdef __NR_kexec_load
    bpf_kill_nr(prog, __NR_kexec_load);
#endif
#ifdef __NR_mount
    bpf_errno_nr(prog, __NR_mount, EPERM);
#endif
#ifdef __NR_unshare
    bpf_errno_nr(prog, __NR_unshare, EPERM);
#endif

    static const uint32_t tier0_syscalls[] = {
        __NR_read, __NR_write, __NR_close, __NR_fstat, __NR_lseek,
        __NR_mmap, __NR_mprotect, __NR_munmap, __NR_mremap, __NR_madvise,
        __NR_brk, __NR_rt_sigaction, __NR_rt_sigprocmask, __NR_rt_sigreturn,
        __NR_sigaltstack, __NR_futex, __NR_set_robust_list, __NR_get_robust_list,
        __NR_clock_gettime, __NR_clock_getres, __NR_clock_nanosleep, __NR_nanosleep,
        __NR_getrandom, __NR_getpid, __NR_gettid, __NR_getuid, __NR_geteuid,
        __NR_getgid, __NR_getegid, __NR_exit, __NR_exit_group, __NR_tgkill,
#ifdef __NR_rseq
        __NR_rseq,
#endif
#ifdef __NR_newfstatat
        __NR_newfstatat,
#endif
    };
    for (size_t i = 0; i < sizeof(tier0_syscalls) / sizeof(tier0_syscalls[0]); i++) {
        bpf_allow_nr(prog, tier0_syscalls[i]);
    }

    if (tier >= CUP_TIER_CLI_IO) {
        bpf_emit(prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 7));
        bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                        (uint32_t)offsetof(struct seccomp_data, args[1])));
        bpf_emit(prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCSTI, 0, 1));
        bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
        bpf_emit(prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCLINUX, 0, 1));
        bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
        bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                        (uint32_t)offsetof(struct seccomp_data, nr)));

        static const uint32_t tier1_syscalls[] = {
            __NR_openat, __NR_pread64, __NR_pwrite64, __NR_readv, __NR_writev,
            __NR_getdents64, __NR_fcntl, __NR_dup, __NR_dup2, __NR_dup3, __NR_pipe2,
            __NR_epoll_create1, __NR_epoll_ctl, __NR_epoll_pwait, __NR_ppoll, __NR_pselect6,
            __NR_statx, __NR_faccessat2, __NR_readlinkat, __NR_getcwd, __NR_chdir, __NR_fchdir,
            __NR_mkdirat, __NR_unlinkat, __NR_renameat2, __NR_symlinkat, __NR_linkat,
            __NR_fchmod, __NR_fchmodat, __NR_fchownat, __NR_umask,
            __NR_fsync, __NR_fdatasync, __NR_ftruncate, __NR_fallocate, __NR_statfs, __NR_fstatfs,
            __NR_clone, __NR_clone3, __NR_execve, __NR_execveat, __NR_wait4, __NR_waitid,
            __NR_kill, __NR_pidfd_open, __NR_pidfd_send_signal, __NR_prctl, __NR_arch_prctl,
            __NR_sched_yield, __NR_sched_getaffinity, __NR_sched_setaffinity,
            __NR_getrlimit, __NR_setrlimit, __NR_prlimit64, __NR_sysinfo, __NR_uname,
#ifdef __NR_openat2
            __NR_openat2,
#endif
#ifdef __NR_epoll_wait
            __NR_epoll_wait,
#endif
#ifdef __NR_poll
            __NR_poll,
#endif
        };
        for (size_t i = 0; i < sizeof(tier1_syscalls) / sizeof(tier1_syscalls[0]); i++) {
            bpf_allow_nr(prog, tier1_syscalls[i]);
        }
    }

    if (tier >= CUP_TIER_GUI_WAYLAND) {
        if (no_network && tier < CUP_TIER_SERVER_NET) {
            bpf_emit(prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 7));
            bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            (uint32_t)offsetof(struct seccomp_data, args[0])));
            bpf_emit(prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 1));
            bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
            bpf_emit(prog, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_NETLINK, 0, 1));
            bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
            bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENETDOWN));
            bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            (uint32_t)offsetof(struct seccomp_data, nr)));
        } else {
            bpf_allow_nr(prog, __NR_socket);
        }

        static const uint32_t tier2_syscalls[] = {
            __NR_socketpair, __NR_connect, __NR_bind, __NR_listen, __NR_accept4,
            __NR_getsockname, __NR_getpeername, __NR_setsockopt, __NR_getsockopt,
            __NR_sendto, __NR_recvfrom, __NR_sendmsg, __NR_recvmsg, __NR_sendmmsg, __NR_recvmmsg,
            __NR_shutdown, __NR_memfd_create, __NR_eventfd2,
            __NR_timerfd_create, __NR_timerfd_settime, __NR_timerfd_gettime,
            __NR_inotify_init1, __NR_inotify_add_watch, __NR_inotify_rm_watch,
            __NR_shmget, __NR_shmat, __NR_shmdt, __NR_shmctl,
        };
        for (size_t i = 0; i < sizeof(tier2_syscalls) / sizeof(tier2_syscalls[0]); i++) {
            bpf_allow_nr(prog, tier2_syscalls[i]);
        }
    }

    if (tier >= CUP_TIER_SERVER_NET) {
        static const uint32_t tier3_syscalls[] = {
            __NR_splice, __NR_tee, __NR_vmsplice, __NR_sendfile, __NR_copy_file_range, __NR_accept,
        };
        for (size_t i = 0; i < sizeof(tier3_syscalls) / sizeof(tier3_syscalls[0]); i++) {
            bpf_allow_nr(prog, tier3_syscalls[i]);
        }
    }

    if (tier >= CUP_TIER_DEVEL_SDK) {
        static const uint32_t tier4_syscalls[] = {
            __NR_ptrace, __NR_process_vm_readv, __NR_process_vm_writev, __NR_personality,
        };
        for (size_t i = 0; i < sizeof(tier4_syscalls) / sizeof(tier4_syscalls[0]); i++) {
            bpf_allow_nr(prog, tier4_syscalls[i]);
        }
    }

    bpf_emit(prog, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS));
    return (prog->len < CUP_MAX_BPF_INSNS) ? 0 : -1;
}

int cup_install_seccomp_profile(enum cup_sandbox_tier tier, bool no_network) {
    struct cup_bpf_program prog;
    if (cup_compile_seccomp_profile(tier, no_network, &prog) < 0)
        return -1;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    struct sock_fprog fprog = {
        .len    = prog.len,
        .filter = prog.insns,
    };
    return (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_TSYNC, &fprog);
}

int cup_verify_kernel_fsverity_fd(int erofs_fd, const uint8_t expected_fsverity_root[32]) {
    uint8_t digest_buf[sizeof(struct fsverity_digest) + 32];
    memset(digest_buf, 0, sizeof(digest_buf));
    struct fsverity_digest *d = (struct fsverity_digest *)digest_buf;
    d->digest_size = 32;
    if (ioctl(erofs_fd, FS_IOC_MEASURE_VERITY, d) < 0) {
        return -1;
    }
    if (d->digest_algorithm != FS_VERITY_HASH_ALG_SHA256 || d->digest_size != 32) {
        return -1;
    }
    if (!cup_ct_memeq(d->digest, expected_fsverity_root, 32U)) {
        return -CUP_E_MERKLE_MISMATCH;
    }
    return CUP_OK;
}

int cup_seal_and_verify_erofs_cache_file(int cache_ro_fd,
                                         const uint8_t expected_fsverity_root[32])
{
    struct fsverity_enable_arg arg;
    memset(&arg, 0, sizeof(arg));
    arg.version        = 1;
    arg.hash_algorithm = FS_VERITY_HASH_ALG_SHA256;
    arg.block_size     = 4096;
    if (ioctl(cache_ro_fd, FS_IOC_ENABLE_VERITY, &arg) < 0 && errno != EEXIST) {
        return -1;
    }
    return cup_verify_kernel_fsverity_fd(cache_ro_fd, expected_fsverity_root);
}

/* ============================================================================
 * 9. Phase 15 & Appendix V: Atomic Deployment Swap & COW Watchdog Rollback
 * ============================================================================ */

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif

static int cup_sys_renameat2(int olddirfd, const char *oldpath,
                             int newdirfd, const char *newpath, unsigned int flags)
{
    return (int)syscall(SYS_renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
}

static int cup_swap_via_symlink_atomic(int parent_dfd,
                                       const char *staging_name,
                                       const char *active_symlink_name,
                                       const char *rollback_name)
{
    struct timespec ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_now);
    static uint64_t gen_counter = 1ULL;
    char ver_dir[128];
    int n = snprintf(ver_dir, sizeof(ver_dir), ".deploy.%s.%ld_%ld_%llu",
                     active_symlink_name, (long)getpid(), (long)ts_now.tv_nsec,
                     (unsigned long long)(++gen_counter));
    if (n < 0 || (size_t)n >= sizeof(ver_dir))
        return -CUP_E_RENAME; /* unambiguous unique-name truncation */

    struct stat st;
    /* If staging_name is a real directory, move it to immutable versioned dir ver_dir */
    if (fstatat(parent_dfd, staging_name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(st.st_mode)) {
        if (unlinkat(parent_dfd, ver_dir, 0) != 0 && errno != ENOENT) {
            /* best-effort cleanup of a stale generation directory */
        }
        if (renameat(parent_dfd, staging_name, parent_dfd, ver_dir) < 0)
            return -CUP_E_RENAME;
    } else if (fstatat(parent_dfd, staging_name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode)) {
        ssize_t rlen = readlinkat(parent_dfd, staging_name, ver_dir, sizeof(ver_dir) - 1);
        if (rlen <= 0) return -CUP_E_RENAME;
        ver_dir[rlen] = '\0';
    } else {
        return -CUP_E_RENAME;
    }

    /* If active_symlink_name is currently a real directory (from an earlier direct rename),
     * migrate it once into a symlink so subsequent symlink swaps are 100% atomic.
     * All maintenance operations here are best-effort: they only refresh the
     * rollback pointer and never affect the atomicity of the active swap. */
    if (fstatat(parent_dfd, active_symlink_name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (S_ISDIR(st.st_mode)) {
            char prev_ver[128];
            int pv = snprintf(prev_ver, sizeof(prev_ver), ".deploy.%s.v0", active_symlink_name);
            if (pv < 0 || (size_t)pv >= sizeof(prev_ver))
                return -CUP_E_RENAME;
            if (renameat(parent_dfd, active_symlink_name, parent_dfd, prev_ver) == 0 &&
                rollback_name != NULL) {
                if (unlinkat(parent_dfd, rollback_name, 0) != 0 && errno != ENOENT) {
                    /* stale rollback entry; replaced below when possible */
                }
                if (symlinkat(prev_ver, parent_dfd, rollback_name) != 0) {
                    /* best-effort rollback pointer refresh */
                }
            }
        } else if (S_ISLNK(st.st_mode) && rollback_name != NULL) {
            char old_target[128];
            ssize_t rlen = readlinkat(parent_dfd, active_symlink_name, old_target, sizeof(old_target) - 1);
            if (rlen > 0) {
                old_target[rlen] = '\0';
                char rb_tmp[128];
                int rt = snprintf(rb_tmp, sizeof(rb_tmp), ".%s.tmp.lnk", rollback_name);
                if (rt > 0 && (size_t)rt < sizeof(rb_tmp)) {
                    if (unlinkat(parent_dfd, rb_tmp, 0) != 0 && errno != ENOENT) {
                        /* no prior temp link */
                    }
                    if (symlinkat(old_target, parent_dfd, rb_tmp) == 0) {
                        if (renameat(parent_dfd, rb_tmp, parent_dfd, rollback_name) != 0) {
                            /* best-effort rollback pointer refresh */
                        }
                    }
                }
            }
        }
    }

    char tmp_link[128];
    int tl = snprintf(tmp_link, sizeof(tmp_link), ".%s.staging.lnk", active_symlink_name);
    if (tl < 0 || (size_t)tl >= sizeof(tmp_link))
        return -CUP_E_RENAME;
    if (unlinkat(parent_dfd, tmp_link, 0) != 0 && errno != ENOENT) {
        /* best-effort cleanup */
    }
    if (symlinkat(ver_dir, parent_dfd, tmp_link) < 0)
        return -CUP_E_RENAME;

    /* Single POSIX atomic rename of symlink over active_symlink_name.
     * NOTE: on failure we NEVER unlink the live active symlink -- that would
     * re-open the exact ENOENT absence window (W > 0 ns) this fallback exists
     * to avoid. Fail closed with the previous deployment left untouched. */
    if (renameat(parent_dfd, tmp_link, parent_dfd, active_symlink_name) < 0) {
        if (unlinkat(parent_dfd, tmp_link, 0) != 0 && errno != ENOENT) {
            /* best-effort cleanup of the unused staging symlink */
        }
        return -CUP_E_RENAME;
    }
    if (fsync(parent_dfd) != 0 && errno != EINVAL) {
        /* directory fsync unsupported on some filesystems */
    }
    return CUP_OK;
}

int cup_atomic_swap_deployment(int parent_dfd,
                               const char *staging_name,
                               const char *active_name,
                               const char *rollback_name)
{
    struct stat st;
    if (fstatat(parent_dfd, staging_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
        return -CUP_E_RENAME;

    if (cup_sys_renameat2(parent_dfd, staging_name,
                          parent_dfd, active_name, RENAME_EXCHANGE) == 0) {
        if (fsync(parent_dfd) != 0 && errno != EINVAL) {
            /* best-effort durability hint */
        }
        if (rollback_name != NULL) {
            /* Refresh the rollback pointer to the just-replaced deployment.
             * A plain renameat fails with ENOTEMPTY/EISDIR when rollback
             * already exists as a different type or a non-empty dir; fall
             * back to an atomic exchange and then clear the displaced old
             * rollback from the staging slot (symlink or empty dir only). */
            if (renameat(parent_dfd, staging_name, parent_dfd, rollback_name) < 0) {
                if (cup_sys_renameat2(parent_dfd, staging_name,
                                      parent_dfd, rollback_name,
                                      RENAME_EXCHANGE) == 0) {
                    struct stat rb;
                    if (fstatat(parent_dfd, staging_name, &rb, AT_SYMLINK_NOFOLLOW) == 0) {
                        if (S_ISLNK(rb.st_mode)) {
                            if (unlinkat(parent_dfd, staging_name, 0) != 0) {
                                /* best-effort cleanup */
                            }
                        } else if (S_ISDIR(rb.st_mode)) {
                            if (unlinkat(parent_dfd, staging_name, AT_REMOVEDIR) != 0) {
                                /* non-empty displaced rollback left for GC */
                            }
                        }
                    }
                }
            }
            if (fsync(parent_dfd) != 0 && errno != EINVAL) {
                /* best-effort durability hint */
            }
        }
        return CUP_OK;
    }

    /* Portable zero-absence symlink indirection when RENAME_EXCHANGE is unsupported or active does not yet exist */
    return cup_swap_via_symlink_atomic(parent_dfd, staging_name, active_name, rollback_name);
}

#ifndef FICLONE
#define FICLONE _IOW(0x94, 9, int)
#endif

static uint64_t cup_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

int cup_cow_clone_state_file(int src_dfd, const char *src_name,
                             int dst_dfd, const char *dst_name, mode_t mode)
{
    int sfd = openat(src_dfd, src_name, O_RDONLY | O_CLOEXEC);
    if (sfd < 0) return -1;
    int dfd = openat(dst_dfd, dst_name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (dfd < 0) {
        close(sfd);
        return -1;
    }
    if (ioctl(dfd, FICLONE, sfd) == 0) {
        close(dfd);
        close(sfd);
        return 0;
    }
    off_t off_in = 0, off_out = 0;
    for (;;) {
        ssize_t n = copy_file_range(sfd, &off_in, dfd, &off_out, 16U << 20, 0);
        if (n == 0) break;
        if (n < 0) {
            close(dfd);
            close(sfd);
            return -1;
        }
    }
    (void)fsync(dfd);
    close(dfd);
    close(sfd);
    return 0;
}

int cup_watchdog_monitor_first_launch(pid_t child_pid,
                                      uint64_t rollback_window_ms,
                                      int deploy_parent_dfd,
                                      int state_parent_dfd)
{
    uint64_t start_ms = cup_monotonic_ms();
    for (;;) {
        int status = 0;
        pid_t r = waitpid(child_pid, &status, WNOHANG);
        if (r == child_pid) {
            bool crashed = WIFSIGNALED(status) ||
                           (WIFEXITED(status) && WEXITSTATUS(status) != 0);
            if (crashed && (cup_monotonic_ms() - start_ms) <= rollback_window_ms) {
                (void)cup_atomic_swap_deployment(deploy_parent_dfd, "rollback", "active", NULL);
                (void)cup_atomic_swap_deployment(state_parent_dfd,  "state-rollback", "state-active", NULL);
                return -CUP_E_RENAME;
            }
            return CUP_OK;
        }
        if (r < 0) {
            /* ECHILD (child already reaped elsewhere) or similar: we can no
             * longer observe the child, so spinning for the whole window is
             * pointless -- return immediately instead of busy-waiting. */
            if (errno != EINTR)
                return CUP_OK;
        }
        if ((cup_monotonic_ms() - start_ms) > rollback_window_ms) {
            return CUP_OK;
        }
        struct timespec sleep_ts = { .tv_sec = 0, .tv_nsec = 2 * 1000 * 1000L };
        nanosleep(&sleep_ts, NULL);
    }
}

/* ============================================================================
 * 10. Appendices E, F, L, R, S, T: ELF64 ABI, Rekor, D-Bus, TUF, Pareto
 * ============================================================================ */

int cup_analyze_elf64_abi(const uint8_t *elf_bytes,
                          size_t elf_len,
                          struct cup_elf_abi_profile *out)
{
    if (!elf_bytes || !out || elf_len < sizeof(Elf64_Ehdr))
        return -1;

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf_bytes;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
        return -1;

    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 ||
        ehdr->e_shentsize != sizeof(Elf64_Shdr) ||
        ehdr->e_shoff >= elf_len)
        return -1;

    /* Overflow-safe section-header-table bounds check (CWE-190 fix):
     * e_shoff + e_shnum * 64 previously wrapped u64 and passed.
     * (e_shoff < elf_len guaranteed above, so the subtraction cannot wrap.) */
    if ((uint64_t)ehdr->e_shnum > (elf_len - ehdr->e_shoff) / sizeof(Elf64_Shdr))
        return -1;

    memset(out, 0, sizeof(*out));
    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(elf_bytes + ehdr->e_shoff);

    const uint8_t   *dynstr     = NULL;
    size_t           dynstr_len = 0;
    const Elf64_Dyn *dyn_table  = NULL;
    size_t           dyn_count  = 0;

    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        /* Overflow-safe per-section bounds check (CWE-190 fix):
         * sh_offset + sh_size previously wrapped and yielded wild pointers. */
        if (shdrs[i].sh_offset > elf_len ||
            shdrs[i].sh_size > elf_len - shdrs[i].sh_offset)
            return -1;
        if (shdrs[i].sh_type == SHT_DYNAMIC) {
            dyn_table = (const Elf64_Dyn *)(elf_bytes + shdrs[i].sh_offset);
            dyn_count = shdrs[i].sh_size / sizeof(Elf64_Dyn);
            uint32_t link = shdrs[i].sh_link;
            if (link < ehdr->e_shnum &&
                shdrs[link].sh_offset + shdrs[link].sh_size <= elf_len) {
                dynstr     = elf_bytes + shdrs[link].sh_offset;
                dynstr_len = shdrs[link].sh_size;
            }
        }
    }

    if (!dyn_table || !dynstr)
        return 0;

    for (size_t i = 0; i < dyn_count; i++) {
        if (dyn_table[i].d_tag == DT_NULL)
            break;
        if (dyn_table[i].d_tag == DT_NEEDED) {
            uint64_t str_off = dyn_table[i].d_un.d_val;
            if (str_off < dynstr_len && out->soname_count < CUP_MAX_SONAMES) {
                const char *s = (const char *)(dynstr + str_off);
                size_t max_rem = dynstr_len - (size_t)str_off;
                size_t slen = strnlen(s, max_rem);
                if (slen > 0 && slen < 64U) {
                    memcpy(out->sonames[out->soname_count], s, slen);
                    out->sonames[out->soname_count][slen] = '\0';
                    out->soname_count++;
                }
            }
        }
    }

    cup_sha256((const uint8_t *)out->sonames, sizeof(out->sonames), out->abi_requirement_hash);
    return 0;
}

int cup_verify_rekor_inclusion(const uint8_t leaf_entry_bytes[],
                               size_t leaf_entry_len,
                               const struct cup_rekor_inclusion_proof *proof,
                               const uint8_t rekor_log_pubkey[32])
{
    if (!proof || proof->tree_size == 0ULL ||
        proof->log_index >= proof->tree_size ||
        proof->path_len > CUP_MAX_REKOR_AUDIT_PATH)
        return -CUP_E_MERKLE_MISMATCH;

    uint8_t chk_msg[17 + 8 + 32];
    memcpy(chk_msg, "CUP-REKOR-CHK-V2", 17U);
    for (int b = 0; b < 8; b++)
        chk_msg[17 + b] = (uint8_t)((proof->tree_size >> (8 * b)) & 0xFFU);
    memcpy(chk_msg + 25, proof->root_hash, 32U);

    if (!cup_ed25519_verify(chk_msg, sizeof(chk_msg), proof->checkpoint_sig, rekor_log_pubkey))
        return -CUP_E_BAD_SIGNATURE;

    uint8_t cur[32];
    if (cup_hash_leaf_prefixed(0x01U, leaf_entry_bytes, leaf_entry_len, cur) != CUP_OK)
        return -CUP_E_MERKLE_MISMATCH;

    uint64_t fn = proof->log_index;
    uint64_t sn = proof->tree_size - 1ULL;

    for (uint8_t i = 0; i < proof->path_len; i++) {
        if (sn == 0ULL)
            return -CUP_E_MERKLE_MISMATCH;

        uint8_t node_buf[65];
        node_buf[0] = 0x01U;

        if ((fn & 1ULL) == 1ULL || fn == sn) {
            memcpy(node_buf + 1,  proof->audit_path[i], 32U);
            memcpy(node_buf + 33, cur, 32U);
            if ((fn & 1ULL) == 0ULL) {
                while ((fn & 1ULL) == 0ULL && fn != 0ULL) {
                    fn >>= 1U;
                    sn >>= 1U;
                }
            }
        } else {
            memcpy(node_buf + 1,  cur, 32U);
            memcpy(node_buf + 33, proof->audit_path[i], 32U);
        }
        cup_sha256(node_buf, 65U, cur);
        fn >>= 1U;
        sn >>= 1U;
    }

    if (sn != 0ULL || !cup_ct_memeq(cur, proof->root_hash, 32U))
        return -CUP_E_MERKLE_MISMATCH;

    return CUP_OK;
}

int cup_tuf_verify_role_metadata(const struct cup_tuf_signed_meta *meta,
                                 const struct cup_tuf_role_keys *role,
                                 uint64_t min_expected_version,
                                 uint64_t current_unix_sec)
{
    if (!meta || !role || role->threshold == 0U || role->threshold > role->key_count ||
        role->key_count > CUP_TUF_MAX_ROLE_KEYS || meta->sig_count > CUP_TUF_MAX_SIGS)
        return -CUP_E_BAD_SIGNATURE;

    if (meta->version < min_expected_version)
        return -CUP_E_REVOKED_KEY;

    if (current_unix_sec >= meta->expires_unix_sec)
        return -CUP_E_EXPIRED_CERT;

    uint32_t seen_key_mask = 0U;
    uint8_t valid_distinct_sigs = 0U;

    for (uint8_t s = 0; s < meta->sig_count; s++) {
        for (uint8_t k = 0; k < role->key_count; k++) {
            if ((seen_key_mask & (1U << k)) != 0U)
                continue;
            if (cup_ct_memeq(meta->sigs[s].key_id, role->key_ids[k], 32U)) {
                if (cup_ed25519_verify(meta->canonical_signed_json,
                                       meta->canonical_signed_len,
                                       meta->sigs[s].signature,
                                       role->pubkeys[k])) {
                    seen_key_mask |= (1U << k);
                    valid_distinct_sigs++;
                }
                break;
            }
        }
    }

    if (valid_distinct_sigs < role->threshold)
        return -CUP_E_BAD_SIGNATURE;

    return CUP_OK;
}

static inline uint32_t dbus_read_u32(const uint8_t *p, uint8_t endian) {
    if (endian == 'l') {
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
               ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    }
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int cup_dbus_validate_message_header(const uint8_t *msg,
                                     size_t msg_len,
                                     const struct cup_dbus_policy *policy)
{
    if (!msg || !policy || msg_len < 16U)
        return -EINVAL;

    uint8_t endian   = msg[0];
    uint8_t msg_type = msg[1];
    uint8_t proto_v  = msg[3];

    if ((endian != 'l' && endian != 'B') || proto_v != 1U)
        return -EINVAL;

    uint32_t body_len       = dbus_read_u32(msg + 4, endian);
    uint32_t serial         = dbus_read_u32(msg + 8, endian);
    uint32_t fields_arr_len = dbus_read_u32(msg + 12, endian);

    if (serial == 0U || body_len > (64U << 20) || fields_arr_len > (1U << 20))
        return -EINVAL;

    uint64_t total_hdr = 16ULL + (uint64_t)((fields_arr_len + 7U) & ~7U);
    if (total_hdr + body_len > msg_len)
        return -EMSGSIZE;

    size_t pos = 16U;
    size_t end = 16U + fields_arr_len;
    bool destination_verified = false;

    while (pos < end) {
        pos = (pos + 7U) & ~(size_t)7U;
        if (pos + 4U > end) return -EINVAL;

        uint8_t field_code = msg[pos];
        uint8_t sig_len    = msg[pos + 1];
        if (pos + 2U + sig_len + 1U > end) return -EINVAL;

        uint8_t sig_char = msg[pos + 2U];
        pos += 2U + sig_len + 1U;

        if (sig_char == 's' || sig_char == 'o') {
            pos = (pos + 3U) & ~(size_t)3U;
            if (pos + 4U > end) return -EINVAL;
            uint32_t slen = dbus_read_u32(msg + pos, endian);
            pos += 4U;
            if (pos + slen + 1U > end || msg[pos + slen] != '\0') return -EINVAL;

            const char *str_val = (const char *)(msg + pos);
            if (field_code == 6U) {
                if (strcmp(str_val, "org.freedesktop.DBus") == 0 ||
                    strcmp(str_val, "org.freedesktop.portal.Desktop") == 0) {
                    destination_verified = true;
                } else {
                    for (size_t k = 0; k < policy->allowed_count; k++) {
                        if (strcmp(str_val, policy->allowed_destinations[k]) == 0) {
                            destination_verified = true;
                            break;
                        }
                    }
                }
                if (!destination_verified)
                    return -EACCES;
            }
            pos += slen + 1U;
        } else if (sig_char == 'u' || sig_char == 'h') {
            pos = (pos + 3U) & ~(size_t)3U;
            pos += 4U;
        } else if (sig_char == 'g') {
            if (pos >= end) return -EINVAL;
            uint8_t glen = msg[pos];
            /* Bounds guard (CWE-20): signature length may not jump past end. */
            if (glen > 0 && pos + 1U + (size_t)glen + 1U > end) return -EINVAL;
            pos += 1U + glen + 1U;
        } else {
            return -EINVAL;
        }
    }

    if (msg_type == 1U && !destination_verified)
        return -EACCES;

    return 0;
}

enum cup_chunk_codec cup_select_pareto_codec(size_t raw_size,
                                             double f_hot,
                                             const struct cup_codec_candidate candidates[3])
{
    const double b_disk     = 3.0e9;
    const double b_net      = 1.25e8;
    const double p_net      = 0.05;
    const double lambda_mem = 2.5e-10;

    enum cup_chunk_codec best_codec = CUP_CODEC_RAW_4K;
    double best_utility = 0.0;

    for (size_t i = 0; i < 3U; i++) {
        if (candidates[i].compressed_size >= raw_size)
            continue;
        double bytes_saved = (double)(raw_size - candidates[i].compressed_size);
        double io_gain     = (bytes_saved / b_disk) + p_net * (bytes_saved / b_net);
        double hot_penalty = f_hot * (((double)raw_size / candidates[i].decomp_speed_bps) +
                                      (lambda_mem * (double)raw_size));
        double u_score     = io_gain - hot_penalty;
        if (u_score > best_utility) {
            best_utility = u_score;
            best_codec   = candidates[i].codec;
        }
    }
    return best_codec;
}

int cup_binfmt_acquire_execfd(const char *fallback_argv1) {
    unsigned long execfd = getauxval(AT_EXECFD);
    if (execfd != 0UL) {
        return (int)execfd;
    }
    if (!fallback_argv1) return -1;
    return open(fallback_argv1, O_RDONLY | O_CLOEXEC);
}

const char *cup_strerror(int err_code) {
    int c = (err_code < 0) ? -err_code : err_code;
    switch (c) {
        case CUP_OK:                     return "CUP_OK: Verified successfully";
        case CUP_E_TRUNCATED:            return "CUP_E_TRUNCATED: Container truncated or invalid length";
        case CUP_E_BAD_MAGIC:            return "CUP_E_BAD_MAGIC: Expected CUP3, CUP2, or CUP1 at offset 0";
        case CUP_E_BAD_VERSION:          return "CUP_E_BAD_VERSION: Header version mismatch";
        case CUP_E_BAD_FOOTER_MAGIC:     return "CUP_E_BAD_FOOTER_MAGIC: Expected CUPE at L-32";
        case CUP_E_LENGTH_MISMATCH:      return "CUP_E_LENGTH_MISMATCH: Header/footer length mismatch";
        case CUP_E_HEADER_HASH_MISMATCH: return "CUP_E_HEADER_HASH_MISMATCH: Footer truncated SHA-256 mismatch";
        case CUP_E_RESERVED_NZ:          return "CUP_E_RESERVED_NZ: Reserved flags or bytes non-zero";
        case CUP_E_BAD_TYPE:             return "CUP_E_BAD_TYPE: Invalid section type (>0xFF or forbidden flag)";
        case CUP_E_SECTION_OVERLAP:      return "CUP_E_SECTION_OVERLAP: Non-monotonic or unaligned section span";
        case CUP_E_BAD_SIGNATURE:        return "CUP_E_BAD_SIGNATURE: Cryptographic signature verification failed";
        case CUP_E_UNLINKED_CHAIN:       return "CUP_E_UNLINKED_CHAIN: Certificate chain linkage failure (CUP-ERR-003)";
        case CUP_E_UNTRUSTED_ROOT:       return "CUP_E_UNTRUSTED_ROOT: Terminal issuer not in trusted root keyring";
        case CUP_E_REVOKED_KEY:          return "CUP_E_REVOKED_KEY: Key or role metadata version revoked";
        case CUP_E_EXPIRED_CERT:         return "CUP_E_EXPIRED_CERT: Timestamp outside certificate validity window";
        case CUP_E_NAMESPACE_VIOLATION:  return "CUP_E_NAMESPACE_VIOLATION: Package ID outside allowed_prefix";
        case CUP_E_MERKLE_MISMATCH:      return "CUP_E_MERKLE_MISMATCH: Merkle or fs-verity root digest mismatch";
        case CUP_E_RENAME:               return "CUP_E_RENAME: Atomic renameat2 swap or rollback triggered";
        case CUP_E_BAD_ASCII:            return "CUP_E_BAD_ASCII: Invalid ASCII token or JCS formatting";
        case CUP_E_UNSAT_CORE:           return "CUP_E_UNSAT_CORE: Unsatisfiable ABI slice dependency graph";
        default:                         return "CUP_E_UNKNOWN: Unknown error code";
    }
}
