/* [NORMATIVE] libcup2.h: Unified Public Header for CUP v3.0 / v2.0 / v1.0.2 (C23 & C++20)
 * Resolves all 33 CUP-REV-001 Errata (CUP-ERR-001 through CUP-ERR-033) and implements
 * v3.0 Self-Bootstrap, Composefs DAX, PGO Pareto Compression, MaxSMT ABI Slicing,
 * and Transactional COW User-State Rollback.
 */
#ifndef CUP_LIBCUP2_H
#define CUP_LIBCUP2_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CUP_HEADER_SIZE        128U
#define CUP_FOOTER_SIZE        32U
#define CUP_SECTION_ENTRY_SIZE 64U
#define CUP_CERT_SIZE          168U
#define CUP_MIN_FILE_SIZE      (CUP_HEADER_SIZE + CUP_SECTION_ENTRY_SIZE + CUP_FOOTER_SIZE)
#define CUP_MAX_VOLUME_SIZE    (1ULL << 48)
#define CUP_MAX_SECTIONS       256U
#define CUP_MAX_MERKLE_DEPTH   32U
#define CUP_MAX_SONAMES        64U
#define CUP_MAX_VERNEEDS       128U
#define CUP_MAX_REKOR_AUDIT_PATH 64U
#define CUP_TUF_MAX_ROLE_KEYS  16U
#define CUP_TUF_MAX_SIGS       16U
#define CUP_MLDSA65_PUBKEY_BYTES 1952U
#define CUP_MLDSA65_SIG_BYTES    3309U

/* Unified Package Flags (Table 6.2 - CUP-ERR-005 Fixed + v3.0 Superset) */
#define CUP_FLAG_MULTI_VOLUME    (1U << 0)
#define CUP_FLAG_EXPERIMENTAL    (1U << 1)
#define CUP_FLAG_DETACHED_SIG    (1U << 2)
#define CUP_FLAG_DELTA_UPDATE    (1U << 3)
#define CUP_FLAG_READ_ONLY_RT    (1U << 4)
#define CUP_FLAG_NO_NETWORK      (1U << 5)
#define CUP_FLAG_EROFS_DIRECT    (1U << 6)
#define CUP_FLAG_FSVERITY_SEALED (1U << 7)
#define CUP_FLAG_BLAKE3_INDEX    (1U << 8)
#define CUP_FLAG_ABI_SLICE       (1U << 9)
#define CUP_FLAG_TUF_REKOR       (1U << 10)
#define CUP_FLAG_SYSTEM_DAEMON   (1U << 11)
#define CUP_FLAG_SELF_BOOTSTRAP  (1U << 12)
#define CUP_FLAG_PGO_DAX_HOT     (1U << 13)
#define CUP_FLAG_COW_STATE_SNAP  (1U << 14)
#define CUP_FLAG_COMPOSEFS_DAX   (1U << 15)

#define CUP_FLAG_V1_RESERVED_MASK 0xFFFFFFC0U
#define CUP_FLAG_V2_RESERVED_MASK 0xFFFFF000U
#define CUP_FLAG_V3_RESERVED_MASK 0xFFFF0000U

/* Registered Section Types (Table 7.1) */
#define CUP_SECT_MANIFEST        0x01U
#define CUP_SECT_SIGNATURE       0x02U
#define CUP_SECT_INDEX           0x03U
#define CUP_SECT_PAYLOAD         0x04U
#define CUP_SECT_SBOM            0x05U
#define CUP_SECT_ICON_META       0x06U
#define CUP_SECT_SANDBOX_BPF     0x07U
#define CUP_SECT_DELTA_MAN       0x08U
#define CUP_SECT_VOLUME_MAP      0x09U
#define CUP_SECT_ZSTD_DICT       0x0AU
#define CUP_SECT_LOCALIZATION    0x0BU
#define CUP_SECT_EROFS_IMAGE     0x0CU
#define CUP_SECT_FSVERITY        0x0DU
#define CUP_SECT_ABI_SLICE       0x0EU
#define CUP_SECT_SYSTEMD_UNIT    0x0FU
#define CUP_SECT_ELF_BOOTSTRAP   0x10U
#define CUP_SECT_COMPOSEFS       0x11U
#define CUP_SECT_STATE_MIGRATION 0x12U
#define CUP_SECT_WASM_PORTABLE   0x13U
#define CUP_SECT_VENDOR_EXT      0xFFU

/* Section Flags (Table 7.2) */
#define CUP_SFLAG_COMPRESSED     0x00000001U
#define CUP_SFLAG_ENCRYPTED      0x00000002U
#define CUP_SFLAG_STREAMABLE     0x00000004U
#define CUP_SFLAG_OPTIONAL       0x00000008U
#define CUP_SFLAG_COMP_MASK      0x00000030U
#define CUP_SFLAG_PAGE_ALIGNED   0x00000040U
#define CUP_SFLAG_RESERVED       0xFFFFFF80U

/* Certificate Key Usage Masks */
#define CUP_KEY_USAGE_PKG_SIGN   0x0001U
#define CUP_KEY_USAGE_CA_INT     0x0002U
#define CUP_KEY_USAGE_CA_ROOT    0x0004U

/* Normalized FastCDC Constants (Phase 12 - CUP-ERR-004 & CUP-ERR-023 Fixed) */
#define CUP_CDC_MIN_SIZE         65536U
#define CUP_CDC_AVG_SIZE         1048576U
#define CUP_CDC_MAX_SIZE         8388608U
#define CUP_CDC_MASK_S           0x0003FFFFC0000000ULL
#define CUP_CDC_MASK_L           0x00003FFFC0000000ULL

#define CUP_HASH_ALG_SHA256      0x01U
#define CUP_HASH_ALG_BLAKE3      0x02U

enum cup_err {
    CUP_OK                      = 0,
    CUP_E_TRUNCATED             = 1,
    CUP_E_BAD_MAGIC             = 2,
    CUP_E_BAD_VERSION           = 3,
    CUP_E_BAD_FOOTER_MAGIC      = 4,
    CUP_E_LENGTH_MISMATCH       = 5,
    CUP_E_HEADER_HASH_MISMATCH  = 6,
    CUP_E_RESERVED_NZ           = 7,
    CUP_E_BAD_TYPE              = 8,
    CUP_E_SECTION_OVERLAP       = 9,
    CUP_E_BAD_SIGNATURE         = 10,
    CUP_E_UNLINKED_CHAIN        = 11,
    CUP_E_UNTRUSTED_ROOT        = 12,
    CUP_E_REVOKED_KEY           = 13,
    CUP_E_EXPIRED_CERT          = 14,
    CUP_E_NAMESPACE_VIOLATION   = 15,
    CUP_E_MERKLE_MISMATCH       = 16,
    CUP_E_RENAME                = 17,
    CUP_E_BAD_ASCII             = 18,
    CUP_E_UNSAT_CORE            = 19
};

enum cup_sandbox_tier {
    CUP_TIER_COMPUTE_PURE = 0,
    CUP_TIER_CLI_IO       = 1,
    CUP_TIER_GUI_WAYLAND  = 2,
    CUP_TIER_SERVER_NET   = 3,
    CUP_TIER_DEVEL_SDK    = 4
};

enum cup_chunk_codec {
    CUP_CODEC_RAW_4K        = 0,
    CUP_CODEC_LZ4HC         = 1,
    CUP_CODEC_ZSTD_L9       = 2,
    CUP_CODEC_ZSTD_L19_DICT = 3
};

struct cup_fixed_str16 {
    char   buf[17];
    size_t len;
};

struct cup_section_entry {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t length;
    uint8_t  sha256[32];
    uint64_t uncompressed_len;
};

struct cup_catalog {
    size_t                   total_entries;
    struct cup_section_entry entries[CUP_MAX_SECTIONS];
    uint16_t                 count_by_type[256];
    uint16_t                 first_idx_by_type[256];
};

struct cup_certificate {
    uint8_t  subject_pubkey[32];
    uint8_t  issuer_pubkey[32];
    uint8_t  cert_signature[64];
    uint64_t valid_from;
    uint64_t valid_until;
    uint16_t usage_mask;
    uint8_t  cert_reserved[6];
    char     allowed_prefix[16];
};

struct cup_signature_section {
    uint32_t               sig_format_version;
    uint8_t                sig_alg;
    uint8_t                chain_length;
    uint16_t               rekor_proof_len;
    uint8_t                signer_pubkey[32];
    uint8_t                ed25519_signature[64];
    uint64_t               tsa_timestamp;
    uint8_t                tsa_pubkey[32];
    uint8_t                tsa_signature[64];
    struct cup_certificate chain[8];
};

struct cup_manifest_view {
    const uint8_t *body;
    size_t         body_len;
    const char    *app_id;
};

struct cup_root_keyring {
    size_t  root_count;
    uint8_t root_pubkeys[16][32];
    size_t  tsa_count;
    uint8_t tsa_pubkeys[16][32];
    size_t  revoked_count;
    uint8_t revoked_pubkeys[64][32];
};

struct cup_merkle_proof {
    uint8_t  hash_alg;
    uint8_t  depth;
    uint64_t chunk_index;
    uint64_t total_chunks;
    uint8_t  siblings[CUP_MAX_MERKLE_DEPTH][32];
};

struct cup_chunk_desc {
    uint64_t payload_rel_offset;
    uint32_t uncompressed_len;
    uint32_t compressed_len;
    uint8_t  leaf_hash[32];
};

struct cup_elf_abi_profile {
    size_t  soname_count;
    char    sonames[CUP_MAX_SONAMES][64];
    size_t  verneed_count;
    char    verneeds[CUP_MAX_VERNEEDS][64];
    uint8_t abi_requirement_hash[32];
};

struct cup_rekor_inclusion_proof {
    uint64_t log_index;
    uint64_t tree_size;
    uint8_t  path_len;
    uint8_t  root_hash[32];
    uint8_t  checkpoint_sig[64];
    uint8_t  audit_path[CUP_MAX_REKOR_AUDIT_PATH][32];
};

struct cup_tuf_role_keys {
    uint8_t threshold;
    uint8_t key_count;
    uint8_t key_ids[CUP_TUF_MAX_ROLE_KEYS][32];
    uint8_t pubkeys[CUP_TUF_MAX_ROLE_KEYS][32];
};

struct cup_tuf_sig_entry {
    uint8_t key_id[32];
    uint8_t signature[64];
};

struct cup_tuf_signed_meta {
    const uint8_t           *canonical_signed_json;
    size_t                   canonical_signed_len;
    uint64_t                 version;
    uint64_t                 expires_unix_sec;
    uint8_t                  sig_count;
    struct cup_tuf_sig_entry sigs[CUP_TUF_MAX_SIGS];
};

struct cup_pq_hybrid_bundle {
    uint8_t magic[4];
    uint8_t mldsa65_pubkey[CUP_MLDSA65_PUBKEY_BYTES];
    uint8_t mldsa65_sig[CUP_MLDSA65_SIG_BYTES];
    uint8_t pad_zero[3];
    uint8_t pubkey_sha256[32];
};

struct cup_codec_candidate {
    enum cup_chunk_codec codec;
    size_t               compressed_size;
    double               decomp_speed_bps;
};

struct cup_dbus_policy {
    size_t allowed_count;
    char   allowed_destinations[32][128];
};

/* Inline Endianness & Constant-Time Helpers */
static inline int cup_ct_memeq(const uint8_t *a, const uint8_t *b, size_t n) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static inline uint32_t cup_read_u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t cup_read_u64le(const uint8_t *p) {
    return (uint64_t)cup_read_u32le(p) | ((uint64_t)cup_read_u32le(p + 4) << 32);
}

static inline void cup_write_u16le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
}

static inline void cup_write_u32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
}

static inline void cup_write_u64le(uint8_t *p, uint64_t v) {
    cup_write_u32le(p, (uint32_t)(v & 0xFFFFFFFFULL));
    cup_write_u32le(p + 4, (uint32_t)(v >> 32));
}

/* Core Cryptographic Primitives (OpenSSL 3.x + BLAKE3 + Ed25519 + ML-DSA-65) */
void cup_sha256(const uint8_t *data, size_t len, uint8_t out_digest[32]);
void cup_sha512(const uint8_t *data, size_t len, uint8_t out_digest[64]);
void cup_blake3_256(const uint8_t *data, size_t len, uint8_t out_digest[32]);
/* Returns CUP_OK, or -CUP_E_TRUNCATED when chunk_len exceeds SIZE_MAX-1
 * (allocation-overflow guard, CWE-190) or the provider fails closed. */
int  cup_hash_leaf_prefixed(uint8_t hash_alg, const uint8_t *chunk, size_t chunk_len, uint8_t out_leaf[32]);

int  cup_ed25519_keypair_from_seed(const uint8_t seed[32], uint8_t out_pubkey[32], uint8_t out_privkey[64]);
int  cup_ed25519_sign(const uint8_t *msg, size_t msg_len, const uint8_t seed[32], uint8_t out_sig[64]);
bool cup_ed25519_verify(const uint8_t *msg, size_t msg_len, const uint8_t sig[64], const uint8_t pubkey[32]);
int  cup_ed25519ph_sign(const uint8_t *msg, size_t msg_len, const uint8_t *ctx, size_t ctx_len, const uint8_t seed[32], uint8_t out_sig[64]);
bool cup_ed25519ph_verify(const uint8_t *msg, size_t msg_len, const uint8_t *ctx, size_t ctx_len, const uint8_t sig[64], const uint8_t pubkey[32]);

int  cup_mldsa65_keypair_from_seed(const uint8_t seed[32], uint8_t out_pubkey[CUP_MLDSA65_PUBKEY_BYTES], uint8_t out_priv_seed[32]);
int  cup_mldsa65_sign(const uint8_t *msg, size_t msg_len, const uint8_t priv_seed[32], uint8_t out_sig[CUP_MLDSA65_SIG_BYTES]);
bool cup_mldsa65_verify(const uint8_t *msg, size_t msg_len, const uint8_t sig[CUP_MLDSA65_SIG_BYTES], const uint8_t pubkey[CUP_MLDSA65_PUBKEY_BYTES]);

/* Normative Specification Algorithms */
int cup_validate_header_and_footer(const uint8_t header[CUP_HEADER_SIZE],
                                   const uint8_t footer[CUP_FOOTER_SIZE],
                                   uint64_t actual_file_len);
int cup_parse_header_str16(const uint8_t raw[16], struct cup_fixed_str16 *out);
int cup_parse_uri(const char *uri, uint8_t out_sha256[32]);

int cup_catalog_build_safe(const uint8_t *raw_table,
                           size_t section_count,
                           uint64_t total_file_len,
                           struct cup_catalog *out);
const struct cup_section_entry *cup_catalog_find_by_offset(const struct cup_catalog *cat, uint64_t byte_offset);

int cup_verify_signature_v2(const struct cup_manifest_view *m,
                            const struct cup_signature_section *s,
                            const struct cup_root_keyring *kr,
                            uint8_t out_manifest_sha256[32]);

int cup_verify_hybrid_pq_bundle(const uint8_t manifest_sha256[32],
                                const uint8_t ed25519_sig[64],
                                const uint8_t ed25519_pubkey[32],
                                const struct cup_pq_hybrid_bundle *pq);

int cup_merkle_verify_chunk(const uint8_t *chunk,
                            size_t chunk_len,
                            const struct cup_merkle_proof *proof,
                            const uint8_t expected_root[32]);
int cup_merkle_build_root(uint8_t hash_alg,
                          const struct cup_chunk_desc *chunks,
                          size_t chunk_count,
                          uint8_t out_root[32],
                          size_t *out_depth);
int cup_merkle_generate_proof(uint8_t hash_alg,
                              const struct cup_chunk_desc *chunks,
                              size_t chunk_count,
                              size_t target_index,
                              struct cup_merkle_proof *out_proof);

void   cup_fastcdc_init_gear_table(uint64_t gear_table[256]);
const uint64_t *cup_fastcdc_get_static_gear_table(void);
size_t cup_fastcdc_next_chunk(const uint8_t *buf, size_t len, const uint64_t gear_table[256]);

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
                                   uint8_t out_footer[32]);

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
                                  uint8_t out_footer[32]);

int cup_sandbox_apply_landlock(const char *rw_appdata_dir);
int cup_install_seccomp_profile(enum cup_sandbox_tier tier, bool no_network);
int cup_verify_kernel_fsverity_fd(int erofs_fd, const uint8_t expected_fsverity_root[32]);
int cup_seal_and_verify_erofs_cache_file(int cache_ro_fd, const uint8_t expected_fsverity_root[32]);

int cup_atomic_swap_deployment(int parent_dfd,
                               const char *staging_name,
                               const char *active_name,
                               const char *rollback_name);
int cup_cow_clone_state_file(int src_dfd, const char *src_name,
                             int dst_dfd, const char *dst_name, mode_t mode);
int cup_watchdog_monitor_first_launch(pid_t child_pid,
                                      uint64_t rollback_window_ms,
                                      int deploy_parent_dfd,
                                      int state_parent_dfd);

int cup_analyze_elf64_abi(const uint8_t *elf_bytes, size_t elf_len, struct cup_elf_abi_profile *out);
int cup_verify_rekor_inclusion(const uint8_t leaf_entry_bytes[],
                               size_t leaf_entry_len,
                               const struct cup_rekor_inclusion_proof *proof,
                               const uint8_t rekor_log_pubkey[32]);
int cup_tuf_verify_role_metadata(const struct cup_tuf_signed_meta *meta,
                                 const struct cup_tuf_role_keys *role,
                                 uint64_t min_expected_version,
                                 uint64_t current_unix_sec);
int cup_dbus_validate_message_header(const uint8_t *msg,
                                     size_t msg_len,
                                     const struct cup_dbus_policy *policy);
enum cup_chunk_codec cup_select_pareto_codec(size_t raw_size,
                                             double f_hot,
                                             const struct cup_codec_candidate candidates[3]);
int cup_binfmt_acquire_execfd(const char *fallback_argv1);
const char *cup_strerror(int err_code);

#ifdef __cplusplus
}
#endif

#endif /* CUP_LIBCUP2_H */
