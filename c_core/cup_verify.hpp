/* [NORMATIVE] cup_verify.hpp - structured package verification engine shared by verify / inspect / install.
 *
 * Differences from the original in-line cmd_verify_package():
 *   - every read of the SIGNATURE section is bounds-checked BEFORE it is copied (chain_length > 8 used to
 *     overflow the on-stack cup_signature_section);
 *   - the package id comes from a strict JSON parse of the signed manifest, never from a substring search;
 *   - INDEX chunks, the payload, the Merkle root and the EROFS image are bound to the SIGNED manifest
 *     (previously a re-sealed section table was accepted with arbitrary payload bytes);
 *   - header sig_alg must agree with the signature section (cheap downgrade tripwire);
 *   - flags that promise a section (SELF_BOOTSTRAP, EROFS_DIRECT, FSVERITY_SEALED) are checked against it;
 *   - results are structured (status / spec reference / hint) so the CLI can render or emit JSON. */
#pragma once

#include "libcup2.h"
#include "cup_json.hpp"
#include "cup_ui.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

static_assert(sizeof(struct cup_chunk_desc) == 48, "wire layout: chunk descriptor is 48 bytes");
static_assert(sizeof(struct cup_certificate) == 168, "wire layout: certificate is 168 bytes");
static_assert(sizeof(struct cup_pq_hybrid_bundle) == 5300, "wire layout: PQ bundle is 5300 bytes");

namespace cupv {

using Key32 = std::array<uint8_t, 32>;

inline std::string hex(const uint8_t *p, size_t n) {
    static const char *d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
inline bool unhex(const std::string &h, uint8_t *out, size_t n) {
    if (h.size() != n * 2) return false;
    for (size_t i = 0; i < n; i++) {
        int v = 0;
        for (int k = 0; k < 2; k++) {
            char c = h[i * 2 + k]; v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0'; else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10; else return false;
        }
        out[i] = (uint8_t)v;
    }
    return true;
}

/* Deterministic DEMO key material derived from public seeds. Anyone can derive these keys: they exist so
 * `build` and `verify` work out of the box. Never trust them in production (use --trust-root). */
struct DemoKeys {
    uint8_t root_seed[32], root_pub[32], distro_seed[32], distro_pub[32];
    uint8_t maint_seed[32], maint_pub[32], tsa_seed[32], tsa_pub[32], pq_seed[32];
    DemoKeys() {
        cup_sha256(reinterpret_cast<const uint8_t *>("CUP-V3-ROOT-CA-SEED"), 19, root_seed);
        cup_sha256(reinterpret_cast<const uint8_t *>("CUP-V3-DISTRO-CA-SEED"), 21, distro_seed);
        cup_sha256(reinterpret_cast<const uint8_t *>("CUP-V3-MAINT-LEAF-SEED"), 22, maint_seed);
        cup_sha256(reinterpret_cast<const uint8_t *>("CUP-V3-RFC3161-TSA-SEED"), 23, tsa_seed);
        cup_sha256(reinterpret_cast<const uint8_t *>("CUP-V3-MLDSA65-PQ-SEED"), 22, pq_seed);
        cup_ed25519_keypair_from_seed(root_seed, root_pub, nullptr);
        cup_ed25519_keypair_from_seed(distro_seed, distro_pub, nullptr);
        cup_ed25519_keypair_from_seed(maint_seed, maint_pub, nullptr);
        cup_ed25519_keypair_from_seed(tsa_seed, tsa_pub, nullptr);
    }
};

enum class St { Pass, Fail, Warn, Info };
inline const char *st_name(St s) {
    switch (s) { case St::Pass: return "pass"; case St::Fail: return "fail"; case St::Warn: return "warn"; default: return "info"; }
}

struct Check { std::string group, text, detail, spec, hint; St st; };
struct SectionInfo { uint32_t type = 0, flags = 0; uint64_t off = 0, len = 0; std::string sha_hex; };
struct CertInfo { std::string subject_fp, issuer_fp, prefix; uint16_t usage = 0; uint64_t from = 0, until = 0; };

struct Options {
    bool strict = false;
    bool require_pq = false;
    bool builtin_roots = true;
    std::vector<Key32> roots, tsa_keys;
};

struct Report {
    std::string path;
    uint64_t size = 0;
    int major = 0;
    uint32_t flags = 0, min_kernel = 0;
    uint8_t hash_alg = 0, hdr_sig_alg = 0, comp_alg = 0, erofs_shift = 0;
    std::string abi_tag, runtime_ref;
    std::vector<SectionInfo> sections;
    std::string app_id, version, schema, manifest_text;
    cupjson::Val manifest;
    std::string manifest_sha_hex, uri;
    uint8_t sig_alg = 0;
    uint32_t sig_format = 0;
    uint64_t tsa_ts = 0;
    std::string signer_fp;
    std::vector<CertInfo> chain;
    uint64_t chunk_count = 0;
    std::string merkle_root, erofs_root;
    bool used_demo_root = false;
    std::vector<Check> checks;
    int fails = 0, warns = 0;

    bool ok() const { return fails == 0; }
    void add(const char *group, St st, const std::string &text, const std::string &detail = "",
             const char *spec = "", const std::string &hint = "") {
        checks.push_back({group, text, detail, spec, hint, st});
        if (st == St::Fail) fails++;
        if (st == St::Warn) warns++;
    }
};

inline const char *section_name(uint32_t t) {
    switch (t) {
        case 0x01: return "MANIFEST";    case 0x02: return "SIGNATURE";   case 0x03: return "INDEX";
        case 0x04: return "PAYLOAD";     case 0x05: return "SBOM";        case 0x06: return "ICON_META";
        case 0x07: return "SANDBOX_BPF"; case 0x08: return "DELTA_MAN";   case 0x09: return "VOLUME_MAP";
        case 0x0A: return "ZSTD_DICT";   case 0x0B: return "LOCALIZATION"; case 0x0C: return "EROFS_IMAGE";
        case 0x0D: return "FSVERITY";    case 0x0E: return "ABI_SLICE";   case 0x0F: return "SYSTEMD_UNIT";
        case 0x10: return "ELF_BOOTSTRAP"; case 0x11: return "COMPOSEFS"; case 0x12: return "STATE_MIGRATION";
        case 0x13: return "WASM_PORTABLE"; case 0xFF: return "VENDOR_EXT"; default: return "UNKNOWN";
    }
}

inline std::string flag_names(uint32_t f) {
    static const char *n[16] = {"MULTI_VOLUME", "EXPERIMENTAL", "DETACHED_SIG", "DELTA_UPDATE", "READ_ONLY_RT", "NO_NETWORK",
                                "EROFS_DIRECT", "FSVERITY_SEALED", "BLAKE3_INDEX", "ABI_SLICE", "TUF_REKOR", "SYSTEM_DAEMON",
                                "SELF_BOOTSTRAP", "PGO_DAX_HOT", "COW_STATE_SNAP", "COMPOSEFS_DAX"};
    std::string s;
    for (int i = 0; i < 16; i++) if (f & (1U << i)) { if (!s.empty()) s += ' '; s += n[i]; }
    return s.empty() ? "(none)" : s;
}

inline std::string date_utc(uint64_t ts) {
    time_t t = (time_t)ts; struct tm tmv{};
    if (!gmtime_r(&t, &tmv)) return "?";
    char b[16]; std::strftime(b, sizeof b, "%Y-%m-%d", &tmv);
    return b;
}

/* constant-time equality for equal-length public digests (hex strings); false if lengths differ */
inline bool ct_streq(const std::string &a, const std::string &b) {
    if (a.size() != b.size() || a.empty()) return false;
    return cup_ct_memeq(reinterpret_cast<const uint8_t *>(a.data()), reinterpret_cast<const uint8_t *>(b.data()), a.size()) != 0;
}

inline bool valid_app_id(const std::string &id) {
    if (id.empty() || id.size() > 128 || id.front() == '.' || id.back() == '.' || id.find("..") != std::string::npos) return false;
    if (id.find('.') == std::string::npos) return false;
    for (unsigned char c : id) if (!(std::isalnum(c) || c == '.' || c == '_' || c == '-')) return false;
    return true;
}

struct Why { const char *what; const char *hint; };
inline Why explain(int code) {
    if (code < 0) code = -code;
    switch (code) {
        case CUP_E_TRUNCATED:            return {"file is truncated or its length field is wrong", "The download was probably cut short - fetch the package again."};
        case CUP_E_BAD_MAGIC:            return {"not a CUP container (bad magic at offset 0)", "Expected CUP1/CUP2/CUP3. Check that this really is a .cup file."};
        case CUP_E_BAD_VERSION:          return {"unsupported format version", "Upgrade the toolchain, or rebuild the package with a supported --v1/--v2/--v3."};
        case CUP_E_BAD_FOOTER_MAGIC:     return {"footer magic 'CUPE' missing", "The end of the file is damaged or the file was appended to."};
        case CUP_E_LENGTH_MISMATCH:      return {"header and footer disagree about the file length", "The file was truncated or extended after it was built."};
        case CUP_E_HEADER_HASH_MISMATCH: return {"header does not match the footer seal", "The 128-byte header was modified after the package was built."};
        case CUP_E_RESERVED_NZ:          return {"reserved bits are set", "The package uses flags this toolchain does not know."};
        case CUP_E_BAD_TYPE:             return {"invalid section type", "The section table is corrupt."};
        case CUP_E_SECTION_OVERLAP:      return {"sections overlap, are out of order, or run past the file", "The section table is corrupt or hostile."};
        case CUP_E_BAD_SIGNATURE:        return {"a signature does not verify (manifest, certificate or timestamp)", "The package was modified after signing, or it was signed with a different key."};
        case CUP_E_UNLINKED_CHAIN:       return {"certificate chain does not link signer to root (or wrong key usage)", "The chain was re-ordered or a certificate is missing."};
        case CUP_E_UNTRUSTED_ROOT:       return {"signed by a key that is not trusted (root or timestamp authority)", "Provide your repository's keys with --trust-root <hex> and --tsa-key <hex>."};
        case CUP_E_REVOKED_KEY:          return {"a key in the chain is revoked", "Do not install this package; ask the publisher for a re-signed build."};
        case CUP_E_EXPIRED_CERT:         return {"a certificate was not valid at the signing timestamp", "The publisher's certificate expired; a re-signed build is needed."};
        case CUP_E_NAMESPACE_VIOLATION:  return {"package id is outside the namespace the signing certificate allows", "A key certified for one vendor cannot sign for another (CUP-ERR-003)."};
        case CUP_E_MERKLE_MISMATCH:      return {"payload does not match the signed Merkle root", "The package contents were swapped after signing."};
        default:                         return {cup_strerror(code), ""};
    }
}

inline Report verify_buffer(const std::vector<uint8_t> &buf, const Options &opt) {
    Report R;
    R.size = buf.size();
    const char *G1 = "Container", *G2 = "Authenticity", *G3 = "Integrity", *G4 = "Policy";

    if (buf.size() < CUP_MIN_FILE_SIZE) {
        R.add(G1, St::Fail, "file too small to be a CUP container", std::to_string(buf.size()) + " bytes", "CUP-ERR-001",
              "Is this really a .cup file? If it was downloaded, fetch it again.");
        return R;
    }
    const uint8_t *hdr = buf.data();
    const uint8_t *ftr = buf.data() + buf.size() - CUP_FOOTER_SIZE;
    int rc = cup_validate_header_and_footer(hdr, ftr, buf.size());
    if (rc != CUP_OK) {
        Why w = explain(rc);
        R.add(G1, St::Fail, w.what, cup_strerror(rc), "CUP-ERR-001", w.hint);
        return R;
    }
    R.major = (hdr[3] == '3') ? 3 : (hdr[3] == '2') ? 2 : 1;
    R.flags = cup_read_u32le(hdr + 8);
    R.abi_tag.assign(reinterpret_cast<const char *>(hdr + 64), 16);
    R.runtime_ref.assign(reinterpret_cast<const char *>(hdr + 80), 16);
    while (!R.abi_tag.empty() && (R.abi_tag.back() == ' ' || R.abi_tag.back() == 0)) R.abi_tag.pop_back();
    while (!R.runtime_ref.empty() && (R.runtime_ref.back() == ' ' || R.runtime_ref.back() == 0)) R.runtime_ref.pop_back();
    if (R.major >= 2) {
        R.hash_alg = hdr[96]; R.hdr_sig_alg = hdr[97]; R.comp_alg = hdr[98]; R.erofs_shift = hdr[99];
        R.min_kernel = cup_read_u32le(hdr + 100);
    }
    R.add(G1, St::Pass, "header [0..127] sealed by footer, length consistent", "CUP" + std::to_string(R.major), "CUP-ERR-001/012");

    uint32_t scount = cup_read_u32le(hdr + 20);
    auto cat = std::make_unique<struct cup_catalog>();
    std::memset(cat.get(), 0, sizeof(*cat));
    rc = cup_catalog_build_safe(buf.data() + CUP_HEADER_SIZE, scount, buf.size(), cat.get());
    if (rc != CUP_OK) {
        Why w = explain(rc);
        R.add(G1, St::Fail, w.what, cup_strerror(rc), "CUP-ERR-008", w.hint);
        return R;
    }
    for (size_t i = 0; i < cat->total_entries; i++) {
        const auto &e = cat->entries[i];
        SectionInfo si; si.type = e.type; si.flags = e.flags; si.off = e.offset; si.len = e.length;
        si.sha_hex = hex(e.sha256, 32);
        R.sections.push_back(si);
    }
    /* section digests */
    std::string bad;
    for (size_t i = 0; i < cat->total_entries; i++) {
        const auto &e = cat->entries[i];
        if (e.offset > buf.size() || e.length > buf.size() - e.offset) { bad += " #" + std::to_string(i) + "(range)"; continue; }
        uint8_t d[32];
        cup_sha256(buf.data() + e.offset, e.length, d);
        if (!cup_ct_memeq(d, e.sha256, 32)) bad += std::string(" #") + std::to_string(i) + "(" + section_name(e.type) + ")";
    }
    if (!bad.empty()) {
        R.add(G1, St::Fail, "section digest mismatch", bad, "CUP-ERR-008",
              "Section bytes differ from the table - the file is corrupt or was edited. Download it again.");
        return R;
    }
    R.add(G1, St::Pass, std::to_string(cat->total_entries) + " sections: bounds, order, no overlap, SHA-256 digests", "", "CUP-ERR-008");
    {
        /* section flags / lengths: this verifier only understands raw, unencrypted sections */
        std::string odd;
        for (size_t i = 0; i < cat->total_entries; i++) {
            const auto &e = cat->entries[i];
            if ((e.flags & CUP_SFLAG_RESERVED) || (e.flags & (CUP_SFLAG_COMPRESSED | CUP_SFLAG_ENCRYPTED | CUP_SFLAG_COMP_MASK)) || e.uncompressed_len != e.length)
                odd += " #" + std::to_string(i) + "(" + section_name(e.type) + ")";
        }
        if (!odd.empty()) {
            R.add(G1, St::Fail, "unsupported or unauthenticated section flags / sizes", odd, "CUP-ERR-005",
                  "Reserved, compressed or encrypted flags cannot be verified by this build; the table fields are not signed.");
            return R;
        }
        /* bytes that belong to no section (alignment gaps) are covered by nothing: they must be zero */
        std::vector<std::pair<uint64_t, uint64_t>> spans;
        for (size_t i = 0; i < cat->total_entries; i++) spans.push_back({cat->entries[i].offset, cat->entries[i].offset + cat->entries[i].length});
        std::sort(spans.begin(), spans.end());
        uint64_t pos = CUP_HEADER_SIZE + (uint64_t)cat->total_entries * CUP_SECTION_ENTRY_SIZE, endp = buf.size() - CUP_FOOTER_SIZE, dirty = 0;
        for (auto &sp2 : spans) {
            for (uint64_t k = pos; k < std::min<uint64_t>(sp2.first, endp); k++) if (buf[k]) dirty++;
            pos = std::max(pos, sp2.second);
        }
        for (uint64_t k = pos; k < endp; k++) if (buf[k]) dirty++;
        if (dirty) R.add(G1, St::Fail, "non-zero bytes between sections", std::to_string(dirty) + " byte(s) outside every signed section", "CUP-ERR-008",
                         "Gaps are covered by nothing, so they must be zero.");
    }

    auto count = [&](uint32_t t) -> unsigned { return t < 256 ? cat->count_by_type[t] : 0; };
    auto first = [&](uint32_t t) -> const struct cup_section_entry * { return count(t) ? &cat->entries[cat->first_idx_by_type[t]] : nullptr; };
    bool req_ok = true;
    for (uint32_t t : {CUP_SECT_MANIFEST, CUP_SECT_SIGNATURE}) {
        if (count(t) == 0) { R.add(G1, St::Fail, std::string("required ") + section_name(t) + " section is missing", "", "CUP-ERR-008", "Unsigned or incomplete package - it must not be installed."); req_ok = false; }
        else if (count(t) > 1) { R.add(G1, St::Fail, std::string("duplicate ") + section_name(t) + " sections (ambiguous)", std::to_string(count(t)) + " found", "CUP-ERR-008", "Exactly one is allowed; a second one can be used to confuse verifiers."); req_ok = false; }
    }
    if (!req_ok) return R;
    const auto *man = first(CUP_SECT_MANIFEST);
    const auto *sig = first(CUP_SECT_SIGNATURE);
    const auto *idx = first(CUP_SECT_INDEX);
    const auto *pay = first(CUP_SECT_PAYLOAD);
    const auto *ero = first(CUP_SECT_EROFS_IMAGE);
    const auto *fsv = first(CUP_SECT_FSVERITY);
    const auto *stub = first(CUP_SECT_ELF_BOOTSTRAP);

    /* header pointers must agree with the section table */
    {
        bool agree = cup_read_u64le(hdr + 32) == man->offset && cup_read_u64le(hdr + 40) == man->length;
        if (idx && cup_read_u64le(hdr + 48) != idx->offset) agree = false;
        if (pay && cup_read_u64le(hdr + 56) != pay->offset) agree = false;
        R.add(G1, agree ? St::Pass : St::Fail, agree ? "header offsets agree with the section table" : "header offsets disagree with the section table",
              "", "CUP-ERR-001", agree ? "" : "Header and table describe different layouts; refuse to guess which one is right.");
    }

    /* ---- manifest (strict JSON) ---- */
    R.manifest_text.assign(reinterpret_cast<const char *>(buf.data() + man->offset), man->length);
    std::string jerr;
    if (!cupjson::parse(R.manifest_text, R.manifest, jerr) || R.manifest.t != cupjson::Val::Obj) {
        R.add(G2, St::Fail, "manifest is not valid JSON", jerr, "CUP-ERR-029", "The signed manifest must be a strict JSON object.");
        return R;
    }
    {
        const auto *id = R.manifest.get("id");
        if (!id || id->t != cupjson::Val::Str || !valid_app_id(id->s)) {
            R.add(G2, St::Fail, "manifest has no valid top-level \"id\"", "", "CUP-ERR-003",
                  "The id decides which signing namespace applies, so it must be a reverse-DNS string such as org.vendor.App.");
            return R;
        }
        R.app_id = id->s;
        if (const auto *v = R.manifest.get("version")) if (v->t == cupjson::Val::Str) R.version = v->s;
        if (const auto *v = R.manifest.get("schema")) if (v->t == cupjson::Val::Str) R.schema = v->s;
        if (const auto *v = R.manifest.get("merkle_root")) if (v->t == cupjson::Val::Str) R.merkle_root = v->s;
        if (const auto *v = R.manifest.get("erofs_verity_root")) if (v->t == cupjson::Val::Str) R.erofs_root = v->s;
        if (const auto *v = R.manifest.get("chunk_count")) if (v->t == cupjson::Val::Num) R.chunk_count = (uint64_t)v->n;
    }

    /* ---- signature section: bounds first, copy second ---- */
    const uint8_t *sp = buf.data() + sig->offset;
    size_t sl = (size_t)sig->length;
    struct cup_signature_section ss;
    std::memset(&ss, 0, sizeof ss);
    if (sl < 208) {
        R.add(G2, St::Fail, "signature section too short", std::to_string(sl) + " bytes (need >= 208)", "CUP-ERR-008", "Truncated or forged signature section.");
        return R;
    }
    ss.sig_format_version = cup_read_u32le(sp);
    ss.sig_alg = sp[4];
    ss.chain_length = sp[5];
    ss.rekor_proof_len = (uint16_t)(sp[6] | (sp[7] << 8));
    if (ss.chain_length < 1 || ss.chain_length > 8) {
        R.add(G2, St::Fail, "certificate chain length out of range", "chain_length=" + std::to_string(ss.chain_length) + " (allowed 1..8)", "CUP-ERR-008",
              "Rejected before parsing - this field used to overflow a fixed-size buffer.");
        return R;
    }
    size_t chain_bytes = (size_t)ss.chain_length * CUP_CERT_SIZE;
    if (sl < 208 + chain_bytes) {
        R.add(G2, St::Fail, "signature section shorter than its certificate chain", std::to_string(sl) + " < " + std::to_string(208 + chain_bytes), "CUP-ERR-008");
        return R;
    }
    std::memcpy(ss.signer_pubkey, sp + 8, 32);
    std::memcpy(ss.ed25519_signature, sp + 40, 64);
    ss.tsa_timestamp = cup_read_u64le(sp + 104);
    std::memcpy(ss.tsa_pubkey, sp + 112, 32);
    std::memcpy(ss.tsa_signature, sp + 144, 64);
    std::memcpy(ss.chain, sp + 208, chain_bytes);
    R.sig_alg = ss.sig_alg; R.sig_format = ss.sig_format_version; R.tsa_ts = ss.tsa_timestamp;
    { uint8_t d[32]; cup_sha256(ss.signer_pubkey, 32, d); R.signer_fp = hex(d, 8); }
    for (unsigned i = 0; i < ss.chain_length; i++) {
        CertInfo ci; uint8_t d[32];
        cup_sha256(ss.chain[i].subject_pubkey, 32, d); ci.subject_fp = hex(d, 4);
        cup_sha256(ss.chain[i].issuer_pubkey, 32, d);  ci.issuer_fp = hex(d, 4);
        ci.prefix = std::string(ss.chain[i].allowed_prefix, strnlen(ss.chain[i].allowed_prefix, 16));
        ci.usage = ss.chain[i].usage_mask; ci.from = ss.chain[i].valid_from; ci.until = ss.chain[i].valid_until;
        R.chain.push_back(ci);
    }
    size_t exact = 208 + chain_bytes + (ss.sig_alg == 0x03 ? sizeof(struct cup_pq_hybrid_bundle) : 0);
    if (ss.sig_alg == 0x03 && sl < exact) {
        R.add(G2, St::Fail, "hybrid signature declared but the PQ bundle is truncated", std::to_string(sl) + " < " + std::to_string(exact), "CUP-ERR-020");
        return R;
    }
    if (ss.rekor_proof_len != (ss.sig_alg == 0x03 ? sizeof(struct cup_pq_hybrid_bundle) : 0)) {
        R.add(G2, St::Fail, "bundle length field is inconsistent with sig_alg", "rekor_proof_len=" + std::to_string(ss.rekor_proof_len), "CUP-ERR-018",
              "This field is not signed; it must match the algorithm exactly.");
        return R;
    }
    if (sl != exact) R.add(G2, St::Fail, "signature section has unauthenticated trailing bytes", std::to_string(sl - exact) + " extra", "CUP-ERR-018",
                           "Nothing covers these bytes.");
    if (R.major >= 2 && R.hdr_sig_alg != ss.sig_alg) {
        R.add(G2, St::Fail, "header sig_alg disagrees with the signature section", "header=" + std::to_string(R.hdr_sig_alg) + " section=" + std::to_string(ss.sig_alg), "CUP-ERR-020",
              "Possible downgrade (e.g. hybrid -> classical). Refuse and re-download.");
        return R;
    }

    /* ---- trust anchors ---- */
    DemoKeys dk;
    struct cup_root_keyring kr;
    std::memset(&kr, 0, sizeof kr);
    if (opt.builtin_roots) {
        std::memcpy(kr.root_pubkeys[kr.root_count++], dk.root_pub, 32);
        std::memcpy(kr.tsa_pubkeys[kr.tsa_count++], dk.tsa_pub, 32);
    }
    for (auto &k : opt.roots) if (kr.root_count < 16) std::memcpy(kr.root_pubkeys[kr.root_count++], k.data(), 32);
    for (auto &k : opt.tsa_keys) if (kr.tsa_count < 16) std::memcpy(kr.tsa_pubkeys[kr.tsa_count++], k.data(), 32);
    if (kr.root_count == 0) {
        R.add(G2, St::Fail, "no trust root configured", "", "CUP-ERR-003", "Pass --trust-root <64-hex-char Ed25519 key> (repeatable), or drop --no-builtin-root.");
        return R;
    }

    struct cup_manifest_view mv{buf.data() + man->offset, (size_t)man->length, R.app_id.c_str()};
    uint8_t msha[32];
    rc = cup_verify_signature_v2(&mv, &ss, &kr, msha);
    cup_sha256(buf.data() + man->offset, man->length, msha);
    R.manifest_sha_hex = hex(msha, 32);
    R.uri = "cup://sha256/" + R.manifest_sha_hex + "?id=" + R.app_id + (R.version.empty() ? "" : "&v=" + R.version);
    if (rc != CUP_OK) {
        Why w = explain(rc);
        R.add(G2, St::Fail, w.what, cup_strerror(rc), (rc == -CUP_E_NAMESPACE_VIOLATION || rc == -CUP_E_UNLINKED_CHAIN) ? "CUP-ERR-003" : "CUP-ERR-002", w.hint);
        return R;
    }
    R.add(G2, St::Pass, "manifest SHA-256 " + ui::short_hex(R.manifest_sha_hex), "", "CUP-ERR-002");
    R.add(G2, St::Pass, "Ed25519 signature (domain-separated) valid", "signer " + R.signer_fp, "CUP-ERR-020");
    {
        std::string c = "chain ";
        for (size_t i = 0; i < R.chain.size(); i++) c += (i ? " " + std::string(ui::g_arrow()) + " " : "") + R.chain[i].subject_fp;
        c += std::string(" ") + ui::g_arrow() + " root " + R.chain.back().issuer_fp;
        R.add(G2, St::Pass, "trust chain links signer to a trusted root", c, "CUP-ERR-003");
    }
    R.add(G2, St::Pass, "namespace '" + R.chain[0].prefix + "*' covers " + R.app_id, "", "CUP-ERR-003");
    {
        /* header flags and sig_alg are NOT inside the signed digest; the manifest therefore repeats them */
        const auto *mf = R.manifest.get("flags"); const auto *ma = R.manifest.get("sig_alg");
        if (mf && ma && mf->t == cupjson::Val::Num && ma->t == cupjson::Val::Num) {
            bool same = (uint32_t)mf->n == R.flags && (uint8_t)ma->n == ss.sig_alg && (R.major < 2 || (uint8_t)ma->n == R.hdr_sig_alg);
            if (same) R.add(G2, St::Pass, "header flags and sig_alg match the signed manifest", "flags 0x" + [&]{ char b[16]; std::snprintf(b, sizeof b, "%x", R.flags); return std::string(b); }(), "CUP-ERR-005");
            else {
                R.add(G2, St::Fail, "header flags / sig_alg differ from the signed manifest", "possible downgrade or flag stripping", "CUP-ERR-005",
                      "The unsigned header was edited after signing. Do not install.");
                return R;
            }
        } else {
            R.add(G2, opt.strict ? St::Fail : St::Warn, "manifest does not sign flags / sig_alg", "header can be edited undetected (e.g. hybrid -> classical)", "CUP-ERR-005",
                  "Rebuild with this toolchain; older packages cannot protect the header.");
        }
        if (stub) {
            uint8_t d[32]; cup_sha256(buf.data() + stub->offset, stub->length, d);
            const auto *ms = R.manifest.get("stub_sha256");
            if (ms && ms->t == cupjson::Val::Str && ct_streq(ms->s, hex(d, 32)))
                R.add(G2, St::Pass, "bootstrap stub digest matches the signed manifest", ui::short_hex(hex(d, 32)), "RFC §0.1(13)");
            else if (ms) {
                R.add(G2, St::Fail, "bootstrap stub differs from the signed manifest", "executable code was swapped", "RFC §0.1(13)", "Do not run this package.");
                return R;
            } else R.add(G2, opt.strict ? St::Fail : St::Warn, "embedded executable stub is not covered by the signature", "", "RFC §0.1(13)",
                         "Rebuild with this toolchain, or strip the stub.");
        }
    }
    {
        bool demo_root = false;
        if (opt.builtin_roots) {
            uint8_t last_issuer[32]; std::memcpy(last_issuer, ss.chain[ss.chain_length - 1].issuer_pubkey, 32);
            demo_root = cup_ct_memeq(last_issuer, dk.root_pub, 32) != 0;
        }
        R.used_demo_root = demo_root;
        if (demo_root)
            R.add(G2, St::Warn, "anchored in the built-in DEMO root", "its seed is public - anyone can mint packages this root accepts", "CUP-ERR-003",
                  "Fine for testing. For real use run with --trust-root <key> --tsa-key <key> --no-builtin-root.");
    }

    /* ---- hybrid PQ half ---- */
    if (ss.sig_alg == 0x03) {
        auto pq = std::make_unique<struct cup_pq_hybrid_bundle>();
        std::memcpy(pq.get(), sp + 208 + chain_bytes, sizeof(*pq));
        int prc = cup_verify_hybrid_pq_bundle(msha, ss.ed25519_signature, ss.signer_pubkey, pq.get());
        if (prc != CUP_OK) {
            Why w = explain(prc);
            R.add(G2, St::Fail, std::string("post-quantum half invalid: ") + w.what, cup_strerror(prc), "CUP-ERR-020", w.hint);
            return R;
        }
        R.add(G2, St::Warn, "ML-DSA-65 slot is structurally valid but NOT real FIPS 204", "reference construction (SHAKE256 over an Ed25519 anchor); the key is not certified by the chain",
              "libcup2.c", "Do not rely on it for post-quantum security. Treat this package as Ed25519-only.");
    } else if (opt.require_pq) {
        R.add(G4, St::Fail, "--require-pq: package carries no post-quantum half", "sig_alg=" + std::to_string(ss.sig_alg), "CUP-ERR-020", "Ask the publisher for a hybrid (sig_alg 3) build.");
    } else if (R.major == 3) {
        R.add(G4, St::Warn, "CUP3 package signed with classical Ed25519 only", "", "CUP-ERR-020");
    }
    if (opt.require_pq && ss.sig_alg == 0x03)
        R.add(G4, St::Fail, "--require-pq cannot be satisfied: no real ML-DSA-65 implementation in this build", "", "libcup2.c", "Link a FIPS 204 implementation (e.g. OpenSSL >= 3.5 or liboqs).");

    /* ---- payload / image binding to the SIGNED manifest ---- */
    {
        const auto *mr = R.manifest.get("merkle_root");
        bool has_data = (idx != nullptr) || (pay != nullptr);
        if (has_data) {
            if (!(idx && pay)) {
                R.add(G3, St::Fail, "INDEX and PAYLOAD must appear together", "", "CUP-ERR-004");
            } else if (idx->length == 0 || idx->length % sizeof(struct cup_chunk_desc) != 0 || idx->length / sizeof(struct cup_chunk_desc) > (1u << 20)) {
                R.add(G3, St::Fail, "INDEX length is not a whole number of chunk descriptors", std::to_string(idx->length) + " bytes", "CUP-ERR-004");
            } else {
                size_t n = (size_t)(idx->length / sizeof(struct cup_chunk_desc));
                std::vector<struct cup_chunk_desc> cd(n);
                std::memcpy(cd.data(), buf.data() + idx->offset, (size_t)idx->length);
                uint8_t halg = (R.hash_alg == CUP_HASH_ALG_BLAKE3) ? CUP_HASH_ALG_BLAKE3 : CUP_HASH_ALG_SHA256;
                uint64_t expect = 0; std::string why;
                for (size_t i = 0; i < n && why.empty(); i++) {
                    uint64_t ro = cd[i].payload_rel_offset, ul = cd[i].uncompressed_len;
                    if (ro != expect) why = "chunk " + std::to_string(i) + " is not contiguous";
                    else if (ul == 0 || cd[i].compressed_len != cd[i].uncompressed_len) why = "chunk " + std::to_string(i) + " uses a codec this build cannot verify";
                    else if (ro > pay->length || ul > pay->length - ro) why = "chunk " + std::to_string(i) + " runs past the payload";
                    else {
                        uint8_t leaf[32];
                        if (cup_hash_leaf_prefixed(halg, buf.data() + pay->offset + ro, (size_t)ul, leaf) != CUP_OK) why = "chunk " + std::to_string(i) + " could not be hashed";
                        else if (!cup_ct_memeq(leaf, cd[i].leaf_hash, 32)) why = "chunk " + std::to_string(i) + " hash differs from INDEX";
                    }
                    expect = ro + ul;
                }
                if (why.empty() && expect != pay->length) why = "payload has " + std::to_string(pay->length - expect) + " bytes not covered by any chunk";
                if (!why.empty()) {
                    R.add(G3, St::Fail, "payload does not match the INDEX", why, "CUP-ERR-004", "The payload was altered or appended to. Do not install.");
                } else {
                    R.add(G3, St::Pass, std::to_string(n) + " chunk" + (n == 1 ? "" : "s") + " hash-verified, payload fully covered", ui::human_bytes(pay->length), "CUP-ERR-004");
                    uint8_t root[32]; size_t depth = 0;
                    cup_merkle_build_root(halg, cd.data(), n, root, &depth);
                    std::string root_hex = hex(root, 32);
                    if (!mr) {
                        R.add(G3, opt.strict ? St::Fail : St::Warn, "manifest has no merkle_root: payload is not bound to the signature", "", "CUP-ERR-004",
                              "Without it an attacker can swap the payload and re-seal the section table.");
                    } else if (!ct_streq(mr->t == cupjson::Val::Str ? mr->s : std::string(), root_hex)) {
                        R.add(G3, St::Fail, "Merkle root differs from the one in the signed manifest", "computed " + ui::short_hex(root_hex), "CUP-ERR-004",
                              "The contents were swapped after signing. Do not install.");
                    } else {
                        R.add(G3, St::Pass, "Merkle root matches the signed manifest", ui::short_hex(root_hex) + " depth " + std::to_string(depth), "CUP-ERR-004");
                    }
                    if (R.chunk_count && R.chunk_count != n)
                        R.add(G3, St::Fail, "chunk_count in the signed manifest disagrees with INDEX", std::to_string(R.chunk_count) + " vs " + std::to_string(n), "CUP-ERR-004");
                }
            }
        } else if (mr) {
            R.add(G3, St::Fail, "manifest commits to a payload that is not in the file", "", "CUP-ERR-004");
        }
        if (ero) {
            uint8_t d[32]; cup_sha256(buf.data() + ero->offset, ero->length, d);
            std::string dh = hex(d, 32);
            if (R.erofs_root.empty()) {
                R.add(G3, opt.strict ? St::Fail : St::Warn, "manifest has no erofs_verity_root: image is not bound to the signature", "", "CUP-ERR-004");
            } else if (!ct_streq(R.erofs_root, dh)) {
                R.add(G3, St::Fail, "EROFS image differs from the digest in the signed manifest", "computed " + ui::short_hex(dh), "CUP-ERR-004", "The image was swapped after signing. Do not mount it.");
            } else {
                R.add(G3, St::Pass, "EROFS image digest matches the signed manifest", ui::human_bytes(ero->length) + " " + ui::short_hex(dh), "CUP-ERR-004");
            }
            if (fsv) {
                if (fsv->length < 32 || !cup_ct_memeq(buf.data() + fsv->offset, d, 32))
                    R.add(G3, St::Fail, "FSVERITY descriptor does not match the EROFS image", "", "CUP-ERR-004");
                else {
                    uint64_t dirty = 0;
                    for (uint64_t k = 32; k < fsv->length; k++) if (buf[fsv->offset + k]) dirty++;
                    if (dirty) R.add(G3, St::Fail, "FSVERITY section carries unauthenticated extra bytes", std::to_string(dirty) + " non-zero", "CUP-ERR-004");
                }
            }
        }
    }

    /* ---- flag / section consistency ---- */
    {
        bool inconsistent = false;
        auto need = [&](bool flag_set, const struct cup_section_entry *s, const char *flag, const char *sect, bool hard) {
            if (flag_set && !s) {
                R.add(G4, (hard || opt.strict) ? St::Fail : St::Warn, std::string("flag ") + flag + " set but no " + sect + " section", "", "CUP-ERR-005",
                      std::string("The signed header promises the ") + sect + " section, but it is not in the file. Rebuild the package.");
                inconsistent = true;
            }
        };
        need(R.flags & CUP_FLAG_EROFS_DIRECT, ero, "EROFS_DIRECT", "EROFS_IMAGE", true);
        need(R.flags & CUP_FLAG_FSVERITY_SEALED, fsv, "FSVERITY_SEALED", "FSVERITY", true);
        need(R.flags & CUP_FLAG_SELF_BOOTSTRAP, stub, "SELF_BOOTSTRAP", "ELF_BOOTSTRAP", true);
        for (auto &s : R.sections)
            if ((s.flags & CUP_SFLAG_PAGE_ALIGNED) && (s.off % 4096) != 0) {
                R.add(G4, St::Fail, std::string(section_name(s.type)) + " is flagged page-aligned but starts at " + std::to_string(s.off), "", "CUP-ERR-001"); inconsistent = true;
            }
        if (stub) {
            bool elf = stub->length >= 4 && buf[stub->offset] == 0x7F && buf[stub->offset + 1] == 'E' && buf[stub->offset + 2] == 'L' && buf[stub->offset + 3] == 'F';
            if (!elf) R.add(G4, St::Fail, "ELF_BOOTSTRAP section is not an ELF image", "", "CUP-ERR-005");
            else if (stub->length > 24 * 1024) R.add(G4, St::Warn, "bootstrap stub exceeds the 24 KiB budget", ui::human_bytes(stub->length), "RFC §0.1(13)");
            else R.add(G4, St::Pass, "self-bootstrap stub present (static ELF)", ui::human_bytes(stub->length), "RFC §0.1(13)");
        }
        if (!inconsistent && !stub)
            R.add(G4, St::Pass, "header flags are consistent with the sections present", "", "CUP-ERR-005");
    }
    return R;
}

/* a < b : -1, equal 0, a > b 1 ; numeric dotted compare, suffix after - or + ignored */
inline int version_cmp(const std::string &a, const std::string &b) {
    auto split = [](const std::string &s) {
        std::vector<long> v; size_t i = 0;
        while (i < s.size() && s[i] != '-' && s[i] != '+') {
            size_t j = i; while (j < s.size() && std::isdigit((unsigned char)s[j])) j++;
            v.push_back(j > i ? std::atol(s.substr(i, j - i).c_str()) : 0);
            while (j < s.size() && s[j] != '.' && s[j] != '-' && s[j] != '+') j++;
            i = (j < s.size() && s[j] == '.') ? j + 1 : j;
        }
        return v;
    };
    auto x = split(a), y = split(b);
    size_t n = std::max(x.size(), y.size());
    x.resize(n); y.resize(n);
    for (size_t i = 0; i < n; i++) if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1;
    return 0;
}

} // namespace cupv
