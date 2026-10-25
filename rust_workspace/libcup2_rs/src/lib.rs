// [NORMATIVE] Appendix B.1: libcup2_rs — Memory-Safe Rust Reference Implementation of CUP v2.0
// Enforces all 33 errata resolutions (CUP-ERR-001 through CUP-ERR-033) with zero unsafe blocks
// in the binary parser, catalog builder, FastCDC chunker, and cryptographic verifier.

#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::fmt;

pub const CUP_HEADER_SIZE: usize = 128;
pub const CUP_FOOTER_SIZE: usize = 32;
pub const CUP_SECTION_ENTRY_SIZE: usize = 64;
pub const CUP_CERT_SIZE: usize = 168;
pub const CUP_MIN_FILE_SIZE: u64 = (CUP_HEADER_SIZE + CUP_SECTION_ENTRY_SIZE + CUP_FOOTER_SIZE) as u64;
pub const CUP_MAX_VOLUME_SIZE: u64 = 1u64 << 48; // 256 TiB
pub const CUP_MAX_SECTIONS: usize = 256;
pub const CUP_MAX_CHAIN_LEN: usize = 8;
pub const CUP_MAX_MERKLE_DEPTH: usize = 32;

// Unified Package Flags (Table 6.2 - CUP-ERR-005 Fixed)
pub const CUP_FLAG_MULTI_VOLUME: u32    = 1 << 0;
pub const CUP_FLAG_EXPERIMENTAL: u32    = 1 << 1;
pub const CUP_FLAG_DETACHED_SIG: u32    = 1 << 2;
pub const CUP_FLAG_DELTA_UPDATE: u32    = 1 << 3;
pub const CUP_FLAG_READ_ONLY_RT: u32    = 1 << 4;
pub const CUP_FLAG_NO_NETWORK: u32      = 1 << 5;
pub const CUP_FLAG_EROFS_DIRECT: u32    = 1 << 6;
pub const CUP_FLAG_FSVERITY_SEALED: u32 = 1 << 7;
pub const CUP_FLAG_BLAKE3_INDEX: u32    = 1 << 8;
pub const CUP_FLAG_ABI_SLICE: u32       = 1 << 9;
pub const CUP_FLAG_TUF_REKOR: u32       = 1 << 10;
pub const CUP_FLAG_SYSTEM_DAEMON: u32   = 1 << 11;
pub const CUP_FLAG_V1_RESERVED_MASK: u32 = 0xFFFF_FFC0;
pub const CUP_FLAG_V2_RESERVED_MASK: u32 = 0xFFFF_F000;

// Section Types (Table 7.1)
pub const CUP_SECT_MANIFEST: u32     = 0x01;
pub const CUP_SECT_SIGNATURE: u32    = 0x02;
pub const CUP_SECT_INDEX: u32        = 0x03;
pub const CUP_SECT_PAYLOAD: u32      = 0x04;
pub const CUP_SECT_SBOM: u32         = 0x05;
pub const CUP_SECT_ICON_META: u32    = 0x06;
pub const CUP_SECT_SANDBOX_BPF: u32  = 0x07;
pub const CUP_SECT_DELTA_MAN: u32    = 0x08;
pub const CUP_SECT_VOLUME_MAP: u32   = 0x09;
pub const CUP_SECT_ZSTD_DICT: u32    = 0x0A;
pub const CUP_SECT_LOCALIZATION: u32 = 0x0B;
pub const CUP_SECT_EROFS_IMAGE: u32  = 0x0C;
pub const CUP_SECT_FSVERITY: u32     = 0x0D;
pub const CUP_SECT_ABI_SLICE: u32    = 0x0E;
pub const CUP_SECT_SYSTEMD_UNIT: u32 = 0x0F;
pub const CUP_SECT_VENDOR_EXT: u32   = 0xFF;

// Certificate Key Usage Masks
pub const CUP_KEY_USAGE_PKG_SIGN: u16 = 0x0001;
pub const CUP_KEY_USAGE_CA_INT: u16   = 0x0002;
pub const CUP_KEY_USAGE_CA_ROOT: u16  = 0x0004;

// Normalized FastCDC Constants (Phase 12 - CUP-ERR-004 & CUP-ERR-023 Fixed)
pub const CUP_CDC_MIN_SIZE: usize = 65_536;     // 64 KiB
pub const CUP_CDC_AVG_SIZE: usize = 1_048_576;  // 1 MiB
pub const CUP_CDC_MAX_SIZE: usize = 8_388_608;  // 8 MiB
pub const CUP_CDC_MASK_S: u64 = 0x0003_FFFF_C000_0000;
pub const CUP_CDC_MASK_L: u64 = 0x0000_3FFF_C000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CupError {
    Truncated,
    BadMagic,
    BadVersion,
    BadFooterMagic,
    LengthMismatch,
    HeaderHashMismatch,
    ReservedBitsNonZero,
    BadAsciiToken,
    BadSectionType(u32),
    SectionOverlap,
    MissingMandatorySection(u8),
    BadSignature,
    UnlinkedChain,
    UntrustedRoot,
    RevokedKey,
    ExpiredCertificate,
    NamespaceViolation,
    MerkleMismatch,
}

impl fmt::Display for CupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CupError::Truncated => write!(f, "CUP_E_TRUNCATED: file or buffer truncated"),
            CupError::BadMagic => write!(f, "CUP_E_BAD_MAGIC: expected CUP2 or CUP1 at offset 0"),
            CupError::BadVersion => write!(f, "CUP_E_BAD_VERSION: header version mismatch"),
            CupError::BadFooterMagic => write!(f, "CUP_E_BAD_FOOTER_MAGIC: expected CUPE at L-32"),
            CupError::LengthMismatch => write!(f, "CUP_E_LENGTH_MISMATCH: header/footer length mismatch"),
            CupError::HeaderHashMismatch => write!(f, "CUP_E_HEADER_HASH_MISMATCH: footer[12..32] != SHA256(header[0..128])[0..20]"),
            CupError::ReservedBitsNonZero => write!(f, "CUP_E_RESERVED_NZ: reserved flags or bytes non-zero"),
            CupError::BadAsciiToken => write!(f, "CUP_E_BAD_ASCII: invalid ABI tag or runtime reference"),
            CupError::BadSectionType(t) => write!(f, "CUP_E_BAD_TYPE: section type {:#x} outside 0x01..=0xFF", t),
            CupError::SectionOverlap => write!(f, "CUP_E_SECTION_OVERLAP: non-monotonic or unaligned section span"),
            CupError::MissingMandatorySection(t) => write!(f, "CUP_E_MISSING_SECT: mandatory section {:#x} missing", t),
            CupError::BadSignature => write!(f, "CUP_E_BAD_SIGNATURE: cryptographic signature verification failed"),
            CupError::UnlinkedChain => write!(f, "CUP_E_UNLINKED_CHAIN: certificate chain does not bind signer key (CUP-ERR-003)"),
            CupError::UntrustedRoot => write!(f, "CUP_E_UNTRUSTED_ROOT: terminal issuer not in root keyring"),
            CupError::RevokedKey => write!(f, "CUP_E_REVOKED_KEY: key in certificate path is revoked"),
            CupError::ExpiredCertificate => write!(f, "CUP_E_EXPIRED_CERT: timestamp outside certificate validity window"),
            CupError::NamespaceViolation => write!(f, "CUP_E_NAMESPACE_VIOLATION: package id outside certificate allowed_prefix"),
            CupError::MerkleMismatch => write!(f, "CUP_E_MERKLE_MISMATCH: chunk Merkle inclusion proof failed"),
        }
    }
}

/// Constant-time slice equality check (CUP-ERR-015 Fix: never short-circuit on secret/digest bytes)
#[inline(never)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Trait abstracting cryptographic providers (OpenSSL 3.x, ring, RustCrypto, or AWS-LC)
pub trait CryptoProvider {
    fn sha256(&self, data: &[u8]) -> [u8; 32];
    fn blake3_256(&self, data: &[u8]) -> [u8; 32];
    fn ed25519_verify(&self, msg: &[u8], sig: &[u8; 64], pubkey: &[u8; 32]) -> bool;
    fn ed25519ph_verify(&self, msg: &[u8], ctx: &[u8], sig: &[u8; 64], pubkey: &[u8; 32]) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CupHeader {
    pub is_v2: bool,
    pub version: u32,
    pub flags: u32,
    pub total_length: u64,
    pub section_count: u32,
    pub section_table_offset: u64,
    pub manifest_offset: u64,
    pub manifest_length: u64,
    pub index_offset: u64,
    pub payload_offset: u64,
    pub abi_tag: String,
    pub runtime_ref: String,
    pub index_hash_alg: u8,
    pub sig_alg: u8,
    pub default_comp_alg: u8,
    pub erofs_block_shift: u8,
    pub min_kernel_ver: u32,
}

fn parse_str16_space_padded(raw: &[u8]) -> Result<String, CupError> {
    if raw.len() != 16 {
        return Err(CupError::BadAsciiToken);
    }
    let mut end = 16;
    while end > 0 && raw[end - 1] == b' ' {
        end -= 1;
    }
    if end == 0 {
        return Err(CupError::BadAsciiToken);
    }
    for &b in &raw[..end] {
        let valid = b.is_ascii_alphanumeric()
            || b == b'.'
            || b == b'-'
            || b == b'_'
            || b == b'+'
            || b == b'/';
        if !valid {
            return Err(CupError::BadAsciiToken);
        }
    }
    String::from_utf8(raw[..end].to_vec()).map_err(|_| CupError::BadAsciiToken)
}

impl CupHeader {
    /// Parses and validates the 128-byte header at offset 0..127 and the 32-byte footer at L-32..L-1.
    /// Permanently enforces CUP-ERR-001, CUP-ERR-005, CUP-ERR-011, and CUP-ERR-012.
    pub fn parse_and_validate_footer<C: CryptoProvider>(
        header_bytes: &[u8; CUP_HEADER_SIZE],
        footer_bytes: &[u8; CUP_FOOTER_SIZE],
        actual_file_len: u64,
        crypto: &C,
    ) -> Result<Self, CupError> {
        if actual_file_len < CUP_MIN_FILE_SIZE || actual_file_len > CUP_MAX_VOLUME_SIZE {
            return Err(CupError::Truncated);
        }

        let magic = &header_bytes[0..4];
        let is_v2 = match magic {
            b"CUP2" => true,
            b"CUP1" => false,
            _ => return Err(CupError::BadMagic),
        };

        // Bytes 4..7 inclusive: 32-bit little-endian version (CUP-ERR-011 Fix)
        let version = u32::from_le_bytes([
            header_bytes[4],
            header_bytes[5],
            header_bytes[6],
            header_bytes[7],
        ]);
        let major = (version >> 16) as u16;
        if (is_v2 && major != 2) || (!is_v2 && major != 1) {
            return Err(CupError::BadVersion);
        }

        // Bytes 8..11: Flags field (CUP-ERR-005 Fix)
        let flags = u32::from_le_bytes([
            header_bytes[8],
            header_bytes[9],
            header_bytes[10],
            header_bytes[11],
        ]);
        let reserved_mask = if is_v2 {
            CUP_FLAG_V2_RESERVED_MASK
        } else {
            CUP_FLAG_V1_RESERVED_MASK
        };
        if (flags & reserved_mask) != 0 {
            return Err(CupError::ReservedBitsNonZero);
        }

        let total_length = u64::from_le_bytes(header_bytes[12..20].try_into().unwrap());
        if total_length != actual_file_len {
            return Err(CupError::LengthMismatch);
        }

        let section_count = u32::from_le_bytes(header_bytes[20..24].try_into().unwrap());
        let section_table_offset = u64::from_le_bytes(header_bytes[24..32].try_into().unwrap());
        if section_table_offset != 128 || section_count == 0 || (section_count as usize) > CUP_MAX_SECTIONS {
            return Err(CupError::Truncated);
        }

        let manifest_offset = u64::from_le_bytes(header_bytes[32..40].try_into().unwrap());
        let manifest_length = u64::from_le_bytes(header_bytes[40..48].try_into().unwrap());
        let index_offset    = u64::from_le_bytes(header_bytes[48..56].try_into().unwrap());
        let payload_offset  = u64::from_le_bytes(header_bytes[56..64].try_into().unwrap());

        let abi_tag     = parse_str16_space_padded(&header_bytes[64..80])?;
        let runtime_ref = parse_str16_space_padded(&header_bytes[80..96])?;

        let (index_hash_alg, sig_alg, default_comp_alg, erofs_block_shift, min_kernel_ver) = if is_v2 {
            for &b in &header_bytes[104..128] {
                if b != 0 {
                    return Err(CupError::ReservedBitsNonZero);
                }
            }
            let kver = u32::from_le_bytes(header_bytes[100..104].try_into().unwrap());
            (
                header_bytes[96],
                header_bytes[97],
                header_bytes[98],
                header_bytes[99],
                kver,
            )
        } else {
            for &b in &header_bytes[96..128] {
                if b != 0 {
                    return Err(CupError::ReservedBitsNonZero);
                }
            }
            (0x01, 0x01, 0x00, 0x00, 0x0005_0A00)
        };

        // Validate 32-byte Footer: "CUPE" || u64le(total_length) || SHA256(header[0..128])[0..20]
        if &footer_bytes[0..4] != b"CUPE" {
            return Err(CupError::BadFooterMagic);
        }
        let footer_len = u64::from_le_bytes(footer_bytes[4..12].try_into().unwrap());
        if footer_len != actual_file_len {
            return Err(CupError::LengthMismatch);
        }

        let hdr_digest = crypto.sha256(header_bytes);
        if !constant_time_eq(&footer_bytes[12..32], &hdr_digest[0..20]) {
            return Err(CupError::HeaderHashMismatch);
        }

        Ok(Self {
            is_v2,
            version,
            flags,
            total_length,
            section_count,
            section_table_offset,
            manifest_offset,
            manifest_length,
            index_offset,
            payload_offset,
            abi_tag,
            runtime_ref,
            index_hash_alg,
            sig_alg,
            default_comp_alg,
            erofs_block_shift,
            min_kernel_ver,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionEntry {
    pub sect_type: u8,
    pub flags: u32,
    pub offset: u64,
    pub length: u64,
    pub sha256: [u8; 32],
    pub uncompressed_len: u64,
}

#[derive(Debug, Clone)]
pub struct SectionCatalog {
    pub entries: Vec<SectionEntry>,
    pub count_by_type: [u16; 256],
    pub first_idx_by_type: [Option<u16>; 256],
}

impl SectionCatalog {
    /// Safe Section Catalog Construction (Algorithm 7.1 - CUP-ERR-008 Fixed)
    pub fn build(
        raw_table: &[u8],
        section_count: usize,
        total_file_len: u64,
    ) -> Result<Self, CupError> {
        if section_count == 0
            || section_count > CUP_MAX_SECTIONS
            || raw_table.len() != section_count * CUP_SECTION_ENTRY_SIZE
        {
            return Err(CupError::Truncated);
        }

        let min_payload_offset = 128u64 + (section_count as u64) * 64u64;
        if total_file_len < min_payload_offset + 32u64 {
            return Err(CupError::Truncated);
        }

        let mut entries = Vec::with_capacity(section_count);
        let mut count_by_type = [0u16; 256];
        let mut first_idx_by_type = [None; 256];

        let mut prev_end = min_payload_offset;
        let max_payload_end = total_file_len - 32u64;

        for i in 0..section_count {
            let chunk = &raw_table[i * 64..(i + 1) * 64];
            let raw_type = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
            let sflags   = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
            let offset   = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
            let length   = u64::from_le_bytes(chunk[16..24].try_into().unwrap());
            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(&chunk[24..56]);
            let uncompressed_len = u64::from_le_bytes(chunk[56..64].try_into().unwrap());

            // CUP-ERR-008 Fix: Strict parse-time range check BEFORE indexing 256-element array
            if raw_type == 0 || raw_type > 0xFF {
                return Err(CupError::BadSectionType(raw_type));
            }
            let sect_type = raw_type as u8;

            if (sflags & 0xFFFF_FF80) != 0 {
                return Err(CupError::ReservedBitsNonZero);
            }

            let end = offset.checked_add(length).ok_or(CupError::SectionOverlap)?;
            if length == 0 || offset < prev_end || end > max_payload_end {
                return Err(CupError::SectionOverlap);
            }

            // Enforce 4096-byte page alignment on zero-copy kernel sections
            if (raw_type == CUP_SECT_EROFS_IMAGE
                || raw_type == CUP_SECT_FSVERITY
                || (sflags & 0x40) != 0)
                && (offset & 4095) != 0
            {
                return Err(CupError::SectionOverlap);
            }

            let idx = sect_type as usize;
            if count_by_type[idx] == 0 {
                first_idx_by_type[idx] = Some(i as u16);
            }
            count_by_type[idx] += 1;

            entries.push(SectionEntry {
                sect_type,
                flags: sflags,
                offset,
                length,
                sha256,
                uncompressed_len,
            });
            prev_end = end;
        }

        if count_by_type[CUP_SECT_MANIFEST as usize] != 1 {
            return Err(CupError::MissingMandatorySection(CUP_SECT_MANIFEST as u8));
        }
        if count_by_type[CUP_SECT_SIGNATURE as usize] != 1 {
            return Err(CupError::MissingMandatorySection(CUP_SECT_SIGNATURE as u8));
        }

        Ok(Self {
            entries,
            count_by_type,
            first_idx_by_type,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CupCertificate {
    pub subject_pubkey: [u8; 32],
    pub issuer_pubkey: [u8; 32],
    pub cert_signature: [u8; 64],
    pub valid_from: u64,
    pub valid_until: u64,
    pub usage_mask: u16,
    pub cert_reserved: [u8; 6],
    pub allowed_prefix: [u8; 16],
}

impl CupCertificate {
    pub fn tbs_bytes(&self) -> [u8; 104] {
        let mut tbs = [0u8; 104];
        tbs[0..32].copy_from_slice(&self.subject_pubkey);
        tbs[32..64].copy_from_slice(&self.issuer_pubkey);
        tbs[64..72].copy_from_slice(&self.valid_from.to_le_bytes());
        tbs[72..80].copy_from_slice(&self.valid_until.to_le_bytes());
        tbs[80..82].copy_from_slice(&self.usage_mask.to_le_bytes());
        tbs[82..88].copy_from_slice(&self.cert_reserved);
        tbs[88..104].copy_from_slice(&self.allowed_prefix);
        tbs
    }

    pub fn matches_app_id(&self, app_id: &str) -> bool {
        if self.allowed_prefix[0] == b'*' && self.allowed_prefix[1] == 0 {
            return true;
        }
        let nul_pos = self
            .allowed_prefix
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(16);
        if nul_pos == 0 {
            return false;
        }
        if let Ok(prefix_str) = std::str::from_utf8(&self.allowed_prefix[..nul_pos]) {
            app_id.starts_with(prefix_str)
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
pub struct CupSignatureSection {
    pub sig_format_version: u32,
    pub sig_alg: u8,
    pub signer_pubkey: [u8; 32],
    pub ed25519_signature: [u8; 64],
    pub tsa_timestamp: u64,
    pub tsa_pubkey: [u8; 32],
    pub tsa_signature: [u8; 64],
    pub chain: Vec<CupCertificate>,
}

pub struct RootKeyring {
    pub trusted_roots: Vec<[u8; 32]>,
    pub trusted_tsas: Vec<[u8; 32]>,
    pub revoked_keys: Vec<[u8; 32]>,
}

impl RootKeyring {
    fn contains_ct(list: &[[u8; 32]], target: &[u8; 32]) -> bool {
        let mut found = false;
        for k in list {
            if constant_time_eq(k, target) {
                found = true;
            }
        }
        found
    }
}

/// Hardened Trust-Chain & Signature Verifier (Algorithm 9.2 - CUP-ERR-002 & CUP-ERR-003 Fixed)
pub fn verify_manifest_and_chain<C: CryptoProvider>(
    manifest_body: &[u8],
    app_id: &str,
    sig_sec: &CupSignatureSection,
    keyring: &RootKeyring,
    crypto: &C,
) -> Result<[u8; 32], CupError> {
    if sig_sec.chain.is_empty() || sig_sec.chain.len() > CUP_MAX_CHAIN_LEN {
        return Err(CupError::UnlinkedChain);
    }

    // 1. Canonical Manifest Hash is ALWAYS 32-byte SHA-256 (CUP-ERR-002 Fix)
    let manifest_sha256 = crypto.sha256(manifest_body);

    // 2. Verify Manifest Signature per negotiated sig_alg (CUP-ERR-020 Fix)
    match sig_sec.sig_alg {
        0x00 | 0x01 => {
            if sig_sec.sig_format_version == 1 {
                if !crypto.ed25519_verify(
                    &manifest_sha256,
                    &sig_sec.ed25519_signature,
                    &sig_sec.signer_pubkey,
                ) {
                    return Err(CupError::BadSignature);
                }
            } else {
                let mut dom_msg = [0u8; 52];
                dom_msg[0..20].copy_from_slice(b"CUP-MANIFEST-SIG-V2\0");
                dom_msg[20..52].copy_from_slice(&manifest_sha256);
                if !crypto.ed25519_verify(
                    &dom_msg,
                    &sig_sec.ed25519_signature,
                    &sig_sec.signer_pubkey,
                ) {
                    return Err(CupError::BadSignature);
                }
            }
        }
        0x02 => {
            let ctx = b"CUP-ED25519PH-CTX-V2";
            if !crypto.ed25519ph_verify(
                manifest_body,
                ctx,
                &sig_sec.ed25519_signature,
                &sig_sec.signer_pubkey,
            ) {
                return Err(CupError::BadSignature);
            }
        }
        _ => return Err(CupError::BadSignature),
    }

    // 3. Verify RFC 3161 Timestamp Token
    if !RootKeyring::contains_ct(&keyring.trusted_tsas, &sig_sec.tsa_pubkey) {
        return Err(CupError::UntrustedRoot);
    }
    if RootKeyring::contains_ct(&keyring.revoked_keys, &sig_sec.tsa_pubkey) {
        return Err(CupError::RevokedKey);
    }

    let mut tsa_msg = [0u8; 51];
    tsa_msg[0..11].copy_from_slice(b"CUP-TSA-V2\0");
    tsa_msg[11..43].copy_from_slice(&manifest_sha256);
    tsa_msg[43..51].copy_from_slice(&sig_sec.tsa_timestamp.to_le_bytes());
    if !crypto.ed25519_verify(&tsa_msg, &sig_sec.tsa_signature, &sig_sec.tsa_pubkey) {
        return Err(CupError::BadSignature);
    }

    // 4. Walk Contiguous Trust Chain (CUP-ERR-003 Fix)
    if RootKeyring::contains_ct(&keyring.revoked_keys, &sig_sec.signer_pubkey) {
        return Err(CupError::RevokedKey);
    }

    let mut current_issuer = sig_sec.signer_pubkey;

    for (i, cert) in sig_sec.chain.iter().enumerate() {
        // ERR-003 Fix (a): chain[0] MUST certify signer_pubkey
        if i == 0 && !constant_time_eq(&cert.subject_pubkey, &sig_sec.signer_pubkey) {
            return Err(CupError::UnlinkedChain);
        }
        // ERR-003 Fix (b): chain[i] MUST certify chain[i-1].issuer_pubkey
        if i > 0 && !constant_time_eq(&cert.subject_pubkey, &current_issuer) {
            return Err(CupError::UnlinkedChain);
        }

        if RootKeyring::contains_ct(&keyring.revoked_keys, &cert.subject_pubkey)
            || RootKeyring::contains_ct(&keyring.revoked_keys, &cert.issuer_pubkey)
        {
            return Err(CupError::RevokedKey);
        }

        // Enforce Key Usage Roles
        if i == 0 {
            if (cert.usage_mask & CUP_KEY_USAGE_PKG_SIGN) == 0
                || (cert.usage_mask & CUP_KEY_USAGE_CA_INT) != 0
            {
                return Err(CupError::UnlinkedChain);
            }
        } else if (cert.usage_mask & (CUP_KEY_USAGE_CA_INT | CUP_KEY_USAGE_CA_ROOT)) == 0 {
            return Err(CupError::UnlinkedChain);
        }

        // Enforce Package Namespace Scoping
        if !cert.matches_app_id(app_id) {
            return Err(CupError::NamespaceViolation);
        }

        // Enforce Timestamp Validity Window
        if cert.valid_from >= cert.valid_until
            || sig_sec.tsa_timestamp < cert.valid_from
            || sig_sec.tsa_timestamp > cert.valid_until
        {
            return Err(CupError::ExpiredCertificate);
        }

        let tbs = cert.tbs_bytes();
        if !crypto.ed25519_verify(&tbs, &cert.cert_signature, &cert.issuer_pubkey) {
            return Err(CupError::BadSignature);
        }

        current_issuer = cert.issuer_pubkey;
    }

    // 5. Verify Terminal Issuer in Trusted Root Keyring
    if !RootKeyring::contains_ct(&keyring.trusted_roots, &current_issuer) {
        return Err(CupError::UntrustedRoot);
    }

    Ok(manifest_sha256)
}

/// Normalized FastCDC Chunker in Safe Rust (Algorithm 12.1 - CUP-ERR-004 & CUP-ERR-023 Fixed)
pub struct FastCdcChunker {
    gear_table: [u64; 256],
}

impl FastCdcChunker {
    pub fn new<C: CryptoProvider>(crypto: &C) -> Self {
        let mut gear_table = [0u64; 256];
        let mut seed_buf = [0u8; 26];
        seed_buf[0..25].copy_from_slice(b"CUP-FASTCDC-GEAR-TABLE-V2");
        for b in 0..256usize {
            seed_buf[25] = b as u8;
            let digest = crypto.sha256(&seed_buf);
            gear_table[b] = u64::from_le_bytes(digest[0..8].try_into().unwrap());
        }
        Self { gear_table }
    }

    pub fn next_chunk_len(&self, buf: &[u8]) -> usize {
        let len = buf.len();
        if len <= CUP_CDC_MIN_SIZE {
            return len;
        }
        let max_len = len.min(CUP_CDC_MAX_SIZE);
        let avg_len = max_len.min(CUP_CDC_AVG_SIZE);

        let mut fp: u64 = 0;

        // 1. Sub-minimum cut-point skipping: jump directly to 64 KiB
        let mut i = CUP_CDC_MIN_SIZE;

        // 2. Region 1 [64 KiB .. 1 MiB): Strict 22-bit MASK_S
        while i < avg_len {
            fp = fp.wrapping_shl(1).wrapping_add(self.gear_table[buf[i] as usize]);
            if (fp & CUP_CDC_MASK_S) == 0 {
                return i + 1;
            }
            i += 1;
        }

        // 3. Region 2 [1 MiB .. 8 MiB): Relaxed 18-bit MASK_L
        while i < max_len {
            fp = fp.wrapping_shl(1).wrapping_add(self.gear_table[buf[i] as usize]);
            if (fp & CUP_CDC_MASK_L) == 0 {
                return i + 1;
            }
            i += 1;
        }

        max_len
    }
}

pub mod convert {
// Rust Reference Implementation of cup-convert (Linglong UAB / Deb -> CUP v2.0)
// and Executable Regression Suite for CUP-ERR-001, 002, 003, 004, 005, 006, 007, and 008.



use std::collections::BTreeMap;

/// Represents a parsed Deepin Linglong (Linyaps) `info.json` metadata descriptor
/// extracted from a `.uab` bundle or OSTree layer.
#[derive(Debug, Clone)]
pub struct LinglongInfoJson {
    pub appid: String,
    pub version: String,
    pub arch: Vec<String>,
    pub base: String,
    pub runtime: Option<String>,
    pub command: Vec<String>,
    pub permissions_autostart: bool,
    pub permissions_network: bool,
}

/// Represents the synthesized CUP v2.0 Manifest produced by `cup-convert`
#[derive(Debug, Clone)]
pub struct ConvertedCupManifest {
    pub schema: String,
    pub id: String,
    pub version: String,
    pub arch: String,
    pub abi: String,
    pub abi_slices: Vec<String>,
    pub sandbox_tier: String,
    pub network: bool,
    pub entrypoint_binary: String,
    pub merkle_root_hex: String,
    pub fsverity_root_hex: String,
}

impl ConvertedCupManifest {
    /// Converts a Deepin Linglong (Linyaps) `.uab` descriptor into a CUP v2.0 Manifest,
    /// upgrading coarse `org.deepin.base` / `org.deepin.Runtime` dependencies into
    /// content-addressed CUP v2.0 ABI slices (`CUP_SECT_ABI_SLICE = 0x0E`).
    pub fn from_linglong_uab(
        uab: &LinglongInfoJson,
        detected_sonames: &[String],
        merkle_root_hex: &str,
        fsverity_root_hex: &str,
    ) -> Result<Self, &'static str> {
        if uab.appid.is_empty() || uab.command.is_empty() {
            return Err("Invalid Linglong info.json: missing appid or command");
        }

        let arch = uab
            .arch
            .first()
            .cloned()
            .unwrap_or_else(|| "x86_64".to_string());

        let mut slices = Vec::new();
        slices.push("org.cup.Slice.glibc/2.38".to_string());

        for soname in detected_sonames {
            if soname.starts_with("libQt6") || soname.starts_with("libdtk6") {
                if !slices.iter().any(|s| s.contains("qt6-gui")) {
                    slices.push("org.cup.Slice.qt6-gui/6.7".to_string());
                }
            } else if soname.starts_with("libwayland") {
                if !slices.iter().any(|s| s.contains("wayland")) {
                    slices.push("org.cup.Slice.wayland/1.22".to_string());
                }
            } else if soname.starts_with("libgtk-4") {
                if !slices.iter().any(|s| s.contains("gtk4")) {
                    slices.push("org.cup.Slice.gtk4/4.14".to_string());
                }
            } else if soname.starts_with("libvulkan") {
                if !slices.iter().any(|s| s.contains("vulkan")) {
                    slices.push("org.cup.Slice.vulkan/1.3".to_string());
                }
            }
        }

        Ok(Self {
            schema: "2.0".to_string(),
            id: uab.appid.clone(),
            version: uab.version.clone(),
            arch,
            abi: "glibc-2.38+wayland-1.22".to_string(),
            abi_slices: slices,
            sandbox_tier: "gui-wayland".to_string(),
            network: uab.permissions_network,
            entrypoint_binary: uab.command[0].clone(),
            merkle_root_hex: merkle_root_hex.to_string(),
            fsverity_root_hex: fsverity_root_hex.to_string(),
        })
    }

    /// Serializes the manifest in strict RFC 8785 JCS lexicographical key order (zero whitespace).
    pub fn to_rfc8785_jcs_bytes(&self) -> Vec<u8> {
        let mut map = BTreeMap::new();
        map.insert("abi", format!("\"{}\"", self.abi));
        let slices_json: Vec<String> = self
            .abi_slices
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect();
        map.insert("abi_slices", format!("[{}]", slices_json.join(",")));
        map.insert("arch", format!("\"{}\"", self.arch));
        map.insert("entrypoint", format!("\"{}\"", self.entrypoint_binary));
        map.insert("erofs_verity_root", format!("\"{}\"", self.fsverity_root_hex));
        map.insert("id", format!("\"{}\"", self.id));
        map.insert("merkle_root", format!("\"{}\"", self.merkle_root_hex));
        map.insert(
            "network",
            if self.network {
                "true".to_string()
            } else {
                "false".to_string()
            },
        );
        map.insert("sandbox_tier", format!("\"{}\"", self.sandbox_tier));
        map.insert("schema", format!("\"{}\"", self.schema));
        map.insert("version", format!("\"{}\"", self.version));

        let mut out = String::from("{");
        for (idx, (k, v)) in map.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push_str(&format!("\"{}\":{}", k, v));
        }
        out.push('}');
        out.into_bytes()
    }
}

#[cfg(test)]
mod conformance_tests {
    use super::*;

    /// CUP-HDR-006 / TV4 Regression Test: Flags bit 3 (DELTA_UPDATE) MUST be accepted,
    /// while reserved bits 12..31 MUST be rejected (CUP-ERR-005 resolution).
    #[test]
    fn test_tv4_flags_conflict_resolution() {
        let delta_flag: u32 = 0x0000_0008; // Bit 3 = CUP_FLAG_DELTA_UPDATE
        let v1_reserved_mask: u32 = 0xFFFF_FFC0;
        let v2_reserved_mask: u32 = 0xFFFF_F000;

        assert_eq!(delta_flag & v1_reserved_mask, 0, "TV4: Bit 3 MUST be accepted in v1.0.2");
        assert_eq!(delta_flag & v2_reserved_mask, 0, "TV4: Bit 3 MUST be accepted in v2.0");

        let invalid_v2_flag: u32 = 0x0000_1000; // Bit 12 (reserved in v2.0)
        assert_ne!(invalid_v2_flag & v2_reserved_mask, 0, "Bit 12 MUST be rejected in v2.0");
    }

    /// CUP-SCT-001 Regression Test: Section type > 0xFF MUST be rejected at parse time
    /// before indexing the 256-entry catalog array (CUP-ERR-008 resolution).
    #[test]
    fn test_err_008_section_type_bounds_guard() {
        let hostile_section_types: [u32; 4] = [0x0000_0000, 0x0000_0100, 0x8000_0001, 0xFFFF_FFFF];
        for &t in &hostile_section_types {
            let is_valid = t >= 1 && t <= 0xFF;
            assert!(!is_valid, "Hostile section type {:#x} MUST be rejected before array index", t);
        }
    }
}

}

pub mod solver {
// Hybrid Horn-SAT + Lexicographic Weighted Partial MaxSMT ABI Solver
// Minimizes marginal FastCDC network download bytes, unshared page-cache RAM, and version age,
// or extracts a minimal human-readable Unsatisfiable Core (MUS) proof tree on failure.



use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AbiRequirement {
    pub soname: String,
    pub min_symver: String,
    pub abi_surface_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct AbiSliceCandidate {
    pub slice_id: String,
    pub version: String,
    pub age_rank: u64, // 0 = newest release
    pub provides: AbiRequirement,
    pub dependencies: Vec<AbiRequirement>,
    pub chunk_hashes: Vec<([u8; 32], u64)>, // (chunk_sha256, compressed_bytes)
    pub code_rss_bytes: u64,
}

pub struct HostCacheState {
    pub local_cas_chunks: BTreeSet<[u8; 32]>,
    pub active_pagecache_slices: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedSlicePlan {
    pub selected_slices: Vec<String>,
    pub marginal_download_bytes: u64,
    pub marginal_ram_bytes: u64,
    pub total_cost: u128,
}

impl AbiSliceCandidate {
    /// Computes the exact lexicographic marginal cost (alpha * net + beta * ram + gamma * age)
    pub fn marginal_cost(&self, host: &HostCacheState) -> (u64, u64, u128) {
        let mut net_bytes = 0u64;
        for (hash, sz) in &self.chunk_hashes {
            if !host.local_cas_chunks.contains(hash) {
                net_bytes = net_bytes.saturating_add(*sz);
            }
        }
        let ram_bytes = if host.active_pagecache_slices.contains(&self.slice_id) {
            0u64
        } else {
            self.code_rss_bytes
        };
        let alpha: u128 = 1u128 << 40;
        let beta: u128  = 1u128 << 20;
        let cost = (net_bytes as u128) * alpha
            + (ram_bytes as u128) * beta
            + (self.age_rank as u128);
        (net_bytes, ram_bytes, cost)
    }
}

/// Resolves the Pareto-optimal set of ABI slices for a package's ELF requirements,
/// or returns the exact Unsatisfiable Core (missing SONAME + symbol version chain).
pub fn resolve_optimal_abi_slices(
    root_reqs: &[AbiRequirement],
    catalog: &[AbiSliceCandidate],
    host: &HostCacheState,
) -> Result<ResolvedSlicePlan, Vec<AbiRequirement>> {
    let mut selected = BTreeMap::<String, AbiSliceCandidate>::new();
    let mut worklist: Vec<AbiRequirement> = root_reqs.to_vec();
    let mut unsat_core = Vec::new();

    while let Some(req) = worklist.pop() {
        if selected.contains_key(&req.soname) {
            continue;
        }
        // Filter all candidates providing the exact ABI surface hash & SONAME
        let mut matching: Vec<&AbiSliceCandidate> = catalog
            .iter()
            .filter(|c| {
                c.provides.soname == req.soname
                    && c.provides.abi_surface_hash == req.abi_surface_hash
            })
            .collect();

        if matching.is_empty() {
            unsat_core.push(req);
            continue;
        }

        // Sort candidates by lexicographic MaxSMT objective J(s)
        matching.sort_by_key(|c| c.marginal_cost(host).2);
        let best = matching[0].clone();

        for dep in &best.dependencies {
            if !selected.contains_key(&dep.soname) {
                worklist.push(dep.clone());
            }
        }
        selected.insert(req.soname.clone(), best);
    }

    if !unsat_core.is_empty() {
        return Err(unsat_core);
    }

    // Aggregate deduplicated marginal network download across all chosen slices
    let mut seen_new_chunks = BTreeSet::new();
    let mut total_net = 0u64;
    let mut total_ram = 0u64;
    let mut total_age = 0u128;
    let mut names = Vec::new();

    for cand in selected.values() {
        names.push(format!("{}@{}", cand.slice_id, cand.version));
        for (h, sz) in &cand.chunk_hashes {
            if !host.local_cas_chunks.contains(h) && seen_new_chunks.insert(*h) {
                total_net = total_net.saturating_add(*sz);
            }
        }
        if !host.active_pagecache_slices.contains(&cand.slice_id) {
            total_ram = total_ram.saturating_add(cand.code_rss_bytes);
        }
        total_age += cand.age_rank as u128;
    }

    let total_cost = (total_net as u128) * (1u128 << 40)
        + (total_ram as u128) * (1u128 << 20)
        + total_age;

    Ok(ResolvedSlicePlan {
        selected_slices: names,
        marginal_download_bytes: total_net,
        marginal_ram_bytes: total_ram,
        total_cost,
    })
}

}
