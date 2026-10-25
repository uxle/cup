use libcup2_rs::solver::{resolve_optimal_abi_slices, AbiRequirement, AbiSliceCandidate, HostCacheState};
use std::collections::BTreeSet;

fn main() {
    println!("CUP v3.0 Rust Driver (cup-installer-rs) + libcup2 Rust reference implementation");
    let req = AbiRequirement {
        soname: "libc.so.6".to_string(),
        min_symver: "GLIBC_2.38".to_string(),
        abi_surface_hash: [0x9F; 32],
    };
    let cand = AbiSliceCandidate {
        slice_id: "org.cup.Slice.glibc".to_string(),
        version: "2.38.0".to_string(),
        age_rank: 0,
        provides: req.clone(),
        dependencies: vec![],
        chunk_hashes: vec![([0xAA; 32], 1048576)],
        code_rss_bytes: 2097152,
    };
    let host = HostCacheState {
        local_cas_chunks: BTreeSet::from([[0xAA; 32]]),
        active_pagecache_slices: BTreeSet::from(["org.cup.Slice.glibc".to_string()]),
    };
    if let Ok(plan) = resolve_optimal_abi_slices(&[req], &[cand], &host) {
        println!(
            "Resolved ABI Slices: {:?} (Marginal Net: {} B, Marginal RAM: {} B)",
            plan.selected_slices, plan.marginal_download_bytes, plan.marginal_ram_bytes
        );
    }
}
