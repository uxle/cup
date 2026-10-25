/* [NORMATIVE] cup_abi_solver.hpp: C++20 Header for Hybrid Horn-SAT + Lexicographic MaxSMT ABI Solver
 * and Universal Format Transpiler (Appendix P & Appendix U of RFC CUP-3.0).
 */
#ifndef CUP_ABI_SOLVER_HPP
#define CUP_ABI_SOLVER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <array>
#include <set>
#include <map>

namespace cup::v3 {

struct AbiRequirement {
    std::string              soname;
    std::string              min_symver;
    std::array<uint8_t, 32>  abi_surface_hash;

    bool operator<(const AbiRequirement &other) const noexcept {
        if (soname != other.soname) return soname < other.soname;
        if (min_symver != other.min_symver) return min_symver < other.min_symver;
        return abi_surface_hash < other.abi_surface_hash;
    }
};

struct AbiSliceCandidate {
    std::string                                        slice_id;
    std::string                                        version;
    uint64_t                                           age_rank;
    AbiRequirement                                     provides;
    std::vector<AbiRequirement>                        dependencies;
    std::vector<std::pair<std::array<uint8_t, 32>, uint64_t>> chunk_hashes;
    uint64_t                                           code_rss_bytes;
};

struct HostCacheState {
    std::set<std::array<uint8_t, 32>> local_cas_chunks;
    std::set<std::string>             active_pagecache_slices;
};

struct ResolvedSlicePlan {
    bool                     feasible;
    std::vector<std::string> selected_slices;
    uint64_t                 marginal_download_bytes;
    uint64_t                 marginal_ram_bytes;
    unsigned __int128        total_cost;
    std::vector<AbiRequirement> unsat_core;
};

ResolvedSlicePlan resolve_optimal_abi_slices(
    const std::vector<AbiRequirement> &root_reqs,
    const std::vector<AbiSliceCandidate> &catalog,
    const HostCacheState &host);

struct LinglongInfoJson {
    std::string              appid;
    std::string              version;
    std::vector<std::string> arch;
    std::string              base;
    std::string              runtime;
    std::vector<std::string> command;
    bool                     permissions_autostart;
    bool                     permissions_network;
};

std::string convert_linglong_uab_to_jcs(
    const LinglongInfoJson &uab,
    const std::vector<std::string> &detected_sonames,
    const std::string &merkle_root_hex,
    const std::string &fsverity_root_hex);

} // namespace cup::v3

extern "C" {
int cup_maxsmt_resolve_c_bridge(uint64_t cached_chunk_bytes,
                                uint64_t uncached_chunk_bytes,
                                bool slice_in_pagecache,
                                uint64_t slice_rss_bytes,
                                uint64_t *out_net_bytes,
                                uint64_t *out_ram_bytes);
}

#endif /* CUP_ABI_SOLVER_HPP */
