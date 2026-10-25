/* [NORMATIVE] cup_abi_solver.cpp: C++20 Implementation of Appendix U MaxSMT ABI Solver
 * and Appendix P Universal Format Transpiler (Linglong .uab / .deb / .flatpak -> CUP v3.0).
 */
#include "cup_abi_solver.hpp"
#include "libcup2.h"
#include <algorithm>
#include <sstream>

namespace cup::v3 {

static std::tuple<uint64_t, uint64_t, unsigned __int128> compute_marginal_cost(
    const AbiSliceCandidate &cand,
    const HostCacheState &host)
{
    uint64_t net_bytes = 0;
    for (const auto &ch : cand.chunk_hashes) {
        if (host.local_cas_chunks.find(ch.first) == host.local_cas_chunks.end()) {
            net_bytes += ch.second;
        }
    }
    uint64_t ram_bytes = (host.active_pagecache_slices.find(cand.slice_id) !=
                          host.active_pagecache_slices.end())
                         ? 0ULL
                         : cand.code_rss_bytes;

    const unsigned __int128 alpha = static_cast<unsigned __int128>(1ULL) << 40;
    const unsigned __int128 beta  = static_cast<unsigned __int128>(1ULL) << 20;
    unsigned __int128 cost = static_cast<unsigned __int128>(net_bytes) * alpha +
                             static_cast<unsigned __int128>(ram_bytes) * beta +
                             static_cast<unsigned __int128>(cand.age_rank);
    return {net_bytes, ram_bytes, cost};
}

ResolvedSlicePlan resolve_optimal_abi_slices(
    const std::vector<AbiRequirement> &root_reqs,
    const std::vector<AbiSliceCandidate> &catalog,
    const HostCacheState &host)
{
    ResolvedSlicePlan plan{};
    plan.feasible = false;
    plan.marginal_download_bytes = 0;
    plan.marginal_ram_bytes = 0;
    plan.total_cost = 0;

    std::map<std::string, AbiSliceCandidate> selected;
    std::vector<AbiRequirement> worklist = root_reqs;

    while (!worklist.empty()) {
        AbiRequirement req = worklist.back();
        worklist.pop_back();

        if (selected.find(req.soname) != selected.end()) {
            continue;
        }

        std::vector<const AbiSliceCandidate *> matching;
        for (const auto &c : catalog) {
            if (c.provides.soname == req.soname &&
                c.provides.abi_surface_hash == req.abi_surface_hash) {
                matching.push_back(&c);
            }
        }

        if (matching.empty()) {
            plan.unsat_core.push_back(req);
            continue;
        }

        std::sort(matching.begin(), matching.end(),
                  [&host](const AbiSliceCandidate *a, const AbiSliceCandidate *b) {
                      return std::get<2>(compute_marginal_cost(*a, host)) <
                             std::get<2>(compute_marginal_cost(*b, host));
                  });

        AbiSliceCandidate best = *matching.front();
        for (const auto &dep : best.dependencies) {
            if (selected.find(dep.soname) == selected.end()) {
                worklist.push_back(dep);
            }
        }
        selected.emplace(req.soname, std::move(best));
    }

    if (!plan.unsat_core.empty()) {
        return plan;
    }

    plan.feasible = true;
    std::set<std::array<uint8_t, 32>> seen_new_chunks;
    unsigned __int128 total_age = 0;

    for (const auto &[soname, cand] : selected) {
        plan.selected_slices.push_back(cand.slice_id + "@" + cand.version);
        for (const auto &[h, sz] : cand.chunk_hashes) {
            if (host.local_cas_chunks.find(h) == host.local_cas_chunks.end() &&
                seen_new_chunks.insert(h).second) {
                plan.marginal_download_bytes += sz;
            }
        }
        if (host.active_pagecache_slices.find(cand.slice_id) ==
            host.active_pagecache_slices.end()) {
            plan.marginal_ram_bytes += cand.code_rss_bytes;
        }
        total_age += cand.age_rank;
    }

    plan.total_cost =
        static_cast<unsigned __int128>(plan.marginal_download_bytes) * (static_cast<unsigned __int128>(1ULL) << 40) +
        static_cast<unsigned __int128>(plan.marginal_ram_bytes) * (static_cast<unsigned __int128>(1ULL) << 20) +
        total_age;

    return plan;
}

std::string convert_linglong_uab_to_jcs(
    const LinglongInfoJson &uab,
    const std::vector<std::string> &detected_sonames,
    const std::string &merkle_root_hex,
    const std::string &fsverity_root_hex)
{
    std::vector<std::string> slices = {"org.cup.Slice.glibc/2.38"};
    auto push_slice_unique = [&slices](const char *needle, const char *slice_id) {
        for (const auto &s : slices) {
            if (s.find(needle) != std::string::npos) {
                return; /* already present: dedup like the Rust reference */
            }
        }
        slices.push_back(slice_id);
    };
    for (const auto &s : detected_sonames) {
        if (s.find("libQt6") == 0 || s.find("libdtk6") == 0) {
            push_slice_unique("qt6-gui", "org.cup.Slice.qt6-gui/6.7");
        } else if (s.find("libwayland") == 0) {
            push_slice_unique("wayland", "org.cup.Slice.wayland/1.22");
        } else if (s.find("libvulkan") == 0) {
            push_slice_unique("vulkan", "org.cup.Slice.vulkan/1.3");
        }
    }
    std::string arch = uab.arch.empty() ? "x86_64" : uab.arch.front();
    std::string cmd  = uab.command.empty() ? "/app/bin/app" : uab.command.front();

    std::ostringstream oss;
    oss << "{\"abi\":\"glibc-2.38+wayland-1.22\",\"abi_slices\":[";
    for (size_t i = 0; i < slices.size(); i++) {
        if (i > 0) oss << ",";
        oss << "\"" << slices[i] << "\"";
    }
    oss << "],\"arch\":\"" << arch << "\","
        << "\"entrypoint\":\"" << cmd << "\","
        << "\"erofs_verity_root\":\"" << fsverity_root_hex << "\","
        << "\"id\":\"" << uab.appid << "\","
        << "\"merkle_root\":\"" << merkle_root_hex << "\","
        << "\"network\":" << (uab.permissions_network ? "true" : "false") << ","
        << "\"sandbox_tier\":\"gui-wayland\","
        << "\"schema\":\"3.0\","
        << "\"version\":\"" << uab.version << "\"}";
    return oss.str();
}

} // namespace cup::v3

extern "C" int cup_maxsmt_resolve_c_bridge(uint64_t cached_chunk_bytes,
                                           uint64_t uncached_chunk_bytes,
                                           bool slice_in_pagecache,
                                           uint64_t slice_rss_bytes,
                                           uint64_t *out_net_bytes,
                                           uint64_t *out_ram_bytes)
{
    using namespace cup::v3;
    std::array<uint8_t, 32> h_cached{};
    h_cached[0] = 0xAA;
    std::array<uint8_t, 32> h_uncached{};
    h_uncached[0] = 0xBB;
    std::array<uint8_t, 32> abi_hash{};
    abi_hash[0] = 0x9F;

    HostCacheState host;
    host.local_cas_chunks.insert(h_cached);
    if (slice_in_pagecache) {
        host.active_pagecache_slices.insert("org.cup.Slice.glibc");
    }

    AbiRequirement req{"libc.so.6", "GLIBC_2.38", abi_hash};
    AbiSliceCandidate cand1{
        "org.cup.Slice.glibc",
        "2.38.1",
        0,
        req,
        {},
        {{h_cached, cached_chunk_bytes}, {h_uncached, uncached_chunk_bytes}},
        slice_rss_bytes
    };

    auto plan = resolve_optimal_abi_slices({req}, {cand1}, host);
    if (!plan.feasible) return -CUP_E_UNSAT_CORE;
    if (out_net_bytes) *out_net_bytes = plan.marginal_download_bytes;
    if (out_ram_bytes) *out_ram_bytes = plan.marginal_ram_bytes;
    return CUP_OK;
}
