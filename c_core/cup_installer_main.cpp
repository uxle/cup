/* [NORMATIVE] cup_installer_main.cpp: CUP v3.0 toolchain front-end (cup-installer / cup-cli / cup-builder)
 *
 *   build    <out.cup> [--app-id ID] [--version VER] [--v1|--v2|--v3] [--payload FILE] [--erofs FILE]
 *                      [--entrypoint PATH] [--stub FILE|--no-stub]
 *   verify   <pkg.cup>... [--strict] [--require-pq] [--trust-root HEX]... [--tsa-key HEX]... [--no-builtin-root]
 *   inspect  <pkg.cup>
 *   install  <pkg.cup> --root DIR [--dry-run]
 *   upgrade  <pkg.cup> --root DIR [--dry-run] [--allow-downgrade] [--simulate-crash]
 *   rollback --root DIR
 *   help [command] | --version
 *
 * Global: --json  -q/--quiet  -v/--verbose  --color=auto|always|never  --no-color  --ascii|--unicode
 * Exit codes: 0 ok | 1 verification/integrity failure | 2 usage error | 3 I/O error | 4 not available in this build
 */
#include "libcup2.h"
#include "cup_json.hpp"
#include "cup_ui.hpp"
#include "cup_verify.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace cupv;
using ui::C;

namespace {

constexpr int EX_OK_ = 0, EX_VERIFY_ = 1, EX_USAGE_ = 2, EX_IO_ = 3, EX_UNAVAIL_ = 4;
const char *TOOL_VERSION = "3.0.0";

std::string g_prog = "cup-installer";

/* ------------------------------------------------------------------ args */
struct Args {
    std::vector<std::string> pos;
    std::map<std::string, std::string> val;
    std::vector<std::string> roots, tsas;
    std::set<std::string> flag;
    bool has(const char *f) const { return flag.count(f) != 0; }
    std::string get(const char *k, const std::string &d = "") const { auto it = val.find(k); return it == val.end() ? d : it->second; }
};

const std::set<std::string> kValueOpts = {"--app-id", "--version", "--root", "--payload", "--erofs", "--stub", "--entrypoint",
                                          "--trust-root", "--tsa-key", "--color", "--report"};
const std::set<std::string> kFlagOpts = {"--strict", "--json", "--quiet", "-q", "--verbose", "-v", "--ascii", "--unicode", "--no-color",
                                         "--v1", "--v2", "--v3", "--simulate-crash", "--dry-run", "--require-pq", "--no-builtin-root",
                                         "--allow-downgrade", "--no-stub", "--help", "-h"};

bool parse_args(int argc, char **argv, int from, Args &a, std::string &err) {
    for (int i = from; i < argc; i++) {
        std::string t = argv[i];
        if (t == "--") { for (i++; i < argc; i++) a.pos.push_back(argv[i]); break; }
        if (t.size() > 1 && t[0] == '-') {
            std::string k = t, v; bool has_v = false;
            size_t eq = t.find('=');
            if (t.rfind("--", 0) == 0 && eq != std::string::npos) { k = t.substr(0, eq); v = t.substr(eq + 1); has_v = true; }
            if (kValueOpts.count(k)) {
                if (!has_v) { if (i + 1 >= argc) { err = "option " + k + " needs a value"; return false; } v = argv[++i]; }
                if (k == "--trust-root") a.roots.push_back(v);
                else if (k == "--tsa-key") a.tsas.push_back(v);
                else a.val[k] = v;
            } else if (kFlagOpts.count(k) && !has_v) {
                a.flag.insert(k);
            } else {
                err = "unknown option '" + t + "'";
                return false;
            }
        } else a.pos.push_back(t);
    }
    return true;
}

/* ------------------------------------------------------------------ output helpers */
void print_err(const std::string &msg, const std::string &hint = "") {
    std::cerr << ui::paint(C::Red, "error:", true) << " " << msg << "\n";
    if (!hint.empty()) std::cerr << "       " << ui::dim(hint, true) << "\n";
}

std::string base_name(const std::string &p) { size_t s = p.find_last_of('/'); return s == std::string::npos ? p : p.substr(s + 1); }

void banner(const std::string &cmd, const std::string &what) {
    if (ui::S().quiet) return;
    std::cout << "\n" << ui::paint(C::Teal, ui::g_mark()) << " " << ui::bold("CUP") << " " << ui::paint(C::Sky, cmd) << "  " << what << "\n\n";
}

void step(St st, const std::string &text, const std::string &detail = "") {
    if (ui::S().quiet && st != St::Fail) return;
    const char *g = ui::g_info(); C col = C::Dim;
    if (st == St::Pass) { g = ui::g_ok(); col = C::Green; }
    else if (st == St::Fail) { g = ui::g_fail(); col = C::Red; }
    else if (st == St::Warn) { g = ui::g_warn(); col = C::Amber; }
    std::cout << "  " << ui::paint(col, g) << " " << ui::pad(text, 44);
    if (!detail.empty()) std::cout << " " << ui::dim(detail);
    std::cout << "\n";
}

bool read_file(const std::string &path, std::vector<uint8_t> &out, std::string &err, uint64_t cap = 4ULL << 30) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) { err = std::string("cannot open '") + path + "': " + std::strerror(errno); return false; }
    if (!S_ISREG(st.st_mode)) { err = "'" + path + "' is not a regular file"; return false; }
    if ((uint64_t)st.st_size > cap) { err = "'" + path + "' is larger than the " + ui::human_bytes(cap) + " limit"; return false; }
    std::ifstream f(path, std::ios::binary);
    if (!f) { err = std::string("cannot read '") + path + "': " + std::strerror(errno); return false; }
    try { out.resize((size_t)st.st_size); }
    catch (const std::bad_alloc &) { err = "cannot hold " + ui::human_bytes((uint64_t)st.st_size) + " in memory for '" + path + "'"; return false; }
    f.read(reinterpret_cast<char *>(out.data()), (std::streamsize)out.size());
    if ((uint64_t)f.gcount() != (uint64_t)st.st_size) { err = "'" + path + "' changed size while it was being read"; return false; }
    return true;
}

bool write_file_atomic(const std::string &path, const std::vector<uint8_t> &data, std::string &err) {
    std::string tmp = path + ".tmp." + std::to_string(getpid());
    {
        std::ofstream o(tmp, std::ios::binary | std::ios::trunc);
        if (!o) { err = "cannot write '" + path + "': " + std::strerror(errno); return false; }
        o.write(reinterpret_cast<const char *>(data.data()), (std::streamsize)data.size());
        o.flush();
        if (!o) { unlink(tmp.c_str()); err = "write failed for '" + path + "'"; return false; }
    }
    if (rename(tmp.c_str(), path.c_str()) != 0) { unlink(tmp.c_str()); err = "cannot move result into place at '" + path + "': " + std::strerror(errno); return false; }
    return true;
}

bool write_text(const std::string &path, const std::string &s) {
    std::ofstream o(path, std::ios::trunc);
    if (!o) return false;
    o << s;
    return (bool)o;
}

int rm_cb(const char *p, const struct stat *, int, struct FTW *) { return remove(p); }
void rm_rf(const std::string &p) { struct stat st{}; if (lstat(p.c_str(), &st) == 0) nftw(p.c_str(), rm_cb, 16, FTW_DEPTH | FTW_PHYS); }

std::string read_kv(const std::string &path, const std::string &key) {
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) if (line.rfind(key + "=", 0) == 0) return line.substr(key.size() + 1);
    return "";
}

std::string jbool(bool b) { return b ? "true" : "false"; }
std::string jq(const std::string &s) { return "\"" + ui::json_escape(s) + "\""; }

/* ------------------------------------------------------------------ verify report rendering */
std::string report_json(const Report &r) {
    std::ostringstream o;
    o << "{\"path\":" << jq(r.path) << ",\"ok\":" << jbool(r.ok()) << ",\"failures\":" << r.fails << ",\"warnings\":" << r.warns
      << ",\"bytes\":" << r.size << ",\"format\":" << r.major << ",\"app_id\":" << jq(r.app_id) << ",\"version\":" << jq(r.version)
      << ",\"manifest_sha256\":" << jq(r.manifest_sha_hex) << ",\"uri\":" << jq(r.uri) << ",\"sig_alg\":" << (int)r.sig_alg
      << ",\"demo_trust_root\":" << jbool(r.used_demo_root) << ",\"checks\":[";
    for (size_t i = 0; i < r.checks.size(); i++) {
        const Check &c = r.checks[i];
        o << (i ? "," : "") << "{\"group\":" << jq(c.group) << ",\"status\":" << jq(st_name(c.st)) << ",\"text\":" << jq(c.text)
          << ",\"detail\":" << jq(c.detail) << ",\"spec\":" << jq(c.spec) << ",\"hint\":" << jq(c.hint) << "}";
    }
    o << "]}";
    return o.str();
}

void print_report(const Report &r) {
    if (!ui::S().quiet) {
        std::cout << "\n" << ui::paint(C::Teal, ui::g_mark()) << " " << ui::bold("CUP") << " " << ui::paint(C::Sky, "verify") << "  " << ui::bold(base_name(r.path))
                  << "  " << ui::dim(ui::human_bytes(r.size) + " " + ui::g_dot() + " CUP" + std::to_string(r.major) + " " + ui::g_dot() + " " + std::to_string(r.sections.size()) + " sections") << "\n";
        std::string group;
        for (const Check &c : r.checks) {
            if (c.group != group) { group = c.group; std::cout << "\n  " << ui::paint(C::Indigo, ui::bold(group)) << "\n"; }
            const char *g = ui::g_info(); C col = C::Dim;
            if (c.st == St::Pass) { g = ui::g_ok(); col = C::Green; }
            else if (c.st == St::Fail) { g = ui::g_fail(); col = C::Red; }
            else if (c.st == St::Warn) { g = ui::g_warn(); col = C::Amber; }
            std::cout << "   " << ui::paint(col, g) << " " << c.text;
            if (!c.detail.empty()) std::cout << "  " << ui::dim(c.detail);
            if (!c.spec.empty() && ui::S().verbose) std::cout << "  " << ui::dim("[" + c.spec + "]");
            std::cout << "\n";
            if ((c.st == St::Fail || c.st == St::Warn) && !c.hint.empty()) std::cout << "       " << ui::dim(std::string(ui::g_arrow()) + " " + c.hint) << "\n";
        }
        std::cout << "\n";
    } else {
        for (const Check &c : r.checks) if (c.st == St::Fail) std::cerr << base_name(r.path) << ": " << c.text << (c.detail.empty() ? "" : " (" + c.detail + ")") << "\n";
    }
    if (r.ok()) {
        std::cout << "  " << ui::paint(C::Green, ui::bold(std::string(ui::g_ok()) + " VERIFIED OK:")) << " " << r.uri;
        if (r.warns) std::cout << "  " << ui::paint(C::Amber, std::to_string(r.warns) + " warning" + (r.warns == 1 ? "" : "s"));
        std::cout << "\n";
    } else {
        std::cout << "  " << ui::paint(C::Red, ui::bold(std::string(ui::g_fail()) + " NOT VERIFIED")) << "  " << base_name(r.path) << "  "
                  << ui::paint(C::Red, std::to_string(r.fails) + " failure" + (r.fails == 1 ? "" : "s")) << "\n";
    }
    if (!ui::S().quiet) std::cout << "\n";
}

bool build_options(const Args &a, Options &o, std::string &err) {
    o.strict = a.has("--strict");
    o.require_pq = a.has("--require-pq");
    o.builtin_roots = !a.has("--no-builtin-root");
    for (auto &h : a.roots) { Key32 k; if (!unhex(h, k.data(), 32)) { err = "--trust-root expects 64 hex characters (an Ed25519 public key)"; return false; } o.roots.push_back(k); }
    for (auto &h : a.tsas)  { Key32 k; if (!unhex(h, k.data(), 32)) { err = "--tsa-key expects 64 hex characters (an Ed25519 public key)"; return false; } o.tsa_keys.push_back(k); }
    return true;
}

/* ------------------------------------------------------------------ help */
void print_help() {
    using namespace ui;
    std::cout << "\n" << paint(C::Teal, g_mark()) << " " << bold("CUP") << "  CuteFish Universal Package toolchain " << dim("v" + std::string(TOOL_VERSION) + " " + g_dot() + " RFC CUP-3.0") << "\n\n"
              << "  " << bold("Usage") << "   " << g_prog << " <command> [options]\n\n"
              << "  " << bold("Commands") << "\n"
              << "    " << paint(C::Sky, pad("build", 10)) << "Create and sign a package               " << dim("build app.cup --app-id org.me.App --version 1.0.0") << "\n"
              << "    " << paint(C::Sky, pad("verify", 10)) << "Check integrity, signature and trust     " << dim("verify app.cup [--strict]") << "\n"
              << "    " << paint(C::Sky, pad("inspect", 10)) << "Show sections, flags, chain, manifest     " << dim("inspect app.cup") << "\n"
              << "    " << paint(C::Sky, pad("install", 10)) << "Verify, stage and atomically activate     " << dim("install app.cup --root ~/.cup") << "\n"
              << "    " << paint(C::Sky, pad("upgrade", 10)) << "Same, keeping the old version to roll back" << dim(" upgrade app.cup --root ~/.cup") << "\n"
              << "    " << paint(C::Sky, pad("rollback", 10)) << "Swap back to the previous version          " << dim("rollback --root ~/.cup") << "\n"
              << "    " << paint(C::Sky, pad("help", 10)) << "Help for a command                        " << dim("help verify") << "\n\n"
              << "  " << bold("Global options") << "\n"
              << "    --json            machine-readable output (no colour, stable keys)\n"
              << "    -q, --quiet       print only the result line / failures\n"
              << "    -v, --verbose     show spec references next to every check\n"
              << "    --color=MODE      auto (default) | always | never      " << dim("NO_COLOR is honoured") << "\n"
              << "    --ascii           plain ASCII symbols instead of Unicode\n"
              << "    --version         print the tool version\n\n"
              << "  " << bold("Exit codes") << "   0 ok  " << g_dot() << "  1 verification failed  " << g_dot() << "  2 usage  " << g_dot() << "  3 I/O  " << g_dot() << "  4 not available\n\n"
              << "  " << dim("Not in this reference build: run (needs cup-box sandbox), convert (Linglong/deb import).") << "\n\n";
}

int print_cmd_help(const std::string &cmd) {
    using namespace ui;
    auto head = [&](const char *usage) { std::cout << "\n  " << bold("Usage") << "  " << g_prog << " " << usage << "\n\n"; };
    if (cmd == "build") {
        head("build <out.cup> [options]");
        std::cout << "    --app-id ID       reverse-DNS id (default org.foopaint.FooPaint)\n"
                  << "    --version VER     package version (default 3.0.0)\n"
                  << "    --v1 | --v2 | --v3  container generation (default --v3)\n"
                  << "    --payload FILE    chunk and seal this file as the payload (default: 160 KiB synthetic demo payload)\n"
                  << "    --erofs FILE      EROFS image to seal, size must be a multiple of 4096 (default: 8 KiB demo image)\n"
                  << "    --entrypoint PATH launch path inside the image (default /app/bin/<last id label, lower-case>)\n"
                  << "    --stub FILE       bootstrap stub to embed (default: cup-stub next to this binary)   --no-stub to omit\n\n"
                  << "  Signs with the public DEMO keys. Packages built here verify only against the demo root.\n\n";
    } else if (cmd == "verify") {
        head("verify <pkg.cup>... [options]");
        std::cout << "    --strict            also fail on unbound manifest fields, trailing bytes and missing promised sections\n"
                  << "    --require-pq        fail unless a post-quantum half is present (see note in `inspect`)\n"
                  << "    --trust-root HEX    trust this Ed25519 root key (repeatable)\n"
                  << "    --tsa-key HEX       trust this timestamp-authority key (repeatable)\n"
                  << "    --no-builtin-root   ignore the built-in public DEMO root and TSA\n\n"
                  << "  " << dim("Several files may be given; the exit code is 1 if any fails.") << "\n\n";
    } else if (cmd == "inspect") {
        head("inspect <pkg.cup>");
        std::cout << "  Decodes header, flags, section table, signature chain and manifest, then runs verify.\n\n";
    } else if (cmd == "install" || cmd == "upgrade") {
        head((cmd + " <pkg.cup> --root DIR [options]").c_str());
        std::cout << "    --root DIR          deployment root (required)\n"
                  << "    --dry-run           verify and show the plan, change nothing\n"
                  << "    --strict, --trust-root, --tsa-key, --no-builtin-root   as for verify\n";
        if (cmd == "upgrade") std::cout << "    --allow-downgrade   permit installing an older version\n    --simulate-crash    start the new version, crash it, and show the coupled rollback\n";
        std::cout << "\n  Layout:  DIR/active  DIR/rollback  DIR/state-active  DIR/state-rollback\n\n";
    } else if (cmd == "rollback") {
        head("rollback --root DIR");
        std::cout << "  Atomically swaps active <-> rollback for the binary and its user state.\n\n";
    } else {
        print_err("no such command '" + cmd + "'", "Run '" + g_prog + " help' for the list.");
        return EX_USAGE_;
    }
    return EX_OK_;
}

/* ------------------------------------------------------------------ verify / inspect */
int cmd_verify(const Args &a, bool json) {
    if (a.pos.empty()) { print_err("verify needs at least one package", "Example: " + g_prog + " verify app.cup --strict"); return EX_USAGE_; }
    Options opt; std::string err;
    if (!build_options(a, opt, err)) { print_err(err); return EX_USAGE_; }
    int rc = EX_OK_;
    std::vector<Report> reps;
    for (const std::string &p : a.pos) {
        std::vector<uint8_t> buf;
        if (!read_file(p, buf, err)) { print_err(err); rc = std::max(rc, EX_IO_); continue; }
        Report r = verify_buffer(buf, opt);
        r.path = p;
        if (!r.ok()) rc = std::max(rc, EX_VERIFY_);
        if (json) reps.push_back(r); else print_report(r);
    }
    if (json) {
        std::cout << "{\"tool\":\"cup-installer\",\"version\":\"" << TOOL_VERSION << "\",\"command\":\"verify\",\"results\":[";
        for (size_t i = 0; i < reps.size(); i++) std::cout << (i ? "," : "") << report_json(reps[i]);
        std::cout << "]}\n";
    }
    return rc;
}

int cmd_inspect(const Args &a, bool json) {
    if (a.pos.size() != 1) { print_err("inspect needs exactly one package"); return EX_USAGE_; }
    Options opt; std::string err;
    if (!build_options(a, opt, err)) { print_err(err); return EX_USAGE_; }
    std::vector<uint8_t> buf;
    if (!read_file(a.pos[0], buf, err)) { print_err(err); return EX_IO_; }
    Report r = verify_buffer(buf, opt);
    r.path = a.pos[0];
    if (json) {
        std::ostringstream o;
        o << "{\"tool\":\"cup-installer\",\"command\":\"inspect\",\"flags\":" << jq(flag_names(r.flags)) << ",\"abi_tag\":" << jq(r.abi_tag)
          << ",\"runtime_ref\":" << jq(r.runtime_ref) << ",\"min_kernel\":" << jq(std::to_string(r.min_kernel >> 16) + "." + std::to_string((r.min_kernel >> 8) & 255) + "." + std::to_string(r.min_kernel & 255))
          << ",\"sections\":[";
        for (size_t i = 0; i < r.sections.size(); i++)
            o << (i ? "," : "") << "{\"index\":" << i << ",\"type\":" << jq(section_name(r.sections[i].type)) << ",\"offset\":" << r.sections[i].off << ",\"length\":" << r.sections[i].len << ",\"sha256\":" << jq(r.sections[i].sha_hex) << "}";
        o << "],\"chain\":[";
        for (size_t i = 0; i < r.chain.size(); i++)
            o << (i ? "," : "") << "{\"subject\":" << jq(r.chain[i].subject_fp) << ",\"issuer\":" << jq(r.chain[i].issuer_fp) << ",\"prefix\":" << jq(r.chain[i].prefix) << ",\"valid_from\":" << jq(date_utc(r.chain[i].from)) << ",\"valid_until\":" << jq(date_utc(r.chain[i].until)) << "}";
        o << "],\"verification\":" << report_json(r) << "}";
        std::cout << o.str() << "\n";
        return r.ok() ? EX_OK_ : EX_VERIFY_;
    }
    if (r.sections.empty() && !r.ok()) { print_report(r); return EX_VERIFY_; }
    using namespace ui;
    banner("inspect", bold(base_name(r.path)));
    auto kv = [&](const char *k, const std::string &v) { std::cout << "  " << paint(C::Dim, pad(k, 11)) << v << "\n"; };
    kv("Package", r.app_id.empty() ? "(unreadable manifest)" : bold(r.app_id) + "  " + r.version);
    kv("Format", "CUP" + std::to_string(r.major) + " " + std::string(g_dot()) + " " + human_bytes(r.size) + " " + g_dot() + " sig_alg " + std::to_string(r.sig_alg) +
                  (r.sig_alg == 3 ? " (Ed25519 + PQ slot)" : r.sig_alg == 2 ? " (Ed25519ph)" : " (Ed25519)"));
    if (!r.uri.empty()) kv("Identity", r.uri);
    kv("Flags", flag_names(r.flags));
    kv("Runtime", r.abi_tag + " " + g_dot() + " " + r.runtime_ref + " " + g_dot() + " kernel >= " + std::to_string(r.min_kernel >> 16) + "." + std::to_string((r.min_kernel >> 8) & 255) + "." + std::to_string(r.min_kernel & 255));
    std::cout << "\n  " << paint(C::Indigo, bold("Sections")) << "\n";
    std::cout << "   " << dim(pad("#", 3) + pad("type", 16) + pad("offset", 10) + pad("size", 11) + "sha-256") << "\n";
    for (size_t i = 0; i < r.sections.size(); i++) {
        const auto &s = r.sections[i];
        std::cout << "   " << pad(std::to_string(i), 3) << paint(C::Sky, pad(section_name(s.type), 16)) << pad(std::to_string(s.off), 10) << pad(human_bytes(s.len), 11) << dim(short_hex(s.sha_hex)) << "\n";
    }
    if (!r.chain.empty()) {
        std::cout << "\n  " << paint(C::Indigo, bold("Signature chain")) << "  " << dim("signer " + r.signer_fp + " " + g_dot() + " timestamp " + date_utc(r.tsa_ts)) << "\n";
        for (size_t i = 0; i < r.chain.size(); i++) {
            const auto &c = r.chain[i];
            const char *role = (c.usage & CUP_KEY_USAGE_PKG_SIGN) ? "package signer" : (c.usage & CUP_KEY_USAGE_CA_ROOT) ? "root CA" : "intermediate CA";
            std::cout << "   " << pad(std::to_string(i), 3) << pad(c.subject_fp, 10) << pad(role, 17) << pad("namespace " + c.prefix + "*", 24)
                      << dim(date_utc(c.from) + " " + g_arrow() + " " + date_utc(c.until)) << "\n";
        }
        std::cout << "   " << dim("    " + r.chain.back().issuer_fp + "  trust anchor") << "\n";
    }
    if (r.manifest.t == cupjson::Val::Obj) {
        std::cout << "\n  " << paint(C::Indigo, bold("Manifest")) << "  " << dim("signed, canonical JSON") << "\n";
        for (auto &kvp : r.manifest.o) {
            std::string v;
            const auto &x = kvp.second;
            if (x.t == cupjson::Val::Str) v = (x.s.size() == 64 && x.s.find_first_not_of("0123456789abcdef") == std::string::npos) ? short_hex(x.s, 12, 8) : x.s;
            else if (x.t == cupjson::Val::Num) v = std::to_string((long long)x.n);
            else if (x.t == cupjson::Val::Bool) v = x.b ? "true" : "false";
            else if (x.t == cupjson::Val::Arr) { for (size_t i = 0; i < x.a.size(); i++) v += (i ? ", " : "") + x.a[i].s; }
            else v = "...";
            std::cout << "   " << pad(kvp.first, 18) << v << "\n";
        }
    }
    std::cout << "\n  " << paint(C::Indigo, bold("Verification")) << "  ";
    if (r.ok()) std::cout << paint(C::Green, std::string(g_ok()) + " verified") << (r.warns ? "  " + paint(C::Amber, std::to_string(r.warns) + " warning(s)") : "");
    else std::cout << paint(C::Red, std::string(g_fail()) + " NOT verified");
    std::cout << "  " << dim("run `" + g_prog + " verify " + base_name(r.path) + "` for details") << "\n\n";
    return r.ok() ? EX_OK_ : EX_VERIFY_;
}

/* ------------------------------------------------------------------ build */
bool valid_token_path(const std::string &s) {
    if (s.empty() || s[0] != '/' || s.size() > 200) return false;
    for (unsigned char c : s) if (!(std::isalnum(c) || c == '/' || c == '.' || c == '_' || c == '-')) return false;
    return s.find("..") == std::string::npos;
}

uint64_t align_up(uint64_t v, uint64_t a) { return (v + a - 1ULL) & ~(a - 1ULL); }

std::string find_stub(const std::string &explicit_path) {
    std::vector<std::string> cands;
    if (!explicit_path.empty()) cands.push_back(explicit_path);
    if (const char *e = std::getenv("CUP_STUB")) cands.push_back(e);
    char self[4096]; ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n > 0) { self[n] = 0; std::string d(self); size_t s = d.find_last_of('/'); if (s != std::string::npos) cands.push_back(d.substr(0, s) + "/cup-stub"); }
    cands.push_back("bin/cup-stub");
    for (auto &c : cands) { struct stat st{}; if (stat(c.c_str(), &st) == 0 && S_ISREG(st.st_mode)) return c; }
    return "";
}

int cmd_build(const Args &a, bool json) {
    if (a.pos.size() != 1) { print_err("build needs exactly one output path", "Example: " + g_prog + " build app.cup --app-id org.me.App --version 1.0.0"); return EX_USAGE_; }
    const std::string out_path = a.pos[0];
    const std::string app_id = a.get("--app-id", "org.foopaint.FooPaint");
    const std::string version = a.get("--version", "3.0.0");
    uint8_t major_ver = a.has("--v1") ? 1 : a.has("--v2") ? 2 : 3;
    if (!valid_app_id(app_id)) { print_err("invalid --app-id '" + app_id + "'", "Use reverse-DNS: letters, digits, '.', '_' or '-', at least two labels (org.vendor.App)."); return EX_USAGE_; }
    if (version.empty() || version.size() > 32 || version.find_first_not_of("0123456789.+-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != std::string::npos) { print_err("invalid --version '" + version + "'", "Example: 1.2.3 or 1.2.3-rc1"); return EX_USAGE_; }
    std::string last = app_id.substr(app_id.rfind('.') + 1), entry = a.get("--entrypoint");
    if (entry.empty()) { for (auto &ch : last) ch = (char)std::tolower((unsigned char)ch); entry = "/app/bin/" + last; }
    if (!valid_token_path(entry)) { print_err("invalid --entrypoint '" + entry + "'", "Use an absolute path of safe characters, e.g. /app/bin/tool"); return EX_USAGE_; }
    /* namespace prefix the leaf certificate may sign for: whole labels, <= 15 chars, strictly shorter than the id */
    std::string prefix;
    for (size_t pos = 0;;) {
        size_t dot = app_id.find('.', pos);
        if (dot == std::string::npos) break;
        std::string cand = app_id.substr(0, dot + 1);
        if (cand.size() > 15) break;
        prefix = cand; pos = dot + 1;
    }
    if (prefix.empty()) { print_err("the first label of --app-id is too long for the 16-byte namespace field", "Use a first label of at most 14 characters (e.g. org, com, io)."); return EX_USAGE_; }

    auto t0 = std::chrono::steady_clock::now();
    auto lap = [&]() { auto t1 = std::chrono::steady_clock::now(); double ms = std::chrono::duration<double, std::milli>(t1 - t0).count(); t0 = t1; char b[32]; std::snprintf(b, sizeof b, "%.1f ms", ms); return std::string(b); };
    std::string err;
    DemoKeys keys;

    if (!json) banner("build", ui::bold(app_id) + " " + version + " " + ui::g_arrow() + " " + base_name(out_path));

    /* 1. payload */
    std::vector<uint8_t> payload_raw; bool demo_payload = a.get("--payload").empty();
    if (demo_payload) {
        payload_raw.resize(160 * 1024);
        for (size_t i = 0; i < payload_raw.size(); i++) payload_raw[i] = static_cast<uint8_t>((i * 131 + 17) & 0xFF);
    } else if (!read_file(a.get("--payload"), payload_raw, err, 512ULL << 20)) { print_err(err); return EX_IO_; }
    if (payload_raw.empty()) { print_err("payload is empty"); return EX_USAGE_; }
    const uint64_t *gear = cup_fastcdc_get_static_gear_table();
    std::vector<struct cup_chunk_desc> chunks;
    for (size_t off = 0; off < payload_raw.size();) {
        size_t clen = cup_fastcdc_next_chunk(payload_raw.data() + off, payload_raw.size() - off, gear);
        if (clen == 0) { print_err("chunker returned an empty chunk"); return EX_IO_; }
        struct cup_chunk_desc cd{};
        cd.payload_rel_offset = off; cd.uncompressed_len = static_cast<uint32_t>(clen); cd.compressed_len = static_cast<uint32_t>(clen);
        if (cup_hash_leaf_prefixed(CUP_HASH_ALG_SHA256, payload_raw.data() + off, clen, cd.leaf_hash) != CUP_OK) { print_err("leaf-hash overflow guard triggered"); return EX_IO_; }
        chunks.push_back(cd);
        off += clen;
    }
    uint8_t merkle_root[32]; size_t merkle_depth = 0;
    cup_merkle_build_root(CUP_HASH_ALG_SHA256, chunks.data(), chunks.size(), merkle_root, &merkle_depth);
    std::string merkle_hex = hex(merkle_root, 32);
    if (!json) step(St::Pass, "chunked payload", ui::human_bytes(payload_raw.size()) + " " + ui::g_arrow() + " " + std::to_string(chunks.size()) + " chunk" + (chunks.size() == 1 ? "" : "s") + (demo_payload ? "  (synthetic demo payload)" : "") + "  " + lap());
    if (!json) step(St::Pass, "merkle root", ui::short_hex(merkle_hex, 10, 8) + "  depth " + std::to_string(merkle_depth));

    /* 2. EROFS image + digest */
    std::vector<uint8_t> erofs_img; bool demo_erofs = a.get("--erofs").empty();
    if (demo_erofs) {
        erofs_img.assign(8192, 0);
        erofs_img[1024] = 0xE2; erofs_img[1025] = 0xE1; erofs_img[1026] = 0xF5; erofs_img[1027] = 0xE0;
        std::memcpy(erofs_img.data() + 1028, app_id.c_str(), std::min(app_id.size(), size_t(64)));
    } else {
        if (!read_file(a.get("--erofs"), erofs_img, err, 2ULL << 30)) { print_err(err); return EX_IO_; }
        if (erofs_img.size() < 4096 || erofs_img.size() % 4096 != 0) { print_err("--erofs image must be a non-empty multiple of 4096 bytes", "Pad it, or build it with mkfs.erofs -b 4096."); return EX_USAGE_; }
    }
    std::vector<uint8_t> fsverity_sec(4096, 0);
    cup_sha256(erofs_img.data(), erofs_img.size(), fsverity_sec.data());
    std::string fsverity_hex = hex(fsverity_sec.data(), 32);
    if (!json) step(demo_erofs ? St::Warn : St::Pass, "sealed EROFS image", ui::human_bytes(erofs_img.size()) + (demo_erofs ? "  (demo image, not a real filesystem)" : "") + "  " + ui::short_hex(fsverity_hex, 8, 6));

    /* 2b. bootstrap stub (v3 only) and header flags, decided BEFORE the manifest so the manifest can sign them */
    std::vector<uint8_t> stub_bytes; std::string stub_note;
    if (major_ver == 3 && !a.has("--no-stub")) {
        std::string sp = find_stub(a.get("--stub"));
        if (sp.empty()) stub_note = "cup-stub not found next to this binary; flag cleared";
        else if (!read_file(sp, stub_bytes, err, 64 * 1024)) { print_err(err); return EX_IO_; }
        else if (stub_bytes.size() < 64 || stub_bytes[0] != 0x7F || stub_bytes[1] != 'E') { print_err("'" + sp + "' is not an ELF image"); return EX_USAGE_; }
    }
    bool stub_in = !stub_bytes.empty();
    uint32_t pkg_flags = CUP_FLAG_READ_ONLY_RT | CUP_FLAG_NO_NETWORK;
    if (major_ver >= 2) pkg_flags |= CUP_FLAG_EROFS_DIRECT | CUP_FLAG_FSVERITY_SEALED | CUP_FLAG_ABI_SLICE;
    if (major_ver == 3) {
        pkg_flags |= CUP_FLAG_PGO_DAX_HOT | CUP_FLAG_COW_STATE_SNAP | CUP_FLAG_COMPOSEFS_DAX;
        if (stub_in) pkg_flags |= CUP_FLAG_SELF_BOOTSTRAP;
    }
    const unsigned sig_alg_id = (major_ver == 3) ? 3u : 1u;
    std::string stub_hex;
    if (stub_in) { uint8_t sd[32]; cup_sha256(stub_bytes.data(), stub_bytes.size(), sd); stub_hex = hex(sd, 32); }

    /* 3. manifest */
    std::ostringstream man_oss;
    man_oss << "{\"abi\":\"glibc-2.38+wayland-1.22\","
            << "\"abi_slices\":[\"org.cup.Slice.glibc/2.38\",\"org.cup.Slice.wayland/1.22\",\"org.cup.Slice.qt6-gui/6.7\"],"
            << "\"arch\":\"x86_64\",\"chunk_count\":" << chunks.size() << ",\"entrypoint\":\"" << entry << "\","
            << "\"erofs_verity_root\":\"" << fsverity_hex << "\",\"flags\":" << pkg_flags << ",\"id\":\"" << app_id << "\",\"merkle_root\":\"" << merkle_hex << "\","
            << "\"network\":false,\"sandbox_tier\":\"gui-wayland\",\"schema\":\"" << static_cast<int>(major_ver) << ".0\",\"sig_alg\":" << sig_alg_id << ","
            << (stub_in ? "\"stub_sha256\":\"" + stub_hex + "\"," : std::string()) << "\"version\":\"" << version << "\"}";
    std::string man_str = man_oss.str();
    std::vector<uint8_t> man_bytes(man_str.begin(), man_str.end());
    uint8_t man_sha256[32];
    cup_sha256(man_bytes.data(), man_bytes.size(), man_sha256);
    std::string man_hex = hex(man_sha256, 32);
    if (!json) step(St::Pass, "canonical manifest", ui::human_bytes(man_bytes.size()) + "  sha256 " + ui::short_hex(man_hex, 8, 6));

    /* 4. signature section */
    struct cup_signature_section sig_sec{};
    sig_sec.sig_format_version = major_ver;
    sig_sec.sig_alg = (major_ver == 3) ? 0x03 : 0x01;
    sig_sec.chain_length = 2;
    sig_sec.rekor_proof_len = (major_ver == 3) ? sizeof(struct cup_pq_hybrid_bundle) : 0;
    std::memcpy(sig_sec.signer_pubkey, keys.maint_pub, 32);
    uint8_t dom_msg[20 + 32];
    const char *dom_prefix = (major_ver == 3) ? "CUP-MANIFEST-SIG-V3" : "CUP-MANIFEST-SIG-V2";
    std::memcpy(dom_msg, dom_prefix, 20);
    std::memcpy(dom_msg + 20, man_sha256, 32);
    if (major_ver == 1) cup_ed25519_sign(man_sha256, 32, keys.maint_seed, sig_sec.ed25519_signature);
    else                cup_ed25519_sign(dom_msg, sizeof(dom_msg), keys.maint_seed, sig_sec.ed25519_signature);
    sig_sec.tsa_timestamp = 1761264000ULL;
    std::memcpy(sig_sec.tsa_pubkey, keys.tsa_pub, 32);
    uint8_t tsa_msg[11 + 32 + 8];
    std::memcpy(tsa_msg, "CUP-TSA-V2", 11);
    std::memcpy(tsa_msg + 11, man_sha256, 32);
    cup_write_u64le(tsa_msg + 43, sig_sec.tsa_timestamp);
    cup_ed25519_sign(tsa_msg, sizeof(tsa_msg), keys.tsa_seed, sig_sec.tsa_signature);

    auto make_cert = [&](struct cup_certificate &c, const uint8_t *subj, const uint8_t *iss, const uint8_t *iss_seed, uint64_t until, uint16_t usage, const char *pfx) {
        std::memcpy(c.subject_pubkey, subj, 32); std::memcpy(c.issuer_pubkey, iss, 32);
        c.valid_from = 1700000000ULL; c.valid_until = until; c.usage_mask = usage;
        std::strncpy(c.allowed_prefix, pfx, 15);
        uint8_t tbs[104];
        std::memcpy(tbs, c.subject_pubkey, 32); std::memcpy(tbs + 32, c.issuer_pubkey, 32);
        std::memcpy(tbs + 64, reinterpret_cast<const uint8_t *>(&c) + 128, 40);
        cup_ed25519_sign(tbs, sizeof(tbs), iss_seed, c.cert_signature);
    };
    make_cert(sig_sec.chain[0], keys.maint_pub, keys.distro_pub, keys.distro_seed, 1900000000ULL, CUP_KEY_USAGE_PKG_SIGN, prefix.c_str());
    make_cert(sig_sec.chain[1], keys.distro_pub, keys.root_pub, keys.root_seed, 1950000000ULL, CUP_KEY_USAGE_CA_INT, "*");

    size_t sig_wire_len = 208 + 2 * sizeof(struct cup_certificate) + sig_sec.rekor_proof_len;
    std::vector<uint8_t> sig_wire(sig_wire_len, 0);
    cup_write_u32le(sig_wire.data() + 0, sig_sec.sig_format_version);
    sig_wire[4] = sig_sec.sig_alg; sig_wire[5] = sig_sec.chain_length;
    cup_write_u16le(sig_wire.data() + 6, sig_sec.rekor_proof_len);
    std::memcpy(sig_wire.data() + 8, sig_sec.signer_pubkey, 32);
    std::memcpy(sig_wire.data() + 40, sig_sec.ed25519_signature, 64);
    cup_write_u64le(sig_wire.data() + 104, sig_sec.tsa_timestamp);
    std::memcpy(sig_wire.data() + 112, sig_sec.tsa_pubkey, 32);
    std::memcpy(sig_wire.data() + 144, sig_sec.tsa_signature, 64);
    std::memcpy(sig_wire.data() + 208, &sig_sec.chain[0], 2 * sizeof(struct cup_certificate));
    if (major_ver == 3) {
        auto pq = std::make_unique<struct cup_pq_hybrid_bundle>();
        std::memset(pq.get(), 0, sizeof(*pq));
        std::memcpy(pq->magic, "PQ65", 4);
        cup_mldsa65_keypair_from_seed(keys.pq_seed, pq->mldsa65_pubkey, nullptr);
        cup_mldsa65_sign(dom_msg, sizeof(dom_msg), keys.pq_seed, pq->mldsa65_sig);
        cup_sha256(pq->mldsa65_pubkey, CUP_MLDSA65_PUBKEY_BYTES, pq->pubkey_sha256);
        std::memcpy(sig_wire.data() + 208 + 2 * sizeof(struct cup_certificate), pq.get(), sizeof(*pq));
    }
    if (!json) step(St::Pass, major_ver == 3 ? "signed (Ed25519 + PQ slot)" : "signed (Ed25519)", "chain leaf " + std::string(ui::g_arrow()) + " distro CA " + ui::g_arrow() + " root, namespace " + prefix + "*");

    std::vector<uint8_t> idx_bytes(chunks.size() * sizeof(struct cup_chunk_desc));
    std::memcpy(idx_bytes.data(), chunks.data(), idx_bytes.size());

    /* 5. bootstrap stub: loaded above */
    if (!json && major_ver == 3) step(stub_in ? St::Pass : St::Warn, "bootstrap stub", stub_in ? ui::human_bytes(stub_bytes.size()) + " static ELF64" : (a.has("--no-stub") ? std::string("omitted (--no-stub); SELF_BOOTSTRAP flag cleared") : stub_note));

    /* 6. layout */
    struct RawSec { uint32_t type, flags; uint64_t align; const std::vector<uint8_t> *data; uint64_t offset; };
    std::vector<RawSec> secs = {
        {CUP_SECT_MANIFEST, CUP_SFLAG_STREAMABLE, 8, &man_bytes, 0},
        {CUP_SECT_SIGNATURE, 0, 8, &sig_wire, 0},
        {CUP_SECT_INDEX, 0, 64, &idx_bytes, 0},
        {CUP_SECT_PAYLOAD, CUP_SFLAG_PAGE_ALIGNED, 4096, &payload_raw, 0},
        {CUP_SECT_EROFS_IMAGE, CUP_SFLAG_PAGE_ALIGNED, 4096, &erofs_img, 0},
        {CUP_SECT_FSVERITY, CUP_SFLAG_PAGE_ALIGNED, 4096, &fsverity_sec, 0},
    };
    if (stub_in) secs.push_back({CUP_SECT_ELF_BOOTSTRAP, 0, 64, &stub_bytes, 0});
    const uint32_t section_count = (uint32_t)secs.size();
    uint64_t cur = 128ULL + section_count * 64ULL;
    for (auto &s : secs) { cur = align_up(cur, s.align); s.offset = cur; cur += s.data->size(); }
    cur = align_up(cur, 8);
    uint64_t total = cur + 32ULL;

    uint8_t header[128], footer[32];
    int rc = cup_pack_header_and_footer_ext(major_ver, pkg_flags, total, section_count, secs[0].offset, secs[0].data->size(), secs[2].offset, secs[3].offset,
                                            "glibc-2.38+wl", (major_ver == 3) ? "org.cup.Rt/3.0" : "org.cup.Rt/2.0", 0x01, sig_sec.sig_alg, 0x01, 12, 0x00060600U, header, footer);
    if (rc != CUP_OK) { print_err(std::string("header pack error: ") + cup_strerror(rc)); return EX_IO_; }

    std::vector<uint8_t> file_buf(total, 0);
    std::memcpy(file_buf.data(), header, 128);
    for (size_t i = 0; i < secs.size(); i++) {
        uint8_t *ent = file_buf.data() + 128 + i * 64;
        cup_write_u32le(ent + 0, secs[i].type); cup_write_u32le(ent + 4, secs[i].flags);
        cup_write_u64le(ent + 8, secs[i].offset); cup_write_u64le(ent + 16, secs[i].data->size());
        uint8_t h[32]; cup_sha256(secs[i].data->data(), secs[i].data->size(), h);
        std::memcpy(ent + 24, h, 32); cup_write_u64le(ent + 56, secs[i].data->size());
        std::memcpy(file_buf.data() + secs[i].offset, secs[i].data->data(), secs[i].data->size());
    }
    std::memcpy(file_buf.data() + total - 32, footer, 32);

    if (!write_file_atomic(out_path, file_buf, err)) { print_err(err); return EX_IO_; }
    std::string uri = "cup://sha256/" + man_hex + "?id=" + app_id + "&v=" + version;
    if (json) {
        std::cout << "{\"tool\":\"cup-installer\",\"command\":\"build\",\"ok\":true,\"path\":" << jq(out_path) << ",\"bytes\":" << total << ",\"format\":" << (int)major_ver
                  << ",\"app_id\":" << jq(app_id) << ",\"version\":" << jq(version) << ",\"uri\":" << jq(uri) << ",\"chunks\":" << chunks.size()
                  << ",\"merkle_root\":" << jq(merkle_hex) << ",\"erofs_digest\":" << jq(fsverity_hex) << ",\"sections\":" << section_count
                  << ",\"stub_embedded\":" << jbool(stub_in) << ",\"demo_keys\":true}\n";
        return EX_OK_;
    }
    step(St::Pass, "wrote " + out_path, ui::human_bytes(total) + " " + ui::g_dot() + " " + std::to_string(section_count) + " sections");
    std::cout << "\n  " << ui::paint(C::Green, ui::bold(std::string(ui::g_ok()) + " BUILT")) << "  " << uri << "\n";
    if (!ui::S().quiet) {
        std::cout << "\n  " << ui::paint(C::Amber, ui::g_warn()) << " " << "signed with the public DEMO keys: fine for testing, never publish it.\n"
                  << "  " << ui::dim(std::string(ui::g_arrow()) + " next:  " + g_prog + " verify " + out_path) << "\n\n";
    }
    return EX_OK_;
}

/* ------------------------------------------------------------------ install / upgrade / rollback */
bool stage_package(const std::vector<uint8_t> &buf, const Report &r, const std::string &dir, std::string &summary) {
    mkdir(dir.c_str(), 0755);
    if (!write_text(dir + "/manifest.json", r.manifest_text)) return false;
    size_t chunks = 0, bytes = 0; bool img = false;
    uint64_t pay_off = 0, pay_len = 0, idx_off = 0, idx_len = 0, ero_off = 0, ero_len = 0;
    for (auto &s : r.sections) {
        if (s.type == CUP_SECT_PAYLOAD) { pay_off = s.off; pay_len = s.len; }
        if (s.type == CUP_SECT_INDEX) { idx_off = s.off; idx_len = s.len; }
        if (s.type == CUP_SECT_EROFS_IMAGE) { ero_off = s.off; ero_len = s.len; }
    }
    if (idx_len && pay_len) {
        mkdir((dir + "/cas").c_str(), 0755);
        for (uint64_t i = 0; i + sizeof(struct cup_chunk_desc) <= idx_len; i += sizeof(struct cup_chunk_desc)) {
            struct cup_chunk_desc cd; std::memcpy(&cd, buf.data() + idx_off + i, sizeof cd);
            std::ofstream o(dir + "/cas/" + hex(cd.leaf_hash, 32), std::ios::binary | std::ios::trunc);
            o.write(reinterpret_cast<const char *>(buf.data() + pay_off + cd.payload_rel_offset), cd.uncompressed_len);
            if (!o) return false;
            chunks++; bytes += cd.uncompressed_len;
        }
    }
    if (ero_len) {
        std::ofstream o(dir + "/app.erofs", std::ios::binary | std::ios::trunc);
        o.write(reinterpret_cast<const char *>(buf.data() + ero_off), (std::streamsize)ero_len);
        if (!o) return false;
        img = true;
    }
    std::ostringstream s;
    s << "manifest.json, " << chunks << " chunk" << (chunks == 1 ? "" : "s") << " (" << ui::human_bytes(bytes) << ")" << (img ? ", app.erofs" : "");
    summary = s.str();
    return true;
}

int cmd_deploy(const Args &a, bool is_upgrade, bool json) {
    const char *verb = is_upgrade ? "upgrade" : "install";
    if (a.pos.size() != 1) { print_err(std::string(verb) + " needs exactly one package"); return EX_USAGE_; }
    if (a.get("--root").empty()) { print_err("--root DIR is required", "Pick where packages live, e.g. " + g_prog + " " + verb + " app.cup --root ~/.cup"); return EX_USAGE_; }
    const std::string pkg = a.pos[0], root = a.get("--root");
    Options opt; std::string err;
    if (!build_options(a, opt, err)) { print_err(err); return EX_USAGE_; }
    std::vector<uint8_t> buf;
    if (!read_file(pkg, buf, err)) { print_err(err); return EX_IO_; }
    Report r = verify_buffer(buf, opt);
    r.path = pkg;
    if (!r.ok()) {
        if (json) std::cout << "{\"tool\":\"cup-installer\",\"command\":\"" << verb << "\",\"ok\":false,\"stage\":\"verify\",\"verification\":" << report_json(r) << "}\n";
        else { print_report(r); std::cout << "  " << ui::dim("Nothing was changed on disk.") << "\n\n"; }
        return EX_VERIFY_;
    }
    const std::string active_marker = root + "/active/DEPLOYED_PACKAGE.txt";
    std::string cur_digest = read_kv(active_marker, "digest"), cur_ver = read_kv(active_marker, "version"), cur_id = read_kv(active_marker, "id");
    bool have_active = !cur_digest.empty();
    auto fail = [&](const std::string &m, const std::string &h) { if (json) std::cout << "{\"tool\":\"cup-installer\",\"command\":\"" << verb << "\",\"ok\":false,\"error\":" << jq(m) << "}\n"; else print_err(m, h); };
    if (have_active && cur_digest == r.manifest_sha_hex) {
        if (json) std::cout << "{\"tool\":\"cup-installer\",\"command\":\"" << verb << "\",\"ok\":true,\"changed\":false,\"reason\":\"already installed\"}\n";
        else { banner(verb, ui::bold(r.app_id) + " " + r.version); step(St::Info, "already installed", "same manifest digest, nothing to do"); std::cout << "\n"; }
        return EX_OK_;
    }
    if (!is_upgrade && have_active && !cur_id.empty() && cur_id != r.app_id) { fail("'" + cur_id + "' is already active in " + root, "One deployment root holds one package id; pick another --root."); return EX_VERIFY_; }
    const bool upgrading = is_upgrade || have_active;   /* 'install' over the same id == upgrade (keeps a rollback copy) */
    if (is_upgrade && !have_active) { fail("nothing is installed in " + root + " yet", "Use '" + g_prog + " install' for the first deployment."); return EX_VERIFY_; }
    if (is_upgrade && !cur_id.empty() && cur_id != r.app_id) { fail("active package is '" + cur_id + "', this one is '" + r.app_id + "'", "Upgrades must keep the same package id."); return EX_VERIFY_; }
    if (upgrading && version_cmp(r.version, cur_ver) < 0 && !a.has("--allow-downgrade")) {
        fail("refusing to downgrade " + cur_ver + " " + std::string(ui::g_arrow()) + " " + r.version, "Pass --allow-downgrade if this is intentional (rollback attacks replay old, vulnerable builds).");
        return EX_VERIFY_;
    }
    bool dry = a.has("--dry-run");
    if (!json) banner(verb, ui::bold(r.app_id) + " " + r.version + " " + ui::g_arrow() + " " + root + (dry ? "  (dry run)" : ""));
    if (!json) step(St::Pass, "verified", ui::short_hex(r.manifest_sha_hex, 8, 6) + (r.warns ? "  " + std::to_string(r.warns) + " warning(s), run verify for details" : ""));
    if (dry) {
        if (json) std::cout << "{\"tool\":\"cup-installer\",\"command\":\"" << verb << "\",\"ok\":true,\"dry_run\":true,\"uri\":" << jq(r.uri) << "}\n";
        else { step(St::Info, "plan", std::string("stage ") + ui::g_arrow() + " swap active" + (upgrading ? " (keep previous as rollback)" : "")); std::cout << "\n  " << ui::dim("Dry run: nothing was changed.") << "\n\n"; }
        return EX_OK_;
    }

    if (mkdir(root.c_str(), 0755) != 0 && errno != EEXIST) { print_err("cannot create '" + root + "': " + std::strerror(errno)); return EX_IO_; }
    const std::string staging = root + "/staging", state_staging = root + "/state-staging";
    rm_rf(staging); rm_rf(state_staging);
    std::string summary;
    if (!stage_package(buf, r, staging, summary)) { rm_rf(staging); print_err("could not stage package contents in " + staging + ": " + std::strerror(errno)); return EX_IO_; }
    char ts[32]; { time_t t = time(nullptr); struct tm tmv{}; gmtime_r(&t, &tmv); std::strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tmv); }
    write_text(staging + "/DEPLOYED_PACKAGE.txt", "package=" + pkg + "\nid=" + r.app_id + "\nversion=" + r.version + "\ndigest=" + r.manifest_sha_hex + "\nmode=" + verb + "\ninstalled_at=" + ts + "\n");
    if (!json) step(St::Pass, "staged", summary);

    mkdir(state_staging.c_str(), 0755);
    size_t cloned = 0;
    if (upgrading) {
        int sfd = open((root + "/state-active").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC), dfd2 = open(state_staging.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (sfd >= 0 && dfd2 >= 0) {
            int dup_fd = dup(sfd);
            if (DIR *d = fdopendir(dup_fd)) {
                while (struct dirent *e = readdir(d)) {
                    struct stat st{};
                    if (e->d_name[0] == '.' || fstatat(sfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode)) continue;
                    if (cup_cow_clone_state_file(sfd, e->d_name, dfd2, e->d_name, st.st_mode & 0777) == 0) cloned++;
                }
                closedir(d);
            } else close(dup_fd);
        }
        if (sfd >= 0) close(sfd);
        if (dfd2 >= 0) close(dfd2);
    } else {
        write_text(state_staging + "/user_state.db", "schema=v3.0\nid=" + r.app_id + "\n");
    }
    write_text(state_staging + "/.cup-state-meta", "id=" + r.app_id + "\nversion=" + r.version + "\n");
    if (!json) step(St::Pass, upgrading ? "user state snapshot" : "user state created", upgrading ? std::to_string(cloned) + " file(s) cloned (reflink or copy)" : "state-active/user_state.db");

    int dfd = open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) { print_err("cannot open deployment root: " + std::string(std::strerror(errno))); return EX_IO_; }
    int rc1 = cup_atomic_swap_deployment(dfd, "staging", "active", "rollback");
    int rc2 = cup_atomic_swap_deployment(dfd, "state-staging", "state-active", "state-rollback");
    if (rc1 != CUP_OK || rc2 != CUP_OK) {
        close(dfd);
        print_err(std::string("atomic swap failed: ") + cup_strerror(rc1 != CUP_OK ? rc1 : rc2), "The previous version is untouched.");
        return EX_IO_;
    }
    struct stat ls{};
    bool symlinked = fstatat(dfd, "active", &ls, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(ls.st_mode);
    std::string how = symlinked ? "atomic symlink swap (renameat over 'active')" : "renameat2(RENAME_EXCHANGE): 'active' never absent";
    if (!json) step(St::Pass, "activated", how);

    bool rolled_back = false;
    if (upgrading && a.has("--simulate-crash")) {
        if (!json) step(St::Info, "watchdog", "starting new version under the 5000 ms health window");
        pid_t pid = fork();
        if (pid == 0) { usleep(20 * 1000); _exit(139); }
        int wrc = cup_watchdog_monitor_first_launch(pid, 5000, dfd, dfd);
        if (wrc == -CUP_E_RENAME) {
            rolled_back = true;
            if (!json) step(St::Warn, "crash detected (simulated, exit 139)", "binary AND user state rolled back together");
        }
    }
    close(dfd);
    std::string now_ver = read_kv(active_marker, "version");
    if (json) {
        std::cout << "{\"tool\":\"cup-installer\",\"command\":\"" << verb << "\",\"ok\":true,\"changed\":true,\"rolled_back\":" << jbool(rolled_back)
                  << ",\"active_version\":" << jq(now_ver) << ",\"previous_version\":" << jq(cur_ver) << ",\"uri\":" << jq(r.uri) << "}\n";
        return EX_OK_;
    }
    std::cout << "\n  " << ui::paint(C::Green, ui::bold(std::string(ui::g_ok()) + (rolled_back ? " ROLLED BACK" : " ACTIVE"))) << "  " << r.app_id << " " << ui::bold(now_ver);
    if (!cur_ver.empty() && !rolled_back) std::cout << ui::dim("  (previous " + cur_ver + " kept: " + g_prog + " rollback --root " + root + ")");
    std::cout << "\n\n";
    return EX_OK_;
}

int cmd_rollback(const Args &a, bool json) {
    if (a.get("--root").empty()) { print_err("--root DIR is required", "Example: " + g_prog + " rollback --root ~/.cup"); return EX_USAGE_; }
    const std::string root = a.get("--root");
    struct stat st{};
    if (lstat((root + "/rollback").c_str(), &st) != 0) {
        print_err("nothing to roll back to in " + root, "A rollback copy exists only after an 'upgrade'.");
        return EX_VERIFY_;
    }
    std::string from = read_kv(root + "/active/DEPLOYED_PACKAGE.txt", "version"), to = read_kv(root + "/rollback/DEPLOYED_PACKAGE.txt", "version");
    int dfd = open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) { print_err("cannot open '" + root + "': " + std::strerror(errno)); return EX_IO_; }
    int rc1 = cup_atomic_swap_deployment(dfd, "rollback", "active", nullptr);
    int rc2 = (lstat((root + "/state-rollback").c_str(), &st) == 0) ? cup_atomic_swap_deployment(dfd, "state-rollback", "state-active", nullptr) : CUP_OK;
    close(dfd);
    if (rc1 != CUP_OK || rc2 != CUP_OK) { print_err(std::string("atomic swap failed: ") + cup_strerror(rc1 != CUP_OK ? rc1 : rc2)); return EX_IO_; }
    if (json) { std::cout << "{\"tool\":\"cup-installer\",\"command\":\"rollback\",\"ok\":true,\"from\":" << jq(from) << ",\"to\":" << jq(to) << "}\n"; return EX_OK_; }
    banner("rollback", root);
    step(St::Pass, "binary", from + " " + ui::g_arrow() + " " + to);
    step(St::Pass, "user state", "swapped together with the binary");
    std::cout << "\n  " << ui::paint(C::Green, ui::bold(std::string(ui::g_ok()) + " ACTIVE")) << "  " << to << ui::dim("  (run rollback again to swap forward)") << "\n\n";
    return EX_OK_;
}

} // namespace

int main(int argc, char **argv) {
    g_prog = base_name(argv[0]);
    if (argc < 2) { ui::init("auto", "auto"); print_help(); return EX_OK_; }
    std::string cmd = argv[1];
    if (cmd == "--version" || cmd == "-V") { std::cout << g_prog << " " << TOOL_VERSION << " (RFC CUP-3.0, libcup2)\n"; return EX_OK_; }

    Args a; std::string err;
    int first = (cmd.size() > 0 && cmd[0] == '-') ? 1 : 2;
    if (!parse_args(argc, argv, first, a, err)) { ui::init("auto", "auto"); print_err(err, "Run '" + g_prog + " help' for usage."); return EX_USAGE_; }
    std::string mode = a.has("--no-color") ? "never" : a.get("--color", "auto");
    if (mode != "auto" && mode != "always" && mode != "never") { ui::init("auto", "auto"); print_err("--color expects auto, always or never"); return EX_USAGE_; }
    bool json = a.has("--json");
    ui::init(json ? "never" : mode, a.has("--ascii") ? "ascii" : a.has("--unicode") ? "unicode" : "auto");
    ui::S().quiet = a.has("--quiet") || a.has("-q");
    ui::S().verbose = a.has("--verbose") || a.has("-v");

    if (cmd == "--help" || cmd == "-h") { print_help(); return EX_OK_; }
    if (cmd == "help") { if (a.pos.empty()) { print_help(); return EX_OK_; } return print_cmd_help(a.pos[0]); }
    if (a.has("--help") || a.has("-h")) return print_cmd_help(cmd);

    if (cmd == "build")   return cmd_build(a, json);
    if (cmd == "verify")  return cmd_verify(a, json);
    if (cmd == "inspect") return cmd_inspect(a, json);
    if (cmd == "install") return cmd_deploy(a, false, json);
    if (cmd == "upgrade") return cmd_deploy(a, true, json);
    if (cmd == "rollback") return cmd_rollback(a, json);
    if (cmd == "run" || cmd == "convert") {
        print_err("'" + cmd + "' is not available in this reference build",
                  cmd == "run" ? "Launching needs the cup-box sandbox (user namespaces + Landlock + seccomp). Use 'install' to deploy verified packages."
                               : "Linglong/deb import is not implemented here.");
        return EX_UNAVAIL_;
    }
    print_err("unknown command '" + cmd + "'", "Run '" + g_prog + " help' for the list of commands.");
    return EX_USAGE_;
}
