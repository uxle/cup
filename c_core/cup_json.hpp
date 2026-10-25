/* [NORMATIVE] cup_json.hpp - minimal STRICT JSON parser for CUP manifests (RFC 8259 subset).
 * Replaces substring searching of raw manifest bytes (which let a nested decoy "id" shadow the real
 * top-level id). Rejects: duplicate object keys, trailing garbage, control characters in strings,
 * depth > 32, malformed numbers/escapes, invalid UTF-8 in \u escapes (lone surrogates). */
#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace cupjson {

struct Val {
    enum T { Null, Bool, Num, Str, Arr, Obj } t = Null;
    bool b = false;
    double n = 0;
    std::string s;
    std::vector<Val> a;
    std::vector<std::pair<std::string, Val>> o;
    const Val *get(const char *key) const {
        if (t != Obj) return nullptr;
        for (auto &kv : o) if (kv.first == key) return &kv.second;
        return nullptr;
    }
};

class Parser {
public:
    Parser(const char *p, size_t n) : p_(p), end_(p + n) {}
    bool parse(Val &out, std::string &err) {
        skip();
        if (!value(out, 0)) { err = err_ + " at byte " + std::to_string(p_ - start_()); return false; }
        skip();
        if (p_ != end_) { err = "trailing data after JSON value at byte " + std::to_string(p_ - start_()); return false; }
        return true;
    }
private:
    const char *p_, *end_;
    const char *s0_ = nullptr;
    std::string err_;
    const char *start_() { if (!s0_) s0_ = p_; return s0_; }
    bool fail(const char *m) { err_ = m; return false; }
    void skip() { while (p_ < end_ && (*p_ == ' ' || *p_ == '\t' || *p_ == '\n' || *p_ == '\r')) p_++; }
    bool lit(const char *w) { size_t l = std::strlen(w); if ((size_t)(end_ - p_) >= l && !std::memcmp(p_, w, l)) { p_ += l; return true; } return false; }
    static void put_utf8(std::string &o, uint32_t cp) {
        if (cp < 0x80) o += (char)cp;
        else if (cp < 0x800) { o += (char)(0xC0 | (cp >> 6)); o += (char)(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) { o += (char)(0xE0 | (cp >> 12)); o += (char)(0x80 | ((cp >> 6) & 0x3F)); o += (char)(0x80 | (cp & 0x3F)); }
        else { o += (char)(0xF0 | (cp >> 18)); o += (char)(0x80 | ((cp >> 12) & 0x3F)); o += (char)(0x80 | ((cp >> 6) & 0x3F)); o += (char)(0x80 | (cp & 0x3F)); }
    }
    bool hex4(uint32_t &v) {
        if (end_ - p_ < 4) return fail("short \\u escape");
        v = 0;
        for (int i = 0; i < 4; i++) {
            char c = *p_++; v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0'; else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10; else return fail("bad hex digit in \\u escape");
        }
        return true;
    }
    bool str(std::string &o) {
        if (p_ >= end_ || *p_ != '"') return fail("expected string");
        p_++;
        while (p_ < end_) {
            unsigned char c = (unsigned char)*p_++;
            if (c == '"') return true;
            if (c < 0x20) return fail("control character in string");
            if (c != '\\') { o += (char)c; continue; }
            if (p_ >= end_) break;
            char e = *p_++;
            switch (e) {
                case '"': o += '"'; break; case '\\': o += '\\'; break; case '/': o += '/'; break;
                case 'b': o += '\b'; break; case 'f': o += '\f'; break; case 'n': o += '\n'; break;
                case 'r': o += '\r'; break; case 't': o += '\t'; break;
                case 'u': {
                    uint32_t cp;
                    if (!hex4(cp)) return false;
                    if (cp >= 0xD800 && cp < 0xDC00) {
                        uint32_t lo;
                        if (end_ - p_ < 2 || p_[0] != '\\' || p_[1] != 'u') return fail("lone high surrogate");
                        p_ += 2;
                        if (!hex4(lo)) return false;
                        if (lo < 0xDC00 || lo > 0xDFFF) return fail("bad low surrogate");
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) return fail("lone low surrogate");
                    put_utf8(o, cp);
                    break;
                }
                default: return fail("invalid escape");
            }
        }
        return fail("unterminated string");
    }
    bool value(Val &v, int depth) {
        if (depth > 32) return fail("nesting too deep");
        if (p_ >= end_) return fail("unexpected end of input");
        char c = *p_;
        if (c == '{') {
            v.t = Val::Obj; p_++; skip();
            if (p_ < end_ && *p_ == '}') { p_++; return true; }
            for (;;) {
                skip();
                std::string k;
                if (!str(k)) return false;
                for (auto &kv : v.o) if (kv.first == k) return fail("duplicate object key");
                skip();
                if (p_ >= end_ || *p_ != ':') return fail("expected ':'");
                p_++; skip();
                Val child;
                if (!value(child, depth + 1)) return false;
                v.o.emplace_back(std::move(k), std::move(child));
                skip();
                if (p_ < end_ && *p_ == ',') { p_++; continue; }
                if (p_ < end_ && *p_ == '}') { p_++; return true; }
                return fail("expected ',' or '}'");
            }
        }
        if (c == '[') {
            v.t = Val::Arr; p_++; skip();
            if (p_ < end_ && *p_ == ']') { p_++; return true; }
            for (;;) {
                skip();
                Val child;
                if (!value(child, depth + 1)) return false;
                v.a.push_back(std::move(child));
                skip();
                if (p_ < end_ && *p_ == ',') { p_++; continue; }
                if (p_ < end_ && *p_ == ']') { p_++; return true; }
                return fail("expected ',' or ']'");
            }
        }
        if (c == '"') { v.t = Val::Str; return str(v.s); }
        if (lit("true"))  { v.t = Val::Bool; v.b = true;  return true; }
        if (lit("false")) { v.t = Val::Bool; v.b = false; return true; }
        if (lit("null"))  { v.t = Val::Null; return true; }
        if (c == '-' || (c >= '0' && c <= '9')) {
            const char *q = p_;
            if (*q == '-') q++;
            if (q >= end_ || !(*q >= '0' && *q <= '9')) return fail("bad number");
            if (*q == '0' && q + 1 < end_ && q[1] >= '0' && q[1] <= '9') return fail("leading zero in number");
            while (q < end_ && *q >= '0' && *q <= '9') q++;
            if (q < end_ && *q == '.') { q++; if (q >= end_ || !(*q >= '0' && *q <= '9')) return fail("bad fraction"); while (q < end_ && *q >= '0' && *q <= '9') q++; }
            if (q < end_ && (*q == 'e' || *q == 'E')) { q++; if (q < end_ && (*q == '+' || *q == '-')) q++; if (q >= end_ || !(*q >= '0' && *q <= '9')) return fail("bad exponent"); while (q < end_ && *q >= '0' && *q <= '9') q++; }
            std::string tmp(p_, q);
            v.t = Val::Num; v.n = std::strtod(tmp.c_str(), nullptr);
            p_ = q;
            return true;
        }
        return fail("unexpected character");
    }
};

inline bool parse(const std::string &text, Val &out, std::string &err) {
    Parser p(text.data(), text.size());
    return p.parse(out, err);
}

} // namespace cupjson
