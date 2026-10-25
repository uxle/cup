/* [ILLUSTRATIVE] cup_ui.hpp - terminal presentation layer for the CUP toolchain.
 * Rules: colour only on a TTY (or CLICOLOR_FORCE), never when NO_COLOR is set or TERM=dumb;
 * Unicode glyphs only when the locale is UTF-8, otherwise a clean ASCII fallback;
 * machine-readable output (--json) never contains escape codes. */
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <strings.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace ui {

struct Style {
    bool color_out = false;
    bool color_err = false;
    bool unicode   = false;
    int  width     = 80;
    bool quiet     = false;
    bool verbose   = false;
};

inline Style &S() { static Style s; return s; }

inline bool env_utf8() {
    for (const char *k : {"LC_ALL", "LC_CTYPE", "LANG"}) {
        const char *v = std::getenv(k);
        if (v && *v) {
            return strcasestr(v, "utf-8") != nullptr || strcasestr(v, "utf8") != nullptr;
        }
    }
    return false;
}

/* mode: "auto" | "always" | "never" ; glyphs: "auto" | "unicode" | "ascii" */
inline void init(const std::string &mode, const std::string &glyphs) {
    Style &s = S();
    const char *term = std::getenv("TERM");
    bool dumb = (term && std::strcmp(term, "dumb") == 0);
    bool no_color = std::getenv("NO_COLOR") && *std::getenv("NO_COLOR");
    bool force = std::getenv("CLICOLOR_FORCE") && std::strcmp(std::getenv("CLICOLOR_FORCE"), "0") != 0;
    if (mode == "always")      { s.color_out = s.color_err = true; }
    else if (mode == "never")  { s.color_out = s.color_err = false; }
    else {
        s.color_out = !no_color && (force || (!dumb && isatty(STDOUT_FILENO)));
        s.color_err = !no_color && (force || (!dumb && isatty(STDERR_FILENO)));
    }
    if (glyphs == "unicode")    s.unicode = true;
    else if (glyphs == "ascii") s.unicode = false;
    else                        s.unicode = env_utf8();
    struct winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col >= 40) s.width = ws.ws_col;
    if (const char *cols = std::getenv("COLUMNS")) { int c = std::atoi(cols); if (c >= 40) s.width = c; }
    if (s.width > 100) s.width = 100;
}

/* palette (256-colour, matches the logo: teal / sky / indigo / coral) */
enum class C { Teal, Sky, Indigo, Coral, Amber, Green, Dim, Bold, Red };
inline const char *code(C c) {
    switch (c) {
        case C::Teal:   return "38;5;80";
        case C::Sky:    return "38;5;75";
        case C::Indigo: return "38;5;105";
        case C::Coral:  return "38;5;204";
        case C::Amber:  return "38;5;214";
        case C::Green:  return "38;5;78";
        case C::Red:    return "38;5;203";
        case C::Dim:    return "2";
        case C::Bold:   return "1";
    }
    return "0";
}
inline std::string paint(C c, const std::string &s, bool err = false) {
    bool on = err ? S().color_err : S().color_out;
    if (!on) return s;
    return std::string("\033[") + code(c) + "m" + s + "\033[0m";
}
inline std::string bold(const std::string &s, bool err = false) { return paint(C::Bold, s, err); }
inline std::string dim(const std::string &s, bool err = false)  { return paint(C::Dim, s, err); }

/* glyphs */
inline const char *g_ok()    { return S().unicode ? "\xE2\x9C\x94" : "OK"; }   /* ✔ */
inline const char *g_fail()  { return S().unicode ? "\xE2\x9C\x98" : "XX"; }   /* ✘ */
inline const char *g_warn()  { return S().unicode ? "\xE2\x96\xB2" : "!!"; }   /* ▲ */
inline const char *g_info()  { return S().unicode ? "\xE2\x80\xA2" : "--"; }   /* • */
inline const char *g_arrow() { return S().unicode ? "\xE2\x86\x92" : "->"; }   /* → */
inline const char *g_dot()   { return S().unicode ? "\xC2\xB7" : "|"; }        /* · */
inline const char *g_ell()   { return S().unicode ? "\xE2\x80\xA6" : "..."; }  /* … */
inline const char *g_rule()  { return S().unicode ? "\xE2\x94\x80" : "-"; }    /* ─ */
inline const char *g_mark()  { return S().unicode ? "\xE2\xAC\xA2" : "<>"; }   /* ⬢ */

inline std::string rule(int n = -1) {
    if (n < 0) n = S().width - 2;
    std::string r;
    for (int i = 0; i < n; i++) r += g_rule();
    return r;
}

inline std::string human_bytes(uint64_t b) {
    char buf[32];
    if (b < 1024ULL)                std::snprintf(buf, sizeof buf, "%llu B", (unsigned long long)b);
    else if (b < (1ULL << 20))      std::snprintf(buf, sizeof buf, "%.1f KiB", b / 1024.0);
    else if (b < (1ULL << 30))      std::snprintf(buf, sizeof buf, "%.1f MiB", b / 1048576.0);
    else                            std::snprintf(buf, sizeof buf, "%.2f GiB", b / 1073741824.0);
    return buf;
}

/* 82758c1c64ef...a3ba2 -> "82758c1c" + … + "a3ba2" */
inline std::string short_hex(const std::string &h, size_t head = 8, size_t tail = 6) {
    if (h.size() <= head + tail + 1) return h;
    return h.substr(0, head) + g_ell() + h.substr(h.size() - tail);
}

inline std::string pad(const std::string &s, size_t w) {
    /* width by display columns: count UTF-8 lead bytes */
    size_t cols = 0;
    for (unsigned char ch : s) if ((ch & 0xC0) != 0x80) cols++;
    return cols >= w ? s : s + std::string(w - cols, ' ');
}

inline std::string json_escape(const std::string &s) {
    std::string o;
    for (unsigned char ch : s) {
        switch (ch) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (ch < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", ch); o += b; }
                else o += (char)ch;
        }
    }
    return o;
}

/* wrap text to the terminal width with a hanging indent */
inline std::string wrap(const std::string &text, size_t indent, size_t first_indent) {
    size_t width = (size_t)S().width;
    std::string out, line(first_indent, ' ');
    size_t col = first_indent;
    size_t i = 0;
    while (i < text.size()) {
        size_t j = text.find(' ', i);
        if (j == std::string::npos) j = text.size();
        std::string w = text.substr(i, j - i);
        if (col + w.size() + 1 > width && col > indent) {
            out += line + "\n";
            line.assign(indent, ' ');
            col = indent;
        }
        if (col > indent && col > first_indent - (first_indent > indent ? 0 : 0) && line.size() > 0 && line.back() != ' ') { line += ' '; col++; }
        line += w; col += w.size();
        i = j + 1;
    }
    return out + line;
}

} // namespace ui
