#!/usr/bin/env python3
"""render_assets.py - generate the CUP brand assets (SVG + PNG) from one geometric source.

    python3 tools/render_assets.py            # SVGs + PNGs (PNG needs python3-playwright + chromium)
    python3 tools/render_assets.py --svg-only

The mark is a package cube that is also a fish: three faces (teal top, sky left, indigo
right), a forked coral tail, and an eye that doubles as a "verified" dot. It is built from
plain polygons so it stays legible from 16 px up. The wordmark "CUP" is drawn with strokes,
so it does not depend on any installed font. Only the small taglines use system fonts.
"""
import math, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = os.path.join(ROOT, "assets")
G = os.path.join(ROOT, "gui", "icons")

NAVY, NAVY2 = "#0B132B", "#111C3A"
TEAL, TEAL2 = "#5EEAD4", "#2DD4BF"
SKY, SKY2 = "#38BDF8", "#0EA5E9"
IND, IND2 = "#818CF8", "#5457E5"
CORAL, CORAL2 = "#FB7185", "#F43F5E"
INK = "#0F172A"
SANS = "Inter, 'Segoe UI', 'Helvetica Neue', Arial, 'DejaVu Sans', sans-serif"
MONO = "'JetBrains Mono', 'DejaVu Sans Mono', Consolas, monospace"

# ---- geometry (native coordinates, then centred on the bounding box) ---------------------
CX, CY, R = 112.0, 128.0, 72.0
def hexv(k):  # pointy-top hexagon vertices
    a = math.radians(-90 + 60 * k)
    return (CX + R * math.cos(a), CY + R * math.sin(a))
TOP, UR, LR, BOT, LL, UL = [hexv(k) for k in range(6)]
CEN = (CX, CY)
FACES = dict(top=[TOP, UR, CEN, UL], left=[UL, CEN, BOT, LL], right=[CEN, UR, LR, BOT])
TAIL = [(160, 98), (228, 64), (205, 128), (228, 192), (160, 158)]
OFFX, OFFY = 139.0, 128.0   # bbox centre of the mark


def shrink(pts, f):
    cx = sum(p[0] for p in pts) / len(pts); cy = sum(p[1] for p in pts) / len(pts)
    return [(cx + (x - cx) * f, cy + (y - cy) * f) for x, y in pts]

def P(pts):
    return " ".join(f"{x - OFFX:.2f},{y - OFFY:.2f}" for x, y in pts)

def lin(i, c1, c2, x2="1", y2="1"):
    return (f'<linearGradient id="{i}" x1="0" y1="0" x2="{x2}" y2="{y2}">'
            f'<stop offset="0" stop-color="{c1}"/><stop offset="1" stop-color="{c2}"/></linearGradient>')

def mark_defs(p):
    return (lin(p + "t", TEAL, TEAL2) + lin(p + "l", SKY, SKY2, "0", "1") +
            lin(p + "r", IND, IND2) + lin(p + "f", CORAL, CORAL2, "1", "0"))

def mark(p="m", mono=False, eye="#0F172A", glint="#fff"):
    """Return <g> of the mark centred on (0,0), about 182 x 148 units."""
    sw = 7
    if mono:
        fills = dict(top=("currentColor", 1), left=("currentColor", .66), right=("currentColor", .42))
        tail = ("currentColor", 1)
    else:
        fills = dict(top=(f"url(#{p}t)", 1), left=(f"url(#{p}l)", 1), right=(f"url(#{p}r)", 1))
        tail = (f"url(#{p}f)", 1)
    out = []
    # tail first, so the body overlaps it
    out.append(f'<polygon points="{P(shrink(TAIL, .98))}" fill="{tail[0]}" stroke="{tail[0]}" stroke-width="{sw}" stroke-linejoin="round"/>')
    for k in ("left", "right", "top"):
        f, o = fills[k]
        out.append(f'<polygon points="{P(shrink(FACES[k], .93))}" fill="{f}" stroke="{f}" stroke-width="{sw}" stroke-linejoin="round" opacity="{o}"/>')
    ex, ey = 78 - OFFX, 128 - OFFY
    if mono:
        out.append(f'<circle cx="{ex}" cy="{ey}" r="11" fill="#000"/>')   # mask hole
    else:
        out.append(f'<circle cx="{ex}" cy="{ey}" r="12" fill="{eye}"/>'
                   f'<circle cx="{ex}" cy="{ey}" r="6.5" fill="{TEAL}"/>'
                   f'<circle cx="{ex - 2.2}" cy="{ey - 2.4}" r="2.4" fill="{glint}"/>')
        out.append(f'<path d="M {97 - OFFX} {150 - OFFY} Q {85 - OFFX} {168 - OFFY} {97 - OFFX} {188 - OFFY}" '
                   f'fill="none" stroke="#fff" stroke-opacity=".55" stroke-width="4" stroke-linecap="round"/>')
    return "<g>" + "".join(out) + "</g>"

def mono_mark(p="mm"):
    ex, ey = 78 - OFFX, 128 - OFFY
    body = mark(p, mono=True).replace(f'<circle cx="{ex}" cy="{ey}" r="11" fill="#000"/>', "")
    return (f'<mask id="{p}eye" maskUnits="userSpaceOnUse" x="-120" y="-100" width="240" height="200">'
            f'<rect x="-120" y="-100" width="240" height="200" fill="#fff"/>'
            f'<circle cx="{ex}" cy="{ey}" r="11" fill="#000"/></mask><g mask="url(#{p}eye)">{body}</g>')

def wordmark(color, sw=12):
    """'CUP' as strokes; local box 0..~196 x 0..56."""
    c = (f'<path d="M 46 15.4 A 22 22 0 1 0 46 40.6" />')
    u = (f'<path d="M 78 6 V 28 A 22 22 0 0 0 122 28 V 6" />')
    pp = (f'<path d="M 152 50 V 6 H 174 A 11 11 0 0 1 174 28 H 152" />')
    return (f'<g fill="none" stroke="{color}" stroke-width="{sw}" stroke-linecap="round" stroke-linejoin="round">'
            f'{c}{u}{pp}</g>')

def svg(w, h, body, defs="", label="CUP", extra=""):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
            f'role="img" aria-label="{label}"{extra}>\n<defs>{defs}</defs>\n{body}\n</svg>\n')

def squircle(size, rx_ratio=.2237, fill="url(#bg)"):
    return f'<rect width="{size}" height="{size}" rx="{size * rx_ratio:.1f}" fill="{fill}"/>'

def bg_defs():
    return (f'<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{NAVY2}"/>'
            f'<stop offset="1" stop-color="{NAVY}"/></linearGradient>'
            f'<radialGradient id="glow" cx=".3" cy=".18" r=".8"><stop offset="0" stop-color="{TEAL}" stop-opacity=".22"/>'
            f'<stop offset="1" stop-color="{TEAL}" stop-opacity="0"/></radialGradient>')

# ---- individual assets -----------------------------------------------------------------
def app_icon(size=512, scale=1.0):
    s = size / 512
    body = (squircle(512) + '<rect width="512" height="512" rx="114" fill="url(#glow)"/>'
            f'<g transform="translate(256 256) scale({1.75 * scale:.3f})">{mark("a")}</g>')
    return svg(512, 512, body, bg_defs() + mark_defs("a"), "CUP - CuteFish Universal Package")

def mark_only():
    return svg(200, 170, f'<g transform="translate(100 85)">{mark("b")}</g>', mark_defs("b"), "CUP mark")

def mark_mono():
    return svg(200, 170, f'<g transform="translate(100 85)" style="color:#0F172A">{mono_mark("c")}</g>', "",
               "CUP mark, single colour (uses currentColor)")

def lockup(dark):
    fg = "#F1F5F9" if dark else INK
    sub = "#94A3B8" if dark else "#475569"
    bgc = NAVY if dark else "#FFFFFF"
    body = (f'<rect width="520" height="170" rx="20" fill="{bgc}"/>'
            f'<g transform="translate(100 85) scale(.82)">{mark("d", eye=INK)}</g>'
            f'<g transform="translate(196 54)">{wordmark(fg)}</g>'
            f'<text x="198" y="134" font-family="{SANS}" font-size="15" font-weight="500" letter-spacing=".3" fill="{sub}">CuteFish Universal Package</text>'
            f'<g transform="translate(442 70)"><rect width="52" height="26" rx="13" fill="none" stroke="{TEAL2}" stroke-width="1.8"/>'
            f'<text x="26" y="18" text-anchor="middle" font-family="{MONO}" font-size="13" font-weight="700" fill="{TEAL2}">v3.0</text></g>')
    return svg(520, 170, body, mark_defs("d"), "CUP - CuteFish Universal Package")

def badge():
    chips = [("Ed25519 chain", TEAL2), ("SHA-256 Merkle", SKY), ("EROFS + fs-verity", IND)]
    cx, parts = 196, []
    for t, c in chips:
        w = 12 + 8.1 * len(t)
        parts.append(f'<g transform="translate({cx} 128)"><rect width="{w:.0f}" height="28" rx="14" fill="{c}" fill-opacity=".14" stroke="{c}" stroke-opacity=".8"/>'
                     f'<text x="{w / 2:.0f}" y="19" text-anchor="middle" font-family="{SANS}" font-size="12.5" font-weight="600" fill="#E2E8F0">{t}</text></g>')
        cx += w + 10
    body = (f'<rect width="640" height="200" rx="24" fill="url(#bg)"/><rect width="640" height="200" rx="24" fill="url(#glow)"/>'
            f'<rect x=".75" y=".75" width="638.5" height="198.5" rx="23.3" fill="none" stroke="#334155" stroke-width="1.5"/>'
            f'<g transform="translate(100 100) scale(.76)">{mark("e")}</g>'
            f'<g transform="translate(196 38) scale(.78)">{wordmark("#F1F5F9")}</g>'
            f'<text x="364" y="76" font-family="{SANS}" font-size="20" font-weight="700" letter-spacing="3" fill="{TEAL}">INSTALLER</text>'
            f'<text x="196" y="108" font-family="{SANS}" font-size="14" font-weight="500" fill="#94A3B8">Verify first. Then install, upgrade or roll back - atomically.</text>'
            + "".join(parts))
    return svg(640, 200, body, bg_defs() + mark_defs("e"), "CUP Installer")

def favicon():
    body = (squircle(64, .24) + f'<g transform="translate(32 32) scale(.255)">{mark("f")}</g>')
    return svg(64, 64, body, bg_defs() + mark_defs("f"), "CUP")

def mime_icon():
    """application-x-cup: document with folded corner + mini mark."""
    body = ('<path d="M13 4h26l12 12v40a5 5 0 0 1-5 5H13a5 5 0 0 1-5-5V9a5 5 0 0 1 5-5z" fill="url(#pg)"/>'
            '<path d="M39 4v8a4 4 0 0 0 4 4h8z" fill="#fff" opacity=".4"/>'
            f'<g transform="translate(30 36) scale(.2)">{mark("g", eye="#0F172A")}</g>'
            '<rect x="17" y="49" width="26" height="3.5" rx="1.75" fill="#fff" opacity=".75"/>')
    defs = ('<linearGradient id="pg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#1E293B"/>'
            '<stop offset="1" stop-color="#0B132B"/></linearGradient>' + mark_defs("g"))
    return svg(64, 64, body, defs, "CUP package file")

def gui_icon():
    body = (squircle(64, .2237) + '<rect width="64" height="64" rx="14.3" fill="url(#glow)"/>'
            f'<g transform="translate(32 30) scale(.235)">{mark("h")}</g>'
            f'<path d="M23 54h18" stroke="{TEAL}" stroke-width="3" stroke-linecap="round"/>'
            f'<path d="M32 46v-1m0 1l-4-4m4 4l4-4" stroke="none"/>')
    return svg(64, 64, body, bg_defs() + mark_defs("h"), "CUP Installer")

def palette_html():
    sw = [("Teal", TEAL, "#5EEAD4"), ("Sky", SKY, "#38BDF8"), ("Indigo", IND, "#818CF8"),
          ("Coral", CORAL2, "#F43F5E"), ("Navy", NAVY, "#0B132B"), ("Ink", INK, "#0F172A")]
    cells = "".join(f'<div class="sw"><i style="background:{c}"></i><b>{n}</b><code>{h}</code></div>' for n, c, h in sw)
    sizes = "".join(f'<img src="cup_favicon.svg" width="{s}" height="{s}" alt="{s}px">' for s in (16, 24, 32, 48, 64, 96))
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CUP brand sheet</title>
<style>
:root{{color-scheme:dark;--bg:#0B132B;--fg:#E2E8F0;--mut:#94A3B8;--card:#111C3A;--line:#263250}}
@media (prefers-color-scheme:light){{:root{{color-scheme:light;--bg:#F8FAFC;--fg:#0F172A;--mut:#475569;--card:#fff;--line:#E2E8F0}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 {SANS};padding:32px 16px}}
main{{max-width:960px;margin:auto}}h1{{font-size:28px;margin:0 0 4px}}h2{{font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:var(--mut);margin:36px 0 12px}}
p{{color:var(--mut);margin:0 0 8px}}.grid{{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px;display:flex;flex-direction:column;gap:10px;align-items:center;justify-content:center}}
.card img{{max-width:100%;height:auto}}.card small{{color:var(--mut);font:12px {MONO}}}
.sw{{display:flex;gap:10px;align-items:center}}.sw i{{width:36px;height:36px;border-radius:10px;border:1px solid var(--line)}}.sw code{{color:var(--mut)}}
.row{{display:flex;gap:16px;align-items:flex-end;flex-wrap:wrap}}
.mono{{color:var(--fg)}}
</style><main>
<h1>CUP brand sheet</h1><p>One mark: a package cube that is a fish. Three faces, a forked tail, an eye that doubles as a "verified" dot.</p>
<h2>App icon &amp; mark</h2><div class="grid">
<div class="card"><img src="cup_logo.svg" width="200" height="200" alt="App icon"><small>cup_logo.svg (512, squircle)</small></div>
<div class="card"><img src="cup_mark.svg" width="200" alt="Mark"><small>cup_mark.svg (transparent)</small></div>
<div class="card"><img class="mono" src="cup_mark_mono.svg" width="200" alt="Mono mark"><small>cup_mark_mono.svg (currentColor)</small></div></div>
<h2>Lockups</h2><div class="grid"><div class="card"><img src="cup_lockup_dark.svg" alt="Dark lockup"><small>cup_lockup_dark.svg</small></div>
<div class="card"><img src="cup_lockup_light.svg" alt="Light lockup"><small>cup_lockup_light.svg</small></div></div>
<h2>Installer badge</h2><div class="card"><img src="cup_installer_badge.svg" alt="Badge"><small>cup_installer_badge.svg (640 x 200)</small></div>
<h2>Small sizes (must stay readable)</h2><div class="card"><div class="row">{sizes}</div><small>16 - 96 px</small></div>
<h2>Palette</h2><div class="grid">{cells}</div>
<h2>Rules</h2><p>Clear space: at least the eye diameter on every side. Minimum size: 16 px (favicon) / 24 px (mark). Single-colour use: cup_mark_mono.svg. Never recolour the faces, stretch, or add effects.</p>
</main></html>'''


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

def main():
    svg_only = "--svg-only" in sys.argv
    write(f"{A}/cup_logo.svg", app_icon())
    write(f"{A}/cup_mark.svg", mark_only())
    write(f"{A}/cup_mark_mono.svg", mark_mono())
    write(f"{A}/cup_lockup_dark.svg", lockup(True))
    write(f"{A}/cup_lockup_light.svg", lockup(False))
    write(f"{A}/cup_installer_badge.svg", badge())
    write(f"{A}/cup_favicon.svg", favicon())
    write(f"{A}/brand.html", palette_html())
    write(f"{G}/application-x-cup.svg", mime_icon())
    write(f"{G}/cup-gui-installer.svg", gui_icon())
    print("svg: wrote 8 assets + 2 GUI icons")
    if svg_only:
        return 0
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        print("png: python playwright not available - skipped"); return 0
    png = {"cup_logo": (512, 512, (512, 256, 128, 64)), "cup_mark": (200, 170, (400,)),
           "cup_lockup_dark": (520, 170, (1040,)), "cup_lockup_light": (520, 170, (1040,)),
           "cup_installer_badge": (640, 200, (1280,)), "cup_favicon": (64, 64, (180, 48, 32, 16))}
    with sync_playwright() as pw:
        b = pw.chromium.launch()
        for name, (w, h, outs) in png.items():
            for ow in outs:
                oh = round(ow * h / w)
                pg = b.new_page(viewport={"width": ow, "height": oh})
                pg.set_content(f'<body style="margin:0;background:transparent"><img src="file://{A}/{name}.svg" width="{ow}" height="{oh}"></body>')
                pg.goto(f"file://{A}/{name}.svg")
                pg.set_viewport_size({"width": ow, "height": oh})
                pg.evaluate("s=>{const e=document.documentElement;e.setAttribute('width',s[0]);e.setAttribute('height',s[1])}", [ow, oh])
                suffix = "" if ow == w else f"_{ow}"
                pg.screenshot(path=f"{A}/png/{name}{suffix}.png", omit_background=True)
                pg.close()
        pg = b.new_page(viewport={"width": 1000, "height": 1500})
        pg.goto(f"file://{A}/brand.html"); pg.screenshot(path=f"{A}/png/brand_sheet.png", full_page=True)
        b.close()
    print("png: rendered to assets/png/")
    return 0

if __name__ == "__main__":
    os.makedirs(f"{A}/png", exist_ok=True)
    sys.exit(main())
