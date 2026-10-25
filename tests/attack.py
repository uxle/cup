"""Independent adversarial harness for cup-installer verify (black-box, ASAN build).
usage: attack.py <verify-binary> <package.cup> [--quick]
Classification per mutant: REJECT (clean nonzero exit), ACCEPT (exit 0), CRASH (sanitizer/signal)."""
import sys, os, struct, hashlib, subprocess, tempfile, random, concurrent.futures as cf, collections, json

BIN, PKG = sys.argv[1], sys.argv[2]
QUICK = "--quick" in sys.argv
orig = open(PKG, "rb").read()
N = struct.unpack_from("<I", orig, 20)[0]
secs = []
for i in range(N):
    t, f, o, l = struct.unpack_from("<IIQQ", orig, 128 + 64 * i)
    secs.append(dict(i=i, type=t, flags=f, off=o, len=l))
NAMES = {1: "MANIFEST", 2: "SIGNATURE", 3: "INDEX", 4: "PAYLOAD", 0xC: "EROFS", 0xD: "FSVERITY"}
for s in secs: s["name"] = NAMES.get(s["type"], hex(s["type"]))
tmpd = tempfile.mkdtemp(prefix="cupatk_")
env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:exitcode=99", UBSAN_OPTIONS="print_stacktrace=0:halt_on_error=1:exitcode=98")

def reseal(buf):
    """attacker recomputes every per-section SHA-256 in the (unsigned) section table"""
    b = bytearray(buf)
    for i in range(N):
        o, l = struct.unpack_from("<QQ", b, 128 + 64 * i + 8)
        if o + l <= len(b):
            b[128 + 64 * i + 24: 128 + 64 * i + 56] = hashlib.sha256(bytes(b[o:o + l])).digest()
    return bytes(b)

def run(buf, tag):
    p = os.path.join(tmpd, f"m_{tag}.cup")
    open(p, "wb").write(buf)
    try:
        r = subprocess.run([BIN, "verify", p], capture_output=True, env=env, timeout=20)
        rc, err = r.returncode, r.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        rc, err = -999, "TIMEOUT"
    finally:
        try: os.unlink(p)
        except OSError: pass
    if rc == 0: return "ACCEPT", err
    if rc in (98, 99) or rc < 0 or "AddressSanitizer" in err or "runtime error" in err: return "CRASH", err
    return "REJECT", err

def region(off):
    if off < 128: return "header"
    if off < 128 + 64 * N: return "sect-table"
    if off >= len(orig) - 32: return "footer"
    for s in secs:
        if s["off"] <= off < s["off"] + s["len"]: return s["name"]
    return "padding"

results = collections.defaultdict(collections.Counter)
examples = {}
def record(group, verdict, tag, err):
    results[group][verdict] += 1
    if verdict != "REJECT": examples.setdefault((group, verdict), []).append((tag, err.strip().splitlines()[:3]))

jobs = []
# A. raw single byte flips (no reseal)
rng = random.Random(1337)
offs = set(range(0, 128 + 64 * N + 8)) | set(range(len(orig) - 32, len(orig)))
for s in secs:
    cnt = (s["len"] if s["name"] in ("MANIFEST", "SIGNATURE", "INDEX") else 400)
    if QUICK: cnt = min(cnt, 60)
    base = list(range(s["off"], s["off"] + s["len"]))
    offs |= set(base if cnt >= len(base) else rng.sample(base, cnt))
for o in sorted(offs):
    b = bytearray(orig); b[o] ^= 0x01
    jobs.append((f"flip-raw/{region(o)}", bytes(b), f"f{o}"))
# B. flips + reseal (attacker fixes the unsigned section table hashes)
for o in sorted(offs):
    if 128 <= o < 128 + 64 * N: continue
    b = bytearray(orig); b[o] ^= 0x01
    jobs.append((f"flip-resealed/{region(o)}", reseal(bytes(b)), f"r{o}"))
# C. truncations
for L in list(range(0, 600)) + list(range(600, len(orig), 4099)):
    jobs.append(("truncate", orig[:L], f"t{L}"))
# D. targeted structural attacks
sig = next(s for s in secs if s["type"] == 2)
def mut(fn, name, do_reseal=True):
    b = bytearray(orig); fn(b)
    jobs.append((f"targeted/{name}", reseal(bytes(b)) if do_reseal else bytes(b), name))
mut(lambda b: b.__setitem__(sig["off"] + 5, 255), "chain_length=255")
mut(lambda b: b.__setitem__(sig["off"] + 5, 9), "chain_length=9")
mut(lambda b: b.__setitem__(sig["off"] + 5, 0), "chain_length=0")
mut(lambda b: b.__setitem__(sig["off"] + 4, 0x01), "sig_alg 3->1 (strip PQ half)")
mut(lambda b: b.__setitem__(sig["off"] + 4, 0x7F), "sig_alg=0x7F")
mut(lambda b: b.__setitem__(slice(sig["off"] + 6, sig["off"] + 8), b"\xff\xff"), "rekor_proof_len=0xffff")
# shrink the SIGNATURE section length in the table to 100 B (sig fields read past section end)
def shrink(b):
    struct.pack_into("<Q", b, 128 + 64 * sig["i"] + 16, 100)
mut(shrink, "SIGNATURE len=100")
# change type of SIGNATURE entry -> missing signature section
mut(lambda b: struct.pack_into("<I", b, 128 + 64 * sig["i"], 0x20), "no SIGNATURE section")
man = next(s for s in secs if s["type"] == 1)
mut(lambda b: struct.pack_into("<I", b, 128 + 64 * man["i"], 0x20), "no MANIFEST section")
# E. payload swap: replace payload with attacker data, reseal table
pay = next(s for s in secs if s["type"] == 4)
def evil_payload(b): b[pay["off"]:pay["off"] + pay["len"]] = b"EVIL" * (pay["len"] // 4)
mut(evil_payload, "payload fully replaced")
ero = next(s for s in secs if s["type"] == 0xC)
def evil_erofs(b): b[ero["off"] + 2000:ero["off"] + 2064] = b"\x90" * 64
mut(evil_erofs, "EROFS image tampered")
idx = next(s for s in secs if s["type"] == 3)
def evil_idx(b): b[idx["off"] + 8:idx["off"] + 12] = struct.pack("<I", 0xFFFFFFF0)
mut(evil_idx, "INDEX chunk len huge")
# header flag tampering (footer hash covers header; attacker recomputes it - emulate by patching header+footer)
def hdr_flags(b):
    f = struct.unpack_from("<I", b, 8)[0]
    struct.pack_into("<I", b, 8, f & ~0x200)  # clear a security flag
    b[len(b)-20:len(b)] = hashlib.sha256(bytes(b[:128])).digest()[:20]
mut(hdr_flags, "header flag cleared + footer rehashed")

def work(j):
    g, buf, tag = j
    v, err = run(buf, tag)
    return g, v, tag, err
with cf.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as ex:
    for g, v, tag, err in ex.map(work, jobs, chunksize=8):
        record(g, v, tag, err)

print(f"mutants executed: {len(jobs)}\n")
print(f"{'group':58s} {'REJECT':>7s} {'ACCEPT':>7s} {'CRASH':>6s}")
for g in sorted(results):
    c = results[g]
    print(f"{g:58s} {c['REJECT']:7d} {c['ACCEPT']:7d} {c['CRASH']:6d}")
print()
for (g, v), lst in sorted(examples.items()):
    print(f"## {v} in {g}: {len(lst)} case(s); first: {lst[0][0]} -> {lst[0][1]}")
json.dump({g: dict(c) for g, c in results.items()}, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "attack_results.json"), "w"), indent=1)
