"""cup_ref.py - independent reference parser / verifier / (test-key) re-packer for CUP v2/v3 packages.

Written from the wire layout only (header 128 B, 64 B section entries, 32 B footer), NOT from the C code,
so that disagreements with `cup-installer verify` are real findings. Uses the published demo seeds
(public in cup_installer_main.cpp), so it can also forge packages for negative testing.
"""
import hashlib, struct, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SEEDS = {k: hashlib.sha256(v).digest() for k, v in dict(
    root=b"CUP-V3-ROOT-CA-SEED", distro=b"CUP-V3-DISTRO-CA-SEED", maint=b"CUP-V3-MAINT-LEAF-SEED",
    tsa=b"CUP-V3-RFC3161-TSA-SEED", pq=b"CUP-V3-MLDSA65-PQ-SEED").items()}

def sk(seed): return Ed25519PrivateKey.from_private_bytes(seed)
def pub(seed): return sk(seed).public_key().public_bytes_raw()
def ed_verify(pk, sig, msg):
    try: Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg); return True
    except Exception: return False
def sha(b): return hashlib.sha256(b).digest()

CERT = 168
TYPES = {1: "MANIFEST", 2: "SIGNATURE", 3: "INDEX", 4: "PAYLOAD", 0xC: "EROFS", 0xD: "FSVERITY", 0x10: "ELF_BOOTSTRAP"}

def parse(buf):
    d = dict(len=len(buf), magic=buf[:4], flags=struct.unpack_from("<I", buf, 8)[0],
             total=struct.unpack_from("<Q", buf, 12)[0], n=struct.unpack_from("<I", buf, 20)[0])
    d["secs"] = []
    for i in range(d["n"]):
        t, f, o, l = struct.unpack_from("<IIQQ", buf, 128 + 64 * i)
        d["secs"].append(dict(i=i, type=t, flags=f, off=o, len=l, sha=buf[128 + 64 * i + 24:128 + 64 * i + 56],
                              name=TYPES.get(t, hex(t))))
    return d

def sec(buf, p, t):
    for s in p["secs"]:
        if s["type"] == t: return s, buf[s["off"]:s["off"] + s["len"]]
    return None, None

def merkle_root(leaves):
    lvl = list(leaves)
    while len(lvl) > 1:
        nxt = [sha(b"\x01" + lvl[i] + lvl[i + 1]) for i in range(0, len(lvl) - 1, 2)]
        if len(lvl) % 2: nxt.append(lvl[-1])
        lvl = nxt
    return lvl[0]

def manifest_field(man: bytes, key: str):
    """strict: real JSON parse, top-level key only"""
    import json
    return json.loads(man)[key]

def verify(buf, roots=None, tsa_keys=None, strict=True):
    """returns list of (check, ok, detail)"""
    roots = roots or [pub(SEEDS["root"])]; tsa_keys = tsa_keys or [pub(SEEDS["tsa"])]
    out = []
    def ck(name, ok, detail=""): out.append((name, bool(ok), detail))
    p = parse(buf)
    ck("header-magic", p["magic"] in (b"CUP1", b"CUP2", b"CUP3"))
    ck("footer-len", struct.unpack_from("<Q", buf, len(buf) - 28)[0] == len(buf))
    ck("footer-hdr-hash", buf[-20:] == sha(buf[:128])[:20])
    for s in p["secs"]:
        ck(f"section-sha256[{s['name']}]", sha(buf[s["off"]:s["off"] + s["len"]]) == s["sha"])
    ms, man = sec(buf, p, 1); ss, sig = sec(buf, p, 2); xs, idx = sec(buf, p, 3)
    ps, pay = sec(buf, p, 4); es, ero = sec(buf, p, 0xC)
    if not (man and sig): ck("manifest+signature present", False); return out
    msha = sha(man)
    ver, alg, clen, rlen = struct.unpack_from("<IBBH", sig, 0)
    signer, esig = sig[8:40], sig[40:104]
    tsa_ts = struct.unpack_from("<Q", sig, 104)[0]; tpk, tsig = sig[112:144], sig[144:208]
    dom = b"CUP-MANIFEST-SIG-V%d\0"[:19] % ver if False else (b"CUP-MANIFEST-SIG-V%d" % ver).ljust(20, b"\0")
    ck("ed25519 manifest signature (domain-separated)", ed_verify(signer, esig, dom + msha))
    ck("TSA key trusted", tpk in tsa_keys)
    ck("TSA signature", ed_verify(tpk, tsig, b"CUP-TSA-V2\0" + msha + struct.pack("<Q", tsa_ts)))
    ck("chain length sane (1..8) and fits section", 1 <= clen <= 8 and 208 + clen * CERT <= len(sig), f"chain_length={clen}")
    cur = signer; man_id = json.loads(man).get("id", "<MISSING>")
    for i in range(min(clen, 8)):
        c = sig[208 + i * CERT:208 + (i + 1) * CERT]
        subj, iss, csig = c[:32], c[32:64], c[64:128]
        vf, vu, um = struct.unpack_from("<QQH", c, 128); pref = c[152:168].split(b"\0")[0].decode()
        ck(f"chain[{i}] subject links", subj == cur)
        ck(f"chain[{i}] cert signature", ed_verify(iss, csig, subj + iss + c[128:168]))
        ck(f"chain[{i}] validity encloses TSA time", vf < vu and vf <= tsa_ts <= vu)
        ck(f"chain[{i}] namespace '{pref}' covers id '{man_id}'", pref == "*" or man_id.startswith(pref))
        cur = iss
    ck("terminal issuer is trusted root", cur in roots)
    # ---- PQ half
    if alg == 3:
        pq = sig[208 + clen * CERT:]
        ck("PQ bundle present & sized", len(pq) >= 4 + 1952 + 3309 + 3 + 32, f"{len(pq)} B")
        if len(pq) >= 4 + 1952 + 3309 + 35:
            pqpk, pqsig = pq[4:4 + 1952], pq[4 + 1952:4 + 1952 + 3309]
            ck("PQ pubkey bound to signer/cert chain", pqpk[:32] == signer, "ML-DSA key must be certified, not self-asserted")
    # ---- payload binding (what a verifier MUST check, spec §10)
    if idx is not None and pay is not None:
        n = len(idx) // 48; leaves = []; ok = True
        for k in range(n):
            ro, ul, cl = struct.unpack_from("<QII", idx, k * 48); lh = idx[k * 48 + 16:k * 48 + 48]
            leaf = sha(b"\x00" + pay[ro:ro + ul]); leaves.append(leaf); ok &= (leaf == lh)
        ck("payload chunks match INDEX leaf hashes", ok)
        ck("INDEX Merkle root == signed manifest merkle_root", merkle_root(leaves).hex() == manifest_field(man, "merkle_root"))
    if ero is not None:
        ck("EROFS image digest == signed manifest erofs_verity_root", sha(ero).hex() == manifest_field(man, "erofs_verity_root"))
    ck("SELF_BOOTSTRAP flag implies a 0x10 section", (not p["flags"] & 0x1000) or any(s["type"] == 0x10 for s in p["secs"]))
    return out

def report(buf, **kw):
    r = verify(buf, **kw); bad = [x for x in r if not x[1]]
    return r, bad

if __name__ == "__main__":
    import sys
    r, bad = report(open(sys.argv[1], "rb").read())
    for n, ok, d in r: print(("PASS " if ok else "FAIL ") + n + (f"  [{d}]" if d else ""))
    print(f"\n{len(r) - len(bad)}/{len(r)} checks passed"); sys.exit(1 if bad else 0)
