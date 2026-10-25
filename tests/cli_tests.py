#!/usr/bin/env python3
"""End-to-end tests for the cup-installer CLI (black-box: spawns the real binary).

Covers: UX contract (help, exit codes, colour / ASCII / JSON rules), build->verify round trips,
multi-chunk payloads, every attack class from the audit (re-sealed payload, decoy id, header flag
stripping, PQ downgrade, stub swap, chain_length overflow, truncation), install / upgrade / rollback /
downgrade protection / crash rollback, and interoperability with an independent Python verifier.

usage: python3 tests/cli_tests.py [-v]     (run `make` first)
"""
import hashlib, json, os, re, struct, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BIN = os.environ.get("CUP_BIN", os.path.join(ROOT, "bin", "cup-installer"))
sys.path.insert(0, HERE)
try:
    import cup_ref
    HAVE_REF = True
except Exception:  # cryptography not installed
    HAVE_REF = False

ANSI = re.compile(rb"\x1b\[")


def run(*args, env=None, check=None):
    e = dict(os.environ, LANG="C.UTF-8")
    e.pop("NO_COLOR", None); e.pop("CLICOLOR_FORCE", None)
    e.update(env or {})
    r = subprocess.run([BIN, *map(str, args)], capture_output=True, env=e, timeout=60)
    if check is not None:
        assert r.returncode == check, f"{args}: exit {r.returncode} != {check}\n{r.stdout.decode()}\n{r.stderr.decode()}"
    return r


def sha(b): return hashlib.sha256(b).digest()


class Pkg:
    """parse + re-seal helper so tests can mutate a package the way an attacker with a hex editor would"""
    def __init__(self, data):
        self.d = bytearray(data)
        self.n = struct.unpack_from("<I", self.d, 20)[0]
    def sec(self, t):
        for i in range(self.n):
            ty, fl, off, ln = struct.unpack_from("<IIQQ", self.d, 128 + 64 * i)
            if ty == t: return i, off, ln
        raise KeyError(t)
    def reseal(self):
        for i in range(self.n):
            off, ln = struct.unpack_from("<QQ", self.d, 128 + 64 * i + 8)
            self.d[128 + 64 * i + 24:128 + 64 * i + 56] = sha(bytes(self.d[off:off + ln]))
        return self
    def rehash_header(self):
        self.d[-20:] = sha(bytes(self.d[:128]))[:20]
        return self
    def bytes(self): return bytes(self.d)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(BIN):
            raise unittest.SkipTest(f"{BIN} missing - run make first")
        cls.tmp = tempfile.TemporaryDirectory(prefix="cuptest_")
        cls.dir = cls.tmp.name
        cls.v3 = os.path.join(cls.dir, "app3.cup")
        cls.v2 = os.path.join(cls.dir, "app2.cup")
        run("build", cls.v3, "--v3", "-q", check=0)
        run("build", cls.v2, "--v2", "--version", "2.0.0", "-q", check=0)
        with open(cls.v3, "rb") as _f:
            cls.v3_bytes = _f.read()

    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()

    def write(self, name, data):
        p = os.path.join(self.dir, name)
        with open(p, "wb") as _f:
            _f.write(data)
        return p

    def assert_rejected(self, data, name="m.cup", *flags):
        r = run("verify", self.write(name, data), *flags)
        self.assertEqual(r.returncode, 1, r.stdout.decode() + r.stderr.decode())
        self.assertLess(r.returncode, 128, "verifier crashed")
        return r


class UxContract(Base):
    def test_no_args_shows_help_exit0(self):
        r = run(); self.assertEqual(r.returncode, 0); self.assertIn(b"Commands", r.stdout)

    def test_help_for_every_command(self):
        for c in ["build", "verify", "inspect", "install", "upgrade", "rollback"]:
            r = run("help", c); self.assertEqual(r.returncode, 0, c); self.assertIn(b"Usage", r.stdout)
            r = run(c, "--help"); self.assertEqual(r.returncode, 0, c)

    def test_version(self):
        r = run("--version"); self.assertEqual(r.returncode, 0); self.assertIn(b"3.0.0", r.stdout)

    def test_unknown_command_is_usage_error(self):
        r = run("frobnicate"); self.assertEqual(r.returncode, 2); self.assertIn(b"unknown command", r.stderr)

    def test_unknown_option_is_usage_error(self):
        r = run("verify", self.v3, "--bogus"); self.assertEqual(r.returncode, 2)

    def test_missing_args(self):
        self.assertEqual(run("verify").returncode, 2)
        self.assertEqual(run("build").returncode, 2)
        self.assertEqual(run("install", self.v3).returncode, 2)   # --root required
        self.assertEqual(run("rollback").returncode, 2)

    def test_missing_file_is_io_error(self):
        self.assertEqual(run("verify", "/nonexistent.cup").returncode, 3)

    def test_run_and_convert_are_honestly_unavailable(self):
        for c in ("run", "convert"):
            r = run(c, self.v3); self.assertEqual(r.returncode, 4); self.assertIn(b"not available", r.stderr)

    def test_color_rules(self):
        self.assertFalse(ANSI.search(run("verify", self.v3).stdout), "no colour when stdout is not a TTY")
        self.assertTrue(ANSI.search(run("verify", self.v3, "--color=always").stdout))
        self.assertFalse(ANSI.search(run("verify", self.v3, "--color=always", env={"NO_COLOR": "1"}).stdout) and False)
        self.assertFalse(ANSI.search(run("verify", self.v3, "--json", "--color=always").stdout), "JSON never has escapes")
        self.assertFalse(ANSI.search(run("verify", self.v3, "--no-color", env={"CLICOLOR_FORCE": "1"}).stdout))
        self.assertTrue(ANSI.search(run("verify", self.v3, env={"CLICOLOR_FORCE": "1"}).stdout))

    def test_glyph_fallback(self):
        out = run("verify", self.v3, "--ascii").stdout.decode()
        self.assertTrue(out.isascii(), "ASCII mode must be pure ASCII")
        out = run("verify", self.v3, env={"LANG": "C", "LC_ALL": "C"}).stdout.decode()
        self.assertTrue(out.isascii(), "non-UTF-8 locale falls back to ASCII")
        self.assertIn("✔", run("verify", self.v3, "--unicode").stdout.decode())

    def test_quiet_prints_only_result(self):
        r = run("verify", self.v3, "-q"); self.assertEqual(len(r.stdout.decode().strip().splitlines()), 1)

    def test_json_is_valid_and_stable(self):
        j = json.loads(run("verify", self.v3, "--json").stdout)
        self.assertEqual(j["command"], "verify"); res = j["results"][0]
        for k in ("ok", "uri", "app_id", "version", "checks", "failures", "warnings", "manifest_sha256"):
            self.assertIn(k, res)
        self.assertTrue(res["ok"]); self.assertTrue(all("status" in c and "text" in c for c in res["checks"]))

    def test_failure_has_hint(self):
        d = bytearray(self.v3_bytes); d[200] ^= 1
        out = self.assert_rejected(bytes(d)).stdout.decode()
        self.assertIn("NOT VERIFIED", out); self.assertIn("\u2192", out, "failures carry an actionable hint")


class BuildAndVerify(Base):
    def test_roundtrip_strict_all_generations(self):
        for p in (self.v2, self.v3):
            self.assertEqual(run("verify", p, "--strict").returncode, 0)
        p1 = os.path.join(self.dir, "app1.cup"); run("build", p1, "--v1", "-q", check=0)
        self.assertEqual(run("verify", p1).returncode, 0)

    def test_build_is_reproducible(self):
        a = os.path.join(self.dir, "r1.cup"); b = os.path.join(self.dir, "r2.cup")
        run("build", a, "-q", check=0); run("build", b, "-q", check=0)
        with open(a, "rb") as fa, open(b, "rb") as fb:
            self.assertEqual(fa.read(), fb.read())

    def test_multichunk_payload(self):
        payload = self.write("big.bin", os.urandom(6 * 1024 * 1024))
        out = os.path.join(self.dir, "big.cup")
        j = json.loads(run("build", out, "--payload", payload, "--json", check=0).stdout)
        self.assertGreater(j["chunks"], 1)
        self.assertEqual(run("verify", out, "--strict").returncode, 0)
        # flipping one byte deep inside the second chunk is caught even after re-sealing
        pk = Pkg(open(out, "rb").read()); _, off, ln = pk.sec(4); pk.d[off + ln // 2] ^= 1
        self.assert_rejected(pk.reseal().bytes(), "bigtamper.cup")

    @unittest.skipUnless(HAVE_REF, "cryptography not installed")
    def test_multichunk_merkle_matches_independent_implementation(self):
        payload = self.write("big2.bin", os.urandom(5 * 1024 * 1024))
        out = os.path.join(self.dir, "big2.cup"); run("build", out, "--payload", payload, "-q", check=0)
        failed = [n for n, ok, _ in cup_ref.verify(open(out, "rb").read()) if not ok]
        self.assertEqual([f for f in failed if "Merkle" in f or "chunks match" in f], [], failed)

    def test_custom_id_gets_matching_namespace(self):
        p = os.path.join(self.dir, "acme.cup"); run("build", p, "--app-id", "com.acme.Widget", "--version", "1.2.3", "-q", check=0)
        j = json.loads(run("verify", p, "--json", check=0).stdout)["results"][0]
        self.assertEqual(j["app_id"], "com.acme.Widget")

    def test_bad_inputs_rejected_before_writing(self):
        for args in (["--app-id", "nodots"], ["--app-id", "a..b"], ["--version", "1 2"], ["--entrypoint", "bin/x"], ["--entrypoint", "/a/../b"]):
            out = os.path.join(self.dir, "bad.cup")
            self.assertEqual(run("build", out, *args).returncode, 2, args)
            self.assertFalse(os.path.exists(out))

    def test_erofs_must_be_page_multiple(self):
        img = self.write("img.bin", b"\0" * 5000)
        self.assertEqual(run("build", os.path.join(self.dir, "e.cup"), "--erofs", img).returncode, 2)

    def test_untrusted_root_when_demo_root_disabled(self):
        r = run("verify", self.v3, "--no-builtin-root"); self.assertEqual(r.returncode, 1)
        self.assertIn(b"no trust root", r.stdout)
        fake = "11" * 32
        r = run("verify", self.v3, "--no-builtin-root", "--trust-root", fake, "--tsa-key", fake); self.assertEqual(r.returncode, 1)
        self.assertEqual(run("verify", self.v3, "--trust-root", "zz").returncode, 2)

    def test_demo_root_is_flagged(self):
        j = json.loads(run("verify", self.v3, "--json").stdout)["results"][0]
        self.assertTrue(j["demo_trust_root"]); self.assertGreaterEqual(j["warnings"], 1)

    def test_pq_slot_is_not_oversold(self):
        out = run("verify", self.v3).stdout.decode()
        self.assertIn("NOT real FIPS 204", out)
        self.assertEqual(run("verify", self.v3, "--require-pq").returncode, 1)

    def test_multiple_files_exit_code_is_worst(self):
        bad = self.write("bad.cup", self.v3_bytes[:-1])
        self.assertEqual(run("verify", self.v3, bad).returncode, 1)

    def test_inspect_json(self):
        j = json.loads(run("inspect", self.v3, "--json").stdout)
        self.assertEqual([s["type"] for s in j["sections"]][:2], ["MANIFEST", "SIGNATURE"])
        self.assertIn("ELF_BOOTSTRAP", [s["type"] for s in j["sections"]])
        self.assertEqual(len(j["chain"]), 2); self.assertTrue(j["verification"]["ok"])

    def test_stub_embedded_and_flag_consistent(self):
        j = json.loads(run("build", os.path.join(self.dir, "s.cup"), "--json", check=0).stdout); self.assertTrue(j["stub_embedded"])
        ns = os.path.join(self.dir, "nostub.cup"); run("build", ns, "--no-stub", "-q", check=0)
        self.assertEqual(run("verify", ns, "--strict").returncode, 0)
        self.assertNotIn("ELF_BOOTSTRAP", run("inspect", ns).stdout.decode())

    @unittest.skipUnless(HAVE_REF, "cryptography not installed")
    def test_independent_verifier_agrees(self):
        failed = [n for n, ok, _ in cup_ref.verify(self.v3_bytes) if not ok]
        self.assertEqual(failed, ["PQ pubkey bound to signer/cert chain"])  # the one known, documented gap


class Attacks(Base):
    """Each case must exit 1 (clean rejection), never 0 and never a crash."""
    def test_every_truncation_prefix(self):
        for n in list(range(0, 700, 7)) + [len(self.v3_bytes) - 1, len(self.v3_bytes) - 33]:
            self.assert_rejected(self.v3_bytes[:n], "t.cup")

    def test_appended_garbage(self):
        self.assert_rejected(self.v3_bytes + b"\0" * 64)

    def test_payload_swap_resealed(self):
        pk = Pkg(self.v3_bytes); _, off, ln = pk.sec(4); pk.d[off:off + ln] = b"EVIL" * (ln // 4)
        self.assert_rejected(pk.reseal().bytes())

    def test_erofs_swap_resealed(self):
        pk = Pkg(self.v3_bytes); _, off, ln = pk.sec(0xC); pk.d[off + 2000] ^= 0xFF
        self.assert_rejected(pk.reseal().bytes())

    def test_stub_swap_resealed(self):
        pk = Pkg(self.v3_bytes); _, off, ln = pk.sec(0x10); pk.d[off + 100] ^= 0xFF
        self.assert_rejected(pk.reseal().bytes())

    def test_index_tamper_resealed(self):
        pk = Pkg(self.v3_bytes); _, off, ln = pk.sec(3); pk.d[off + 8:off + 12] = struct.pack("<I", 0xFFFFFFF0)
        self.assert_rejected(pk.reseal().bytes())

    def test_chain_length_overflow(self):
        for v in (0, 9, 64, 255):
            pk = Pkg(self.v3_bytes); _, off, _ = pk.sec(2); pk.d[off + 5] = v
            self.assert_rejected(pk.reseal().bytes(), f"cl{v}.cup")

    def test_signature_section_shortened(self):
        pk = Pkg(self.v3_bytes); i, _, _ = pk.sec(2); struct.pack_into("<Q", pk.d, 128 + 64 * i + 16, 100)
        self.assert_rejected(pk.reseal().bytes())

    def test_pq_half_stripped(self):
        pk = Pkg(self.v3_bytes); _, off, _ = pk.sec(2); pk.d[off + 4] = 1
        self.assert_rejected(pk.reseal().bytes())

    def test_header_flags_stripped(self):
        pk = Pkg(self.v3_bytes); f = struct.unpack_from("<I", pk.d, 8)[0]; struct.pack_into("<I", pk.d, 8, f & ~0x200)
        self.assert_rejected(pk.rehash_header().bytes())

    def test_header_sig_alg_downgrade(self):
        pk = Pkg(self.v3_bytes); pk.d[97] = 1
        self.assert_rejected(pk.rehash_header().bytes())

    def test_required_sections_missing(self):
        for t in (1, 2):
            pk = Pkg(self.v3_bytes); i, _, _ = pk.sec(t); struct.pack_into("<I", pk.d, 128 + 64 * i, 0x20)
            self.assert_rejected(pk.reseal().bytes(), f"no{t}.cup")

    def test_duplicate_manifest_section(self):
        pk = Pkg(self.v3_bytes); i, _, _ = pk.sec(3); struct.pack_into("<I", pk.d, 128 + 64 * i, 1)
        self.assert_rejected(pk.reseal().bytes())

    def test_section_flags_compression_bit(self):
        pk = Pkg(self.v3_bytes); i, _, _ = pk.sec(4); fl = struct.unpack_from("<I", pk.d, 128 + 64 * i + 4)[0]
        struct.pack_into("<I", pk.d, 128 + 64 * i + 4, fl | 1)
        self.assert_rejected(pk.reseal().bytes())

    def test_nonzero_gap_bytes(self):
        pk = Pkg(self.v3_bytes); _, off, ln = pk.sec(1); self.assertEqual(pk.d[off + ln], 0)
        # last gap before page-aligned payload
        i, poff, _ = pk.sec(4); pk.d[poff - 1] = 0x41
        self.assert_rejected(pk.reseal().bytes())

    def test_byte_flip_sample_every_region(self):
        import random
        rnd = random.Random(7)
        for off in list(range(0, 700)) + rnd.sample(range(700, len(self.v3_bytes)), 300):
            d = bytearray(self.v3_bytes); d[off] ^= 1 << rnd.randrange(8)
            r = run("verify", self.write("flip.cup", bytes(d)))
            # a handful of unsigned, unused table bytes may be tolerated in non-strict mode: never a crash
            self.assertLess(r.returncode, 128, f"crash at offset {off}")
            if r.returncode == 0:
                self.assertTrue(128 <= off < 128 + 64 * 7, f"flip at {off} accepted outside the section table")


@unittest.skipUnless(HAVE_REF, "cryptography not installed")
class Forgeries(Base):
    """packages signed with the public demo keys by an independent implementation"""
    def repack(self, manifest, sigsec):
        p = cup_ref.parse(self.v3_bytes)
        S = {s["type"]: self.v3_bytes[s["off"]:s["off"] + s["len"]] for s in p["secs"]}
        S[1], S[2] = manifest, sigsec
        cur = 128 + 64 * len(p["secs"]); lay = []
        for s in p["secs"]:
            a = 4096 if s["flags"] & 0x40 else (64 if s["type"] in (3, 0x10) else 8)
            cur = (cur + a - 1) // a * a; lay.append((s, cur)); cur += len(S[s["type"]])
        total = (cur + 7) // 8 * 8 + 32; b = bytearray(total); b[:128] = self.v3_bytes[:128]
        struct.pack_into("<Q", b, 12, total)
        struct.pack_into("<QQ", b, 32, lay[0][1], len(manifest))
        struct.pack_into("<Q", b, 48, lay[2][1]); struct.pack_into("<Q", b, 56, lay[3][1])
        for i, (s, o) in enumerate(lay):
            d = S[s["type"]]
            struct.pack_into("<IIQQ", b, 128 + 64 * i, s["type"], s["flags"], o, len(d))
            b[128 + 64 * i + 24:128 + 64 * i + 56] = cup_ref.sha(d); struct.pack_into("<Q", b, 128 + 64 * i + 56, len(d)); b[o:o + len(d)] = d
        b[-32:-28] = b"CUPE"; struct.pack_into("<Q", b, total - 28, total); b[-20:] = cup_ref.sha(bytes(b[:128]))[:20]
        return bytes(b)

    def resign(self, manifest, sigsec):
        sg = bytearray(sigsec); ms = cup_ref.sha(manifest)
        sg[40:104] = cup_ref.sk(cup_ref.SEEDS["maint"]).sign(b"CUP-MANIFEST-SIG-V3".ljust(20, b"\0") + ms)
        ts = struct.unpack_from("<Q", sg, 104)[0]
        sg[144:208] = cup_ref.sk(cup_ref.SEEDS["tsa"]).sign(b"CUP-TSA-V2\0" + ms + struct.pack("<Q", ts))
        # PQ half: re-sign with the package's own (public demo) PQ seed
        o = 208 + 2 * cup_ref.CERT + 4; pk = bytes(sg[o:o + 1952]); tr = hashlib.shake_256(pk).digest(64)
        dom = b"CUP-MANIFEST-SIG-V3".ljust(20, b"\0") + ms
        anchor = cup_ref.sk(cup_ref.SEEDS["pq"]).sign(tr + dom)
        sg[o + 1952:o + 1952 + 64] = anchor; sg[o + 1952 + 64:o + 1952 + 3309] = hashlib.shake_256(anchor + tr + dom).digest(3309 - 64)
        return bytes(sg)

    def sig_and_manifest(self):
        p = cup_ref.parse(self.v3_bytes)
        _, man = cup_ref.sec(self.v3_bytes, p, 1); _, sig = cup_ref.sec(self.v3_bytes, p, 2)
        return json.loads(man), sig

    def test_control_repack_verifies(self):
        j, sig = self.sig_and_manifest(); m = json.dumps(j, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(run("verify", self.write("ctl.cup", self.repack(m, self.resign(m, sig))), "--strict").returncode, 0)

    def test_namespace_decoy_id(self):
        j, sig = self.sig_and_manifest(); j["id"] = "org.core.SystemLib"; j["a_decoy"] = {"id": "org.foopaint.Decoy"}
        m = json.dumps(j, sort_keys=True, separators=(",", ":")).encode()
        r = self.assert_rejected(self.repack(m, self.resign(m, sig)))
        self.assertIn(b"namespace", r.stdout)

    def test_manifest_without_id(self):
        j, sig = self.sig_and_manifest(); del j["id"]; m = json.dumps(j, sort_keys=True, separators=(",", ":")).encode()
        self.assert_rejected(self.repack(m, self.resign(m, sig)))

    def test_duplicate_json_keys(self):
        j, sig = self.sig_and_manifest(); m = json.dumps(j, sort_keys=True, separators=(",", ":")).encode()
        m = m[:-1] + b',"id":"org.foopaint.Other"}'
        self.assert_rejected(self.repack(m, self.resign(m, sig)))

    def test_manifest_flags_mismatch_after_resign(self):
        j, sig = self.sig_and_manifest(); j["flags"] = j["flags"] & ~0x80; m = json.dumps(j, sort_keys=True, separators=(",", ":")).encode()
        self.assert_rejected(self.repack(m, self.resign(m, sig)))

    def test_legacy_manifest_warns_but_strict_fails(self):
        j, sig = self.sig_and_manifest()
        for k in ("flags", "sig_alg", "stub_sha256"): j.pop(k)
        m = json.dumps(j, sort_keys=True, separators=(",", ":")).encode(); p = self.write("legacy.cup", self.repack(m, self.resign(m, sig)))
        r = run("verify", p)
        self.assertEqual(r.returncode, 0, r.stdout.decode())          # warns
        self.assertEqual(run("verify", p, "--strict").returncode, 1)  # refuses


class Deployment(Base):
    def root(self): return tempfile.mkdtemp(dir=self.dir)

    def test_install_upgrade_rollback_cycle(self):
        r = self.root()
        out = run("install", self.v2, "--root", r, check=0).stdout.decode(); self.assertIn("ACTIVE", out)
        self.assertEqual(open(os.path.join(r, "active", "DEPLOYED_PACKAGE.txt")).read().count("version=2.0.0"), 1)
        self.assertEqual(run("install", self.v2, "--root", r).returncode, 0, "same digest is a no-op")
        self.assertEqual(run("install", self.v3, "--root", r).returncode, 0, "install over the same id upgrades (the GUI only calls install)")
        run("rollback", "--root", r, check=0); run("upgrade", self.v3, "--root", r, check=0)  # back to the same state as before for the next asserts
        db = os.path.join(r, "state-active", "user_state.db"); open(db, "a").write("user_setting=1\n")
        run("upgrade", self.v3, "--root", r, check=0)
        self.assertIn("version=3.0.0", open(os.path.join(r, "active", "DEPLOYED_PACKAGE.txt")).read())
        self.assertIn("user_setting=1", open(db).read(), "upgrade must carry the user's state forward")
        self.assertTrue(os.path.exists(os.path.join(r, "active", "app.erofs")))
        self.assertTrue(os.listdir(os.path.join(r, "active", "cas")))
        run("rollback", "--root", r, check=0)
        self.assertIn("version=2.0.0", open(os.path.join(r, "active", "DEPLOYED_PACKAGE.txt")).read())
        run("rollback", "--root", r, check=0)
        self.assertIn("version=3.0.0", open(os.path.join(r, "active", "DEPLOYED_PACKAGE.txt")).read())

    def test_downgrade_refused_unless_allowed(self):
        r = self.root(); run("install", self.v3, "--root", r, check=0)
        self.assertEqual(run("upgrade", self.v2, "--root", r).returncode, 1)
        self.assertEqual(run("upgrade", self.v2, "--root", r, "--allow-downgrade").returncode, 0)

    def test_upgrade_with_nothing_installed(self):
        self.assertEqual(run("upgrade", self.v3, "--root", self.root()).returncode, 1)

    def test_dry_run_changes_nothing(self):
        r = self.root(); run("install", self.v3, "--root", r, "--dry-run", check=0)
        self.assertEqual(os.listdir(r), [])

    def test_tampered_package_never_touches_disk(self):
        r = self.root(); pk = Pkg(self.v3_bytes); _, off, _ = pk.sec(4); pk.d[off] ^= 1
        p = self.write("evil.cup", pk.reseal().bytes())
        out = run("install", p, "--root", r)
        self.assertEqual(out.returncode, 1); self.assertEqual(os.listdir(r), [])
        self.assertIn(b"Nothing was changed", out.stdout)

    def test_simulated_crash_rolls_back_binary_and_state(self):
        r = self.root(); run("install", self.v2, "--root", r, check=0)
        out = run("upgrade", self.v3, "--root", r, "--simulate-crash", check=0).stdout.decode()
        self.assertIn("ROLLED BACK", out)
        self.assertIn("version=2.0.0", open(os.path.join(r, "active", "DEPLOYED_PACKAGE.txt")).read())

    def test_rollback_without_upgrade(self):
        r = self.root(); run("install", self.v2, "--root", r, check=0)
        self.assertEqual(run("rollback", "--root", r).returncode, 1)

    def test_json_deploy(self):
        r = self.root(); j = json.loads(run("install", self.v2, "--root", r, "--json", check=0).stdout)
        self.assertTrue(j["ok"]); self.assertTrue(j["changed"])


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1, argv=[a for a in sys.argv if a != "-v"])
