"""Tests of gen_v016.py itself: the CoreDet codec, the primitives, and the golden-xcheck machinery.

Run from ANetCore: python3 -B golden/py/test_gen_v016.py (-B keeps __pycache__ out of the tree).
"""

import contextlib
import io
import json
import os
import random
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import gen_v016 as g  # noqa: E402


class CoreDet(unittest.TestCase):
    def test_refuses_what_is_not_coredet(self):
        for hexstr, why in [
            ("1817", "23 in two bytes"),
            ("190017", "23 in three bytes"),
            ("5801ff", "a one-byte length in two bytes"),
            ("a202010102", "map keys out of order"),
            ("a201010102", "duplicate map key"),
            ("a2617a01616102", "text keys out of order (z before a)"),
            ("9fff", "indefinite array"),
            ("5f40ff", "indefinite byte string"),
            ("c100", "tag"),
            ("61ff", "invalid UTF-8"),
            ("f97e00", "NaN"),
            ("f97c00", "infinity"),
            ("fa3f800000", "1.0 as float32"),
            ("fb3ff0000000000000", "1.0 as float64"),
            ("f7", "undefined"),
            ("f820", "simple value 32"),
            ("0000", "trailing byte"),
            ("1c", "reserved additional information"),
            ("a1810100", "an array as a map key"),
            ("82", "truncated array"),
        ]:
            with self.subTest(why=why), self.assertRaises(g.GoldenError):
                g.uncbor(bytes.fromhex(hexstr))

    def test_lax_mode_takes_order_but_not_structure(self):
        self.assertEqual(g.uncbor(bytes.fromhex("a202010102"), canonical=False), {1: 2, 2: 1})
        with self.assertRaises(g.GoldenError):
            g.uncbor(bytes.fromhex("a201010102"), canonical=False)  # duplicates stay refused

    def test_refuses_to_encode(self):
        for v in (float("nan"), float("inf"), 2 ** 64, -(2 ** 64) - 1, "\ud800", object(), {1.5: 2}, {(1,): 2}, {True: 1}):
            with self.subTest(v=repr(v)), self.assertRaises(g.GoldenError):
                g.cbor(v)

    def test_negative_helpers(self):
        m = g.cbor({1: "a", 2: b"\x00"})
        self.assertEqual(g.drop_key(m, 2), g.cbor({1: "a"}))
        self.assertEqual(g.add_key(m, 9), g.cbor({1: "a", 2: b"\x00", 9: None}))
        self.assertEqual(g.flip(m), m[:-1] + b"\x01")
        with self.assertRaises(g.GoldenError):
            g.drop_key(m, 3)
        with self.assertRaises(g.GoldenError):
            g.add_key(m, 1)

    def test_nesting_limit(self):
        g.uncbor(bytes.fromhex("81" * 64 + "00"))
        with self.assertRaises(g.GoldenError):
            g.uncbor(bytes.fromhex("81" * 65 + "00"))

    def test_refuses_keys_that_encode_alike(self):
        with self.assertRaises(g.GoldenError):
            g.cbor({g.Raw(b"\x01"): "raw", 1: "int"})

    def test_raw_is_copied(self):
        self.assertEqual(g.cbor({1: g.Raw(b"\x18\x18")}), bytes.fromhex("a1011818"))

    def test_round_trip(self):
        rnd = random.Random(16)

        def value(depth):
            k = rnd.randrange(9 if depth < 4 else 6)
            if k == 0:
                return rnd.randrange(-(2 ** 64), 2 ** 64)
            if k == 1:
                return rnd.randbytes(rnd.randrange(40))
            if k == 2:
                return "".join(chr(rnd.choice([rnd.randrange(32, 127), rnd.randrange(0xA0, 0xD7FF), rnd.randrange(0x10000, 0x10FFFF)])) for _ in range(rnd.randrange(12)))
            if k == 3:
                return rnd.choice([True, False, None])
            if k == 4:
                return rnd.choice([0.5, -2.25, 1.1, 65504.0, 1e300, -0.0, 3.0e-8])
            if k == 5:
                return rnd.randrange(300)
            if k in (6, 7):
                return {rnd.choice([rnd.randrange(-50, 500), "k%d" % rnd.randrange(50)]): value(depth + 1) for _ in range(rnd.randrange(6))}
            return [value(depth + 1) for _ in range(rnd.randrange(6))]

        for _ in range(500):
            v = value(0)
            b = g.cbor(v)
            self.assertEqual(g.uncbor(b), v)
            self.assertEqual(g.cbor(g.uncbor(b)), b)


class FuzzUncbor(unittest.TestCase):
    """The CoreDet decoder either refuses an input with GoldenError or decodes it to a value that
    cbor() encodes back to exactly the same bytes: nothing it accepts is ambiguous. Inputs are
    mutations and splices of valid encodings. GEN_V016_FUZZ_SECONDS sets how long it runs
    (default 2; the package's acceptance runs it for 600), GEN_V016_FUZZ_SEED the start."""

    SEEDS = [
        {1: "a", 2: b"\x00\x01", 3: [1, -1, 24, 255, 256, 65535, 65536, 2 ** 32, 2 ** 64 - 1, -(2 ** 64)]},
        {"k": {"n": None, "t": True, "f": False}, -5: [0.5, 1.1, -0.0, 65504.0, 1e300]},
        [[], {}, "", b"", "\u6c34\U00010151", list(range(30))],
        {0: "anet-relay-sig/v2", 9: b"\x00" * 32, 33: None, 34: None, 64: {1: 2}},
    ]

    def mutate(self, rnd, b):
        b = bytearray(b)
        for _ in range(rnd.randrange(1, 4)):
            op = rnd.randrange(6)
            if op == 0 and b:
                b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
            elif op == 1 and b:
                b[rnd.randrange(len(b))] = rnd.choice([0x18, 0x19, 0x1a, 0x1b, 0x1f, 0x5f, 0x7f, 0x9f, 0xbf, 0xc0, 0xf7, 0xf9, 0xfa, 0xfb, 0xff, rnd.randrange(256)])
            elif op == 2:
                i = rnd.randrange(len(b) + 1)
                b[i:i] = rnd.randbytes(rnd.randrange(1, 5))
            elif op == 3 and b:
                i = rnd.randrange(len(b))
                del b[i:i + rnd.randrange(1, 5)]
            elif op == 4:
                other = g.cbor(rnd.choice(self.SEEDS))
                i, j = rnd.randrange(len(b) + 1), rnd.randrange(len(other) + 1)
                b = b[:i] + other[j:]
            else:
                b = bytearray(rnd.randbytes(rnd.randrange(1, 24)))
        return bytes(b)

    def test_uncbor_accepts_only_what_it_reencodes(self):
        seconds = float(os.environ.get("GEN_V016_FUZZ_SECONDS", "2"))
        rnd = random.Random(int(os.environ.get("GEN_V016_FUZZ_SEED", "1")))
        corpus = [g.cbor(v) for v in self.SEEDS]
        deadline, runs, accepted = time.monotonic() + seconds, 0, 0
        while time.monotonic() < deadline:
            b = self.mutate(rnd, rnd.choice(corpus))
            runs += 1
            try:
                v = g.uncbor(b)
            except g.GoldenError:
                continue
            accepted += 1
            self.assertEqual(g.cbor(v), b, "accepted %s but re-encodes differently" % b.hex())
            if len(corpus) < 2000 and rnd.random() < 0.05:
                corpus.append(b)
        if seconds >= 60:
            print("uncbor fuzz: %d inputs in %.0f s, %d accepted" % (runs, seconds, accepted), file=sys.stderr)


class Primitives(unittest.TestCase):
    def test_hpke_suite1(self):
        sk, pk = g.SUITE1.derive_key_pair(g.seed("TEST", "r"))
        enc, s = g.SUITE1.setup_base_s(pk, b"info", g.seed("TEST", "e"))
        r = g.SUITE1.setup_base_r(enc, sk, b"info")
        c1, c2 = s.seal(b"a", b"one"), s.seal(b"b", b"two")
        self.assertEqual(r.open(b"a", c1), b"one")
        self.assertEqual(r.open(b"b", c2), b"two")
        self.assertEqual(s.export(b"anet-dack/v1", 32), r.export(b"anet-dack/v1", 32))
        self.assertNotEqual(s.export(b"anet-dack/v1", 32), s.export(b"anet-dack/v2", 32))
        r2 = g.SUITE1.setup_base_r(enc, sk, b"other info")
        with self.assertRaises(g.GoldenError):
            r2.open(b"a", c1)
        r3 = g.SUITE1.setup_base_r(enc, sk, b"info")
        with self.assertRaises(g.GoldenError):
            r3.open(b"a", c2)  # out of sequence

    def test_aeads_refuse_a_changed_byte(self):
        key, n12, n24 = bytes(32), bytes(12), bytes(24)
        for seal, open_, n in ((g.chacha20poly1305_seal, g.chacha20poly1305_open, n12),
                               (g.xchacha20poly1305_seal, g.xchacha20poly1305_open, n24),
                               (g.aes_gcm_seal, g.aes_gcm_open, n12)):
            ct = seal(key, n, b"plaintext", b"aad")
            self.assertEqual(open_(key, n, ct, b"aad"), b"plaintext")
            with self.assertRaises(g.GoldenError):
                open_(key, n, bytes([ct[0] ^ 1]) + ct[1:], b"aad")
            with self.assertRaises(g.GoldenError):
                open_(key, n, ct, b"other aad")

    def test_hpke_limits(self):
        sk, pk = g.SUITE1.derive_key_pair(g.seed("TEST", "r"))
        _, export_only = g.HPKESuite(aead=0xFFFF).setup_base_s(pk, b"", g.seed("TEST", "e"))
        self.assertEqual(len(export_only.export(b"x", 32)), 32)
        for op in (export_only.seal, export_only.open):
            with self.assertRaises(g.GoldenError):
                op(b"", b"")
        _, s = g.SUITE1.setup_base_s(pk, b"", g.seed("TEST", "e"))
        s.seq = 1 << 96
        with self.assertRaises(g.GoldenError):
            s.seal(b"", b"")
        with self.assertRaises(g.GoldenError):
            g.HPKESuite(kem=0x0021)

    def test_x25519_small_order_point(self):
        with self.assertRaises(g.GoldenError):
            g.x25519(g.seed("TEST", "x"), bytes(32))
        with self.assertRaises(g.GoldenError):
            g.SUITE1.setup_base_r(bytes(32), g.seed("TEST", "r"), b"")

    def test_hkdf_output_length(self):
        prk = g.seed("TEST", "prk")
        self.assertEqual(len(g.hkdf_expand(prk, b"", 255 * 32)), 255 * 32)
        self.assertEqual(g.hkdf_expand(prk, b"", 0), b"")
        for n in (-1, 255 * 32 + 1):
            with self.subTest(n=n), self.assertRaises(g.GoldenError):
                g.hkdf_expand(prk, b"", n)

    def test_nfc(self):
        self.assertEqual(g.nfc("e\u0301"), "\u00e9")

    def test_seed_rule(self):
        self.assertEqual(g.seed("RECOVERY-1", "rs"), g.sha256(b"anet-golden/v016/RECOVERY-1/rs"))

    def test_selftest_catches_a_broken_primitive(self):
        g.selftest()
        for name, broken in (
            ("x25519_public", lambda sk: bytes(32)),
            ("hchacha20", lambda k, n: bytes(32)),
            ("hkdf_expand", lambda prk, info, n: bytes(n)),
            ("cbor", lambda v: b"\x00"),
            ("argon2id", lambda *a, **k: bytes(a[5])),
        ):
            with self.subTest(name=name), mock.patch.object(g, name, broken), self.assertRaises(g.GoldenError):
                g.selftest()


class Framework(unittest.TestCase):
    def test_vector_paths_are_checked(self):
        for bad in ("Other/x.json", "ANetCore", "ANetCore/../ANet/x.json", "ANetCore/x/"):
            with self.subTest(path=bad), self.assertRaises(g.GoldenError):
                g.vector("ZZ-TEST", bad)
        with self.assertRaises(g.GoldenError):
            g.vector("ZZ-TEST")

    def test_one_generator_per_vector(self):
        with mock.patch.dict(g.GENERATORS):
            g.vector("ZZ-TEST", "ANetCore/x.json")(lambda: {})
            with self.assertRaises(g.GoldenError):
                g.vector("ZZ-TEST", "ANetCore/y.json")(lambda: {})
        self.assertNotIn("ZZ-TEST", g.GENERATORS)

    def test_serialize(self):
        self.assertEqual(g.serialize({"t": "\u6c34"}), '{\n  "t": "\u6c34"\n}\n'.encode("utf-8"))
        self.assertEqual(g.serialize(b"\x00\xff"), b"\x00\xff")
        self.assertEqual(g.serialize("\u00e9"), b"\xc3\xa9")
        with self.assertRaises(g.GoldenError):
            g.serialize(1)

    def test_an_error_in_the_script_exits_2(self):
        err = io.StringIO()
        with mock.patch.object(g, "check", side_effect=KeyError("id")), contextlib.redirect_stderr(err):
            self.assertEqual(g.main(["check"]), 2)
        self.assertIn("internal error, KeyError", err.getvalue())


class XCheck(unittest.TestCase):
    """golden-xcheck on a made-up tree: one Python vector in ANetCore, one in ANet."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gen_v016_test_"))
        self.addCleanup(shutil.rmtree, self.tmp)
        core = self.tmp / "ANetCore"
        (core / "golden/testdata").mkdir(parents=True)
        (core / "go.mod").write_text("module github.com/ANetResearch/ANetCore\n")
        self.index = {
            "format": "anet-golden-index/1",
            "vectors": [
                {"id": "V1", "gen": "go+python", "at": [{"repo": "ANetCore", "path": "x/testdata/v1.json"}]},
                {"id": "V2", "gen": "python", "at": [{"repo": "ANet", "path": "y/v2.cbor"}]},
                {"id": "V3", "gen": "python", "at": [{"repo": "ANetCore", "path": "x/v3.json", "todo": "v030-todo(XX-3)"}]},
                {"id": "V4", "gen": "go", "at": [{"repo": "ANetCore", "path": "x/v4_test.go", "test": "TestV4"}]},
            ],
        }
        (core / g.INDEX_PATH).write_text(json.dumps(self.index))
        self.ws = g.Workspace(root=self.tmp, core=core)
        self.gens = {}
        self.register("V1", ("ANetCore/x/testdata/v1.json",), lambda: {"k": g.b16(g.seed("V1", "k"))})

    def register(self, vid, paths, fn):
        self.gens[vid] = g.Generator(vid, paths, fn)

    def check(self, all_repos=False):
        return g.check(self.ws, generators=self.gens, all_repos=all_repos)

    def written(self):
        g.write(self.ws, ["V1"], generators=self.gens)
        return self.tmp / "ANetCore/x/testdata/v1.json"

    def assertProblem(self, text, all_repos=False):
        problems, _ = self.check(all_repos)
        self.assertTrue(any(text in p for p in problems), "want a problem with %r, got %r" % (text, problems))

    def test_written_vector_reproduces(self):
        f = self.written()
        self.assertTrue(f.read_text().endswith("}\n"))
        problems, notes = self.check()
        self.assertEqual(problems, [])
        self.assertTrue(any("V3: not delivered yet (v030-todo(XX-3))" in n for n in notes), notes)

    def test_one_changed_byte_fails(self):
        f = self.written()
        b = bytearray(f.read_bytes())
        b[9] ^= 1
        f.write_bytes(bytes(b))
        self.assertProblem("V1: ANetCore/x/testdata/v1.json differs from what gen_v016.py writes: first difference at byte 9")

    def test_one_more_byte_fails(self):
        f = self.written()
        f.write_bytes(f.read_bytes() + b"\n")
        self.assertProblem("first difference at byte")

    def test_missing_file_fails(self):
        self.assertProblem("V1: ANetCore/x/testdata/v1.json does not exist; write it with: gen_v016.py write V1")

    def test_generator_without_row_fails(self):
        self.written()
        self.register("V9", ("ANetCore/x/v9.json",), lambda: {})
        self.assertProblem("V9: has a generator but no row")

    def test_generator_for_go_vector_fails(self):
        self.written()
        self.register("V4", ("ANetCore/x/v4_test.go",), lambda: "")
        self.assertProblem("V4: golden/testdata/index.json says gen 'go'")

    def test_generator_paths_must_match_row(self):
        self.written()
        self.register("V1", ("ANetCore/x/testdata/other.json",), lambda: {})
        self.assertProblem("V1: the generator writes ['ANetCore/x/testdata/other.json'] but the index lists ['ANetCore/x/testdata/v1.json']")

    def test_file_without_generator_fails(self):
        self.written()
        (self.tmp / "ANetCore/x/v3.json").write_text("{}\n")
        self.assertProblem("V3: ANetCore/x/v3.json exists but gen_v016.py has no generator for it")

    def test_missing_repository(self):
        self.written()
        self.register("V2", ("ANet/y/v2.cbor",), lambda: g.cbor({1: 2}))
        problems, notes = self.check()
        self.assertEqual(problems, [])
        self.assertTrue(any("V2: ANet/y/v2.cbor is not checked because repository ANet is not next to ANetCore" in n for n in notes), notes)
        self.assertProblem("repository ANet is not next to ANetCore (--all-repos)", all_repos=True)
        with self.assertRaises(g.GoldenError):
            g.write(self.ws, ["V2"], generators=self.gens)
        (self.tmp / "ANet").mkdir()
        (self.tmp / "ANet/go.mod").write_text("module github.com/ANetResearch/ANet\n")
        self.assertEqual(g.write(self.ws, ["V2"], generators=self.gens), ["ANet/y/v2.cbor"])
        self.assertEqual((self.tmp / "ANet/y/v2.cbor").read_bytes(), bytes.fromhex("a10102"))
        self.assertEqual(self.check(all_repos=True)[0], [])

    def test_generator_that_raises_is_a_problem(self):
        def bug():
            return {"k": bytes(3)[7]}
        self.register("V1", ("ANetCore/x/testdata/v1.json",), bug)
        self.assertProblem("V1: the generator raised IndexError")

    def test_repository_is_known_by_its_module(self):
        (self.tmp / "ANet").mkdir()
        (self.tmp / "ANet/go.mod").write_text("module example.com/ANet\n")
        self.assertIsNone(self.ws.repo("ANet"))
        (self.tmp / "Refs/ANet").mkdir(parents=True)
        (self.tmp / "Refs/ANet/go.mod").write_text("module github.com/ANetResearch/ANet\n\ngo 1.26\n")
        self.assertEqual(self.ws.repo("ANet"), (self.tmp / "Refs/ANet").resolve())

    def test_generator_that_fails_is_a_problem(self):
        def boom():
            raise g.GoldenError("no key")
        self.register("V1", ("ANetCore/x/testdata/v1.json",), boom)
        self.assertProblem("V1: the generator failed: no key")

    def test_several_paths_need_a_dict_of_exactly_them(self):
        self.index["vectors"][0]["at"].append({"repo": "ANetCore", "path": "x/testdata/v1b.json"})
        (self.ws.core / g.INDEX_PATH).write_text(json.dumps(self.index))
        self.register("V1", ("ANetCore/x/testdata/v1.json", "ANetCore/x/testdata/v1b.json"), lambda: {"ANetCore/x/testdata/v1.json": {}})
        self.assertProblem("must return a dict with exactly its paths")


class SealV2(unittest.TestCase):
    """The helpers behind SEALED-2A and SEALED-2C (CORE-2)."""

    def test_padme_values(self):
        # The values of the Go test TestPadmeValues, computed by hand from the definition.
        for n, want in [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (7, 7), (8, 8), (9, 10), (11, 12),
                        (100, 104), (1000, 1024), (1025, 1088), (5000, 5120), (65536, 65536), (65537, 67584)]:
            self.assertEqual(g.padme(n), want, n)
        for n in range(2, 5000):
            p = g.padme(n)
            self.assertTrue(p >= n and g.padme(p) == p, n)

    def test_wrap_lands_on_a_padme_length(self):
        unreachable = 0
        for n in range(0, 1300):
            body = bytes(n)
            w, pad = g.seal_wrap(body)
            self.assertEqual(g.padme(len(w)), len(w), n)
            self.assertEqual(g.uncbor(w), {3: body, 21: bytes(pad)})
            unpadded = len(g.cbor({3: body, 21: b""}))
            if len(w) != g.padme(unpadded):
                unreachable += 1  # the next Padmé length, because the first is out of reach
        self.assertGreater(unreachable, 0)

    def test_preimage_refuses_its_own_keys(self):
        fields = {1: g.Raw(g.cbor("a")), 9: g.Raw(g.cbor(b"body"))}
        pre = g.uncbor(g.seal_preimage(fields, b"e" * 32, b"k" * 16, 1))
        self.assertEqual(pre[9], g.sha256(b"body"))
        self.assertIsNone(pre[33])
        self.assertIsNone(pre[34])
        self.assertEqual(pre[0], "anet-relay-sig/v2")
        for k in (0, 30, 31, 32, 33, 34):
            with self.assertRaises(g.GoldenError):
                g.seal_preimage({**fields, k: g.Raw(g.cbor("x"))}, b"e" * 32, b"k" * 16, 1)

    def test_sealed_2a_opens_in_python(self):
        """The independent side reads its own vector back: layer 1 opens with the recipient key and
        gives the Wrap, the ack_key and the inner it records."""
        v = g.gen_sealed_2a()
        env = g.uncbor(bytes.fromhex(v["envelope"]))
        info = bytes.fromhex(v["hpke_info"])
        ctx = g.SUITE1.setup_base_r(env[5], bytes.fromhex(v["recipient"]["sk"]), info)
        self.assertEqual(ctx.open(b"", env[6]), bytes.fromhex(v["wrap"]))
        self.assertEqual(ctx.export(b"anet-dack/v1", 32).hex(), v["ack_key"])
        wrap = g.uncbor(bytes.fromhex(v["wrap"]))
        self.assertEqual(wrap[3], bytes.fromhex(v["inner_cbor"]))
        self.assertTrue(g.ed25519_verify(bytes.fromhex(v["sender"]["pub"]), bytes.fromhex(v["sig_preimage"]),
                                         bytes.fromhex(v["inner"]["sig"])))

    def test_sealed_2b_opens_in_python(self):
        """Both layers of SEALED-2B open on the independent side: layer 1 with the epoch key, layer 2
        with the interaction key under the anet-ix/v2 info; the single-layer envelope of the same
        layer-1 ephemeral key has the same ack_key; the signature is over the preimage with ikid and
        enc2, not over the single-layer one."""
        v = g.gen_sealed_2b()
        env = g.uncbor(bytes.fromhex(v["envelope"]))
        ctx = g.SUITE1.setup_base_r(env[5], bytes.fromhex(v["recipient"]["sk"]), bytes.fromhex(v["hpke_info"]))
        wrap = g.uncbor(ctx.open(b"", env[6]))
        self.assertEqual(ctx.export(b"anet-dack/v1", 32).hex(), v["ack_key"])
        self.assertEqual(sorted(wrap), [1, 2, 3, 21])
        self.assertEqual(wrap[1].hex(), v["recipient_ix"]["kid"])
        self.assertEqual(g.seal_ix_info(v["recipient"]["aid"], wrap[1]).hex(), v["ix_info"])
        ctx2 = g.SUITE1.setup_base_r(wrap[2], bytes.fromhex(v["recipient_ix"]["sk"]), bytes.fromhex(v["ix_info"]))
        inner = ctx2.open(b"", wrap[3])
        self.assertEqual(inner.hex(), v["inner_cbor"])
        one = g.uncbor(bytes.fromhex(v["single_layer"]["envelope"]))
        ctx1 = g.SUITE1.setup_base_r(one[5], bytes.fromhex(v["recipient"]["sk"]), bytes.fromhex(v["hpke_info"]))
        self.assertEqual(ctx1.export(b"anet-dack/v1", 32).hex(), v["ack_key"])
        pub, sig = bytes.fromhex(v["sender"]["pub"]), bytes.fromhex(v["inner"]["sig"])
        self.assertTrue(g.ed25519_verify(pub, bytes.fromhex(v["sig_preimage"]), sig))
        self.assertFalse(g.ed25519_verify(pub, bytes.fromhex(v["single_layer"]["sig_preimage"]), sig))
        self.assertEqual(env[8], v["inner"]["exp"])
        self.assertEqual(env[7][1], 1)


class AccessAndGrant(unittest.TestCase):
    """The reference checks behind ACCESS-1 and GRANT-1: each refuses at the step it names, and
    the vectors' cases are judged by it, not only declared."""

    def setUp(self):
        self.mbox, self.holder = g.seed("test", "mbox"), g.seed("test", "holder")
        self.owner, self.now = "bafyowner", g.SS_TS
        self.body = g.cap_body_map(self.owner, 1, bytes(range(16)), 1, self.now + g.SEAL_DAY, g.ed25519_public(self.holder))
        self.outer = {1: 2, 2: self.owner, 3: 1, 4: bytes(16), 5: bytes(32), 6: b"ct"}

    def env(self, body: bytes, holder=None, outer=None, sig=None) -> bytes:
        o = outer or self.outer
        d = g.seal_env_digest(self.outer)
        a = {1: 1, 2: {1: body, 2: sig or g.ed25519_sign(self.mbox, body)},
             3: g.ed25519_sign(holder or self.holder, g.access_input(self.body[3], d))}
        return g.cbor({**o, 7: a})

    def verify(self, env: bytes, epoch=1, mbox=None, now=None) -> str:
        return g.verify_access(env, epoch, g.ed25519_public(mbox or self.mbox), now if now is not None else self.now)

    def test_verify_access_steps(self):
        body = g.cbor(self.body)
        self.assertEqual(self.verify(self.env(body)), "")
        self.assertEqual(self.verify(g.cbor({**self.outer, 7: {1: 0}})), "parse")
        self.assertEqual(self.verify(self.env(g.cbor({**self.body, 4: 3}))), "decode")
        self.assertEqual(self.verify(self.env(g.cbor({**self.body, 0: "anet.cap/2"}))), "type")
        self.assertEqual(self.verify(self.env(g.cbor({**self.body, 1: "bafyother"}))), "owner")
        self.assertEqual(self.verify(self.env(body), epoch=2), "epoch")
        self.assertEqual(self.verify(self.env(body), mbox=g.seed("test", "other")), "sig")
        self.assertEqual(self.verify(self.env(body), now=self.body[5] + g.CAP_GRACE + 1), "exp")
        self.assertEqual(self.verify(self.env(body, holder=g.seed("test", "other"))), "proof")
        self.assertEqual(self.verify(self.env(body, outer={**self.outer, 6: b"other"})), "proof")

    def test_cap_body_decode_is_strict(self):
        body = g.cbor(self.body)
        self.assertEqual(g.decode_cap_body(body), self.body)
        for bad in (g.cbor({**self.body, 7: 1}), g.cbor({k: v for k, v in self.body.items() if k != 6}),
                    g.cbor({**self.body, 3: bytes(15)}), g.cbor({**self.body, 2: -1}), g.cbor({**self.body, 4: True}),
                    g._cbor_map_in_order([(1, self.owner), (0, g.CAP_TYPE)] + [(k, self.body[k]) for k in range(2, 7)]),
                    g.cbor([1])):
            self.assertIsNone(g.decode_cap_body(bad), bad.hex())

    def test_access_input(self):
        self.assertEqual(g.access_input(bytes(16), bytes(32)), b"anet-access/v2\x00" + bytes(48))
        for cid, d in ((bytes(15), bytes(32)), (bytes(16), bytes(31))):
            with self.assertRaises(g.GoldenError):
                g.access_input(cid, d)

    def test_check_grant_steps(self):
        body = g.cbor(self.body)
        base = {1: {1: body, 2: g.ed25519_sign(self.mbox, body)}, 2: self.holder, 3: "bafyhome"}
        pub = g.ed25519_public(self.mbox)

        def check(gr, frm=self.owner, ix="ix", keys=self.owner):
            return g.check_grant(g.cbor(gr), frm, ix, keys, 1, pub, self.now)

        self.assertEqual(check(base), "")
        self.assertEqual(check({**base, 6: 1}), "decode")
        for k in (3, 4, 5, 6):  # a null is not an absent key, "" or false
            self.assertEqual(check({**base, k: None}), "decode", k)
        self.assertEqual(check({**base, 3: "a\x00b"}), "decode")
        self.assertEqual(check(base, frm="bafyother", keys="bafyother"), "owner")
        self.assertEqual(check(base, keys="bafyother"), "keys")
        self.assertEqual(check({**base, 2: g.seed("test", "other")}), "holder")
        self.assertEqual(check({**base, 4: "ix-2"}), "ix")
        self.assertEqual(check({**base, 4: "ix", 5: "192.0.2.1:1"}), "p2p")
        self.assertEqual(check({**base, 4: "ix", 6: True}), "pay")
        self.assertEqual(check({**base, 4: "ix"}), "")

    def test_vectors_judge_their_cases(self):
        """A case whose declared step the reference does not reach makes the generator fail."""
        orig = g.verify_access
        try:
            g.verify_access = lambda *a: "never"
            with self.assertRaises(g.GoldenError):
                g.gen_access_1()
        finally:
            g.verify_access = orig
        orig = g.check_grant
        try:
            g.check_grant = lambda *a: "never"
            with self.assertRaises(g.GoldenError):
                g.gen_grant_1()
        finally:
            g.check_grant = orig



class Notices(unittest.TestCase):
    """The reference behind KSN-1: its own KEL replay agrees with KEL-2A and KEL-2B, the notice check
    refuses at the step each case names, and the generator asks it about every case."""

    def test_replay_matches_the_kel_vectors(self):
        root = Path(__file__).resolve().parents[2]
        for name in ("vec-kel-2a.json", "vec-kel-2b.json"):
            v = json.loads((root / "identity" / "testdata" / name).read_text(encoding="utf-8"))
            states = g.kel_replay_states(bytes.fromhex(v["kel"]))
            keys = {k["pub"]: k["name"] for k in v["keys"]}
            self.assertEqual(len(states), len(v["states"]), name)
            for got, want in zip(states, v["states"]):
                self.assertEqual((got["seq"], got["status"], got["toad"], got["witness"], got["superseded_at"],
                                  got["urgent"], keys.get(got["key"].hex(), "") if got["key"] else ""),
                                 (want["seq"], want["status"], want["toad"], want["witness"], want["superseded_at"],
                                  want["retired_urgently"], want["key"]), name)

    def test_replay_refuses(self):
        a = g.kel_2a().events
        g.kel_replay_states(g.kel_wire_of(a))
        e, pre, eid, sig = a[1]
        for bad in ([a[0], (e, pre, eid, g.flip(sig, 0))] + a[2:], [a[0]] + a[2:], a[1:], [a[0], a[0]]):
            with self.assertRaises(g.GoldenError):
                g.kel_replay_states(g.kel_wire_of(bad))

    def test_decode_is_strict(self):
        body = g.cbor({0: g.KSN_TYPE, 1: "a", 2: 1, 3: "h", 4: 5, 5: "w"})
        env = {1: "w", 2: 0, 3: -8, 4: bytes(64)}
        self.assertIsNotNone(g.notice_decode(g.cbor({1: body, 2: env})))
        for bad in (g.cbor({1: body, 2: {**env, 5: "r"}}), g.cbor({1: body, 2: {**env, 3: -7}}),
                    g.cbor({1: body, 2: {**env, 2: True}}), g.cbor({1: body, 2: {**env, 4: bytes(63)}}),
                    g.cbor({1: body, 2: env, 3: 0}), g.cbor({1: body}), g.cbor({1: g.cbor([1]), 2: env}),
                    g.cbor({1: g.cbor({0: g.KSN_TYPE, 1: "a", 2: -1, 3: "h", 4: 5, 5: "w"}), 2: env}),
                    g.cbor({1: g.cbor({0: "anet.ksn/2", 1: "a", 2: 1, 3: "h", 4: 5, 5: "w"}), 2: env}),
                    g._cbor_map_in_order([(2, env), (1, body)]), b"\xff"):
            self.assertIsNone(g.notice_decode(bad), bad.hex())

    def test_vector_judges_its_cases(self):
        """A case whose declared reason the reference does not give makes the generator fail."""
        orig = g.notice_verify
        try:
            g.notice_verify = lambda *a: "never"
            with self.assertRaises(g.GoldenError):
                g.gen_ksn_1()
        finally:
            g.notice_verify = orig


class Repository(unittest.TestCase):
    def test_every_registered_vector_reproduces(self):
        """What the CI job golden-xcheck runs, on this checkout."""
        problems, _ = g.check(g.Workspace())
        self.assertEqual(problems, [])

    def test_vector_paths_are_valid(self):
        for vid, gen in g.GENERATORS.items():
            for p in gen.paths:
                self.assertIn(p.split("/", 1)[0], g.REPOS, vid)

    def test_relayauth3_pins_match_the_go_test(self):
        """RELAYAUTH-3 is held by a Go test (gen "go"), so check does not regenerate it; the
        preimages and signatures it pins must still be the ones computed here independently, in
        the order of its ra3Rows."""
        import re
        src = (g.CORE_DIR / "golden" / "relayauth_v3_test.go").read_text(encoding="utf-8")
        rows = src[src.index("var ra3Rows"):src.index("var ra3Pending")]
        pinned = list(zip(re.findall(r'"(anet-relay/v2/[^"]*)"', rows), re.findall(r'"([0-9a-f]{128})"', rows)))
        self.assertEqual(pinned, g.relayauth3_pins())

    def test_session_and_dir_helpers_refuse_nul(self):
        """CORE-E9 holds in the independent implementation too: no vector is built on a field
        that holds U+0000."""
        for call in (lambda: g.session_key_info("h\x00", bytes(16)),
                     lambda: g.session_mac_input(bytes(16), 1, "PO\x00ST", "/", "", b""),
                     lambda: g.session_mac_input(bytes(16), 1, "POST", "/\x00", "", b""),
                     lambda: g.session_mac_input(bytes(16), 1, "POST", "/", "\x00", b""),
                     lambda: g.dir_hash("a\x00b")):
            with self.assertRaises(g.GoldenError):
                call()

    def test_hpp_go_pins_match_the_go_tests(self):
        """CARD-1, TASKDOC-3 and SUPPLY-EPOCH-1 are held by Go tests (gen "go"), and so are the 0.2
        completion vectors that carry the EV2-1 receipt; the bytes they pin must be the ones
        computed here independently."""
        for path, values in g.hpp_go_pins().items():
            src = (g.CORE_DIR / path).read_text(encoding="utf-8")
            for v in values:
                self.assertIn('"%s"' % v, src, "%s does not pin %s" % (path, v[:24]))

    def test_evidence_helpers_refuse_nul_and_empty(self):
        """CORE-E9 (and "not empty") in the independent implementation of L27, L28, L31, L33 and
        L34: no evidence vector is built on a field that holds U+0000."""
        for call in (lambda: g.ix_commit_preimage("a\x00b", "c"),
                     lambda: g.ix_commit_preimage("a", "b\x00c"),
                     lambda: g.ix_commit_preimage("", "c"),
                     lambda: g.requester_commit_preimage("r\x00", bytes(32)),
                     lambda: g.requester_commit_preimage("r", bytes(31)),
                     lambda: g.review_tag(bytes(32), "r", "s\x00"),
                     lambda: g.review_tag(bytes(16), "r", "s"),
                     lambda: g.settle_guard_preimage("p", ""),
                     lambda: g.pay_bind_preimage("a\x00b", "c")):
            with self.assertRaises(g.GoldenError):
                call()
        self.assertEqual(g.suite_kel().aid, g.SUITE_AID)


if __name__ == "__main__":
    unittest.main()
