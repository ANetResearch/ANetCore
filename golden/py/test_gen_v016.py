"""Tests of gen_v016.py itself: the CoreDet codec, the primitives, and the golden-xcheck machinery.

Run from ANetCore: python3 -B golden/py/test_gen_v016.py (-B keeps __pycache__ out of the tree).
"""

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


class Repository(unittest.TestCase):
    def test_every_registered_vector_reproduces(self):
        """What the CI job golden-xcheck runs, on this checkout."""
        problems, _ = g.check(g.Workspace())
        self.assertEqual(problems, [])

    def test_vector_paths_are_valid(self):
        for vid, gen in g.GENERATORS.items():
            for p in gen.paths:
                self.assertIn(p.split("/", 1)[0], g.REPOS, vid)


if __name__ == "__main__":
    unittest.main()
