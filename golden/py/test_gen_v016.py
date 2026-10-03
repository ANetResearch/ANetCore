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
