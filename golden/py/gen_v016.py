#!/usr/bin/env python3
"""The independent implementation behind the golden vectors of ANetCore v0.16 (anet 0.3.0).

Every cryptographic golden vector is written by this script, from published seeds, with code that
shares nothing with the Go implementation: pure Python on the `cryptography` package (OpenSSL),
with CoreDet-CBOR, CIDs, HPKE (RFC 9180, with Export), HKDF and XChaCha20-Poly1305 written out
below. The Go tests read the files this script writes and must open or reproduce them byte for
byte. The CI job golden-xcheck runs `check`: it regenerates every vector registered here and
compares it with the file in the repository, so a file that drifts from its generator, or a
generator that drifts from its file, fails.

Commands
  check (default)  run the known-answer tests, regenerate every registered vector and compare it
                   byte for byte with its file; also check that golden/testdata/index.json and the
                   generators below agree
  write ID...      write the files of the named vectors (write --all: every registered vector)
  list             every vector of golden/testdata/index.json and where it stands
  selftest         only the known-answer tests of the primitives

Options
  --root DIR       where to look for ANet, ANetHub and ANetLink: DIR/<name> or DIR/Refs/<name>, a
                   directory whose go.mod names module github.com/ANetResearch/<name> (default: the
                   directory that holds this ANetCore checkout). ANetCore, its index and the
                   generators are always this checkout
  --all-repos      a repository that is not there is an error; without it, the vectors that live
                   in a missing repository are listed as not checked

Environment: Python 3.10 or later and the packages in requirements.txt beside this file
(`python3 -m pip install -r golden/py/requirements.txt`).

Exit status: 0 everything reproduced; 1 a vector or the index disagrees (each problem is printed
with what to do, including a generator that raised); 2 the tool could not run (a missing library,
a failed known-answer test, bad arguments, an error in this script).

Adding a vector
  1. Its row is in golden/testdata/index.json already: the id, the files, the labels and objects
     it covers, and "gen" (who produces the bytes). Remove the row's "todo" marker when the file
     is delivered; golden/index_test.go fails while a delivered file still carries one.
  2. Write a generator below, in the section of its area, and register it with @vector(id, paths),
     written at the start of a line with the id as a string literal (golden/index_test.go reads
     the ids from this file's text): the paths are "<repository>/<path in it>", exactly the files
     of the index row. It returns the
     content: a dict or list (written as JSON, two-space indent, one trailing newline), bytes
     (written as they are) or str; with several paths, a dict from path to content.
  3. Every random input comes from seed(vector id, role) = SHA-256("anet-golden/v016/<id>/<role>")
     (CORE-G5). HPKE sender keys come from DeriveKeyPair(seed(...)), which Go cannot do, so a
     sealed vector is opened by Go, not reproduced (CORE-G2).
  4. `gen_v016.py write <id>` writes the file; the Go test that reads it lands in the same change;
     `gen_v016.py check` must then pass.

Nothing here is a real key: every secret is derived from a public label.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import struct
import sys
import traceback
import unicodedata
from pathlib import Path

_REQUIREMENTS = Path(__file__).resolve().with_name("requirements.txt")

try:
    import cryptography
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import hmac as _hmac
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.exceptions import InvalidSignature, InvalidTag
except ImportError as e:  # pragma: no cover - environment
    print("gen_v016.py: the cryptography package it needs is missing or too old (%s); "
          "run: python3 -m pip install -r %s" % (e, _REQUIREMENTS), file=sys.stderr)
    sys.exit(2)

CORE_DIR = Path(__file__).resolve().parents[2]  # this ANetCore checkout
INDEX_PATH = "golden/testdata/index.json"       # in ANetCore
REPOS = ("ANetCore", "ANet", "ANetHub", "ANetLink")
# Kinds of "gen" in index.json whose files this script writes (and golden-xcheck regenerates).
PY_GENS = ("python", "go+python", "rfc")
ALL_GENS = PY_GENS + ("go", "a2a-python")


class GoldenError(Exception):
    """A primitive, a known-answer test or an encoding refused its input."""


# ---------------------------------------------------------------------------------------------
# CoreDet-CBOR (RFC 8949 §4.2 core deterministic encoding; no tags, no NaN or infinities)
# ---------------------------------------------------------------------------------------------

class Raw(bytes):
    """Bytes that are already CBOR: cbor() copies them unchanged (a field "as received")."""


def _head(major: int, n: int) -> bytes:
    if n < 0:
        raise GoldenError("cbor: negative length or argument")
    if n < 24:
        return bytes([major << 5 | n])
    if n <= 0xFF:
        return bytes([major << 5 | 24, n])
    if n <= 0xFFFF:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if n <= 0xFFFFFFFF:
        return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    if n <= 0xFFFFFFFFFFFFFFFF:
        return bytes([major << 5 | 27]) + n.to_bytes(8, "big")
    raise GoldenError("cbor: integer does not fit in 64 bits (CoreDet has no big numbers)")


def _float(x: float) -> bytes:
    if math.isnan(x) or math.isinf(x):
        raise GoldenError("cbor: NaN and infinities are not CoreDet")
    # Preferred serialization: the shortest of float16, float32, float64 that keeps the value.
    for code, fmt in ((0xF9, ">e"), (0xFA, ">f")):
        try:
            b = struct.pack(fmt, x)
        except (OverflowError, struct.error):
            continue
        if struct.unpack(fmt, b)[0] == x and math.copysign(1, struct.unpack(fmt, b)[0]) == math.copysign(1, x):
            return bytes([code]) + b
    return b"\xfb" + struct.pack(">d", x)


def cbor(v) -> bytes:
    """Encodes v as CoreDet-CBOR: int, bytes, str, list or tuple, dict (int or str keys), bool,
    None, float, or Raw (copied unchanged)."""
    if isinstance(v, Raw):
        return bytes(v)
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        return _head(2, len(b)) + b
    if isinstance(v, str):
        try:
            b = v.encode("utf-8")
        except UnicodeEncodeError as e:
            raise GoldenError("cbor: text is not valid Unicode (%s)" % e) from None
        return _head(3, len(b)) + b
    if isinstance(v, (list, tuple)):
        return _head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        for k in v:
            if isinstance(k, bool) or not isinstance(k, (int, str, bytes)):
                raise GoldenError("cbor: map key %r is not an integer, text or bytes" % (k,))
        items = sorted((cbor(k), cbor(x)) for k, x in v.items())
        for a, b in zip(items, items[1:]):
            if a[0] == b[0]:
                raise GoldenError("cbor: two map keys encode to the same bytes")
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    if isinstance(v, float):
        return _float(v)
    raise GoldenError("cbor: cannot encode %s" % type(v).__name__)


class _Reader:
    def __init__(self, b: bytes, canonical: bool, max_depth: int):
        self.b, self.i, self.canonical, self.max_depth = b, 0, canonical, max_depth

    def take(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.b):
            raise GoldenError("cbor: truncated at byte %d" % self.i)
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def arg(self, ai: int) -> int:
        if ai < 24:
            return ai
        if ai == 31:
            raise GoldenError("cbor: indefinite length at byte %d (not CoreDet)" % (self.i - 1))
        if ai > 27:
            raise GoldenError("cbor: reserved additional information %d at byte %d" % (ai, self.i - 1))
        n = int.from_bytes(self.take(1 << (ai - 24)), "big")
        if self.canonical and n < (24, 0x100, 0x10000, 0x100000000)[ai - 24]:
            raise GoldenError("cbor: integer or length not in its shortest form at byte %d" % self.i)
        return n

    def item(self, depth: int = 0):
        if depth > self.max_depth:
            raise GoldenError("cbor: nested deeper than %d" % self.max_depth)
        start = self.i
        ib = self.take(1)[0]
        major, ai = ib >> 5, ib & 31
        if major == 7:
            return self.simple(ai, start)
        n = self.arg(ai)
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major == 2:
            return self.take(n)
        if major == 3:
            try:
                return self.take(n).decode("utf-8")
            except UnicodeDecodeError:
                raise GoldenError("cbor: text at byte %d is not valid UTF-8" % start) from None
        if major == 4:
            return [self.item(depth + 1) for _ in range(n)]
        if major == 5:
            out, prev = {}, None
            for _ in range(n):
                k0 = self.i
                k = self.item(depth + 1)
                kb = self.b[k0:self.i]
                if isinstance(k, bool) or not isinstance(k, (int, str, bytes)):
                    raise GoldenError("cbor: map key at byte %d is not an integer, text or bytes" % k0)
                if k in out:
                    raise GoldenError("cbor: duplicate map key at byte %d" % k0)
                if self.canonical and prev is not None and kb <= prev:
                    raise GoldenError("cbor: map keys not in CoreDet order at byte %d" % k0)
                prev = kb
                out[k] = self.item(depth + 1)
            return out
        raise GoldenError("cbor: tag at byte %d (CoreDet has no tags)" % start)

    def simple(self, ai: int, start: int):
        if ai == 20:
            return False
        if ai == 21:
            return True
        if ai == 22:
            return None
        if ai in (25, 26, 27):
            fmt = {25: ">e", 26: ">f", 27: ">d"}[ai]
            raw = self.take(struct.calcsize(fmt))
            x = struct.unpack(fmt, raw)[0]
            if math.isnan(x) or math.isinf(x):
                raise GoldenError("cbor: NaN or infinity at byte %d" % start)
            if self.canonical and _float(x) != self.b[start:self.i]:
                raise GoldenError("cbor: float at byte %d not in its shortest form" % start)
            return x
        raise GoldenError("cbor: simple value %d at byte %d is not CoreDet" % (ai, start))


def uncbor(b: bytes, canonical: bool = True, max_depth: int = 64):
    """Decodes one CBOR item. With canonical (the default) it also refuses every encoding that is
    not CoreDet: a long-form length, an unsorted map, a non-shortest float. Maps come back as
    dicts, byte strings as bytes."""
    r = _Reader(bytes(b), canonical, max_depth)
    v = r.item()
    if r.i != len(r.b):
        raise GoldenError("cbor: %d bytes after the item" % (len(r.b) - r.i))
    return v


# ---------------------------------------------------------------------------------------------
# CIDs (CIDv1, sha2-256, base32 lower case; dag-cbor 0x71 for objects, raw 0x55 for bytes)
# ---------------------------------------------------------------------------------------------

def _cid(codec: int, data: bytes) -> str:
    raw = bytes([0x01, codec, 0x12, 0x20]) + sha256(data)
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def cid(preimage: bytes) -> str:
    """The CID of a CoreDet preimage (anetcid.Sum)."""
    return _cid(0x71, preimage)


def cid_raw(data: bytes) -> str:
    """The CID of opaque bytes (anetcid.SumRaw)."""
    return _cid(0x55, data)


# ---------------------------------------------------------------------------------------------
# Primitives (all from the cryptography package, except HChaCha20 and HKDF-Expand, written out)
# ---------------------------------------------------------------------------------------------

def sha256(b: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(bytes(b))
    return h.finalize()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    h = _hmac.HMAC(bytes(key), hashes.SHA256())
    h.update(bytes(msg))
    return h.finalize()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 §2.2; an empty salt is HashLen zero bytes."""
    return hmac_sha256(salt if salt else b"\x00" * 32, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 §2.3 (length 0 gives b"")."""
    if not 0 <= length <= 255 * 32:
        raise GoldenError("hkdf: output length %d out of range" % length)
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac_sha256(prk, t + info + bytes([i]))
        out += t
        i += 1
    return out[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 (RFC 5869)."""
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def ed25519_public(seed: bytes) -> bytes:
    """The Ed25519 public key of a 32-byte seed (RFC 8032 private key)."""
    return Ed25519PrivateKey.from_private_bytes(bytes(seed)).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(bytes(seed)).sign(bytes(msg))


def ed25519_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes(public)).verify(bytes(sig), bytes(msg))
        return True
    except (InvalidSignature, ValueError):
        return False


def x25519_public(sk: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(bytes(sk)).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def x25519(sk: bytes, pk: bytes) -> bytes:
    """X25519(sk, pk); an all-zero result (a small-order point) is refused, as RFC 9180 requires."""
    try:
        out = X25519PrivateKey.from_private_bytes(bytes(sk)).exchange(X25519PublicKey.from_public_bytes(bytes(pk)))
    except ValueError as e:  # the package refuses a small-order point itself, and a wrong length
        raise GoldenError("x25519: %s" % e) from None
    if out == b"\x00" * 32:
        raise GoldenError("x25519: all-zero shared secret")
    return out


def chacha20poly1305_seal(key: bytes, nonce: bytes, pt: bytes, aad: bytes = b"") -> bytes:
    return ChaCha20Poly1305(bytes(key)).encrypt(bytes(nonce), bytes(pt), bytes(aad))


def chacha20poly1305_open(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    try:
        return ChaCha20Poly1305(bytes(key)).decrypt(bytes(nonce), bytes(ct), bytes(aad))
    except InvalidTag:
        raise GoldenError("chacha20poly1305: authentication failed") from None


def _rotl(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """HChaCha20 (draft-irtf-cfrg-xchacha §2.2): the subkey of XChaCha20."""
    if len(key) != 32 or len(nonce16) != 16:
        raise GoldenError("hchacha20: key must be 32 bytes and nonce 16")
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))

    def qr(a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def _xchacha(key: bytes, nonce: bytes):
    if len(nonce) != 24:
        raise GoldenError("xchacha20poly1305: nonce must be 24 bytes")
    return hchacha20(bytes(key), bytes(nonce[:16])), b"\x00" * 4 + bytes(nonce[16:])


def xchacha20poly1305_seal(key: bytes, nonce: bytes, pt: bytes, aad: bytes = b"") -> bytes:
    sub, n12 = _xchacha(key, nonce)
    return chacha20poly1305_seal(sub, n12, pt, aad)


def xchacha20poly1305_open(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    sub, n12 = _xchacha(key, nonce)
    try:
        return chacha20poly1305_open(sub, n12, ct, aad)
    except GoldenError:
        raise GoldenError("xchacha20poly1305: authentication failed") from None


def aes_gcm_seal(key: bytes, nonce: bytes, pt: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(bytes(key)).encrypt(bytes(nonce), bytes(pt), bytes(aad))


def aes_gcm_open(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    try:
        return AESGCM(bytes(key)).decrypt(bytes(nonce), bytes(ct), bytes(aad))
    except InvalidTag:
        raise GoldenError("aes-gcm: authentication failed") from None


def argon2id(password: bytes, salt: bytes, t: int, m_kib: int, p: int, length: int,
             secret: bytes | None = None, ad: bytes | None = None) -> bytes:
    """Argon2id (RFC 9106): t passes, m_kib KiB of memory, p lanes."""
    kw = {}
    if secret:
        kw["secret"] = bytes(secret)
    if ad:
        kw["ad"] = bytes(ad)
    return Argon2id(salt=bytes(salt), length=length, iterations=t, lanes=p, memory_cost=m_kib, **kw).derive(bytes(password))


def nfc(s: str) -> str:
    """Unicode NFC (passphrases are normalized before argon2id)."""
    return unicodedata.normalize("NFC", s)


# ---------------------------------------------------------------------------------------------
# HPKE (RFC 9180): base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, any of the three AEADs
# or export only. anet's suite 1 is HPKESuite(0x0020, 0x0001, 0x0003).
# ---------------------------------------------------------------------------------------------

_AEADS = {  # id: (Nk, Nn, constructor)
    0x0001: (16, 12, AESGCM),
    0x0002: (32, 12, AESGCM),
    0x0003: (32, 12, ChaCha20Poly1305),
    0xFFFF: (0, 0, None),  # export only
}


class HPKEContext:
    """An HPKE encryption context (RFC 9180 §5.2): seal and open advance the sequence number."""

    def __init__(self, suite: "HPKESuite", key: bytes, base_nonce: bytes, exporter_secret: bytes):
        self.suite, self.key, self.base_nonce, self.exporter_secret, self.seq = suite, key, base_nonce, exporter_secret, 0

    def _nonce(self) -> bytes:
        nn = len(self.base_nonce)
        if self.seq >= 1 << (8 * nn):
            raise GoldenError("hpke: message limit reached")
        return bytes(a ^ b for a, b in zip(self.base_nonce, self.seq.to_bytes(nn, "big")))

    def _aead(self):
        ctor = _AEADS[self.suite.aead][2]
        if ctor is None:
            raise GoldenError("hpke: export-only context cannot seal or open")
        return ctor(self.key)

    def seal(self, aad: bytes, pt: bytes) -> bytes:
        ct = self._aead().encrypt(self._nonce(), bytes(pt), bytes(aad))
        self.seq += 1
        return ct

    def open(self, aad: bytes, ct: bytes) -> bytes:
        try:
            pt = self._aead().decrypt(self._nonce(), bytes(ct), bytes(aad))
        except InvalidTag:
            raise GoldenError("hpke: authentication failed") from None
        self.seq += 1
        return pt

    def export(self, exporter_context: bytes, length: int) -> bytes:
        """Secret export (RFC 9180 §5.3)."""
        return self.suite._labeled_expand(self.suite.suite_id, self.exporter_secret, b"sec", bytes(exporter_context), length)


class HPKESuite:
    def __init__(self, kem: int = 0x0020, kdf: int = 0x0001, aead: int = 0x0003):
        if kem != 0x0020 or kdf != 0x0001 or aead not in _AEADS:
            raise GoldenError("hpke: only DHKEM(X25519, HKDF-SHA256) with HKDF-SHA256 is written here")
        self.kem, self.kdf, self.aead = kem, kdf, aead
        self.kem_suite_id = b"KEM" + kem.to_bytes(2, "big")
        self.suite_id = b"HPKE" + kem.to_bytes(2, "big") + kdf.to_bytes(2, "big") + aead.to_bytes(2, "big")

    @staticmethod
    def _labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
        return hkdf_extract(salt, b"HPKE-v1" + suite_id + label + ikm)

    @staticmethod
    def _labeled_expand(suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
        return hkdf_expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite_id + label + info, length)

    def derive_key_pair(self, ikm: bytes):
        """DeriveKeyPair (RFC 9180 §7.1.3): (sk, pk) from ikm."""
        prk = self._labeled_extract(self.kem_suite_id, b"", b"dkp_prk", bytes(ikm))
        sk = self._labeled_expand(self.kem_suite_id, prk, b"sk", b"", 32)
        return sk, x25519_public(sk)

    def _shared_secret(self, dh: bytes, kem_context: bytes) -> bytes:
        prk = self._labeled_extract(self.kem_suite_id, b"", b"eae_prk", dh)
        return self._labeled_expand(self.kem_suite_id, prk, b"shared_secret", kem_context, 32)

    def _schedule(self, shared_secret: bytes, info: bytes) -> HPKEContext:
        psk_id_hash = self._labeled_extract(self.suite_id, b"", b"psk_id_hash", b"")
        info_hash = self._labeled_extract(self.suite_id, b"", b"info_hash", bytes(info))
        ks_context = b"\x00" + psk_id_hash + info_hash  # mode_base
        secret = self._labeled_extract(self.suite_id, shared_secret, b"secret", b"")
        nk, nn, _ = _AEADS[self.aead]
        key = self._labeled_expand(self.suite_id, secret, b"key", ks_context, nk)
        base_nonce = self._labeled_expand(self.suite_id, secret, b"base_nonce", ks_context, nn)
        exporter_secret = self._labeled_expand(self.suite_id, secret, b"exp", ks_context, 32)
        return HPKEContext(self, key, base_nonce, exporter_secret)

    def setup_base_s(self, pk_r: bytes, info: bytes, ikm_e: bytes):
        """SetupBaseS with the ephemeral key DeriveKeyPair(ikm_e): (enc, sender context)."""
        sk_e, pk_e = self.derive_key_pair(ikm_e)
        dh = x25519(sk_e, pk_r)
        return pk_e, self._schedule(self._shared_secret(dh, pk_e + bytes(pk_r)), info)

    def setup_base_r(self, enc: bytes, sk_r: bytes, info: bytes) -> HPKEContext:
        """SetupBaseR: the recipient context."""
        dh = x25519(sk_r, enc)
        return self._schedule(self._shared_secret(dh, bytes(enc) + x25519_public(sk_r)), info)


SUITE1 = HPKESuite(0x0020, 0x0001, 0x0003)  # anet suite 1 (seal layers 1 and 2, session key delivery)


# ---------------------------------------------------------------------------------------------
# Known-answer tests: every primitive above against published values before any vector is
# written. The CoreDet and CID rows also pin values the Go tests pin (golden/golden_test.go).
# ---------------------------------------------------------------------------------------------

def _h(s: str) -> bytes:
    return bytes.fromhex(s)


def _expect(name: str, got: bytes, want: bytes):
    if got != want:
        raise GoldenError("known-answer test %s failed: got %s, want %s" % (name, got.hex(), want.hex()))


# RFC 9180 test vectors, mode 0, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, for each AEAD, with the
# accumulated forms of 1000 encryptions and 1000 exports (a SHAKE128 stream of inputs, a SHAKE128
# digest of the outputs); aead 3 is Appendix A.2.1.
_HPKE_KATS = [
    dict(aead=0x0001, ikmE="7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
         ikmR="6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
         skRm="4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
         pkRm="3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
         enc="37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
         acc_enc="dcabb32ad8e8acea785275323395abd0", acc_exp="45db490fc51c86ba46cca1217f66a75e"),
    dict(aead=0x0002, ikmE="2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9",
         ikmR="dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee",
         skRm="497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d",
         pkRm="430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c",
         enc="6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256",
         acc_enc="1702e73e1e71705faa8241022af1deea", acc_exp="5cb678bf1c52afbd9afb58b8f7c1ced3"),
    dict(aead=0x0003, ikmE="909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
         ikmR="1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
         skRm="8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
         pkRm="4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
         enc="1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
         acc_enc="225fb3d35da3bb25e4371bcee4273502", acc_exp="54e2189c04100b583c84452f94eb9a4a"),
    dict(aead=0xFFFF, ikmE="55bc245ee4efda25d38f2d54d5bb6665291b99f8108a8c4b686c2b14893ea5d9",
         ikmR="683ae0da1d22181e74ed2e503ebf82840deb1d5e872cade20f4b458d99783e31",
         skRm="33d196c830a12f9ac65d6e565a590d80f04ee9b19c83c87f2c170d972a812848",
         pkRm="194141ca6c3c3beb4792cd97ba0ea1faff09d98435012345766ee33aae2d7664",
         enc="e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918",
         acc_enc=None, acc_exp="3fe376e3f9c349bc5eae67bbce867a16"),
]
_HPKE_INFO = _h("4f6465206f6e2061204772656369616e2055726e")  # "Ode on a Grecian Urn"


class _Draws:
    """Length-prefixed inputs drawn from one SHAKE128 stream (the accumulated test vectors)."""

    def __init__(self, n: int):
        self.buf, self.i = hashlib.shake_128(b"").digest(n), 0

    def draw(self) -> bytes:
        n = self.buf[self.i]
        out = self.buf[self.i + 1:self.i + 1 + n]
        if len(out) != n:
            raise GoldenError("known-answer test: SHAKE128 stream too short")
        self.i += 1 + n
        return out


def _kat_hpke():
    for v in _HPKE_KATS:
        s = HPKESuite(0x0020, 0x0001, v["aead"])
        name = "HPKE aead %04x" % v["aead"]
        sk, pk = s.derive_key_pair(_h(v["ikmR"]))
        _expect(name + " skRm", sk, _h(v["skRm"]))
        _expect(name + " pkRm", pk, _h(v["pkRm"]))
        enc, snd = s.setup_base_s(pk, _HPKE_INFO, _h(v["ikmE"]))
        _expect(name + " enc", enc, _h(v["enc"]))
        rcv = s.setup_base_r(enc, sk, _HPKE_INFO)
        if v["acc_enc"]:
            src, sink = _Draws(1000 * 2 * 256), hashlib.shake_128()
            for _ in range(1000):
                aad, pt = src.draw(), src.draw()
                ct = snd.seal(aad, pt)
                sink.update(ct)
                if rcv.open(aad, ct) != pt:
                    raise GoldenError("known-answer test %s: open does not invert seal" % name)
            _expect(name + " encryptions", sink.digest(16), _h(v["acc_enc"]))
        src, sink = _Draws(1000 * 256), hashlib.shake_128()
        for length in range(1000):
            ctx = src.draw()
            out = snd.export(ctx, length)
            sink.update(out)
            if rcv.export(ctx, length) != out:
                raise GoldenError("known-answer test %s: sender and recipient exports differ" % name)
        _expect(name + " exports", sink.digest(16), _h(v["acc_exp"]))
    # The same construction against the cryptography package's own HPKE, both ways: its
    # single-shot form is enc ‖ ct of the first message with an empty aad.
    try:
        from cryptography.hazmat.primitives import hpke
    except ImportError:
        raise GoldenError("the cryptography package %s has no HPKE to check against; "
                          "run: python3 -m pip install -r %s" % (cryptography.__version__, _REQUIREMENTS)) from None
    other = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
    sk_r, pk_r = SUITE1.derive_key_pair(sha256(b"anet-golden/v016/selftest/recipient"))
    info, pt = b"anet golden self-test", b"opened by another HPKE"
    enc, ctx = SUITE1.setup_base_s(pk_r, info, sha256(b"anet-golden/v016/selftest/ephemeral"))
    if other.decrypt(enc + ctx.seal(b"", pt), X25519PrivateKey.from_private_bytes(sk_r), info=info) != pt:
        raise GoldenError("known-answer test HPKE: the cryptography package does not open our envelope")
    theirs = other.encrypt(pt, X25519PublicKey.from_public_bytes(pk_r), info=info)
    if SUITE1.setup_base_r(theirs[:32], sk_r, info).open(b"", theirs[32:]) != pt:
        raise GoldenError("known-answer test HPKE: we do not open the cryptography package's envelope")


def _kat_primitives():
    # RFC 4231 test case 2; RFC 5869 test case 1 (and the package's own HKDF on the same input).
    _expect("HMAC-SHA256", hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
            _h("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"))
    ikm, salt, info = b"\x0b" * 22, _h("000102030405060708090a0b0c"), _h("f0f1f2f3f4f5f6f7f8f9")
    _expect("HKDF extract", hkdf_extract(salt, ikm), _h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"))
    okm = _h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    _expect("HKDF", hkdf(ikm, salt, info, 42), okm)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    _expect("HKDF (package)", HKDF(hashes.SHA256(), 42, salt, info).derive(ikm), okm)
    # RFC 8032 §7.1 test 1; and the frozen suite test key of package aobj (golden TestSuiteKey).
    sk = _h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    _expect("Ed25519 public", ed25519_public(sk), _h("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
    sig = ed25519_sign(sk, b"")
    _expect("Ed25519 signature", sig, _h("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"))
    if not ed25519_verify(ed25519_public(sk), b"", sig) or ed25519_verify(ed25519_public(sk), b"x", sig):
        raise GoldenError("known-answer test Ed25519: verify")
    suite_seed = sha256(b"anet-suite-test-key-v1")
    _expect("aobj suite seed", suite_seed, _h("4700ce56fd7bd46d6523e5c2360f22151120678c42b0b18b2fe215f3d1b9d170"))
    _expect("aobj suite key", ed25519_public(suite_seed), _h("ae5ec9a111f7af2b7981b4d5afc401ce41dac0c3ce1b70429b2b85ba071e802e"))
    # RFC 7748 §6.1.
    a, b = _h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), _h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    _expect("X25519 public", x25519_public(a), _h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    _expect("X25519", x25519(a, x25519_public(b)), _h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))
    # RFC 8439 §2.8.2.
    key, nonce, aad = _h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"), _h("070000004041424344454647"), _h("50515253c0c1c2c3c4c5c6c7")
    pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    ct = _h("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
            "1ae10b594f09e26a7e902ecbd0600691")
    _expect("ChaCha20-Poly1305", chacha20poly1305_seal(key, nonce, pt, aad), ct)
    _expect("ChaCha20-Poly1305 open", chacha20poly1305_open(key, nonce, ct, aad), pt)
    # draft-irtf-cfrg-xchacha-03 §2.2.1 (HChaCha20) and §A.3.1 (XChaCha20-Poly1305).
    _expect("HChaCha20", hchacha20(bytes(range(32)), _h("000000090000004a0000000031415927")),
            _h("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"))
    xn = _h("404142434445464748494a4b4c4d4e4f5051525354555657")
    xct = _h("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49")
    _expect("XChaCha20-Poly1305", xchacha20poly1305_seal(key, xn, pt, aad), xct)
    _expect("XChaCha20-Poly1305 open", xchacha20poly1305_open(key, xn, xct, aad), pt)
    try:
        xchacha20poly1305_open(key, xn, xct[:-1] + bytes([xct[-1] ^ 1]), aad)
        raise GoldenError("known-answer test XChaCha20-Poly1305: a changed tag opened")
    except GoldenError as e:
        if "authentication failed" not in str(e):
            raise
    # AES-256-GCM: test cases 13 and 14 of the GCM specification (McGrew and Viega).
    _expect("AES-256-GCM empty", aes_gcm_seal(b"\x00" * 32, b"\x00" * 12, b""), _h("530f8afbc74536b9a963b4f1c4cb738b"))
    _expect("AES-256-GCM", aes_gcm_seal(b"\x00" * 32, b"\x00" * 12, b"\x00" * 16),
            _h("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"))
    # RFC 9106 §5.3 (with secret and associated data); a reference-CLI vector without them.
    _expect("argon2id RFC 9106", argon2id(b"\x01" * 32, b"\x02" * 16, 3, 32, 4, 32, secret=b"\x03" * 8, ad=b"\x04" * 12),
            _h("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"))
    _expect("argon2id reference", argon2id(b"password", b"somesalt", 2, 64, 2, 24), _h("350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362"))


def _kat_coredet():
    # RFC 8949 Appendix A, the items whose preferred encoding is also deterministic.
    rows = [
        (0, "00"), (23, "17"), (24, "1818"), (100, "1864"), (1000, "1903e8"), (1000000, "1a000f4240"),
        (1000000000000, "1b000000e8d4a51000"), (18446744073709551615, "1bffffffffffffffff"),
        (-1, "20"), (-10, "29"), (-100, "3863"), (-1000, "3903e7"), (-18446744073709551616, "3bffffffffffffffff"),
        (0.0, "f90000"), (-0.0, "f98000"), (1.0, "f93c00"), (1.1, "fb3ff199999999999a"), (1.5, "f93e00"),
        (65504.0, "f97bff"), (100000.0, "fa47c35000"), (3.4028234663852886e+38, "fa7f7fffff"), (1.0e+300, "fb7e37e43c8800759c"),
        (5.960464477539063e-8, "f90001"), (0.00006103515625, "f90400"), (-4.0, "f9c400"), (-4.1, "fbc010666666666666"),
        (False, "f4"), (True, "f5"), (None, "f6"), (b"", "40"), (_h("01020304"), "4401020304"),
        ("", "60"), ("a", "6161"), ("IETF", "6449455446"), ("\"\\", "62225c"), ("ü", "62c3bc"), ("水", "63e6b0b4"),
        ("\U00010151", "64f0908591"), ([], "80"), ([1, 2, 3], "83010203"), ([1, [2, 3], [4, 5]], "8301820203820405"),
        (list(range(1, 26)), "98190102030405060708090a0b0c0d0e0f101112131415161718181819"),
        ({}, "a0"), ({1: 2, 3: 4}, "a201020304"), ({"a": 1, "b": [2, 3]}, "a26161016162820203"),
        (["a", {"b": "c"}], "826161a161626163"),
        ({"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}, "a56161614161626142616361436164614461656145"),
        # §4.2.1: keys sort by their encoded bytes, so 10 < 100 < -1 < "z" < "aa" (not by length first).
        ({"aa": 3, "z": 4, -1: 5, 100: 6, 10: 7}, "a50a071864062005617a0462616103"),
    ]
    for v, want in rows:
        _expect("CoreDet %r" % (v,), cbor(v), _h(want))
        back = uncbor(_h(want))
        if back != v or (isinstance(v, float) and math.copysign(1, back) != math.copysign(1, v)):
            raise GoldenError("known-answer test CoreDet: %s decodes to %r, want %r" % (want, back, v))
    # The Go side's frozen preimages and CIDs (golden/golden_test.go).
    aet = {1: {1: 1}, 4: [{1: "s1", 3: "do x"}]}
    _expect("VEC_AET_CID_1 preimage", cbor(aet), _h("a201a101010481a2016273310364646f2078"))
    if cid(cbor(aet)) != "bafyreibgtk5ei4nbd2vho4ty7ws3z3ovqq243iu2pcjixu7bgdvqz67wdm":
        raise GoldenError("known-answer test VEC_AET_CID_1: CID")
    tsir = {1: {1: 1}, 4: [{1: "t1", 10: {3: "do x"}}]}
    _expect("VEC_TSIR_CID_1 preimage", cbor(tsir), _h("a201a101010481a2016274310aa10364646f2078"))
    if cid(cbor(tsir)) != "bafyreif46dhnfcecy7fapphwd5y5fqht3c454h24haarppz6g2ez44qafq":
        raise GoldenError("known-answer test VEC_TSIR_CID_1: CID")
    if cid_raw(b"anet-attachment-vector-1") != "bafkreif2oxdrzwsd6eevltslywywuu3o4sgj2vkyvhkfjqyj2vycd3sbqm":
        raise GoldenError("known-answer test VEC_CID_RAW_1: CID")


def selftest():
    """Runs every known-answer test; raises GoldenError on the first that fails."""
    _kat_coredet()
    _kat_primitives()
    _kat_hpke()


# ---------------------------------------------------------------------------------------------
# The vector framework
# ---------------------------------------------------------------------------------------------

def seed(vector_id: str, role: str) -> bytes:
    """A published seed: SHA-256("anet-golden/v016/<vector id>/<role>")."""
    return sha256(("anet-golden/v016/%s/%s" % (vector_id, role)).encode("utf-8"))


def b16(b: bytes) -> str:
    """Bytes as lower-case hex, the form every vector file uses."""
    return bytes(b).hex()


def flip(b: bytes, i: int = -1) -> bytes:
    """b with the lowest bit of byte i changed: the "one byte changed" negative (CORE-G4)."""
    out = bytearray(b)
    out[i] ^= 1
    return bytes(out)


def drop_key(m: bytes, key) -> bytes:
    """The CoreDet map m without one key: the "required key missing" negative (CORE-G4)."""
    d = uncbor(m)
    if not isinstance(d, dict) or key not in d:
        raise GoldenError("drop_key: %r is not a key of the map" % (key,))
    del d[key]
    return cbor(d)


def add_key(m: bytes, key, value=None) -> bytes:
    """The CoreDet map m with one more key: the "unregistered key added" negative (CORE-G4). The
    value defaults to null, which every field type accepts, so a decoder that refuses the result
    refuses it for the key and not for the value."""
    d = uncbor(m)
    if not isinstance(d, dict) or key in d:
        raise GoldenError("add_key: the map already has %r" % (key,))
    d[key] = value
    return cbor(d)


class Generator:
    def __init__(self, vid: str, paths: tuple, fn):
        self.id, self.paths, self.fn = vid, paths, fn


GENERATORS: dict[str, Generator] = {}


def vector(vid: str, *paths: str):
    """Registers fn as the generator of vector vid, whose files are paths ("<repository>/<path>")."""
    if not paths:
        raise GoldenError("vector %s: no file" % vid)
    for p in paths:
        if p.split("/", 1)[0] not in REPOS or "/" not in p or ".." in p.split("/") or p.endswith("/"):
            raise GoldenError("vector %s: path %r is not <repository>/<file>" % (vid, p))

    def register(fn):
        if vid in GENERATORS:
            raise GoldenError("vector %s registered twice" % vid)
        GENERATORS[vid] = Generator(vid, tuple(paths), fn)
        return fn
    return register


def serialize(content) -> bytes:
    if isinstance(content, (dict, list)):
        return (json.dumps(content, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    if isinstance(content, str):
        return content.encode("utf-8")
    raise GoldenError("a generator returned %s (want dict, list, bytes or str)" % type(content).__name__)


def render(g: Generator) -> dict[str, bytes]:
    """Runs a generator: path → bytes."""
    out = g.fn()
    if len(g.paths) == 1:
        return {g.paths[0]: serialize(out)}
    if not isinstance(out, dict) or set(out) != set(g.paths):
        raise GoldenError("vector %s: the generator must return a dict with exactly its paths %s" % (g.id, list(g.paths)))
    return {p: serialize(out[p]) for p in g.paths}


def _module_of(d: Path) -> str:
    """The module path a go.mod declares, or "" (the same test golden/index_test.go applies)."""
    try:
        text = (d / "go.mod").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("module "):
            return line[len("module "):].strip().strip('"')
    return ""


class Workspace:
    """Where the repositories are: ANetCore is the checkout this script is in (or core); each
    other repository is root/<name> or root/Refs/<name>, whichever declares its module."""

    def __init__(self, root: Path | None = None, core: Path | None = None):
        self.core = (core or CORE_DIR).resolve()
        self.root = (root or self.core.parent).resolve()

    def repo(self, name: str) -> Path | None:
        if name == "ANetCore":
            return self.core
        for d in (self.root / name, self.root / "Refs" / name):
            if _module_of(d) == "github.com/ANetResearch/" + name:
                return d
        return None

    def file(self, path: str) -> Path | None:
        repo, rel = path.split("/", 1)
        base = self.repo(repo)
        return None if base is None else base / rel


def load_index(ws: Workspace) -> dict:
    p = ws.core / INDEX_PATH
    try:
        ix = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise GoldenError("%s cannot be read (%s)" % (INDEX_PATH, e)) from None
    if ix.get("format") != "anet-golden-index/1" or not isinstance(ix.get("vectors"), list):
        raise GoldenError("%s is not an anet-golden-index/1 file" % INDEX_PATH)
    return ix


def index_files(entry: dict) -> list[tuple[str, dict]]:
    """The file artifacts of an index row as ("<repository>/<path>", artifact)."""
    return [("%s/%s" % (a["repo"], a["path"]), a) for a in entry.get("at", []) if not a.get("test") and not a["path"].endswith("/")]


def _where(e: BaseException) -> str:
    """The exception's type and the line of this script it was raised from."""
    frames = [f for f in traceback.extract_tb(e.__traceback__) if Path(f.filename).resolve() == Path(__file__).resolve()]
    at = (" at line %d (%s)" % (frames[-1].lineno, frames[-1].name)) if frames else ""
    return type(e).__name__ + at


def _first_difference(want: bytes, got: bytes) -> str:
    n = next((i for i, (x, y) in enumerate(zip(want, got)) if x != y), min(len(want), len(got)))
    line = got[:n].count(b"\n") + 1
    return "first difference at byte %d (line %d): the file has %s, the generator writes %s" % (
        n, line, got[n:n + 12].hex() or "(end)", want[n:n + 12].hex() or "(end)")


def check(ws: Workspace, generators: dict[str, Generator] | None = None, index: dict | None = None,
          all_repos: bool = False):
    """golden-xcheck: returns (problems, notes). Each problem is one sentence that says what is
    wrong and what to do."""
    gens = GENERATORS if generators is None else generators
    ix = load_index(ws) if index is None else index
    problems, notes = [], []
    rows = {v["id"]: v for v in ix["vectors"]}

    def absent_repo(path: str, vid: str) -> bool:
        repo = path.split("/", 1)[0]
        if ws.repo(repo) is not None:
            return False
        msg = "%s: %s is not checked because repository %s is not next to ANetCore" % (vid, path, repo)
        (problems if all_repos else notes).append(msg + (" (--all-repos)" if all_repos else ""))
        return True

    for vid, g in sorted(gens.items()):
        row = rows.get(vid)
        if row is None:
            problems.append("%s: has a generator but no row in %s; add the row (files, labels, objects, gen)" % (vid, INDEX_PATH))
            continue
        if row.get("gen") not in PY_GENS:
            problems.append("%s: %s says gen %r, but gen_v016.py writes it; set gen to one of %s" % (vid, INDEX_PATH, row.get("gen"), ", ".join(PY_GENS)))
        want_paths = sorted(p for p, _ in index_files(row))
        if sorted(g.paths) != want_paths:
            problems.append("%s: the generator writes %s but the index lists %s; make them the same" % (vid, sorted(g.paths), want_paths))
            continue
        try:
            outputs = render(g)
        except GoldenError as e:
            problems.append("%s: the generator failed: %s" % (vid, e))
            continue
        except Exception as e:  # a bug in one generator must not hide the others' results
            problems.append("%s: the generator raised %s; fix it there: %s" % (vid, _where(e), e))
            continue
        for path, want in outputs.items():
            if absent_repo(path, vid):
                continue
            f = ws.file(path)
            try:
                got = f.read_bytes()
            except FileNotFoundError:
                problems.append("%s: %s does not exist; write it with: gen_v016.py write %s" % (vid, path, vid))
                continue
            if got != want:
                problems.append("%s: %s differs from what gen_v016.py writes: %s; if the generator is right and the "
                                "change is intended, it is a wire change (CORE-F2)" % (vid, path, _first_difference(want, got)))
    for vid, row in rows.items():
        if row.get("gen") not in PY_GENS or vid in gens:
            continue
        files = index_files(row)
        present = [p for p, _ in files if ws.repo(p.split("/", 1)[0]) is not None and ws.file(p).exists()]
        if present:
            problems.append("%s: %s exists but gen_v016.py has no generator for it, so nothing reproduces it "
                            "independently; register one with @vector(%r, ...)" % (vid, ", ".join(present), vid))
        elif all(a.get("todo") for _, a in files):
            notes.append("%s: not delivered yet (%s)" % (vid, ", ".join(sorted({a["todo"] for _, a in files}))))
    return problems, notes


def write(ws: Workspace, ids: list[str], generators: dict[str, Generator] | None = None) -> list[str]:
    gens = GENERATORS if generators is None else generators
    written = []
    for vid in ids:
        g = gens.get(vid)
        if g is None:
            raise GoldenError("no generator for %s; registered: %s" % (vid, ", ".join(sorted(gens)) or "none"))
        for path, data in render(g).items():
            f = ws.file(path)
            if f is None:
                raise GoldenError("%s: repository %s is not next to ANetCore; nothing written" % (vid, path.split("/", 1)[0]))
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
            written.append(path)
    return written


# ---------------------------------------------------------------------------------------------
# Vectors. One section per area, in the order of golden/testdata/index.json; each generator is
# registered under the id of the index row it produces.
# ---------------------------------------------------------------------------------------------

# --- RFC 9180 (the HPKE instantiation of seal suite 1) -----------------------------------------

_RFC9180_A21 = dict(
    ikmE="909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
    ikmR="1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
    info="4f6465206f6e2061204772656369616e2055726e",
    encryptions=[(0, "436f756e742d30", "4265617574792069732074727574682c20747275746820626561757479")],
)


@vector("rfc9180", "ANetCore/seal/testdata/rfc9180-a2-1.json")
def gen_rfc9180():
    """RFC 9180 Appendix A.2.1, regenerated from the RFC's inputs (ikmE, ikmR, info, aad, pt):
    the public key, enc and every ciphertext are computed here and must equal the RFC's."""
    v = _RFC9180_A21
    sk, pk = SUITE1.derive_key_pair(_h(v["ikmR"]))
    enc, ctx = SUITE1.setup_base_s(pk, _h(v["info"]), _h(v["ikmE"]))
    encryptions = []
    for seq, aad, pt in v["encryptions"]:
        while ctx.seq < seq:
            ctx.seal(b"", b"")
        encryptions.append({"seq": seq, "aad": aad, "ct": b16(ctx.seal(_h(aad), _h(pt))), "pt": pt})
    return {
        "source": "RFC 9180 Appendix A.2.1, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, Base setup "
                  "(mode 0). pkRm and enc also match crypto/hpke/testdata/rfc9180.json of Go 1.26.",
        "mode": 0,
        "kem_id": SUITE1.kem,
        "kdf_id": SUITE1.kdf,
        "aead_id": SUITE1.aead,
        "info": v["info"],
        "ikmR": v["ikmR"],
        "pkRm": b16(pk),
        "enc": b16(enc),
        "encryptions": encryptions,
    }


# --- KEL (KEL-1): KEL-2A, KEL-2B ---------------------------------------------------------------
#
# KeyEvent (core §2.6): 0 t_obj "anet.kel/2", 1 aid (not in the icp), 2 seq, 3 prev (not in the
# icp), 4 t, 5 keys, 6 next (icp and rot), 7 kt = 1, 8 ts, 9 witnesses (a toad-1 rot), 11 toad
# (icp and rot, written even when 0), 12 emergency (a rot, only true). SignedEvent: 1 event, 2 sig,
# 3 event_id. The icp is signed by k0, a rot or a dip by the key it reveals (L17). AID = CID of the
# icp preimage. Key seeds: seed(<vector id>, "k0".."k3").

KEL_TYPE = "anet.kel/2"
KEL_MINUTE = 60 * 1000
KEL_HUB_T0 = 1760000000000
KEL_HUB_DIP_TS = KEL_HUB_T0 + 10 * KEL_MINUTE  # the KEL-2B agent's whole KEL lies between the hub's icp and dip
KEL_AGENT_T0 = 1760000180000

KEL_ABOUT_2A = ("KEL v2 hub identity (toad 0): icp, rot 1 (setup-recovery), rot 2 (emergency), dip 3. "
                "Key seeds are SHA-256 of the labels. The icp is signed by k0, every rot and dip by the key it reveals. "
                "preimage is coredet(KeyEvent) (L17), event_id its CID, kel is MarshalKEL.")
KEL_ABOUT_2B = ("KEL v2 agent identity (toad 1): icp (witness pending), rot 1 (designates W1), rot 2 (moves to W2), dip 3. "
                "W1 is the hub incepted from the labels given, W2 the KEL-2A hub. "
                "Key seeds are SHA-256 of the labels. The icp is signed by k0, every rot and dip by the key it reveals. "
                "preimage is coredet(KeyEvent) (L17), event_id its CID, kel is MarshalKEL.")


class KelLog:
    """A KEL being written: each event as a map, with its preimage, id and signature."""

    def __init__(self):
        self.events = []  # (event map, preimage, event_id, signature)

    @property
    def aid(self) -> str:
        return self.events[0][2]

    def add(self, event: dict, signer_seed: bytes) -> "KelLog":
        if self.events:
            event[1] = self.aid
            event[2] = len(self.events)
            event[3] = self.events[-1][2]
        pre = cbor(event)
        self.events.append((event, pre, cid(pre), ed25519_sign(signer_seed, pre)))
        return self

    def wire(self) -> bytes:
        return cbor([{1: e, 2: sig, 3: eid} for e, _, eid, sig in self.events])


def kel_icp(k0: bytes, k1: bytes, ts: int, toad: int) -> dict:
    return {0: KEL_TYPE, 2: 0, 4: "icp", 5: [ed25519_public(k0)], 6: sha256(ed25519_public(k1)), 7: 1, 8: ts, 11: toad}


def kel_rot(rev: bytes, nxt: bytes, ts: int, toad: int, witness=None, emergency=False) -> dict:
    e = {0: KEL_TYPE, 4: "rot", 5: [ed25519_public(rev)], 6: sha256(ed25519_public(nxt)), 7: 1, 8: ts, 11: toad}
    if witness is not None:
        e[9] = [witness]
    if emergency:
        e[12] = True
    return e


def kel_dip(rev: bytes, ts: int) -> dict:
    return {0: KEL_TYPE, 4: "dip", 5: [ed25519_public(rev)], 7: 1, 8: ts}


def kel_keys(vid: str) -> list:
    return [seed(vid, "k%d" % i) for i in range(4)]


def kel_2a() -> KelLog:
    k = kel_keys("KEL-2A")
    kel = KelLog().add(kel_icp(k[0], k[1], KEL_HUB_T0, 0), k[0])
    kel.add(kel_rot(k[1], k[2], KEL_HUB_T0 + KEL_MINUTE, 0), k[1])
    kel.add(kel_rot(k[2], k[3], KEL_HUB_T0 + 2 * KEL_MINUTE, 0, emergency=True), k[2])
    kel.add(kel_dip(k[3], KEL_HUB_DIP_TS), k[3])
    return kel


def kel_w1() -> KelLog:
    k0, k1 = seed("KEL-2B", "w1-k0"), seed("KEL-2B", "w1-k1")
    return KelLog().add(kel_icp(k0, k1, KEL_HUB_T0, 0), k0)


def kel_2b() -> KelLog:
    k = kel_keys("KEL-2B")
    w1, w2 = kel_w1().aid, kel_2a().aid
    kel = KelLog().add(kel_icp(k[0], k[1], KEL_AGENT_T0, 1), k[0])
    kel.add(kel_rot(k[1], k[2], KEL_AGENT_T0 + KEL_MINUTE, 1, witness=w1), k[1])
    kel.add(kel_rot(k[2], k[3], KEL_AGENT_T0 + 2 * KEL_MINUTE, 1, witness=w2), k[2])
    kel.add(kel_dip(k[3], KEL_AGENT_T0 + 3 * KEL_MINUTE), k[3])
    return kel


def kel_states(kel: KelLog, names: dict) -> list:
    """The key states the KEL v2 replay rules give each event (KEL §2.2), from the event maps."""
    states = []
    toad, witness = None, ""
    for i, (e, _, _, _) in enumerate(kel.events):
        if e[4] in ("icp", "rot"):
            toad = e[11]
            witness = e[9][0] if 9 in e else witness
            key, status = names[e[5][0]], "active"
        else:
            key, status = "", "deactivated"
        states.append({"seq": i, "status": status, "key": key, "toad": toad, "witness": witness,
                       "superseded_at": 0, "retired_urgently": False})
    for i in range(len(states) - 1):
        nxt = kel.events[i + 1][0]
        states[i]["status"] = "rotated"
        states[i]["superseded_at"] = nxt[8]
        states[i]["retired_urgently"] = nxt[4] == "dip" or nxt.get(12, False)
    return states


def kel_vector(vid: str, about: str, kel: KelLog, witnesses: list) -> dict:
    names, keys = {}, []
    for i, k in enumerate(kel_keys(vid)):
        pub = ed25519_public(k)
        names[pub] = "k%d" % i
        keys.append({"name": "k%d" % i, "label": "anet-golden/v016/%s/k%d" % (vid, i), "pub": b16(pub)})
    return {
        "id": vid,
        "about": about,
        "keys": keys,
        "witnesses": witnesses,
        "aid": kel.aid,
        "events": [{"seq": i, "t": e[4], "signer": names[e[5][0]], "preimage": b16(pre), "event_id": eid,
                    "sig": b16(sig)} for i, (e, pre, eid, sig) in enumerate(kel.events)],
        "kel": b16(kel.wire()),
        "states": kel_states(kel, names),
    }


@vector("KEL-2A", "ANetCore/identity/testdata/vec-kel-2a.json")
def gen_kel_2a():
    return kel_vector("KEL-2A", KEL_ABOUT_2A, kel_2a(), [])


@vector("KEL-2B", "ANetCore/identity/testdata/vec-kel-2b.json")
def gen_kel_2b():
    w1, a = kel_w1(), kel_2a()
    return kel_vector("KEL-2B", KEL_ABOUT_2B, kel_2b(), [
        {"name": "W1", "aid": w1.aid, "labels": ["anet-golden/v016/KEL-2B/w1-k0", "anet-golden/v016/KEL-2B/w1-k1"],
         "kel": b16(w1.wire())},
        {"name": "W2", "aid": a.aid, "labels": [], "kel": b16(a.wire())},
    ])


# --- SS: relayauth (RELAYAUTH-3 pins), the first-contact session (SESSION-1), the directory box (DIR-1)

SS_AGENT_AID = "bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay"
SS_OTHER_AID = "bafyreigoldenrecipient"
SS_HUB_AID = "bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y"
SS_OTHER_HUB_AID = "bafyreianotherhub"
SS_TS = 1767225600000

SESS_KEY_LABEL = b"anet-sess-key/v1"
SESS_MAC_LABEL = b"anet-sess-mac/v1"
DIR_HASH_LABEL = b"anet-dir-hash/v1"
DIR_BOX_LABEL = b"anet-dir-box/v1"


def _no_nul(*fields: str):
    """CORE-E9: a 0x00-separated text field must not hold U+0000."""
    for f in fields:
        if "\x00" in f:
            raise GoldenError("a 0x00-separated field holds U+0000: %r" % f)


def session_key_info(hub_aid: str, sid: bytes) -> bytes:
    """L7: the HPKE info of a session key delivery."""
    _no_nul(hub_aid)
    if not hub_aid or len(sid) != 16:
        raise GoldenError("session key info: empty hub AID or a session id that is not 16 bytes")
    return SESS_KEY_LABEL + b"\x00" + hub_aid.encode("utf-8") + b"\x00" + bytes(sid)


def session_mac_input(sid: bytes, ts: int, method: str, target: str, home: str, body: bytes) -> bytes:
    """L8: the HMAC message of a session MAC."""
    _no_nul(method, target, home)
    if len(sid) != 16:
        raise GoldenError("session MAC: a session id that is not 16 bytes")
    return (SESS_MAC_LABEL + b"\x00" + bytes(sid) + b"\x00" + str(ts).encode("ascii") + b"\x00"
            + method.encode("utf-8") + b"\x00" + target.encode("utf-8") + b"\x00" + home.encode("utf-8")
            + b"\x00" + sha256(body))


def session_mac(k: bytes, sid: bytes, ts: int, method: str, target: str, home: str, body: bytes) -> bytes:
    return hmac_sha256(k, session_mac_input(sid, ts, method, target, home, body))


@vector("SESSION-1", "ANetCore/relayauth/testdata/vec-session-1.json")
def gen_session_1():
    """L7 (receiving side: Go opens enc and ct with the recorded skR) and L8 (the MAC input and
    output); the refused variants say which error each must give."""
    vid = "SESSION-1"
    sid = seed(vid, "sid")[:16]
    k = seed(vid, "k_sess")
    ikm_r = seed(vid, "epk")
    ikm_e = seed(vid, "hpke-ephemeral")
    sk_r, epk = SUITE1.derive_key_pair(ikm_r)
    info = session_key_info(SS_HUB_AID, sid)
    enc, sender = SUITE1.setup_base_s(epk, info, ikm_e)
    ct = sender.seal(b"", k)
    if SUITE1.setup_base_r(enc, sk_r, info).open(b"", ct) != k:
        raise GoldenError("SESSION-1: the session key does not open")

    def refused_key(name, error, hub_aid=SS_HUB_AID, sid_=sid, enc_=enc, ct_=ct):
        return {"name": name, "hub_aid": hub_aid, "sid": b16(sid_), "enc": b16(enc_), "ct": b16(ct_), "error": error}

    other_sid = seed(vid, "other-sid")[:16]
    key_refused = [
        refused_key("sealed by another hub", "session-key", hub_aid=SS_OTHER_HUB_AID),
        refused_key("sealed for another session id", "session-key", sid_=other_sid),
        refused_key("ct with one byte changed", "session-key", ct_=flip(ct, 5)),
        refused_key("enc with one byte changed", "session-key", enc_=flip(enc, 7)),
        refused_key("ct one byte short", "session-key", ct_=ct[:-1]),
        refused_key("hub AID holding U+0000", "nul", hub_aid=SS_HUB_AID[:8] + "\x00" + SS_HUB_AID[8:]),
        refused_key("session id one byte short", "input", sid_=sid[:15]),
    ]
    # Each refused delivery must really fail to open here too, or the vector proves nothing.
    for r in key_refused:
        try:
            got = SUITE1.setup_base_r(_h(r["enc"]), sk_r, session_key_info(r["hub_aid"], _h(r["sid"]))).open(b"", _h(r["ct"]))
        except GoldenError:
            continue
        raise GoldenError("SESSION-1: refused delivery %r opens to %s" % (r["name"], b16(got)))

    body = b"\xa6" + seed(vid, "envelope") * 3  # stands for the envelope bytes of a send
    cases = [
        ("send with a home hint", SS_TS, "POST", "/relay/send", SS_OTHER_HUB_AID, body),
        ("send without a home hint", SS_TS + 1, "POST", "/relay/send", "", body),
        ("empty body and a query", 7, "POST", "/relay/send?x=%2F1", "", b""),
    ]
    mac = []
    for name, ts, method, target, home, b in cases:
        mac.append({"name": name, "k_sess": b16(k), "sid": b16(sid), "ts": ts, "method": method,
                    "path_and_query": target, "home": home, "body": b16(b),
                    "input": b16(session_mac_input(sid, ts, method, target, home, b)),
                    "mac": b16(session_mac(k, sid, ts, method, target, home, b))})

    base = mac[0]
    other_k = seed(vid, "other-k_sess")

    def refused_mac(name, error, **over):
        m = {key: base[key] for key in ("k_sess", "sid", "ts", "method", "path_and_query", "home", "body")}
        m.update(over)
        m["mac"] = base["mac"]
        return {"name": name, **m, "error": error}

    mac_refused = [
        refused_mac("body changed by one byte", "mac", body=b16(flip(body, 40))),
        refused_mac("body one byte longer", "mac", body=b16(body + b"\x00")),
        refused_mac("home hint changed", "mac", home=SS_HUB_AID),
        refused_mac("home hint removed", "mac", home=""),
        refused_mac("ts changed", "mac", ts=SS_TS + 1),
        refused_mac("request target changed", "mac", path_and_query="/relay/send?"),
        refused_mac("method changed", "mac", method="PUT"),
        refused_mac("another session id", "mac", sid=b16(other_sid)),
        refused_mac("another session key", "mac", k_sess=b16(other_k)),
        refused_mac("byte moved from target to method", "mac", method="POST/", path_and_query="relay/send"),
        refused_mac("method holding U+0000", "nul", method="PO\x00ST"),
        refused_mac("request target holding U+0000", "nul", path_and_query="/relay/send\x00"),
        refused_mac("home hint holding U+0000", "nul", home=SS_OTHER_HUB_AID + "\x00"),
    ]
    # The refused cases must really differ from the base, or the vector proves nothing.
    for r in mac_refused:
        if r["error"] == "mac":
            got = session_mac(_h(r["k_sess"]), _h(r["sid"]), r["ts"], r["method"], r["path_and_query"], r["home"],
                              _h(r["body"]))
            if b16(got) == base["mac"]:
                raise GoldenError("SESSION-1: refused MAC case %r has the base MAC" % r["name"])

    return {
        "id": vid,
        "about": ("First-contact session: L7 session key delivery (receiving side: open enc and ct with skR) "
                  "and L8 session MAC (input and output). Seeds: SHA-256(\"anet-golden/v016/SESSION-1/<role>\") for "
                  "roles sid (first 16 bytes), k_sess, epk (ikm of the daemon's one-time key), hpke-ephemeral "
                  "(ikm of the hub's HPKE ephemeral key), envelope, other-sid, other-k_sess. "
                  "Generated by golden/py/gen_v016.py."),
        "key_delivery": {"hub_aid": SS_HUB_AID, "sid": b16(sid), "k_sess": b16(k), "ikmR": b16(ikm_r),
                         "skR": b16(sk_r), "epk": b16(epk), "ikmE": b16(ikm_e), "info": b16(info),
                         "enc": b16(enc), "ct": b16(ct)},
        "key_delivery_refused": key_refused,
        "mac": mac,
        "mac_refused": mac_refused,
    }


def dir_hash(aid: str) -> bytes:
    """L9: h = SHA-256("anet-dir-hash/v1" || 0x00 || UTF-8(aid))."""
    _no_nul(aid)
    return sha256(DIR_HASH_LABEL + b"\x00" + aid.encode("utf-8"))


def dir_key(aid: str) -> bytes:
    """L10: K = HKDF-SHA256(ikm = UTF-8(aid), salt = empty, info = "anet-dir-box/v1", L = 32)."""
    return hkdf(aid.encode("utf-8"), b"", DIR_BOX_LABEL, 32)


def dir_box(aid: str, pt: bytes, nonce: bytes, aad: bytes | None = None) -> bytes:
    """L10: box = nonce || ChaCha20-Poly1305(K, nonce, aad = h, pt); aad overrides h for a negative."""
    return nonce + chacha20poly1305_seal(dir_key(aid), nonce, pt, dir_hash(aid) if aad is None else aad)


def _cbor_map_in_order(pairs) -> bytes:
    """A map written in the order given: only to make a non-canonical negative."""
    return _head(5, len(pairs)) + b"".join(cbor(k) + cbor(x) for k, x in pairs)


def _dir_entry_map(e: dict) -> dict:
    m = {1: e["aid"], 2: e["home"], 3: e["kel"], 4: e["keys"]}
    if "card" in e:
        m[5] = e["card"]
    if "notice" in e:
        m[6] = e["notice"]
    return m


def _dir_entry_json(e: dict) -> dict:
    out = {"aid": e["aid"], "home": e["home"], "kel": b16(e["kel"]), "keys": b16(e["keys"])}
    for k in ("card", "notice"):
        if k in e:
            out[k] = b16(e[k])
    return out


@vector("DIR-1", "ANetCore/dirbox/testdata/vec-dir-1.json")
def gen_dir_1():
    """L9 h and L10 K; the box of a full and a minimal DirEntry under fixed nonces, which Go
    reproduces and opens; boxes that must not open or must not decode; AIDs Hash must refuse."""
    vid = "DIR-1"
    full = {"aid": SS_AGENT_AID, "home": SS_HUB_AID,
            "kel": seed(vid, "kel") + seed(vid, "kel-2"),
            "keys": seed(vid, "keys") * 2,
            "card": b'{"name":"golden agent","version":"1.0.0"}',
            "notice": seed(vid, "notice")}
    minimal = {"aid": SS_OTHER_AID, "home": SS_OTHER_HUB_AID, "kel": seed(vid, "kel-min"),
               "keys": seed(vid, "keys-min")}
    cases = []
    for name, e, role in (("full entry", full, "nonce-full"), ("required keys only", minimal, "nonce-min")):
        pt = cbor(_dir_entry_map(e))
        nonce = seed(vid, role)[:12]
        box = dir_box(e["aid"], pt, nonce)
        if chacha20poly1305_open(dir_key(e["aid"]), box[:12], box[12:], dir_hash(e["aid"])) != pt:
            raise GoldenError("DIR-1: the box of %r does not open" % name)
        cases.append({"name": name, "aid": e["aid"], "entry": _dir_entry_json(e), "plaintext": b16(pt),
                      "h": b16(dir_hash(e["aid"])), "k": b16(dir_key(e["aid"])), "nonce": b16(nonce),
                      "box": b16(box)})

    a = full["aid"]
    box_a = _h(cases[0]["box"])
    nonce = seed(vid, "nonce-refused")[:12]

    def sealed(pairs_or_map, in_order=False):
        pt = _cbor_map_in_order(pairs_or_map) if in_order else cbor(pairs_or_map)
        return b16(dir_box(a, pt, nonce))

    base = _dir_entry_map(full)
    with7 = dict(base)
    with7[7] = b"\x01"
    without4 = {k: v for k, v in base.items() if k != 4}
    other = dict(base)
    other[1] = SS_OTHER_AID
    kel_text = dict(base)
    kel_text[3] = "kel"
    empty_card = dict(base)
    empty_card[5] = b""
    unlabeled_h = sha256(a.encode("utf-8"))
    h_a = b16(dir_hash(a))
    refused = [
        {"name": "opened with another AID", "aid": SS_OTHER_AID, "h": b16(dir_hash(SS_OTHER_AID)),
         "box": b16(box_a), "error": "open"},
        {"name": "filed under another AID's hash", "aid": a, "h": b16(dir_hash(SS_OTHER_AID)),
         "box": b16(box_a), "error": "hash"},
        {"name": "hash without its label", "aid": a, "h": b16(unlabeled_h),
         "box": b16(dir_box(a, cbor(base), nonce, aad=unlabeled_h)), "error": "hash"},
        {"name": "box with one byte changed", "aid": a, "h": h_a, "box": b16(flip(box_a, 20)), "error": "open"},
        {"name": "nonce with one byte changed", "aid": a, "h": h_a, "box": b16(flip(box_a, 3)), "error": "open"},
        {"name": "box one byte short", "aid": a, "h": h_a, "box": b16(box_a[:-1]), "error": "open"},
        {"name": "shorter than a nonce and a tag", "aid": a, "h": h_a, "box": b16(box_a[:27]), "error": "open"},
        {"name": "sealed without the hash as aad", "aid": a, "h": h_a,
         "box": b16(dir_box(a, cbor(base), nonce, aad=b"")), "error": "open"},
        {"name": "sealed with the key of another AID", "aid": a, "h": h_a,
         "box": b16(nonce + chacha20poly1305_seal(dir_key(SS_OTHER_AID), nonce, cbor(base), dir_hash(a))),
         "error": "open"},
        {"name": "unregistered key 7", "aid": a, "h": h_a, "box": sealed(with7), "error": "entry"},
        {"name": "key 4 (keys) missing", "aid": a, "h": h_a, "box": sealed(without4), "error": "entry"},
        {"name": "key 1 names another AID", "aid": a, "h": h_a, "box": sealed(other), "error": "entry"},
        {"name": "key 3 (kel) is a text string", "aid": a, "h": h_a, "box": sealed(kel_text), "error": "entry"},
        {"name": "empty card instead of no card", "aid": a, "h": h_a, "box": sealed(empty_card), "error": "entry"},
        {"name": "keys out of canonical order", "aid": a, "h": h_a,
         "box": sealed([(2, full["home"]), (1, a), (3, full["kel"]), (4, full["keys"])], in_order=True),
         "error": "entry"},
        {"name": "an array, not a map", "aid": a, "h": h_a,
         "box": b16(dir_box(a, cbor([a, full["home"]]), nonce)), "error": "entry"},
    ]
    hash_refused = [
        {"name": "empty AID", "aid": "", "error": "aid"},
        {"name": "AID holding U+0000", "aid": a[:6] + "\x00" + a[6:], "error": "aid"},
    ]
    return {
        "id": vid,
        "about": ("Directory box: L9 h, L10 K, the box under a fixed nonce, opening, and boxes that must not "
                  "open or must not decode. Seeds: SHA-256(\"anet-golden/v016/DIR-1/<role>\") for roles kel, kel-2, "
                  "keys, notice, kel-min, keys-min, nonce-full, nonce-min, nonce-refused (nonces: first 12 bytes). "
                  "kel, keys, card and notice are opaque to the box and are placeholders here. "
                  "Generated by golden/py/gen_v016.py."),
        "cases": cases,
        "refused": refused,
        "hash_refused": hash_refused,
    }


def relayauth_preimage(action: str, aid: str, hub_aid: str, ts: int, method: str, target: str, body: bytes) -> str:
    """L22: "anet-relay/v2/" + action + "/" + aid + "/" + hubAID + "/" + decimal(ts) + "/" +
    base64url(SHA-256(method || 0x00 || pathAndQuery || 0x00 || body)), no padding."""
    for f in (action, aid, hub_aid):
        if "/" in f:
            raise GoldenError("relayauth: %r holds the separator" % f)
    d = sha256(method.encode("utf-8") + b"\x00" + target.encode("utf-8") + b"\x00" + bytes(body))
    digest = base64.urlsafe_b64encode(d).rstrip(b"=").decode("ascii")
    return "anet-relay/v2/%s/%s/%s/%d/%s" % (action, aid, hub_aid, ts, digest)


def relayauth3_pins() -> list[tuple[str, str]]:
    """RELAYAUTH-3 (gen "go": golden/relayauth_v3_test.go holds the rows): the (preimage, hex
    signature) of each pinned action, in the order of the Go test's ra3Rows, computed here
    independently. test_gen_v016.py compares them with the literals of the Go test. Signers:
    Ed25519 seeds seed("RELAYAUTH-3", "agent") and seed("RELAYAUTH-3", "peer-hub")."""
    a = SS_AGENT_AID
    rows = [
        ("poll", "agent", "POST", "/relay/poll", b'{"limit":10}'),
        ("ack", "agent", "POST", "/relay/ack", b'{"items":[{"id":1}]}'),
        ("register", "agent", "POST", "/register", b'{"aid":"' + a.encode() + b'"}'),
        ("profile", "agent", "POST", "/profile", b'{"summary":"golden"}'),
        ("visibility", "agent", "POST", "/visibility", b'{"visible":true}'),
        ("deregister", "agent", "POST", "/deregister", b"{}"),
        ("balance", "agent", "GET", "/agents/" + a + "/balance", b""),
        ("ledger", "agent", "GET", "/agents/" + a + "/ledger?limit=10", b""),
        ("redemptions", "agent", "GET", "/agents/" + a + "/redemptions?limit=500", b""),
        ("keys", "agent", "POST", "/agents/" + a + "/keys", b'{"prev_seq":0}'),
        ("session", "agent", "POST", "/relay/session", b'{"epk":"' + b"A" * 43 + b'"}'),
        ("revoke", "agent", "POST", "/mailbox/revoke", b'{"cap_ids":["' + b"A" * 22 + b'"]}'),
        ("review", "agent", "POST", "/reviews", b'{"receipt":"oQE","review":"oQE","rsalt":"' + b"A" * 43 + b'"}'),
        ("liab_proof", "agent", "GET", "/agents/" + a + "/liability-proof?to_day=20454", b""),
        ("fed_forward", "peer-hub", "POST", "/fed/v3/forward", b"\xa6\x01\x02"),
        ("fed_bucket", "peer-hub", "POST", "/fed/v3/directory:bucket", b'{"prefix":"AA","bits":8}'),
        ("fed_cards", "peer-hub", "GET", "/fed/v3/cards?cursor=0", b""),
        ("fed_settle", "peer-hub", "POST", "/fed/v3/settle", b'{"x402Version":2}'),
        ("fed_reviews", "peer-hub", "GET", "/fed/v3/reviews?cursor=0", b""),
        ("fed_clear", "peer-hub", "POST", "/fed/v3/clear", b'{"receipts":[]}'),
    ]
    signer_aid = {"agent": SS_AGENT_AID, "peer-hub": SS_OTHER_HUB_AID}
    out = []
    for action, signer, method, target, body in rows:
        pre = relayauth_preimage(action, signer_aid[signer], SS_HUB_AID, SS_TS, method, target, body)
        out.append((pre, b16(ed25519_sign(seed("RELAYAUTH-3", signer), pre.encode("ascii")))))
    return out


# --- HPP: evidence v2 (EV2-1, REVIEW-2) ---------------------------------------------------------
#
# ReceiptBody (core §2.9): 0 "anet.receipt/2", 1 ix_commit (L27), 2 requester_commit (L28),
# 3 review_key, 4 provider, 5 request_cid, 6 result_cid, 7 completed_day. ReceiptWire {1: body bstr,
# 2: aobj envelope {1 signer_aid, 2 key_state_seq, 3 alg -8, 4 sig}}; the provider's identity key
# signs the body bytes (L29). ReviewBody: 0 "anet.review/2", 1 receipt_cid, 2 subject, 3 rating,
# 4 comment (absent when empty), 5 created_day; ReviewWire {1: body, 2: pub, 3: sig}, signed by the
# one-time review key (L30). ReviewAttBody: 0 "anet.review-att/1", 1 review_cid, 2 receipt_cid,
# 3 subject, 4 tag (L31), 5 tag_key_id, 6 day, 7 hub; ReviewAttWire like ReceiptWire, signed by the
# hub (L32). receipt_cid and review_cid are the CIDs of the body bytes (CORE-K12).
#
# The provider is the frozen conformance identity (identity/suite.go: icp of the seeds
# SHA-256("anet-suite-identity-v1/cur"), ".../nxt", toad 0, ts 1760000000000), so the Go test signs
# with the real code path; the review key, the salt, the nonce, the tag key and the attesting hub
# come from seed(<vector id>, <role>).

RECEIPT_TYPE = "anet.receipt/2"
REVIEW_TYPE = "anet.review/2"
REVIEW_ATT_TYPE = "anet.review-att/1"
IX_LABEL = b"anet-receipt-ix/v2"
REQUESTER_LABEL = b"anet-receipt-requester/v2"
REVIEW_TAG_LABEL = b"anet-review-tag/v1"
SETTLE_GUARD_LABEL = b"anet-settle-guard/v1"
PAY_BIND_LABEL = b"anet/x402-bind/v1"
SUITE_AID = "bafyreihq42j7esljj5drxgieudh2ar4gsspogpejmdxmg4nezfa3twdmke"
SUITE_TS = 1760000000000
EV2_DAY = 20454  # 2026-01-01
ALG_EDDSA = -8


def b64u(b: bytes) -> str:
    """base64url without padding (CORE-E5)."""
    return base64.urlsafe_b64encode(bytes(b)).rstrip(b"=").decode("ascii")


def _commit_text(*fields: str):
    """CORE-E9 plus "not empty": the text fields of an evidence commitment."""
    for f in fields:
        if not f:
            raise GoldenError("an evidence commitment field is empty")
    _no_nul(*fields)


def ix_commit_preimage(ix: str, nonce: str) -> bytes:
    """L27: "anet-receipt-ix/v2" 0x00 ix 0x00 anet.nonce (as written, not decoded)."""
    _commit_text(ix, nonce)
    return IX_LABEL + b"\x00" + ix.encode("utf-8") + b"\x00" + nonce.encode("utf-8")


def requester_commit_preimage(requester_aid: str, rsalt: bytes) -> bytes:
    """L28: "anet-receipt-requester/v2" 0x00 requester_aid 0x00 rsalt(32)."""
    _commit_text(requester_aid)
    if len(rsalt) != 32:
        raise GoldenError("rsalt is 32 bytes")
    return REQUESTER_LABEL + b"\x00" + requester_aid.encode("utf-8") + b"\x00" + bytes(rsalt)


def review_tag_message(reviewer_aid: str, subject_aid: str) -> bytes:
    """L31: the HMAC message "anet-review-tag/v1" 0x00 reviewer_aid 0x00 subject_aid."""
    _commit_text(reviewer_aid, subject_aid)
    return REVIEW_TAG_LABEL + b"\x00" + reviewer_aid.encode("utf-8") + b"\x00" + subject_aid.encode("utf-8")


def review_tag(key: bytes, reviewer_aid: str, subject_aid: str) -> bytes:
    if len(key) != 32:
        raise GoldenError("a review tag key is 32 bytes")
    return hmac_sha256(key, review_tag_message(reviewer_aid, subject_aid))[:16]


def settle_guard_preimage(payer: str, pay_bind: str) -> bytes:
    """L33: "anet-settle-guard/v1" 0x00 payer 0x00 pay_bind."""
    _commit_text(payer, pay_bind)
    return SETTLE_GUARD_LABEL + b"\x00" + payer.encode("utf-8") + b"\x00" + pay_bind.encode("utf-8")


def pay_bind_preimage(ix: str, task_nonce: str) -> bytes:
    """L34 (carried): "anet/x402-bind/v1" 0x00 ix 0x00 taskNonce; PayBind is the hex of its SHA-256."""
    _no_nul(ix, task_nonce)
    return PAY_BIND_LABEL + b"\x00" + ix.encode("utf-8") + b"\x00" + task_nonce.encode("utf-8")


def suite_kel() -> KelLog:
    cur = sha256(b"anet-suite-identity-v1/cur")
    nxt = sha256(b"anet-suite-identity-v1/nxt")
    kel = KelLog().add(kel_icp(cur, nxt, SUITE_TS, 0), cur)
    if kel.aid != SUITE_AID:
        raise GoldenError("the conformance identity moved: %s" % kel.aid)
    return kel


def envelope(aid: str, seq: int, sig: bytes) -> dict:
    return {1: aid, 2: seq, 3: ALG_EDDSA, 4: sig}


def ev2_task() -> dict:
    """The EV2-1 task as its requester holds it: ix, the binding contexts and the TaskDoc bytes."""
    V = "EV2-1"
    ix = "ix-golden-1"
    nonce = b64u(seed(V, "nonce")[:16])
    requester = aid_for(V, "requester")
    rsalt = seed(V, "rsalt")
    review_seed = seed(V, "review-key")
    review_pub = ed25519_public(review_seed)
    rcommit = sha256(requester_commit_preimage(requester, rsalt))

    def ctx(k, v):
        return {1: k, 2: v, 4: "text", 5: "private"}
    # tsir.TaskDoc {1 version {1 major}, 4 tasks [{10 intent {1 summary, 3 body}, 13 contexts}]}
    taskdoc = cbor({1: {1: 1}, 4: [{10: {1: "caption", 3: "caption the image"},
                                    13: [ctx("anet.nonce", nonce), ctx("anet.requester_commit", b64u(rcommit)),
                                         ctx("anet.review_key", b64u(review_pub))]}]})
    deliverable = b'{"ok":true}'
    return {"ix": ix, "nonce": nonce, "requester": requester, "rsalt": rsalt, "review_seed": review_seed,
            "review_pub": review_pub, "requester_commit": rcommit, "taskdoc": taskdoc, "request_cid": cid(taskdoc),
            "deliverable": deliverable, "result_cid": cid(deliverable)}


def ev2_receipt() -> dict:
    """The EV2-1 receipt: body, signature by the conformance identity, wire."""
    tk = ev2_task()
    kel = suite_kel()
    body = cbor({0: RECEIPT_TYPE, 1: sha256(ix_commit_preimage(tk["ix"], tk["nonce"])), 2: tk["requester_commit"],
                 3: tk["review_pub"], 4: kel.aid, 5: tk["request_cid"], 6: tk["result_cid"], 7: EV2_DAY})
    sig = ed25519_sign(sha256(b"anet-suite-identity-v1/cur"), body)
    wire = cbor({1: body, 2: envelope(kel.aid, 0, sig)})
    return {"task": tk, "kel": kel, "body": body, "sig": sig, "wire": wire}


def hpp_go_pins() -> dict:
    """The bytes that the gen "go" vectors of this area (CARD-1, TASKDOC-3, SUPPLY-EPOCH-1) and the
    0.2 completion vectors carrying the EV2-1 receipt (VEC_RESULT_1, VEC_RESULT_2, VEC_DELEGATE_2)
    pin in their Go tests, computed here independently; test_gen_v016.py checks that each value is
    a literal of the Go test named."""
    pins = {}
    card = b'{"name":"golden","capabilities":{"extendedAgentCard":true}}'
    pins["golden/a2a_wire_v3_test.go"] = [b16(cbor({1: card})), b16(cbor({2: "not_configured"})), b16(cbor({2: "busy"}))]

    def sd(role):
        return seed("TASKDOC-3", role)
    file_cid = "bafkreif2pall7dybz7vecqka3zo24irdwabwdi4wc55jznaq75q7eaavvu"
    args = '{"prompt":"describe it","$files":[{"name":"a.txt","mime":"text/plain","size":3,"cid":"' + file_cid + '"}]}'
    goal = "invoke capability image.caption"

    def ctx(k, v):
        return {1: k, 2: v, 4: "text", 5: "private"}
    rc = sha256(requester_commit_preimage(SUITE_AID, sd("rsalt")))
    td = cbor({1: {1: 1}, 4: [{10: {1: goal, 3: goal}, 11: [{1: "image.caption", 2: "capability", 3: "must"}],
                               13: [{1: "args", 2: args, 4: "json"}, ctx("anet.nonce", b64u(sd("nonce")[:16])),
                                    ctx("anet.requester_commit", b64u(rc)), ctx("anet.review_key", b64u(ed25519_public(sd("review-key"))))]}]})
    pins["golden/taskdoc_v3_test.go"] = [b16(td), cid(td)]

    # SUPPLY-EPOCH-1 states the LIAB-1 tree; the hub is the conformance identity.
    liab = gen_liab_1()["build"]
    payload = {"v": 2, "from_day": liab["to_day"] - 6, "to_day": liab["to_day"], "root": liab["root"],
               "outstanding": liab["outstanding"], "depth": liab["depth"]}
    genesis = cid(cbor("anet:ael:genesis"))
    rec = {1: SUITE_AID, 2: 0, 3: genesis, 4: "anet.supply.epoch", 5: 2, 6: payload, 7: (liab["to_day"] + 1) * 86400000,
           8: SUITE_AID, 9: 0}
    pre = cbor(rec)
    sig = ed25519_sign(sha256(b"anet-suite-identity-v1/cur"), pre)
    pins["golden/supply_epoch_test.go"] = [b16(pre), b16(sig), b16(cbor({**rec, 11: cid(pre), 12: sig}))]

    r = ev2_receipt()
    deliverable, wire, kel = r["task"]["deliverable"], r["wire"], r["kel"].wire()
    meta = b'{"a2a.serviceParameters":{"A2A-Version":"1.0"}}'
    pins["golden/wire_test.go"] = [cid(cbor({1: "done", 2: deliverable, 3: wire}))]
    gtd = {1: {1: 1}, 4: [{10: {1: "golden task", 3: "describe the image"}}]}
    gsig = ed25519_sign(sha256(b"anet-suite-identity-v1/cur"), cbor(gtd))
    att = {1: "a.txt", 2: "text/plain", 3: 3, 4: "bafkreif2pall7dybz7vecqka3zo24irdwabwdi4wc55jznaq75q7eaavvu", 5: b"abc"}
    delegate = {1: cbor(gtd), 2: envelope(SUITE_AID, 0, gsig), 3: kel, 4: "ix-golden-1", 5: [att], 7: "ctx-golden-1", 8: meta}
    pins["golden/a2a_wire_test.go"] = [cid(cbor({1: "done", 2: deliverable, 3: wire, 4: kel, 5: meta})), cid(cbor(delegate))]
    return pins


@vector("EV2-1", "ANetCore/evidence/testdata/vec-ev2-1.json")
def gen_ev2_1():
    V = "EV2-1"
    r = ev2_receipt()
    tk, kel, body = r["task"], r["kel"], r["body"]
    ixc_pre = ix_commit_preimage(tk["ix"], tk["nonce"])
    rq_pre = requester_commit_preimage(tk["requester"], tk["rsalt"])
    pb_pre = pay_bind_preimage(tk["ix"], tk["nonce"])
    pay_bind = b16(sha256(pb_pre))
    sg_pre = settle_guard_preimage(tk["requester"], pay_bind)
    wire = r["wire"]
    env = envelope(kel.aid, 0, r["sig"])

    def rewire(new_body):
        return b16(cbor({1: new_body, 2: env}))

    # SI-81: the receipt's signature, by the same key and key state, carried by a payment
    # authorization (PaymentAuthorizationWire {1: auth, 2: envelope}) that pays the task.
    auth = {1: kel.aid, 2: aid_for(V, "payee"), 3: 7919, 4: "hub:" + aid_for(V, "hub"), 5: "golden-nonce",
            6: 1767225600000, 7: 1767225900000, 8: pay_bind}
    moved = cbor({1: auth, 2: env})
    for ix, nonce in (("a\x00b", "c"), ("a", "b\x00c")):
        for fn in (ix_commit_preimage, pay_bind_preimage):
            try:
                fn(ix, nonce)
            except GoldenError:
                continue
            raise GoldenError("%s accepted a field holding U+0000" % fn.__name__)
    return {
        "id": V,
        "description": ("Evidence v2 receipt: the ix and requester commitments (L27, L28), the settle guard (L33) over the "
                        "task's PayBind (L34), ReceiptBody and ReceiptWire signed by the provider's identity (L29). The "
                        "provider is the conformance identity; the other inputs come from the seeds named. Negatives: "
                        "each must be refused (decode: not a receipt, the hub answers receipt_not_reviewable; signature: "
                        "does not verify)."),
        "labels": {"ix_commit": IX_LABEL.decode(), "requester_commit": REQUESTER_LABEL.decode(),
                   "settle_guard": SETTLE_GUARD_LABEL.decode(), "pay_bind": PAY_BIND_LABEL.decode()},
        "task": {
            "ix": tk["ix"],
            "nonce": tk["nonce"], "nonce_seed": "anet-golden/v016/%s/nonce (first 16 bytes, base64url)" % V,
            "requester_aid": tk["requester"],
            "rsalt": b16(tk["rsalt"]),
            "review_key_seed": b16(tk["review_seed"]), "review_key": b16(tk["review_pub"]),
            "taskdoc": b16(tk["taskdoc"]), "request_cid": tk["request_cid"],
            "deliverable": b16(tk["deliverable"]), "result_cid": tk["result_cid"],
            "completed_day": EV2_DAY,
        },
        "provider": {"aid": kel.aid, "kel": b16(kel.wire())},
        "ix_commit": {"preimage": b16(ixc_pre), "hash": b16(sha256(ixc_pre))},
        "requester_commit": {"preimage": b16(rq_pre), "hash": b16(sha256(rq_pre))},
        "pay_bind": {"preimage": b16(pb_pre), "hex": pay_bind},
        "settle_guard": {"payer": tk["requester"], "pay_bind": pay_bind, "preimage": b16(sg_pre), "hash": b16(sha256(sg_pre))},
        "receipt": {
            "body": b16(body), "body_cid": cid(body), "sig": b16(r["sig"]),
            "envelope": {"signer_aid": kel.aid, "key_state_seq": 0, "alg": ALG_EDDSA},
            "wire": b16(wire), "verify_at": EV2_DAY * 86400000,
        },
        "negatives": [
            {"name": "sig_byte_changed", "note": "the last byte of the wire (of the signature) changed", "wire": b16(flip(wire)), "refused": "signature"},
            {"name": "body_byte_changed", "note": "the last byte of completed_day in the body changed, the envelope kept",
             "wire": rewire(flip(body)), "refused": "signature"},
            {"name": "ix_commit_dropped", "note": "body without key 1", "wire": rewire(drop_key(body, 1)), "refused": "decode"},
            {"name": "body_key_8", "note": "body with an unregistered key 8", "wire": rewire(add_key(body, 8, 0)), "refused": "decode"},
            {"name": "wire_key_3", "note": "wire with an unregistered key 3", "wire": b16(add_key(wire, 3, 0)), "refused": "decode"},
            {"name": "type_tag_v1", "note": "key 0 is anet.receipt/1", "wire": rewire(cbor({**uncbor(body), 0: "anet.receipt/1"})), "refused": "decode"},
            {"name": "receipt_signature_on_authorization", "note": "SI-81: the receipt's signature carried by a payment authorization",
             "authorization_wire": b16(moved), "verify_at": 1767225600001, "refused": "signature"},
        ],
        "nul_refused": [
            {"ix": "a\x00b", "nonce": "c", "note": "refused by the L27 function and by PayBind (L34)"},
            {"ix": "a", "nonce": "b\x00c", "note": "the same bytes with the boundary moved; refused the same way"},
        ],
    }


@vector("REVIEW-2", "ANetCore/evidence/testdata/vec-review-2.json")
def gen_review_2():
    V = "REVIEW-2"
    r = ev2_receipt()
    tk, provider = r["task"], r["kel"].aid
    receipt_cid = cid(r["body"])
    body = cbor({0: REVIEW_TYPE, 1: receipt_cid, 2: provider, 3: 5, 4: "准时、清楚", 5: EV2_DAY + 1})
    sig = ed25519_sign(tk["review_seed"], body)
    wire = cbor({1: body, 2: tk["review_pub"], 3: sig})
    tag_key = seed(V, "tag-key")
    tag = review_tag(tag_key, tk["requester"], provider)
    hk0, hk1 = seed(V, "hub-k0"), seed(V, "hub-k1")
    hub = KelLog().add(kel_icp(hk0, hk1, SUITE_TS, 0), hk0)
    att_body = cbor({0: REVIEW_ATT_TYPE, 1: cid(body), 2: receipt_cid, 3: provider, 4: tag, 5: 1, 6: EV2_DAY + 2, 7: hub.aid})
    att_sig = ed25519_sign(hk0, att_body)
    att = cbor({1: att_body, 2: envelope(hub.aid, 0, att_sig)})
    other = seed(V, "other-key")

    def review_wire(b, key_seed=None, pub=None):
        key_seed = key_seed or tk["review_seed"]
        return b16(cbor({1: b, 2: pub or ed25519_public(key_seed), 3: ed25519_sign(key_seed, b)}))

    rv = uncbor(body)
    return {
        "id": V,
        "description": ("Evidence v2 review of the EV2-1 receipt: ReviewBody and ReviewWire signed by the one-time review key (L30); "
                        "the review tag (L31) of the requester for the provider under a hub tag key; ReviewAttBody and ReviewAttWire "
                        "signed by a hub (L32). Negatives say which refusal each must get: decode (receipt_not_reviewable), "
                        "signer (a key other than the receipt's review_key), signature, rating or comment (bad_request), "
                        "nul (a subject holding U+0000, bad_request, CORE-E9)."),
        "labels": {"tag": REVIEW_TAG_LABEL.decode()},
        "receipt": {"wire": b16(r["wire"]), "body_cid": receipt_cid, "provider_kel": b16(r["kel"].wire())},
        "review": {"key_seed": b16(tk["review_seed"]), "pub": b16(tk["review_pub"]), "body": b16(body),
                   "review_cid": cid(body), "sig": b16(sig), "wire": b16(wire)},
        "tag": {"key": b16(tag_key), "reviewer_aid": tk["requester"], "subject_aid": provider,
                "message": b16(review_tag_message(tk["requester"], provider)), "tag": b16(tag)},
        "hub": {"aid": hub.aid, "labels": ["anet-golden/v016/%s/hub-k0" % V, "anet-golden/v016/%s/hub-k1" % V], "kel": b16(hub.wire())},
        "attestation": {"body": b16(att_body), "sig": b16(att_sig), "wire": b16(att), "verify_at": (EV2_DAY + 2) * 86400000},
        "negatives": [
            {"name": "another_review_key", "note": "signed by another key, which it carries", "review_wire": review_wire(body, key_seed=other),
             "refused": "signer"},
            {"name": "pub_swapped", "note": "carries the receipt's review_key, signed by another key",
             "review_wire": review_wire(body, key_seed=other, pub=tk["review_pub"]), "refused": "signature"},
            {"name": "rating_6", "note": "rating 6", "review_wire": review_wire(cbor({**rv, 3: 6})), "refused": "rating"},
            {"name": "comment_281", "note": "a comment of 281 characters", "review_wire": review_wire(cbor({**rv, 4: "评" * 281})),
             "refused": "comment"},
            {"name": "review_key_6", "note": "review body with an unregistered key 6", "review_wire": review_wire(add_key(body, 6, 0)),
             "refused": "decode"},
            {"name": "subject_nul", "note": "U+0000 in the subject (CORE-E9)", "review_wire": review_wire(cbor({**rv, 2: provider[:8] + "\x00" + provider[8:]})),
             "refused": "nul"},
            {"name": "attestation_tag_15", "note": "a 15-byte tag", "attestation_wire": b16(cbor({1: cbor({**uncbor(att_body), 4: tag[:15]}),
                                                                                               2: envelope(hub.aid, 0, att_sig)})),
             "refused": "decode"},
            {"name": "attestation_by_the_provider", "note": "the attestation's body signed by the provider's key under the hub's AID",
             "attestation_wire": b16(cbor({1: att_body, 2: envelope(hub.aid, 0, ed25519_sign(sha256(b"anet-suite-identity-v1/cur"), att_body))})),
             "refused": "signature"},
        ],
    }


# --- HPP: the liability tree (LIAB-1) and the registration proof of work (REGPOW-1) ------------

U64 = 1 << 64
MAX_SUM = (1 << 63) - 1


def u64be(n: int) -> bytes:
    return struct.pack(">Q", n % U64)


class Stream:
    """The test random source: SHA-256(UTF-8(label) || u64be(i)) for i = 0, 1, …, concatenated."""

    def __init__(self, label: str):
        self.label = label.encode("utf-8")
        self.i = 0
        self.buf = b""

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            self.buf += sha256(self.label + u64be(self.i))
            self.i += 1
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def aid_for(vector_id: str, role: str) -> str:
    """A stand-in AID: CIDv1, dag-cbor (0x71), sha2-256, base32 lower without padding, whose digest
    is seed(vector id, "aid/<role>")."""
    raw = bytes([0x01, 0x71, 0x12, 0x20]) + seed(vector_id, "aid/" + role)
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


LEAF_LABEL = b"anet-liab-leaf/v1"
NODE_LABEL = b"anet-liab-node/v1"


def liab_content(aid, to_day, balance):
    return cbor({1: aid, 2: to_day, 3: balance})


def liab_leaf_preimage(aid, to_day, balance, salt):
    return LEAF_LABEL + b"\x00" + salt + liab_content(aid, to_day, balance)


def liab_leaf(aid, to_day, balance, salt):
    return sha256(liab_leaf_preimage(aid, to_day, balance, salt))


def liab_node_preimage(l, r):
    (lh, ls), (rh, rs) = l, r
    return NODE_LABEL + b"\x00" + lh + u64be(ls) + rh + u64be(rs)


def liab_node(l, r):
    return sha256(liab_node_preimage(l, r))


def uniform(rnd, m):
    """Uniform integer in [0, m): 8 bytes big-endian, read again while x >= 2^64 - (2^64 mod m)."""
    limit = U64 - (U64 % m)
    while True:
        x = struct.unpack(">Q", rnd.read(8))[0]
        if x < limit:
            return x % m


def liab_build(accounts, to_day, rnd, min_leaves=16):
    """Pad, shuffle (Fisher-Yates, i = n-1 … 1, j = uniform(i+1)), then one salt per position."""
    size = min_leaves
    while size < len(accounts):
        size *= 2
    entries = [[a, b] for a, b in accounts] + [["", 0] for _ in range(size - len(accounts))]
    for i in range(size - 1, 0, -1):
        j = uniform(rnd, i + 1)
        entries[i], entries[j] = entries[j], entries[i]
    return [(a, b, rnd.read(32)) for a, b in entries]


def liab_levels(entries, to_day, wrap=False):
    """Every level, leaves first, of (hash, sum). Sums above 2^63-1 raise unless wrap is set; with
    wrap the sums are taken mod 2^64, which is how a tree that hides a debt by overflow is made."""
    cur = [(liab_leaf(a, to_day, b, s), b) for a, b, s in entries]
    levels = [cur]
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            l, r = cur[i], cur[i + 1]
            total = l[1] + r[1]
            if wrap:
                total %= U64
            elif l[1] > MAX_SUM or r[1] > MAX_SUM or total > MAX_SUM:
                raise GoldenError("liability tree: a sum over 2^63-1")
            nxt.append((liab_node(l, r), total))
        levels.append(nxt)
        cur = nxt
    return levels


def liab_fold(p):
    """The (hash, sum) a proof's leaf and path reach under L25 and L26."""
    h = liab_leaf(p["aid"], p["to_day"], p["balance"], bytes.fromhex(p["salt"]))
    cur = (h, p["balance"])
    for st in p["path"]:
        sib = (bytes.fromhex(st["h"]), st["sum"])
        l, r = (sib, cur) if st["side"] == "L" else (cur, sib)
        cur = (liab_node(l, r), l[1] + r[1])
    return cur


def liab_proof(entries, levels, to_day, index):
    a, b, s = entries[index]
    path = []
    i = index
    for lvl in range(len(levels) - 1):
        sib, side = (i + 1, "R") if i % 2 == 0 else (i - 1, "L")
        h, sm = levels[lvl][sib]
        path.append({"h": b16(h), "sum": sm, "side": side})
        i //= 2
    return {"to_day": to_day, "aid": a, "balance": b, "salt": b16(s), "path": path}


def copy_proof(p):
    return json.loads(json.dumps(p))


@vector("LIAB-1", "ANetCore/liabtree/testdata/vec-liab-1.json")
def gen_liab_1():
    V = "LIAB-1"
    to_day = 20454  # 2026-01-01
    balances = [120, 0, 7919, 1000000, 42]
    accounts = [(aid_for(V, "account-%d" % (i + 1)), b) for i, b in enumerate(balances)]
    rand_label = "anet-golden/v016/%s/rand" % V

    # the two hashes, alone
    leaf_salt = seed(V, "salt/leaf")
    a3, b3 = accounts[2]
    pad_salt = seed(V, "salt/padding")
    lnode = (seed(V, "node/left"), 5)
    rnode = (seed(V, "node/right"), 7)

    entries = liab_build(accounts, to_day, Stream(rand_label))
    levels = liab_levels(entries, to_day)
    root, outstanding = levels[-1][0]
    assert outstanding == sum(balances)
    third = next(i for i, e in enumerate(entries) if e[0] == a3)
    proof = liab_proof(entries, levels, to_day, third)

    neg = []

    # moved sums on one path: take k from one sibling's sum and add it to another's. The root sum is
    # the same, so a node hash that covers no sums at all would accept. (A hash over a node's total
    # alone still refuses this single path; moved_split below is the case it misses.)
    moved = copy_proof(proof)
    i = next(n for n, st in enumerate(moved["path"]) if st["sum"] >= 1)
    j = next(n for n in range(len(moved["path"])) if n != i)
    moved["path"][i]["sum"] -= 1
    moved["path"][j]["sum"] += 1
    neg.append({"name": "moved_sum", "note": "path[%d].sum - 1 and path[%d].sum + 1: the root sum is unchanged, the root hash is not" % (i, j),
                "proof": moved, "error": "root"})

    for name, note, edit in [
        ("balance_changed", "the leaf's balance - 1", lambda p: p.__setitem__("balance", p["balance"] - 1)),
        ("salt_changed", "one byte of the salt", lambda p: p.__setitem__("salt", ("%02x" % (int(p["salt"][:2], 16) ^ 1)) + p["salt"][2:])),
        ("day_changed", "to_day + 1", lambda p: p.__setitem__("to_day", p["to_day"] + 1)),
        ("aid_changed", "another account's AID", lambda p: p.__setitem__("aid", accounts[0][0])),
        ("sibling_hash_changed", "one byte of path[1].h", lambda p: p["path"][1].__setitem__("h", ("%02x" % (int(p["path"][1]["h"][:2], 16) ^ 1)) + p["path"][1]["h"][2:])),
        ("sibling_sum_changed", "path[2].sum + 1, which also changes the root sum", lambda p: p["path"][2].__setitem__("sum", p["path"][2]["sum"] + 1)),
        ("side_flipped", "path[0].side swapped", lambda p: p["path"][0].__setitem__("side", "L" if p["path"][0]["side"] == "R" else "R")),
    ]:
        q = copy_proof(proof)
        edit(q)
        neg.append({"name": name, "note": note, "proof": q, "error": "root"})

    short = copy_proof(proof)
    short["path"] = short["path"][:-1]
    neg.append({"name": "path_short", "note": "the last step dropped", "proof": short, "error": "malformed"})
    neg.append({"name": "depth_mismatch", "note": "depth 5 for a tree of depth 4", "proof": copy_proof(proof), "depth": 5, "error": "malformed"})
    neg.append({"name": "outstanding_mismatch", "note": "the record's outstanding is the true sum + 1",
                "proof": copy_proof(proof), "outstanding": outstanding + 1, "error": "sum"})
    pad = copy_proof(proof)
    pad["aid"] = ""
    neg.append({"name": "padding_aid", "note": "the empty AID marks a padding leaf, which is nobody's", "proof": pad, "error": "malformed"})

    # Sum overflow: a tree in which one leaf holds 2^64 - 3, so with sums taken mod 2^64 the
    # victim's subtree adds up to 5 + 2^64 - 3 = 2 and the debt disappears from the total. Every
    # hash is consistent; only the sum check refuses it.
    victim = (accounts[0][0], 5, seed(V, "overflow/victim"))
    giant = (aid_for(V, "overflow-giant"), U64 - 3, seed(V, "overflow/giant"))
    others = [("", 0, seed(V, "overflow/pad-%d" % k)) for k in range(14)]
    ov_entries = [victim, giant] + others
    ov_levels = liab_levels(ov_entries, to_day, wrap=True)
    ov_root, ov_sum = ov_levels[-1][0]
    assert ov_sum == 2
    neg.append({"name": "sum_wraps", "note": "a sibling sum of 2^64 - 3: taken mod 2^64 the root sum is 2, and every hash matches",
                "proof": liab_proof(ov_entries, ov_levels, to_day, 0), "root": b16(ov_root), "outstanding": ov_sum, "depth": 4, "error": "overflow"})

    big = (aid_for(V, "overflow-big"), 1 << 63, seed(V, "overflow/big"))
    big_entries = [victim, big] + others
    big_levels = liab_levels(big_entries, to_day, wrap=True)
    big_root, big_sum = big_levels[-1][0]
    neg.append({"name": "sum_over_max", "note": "a sibling sum of 2^63: no wrap, but the sums and the outstanding are over 2^63 - 1",
                "proof": liab_proof(big_entries, big_levels, to_day, 0), "root": b16(big_root), "outstanding": big_sum, "depth": 4, "error": "overflow"})

    # Moved split: two sibling accounts (30 and 12) under one parent. A hub that hashed only a
    # node's total could store that parent with the sum 30, hiding 12, and show each account a
    # different split of it: a sees (30, 0), b sees (18, 12), one side minus 12 and the other plus
    # 12. Both paths would reach one root. Under L26 the two parents differ, so the paths reach
    # different roots and at most one of them can match the record.
    hidden = 12
    sa = (aid_for(V, "split-a"), 30, seed(V, "split/a"))
    sb = (aid_for(V, "split-b"), 12, seed(V, "split/b"))
    sp_entries = [sa, sb] + [("", 0, seed(V, "split/pad-%d" % k)) for k in range(14)]
    sp_levels = liab_levels(sp_entries, to_day)
    pa = liab_proof(sp_entries, sp_levels, to_day, 0)
    pb = liab_proof(sp_entries, sp_levels, to_day, 1)
    pa["path"][0]["sum"] -= hidden
    pb["path"][0]["sum"] -= hidden
    ra, sum_a = liab_fold(pa)
    rb, sum_b = liab_fold(pb)
    assert sum_a == sum_b == sa[1] + sb[1] - hidden and ra != rb
    split = {"note": "sibling accounts of 30 and 12 under a parent stored with the sum 30: a is shown (30, 0), b is shown (18, 12); each path reaches its own root, and each is refused against the other's",
             "hidden": hidden, "proofs": [pa, pb], "roots": [b16(ra), b16(rb)], "sum": sum_a, "depth": 4}

    return {
        "id": V,
        "description": "Liability tree: the L25 leaf and L26 node hashes; 5 accounts padded to 16 leaves with a fixed random source; the root, outstanding and depth; the third account's proof in its response form; refused proofs; two sibling accounts shown different splits of one parent sum (moved_split).",
        "labels": {"leaf": LEAF_LABEL.decode(), "node": NODE_LABEL.decode()},
        "leaf": {"aid": a3, "to_day": to_day, "balance": b3, "salt": b16(leaf_salt),
                 "content": b16(liab_content(a3, to_day, b3)),
                 "preimage": b16(liab_leaf_preimage(a3, to_day, b3, leaf_salt)),
                 "hash": b16(liab_leaf(a3, to_day, b3, leaf_salt))},
        "padding_leaf": {"aid": "", "to_day": to_day, "balance": 0, "salt": b16(pad_salt),
                         "content": b16(liab_content("", to_day, 0)),
                         "preimage": b16(liab_leaf_preimage("", to_day, 0, pad_salt)),
                         "hash": b16(liab_leaf("", to_day, 0, pad_salt))},
        "node": {"left": {"h": b16(lnode[0]), "sum": lnode[1]}, "right": {"h": b16(rnode[0]), "sum": rnode[1]},
                 "preimage": b16(liab_node_preimage(lnode, rnode)), "hash": b16(liab_node(lnode, rnode)), "sum": lnode[1] + rnode[1]},
        "build": {
            "rand": "SHA-256(UTF-8(rand_label) || u64be(i)) for i = 0, 1, ..., concatenated; consumed by liabtree.Build",
            "rand_label": rand_label,
            "to_day": to_day,
            "accounts": [{"aid": a, "balance": b} for a, b in accounts],
            "leaves": len(entries),
            "depth": len(levels) - 1,
            "entries": [{"aid": a, "balance": b, "salt": b16(s), "hash": b16(levels[0][k][0])} for k, (a, b, s) in enumerate(entries)],
            "root": b16(root),
            "outstanding": outstanding,
        },
        "proof": proof,
        "negatives": neg,
        "moved_split": split,
    }


POW_LABEL = b"anet-regpow/v1"
SEED_LABEL = b"anet-regpow-seed/v1"
HOUR_MS = 3600000


def pow_seed(key, hour):
    return hmac_sha256(key, SEED_LABEL + u64be(hour))


def pow_prefix(hub_aid, aid, hour_seed):
    return POW_LABEL + b"\x00" + hub_aid.encode("utf-8") + b"\x00" + aid.encode("utf-8") + b"\x00" + hour_seed


def zero_bits(h):
    n = int.from_bytes(h, "big")
    return 256 - n.bit_length()


def pow_search(prefix, accept):
    """The smallest counter c whose nonce u64be(c) gives a hash accepted by accept(zero bits). The
    search keeps the SHA-256 state after the prefix (hashlib, for speed: millions of tries); every
    hash written to the vector is computed again with sha256() above."""
    base = hashlib.sha256(prefix)
    c = 0
    while True:
        h = base.copy()
        h.update(u64be(c))
        if accept(zero_bits(h.digest())):
            return c
        c += 1


@vector("REGPOW-1", "ANetCore/regpow/testdata/vec-regpow-1.json")
def gen_regpow_1():
    V = "REGPOW-1"
    bits = 22
    key = seed(V, "pow_key")
    ms = 1767225600000 + 5400000  # 2026-01-01T01:30:00Z
    hour = ms // HOUR_MS
    hour_seed = pow_seed(key, hour)
    hub = aid_for(V, "hub")
    aid = aid_for(V, "agent")
    pre = pow_prefix(hub, aid, hour_seed)

    def solution(name, c, note):
        nonce = u64be(c)
        h = sha256(pre + nonce)
        z = zero_bits(h)
        return {"name": name, "note": note, "counter": c, "nonce": b16(nonce), "preimage": b16(pre + nonce), "hash": b16(h), "zero_bits": z,
                "check": {str(b): z >= b for b in (8, 21, 22, 23)}}

    c22 = pow_search(pre, lambda z: z >= 22)
    c21 = pow_search(pre, lambda z: z == 21)
    c8 = pow_search(pre, lambda z: z >= 8)
    nonce22 = u64be(c22)
    prev_seed = pow_seed(key, hour - 1)
    other_hub = aid_for(V, "other-hub")
    return {
        "id": V,
        "description": "Registration proof of work: the L24 seed of an hour under a fixed pow_key; the L23 hash; the smallest counters whose 8-byte big-endian nonce passes 22 bits, has exactly 21 bits, and passes 8 bits; refused inputs.",
        "labels": {"hash": POW_LABEL.decode(), "seed": SEED_LABEL.decode()},
        "bits": bits,
        "seed": {"pow_key": b16(key), "ms": ms, "hour": hour, "message": b16(SEED_LABEL + u64be(hour)), "seed": b16(hour_seed), "not_after": (hour + 2) * HOUR_MS},
        "hub_aid": hub,
        "aid": aid,
        "prefix": b16(pre),
        "solutions": [
            solution("pass_22", c22, "the first nonce with at least 22 leading zero bits"),
            solution("fail_21", c21, "the first nonce with exactly 21 leading zero bits: passes 21, fails 22"),
            solution("fast_8", c8, "the first nonce with at least 8 leading zero bits"),
        ],
        "negatives": [
            {"name": "previous_hour_seed", "note": "pass_22's nonce against the previous hour's seed", "hub_aid": hub, "aid": aid,
             "seed": b16(prev_seed), "nonce": b16(nonce22), "hash": b16(sha256(pow_prefix(hub, aid, prev_seed) + nonce22)), "error": ""},
            {"name": "other_hub", "note": "pass_22's nonce for another hub", "hub_aid": other_hub, "aid": aid,
             "seed": b16(hour_seed), "nonce": b16(nonce22), "hash": b16(sha256(pow_prefix(other_hub, aid, hour_seed) + nonce22)), "error": ""},
            {"name": "empty_nonce", "note": "a nonce is 1 to 32 bytes", "hub_aid": hub, "aid": aid, "seed": b16(hour_seed), "nonce": "", "error": "nonce"},
            {"name": "nonce_33_bytes", "note": "a nonce is 1 to 32 bytes", "hub_aid": hub, "aid": aid, "seed": b16(hour_seed), "nonce": "00" * 33, "error": "nonce"},
            {"name": "hub_aid_nul", "note": "U+0000 in hub_aid (CORE-E9)", "hub_aid": hub[:8] + "\u0000" + hub[8:], "aid": aid, "seed": b16(hour_seed), "nonce": b16(nonce22), "error": "nul"},
            {"name": "aid_nul", "note": "U+0000 in aid (CORE-E9)", "hub_aid": hub, "aid": aid[:8] + "\u0000" + aid[8:], "seed": b16(hour_seed), "nonce": b16(nonce22), "error": "nul"},
            {"name": "boundary_moved", "note": "hub_aid + U+0000 + the start of aid, then the rest of aid: the same hash input bytes as aid_nul with the boundary moved; both refused (CORE-E9)",
             "hub_aid": hub + "\u0000" + aid[:8], "aid": aid[8:], "seed": b16(hour_seed), "nonce": b16(nonce22), "error": "nul"},
        ],
    }


# ---------------------------------------------------------------------------------------------

def _list(ws: Workspace) -> int:
    ix = load_index(ws)
    for row in ix["vectors"]:
        states = []
        for a in row.get("at", []):
            where = "%s/%s%s" % (a["repo"], a["path"], ("#" + a["test"]) if a.get("test") else "")
            if ws.repo(a["repo"]) is None:
                st = "repository not here"
            elif a.get("todo"):
                st = a["todo"]
            elif a.get("rework"):
                st = "present, " + a["rework"]
            else:
                st = "present" if ws.file("%s/%s" % (a["repo"], a["path"])).exists() else "MISSING"
            states.append("%s [%s]" % (where, st))
        gen = row.get("gen")
        mark = "generator" if row["id"] in GENERATORS else ("no generator" if gen in PY_GENS else "-")
        print("%-18s %-10s %-12s %s" % (row["id"], gen, mark, "; ".join(states)))
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="gen_v016.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("command", nargs="?", default="check", choices=("check", "write", "list", "selftest"))
    ap.add_argument("ids", nargs="*")
    ap.add_argument("--all", action="store_true", help="write: every registered vector")
    ap.add_argument("--root", type=Path, help="where to look for ANet, ANetHub and ANetLink (DIR/<name> or DIR/Refs/<name>)")
    ap.add_argument("--all-repos", action="store_true", help="a missing repository is an error")
    a = ap.parse_args(argv)
    ws = Workspace(root=a.root)
    try:
        selftest()
        if a.command == "selftest":
            print("gen_v016.py: every known-answer test passed")
            return 0
        if a.command == "list":
            return _list(ws)
        if a.command == "write":
            ids = sorted(GENERATORS) if a.all else a.ids
            if not ids:
                ap.error("write needs vector ids, or --all")
            for p in write(ws, ids):
                print("wrote", p)
            return 0
        if a.ids:
            ap.error("check takes no ids; it checks every registered vector")
        problems, notes = check(ws, all_repos=a.all_repos)
    except GoldenError as e:
        print("gen_v016.py: %s" % e, file=sys.stderr)
        return 2
    except Exception as e:  # an error in this script: say where, and do not pass for a vector mismatch
        print("gen_v016.py: internal error, %s: %s; the traceback follows" % (_where(e), e), file=sys.stderr)
        traceback.print_exc()
        return 2
    for n in notes:
        print("note:", n)
    for p in problems:
        print("FAIL:", p)
    if problems:
        print("golden-xcheck: %d problem(s)" % len(problems))
        return 1
    print("golden-xcheck: %d vector(s) reproduced byte for byte" % len(GENERATORS))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
