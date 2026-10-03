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
