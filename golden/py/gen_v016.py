#!/usr/bin/env python3
"""gen_v016.py: the independent implementation of the ANetCore v0.16 golden vectors (core §5, CORE-G3).

Pure Python: nothing here calls into Go or shares code with it. Each vector is rebuilt from the
public labels its seeds derive from (CORE-G5) and written in the JSON form the Go tests write
(two-space indent, final newline), so the CI job golden-xcheck compares the two implementations
byte for byte by regenerating the files and diffing them with the committed ones.

  gen_v016.py check [ID…]      regenerate in memory and fail on any difference (golden-xcheck)
  gen_v016.py write [ID…]      regenerate into the repository

Requires the cryptography package (Ed25519).

The file has two parts. The framework (CoreDet, CID, seeds, Ed25519, the @vector registry and the
driver) is the subset the vectors below need; it uses the names and conventions of the full golden
framework (CORE-3), so each work item's section moves into that framework unchanged. Sections:
  KEL (KEL-1)   KEL-2A, KEL-2B: KEL v2 events, preimages (L17), event ids, signatures, key states
"""

import hashlib
import json
import sys
from base64 import b32encode
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CORE_DIR = Path(__file__).resolve().parents[2]  # this ANetCore checkout


# ---------------------------------------------------------------------------------------------
# The framework (subset)
# ---------------------------------------------------------------------------------------------

class GoldenError(Exception):
    pass


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise GoldenError("integer too large")


def cbor(v) -> bytes:
    """CoreDet (RFC 8949 §4.2): shortest-form integers and lengths, definite lengths, map keys
    sorted by the bytewise order of their encodings, no tags. Only what the vectors here use."""
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        if v < 0:
            raise GoldenError("negative integers are not used here")
        return _head(0, v)
    if isinstance(v, (bytes, bytearray)):
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, (list, tuple)):
        return _head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        items = sorted((cbor(k), cbor(x)) for k, x in v.items())
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    raise GoldenError("cannot encode %s" % type(v).__name__)


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def cid(preimage: bytes) -> str:
    """CIDv1, dag-cbor, sha2-256, multibase base32 lower without padding (anetcid.Sum)."""
    raw = b"\x01\x71\x12\x20" + sha256(preimage)
    return "b" + b32encode(raw).decode().lower().rstrip("=")


def ed25519_public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)


def seed(vector_id: str, role: str) -> bytes:
    """A published seed: SHA-256("anet-golden/v016/<vector id>/<role>")."""
    return sha256(("anet-golden/v016/%s/%s" % (vector_id, role)).encode("utf-8"))


def b16(b: bytes) -> str:
    return bytes(b).hex()


GENERATORS = {}


def vector(vid: str, path: str):
    """Registers fn as the generator of vector vid, whose file is path ("<repository>/<path>")."""
    def register(fn):
        if vid in GENERATORS:
            raise GoldenError("vector %s registered twice" % vid)
        GENERATORS[vid] = (path, fn)
        return fn
    return register


def serialize(content) -> bytes:
    return (json.dumps(content, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main(argv) -> int:
    cmd = argv[0] if argv and argv[0] in ("check", "write") else "check"
    ids = [a for a in argv if a not in ("check", "write")] or sorted(GENERATORS)
    unknown = [i for i in ids if i not in GENERATORS]
    if unknown:
        print("unknown vector(s) %s; known: %s" % (" ".join(unknown), " ".join(sorted(GENERATORS))), file=sys.stderr)
        return 2
    bad = 0
    for vid in ids:
        path, fn = GENERATORS[vid]
        repo, rel = path.split("/", 1)
        if repo != "ANetCore":
            raise GoldenError("vector %s: only ANetCore files are known here" % vid)
        target = CORE_DIR / rel
        got = serialize(fn())
        if cmd == "write":
            target.write_bytes(got)
            print("%s: wrote %s" % (vid, path))
            continue
        have = target.read_bytes() if target.is_file() else None
        if have == got:
            print("%s: %s identical" % (vid, path))
        else:
            bad += 1
            print("%s: %s differs from what this implementation generates; regenerate and check the diff"
                  % (vid, path), file=sys.stderr)
    return 1 if bad else 0


# ---------------------------------------------------------------------------------------------
# KEL (KEL-1): KEL-2A, KEL-2B
# ---------------------------------------------------------------------------------------------
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


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
