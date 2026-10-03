#!/usr/bin/env python3
"""gen_v016.py: the independent implementation of the ANetCore v0.16 golden vectors (core §5, CORE-G3).

Pure Python: nothing here calls into Go or shares code with it. Each vector is rebuilt from the
public labels its seeds derive from (CORE-G5) and written in the JSON form the Go tests write
(two-space indent, final newline), so the CI job golden-xcheck compares the two implementations
byte for byte by regenerating the files and diffing them with the committed ones.

  gen_v016.py                  regenerate every vector this file knows into the repository
  gen_v016.py --check          regenerate in memory and fail on any difference (golden-xcheck)
  gen_v016.py [--check] ID…    only these vectors (for example KEL-2A KEL-2B)

Environment: Python 3 with the cryptography package (Ed25519).

Each work item adds its vectors as a section below and registers them in VECTORS. Sections so far:
  CoreDet and CID   the subset of RFC 8949 §4.2 the sections below need
  KEL (KEL-1)       KEL-2A, KEL-2B: KEL v2 events, preimages (L17), event ids, signatures, states
"""

import hashlib
import json
import os
import sys
from base64 import b32encode

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


# ---- CoreDet and CID ------------------------------------------------------------------------------
#
# CoreDet is RFC 8949 §4.2 core deterministic encoding: shortest-form integers and lengths, definite
# lengths, map keys sorted by the bytewise order of their encodings, no tags.


def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError("integer too large")


def coredet(v):
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        if v < 0:
            raise ValueError("negative integers are not used here")
        return _head(0, v)
    if isinstance(v, (bytes, bytearray)):
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, (list, tuple)):
        return _head(4, len(v)) + b"".join(coredet(x) for x in v)
    if isinstance(v, dict):
        items = sorted((coredet(k), coredet(x)) for k, x in v.items())
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(type(v))


def cid(preimage):
    """CIDv1, dag-cbor, sha2-256, multibase base32 lower without padding (anetcid.Sum)."""
    raw = b"\x01\x71\x12\x20" + hashlib.sha256(preimage).digest()
    return "b" + b32encode(raw).decode().lower().rstrip("=")


def seed_key(label):
    """The Ed25519 key whose seed is SHA-256(label)."""
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def pub(k):
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def dump(v):
    """The JSON form both generators write."""
    return (json.dumps(v, indent=2) + "\n").encode()


# ---- KEL (KEL-1): KEL-2A, KEL-2B --------------------------------------------------------------------
#
# KeyEvent (core §2.6): 0 t_obj "anet.kel/2", 1 aid (not in the icp), 2 seq, 3 prev (not in the icp),
# 4 t, 5 keys, 6 next (icp and rot), 7 kt = 1, 8 ts, 9 witnesses (a toad-1 rot), 11 toad (icp and rot,
# written even when 0), 12 emergency (a rot, only true). SignedEvent: 1 event, 2 sig, 3 event_id. The
# icp is signed by k0, a rot or a dip by the key it reveals (L17). AID = CID(icp preimage).

KEL_TYPE = "anet.kel/2"
MINUTE = 60 * 1000
HUB_T0 = 1760000000000
AGENT_T0 = 1760000300000

ABOUT_2A = ("KEL v2 hub identity (toad 0): icp, rot 1 (setup-recovery), rot 2 (emergency), dip 3. "
            "Key seeds are SHA-256 of the labels. The icp is signed by k0, every rot and dip by the key it reveals. "
            "preimage is coredet(KeyEvent) (L17), event_id its CID, kel is MarshalKEL.")
ABOUT_2B = ("KEL v2 agent identity (toad 1): icp (witness pending), rot 1 (designates W1), rot 2 (moves to W2), dip 3. "
            "W1 is the hub incepted from the labels given, W2 the KEL-2A hub. "
            "Key seeds are SHA-256 of the labels. The icp is signed by k0, every rot and dip by the key it reveals. "
            "preimage is coredet(KeyEvent) (L17), event_id its CID, kel is MarshalKEL.")


class KEL:
    """A KEL being written: the events as maps, with their preimages, ids and signatures."""

    def __init__(self):
        self.events = []  # (event map, preimage, event_id, signature)

    @property
    def aid(self):
        return self.events[0][2]

    def add(self, event, signer):
        if self.events:
            event[1] = self.aid
            event[2] = len(self.events)
            event[3] = self.events[-1][2]
        pre = coredet(event)
        self.events.append((event, pre, cid(pre), signer.sign(pre)))
        return self

    def wire(self):
        return coredet([{1: e, 2: sig, 3: eid} for e, _, eid, sig in self.events])


def icp(k0, k1, ts, toad):
    return {0: KEL_TYPE, 2: 0, 4: "icp", 5: [pub(k0)], 6: hashlib.sha256(pub(k1)).digest(), 7: 1, 8: ts, 11: toad}


def rot(rev, nxt, ts, toad, witness=None, emergency=False):
    e = {0: KEL_TYPE, 4: "rot", 5: [pub(rev)], 6: hashlib.sha256(pub(nxt)).digest(), 7: 1, 8: ts, 11: toad}
    if witness is not None:
        e[9] = [witness]
    if emergency:
        e[12] = True
    return e


def dip(rev, ts):
    return {0: KEL_TYPE, 4: "dip", 5: [pub(rev)], 7: 1, 8: ts}


def vec_keys(vid):
    labels = ["anet-golden/v016/%s/k%d" % (vid, i) for i in range(4)]
    return labels, [seed_key(l) for l in labels]


def kel_2a():
    _, k = vec_keys("KEL-2A")
    kel = KEL().add(icp(k[0], k[1], HUB_T0, 0), k[0])
    kel.add(rot(k[1], k[2], HUB_T0 + MINUTE, 0), k[1])
    kel.add(rot(k[2], k[3], HUB_T0 + 2 * MINUTE, 0, emergency=True), k[2])
    kel.add(dip(k[3], HUB_T0 + 3 * MINUTE), k[3])
    return kel


W1_LABELS = ["anet-golden/v016/KEL-2B/w1-k0", "anet-golden/v016/KEL-2B/w1-k1"]


def kel_w1():
    k0, k1 = (seed_key(l) for l in W1_LABELS)
    return KEL().add(icp(k0, k1, HUB_T0, 0), k0)


def kel_2b():
    _, k = vec_keys("KEL-2B")
    w1, w2 = kel_w1().aid, kel_2a().aid
    kel = KEL().add(icp(k[0], k[1], AGENT_T0, 1), k[0])
    kel.add(rot(k[1], k[2], AGENT_T0 + MINUTE, 1, witness=w1), k[1])
    kel.add(rot(k[2], k[3], AGENT_T0 + 2 * MINUTE, 1, witness=w2), k[2])
    kel.add(dip(k[3], AGENT_T0 + 3 * MINUTE), k[3])
    return kel


def kel_states(kel, names):
    """The key states the KEL v2 replay rules give each event (KEL §2.2), computed from the maps."""
    states = []
    toad, witness = None, ""
    for i, (e, _, _, _) in enumerate(kel.events):
        t = e[4]
        if t in ("icp", "rot"):
            toad = e[11]
            if 9 in e:
                witness = e[9][0]
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


def kel_vector(vid, about, kel, witnesses):
    labels, keys = vec_keys(vid)
    names = {}
    key_list = []
    for i, (l, k) in enumerate(zip(labels, keys)):
        names[pub(k)] = "k%d" % i
        key_list.append({"name": "k%d" % i, "label": l, "pub": pub(k).hex()})
    return {
        "id": vid,
        "about": about,
        "keys": key_list,
        "witnesses": witnesses,
        "aid": kel.aid,
        "events": [{"seq": i, "t": e[4], "signer": names[e[5][0]], "preimage": pre.hex(), "event_id": eid,
                    "sig": sig.hex()} for i, (e, pre, eid, sig) in enumerate(kel.events)],
        "kel": kel.wire().hex(),
        "states": kel_states(kel, names),
    }


def gen_kel_2a():
    return dump(kel_vector("KEL-2A", ABOUT_2A, kel_2a(), []))


def gen_kel_2b():
    w1, a = kel_w1(), kel_2a()
    return dump(kel_vector("KEL-2B", ABOUT_2B, kel_2b(), [
        {"name": "W1", "aid": w1.aid, "labels": W1_LABELS, "kel": w1.wire().hex()},
        {"name": "W2", "aid": a.aid, "labels": [], "kel": a.wire().hex()},
    ]))


# ---- registry and driver ------------------------------------------------------------------------------

VECTORS = {
    "KEL-2A": ("identity/testdata/vec-kel-2a.json", gen_kel_2a),
    "KEL-2B": ("identity/testdata/vec-kel-2b.json", gen_kel_2b),
}


def main(argv):
    check = "--check" in argv
    ids = [a for a in argv if not a.startswith("--")] or list(VECTORS)
    unknown = [i for i in ids if i not in VECTORS]
    if unknown:
        print("unknown vector(s): %s; known: %s" % (" ".join(unknown), " ".join(VECTORS)), file=sys.stderr)
        return 2
    bad = 0
    for vid in ids:
        rel, gen = VECTORS[vid]
        path = os.path.join(ROOT, rel)
        got = gen()
        if check:
            try:
                with open(path, "rb") as f:
                    have = f.read()
            except FileNotFoundError:
                have = None
            if have != got:
                bad += 1
                print("%s: %s differs from what Python generates" % (vid, rel), file=sys.stderr)
            else:
                print("%s: %s identical" % (vid, rel))
        else:
            with open(path, "wb") as f:
                f.write(got)
            print("%s: wrote %s" % (vid, rel))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
