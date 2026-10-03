#!/usr/bin/env python3
"""gen_v016.py - independent generator of the ANetCore v0.16 golden vectors.

Pure Python (standard library only for the vectors below); it never reads Go output. Each vector
has one generator function, registered in VECTORS by its id. The Go tests next to each vector file
recompute every value with the Go implementation and must agree byte for byte.

  python3 gen_v016.py                write every vector file
  python3 gen_v016.py --check        regenerate in memory and compare byte for byte with the
                                     committed files (the golden cross-check); exit 1 on any
                                     difference
  python3 gen_v016.py [--check] ID…  only these vectors

Every input that would be random is derived from a public label (no real key or token is in any
file): SHA-256("anet-golden/v016/<vector>/<role>"). Paths are relative to the ANetCore root.
"""

import hashlib
import hmac
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

U64 = 1 << 64
MAX_SUM = (1 << 63) - 1


# ---------------------------------------------------------------- common helpers


def sha256(b):
    return hashlib.sha256(b).digest()


def u64be(n):
    return struct.pack(">Q", n % U64)


def label_seed(vector, role):
    return sha256(("anet-golden/v016/%s/%s" % (vector, role)).encode())


class Stream:
    """The test random source: SHA-256(UTF-8(label) || u64be(i)) for i = 0, 1, …, concatenated."""

    def __init__(self, label):
        self.label = label.encode()
        self.i = 0
        self.buf = b""

    def read(self, n):
        while len(self.buf) < n:
            self.buf += sha256(self.label + u64be(self.i))
            self.i += 1
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def cid_of(digest):
    """CIDv1, dag-cbor (0x71), sha2-256 multihash, base32 lower without padding: the form of an AID."""
    import base64

    raw = bytes([0x01, 0x71, 0x12, 0x20]) + digest
    return "b" + base64.b32encode(raw).decode().lower().rstrip("=")


def aid_for(vector, role):
    return cid_of(label_seed(vector, "aid/" + role))


# CoreDet (RFC 8949 §4.2 core deterministic encoding): only the types these vectors use.


def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 1 << 8:
        return bytes([major << 5 | 24, n])
    if n < 1 << 16:
        return bytes([major << 5 | 25]) + struct.pack(">H", n)
    if n < 1 << 32:
        return bytes([major << 5 | 26]) + struct.pack(">I", n)
    return bytes([major << 5 | 27]) + struct.pack(">Q", n)


def coredet(v):
    if isinstance(v, bool) or v is None:
        raise TypeError("not used by these vectors")
    if isinstance(v, int):
        if v < 0:
            return _head(1, -1 - v)
        return _head(0, v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(coredet(x) for x in v)
    if isinstance(v, dict):
        items = sorted((coredet(k), coredet(x)) for k, x in v.items())  # bytewise key order
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(type(v))


def hx(b):
    return b.hex()


# ---------------------------------------------------------------- LIAB-1 (labels L25, L26)

LEAF_LABEL = b"anet-liab-leaf/v1"
NODE_LABEL = b"anet-liab-node/v1"


def liab_content(aid, to_day, balance):
    return coredet({1: aid, 2: to_day, 3: balance})


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
                raise ValueError("sum over 2^63-1")
            nxt.append((liab_node(l, r), total))
        levels.append(nxt)
        cur = nxt
    return levels


def liab_proof(entries, levels, to_day, index):
    a, b, s = entries[index]
    path = []
    i = index
    for lvl in range(len(levels) - 1):
        sib, side = (i + 1, "R") if i % 2 == 0 else (i - 1, "L")
        h, sm = levels[lvl][sib]
        path.append({"h": hx(h), "sum": sm, "side": side})
        i //= 2
    return {"to_day": to_day, "aid": a, "balance": b, "salt": hx(s), "path": path}


def copy_proof(p):
    return json.loads(json.dumps(p))


def gen_liab_1():
    V = "LIAB-1"
    to_day = 20454  # 2026-01-01
    balances = [120, 0, 7919, 1000000, 42]
    accounts = [(aid_for(V, "account-%d" % (i + 1)), b) for i, b in enumerate(balances)]
    rand_label = "anet-golden/v016/%s/rand" % V

    # the two hashes, alone
    leaf_salt = label_seed(V, "salt/leaf")
    a3, b3 = accounts[2]
    pad_salt = label_seed(V, "salt/padding")
    lnode = (label_seed(V, "node/left"), 5)
    rnode = (label_seed(V, "node/right"), 7)

    entries = liab_build(accounts, to_day, Stream(rand_label))
    levels = liab_levels(entries, to_day)
    root, outstanding = levels[-1][0]
    assert outstanding == sum(balances)
    third = next(i for i, e in enumerate(entries) if e[0] == a3)
    proof = liab_proof(entries, levels, to_day, third)

    neg = []

    # moved sums: take k from one sibling's sum and add it to another's. The root sum is the same,
    # so a node hash that does not cover the child sums (the original Maxwell scheme) would accept.
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
    victim = (accounts[0][0], 5, label_seed(V, "overflow/victim"))
    giant = (aid_for(V, "overflow-giant"), U64 - 3, label_seed(V, "overflow/giant"))
    others = [("", 0, label_seed(V, "overflow/pad-%d" % k)) for k in range(14)]
    ov_entries = [victim, giant] + others
    ov_levels = liab_levels(ov_entries, to_day, wrap=True)
    ov_root, ov_sum = ov_levels[-1][0]
    assert ov_sum == 2
    neg.append({"name": "sum_wraps", "note": "a sibling sum of 2^64 - 3: taken mod 2^64 the root sum is 2, and every hash matches",
                "proof": liab_proof(ov_entries, ov_levels, to_day, 0), "root": hx(ov_root), "outstanding": ov_sum, "depth": 4, "error": "overflow"})

    big = (aid_for(V, "overflow-big"), 1 << 63, label_seed(V, "overflow/big"))
    big_entries = [victim, big] + others
    big_levels = liab_levels(big_entries, to_day, wrap=True)
    big_root, big_sum = big_levels[-1][0]
    neg.append({"name": "sum_over_max", "note": "a sibling sum of 2^63: no wrap, but the sums and the outstanding are over 2^63 - 1",
                "proof": liab_proof(big_entries, big_levels, to_day, 0), "root": hx(big_root), "outstanding": big_sum, "depth": 4, "error": "overflow"})

    return {
        "id": V,
        "description": "Liability tree: the L25 leaf and L26 node hashes; 5 accounts padded to 16 leaves with a fixed random source; the root, outstanding and depth; the third account's proof in its response form; refused proofs.",
        "labels": {"leaf": LEAF_LABEL.decode(), "node": NODE_LABEL.decode()},
        "leaf": {"aid": a3, "to_day": to_day, "balance": b3, "salt": hx(leaf_salt),
                 "content": hx(liab_content(a3, to_day, b3)),
                 "preimage": hx(liab_leaf_preimage(a3, to_day, b3, leaf_salt)),
                 "hash": hx(liab_leaf(a3, to_day, b3, leaf_salt))},
        "padding_leaf": {"aid": "", "to_day": to_day, "balance": 0, "salt": hx(pad_salt),
                         "content": hx(liab_content("", to_day, 0)),
                         "preimage": hx(liab_leaf_preimage("", to_day, 0, pad_salt)),
                         "hash": hx(liab_leaf("", to_day, 0, pad_salt))},
        "node": {"left": {"h": hx(lnode[0]), "sum": lnode[1]}, "right": {"h": hx(rnode[0]), "sum": rnode[1]},
                 "preimage": hx(liab_node_preimage(lnode, rnode)), "hash": hx(liab_node(lnode, rnode)), "sum": lnode[1] + rnode[1]},
        "build": {
            "rand": "SHA-256(UTF-8(rand_label) || u64be(i)) for i = 0, 1, ..., concatenated; consumed by liabtree.Build",
            "rand_label": rand_label,
            "to_day": to_day,
            "accounts": [{"aid": a, "balance": b} for a, b in accounts],
            "leaves": len(entries),
            "depth": len(levels) - 1,
            "entries": [{"aid": a, "balance": b, "salt": hx(s), "hash": hx(levels[0][k][0])} for k, (a, b, s) in enumerate(entries)],
            "root": hx(root),
            "outstanding": outstanding,
        },
        "proof": proof,
        "negatives": neg,
    }


# ---------------------------------------------------------------- REGPOW-1 (labels L23, L24)

POW_LABEL = b"anet-regpow/v1"
SEED_LABEL = b"anet-regpow-seed/v1"
HOUR_MS = 3600000


def pow_seed(key, hour):
    return hmac.new(key, SEED_LABEL + u64be(hour), hashlib.sha256).digest()


def pow_prefix(hub_aid, aid, seed):
    return POW_LABEL + b"\x00" + hub_aid.encode() + b"\x00" + aid.encode() + b"\x00" + seed


def zero_bits(h):
    n = int.from_bytes(h, "big")
    return 256 - n.bit_length()


def pow_search(prefix, accept):
    """The smallest counter c whose nonce u64be(c) gives a hash accepted by accept(zero bits)."""
    base = hashlib.sha256(prefix)
    c = 0
    while True:
        h = base.copy()
        h.update(u64be(c))
        if accept(zero_bits(h.digest())):
            return c
        c += 1


def gen_regpow_1():
    V = "REGPOW-1"
    bits = 22
    key = label_seed(V, "pow_key")
    ms = 1767225600000 + 5400000  # 2026-01-01T01:30:00Z
    hour = ms // HOUR_MS
    seed = pow_seed(key, hour)
    hub = aid_for(V, "hub")
    aid = aid_for(V, "agent")
    pre = pow_prefix(hub, aid, seed)

    def solution(name, c, note):
        nonce = u64be(c)
        h = sha256(pre + nonce)
        z = zero_bits(h)
        return {"name": name, "note": note, "counter": c, "nonce": hx(nonce), "preimage": hx(pre + nonce), "hash": hx(h), "zero_bits": z,
                "check": {str(b): z >= b for b in (8, 21, 22, 23)}}

    c22 = pow_search(pre, lambda z: z >= 22)
    c21 = pow_search(pre, lambda z: z == 21)
    c8 = pow_search(pre, lambda z: z >= 8)
    nonce22 = u64be(c22)
    prev_seed = pow_seed(key, hour - 1)
    return {
        "id": V,
        "description": "Registration proof of work: the L24 seed of an hour under a fixed pow_key; the L23 hash; the smallest counters whose 8-byte big-endian nonce passes 22 bits, has exactly 21 bits, and passes 8 bits; refused inputs.",
        "labels": {"hash": POW_LABEL.decode(), "seed": SEED_LABEL.decode()},
        "bits": bits,
        "seed": {"pow_key": hx(key), "ms": ms, "hour": hour, "message": hx(SEED_LABEL + u64be(hour)), "seed": hx(seed), "not_after": (hour + 2) * HOUR_MS},
        "hub_aid": hub,
        "aid": aid,
        "prefix": hx(pre),
        "solutions": [
            solution("pass_22", c22, "the first nonce with at least 22 leading zero bits"),
            solution("fail_21", c21, "the first nonce with exactly 21 leading zero bits: passes 21, fails 22"),
            solution("fast_8", c8, "the first nonce with at least 8 leading zero bits"),
        ],
        "negatives": [
            {"name": "previous_hour_seed", "note": "pass_22's nonce against the previous hour's seed", "hub_aid": hub, "aid": aid,
             "seed": hx(prev_seed), "nonce": hx(nonce22), "hash": hx(sha256(pow_prefix(hub, aid, prev_seed) + nonce22)), "error": ""},
            {"name": "other_hub", "note": "pass_22's nonce for another hub", "hub_aid": aid_for(V, "other-hub"), "aid": aid,
             "seed": hx(seed), "nonce": hx(nonce22), "hash": hx(sha256(pow_prefix(aid_for(V, "other-hub"), aid, seed) + nonce22)), "error": ""},
            {"name": "empty_nonce", "note": "a nonce is 1 to 32 bytes", "hub_aid": hub, "aid": aid, "seed": hx(seed), "nonce": "", "error": "nonce"},
            {"name": "nonce_33_bytes", "note": "a nonce is 1 to 32 bytes", "hub_aid": hub, "aid": aid, "seed": hx(seed), "nonce": "00" * 33, "error": "nonce"},
            {"name": "hub_aid_nul", "note": "U+0000 in hub_aid (CORE-E9)", "hub_aid": hub[:8] + "\u0000" + hub[8:], "aid": aid, "seed": hx(seed), "nonce": hx(nonce22), "error": "nul"},
            {"name": "aid_nul", "note": "U+0000 in aid (CORE-E9)", "hub_aid": hub, "aid": aid[:8] + "\u0000" + aid[8:], "seed": hx(seed), "nonce": hx(nonce22), "error": "nul"},
            {"name": "boundary_moved", "note": "hub_aid + U+0000 + the start of aid, then the rest of aid: the same hash input bytes as aid_nul with the boundary moved; both refused (CORE-E9)",
             "hub_aid": hub + "\u0000" + aid[:8], "aid": aid[8:], "seed": hx(seed), "nonce": hx(nonce22), "error": "nul"},
        ],
    }


# ---------------------------------------------------------------- driver

VECTORS = {
    "LIAB-1": ("liabtree/testdata/vec-liab-1.json", gen_liab_1),
    "REGPOW-1": ("regpow/testdata/vec-regpow-1.json", gen_regpow_1),
}


def render(v):
    return (json.dumps(v, indent=2, ensure_ascii=True) + "\n").encode()


def main(argv):
    check = "--check" in argv
    ids = [a for a in argv if not a.startswith("--")] or list(VECTORS)
    bad = 0
    for vid in ids:
        if vid not in VECTORS:
            print("unknown vector %s (known: %s)" % (vid, ", ".join(VECTORS)), file=sys.stderr)
            return 2
        rel, fn = VECTORS[vid]
        data = render(fn())
        path = os.path.join(ROOT, rel)
        if check:
            try:
                with open(path, "rb") as f:
                    have = f.read()
            except FileNotFoundError:
                have = None
            if have != data:
                bad += 1
                print("%s: %s differs from the regenerated vector; run gen_v016.py %s and review the diff" % (vid, rel, vid), file=sys.stderr)
            else:
                print("%s: %s matches" % (vid, rel))
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(data)
            print("%s: wrote %s" % (vid, rel))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
