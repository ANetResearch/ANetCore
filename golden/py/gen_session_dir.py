#!/usr/bin/env python3
"""Independent generator of the golden vectors SESSION-1 and DIR-1, and of the RELAYAUTH-3 pins.

It shares no code with the Go implementation: CoreDet CBOR and RFC 9180 HPKE (base mode, suite
DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305) are written out below on top of the
`cryptography` package (X25519, Ed25519, ChaCha20-Poly1305) and the standard library (hashlib,
hmac). Before generating anything it checks its HPKE against RFC 9180 Appendix A.2.1
(seal/testdata/rfc9180-a2-1.json).

  gen_session_dir.py            regenerate both vectors and compare them byte for byte with the
                                files in the repository (exit 1 on any difference)
  gen_session_dir.py --write    write the vectors
  gen_session_dir.py --relayauth3
                                print the RELAYAUTH-3 rows that golden/relayauth_v3_test.go pins

Every seed is SHA-256("anet-golden/v016/<vector>/<role>"); nothing here is a real key.
"""
import hashlib
import hmac
import json
import os
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.abspath(os.path.join(HERE, "..", ".."))
SESSION_FILE = os.path.join(CORE, "relayauth", "testdata", "vec-session-1.json")
DIR_FILE = os.path.join(CORE, "dirbox", "testdata", "vec-dir-1.json")
RFC9180_FILE = os.path.join(CORE, "seal", "testdata", "rfc9180-a2-1.json")


def seed(vector, role):
    return hashlib.sha256(("anet-golden/v016/%s/%s" % (vector, role)).encode()).digest()


# ---------------------------------------------------------------- CoreDet CBOR (RFC 8949 §4.2)

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


def cbor(v):
    if isinstance(v, bool) or v is None:
        raise TypeError("not used here")
    if isinstance(v, int):
        if v < 0:
            raise TypeError("negative integers are not used here")
        return _head(0, v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        items = sorted((cbor(k), cbor(x)) for k, x in v.items())  # bytewise order of encoded keys
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(type(v))


def cbor_map_in_order(pairs):
    """A map written in the order given (used only to make a non-canonical negative)."""
    return _head(5, len(pairs)) + b"".join(cbor(k) + cbor(x) for k, x in pairs)


# ---------------------------------------------------------------- HKDF-SHA256 (RFC 5869)

def hkdf_extract(salt, ikm):
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def hkdf(ikm, salt, info, length):
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


# ---------------------------------------------------------------- HPKE (RFC 9180), base mode, suite 1

KEM_ID, KDF_ID, AEAD_ID = 0x0020, 0x0001, 0x0003
KEM_SUITE = b"KEM" + struct.pack(">H", KEM_ID)
HPKE_SUITE = b"HPKE" + struct.pack(">HHH", KEM_ID, KDF_ID, AEAD_ID)


def labeled_extract(suite, salt, label, ikm):
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite, prk, label, info, length):
    return hkdf_expand(prk, struct.pack(">H", length) + b"HPKE-v1" + suite + label + info, length)


def x25519_pub(sk):
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def derive_key_pair(ikm):
    prk = labeled_extract(KEM_SUITE, b"", b"dkp_prk", ikm)
    sk = labeled_expand(KEM_SUITE, prk, b"sk", b"", 32)
    return sk, x25519_pub(sk)


def _shared_secret(dh, kem_context):
    prk = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh)
    return labeled_expand(KEM_SUITE, prk, b"shared_secret", kem_context, 32)


def _key_schedule(shared_secret, info):
    psk_id_hash = labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(HPKE_SUITE, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash  # mode_base
    secret = labeled_extract(HPKE_SUITE, shared_secret, b"secret", b"")
    key = labeled_expand(HPKE_SUITE, secret, b"key", context, 32)
    base_nonce = labeled_expand(HPKE_SUITE, secret, b"base_nonce", context, 12)
    return key, base_nonce


def hpke_seal(pk_r, info, aad, pt, ikm_e):
    """SetupBaseS with the ephemeral key DeriveKeyPair(ikm_e), then Seal at sequence 0."""
    sk_e, enc = derive_key_pair(ikm_e)
    dh = X25519PrivateKey.from_private_bytes(sk_e).exchange(X25519PublicKey.from_public_bytes(pk_r))
    key, nonce = _key_schedule(_shared_secret(dh, enc + pk_r), info)
    return enc, ChaCha20Poly1305(key).encrypt(nonce, pt, aad)


def hpke_open(sk_r, enc, info, aad, ct):
    pk_r = x25519_pub(sk_r)
    dh = X25519PrivateKey.from_private_bytes(sk_r).exchange(X25519PublicKey.from_public_bytes(enc))
    key, nonce = _key_schedule(_shared_secret(dh, enc + pk_r), info)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)


def check_rfc9180():
    """RFC 9180 A.2.1. ikmE is from the RFC; the rest is in seal/testdata/rfc9180-a2-1.json."""
    v = json.load(open(RFC9180_FILE))
    assert (v["kem_id"], v["kdf_id"], v["aead_id"]) == (KEM_ID, KDF_ID, AEAD_ID)
    ikm_e = bytes.fromhex("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b")
    sk_r, pk_r = derive_key_pair(bytes.fromhex(v["ikmR"]))
    assert pk_r.hex() == v["pkRm"], "DeriveKeyPair(ikmR) does not give pkRm"
    e = v["encryptions"][0]
    assert e["seq"] == 0
    enc, ct = hpke_seal(pk_r, bytes.fromhex(v["info"]), bytes.fromhex(e["aad"]), bytes.fromhex(e["pt"]), ikm_e)
    assert enc.hex() == v["enc"], "enc differs from RFC 9180 A.2.1"
    assert ct.hex() == e["ct"], "ciphertext differs from RFC 9180 A.2.1"
    assert hpke_open(sk_r, enc, bytes.fromhex(v["info"]), bytes.fromhex(e["aad"]), ct) == bytes.fromhex(e["pt"])


# ---------------------------------------------------------------- fixed identities of the vectors

AGENT_AID = "bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay"
OTHER_AID = "bafyreigoldenrecipient"
HUB_AID = "bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y"
OTHER_HUB_AID = "bafyreianotherhub"
TS = 1767225600000

# ---------------------------------------------------------------- SESSION-1 (L7, L8)

SESS_KEY_LABEL = b"anet-sess-key/v1"
SESS_MAC_LABEL = b"anet-sess-mac/v1"


def session_key_info(hub_aid, sid):
    return SESS_KEY_LABEL + b"\x00" + hub_aid.encode() + b"\x00" + sid


def session_mac_input(sid, ts, method, target, home, body):
    for f in (method, target, home):
        if "\x00" in f:
            raise ValueError("nul")
    return (SESS_MAC_LABEL + b"\x00" + sid + b"\x00" + str(ts).encode() + b"\x00" + method.encode() + b"\x00"
            + target.encode() + b"\x00" + home.encode() + b"\x00" + hashlib.sha256(body).digest())


def session_mac(k, sid, ts, method, target, home, body):
    return hmac.new(k, session_mac_input(sid, ts, method, target, home, body), hashlib.sha256).digest()


def flip(b, i=0):
    b = bytearray(b)
    b[i] ^= 0x01
    return bytes(b)


def gen_session_1():
    sid = seed("SESSION-1", "sid")[:16]
    k = seed("SESSION-1", "k_sess")
    ikm_r = seed("SESSION-1", "epk")
    ikm_e = seed("SESSION-1", "hpke-ephemeral")
    sk_r, epk = derive_key_pair(ikm_r)
    info = session_key_info(HUB_AID, sid)
    enc, ct = hpke_seal(epk, info, b"", k, ikm_e)
    assert hpke_open(sk_r, enc, info, b"", ct) == k

    def refused_key(name, error, hub_aid=HUB_AID, sid_=sid, enc_=enc, ct_=ct):
        return {"name": name, "hub_aid": hub_aid, "sid": sid_.hex(), "enc": enc_.hex(), "ct": ct_.hex(),
                "error": error}

    other_sid = seed("SESSION-1", "other-sid")[:16]
    key_refused = [
        refused_key("sealed by another hub", "session-key", hub_aid=OTHER_HUB_AID),
        refused_key("sealed for another session id", "session-key", sid_=other_sid),
        refused_key("ct with one byte changed", "session-key", ct_=flip(ct, 5)),
        refused_key("enc with one byte changed", "session-key", enc_=flip(enc, 7)),
        refused_key("ct one byte short", "session-key", ct_=ct[:-1]),
        refused_key("hub AID holding U+0000", "nul", hub_aid=HUB_AID[:8] + "\x00" + HUB_AID[8:]),
        refused_key("session id one byte short", "input", sid_=sid[:15]),
    ]

    body = b"\xa6" + seed("SESSION-1", "envelope") * 3  # stands for the envelope bytes of a send
    cases = [
        ("send with a home hint", TS, "POST", "/relay/send", OTHER_HUB_AID, body),
        ("send without a home hint", TS + 1, "POST", "/relay/send", "", body),
        ("empty body and a query", 7, "POST", "/relay/send?x=%2F1", "", b""),
    ]
    mac = []
    for name, ts, method, target, home, b in cases:
        mac.append({"name": name, "k_sess": k.hex(), "sid": sid.hex(), "ts": ts, "method": method,
                    "path_and_query": target, "home": home, "body": b.hex(),
                    "input": session_mac_input(sid, ts, method, target, home, b).hex(),
                    "mac": session_mac(k, sid, ts, method, target, home, b).hex()})

    base = mac[0]
    other_k = seed("SESSION-1", "other-k_sess")

    def refused_mac(name, error, **over):
        m = {key: base[key] for key in ("k_sess", "sid", "ts", "method", "path_and_query", "home", "body")}
        m.update(over)
        m["mac"] = base["mac"]
        return {"name": name, **m, "error": error}

    mac_refused = [
        refused_mac("body changed by one byte", "mac", body=flip(body, 40).hex()),
        refused_mac("body one byte longer", "mac", body=(body + b"\x00").hex()),
        refused_mac("home hint changed", "mac", home=HUB_AID),
        refused_mac("home hint removed", "mac", home=""),
        refused_mac("ts changed", "mac", ts=TS + 1),
        refused_mac("request target changed", "mac", path_and_query="/relay/send?"),
        refused_mac("method changed", "mac", method="PUT"),
        refused_mac("another session id", "mac", sid=other_sid.hex()),
        refused_mac("another session key", "mac", k_sess=other_k.hex()),
        refused_mac("byte moved from target to method", "mac", method="POST/", path_and_query="relay/send"),
        refused_mac("method holding U+0000", "nul", method="PO\x00ST"),
        refused_mac("request target holding U+0000", "nul", path_and_query="/relay/send\x00"),
        refused_mac("home hint holding U+0000", "nul", home=OTHER_HUB_AID + "\x00"),
    ]
    # The refused cases must really differ from the base, or the vector proves nothing.
    for r in mac_refused:
        if r["error"] == "mac":
            got = session_mac(bytes.fromhex(r["k_sess"]), bytes.fromhex(r["sid"]), r["ts"], r["method"],
                              r["path_and_query"], r["home"], bytes.fromhex(r["body"]))
            assert got.hex() != base["mac"], r["name"]

    return {
        "id": "SESSION-1",
        "about": ("First-contact session: L7 session key delivery (receiving side: open enc and ct with skR) "
                  "and L8 session MAC (input and output). Seeds: SHA-256(\"anet-golden/v016/SESSION-1/<role>\") for "
                  "roles sid (first 16 bytes), k_sess, epk (ikm of the daemon's one-time key), hpke-ephemeral "
                  "(ikm of the hub's HPKE ephemeral key), envelope, other-sid, other-k_sess. "
                  "Generated by golden/py/gen_session_dir.py."),
        "key_delivery": {"hub_aid": HUB_AID, "sid": sid.hex(), "k_sess": k.hex(), "ikmR": ikm_r.hex(),
                         "skR": sk_r.hex(), "epk": epk.hex(), "ikmE": ikm_e.hex(), "info": info.hex(),
                         "enc": enc.hex(), "ct": ct.hex()},
        "key_delivery_refused": key_refused,
        "mac": mac,
        "mac_refused": mac_refused,
    }


# ---------------------------------------------------------------- DIR-1 (L9, L10)

DIR_HASH_LABEL = b"anet-dir-hash/v1"
DIR_BOX_LABEL = b"anet-dir-box/v1"


def dir_hash(aid):
    return hashlib.sha256(DIR_HASH_LABEL + b"\x00" + aid.encode("utf-8")).digest()


def dir_key(aid):
    return hkdf(aid.encode("utf-8"), b"", DIR_BOX_LABEL, 32)


def dir_seal_plaintext(aid, pt, nonce, aad=None):
    return nonce + ChaCha20Poly1305(dir_key(aid)).encrypt(nonce, pt, dir_hash(aid) if aad is None else aad)


def entry_map(e):
    m = {1: e["aid"], 2: e["home"], 3: e["kel"], 4: e["keys"]}
    if "card" in e:
        m[5] = e["card"]
    if "notice" in e:
        m[6] = e["notice"]
    return m


def entry_json(e):
    out = {"aid": e["aid"], "home": e["home"], "kel": e["kel"].hex(), "keys": e["keys"].hex()}
    for k in ("card", "notice"):
        if k in e:
            out[k] = e[k].hex()
    return out


def gen_dir_1():
    full = {"aid": AGENT_AID, "home": HUB_AID,
            "kel": seed("DIR-1", "kel") + seed("DIR-1", "kel-2"),
            "keys": seed("DIR-1", "keys") * 2,
            "card": b'{"name":"golden agent","version":"1.0.0"}',
            "notice": seed("DIR-1", "notice")}
    minimal = {"aid": OTHER_AID, "home": OTHER_HUB_AID, "kel": seed("DIR-1", "kel-min"),
               "keys": seed("DIR-1", "keys-min")}
    cases = []
    for name, e, role in (("full entry", full, "nonce-full"), ("required keys only", minimal, "nonce-min")):
        pt = cbor(entry_map(e))
        nonce = seed("DIR-1", role)[:12]
        box = dir_seal_plaintext(e["aid"], pt, nonce)
        cases.append({"name": name, "aid": e["aid"], "entry": entry_json(e), "plaintext": pt.hex(),
                      "h": dir_hash(e["aid"]).hex(), "k": dir_key(e["aid"]).hex(), "nonce": nonce.hex(),
                      "box": box.hex()})

    a = full["aid"]
    box_a = bytes.fromhex(cases[0]["box"])
    nonce = seed("DIR-1", "nonce-refused")[:12]

    def sealed(pairs_or_map, in_order=False):
        pt = cbor_map_in_order(pairs_or_map) if in_order else cbor(pairs_or_map)
        return dir_seal_plaintext(a, pt, nonce).hex()

    base = entry_map(full)
    with7 = dict(base)
    with7[7] = b"\x01"
    without4 = {k: v for k, v in base.items() if k != 4}
    other = dict(base)
    other[1] = OTHER_AID
    kel_text = dict(base)
    kel_text[3] = "kel"
    empty_card = dict(base)
    empty_card[5] = b""
    unlabeled_h = hashlib.sha256(a.encode()).digest()
    refused = [
        {"name": "opened with another AID", "aid": OTHER_AID, "h": dir_hash(OTHER_AID).hex(),
         "box": box_a.hex(), "error": "open"},
        {"name": "filed under another AID's hash", "aid": a, "h": dir_hash(OTHER_AID).hex(),
         "box": box_a.hex(), "error": "hash"},
        {"name": "hash without its label", "aid": a, "h": unlabeled_h.hex(),
         "box": dir_seal_plaintext(a, cbor(base), nonce, aad=unlabeled_h).hex(), "error": "hash"},
        {"name": "box with one byte changed", "aid": a, "h": dir_hash(a).hex(),
         "box": flip(box_a, 20).hex(), "error": "open"},
        {"name": "nonce with one byte changed", "aid": a, "h": dir_hash(a).hex(),
         "box": flip(box_a, 3).hex(), "error": "open"},
        {"name": "box one byte short", "aid": a, "h": dir_hash(a).hex(), "box": box_a[:-1].hex(), "error": "open"},
        {"name": "shorter than a nonce and a tag", "aid": a, "h": dir_hash(a).hex(), "box": box_a[:27].hex(),
         "error": "open"},
        {"name": "sealed without the hash as aad", "aid": a, "h": dir_hash(a).hex(),
         "box": dir_seal_plaintext(a, cbor(base), nonce, aad=b"").hex(), "error": "open"},
        {"name": "sealed with the key of another AID", "aid": a, "h": dir_hash(a).hex(),
         "box": (nonce + ChaCha20Poly1305(dir_key(OTHER_AID)).encrypt(nonce, cbor(base), dir_hash(a))).hex(),
         "error": "open"},
        {"name": "unregistered key 7", "aid": a, "h": dir_hash(a).hex(), "box": sealed(with7), "error": "entry"},
        {"name": "key 4 (keys) missing", "aid": a, "h": dir_hash(a).hex(), "box": sealed(without4), "error": "entry"},
        {"name": "key 1 names another AID", "aid": a, "h": dir_hash(a).hex(), "box": sealed(other), "error": "entry"},
        {"name": "key 3 (kel) is a text string", "aid": a, "h": dir_hash(a).hex(), "box": sealed(kel_text),
         "error": "entry"},
        {"name": "empty card instead of no card", "aid": a, "h": dir_hash(a).hex(), "box": sealed(empty_card),
         "error": "entry"},
        {"name": "keys out of canonical order", "aid": a, "h": dir_hash(a).hex(),
         "box": sealed([(2, full["home"]), (1, a), (3, full["kel"]), (4, full["keys"])], in_order=True),
         "error": "entry"},
        {"name": "an array, not a map", "aid": a, "h": dir_hash(a).hex(),
         "box": dir_seal_plaintext(a, cbor([a, full["home"]]), nonce).hex(), "error": "entry"},
    ]
    hash_refused = [
        {"name": "empty AID", "aid": "", "error": "aid"},
        {"name": "AID holding U+0000", "aid": a[:6] + "\x00" + a[6:], "error": "aid"},
    ]
    return {
        "id": "DIR-1",
        "about": ("Directory box: L9 h, L10 K, the box under a fixed nonce, opening, and boxes that must not "
                  "open or must not decode. Seeds: SHA-256(\"anet-golden/v016/DIR-1/<role>\") for roles kel, kel-2, "
                  "keys, notice, kel-min, keys-min, nonce-full, nonce-min, nonce-refused (nonces: first 12 bytes). "
                  "kel, keys, card and notice are opaque to the box and are placeholders here. "
                  "Generated by golden/py/gen_session_dir.py."),
        "cases": cases,
        "refused": refused,
        "hash_refused": hash_refused,
    }


# ---------------------------------------------------------------- RELAYAUTH-3 (L22)

def relayauth_rows():
    """(action, signer, method, path, body) per pinned action; signer agent or peer-hub."""
    a = AGENT_AID
    return [
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
        ("fed_forward", "peer-hub", "POST", "/fed/v3/forward", b"\xa6\x01\x02"),
        ("fed_bucket", "peer-hub", "POST", "/fed/v3/directory:bucket", b'{"prefix":"AA","bits":8}'),
        ("fed_cards", "peer-hub", "GET", "/fed/v3/cards?cursor=0", b""),
    ]


def relayauth_preimage(action, aid, hub, ts, method, path, body):
    d = hashlib.sha256(method.encode() + b"\x00" + path.encode() + b"\x00" + body).digest()
    import base64
    digest = base64.urlsafe_b64encode(d).rstrip(b"=").decode()
    return "anet-relay/v2/%s/%s/%s/%d/%s" % (action, aid, hub, ts, digest)


def print_relayauth3():
    keys = {"agent": seed("RELAYAUTH-3", "agent"), "peer-hub": seed("RELAYAUTH-3", "peer-hub")}
    signer_aid = {"agent": AGENT_AID, "peer-hub": OTHER_HUB_AID}
    for role, s in keys.items():
        pub = Ed25519PrivateKey.from_private_bytes(s).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        print("// %s seed %s pub %s" % (role, s.hex(), pub.hex()))
    for action, signer, method, path, body in relayauth_rows():
        pre = relayauth_preimage(action, signer_aid[signer], HUB_AID, TS, method, path, body)
        sig = Ed25519PrivateKey.from_private_bytes(keys[signer]).sign(pre.encode())
        print('{%r, %r, %r, %r, %r,\n\t%r,\n\t%r},' % (action, signer, method, path, body.hex(), pre, sig.hex()))


# ---------------------------------------------------------------- main

def dump(v):
    return (json.dumps(v, indent=2) + "\n").encode()


def main(argv):
    check_rfc9180()
    if "--relayauth3" in argv:
        print_relayauth3()
        return 0
    out = {SESSION_FILE: dump(gen_session_1()), DIR_FILE: dump(gen_dir_1())}
    if "--write" in argv:
        for path, b in out.items():
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(b)
            print("wrote", os.path.relpath(path, CORE))
        return 0
    bad = 0
    for path, b in out.items():
        try:
            have = open(path, "rb").read()
        except FileNotFoundError:
            have = None
        if have != b:
            print("DIFFERS", os.path.relpath(path, CORE))
            bad = 1
        else:
            print("same", os.path.relpath(path, CORE))
    return bad


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
