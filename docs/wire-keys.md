# anet 0.3.0 wire keys

<!-- Generated from wire/registry.json by `go run ./wire/gen`. Do not edit by hand. -->

This is the register of everything anet 0.3.0 puts on the wire or under a signature: key numbers and
types of every CBOR object, domain-separation labels, relayauth actions, reason codes, the hub API,
the control-plane fields other components rely on, A2A metadata keys and evidence events.
`wire/registry.json` is the source; `TestWireRegistry` in each repository checks the code against it.

Key numbers, labels, actions and codes are never reused: a removed key is *retired* and refused when
present; a *reserved* key has never been assigned and is refused too. CBOR is CoreDet (RFC 8949 §4.2
deterministic encoding, no tags); signed bodies travel as byte strings holding their CoreDet encoding.

## Versions

| | Layer | 0.3.0 | Where | Constant |
|---|---|---|---|---|
| V1 | release | ANetCore v0.16.0; anet 0.3.0; ANetHub 0.3.0; ANetLink 0.2.0 (C1 v1) | Go module tags, go.mod | ANetHub internal/aghub RequiredAnet = "0.3.0" |
| V2 | hub wire | X-ANet-Wire: 3 | request and response header | ANetHub wireVersion = 3; ANet hubapi.WireVersion = 3 |
| V3 | outer envelope | v = 2: key 7 access required, key 8 exp optional | outer key 1 | seal.EnvelopeVersion = 2 |
| V4 | HPKE info label | anet-seal/v2; second layer anet-ix/v2 | info map key 1 | seal.HPKELabel, seal.IXLabel |
| V5 | layer-1 plaintext | Wrap (with or without a second layer) | Wrap | seal |
| V6 | inner | adds 11 notice, 14 grant, 15 rk; 21 retired; 10 and 12 conditional; preimage v2 | SealedInner | seal.SigLabel |
| V7 | encryption key set | anet.enckeys/2: <= 32 keys, each <= 2 days, key 5 mbox required | key set key 0 | seal.EncKeySetType |
| V8 | KEL | KEL v2: key 0 anet.kel/2; icp, rot, dip only; keys 9, 11, 12; every identity re-incepted | event key 0 | identity.KELType |
| V9 | identity file | anet.identity/2 | file key 0 | identity |
| V10 | new signed objects | anet.cap/1, anet.ksn/1, anet.receipt/2, anet.review/2, anet.review-att/1 | body key 0 | - |
| V11 | relayauth | preimage anet-relay/v2/ unchanged; the action set of relayauth.actions; replay rule RC1 | X-ANet-* headers | relayauth |
| V12 | p2p frames | v: 3: adds dack, addr; removes not_delivered, reach, reachable | frame v | ANet module/p2p WireVersion = 3; tools/anetpeer |
| V13 | C1 (ANet <-> ANetLink) | v1: CBOR only, /v1/* | URL path prefix | ANet provider/anetlink; ANetLink northbound/c1serv |
| V14 | A2A card | anet-relay/v2 binding; anet-p2p/v1 and anet-pricing/v1 removed; anet-price/v1 (extended card only), anet-preview/v1 | card URIs | a2acard.BindingRelayURI; ANet module/card.go |
| V15 | evidence and payment | evidence v2; supply chain v2 (anet.supply.epoch, ael VersionMajor2); vouchers removed | body key 0; ael EventType | evidence, ael |
| V16 | local data | PRAGMA user_version = 3 (interactions.db, hub.db); enc_keys.cbor v = 2; removed config.json keys refuse to start | SQLite header; file key | ANet internal/runtime/interactions; ANetHub internal/aghub |
| V17 | local A2A | A2A 1.0; error detail domain agentnetwork.org.cn | - | module/a2a |

## Objects

Types: `uint`, `int`, `tstr`, `bstr`, `bool`, `float`, `any`, `map`; `<X>` is object X; `bstr<X>` a byte
string holding CoreDet(X); `[T]` an array of T. Objects marked *typed* carry their type tag in key 0.

### Sealed envelope

#### SealedEnvelope

Outer sealed envelope v2, the only part a hub sees. Keys 0-63 must be understood; >= 64 are kept and digested.

*keys 0–63 must be understood; keys ≥ 64 may be ignored but stay covered; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | — | — | reserved | — |
| 1 | `v` | `uint` = `2` | required | outer version; anything but 2 is bad-version |
| 2 | `to` | `tstr` | required | recipient AID |
| 3 | `suite` | `uint` | required | 1 = DHKEM-X25519 / HKDF-SHA256 / ChaCha20-Poly1305; 2 reserved for a post-quantum suite |
| 4 | `kid` | `bstr` (16 bytes) | required | kid of one of the recipient's encryption epoch keys; never an interaction key |
| 5 | `enc` | `bstr` | required | layer-1 HPKE enc, Nenc bytes |
| 6 | `ct` | `bstr` | required | layer-1 ciphertext; the plaintext is Wrap |
| 7 | `access` | `<Access>` | required | delivery credential; outside the HPKE info, the inner signature and env_digest |
| 8 | `exp` | `uint` | optional | expiry of a one-shot envelope; when present it equals inner key 8 (else exp-mismatch); queued envelopes never carry it |
| 9–63 | — | — | reserved | unknown-critical-field; the hub answers 400 bad_envelope |

#### Access

Delivery credential in outer key 7.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `kind` | `uint` | required | 0 = first-contact session; 1 = capability; 2 reserved for an anonymous first-contact token (refused in 0.3.0) |
| 2 | `cap` | `<Cap>` | if kind = 1; forbidden when kind = 0 | — |
| 3 | `proof` | `bstr` (64 bytes) | if kind = 1; forbidden when kind = 0 | proof of possession, Ed25519 by the holder key (L5) |

#### Cap

Capability as carried on the wire.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `body` | `bstr<CapBody>` | required | coredet(CapBody) |
| 2 | `sig` | `bstr` (64 bytes) | required | Ed25519 over body by the mailbox signing key |

#### CapBody

Signed body of a capability issued by the recipient.

*typed `anet.cap/1`; closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `t` | `tstr` = `anet.cap/1` | required | type tag |
| 1 | `owner` | `tstr` | required | issuer AID; must equal outer to |
| 2 | `epoch` | `uint` | required | must equal the owner's current mbox.epoch (>= 1) |
| 3 | `cap_id` | `bstr` (16 bytes) | required | random |
| 4 | `class` | `uint` | required | 1 = contact; 2 = stranger |
| 5 | `cap_exp` | `uint` | required | expiry; accepted window now - 5 min <= cap_exp <= now + 31 days |
| 6 | `holder` | `bstr` (32 bytes) | required | holder Ed25519 public key, new for every capability |

#### Wrap

Layer-1 plaintext. Unknown keys 0-63 are bad-wrap; >= 64 are ignored.

*keys 0–63 must be understood; keys ≥ 64 may be ignored but stay covered.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | — | — | reserved | — |
| 1 | `ikid` | `bstr` (16 bytes) | if present exactly when there is a second layer, together with key 2 | KID(suite2, rk.pub) |
| 2 | `enc2` | `bstr` | if with key 1 | layer-2 HPKE enc |
| 3 | `body` | `bstr` | required | layer-2 ciphertext, or coredet(SealedInner) when there is no second layer |
| 4–20 | — | — | reserved | — |
| 21 | `pad` | `bstr` | required | all-zero Padme padding: len(coredet(Wrap)) falls on a Padme step |
| 22–63 | — | — | reserved | — |

#### SealedInner

Inner signed message v2 (no version field; it takes effect with outer v = 2).

*keys 0–63 must be understood; keys ≥ 64 may be ignored but stay covered; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | — | — | forbidden | preimage only (label) |
| 1 | `from` | `tstr` | required | sender AID; no U+0000 |
| 2 | `key_state_seq` | `uint` | required | key state the signature uses |
| 3 | `to` | `tstr` | required | must equal outer to; no U+0000 |
| 4 | `type` | `tstr` | required | inner type (L39) |
| 5 | `ix` | `tstr` | required | interaction id; no U+0000 |
| 6 | `mid` | `bstr` (16 bytes) | required | message id; (from, mid) is the replay key |
| 7 | `ts` | `uint` | required | send time |
| 8 | `exp` | `uint` | required | exp - ts <= 15 days |
| 9 | `body` | `bstr` | required | body; the signature preimage holds its SHA-256 |
| 10 | `kel` | `bstr` | if forbidden in preview frames, required in every other type | sender KEL v2, <= 256 events, <= 64 KiB |
| 11 | `notice` | `[bstr<NoticeWire>]` | if present exactly when key 10 is | witness notices; exactly one in 0.3.0; each <= 1024 bytes |
| 12 | `keys` | `bstr<SignedEncKeySet>` | if forbidden in preview frames, required in every other type | — |
| 13 | — | — | reserved | proposed once for a witness KEL; not adopted |
| 14 | `grant` | `<Grant>` | optional | forbidden in preview frames, after-the-fact refusal notices and anet.card/1 |
| 15 | `rk` | `<RK>` | if while the sender still holds its interaction key for this interaction | sender's interaction public key |
| 16–19 | — | — | reserved | — |
| 20 | `sig` | `bstr` (64 bytes) | required | Ed25519 over the v2 signature preimage (L3) |
| 21 | — | — | retired | was `pad`. unknown-critical-field |
| 22–29 | — | — | reserved | — |
| 30–34 | — | — | forbidden | preimage only (enc1, kid, suite, ikid, enc2) |
| 35–63 | — | — | reserved | — |

#### Grant

Capability handed to the recipient inside the sealed message (inner key 14).

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `cap` | `<Cap>` | required | — |
| 2 | `holder_seed` | `bstr` (32 bytes) | required | holder Ed25519 private seed |
| 3 | `home` | `tstr` | required | issuer's hub AID (a routing hint, not a URL) |
| 4 | `ix` | `tstr` | optional | present: a one-shot capability for this interaction only; must equal inner ix |
| 5 | `p2p` | `tstr` | optional | issuer's direct address host:port; only with class = 1 and no key 4 |
| 6 | `pay` | `bool` | optional | true: the issuer prices a capability; only without key 4 |

#### RK

Interaction public key (inner key 15).

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `suite` | `uint` = `1` | required | — |
| 2 | `pub` | `bstr` | required | 32 bytes for suite 1 |

#### InnerSigPreimage

Signature preimage v2 M: the inner fields except 20 as received, key 9 replaced by coredet(bstr(SHA-256(body))), plus keys 0 and 30-34. Built, never decoded.

*typed `anet-relay-sig/v2`; built and hashed or signed, never decoded.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `label` | `tstr` = `anet-relay-sig/v2` | required | — |
| 30 | `enc` | `bstr` | required | outer key 5 |
| 31 | `kid` | `bstr` | required | outer key 4 |
| 32 | `suite` | `uint` | required | outer key 3 |
| 33 | `ikid` | `bstr\|null` | required | Wrap key 1, CBOR null for a single layer |
| 34 | `enc2` | `bstr\|null` | required | Wrap key 2, CBOR null for a single layer |

#### HPKEInfo

HPKE info map of layer 1 (L1) and layer 2 (L2). Built, never decoded.

*built and hashed or signed, never decoded.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `label` | `tstr` | required | anet-seal/v2 (layer 1) or anet-ix/v2 (layer 2) |
| 2 | `to` | `tstr` | required | — |
| 3 | `suite` | `uint` | required | — |
| 4 | `kid` | `bstr` (16 bytes) | required | outer kid (layer 1) or ikid (layer 2) |

### Message bodies

#### DelegateReq

Body of anet.delegate/1.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `taskdoc` | `bstr` | required | signed TaskDoc bytes |
| 2 | `envelope` | `<aobj.Envelope>` | required | detached TaskDoc signature |
| 3 | — | — | retired | was `kel`. the KEL travels only in inner key 10 |
| 4 | `interaction_id` | `tstr` | required | must equal inner ix; no U+0000 |
| 5 | `attachments` | `[<Attachment>]` | optional | order is the order of $files |
| 6 | — | — | retired | was `payment`. prepayment, removed with the gateway |
| 7 | `context_id` | `tstr` | optional | — |
| 8 | `metadata` | `bstr` | optional | JSON object |

#### Attachment

A file attached to a delegation or message.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `name` | `tstr` | required | — |
| 2 | `mime` | `tstr` | optional | — |
| 3 | `size` | `int` | required | — |
| 4 | `cid` | `tstr` | required | — |
| 5 | `data` | `bstr` | optional | — |

#### ChatMsg

Body of anet.message/1. Keys 4-7 and 11-13 only in kind = stream_preview (else bad-body).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `kind` | `tstr` | required | text, end_request, cancel, stream_preview; end_accept retired |
| 2 | `body` | `tstr` | optional | in a preview frame the tail window, <= 8192 bytes |
| 3 | `attachments` | `[<Attachment>]` | optional | forbidden in preview frames |
| 4 | `stream_seq` | `uint` | if preview frames only, required there | — |
| 5 | `stream_at_ms` | `int` | if preview frames only, required there | — |
| 6 | `reasoning_body` | `tstr` | if preview frames only, optional | — |
| 7 | `reasoning_at_ms` | `int` | if preview frames only, optional | — |
| 8 | — | — | reserved | never assigned |
| 9 | `msg_id` | `tstr` | if required in preview frames, optional otherwise | — |
| 10 | `metadata` | `bstr` | optional | JSON; forbidden in preview frames |
| 11 | `omitted` | `uint` | if preview frames only, optional | — |
| 12 | `reasoning_omitted` | `uint` | if preview frames only, optional | — |
| 13 | `answers` | `tstr` | if preview frames only, required there | — |

#### ResultResp

Body of anet.result/1.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `status` | `tstr` | required | done or failed (queued never on the wire) |
| 2 | `deliverable` | `bstr` | optional | — |
| 3 | `receipt` | `bstr<ReceiptWire>` | optional | — |
| 4 | — | — | retired | was `kel`. |
| 5 | `metadata` | `bstr` | optional | JSON |
| 6 | `reply` | `<ReplyMsg>` | if text task with status = done: optional; capability task: forbidden | — |

#### ReplyMsg

The reply folded into a text task's result: a subset of ChatMsg; any other key is bad-body.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `kind` | `tstr` = `text` | required | — |
| 2 | `body` | `tstr` | optional | — |
| 3 | `attachments` | `[<Attachment>]` | optional | — |
| 9 | `msg_id` | `tstr` | required | — |

#### StatusMsg

Body of anet.status/1.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `state` | `tstr` | required | — |
| 2 | `text` | `tstr` | optional | — |
| 3 | `metadata` | `bstr` | optional | — |
| 4 | `at` | `uint` | required | — |

#### CardGet

Body of anet.card.get/1: the empty map (the type string carries the version).

*closed: every unregistered key is refused.*

No keys: the empty map.

#### CardResp

Body of anet.card/1: exactly one of the two keys.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `card` | `bstr` | if exactly one of 1 and 2 | the provider-signed extended card bytes, <= 64 KiB |
| 2 | `error` | `tstr` | if exactly one of 1 and 2 | not_configured or busy |

### Encryption key set

#### EncKeySet

Encryption key set anet.enckeys/2.

*typed `anet.enckeys/2`; closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `t` | `tstr` = `anet.enckeys/2` | required | type tag |
| 1 | `aid` | `tstr` | required | — |
| 2 | `seq` | `uint` | required | publication sequence, unix-ms scale; the hub's prev_seq compare-and-swap uses it |
| 3 | `keys` | `[<EncKey>]` | required | 1..32 keys, ascending not_before |
| 4 | `issued_at` | `uint` | required | — |
| 5 | `mbox` | `<Mbox>` | required | mailbox signing key |

#### EncKey

One encryption key; not_after - not_before <= 2 days.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `kid` | `bstr` (16 bytes) | required | — |
| 2 | `suite` | `uint` | required | — |
| 3 | `pub` | `bstr` | required | — |
| 4 | `not_before` | `uint` | required | — |
| 5 | `not_after` | `uint` | required | — |

#### Mbox

Mailbox signing key in a key set.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `epoch` | `uint` | required | >= 1; +1 only when the key changes |
| 2 | `pub` | `bstr` (32 bytes) | required | Ed25519 public key |

#### SignedEncKeySet

A key set and the identity signature over it.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `set` | `bstr<EncKeySet>` | required | — |
| 2 | `key_state_seq` | `uint` | required | must be the active tip of the KEL |
| 3 | `sig` | `bstr` (64 bytes) | required | — |

### Key event log and witness notices

#### KeyEvent

KEL v2 event. AID = CID(icp preimage); the icp preimage and stored form carry no key 1.

*typed `anet.kel/2`; closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `t_obj` | `tstr` = `anet.kel/2` | required | v2 marker and domain separation; a missing or wrong key 0 makes the KEL unreplayable |
| 1 | `aid` | `tstr` | if absent in the icp preimage, required otherwise | — |
| 2 | `seq` | `uint` | required | — |
| 3 | `prev` | `tstr` | if absent in icp, required otherwise | previous event id |
| 4 | `t` | `tstr` | required | icp, rot or dip |
| 5 | `keys` | `[bstr]` | required | exactly one 32-byte key: k0 for icp, the revealed key for rot and dip |
| 6 | `next` | `bstr` (32 bytes) | if icp and rot; forbidden in dip | SHA-256 of the next public key |
| 7 | `kt` | `uint` = `1` | required | — |
| 8 | `ts` | `uint` | required | > 0 |
| 9 | `witnesses` | `[tstr]` | if icp and rot may carry it; forbidden in dip | 0 or 1 witness hub AID |
| 10 | — | — | retired | was `revoked_since`. never used |
| 11 | `toad` | `uint` | if icp and rot, written even when 0; forbidden in dip | 0 for a hub, 1 for an agent |
| 12 | `emergency` | `bool` | if rot only, and only true | emergency rotation: zero grace |
| 13–63 | — | — | reserved | — |

#### SignedEvent

A KEL event with its signature. The raw event bytes must equal coredet(decoded event).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `event` | `<KeyEvent>` | required | — |
| 2 | `sig` | `bstr` (64 bytes) | required | — |
| 3 | `event_id` | `tstr` | required | CID of the preimage |
| 4 | — | — | reserved | kept for multi-witness receipts |

#### NoticeBody

Witness notice (key state notice) body.

*typed `anet.ksn/1`; closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `t` | `tstr` = `anet.ksn/1` | required | type tag |
| 1 | `aid` | `tstr` | required | the AID the notice is about |
| 2 | `seq` | `uint` | required | tip seq of the KEL the witness holds |
| 3 | `head` | `tstr` | required | tip event id |
| 4 | `observed_at` | `uint` | required | the witness hub's clock |
| 5 | `witness` | `tstr` | required | the signing witness hub AID |

#### NoticeWire

Witness notice on the wire.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `body` | `bstr<NoticeBody>` | required | — |
| 2 | `env` | `<aobj.Envelope>` | required | signer_aid must equal witness |

### Directory

#### DirEntry

Plaintext of a directory box. An entry with an unknown key, or one that does not open, is skipped.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `aid` | `tstr` | required | — |
| 2 | `home` | `tstr` | required | hub AID |
| 3 | `kel` | `bstr` | required | — |
| 4 | `keys` | `bstr<SignedEncKeySet>` | required | — |
| 5 | `card` | `bstr` | optional | A2A card bytes |
| 6 | `notice` | `bstr<NoticeWire>` | optional | — |

### Evidence, reviews and liabilities

#### ReceiptBody

Evidence receipt v2 body.

*typed `anet.receipt/2`; closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `t` | `tstr` = `anet.receipt/2` | required | type tag |
| 1 | `ix_commit` | `bstr` (32 bytes) | required | L27 |
| 2 | `requester_commit` | `bstr` (32 bytes) | required | L28 |
| 3 | `review_key` | `bstr` (32 bytes) | required | one-time review public key |
| 4 | `provider` | `tstr` | required | — |
| 5 | `request_cid` | `tstr` | required | — |
| 6 | `result_cid` | `tstr` | required | — |
| 7 | `completed_day` | `uint` | required | UTC day number |

#### ReceiptWire

Receipt v2 on the wire.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `body` | `bstr<ReceiptBody>` | required | — |
| 2 | `env` | `<aobj.Envelope>` | required | provider identity signature |

#### ReviewBody

Review v2 body.

*typed `anet.review/2`; closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `t` | `tstr` = `anet.review/2` | required | type tag |
| 1 | `receipt_cid` | `tstr` | required | — |
| 2 | `subject` | `tstr` | required | reviewed AID |
| 3 | `rating` | `uint` | required | 1..5 |
| 4 | `comment` | `tstr` | optional | <= 280 Unicode characters |
| 5 | `created_day` | `uint` | required | — |

#### ReviewWire

Review v2 on the wire.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `body` | `bstr<ReviewBody>` | required | — |
| 2 | `pub` | `bstr` (32 bytes) | required | must equal the receipt's review_key |
| 3 | `sig` | `bstr` (64 bytes) | required | Ed25519(review_sk, body) |

#### ReviewAttBody

Hub attestation of a stored review.

*typed `anet.review-att/1`; closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `t` | `tstr` = `anet.review-att/1` | required | type tag |
| 1 | `review_cid` | `tstr` | required | — |
| 2 | `receipt_cid` | `tstr` | required | — |
| 3 | `subject` | `tstr` | required | — |
| 4 | `tag` | `bstr` (16 bytes) | required | L31 |
| 5 | `tag_key_id` | `uint` | required | — |
| 6 | `day` | `uint` | required | — |
| 7 | `hub` | `tstr` | required | — |

#### ReviewAttWire

Review attestation on the wire.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `body` | `bstr<ReviewAttBody>` | required | — |
| 2 | `env` | `<aobj.Envelope>` | required | hub identity signature |

#### LiabLeafContent

Content of a liability tree leaf (hashed under L25).

*built and hashed or signed, never decoded.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `aid` | `tstr` | required | empty for a padding leaf |
| 2 | `to_day` | `uint` | required | — |
| 3 | `balance` | `uint` | required | — |

### C1 (anet ↔ ANetLink) and capability effects

#### EffectEvidence

Capability-effect evidence (C1 InvokeResp key 4; unchanged).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `requested` | `tstr` | optional | — |
| 2 | `protocol` | `tstr` | optional | — |
| 3 | `native_ack` | `bool` | optional | — |
| 4 | `observed_state` | `tstr` | optional | — |
| 5 | `latency_ms` | `int` | optional | — |
| 6 | `verify_trust` | `uint` | optional | — |
| 7 | `auth_trust` | `uint` | optional | — |
| 8 | `quirk` | `tstr` | optional | — |

#### Effect

Result of a capability invocation in the kernel (unchanged).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `status` | `tstr` | required | — |
| 2 | `record` | `<EffectRecord>` | optional | — |
| 3 | `message` | `tstr` | optional | — |
| 4 | `evidence` | `<EffectEvidence>` | optional | — |

#### CapList

C1 v1: capabilities the adapter serves.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `caps` | `[<CapEntry>]` | required | — |

#### CapEntry

C1 v1: one capability.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `id` | `tstr` | required | <cap>@<adapter>/<device>; the daemon does not parse it |
| 2 | `remote` | `uint` | required | 0 = none; 1 = relay |

#### Describe

C1 v1: describe answer.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `cid` | `tstr` | required | empty: no description object |

#### InvokeReq

C1 v1 invoke request (CBOR only, /v1/*).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `capability` | `tstr` | required | — |
| 2 | `args` | `map` | optional | — |
| 3 | `call_id` | `tstr` | optional | — |
| 4 | — | — | retired | was `caller_aid`. v0 caller as a string |
| 5 | `caller` | `<Caller>` | required | — |

#### Caller

C1 v1 caller, verified by the daemon.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `via` | `uint` | required | 0 = local; 1 = relay; 2 retired (v0 voucher) |
| 2 | `aid` | `tstr` | if required when via = 1; forbidden when via = 0 | — |
| 3 | — | — | reserved | kept for a later non-witness mode |

#### InvokeResp

C1 v1 invoke answer (fields as in v0).

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `status` | `tstr` | required | — |
| 2 | `metrics` | `map` | optional | — |
| 3 | `message` | `tstr` | optional | — |
| 4 | `evidence` | `<EffectEvidence>` | optional | — |

#### Refusal

C1 v1 refusal.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `reason` | `tstr` | required | a C1 reason code |

### Carried signed objects

#### aobj.Envelope

Detached signature envelope of signed objects (unchanged since 0.2.1).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `signer_aid` | `tstr` | required | — |
| 2 | `key_state_seq` | `uint` | required | — |
| 3 | `alg` | `int` | required | — |
| 4 | `sig` | `bstr` | required | — |
| 5 | `preimage_ref` | `tstr` | optional | — |

#### PaymentAuthorization

x402 anet-credit payment authorization (signed preimage; unchanged). Key 8 is PayBind.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `payer` | `tstr` | required | — |
| 2 | `pay_to` | `tstr` | required | — |
| 3 | `amount` | `uint` | required | — |
| 4 | `network` | `tstr` | required | — |
| 5 | `nonce` | `tstr` | required | — |
| 6 | `issued_at` | `int` | required | — |
| 7 | `not_after` | `int` | required | — |
| 8 | `interaction_id` | `tstr` | optional | PayBind (L34) |

#### PaymentAuthorizationWire

Payment authorization on the wire (unchanged).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `auth` | `<PaymentAuthorization>` | required | — |
| 2 | `env` | `<aobj.Envelope>` | required | — |

#### PaymentReceipt

Hub settlement receipt (signed preimage; unchanged).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `auth_id` | `tstr` | required | — |
| 2 | `payer` | `tstr` | required | — |
| 3 | `pay_to` | `tstr` | required | — |
| 4 | `amount` | `uint` | required | — |
| 5 | `network` | `tstr` | required | — |
| 6 | `settle_at` | `int` | required | — |

#### PaymentReceiptWire

Settlement receipt on the wire (unchanged).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `receipt` | `<PaymentReceipt>` | required | — |
| 2 | `env` | `<aobj.Envelope>` | required | — |

#### AELRecord

Evidence event log record (unchanged; the supply epoch record uses version_major 2).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `chain_did` | `tstr` | required | — |
| 2 | `seq` | `uint` | required | — |
| 3 | `prev_id` | `tstr` | required | — |
| 4 | `event_type` | `tstr` | required | — |
| 5 | `version_major` | `uint` | required | — |
| 6 | `payload` | `any` | required | — |
| 7 | `timestamp` | `int` | required | — |
| 8 | `signer_aid` | `tstr` | required | — |
| 9 | `key_state_seq` | `uint` | required | — |
| 10 | `critical_extensions` | `[tstr]` | optional | — |
| 11 | `id` | `tstr` | optional | — |
| 12 | `sig` | `bstr` | optional | — |
| 13 | `version_minor` | `uint` | optional | — |
| 14 | `corr_id` | `tstr` | optional | — |

#### AELHeadAttestation

Witness attestation of an ael chain head (signed preimage; unchanged).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `chain_did` | `tstr` | required | — |
| 2 | `seq` | `uint` | required | — |
| 3 | `head_id` | `tstr` | required | — |
| 4 | `observed_at` | `int` | required | — |

#### AELHeadAttestationWire

Head attestation on the wire (unchanged).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `body` | `<AELHeadAttestation>` | required | — |
| 2 | `env` | `<aobj.Envelope>` | required | — |

### Task documents

#### TaskDoc

Task document (unchanged). Its signature is a detached aobj envelope over TaskDocPreimage.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `version` | `<VersionPair>` | required | — |
| 2 | `meta` | `[<MetaEntry>]` | optional | — |
| 3 | `links` | `[<Link>]` | optional | — |
| 4 | `tasks` | `[<Task>]` | required | — |
| 7 | `critical` | `[uint]` | optional | — |

#### TaskDocPreimage

The part of a TaskDoc the signature covers.

*built and hashed or signed, never decoded; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `version` | `<VersionMajor>` | required | — |
| 3 | `links` | `[<Link>]` | optional | — |
| 4 | `tasks` | `[<Task>]` | required | — |

#### VersionPair

TaskDoc version.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `major` | `uint` | required | — |
| 2 | `minor` | `uint` | optional | — |

#### VersionMajor

TaskDoc version as signed.

*built and hashed or signed, never decoded; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `major` | `uint` | required | — |

#### MetaEntry

TaskDoc meta entry.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `name` | `tstr` | required | — |
| 2 | `value` | `tstr` | required | — |

#### Link

TaskDoc link.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `rel` | `tstr` | required | — |
| 2 | `href` | `tstr` | required | — |
| 3 | `title` | `tstr` | optional | — |

#### Task

One task of a TaskDoc.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `id` | `tstr` | optional | — |
| 10 | `intent` | `<Intent>` | required | — |
| 11 | `requires` | `[<Require>]` | optional | — |
| 12 | `accepts` | `[<Accept>]` | optional | — |
| 13 | `contexts` | `[<Context>]` | optional | — |
| 14 | `positive_scope` | `<Predicate>` | optional | — |
| 15 | `negative_scope` | `<Predicate>` | optional | — |
| 16 | `coupling_hint` | `int` | optional | — |

#### Intent

Task intent.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `summary` | `tstr` | optional | — |
| 2 | `format` | `tstr` | optional | — |
| 3 | `body` | `tstr` | required | — |

#### Require

Task requirement.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `id` | `tstr` | required | — |
| 2 | `type` | `tstr` | optional | — |
| 3 | `necessity` | `tstr` | required | — |
| 4 | `description` | `tstr` | optional | — |

#### Output

Accepted output.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `format` | `tstr` | required | — |
| 2 | `max_size` | `tstr` | optional | — |
| 3 | `name` | `tstr` | optional | — |

#### Schema

Output schema.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `type` | `tstr` | required | — |
| 2 | `body` | `tstr` | required | — |

#### Accept

Acceptance criteria.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `type` | `tstr` | required | — |
| 2 | `description` | `tstr` | optional | — |
| 3 | `outputs` | `[<Output>]` | optional | — |
| 4 | `schema` | `<Schema>` | optional | — |

#### Context

Task context entry (anet's keys: see taskdoc_contexts).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `key` | `tstr` | required | — |
| 2 | `value` | `tstr` | optional | — |
| 3 | `src` | `tstr` | optional | — |
| 4 | `format` | `tstr` | optional | — |
| 5 | `visibility` | `tstr` | optional | — |

#### Predicate

Scope predicate.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `op` | `int` | required | — |
| 2 | `children` | `[<Predicate>]` | optional | — |
| 10 | `artifact` | `<ArtifactClause>` | optional | — |
| 11 | `test` | `<TestClause>` | optional | — |
| 12 | `thresh` | `<ThresholdClause>` | optional | — |
| 13 | `scope` | `<ScopeClause>` | optional | — |

#### ArtifactClause

Predicate clause on an artifact.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `path_glob` | `tstr` | required | — |
| 2 | `exists` | `bool` | optional | — |
| 3 | `min_size_bytes` | `uint` | optional | — |
| 4 | `schema_ref` | `tstr` | optional | — |
| 5 | `contains` | `[tstr]` | optional | — |

#### TestClause

Predicate clause on a test.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `test_id` | `tstr` | required | — |
| 2 | `expect` | `int` | required | — |

#### ThresholdClause

Predicate clause on a metric.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `metric` | `tstr` | required | — |
| 2 | `op` | `int` | required | — |
| 3 | `value` | `float` | required | — |

#### ScopeClause

Predicate clause on a resource.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `verb` | `int` | required | — |
| 2 | `kind` | `int` | required | — |
| 3 | `match` | `<ResourceMatch>` | required | — |
| 4 | `merge_class` | `int` | optional | — |

#### ResourceMatch

Resource matcher.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `kind` | `int` | required | — |
| 2 | `val` | `tstr` | required | — |

#### EffectRecord

Observed effects of a task.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `artifacts` | `[<Artifact>]` | optional | — |
| 2 | `tests` | `[<TestResult>]` | optional | — |
| 3 | `metrics` | `map` | optional | — |
| 4 | `resources` | `[<ResourceRef>]` | optional | — |
| 5 | `effects` | `[<EffectRef>]` | optional | — |

#### Artifact

A produced artifact.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `path` | `tstr` | required | — |
| 2 | `size_bytes` | `uint` | required | — |
| 3 | `content_cid` | `tstr` | optional | — |
| 4 | `media_type` | `tstr` | optional | — |

#### TestResult

A test result.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `id` | `tstr` | required | — |
| 2 | `status` | `int` | required | — |

#### ResourceRef

A resource reference.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `kind` | `int` | required | — |
| 2 | `id` | `tstr` | required | — |
| 3 | `merge_class` | `int` | required | — |

#### EffectRef

An effect on a resource.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `verb` | `int` | required | — |
| 2 | `resource` | `<ResourceRef>` | required | — |

### Local files

#### IdentityFile

identity.kel in the data directory (also the hub identity file), 0600.

*typed `anet.identity/2`; closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `t` | `tstr` = `anet.identity/2` | required | type tag |
| 1 | `kel` | `bstr` | required | events accepted by the witness (MarshalKEL) |
| 2 | `cur` | `bstr` (32 bytes) | if absent while a recover is waiting to publish | current signing key seed |
| 3 | `hot_next` | `bstr` (32 bytes) | if only while the KEL has one event | hot key seed committed by icp |
| 4 | `pending` | `<IdentityPending>` | optional | — |
| 5 | `witnesses_to_push` | `[<WitnessPush>]` | optional | — |
| 6 | `state` | `tstr` | required | ok, stopped or deactivated; anything else is refused |
| 7 | `local_commit` | `bstr` (32 bytes) | optional | next_digest derived from the RS of the unprotected recovery file when joined without a terminal; written once, never deleted; public |

#### IdentityPending

An identity event being built or published (IdentityFile key 4).

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `kind` | `tstr` | required | witness, rot or dip |
| 2 | `revealed` | `bstr` (32 bytes) | required | seed of the key this event reveals |
| 3 | `next` | `bstr` (32 bytes) | if absent for dip | — |
| 4 | `hub_url` | `tstr` | required | — |
| 5 | `emergency` | `bool` | required | — |
| 6 | `event` | `bstr` | optional | the built SignedEvent bytes |
| 7 | `since` | `uint` | required | — |

#### WitnessPush

A witness the identity still has to push to (IdentityFile key 5).

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `hub_aid` | `tstr` | required | — |
| 2 | `hub_url` | `tstr` | required | — |
| 3 | `acked_seq` | `uint` | required | — |
| 4 | `next_try` | `uint` | required | — |

#### RecoveryBlob

The base64 block of a recovery file. aad = coredet(RecoveryBlob without key 7).

*typed `anet.recovery/1`; closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `t` | `tstr` = `anet.recovery/1` | required | type tag |
| 1 | `aid` | `tstr` | required | — |
| 2 | `kdf` | `<RecoveryKDF>` | required | exactly one of two shapes: passphrase (argon2id) or local (unprotected file) |
| 3 | `aead` | `tstr` = `xchacha20poly1305` | required | — |
| 4 | `nonce` | `bstr` (24 bytes) | required | — |
| 5 | `hub` | `tstr` | required | witness hub URL at creation (a hint) |
| 6 | `commits` | `tuple(uint,bstr)` | required | [seq, next_digest] this RS commits to; public |
| 7 | `ct` | `bstr` | required | XChaCha20-Poly1305 of RS |

#### RecoveryKDF

Key derivation of a recovery file (RecoveryBlob key 2).

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `alg` | `tstr` | required | argon2id or local |
| 2 | `t` | `uint` = `3` | if argon2id only | — |
| 3 | `m_kib` | `uint` = `65536` | if argon2id only | — |
| 4 | `p` | `uint` = `4` | if argon2id only | — |
| 5 | `salt` | `bstr` (16 bytes) | if argon2id only | — |

- Shape: alg = argon2id: passphrase-protected recovery file — keys 1, 2, 3, 4, 5.
- Shape: alg = local: unprotected recovery file, AEAD key = the 32 bytes of recovery_local.key — keys 1.

#### KeyStateNoticeFile

key_state_notice.cbor in the data directory, 0600.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `notice` | `bstr<NoticeWire>` | required | — |
| 2 | `saved_at` | `uint` | required | — |

#### MboxKeyFile

mbox.key in the data directory, 0600.

*typed `anet.mbox/1`; closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `t` | `tstr` = `anet.mbox/1` | required | type tag |
| 1 | `epoch` | `uint` | required | — |
| 2 | `seed` | `bstr` (32 bytes) | required | — |

#### EncKeyFile

enc_keys.cbor v2 in the data directory, 0600; a v other than 2 refuses to start.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `v` | `uint` = `2` | required | — |
| 2 | `aid` | `tstr` | required | — |
| 3 | `last_seq` | `uint` | required | largest key-set seq this ring signed |
| 4 | `keys` | `[<RingKey>]` | required | — |
| 5 | `signed` | `bstr<SignedEncKeySet>` | optional | last SignedEncKeySet signed |
| 6 | `last_wall` | `uint` | required | local wall clock at the last maintenance |
| 7 | `rollback` | `<RollbackMark>` | optional | last local state rollback |
| 8 | `regen_tag` | `uint` | optional | — |
| 9 | `unverified_run` | `uint` | required | run time with the hub gate closed; 0 when open or without a hub |

#### RingKey

One key of the epoch key ring.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `pair` | `<KeyPair>` | required | — |
| 2 | `removed_at` | `uint` | required | 0 while still in the hub's registered set |
| 3 | `retired` | `bool` | required | — |

#### KeyPair

An encryption key pair (seal.KeyPair; unchanged).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `public` | `<EncKey>` | required | — |
| 2 | `private` | `bstr` | required | 32 bytes for suite 1 |

#### RollbackMark

A detected local state rollback.

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `at` | `uint` | required | — |
| 2 | `stored_seq` | `uint` | required | — |
| 3 | `tasks` | `uint` | required | in-flight interactions ended |
| 4 | `logged` | `bool` | required | — |
| 5 | `prev_at` | `uint` | required | at of the previous mark; 0 = none |
| 6 | `silent` | `bool` | required | a silent adoption: not shown, no evidence |

### ANet module objects

#### OrgGenesis

Organization genesis; not signed, its CID is the org_id (L41).

*typed `anet.org-genesis/1`; closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `t` | `tstr` = `anet.org-genesis/1` | required | type tag |
| 1 | `governance_root` | `[tstr]` | required | founder AIDs, byte-sorted and deduplicated |
| 2 | `m` | `uint` | required | governance threshold, 1 <= m <= founders |
| 3 | `nonce` | `tstr` | optional | — |

#### OrgCredBody

Organization membership credential body.

*typed `anet.org-cred/1`; closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `t` | `tstr` = `anet.org-cred/1` | required | type tag |
| 1 | `org_id` | `tstr` | required | CID(coredet(OrgGenesis)) |
| 2 | `subject` | `tstr` | required | — |
| 3 | `role` | `tstr` | required | admin, member or guest |
| 4 | `epoch` | `uint` | optional | 0.3.0 accepts only the default (0) |
| 5 | `issued_at` | `int` | required | unix ms |
| 6 | `not_after` | `int` | required | unix ms, > issued_at |

#### SignedCredential

Credential on the wire (unchanged form).

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `cred` | `bstr<OrgCredBody>` | required | — |
| 2 | `env` | `<aobj.Envelope>` | required | — |

#### CogUnitBody

Blackboard cognitive unit body; its CID is the unit id.

*typed `anet.cogunit/1`; closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 0 | `t` | `tstr` = `anet.cogunit/1` | required | type tag |
| 1 | `author` | `tstr` | required | must equal env.signer_aid |
| 2 | `task_id` | `tstr` | optional | — |
| 3 | `scope` | `tstr` | optional | — |
| 4 | `type` | `tstr` | required | — |
| 5 | `stamp` | `<HLC>` | required | — |
| 6 | `body` | `bstr` | optional | inline small payload |
| 7 | `body_cid` | `tstr` | optional | — |

#### CogUnitWire

Cognitive unit on the wire (the envelope moved from key 8 of the same map into a bstr-carried body).

*closed: every unregistered key is refused.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `body` | `bstr<CogUnitBody>` | required | — |
| 2 | `env` | `<aobj.Envelope>` | required | — |

#### HLC

Hybrid logical clock stamp.

*closed: every unregistered key is refused; name carried over from 0.2.1.*

| Key | Name | Type | Presence | Notes |
|---|---|---|---|---|
| 1 | `wall` | `int` | required | unix ms |
| 2 | `logical` | `uint` | optional | — |
| 3 | `node_id` | `tstr` | optional | — |

## Labels and type tags

Classes: A = typed CoreDet map (key 0 is the tag); B = prefix string `label || 0x00 || fields`;
C = KDF, HPKE or MAC context; text = relayauth text preimage. Labels are ASCII bytes, no length
prefix, no trailing NUL.

| | Label | Class | Construction | Key | Vectors |
|---|---|---|---|---|---|
| L1 | `anet-seal/v2` | C | layer-1 HPKE info = coredet({1: "anet-seal/v2", 2: to, 3: suite, 4: kid}); aad empty | recipient encryption epoch key | SEALED-2A, SEALED-2B |
| L2 | `anet-ix/v2` | C | layer-2 HPKE info = coredet({1: "anet-ix/v2", 2: to, 3: suite2, 4: ikid}); aad empty | recipient interaction key | SEALED-2B |
| L3 | `anet-relay-sig/v2` | A | inner signature preimage v2 (InnerSigPreimage) | sender identity current key | SEALED-2A, SEALED-2B, SEALED-2C |
| L4 | `anet-env/v2` | B | env_digest = SHA-256("anet-env/v2" \|\| 0x00 \|\| coredet(outer field map without key 7)), field values as received | - | ACCESS-1, SEALED-2B |
| L5 | `anet-access/v2` | B | proof = Ed25519(holder_sk, "anet-access/v2" \|\| 0x00 \|\| cap_id(16) \|\| env_digest(32)) | holder key | ACCESS-1 |
| L6 | `anet.cap/1` | A | Cap.sig = Ed25519(mbox_sk, coredet(CapBody)) | mailbox signing key | ACCESS-1 |
| L7 | `anet-sess-key/v1` | C | session key delivery: HPKE base, suite 1, pkR = epk, info = "anet-sess-key/v1" \|\| 0x00 \|\| hubAID \|\| 0x00 \|\| sid(16); aad empty; plaintext k_sess(32) | one-time epk | SESSION-1 |
| L8 | `anet-sess-mac/v1` | B | MAC = HMAC-SHA256(k_sess, "anet-sess-mac/v1" \|\| 0x00 \|\| sid(16) \|\| 0x00 \|\| ts(decimal) \|\| 0x00 \|\| method \|\| 0x00 \|\| pathAndQuery \|\| 0x00 \|\| X-ANet-Home or empty \|\| 0x00 \|\| SHA-256(body)) | k_sess | SESSION-1 |
| L9 | `anet-dir-hash/v1` | B | h = SHA-256("anet-dir-hash/v1" \|\| 0x00 \|\| UTF-8(aid)) | - | DIR-1 |
| L10 | `anet-dir-box/v1` | C | K = HKDF-SHA256(ikm = UTF-8(aid), salt = empty, info = "anet-dir-box/v1", L = 32); box = nonce(12) \|\| ChaCha20-Poly1305(K, nonce, aad = h, pt = coredet(DirEntry)) | derived from the AID | DIR-1 |
| L11 | `anet-dack/v1` | C | ack_key = HPKE.Export(layer-1 context, exporter_context = "anet-dack/v1", L = 32) | layer-1 HPKE | DACK-1, rfc9180 |
| L12 | `anet-dack-handle/v1` | C | handle = HMAC-SHA256(ack_key, "anet-dack-handle/v1")[0:16] | ack_key | DACK-1 |
| L13 | `anet-dack-tok/v1` | C | tok(o) = HMAC-SHA256(ack_key, "anet-dack-tok/v1" \|\| u8(o))[0:16] | ack_key | DACK-1 |
| L14 | `anet-dack-note/v1` | C | note_key = HMAC-SHA256(ack_key, "anet-dack-note/v1"); the note AEAD aad is tok(o) | ack_key | DACK-1 |
| L15 | `anet-enc-kid/v1` | B | KID = SHA-256("anet-enc-kid/v1" \|\| u8(suite) \|\| pub)[0:16] (no 0x00; epoch and interaction keys alike) | - | ENCKEYS-2 |
| L16 | `anet.enckeys/2` | A | SignedEncKeySet.sig = Ed25519(identity key, coredet(EncKeySet)) | identity current key | ENCKEYS-2 |
| L17 | `anet.kel/2` | A | SignedEvent.sig = Ed25519(k, coredet(KeyEvent)); icp by k0, rot and dip by the key the event reveals | identity key | KEL-2A, KEL-2B, KEL-2N |
| L18 | `anet.ksn/1` | A | aobj envelope signature over coredet(NoticeBody) | witness hub identity key | KSN-1 |
| L19 | `anet-kel-next/v1` | C | seed(aid, seq) = HKDF-SHA256(ikm = RS, salt = "anet-kel-next/v1", info = UTF-8(aid) \|\| 0x00 \|\| u64be(seq), L = 32) | recovery seed RS | RECOVERY-1 |
| L20 | `anet.recovery/1` | A | ct = XChaCha20-Poly1305(key, nonce, RS, aad = coredet(RecoveryBlob without key 7)); key = argon2id(NFC(passphrase), salt, t = 3, m = 64 MiB, p = 4, 32) when kdf = argon2id, or the 32 bytes of recovery_local.key when kdf = {1: "local"}; kdf is inside the aad, so neither mode passes for the other | passphrase-derived key; local recovery key | RECOVERY-1 |
| L21 | `anet.identity/2`, `anet.mbox/1` | file | local file type tags; not signed | - | - |
| L22 | `anet-relay/v2/` | text | "anet-relay/v2/" + action + "/" + aid + "/" + hubAID + "/" + decimal(ts) + "/" + base64url(SHA-256(method \|\| 0x00 \|\| pathAndQuery \|\| 0x00 \|\| body)); agents and peer hubs alike | signer identity current key | RELAYAUTH-3 |
| L23 | `anet-regpow/v1` | B | pow_hash = SHA-256("anet-regpow/v1" \|\| 0x00 \|\| hub_aid \|\| 0x00 \|\| aid \|\| 0x00 \|\| seed(32) \|\| nonce(<= 32)); >= 22 leading zero bits | - | REGPOW-1 |
| L24 | `anet-regpow-seed/v1` | C | seed = HMAC-SHA256(pow_key, "anet-regpow-seed/v1" \|\| u64be(floor(ms / 3 600 000))) | pow_key (hub process memory only) | REGPOW-1 |
| L25 | `anet-liab-leaf/v1` | B | leaf = SHA-256("anet-liab-leaf/v1" \|\| 0x00 \|\| salt(32) \|\| coredet(LiabLeafContent)) | - | LIAB-1 |
| L26 | `anet-liab-node/v1` | B | node = SHA-256("anet-liab-node/v1" \|\| 0x00 \|\| L.h \|\| u64be(L.sum) \|\| R.h \|\| u64be(R.sum)) | - | LIAB-1 |
| L27 | `anet-receipt-ix/v2` | B | ix_commit = SHA-256("anet-receipt-ix/v2" \|\| 0x00 \|\| ix \|\| 0x00 \|\| anet.nonce); neither holds U+0000 | - | EV2-1 |
| L28 | `anet-receipt-requester/v2` | B | requester_commit = SHA-256("anet-receipt-requester/v2" \|\| 0x00 \|\| requester_aid \|\| 0x00 \|\| rsalt(32)) | - | EV2-1 |
| L29 | `anet.receipt/2` | A | provider aobj envelope signature over coredet(ReceiptBody) | provider identity current key | EV2-1 |
| L30 | `anet.review/2` | A | ReviewWire.sig = Ed25519(review_sk, coredet(ReviewBody)) | one-time review key | REVIEW-2 |
| L31 | `anet-review-tag/v1` | C | tag = HMAC-SHA256(hub_tag_key, "anet-review-tag/v1" \|\| 0x00 \|\| reviewer_aid \|\| 0x00 \|\| subject_aid)[0:16] | hub_tag_key | REVIEW-2 |
| L32 | `anet.review-att/1` | A | hub aobj envelope signature over coredet(ReviewAttBody) | hub identity key | REVIEW-2 |
| L33 | `anet-settle-guard/v1` | B | h = SHA-256("anet-settle-guard/v1" \|\| 0x00 \|\| payer \|\| 0x00 \|\| pay_bind) (hub local) | - | EV2-1 |
| L34 | `anet/x402-bind/v1` | B | PayBind = hex(SHA-256("anet/x402-bind/v1" \|\| 0x00 \|\| ix \|\| 0x00 \|\| taskNonce)); an ix or taskNonce holding 0x00 is an error | - | EV2-1 (NUL cases) |
| L35 | `anet-local/v1` | C (local) | local encrypted field: 0x01 \|\| nonce(12) \|\| AES-256-GCM(aead_key, nonce, plaintext, aad = coredet({1: "anet-local/v1", 2: ix, 3: "<table>.<column>"})) | aead_key derived from ix_dek (L36) | LOCAL-1 |
| L36 | `anet-local-aead/v1`, `anet-local-mac/v1` | C (local) | aead_key = HKDF-SHA256(ikm = ix_dek, salt = empty, info = "anet-local-aead/v1", L = 32); mac_key = HKDF-SHA256(ikm = ix_dek, salt = empty, info = "anet-local-mac/v1", L = 32) | ix_dek | LOCAL-1 |
| L37 | `anet-client-key/v1` | B (local) | client_key = SHA-256("anet-client-key/v1" \|\| 0x00 \|\| messageId) | - | LOCAL-1 |
| L38 | `anet-client-msg/v1` | B (local) | client_digest = HMAC-SHA256(mac_key, "anet-client-msg/v1" \|\| 0x00 \|\| canon(normalized content)); canon: members sorted (RFC 8785 3.2.3), strings escaped (3.2.2.2), no whitespace, numbers kept as the client wrote them | mac_key derived from ix_dek | LOCAL-1 |
| L39 | `anet.delegate/1`, `anet.message/1`, `anet.status/1`, `anet.result/1`, `anet.card.get/1`, `anet.card/1` | type | inner type (key 4); not a signing label; inside the signature preimage | - | SEALED-2A, CARD-1 |
| L40 | `anet/localpeer-key/v1`, `anet-release/1`, `anet-release/2`, `anet-official/1`, `anet-suite-identity-v1/cur`, `anet-suite-identity-v1/nxt`, `anet-suite-test-key-v1` | carried | unchanged | - | unchanged |
| L41 | `anet.org-genesis/1` | A | org_id = CID(coredet(OrgGenesis)); not signed | - | MODOBJ-1 |
| L42 | `anet.org-cred/1` | A | SignedCredential.env signs coredet(OrgCredBody) | issuer identity current key | MODOBJ-1 |
| L43 | `anet.cogunit/1` | A | CogUnitWire.env signs coredet(CogUnitBody) | author identity current key | MODOBJ-1 |

## relayauth actions

Preimage: `anet-relay/v2/` + action + `/` + aid + `/` + hubAID + `/` + decimal(ts) + `/` + base64url(SHA-256(method || 0x00 || pathAndQuery || 0x00 || body)).

| Action | Route | Signer | Status |
|---|---|---|---|
| `poll` | POST /relay/poll | agent | active |
| `ack` | POST /relay/ack | agent | active |
| `register` | POST /register | agent | active |
| `profile` | POST /profile | agent | active |
| `visibility` | POST /visibility | agent | active |
| `deregister` | POST /deregister | agent | active |
| `balance` | GET /agents/{aid}/balance | agent | active |
| `ledger` | GET /agents/{aid}/ledger | agent | active |
| `redemptions` | GET /agents/{aid}/redemptions | agent | active |
| `keys` | POST /agents/{aid}/keys | agent | active |
| `session` | POST /relay/session | agent | active |
| `revoke` | POST /mailbox/revoke | agent | active |
| `review` | POST /reviews | agent (the reviewer) | active |
| `liab_proof` | GET /agents/{aid}/liability-proof | agent (itself) | active |
| `fed_forward` | POST /fed/v3/forward | peer hub | active |
| `fed_bucket` | POST /fed/v3/directory:bucket | peer hub | active |
| `fed_status` | POST /fed/v3/relay-status | peer hub | active |
| `fed_settle` | POST /fed/v3/settle | peer hub | active |
| `fed_reviews` | GET /fed/v3/reviews | peer hub | active |
| `fed_cards` | GET /fed/v3/cards | peer hub | active |
| `fed_clear` | POST /fed/v3/clear | peer hub | active |
| `send` | - | - | retired |
| `p2p` | - | - | retired |
| `fedkeys` | - | - | retired |

## Hub API (wire 3)

Binary values in JSON are base64url without padding, except public hashes (64 lowercase hex).
Every error body is `{"reason": <code>, "error": <one English sentence>, …}`.

### Headers

| Header | Direction | Where | Value |
|---|---|---|---|
| `X-ANet-Wire` | request and response | every hub request and response | 3 |
| `X-ANet-AID` | request | relayauth routes, /fed/v3/* included | signer AID |
| `X-ANet-TS` | request | relayauth routes; kind-0 /relay/send | unix ms |
| `X-ANet-Seq` | request | relayauth routes | key_state_seq |
| `X-ANet-Sig` | request | relayauth routes | signature over the L22 preimage |
| `X-ANet-Access` | request | /relay/send, /fed/v3/forward | base64url(coredet(Access)), byte-equal to outer key 7, <= 1 KiB |
| `X-ANet-Session` | request | kind-0 /relay/send | sid, 16 bytes, base64url |
| `X-ANet-MAC` | request | kind-0 /relay/send | session MAC, 32 bytes, base64url (L8) |
| `X-ANet-Home` | request | /relay/send, optional | hub AID |
| `X-ANet-TS-Floor` | response | 401 ts_stale only, after the signature verified | unix ms |
| `Retry-After` | response | 429, 502, 503 and refusals that wait | seconds |
| `Content-Type` | request | /relay/send, /fed/v3/forward | application/vnd.anet.envelope+cbor |

### Endpoints

#### `POST /relay/session`

Authentication: relayauth session.

Request; decoded strictly: an unknown member is 400 `bad_request`:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `epk` | b64url | required | 32 bytes |

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `sid` | b64url | required | — |
| `exp` | uint | required | — |
| `enc` | b64url | required | — |
| `ct` | b64url | required | — |

Codes: `admission_required`.

#### `POST /relay/send`

Authentication: kind 0: session MAC; kind 1: none (the capability).

Request: application/vnd.anet.envelope+cbor: the envelope bytes

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `status` | enum: `queued`, `duplicate` | required | — |
| `rid` | b64url | required | — |
| `via_hub` | string | optional | when the envelope was queued at another hub |
| `recipient_quiet` | bool | required | — |

refusals: the relay codes of reasons.hub; checks in a fixed order (envelope parse with outer key 8, access, kid in the queueing transaction).

#### `POST /relay/poll`

Authentication: relayauth poll.

Request; decoded strictly: an unknown member is 400 `bad_request`:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `limit` | uint | optional | — |
| `after_id` | uint | optional | — |

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `messages` | array | required | — |
| `messages.id` | uint | required | — |
| `messages.envelope` | b64url | required | — |
| `messages.accepted_at` | uint | required | — |
| `more` | bool | required | — |
| `key_state_notice` | b64url | optional | NoticeWire bytes |
| `key_state_notice_error` | enum: `quarantine`, `not_admitted`, `not_witness` | optional | — |

no rid; rows with exp <= now are not returned.

#### `POST /relay/ack`

Authentication: relayauth ack.

Request; decoded strictly: an unknown member is 400 `bad_request`:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `items` | array | required | <= 1000 |
| `items.id` | uint | required | — |
| `items.handle` | b64url | conditional | with dack |
| `items.dack` | b64url | conditional | with handle |

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `acked` | uint | required | — |
| `stored` | uint | required | — |

Codes: `bad_ack_item`.

#### `POST /relay/status`

Authentication: none (anonymous side).

Request; decoded strictly: an unknown member is 400 `bad_request`:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `items` | array | required | 1-64 items, one via_hub for all, <= 16 KiB |
| `items.rid` | b64url | required | — |
| `items.handle` | b64url | required | — |
| `items.via_hub` | string | optional | — |

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `items` | array | required | — |
| `items.state` | enum: `queued`, `done`, `unknown` | required | — |
| `items.dack` | b64url | optional | — |

Codes: `bad_status_query`, `rate_limited`, `home_unreachable`.

#### `POST /mailbox/revoke`

Authentication: relayauth revoke.

Request; decoded strictly: an unknown member is 400 `bad_request`:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `cap_ids` | array | required | <= 1000 cap_id values, b64url |

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `revoked` | uint | required | — |
| `total` | uint | required | — |

Codes: `revocation_list_full`.

#### `POST /directory:bucket`

Authentication: none (anonymous side).

Request; decoded strictly: an unknown member is 400 `bad_request`:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `prefix` | b64url | required | — |
| `bits` | uint | required | — |
| `cursor` | string | optional | — |

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `max_bits` | uint | required | — |
| `entries` | array | required | — |
| `entries.h` | b64url | required | — |
| `entries.box` | b64url | required | — |
| `next` | string | optional | — |
| `partial` | bool | optional | present only when true: a peer hub did not answer and no cached answer exists; a target missing from a partial bucket is 'temporarily unavailable', never recipient_unknown |

Codes: `bucket_too_narrow`, `rate_limited`.

#### `POST /register`

Authentication: relayauth register.

Request; decoded strictly: an unknown member is 400 `bad_request`:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `aid` | string | required | — |
| `kel` | b64url | required | — |
| `name` | string | optional | — |
| `caps` | array | optional | — |
| `summary` | string | optional | — |
| `readme` | string | optional | — |
| `enc_keys` | b64url | optional | — |
| `prev_seq` | uint | conditional | required with enc_keys |
| `a2a_card` | object | optional | — |
| `pow` | object | optional | — |
| `pow.seed` | b64url | required | — |
| `pow.nonce` | b64url | required | — |
| `check_only` | bool | optional | — |

Response (registration):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `aid` | string | required | — |
| `status` | enum: `registered` | required | — |
| `keys_status` | string | required | — |
| `keys_error` | string | optional | — |
| `card_status` | string | required | — |
| `card_error` | string | optional | price_in_public_card among others |
| `probation_until` | uint | optional | — |
| `trial` | enum: `pending`, `granted` | optional | only for an account that came in through a sign-up window or open registration |
| `revocations` | array | required | — |
| `key_state_notice` | b64url | optional | NoticeWire bytes |
| `key_state_notice_error` | enum: `quarantine`, `not_admitted`, `not_witness` | optional | — |

Response (check_only: nothing is written):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `status` | enum: `admitted`, `open` | required | — |

Codes: `admission_required`, `pow_required`, `registration_quota`, `invite_removed`, `witness_not_this_hub`, `aid_deactivated`, `kel_invalid`, `kel_fork`, `kel_rollback`, `kel_ts_out_of_window`, `keys_rollback`.

admission_required carries aid; pow_required carries challenge {seed, bits, not_after}; check_only does not check witness_not_this_hub.

#### `POST /agents/{aid}/keys`

Authentication: relayauth keys.

Request; decoded strictly: an unknown member is 400 `bad_request`:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `keys` | b64url | required | — |
| `prev_seq` | uint | required | — |

Response (only the members this version adds or changes): as in wire 2.

Codes: `keys_rollback`.

keys_rollback carries stored_seq.

#### `POST /agents/kel:push`

Authentication: none; rate limited per client address (IPv4 address, IPv6 /64): 60/min, burst 20 (KELPushRate).

Request; decoded strictly: an unknown member is 400 `bad_request`:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `aid` | string | required | — |
| `kel` | b64url | required | — |

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `aid` | string | required | — |
| `seq` | uint | required | — |
| `head` | string | required | — |
| `unchanged` | bool | required | — |

Codes: `unknown_aid`, `kel_fork`, `kel_rollback`, `kel_invalid`, `kel_ts_out_of_window`, `rate_limited`.

#### `GET /hub/identity`

Authentication: none.

Response (only the members this version adds or changes):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `wire` | uint | required | 3 |
| `dir_max_bits` | uint | required | — |

#### `GET /hub/kels`

Authentication: none.

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `hubs` | array | required | — |
| `hubs.aid` | string | required | — |
| `hubs.kel` | b64url | required | — |

Cache-Control: max-age=300.

#### `GET /agents/{aid}/kel`

Authentication: none.

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `aid` | string | required | — |
| `kel` | b64url | required | — |
| `registered` | bool | required | false: the AID is only in departed_kel |

Codes: `unknown_aid`.

#### `GET /a2a/v1/agents`

Authentication: none (anonymous side).

Response (only the members this version adds or changes):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `kel` | b64url | required | — |
| `keys` | b64url | required | — |
| `key_state_notice` | b64url | optional | — |

per entry; lastSeen cut to the hour, quiet only a boolean, registered_at cut to the UTC day, pricing removed.

#### `GET /agents`

Authentication: none (anonymous side).

Response (only the members this version adds or changes):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `kel` | b64url | required | — |
| `keys` | b64url | required | — |
| `key_state_notice` | b64url | optional | — |

as /a2a/v1/agents.

#### `GET /agents/{aid}/balance`

Authentication: relayauth balance.

Response (only the members this version adds or changes):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `probation_until` | uint | optional | — |
| `trial` | enum: `pending`, `granted` | optional | only for an account that came in through a sign-up window or open registration |

#### `GET /agents/{aid}/ledger`

Authentication: relayauth ledger.

Response (only the members this version adds or changes):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `window_days` | uint | required | always 14 |
| `oldest_seq` | uint | required | earliest row in the window; 0 when empty |

only rows inside the ledger window.

#### `GET /agents/{aid}/redemptions`

Authentication: relayauth redemptions.

Response (only the members this version adds or changes):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `window_days` | uint | required | — |
| `oldest_seq` | uint | required | — |

as /ledger.

#### `GET /agents/{aid}/liability-proof`

Authentication: relayauth liab_proof.

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `to_day` | uint | required | — |
| `from_day` | uint | required | — |
| `aid` | string | required | — |
| `balance` | uint | required | — |
| `salt` | hex | required | — |
| `path` | array | required | — |
| `path.h` | hex | required | — |
| `path.sum` | uint | required | — |
| `path.side` | string | required | — |
| `ledger_hw` | uint | required | — |
| `record` | object | required | — |

Codes: `proof_unavailable`.

optional ?to_day=N.

#### `POST /reviews`

Authentication: relayauth review.

Request; decoded strictly: an unknown member is 400 `bad_request`:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `receipt` | b64url | required | — |
| `review` | b64url | required | — |
| `rsalt` | b64url | required | — |

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `status` | enum: `stored` | required | — |
| `attestation` | b64url | required | — |

Codes: `probation`, `review_exists`, `requester_commit_mismatch`, `receipt_not_reviewable`, `review_window_closed`.

<= 16 KiB.

#### `GET /agents/{aid}/reputation`

Authentication: none.

#### `GET /graph`

Authentication: none.

edges removed.

#### `GET /x402/supply`

Authentication: none.

published epochs only.

#### `GET /x402/issuance`

Authentication: none.

published epochs only.

#### `GET /x402/issuance/head`

Authentication: none.

published epochs only.

#### `POST /x402/verify`

Authentication: as before.

x402 standard; errorReason adds payee_not_local, auth_window_too_long.

#### `POST /x402/settle`

Authentication: as before.

x402 standard; errorReason adds payee_not_local, auth_window_too_long.

#### `GET /x402/resource/*`

Authentication: -.

Codes: `gateway_removed`.

410 tombstone.

#### `POST /fed/v3/forward`

Authentication: relayauth fed_forward, peer hubs only.

Request: the envelope bytes, with X-ANet-Access

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `status` | enum: `queued`, `duplicate` | required | — |
| `rid` | b64url | required | — |
| `recipient_quiet` | bool | required | — |

Codes: `not_peer`, `unknown_destination`, `source_rate`, `access_invalid`, `kid_stale`, `expired`, `bad_exp`.

success is always 200.

#### `POST /fed/v3/directory:bucket`

Authentication: relayauth fed_bucket.

Request; decoded strictly: an unknown member is 400 `bad_request`:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `prefix` | b64url | required | — |
| `bits` | uint | required | — |
| `cursor` | string | optional | — |

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `max_bits` | uint | required | — |
| `entries` | array | required | — |
| `entries.h` | b64url | required | — |
| `entries.box` | b64url | required | — |
| `next` | string | optional | — |

Codes: `not_peer`.

no partial: a peer answers for its own entries only.

#### `POST /fed/v3/relay-status`

Authentication: relayauth fed_status.

Request; decoded strictly: an unknown member is 400 `bad_request`:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `items` | array | required | — |
| `items.rid` | b64url | required | — |
| `items.handle` | b64url | required | — |

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `items` | array | required | — |
| `items.state` | enum: `queued`, `done`, `unknown` | required | — |
| `items.dack` | b64url | optional | — |

Codes: `not_peer`, `rate_limited`.

#### `POST /fed/v3/settle`

Authentication: relayauth fed_settle.

Request: x402 FacilitatorRequest

Response: x402 SettlementResponse

x402 errorReason; payee is this hub's own account: payee_mismatch.

#### `GET /fed/v3/reviews`

Authentication: relayauth fed_reviews.

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `format` | enum: `review/2` | required | — |
| `receipt` | b64url | required | — |
| `review` | b64url | required | — |
| `attestation` | b64url | required | — |
| `provider_kel` | b64url | required | — |
| `fed_seq` | uint | required | — |

Codes: `not_peer`.

per entry; ?cursor=.

#### `GET /fed/v3/cards`

Authentication: relayauth fed_cards.

Response (only the members this version adds or changes):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `kel` | b64url | required | — |
| `keys` | b64url | required | — |
| `key_state_notice` | b64url | optional | — |

Codes: `not_peer`.

per entry, otherwise the /fed/v2/cards entry shape; ?cursor=.

#### `POST /fed/v3/clear`

Authentication: relayauth fed_clear.

Request (only the members this version adds or changes): as in wire 2.

Response (only the members this version adds or changes): as in wire 2.

Codes: `not_peer`.

body of the former /federation/clear.

Removed: /fed/v1/*; /fed/v2/* (with /fed/v2/keys/{aid}); /federation/clear (moved to /fed/v3/clear); POST /agents/keys:lookup; POST /agents/kel:lookup; POST /a2a/v1/agents/card:lookup; POST/GET /agents/{aid}/p2p; GET /p2p/peers; GET /agents/{aid}/card (ADP card); GET /x402/resource/{aid}/{capability} (410 tombstone); the federation fallback of GET /agents/{aid}/keys; request fields: /register invite, pricing, card; /profile pricing; /relay/send to_aid and base64 body; /relay/ack ids; /relay/send response id and warning.

## p2p frames (v 3)

| Op | Direction | Members | Optional | Notes |
|---|---|---|---|---|
| `hello` | both | `v`, `self` | — | — |
| `send` | daemon -> local anetpeer | `v`, `id`, `to`, `envelope`, `addr` | — | addr from the p2p field of a contact-class grant |
| `send` | anetpeer -> remote anetpeer | `v`, `id`, `to`, `envelope` | — | — |
| `send answer` | remote anetpeer -> anetpeer; anetpeer -> daemon | `v`, `id` | `dack`, `error` | dack is 107 characters; error only goes to logs |
| `recv` | anetpeer -> local daemon | `v`, `id`, `envelope` | — | — |
| `ack` | daemon -> anetpeer | `v`, `id` | `dack` | — |
| `nack` | daemon -> anetpeer | `v`, `id`, `error` | — | — |
| `error` | either | `v` | `id`, `error` | — |

Removed: reach frame, reachable, not_delivered.

## Control plane

The local bearer-authenticated API of the daemon. Only the members several components rely on are
registered. Binary values are standard base64.

### error body

Response (only the members this version adds or changes):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `error` | string | required | one sentence in the user's language |
| `reason` | string | required | user reason code |
| `next` | string | optional | a command to copy; omitted when there is none |
| `hub_code` | string | optional | hub_refused only: the hub's code |

every control-plane error; MCP tool error text = error.

### /status

Response (only the members this version adds or changes):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `summary` | array | required | — |
| `summary.topic` | string | required | — |
| `summary.level` | string | required | — |
| `summary.text` | string | required | — |
| `summary.next` | string | optional | — |

summary from a2ashape.StatusSummary; MCP node_status.summary passes it through.

### /tasks/events delivery

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `delivery` | string | required | — |
| `detail` | string | required | — |
| `wait` | string | required | — |
| `text` | string | required | — |

sent when anet.delivery, anet.delivery_detail or anet.delivery_wait changes; does not change anet.state_seq; not in the A2A stream.

### /identity/status

Request: as in wire 2.

Response:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `aid` | string | required | — |
| `name` | string | required | — |
| `state` | enum: `no_hub`, `publishing`, `ok`, `notice_stale`, `stopped`, `deactivated` | required | — |
| `reason` | string | required | — |
| `message` | string | required | — |
| `next` | string | optional | — |
| `key_seq` | uint | required | — |
| `commitment` | base64 | required | key 6 of the latest stored event, 32 bytes |
| `last_rotation` | object | required | {at, mode} or null; mode witness, scheduled, emergency or recover |
| `witness` | object | required | {url, aid} or null |
| `notice` | object | required | {observed_at, age_s} or null |
| `pending` | object | required | {kind, since} or null |
| `old_witness_unacked` | array | required | — |
| `old_witness_unacked.url` | string | required | — |
| `old_witness_unacked.since` | string | required | — |
| `old_witness_unacked.next_try` | string | required | — |
| `recovery` | object | required | an extra attribute, not a state: none, unprotected (with message and next) or protected |
| `recovery.state` | enum: `none`, `unprotected`, `protected` | required | — |
| `recovery.message` | string | optional | — |
| `recovery.next` | string | optional | — |

= MCP node_status.identity.

### /hub-register

Request:

| Member | Type | Presence | Notes |
|---|---|---|---|
| `hub` | string | required | — |
| `name` | string | optional | — |
| `caps` | array | optional | — |
| `next_digest` | base64 | optional | — |
| `unprotected` | bool | optional | only with next_digest: it comes from the unprotected recovery file |
| `dry_run` | bool | optional | — |

Response (joined, updated or refused):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `hub` | string | required | — |
| `aid` | string | required | — |
| `state` | enum: `registered`, `pending_admission`, `retrying`, `refused` | required | — |
| `reason` | string | required | — |
| `message` | string | required | — |
| `next` | string | optional | — |
| `next_attempt_at` | string | optional | — |
| `recovery` | object | optional | — |
| `recovery.state` | enum: `none`, `unprotected`, `protected` | required | — |
| `recovery.message` | string | optional | — |
| `recovery.next` | string | optional | — |
| `hub_code` | string | optional | — |
| `hub_error` | string | optional | — |

Response (dry_run):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `hub` | string | required | — |
| `hub_aid` | string | required | — |
| `action` | enum: `join`, `update`, `switch` | required | — |
| `recovery_needed` | bool | required | — |

a first join without next_digest is 400 config_invalid; recovery_setup_required is not a join state.

### /payments/status

Response (only the members this version adds or changes):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `spent_today` | uint | required | — |
| `agent_spent_today` | uint | required | — |
| `left_today` | uint | required | — |
| `agent_left_today` | uint | required | — |
| `payees` | uint | required | — |

spent_24h and agent_spent_24h renamed; payees_file and payees_restricted removed.

### /agents/card

Response (only the members this version adds or changes):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `charge` | enum: `free`, `partial`, `paid` | required | — |
| `key_state` | string | required | — |
| `prices` | array | optional | — |
| `pricesFetchedAt` | string | optional | — |
| `priceNote` | string | optional | — |

charge from the card shown (the verified extended card, else the public card).

### /agents/list

Response (only the members this version adds or changes):

| Member | Type | Presence | Notes |
|---|---|---|---|
| `charge` | enum: `free`, `partial`, `paid` | required | — |
| `key_state` | string | required | — |

per entry; public card only; never fetches an extended card.

## A2A URIs

| URI | Where | Status | Notes |
|---|---|---|---|
| `https://agentnetwork.org.cn/a2a/bindings/anet-relay/v2` | public card protocolBinding | active | replaces v1 |
| `https://agentnetwork.org.cn/a2a/bindings/anet-relay/v1` | - | deleted | — |
| `https://agentnetwork.org.cn/a2a/bindings/anet-p2p/v1` | - | deleted | cards no longer contribute a direct interface |
| `https://agentnetwork.org.cn/a2a/ext/anet-card/v1` | public and extended card | active | — |
| `https://agentnetwork.org.cn/a2a/ext/anet-evidence/v1` | public card | active | — |
| `https://agentnetwork.org.cn/a2a/ext/anet-pricing/v1` | - | deleted | a hub refuses a public card carrying it |
| `https://agentnetwork.org.cn/a2a/ext/anet-price/v1` | provider-signed extended card only | active | params {network, asset, prices: [{skillId, amount}]}; a hub refuses a public card carrying it |
| `https://agentnetwork.org.cn/a2a/ext/anet-origin/v1` | local proxy card | active | params add originExtendedCard and keyState |
| `https://agentnetwork.org.cn/a2a/ext/anet-preview/v1` | public card when stream_preview is not off; the proxy card only when the remote public card declares it | active | never required; no params |
| `https://github.com/google-agentic-commerce/a2a-x402/blob/main/spec/v0.2` | public card | active | a2a-x402 |

## Metadata keys

`e2e`: inside the sealed body, between peers. `local`: on what this node projects to its own clients
(local A2A, control plane, MCP); a local-only key is never sent to a peer and never read from one.

| Key | Where | Value | Status | Notes |
|---|---|---|---|---|
| `anet.reason` | e2e, local | string | active | a user reason code (StatusMsg, ResultResp, Task, Message) |
| `anet.retry_after_ms` | e2e, local | uint | active | required with budget |
| `anet.preview_mode` | e2e | string: on, with_reasoning | active | first DelegateReq.metadata or a follow-up ChatMsg.metadata |
| `anet.a2aError` | e2e | string | active | an A2A error name in a status message |
| `anet.state` | e2e | string | active | the task state a provider message or result asks for; a final reply no longer carries working |
| `anet.inbound` | e2e, local | string | active | inbound-policy outcome, e.g. pending_approval |
| `anet.final` | — | bool | deleted | removed |
| `anet.delivery` | local (local only) | string: pending, confirmed, unconfirmed | active | — |
| `anet.delivery_detail` | local (local only) | string: not_sent, sent, queued_at_hub | active | only with pending or unconfirmed |
| `anet.delivery_wait` | local (local only) | string | active | a waiting hub code, session_unavailable, rotation_pending, notice_stale or credential_refused |
| `anet.content_expires_at` | local (local only) | string | active | RFC 3339, Task |
| `anet.payment_note` | local (local only) | string | active | one sentence, Task |
| `anet.spend_check` | local (local only) | object | active | {who, amount, reason, reason_tier?, reason_limit?}; reason_tier auto, agent or manual |
| `anet.deduplicated` | local (local only) | bool | active | only on the answer judged a retry; true |
| `anet.preview` | local, artifact (local only) | bool | active | preview artifacts and TaskArtifactUpdateEvent; true |
| `anet.identity_note` | local (local only) | string | active | one sentence (identity.unprotected or its .resume variant) on tasks this node projects (local A2A, control /tasks/*, MCP), only while the identity has no recovery passphrase |
| `anet.receipt_verified` | local | string: verified, unverified, unknown, mismatch | active | — |
| `anet.effect_status` | local | string | active | capability effect status: OK, UNVERIFIED, FAILED, UNAVAILABLE, PAYMENT_REQUIRED |
| `anet.request_cid` | local | string | active | — |
| `anet.result_cid` | local | string | active | — |
| `anet.peer_aid` | local | string | active | — |
| `anet.role` | local | string | active | requester or provider |
| `anet.skill` | local | string | active | capability of a capability task; on an incoming SendMessage it asks for a capability call |
| `anet.state_seq` | local | uint | active | increases with every state write |
| `anet.trust` | local | string | active | how an inbound task was admitted |
| `anet.receipt` | local | object | active | the provider's signed receipt and its check |
| `anet.cancel_requested` | local | bool | active | — |
| `anet.trusted` | local | bool | active | tells a provider-side backend whether the peer is trusted |
| `anet.payment.accept` | local | object | active | the payment option a local client chose |
| `anet.quote_expires_at` | local | uint | active | unix ms |
| `anet.unverified_receipts` | local | array | active | — |
| `anet.auth_id` | local | string | active | — |
| `anet.wait` | local | string | active | control-plane wait hint |
| `anet.args` | local | object | active | capability arguments on a local message |
| `anet.official` | local | bool | active | marks an agent the official manifest lists |
| `anet.cid` | part, local | string | active | file part: the attachment's content id |
| `anet.size` | part, local | uint | active | file part: size |
| `anet.attachment_cid` | part, local | string | active | file part carrying only metadata |
| `anet.truncated` | part, local | bool | active | what a stream event cut |
| `anet.settlement.receipt` | extension | any | active | x402 SettlementResponse extension: the hub's signed receipt |
| `anet.replayed` | extension | any | active | x402 SettlementResponse extension |
| `anet.original_transaction` | extension | any | active | x402 SettlementResponse extension |
| `anet.error_detail` | extension | any | active | x402 SettlementResponse extension |
| `anet.settlement_verified` | extension | any | active | x402 SettlementResponse extension: the requester's verdict |
| `anet.settlement.voucher` | extension | any | deleted | vouchers removed |
| `anet.pricing` | card | any | deleted | public price list removed |

## TaskDoc contexts

| Key | Format | Visibility | Presence | Notes |
|---|---|---|---|---|
| `args` | json | as before | cond | required for a capability call; top-level keys starting with $ are anet's; 0.3.0 defines only $files |
| `anet.nonce` | text | private | must | no U+0000 |
| `anet.requester_commit` | text | private | must | 32 bytes, base64url |
| `anet.review_key` | text | private | must | 32 bytes, base64url |

## Evidence events

| Event | Status | Payload | Notes |
|---|---|---|---|
| `anet.delivery.expired` | active | `handed`, `reason` | reason in undeliverable, delivery_unconfirmed, withdrawn, recipient_unknown, too_large, too_large_for_stranger, bad_envelope; expired and refused removed |
| `anet.local_state.lost` | active | `hub_seq`, `local_seq`, `failed_tasks` | — |
| `anet.retention.changed` | active | `from`, `to`, `deleted_interactions` | — |
| `anet.interaction.pruned` | active | `trust` | trust covers every class |
| `anet.identity.rotated` | active | `seq`, `mode`, `witness` | mode witness, scheduled, emergency or recover |
| `anet.autoreply.invoked` | active | `mode`, `sandbox`, `exit`, `unavailable`, `egress` | mode direct, sandbox or openai; sandbox bwrap, seatbelt or empty |
| `anet.hub.admission` | active | `hub`, `state`, `reason` | — |
| `anet.policy.changed` | active | — | covers auto_reply.trusted, auto_reply.sandbox.egress_allow, runs_per_day, runs_per_peer_per_day, api_key_set |
| `anet.capability.effect` | active | — | observed_state is recorded as a CID only |
| `anet.supply.proof` | active | `to_day`, `root`, `balance`, `result` | — |
| `anet.review.uploaded` | active | `ix`, `subject`, `rating`, `day` | — |
| `anet.credit.redeemed` | active | — | the redeemer's permanent local record |
| `anet.issuance.head_seen` | active | `hub`, `seq`, `id` | payload is the epoch chain head |
| `anet.voucher.redeemed` | deleted | — | — |
| `anet.voucher.refused` | deleted | — | — |
| `anet.delegation.sent` | active | — | carried over from 0.2.1 |
| `anet.delegation.received` | active | — | carried over from 0.2.1 |
| `anet.delegation.refused_summary` | active | — | carried over from 0.2.1 |
| `anet.result.accepted` | active | — | carried over from 0.2.1 |
| `anet.interaction.receipt` | active | — | carried over from 0.2.1 |
| `anet.payment.settled` | active | — | carried over from 0.2.1 |
| `anet.payment.authorized` | active | — | carried over from 0.2.1 |
| `anet.payment.quoted` | active | — | carried over from 0.2.1 |
| `anet.shell.command` | active | — | carried over from 0.2.1 |
| `anet.shell.refused` | active | — | carried over from 0.2.1 |
| `anet.backend.forwarded` | active | — | carried over from 0.2.1 |
| `anet.backend.failed` | active | — | carried over from 0.2.1 |
| `anet.task.no_response` | active | — | carried over from 0.2.1 |
| `anet.evidence.gap` | active | — | carried over from 0.2.1 |
| `anet.message.sent` | active | — | carried over from 0.2.1 |
| `anet.message.received` | active | — | carried over from 0.2.1 |

ael records:

| Type | Version | Payload | Status |
|---|---|---|---|
| `anet.supply.epoch` | 2 | `v`, `from_day`, `to_day`, `root`, `outstanding`, `depth` | active |
| `anet.credit.issued` | 1 | — | deleted |
| `anet.credit.retired` | 1 | — | deleted |
| `anet.credit.opening` | 1 | — | deleted |

## Reason codes

Seal reasons are kebab-case and only counted and logged. Wire and user codes match
`^[a-z][a-z0-9_]{0,29}$`; one code has one meaning wherever it appears.

Hub (wire 3):

| Code | HTTP | Class | Notes |
|---|---|---|---|
| `wire_too_old` | 426 | wire | — |
| `wire_too_new` | 400 | wire | — |
| `bad_request` | 400 | wire | — |
| `not_found` | 404 | wire | — |
| `too_large` | 413 | wire | — |
| `internal` | 500 | wire | — |
| `unauthorized` | 401 | auth | — |
| `ts_stale` | 401 | auth | carries floor |
| `replayed` | 401 | auth | — |
| `key_retired` | 401 | auth | — |
| `identity_headers_not_allowed` | 400 | auth | — |
| `bad_envelope` | 400 | relay | — |
| `expired` | 400 | relay | — |
| `bad_exp` | 400 | relay | — |
| `session_invalid` | 401 | relay | — |
| `access_invalid` | 403 | relay | — |
| `recipient_unknown` | 404 | relay | — |
| `too_large_for_stranger` | 413 | relay | — |
| `kid_stale` | 409 | relay | — |
| `rate_limited` | 429 | relay | waits: the daemon puts it in anet.delivery_wait and keeps the task |
| `strangers_busy` | 429 | relay | waits: the daemon puts it in anet.delivery_wait and keeps the task |
| `redelivery_limited` | 429 | relay | waits: the daemon puts it in anet.delivery_wait and keeps the task |
| `mailbox_full` | 507 | relay | waits: the daemon puts it in anet.delivery_wait and keeps the task |
| `home_unreachable` | 502 | relay | waits: the daemon puts it in anet.delivery_wait and keeps the task |
| `revocation_list_full` | 429 | relay | — |
| `bucket_too_narrow` | 400 | relay | — |
| `bad_status_query` | 400 | delivery | — |
| `bad_ack_item` | 400 | delivery | — |
| `not_peer` | 403 | federation | — |
| `unknown_destination` | 404 | federation | — |
| `source_rate` | 429 | federation | — |
| `admission_required` | 403 | register | — |
| `pow_required` | 403 | register | — |
| `registration_quota` | 429 | register | — |
| `invite_removed` | 400 | register | — |
| `witness_not_this_hub` | 400 | register | — |
| `aid_deactivated` | 410 | register | — |
| `unknown_aid` | 404 | register | — |
| `kel_invalid` | 400 | register | — |
| `kel_fork` | 409 | register | — |
| `kel_rollback` | 409 | register | — |
| `kel_ts_out_of_window` | 400 | register | — |
| `keys_rollback` | 409 | register | carries stored_seq |
| `proof_unavailable` | 404 | payment | — |
| `gateway_removed` | 410 | payment | — |
| `probation` | 403 | payment | — |
| `review_exists` | 409 | payment | — |
| `requester_commit_mismatch` | 400 | payment | — |
| `receipt_not_reviewable` | 400 | payment | — |
| `review_window_closed` | 400 | payment | — |

Seal: `bad-outer`, `bad-version`, `unknown-suite`, `wrong-recipient`, `sealed-to-unknown-key`, `decrypt-failed`, `bad-inner`, `unknown-critical-field`, `to-mismatch`, `bad-pad`, `kel-too-large`, `bad-kel`, `from-mismatch`, `expired`, `from-future`, `bad-lifetime`, `bad-sig`, `bad-key-state`, `revoked-key`, `rotation-grace-expired`, `aid-mismatch`, `bad-keyset`, `no-usable-key`, `invalid-input`, `internal`, `bad-wrap`, `bad-rk`, `rk-mismatch`, `sealed-to-closed-interaction`, `ikey-mismatch`, `exp-mismatch`, `access-invalid`, `witness-missing`, `witness-stale`, `witness-mismatch`, `witness-invalid`, `witness-unknown`, `kel-from-future`.

Delivery note: `not_accepting`, `denied`, `capability_not_public`, `pending_full`, `busy`, `caller_busy`, `quota_caller_per_min`, `quota_caller_per_day`, `args_too_large`, `files_count`, `files_too_large`, `file_type_not_accepted`, `bad_request`, `key_state`, `canceled`, `task_not_found`, `task_ended`, `invalid`.

C1 (internal to ANetLink; never shown to a user as is): `not_permitted`, `bad_request`, `too_large`, `unsupported_media`, `unknown_capability`, `c1_version`, `not_found`, `internal`.

x402 errorReason additions: `payee_not_local`, `auth_window_too_long`, `payee_mismatch`.

User (the reason table of the daemon; sentences and variants live only there): `agent_unsupported`, `aid_invalid`, `allow_confirm`, `api_base_insecure`, `api_key_empty`, `api_key_on_argv`, `approve_confirm`, `args_reserved_key`, `args_too_large`, `auth_window_too_long`, `backend_failed`, `bad_envelope`, `bad_image`, `bad_request`, `balance_mismatch`, `binding_mismatch`, `budget`, `budget_invalid`, `busy`, `c1_uid_refused`, `c1_version`, `caller_busy`, `canceled`, `capability_not_public`, `capability_not_served`, `card_price_unavailable`, `cli_removed`, `client_payload_unsupported`, `clock_skew`, `config_invalid`, `config_key_removed`, `connection_lost`, `credential_refused`, `daemon_not_running`, `deduplicated`, `delivery_unconfirmed`, `denied`, `egress_allow_invalid`, `egress_allow_model_host`, `egress_allow_too_many`, `egress_confirm`, `egress_ech`, `egress_host_not_allowed`, `egress_not_tls`, `egress_plain_http`, `egress_port`, `egress_private_address`, `egress_sni_mismatch`, `egress_too_large`, `egress_tunnels`, `egress_unauthorized`, `extended_card_not_configured`, `extended_card_not_offered`, `extended_card_unavailable`, `file_type_not_accepted`, `files_count`, `files_too_large`, `fs_isolation_failed`, `home_unreachable`, `hub_pending_admission`, `hub_refused`, `hub_retrying`, `hub_switch_pending_admission`, `hub_switch_requires_rotation`, `hub_unreachable`, `identity_deactivated`, `identity_stopped`, `identity_v02`, `interrupted`, `invalid`, `invite_removed`, `key_compromise`, `key_state`, `limits_confirm`, `limits_summary`, `local_state_lost`, `mailbox_full`, `message_id_reused`, `needs_operator_approval`, `netns_failed`, `no_api_base`, `no_api_key`, `no_bwrap`, `no_cgroup_limits`, `no_face_in_a`, `no_face_in_b`, `no_hub_yet`, `no_local_task`, `no_model`, `no_pending_quote`, `no_response`, `no_sandbox_exec`, `not_accepting`, `not_requested`, `notice_stale`, `old_hub_unacked`, `omitted_from_ledger`, `operator_rejected`, `option_not_offered`, `over_agent_daily_limit`, `over_daily_limit`, `over_single_limit`, `passphrase_too_short`, `payee_confirm`, `payee_not_allowed`, `payee_not_local`, `payees_unreadable`, `payer_mismatch`, `payments_unavailable`, `peer_cred_unsupported`, `peer_uid_mismatch`, `pending_approval`, `pending_expired`, `pending_full`, `platform_unsupported`, `policy_encoding`, `policy_field`, `policy_mcp_servers`, `policy_path`, `policy_server_tool`, `preview_off`, `probation`, `proof_expired`, `proof_invalid`, `proof_unavailable`, `provider_policy`, `publishing`, `quota_caller_per_day`, `quota_caller_per_min`, `quote_above_card_price`, `quote_expired`, `rail_not_payable`, `rate_limited`, `receipt_mismatch`, `receipt_not_reviewable`, `recipient_unknown`, `recipient_unverifiable`, `recover_not_witness`, `recover_target_exists`, `recovery_file_missing`, `recovery_file_unprotected`, `recovery_mismatch`, `recovery_passphrase_wrong`, `recovery_wrong_identity`, `redeem_confirm`, `redelivery_limited`, `refused`, `registered`, `requester_commit_mismatch`, `result_refused`, `retention_invalid`, `review_exists`, `review_window_closed`, `rotation_emergency_done`, `rotation_pending`, `run_budget_requests`, `run_budget_upload`, `sandbox_unavailable`, `seccomp_failed`, `session_unavailable`, `strangers_busy`, `task_ended`, `task_not_found`, `task_not_open`, `timeout`, `too_large`, `too_large_for_stranger`, `trusted_direct_confirm`, `tty_required`, `unavailable`, `undeliverable`, `unknown_code`, `unknown_debit`, `userns_blocked`, `userns_unavailable`, `wire_too_new`, `wire_too_old`, `witness_hub_leave`, `witness_unreachable`, `work_dir_invalid`.

Hub operator: `hub_flag_removed`, `quota_below_default`, `hub_recovery_setup_required`, `hub_running`, `hub_identity_v02`.

Retired or never introduced (never to be reused):

- `signed_status_query`: merged into identity_headers_not_allowed
- `bad_signature`: merged into unauthorized
- `access_revoked`: merged into access_invalid
- `home_unknown`: merged into recipient_unknown
- `forwarded`: no longer a status value
- `quota_global_per_min`: merged into busy
- `max_inflight`: merged into busy
- `provider_busy`: x402a2a; merged into busy
- `task_nonce_required`: merged into bad_request
- `peer_refused_key_state`: merged into key_state
- `caller_unwitnessed`: removed
- `prepay_removed`: never introduced: DelegateReq key 6 is retired
- `hub_flag_fixed`: never introduced: hub_flag_removed.fixed
- `recovery_setup_required`: never introduced: an identity without a recovery passphrase is the recovery.state unprotected; not to be reused
- `payment_extension_not_activated`: not registered
- `receipt.mismatch`: spelled receipt_mismatch

## Layout: dack (80 bytes)

| Part | Offset | Length | Content |
|---|---|---|---|
| dack | 0 | 16 | tok(o): o = 1 processed, 2 refused |
| dack | 16 | 64 | note |
| note | 0 | 12 | nonce, fresh from crypto/rand |
| note | 12 | 52 | ChaCha20-Poly1305(note_key, nonce, pt, aad = tok(o)): ciphertext and 16-byte tag |
| pt | 0 | 1 | format, 0x01 |
| pt | 1 | 4 | retry_after, seconds, big-endian u32, capped at 86 400 |
| pt | 5 | 1 | reason length L, 0-30 |
| pt | 6 | 30 | reason code: L bytes of [a-z0-9_], then zeros |

## Shared storage

| Where | Table | Columns | Never | Notes |
|---|---|---|---|---|
| hub | `relay_message` | id INTEGER PK AUTOINCREMENT (recipient cursor and ack only); rid BLOB(16) NOT NULL UNIQUE (sender only); to_aid; env_digest BLOB(32) NOT NULL; class INTEGER (1 or 2; kind 0 counts as 2); cap_id BLOB(16), NULL for kind 0; size; created_at (= accepted_at, read in the queueing transaction); exp INTEGER NULL; payload | `sender`, `kind`, `ix`, `kid` | UNIQUE(to_aid, env_digest); partial index WHERE exp IS NOT NULL |
| hub | `other` | relay_dack(handle PK, dack, exp); relay_redelivery(env_digest PK, count, window_start); cap_revocation(owner, cap_id, revoked_at) PK(owner, cap_id); quota_override; agent.dir_hash; agent.dir_box; notice_cache; restore_state; x402_first_verify; dereg_event | — | every path that deletes an agent row goes through aghub.DeregisterTx; areas register their AID-keyed deletions in deregSteps |
| hub | `backup` | includes cap_revocation, quota_override, the admission tables and the ledger-window tables | `relay_message`, `relay_dack`, `relay_redelivery`, `notice_cache`, `dereg_event`, `keys/review_tag.key` | — |
| daemon | `outbox` | the delivery outbox columns; sealed_kid; sealed_kid_na; sealed_kss; sealed_notice_at; body (data-key ciphertext) | `access` | the capability credential is rebuilt on every attempt |
| daemon | `outbox_ver` | the delivery outbox version columns, with via renamed via_hub | — | — |
| daemon | `other` | caps_issued; caps_held; ix_key; ix_dek; interaction.peer_rk; pending.peer_rk; cancel_tomb; refused.reason; interaction.reason_variant TEXT NOT NULL DEFAULT ''; interaction.reason_arg TEXT NOT NULL DEFAULT ''; message.client_key; client_digest; client_unanswered; review_seed; review_rsalt; pay_note; peer_ext_card; liab_proof; review_outbox; pending row arrival | — | — |
| daemon | `key files` | mbox.key (MboxKeyFile); enc_keys.cbor (EncKeyFile); identity.kel (IdentityFile); key_state_notice.cbor (KeyStateNoticeFile); recovery_local.key (32 raw bytes) and recovery_local.anetrec (RecoveryBlob with kdf = local): read and written by the CLI only; the daemon never opens them | — | — |

## Other registered strings

| String | Class | Status | Notes |
|---|---|---|---|
| `anet-credit` | asset | active | x402 asset of the anet-credit scheme |
| `anet-relay/` | label | deleted | relayauth v1 preimage prefix |
| `anet.doctor/1` | json-format | active | anet doctor --json schema |
| `anet.evidence-export/1` | json-format | active | evidence export format |
| `anet/localpeer-proof/v1` | label | active | local peer challenge MAC (HMAC under the anet/localpeer-key/v1 key); local only |
| `anet/backend-context/1` | label | active | hash prefix of the context id a local backend sees; local only |
| `anet/backend-message/1` | label | active | hash prefix of the message id a local backend sees; local only |
| `anet-daemon` | name | active | signer name in the local proxy card's anet-card params |
| `anet-official` | name | active | program name |
| `anet-hub` | name | active | program name |
| `anet-hub-admin` | name | active | program name |
| `anet.reply` | artifact-id | active | A2A artifact id of a text task's reply |
| `anet.result` | artifact-id | active | A2A artifact id of a capability call's deliverable |
| `anet-wire-registry/1` | json-format | active | format of this register |

## Identity-key signers

Every call of an identity signing method (`(*github.com/ANetResearch/ANetCore/identity.Controller).Sign`, `(*github.com/ANetResearch/ANetCore/identity.Controller).CurrentPrivateKey`), and every reference that hands one on, is
made from one of these functions; each signs a typed object, one of the carried untyped ones,
or the relayauth text preimage (L22).

| Repository | Function | Signs |
|---|---|---|
| ANetCore | `(*payment.Authorization).Sign` | PaymentAuthorization |
| ANetCore | `(*payment.Receipt).Sign` | PaymentReceipt |
| ANetCore | `(*tsir.TaskDoc).Sign` | TaskDocPreimage |
| ANetCore | `(*ael.EventRecord).Sign` | AELRecord |
| ANetCore | `(*ael.HeadAttestation).Sign` | AELHeadAttestation |

## Fields that must not hold U+0000

Functions that build a 0x00-separated input refuse a text field holding U+0000:

- ANetCore dirbox h (L9)
- ANetCore session key delivery (L7)
- ANetCore session MAC (L8)
- ANetCore KEL next-key derivation (L19)
- ANetCore regpow hash (L23)
- ANetCore evidence ix_commit (L27)
- ANetCore evidence requester_commit (L28)
- ANet x402a2a.PayBind (L34)
- ANetHub review tag (L31)
- ANetHub settlement guard (L33)
