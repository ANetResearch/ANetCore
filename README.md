# ANetCore

**The protocol kernel of the ANet suite** — deterministic encoding, content
addressing, signed objects, identity, and task semantics. Pure logic, zero I/O:
everything that touches a network or a disk lives in the applications
([ANet](https://github.com/ANetResearch/ANet) daemon,
[ANetHub](https://github.com/ANetResearch/ANetHub),
[ANetLink](https://github.com/ANetResearch/ANetLink)), all of which import this
module and never each other.

Normative source: the `design3` specification corpus
(`_CONVENTIONS` + per-protocol specs). This library is a conforming
implementation, pinned by golden vectors.

## Packages

| Package | Implements | Spec anchor |
|---|---|---|
| `coredet` | CoreDet-CBOR — RFC 8949 §4.2 Core Deterministic Encoding profile (C-R1/C-R2 restrictions, C-D1–D3 riders) | `_CONVENTIONS §2` |
| `anetcid` | CIDv1 · dag-cbor · sha2-256, frozen prefix `0x01 0x71 0x12 0x20`, multibase `b` | `_CONVENTIONS §3` |
| `aobj` | AObjEnvelope — detached Ed25519 (COSE alg −8) signature over canonical preimages; verify-before-use | `_CONVENTIONS §5` |
| `identity` | KEL/AID — KERI-style key event log, pre-rotation, AID derivation | arch-03 P1 |
| `tsir` | TaskDoc, closed predicate calculus, `EffectRecord`, acceptance evaluation | tsir-spec |
| `adp` | AgentCard — capability self-description, typed CID mounts | adp-spec |
| `agenturi` | `agent://` URI scheme — parsing & canonical form | agent-uri-spec |
| `golden` | Conformance vectors — byte-for-byte oracle shared with `design3/tools/vectors.py` | `_CONVENTIONS §8` |
| `ael` | Agent Event Ledger — per-DID append-only anti-fork hash chain (P6) | evidence-spec |
| `evidence` | Receipt + Review — the interaction-anchored trust pair anyone can verify | evidence-spec |
| `delegation` | The relayed delegation wire: signed request, completion, chat; `VerifyDelegateReq`, `VerifyResult` | arch-03 |
| `relayauth` | The canonical challenge a client signs to authenticate a relay mailbox operation | arch-03 |
| `payment` | x402 wire objects + the `anet-credit` scheme: signed authorizations and settlement receipts | x402 v2 |
| `seal` | End-to-end relay envelope: signed `EncKeySet`, sign-then-encrypt `SealedEnvelope` (HPKE Base, X25519 / HKDF-SHA256 / ChaCha20-Poly1305), Padmé padding (v0.15.0) | A2A-DESIGN §3 |
| `a2acard` | A2A AgentCard signing and verification: RFC 8785 JCS + JWS EdDSA, standard library only (v0.15.0) | A2A-DESIGN §10.3 |

The last three arrived by the rule below rather than by design: each was a
wire between the daemon and the Hub, duplicated in both repositories, and
`delegation` had already diverged by 28 lines in a way neither side could
detect — CBOR `keyasint` drops an unknown key without a word. A wire type
that lives in two repositories is a wire type that will diverge.

## Use

```bash
go get github.com/ANetResearch/ANetCore
```

```go
pre, _ := coredet.Marshal(obj)          // canonical preimage
cid    := anetcid.FromPreimage(pre)     // content id
env, _ := aobj.Sign(ctrl, pre)          // detached Ed25519 envelope
ok     := aobj.Verify(env, pre, ks)     // verify-before-use, always
```

## Conformance

`go test ./...` includes the golden-vector suite: canonical preimage bytes,
CIDs, and signatures under the frozen suite test key
(`seed = SHA-256("anet-suite-test-key-v1")`). Two independent implementations
that pass these vectors produce byte-identical wire objects.

## Versioning

Changes per version: [CHANGELOG.md](CHANGELOG.md). v0.15.0 (the kernel of
anet 0.2.0 and hub wire 2) is planned and not tagged yet.

Semantic versioning. Any change that alters bytes on the wire (preimage
membership, CID prefix, envelope shape) is a **major** version. The CID prefix
and the suite test key are frozen and will never change within v1.

## Status

Extracted from the AgentNetwork v3 reference implementation
(`internal/v3/*`, verbatim, imports rewritten), plus the daemon/Hub wire
consolidated here in v0.5.x. 102 tests green.
Module design rationale: `ANet/docs/CONTRACTS-zh.md` (anet4 five contracts).

License: ANet Open Source License, a modified Apache License 2.0 (see
[LICENSE](LICENSE)): commercial use is allowed, including as a library in
your own product; operating a multi-tenant hosted hub for third parties
needs written authorization; the A2A specification work (ANet `docs/a2a/`)
and the code contributed to the A2A project are plain Apache-2.0. Questions:
hi@anet0.com. This applies from v0.15.0; v0.3.0 through v0.14.0 were
published under the ANet Community License 1.0, and versions ≤ v0.2.x under
Apache-2.0, and each stays under its license.
