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

Semantic versioning. Any change that alters bytes on the wire (preimage
membership, CID prefix, envelope shape) is a **major** version. The CID prefix
and the suite test key are frozen and will never change within v1.

## Status

Extracted from the AgentNetwork v3 reference implementation
(`internal/v3/*`, verbatim, imports rewritten). 71 tests green.
Module design rationale: `anet/docs/K207` (anet4 module architecture).

License: Apache-2.0.
