<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/media/hero-dark.png" />
  <img src="docs/media/hero-light.png" alt="ANetCore — protocol and cryptography kernel of the ANet A2A network" width="100%" />
</picture>

[![Go Reference](https://img.shields.io/badge/go.dev-reference-3D4146?style=flat-square&labelColor=1A1C1F&logo=go&logoColor=white)](https://pkg.go.dev/github.com/ANetResearch/ANetCore)
[![CI](https://img.shields.io/github/actions/workflow/status/ANetResearch/ANetCore/ci.yml?branch=main&style=flat-square&label=CI&labelColor=1A1C1F&color=3D4146)](https://github.com/ANetResearch/ANetCore/actions/workflows/ci.yml)
[![Tag](https://img.shields.io/github/v/tag/ANetResearch/ANetCore?sort=semver&style=flat-square&label=tag&labelColor=1A1C1F&color=C9241B)](https://github.com/ANetResearch/ANetCore/tags)
[![Go](https://img.shields.io/github/go-mod/go-version/ANetResearch/ANetCore?style=flat-square&labelColor=1A1C1F&color=3D4146)](go.mod)
[![License](https://img.shields.io/badge/license-ANet%20Open%20Source-3D4146?style=flat-square&labelColor=1A1C1F)](LICENSE)

| **[Docs](https://docs.agentnetwork.org.cn/docs/en/latest/)** | **[Use](#use)** | **[Releases](https://github.com/ANetResearch/ANetCore/tags)** | **[ANet](https://github.com/ANetResearch/ANet)** | **[ANetHub](https://github.com/ANetResearch/ANetHub)** | **[Discussions](https://github.com/ANetResearch/ANet/discussions)** |
|:---:|:---:|:---:|:---:|:---:|:---:|

**English** · [简体中文](README.zh-CN.md)

# ANetCore

**The protocol and cryptography kernel for agent interoperability and security in ANet.**

ANetCore defines the bytes that must be identical across ANet implementations: deterministic encoding, content
addressing, signatures, identity and key evolution, end-to-end sealing, and the wire registry. It is pure logic
with no I/O, pinned by golden vectors and cross-checked by an independent implementation. ANet and ANetHub import
this module; networks, disks and clocks remain in the applications. Wire objects follow A2A and a2a-x402 where
those define them, with additions published as drafts for the A2A community.

## Use

```sh
go get github.com/ANetResearch/ANetCore@v0.16.0
```

**Compatibility:** v0.16.0 is required by anet 0.3.0 and ANetHub 0.3.0, and implements hub wire 3. It introduces
a breaking wire change: every identity is new and nothing is migrated. 0.2.x nodes and hubs do not interoperate
with it. See [CHANGELOG.md](CHANGELOG.md).

Releases are Git tags consumed as Go modules. The `go` command checks them against the public checksum database
([sum.golang.org](https://sum.golang.org)); `go mod verify` re-checks the local module cache.

## Get started

Encode canonical bytes, compute their CID, reject unknown keys during decoding, and create an agent identity:

```go
// Canonical bytes: sorted keys, shortest integers, definite lengths.
pre, _ := coredet.Marshal(map[int]any{2: uint64(42), 1: "hello"})
// a2 01 65 68656c6c6f 02 18 2a

// The content id of those bytes.
cid, _ := anetcid.Sum(pre)
// bafyreidsnafaklrfgsm5a2uk5u3kdosvqlmf2v6a77yajzzuqxsybvmf3u

// Strict decoding: a key the struct does not name is an error, never silently dropped.
var v struct {
	Greeting string `cbor:"1,keyasint"`
}
err := coredet.UnmarshalStrict(pre, &v) // error: key 2 is unknown

// A new agent identity. Its AID is the CID of its inception event and survives every rotation.
ctrl, _ := identity.InceptAgent(uint64(time.Now().UnixMilli()))
fmt.Println(ctrl.AID()) // bafyrei…
```

The CID can be checked independently in Python, without this module:

```sh
python3 -c 'import hashlib,base64; b=bytes.fromhex("a2016568656c6c6f02182a"); print("b"+base64.b32encode(bytes([1,0x71,0x12,0x20])+hashlib.sha256(b).digest()).decode().lower().rstrip("="))'
# bafyreidsnafaklrfgsm5a2uk5u3kdosvqlmf2v6a77yajzzuqxsybvmf3u
```

See the [Go reference](https://pkg.go.dev/github.com/ANetResearch/ANetCore) for package APIs and
[wire keys](docs/wire-keys.md) for exact wire constructions.

## When to use ANetCore

- **Implementing ANet wire objects:** encoding, hashing, signing and sealing must produce the same bytes across applications.
- **Building a second implementation:** golden vectors and an independent Python implementation provide conformance checks.
- **Auditing ANet:** the protocol kernel defines identity, cryptographic constructions and every key number on the wire.
- **Sharing protocol logic between applications:** ANet and ANetHub import the same wire types rather than defining them separately.

ANetCore is not the daemon, CLI, MCP endpoint, registry or relay. Those belong to
[ANet](https://github.com/ANetResearch/ANet) and [ANetHub](https://github.com/ANetResearch/ANetHub).
ANetLink remains on an earlier ANetCore; its interface with the daemon is checked against vector files tested
by both repositories.

## Key properties

| Property | Behavior |
|---|---|
| **Pure logic, no I/O** | No network, files or clock; callers supply `now` for time checks |
| **Deterministic encoding** | CoreDet-CBOR uses sorted keys, shortest integers and definite lengths; no tags or duplicate keys |
| **Frozen content addressing** | CIDv1, dag-cbor and sha2-256 with prefix `0x01 0x71 0x12 0x20` |
| **One wire registry** | Keys, labels, actions and reason codes are registered once; retired values are never reused and are refused |
| **Byte-for-byte conformance** | Golden vectors, negative cases and an independent Python implementation check the covered constructions |
| **Daily encryption keys** | One key per UTC day, published 14 days ahead, each valid for at most two days |
| **Stable identity** | An agent's AID is the CID of its inception event and survives every rotation |
| **Explicit wire versioning** | Before 1.0, a minor version may change wire bytes; a patch version never does |

## What ANetCore does

ANetCore supplies the shared protocol constructions used by the daemon and hub. A wire type is defined once
and cannot drift between them. For sealed messages, the kernel provides the following flow:

1. **Encode and address.** Produce CoreDet-CBOR bytes and compute their content identifier.
2. **Sign.** Create detached Ed25519 signatures over CoreDet preimages, using registered type tags and labels.
3. **Seal.** Apply envelope v2 sign-then-seal with HPKE, optionally adding a second layer to a per-interaction key.
   The signature covers both layers.
4. **Authenticate delivery.** Use a recipient-issued delivery credential after first contact; first contact uses
   a session MAC that the hub can check but cannot pass on as proof.
5. **Open and verify.** Verify signed objects before use and require decoded signed bodies to re-encode to the
   received bytes.
6. **Confirm delivery.** Derive confirmation tokens from the HPKE exporter. A hub can withhold a confirmation
   but cannot forge one.

### Core capabilities

| Capability | What it does | Why it matters |
|---|---|---|
| **Canonical encoding and CIDs** | Encodes CoreDet-CBOR and hashes it with the frozen CID prefix | Implementations can produce and check identical bytes and identifiers |
| **Signatures and domain separation** | Signs CoreDet preimages with Ed25519 using registered constructions | A valid signature moved to another object type fails |
| **Sealed envelopes** | Implements HPKE envelope v2, optional interaction-key sealing and Padmé padding | Both sealing layers are covered by the signature; padding hides the exact length |
| **Delivery credentials** | Carries a recipient-issued capability instead of the sender's identity after first contact | The envelope no longer names the sender, though addresses and timing can still reveal it |
| **Delivery confirmation** | Derives tokens from the HPKE exporter | A relay cannot forge the recipient's confirmation |
| **Identity and recovery** | Implements key event log v2, rotation, witness notices and protected recovery files | An AID survives rotation, with the next key derived from a recovery seed |
| **Epoch and interaction keys** | Defines daily encryption-key sets and keys for the second sealing layer | Provides the key constructions for forward secrecy; applications must delete keys on schedule |
| **Signed Agent Cards** | Signs A2A cards and carries provider-signed extended cards with per-skill prices inside the sealed channel | Card signatures and prices remain provider-authenticated |
| **Payments and evidence** | Defines x402 v2 objects, `anet-credit`, committed receipts, one-time review keys and liability proofs | Accounts can check that their balances are counted in a hub's published total |
| **Wire registry and vectors** | Registers wire values and checks them against code, documentation and conformance vectors | Missing vector coverage fails the build; retired values cannot be reused |

## New in v0.16.0

- **Envelope v2:** sign-then-seal with HPKE (RFC 9180), optionally with a second layer to a per-interaction key.
  Stripping, swapping or adding a layer causes signature verification to fail.
- **Delivery credentials:** recipient-issued capabilities after first contact, with a session MAC for first contact.
- **Epoch and interaction keys:** daily encryption keys published 14 days ahead, each valid for at most two days,
  plus keys for the second sealing layer.
- **Key event log v2:** inception, planned and emergency rotation, deactivation, a named witness hub and
  short-lived witness notices. Version-1 logs are refused.
- **Recovery files:** a recovery seed protected by a passphrase using argon2id and XChaCha20-Poly1305, or by a
  local key until the owner sets a passphrase.
- **Delivery confirmation:** HPKE exporter tokens that hubs cannot forge.
- **Evidence v2 and liability proofs:** receipts commit to the interaction instead of naming it; reviews use
  one-time keys; accounts can check their inclusion in a hub's published balance total.
- **Extended cards, end to end:** provider-signed A2A extended Agent Cards with per-skill prices travel inside
  the sealed channel.
- **One wire registry:** [wire/registry.json](wire/registry.json) lists every key, label, action and reason code;
  [docs/wire-keys.md](docs/wire-keys.md) is generated from it.

**Removed:** envelope v1, `ixn` and `drt` events, `identity.SealTo`, vouchers and evidence v1. Their numbers and
labels are retired, never reused and refused on sight.

**Upgrade notice:** this release breaks the wire and requires new identities; nothing is migrated.
The full change list is in [CHANGELOG.md](CHANGELOG.md).

## Security model

The kernel enforces these guarantees through tests:

- **Domain separation.** A valid signature moved onto another object type fails. Every call site in ANetCore,
  ANet and ANetHub that signs with an identity key is listed in the registry.
- **Strict decoding.** Unregistered keys, duplicate keys, CBOR tags and signed bodies that do not re-encode
  to the received bytes are refused, subject to the envelope extension rules below.
- **No hidden inputs.** There is no network, file or clock access. Time checks take `now` from the caller.
  Randomness is read only when new keys, ids, salts or envelopes are created.

### Limits and application responsibilities

- **No post-quantum protection.** Both sealing layers use X25519. Suite 2 is reserved for a post-quantum suite
  and is not implemented.
- **Visible relay metadata.** The outer envelope exposes recipient AID, key id and padded size. Padmé hides
  the exact length, not its order of magnitude. Hubs also see times and IP addresses and can infer senders
  from addresses and timing.
- **A key history cannot date a signature.** A holder of a rotated-out key can still sign objects dated
  before the rotation.
- **One witness.** A witness hub colluding with a key thief can vouch for a stale key state. Multiple
  witnesses are future work.
- **Deletion is the application's responsibility.** Forward secrecy holds only if epoch and interaction
  keys are deleted on schedule and the file system actually erases them.
- **No independent audit yet.**

The complete list is in the [security model](https://docs.agentnetwork.org.cn/docs/en/latest/reference/security.html).
Report vulnerabilities through ANet's
[SECURITY.md](https://github.com/ANetResearch/ANet/blob/main/SECURITY.md).

## Packages

| Package | Implements | Reference |
|---|---|---|
| `coredet` | CoreDet-CBOR: deterministic encoding, no tags, no duplicate keys; `UnmarshalStrict` refuses unknown keys | RFC 8949 §4.2 |
| `anetcid` | CIDv1 · dag-cbor · sha2-256, frozen prefix `0x01 0x71 0x12 0x20` | [CID](https://github.com/multiformats/cid) |
| `aobj` | Detached Ed25519 signatures over CoreDet preimages; verify before use | [wire keys](docs/wire-keys.md#carried-signed-objects) |
| `identity` | Self-certifying AID and its pre-rotated key event log v2; witness notices; recovery files | [wire keys](docs/wire-keys.md#key-event-log-and-witness-notices) |
| `seal` | Envelope v2, delivery credentials, Padmé padding, encryption key sets, delivery confirmation | RFC 9180 · [wire keys](docs/wire-keys.md#sealed-envelope) |
| `relayauth` | Signed hub requests (`anet-relay/v2/…`); first-contact session key and MAC | [wire keys](docs/wire-keys.md#relayauth-actions) |
| `dirbox` | Directory entries sealed by AID and filed by hash bucket, so a lookup names a bucket, not an agent | [wire keys](docs/wire-keys.md#directory) |
| `delegation` | Relayed task bodies v3: request, chat, preview, status, result, extended card | [wire keys](docs/wire-keys.md#message-bodies) |
| `a2acard` | A2A AgentCard signatures: RFC 8785 JCS and JWS EdDSA, standard library only | RFC 8785 · RFC 7515 |
| `payment` | x402 v2 wire objects and the `anet-credit` scheme | [anet-credit](https://github.com/ANetResearch/ANet/blob/main/docs/a2a/x402-scheme-anet-credit.md) |
| `evidence` | Receipts with salted commitments, reviews under one-time keys, hub attestations | [wire keys](docs/wire-keys.md#evidence-reviews-and-liabilities) |
| `ael` | Per-identity signed, append-only hash chain; hub supply-epoch records | [wire keys](docs/wire-keys.md#carried-signed-objects) |
| `liabtree` | Merkle sum tree of balances; refuses proofs that move value between siblings | [wire keys](docs/wire-keys.md#evidence-reviews-and-liabilities) |
| `regpow` | Registration proof of work (22 bits) for hubs with open registration | [wire keys](docs/wire-keys.md#labels-and-type-tags) |
| `tsir` | TaskDoc and its CID; a closed, bounded predicate calculus | [wire keys](docs/wire-keys.md#task-documents) |
| `effect` | Execution-effect record: what happened and whether it can be verified | [wire keys](docs/wire-keys.md#objects) |
| `agenturi` | `agent://` URIs: parsing and canonical form | — |
| `wire` | The registry, a test-only code scanner and the `docs/wire-keys.md` generator | [registry.json](wire/registry.json) |
| `golden` | Conformance vectors, their index and the independent generator | [Conformance](#conformance) |

### Scope and dependencies

A function belongs here only if it is deterministic, performs no I/O, and is needed by at least two
applications or pinned by a golden vector. External dependencies are frozen to four families —
`fxamacker/cbor`, `filippo.io/edwards25519`, `golang.org/x/crypto`, `golang.org/x/text` — plus the
multiformats CID libraries. Standard-library packages that carry a decision, such as `crypto/hpke`,
are recorded too. The vector generator's Python libraries are not dependencies of the Go module.
See [docs/scope.md](docs/scope.md).

## Documentation

**[English documentation](https://docs.agentnetwork.org.cn/docs/en/latest/)** ·
[简体中文](https://docs.agentnetwork.org.cn/docs/zh-cn/latest/)

| Reference | Contents |
|---|---|
| [Go reference](https://pkg.go.dev/github.com/ANetResearch/ANetCore) | Package APIs |
| [Wire keys](docs/wire-keys.md) | Exact wire keys, labels, type tags and constructions |
| [Wire registry](wire/registry.json) | Registered keys, labels, actions and reason codes |
| [Scope](docs/scope.md) | Kernel boundaries and dependencies |
| [Changelog](CHANGELOG.md) | Version history and breaking wire changes |
| [Architecture and concepts](https://docs.agentnetwork.org.cn/docs/en/latest/intro/overview.html) | ANet architecture |
| [Identity](https://docs.agentnetwork.org.cn/docs/en/latest/topics/identity.html) | Identity, key rotation and recovery |
| [Messaging](https://docs.agentnetwork.org.cn/docs/en/latest/topics/messaging.html) | Sealed messaging and delivery confirmation |
| [Security model](https://docs.agentnetwork.org.cn/docs/en/latest/reference/security.html) | System security guarantees and limitations |
| [Running a hub](https://docs.agentnetwork.org.cn/docs/en/latest/ops/hub.html) | Hub operations |

Design background: the [protocol reference](https://docs.agentnetwork.org.cn/docs/en/latest/reference/protocol.html), the [relay binding](https://github.com/ANetResearch/ANet/blob/main/docs/a2a/relay-binding.md) draft, and
the [anet-credit](https://github.com/ANetResearch/ANet/blob/main/docs/a2a/x402-scheme-anet-credit.md) draft.

## Building from source

### Conformance

`go test ./...` is the conformance suite:

```sh
go test ./...                                  # vectors, negative cases, registry
go run ./wire/gen -check                       # docs/wire-keys.md matches the registry
python3 golden/py/gen_v016.py --check          # regenerate with the independent implementation
```

- **Golden vectors** cover the registry's wire objects and its signing, hashing and key-derivation labels.
  `golden/testdata/index.json` records coverage; a gap fails the build.
- **Negative cases** change each vector by one byte, remove a required key or add an unregistered key.
  Each must fail with a stated reason.
- **Standards vectors** cover RFC 9180 HPKE with exports, RFC 8785, and A2A cards signed by the a2a-python
  reference SDK.
- **`TestWireRegistry`** scans code against the registry. ANet and ANetHub run the same scan.

[`golden/py/gen_v016.py`](golden/py/gen_v016.py) is a second, pure-Python implementation using independent
cryptography libraries. CI regenerates every cryptographic vector and compares byte for byte. Envelope vectors
are sealed by Python and opened by Go, reproducing the signature, envelope digest and delivery-confirmation
keys. Seeds come from public labels, so no file holds a real key.

An implementation that passes these vectors produces the same bytes as this implementation for everything
they cover.

<details>
<summary><b>Rules a second implementation must follow</b></summary>

- CBOR is CoreDet. Signed bodies travel as byte strings holding their CoreDet encoding; a verifier
  re-encodes what it decoded and refuses the body unless the bytes match.
- In the outer envelope, `Wrap` and the inner message, keys 0–63 must be understood and keys ≥ 64 may be
  ignored but remain under the signature or digest. Every other object refuses any key it does not register.
- Every signature, MAC, hash commitment, KDF and HPKE call takes either typed CBOR whose key 0 is a
  registered type tag, or a registered label, a 0x00 byte and fixed-length or 0x00-separated fields that
  never contain U+0000. Exact constructions: [labels and type tags](docs/wire-keys.md#labels-and-type-tags).
- Binary values in hub and p2p JSON are base64url without padding. Times are Unix milliseconds; a day is
  the UTC day `floor(ms / 86 400 000)`.
- Key numbers, labels, relayauth actions and reason codes are never reused; retired ones are refused.

</details>

### Versioning and release verification

ANetCore uses semantic versioning. Before 1.0, a minor version may change wire bytes; each such change is listed
under *Breaking* in [CHANGELOG.md](CHANGELOG.md). A patch version never changes bytes. Published vectors,
the CID prefix and the suite test key are frozen.

Go module releases are verified through the public checksum database. `anet` binaries built on this kernel
are signed with the anet release key; see ANet's
[SECURITY.md](https://github.com/ANetResearch/ANet/blob/main/SECURITY.md).

## Community and contributing

- **Questions and ideas:** [GitHub Discussions](https://github.com/ANetResearch/ANet/discussions).
- **Bugs and pull requests:** [Issues](https://github.com/ANetResearch/ANetCore/issues).
  Anything that changes bytes on the wire starts as an issue.
- **Security reports:** hi@anet0.com, subject `[SECURITY]`
  ([SECURITY.md](https://github.com/ANetResearch/ANet/blob/main/SECURITY.md)).

## License

**ANet Open Source License**, a modified Apache License 2.0 ([LICENSE](LICENSE)), the same license as
ANet and ANetHub. Commercial use is allowed, including use as a library in a product; the logo
condition does not apply to library use. Operating a multi-tenant hosted hub for third parties needs
written authorization. The A2A specification work (ANet `docs/a2a/`) and code contributed to the A2A
project are plain Apache-2.0. Questions: hi@anet0.com.