# Scope & Dependency Policy

## What belongs here

Pure protocol logic: encoding, hashing, signing, object schemas, predicate
evaluation. A function belongs in ANetCore iff it is deterministic, I/O-free,
and required by at least two of the three applications (ANet / ANetHub /
ANetLink) — or pinned by a golden vector.

## What never belongs here

Network clients or servers, storage engines, CLI/API surfaces, adapters,
anything with a goroutine lifecycle. Those live in the applications behind the
five contracts (K207 §3).

## Dependency allow-list

External dependencies are frozen to four families and extend only by explicit
decision (registered in K-docs):

- `github.com/fxamacker/cbor/v2` — CBOR engine under the CoreDet profile
- `filippo.io/edwards25519` — Ed25519 arithmetic
- `golang.org/x/crypto` — blake2b, curve25519, nacl/box
- `golang.org/x/text` — Unicode normalization (agent-uri canonical form)

## Import direction

Applications → ANetCore. Never the reverse; never application ↔ application.

## Standard-library registrations (v0.15.0)

The allow-list above covers external modules only. Standard-library packages need no allow-list
entry, but the ones below are recorded because they carry a decision (A2A-DESIGN §18).

- `crypto/hpke` (Go standard library, available from Go 1.26; `go.mod` already requires 1.26) —
  used by package `seal` for the end-to-end relay envelope: HPKE Base mode, suite 1 =
  DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 (A2A-DESIGN §3.1–§3.3). Chosen
  over `golang.org/x/crypto/nacl/box` (which `identity/encrypt.go` uses) because HPKE binds a
  context string (`info`) into the key schedule and names its algorithms by registered suite ids,
  so a second suite (suite 2 is reserved for MLKEM768-X25519) can be added without changing the
  envelope format. No external dependency is added.
  `seal` reads `crypto/rand` in the functions that create new material: the HPKE ephemeral key
  when sealing, a fresh message id, and a newly generated encryption key pair, as
  `identity.Incept` and `identity.SealTo` already do. It reads no clock (callers pass `now`) and
  performs no I/O. Opening and verification are deterministic and are pinned by golden vectors
  with a recipient key fixed by `DeriveKeyPair(ikm)`.

## Package placement: `a2acard`

`a2acard` signs and verifies A2A AgentCards: RFC 8785 JSON canonicalization and JWS with EdDSA,
implemented with the standard library only (A2A-DESIGN §10.3). It belongs here under the rule at
the top of this file:

- Two applications need the identical computation. The daemon (ANet) signs its card and verifies
  peers' cards; the hub (ANetHub) verifies cards at registry admission and serves them to other
  hubs. A canonicalization that differs by one byte between signer and verifier makes every
  signature fail, so the code must be one copy in the module both sides import, like
  `relayauth` and `delegation`.
- It is deterministic and performs no I/O: canonical bytes and signature checks depend only on
  the inputs.
- It is pinned by golden vectors: the RFC 8785 appendix vectors, a golden signed card, and
  cards signed by the a2a-python reference SDK (`a2acard/testdata/python-vectors.json`, with
  the AgentCard field table dumped from that SDK's proto descriptors). The generator script is
  committed next to the vectors; Python is needed only to regenerate them, never to build or
  test.

It does not import `github.com/a2aproject/a2a-go`. The dependency allow-list is frozen, and the
card format is small enough to implement from the specifications. Interoperability with a2a-go is
checked by contract tests in ANet, which may import a2a-go, not here.
