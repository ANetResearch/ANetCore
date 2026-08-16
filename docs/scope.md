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
