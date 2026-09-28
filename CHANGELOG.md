# Changelog

## v0.15.0 — 2026-09-28

The kernel side of anet 0.2.0 and hub wire 2 (ANet `docs/A2A-DESIGN-zh.md`,
§3, §10.3, §18). anet 0.2.0 and ANetHub 0.2.0 require this version in
their `go.mod`.

No external dependency was added. `go.mod` is unchanged since v0.14.0;
`crypto/hpke` (standard library, Go 1.26) is the only new import that
carries a decision, recorded in [docs/scope.md](docs/scope.md).

### Wire compatibility

Pre-1.0, so a minor version carries wire additions. Every object that
existed in v0.14.0 encodes to the same bytes as before when the new
optional fields are absent (pinned by `golden/`). What is new on the wire
is new objects and a second relay-auth preimage; nothing old was
redefined. The applications that use them (anet 0.2.0, hub wire 2) are
not compatible with 0.1.x / wire 1 for other reasons (sealed relay), see
their release notes.

### Added

- **`seal`** — the end-to-end relay envelope. `EncKeySet` (a signed set of
  X25519 encryption keys, verified against the AID it must belong to),
  `SealedEnvelope` / `SealedInner` (sign-then-encrypt with HPKE Base mode,
  suite 1 = DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305;
  the signature covers recipient, type, interaction, message id, time,
  body, KEL, key set and the HPKE `enc`), Padmé padding, field and size
  limits, key-set high-water marks. Golden vectors are checked on the
  opening side with a recipient key fixed by `DeriveKeyPair(ikm)`; RFC 9180
  vectors run against `NewRecipient`/`Open`.
- **`a2acard`** — signs and verifies A2A AgentCards: RFC 8785 JSON
  canonicalization and JWS with EdDSA, standard library only (it does not
  import a2a-go). Publish form, builder, verification against a KEL, JWKS,
  card high-water marks. Pinned by the RFC 8785 appendix vectors, a golden
  card, and cards signed by the a2a-python reference SDK.
- **`identity.ExtendsKEL`** — accepts a candidate KEL only if it extends
  the known one; a strict prefix is `ErrKELRollback`, a disagreement
  `ErrKELFork`. Compares event preimages, not wrapper bytes.
- **`identity.ReplayCache`** — optional process-wide cache
  (`NewReplayCache`, `SetReplayCache`) so the same KEL is replayed once;
  bounded, hands out copies, keyed on the exact KEL.
- **`relayauth` v2** — `PreimageV2` binds the action, the AID, the hub's
  AID, the time and a hash of the HTTP method, request target and body;
  it travels in `X-ANet-AID`/`-TS`/`-Seq`/`-Sig`. New actions for the v2
  endpoints (send, visibility, deregister, p2p, balance, ledger,
  redemptions, keys). v1 (`Preimage`) is kept for wire-1 peers.
- **`delegation`** — `StatusMsg` and the A2A task states
  (`submitted` … `rejected`, `ValidStatusState`); `KindCancel`; optional
  `ContextID` and `Metadata` fields on the delegation objects;
  `VerifyDelegateReqWithKEL` and `VerifyResultWithKEL` (verify against a
  resolved KEL at the message time); `VerifyResultForRequest`, which also
  binds the receipt's request CID to the request this node sent
  (`ErrRequestMismatch`).
- **`payment`** — `PaymentRequirements` and `FacilitatorRequest` with the
  x402 v2 field names; error reasons `expired_payment`,
  `unsupported_scheme`, `invalid_amount`, `payee_mismatch`,
  `duplicate_nonce`, `duplicate_binding`, `settlement_pending`,
  `settlement_failed`, `invalid_payment_requirements`; response extensions
  `anet.replayed`, `anet.original_transaction`, `anet.error_detail`.
- **Fuzz targets** — Go native fuzzing for the parsing and verification
  entry points of 14 packages (coredet, identity, seal, relayauth,
  delegation, payment, a2acard, adp, tsir, aobj, evidence, ael, agenturi,
  effect): 31 targets, each next to its package in `fuzz_test.go`, with the
  inputs that found a defect kept under `testdata/fuzz/`. A plain `go test`
  runs only the seeds and that corpus (ANet `docs/notes/0033`, core).

### Changed

- `identity.Replay`: every key state that a later `rot`/`dip` retires gets
  that event's `SupersededAt` and is marked inactive, also when `ixn`/`drt`
  events lie in between (pinned by `golden/supersede_test.go`,
  VEC-KEL-SUPERSEDE-1/2). Callers use it to accept a retired key only for
  messages signed before the rotation and within their grace period.
- **`identity.Replay`: pre-rotation honours only the commitment of the
  last establishment event.** A `rot` must match the `next_digest` of the
  most recent `icp`/`rot`; a `next_digest` written on an `ixn` or `drt`
  no longer counts as the commitment (`Restore` uses the same rule). Before
  this, the digest of whichever event came right before the `rot` was
  taken, and an `ixn`/`drt` needs only the current key — so whoever stole
  the current key could append a `drt` re-committing to a key of their own
  and then rotate to it, which is exactly the takeover pre-rotation exists
  to prevent. This is a behaviour change: a KEL whose `rot` matches a
  commitment rewritten by an intervening `ixn`/`drt` is now refused, and a
  KEL whose `rot` matches the establishment event across an `ixn`/`drt`
  carrying another digest is now accepted. KELs written by a correct
  `Controller` replay the same before and after (`Delegate` still writes
  the same digest on its `drt`, so older verifiers accept the next
  `Rotate`). Verifiers on v0.14.0 or earlier still accept the first shape,
  so daemons and hubs both need this version (pinned by
  `identity/prerotation_internal_test.go`).
- `delegation.ChatEndAccept` is deprecated: from this version the provider
  completes a text task on its own (A2A-DESIGN §3.4, §4.2).

### Fixed

- `identity.Replay` refuses an inception or rotation event whose key is
  not 32 bytes instead of panicking inside `ed25519.Verify` (found in the
  0.2 red-team review, F34).
- Receipt verification can bind the request CID (`VerifyResultForRequest`,
  F15): a receipt for another request of the same interaction no longer
  verifies.

Found by fuzzing (ANet `docs/notes/0033`, core; each has a unit regression
that fails without the fix):

- `aobj.Verify` returns an error for a public key that is not 32 bytes
  instead of panicking inside `ed25519.Verify` (the same class as F34, on
  another entry point).
- `agenturi`: the canonical form is a fixed point again. A query key or
  value that is not UTF-8 after percent-decoding is refused (`BAD_UTF8`)
  instead of being rewritten to U+FFFD, which made different URIs compare
  equal; labels are folded after NFC and normalised again afterwards
  (U+212A KELVIN SIGN now folds to `k`); a label that folds to nothing
  (only ZWJ/ZWNJ) is refused (`EMPTY_LABEL`). URIs refused by the first
  and last rule were accepted before.
- `tsir`: glob matching is linear in pattern × input length instead of
  exponential in the number of `*`/`**` (same semantics, checked against
  the old implementation); `Validate` refuses a null child predicate
  (`MALFORMED`) instead of dereferencing it.
- `seal.Padme` no longer wraps to a negative length when the next Padmé
  length would exceed `math.MaxInt`; it returns the length unchanged there.
- `payment`: the validity checks of authorizations and vouchers compare
  differences, so a `NotAfter` near `MaxInt64` ("never expires") no longer
  overflows into "expired at any time".

### License

- ANetCore is released under the ANet Open Source License, a modified
  Apache License 2.0 (`LICENSE`): no node limit on commercial use; operating a multi-tenant hosted hub for third parties needs written
  authorization; code contributed to the A2A project goes upstream under
  Apache-2.0 (condition 3).

## v0.14.0 and earlier

See the tags and commit history.
