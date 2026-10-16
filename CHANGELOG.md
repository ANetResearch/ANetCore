# Changelog

## v0.16.0 - 2026-10-16

### Changed

- **The seal field decoder accepts only the canonical encoding.** The outer
  envelope, the access credential and every other field map read through it
  were taken in any spelling the CBOR decoder understood: an
  indefinite-length map, keys in another order, a longer-than-needed integer
  head. The first two left `EnvDigest` unchanged, so a third party could
  re-spell a sealed message without breaking its proof. `ParseOuter`,
  `EnvDigest` and `Open` now re-encode the fields and refuse a difference
  (bad-outer).
- **A KEL key of small order is refused.** An `icp`, `rot` or `dip` whose
  key is one of the 14 small-order Ed25519 encodings no longer replays;
  under such a key anyone can sign for the AID. The list moved to
  `identity.SmallOrderKey`; `seal` uses it for mailbox and holder keys as
  before.
- **`payment.ParseAmount` reads canonical decimal only, up to
  `math.MaxInt64`.** A leading zero or a value the ledger cannot hold is an
  error, so a caller can no longer forget the range check.
- **`relayauth.PreimageV2` percent-escapes `/` and `%` in action, aid and
  hub AID.** Valid values are unchanged; a caller that breaks the
  precondition can no longer shift a byte between two fields.

### Known limit

- **Evidence objects are judged at their own time.** `identity.VerifyObject`
  and `evidence.CheckV2` check a receipt against the key state in force on
  `completed_day`. Whoever holds a retired key can sign a receipt, and
  through its review key a review, for a past day, even after the key was
  rotated away (an emergency rotation included). The core has no
  arrival-time anchor for receipts. A consumer that relies on a receipt
  must anchor it to the time it first stored it, and refuse one whose
  `completed_day` falls before a key-state change it already knew of.

## v0.16.0-rc.4 — 2026-10-16

The fourth release candidate of the kernel of anet 0.3.0 and hub wire 3.
anet 0.3.0 and ANetHub 0.3.0 require this version in their `go.mod`.
No golden vector changed a byte: the strict decoder refuses more input,
the register follows what the hub and the daemon now send, and the
identity controller can drop a witness designation a hub refused.

### Changed

- **`coredet.UnmarshalStrict` refuses a CBOR null or undefined where a
  value must be.** The decoder takes both into the zero value without a
  word, so `81 f7` decoded into a list of one empty entry, and an object
  with a null member decoded as if the member were zero. No canonical
  encoder writes either. `UnmarshalStrict` now refuses an undefined
  anywhere, and a null wherever it would go into anything but a pointer,
  an interface or a `cbor.RawMessage`; the refusal is a `*NullError`
  (`errors.Is(err, ErrNullOrUndefined)`) naming the path. A type with its
  own `UnmarshalCBOR` is still given its bytes as they are and answers for
  itself. `coredet/coredettest` lists the decode sites of every registered
  object so that a test in each package can check that all of them refuse
  null and undefined.
- `wire.Negatives` still builds its negatives with a null for the added
  key; a strict decoder that still has a field for the key now refuses
  with `ErrNullOrUndefined` instead of for the key, and the negative test
  tells the two apart.

### Added

- `identity.Controller.DiscardPending` drops a pending witness
  designation that its hub refused for good: no hub accepted it, so
  dropping it forks nothing, and the identity can join another hub. Every
  other pending event (a rot, a dip, material without an event) may have
  reached a witness and is refused with `identity.ErrDiscardRefused`.

### Register

- User code `hub_publication_blocked`: a registration this node's own
  publication screen kept back; it is not retried.
- Local object `EvidenceQueueRecord`: one line of the daemon's evidence
  queue, a record written while a key event of the identity is pending,
  signed and chained once the event is adopted or dropped.
- Local projection key `anet.next`: the one command to copy and run, the
  `next` of the `anet.reason` row, on the tasks this node projects; the
  same source as the control-plane error body's `next`.
- Control-plane error body: `task_id` and `state`, for `message_id_reused`
  only (the task the message id already names, and its A2A state).
- Hub reason `source_rate` (429) on `POST /fed/v3/directory:bucket`,
  `POST /fed/v3/relay-status`, `POST /fed/v3/settle` and
  `POST /fed/v3/clear`, as on every `/fed/v3` POST (`/fed/v3/forward`
  already had it).
- `GET /agents/{aid}/keys` answers `not_found` also when the stored KEL
  is over the replay limit.
- Golden `FRAME-3` also covers a p2p frame with an unregistered member or
  a missing one.
- Transition list: the entries for `anet.final` and the retired relayauth
  action `p2p` are gone.

## v0.16.0-rc.3 — 2026-10-10

The third release candidate of the kernel of anet 0.3.0 and hub wire 3.
anet 0.3.0 and ANetHub 0.3.0 require this version in their `go.mod`.
Nothing rc.2 pinned changed a byte: LOCAL-1's file gained its client
member and is otherwise as it was. The KEL decoder refuses an entry
that carries no event, the register follows what the hub and the daemon
now send, and the Python generator reproduces the client's retry key and
digest.

### Changed

- **A KEL entry without an event does not decode.** `identity.UnmarshalKEL`
  returned no error for a null or undefined entry, an empty map or a map
  holding only the signature: such an entry decoded to a zero
  `SignedEvent` without the event's own decoder running, so a caller that
  only decoded took it for a KEL of that length, and `Replay` refused it
  later for the wrong reason (as a v0.2 KEL). Every entry must now carry
  its event; one that does not is a KEL that does not decode. The
  two-byte input that showed it is kept as a fuzz seed.

### Register

- `GET /agents/{aid}/keys` is registered: no authentication, answered
  only for agents registered at that hub, with `aid` and the key set and
  KEL in base64url (`keys`, `kel`); `unknown_aid`, and `not_found` while
  the agent has no key set to serve yet.
- Publishing a key set may be refused with `kel_invalid`, when the key
  history the hub holds cannot verify the new set; `keys_rollback` also
  covers a set whose `seq` is not above the stored one.
- Hub operator codes `hub_passphrase_too_short` and
  `hub_passphrase_not_utf8`, for the hub's own recovery passphrase.
- The daemon signs inner messages in `sealMessage` (the signer list named
  `sealWithOpts`).
- Storage: the hub's restore tables `restore_released` and `kel_hwm` and
  the agent row's `tip_seq` and `tip_head` are listed with what the hub
  keeps (descriptive; no wire value changes).
- Transition list: the hub's copy of evidence v1 (receipts and reviews,
  eight entries) is gone, as the hub now takes and serves evidence v2
  reviews only. The daemon's evidence v1 entries stay until it does too.

### Golden vectors

- LOCAL-1 gains its client part: the client key and client digest of a
  text message, a capability call whose args hold 9007199254740993, a
  message with two files and a payment decision, and two pairs of one
  message ID with two contents (9007199254740993 and 9007199254740992; 1
  and 1.0) whose digests differ. `gen_v016.py` writes the canon itself
  (member order and escapes of RFC 8785, the client's number literals
  kept as written) and reproduces the daemon's file byte for byte. The
  index has no open row left.

## v0.16.0-rc.2 — 2026-10-09

The second release candidate of the kernel of anet 0.3.0 and hub wire 3.
anet 0.3.0 and ANetHub 0.3.0 require this version in their `go.mod`. No
golden vector of rc.1 changed a byte. What changed is that decoders and
checks refuse values rc.1 let through, the register follows what the
daemon and the hub now send, one more vector pins the module objects,
and the `adp` package is gone.

### Changed

- **Keys of small order are refused.** An Ed25519 public key of small
  order is no key at all: anyone can make a signature that verifies under
  it. A key set whose mailbox signing key is one fails its structure
  check; a capability whose holder key is one is neither issued
  (`SignCap`) nor decoded; and `VerifyAccess` and `CheckGrant` refuse such
  a mailbox key at the signature step. Every key made from a seed passes.
- **Grant bounds.** A grant's `home` must be an AID (`identity.ValidAID`).
  Its `p2p`, when present, must be `host:port` with a host, a port from 1
  to 65535 and at most 262 bytes; a port too large to be a number is
  refused, not wrapped. `seal.ValidP2PAddr` lets an issuer leave out an
  address a grant could not carry.
- **Recovery files.** A passphrase that is not valid UTF-8 is refused
  with `identity.ErrPassphraseNotUTF8` by `CheckPassphrase`,
  `SealRecoveryFile` and `OpenRecoveryFile`: such bytes could not be typed
  again in a UTF-8 terminal. The AID in a recovery file's header and block
  must be an AID (`ValidAID`).
- **Preview frames.** `ValidatePreview` refuses a `msg_id` or `answers`
  longer than `delegation.MaxPreviewIDLen` (256 bytes), so an accepted
  frame has a bounded size.
- **Register** (`wire/registry.json`, `docs/wire-keys.md`):
  - user reasons `egress_upstream_unreachable` and `datadir_too_new`; hub
    operator reasons `hub_data_too_new` and `quota_bad_value`;
  - the `record` of a hub's liability proof is base64url text, as every
    binary value of wire 3;
  - the name `anet/`, the User-Agent prefix of every daemon request to its
    hub;
  - signing sites: the daemon signs its key set in one function
    (`ringInputsAt`); the org credential and the cognitive unit of the
    module objects; the hub's federation client (relay-auth L22).
- **Transition list.** 28 entries are gone with the v0.2 shapes they
  stood for: the ADP card signers, public prices and vouchers, the
  daemon's task board and wire-1 relay signing, the old key-ring file, the
  untagged module objects, the hub's per-event credit records, the
  federation v2 signers and the retired relay-auth actions `send` and
  `fedkeys`.
- `wire.TodoWord` and `wire.TodoMarker` spell the open-item marker, so the
  framework that checks markers is not itself one of the hits.

### Added

- **MODOBJ-1** — vectors for the org genesis, the org credential and the
  cognitive unit (labels L41, L42, L43), written by the Python generator
  and checked in Go where the objects live; the negatives show that a
  signature over one kind of object never passes for another.
- `seal.ValidP2PAddr`, `identity.ErrPassphraseNotUTF8`,
  `delegation.MaxPreviewIDLen`, `wire.TodoWord`, `wire.TodoMarker`.

### Removed

- The `adp` package (ADP agent cards, card tombstones and gossip). Nothing
  signs or reads an ADP card any more; an agent's card is its A2A
  AgentCard (`a2acard`).

## v0.16.0-rc.1 — 2026-10-04

The kernel side of anet 0.3.0 and hub wire 3: the first release candidate,
with the wire frozen. anet 0.3.0 and ANetHub 0.3.0 require this version in
their `go.mod`; from here on a change to the wire bytes needs a new
candidate and new vectors, and a defect fix is released as the next
`v0.16.0-rc.N`.

### Wire compatibility

This version breaks compatibility on purpose and carries no migration
code. Envelopes are `v = 2`, encryption key sets `anet.enckeys/2`, key
event logs KEL v2 and hub requests wire 3; a node or hub on v0.15.0 cannot
read what this version writes, and this version refuses what v0.15.0
wrote. Each wire object now has exactly one byte form: decoders are strict
and canonical, refuse unassigned and retired keys, and re-encode to the
bytes they read.

Every key number, label, relay action, hub endpoint, metadata key and
reason code is listed in `wire/registry.json`. A test in each repository
type-checks the code against it, so a key, label or signing site that is
not registered fails the build's tests instead of drifting from the
design. `golden/` pins the bytes: each vector is written by an
independent Python implementation (`golden/py/gen_v016.py`) and
reproduced byte for byte in Go, and `golden/testdata/index.json` requires
every registered object that travels between nodes to be covered.

### Added

- **`wire`** — the registry, its code scanner (`wire/scan`), the
  generator of `docs/wire-keys.md` (`wire/gen`) and `wire.Negatives`, one
  encoding per unassigned key for decoder tests.
- **`coredet.UnmarshalStrict`** — refuses a map key the struct does not
  name, so a silently dropped key cannot make two readers disagree.
- **`seal` v2** — one envelope format for every message: the outer
  envelope with the delivery credential (key 7) and a one-shot expiry
  (key 8), the padded `Wrap`, the strict inner envelope with the witness
  notice, grant and `rk` keys, and a v2 signature preimage that binds both
  layers. Inside an interaction a message is sealed a second time to the
  interaction key the peer announced (`RK`, `IXKey`, `GenerateIXKey`), so
  a stolen day key does not open it once both sides have dropped that
  key; a layer cannot be stripped, swapped or added.
- **Delivery capabilities and grants** — `CapBody`, `SignAccess`,
  `VerifyAccess`, `Grant` and `CheckGrant`: a hub and a recipient admit an
  envelope that presents a delivery credential only when the credential
  holds for that envelope, and a grant is kept only when it checks against
  the key set the same message carried.
- **Delivery confirmations** — `seal/dack.go`: only the recipient can
  confirm delivery, with an 80-byte token under the envelope's `ack_key`
  that only the two ends hold (`VerifyDAck`, `RetryBucket`, note codes).
- **`identity` KEL v2** — key events carry `anet.kel/2`, decode strictly
  and re-encode to the same bytes; a `rot` is signed by the key it
  reveals, timestamps strictly increase, and `ixn`/`drt` are gone.
  `CheckNewEvents` bounds the times of new events.
- **`identity.Signer`** — signing code receives a signer that signs and
  does nothing else; only the holder of the locked `Controller` builds key
  events. Identity file v2 (`Export`/`Restore`) keeps pending material,
  witnesses to push and the local commit together.
- **Recovery seed and recovery file** — `RecoverySeed` and `NextDigest`
  derive every key after the first rotation, so the next key never lives
  in the data directory; `SealRecoveryFile`/`OpenRecoveryFile`
  (Argon2id over the passphrase) and the local-key pair keep the seed;
  `ParseRecoveryFile` reads a file's header without a secret.
- **Witness notices** — `NoticeBody`, `SignNotice`, `VerifyNotice`,
  `CheckNotice`; a rotation names its witness by a well-formed AID
  (`ValidAID`), and the sender's key is checked at the arrival time with
  a fixed one-hour grace for planned rotations.
- **`relayauth`** — first-contact sessions (a session key delivered
  sealed to a one-time key, a MAC on each send), `MonoClock`, and the
  actions of hub wire 3, including `fed_status`.
- **`dirbox`** — sealed directory entries: only a party that already
  knows an AID can find and open its entry.
- **`liabtree`** — the Merkle sum tree behind a hub's supply record, with
  one overflow check shared by build and verify and one JSON proof form.
- **`regpow`** — the registration proof of work an open hub asks of a new
  AID.
- **`evidence` v2** — receipt, review and review attestation bodies with
  their commitments, replacing the v1 receipt and review.
- **`delegation`** — card request and response, task-binding contexts,
  and body v3: every delegation body decodes strictly and canonically, and
  a request decodes its embedded task document strictly.
- **`ael`** — the supply epoch record.
- **Fuzz targets** for every new decoder (envelope, wrap, inner v2, `rk`,
  second layer, access, capability, grant, directory entry, confirmation,
  note, recovery file, notice, liability proof, proof of work, body v3).

### Removed

- `identity.SealTo` and `(*Controller).Open`: a sealed box to a peer's
  identity key had no forward secrecy.
- `CurrentPrivateKey`, `Incept`, `Rotate` and `Deactivate` on the
  identity API; `InceptAgent` and `InceptHub` take the inception time.
- The v1 envelope, the v1 receipt, review and voucher, the prepayment key,
  the wire-1 challenge, and the relay actions `send`, `p2p` and `fedkeys`.
- The golden vectors of those objects; `golden/testdata/index.json` lists
  them as retired.

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
  runs only the seeds and that corpus.

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

Found by fuzzing (each has a unit regression
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
