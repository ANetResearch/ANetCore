// Package seal implements the end-to-end envelope that carries every
// daemon-to-daemon message through a hub or over p2p, and the signed
// encryption key sets it is addressed with. Envelope version 2 (anet 0.3.0)
// is the only one it reads or writes.
//
// # Objects
//
//   - EncKeySet / SignedEncKeySet: an AID's current encryption public keys,
//     signed by the AID's current identity key. Published to the hub and
//     attached to messages.
//   - SealedEnvelope (outer): v = 2, to, suite, kid, enc, ct, the delivery
//     credential access (key 7) and, for a one-shot envelope, exp (key 8).
//     The only part a hub sees. ParseOuter is the hub's structural check.
//   - Wrap (the layer-1 plaintext): the inner, or a second layer's
//     ciphertext, and a zero pad that puts the Wrap on a Padmé length.
//   - SealedInner (inner): sender, key state, recipient, type, interaction,
//     message id, time window, body, the sender's KEL and witness notice,
//     its key set, a grant, its interaction key, and the signature.
//
// All objects are CoreDet-CBOR maps with integer keys (core §2.1-§2.3). Times
// are unix milliseconds.
//
// # Cryptography
//
// Suite 1 is HPKE (RFC 9180) base mode with DHKEM(X25519, HKDF-SHA256),
// HKDF-SHA256 and ChaCha20-Poly1305, from the Go standard library
// crypto/hpke. The layer-1 HPKE info binds the recipient AID, suite and kid
// ("anet-seal/v2"); aad is empty. The inner message is signed before it is
// encrypted, with the sender's Ed25519 identity key, over the preimage v2
// (core §3.3): the inner fields as sent, the body replaced by its SHA-256, and
// the outer enc, kid and suite and the second layer's ikid and enc2. A
// recipient therefore cannot re-encrypt a message it received and present it
// to a third party as addressed to that party, nor strip or add a layer.
// Only the Wrap is padded, so the ciphertext size reveals only a size class.
//
// Seal returns the envelope without its credential and the ack_key, the
// layer-1 export the recipient's delivery token is made under; the caller
// adds the credential with SetAccess on each attempt. env_digest (EnvDigest)
// covers every outer field but the credential.
//
// # Receive path
//
// The receive pipeline (engine §4.2) is split into steps. This package
// implements the steps that depend only on the bytes, a clock and a KEL:
//
//	step 1-4  Open           outer checks, kid lookup, layer-1 open (ack_key), Wrap, inner decode
//	step 5    CheckTime      now <= exp, ts <= now + 5 min, exp - ts <= 15 days
//	step 7    VerifyInnerSig signature under the resolved KEL, rotation grace
//	step 8    VerifyInnerKeys + DecideHighWater  the attached key set
//
// Which keys each message type must carry (step 4a), the sender's KEL (step
// 6), the witness notice (step 6½), authorization (step 9) and the replay
// table and business write (step 10) need the daemon's state and are
// implemented there.
//
// Every failure carries a stable Reason string (a *Error). All reasons except
// ReasonInternalError describe the input and are permanent: the same bytes
// fail the same way on every retry. An error of Open after layer 1 opened
// also carries the ack_key (AckKeyOf), so the recipient can still answer
// with a token.
//
// # Forward secrecy
//
// HPKE generates a fresh sender key per message. The recipient key is an
// epoch key: one per UTC day (EpochMS), published PublishAheadMS ahead and
// valid for its epoch only, so an envelope can be opened only while the
// recipient still holds the private half of the day it was sealed for. When
// the holder deletes it is the holder's policy; MaxMessageLifetimeMS bounds
// how long any envelope sealed to a key can still arrive.
package seal
