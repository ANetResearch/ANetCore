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
//   - Wrap (the layer-1 plaintext): the inner, or a second layer's ikid,
//     enc2 and ciphertext, and a zero pad that puts the Wrap on a Padmé
//     length.
//   - RK and IXKey: an interaction key, one per side of an interaction. A
//     sender announces its public half (rk, inner key 15); the peer seals
//     the second layer of its messages in the interaction to it.
//   - SealedInner (inner): sender, key state, recipient, type, interaction,
//     message id, time window, body, the sender's KEL and witness notice,
//     its key set, a grant, its interaction key, and the signature.
//   - Access, Cap, CapBody: the delivery credential in outer key 7. Kind 0
//     is a first-contact delivery under a hub session; kind 1 carries a
//     capability the recipient issued (CapBody, signed by the recipient's
//     mailbox key in its key set) and the holder's proof of possession over
//     env_digest. Nothing in it names the sender.
//   - Grant (inner key 14): a capability the sender of a message issues to
//     its recipient, with the holder key's seed, so the recipient can later
//     deliver to the sender under it.
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
// A message inside an interaction whose peer announced an interaction key has
// a second layer: the inner is sealed with HPKE to that key ("anet-ix/v2",
// with the recipient AID, suite and ikid in the info), and the Wrap carries
// the result. The second layer's ikid and enc2 are in the signed preimage, so
// a layer cannot be stripped, swapped or added without the signature failing.
// The ack_key is always the layer-1 export.
//
// Seal returns the envelope without its credential and the ack_key, the
// layer-1 export the recipient's delivery token is made under; the caller
// adds the credential with SetAccess on each attempt. env_digest (EnvDigest)
// covers every outer field but the credential.
//
// # Credentials
//
// The recipient issues a capability with SignCap and hands it to its peer in
// a Grant; the peer keeps it after CheckGrant and, for each envelope it sends,
// signs a proof with SignAccess over that envelope's env_digest. A hub admits
// the envelope after VerifyAccess against the recipient's published mailbox
// key: the capability's owner is the envelope's to, its epoch the mailbox
// key's, its signature good, its expiry in the window and the proof the
// holder's over this envelope. A new mailbox key (a new epoch) voids every
// capability the old one signed.
//
// # Receive path
//
// The receive pipeline (engine §4.2) is split into steps. This package
// implements the steps that depend only on the bytes, a clock and a KEL:
//
//	step 1-4  Open           outer checks, kid lookup, layer-1 open (ack_key), Wrap, inner decode
//	step 1a   VerifyAccess   a kind-1 credential issued by this node, under its own mailbox key
//	step 5    CheckTime      now <= exp, ts <= now + 5 min, exp - ts <= 15 days
//	step 6½   CheckNotice    the witness notice, against the carried KEL and the hub KELs held
//	step 7    VerifyInnerSig signature under the resolved KEL; a retired key usable at arrival
//	step 8    VerifyInnerKeys + DecideHighWater  the attached key set
//	step 8    CheckGrant     the grant, against that key set (a bad grant is ignored)
//
// Which keys each message type must carry (step 4a), the sender's KEL (step
// 6), the hub KEL set CheckNotice reads and the arrival time (accepted_at),
// authorization (step 9) and the replay table and business write (step 10)
// need the daemon's state and are implemented there.
//
// Every failure carries a stable Reason string (a *Error). All reasons except
// ReasonInternalError and ReasonWitnessUnknown describe the input and are
// permanent: the same bytes fail the same way on every retry. An error of
// Open after layer 1 opened also carries the ack_key (AckKeyOf), so the
// recipient can still answer with a token.
//
// # Forward secrecy
//
// HPKE generates a fresh sender key per message. The recipient key is an
// epoch key: one per UTC day (EpochMS), published PublishAheadMS ahead and
// valid for its epoch only, so an envelope can be opened only while the
// recipient still holds the private half of the day it was sealed for. When
// the holder deletes it is the holder's policy; MaxMessageLifetimeMS bounds
// how long any envelope sealed to a key can still arrive. A message with a
// second layer also needs the recipient's interaction key, which the
// recipient deletes when its part of the interaction ends: from then on Open
// reports sealed-to-closed-interaction.
package seal
