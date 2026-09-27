// Package seal implements the end-to-end envelope that carries every
// daemon-to-daemon message through a hub or over p2p (A2A design r2, §3.1 to
// §3.6), and the signed encryption key sets it is addressed with.
//
// # Objects
//
//   - EncKeySet / SignedEncKeySet (§3.1): an AID's current encryption public
//     keys, signed by the AID's current identity key. Published to the hub
//     and attached to every message.
//   - SealedEnvelope (§3.3, outer): v, to, suite, kid, enc, ct. The only part
//     a hub sees. ParseOuter is the hub's structural check.
//   - SealedInner (§3.3, inner): sender, recipient, type, interaction, message
//     id, time window, body, the sender's KEL and key set, the signature and
//     the padding.
//
// All objects are CoreDet-CBOR maps with integer keys. Times are unix
// milliseconds.
//
// # Cryptography
//
// Suite 1 is HPKE (RFC 9180) base mode with DHKEM(X25519, HKDF-SHA256),
// HKDF-SHA256 and ChaCha20-Poly1305, from the Go 1.26 standard library
// crypto/hpke. The HPKE info binds the recipient AID, suite and kid; aad is
// empty. The inner message is signed before it is encrypted, with the
// sender's Ed25519 identity key, over a preimage that also covers the outer
// enc, kid and suite. A recipient therefore cannot re-encrypt a message it
// received and present it to a third party as addressed to that party: the
// new enc and kid are not what the sender signed. The inner is padded to a
// Padmé length so the ciphertext size reveals only a size class.
//
// # Receive path
//
// §3.6 splits the receive path into steps. This package implements the
// steps that depend only on the bytes, a clock and a KEL:
//
//	step 1-4  Open           outer checks, kid lookup, HPKE open, inner decode
//	step 5    CheckTime      now <= exp, ts <= now + 5 min, exp - ts <= 15 days
//	step 7    VerifyInnerSig signature under the resolved KEL, rotation grace
//	step 8    VerifyInnerKeys + DecideHighWater  the attached key set
//
// Step 6 (choosing between the carried KEL and the stored one), step 9
// (authorization) and step 10 (replay table, business write) need the
// daemon's storage and are implemented there.
//
// Every failure is a *Error with a stable Reason string. All reasons except
// ReasonInternalError describe the input and are permanent in the sense of
// §3.6: the same bytes fail the same way on every retry.
//
// # Forward secrecy
//
// HPKE generates a fresh sender key per message, but the recipient key is
// static for its lifetime; there are no per-interaction recipient keys (§2).
// Under the key ring policy in limits.go a message can therefore be opened
// by whoever obtains the recipient's key ring for at most
// ForwardSecrecyWindowMS (29 days) after it was sent (§21 item 2).
package seal
