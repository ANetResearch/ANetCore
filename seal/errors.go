package seal

import (
	"errors"
	"fmt"
)

// Reason strings carried by *Error. They are stable: callers count them in
// metrics and logs, and the daemon maps them onto the receive pipeline's
// failure classes (engine §4.2), so a reason is never renamed once released.
// Every one is registered in wire/registry.json (reasons.seal). Detail text is
// free-form and may change.
//
//anet:wire reasons.seal
const (
	// Outer envelope (receive step 1, ParseOuter). No ack_key exists yet.
	ReasonBadOuter       = "bad-outer"       // outer does not decode, misses a field, or has a wrong-typed/sized field
	ReasonBadVersion     = "bad-version"     // outer v is not EnvelopeVersion
	ReasonUnknownSuite   = "unknown-suite"   // suite not implemented by this build
	ReasonWrongRecipient = "wrong-recipient" // outer to != the opening node's AID
	ReasonAccessInvalid  = "access-invalid"  // a capability fails a check; Detail names the step: outer key 7 missing or malformed ("parse"), a step of VerifyAccess, or of CheckGrant (the grant is ignored, not the message)

	// Key lookup and layer-1 decryption (steps 2-3). No ack_key exists yet.
	ReasonUnknownKey = "sealed-to-unknown-key" // kid not in the key ring (never held, or past retention)
	ReasonDecrypt    = "decrypt-failed"        // HPKE setup or AEAD open failed (either layer)

	// After layer 1 (step 3a on), every failure of Open carries the ack_key
	// (AckKeyOf): the inner reasons below and the Wrap and second-layer
	// reasons at the end of this block.

	// Inner structure (step 4).
	ReasonBadInner      = "bad-inner"              // inner does not decode, misses a field, has a wrong-typed/sized field, a from, to or ix with U+0000, or key 11 without key 10 (or the reverse)
	ReasonUnknownField  = "unknown-critical-field" // a key in 0-63 this version does not understand, including the retired 21 and the preimage-only 0 and 30-34
	ReasonToMismatch    = "to-mismatch"            // inner to != outer to
	ReasonExpMismatch   = "exp-mismatch"           // outer key 8 present and != inner exp
	ReasonKELTooLarge   = "kel-too-large"          // inner kel over MaxKELBytes or MaxKELEvents
	ReasonBadKEL        = "bad-kel"                // KEL does not decode or does not replay
	ReasonFromMismatch  = "from-mismatch"          // KEL replays to an AID other than inner from
	ReasonExpired       = "expired"                // now > exp
	ReasonFromFuture    = "from-future"            // ts > now + ClockSkewMS
	ReasonBadLifetime   = "bad-lifetime"           // exp < ts, or exp - ts > MaxMessageLifetimeMS
	ReasonBadSig        = "bad-sig"                // signature does not verify under the declared key state
	ReasonBadKeyState   = "bad-key-state"          // declared key_state_seq is beyond the KEL or not usable for this object
	ReasonRevokedKey    = "revoked-key"            // key state retired before the object's time, or AID deactivated
	ReasonGraceExpired  = "rotation-grace-expired" // old key state, but now is past SupersededAt + rotation grace
	ReasonAIDMismatch   = "aid-mismatch"           // key set AID, KEL AID and expected AID are not all equal
	ReasonBadKeySet     = "bad-keyset"             // key set fails its decoding, structure or validity rules (EncKeySet.checkStructure)
	ReasonNoUsableKey   = "no-usable-key"          // no key in the set is valid now under a supported suite
	ReasonInvalidInput  = "invalid-input"          // caller passed an object Seal or SignEncKeySet cannot produce a valid encoding from
	ReasonInternalError = "internal"               // entropy or encoder failure on the sending side; not a property of any received bytes

	// The first-layer plaintext (Wrap) and the second layer, sealed to the
	// recipient's interaction key. Each is a property of bytes that opened
	// under the recipient's epoch key, so each is permanent.
	ReasonBadWrap                   = "bad-wrap"                     // Wrap does not decode: a key it does not name, ikid without enc2 or the reverse, a wrong length, or pad not all zero
	ReasonBadRK                     = "bad-rk"                       // inner rk is not a suite-1, 32-byte public key
	ReasonSealedToClosedInteraction = "sealed-to-closed-interaction" // the second layer names an interaction key the recipient no longer holds
	ReasonIKeyMismatch              = "ikey-mismatch"                // the interaction key that opened the second layer belongs to another interaction or peer

	// The sender's witness notice (receive step 6½, CheckNotice; KEL C-51, C-56), checked
	// against the KEL the message carries. Every one but witness-unknown is permanent.
	ReasonWitnessMissing  = "witness-missing"  // no notice, or a sender whose KEL names no witness: a hub (toad 0), or an agent whose witness is still pending
	ReasonWitnessStale    = "witness-stale"    // the notice was observed more than 6 h before the arrival, or more than 5 min after it
	ReasonWitnessMismatch = "witness-mismatch" // the notice is about another AID, seq or head than the tip of the carried KEL
	ReasonWitnessInvalid  = "witness-invalid"  // the notice does not decode or has another type, its signer is not the witness the tip names, or its signature fails under that hub's KEL
	ReasonWitnessUnknown  = "witness-unknown"  // this node does not hold the witness hub's KEL as far as the notice's key state; not permanent: refresh the hub KEL set and check again
	ReasonKELFromFuture   = "kel-from-future"  // a new event of the sender's KEL is dated more than 5 min after this node's clock (R-9; counted when step 6 merges)
)

// Error carries every failure this package detects. Reason is one of the
// Reason* constants; Detail says which field or rule failed; Err is the
// underlying cause when there is one (a decoder error, an identity.VErr).
//
// Open wraps the errors it returns after layer 1 was opened in a value that
// also carries the ack_key (AckKeyOf); errors.As still finds the *Error, and
// ReasonOf and IsPermanent see through the wrapper. The one error Open returns
// that is not a *Error is a failure of the caller's IXKeyLookup, passed through
// with the ack_key: its reason is "", and it is not permanent.
type Error struct {
	Reason string
	Detail string
	Err    error
}

func (e *Error) Error() string {
	msg := "seal: " + e.Reason
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

// Permanent reports whether retrying with the same input can give a
// different result. Every reason except two describes the bytes that were
// presented (or the caller's input), so the same bytes fail the same way on
// every attempt: §3.6 class P, ack and drop. The two: an internal error comes
// from the local entropy source or encoder and says nothing about the input;
// and witness-unknown says only that this node does not hold the witness
// hub's KEL yet, which a refresh of the hub KEL set can change (KEL C-56,
// D-24).
func (e *Error) Permanent() bool {
	return e.Reason != ReasonInternalError && e.Reason != ReasonWitnessUnknown
}

// ReasonOf returns the reason carried by err, or "" when err is nil or does
// not wrap a *Error.
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// IsPermanent reports whether err wraps a *Error whose Permanent method
// returns true. An error this package did not produce is reported as not
// permanent, because only the caller knows what it means.
func IsPermanent(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Permanent()
}

func fail(reason, format string, args ...any) *Error {
	return &Error{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

func failWrap(reason string, err error, format string, args ...any) *Error {
	return &Error{Reason: reason, Detail: fmt.Sprintf(format, args...), Err: err}
}

// ackError is an error of Open after layer 1 was opened: it carries the
// ack_key the recipient exports there, so the caller can still answer with a
// delivery token (DLV-C-API-1). It adds nothing to the message: Error and
// Unwrap are those of the wrapped error.
type ackError struct {
	key AckKey
	err error
}

func (e *ackError) Error() string { return e.err.Error() }
func (e *ackError) Unwrap() error { return e.err }

// withAck wraps err, a failure after layer 1, with the ack_key.
func withAck(key AckKey, err error) error { return &ackError{key: key, err: err} }

// AckKeyOf returns the ack_key carried by an error of Open, and whether there
// is one. It is true exactly for the failures after layer 1 was opened (a
// malformed Wrap, a closed interaction, a failed interaction-key lookup or
// second layer, a malformed inner, to-mismatch, exp-mismatch, the KEL caps):
// the envelope was sealed to this node, so its sender is owed a token. It is
// false for a failure of ParseOuter, an unknown kid and a failed layer-1 open
// (DLV-C-API-2), for nil, and for an error this package did not produce.
func AckKeyOf(err error) (AckKey, bool) {
	var e *ackError
	if errors.As(err, &e) {
		return e.key, true
	}
	return AckKey{}, false
}
