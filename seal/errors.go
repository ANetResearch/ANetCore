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
	ReasonBadVersion     = "bad-version"     // outer v != 2
	ReasonUnknownSuite   = "unknown-suite"   // suite not implemented by this build
	ReasonWrongRecipient = "wrong-recipient" // outer to != the opening node's AID
	ReasonAccessInvalid  = "access-invalid"  // outer key 7 is missing or not a well-formed Access (Detail "parse")

	// Key lookup and layer-1 decryption (steps 2-3). No ack_key exists yet.
	ReasonUnknownKey = "sealed-to-unknown-key" // kid not in the key ring (never held, or past retention)
	ReasonDecrypt    = "decrypt-failed"        // HPKE setup or AEAD open failed (either layer)

	// After layer 1 (step 3a on): every failure below carries the ack_key (AckKeyOf).
	ReasonBadWrap           = "bad-wrap"                     // the layer-1 plaintext is not a well-formed Wrap (FS-C8)
	ReasonClosedInteraction = "sealed-to-closed-interaction" // a second layer under an interaction key this node no longer holds
	ReasonIKeyMismatch      = "ikey-mismatch"                // the interaction key's (ix, peer) is not the inner (ix, from)

	// Inner structure (step 4).
	ReasonBadInner      = "bad-inner"              // inner does not decode, misses a field, has a wrong-typed/sized field, a from, to or ix with U+0000, or key 11 without key 10 (or the reverse)
	ReasonUnknownField  = "unknown-critical-field" // a key in 0-63 this version does not understand, including the retired 21 and the preimage-only 0 and 30-34
	ReasonToMismatch    = "to-mismatch"            // inner to != outer to
	ReasonExpMismatch   = "exp-mismatch"           // outer key 8 present and != inner exp
	ReasonBadRK         = "bad-rk"                 // inner key 15 is not {1: suite 1, 2: a 32-byte public key}
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
	ReasonBadKeySet     = "bad-keyset"             // key set fails structure or validity rules (§3.1 rule 3)
	ReasonNoUsableKey   = "no-usable-key"          // no key in the set is valid now under a supported suite
	ReasonInvalidInput  = "invalid-input"          // caller passed an object Seal or SignEncKeySet cannot produce a valid encoding from
	ReasonInternalError = "internal"               // entropy or encoder failure on the sending side; not a property of any received bytes
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
// different result. Every reason except ReasonInternalError describes the
// bytes that were presented (or the caller's input), so the same bytes fail
// the same way on every attempt: §3.6 class P, ack and drop. An internal
// error comes from the local entropy source or encoder and says nothing about
// the input.
func (e *Error) Permanent() bool { return e.Reason != ReasonInternalError }

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
