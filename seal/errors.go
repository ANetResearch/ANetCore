package seal

import (
	"errors"
	"fmt"
)

// Reason strings carried by *Error. They are stable: callers count them in
// metrics and logs, and the daemon maps them onto §3.6 failure classes, so a
// reason is never renamed once released. Detail text is free-form and may
// change.
const (
	// Outer envelope (§3.6 step 1).
	ReasonBadOuter       = "bad-outer"       // outer does not decode, misses a field, or has a wrong-typed/sized field
	ReasonBadVersion     = "bad-version"     // outer v != 1
	ReasonUnknownSuite   = "unknown-suite"   // suite not implemented by this build
	ReasonWrongRecipient = "wrong-recipient" // outer to != the opening node's AID

	// Key lookup and decryption (steps 2-3).
	ReasonUnknownKey = "sealed-to-unknown-key" // kid not in the key ring (never held, or past retention)
	ReasonDecrypt    = "decrypt-failed"        // HPKE setup or AEAD open failed

	// Inner structure (step 4).
	ReasonBadInner      = "bad-inner"              // inner does not decode, misses a field, or has a wrong-typed/sized field
	ReasonUnknownField  = "unknown-critical-field" // a key in 0-63 this version does not understand
	ReasonToMismatch    = "to-mismatch"            // inner to != outer to
	ReasonBadPad        = "bad-pad"                // pad field is not all zero bytes
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

// Error is the only error type this package returns. Reason is one of the
// Reason* constants; Detail says which field or rule failed; Err is the
// underlying cause when there is one (a decoder error, an identity.VErr).
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
