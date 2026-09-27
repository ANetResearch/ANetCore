package a2acard

import "errors"

// Code classifies a rejection. Callers branch on the code, not on the detail text.
type Code string

const (
	// CodeMalformedJSON: the input is not strict I-JSON (syntax error, duplicate member name,
	// invalid UTF-8, lone surrogate, noncharacter, number outside binary64 range, nesting too deep).
	CodeMalformedJSON Code = "MALFORMED_JSON"
	// CodeInvalidCard: a required member is missing, empty or of the wrong type, or the
	// anet-card extension or a signature entry does not have the required shape.
	CodeInvalidCard Code = "INVALID_CARD"
	// CodeTooLarge: a size limit (card bytes, name, description, skills, tags, signatures) is exceeded.
	CodeTooLarge Code = "CARD_TOO_LARGE"
	// CodeUnsigned: the card has no signatures.
	CodeUnsigned Code = "UNSIGNED"
	// CodeBadHeader: the JWS protected header cannot be decoded, names an algorithm other than
	// EdDSA, carries crit, or its kid is not of the form did:anet:<AID>#<seq>.
	CodeBadHeader Code = "BAD_SIGNATURE_HEADER"
	// CodeBindingMismatch: the kid AID differs from the anet-card params.aid, or a relay
	// interface's tenant differs from that AID.
	CodeBindingMismatch Code = "BINDING_MISMATCH"
	// CodeKELUnavailable: the resolver returned an error. The card's validity is unknown, not
	// disproved; Error.Err carries the resolver's error so a caller can retry.
	CodeKELUnavailable Code = "KEL_UNAVAILABLE"
	// CodeUnknownAID: the KEL does not replay, or it replays to a different AID.
	CodeUnknownAID Code = "UNKNOWN_AID"
	// CodeKeyNotCurrent: the kid's key state has been retired by a later rotation or
	// deactivation, or lies beyond the KEL.
	CodeKeyNotCurrent Code = "KEY_NOT_CURRENT"
	// CodeInvalidSignature: the Ed25519 signature does not verify over the signing input.
	CodeInvalidSignature Code = "INVALID_SIGNATURE"
	// CodeNotYetValid: notBefore is more than NotBeforeSkewMillis after now.
	CodeNotYetValid Code = "CARD_NOT_YET_VALID"
	// CodeSeqRollback: params.seq is below the stored high-water mark.
	CodeSeqRollback Code = "SEQ_ROLLBACK"
	// CodeSeqFork: params.seq equals the stored mark but the canonical payload differs.
	CodeSeqFork Code = "SEQ_FORK"
	// CodeNotPublishForm: Sign or CheckPublishForm was given a card that is not in publish form
	// (a default-valued member, a missing or empty REQUIRED member, an unknown member, an empty
	// value inside a Struct; see CheckPublishForm). The card builder is at fault; the detail
	// names the member.
	CodeNotPublishForm Code = "NOT_PUBLISH_FORM"
)

// Error is the error type returned by this package.
type Error struct {
	Code   Code
	Detail string
	// Err is the underlying cause when there is one (the resolver's error for
	// CodeKELUnavailable, the identity package's error for CodeUnknownAID).
	Err error
}

func (e *Error) Error() string {
	s := string(e.Code)
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// IsCode reports whether err is, or wraps, an *Error with the given code.
func IsCode(err error, code Code) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

func newErr(code Code, detail string) *Error { return &Error{Code: code, Detail: detail} }
