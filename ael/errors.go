package ael

// Error codes — the anr:ael.error-code registry (evidence-spec §4.5, Standards-Action). The
// Labels are the implementation-neutral SCREAMING_CASE identifiers exactly as evidence-03 §5.6
// spells them; the integer Codepoints are a registry fact carried so a verifier never silently
// drops (no bare implementation error and no silent drop is conformant). A failure yields a
// typed code, NO store mutation off the equivocation/quarantine path, NO silent drop.
type ErrorCode struct {
	Codepoint int
	Label     string
}

// Frozen labels (§4.5). Codepoints follow the §4.5 table order (0 reserved = no-error). The
// 13 registered codes plus VERSION_UNSUPPORTED — a P2 TypeError carried beside the registry
// (§4.5/§5.8): an unknown MAJOR is rejected before a non-MAJOR-2 record is ever hashed as
// MAJOR-2.
var (
	APPEND_ONLY                  = ErrorCode{1, "APPEND_ONLY"}                   // UPDATE/DELETE on a stored event (§5.6)
	SEQ_GAP                      = ErrorCode{2, "SEQ_GAP"}                       // genuine non-buffer-able ordering fault (§5.6)
	INVALID_SIGNATURE            = ErrorCode{3, "INVALID_SIGNATURE"}             // AObj signature does not verify (§5.3#1)
	UNKNOWN_AID                  = ErrorCode{4, "UNKNOWN_AID"}                   // signer AID not resolvable (§5.3#1)
	REVOKED_KEY                  = ErrorCode{5, "REVOKED_KEY"}                   // signing key deactivated/rotated-away as-of ts (§5.3#2)
	ID_MISMATCH                  = ErrorCode{6, "ID_MISMATCH"}                   // recomputed id ≠ claimed id (§5.3#3)
	PREV_LINK_BROKEN             = ErrorCode{7, "PREV_LINK_BROKEN"}              // prev_id does not match the held predecessor (§5.4#2)
	EQUIVOCATION                 = ErrorCode{8, "EQUIVOCATION"}                  // distinct event already at (chain_did, seq) — fork-trap (§5.4#3)
	CHAIN_QUARANTINED            = ErrorCode{9, "CHAIN_QUARANTINED"}             // append/reliance on a sticky-QUARANTINED chain (§5.1 T6)
	NOT_CAUSALLY_PRIOR           = ErrorCode{10, "NOT_CAUSALLY_PRIOR"}           // referenced decision not causally prior (§5.7.1)
	IMPORT_BUFFER_FULL           = ErrorCode{11, "IMPORT_BUFFER_FULL"}           // bounded out-of-order staging buffer overflowed (§5.4#2)
	CATCHUP_TIMEOUT              = ErrorCode{12, "CATCHUP_TIMEOUT"}              // bounded catch-up window exceeded / staged event reclaimed (§5.5)
	SETTLEMENT_REDRIVE_EXHAUSTED = ErrorCode{13, "SETTLEMENT_REDRIVE_EXHAUSTED"} // outbox retry budget exhausted (§5.9; settlement extension)
	// VERSION_UNSUPPORTED — P2 TypeError (unknown MAJOR), carried beside anr:ael.error-code
	// (§4.5/§5.8). The MAJOR gate MUST raise this so a non-MAJOR-2 record is never hashed as
	// MAJOR-2. (The MAJOR-1 string-concat id is a documented follow-up.)
	VERSION_UNSUPPORTED = ErrorCode{14, "VERSION_UNSUPPORTED"}

	// BAD_GENESIS_PREV — first-event genesis discipline (§3.5/§5.1 T0): seq=0 prev_id MUST be
	// the MAJOR-2 GENESIS_PREV sentinel; a first event with seq≠0 or a wrong genesis prev_id is
	// rejected before store.
	BAD_GENESIS_PREV = ErrorCode{15, "BAD_GENESIS_PREV"}
)

// Error is a typed AEL error carrying the §4.5 registry code plus detail. errors.As/IsCode over
// the Label lets a caller branch on the SCREAMING_CASE identifier without string parsing.
type Error struct {
	Code   ErrorCode
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Code.Label
	}
	return e.Code.Label + ": " + e.Detail
}

// Is reports whether target is an *Error with the same registry codepoint, so a caller can
// write errors.Is(err, &ael.Error{Code: ael.CHAIN_QUARANTINED}).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return t.Code.Codepoint == e.Code.Codepoint
}

// IsCode reports whether err is an *Error with the given registry code. Convenience over
// errors.As for the common "which rejection?" assertion.
func IsCode(err error, code ErrorCode) bool {
	e, ok := err.(*Error)
	return ok && e.Code.Codepoint == code.Codepoint
}

// newErr builds a typed *Error.
func newErr(code ErrorCode, detail string) *Error { return &Error{Code: code, Detail: detail} }
