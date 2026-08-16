package adp

// Error codes — the anr:adp.error-code registry (adp-spec §4.5, Standards-Action). The
// integer Codepoints are FROZEN MUST; the Labels are the implementation-neutral SCREAMING_CASE
// identifiers exactly as adp-03 §9.3 spells them. An Error carries both so a verifier never
// silently drops (P3 M3.1): a failure yields a typed code, NO cache mutation, NO silent drop.
type ErrorCode struct {
	Codepoint int
	Label     string
}

// Frozen codepoints + labels (§4.5). Range: 0 reserved (no-error); 1..199 Standards-Action core.
var (
	MALFORMED_CARD                  = ErrorCode{1, "MALFORMED_CARD"}                   // §5.1 step 1 (parse class)
	UNKNOWN_AID                     = ErrorCode{2, "UNKNOWN_AID"}                      // §5.1 step 2
	INVALID_SIGNATURE               = ErrorCode{3, "INVALID_SIGNATURE"}                // §5.1 step 3
	KEY_STATE_DOWNGRADE             = ErrorCode{4, "KEY_STATE_DOWNGRADE"}              // §5.1 step 3 (anti-downgrade)
	REVOKED_KEY                     = ErrorCode{5, "REVOKED_KEY"}                      // §5.1 step 4 (revocation gate)
	UNAUTHORIZED_SIGNER             = ErrorCode{6, "UNAUTHORIZED_SIGNER"}              // §5.1 step 5
	UNAUTHORIZED_REVOKE             = ErrorCode{7, "UNAUTHORIZED_REVOKE"}              // §5.4 tombstone (third-party)
	STALE_SEQ                       = ErrorCode{8, "STALE_SEQ"}                        // §5.1 step 7 / §5.3 CAS (rollback)
	DANGLING_GENOME_CID             = ErrorCode{9, "DANGLING_GENOME_CID"}              // §5.1 step 8a / genesis CID mismatch
	GENOME_CONFORMANCE_FAIL         = ErrorCode{10, "GENOME_CONFORMANCE_FAIL"}         // §5.1 step 8b / genesis quorum
	CRITICAL_EXTENSION_UNVERIFIABLE = ErrorCode{11, "CRITICAL_EXTENSION_UNVERIFIABLE"} // §5.1 step 6 / §5.2.1
	UNSUPPORTED_SCHEMA_MAJOR        = ErrorCode{12, "UNSUPPORTED_SCHEMA_MAJOR"}        // §5.1 step 1 / §2.4 gossip path
	INSTINCT_NOT_IN_MANIFEST        = ErrorCode{13, "INSTINCT_NOT_IN_MANIFEST"}        // §5.7 gate step 1
	INSTINCT_SCOPE_EXPANSION        = ErrorCode{14, "INSTINCT_SCOPE_EXPANSION"}        // §5.7 gate step 3
	INSTINCT_REVOKED                = ErrorCode{15, "INSTINCT_REVOKED"}                // §5.7 gate step 4 (IRL)
	GOVERNANCE_QUORUM_FAIL          = ErrorCode{16, "GOVERNANCE_QUORUM_FAIL"}          // §5.6 propose/ratify lapse
	CARD_NOT_YET_VALID              = ErrorCode{17, "CARD_NOT_YET_VALID"}              // §5.1 step 7 future-skew (freshness)
	INSTINCT_PROVENANCE_INVALID     = ErrorCode{18, "INSTINCT_PROVENANCE_INVALID"}     // §5.7 gate step 2 (provenance)
)

// Error is a typed ADP error carrying the §4.5 registry code plus detail. Errors.Is/As over
// the Label lets callers branch on the SCREAMING_CASE identifier without string parsing.
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
// write errors.Is(err, &adp.Error{Code: adp.STALE_SEQ}).
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
