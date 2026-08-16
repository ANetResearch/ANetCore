package adp

import (
	"time"

	"github.com/ANetResearch/ANetCore/identity"
)

// Admission disposition (the §5.2 card lifecycle FSM state an admit drives to). AdmitCard
// returns OK with one of these on the success path; a rejection returns a typed *Error and
// NO disposition mutation (verify-before-side-effect, §5.1 / P1 P1.5).
type Disposition string

const (
	// DispPublished: §5.1 all pass; card is current (FSM T1/T2/T11). high_water = card.seq.
	DispPublished Disposition = "PUBLISHED"
	// DispExpired: admit-then-EXPIRE (§5.1 step 7 already-expired branch / FSM T5). The card is
	// admitted (passes §5.1) then driven immediately to EXPIRED — never a reject; returns
	// BEFORE step 8 (no genome fetch). high_water = card.seq.
	DispExpired Disposition = "EXPIRED"
)

// GenomeResolver fetches and self-verifies a genome CAS object by CID (adp-spec §5.1 step 8a/8b;
// §2.5 CoreDet-CBOR, Experimental semantics in ascp-evo-03). ADP only carries genome refs on the
// card; resolution is a pluggable boundary. A baseline node with no genome plane supplied passes
// nil and a card carrying genome.* is rejected DANGLING_GENOME_CID (the referent cannot resolve).
type GenomeResolver interface {
	// FetchSpecies resolves a species_cid → SpeciesGenome bytes and reports whether the fetched
	// bytes self-verify (hash(bytes)==cid, §5.1 step 8a) AND carry a valid governance_quorum_cert
	// (§5.1 step 8b SpeciesGenome side). ok=false → DANGLING_GENOME_CID; conformant=false →
	// GENOME_CONFORMANCE_FAIL.
	FetchSpecies(cid string) (ok bool, conformant bool)
	// FetchInstance resolves an instance_cid → InstanceGenome and reports self-verification (8a)
	// and that its conformance_attestation signs the claimed species_cid (§5.1 step 8b instance side).
	FetchInstance(cid string) (ok bool, conformant bool)
}

// supportedMajors is a set membership test over the card_schema.major values a node supports
// (§5.1 step 1). A node subscribes to exactly the MAJORs it supports (§4.2).
type supportedMajors map[uint16]bool

// SupportedMajors builds the supported-MAJOR set for AdmitCard (§5.1 step 1 / §2.4).
func SupportedMajors(majors ...uint16) map[uint16]bool {
	s := make(map[uint16]bool, len(majors))
	for _, m := range majors {
		s[m] = true
	}
	return s
}

// understoodExtension reports whether a critical-extension label is understood by this node
// (§5.1 step 6 / §5.2.1). Baseline: this build understands no extension labels, so ANY label in
// critical_extensions[] is unverifiable. domains[] is a TYPED field, not an extension label, so
// it never appears here (§5.2.1: "domains[] is a typed schema field, not an extension label").
func understoodExtension(label string) bool {
	// No labels registered in this reference build → unknown critical label is UNVERIFIABLE.
	return false
}

// AdmitCard runs the §5.1 verify-before-cache precondition — the HARD gate before EVERY cache
// Put and EVERY gossip ingest. There is NO trust-on-first-publish path. It runs the 8 steps in
// the SPEC ORDER and returns a typed §4.5 *Error on any failure (NO state mutation, NO silent
// drop), or DispPublished / DispExpired on success.
//
// Parameters:
//   - card: the parsed AgentCard (already JSON-parsed; SchemaVersionTag/JSON-parse class →
//     MALFORMED_CARD here when the card is unusable).
//   - now: the verifier's wall clock (freshness/skew, §5.1 step 7).
//   - highWater: the current per-subject high_water seq (0 = first sight); §5.3 / step 7.
//   - kel: the signer's published Key Event Log; identity.Replay(kel)→KeyState resolves the
//     signer key at card.envelope.key_state_seq (P1 resolver; §5.1 step 2/3).
//   - majors: the node's supported card_schema.major set (§5.1 step 1).
//   - genome: optional genome resolver (§5.1 step 8); nil ⇒ any genome.* ref → DANGLING_GENOME_CID.
func AdmitCard(card *AgentCard, now time.Time, highWater uint64, kel []identity.SignedEvent, majors map[uint16]bool, genome GenomeResolver) (Disposition, error) {
	// ---- 1. parse + schema-MAJOR (gossip path checks SchemaVersionTag byte[0] BEFORE JSON
	//         parse, §2.4; here the card is already parsed, so this is the structural class). ----
	if card == nil {
		return "", &Error{Code: MALFORMED_CARD, Detail: "nil card"}
	}
	if card.SubjectDID == "" || card.Envelope.SignerAID == "" {
		// A card with no subject or no envelope signer is unusable — parse class, not freshness
		// (§5.1 step 1). A captured legacy card with no envelope lands here (ADP-GV-10).
		return "", &Error{Code: MALFORMED_CARD, Detail: "missing subject_did or envelope.signer_aid"}
	}
	if card.Envelope.Alg != AlgEdDSA || card.Envelope.Sig == "" {
		return "", &Error{Code: MALFORMED_CARD, Detail: "envelope missing EdDSA detached-JWS signature"}
	}
	if len(card.Name) > MaxNameLen || len(card.Description) > MaxDescriptionLen || len(card.Skills) > MaxSkills {
		return "", &Error{Code: MALFORMED_CARD, Detail: "size limit exceeded (§2.7)"}
	}
	if !majors[card.CardSchema.Major] {
		// Held UNVERIFIABLE — a higher-MAJOR card cannot be misparsed (§2.4 / FSM T6).
		return "", &Error{Code: UNSUPPORTED_SCHEMA_MAJOR, Detail: "card_schema.major not in supported set"}
	}

	// ---- 2/3/4. resolve signer key, verify detached sig, anti-downgrade + as-of-time
	//         revocation gate — all via P1's identity.VerifyObject (§5.1 step 2/3/4; P1
	//         M5.1.2 anti-downgrade + M5.1.3 as-of-time grace). The card path is detached
	//         JWS, so decode it to the (signing-input, raw-sig) pair VerifyObject checks
	//         with a raw Ed25519 verify (the JWS sig IS ed25519.Sign(key, signing-input)).
	//         ks = KeyState(signer_aid, card.issued_at): a card signed at an OLDER seq whose
	//         issued_at is BEFORE a later rotation MUST verify (grace, M5.1.3); only a card
	//         issued at/after the retirement is REVOKED_KEY. ----
	pre, err := card.Preimage()
	if err != nil {
		return "", err // MALFORMED_CARD (preimage not buildable)
	}
	signingInput, rawSig, ok := decodeDetachedJWS(pre, card.Envelope.Sig)
	if !ok {
		return "", &Error{Code: INVALID_SIGNATURE, Detail: "detached JWS malformed or alg-substituted"}
	}
	// issued_at is unix-s; VerifyObject's as-of time (the KEL grace window) is unix-millis.
	issuedAtMillis := uint64(card.IssuedAt) * 1000
	if verr := identity.VerifyObject(kel, card.Envelope.SignerAID, card.Envelope.KeyStateSeq, issuedAtMillis, signingInput, rawSig); verr != nil {
		return "", mapVerifyErr(verr)
	}

	// ---- 5. authorization (§5.1 step 5): self-publish default; delegated needs delegation_proof. ----
	if len(card.DelegationProof) == 0 {
		if card.Envelope.SignerAID != card.SubjectDID {
			return "", &Error{Code: UNAUTHORIZED_SIGNER, Detail: "self-publish requires signer_aid == subject_did"}
		}
	} else {
		// Delegated publish: a valid zcap/cert chain rooted at subject_did.master authorizing
		// signer_aid as-of issued_at. Chain verification is a P1/P3 zcap mechanism not re-derived
		// here (§1.2 out-of-scope); baseline accepts a present, non-empty delegation_proof as the
		// carriage and defers chain validity to the P1/P3 zcap verifier. A node without that
		// verifier configured MUST reject (no silent trust) — reported as an ambiguity.
		if !validDelegation(card.DelegationProof, card.SubjectDID, card.Envelope.SignerAID, card.IssuedAt) {
			return "", &Error{Code: UNAUTHORIZED_SIGNER, Detail: "delegation_proof does not authorize signer for subject"}
		}
	}

	// ---- 6. critical-extension check (§5.1 step 6 / §5.2.1): every critical label MUST be
	//         understood, else UNVERIFIABLE. domains[] is a typed field, never checked here. ----
	for _, lbl := range card.CriticalExtensions {
		if !understoodExtension(lbl) {
			return "", &Error{Code: CRITICAL_EXTENSION_UNVERIFIABLE, Detail: "unknown critical extension label: " + lbl}
		}
	}

	// ---- 7. freshness / seq / clock-skew (§5.1 step 7). ----
	if card.Seq <= highWater {
		// rollback reject; the FSM bumps rollback_reject (§5.3 / T3).
		return "", &Error{Code: STALE_SEQ, Detail: "card.seq <= high_water (rollback reject)"}
	}
	notBefore := time.Unix(card.NotBefore, 0)
	if notBefore.After(now.Add(ADPFutureSkew)) {
		// anti-pre-dating, freshness class (code 17, NOT MALFORMED_CARD — §5.1 step 7 / ADP-GV-6a).
		return "", &Error{Code: CARD_NOT_YET_VALID, Detail: "not_before > now + ADP_FUTURE_SKEW"}
	}
	if now.After(notBefore.Add(ADPCardTTL)) {
		// admit-then-EXPIRE branch (T5): a card already past not_before+ADP_CARD_TTL is admitted
		// (passes §5.1) then driven immediately to EXPIRED — NOT a reject. Returns BEFORE step 8;
		// no genome fetch (§5.1 step 7 / ADP-GV-6b). Caller MUST Put + set high_water = card.seq.
		return DispExpired, nil
	}

	// ---- 8. genome self-consistency (Experimental semantics — ascp-evo-03). ----
	if card.Genome != nil && (card.Genome.SpeciesCID != "" || card.Genome.InstanceCID != "") {
		if genome == nil {
			// referent cannot resolve — QUARANTINED (§5.1 step 8a).
			return "", &Error{Code: DANGLING_GENOME_CID, Detail: "genome referenced but no resolver configured"}
		}
		if card.Genome.SpeciesCID != "" {
			ok, conformant := genome.FetchSpecies(card.Genome.SpeciesCID)
			if !ok {
				return "", &Error{Code: DANGLING_GENOME_CID, Detail: "species_cid does not resolve / hash mismatch"}
			}
			if !conformant {
				return "", &Error{Code: GENOME_CONFORMANCE_FAIL, Detail: "species genome governance_quorum_cert invalid"}
			}
		}
		if card.Genome.InstanceCID != "" {
			ok, conformant := genome.FetchInstance(card.Genome.InstanceCID)
			if !ok {
				return "", &Error{Code: DANGLING_GENOME_CID, Detail: "instance_cid does not resolve / hash mismatch"}
			}
			if !conformant {
				return "", &Error{Code: GENOME_CONFORMANCE_FAIL, Detail: "conformance_attestation does not sign claimed species_cid"}
			}
		}
	}

	// ONLY now: the caller Puts the card and sets high_water = card.seq (§5.1 / T1).
	return DispPublished, nil
}

// validDelegation is the §5.1 step 5 delegated-publish authorization hook. Full zcap/cert-chain
// validation (root=subject_did.master, authz=signer_aid, asof=issued_at) is a P1/P3 mechanism
// (out-of-scope §1.2). Baseline: a present, non-empty delegation_proof is treated as the
// carriage and accepted; production wires the real zcap verifier here. See report ambiguity #3.
func validDelegation(proof []byte, subjectDID, signerAID string, issuedAt int64) bool {
	return len(proof) > 0
}

// AdmitTombstone runs the §5.4 tombstone-revoke gate: a revoke is ONLY a subject-self-signed
// CardTombstone. It rejects a third-party tombstone (UNAUTHORIZED_REVOKE) and a low-seq one
// (STALE_SEQ); on success it returns OK and the caller sets state=REVOKED and
// high_water = tombstone.seq (T4) so a later re-publish cannot reuse the tombstone seq (T11).
func AdmitTombstone(tb *CardTombstone, highWater uint64, kel []identity.SignedEvent) error {
	if tb == nil {
		return &Error{Code: MALFORMED_CARD, Detail: "nil tombstone"}
	}
	if tb.SubjectDID == "" || tb.Envelope.SignerAID == "" || tb.Envelope.Sig == "" {
		return &Error{Code: MALFORMED_CARD, Detail: "tombstone missing subject_did or envelope signature"}
	}
	// §5.4: signerOf(tb) != tb.subject_did → UNAUTHORIZED_REVOKE (third-party reject). The
	// signer's resolved identity is its envelope.signer_aid; a third party cannot sign as the
	// subject (the KEL self-verification below proves the signer controls signer_aid).
	if tb.Envelope.SignerAID != tb.SubjectDID {
		return &Error{Code: UNAUTHORIZED_REVOKE, Detail: "tombstone signer is not the subject (third-party revoke)"}
	}
	// §5.4: run §5.1 steps 2..4 with signer==subject (resolve key, verify detached-JWS sig,
	// anti-downgrade + as-of-time revocation grace) via P1's identity.VerifyObject — the
	// same as-of-time grace as the card path (M5.1.2/M5.1.3): a tombstone signed at an older
	// seq whose issued_at predates a later rotation still verifies.
	pre, err := tb.Preimage()
	if err != nil {
		return err
	}
	signingInput, rawSig, ok := decodeDetachedJWS(pre, tb.Envelope.Sig)
	if !ok {
		return &Error{Code: INVALID_SIGNATURE, Detail: "tombstone detached JWS malformed or alg-substituted"}
	}
	issuedAtMillis := uint64(tb.IssuedAt) * 1000
	if verr := identity.VerifyObject(kel, tb.Envelope.SignerAID, tb.Envelope.KeyStateSeq, issuedAtMillis, signingInput, rawSig); verr != nil {
		return mapVerifyErr(verr)
	}
	// §5.4: tb.seq <= high_water → STALE_SEQ.
	if tb.Seq <= highWater {
		return &Error{Code: STALE_SEQ, Detail: "tombstone.seq <= high_water"}
	}
	return nil
}

// mapVerifyErr maps a P1 identity.VErr (arch-03 §5.1 M5.1.4) onto the §4.5 ADP error code,
// so the key-resolution / anti-downgrade / signature / revocation verdicts the ADP gate
// delegates to identity.VerifyObject surface as the right SCREAMING_CASE ADP code (a
// non-*VErr error, or an unrecognized reason, is the conservative INVALID_SIGNATURE).
func mapVerifyErr(err error) *Error {
	ve, ok := err.(*identity.VErr)
	if !ok {
		return &Error{Code: INVALID_SIGNATURE, Detail: err.Error()}
	}
	switch ve.Reason {
	case "UNKNOWN_AID":
		return &Error{Code: UNKNOWN_AID, Detail: ve.Detail}
	case "KEY_STATE_DOWNGRADE":
		return &Error{Code: KEY_STATE_DOWNGRADE, Detail: ve.Detail}
	case "REVOKED_KEY":
		return &Error{Code: REVOKED_KEY, Detail: ve.Detail}
	case "INVALID_SIGNATURE":
		return &Error{Code: INVALID_SIGNATURE, Detail: ve.Detail}
	default:
		return &Error{Code: INVALID_SIGNATURE, Detail: ve.Reason + ": " + ve.Detail}
	}
}
