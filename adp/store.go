package adp

import (
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
)

// CardStore is the verify-before-cache card cache (adp-spec §5.1–§5.3). Every Put runs the
// §5.1 AdmitCard gate FIRST — there is NO trust-on-first-publish path; a rejected card leaves
// NO store entry (the conformance test asserts this). It holds:
//
//   - per-subject high_water seq — the §5.3 freshness floor; CAS-guarded (admit iff strictly
//     higher) and MUST survive restart (here an in-memory map; a daemon backs it with the §5.3
//     sqlite adp_highwater table);
//   - current trusted card per subject (FSM PUBLISHED/EXPIRED/REVOKED dispositions);
//   - an optional verify-once cache keyed (card_cid, key_state) so the same card_cid twice is a
//     no-op (idempotent, §5.2 / P1 M1.4); this cache MAY be cold post-restart.
type CardStore struct {
	mu sync.Mutex

	highWater map[string]uint64      // subject_did → max accepted seq (survives restart, §5.3)
	state     map[string]Disposition // subject_did → current FSM disposition
	cards     map[string]*AgentCard  // subject_did → current trusted card
	cardCID   map[string]string      // subject_did → current card's card_cid
	verified  map[string]struct{}    // "<card_cid>|<key_state_seq>" → verified-once (idempotency)

	// §4.6 standard counters (P4 M4.7), MUST export. Guarded by mu.
	cardVerifyFail int64 // any AdmitCard/AdmitTombstone verify failure (§4.6)
	rollbackReject int64 // STALE_SEQ rollback rejects specifically (§4.6 / §5.2 T3)

	majors map[uint16]bool
	genome GenomeResolver
}

// CardVerifyFail returns the §4.6 card_verify_fail counter: total verify failures across all
// AdmitCard/AdmitTombstone gate runs through this store (any typed rejection).
func (s *CardStore) CardVerifyFail() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cardVerifyFail
}

// RollbackReject returns the §4.6 rollback_reject counter: STALE_SEQ rollback rejects (a card
// or tombstone whose seq did not advance past high_water; §5.2 T3 / §5.3 CAS).
func (s *CardStore) RollbackReject() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rollbackReject
}

// NewCardStore builds an empty store. majors is the node's supported card_schema.major set
// (§4.2 — a node subscribes to exactly the MAJORs it supports); genome is the optional §5.1
// step-8 resolver (nil ⇒ any card carrying genome.* is rejected DANGLING_GENOME_CID).
func NewCardStore(majors map[uint16]bool, genome GenomeResolver) *CardStore {
	return &CardStore{
		highWater: map[string]uint64{},
		state:     map[string]Disposition{},
		cards:     map[string]*AgentCard{},
		cardCID:   map[string]string{},
		verified:  map[string]struct{}{},
		majors:    majors,
		genome:    genome,
	}
}

// HighWater returns the persisted per-subject high_water seq (0 = first sight). §5.3.
func (s *CardStore) HighWater(subjectDID string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.highWater[subjectDID]
}

// SetHighWater seeds a persisted high_water (e.g. restored from the §5.3 sqlite row at
// daemon start). Used to model "high_water survives restart" (ADP-GV-5).
func (s *CardStore) SetHighWater(subjectDID string, hw uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.highWater[subjectDID] = hw
}

// State returns the current FSM disposition for a subject (empty = ABSENT). §5.2.
func (s *CardStore) State(subjectDID string) Disposition {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state[subjectDID]
}

// Get returns the current trusted card for a subject, or nil if ABSENT/REVOKED.
func (s *CardStore) Get(subjectDID string) *AgentCard {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cards[subjectDID]
}

// Subjects returns the subject DIDs with a currently-cached card (PUBLISHED or EXPIRED; a revoked
// subject is absent — Revoke deletes its entry). Order is unspecified. This is the enumeration
// primitive a registry needs over the otherwise point-lookup-only store (so it need not keep a
// drift-prone shadow index of subjects).
func (s *CardStore) Subjects() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.cards))
	for did := range s.cards {
		out = append(out, did)
	}
	return out
}

// Put runs the §5.1 AdmitCard gate, then — and ONLY then — caches the card and advances
// high_water = card.seq under the §5.3 CAS guard (admit iff strictly higher). On any rejection
// it returns the typed *Error and mutates NOTHING (verify-before-side-effect). It is idempotent:
// the same card_cid (same key_state) twice is a verified no-op.
//
// On the admit-then-EXPIRE branch (§5.1 step 7 already-expired) Put returns nil with the card
// cached in disposition EXPIRED and high_water advanced — admitted, not rejected (T5).
func (s *CardStore) Put(card *AgentCard, now time.Time, kel []identity.SignedEvent) (Disposition, error) {
	// CardCID needs no lock (pure over the card); compute before taking the mutex.
	cid, cidErr := card.CardCID()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Idempotency (§5.2 / P1 M1.4): a previously verified (card_cid, key_state) is a no-op. Only
	// consult the cache once the card_cid is computable (a malformed card has no stable cid).
	if cidErr == nil {
		vk := cid + "|" + uintToStr(card.Envelope.KeyStateSeq)
		if _, seen := s.verified[vk]; seen {
			return s.state[card.SubjectDID], nil // same card again — no-op
		}
	}

	hw := s.highWater[card.SubjectDID]
	disp, err := AdmitCard(card, now, hw, kel, s.majors, s.genome)
	if err != nil {
		// §4.6 counters: any verify failure bumps card_verify_fail; a STALE_SEQ rollback
		// additionally bumps rollback_reject (§5.2 T3).
		s.cardVerifyFail++
		if IsCode(err, STALE_SEQ) {
			s.rollbackReject++
		}
		return "", err // NO mutation on reject
	}

	// §5.3 CAS guard: admit iff strictly higher (AdmitCard already enforced seq > high_water in
	// step 7, but re-assert atomically under the lock against a concurrent advance).
	if card.Seq <= s.highWater[card.SubjectDID] {
		s.cardVerifyFail++
		s.rollbackReject++
		return "", &Error{Code: STALE_SEQ, Detail: "lost CAS race: seq <= high_water"}
	}

	s.cards[card.SubjectDID] = card
	s.cardCID[card.SubjectDID] = cid
	s.highWater[card.SubjectDID] = card.Seq
	s.state[card.SubjectDID] = disp
	if cidErr == nil {
		s.verified[cid+"|"+uintToStr(card.Envelope.KeyStateSeq)] = struct{}{}
	}
	return disp, nil
}

// Revoke runs the §5.4 tombstone gate, then — and ONLY then — drives the subject to REVOKED and
// advances high_water = tombstone.seq (T4), so a later re-publish cannot reuse the tombstone seq
// (T11). On rejection (third-party UNAUTHORIZED_REVOKE, low-seq STALE_SEQ, bad sig) it mutates
// NOTHING.
func (s *CardStore) Revoke(tb *CardTombstone, kel []identity.SignedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hw := s.highWater[tb.SubjectDID]
	if err := AdmitTombstone(tb, hw, kel); err != nil {
		s.cardVerifyFail++
		if IsCode(err, STALE_SEQ) {
			s.rollbackReject++
		}
		return err // NO mutation on reject
	}
	if tb.Seq <= s.highWater[tb.SubjectDID] {
		s.cardVerifyFail++
		s.rollbackReject++
		return &Error{Code: STALE_SEQ, Detail: "lost CAS race: tombstone.seq <= high_water"}
	}
	delete(s.cards, tb.SubjectDID)
	delete(s.cardCID, tb.SubjectDID)
	s.highWater[tb.SubjectDID] = tb.Seq // T4: advance over the tombstone seq
	s.state[tb.SubjectDID] = Disposition("REVOKED")
	return nil
}

func uintToStr(u uint64) string {
	// small local helper to avoid importing strconv twice for one call site readability
	const digits = "0123456789"
	if u == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = digits[u%10]
		u /= 10
	}
	return string(b[i:])
}
