// Package ael implements the P6 Agent Event Ledger: a per-DID, signed, append-only,
// fork-evident hash chain — the network's cooperative-capture / pcap audit substrate.
//
// Normative source: design3/spec/evidence-spec.md. Core invariants:
//   - EventRecord id = CID over the keys-1..10 preimage (MAJOR-2, _CONVENTIONS §3);
//     chain_did/seq/signer_aid/key_state_seq fold into the id (no cross-chain replay).
//   - genesis prev_id = GENESIS_PREV = CID(CoreDet-CBOR("anet:ael:genesis")).
//   - verify-before-store at every append/import; debit-before-verify is the DoS gate.
//   - UNIQUE(chain_did, seq) is the fork-trap: two distinct ids at one (chain_did, seq)
//     ⇒ EquivocationProof + sticky CHAIN_QUARANTINED (NOT INSERT-OR-IGNORE).
//
// Scope: MAJOR-2 record model, id/preimage, sign/verify, per-DID chain Append/Import with
// equivocation→quarantine. The token-bucket admission numbers, transactional outbox, and
// settlement-profile hook are documented follow-ups over this core.
package ael

import (
	"fmt"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// VersionMajor2 selects the MAJOR-2 CoreDet-CBOR id algorithm (evidence-spec §3.3).
const VersionMajor2 = 2

// ImportBufferCap bounds the per-chain out-of-order staging buffer (evidence-spec §4.7/§5.4#2):
// a future-seq verified record is held until the gap fills; overflow ⇒ IMPORT_BUFFER_FULL.
// (The 30 s StagingReclaimTimeout → CATCHUP_TIMEOUT is a documented follow-up.)
const ImportBufferCap = 1024

// Chain states (evidence-spec §5.4 / §5.5).
const (
	ChainActive      = "ACTIVE"
	ChainQuarantined = "QUARANTINED"
)

// Event-type families (anr:ael.event-type, evidence-spec §4.3). A small set; the registry
// is open (Standards-Action protocol/anchor + FCFS application types).
const (
	EvGenesis      = "genesis"
	EvDispute      = "dispute"
	EvForkDetected = "converge.fork_detected" // P4 fork anchor; payload = ForkRecord (§4.3)
)

var genesisPrev string

func init() {
	pre, err := coredet.Marshal("anet:ael:genesis") // 0x70 ‖ "anet:ael:genesis"
	if err != nil {
		panic(err)
	}
	genesisPrev = anetcid.MustSum(pre)
}

// GenesisPrev returns the MAJOR-2 genesis sentinel prev_id (evidence-spec §3.5).
func GenesisPrev() string { return genesisPrev }

// EventRecord is one ledger entry (evidence-spec §2.1). Payload is an embedded CoreDet-CBOR
// data item (C-D5). id (11)/sig (12)/version.minor (13)/corr_id (14) are NOT in the preimage.
type EventRecord struct {
	ChainDID           string   `cbor:"1,keyasint"`
	Seq                uint64   `cbor:"2,keyasint"`
	PrevID             string   `cbor:"3,keyasint"`
	EventType          string   `cbor:"4,keyasint"`
	VersionMajor       uint64   `cbor:"5,keyasint"`
	Payload            any      `cbor:"6,keyasint"`
	Timestamp          int64    `cbor:"7,keyasint"`
	SignerAID          string   `cbor:"8,keyasint"`
	KeyStateSeq        uint64   `cbor:"9,keyasint"`
	CriticalExtensions []string `cbor:"10,keyasint,omitempty"`
	ID                 string   `cbor:"11,keyasint,omitempty"` // = ComputeID(); excluded from preimage
	Sig                []byte   `cbor:"12,keyasint,omitempty"` // detached over preimage
	VersionMinor       uint64   `cbor:"13,keyasint,omitempty"`
	CorrID             string   `cbor:"14,keyasint,omitempty"` // tstr (§2.1 CDDL); P4 trace correlation; NOT CID-sig
}

// preimageMap returns the CID-significant keys 1..10 (evidence-spec §3.3 MAJOR-2).
func (r *EventRecord) preimageMap() map[uint64]any {
	m := map[uint64]any{
		1: r.ChainDID, 2: r.Seq, 3: r.PrevID, 4: r.EventType,
		5: r.VersionMajor, 6: r.Payload, 7: r.Timestamp,
		8: r.SignerAID, 9: r.KeyStateSeq,
	}
	if len(r.CriticalExtensions) > 0 {
		m[10] = r.CriticalExtensions
	}
	return m
}

// Preimage is the CoreDet-CBOR SignableBytes (evidence-spec §3.3).
func (r *EventRecord) Preimage() ([]byte, error) { return coredet.Marshal(r.preimageMap()) }

// ComputeID returns the MAJOR-2 event id = CID(preimage) (evidence-spec §3.3).
func (r *EventRecord) ComputeID() (string, error) {
	pre, err := r.Preimage()
	if err != nil {
		return "", err
	}
	return anetcid.Sum(pre)
}

// Sign computes the id and a detached owner signature over the preimage (sign-binds-id).
// signer_aid/key_state_seq are CID-significant, so they are stamped BEFORE the preimage is
// built — one preimage feeds both the id and the signature.
func (r *EventRecord) Sign(c *identity.Controller) error {
	r.SignerAID = c.AID()
	r.KeyStateSeq = c.CurrentSeq()
	pre, err := r.Preimage()
	if err != nil {
		return err
	}
	id, err := anetcid.Sum(pre)
	if err != nil {
		return err
	}
	sig, _ := c.Sign(pre)
	r.ID = id
	r.Sig = sig
	return nil
}

// Verify runs the verify-before-store gate (evidence-spec §5.3): id re-derivation + the
// detached signature against the signer KEL, with the revocation gate evaluated as-of the
// record's timestamp (msgTime). A failure is a typed §4.5 *Error.
func (r *EventRecord) Verify(kel []identity.SignedEvent) error {
	pre, err := r.Preimage()
	if err != nil {
		return newErr(ID_MISMATCH, err.Error())
	}
	got, err := anetcid.Sum(pre)
	if err != nil {
		return newErr(ID_MISMATCH, err.Error())
	}
	if got != r.ID {
		return newErr(ID_MISMATCH, "id does not re-derive from preimage")
	}
	// Revocation gate is time-aware (§5.3#2): pass the record's own timestamp as msgTime so a
	// key rotated-away / deactivated as-of that time → REVOKED_KEY (msgTime=0 disabled it).
	if err := identity.VerifyObject(kel, r.SignerAID, r.KeyStateSeq, uint64(r.Timestamp), pre, r.Sig); err != nil {
		return mapIdentityErr(err)
	}
	return nil
}

// mapIdentityErr folds an identity.VErr reason into the anr:ael.error-code group (§5.3). The
// identity reasons (UNKNOWN_AID / INVALID_SIGNATURE / REVOKED_KEY / KEY_STATE_DOWNGRADE) are
// the same SCREAMING_CASE labels; the AEL gate surfaces them as typed §4.5 errors.
func mapIdentityErr(err error) error {
	ve, ok := err.(*identity.VErr)
	if !ok {
		return newErr(INVALID_SIGNATURE, err.Error())
	}
	switch ve.Reason {
	case "UNKNOWN_AID":
		return newErr(UNKNOWN_AID, ve.Detail)
	case "REVOKED_KEY":
		return newErr(REVOKED_KEY, ve.Detail)
	case "INVALID_SIGNATURE", "KEY_STATE_DOWNGRADE":
		return newErr(INVALID_SIGNATURE, ve.Reason+": "+ve.Detail)
	default:
		return newErr(INVALID_SIGNATURE, ve.Error())
	}
}

// EquivocationProof is two distinct full records at one (chain_did, seq) (evidence-spec §2.4).
type EquivocationProof struct {
	ChainDID string
	Seq      uint64
	NodeA    *EventRecord
	NodeB    *EventRecord
}

func (e *EquivocationProof) Error() string {
	return fmt.Sprintf("%s: %s seq %d (%s vs %s)", EQUIVOCATION.Label, e.ChainDID, e.Seq, e.NodeA.ID, e.NodeB.ID)
}

type chain struct {
	events []*EventRecord // index = seq
	state  string
	// staged holds verified future-seq records awaiting their predecessor (§5.4#2 staging
	// buffer), keyed by seq. Bounded by ImportBufferCap → IMPORT_BUFFER_FULL.
	staged map[uint64]*EventRecord
}

// Ledger holds per-DID chains with verify-before-store and the fork-trap (evidence-spec §5.4).
type Ledger struct {
	chains map[string]*chain
}

func NewLedger() *Ledger { return &Ledger{chains: map[string]*chain{}} }

// Append stores one record after the spec's gate ordering (evidence-spec §5.4):
//
//  0. sticky-quarantine guard FIRST (§5.1 T6 / guard_stickiness) — before any verify/work;
//  1. version.major gate (§3.3/§5.8) — a non-MAJOR-2 record is never hashed as MAJOR-2;
//  2. verify-before-store (§5.3): id re-derive + signature + as-of-ts revocation gate;
//  3. genesis / prev-link / fork-trap.
//
// kel resolves the signer for verification. A competing record at an existing seq with a
// different id quarantines the chain (persisting both nodes + a fork_detected anchor) and
// returns *EquivocationProof.
func (l *Ledger) Append(r *EventRecord, kel []identity.SignedEvent) error {
	ch := l.chains[r.ChainDID]
	// F1 (§5.4#... / §5.1 T6): guard_stickiness runs FIRST — once state=QUARANTINED, NO event
	// (however well-formed) moves the chain off quarantine; evaluated before any verify work.
	if ch != nil && ch.state == ChainQuarantined {
		return newErr(CHAIN_QUARANTINED, r.ChainDID)
	}
	// F2 (§3.3/§5.8): version.major gate — reject a non-MAJOR-2 record so it is never hashed
	// as MAJOR-2 (the MAJOR-1 string-concat id is a documented follow-up).
	if r.VersionMajor != VersionMajor2 {
		return newErr(VERSION_UNSUPPORTED, fmt.Sprintf("version.major %d (supported: %d)", r.VersionMajor, VersionMajor2))
	}
	// verify-before-store integrity gate (§5.3).
	if err := r.Verify(kel); err != nil {
		return err
	}
	if ch == nil || len(ch.events) == 0 {
		// genesis (§5.1 T0 / guard_genesis).
		if r.Seq != 0 {
			return newErr(BAD_GENESIS_PREV, "first event must be seq 0")
		}
		if r.PrevID != GenesisPrev() {
			return newErr(BAD_GENESIS_PREV, "genesis prev_id must be GENESIS_PREV")
		}
		l.chains[r.ChainDID] = &chain{events: []*EventRecord{r}, state: ChainActive}
		l.drainStaged(l.chains[r.ChainDID])
		return nil
	}
	return l.appendToChain(ch, r)
}

// appendToChain applies a verified record to an existing ACTIVE chain: fork-trap, prev-link,
// contiguous-advance, or bounded out-of-order staging (evidence-spec §5.4#2/#3).
func (l *Ledger) appendToChain(ch *chain, r *EventRecord) error {
	head := ch.events[len(ch.events)-1]
	// fork-trap (§5.4#3): a record at an already-held seq with a different id ⇒ equivocation.
	if r.Seq <= head.Seq {
		existing := ch.events[r.Seq]
		if existing.ID != r.ID {
			return l.quarantine(ch, existing, r)
		}
		return nil // benign re-delivery of the SAME node — idempotent no-op
	}
	if r.Seq == head.Seq+1 {
		if r.PrevID != head.ID {
			return newErr(PREV_LINK_BROKEN, fmt.Sprintf("seq %d prev_id does not link to head", r.Seq))
		}
		ch.events = append(ch.events, r)
		l.drainStaged(ch)
		return nil
	}
	// F5 (§5.4#2): out-of-order future-seq (r.Seq > head.Seq+1) STAGES (verified, never spliced
	// unverified), drained contiguously when the gap fills — NOT a SEQ_GAP failure.
	if ch.staged == nil {
		ch.staged = map[uint64]*EventRecord{}
	}
	if existing, ok := ch.staged[r.Seq]; ok && existing.ID == r.ID {
		return nil // already staged (idempotent)
	}
	if len(ch.staged) >= ImportBufferCap {
		return newErr(IMPORT_BUFFER_FULL, fmt.Sprintf("staging buffer full (cap %d)", ImportBufferCap))
	}
	ch.staged[r.Seq] = r
	return nil
}

// drainStaged splices contiguous staged records onto the head as long as the next seq is held
// and prev-links cleanly (§5.4#2). A staged record whose prev_id does not link is dropped from
// staging (it will be re-driven via GetEventsSince — a follow-up); never spliced unverified.
func (l *Ledger) drainStaged(ch *chain) {
	for len(ch.staged) > 0 {
		head := ch.events[len(ch.events)-1]
		next, ok := ch.staged[head.Seq+1]
		if !ok {
			return
		}
		delete(ch.staged, head.Seq+1)
		if next.PrevID != head.ID {
			continue // broken link: drop from staging (re-drive follow-up), do not splice
		}
		ch.events = append(ch.events, next)
	}
}

// quarantine persists BOTH equivocating records + a fork_detected anchor, sets sticky
// QUARANTINED, and returns the *EquivocationProof (evidence-spec §5.1 T4 / §5.4#3). Gossip of
// the equivocation-proof is a documented follow-up.
func (l *Ledger) quarantine(ch *chain, existing, incoming *EventRecord) error {
	proof := &EquivocationProof{ChainDID: incoming.ChainDID, Seq: incoming.Seq, NodeA: existing, NodeB: incoming}
	// persist-both: keep the existing node AND the competing node (off the linear head) so the
	// proof's two records survive on the quarantined chain.
	ch.events = append(ch.events, incoming)
	// append a converge.fork_detected anchor carrying both ids + the proof (P4.2 ForkRecord).
	fork := &EventRecord{
		ChainDID:     incoming.ChainDID,
		Seq:          existing.Seq, // anchored at the forked seq (the chain is sticky-quarantined)
		EventType:    EvForkDetected,
		VersionMajor: VersionMajor2,
		Payload: map[uint64]any{
			1: existing.ChainDID,
			2: existing.Seq,
			3: existing.ID,
			4: incoming.ID,
		},
		Timestamp: incoming.Timestamp,
	}
	ch.events = append(ch.events, fork)
	ch.state = ChainQuarantined
	return proof
}

// ImportResult summarizes a per-event Import disposition (evidence-spec §5.4 / F7).
type ImportResult struct {
	Applied int // contiguous records spliced onto the head
	Staged  int // out-of-order verified records held in the staging buffer
	Dups    int // benign re-deliveries (idempotent no-ops)
}

// Import applies a batch of seq-ascending records through the same discipline (evidence-spec
// §5.4). Per F7 it processes seq-ascending with per-event disposition — an idempotent no-op for
// a duplicate, staging for a gap — and returns on a hard fault (the first typed *Error), or on
// equivocation (the surfaced *EquivocationProof). On full success it returns an *ImportResult
// summary via the second return value.
func (l *Ledger) Import(recs []*EventRecord, kel []identity.SignedEvent) error {
	_, err := l.ImportBatch(recs, kel)
	return err
}

// ImportBatch is Import with the per-event disposition summary (F7).
func (l *Ledger) ImportBatch(recs []*EventRecord, kel []identity.SignedEvent) (*ImportResult, error) {
	res := &ImportResult{}
	for _, r := range recs {
		before := l.appliedAndStaged(r.ChainDID)
		err := l.Append(r, kel)
		if err != nil {
			// equivocation + any hard fault stop the batch (equivocation surfaced as the proof).
			return res, err
		}
		after := l.appliedAndStaged(r.ChainDID)
		switch {
		case after.staged > before.staged:
			res.Staged++
		case after.applied > before.applied:
			res.Applied += after.applied - before.applied // a drain can splice >1
		default:
			res.Dups++ // idempotent no-op (dup re-delivery)
		}
	}
	return res, nil
}

type appliedStaged struct{ applied, staged int }

func (l *Ledger) appliedAndStaged(did string) appliedStaged {
	ch := l.chains[did]
	if ch == nil {
		return appliedStaged{}
	}
	return appliedStaged{applied: len(ch.events), staged: len(ch.staged)}
}

// Head returns the chain head id and seq, or ("",0,false) if unknown. The head is the highest
// contiguously-applied record; staged (gap-blocked) records do not advance the head.
func (l *Ledger) Head(did string) (string, uint64, bool) {
	ch := l.chains[did]
	if ch == nil || len(ch.events) == 0 {
		return "", 0, false
	}
	h := ch.events[len(ch.events)-1]
	if ch.state == ChainQuarantined {
		// a quarantined chain's "head" is the last linear record before the fork anchor; report
		// the forked seq's existing node so Head stays meaningful for callers.
		for i := len(ch.events) - 1; i >= 0; i-- {
			if ch.events[i].EventType != EvForkDetected {
				h = ch.events[i]
				break
			}
		}
	}
	return h.ID, h.Seq, true
}

// State returns the chain state (ACTIVE/QUARANTINED) or "" if unknown.
func (l *Ledger) State(did string) string {
	if ch := l.chains[did]; ch != nil {
		return ch.state
	}
	return ""
}

// Events returns the stored records for a chain (including, on a quarantined chain, both
// equivocating nodes and the appended converge.fork_detected anchor) — read-only.
func (l *Ledger) Events(did string) []*EventRecord {
	ch := l.chains[did]
	if ch == nil {
		return nil
	}
	out := make([]*EventRecord, len(ch.events))
	copy(out, ch.events)
	return out
}
