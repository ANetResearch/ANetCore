// Package identity implements the identity and key plane: AID + KEL (key event log) + key state
// resolution, with KERI-style pre-rotation.
//
// KEL v2 (v0.3.0; core §2.6, KEL §2.1–§2.2):
//   - An AID is the CID of the inception event's preimage; the current key evolves through a
//     signed, append-only KEL whose events are only icp, rot and dip. The AID is stable across
//     rotation.
//   - A verifier resolves an AID to a key by REPLAYING the KEL (Replay), which yields a KeyState
//     per event.
//   - Pre-rotation, as KERI has it: every establishment event (icp, rot) commits to the SHA-256 of
//     the next public key, and the rot or dip that follows must reveal exactly that key and be
//     signed by it. The key being replaced takes no part, so whoever stole it can neither rotate
//     nor deactivate the AID; only the holder of the committed next key can.
//   - Every event carries key 0 = "anet.kel/2" and a timestamp ts > 0 that strictly increases
//     along the KEL. A rot or dip retires the key state before it at its ts (SupersededAt); a rot
//     carrying key 12 (emergency), or a dip, retires it urgently (RetiredUrgently).
//   - The witness mode toad is fixed by the icp (0 for a hub, 1 for an agent) and repeated by
//     every rot; an agent's first rot names its witness hub, and no later rot may drop it.
//
// The v0.2 event types ixn and drt, delegated keys and KEL v1 are gone: a KEL without key 0 does
// not replay, and there is no v1 decoding path.
package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
)

// KELType is key 0 of every KEL v2 event: the version marker and the domain separation of the
// event signature (core V8, L17).
const KELType = "anet.kel/2"

// EventType is a KEL event type (key 4).
type EventType string

// The three event types of KEL v2. Any other value of key 4 makes the KEL unreplayable.
const (
	Inception    EventType = "icp"
	Rotation     EventType = "rot"
	Deactivation EventType = "dip"
)

// Witness modes (key 11, toad). A hub identity has no witness; an agent identity has exactly one,
// the hub it registered with, named by its first rot.
const (
	ToadHub   uint64 = 0
	ToadAgent uint64 = 1
)

// Time rules, in unix milliseconds. Neither is configurable.
const (
	// RotationGrace is how long after a planned rotation a message signed by the retired key state
	// may still arrive (C-12). An emergency rotation or a deactivation has no grace.
	RotationGrace uint64 = 60 * 60 * 1000

	// EventClockWindow bounds a new event's ts against the clock of whoever accepts it (R-9, R-10).
	// It equals seal.ClockSkewMS.
	EventClockWindow uint64 = 5 * 60 * 1000
)

// Status values of a KeyState.
//   - StatusActive: the KEL head, not deactivated.
//   - StatusRotated: replaced by a later rot or dip; usable only for objects bound before
//     SupersededAt.
//   - StatusDeactivated: the dip itself, the AID's terminal state.
const (
	StatusActive      = "active"
	StatusRotated     = "rotated"
	StatusDeactivated = "deactivated"
)

// Errors whose text the KEL-2N vectors fix (R-0).
var (
	// ErrKELv1 is any event whose key 0 is missing or is not KELType, which is what a v0.2 KEL
	// looks like.
	ErrKELv1 = errors.New("identity: KEL v1 (v0.2) is not accepted")
	// ErrNonCanonicalEvent is an event whose bytes are not coredet of what they decode to: the
	// same event may only ever have one encoding (CORE-E2).
	ErrNonCanonicalEvent = errors.New("identity: non-canonical event")
)

var (
	errUnregisteredEventKey  = errors.New("identity: event carries an unregistered key")
	errUnregisteredSignedKey = errors.New("identity: signed event carries an unregistered key")
)

// KeyEvent is one KEL entry. coredet(KeyEvent) is the signature preimage (L17), and of the icp
// also the preimage whose CID is the AID; the signature travels beside it in SignedEvent.
//
// Each field encodes to the single form the replay rules allow: omitempty drops a key that must
// be absent, and a key that must be written even when zero (seq, kt, ts, toad) has no omitempty
// or is a pointer. Decoding refuses any other form (UnmarshalCBOR).
//
//anet:wire KeyEvent
type KeyEvent struct {
	KELType    string    `cbor:"0,keyasint"`           // always KELType
	AID        string    `cbor:"1,keyasint,omitempty"` // absent in the icp
	Seq        uint64    `cbor:"2,keyasint"`
	Prev       string    `cbor:"3,keyasint,omitempty"` // previous event id; absent in the icp
	Type       EventType `cbor:"4,keyasint"`
	Keys       [][]byte  `cbor:"5,keyasint"`           // one Ed25519 key: k0 for icp, the revealed key for rot and dip
	NextDigest []byte    `cbor:"6,keyasint,omitempty"` // SHA-256 of the next public key; icp and rot only
	Threshold  uint32    `cbor:"7,keyasint"`           // kt, always 1
	Timestamp  uint64    `cbor:"8,keyasint"`           // ts, unix ms, > 0 and increasing
	Witnesses  []string  `cbor:"9,keyasint,omitempty"` // the witness hub AID; only a toad-1 rot carries it
	Toad       *uint64   `cbor:"11,keyasint,omitempty"`
	Emergency  bool      `cbor:"12,keyasint,omitempty"` // rot only; written only as true
}

// ToadField returns the value of KeyEvent.Toad for toad v. Key 11 is written even when it is 0,
// so the field is a pointer: nil leaves the key out, as a dip must.
func ToadField(v uint64) *uint64 { return &v }

// keyEventFields is KeyEvent without its methods, for decoding inside UnmarshalCBOR.
type keyEventFields KeyEvent

// UnmarshalCBOR decodes one KEL event (R-0): strictly, so that a key the event does not define
// (10, 13–63, 64 and up) is refused; key 0 must be KELType; and the bytes must be exactly the
// coredet encoding of what they decode to, so that one event has one byte form whatever path it
// arrived by. Every decoder of a KeyEvent goes through it.
func (e *KeyEvent) UnmarshalCBOR(b []byte) error {
	var f keyEventFields
	if err := coredet.UnmarshalStrict(b, &f); err != nil {
		var unknown *cbor.UnknownFieldError
		if errors.As(err, &unknown) {
			return errUnregisteredEventKey
		}
		return fmt.Errorf("identity: event does not decode: %w", err)
	}
	if f.KELType != KELType {
		return ErrKELv1
	}
	back, err := coredet.Marshal(KeyEvent(f))
	if err != nil || !bytes.Equal(back, b) {
		return ErrNonCanonicalEvent
	}
	*e = KeyEvent(f)
	return nil
}

// SignedEvent is a KEL entry with its signature and event id.
//
//anet:wire SignedEvent
type SignedEvent struct {
	Event   KeyEvent `cbor:"1,keyasint"`
	Sig     []byte   `cbor:"2,keyasint"` // Ed25519 over coredet(Event), 64 bytes
	EventID string   `cbor:"3,keyasint"` // CID of coredet(Event); for the icp, the AID
}

// MarshalKEL serializes a KEL (the ordered slice of signed events) to coredet bytes, the form a
// KEL is stored and carried in.
func MarshalKEL(kel []SignedEvent) ([]byte, error) { return coredet.Marshal(kel) }

// UnmarshalKEL is the inverse of MarshalKEL. It decodes strictly (R-0): a signed event or an
// event carrying a key KEL v2 does not define is refused, as are an event without key 0 or with
// another type tag (ErrKELv1) and an event whose bytes are not its canonical encoding
// (ErrNonCanonicalEvent). It does not replay: callers pass the result to Replay or ExtendsKEL.
func UnmarshalKEL(b []byte) ([]SignedEvent, error) {
	var kel []SignedEvent
	if err := coredet.UnmarshalStrict(b, &kel); err != nil {
		switch {
		case errors.Is(err, ErrKELv1), errors.Is(err, ErrNonCanonicalEvent),
			errors.Is(err, errUnregisteredEventKey):
			return nil, err
		}
		var unknown *cbor.UnknownFieldError
		if errors.As(err, &unknown) {
			return nil, errUnregisteredSignedKey
		}
		return nil, fmt.Errorf("identity: KEL does not decode: %w", err)
	}
	return kel, nil
}

// KeyState is what a verifier derives for one event of a KEL (KEL §2.2).
type KeyState struct {
	AID string
	// CurrentKeys is the signing key of this state: the key the event introduced (icp, rot). It
	// is empty for the dip's own state.
	CurrentKeys [][]byte
	KeyStateSeq uint64
	Status      string
	LastEventID string
	// Toad and Witness come from the latest establishment event (icp or rot) up to this one.
	// Witness is empty when there is none: always for toad 0, and for an agent's icp until its
	// first rot names one ("witness pending", R-4).
	Toad    uint64
	Witness string
	// SupersededAt is the ts of the event that replaced this state; 0 when nothing has.
	SupersededAt uint64
	// RetiredUrgently is true when that event is an emergency rot (key 12) or a dip.
	RetiredUrgently bool
}

func nextDigest(pub ed25519.PublicKey) []byte {
	h := sha256.Sum256(pub)
	return h[:]
}

// preimage returns coredet(e), what the event's signature and id cover.
func preimage(e KeyEvent) ([]byte, error) { return coredet.Marshal(e) }

// Replay validates a KEL against the KEL v2 rules (R-0 to R-6) and returns the KeyState after each
// event: index i is the state at seq i. Replay checks the events as given; the encoding rules on
// bytes (strict keys, canonical form) are UnmarshalKEL's.
//
// When the process has installed a ReplayCache (SetReplayCache), a KEL replayed before is
// answered from it.
func Replay(kel []SignedEvent) ([]KeyState, error) {
	if c := installedReplayCache.Load(); c != nil {
		return c.replay(kel)
	}
	return replay(kel)
}

// replay is Replay without the cache.
func replay(kel []SignedEvent) ([]KeyState, error) {
	if len(kel) == 0 {
		return nil, errors.New("identity: empty KEL")
	}
	states := make([]KeyState, 0, len(kel))
	var prior KeyState
	// committed is key 6 of the last establishment event: the digest the next rot or dip must
	// reveal a key for.
	var committed []byte
	var lastTS uint64
	for i, se := range kel {
		e := se.Event
		if e.KELType != KELType {
			return nil, ErrKELv1
		}
		var next KeyState
		if i == 0 {
			if err := checkInception(e); err != nil {
				return nil, err
			}
		} else {
			if e.AID != prior.AID {
				return nil, errors.New("identity: event AID mismatch")
			}
			if e.Seq != prior.KeyStateSeq+1 {
				return nil, fmt.Errorf("identity: non-monotonic seq %d after %d", e.Seq, prior.KeyStateSeq)
			}
			if e.Prev != prior.LastEventID {
				return nil, errors.New("identity: broken prev linkage")
			}
			if prior.Status == StatusDeactivated {
				return nil, errors.New("identity: event after deactivation")
			}
			if e.Type != Rotation && e.Type != Deactivation {
				return nil, fmt.Errorf("identity: unsupported event type %q", e.Type)
			}
			if err := checkShape(e); err != nil {
				return nil, err
			}
			if e.Timestamp <= lastTS {
				return nil, errors.New("identity: event ts must be greater than the previous event's")
			}
			var err error
			if e.Type == Rotation {
				err = checkRotation(e, prior)
			} else {
				err = checkDeactivation(e)
			}
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(nextDigest(e.Keys[0]), committed) {
				return nil, fmt.Errorf("identity: %s key does not match pre-committed digest", e.Type)
			}
		}
		pre, err := preimage(e)
		if err != nil {
			return nil, err
		}
		id, err := anetcid.Sum(pre)
		if err != nil {
			return nil, err
		}
		if se.EventID != id {
			return nil, errors.New("identity: event_id is not the CID of the event")
		}
		if len(se.Sig) != ed25519.SignatureSize {
			return nil, errors.New("identity: event signature is not 64 bytes")
		}
		// icp is self-signed by k0; rot and dip by the key they reveal (R-3, R-5). The key being
		// replaced never signs: holding it is not enough to change the AID's keys.
		signer := e.Keys[0]
		if !ed25519.Verify(signer, pre, se.Sig) {
			switch e.Type {
			case Inception:
				return nil, errors.New("identity: icp not self-signed by its key")
			default:
				return nil, fmt.Errorf("identity: %s not signed by the key it reveals", e.Type)
			}
		}
		switch e.Type {
		case Inception:
			next = KeyState{AID: id, CurrentKeys: e.Keys, KeyStateSeq: 0, Status: StatusActive,
				LastEventID: id, Toad: *e.Toad}
			committed = e.NextDigest
		case Rotation:
			next = KeyState{AID: prior.AID, CurrentKeys: e.Keys, KeyStateSeq: e.Seq, Status: StatusActive,
				LastEventID: id, Toad: prior.Toad}
			if len(e.Witnesses) == 1 {
				next.Witness = e.Witnesses[0]
			}
			committed = e.NextDigest
		case Deactivation:
			next = KeyState{AID: prior.AID, KeyStateSeq: e.Seq, Status: StatusDeactivated,
				LastEventID: id, Toad: prior.Toad, Witness: prior.Witness}
			committed = nil
		}
		lastTS = e.Timestamp
		prior = next
		states = append(states, next)
	}
	markSuperseded(kel, states)
	return states, nil
}

// checkShape is R-6 and the ts lower bound: kt is 1, there is exactly one 32-byte key (checked
// before any signature, as ed25519.Verify panics on a key of another length), and ts > 0.
func checkShape(e KeyEvent) error {
	if e.Threshold != 1 {
		return errors.New("identity: kt must be 1")
	}
	if len(e.Keys) != 1 || len(e.Keys[0]) != ed25519.PublicKeySize {
		return fmt.Errorf("identity: %s needs exactly one 32-byte Ed25519 key", e.Type)
	}
	if e.Timestamp == 0 {
		return errors.New("identity: event ts must be greater than 0")
	}
	return nil
}

// checkInception is R-1 apart from the signature.
func checkInception(e KeyEvent) error {
	if e.Type != Inception {
		return errors.New("identity: first event must be icp")
	}
	if e.Seq != 0 {
		return errors.New("identity: icp seq must be 0")
	}
	if e.AID != "" || e.Prev != "" {
		return errors.New("identity: icp must not carry aid or prev")
	}
	if err := checkShape(e); err != nil {
		return err
	}
	if len(e.NextDigest) != sha256.Size {
		return errors.New("identity: icp needs a 32-byte next-key digest")
	}
	if e.Toad == nil {
		return errors.New("identity: icp must carry toad")
	}
	if *e.Toad != ToadHub && *e.Toad != ToadAgent {
		return errors.New("identity: toad must be 0 or 1")
	}
	if len(e.Witnesses) != 0 {
		return errors.New("identity: icp must not carry witnesses")
	}
	if e.Emergency {
		return errors.New("identity: icp must not carry emergency")
	}
	return nil
}

// checkRotation is R-3 apart from the digest and the signature.
func checkRotation(e KeyEvent, prior KeyState) error {
	if len(e.NextDigest) != sha256.Size {
		return errors.New("identity: rot needs a 32-byte next-key digest")
	}
	if e.Toad == nil {
		return errors.New("identity: rot must carry toad")
	}
	if *e.Toad != prior.Toad {
		return errors.New("identity: rot changes toad")
	}
	if prior.Toad == ToadHub {
		if len(e.Witnesses) != 0 {
			return errors.New("identity: rot of a toad-0 identity must not carry witnesses")
		}
		return nil
	}
	switch {
	case len(e.Witnesses) == 0:
		return errors.New("identity: rot of a toad-1 identity must name its witness")
	case len(e.Witnesses) > 1:
		return errors.New("identity: rot must name exactly one witness")
	case e.Witnesses[0] == "":
		return errors.New("identity: rot witness is empty")
	case e.Witnesses[0] == prior.AID:
		return errors.New("identity: rot names its own AID as witness")
	}
	return nil
}

// checkDeactivation is R-5 apart from the digest and the signature.
func checkDeactivation(e KeyEvent) error {
	switch {
	case e.NextDigest != nil:
		return errors.New("identity: dip must not carry next")
	case e.Witnesses != nil:
		return errors.New("identity: dip must not carry witnesses")
	case e.Toad != nil:
		return errors.New("identity: dip must not carry toad")
	case e.Emergency:
		return errors.New("identity: dip must not carry emergency")
	}
	return nil
}

// markSuperseded is Replay's post-pass (C-2). In KEL v2 every event after the icp is a rot or a
// dip, so state i is replaced by event i+1: it takes that event's ts as SupersededAt, and is
// retired urgently when that event is an emergency rot or a dip. The dip's own state stays
// StatusDeactivated with SupersededAt 0.
func markSuperseded(kel []SignedEvent, states []KeyState) {
	for i := 0; i+1 < len(states); i++ {
		e := kel[i+1].Event
		if states[i].Status == StatusActive {
			states[i].Status = StatusRotated
		}
		states[i].SupersededAt = e.Timestamp
		states[i].RetiredUrgently = e.Type == Deactivation || e.Emergency
	}
}

// committedNextDigest returns key 6 of the last establishment event (icp or rot) in kel: the
// digest the next rot or dip must reveal a key for.
func committedNextDigest(kel []SignedEvent) []byte {
	for i := len(kel) - 1; i >= 0; i-- {
		if t := kel[i].Event.Type; t == Inception || t == Rotation {
			return kel[i].Event.NextDigest
		}
	}
	return nil
}

// VerifyObject verifies a signed object against a KEL (C-10). It replays the KEL, selects the key
// state the object declares, and decides in this order:
//
//  1. the KEL does not replay, or replays to another AID: UNKNOWN_AID;
//  2. the declared seq is beyond the KEL: KEY_STATE_DOWNGRADE;
//  3. the state is the dip's (deactivated): REVOKED_KEY;
//  4. the signature does not verify under that state's key: INVALID_SIGNATURE;
//  5. the state is active: accepted;
//  6. the state was replaced by a later rot or dip: REVOKED_KEY when msgTime is 0 (the object's
//     time is unknown, so it cannot be shown to predate the retirement) or msgTime ≥
//     SupersededAt; otherwise accepted.
//
// msgTime is the object's own time in unix ms. Whether a retired state is still usable at the
// time the object arrived is a separate question (RetiredUsableAt).
func VerifyObject(kel []SignedEvent, signerAID string, keyStateSeq, msgTime uint64, objPreimage, sig []byte) error {
	states, err := Replay(kel)
	if err != nil {
		return &VErr{"UNKNOWN_AID", err.Error()}
	}
	final := states[len(states)-1]
	if final.AID != signerAID {
		return &VErr{"UNKNOWN_AID", "KEL AID does not match signer_aid"}
	}
	if keyStateSeq >= uint64(len(states)) {
		return &VErr{"KEY_STATE_DOWNGRADE", "declared key_state_seq beyond KEL"}
	}
	ks := states[keyStateSeq]
	if ks.Status == StatusDeactivated {
		return &VErr{"REVOKED_KEY", "AID deactivated at this key_state_seq"}
	}
	if len(ks.CurrentKeys) != 1 || len(ks.CurrentKeys[0]) != ed25519.PublicKeySize {
		return &VErr{"UNKNOWN_AID", "no current key at declared key_state_seq"}
	}
	if !ed25519.Verify(ks.CurrentKeys[0], objPreimage, sig) {
		return &VErr{"INVALID_SIGNATURE", "signature does not verify under key at key_state_seq"}
	}
	if ks.Status == StatusActive {
		return nil
	}
	if msgTime == 0 {
		return &VErr{"REVOKED_KEY", "key_state_seq retired by a later event, and the object carries no time"}
	}
	if msgTime >= ks.SupersededAt {
		return &VErr{"REVOKED_KEY", "key_state_seq retired by a later event at or before the object's time"}
	}
	return nil
}

// RetiredUsableAt reports whether something signed under key state ks may still be accepted when
// it arrived at arrival (unix ms; the accepting hub's time, not the signer's) (C-12). An active
// state always is. A retired state is until RotationGrace after it was replaced, or not at all
// after an emergency rot or a dip (grace 0, so arrival == SupersededAt is still in). The dip's own
// state never is: it has no key.
func RetiredUsableAt(ks KeyState, arrival uint64) bool {
	switch ks.Status {
	case StatusActive:
		return true
	case StatusDeactivated:
		return false
	}
	grace := RotationGrace
	if ks.RetiredUrgently {
		grace = 0
	}
	return arrival <= ks.SupersededAt || arrival-ks.SupersededAt <= grace
}

// VErr is a typed verification error.
type VErr struct {
	Reason string
	Detail string
}

func (e *VErr) Error() string { return e.Reason + ": " + e.Detail }

// ---- Controller --------------------------------------------------------------------------------

// controllerExport is the v0.2 on-disk form of a Controller: the current and the pre-committed next
// private-key seeds and the KEL. It contains PRIVATE KEYS: store 0600, never publish.
// v030-todo(KEL-2): IdentityFile v2 (Export/Restore of anet.identity/2) replaces it.
type controllerExport struct {
	CurSeed []byte        `cbor:"1,keyasint"`
	NxtSeed []byte        `cbor:"2,keyasint"`
	KEL     []SignedEvent `cbor:"3,keyasint"`
}

// Export serializes the Controller (private-key seeds + KEL) to coredet bytes for durable storage.
// The bytes contain PRIVATE KEYS.
func (c *Controller) Export() ([]byte, error) {
	return coredet.Marshal(controllerExport{CurSeed: c.cur.Seed(), NxtSeed: c.nxt.Seed(), KEL: c.kel})
}

// Restore reconstructs a Controller from Export bytes: it replays the KEL, takes the AID from it,
// and checks that the stored current key is the KEL head's key and that the stored next key is the
// one the last establishment event committed to, so a corrupt or torn file is refused rather than
// yielding a controller that mis-signs or cannot rotate.
func Restore(b []byte) (*Controller, error) {
	var e controllerExport
	if err := coredet.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	if len(e.CurSeed) != ed25519.SeedSize || len(e.NxtSeed) != ed25519.SeedSize {
		return nil, errors.New("identity: bad private-key seed length")
	}
	if len(e.KEL) == 0 {
		return nil, errors.New("identity: empty KEL")
	}
	states, err := Replay(e.KEL)
	if err != nil {
		return nil, fmt.Errorf("identity: restore replay: %w", err)
	}
	last := states[len(states)-1]
	// A deactivated AID must not be reconstituted as a signer.
	if last.Status != StatusActive {
		return nil, fmt.Errorf("identity: cannot restore a non-active identity (status %q)", last.Status)
	}
	cur := ed25519.NewKeyFromSeed(e.CurSeed)
	if !bytes.Equal(last.CurrentKeys[0], cur.Public().(ed25519.PublicKey)) {
		return nil, errors.New("identity: current key does not match the KEL head (corrupt store)")
	}
	nxt := ed25519.NewKeyFromSeed(e.NxtSeed)
	if !bytes.Equal(nextDigest(nxt.Public().(ed25519.PublicKey)), committedNextDigest(e.KEL)) {
		return nil, errors.New("identity: next key does not match the KEL's pre-rotation commitment (corrupt store)")
	}
	return &Controller{aid: last.AID, cur: cur, nxt: nxt, kel: e.KEL}, nil
}

// Controller holds the private key material and the KEL it has produced. It is the signing side;
// verifiers use only the public KEL via Replay.
//
// v030-todo(KEL-2): the locked Controller with Snapshot, the Build* transitions and IdentityFile v2
// (KEL C-20–C-25) replace this one, which still keeps the next key beside the current one.
type Controller struct {
	aid string
	cur ed25519.PrivateKey
	nxt ed25519.PrivateKey
	kel []SignedEvent
}

// inceptPlaceholderTS is the icp ts of Incept, which has no clock: the smallest ts KEL v2 allows,
// so that every later ts a caller passes to Rotate or Deactivate is after it.
// v030-todo(KEL-2): InceptAgent(ts) and InceptHub(ts) take the time (C-5).
const inceptPlaceholderTS = 1

// Incept creates a new hub-mode (toad 0) identity: generates the current key K0 and the
// pre-committed next key K1, builds the icp event (AID = CID of its preimage) and self-signs it
// with K0.
// v030-todo(KEL-2): replaced by InceptAgent and InceptHub (C-5).
func Incept() (*Controller, error) {
	_, k0, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	_, k1, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return inceptWith(k0, k1, inceptPlaceholderTS, ToadHub)
}

// inceptWith builds the controller whose icp commits k1 under k0.
func inceptWith(k0, k1 ed25519.PrivateKey, ts, toad uint64) (*Controller, error) {
	icp := KeyEvent{
		KELType:    KELType,
		Seq:        0,
		Type:       Inception,
		Keys:       [][]byte{k0.Public().(ed25519.PublicKey)},
		NextDigest: nextDigest(k1.Public().(ed25519.PublicKey)),
		Threshold:  1,
		Timestamp:  ts,
		Toad:       ToadField(toad),
	}
	pre, err := preimage(icp) // the AID-deriving preimage has no AID field
	if err != nil {
		return nil, err
	}
	aid, err := anetcid.Sum(pre)
	if err != nil {
		return nil, err
	}
	c := &Controller{aid: aid, cur: k0, nxt: k1}
	c.kel = append(c.kel, SignedEvent{Event: icp, Sig: ed25519.Sign(k0, pre), EventID: aid})
	return c, nil
}

// AID returns the stable identifier (CID of the inception event).
func (c *Controller) AID() string { return c.aid }

// DID returns the did:anet form of the AID.
func (c *Controller) DID() string { return "did:anet:" + c.aid }

// KEL returns the public key event log (safe to publish).
func (c *Controller) KEL() []SignedEvent { return c.kel }

// CurrentSeq is the key_state_seq the controller signs objects under.
func (c *Controller) CurrentSeq() uint64 { return c.kel[len(c.kel)-1].Event.Seq }

// CurrentPrivateKey returns the controller's current signing private key.
// v030-todo(KEL-2): deleted by C-23 (a2acard.SignWithSnapshot replaces its one caller).
func (c *Controller) CurrentPrivateKey() ed25519.PrivateKey { return c.cur }

// Sign signs an object preimage with the current key, returning the signature and the
// key_state_seq a verifier must select.
func (c *Controller) Sign(objPreimage []byte) (sig []byte, keyStateSeq uint64) {
	return ed25519.Sign(c.cur, objPreimage), c.CurrentSeq()
}

// appendEvent fills in the fields every later event shares, signs e with k and appends it.
func (c *Controller) appendEvent(e KeyEvent, k ed25519.PrivateKey) error {
	last := c.kel[len(c.kel)-1]
	if last.Event.Type == Deactivation {
		return errors.New("identity: the AID is deactivated")
	}
	if e.Timestamp <= last.Event.Timestamp {
		return fmt.Errorf("identity: %s ts %d must be after the previous event's %d", e.Type, e.Timestamp, last.Event.Timestamp)
	}
	e.KELType = KELType
	e.AID = c.aid
	e.Seq = last.Event.Seq + 1
	e.Prev = last.EventID
	e.Threshold = 1
	pre, err := preimage(e)
	if err != nil {
		return err
	}
	id, err := anetcid.Sum(pre)
	if err != nil {
		return err
	}
	c.kel = append(c.kel, SignedEvent{Event: e, Sig: ed25519.Sign(k, pre), EventID: id})
	return nil
}

// toad is the witness mode the icp fixed.
func (c *Controller) toad() uint64 {
	if t := c.kel[0].Event.Toad; t != nil {
		return *t
	}
	return ToadHub
}

// Rotate advances a hub-mode (toad 0) KEL by a planned rotation at ts (unix ms, after the previous
// event's): the pre-committed next key K(n) is revealed and becomes current, a fresh K(n+1) is
// committed, and the rot is signed by K(n), the key it reveals.
// v030-todo(KEL-2): BuildRotation (C-21) replaces it, with the witness and the emergency flag.
func (c *Controller) Rotate(ts uint64) error {
	if c.toad() != ToadHub {
		return errors.New("identity: Rotate builds toad-0 rotations only; an agent's rot names its witness")
	}
	_, newNxt, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	rot := KeyEvent{
		Type:       Rotation,
		Keys:       [][]byte{c.nxt.Public().(ed25519.PublicKey)},
		NextDigest: nextDigest(newNxt.Public().(ed25519.PublicKey)),
		Timestamp:  ts,
		Toad:       ToadField(ToadHub),
	}
	if err := c.appendEvent(rot, c.nxt); err != nil {
		return err
	}
	c.cur, c.nxt = c.nxt, newNxt
	return nil
}

// Deactivate appends a dip at ts (unix ms, after the previous event's), terminating the AID. The
// dip reveals the pre-committed next key and is signed by it, so only the holder of the recovery
// material can deactivate.
// v030-todo(KEL-2): BuildDeactivation (C-21) replaces it.
func (c *Controller) Deactivate(ts uint64) error {
	dip := KeyEvent{
		Type:      Deactivation,
		Keys:      [][]byte{c.nxt.Public().(ed25519.PublicKey)},
		Timestamp: ts,
	}
	return c.appendEvent(dip, c.nxt)
}
