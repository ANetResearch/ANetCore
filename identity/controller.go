package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
)

// Errors of the Controller's state transitions.
var (
	// ErrRecoveryMismatch is a revealed key that is not the key the KEL head committed (KEL C-21):
	// a recovery seed of another identity, or a wrong derivation.
	ErrRecoveryMismatch = errors.New("identity: the revealed key is not the key the KEL committed")
	// ErrEventPending is a new event asked for while another one is being published: the pending
	// event is published (Adopt) or rebuilt (Restamp), never replaced (KEL D-14).
	ErrEventPending = errors.New("identity: another key event is still being published")
	// ErrNothingPending is Adopt or Restamp without a pending event.
	ErrNothingPending = errors.New("identity: no key event is being published")
)

// Controller holds an identity's private keys and its KEL (KEL C-20–C-25). It is the signing side;
// verifiers use only the public KEL, through Replay.
//
// It keeps no next key beyond the hot key an icp commits (C-31): every later next key comes from
// the identity's recovery seed, outside the data directory, and is handed to BuildRotation or
// BuildDeactivation when it is revealed. The state transitions build events in memory and do no
// I/O; the owner persists Export after each one.
//
// A Controller is safe for concurrent use. AID, KEL, CurrentSeq, Sign, Snapshot, Export and the
// other readers take its read lock; the transitions take its write lock (C-20).
type Controller struct {
	mu sync.RWMutex

	aid         string
	kel         []SignedEvent      // the events the witness accepted
	cur         ed25519.PrivateKey // key of the accepted head; nil while a recover waits to publish
	hot         ed25519.PrivateKey // the key the icp committed, while the KEL is the icp alone
	pending     *pending           // the event being published, or nil
	push        []WitnessPush
	state       string
	localCommit []byte
}

// pending is IdentityFile key 4 in memory.
type pending struct {
	kind      string
	revealed  ed25519.PrivateKey
	next      []byte
	hubURL    string
	emergency bool
	since     uint64
	event     *SignedEvent // nil until built
}

// InceptAgent creates an agent identity (toad 1, KEL C-5): a fresh key k0 signs an icp at ts
// (unix ms, > 0) that commits a fresh hot key k1 and names no witness yet. The agent's first rot
// reveals k1 and names its witness hub (BuildWitnessDesignation).
func InceptAgent(ts uint64) (*Controller, error) { return incept(ts, ToadAgent) }

// InceptHub creates a hub identity (toad 0, KEL C-5, H-30): as InceptAgent, but with no witness,
// ever. The hub's first rot (setup-recovery, C-32) reveals k1.
func InceptHub(ts uint64) (*Controller, error) { return incept(ts, ToadHub) }

func incept(ts, toad uint64) (*Controller, error) {
	if ts == 0 {
		return nil, errors.New("identity: an icp needs a time (ts > 0)")
	}
	_, k0, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	_, k1, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return inceptWith(k0, k1, ts, toad)
}

// inceptWith builds the controller whose icp at ts commits k1 under k0.
func inceptWith(k0, k1 ed25519.PrivateKey, ts, toad uint64) (*Controller, error) {
	icp := KeyEvent{
		KELType:    KELType,
		Seq:        0,
		Type:       Inception,
		Keys:       [][]byte{publicOf(k0)},
		NextDigest: nextDigest(publicOf(k1)),
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
	kel := []SignedEvent{{Event: icp, Sig: ed25519.Sign(k0, pre), EventID: aid}}
	if _, err := replay(kel); err != nil {
		return nil, err
	}
	return &Controller{aid: aid, kel: kel, cur: k0, hot: k1, state: StateOK}, nil
}

// ---- readers -------------------------------------------------------------------------------------

// AID returns the stable identifier (CID of the inception event).
func (c *Controller) AID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.aid
}

// DID returns the did:anet form of the AID.
func (c *Controller) DID() string { return "did:anet:" + c.AID() }

// KEL returns the public key event log the controller signs under: the events the witness
// accepted and, once built, the event being published (C-21). The slice is a copy.
func (c *Controller) KEL() []SignedEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.kelLocked()
}

func (c *Controller) kelLocked() []SignedEvent {
	n := len(c.kel)
	if c.pending != nil && c.pending.event != nil {
		n++
	}
	out := make([]SignedEvent, len(c.kel), n)
	copy(out, c.kel)
	if c.pending != nil && c.pending.event != nil {
		out = append(out, *c.pending.event)
	}
	return out
}

// Accepted returns the events the witness accepted, without the event being published (KEL D-27
// compares it with the witness's record). The slice is a copy.
func (c *Controller) Accepted() []SignedEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]SignedEvent(nil), c.kel...)
}

// signingLocked is the key and key_state_seq the controller signs with: the key the pending event
// reveals once it is built, the accepted head's key otherwise.
func (c *Controller) signingLocked() (ed25519.PrivateKey, uint64) {
	if p := c.pending; p != nil && p.event != nil {
		return p.revealed, p.event.Event.Seq
	}
	return c.cur, c.kel[len(c.kel)-1].Event.Seq
}

// CurrentSeq is the key_state_seq the controller signs objects under.
func (c *Controller) CurrentSeq() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, seq := c.signingLocked()
	return seq
}

// Sign signs an object preimage with the current key, returning the signature and the
// key_state_seq a verifier must select. It is Snapshot().Sign without the copy (C-22).
func (c *Controller) Sign(objPreimage []byte) (sig []byte, keyStateSeq uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key, seq := c.signingLocked()
	if key == nil {
		return nil, seq
	}
	return ed25519.Sign(key, objPreimage), seq
}

// Snapshot returns an immutable Signer of the current key state (C-22): its AID, seq, a copy of
// the KEL and the key. A rotation built or adopted after the call does not change it, so the seq
// it reports and the key it signs with always belong together.
func (c *Controller) Snapshot() Signer {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key, seq := c.signingLocked()
	return &snapshot{aid: c.aid, seq: seq, kel: c.kelLocked(), key: key}
}

// Toad returns the witness mode the icp fixed: ToadAgent or ToadHub.
func (c *Controller) Toad() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.toadLocked()
}

func (c *Controller) toadLocked() uint64 {
	if t := c.kel[0].Event.Toad; t != nil {
		return *t
	}
	return ToadHub
}

// State returns the identity's state: StateOK, StateStopped or StateDeactivated.
func (c *Controller) State() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// LocalCommit returns IdentityFile key 7 (local_commit), or nil.
func (c *Controller) LocalCommit() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return copyBytes(c.localCommit)
}

// WitnessesToPush returns IdentityFile key 5, a copy.
func (c *Controller) WitnessesToPush() []WitnessPush {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]WitnessPush(nil), c.push...)
}

// Pending returns the event being published, as IdentityFile key 4 holds it but without the
// revealed key (Revealed is nil: the key stays in the controller). ok is false when nothing is
// pending.
func (c *Controller) Pending() (p Pending, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cp := c.pending
	if cp == nil {
		return Pending{}, false
	}
	p = Pending{Kind: cp.kind, Next: copyBytes(cp.next), HubURL: cp.hubURL, Emergency: cp.emergency, Since: cp.since}
	if cp.event != nil {
		b, err := coredet.Marshal(cp.event)
		if err == nil {
			p.Event = b
		}
	}
	return p, true
}

// ---- state transitions (C-21) ------------------------------------------------------------------

// BuildWitnessDesignation builds an agent's first rot (KEL D-13): rot{seq 1, keys [k1], next,
// witnesses [witness], toad 1, ts}, revealing the hot key k1 the icp committed and committing
// next, the next-key digest derived from the recovery seed. The event becomes the pending event
// (kind witness) and the controller signs with k1 from now on (C-21); Adopt it once the witness
// has accepted it.
func (c *Controller) BuildWitnessDesignation(witness string, next []byte, ts uint64) (SignedEvent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.canBuildLocked(); err != nil {
		return SignedEvent{}, err
	}
	switch {
	case c.toadLocked() != ToadAgent:
		return SignedEvent{}, errors.New("identity: only an agent identity (toad 1) designates a witness")
	case len(c.kel) != 1:
		return SignedEvent{}, errors.New("identity: the witness is already designated; a later rot names the next one")
	case c.hot == nil:
		return SignedEvent{}, errors.New("identity: the hot key the icp committed is not held")
	case witness == "":
		return SignedEvent{}, errors.New("identity: a witness designation needs the witness hub's AID")
	}
	return c.buildLocked(&pending{kind: PendingWitness, revealed: c.hot, next: copyBytes(next), since: ts}, witness, ts)
}

// BuildRotation builds a rot at ts that reveals revealed (the key the KEL head committed, derived
// from the recovery seed; nil reveals the hot key the icp committed, which only a hub identity that
// has not rotated yet holds and reveals this way, C-32) and commits next. An agent's rot names
// witness, its current witness or the hub it switches to; a hub's names none. emergency sets key 12
// (zero grace). A revealed key whose digest is not the committed one is ErrRecoveryMismatch. The
// event becomes the pending event and the controller signs with revealed from now on (C-21).
//
// An agent reveals its hot key only in its witness designation (C-31), so that its first rot is
// always pending as kind witness: BuildRotation refuses nil for an agent.
func (c *Controller) BuildRotation(revealed ed25519.PrivateKey, next []byte, witness string, emergency bool, ts uint64) (SignedEvent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.canBuildLocked(); err != nil {
		return SignedEvent{}, err
	}
	if revealed == nil && c.toadLocked() == ToadAgent {
		return SignedEvent{}, errors.New("identity: an agent reveals the hot key its icp committed only by designating its witness (BuildWitnessDesignation)")
	}
	key, err := c.revealedLocked(revealed)
	if err != nil {
		return SignedEvent{}, err
	}
	if c.toadLocked() == ToadHub && witness != "" {
		return SignedEvent{}, errors.New("identity: a hub identity (toad 0) names no witness")
	}
	return c.buildLocked(&pending{kind: PendingRot, revealed: key, next: copyBytes(next), emergency: emergency, since: ts}, witness, ts)
}

// BuildDeactivation builds the dip at ts that ends the identity (KEL D-46). It reveals revealed,
// the committed key (nil: the icp's hot key), so only the holder of the recovery material can
// deactivate. The event becomes the pending event.
func (c *Controller) BuildDeactivation(revealed ed25519.PrivateKey, ts uint64) (SignedEvent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.canBuildLocked(); err != nil {
		return SignedEvent{}, err
	}
	key, err := c.revealedLocked(revealed)
	if err != nil {
		return SignedEvent{}, err
	}
	return c.buildLocked(&pending{kind: PendingDip, revealed: key, since: ts}, "", ts)
}

// Restamp rebuilds the pending event at ts from its material (KEL D-36): the same kind, key,
// next-key digest, witness and emergency flag. A witness that refused the event's bytes for their
// time (kel_ts_out_of_window) never accepted them, so the rebuilt event forks nothing. It also
// builds the event of material that has none yet, such as the rot a recover writes (KEL D-45),
// naming the witness of the KEL head.
func (c *Controller) Restamp(ts uint64) (SignedEvent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending
	if p == nil {
		return SignedEvent{}, ErrNothingPending
	}
	if c.state != StateOK {
		return SignedEvent{}, fmt.Errorf("identity: the identity is %s", c.state)
	}
	var witness string
	switch {
	case p.event != nil && len(p.event.Event.Witnesses) == 1:
		witness = p.event.Event.Witnesses[0]
	case p.event == nil && p.kind != PendingDip && c.toadLocked() == ToadAgent:
		states, err := replay(c.kel)
		if err != nil {
			return SignedEvent{}, err
		}
		witness = states[len(states)-1].Witness
	}
	ev, err := c.buildEvent(p, witness, ts)
	if err != nil {
		return SignedEvent{}, err
	}
	p.event = &ev
	return ev, nil
}

// Adopt marks the pending event as accepted by the witness: it joins the KEL, the key it revealed
// becomes the current key, and the icp's hot key is dropped once revealed. ev must be the pending
// event, byte for byte.
func (c *Controller) Adopt(ev SignedEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending
	if p == nil || p.event == nil {
		return ErrNothingPending
	}
	got, err := coredet.Marshal(ev)
	if err != nil {
		return err
	}
	want, err := coredet.Marshal(p.event)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("identity: the event to adopt is not the pending event")
	}
	kel := make([]SignedEvent, len(c.kel)+1)
	copy(kel, c.kel)
	kel[len(c.kel)] = *p.event
	c.kel = kel
	c.cur = p.revealed
	c.hot = nil
	c.pending = nil
	return nil
}

// SetPendingHubURL records the witness hub the pending event is published to (IdentityPending key
// 4): the event names the hub's AID, the file also keeps where it is.
func (c *Controller) SetPendingHubURL(hubURL string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		return ErrNothingPending
	}
	c.pending.hubURL = hubURL
	return nil
}

// SetState sets the identity's state (IdentityFile key 6): StateOK, StateStopped or
// StateDeactivated.
func (c *Controller) SetState(state string) error {
	switch state {
	case StateOK, StateStopped, StateDeactivated:
	default:
		return fmt.Errorf("identity: state %q", state)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = state
	return nil
}

// SetLocalCommit records IdentityFile key 7 (local_commit): the next-key digest of the recovery
// seed kept, unprotected, in the data directory. It is public and is never removed.
func (c *Controller) SetLocalCommit(digest []byte) error {
	if len(digest) != sha256.Size {
		return errors.New("identity: local_commit is a 32-byte digest")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localCommit = copyBytes(digest)
	return nil
}

// SetWitnessesToPush replaces IdentityFile key 5.
func (c *Controller) SetWitnessesToPush(list []WitnessPush) error {
	for _, w := range list {
		if w.HubAID == "" {
			return errors.New("identity: a witness to push needs its AID")
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.push = append([]WitnessPush(nil), list...)
	return nil
}

// canBuildLocked: a new event needs an identity in state ok, not deactivated in its KEL, with no
// event pending.
func (c *Controller) canBuildLocked() error {
	if c.state != StateOK {
		return fmt.Errorf("identity: the identity is %s", c.state)
	}
	if c.kel[len(c.kel)-1].Event.Type == Deactivation {
		return errors.New("identity: the AID is deactivated")
	}
	if c.pending != nil {
		return ErrEventPending
	}
	return nil
}

// revealedLocked checks the key a rot or dip reveals against the commitment of the KEL head (nil:
// the icp's hot key).
func (c *Controller) revealedLocked(revealed ed25519.PrivateKey) (ed25519.PrivateKey, error) {
	if revealed == nil {
		if c.hot == nil || len(c.kel) != 1 {
			return nil, errors.New("identity: no hot key to reveal; pass the key the recovery seed derives")
		}
		return c.hot, nil
	}
	if len(revealed) != ed25519.PrivateKeySize {
		return nil, errors.New("identity: the revealed key is not an Ed25519 private key")
	}
	if !bytes.Equal(nextDigest(publicOf(revealed)), committedNextDigest(c.kel)) {
		return nil, ErrRecoveryMismatch
	}
	return revealed, nil
}

// buildLocked builds p's event, makes p the pending event and returns the event.
func (c *Controller) buildLocked(p *pending, witness string, ts uint64) (SignedEvent, error) {
	if p.kind != PendingDip && len(p.next) != sha256.Size {
		return SignedEvent{}, errors.New("identity: the next-key digest is not 32 bytes")
	}
	ev, err := c.buildEvent(p, witness, ts)
	if err != nil {
		return SignedEvent{}, err
	}
	p.event = &ev
	c.pending = p
	return ev, nil
}

// buildEvent signs the event p's material makes at ts and checks that the KEL with it replays, so
// that a controller never hands out an event that a verifier refuses.
func (c *Controller) buildEvent(p *pending, witness string, ts uint64) (SignedEvent, error) {
	last := c.kel[len(c.kel)-1]
	e := KeyEvent{
		KELType:   KELType,
		AID:       c.aid,
		Seq:       last.Event.Seq + 1,
		Prev:      last.EventID,
		Keys:      [][]byte{publicOf(p.revealed)},
		Threshold: 1,
		Timestamp: ts,
	}
	if p.kind == PendingDip {
		e.Type = Deactivation
	} else {
		e.Type = Rotation
		e.NextDigest = copyBytes(p.next)
		e.Toad = ToadField(c.toadLocked())
		e.Emergency = p.emergency
		if witness != "" {
			e.Witnesses = []string{witness}
		}
	}
	pre, err := preimage(e)
	if err != nil {
		return SignedEvent{}, err
	}
	id, err := anetcid.Sum(pre)
	if err != nil {
		return SignedEvent{}, err
	}
	ev := SignedEvent{Event: e, Sig: ed25519.Sign(p.revealed, pre), EventID: id}
	kel := make([]SignedEvent, len(c.kel)+1)
	copy(kel, c.kel)
	kel[len(c.kel)] = ev
	if _, err := replay(kel); err != nil {
		return SignedEvent{}, err
	}
	return ev, nil
}
