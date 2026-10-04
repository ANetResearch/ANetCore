package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/coredet"
)

// IdentityFileType is key 0 of an identity file: identity.kel of a node and hub_identity.kel of a
// hub (core §2.6, L21; KEL §2.9).
const IdentityFileType = "anet.identity/2"

// States of an identity (IdentityFile key 6). Any other value is refused.
const (
	StateOK          = "ok"
	StateStopped     = "stopped"     // the identity was rotated or recovered elsewhere (KEL D-27)
	StateDeactivated = "deactivated" // this node deactivated it (KEL D-46)
)

// Kinds of a pending event (IdentityPending key 1).
const (
	PendingWitness = "witness" // an agent's first rot, naming its witness hub (KEL D-13)
	PendingRot     = "rot"     // any other rot: planned, hub switch, emergency, recover
	PendingDip     = "dip"     // the deactivation
)

// Errors of Restore. A file that is not an identity file v2 at all (a v0.2 identity, another file)
// is ErrNotIdentityV2; a v2 file whose parts contradict each other is ErrIdentityFileInconsistent
// (KEL C-25): it is refused rather than loaded as a controller that signs with the wrong key or
// cannot rotate.
var (
	ErrNotIdentityV2            = errors.New("identity: the file is not an anet.identity/2 identity (v0.2 identities are not carried over)")
	ErrIdentityFileInconsistent = errors.New("identity: identity file inconsistent")
)

// IdentityFile is the identity file v2 (core §2.6, KEL §2.9). It holds PRIVATE KEYS: it is
// written 0600, temporary file → fsync → rename, and never published.
//
// A Controller is the live form of one: Export writes it, Restore reads it. The type is exported
// so that a tool can write a file a Controller has never held, such as the one `anet identity
// recover` writes into a new data directory (KEL D-45); Restore checks it all the same.
//
//anet:wire IdentityFile
type IdentityFile struct {
	T               string        `cbor:"0,keyasint"`           // IdentityFileType
	KEL             []byte        `cbor:"1,keyasint"`           // MarshalKEL of the events the witness accepted
	Cur             []byte        `cbor:"2,keyasint,omitempty"` // seed of the current signing key; absent while a recover waits to publish
	HotNext         []byte        `cbor:"3,keyasint,omitempty"` // seed of the hot key the icp committed; only while the KEL is the icp alone
	Pending         *Pending      `cbor:"4,keyasint,omitempty"`
	WitnessesToPush []WitnessPush `cbor:"5,keyasint,omitempty"`
	State           string        `cbor:"6,keyasint"`
	LocalCommit     []byte        `cbor:"7,keyasint,omitempty"` // next_digest of the recovery seed kept unprotected in the data directory; public
}

// Pending is the event an identity is publishing (IdentityFile key 4): the material it is built
// from and, once built, the event itself. Revealed is a PRIVATE KEY seed.
//
//anet:wire IdentityPending
type Pending struct {
	Kind      string `cbor:"1,keyasint"`           // PendingWitness, PendingRot or PendingDip
	Revealed  []byte `cbor:"2,keyasint"`           // seed of the key the event reveals
	Next      []byte `cbor:"3,keyasint,omitempty"` // the next-key digest the event commits; absent for a dip
	HubURL    string `cbor:"4,keyasint"`           // the witness hub it is published to
	Emergency bool   `cbor:"5,keyasint"`
	Event     []byte `cbor:"6,keyasint,omitempty"` // the built SignedEvent, coredet; absent until built
	Since     uint64 `cbor:"7,keyasint"`           // unix ms when the material was first built
}

// WitnessPush is a former witness the identity keeps pushing its KEL to (IdentityFile key 5,
// KEL D-33).
//
//anet:wire WitnessPush
type WitnessPush struct {
	HubAID   string `cbor:"1,keyasint"`
	HubURL   string `cbor:"2,keyasint"`
	AckedSeq uint64 `cbor:"3,keyasint"`
	NextTry  uint64 `cbor:"4,keyasint"`
}

// Marshal encodes f as its file bytes (coredet).
func (f *IdentityFile) Marshal() ([]byte, error) { return coredet.Marshal(f) }

// Export returns the identity file v2 of c (KEL C-25): the KEL, the keys and the state, as Restore
// reads them back. The bytes contain PRIVATE KEYS.
func (c *Controller) Export() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	kel, err := MarshalKEL(c.kel)
	if err != nil {
		return nil, err
	}
	f := IdentityFile{T: IdentityFileType, KEL: kel, State: c.state}
	if c.cur != nil {
		f.Cur = c.cur.Seed()
	}
	if c.hot != nil && len(c.kel) == 1 {
		f.HotNext = c.hot.Seed()
	}
	if p := c.pending; p != nil {
		fp := &Pending{Kind: p.kind, Revealed: p.revealed.Seed(), Next: copyBytes(p.next), HubURL: p.hubURL,
			Emergency: p.emergency, Since: p.since}
		if p.event != nil {
			if fp.Event, err = coredet.Marshal(p.event); err != nil {
				return nil, err
			}
		}
		f.Pending = fp
	}
	f.WitnessesToPush = append([]WitnessPush(nil), c.push...)
	f.LocalCommit = copyBytes(c.localCommit)
	return f.Marshal()
}

// ParseIdentityFile decodes identity file bytes strictly (core CORE-E3): a key the file does not
// define, a type tag other than IdentityFileType or a non-canonical encoding is refused. It does
// not check that the parts agree; Restore does.
func ParseIdentityFile(b []byte) (*IdentityFile, error) {
	// The type tag first, leniently, so that a v0.2 identity (no key 0) is named as such rather
	// than reported as a decoding error of some key.
	var m map[uint64]cbor.RawMessage
	var tag string
	if err := coredet.Unmarshal(b, &m); err != nil || coredet.Unmarshal(m[0], &tag) != nil || tag != IdentityFileType {
		return nil, ErrNotIdentityV2
	}
	var f IdentityFile
	if err := coredet.UnmarshalStrict(b, &f); err != nil {
		return nil, fmt.Errorf("identity: identity file does not decode: %w", err)
	}
	back, err := coredet.Marshal(&f)
	if err != nil || !bytes.Equal(back, b) {
		return nil, fmt.Errorf("%w: not in its canonical encoding", ErrIdentityFileInconsistent)
	}
	return &f, nil
}

// Restore reads an identity file v2 (KEL C-25) and returns its Controller. The KEL must replay,
// and the keys must be the ones it names:
//   - cur is the key of the KEL head, or the key the pending event reveals;
//   - hot_next is the key the icp committed, and is there only while the KEL is the icp alone;
//   - the pending key is the one the KEL head committed, and a built pending event is exactly the
//     event that material makes, extending the KEL.
//
// Anything else is ErrIdentityFileInconsistent: a torn or tampered file is refused rather than
// loaded as a controller that signs with the wrong key or cannot rotate. A deactivated or stopped
// identity is restored as such; what it may still do is its owner's decision (KEL §4.3.1).
func Restore(b []byte) (*Controller, error) {
	f, err := ParseIdentityFile(b)
	if err != nil {
		return nil, err
	}
	return restoreFile(f)
}

func inconsistent(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrIdentityFileInconsistent}, args...)...)
}

func restoreFile(f *IdentityFile) (*Controller, error) {
	switch f.State {
	case StateOK, StateStopped, StateDeactivated:
	default:
		return nil, inconsistent("state %q", f.State)
	}
	kel, err := UnmarshalKEL(f.KEL)
	if err != nil {
		return nil, fmt.Errorf("identity: restore: %w", err)
	}
	states, err := Replay(kel)
	if err != nil {
		return nil, fmt.Errorf("identity: restore replay: %w", err)
	}
	head := states[len(states)-1]
	c := &Controller{aid: head.AID, kel: kel, state: f.State,
		push: append([]WitnessPush(nil), f.WitnessesToPush...)}
	if f.LocalCommit != nil {
		if len(f.LocalCommit) != sha256.Size {
			return nil, inconsistent("local_commit is not 32 bytes")
		}
		c.localCommit = copyBytes(f.LocalCommit)
	}
	for _, w := range f.WitnessesToPush {
		if w.HubAID == "" {
			return nil, inconsistent("a witness to push has no AID")
		}
	}
	if f.HotNext != nil {
		if len(kel) != 1 {
			return nil, inconsistent("hot_next is kept after the first rotation")
		}
		hot, err := keyFromSeed(f.HotNext, "hot_next")
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(nextDigest(publicOf(hot)), kel[0].Event.NextDigest) {
			return nil, inconsistent("hot_next is not the key the icp committed")
		}
		c.hot = hot
	}
	if f.Pending != nil {
		if c.pending, err = restorePending(c, f.Pending, head); err != nil {
			return nil, err
		}
	}
	if f.Cur == nil {
		// Only a recover writes a file without a current key: the KEL head's key is the one the
		// thief holds, and the recovered node signs first with the key its pending rot reveals.
		if c.pending == nil {
			return nil, inconsistent("no current key and nothing pending")
		}
		return c, nil
	}
	cur, err := keyFromSeed(f.Cur, "cur")
	if err != nil {
		return nil, err
	}
	switch pub := publicOf(cur); {
	case len(head.CurrentKeys) == 1 && bytes.Equal(pub, head.CurrentKeys[0]):
		c.cur = cur
	case len(kel) > 0 && kel[len(kel)-1].Event.Type == Deactivation && bytes.Equal(pub, kel[len(kel)-1].Event.Keys[0]):
		// the dip's own state has no current key; the key the dip revealed is the last one held
		c.cur = cur
	case c.pending != nil && c.pending.event != nil && bytes.Equal(pub, c.pending.event.Event.Keys[0]):
		// written by a writer that switched to the revealed key before the witness accepted it:
		// the head's key is not in the file, and the pending key signs until then anyway
	default:
		return nil, inconsistent("cur is neither the key of the KEL head nor the key the pending event reveals")
	}
	return c, nil
}

// restorePending checks the pending material against the accepted KEL and rebuilds its event
// from it, which must give the stored event byte for byte.
func restorePending(c *Controller, fp *Pending, head KeyState) (*pending, error) {
	if head.Status == StatusDeactivated {
		return nil, inconsistent("an event is pending after the deactivation")
	}
	revealed, err := keyFromSeed(fp.Revealed, "pending.revealed")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(nextDigest(publicOf(revealed)), committedNextDigest(c.kel)) {
		return nil, inconsistent("the pending key is not the one the KEL head committed")
	}
	p := &pending{kind: fp.Kind, revealed: revealed, hubURL: fp.HubURL, emergency: fp.Emergency, since: fp.Since}
	switch fp.Kind {
	case PendingWitness:
		if head.Toad != ToadAgent || len(c.kel) != 1 || fp.Emergency {
			return nil, inconsistent("a witness designation pending on an identity that is not an agent with only its icp")
		}
	case PendingRot:
		if head.Toad == ToadAgent && len(c.kel) == 1 {
			return nil, inconsistent("an agent's first rot is its witness designation, pending as kind witness")
		}
	case PendingDip:
		if fp.Next != nil || fp.Emergency {
			return nil, inconsistent("a pending dip with a next key or the emergency flag")
		}
	default:
		return nil, inconsistent("pending kind %q", fp.Kind)
	}
	if fp.Kind != PendingDip {
		if len(fp.Next) != sha256.Size {
			return nil, inconsistent("the pending next-key digest is not 32 bytes")
		}
		p.next = copyBytes(fp.Next)
	}
	if fp.Event == nil {
		if fp.Kind == PendingWitness {
			return nil, inconsistent("a witness designation pending without its event")
		}
		return p, nil
	}
	var ev SignedEvent
	if err := coredet.UnmarshalStrict(fp.Event, &ev); err != nil {
		return nil, inconsistent("the pending event does not decode: %v", err)
	}
	var witness string
	if len(ev.Event.Witnesses) == 1 {
		witness = ev.Event.Witnesses[0]
	}
	want, err := c.buildEvent(p, witness, ev.Event.Timestamp)
	if err != nil {
		return nil, inconsistent("the pending event: %v", err)
	}
	wantBytes, err := coredet.Marshal(want)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(wantBytes, fp.Event) {
		return nil, inconsistent("the pending event is not the event its material makes")
	}
	p.event = &want
	return p, nil
}

func keyFromSeed(seed []byte, what string) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, inconsistent("%s is not a 32-byte seed", what)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func publicOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}
