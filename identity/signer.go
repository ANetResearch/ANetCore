package identity

import (
	"crypto/ed25519"
	"errors"
)

// Signer signs as one identity (KEL C-24). It is what signing code is given: modules, ael,
// evidence, payment and the card signer take a Signer, never a *Controller, so none of them can
// change the identity's keys or hold its private key.
//
// The three methods describe one key state:
//   - AID is the identity the signatures are made as;
//   - Sign signs preimage with the key of the identity's current key state and returns the
//     signature with that state's key_state_seq, which is always the seq of the last event of KEL;
//   - KEL is the key event log a verifier checks the signature against.
//
// A Controller is a Signer whose key state can change between two calls (a rotation). Code that
// writes the key_state_seq into what it signs, before signing, uses SnapshotOf first, so that the
// seq it writes and the key that signs come from one key state (C-22, C-23).
type Signer interface {
	AID() string
	Sign(preimage []byte) (sig []byte, keyStateSeq uint64)
	KEL() []SignedEvent
}

// snapshot is an immutable Signer: one AID, one key state and the KEL up to and including it
// (C-22). Nothing changes it after it is made, so its Sign, KEL and AID always agree.
type snapshot struct {
	aid string
	seq uint64
	kel []SignedEvent // a copy, owned by the snapshot
	key ed25519.PrivateKey
}

func (s *snapshot) AID() string { return s.aid }

// KEL returns the snapshot's KEL. The slice is capped at its length, so appending to it copies.
func (s *snapshot) KEL() []SignedEvent { return s.kel[:len(s.kel):len(s.kel)] }

// Sign signs with the snapshot's key. A snapshot of an identity that holds no key (a recovered
// identity whose first rotation has not been built yet) returns a nil signature, which verifies
// nowhere; its outbound gate is closed in that state, so nothing asks it to sign.
func (s *snapshot) Sign(preimage []byte) ([]byte, uint64) {
	if s.key == nil {
		return nil, s.seq
	}
	return ed25519.Sign(s.key, preimage), s.seq
}

// SnapshotOf returns a Signer whose key state cannot change: s.Snapshot() when s can take one (a
// Controller), and s itself otherwise. A Signer that cannot take a snapshot must not change its
// key state while it is being used.
func SnapshotOf(s Signer) Signer {
	if sn, ok := s.(interface{ Snapshot() Signer }); ok {
		return sn.Snapshot()
	}
	return s
}

// ErrSignerSeq is returned when a Signer's Sign reports another key_state_seq than the last event
// of its KEL: the seq written into the object would name another key than the one that signed.
var ErrSignerSeq = errors.New("identity: the signer signed under another key state than its KEL names")

// SeqOf returns the key_state_seq s signs under: the seq of the last event of s.KEL(). Call it on
// the result of SnapshotOf, and check the seq Sign returns against it (ErrSignerSeq).
func SeqOf(s Signer) (uint64, error) {
	kel := s.KEL()
	if len(kel) == 0 {
		return 0, errors.New("identity: the signer has no KEL")
	}
	return kel[len(kel)-1].Event.Seq, nil
}
