package identity

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrKELRollback is returned by ExtendsKEL when the candidate KEL is a strict prefix of the stored
// one: every event it carries matches, but it ends earlier. Accepting it would move a verifier back
// to a key state it has already seen superseded, which re-enables keys a later rot/dip retired.
var ErrKELRollback = errors.New("identity: KEL rollback (candidate is a strict prefix of the known KEL)")

// ErrKELFork is returned by ExtendsKEL when the two KELs disagree on the key event at some sequence
// number. Both histories cannot be true for one AID; the verifier cannot tell which one the
// controller authored, so it must keep what it has and treat the peer as suspect.
var ErrKELFork = errors.New("identity: KEL fork (the KELs disagree on a key event)")

// ExtendsKEL reports whether next is an acceptable successor of old for the same AID
// (A2A-DESIGN §3.8). It returns nil when next replays successfully and old is a prefix of next
// (equal KELs included), and otherwise:
//
//   - the Replay error, wrapped, when next itself does not validate;
//   - an error wrapping ErrKELFork when the event preimages differ at some index present in both;
//   - an error wrapping ErrKELRollback when every shared event matches but next is shorter.
//
// Events are compared by their CoreDet preimage (coredet(KeyEvent)), not by the SignedEvent
// encoding. The preimage is what the event id, the prev linkage and the signature cover; Replay
// derives linkage from it and never reads SignedEvent.EventID, and next's signatures are checked by
// Replay. Two copies of one event that differ only in an unchecked EventID string or in an
// alternative valid signature therefore describe the same history and are not reported as a fork.
// old is not replayed. When ExtendsKEL returns nil, old's event preimages are a prefix of next's,
// and a prefix of a KEL that replays also replays because each event's validity depends only on
// the events before it; the history old describes is therefore valid. old's own signature and
// EventID bytes are never checked, so the caller stores next, not old.
//
// A divergence is reported as a fork even when next is also shorter, because a disagreement about
// a signed event is the stronger finding.
func ExtendsKEL(old, next []SignedEvent) error {
	if _, err := Replay(next); err != nil {
		return fmt.Errorf("identity: candidate KEL does not replay: %w", err)
	}
	n := len(old)
	if len(next) < n {
		n = len(next)
	}
	for i := 0; i < n; i++ {
		a, err := preimage(old[i].Event)
		if err != nil {
			return fmt.Errorf("identity: known KEL event %d does not encode: %w", i, err)
		}
		b, err := preimage(next[i].Event)
		if err != nil {
			return fmt.Errorf("identity: candidate KEL event %d does not encode: %w", i, err)
		}
		if !bytes.Equal(a, b) {
			return fmt.Errorf("%w: event %d differs", ErrKELFork, i)
		}
	}
	if len(next) < len(old) {
		return fmt.Errorf("%w: candidate has %d events, known KEL has %d", ErrKELRollback, len(next), len(old))
	}
	return nil
}
