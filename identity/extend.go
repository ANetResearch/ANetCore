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
// (A2A-DESIGN §3.8; KEL R-11). Every KEL update goes through it; a party that accepts the longer
// KEL then applies CheckNewEvents to the events it adds. It returns nil when next replays
// successfully and old is a prefix of next (equal KELs included), and otherwise:
//
//   - the Replay error, wrapped, when next itself does not validate;
//   - an error wrapping ErrKELFork when the event preimages differ at some index present in both;
//   - an error wrapping ErrKELRollback when every shared event matches but next is shorter.
//
// Events are compared by their CoreDet preimage (coredet(KeyEvent)), not by the SignedEvent
// encoding. The preimage is what the event id, the prev linkage and the signature cover; Replay
// checks next's event ids and signatures against it. A stored copy of an event that differs from
// the candidate's only in its EventID string or signature bytes therefore describes the same
// history and is not reported as a fork. old is not replayed. When ExtendsKEL returns nil, old's
// event preimages are a prefix of next's, and a prefix of a KEL that replays also replays because
// each event's validity depends only on the events before it; the history old describes is
// therefore valid. old's own signature and EventID bytes are never checked, so the caller stores
// next, not old.
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

// ErrEventFromFuture is returned by CheckNewEvents for a new event whose ts is more than
// EventClockWindow ahead of the accepting party's clock (R-9). A hub answers it with
// kel_ts_out_of_window; a daemon counts it as kel-from-future.
var ErrEventFromFuture = errors.New("identity: new KEL event is from the future")

// ErrEventTooOld is returned by CheckNewEvents for a new event that the hub it designates as
// witness first sees more than EventClockWindow after the event's ts (R-10). A hub answers it with
// kel_ts_out_of_window.
var ErrEventTooOld = errors.New("identity: new KEL event is too old for its witness")

// CheckNewEvents applies the acceptance rules to the events next adds after old (R-9, R-10; KEL
// C-4). The caller has already established with ExtendsKEL that next extends old; the events at
// index len(old) and beyond are the new ones (all of next when nothing is stored).
//
// Every party that accepts a longer KEL — a hub on register or push, a daemon merging a sender's
// KEL, a daemon or hub extending a pinned hub KEL — refuses a new event whose ts is later than
// now + EventClockWindow (ErrEventFromFuture). The hub that is first to accept an event as its
// witness also refuses one whose ts is earlier than now − EventClockWindow (ErrEventTooOld): for
// a rot that is the hub its key 9 names, for a dip the hub the state before it names (the
// Witness of that state in Replay's result). isFirstWitness says whether the caller is that hub
// for the event; nil means it never is, which is the case for every party except a witness hub.
// Both bounds are inclusive. now is unix ms.
func CheckNewEvents(old, next []SignedEvent, now uint64, isFirstWitness func(e KeyEvent) bool) error {
	for i := len(old); i < len(next); i++ {
		e := next[i].Event
		if e.Timestamp > now && e.Timestamp-now > EventClockWindow {
			return fmt.Errorf("%w: seq %d ts %d, now %d", ErrEventFromFuture, e.Seq, e.Timestamp, now)
		}
		if isFirstWitness != nil && isFirstWitness(e) && e.Timestamp < now && now-e.Timestamp > EventClockWindow {
			return fmt.Errorf("%w: seq %d ts %d, now %d", ErrEventTooOld, e.Seq, e.Timestamp, now)
		}
	}
	return nil
}
