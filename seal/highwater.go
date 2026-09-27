package seal

import (
	"bytes"

	"github.com/ANetResearch/ANetCore/coredet"
)

// Decision is the outcome of the consumer high-water rule for key sets
// (§3.1). It is decided on seq and bytes alone, before any signature check:
// Ignore and Fork need no verification, and Same and Replace are acted on
// only after VerifyEncKeySet succeeds.
type Decision uint8

const (
	// Ignore: incoming seq is below the stored one. It is a rollback (an old
	// set replayed by the transport or a stale cache) and is dropped.
	Ignore Decision = iota + 1
	// Same: equal seq and identical set bytes. It is the stored object.
	// The caller still runs VerifyEncKeySet (rules 1-3, which depend on the
	// time and the current KEL) and, on success, refreshes its cache time.
	Same
	// Fork: equal seq, different set bytes. The incoming set is dropped and
	// the event counted; the stored set is kept. The decision is made before
	// any signature check, so Fork alone does not show that the owner signed
	// two sets: an unsigned or mis-signed set with the stored seq also yields
	// Fork. A caller that records a fork as evidence against the owner runs
	// VerifyEncKeySet on the incoming set first; the decision to drop it
	// does not depend on that check.
	Fork
	// Replace: incoming seq is above the stored one, or nothing is stored.
	// The caller runs VerifyEncKeySet and stores the set on success.
	Replace
)

func (d Decision) String() string {
	switch d {
	case Ignore:
		return "ignore"
	case Same:
		return "same"
	case Fork:
		return "fork"
	case Replace:
		return "replace"
	}
	return "invalid"
}

// Seen is what a consumer stores for one AID: the seq and the exact set
// bytes (SignedEncKeySet.Set) of the last key set it accepted.
type Seen struct {
	Seq uint64
	Set []byte
}

// DecideHighWater applies the three-branch consumer rule of §3.1 to an
// incoming set with sequence seq and set bytes set. seen == nil means the
// consumer holds no set for this AID.
//
// A publisher-side check (the hub accepting POST /agents/{aid}/keys) uses
// the same function: Replace is accepted, Same returns 200 without change,
// Ignore and Fork return 409.
func DecideHighWater(seen *Seen, seq uint64, set []byte) Decision {
	switch {
	case seen == nil || seq > seen.Seq:
		return Replace
	case seq < seen.Seq:
		return Ignore
	case bytes.Equal(set, seen.Set):
		return Same
	default:
		return Fork
	}
}

// DecideHighWaterSigned reads the seq from incoming.Set without verifying the
// signature and applies DecideHighWater. It returns an error when the set
// bytes do not decode as an EncKeySet.
func DecideHighWaterSigned(seen *Seen, incoming *SignedEncKeySet) (Decision, error) {
	if incoming == nil {
		return 0, fail(ReasonBadKeySet, "nil signed key set")
	}
	var s EncKeySet
	if err := coredet.Unmarshal(incoming.Set, &s); err != nil {
		return 0, failWrap(ReasonBadKeySet, err, "decode set")
	}
	return DecideHighWater(seen, s.Seq, incoming.Set), nil
}
