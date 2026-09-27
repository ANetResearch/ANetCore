package a2acard

import "fmt"

// Mark is the per-AID record a consumer or publisher keeps for the params.seq high-water rule:
// the highest seq admitted and the SHA-256 of that card's canonical payload.
type Mark struct {
	Seq         uint64
	PayloadHash [32]byte
}

// Decision is the outcome of an admitted CheckHighWater.
type Decision int

const (
	// Advance: the card is new (no stored mark, or seq above it). Store it and its Mark.
	Advance Decision = iota + 1
	// Same: the card repeats the stored one (same seq, same canonical payload). Keep the stored
	// mark; refreshing a cache timestamp is appropriate. The signature may differ from the
	// stored card's, for example after a re-sign under a rotated key, and that is not a change.
	Same
)

func (d Decision) String() string {
	switch d {
	case Advance:
		return "advance"
	case Same:
		return "same"
	default:
		return fmt.Sprintf("Decision(%d)", int(d))
	}
}

// CheckHighWater applies the three-branch params.seq rule (A2A-DESIGN §3.1, §10.3; review C16)
// to a verified card's Mark against the stored one (nil when none is stored):
//
//   - next.Seq < stored.Seq: CodeSeqRollback. An older card is being replayed.
//   - next.Seq == stored.Seq: Same if the payload hashes are equal, otherwise CodeSeqFork (the
//     signer issued two different cards under one seq; count and ignore it).
//   - next.Seq > stored.Seq: Advance.
//
// Accepting the equal, identical case matters: a daemon that re-fetches a card after its cache
// expires, or a hub that receives the same registration twice, would otherwise reject a card
// that has not changed. Publishers (hub admission) apply the same function and map Same to
// "200, unchanged" and both errors to 409.
//
// The caller must run Verify first; the rule orders valid cards, it does not authenticate them.
func CheckHighWater(stored *Mark, next Mark) (Decision, error) {
	if stored == nil {
		return Advance, nil
	}
	switch {
	case next.Seq < stored.Seq:
		return 0, newErr(CodeSeqRollback, fmt.Sprintf("seq %d is below the stored %d", next.Seq, stored.Seq))
	case next.Seq == stored.Seq:
		if next.PayloadHash != stored.PayloadHash {
			return 0, newErr(CodeSeqFork, fmt.Sprintf("seq %d already admitted with a different payload", next.Seq))
		}
		return Same, nil
	default:
		return Advance, nil
	}
}
