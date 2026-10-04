package relayauth

import (
	"math"
	"sync"
)

// FloorClampMillis is how far below the edge of the skew window a hub's floor must stay for a
// client to adopt it (HPP §0.4, PAY-R11): a floor above now + MaxSkewMillis − FloorClampMillis is
// refused, so that a hub cannot push a client's timestamps out of the window every hub accepts.
const FloorClampMillis = 60 * 1000

// MonoClock hands out the X-ANet-TS of signed requests, strictly increasing per target hub (RC1,
// HPP PAY-K7).
//
// A hub accepts a signer's timestamp at most once and never at or below the floor it keeps for
// that signer (PAY-R2), so two requests a client signs in the same millisecond, or a clock that
// steps back, would see one of them refused as replayed. One MonoClock per process, shared by every
// part of the process that signs hub requests (the daemon and its payment module alike), keeps
// their timestamps apart; a counter of each part's own would collide with the other's.
//
// Each target hub has its own counter: one hub's floor never moves the timestamps sent to another
// (PAY-R12). The zero value is ready to use and every method is safe for concurrent use.
type MonoClock struct {
	mu   sync.Mutex
	last map[string]int64
}

// Next returns the timestamp for the next request to target: max(now, last + 1), and records it
// as the last.
func (c *MonoClock) Next(target string, now int64) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	ts := now
	if last, ok := c.last[target]; ok && last >= ts {
		ts = last
		if ts < math.MaxInt64 {
			ts++
		}
	}
	if c.last == nil {
		c.last = map[string]int64{}
	}
	c.last[target] = ts
	return ts
}

// Raise answers a ts_stale refusal from target, which said its floor for this signer is floor. If
// floor ≤ now + MaxSkewMillis − FloorClampMillis, the counter for target moves to max(last, floor),
// so the next timestamp is above the floor, and Raise returns true: the caller signs again and
// retries once. A floor beyond that is not adopted (a hub asking for timestamps the other hubs
// would refuse as being from the future) and Raise returns false; the caller treats the hub as
// unreachable for this request.
func (c *MonoClock) Raise(target string, floor, now int64) bool {
	limit := now
	if limit <= math.MaxInt64-(MaxSkewMillis-FloorClampMillis) {
		limit += MaxSkewMillis - FloorClampMillis
	} else {
		limit = math.MaxInt64
	}
	if floor > limit {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		c.last = map[string]int64{}
	}
	if last, ok := c.last[target]; !ok || floor > last {
		c.last[target] = floor
	}
	return true
}
