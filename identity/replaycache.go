package identity

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"unsafe"
)

// ReplayCache remembers what KELs replay to, so that a process checking many objects against the
// same KELs replays each KEL once rather than once per object.
//
// Replay costs an Ed25519 verification per event, and every check of an object against a KEL
// (VerifyObject, and each Verify in this module built on it: payment authorizations, receipts,
// reviews, key sets, cards) replays the whole KEL first. A process that holds KELs for others and
// answers strangers paid that on every request naming a KEL, whoever sent it and whether or not its
// signature was any good. On a hub, a request naming an agent that had stored a long KEL, with a
// signature of zeros, cost the replay of up to seal.MaxKELEvents events before it was refused, and
// so did each unauthenticated read that checks the agent's signed card or key set [redteam:F36].
//
// Entries are keyed by the SHA-256 of the KEL's encoding (MarshalKEL). Replay depends on nothing
// else, so an entry never goes stale, and a KEL that differs in any byte is another key. A KEL that
// does not replay is remembered with its error. The cache is bounded by an estimate of the bytes it
// holds and forgets the least recently used entries first.
//
// No cache is consulted unless a process installs one (SetReplayCache). The states Replay returns
// from the cache are the caller's own slice; the key bytes in them are shared with the cache and
// must not be modified, as no caller of Replay does.
type ReplayCache struct {
	mu     sync.Mutex
	byKEL  map[[32]byte]*list.Element
	lru    *list.List // of *replayEntry, most recently used first
	bytes  int
	max    int
	hits   uint64
	misses uint64
}

// replayEntry is one KEL's replay: its states (or the reason it does not replay) and what they are
// estimated to cost.
type replayEntry struct {
	key    [32]byte
	states []KeyState
	err    error
	cost   int
}

// NewReplayCache returns a cache that holds at most about maxBytes.
func NewReplayCache(maxBytes int) *ReplayCache {
	return &ReplayCache{byKEL: map[[32]byte]*list.Element{}, lru: list.New(), max: maxBytes}
}

var installedReplayCache atomic.Pointer[ReplayCache]

// SetReplayCache makes Replay consult c, or no cache when c is nil (the default), and returns the
// cache it replaces. It is process-wide.
func SetReplayCache(c *ReplayCache) *ReplayCache { return installedReplayCache.Swap(c) }

// Stats reports how many replays the cache answered and how many it had to make.
func (c *ReplayCache) Stats() (hits, misses uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}

// replay is Replay through the cache.
func (c *ReplayCache) replay(kel []SignedEvent) ([]KeyState, error) {
	enc, err := MarshalKEL(kel)
	if err != nil {
		return replay(kel)
	}
	key := sha256.Sum256(enc)
	c.mu.Lock()
	if el, ok := c.byKEL[key]; ok {
		c.lru.MoveToFront(el)
		c.hits++
		e := el.Value.(*replayEntry)
		c.mu.Unlock()
		if e.err != nil {
			return nil, e.err
		}
		return append([]KeyState(nil), e.states...), nil
	}
	c.misses++
	c.mu.Unlock()

	states, err := replay(kel)
	e := &replayEntry{key: key, err: err}
	if err == nil {
		var ok bool
		if e.states, e.cost, ok = compactStates(states); !ok {
			return states, nil
		}
	}
	e.cost += 256 // the key, the map slot, the list element, an error
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.byKEL[key]; ok || e.cost > c.max {
		return states, err
	}
	for c.bytes+e.cost > c.max {
		old := c.lru.Remove(c.lru.Back()).(*replayEntry)
		delete(c.byKEL, old.key)
		c.bytes -= old.cost
	}
	c.byKEL[key] = c.lru.PushFront(e)
	c.bytes += e.cost
	return states, err
}

// compactStates copies states for the cache without the memory Replay's own result spends on
// delegated keys, and returns the copy and its estimated size. Replay gives every drt a new copy
// of the list so far, so a KEL of n delegations holds n²/2 slice headers; each list is a prefix of
// the last state's, so the copy shares one array, capped so that an append by a caller copies it.
// The keys are copied, so the cache holds no memory of the caller's. ok is false when the states
// are not as Replay makes them, and then nothing is cached.
func compactStates(states []KeyState) (out []KeyState, cost int, ok bool) {
	if len(states) == 0 {
		return nil, 0, false
	}
	copyKeys := func(keys [][]byte) [][]byte {
		if keys == nil {
			return nil
		}
		cp := make([][]byte, len(keys))
		for i, k := range keys {
			cp[i] = append([]byte(nil), k...)
			cost += len(k) + int(unsafe.Sizeof(k))
		}
		return cp
	}
	all := copyKeys(states[len(states)-1].DelegatedKeys)
	out = make([]KeyState, len(states))
	cost += len(out) * int(unsafe.Sizeof(KeyState{}))
	for i, s := range states {
		if len(s.DelegatedKeys) > len(all) {
			return nil, 0, false
		}
		for j, k := range s.DelegatedKeys {
			if !bytes.Equal(k, all[j]) {
				return nil, 0, false
			}
		}
		out[i] = s
		if s.DelegatedKeys != nil {
			out[i].DelegatedKeys = all[:len(s.DelegatedKeys):len(s.DelegatedKeys)]
		}
		if i > 0 && sameKeys(s.CurrentKeys, states[i-1].CurrentKeys) {
			out[i].CurrentKeys = out[i-1].CurrentKeys
		} else {
			out[i].CurrentKeys = copyKeys(s.CurrentKeys)
		}
		cost += len(s.LastEventID)
	}
	return out, cost + len(states[0].AID), true
}

// sameKeys reports whether a and b are the same slice, as Replay carries a key state's keys over
// to the next state when an event does not change them.
func sameKeys(a, b [][]byte) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}
