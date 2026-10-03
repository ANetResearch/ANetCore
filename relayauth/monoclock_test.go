package relayauth

import (
	"math"
	"sync"
	"testing"
)

const t0 = int64(1767225600000)

func TestMonoClockIsStrictlyIncreasingPerTarget(t *testing.T) {
	var c MonoClock
	if got := c.Next("hub-a", t0); got != t0 {
		t.Fatalf("first timestamp %d, want now %d", got, t0)
	}
	// Two requests in one millisecond, and a clock that steps back: still strictly increasing.
	if got := c.Next("hub-a", t0); got != t0+1 {
		t.Fatalf("same millisecond: %d, want %d", got, t0+1)
	}
	if got := c.Next("hub-a", t0-5000); got != t0+2 {
		t.Fatalf("clock stepped back: %d, want %d", got, t0+2)
	}
	// Once the clock passes the counter, the clock is the timestamp again.
	if got := c.Next("hub-a", t0+10_000); got != t0+10_000 {
		t.Fatalf("clock ahead: %d, want %d", got, t0+10_000)
	}
}

// One hub's floor never moves what is sent to another (PAY-R12).
func TestMonoClockKeepsHubsApart(t *testing.T) {
	var c MonoClock
	c.Next("hub-a", t0)
	c.Next("hub-b", t0)
	if !c.Raise("hub-a", t0+60_000, t0) {
		t.Fatal("a floor one minute ahead must be adopted")
	}
	if got := c.Next("hub-b", t0); got != t0+1 {
		t.Fatalf("hub-b moved with hub-a's floor: %d", got)
	}
	if got := c.Next("hub-a", t0); got != t0+60_001 {
		t.Fatalf("hub-a after its floor: %d, want %d", got, t0+60_001)
	}
	// A hub never seen before takes a floor too.
	if !c.Raise("hub-c", t0+1000, t0) || c.Next("hub-c", t0) != t0+1001 {
		t.Fatal("a fresh target did not adopt its floor")
	}
}

// A floor is adopted only up to now + MaxSkew − 60 s (PAY-R11): beyond that a hub would push this
// client's timestamps out of the window other hubs accept.
func TestMonoClockClampsTheFloor(t *testing.T) {
	var c MonoClock
	limit := t0 + MaxSkewMillis - FloorClampMillis
	if !c.Raise("hub-a", limit, t0) {
		t.Fatal("a floor exactly at the limit must be adopted")
	}
	if got := c.Next("hub-a", t0); got != limit+1 {
		t.Fatalf("after the limit floor: %d, want %d", got, limit+1)
	}
	var d MonoClock
	d.Next("hub-a", t0)
	if d.Raise("hub-a", limit+1, t0) {
		t.Fatal("a floor past the limit was adopted")
	}
	if got := d.Next("hub-a", t0); got != t0+1 {
		t.Fatalf("a refused floor moved the counter: %d", got)
	}
	// A floor below the counter changes nothing.
	d.Next("hub-a", t0+30_000)
	if !d.Raise("hub-a", t0, t0) {
		t.Fatal("a floor in the past is fine to accept")
	}
	if got := d.Next("hub-a", t0); got != t0+30_001 {
		t.Fatalf("a lower floor moved the counter back: %d", got)
	}
}

func TestMonoClockAtTheEdgesOfInt64(t *testing.T) {
	var c MonoClock
	if !c.Raise("hub-a", math.MaxInt64, math.MaxInt64) {
		t.Fatal("now at the edge: the limit saturates rather than wrapping")
	}
	if got := c.Next("hub-a", 0); got != math.MaxInt64 {
		t.Fatalf("the counter saturates: %d", got)
	}
	var d MonoClock
	if d.Raise("hub-a", 0, math.MinInt64) {
		t.Fatal("a floor above a limit computed from a very negative now was adopted")
	}
}

// Every goroutine of a process signs through one clock and gets distinct, increasing timestamps
// (run with -race).
func TestMonoClockConcurrentUse(t *testing.T) {
	var c MonoClock
	const workers, each = 16, 500
	seen := make(chan int64, workers*each)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			prev := int64(math.MinInt64)
			for i := 0; i < each; i++ {
				if i%50 == 0 {
					c.Raise("hub-a", t0+int64(i), t0)
					c.Next("hub-b", t0)
				}
				ts := c.Next("hub-a", t0)
				if ts <= prev {
					t.Errorf("worker %d: %d after %d", w, ts, prev)
				}
				prev = ts
				seen <- ts
			}
		}(w)
	}
	wg.Wait()
	close(seen)
	got := map[int64]bool{}
	for ts := range seen {
		if got[ts] {
			t.Fatalf("timestamp %d handed out twice", ts)
		}
		got[ts] = true
	}
}
