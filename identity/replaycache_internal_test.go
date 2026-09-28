package identity

import (
	"crypto/ed25519"
	"reflect"
	"testing"
)

// withReplayCache installs c for the test and puts back what was there.
func withReplayCache(t *testing.T, c *ReplayCache) {
	t.Helper()
	prev := SetReplayCache(c)
	t.Cleanup(func() { SetReplayCache(prev) })
}

// testKELs are KELs of each shape Replay handles, and one that does not replay.
func testKELs(t *testing.T) map[string][]SignedEvent {
	t.Helper()
	host, _, _ := ed25519.GenerateKey(nil)
	mk := func(steps ...func(c *Controller) error) []SignedEvent {
		c, err := Incept()
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range steps {
			if err := s(c); err != nil {
				t.Fatal(err)
			}
		}
		return c.KEL()
	}
	drt := func(c *Controller) error { return c.Delegate(host, 1000) }
	rot := func(c *Controller) error { return c.Rotate(2000) }
	dip := func(c *Controller) error { return c.Deactivate(3000) }
	many := make([]func(c *Controller) error, 40)
	for i := range many {
		many[i] = drt
		if i%7 == 3 {
			many[i] = rot
		}
	}
	broken := mk(drt, rot)
	broken = append([]SignedEvent(nil), broken...)
	broken[1].Sig = append([]byte(nil), broken[1].Sig...)
	broken[1].Sig[0] ^= 1
	return map[string][]SignedEvent{
		"icp": mk(), "icp drt rot drt": mk(drt, rot, drt), "icp rot dip": mk(rot, dip),
		"40 drt and rot": mk(many...), "a drt signature flipped": broken,
	}
}

// With a cache installed, Replay answers each KEL, the first time and every
// time after, exactly as it does without one [redteam:F36].
func TestAReplayCacheAnswersAsReplay(t *testing.T) {
	c := NewReplayCache(1 << 20)
	withReplayCache(t, c)
	for name, kel := range testKELs(t) {
		want, wantErr := replay(kel)
		for i := 0; i < 3; i++ {
			got, err := Replay(kel)
			if (err == nil) != (wantErr == nil) || err != nil && err.Error() != wantErr.Error() {
				t.Fatalf("%s, replay %d: error %v, want %v", name, i, err, wantErr)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s, replay %d: states differ from an uncached replay", name, i)
			}
		}
	}
	if hits, misses := c.Stats(); misses != 5 || hits != 10 {
		t.Fatalf("5 KELs replayed 3 times each: %d hits, %d misses; want 10 and 5", hits, misses)
	}
}

// The cache is keyed by every byte of the KEL: a KEL that differs from one
// the cache holds in a single signature bit, or in any event field, is not
// answered with the other's states.
func TestAReplayCacheIsNotFooledByAKELThatDiffers(t *testing.T) {
	withReplayCache(t, NewReplayCache(1<<20))
	c, err := Incept()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Rotate(2000); err != nil {
		t.Fatal(err)
	}
	genuine := c.KEL()
	if _, err := Replay(genuine); err != nil {
		t.Fatal(err)
	}
	flipSig := append([]SignedEvent(nil), genuine...)
	flipSig[1].Sig = append([]byte(nil), flipSig[1].Sig...)
	flipSig[1].Sig[5] ^= 1
	if _, err := Replay(flipSig); err == nil {
		t.Fatal("a KEL with a forged rot signature replayed from the cache of the genuine one")
	}
	otherTS := append([]SignedEvent(nil), genuine...)
	otherTS[1].Event.Timestamp++
	if _, err := Replay(otherTS); err == nil {
		t.Fatal("a KEL with an altered rot replayed from the cache of the genuine one")
	}
	// The event id is not in any preimage; a KEL that carries another one
	// is another key, and replays on its own.
	otherID := append([]SignedEvent(nil), genuine...)
	otherID[1].EventID = "not-the-id"
	got, err := Replay(otherID)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := replay(otherID)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("a KEL with another event id was answered with states it does not replay to")
	}
}

// What Replay returns from the cache is the caller's: changing a state, or
// appending to its delegated keys, changes nothing the next caller sees.
func TestAReplayCacheHandsOutCopies(t *testing.T) {
	withReplayCache(t, NewReplayCache(1<<20))
	kel := testKELs(t)["icp drt rot drt"]
	want, _ := replay(kel)
	first, _ := Replay(kel)
	second, _ := Replay(kel)
	second[0].Status = StatusDeactivated
	second[1].DelegatedKeys = append(second[1].DelegatedKeys, []byte("x"))
	second[3].CurrentKeys = nil
	third, _ := Replay(kel)
	if !reflect.DeepEqual(third, want) || !reflect.DeepEqual(first, want) {
		t.Fatal("a caller's change to its states reached the cache")
	}
}

// The cache stays under its bound, forgets the least recently used KEL
// first, and holds a KEL of many delegations in space linear in its length
// (Replay's own result is quadratic in it).
func TestAReplayCacheIsBounded(t *testing.T) {
	kels := testKELs(t)
	long := kels["40 drt and rot"]
	states, _ := replay(long)
	_, cost, ok := compactStates(states)
	if !ok {
		t.Fatal("Replay's states did not compact")
	}
	if per := cost / len(states); per > 512 {
		t.Fatalf("a 41-event KEL costs %d bytes a state in the cache", per)
	}

	c := NewReplayCache(3 * (cost + 256))
	withReplayCache(t, c)
	var three [][]SignedEvent
	for i := 0; i < 3; i++ {
		k, err := Incept()
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 40; j++ {
			if err := k.Rotate(uint64(j + 1)); err != nil {
				t.Fatal(err)
			}
		}
		three = append(three, k.KEL())
	}
	for _, k := range three {
		Replay(k)
	}
	Replay(three[0]) // most recently used
	Replay(long)     // evicts three[1], the least recently used
	if c.bytes > c.max {
		t.Fatalf("cache holds %d bytes, bound %d", c.bytes, c.max)
	}
	_, before := c.Stats()
	Replay(three[0])
	if _, after := c.Stats(); after != before {
		t.Fatal("the most recently used KEL was evicted")
	}
	Replay(three[1])
	if _, after := c.Stats(); after != before+1 {
		t.Fatal("the least recently used KEL was not the one evicted")
	}
}
