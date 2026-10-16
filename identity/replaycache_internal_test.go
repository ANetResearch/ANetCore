package identity

import (
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
	mk := func(steps ...func(c *Controller, ts uint64) error) []SignedEvent {
		c, err := testIncept()
		if err != nil {
			t.Fatal(err)
		}
		for i, s := range steps {
			if err := s(c, uint64(i+1)*1000); err != nil {
				t.Fatal(err)
			}
		}
		return c.KEL()
	}
	rot := func(c *Controller, ts uint64) error { return testRotate(c, ts) }
	dip := func(c *Controller, ts uint64) error { return testDeactivate(c, ts) }
	many := make([]func(c *Controller, ts uint64) error, 40)
	for i := range many {
		many[i] = rot
	}
	broken := mk(rot, rot)
	broken = append([]SignedEvent(nil), broken...)
	broken[1].Sig = append([]byte(nil), broken[1].Sig...)
	broken[1].Sig[0] ^= 1
	return map[string][]SignedEvent{
		"icp": mk(), "icp rot rot": mk(rot, rot), "icp rot dip": mk(rot, dip),
		"40 rot": mk(many...), "a rot signature flipped": broken,
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
	c, err := testIncept()
	if err != nil {
		t.Fatal(err)
	}
	if err := testRotate(c, 2000); err != nil {
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
	// is another key, and is refused on its own (the id must be the
	// event's CID).
	otherID := append([]SignedEvent(nil), genuine...)
	otherID[1].EventID = "not-the-id"
	if _, err := Replay(otherID); err == nil {
		t.Fatal("a KEL with another event id replayed from the cache of the genuine one")
	}
}

// What Replay returns from the cache is the caller's: changing a state
// changes nothing the next caller sees.
func TestAReplayCacheHandsOutCopies(t *testing.T) {
	withReplayCache(t, NewReplayCache(1<<20))
	kel := testKELs(t)["icp rot rot"]
	want, _ := replay(kel)
	first, _ := Replay(kel)
	second, _ := Replay(kel)
	second[0].Status = StatusDeactivated
	second[1].Witness = "x"
	second[2].CurrentKeys = nil
	third, _ := Replay(kel)
	if !reflect.DeepEqual(third, want) || !reflect.DeepEqual(first, want) {
		t.Fatal("a caller's change to its states reached the cache")
	}
}

// The cache stays under its bound, forgets the least recently used KEL
// first, and holds a long KEL in space linear in its length.
func TestAReplayCacheIsBounded(t *testing.T) {
	kels := testKELs(t)
	long := kels["40 rot"]
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
		k, err := testIncept()
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 40; j++ {
			if err := testRotate(k, uint64(j+2)); err != nil {
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
