package a2acard

import "testing"

func TestCheckHighWaterBranches(t *testing.T) {
	h1 := [32]byte{1}
	h2 := [32]byte{2}
	stored := &Mark{Seq: 10, PayloadHash: h1}
	cases := []struct {
		name   string
		stored *Mark
		next   Mark
		want   Decision
		code   Code
	}{
		{"first sight", nil, Mark{Seq: 0, PayloadHash: h2}, Advance, ""},
		{"higher seq", stored, Mark{Seq: 11, PayloadHash: h2}, Advance, ""},
		{"higher seq, same payload hash", stored, Mark{Seq: 11, PayloadHash: h1}, Advance, ""},
		{"equal seq, same payload", stored, Mark{Seq: 10, PayloadHash: h1}, Same, ""},
		{"equal seq, different payload", stored, Mark{Seq: 10, PayloadHash: h2}, 0, CodeSeqFork},
		{"lower seq", stored, Mark{Seq: 9, PayloadHash: h1}, 0, CodeSeqRollback},
		{"lower seq to zero", stored, Mark{Seq: 0, PayloadHash: h1}, 0, CodeSeqRollback},
	}
	for _, tc := range cases {
		d, err := CheckHighWater(tc.stored, tc.next)
		if tc.code != "" {
			if !IsCode(err, tc.code) {
				t.Errorf("%s: err %v, want %s", tc.name, err, tc.code)
			}
			continue
		}
		if err != nil || d != tc.want {
			t.Errorf("%s: got %v, %v; want %v", tc.name, d, err, tc.want)
		}
	}
}

// End to end with real cards: re-fetching an unchanged card is Same even when it was re-signed
// under a rotated key; a new card with the same seq is a fork; an older card is a rollback.
func TestCheckHighWaterWithVerifiedCards(t *testing.T) {
	c := incept(t)
	card := baseCard(c.AID())
	first, err := Verify(signCard(t, card, c), newResolver(c).resolve, t0)
	if err != nil {
		t.Fatal(err)
	}
	stored := first.Mark()

	if err := c.Rotate(t0); err != nil {
		t.Fatal(err)
	}
	resigned, err := Verify(signCard(t, card, c), newResolver(c).resolve, t0)
	if err != nil {
		t.Fatal(err)
	}
	if resigned.KeyStateSeq != 1 {
		t.Fatalf("re-signed card KeyStateSeq = %d, want 1", resigned.KeyStateSeq)
	}
	if d, err := CheckHighWater(&stored, resigned.Mark()); err != nil || d != Same {
		t.Fatalf("re-signed unchanged card: %v, %v; want same", d, err)
	}

	forked := baseCard(c.AID())
	forked["name"] = "Changed Name"
	fv, err := Verify(signCard(t, forked, c), newResolver(c).resolve, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckHighWater(&stored, fv.Mark()); !IsCode(err, CodeSeqFork) {
		t.Fatalf("same seq, changed payload: err %v, want %s", err, CodeSeqFork)
	}

	newer := baseCard(c.AID())
	newer["name"] = "Changed Name"
	params(newer)["seq"] = dec(t0 + 1)
	nv, err := Verify(signCard(t, newer, c), newResolver(c).resolve, t0)
	if err != nil {
		t.Fatal(err)
	}
	if d, err := CheckHighWater(&stored, nv.Mark()); err != nil || d != Advance {
		t.Fatalf("higher seq: %v, %v; want advance", d, err)
	}
	advanced := nv.Mark()
	if _, err := CheckHighWater(&advanced, first.Mark()); !IsCode(err, CodeSeqRollback) {
		t.Fatalf("replayed older card: err %v, want %s", err, CodeSeqRollback)
	}
}

func TestDecisionString(t *testing.T) {
	if Advance.String() != "advance" || Same.String() != "same" || Decision(0).String() != "Decision(0)" {
		t.Fatalf("%s %s %s", Advance, Same, Decision(0))
	}
}
