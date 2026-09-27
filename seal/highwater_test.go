package seal

import "testing"

func TestDecideHighWater(t *testing.T) {
	stored := &Seen{Seq: 100, Set: []byte("set-100")}
	cases := []struct {
		name string
		seen *Seen
		seq  uint64
		set  []byte
		want Decision
	}{
		{"no record", nil, 1, []byte("x"), Replace},
		{"higher", stored, 101, []byte("set-101"), Replace},
		{"higher with the stored bytes", stored, 101, []byte("set-100"), Replace},
		{"lower", stored, 99, []byte("set-99"), Ignore},
		{"lower with the stored bytes", stored, 99, []byte("set-100"), Ignore},
		{"equal, same bytes", stored, 100, []byte("set-100"), Same},
		{"equal, different bytes", stored, 100, []byte("set-100'"), Fork},
		{"equal, empty vs stored", stored, 100, nil, Fork},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecideHighWater(tc.seen, tc.seq, tc.set); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
	for d, s := range map[Decision]string{Ignore: "ignore", Same: "same", Fork: "fork", Replace: "replace", 0: "invalid"} {
		if d.String() != s {
			t.Errorf("%d.String() = %q, want %q", d, d.String(), s)
		}
	}
}

func TestDecideHighWaterSigned(t *testing.T) {
	a := newParty(t)
	seen := &Seen{Seq: a.set.Seq, Set: a.signed.Set}
	d, err := DecideHighWaterSigned(seen, a.signed)
	if err != nil || d != Same {
		t.Fatalf("same object: %s %v", d, err)
	}
	first := a.signed
	a.resign(t, a.set.Seq+1)
	if d, _ := DecideHighWaterSigned(seen, a.signed); d != Replace {
		t.Fatalf("newer: %s", d)
	}
	seen = &Seen{Seq: a.set.Seq, Set: a.signed.Set}
	if d, _ := DecideHighWaterSigned(seen, first); d != Ignore {
		t.Fatalf("rollback: %s", d)
	}
	// Same seq, different content (a second key listed).
	kp, _ := GenerateKeyPair(SuiteX25519, t0, t0+dayMS)
	a.resign(t, a.set.Seq, kp.Public)
	if d, _ := DecideHighWaterSigned(seen, a.signed); d != Fork {
		t.Fatalf("fork: %s", d)
	}
	if _, err := DecideHighWaterSigned(seen, &SignedEncKeySet{Set: []byte{0xff}}); ReasonOf(err) != ReasonBadKeySet {
		t.Fatalf("undecodable set: %v", err)
	}
}

// The high-water mark is EncKeySet.seq (key 2 of the set), not issued_at and
// not the signer's key_state_seq (§3.1). The sets below give the three
// numbers different orders, so a decision read from the wrong one differs.
func TestDecideHighWaterSignedUsesSetSeq(t *testing.T) {
	a := newParty(t)
	// Move the signer to key_state_seq 1 so ksn is not 0.
	if err := a.c.Delegate(make([]byte, 32), t0); err != nil {
		t.Fatal(err)
	}
	sign := func(seq, issued uint64) *SignedEncKeySet {
		s, err := SignEncKeySet(&EncKeySet{Type: EncKeySetType, AID: a.aid(), Seq: seq, Keys: []EncKey{a.kp.Public}, IssuedAt: issued}, a.c.Sign)
		if err != nil {
			t.Fatal(err)
		}
		if s.KeyStateSeq != 1 {
			t.Fatalf("setup: ksn %d", s.KeyStateSeq)
		}
		return s
	}
	stored := sign(t0+100, t0+100)
	seen := &Seen{Seq: t0 + 100, Set: stored.Set}
	for _, c := range []struct {
		name string
		in   *SignedEncKeySet
		want Decision
	}{
		// Higher seq, lower issued_at: Replace.
		{"seq up, issued_at down", sign(t0+101, t0), Replace},
		// Lower seq, higher issued_at: Ignore.
		{"seq down, issued_at up", sign(t0+99, t0+500), Ignore},
		// Equal seq, different issued_at: different bytes, Fork.
		{"seq equal, issued_at differs", sign(t0+100, t0+500), Fork},
		{"stored object", stored, Same},
	} {
		d, err := DecideHighWaterSigned(seen, c.in)
		if err != nil || d != c.want {
			t.Errorf("%s: got %s (%v), want %s", c.name, d, err, c.want)
		}
	}
}
