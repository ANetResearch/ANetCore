package identity

import (
	"errors"
	"testing"
)

// ExtendsKEL (A2A-DESIGN §3.8) decides whether a peer's KEL may replace the one a verifier stored.
// The three outcomes the caller acts on differently are: accept (nil), rollback (keep the stored
// KEL; the candidate re-enables retired keys) and fork (keep the stored KEL; the peer published two
// histories). Each case below asserts which one, and that the other sentinel is not also matched.

func cloneKEL(k []SignedEvent) []SignedEvent { return append([]SignedEvent(nil), k...) }

func TestExtendsKELAcceptsEqualAndLonger(t *testing.T) {
	c := SuiteController()
	short := cloneKEL(c.KEL())
	if err := c.Delegate(fixedHostKey(), 1000); err != nil {
		t.Fatal(err)
	}
	if err := c.Rotate(2000); err != nil {
		t.Fatal(err)
	}
	long := cloneKEL(c.KEL())

	if err := ExtendsKEL(long, long); err != nil {
		t.Errorf("an identical KEL must be accepted: %v", err)
	}
	if err := ExtendsKEL(short, long); err != nil {
		t.Errorf("a KEL that appends events must be accepted: %v", err)
	}
	if err := ExtendsKEL(nil, long); err != nil {
		t.Errorf("with nothing stored, any KEL that replays must be accepted: %v", err)
	}
}

func TestExtendsKELRejectsRollback(t *testing.T) {
	c := SuiteController()
	if err := c.Rotate(1000); err != nil {
		t.Fatal(err)
	}
	stored := cloneKEL(c.KEL())
	// The icp alone is a valid KEL; offered after the rotation it would make the retired
	// inception key current again.
	err := ExtendsKEL(stored, stored[:1])
	if !errors.Is(err, ErrKELRollback) {
		t.Fatalf("a strict prefix must be reported as rollback, got %v", err)
	}
	if errors.Is(err, ErrKELFork) {
		t.Error("a rollback must not also be reported as a fork")
	}
}

func TestExtendsKELRejectsFork(t *testing.T) {
	// Two controllers built from the same seeds share the inception event and then diverge.
	a := SuiteController()
	b := SuiteController()
	if err := a.Rotate(1000); err != nil {
		t.Fatal(err)
	}
	if err := a.Delegate(fixedHostKey(), 1500); err != nil {
		t.Fatal(err)
	}
	if err := b.Delegate(fixedHostKey(), 2000); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		stored, got []SignedEvent
	}{
		// Same length, different event at seq 1.
		{"diverges at seq 1, same length", a.KEL()[:2], b.KEL()},
		// The candidate is also shorter; the divergence is the finding reported.
		{"diverges and is shorter", a.KEL(), b.KEL()},
		// The candidate is longer, but not an extension of what is stored.
		{"diverges and is longer", b.KEL(), a.KEL()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ExtendsKEL(tc.stored, tc.got)
			if !errors.Is(err, ErrKELFork) {
				t.Fatalf("want ErrKELFork, got %v", err)
			}
			if errors.Is(err, ErrKELRollback) {
				t.Error("a fork must not also be reported as a rollback")
			}
		})
	}

	// A different identity differs at seq 0.
	other, err := Incept()
	if err != nil {
		t.Fatal(err)
	}
	if err := ExtendsKEL(a.KEL(), other.KEL()); !errors.Is(err, ErrKELFork) {
		t.Errorf("a KEL of another AID must be reported as a fork, got %v", err)
	}
}

func TestExtendsKELRequiresCandidateToReplay(t *testing.T) {
	c := SuiteController()
	if err := c.Rotate(1000); err != nil {
		t.Fatal(err)
	}
	stored := cloneKEL(c.KEL()[:1])
	bad := cloneKEL(c.KEL())
	sig := append([]byte(nil), bad[1].Sig...)
	sig[0] ^= 0xff
	bad[1].Sig = sig
	err := ExtendsKEL(stored, bad)
	if err == nil {
		t.Fatal("a candidate whose rot signature is invalid must be refused")
	}
	if errors.Is(err, ErrKELFork) || errors.Is(err, ErrKELRollback) {
		t.Errorf("an invalid candidate is neither a fork nor a rollback: %v", err)
	}
	if err := ExtendsKEL(nil, nil); err == nil {
		t.Error("an empty candidate does not replay and must be refused")
	}
}

// Events are compared by preimage. A stored copy whose EventID string or signature bytes differ
// from the candidate's describes the same key events: Replay derives linkage from preimages and
// checks the candidate's signatures itself, so neither field is part of the history.
func TestExtendsKELComparesPreimagesNotWrapperBytes(t *testing.T) {
	c := SuiteController()
	if err := c.Rotate(1000); err != nil {
		t.Fatal(err)
	}
	next := cloneKEL(c.KEL())
	stored := cloneKEL(next)
	stored[1].EventID = "bafy-not-the-real-id"
	stored[1].Sig = make([]byte, 64)
	if err := ExtendsKEL(stored, next); err != nil {
		t.Errorf("stored copy with the same preimages must be accepted: %v", err)
	}
}
