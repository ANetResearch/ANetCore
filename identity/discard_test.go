package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

// KEL D-14a: a witness designation the hub refused for good never reached a KEL anyone accepted,
// so the controller drops it and goes back to signing with the icp's key; the hot key stays, and a
// designation of another hub can be built. Every other pending event may have been accepted and
// is not dropped.
func TestDiscardPendingDropsOnlyARefusedWitnessDesignation(t *testing.T) {
	a, err := InceptAgent(1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.DiscardPending(); !errors.Is(err, ErrNothingPending) {
		t.Fatalf("DiscardPending with nothing pending: %v", err)
	}
	icpSeq := a.CurrentSeq()
	sigBefore, _ := a.Sign([]byte("x"))
	if _, err := a.BuildWitnessDesignation(SuiteController().AID(), testNewNext(), 2000); err != nil {
		t.Fatal(err)
	}
	if a.CurrentSeq() != icpSeq+1 {
		t.Fatal("the designation did not switch the signer")
	}
	if err := a.DiscardPending(); err != nil {
		t.Fatalf("DiscardPending of a witness designation: %v", err)
	}
	if _, ok := a.Pending(); ok || len(a.KEL()) != 1 || a.CurrentSeq() != icpSeq {
		t.Fatal("the designation was not dropped")
	}
	if sig, seq := a.Sign([]byte("x")); seq != icpSeq || !bytes.Equal(sig, sigBefore) {
		t.Fatal("the controller does not sign with the icp's key again")
	}
	b, err := a.Export()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Restore(b)
	if err != nil {
		t.Fatalf("the file after a discard does not restore: %v", err)
	}
	if _, ok := r.Pending(); ok {
		t.Fatal("the file after a discard holds a pending event")
	}
	// Another hub can be designated now, with the same hot key.
	other, err := InceptHub(1000)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := a.BuildWitnessDesignation(other.AID(), testNewNext(), 3000)
	if err != nil {
		t.Fatalf("a designation of another hub after the discard: %v", err)
	}
	if err := a.Adopt(ev); err != nil {
		t.Fatal(err)
	}
	if err := a.DiscardPending(); !errors.Is(err, ErrNothingPending) {
		t.Fatalf("DiscardPending after Adopt: %v", err)
	}

	// A rot (planned or emergency) and a dip are never discarded: a witness may hold them.
	seed := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	c, err := InceptAgent(1000)
	if err != nil {
		t.Fatal(err)
	}
	ev, err = c.BuildWitnessDesignation(SuiteController().AID(), nextDigest(publicOf(seed)), 2000)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Adopt(ev); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BuildRotation(seed, testNewNext(), SuiteController().AID(), false, 3000); err != nil {
		t.Fatal(err)
	}
	if err := c.DiscardPending(); !errors.Is(err, ErrDiscardRefused) {
		t.Fatalf("DiscardPending of a rot: %v", err)
	}
	if _, ok := c.Pending(); !ok {
		t.Fatal("a refused discard dropped the rot")
	}
	d, err := InceptAgent(1000)
	if err != nil {
		t.Fatal(err)
	}
	ev, err = d.BuildWitnessDesignation(SuiteController().AID(), nextDigest(publicOf(seed)), 2000)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Adopt(ev); err != nil {
		t.Fatal(err)
	}
	if _, err := d.BuildDeactivation(seed, 3000); err != nil {
		t.Fatal(err)
	}
	if err := d.DiscardPending(); !errors.Is(err, ErrDiscardRefused) {
		t.Fatalf("DiscardPending of a dip: %v", err)
	}
}
