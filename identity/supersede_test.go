package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
)

// Replay post-pass (A2A-DESIGN §3.6, review item C4a).
//
// A key is retired by the first rot or dip after the state that introduced it, whatever ixn or drt
// events sit in between. The earlier post-pass compared each state only with the event directly
// after it, so in icp → drt → rot the icp state stayed active: a signature by the retired key,
// declaring key_state_seq 0, verified at any msgTime. These tests pin the per-state result of
// Replay and the accept/reject outcome of VerifyObject on both sides of the retirement time.

// fixedHostKey is a deterministic delegated key so the drt event does not depend on the run.
func fixedHostKey() ed25519.PublicKey {
	seed := sha256.Sum256([]byte("anet-test/supersede/host"))
	return ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
}

// appendIxn appends an ixn event signed by the current key. Controller has no method for ixn;
// this builds the event the way Delegate builds drt, carrying the pre-rotation commitment forward
// so a later Rotate still passes the pre-rotation gate.
func appendIxn(t *testing.T, c *Controller, ts uint64) {
	t.Helper()
	last := c.kel[len(c.kel)-1]
	ixn := KeyEvent{
		AID:        c.aid,
		Seq:        last.Event.Seq + 1,
		Prev:       last.EventID,
		Type:       Interaction,
		Keys:       [][]byte{c.cur.Public().(ed25519.PublicKey)},
		NextDigest: nextDigest(c.nxt.Public().(ed25519.PublicKey)),
		Threshold:  1,
		Timestamp:  ts,
	}
	pre, err := preimage(ixn)
	if err != nil {
		t.Fatal(err)
	}
	id, err := anetcid.Sum(pre)
	if err != nil {
		t.Fatal(err)
	}
	c.kel = append(c.kel, SignedEvent{Event: ixn, Sig: ed25519.Sign(c.cur, pre), EventID: id})
}

type wantState struct {
	status       string
	supersededAt uint64
}

func checkStates(t *testing.T, kel []SignedEvent, want []wantState) {
	t.Helper()
	states, err := Replay(kel)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(states) != len(want) {
		t.Fatalf("states = %d, want %d", len(states), len(want))
	}
	for i, w := range want {
		if states[i].Status != w.status || states[i].SupersededAt != w.supersededAt {
			t.Errorf("state %d = {%s, SupersededAt %d}, want {%s, SupersededAt %d}",
				i, states[i].Status, states[i].SupersededAt, w.status, w.supersededAt)
		}
	}
}

// signedAt is an object signed by the controller at its current key_state_seq.
type signedAt struct {
	seq uint64
	pre []byte
	sig []byte
}

func signNow(c *Controller, label string) signedAt {
	pre := []byte("object signed at " + label)
	sig, seq := c.Sign(pre)
	return signedAt{seq: seq, pre: pre, sig: sig}
}

// expectAccept and expectRevoked assert the VerifyObject outcome for one object at one msgTime.
func expectAccept(t *testing.T, c *Controller, o signedAt, msgTime uint64) {
	t.Helper()
	if err := VerifyObject(c.KEL(), c.AID(), o.seq, msgTime, o.pre, o.sig); err != nil {
		t.Errorf("seq %d at msgTime %d must be accepted: %v", o.seq, msgTime, err)
	}
}

func expectRevoked(t *testing.T, c *Controller, o signedAt, msgTime uint64) {
	t.Helper()
	err := VerifyObject(c.KEL(), c.AID(), o.seq, msgTime, o.pre, o.sig)
	var ve *VErr
	if !errors.As(err, &ve) || ve.Reason != "REVOKED_KEY" {
		t.Errorf("seq %d at msgTime %d must be REVOKED_KEY, got %v", o.seq, msgTime, err)
	}
}

func TestReplaySupersededIcpDrtRot(t *testing.T) {
	c := SuiteController()
	o0 := signNow(c, "seq 0")
	if err := c.Delegate(fixedHostKey(), 1000); err != nil {
		t.Fatal(err)
	}
	o1 := signNow(c, "seq 1")
	if err := c.Rotate(5000); err != nil {
		t.Fatal(err)
	}
	o2 := signNow(c, "seq 2")

	// SupersededAt is the rot's timestamp for both earlier states, not the drt's.
	checkStates(t, c.KEL(), []wantState{
		{StatusRotated, 5000},
		{StatusRotated, 5000},
		{StatusActive, 0},
	})
	for _, o := range []signedAt{o0, o1} {
		expectAccept(t, c, o, 1)
		expectAccept(t, c, o, 4999)
		expectRevoked(t, c, o, 5000)
		expectRevoked(t, c, o, 6000)
		// msgTime 0 keeps the documented conservative fallback: only the terminal dip seq is refused.
		expectAccept(t, c, o, 0)
	}
	expectAccept(t, c, o2, 6000)
}

func TestReplaySupersededIcpDrtDip(t *testing.T) {
	c := SuiteController()
	o0 := signNow(c, "seq 0")
	if err := c.Delegate(fixedHostKey(), 1000); err != nil {
		t.Fatal(err)
	}
	o1 := signNow(c, "seq 1")
	if err := c.Deactivate(8000); err != nil {
		t.Fatal(err)
	}
	// An object claiming the dip's own seq. The key is the same, so the signature is valid; the
	// revocation gate is what refuses it.
	pre := []byte("object signed after deactivation")
	oDip := signedAt{seq: 2, pre: pre, sig: ed25519.Sign(c.cur, pre)}

	checkStates(t, c.KEL(), []wantState{
		{StatusRotated, 8000},
		{StatusRotated, 8000},
		{StatusDeactivated, 0},
	})
	for _, o := range []signedAt{o0, o1} {
		expectAccept(t, c, o, 7999)
		expectRevoked(t, c, o, 8000)
		expectRevoked(t, c, o, 9000)
	}
	expectRevoked(t, c, oDip, 7999)
	expectRevoked(t, c, oDip, 9000)
	if err := VerifyObject(c.KEL(), c.AID(), oDip.seq, 0, oDip.pre, oDip.sig); err == nil {
		t.Error("the terminal dip seq must be refused at msgTime 0 as well")
	}
}

// ixn and drt between a state and its retiring rot are both skipped, and each state is retired by
// the nearest rot after it, not by a later one.
func TestReplaySupersededSkipsIxnAndDrtAcrossTwoRotations(t *testing.T) {
	c := SuiteController()
	appendIxn(t, c, 500)                                     // seq 1
	if err := c.Delegate(fixedHostKey(), 1000); err != nil { // seq 2
		t.Fatal(err)
	}
	if err := c.Rotate(5000); err != nil { // seq 3
		t.Fatal(err)
	}
	appendIxn(t, c, 6000)                  // seq 4
	if err := c.Rotate(9000); err != nil { // seq 5
		t.Fatal(err)
	}
	appendIxn(t, c, 9500) // seq 6
	checkStates(t, c.KEL(), []wantState{
		{StatusRotated, 5000},
		{StatusRotated, 5000},
		{StatusRotated, 5000},
		{StatusRotated, 9000},
		{StatusRotated, 9000},
		{StatusActive, 0},
		{StatusActive, 0},
	})
}

// A retiring event without a timestamp still retires the key. No grace window can be established,
// so every timed object claiming a retired seq is refused.
func TestReplaySupersededUntimestampedRotStillRetires(t *testing.T) {
	c := SuiteController()
	o0 := signNow(c, "seq 0")
	if err := c.Delegate(fixedHostKey(), 1000); err != nil {
		t.Fatal(err)
	}
	o1 := signNow(c, "seq 1")
	if err := c.Rotate(0); err != nil {
		t.Fatal(err)
	}
	checkStates(t, c.KEL(), []wantState{
		{StatusRotated, 0},
		{StatusRotated, 0},
		{StatusActive, 0},
	})
	for _, o := range []signedAt{o0, o1} {
		expectRevoked(t, c, o, 1)
		expectRevoked(t, c, o, 999)
	}
}
