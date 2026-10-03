package identity

import (
	"errors"
	"testing"
)

// Replay post-pass (KEL C-2). In KEL v2 every event after the icp is a rot or a dip, so state i is
// retired by event i+1 at that event's ts, urgently when the event is an emergency rot or a dip.
// These tests pin the per-state result of Replay and the accept/reject outcome of VerifyObject on
// both sides of the retirement time.

type wantState struct {
	status       string
	supersededAt uint64
	urgent       bool
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
		s := states[i]
		if s.Status != w.status || s.SupersededAt != w.supersededAt || s.RetiredUrgently != w.urgent {
			t.Errorf("state %d = {%s, SupersededAt %d, urgent %v}, want {%s, %d, %v}",
				i, s.Status, s.SupersededAt, s.RetiredUrgently, w.status, w.supersededAt, w.urgent)
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

func TestReplaySupersededRotRot(t *testing.T) {
	const t0 = SuiteInceptionTS
	c := SuiteController()
	o0 := signNow(c, "seq 0")
	if err := c.Rotate(t0 + 5000); err != nil {
		t.Fatal(err)
	}
	o1 := signNow(c, "seq 1")
	if err := c.Rotate(t0 + 9000); err != nil {
		t.Fatal(err)
	}
	o2 := signNow(c, "seq 2")
	checkStates(t, c.KEL(), []wantState{
		{StatusRotated, t0 + 5000, false},
		{StatusRotated, t0 + 9000, false},
		{StatusActive, 0, false},
	})
	expectAccept(t, c, o0, 1)
	expectAccept(t, c, o0, t0+4999)
	expectRevoked(t, c, o0, t0+5000)
	expectRevoked(t, c, o0, t0+6000)
	// msgTime 0: the object's time is unknown, so it cannot be shown to predate the rotation.
	expectRevoked(t, c, o0, 0)
	expectAccept(t, c, o1, t0+8999)
	expectRevoked(t, c, o1, t0+9000)
	expectRevoked(t, c, o1, 0)
	expectAccept(t, c, o2, 0)
	expectAccept(t, c, o2, t0+10000)
}

func TestReplaySupersededRotDip(t *testing.T) {
	const t0 = SuiteInceptionTS
	c := SuiteController()
	o0 := signNow(c, "seq 0")
	if err := c.Rotate(t0 + 1000); err != nil {
		t.Fatal(err)
	}
	o1 := signNow(c, "seq 1")
	if err := c.Deactivate(t0 + 8000); err != nil {
		t.Fatal(err)
	}
	// An object claiming the dip's own seq: the dip state holds no key, so it is refused before
	// any signature is looked at.
	oDip := signedAt{seq: 2, pre: o1.pre, sig: o1.sig}

	checkStates(t, c.KEL(), []wantState{
		{StatusRotated, t0 + 1000, false},
		{StatusRotated, t0 + 8000, true},
		{StatusDeactivated, 0, false},
	})
	expectAccept(t, c, o0, t0+999)
	expectRevoked(t, c, o0, t0+1000)
	expectAccept(t, c, o1, t0+7999)
	expectRevoked(t, c, o1, t0+8000)
	expectRevoked(t, c, o1, t0+9000)
	for _, at := range []uint64{0, t0 + 7999, t0 + 9000} {
		expectRevoked(t, c, oDip, at)
	}
}

// An emergency rot retires the state before it urgently; a planned rot does not.
func TestReplaySupersededEmergencyRot(t *testing.T) {
	kel := kel2A()
	checkStates(t, kel, []wantState{
		{StatusRotated, hubT0 + minute, false},
		{StatusRotated, hubT0 + 2*minute, true},
		{StatusRotated, hubT0 + 3*minute, true},
		{StatusDeactivated, 0, false},
	})
}
