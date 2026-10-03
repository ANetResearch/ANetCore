package identity_test

import (
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
)

// An object signed by a key that was later rotated away is honored only if it can be established to
// predate the retirement: every event carries a ts after the previous one's (KEL R-1, R-2), so a
// rotation always has a retirement time, and an object is honored only when its own time is before
// it (KEL C-10).
func TestRotationGate(t *testing.T) {
	obj := []byte("an object")

	// (1) A rotation without a time, or not after the previous event, is not built.
	c, _ := identity.Incept()
	if err := c.Rotate(0); err == nil {
		t.Fatal("a rotation at ts 0 was built")
	}
	if err := c.Rotate(c.KEL()[0].Event.Timestamp); err == nil {
		t.Fatal("a rotation at the icp's ts was built")
	}

	// (2) The grace window: honored before the rotation's ts, rejected at/after it and when the
	// object carries no time.
	c2, _ := identity.Incept()
	s0, q0 := c2.Sign(obj)
	if err := c2.Rotate(5000); err != nil {
		t.Fatal(err)
	}
	if err := identity.VerifyObject(c2.KEL(), c2.AID(), q0, 4000, obj, s0); err != nil {
		t.Fatalf("object bound before retirement must be honored: %v", err)
	}
	if err := identity.VerifyObject(c2.KEL(), c2.AID(), q0, 6000, obj, s0); err == nil {
		t.Fatal("object bound at/after retirement must be REJECTED")
	}
	if err := identity.VerifyObject(c2.KEL(), c2.AID(), q0, 0, obj, s0); err == nil {
		t.Fatal("object of a retired key with no time must be REJECTED")
	}

	// (3) The CURRENT key still verifies normally.
	cs, cq := c2.Sign(obj)
	if err := identity.VerifyObject(c2.KEL(), c2.AID(), cq, 7000, obj, cs); err != nil {
		t.Fatalf("current key must verify: %v", err)
	}
}
