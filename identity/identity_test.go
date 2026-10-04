package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
)

func TestInceptionAndReplay(t *testing.T) {
	c, err := testIncept()
	if err != nil {
		t.Fatal(err)
	}
	if c.AID() == "" || c.DID() != "did:anet:"+c.AID() {
		t.Fatalf("bad AID/DID: %q / %q", c.AID(), c.DID())
	}
	states, err := Replay(c.KEL())
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(states) != 1 || states[0].KeyStateSeq != 0 || states[0].Status != StatusActive {
		t.Fatalf("bad icp state: %+v", states[0])
	}
	if states[0].AID != c.AID() {
		t.Fatalf("AID mismatch: %s vs %s", states[0].AID, c.AID())
	}
}

// AID is stable across rotation; key_state_seq increments; current key changes.
func TestRotationStableAID(t *testing.T) {
	c, _ := testIncept()
	aid0 := c.AID()
	firstKey := append([]byte(nil), c.cur.Public().(ed25519.PublicKey)...)
	if err := testRotate(c, 1000); err != nil {
		t.Fatal(err)
	}
	if err := testRotate(c, 2000); err != nil {
		t.Fatal(err)
	}
	if c.AID() != aid0 {
		t.Fatalf("AID changed across rotation: %s -> %s", aid0, c.AID())
	}
	states, err := Replay(c.KEL())
	if err != nil {
		t.Fatalf("replay after rotation: %v", err)
	}
	if len(states) != 3 {
		t.Fatalf("want 3 states, got %d", len(states))
	}
	for i, s := range states {
		if uint64(i) != s.KeyStateSeq {
			t.Fatalf("state %d has seq %d", i, s.KeyStateSeq)
		}
		if s.AID != aid0 {
			t.Fatalf("state %d AID drift", i)
		}
	}
	if bytes.Equal(states[2].CurrentKeys[0], firstKey) {
		t.Fatal("current key did not change after rotation")
	}
}

// Object signed under current key verifies at its key_state_seq, before and after rotation.
// A KEL survives Marshal→Unmarshal byte round-trips: the rebuilt KEL re-derives the same AID +
// key-states and still verifies objects signed across a rotation (the basis for persisting/wiring
// member KELs, e.g. org-central restart resume).
func TestKELMarshalRoundTrip(t *testing.T) {
	c, _ := testIncept()
	pre0 := []byte("object-at-seq-0")
	sig0, seq0 := c.Sign(pre0)
	if err := testRotate(c, 5000); err != nil {
		t.Fatal(err)
	}
	pre1 := []byte("object-at-seq-1")
	sig1, seq1 := c.Sign(pre1)

	raw, err := MarshalKEL(c.KEL())
	if err != nil {
		t.Fatalf("marshal kel: %v", err)
	}
	kel2, err := UnmarshalKEL(raw)
	if err != nil {
		t.Fatalf("unmarshal kel: %v", err)
	}
	if len(kel2) != len(c.KEL()) {
		t.Fatalf("round-trip kel len %d, want %d", len(kel2), len(c.KEL()))
	}
	// the rebuilt KEL replays to the same AID + key-state count.
	states, err := Replay(kel2)
	if err != nil {
		t.Fatalf("replay round-tripped kel: %v", err)
	}
	if len(states) != 2 {
		t.Fatalf("round-tripped kel states = %d, want 2", len(states))
	}
	// and it still verifies objects signed by the controller, before and after rotation.
	if err := VerifyObject(kel2, c.AID(), seq0, 4999, pre0, sig0); err != nil {
		t.Fatalf("verify seq0 via round-tripped kel: %v", err)
	}
	if err := VerifyObject(kel2, c.AID(), seq1, 6000, pre1, sig1); err != nil {
		t.Fatalf("verify seq1 via round-tripped kel: %v", err)
	}
}

// A Controller survives Export→Restore (durable daemon identity): the restored controller has the
// same AID, can still Sign verifiably, and can Rotate — even after a prior rotation.
func TestControllerExportRestore(t *testing.T) {
	c, _ := testIncept()
	if err := testRotate(c, 1000); err != nil { // export a controller that has rotated once
		t.Fatal(err)
	}
	blob, err := c.Export()
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	r, err := Restore(blob)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if r.AID() != c.AID() {
		t.Fatalf("restored AID %s != %s", r.AID(), c.AID())
	}
	// restored controller signs verifiably at the current key state.
	pre := []byte("after restore")
	sig, seq := r.Sign(pre)
	if err := VerifyObject(r.KEL(), r.AID(), seq, 2000, pre, sig); err != nil {
		t.Fatalf("restored controller sign/verify: %v", err)
	}
	// and it can still rotate (the KEL's commitment was restored).
	if err := testRotate(r, 3000); err != nil {
		t.Fatalf("restored controller rotate: %v", err)
	}
	if r.CurrentSeq() != 2 {
		t.Fatalf("after restore+rotate seq = %d, want 2", r.CurrentSeq())
	}

	// corruption is rejected (not silently accepted).
	if _, err := Restore([]byte("garbage")); err == nil {
		t.Fatal("Restore must reject garbage")
	}
}

// Restore rejects a tampered hot key (which would silently brick the first rotation), and restores
// a deactivated identity as deactivated: it cannot build another event.
func TestRestoreRejectsCorruptHotKeyAndKeepsDeactivated(t *testing.T) {
	c, _ := testIncept()
	blob, err := c.Export()
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseIdentityFile(blob)
	if err != nil {
		t.Fatal(err)
	}
	f.HotNext[0] ^= 0xff // corrupt the key the icp committed
	bad, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(bad); !errors.Is(err, ErrIdentityFileInconsistent) {
		t.Fatalf("Restore must reject a corrupt hot_next (mismatched pre-rotation commitment): %v", err)
	}

	c2, _ := testIncept()
	if err := testDeactivate(c2, 1000); err != nil {
		t.Fatal(err)
	}
	db, err := c2.Export()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Restore(db)
	if err != nil {
		t.Fatalf("a deactivated identity restores as deactivated: %v", err)
	}
	if r.State() != StateDeactivated {
		t.Fatalf("state %q", r.State())
	}
	if _, err := r.BuildRotation(nil, make([]byte, 32), "", false, 2000); err == nil {
		t.Fatal("a deactivated identity built a rot")
	}
}

func TestSignVerifyAcrossRotation(t *testing.T) {
	c, _ := testIncept()
	pre0 := []byte("object-at-seq-0")
	sig0, seq0 := c.Sign(pre0)
	if err := VerifyObject(c.KEL(), c.AID(), seq0, 0, pre0, sig0); err != nil {
		t.Fatalf("verify at seq0: %v", err)
	}
	// rotate at t=5000.
	if err := testRotate(c, 5000); err != nil {
		t.Fatal(err)
	}
	pre1 := []byte("object-at-seq-1")
	sig1, seq1 := c.Sign(pre1)
	if seq1 != 1 {
		t.Fatalf("want seq1=1, got %d", seq1)
	}
	if err := VerifyObject(c.KEL(), c.AID(), seq1, 6000, pre1, sig1); err != nil {
		t.Fatalf("verify at seq1: %v", err)
	}
	// Unknown time: an object of the retired seq0 key that carries no time cannot be shown to
	// predate the rotation, so it is REVOKED_KEY (KEL C-10).
	if err := VerifyObject(c.KEL(), c.AID(), seq0, 0, pre0, sig0); err == nil {
		t.Fatal("seq0 object with msgTime 0 after rotation must be REVOKED_KEY")
	}
	// time-aware grace: an object time-stamped BEFORE the rotation (t=4999 < 5000) is honored.
	if err := VerifyObject(c.KEL(), c.AID(), seq0, 4999, pre0, sig0); err != nil {
		t.Fatalf("time-aware grace verify at seq0 (msgTime<rot) : %v", err)
	}
	// time-aware revocation (M5.1.3): an object claiming the OLD seq0 key but time-stamped
	// AT/AFTER the rotation (t>=5000) is REVOKED_KEY — the key was already retired.
	err := VerifyObject(c.KEL(), c.AID(), seq0, 5000, pre0, sig0)
	if err == nil {
		t.Fatal("object at retired key after rotation time must be REVOKED_KEY")
	}
	if ve, ok := err.(*VErr); !ok || ve.Reason != "REVOKED_KEY" {
		t.Fatalf("want REVOKED_KEY, got %v", err)
	}
}

// Pre-rotation: a stolen CURRENT key cannot rotate to an attacker-chosen key, because the next key
// was pre-committed only as a digest, and cannot rotate to the committed key either, because a rot
// is signed by the key it reveals (KEL R-3).
func TestPreRotationTheftPrevented(t *testing.T) {
	c, _ := testIncept()
	last := c.kel[len(c.kel)-1]
	rot := func(revealed ed25519.PublicKey, signer ed25519.PrivateKey) []SignedEvent {
		_, nxt, _ := ed25519.GenerateKey(nil)
		e := KeyEvent{KELType: KELType, AID: c.aid, Seq: 1, Prev: last.EventID, Type: Rotation,
			Keys: [][]byte{revealed}, NextDigest: nextDigest(nxt.Public().(ed25519.PublicKey)),
			Threshold: 1, Timestamp: 1000, Toad: ToadField(ToadHub)}
		pre, _ := preimage(e)
		id, _ := anetcid.Sum(pre)
		return append(append([]SignedEvent(nil), c.KEL()...), SignedEvent{Event: e, Sig: ed25519.Sign(signer, pre), EventID: id})
	}

	// Gate 1 — the digest: the attacker holds the current key but not the committed next key, and
	// rotates to a key of its own. The revealed key fails the pre-committed digest.
	_, attacker, _ := ed25519.GenerateKey(nil)
	err := Replay2Err(rot(attacker.Public().(ed25519.PublicKey), c.cur))
	if err == nil || !contains(err.Error(), "pre-committed digest") {
		t.Fatalf("want the pre-committed-digest rejection, got: %v", err)
	}

	// Gate 2 — the signer: the rot reveals the correct committed key (so gate 1 passes) but is
	// signed by the stolen current key, as a v0.2 rot was. It must still be rejected.
	err = Replay2Err(rot(c.hot.Public().(ed25519.PublicKey), c.cur))
	if err == nil || !contains(err.Error(), "not signed by the key it reveals") {
		t.Fatalf("want the revealed-key signature rejection, got: %v", err)
	}
	// And the owner, who holds the committed key, can.
	if err := Replay2Err(rot(c.hot.Public().(ed25519.PublicKey), c.hot)); err != nil {
		t.Fatalf("the owner's rot: %v", err)
	}
}

// Replay2Err is a tiny helper returning only the error from Replay (test readability).
func Replay2Err(kel []SignedEvent) error { _, err := Replay(kel); return err }

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Deactivation terminates the AID; an object at the terminal seq is REVOKED_KEY.
func TestDeactivation(t *testing.T) {
	c, _ := testIncept()
	pre := []byte("final-object")
	sig, seq := c.Sign(pre)
	if err := testDeactivate(c, 8000); err != nil { // dip at t=8000
		t.Fatal(err)
	}
	states, err := Replay(c.KEL())
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if states[len(states)-1].Status != StatusDeactivated {
		t.Fatalf("want deactivated, got %s", states[len(states)-1].Status)
	}
	if err := testRotate(c, 9000); err == nil {
		t.Fatal("rotate after deactivation should fail")
	}
	// An object of seq0 that carries no time cannot be shown to predate the dip (KEL C-10).
	if err := VerifyObject(c.KEL(), c.AID(), seq, 0, pre, sig); err == nil {
		t.Fatal("seq0 object with msgTime 0 after deactivation must be REVOKED_KEY")
	}
	// time-aware grace: the seq0 object time-stamped before the dip (t<8000) is honored.
	if err := VerifyObject(c.KEL(), c.AID(), seq, 7999, pre, sig); err != nil {
		t.Fatalf("time-aware grace of pre-deactivation object: %v", err)
	}
	// time-aware revocation: the seq0 key time-stamped at/after the dip is REVOKED_KEY.
	if err := VerifyObject(c.KEL(), c.AID(), seq, 8000, pre, sig); err == nil {
		t.Fatal("seq0 object at/after deactivation time should be REVOKED_KEY")
	}
	dipSeq := states[len(states)-1].KeyStateSeq
	dipPre := []byte("post-mortem")
	dipSig := ed25519.Sign(c.cur, dipPre)
	// object claiming the terminal (deactivation) seq is REVOKED_KEY, both unknown-time and timed.
	if err := VerifyObject(c.KEL(), c.AID(), dipSeq, 0, dipPre, dipSig); err == nil {
		t.Fatal("object at deactivated seq (msgTime=0) should be REVOKED_KEY")
	}
	if err := VerifyObject(c.KEL(), c.AID(), dipSeq, 9000, dipPre, dipSig); err == nil {
		t.Fatal("object at deactivated seq (timed) should be REVOKED_KEY")
	}
}

func TestTamperAndWrongAID(t *testing.T) {
	c, _ := testIncept()
	pre := []byte("x")
	sig, seq := c.Sign(pre)
	if err := VerifyObject(c.KEL(), "did-not-this", seq, 0, pre, sig); err == nil {
		t.Fatal("wrong AID should fail")
	}
	if err := VerifyObject(c.KEL(), c.AID(), seq, 0, []byte("tampered"), sig); err == nil {
		t.Fatal("tampered preimage should fail")
	}
}
