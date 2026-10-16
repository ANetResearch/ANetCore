package identity

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// FuzzRestoreIdentityFile feeds bytes to Restore, the decoder of the identity file v2 (KEL C-25).
// Restore must never panic, and a file it takes must give a controller that is consistent with
// itself: its KEL replays, it signs verifiably under that KEL with the key it holds, and its own
// Export restores to the same bytes again (a fixed point after one round).
//
// The seeds are files of every shape a controller writes, from fixed keys.
func FuzzRestoreIdentityFile(f *testing.F) {
	w := SuiteController().AID()
	digest := func(i byte) []byte { return nextDigest(fuzzPub(i)) }
	add := func(c *Controller) {
		b, err := c.Export()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	must := func(err error) {
		if err != nil {
			f.Fatal(err)
		}
	}
	hub, err := inceptWith(fuzzKeys[0], fuzzKeys[1], 1000, ToadHub)
	must(err)
	add(hub)
	ev, err := hub.BuildRotation(nil, digest(2), "", false, 2000)
	must(err)
	add(hub)
	must(hub.Adopt(ev))
	ev, err = hub.BuildDeactivation(fuzzKeys[2], 3000)
	must(err)
	add(hub)
	must(hub.Adopt(ev))
	must(hub.SetState(StateDeactivated))
	add(hub)

	a, err := inceptWith(fuzzKeys[4], fuzzKeys[5], 1000, ToadAgent)
	must(err)
	add(a)
	must(a.SetLocalCommit(digest(6)))
	ev, err = a.BuildWitnessDesignation(w, digest(6), 2000)
	must(err)
	must(a.SetPendingHubURL("https://w1.example"))
	add(a)
	must(a.Adopt(ev))
	add(a)
	_, err = a.BuildRotation(fuzzKeys[6], digest(7), testOtherHub, true, 3000)
	must(err)
	must(a.SetWitnessesToPush([]WitnessPush{{HubAID: w, HubURL: "https://w1.example", AckedSeq: 1, NextTry: 4000}}))
	add(a)
	must(a.SetState(StateStopped))
	add(a)

	// a recover file: no current key, the material of an emergency rot without its event
	kel, err := MarshalKEL(a.Accepted())
	must(err)
	rec := &IdentityFile{T: IdentityFileType, KEL: kel, State: StateOK,
		Pending: &Pending{Kind: PendingRot, Revealed: fuzzKeys[6].Seed(), Next: digest(7), HubURL: "https://w1.example", Emergency: true, Since: 3000}}
	b, err := rec.Marshal()
	must(err)
	f.Add(b)

	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := Restore(b)
		if err != nil {
			return
		}
		kel := c.KEL()
		states, err := Replay(kel)
		if err != nil {
			t.Fatalf("a restored controller's KEL does not replay: %v", err)
		}
		pre := []byte("fuzz")
		sig, seq := c.Sign(pre)
		if seq != kel[len(kel)-1].Event.Seq {
			t.Fatalf("signs at %d, its KEL ends at %d", seq, kel[len(kel)-1].Event.Seq)
		}
		if sig != nil && states[seq].Status != StatusDeactivated && !ed25519.Verify(states[seq].CurrentKeys[0], pre, sig) {
			t.Fatal("a restored controller signs with a key its KEL does not name")
		}
		once, err := c.Export()
		if err != nil {
			t.Fatalf("export of a restored controller: %v", err)
		}
		r, err := Restore(once)
		if err != nil {
			t.Fatalf("a restored controller's export does not restore: %v", err)
		}
		twice, err := r.Export()
		if err != nil || !bytes.Equal(once, twice) {
			t.Fatalf("export is not a fixed point: %v", err)
		}
	})
}
