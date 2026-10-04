package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/coredet"
)

// ---- C-5: inception ------------------------------------------------------------------------------

// InceptAgent and InceptHub make icps of the witness mode they name, with the time given, naming
// no witness and committing a hot key the controller holds and nobody else knows.
func TestInceptAgentAndHub(t *testing.T) {
	for _, tc := range []struct {
		name   string
		incept func(uint64) (*Controller, error)
		toad   uint64
	}{{"agent", InceptAgent, ToadAgent}, {"hub", InceptHub, ToadHub}} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.incept(1767225600000)
			if err != nil {
				t.Fatal(err)
			}
			icp := c.KEL()[0].Event
			if *icp.Toad != tc.toad || c.Toad() != tc.toad || len(icp.Witnesses) != 0 || icp.Timestamp != 1767225600000 {
				t.Fatalf("icp %+v", icp)
			}
			states, err := Replay(c.KEL())
			if err != nil || states[0].Witness != "" || states[0].Toad != tc.toad {
				t.Fatalf("replay %v %+v", err, states)
			}
			if c.State() != StateOK || len(c.KEL()) != 1 || c.CurrentSeq() != 0 {
				t.Fatalf("state %q, %d events, seq %d", c.State(), len(c.KEL()), c.CurrentSeq())
			}
			f := exportFile(t, c)
			if !bytes.Equal(nextDigest(publicOf(ed25519.NewKeyFromSeed(f.HotNext))), icp.NextDigest) {
				t.Fatal("the hot key in the file is not the one the icp commits")
			}
			if bytes.Equal(f.Cur, f.HotNext) {
				t.Fatal("k0 and k1 are the same key")
			}
			other, _ := tc.incept(1767225600000)
			if other.AID() == c.AID() || bytes.Equal(exportFile(t, other).HotNext, f.HotNext) {
				t.Fatal("two inceptions share keys")
			}
			if _, err := tc.incept(0); err == nil {
				t.Fatal("an icp at ts 0")
			}
		})
	}
}

// The conformance identities (C-5): the hub identity is the one every golden vector is anchored
// to (VEC_SUITE_IDENTITY_1); the agent identity has the same keys and toad 1. Both AIDs were
// computed independently from the seeds by golden/py/gen_v016.py's KEL writer.
func TestSuiteIdentities(t *testing.T) {
	for _, tc := range []struct {
		c    *Controller
		toad uint64
		aid  string
	}{
		{SuiteController(), ToadHub, "bafyreihq42j7esljj5drxgieudh2ar4gsspogpejmdxmg4nezfa3twdmke"},
		{SuiteAgentController(), ToadAgent, "bafyreigsnw3xcu3x746e6mozdw2vmkbaf3f2ouvuzhk5arsg65jem5glaq"},
	} {
		if tc.c.AID() != tc.aid || tc.c.Toad() != tc.toad {
			t.Fatalf("suite identity toad %d: AID %s, want %s", tc.toad, tc.c.AID(), tc.aid)
		}
		icp := tc.c.KEL()[0].Event
		if icp.Timestamp != SuiteInceptionTS || len(icp.Witnesses) != 0 {
			t.Fatalf("suite icp %+v", icp)
		}
		if _, err := Replay(tc.c.KEL()); err != nil {
			t.Fatal(err)
		}
	}
	// a fresh one per call: rotating one does not move the next
	a := SuiteAgentController()
	if _, err := a.BuildWitnessDesignation(SuiteController().AID(), testNewNext(), SuiteInceptionTS+1); err != nil {
		t.Fatal(err)
	}
	if len(SuiteAgentController().KEL()) != 1 {
		t.Fatal("SuiteAgentController shares state between calls")
	}
}

// ---- C-21: state transitions -----------------------------------------------------------------

// The events the controller builds are KEL v2 events: rot and dip signed by the key they reveal,
// at a ts after the previous event's, none after the dip.
func TestControllerBuildsV2Events(t *testing.T) {
	c, err := testIncept()
	if err != nil {
		t.Fatal(err)
	}
	if err := testRotate(c, 1); err == nil {
		t.Fatal("a rot at the icp's ts was built")
	}
	if c.CurrentSeq() != 0 || len(c.KEL()) != 1 {
		t.Fatal("a refused rot changed the controller")
	}
	if err := testRotate(c, 2000); err != nil {
		t.Fatal(err)
	}
	if err := testRotate(c, 3000); err != nil {
		t.Fatal(err)
	}
	if err := testDeactivate(c, 4000); err != nil {
		t.Fatal(err)
	}
	states, err := replayBytes(mustMarshal(t, c.KEL()))
	if err != nil {
		t.Fatalf("the controller's KEL: %v", err)
	}
	if got := states[len(states)-1].Status; got != StatusDeactivated {
		t.Fatalf("head %s", got)
	}
	if !states[2].RetiredUrgently || states[1].RetiredUrgently {
		t.Fatalf("urgency %v %v", states[1].RetiredUrgently, states[2].RetiredUrgently)
	}
	if err := testRotate(c, 5000); err == nil {
		t.Fatal("rotated after the dip")
	}
	// the emergency flag reaches key 12
	e, _ := testIncept()
	if err := testRotateWith(e, 2000, true); err != nil {
		t.Fatal(err)
	}
	if !e.KEL()[1].Event.Emergency {
		t.Fatal("an emergency rot without key 12")
	}
}

// A revealed key whose digest is not the one the KEL committed is ErrRecoveryMismatch, and the
// controller is left as it was (C-21).
func TestBuildChecksTheRevealedKey(t *testing.T) {
	c, _ := testIncept()
	if err := testRotate(c, 2000); err != nil {
		t.Fatal(err)
	}
	before := c.KEL()
	_, wrong, _ := ed25519.GenerateKey(nil)
	if _, err := c.BuildRotation(wrong, testNewNext(), "", false, 3000); !errors.Is(err, ErrRecoveryMismatch) {
		t.Fatalf("rot revealing another key: %v", err)
	}
	if _, err := c.BuildDeactivation(wrong, 3000); !errors.Is(err, ErrRecoveryMismatch) {
		t.Fatalf("dip revealing another key: %v", err)
	}
	if _, err := c.BuildRotation(wrong[:10], testNewNext(), "", false, 3000); err == nil {
		t.Fatal("a 10-byte private key was taken")
	}
	// the hot key is spent once the first rot is adopted: nil reveals nothing any more
	if _, err := c.BuildRotation(nil, testNewNext(), "", false, 3000); err == nil {
		t.Fatal("nil revealed the hot key after the first rotation")
	}
	k, _ := testNextKey(c)
	if _, err := c.BuildRotation(k, []byte("short"), "", false, 3000); err == nil {
		t.Fatal("a next digest of 5 bytes")
	}
	if _, ok := c.Pending(); ok || c.CurrentSeq() != 1 || !kelEqual(c.KEL(), before) {
		t.Fatal("a refused build changed the controller")
	}
}

// Build* switches the signer at once to the revealed key and the new seq, and KEL() carries the
// pending event; Adopt makes it accepted; until then Accepted() does not have it (C-21).
func TestBuildSwitchesTheSignerAtOnce(t *testing.T) {
	c, _ := InceptAgent(1000)
	witness := SuiteController().AID()
	next := testNewNext()
	ev, err := c.BuildWitnessDesignation(witness, next, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event.Seq != 1 || ev.Event.Type != Rotation || len(ev.Event.Witnesses) != 1 || ev.Event.Witnesses[0] != witness ||
		*ev.Event.Toad != ToadAgent || !bytes.Equal(ev.Event.NextDigest, next) || ev.Event.Emergency {
		t.Fatalf("witness designation %+v", ev.Event)
	}
	if len(c.Accepted()) != 1 || len(c.KEL()) != 2 || c.CurrentSeq() != 1 {
		t.Fatalf("accepted %d, KEL %d, seq %d", len(c.Accepted()), len(c.KEL()), c.CurrentSeq())
	}
	pre := []byte("signed while publishing")
	sig, seq := c.Sign(pre)
	if seq != 1 || VerifyObject(c.KEL(), c.AID(), 1, 2500, pre, sig) != nil {
		t.Fatal("the controller does not sign with the revealed key while the event is pending")
	}
	p, ok := c.Pending()
	if !ok || p.Kind != PendingWitness || p.Revealed != nil || !bytes.Equal(p.Next, next) || p.Since != 2000 {
		t.Fatalf("pending %+v", p)
	}
	if err := c.SetPendingHubURL("https://hub.example"); err != nil {
		t.Fatal(err)
	}
	if err := c.Adopt(ev); err != nil {
		t.Fatal(err)
	}
	if len(c.Accepted()) != 2 || c.CurrentSeq() != 1 || c.hot != nil {
		t.Fatal("Adopt did not make the event accepted and drop the hot key")
	}
	if _, ok := c.Pending(); ok {
		t.Fatal("still pending after Adopt")
	}
	if exportFile(t, c).HotNext != nil {
		t.Fatal("hot_next exported after the first rotation")
	}
	// the next rot reveals the key the designation committed and keeps the witness
	k, _ := testNextKey(c)
	if _, err := c.BuildRotation(k, testNewNext(), "", false, 3000); err == nil {
		t.Fatal("an agent rot without its witness was built")
	}
	if _, err := c.BuildRotation(k, testNewNext(), witness, false, 3000); err != nil {
		t.Fatal(err)
	}
}

// Only an agent with its icp alone designates a witness, once, naming one.
func TestWitnessDesignationRules(t *testing.T) {
	hub, _ := testIncept()
	if _, err := hub.BuildWitnessDesignation(SuiteController().AID(), testNewNext(), 2000); err == nil {
		t.Fatal("a hub identity designated a witness")
	}
	if _, err := hub.BuildRotation(nil, testNewNext(), SuiteController().AID(), false, 2000); err == nil {
		t.Fatal("a hub rot named a witness")
	}
	a, _ := InceptAgent(1000)
	if _, err := a.BuildWitnessDesignation("", testNewNext(), 2000); err == nil {
		t.Fatal("a witness designation naming no hub")
	}
	if _, err := a.BuildWitnessDesignation(a.AID(), testNewNext(), 2000); err == nil {
		t.Fatal("an agent named itself its witness")
	}
	// the hot key of an agent is revealed by its witness designation and in no other way (C-31):
	// a rot that reveals it, even naming a witness, is not built
	for _, emergency := range []bool{false, true} {
		if _, err := a.BuildRotation(nil, testNewNext(), SuiteController().AID(), emergency, 2000); err == nil {
			t.Fatalf("an agent revealed its hot key in a rot (emergency %v), not in its witness designation", emergency)
		}
	}
	if _, ok := a.Pending(); ok || len(a.KEL()) != 1 {
		t.Fatal("a refused rot left the agent with a pending event")
	}
	ev, err := a.BuildWitnessDesignation(SuiteController().AID(), testNewNext(), 2000)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Adopt(ev); err != nil {
		t.Fatal(err)
	}
	if _, err := a.BuildWitnessDesignation(SuiteController().AID(), testNewNext(), 3000); err == nil {
		t.Fatal("a second witness designation")
	}
}

// Only an identity in state ok builds events (C-21, KEL D-30, D-40): a stopped identity was
// rotated or recovered elsewhere and a deactivated one is over, so neither reveals a key, and the
// pending event of one that stopped meanwhile is not rebuilt either. The refusals change nothing.
func TestTransitionsNeedStateOK(t *testing.T) {
	for _, state := range []string{StateStopped, StateDeactivated} {
		t.Run(state, func(t *testing.T) {
			c, _ := testIncept()
			if err := testRotate(c, 2000); err != nil {
				t.Fatal(err)
			}
			k, _ := testNextKey(c)
			before := mustExport(t, c)
			if err := c.SetState(state); err != nil {
				t.Fatal(err)
			}
			if _, err := c.BuildRotation(k, testNewNext(), "", false, 3000); err == nil {
				t.Fatal("rot built")
			}
			if _, err := c.BuildRotation(k, testNewNext(), "", true, 3000); err == nil {
				t.Fatal("emergency rot built")
			}
			if _, err := c.BuildDeactivation(k, 3000); err == nil {
				t.Fatal("dip built")
			}
			if err := c.SetState(StateOK); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(mustExport(t, c), before) {
				t.Fatal("a refused build changed the controller")
			}
			// a rot built while ok, then the identity stops: Restamp does not rebuild it
			if _, err := c.BuildRotation(k, testNewNext(), "", false, 3000); err != nil {
				t.Fatal(err)
			}
			if err := c.SetState(state); err != nil {
				t.Fatal(err)
			}
			pending := mustExport(t, c)
			if _, err := c.Restamp(4000); err == nil {
				t.Fatal("restamped the pending event of an identity that is not ok")
			}
			if !bytes.Equal(mustExport(t, c), pending) {
				t.Fatal("a refused Restamp changed the controller")
			}
		})
	}
	// an agent that never designated a witness, stopped: its hot key stays unrevealed
	a, _ := InceptAgent(1000)
	if err := a.SetState(StateStopped); err != nil {
		t.Fatal(err)
	}
	if _, err := a.BuildWitnessDesignation(SuiteController().AID(), testNewNext(), 2000); err == nil {
		t.Fatal("a stopped agent designated a witness")
	}
}

// One event at a time: a second build is ErrEventPending, Adopt takes only the pending event's
// bytes, and nothing is adopted when nothing is pending.
func TestOneEventAtATime(t *testing.T) {
	c, _ := testIncept()
	if err := c.Adopt(c.KEL()[0]); !errors.Is(err, ErrNothingPending) {
		t.Fatalf("Adopt with nothing pending: %v", err)
	}
	if _, err := c.Restamp(5000); !errors.Is(err, ErrNothingPending) {
		t.Fatalf("Restamp with nothing pending: %v", err)
	}
	if err := c.SetPendingHubURL("x"); !errors.Is(err, ErrNothingPending) {
		t.Fatalf("SetPendingHubURL with nothing pending: %v", err)
	}
	ev, err := c.BuildRotation(nil, testNewNext(), "", false, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.BuildDeactivation(nil, 3000); !errors.Is(err, ErrEventPending) {
		t.Fatalf("a dip while a rot is pending: %v", err)
	}
	other := ev
	other.Sig = append([]byte(nil), ev.Sig...)
	other.Sig[0] ^= 1
	if err := c.Adopt(other); err == nil {
		t.Fatal("adopted an event that is not the pending one")
	}
	if err := c.Adopt(ev); err != nil {
		t.Fatal(err)
	}
}

// Restamp rebuilds the pending event at a new ts from the same material (D-36); the old bytes are
// no longer adoptable.
func TestRestampRebuildsTheSameEventAtANewTime(t *testing.T) {
	c, _ := InceptAgent(1000)
	w := SuiteController().AID()
	first, err := c.BuildWitnessDesignation(w, testNewNext(), 2000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Restamp(1000); err == nil {
		t.Fatal("restamped to the icp's ts")
	}
	again, err := c.Restamp(9000)
	if err != nil {
		t.Fatal(err)
	}
	a, b := first.Event, again.Event
	if b.Timestamp != 9000 || a.Seq != b.Seq || !bytes.Equal(a.Keys[0], b.Keys[0]) || !bytes.Equal(a.NextDigest, b.NextDigest) ||
		b.Witnesses[0] != w || b.Emergency != a.Emergency || again.EventID == first.EventID {
		t.Fatalf("restamped %+v from %+v", b, a)
	}
	if p, _ := c.Pending(); p.Since != 2000 || p.Kind != PendingWitness {
		t.Fatalf("restamp changed the pending material: %+v", p)
	}
	if err := c.Adopt(first); err == nil {
		t.Fatal("adopted the bytes Restamp replaced")
	}
	if err := c.Adopt(again); err != nil {
		t.Fatal(err)
	}
	// an emergency rot keeps its flag
	k, _ := testNextKey(c)
	if _, err := c.BuildRotation(k, testNewNext(), w, true, 10000); err != nil {
		t.Fatal(err)
	}
	if ev, err := c.Restamp(11000); err != nil || !ev.Event.Emergency || ev.Event.Witnesses[0] != w {
		t.Fatalf("restamped emergency rot %+v %v", ev.Event, err)
	}
}

// ---- C-22: snapshots ---------------------------------------------------------------------------

// A snapshot keeps its key state when the controller rotates under it: it signs with the key of its
// seq, and its KEL names that key at that seq. Controller.Sign is Snapshot().Sign.
func TestSnapshotIsImmutable(t *testing.T) {
	c, _ := testIncept()
	s0 := c.Snapshot()
	pre := []byte("x")
	if a, aq := c.Sign(pre); true {
		b, bq := s0.Sign(pre)
		if !bytes.Equal(a, b) || aq != bq {
			t.Fatal("Controller.Sign is not Snapshot().Sign")
		}
	}
	ev, err := c.BuildRotation(nil, testNewNext(), "", false, 2000)
	if err != nil {
		t.Fatal(err)
	}
	s1 := c.Snapshot() // taken while the rot is pending
	if err := c.Adopt(ev); err != nil {
		t.Fatal(err)
	}
	if err := testRotate(c, 3000); err != nil {
		t.Fatal(err)
	}
	for i, s := range []Signer{s0, s1} {
		sig, seq := s.Sign(pre)
		got, err := SeqOf(s)
		if err != nil || seq != uint64(i) || got != seq || len(s.KEL()) != i+1 || s.AID() != c.AID() {
			t.Fatalf("snapshot %d: seq %d, SeqOf %d %v, KEL %d", i, seq, got, err, len(s.KEL()))
		}
		if err := VerifyObject(s.KEL(), s.AID(), seq, 1500, pre, sig); err != nil {
			t.Fatalf("snapshot %d against its own KEL: %v", i, err)
		}
		if err := VerifyObject(c.KEL(), c.AID(), seq, 1500, pre, sig); err != nil {
			t.Fatalf("snapshot %d against the KEL that rotated it away (before the rotation): %v", i, err)
		}
	}
	// a caller appending to a snapshot's KEL does not write into the snapshot
	k := s1.KEL()
	_ = append(k, SignedEvent{})
	if len(s1.KEL()) != 2 || s1.KEL()[1].EventID != ev.EventID {
		t.Fatal("the snapshot's KEL changed")
	}
	// SnapshotOf: of a controller a snapshot, of a snapshot itself
	if _, ok := SnapshotOf(c).(*snapshot); !ok || SnapshotOf(s0) != s0 {
		t.Fatal("SnapshotOf")
	}
}

// P4 (KEL §7.2): Sign, Snapshot, BuildRotation and Adopt run concurrently for 1000 rounds (50
// identities rotated 20 times each). Every (sig, seq) a signer reports verifies under the key the
// final KEL gives seq, and every snapshot is consistent with itself. Run under -race.
func TestConcurrentSignSnapshotRotateAdopt(t *testing.T) {
	const identities, rounds = 50, 20
	type signed struct {
		pre, sig []byte
		seq      uint64
	}
	for n := 0; n < identities; n++ {
		c, _ := testIncept()
		var mu sync.Mutex
		var made []signed
		record := func(s signed) { mu.Lock(); made = append(made, s); mu.Unlock() }
		for r := 0; r < rounds; r++ {
			var wg sync.WaitGroup
			wg.Add(3)
			go func() { // rotate: build, then adopt
				defer wg.Done()
				k, err := testNextKey(c)
				if err != nil {
					t.Error(err)
					return
				}
				ev, err := c.BuildRotation(k, testNewNext(), "", r%5 == 4, uint64(1000*(r+2)))
				if err != nil {
					t.Error(err)
					return
				}
				if err := c.Adopt(ev); err != nil {
					t.Error(err)
				}
			}()
			go func() { // sign through the controller
				defer wg.Done()
				for i := 0; i < 4; i++ {
					pre := []byte(fmt.Sprintf("c %d %d %d", n, r, i))
					sig, seq := c.Sign(pre)
					record(signed{pre, sig, seq})
				}
			}()
			go func() { // sign through snapshots
				defer wg.Done()
				for i := 0; i < 4; i++ {
					s := c.Snapshot()
					pre := []byte(fmt.Sprintf("s %d %d %d", n, r, i))
					sig, seq := s.Sign(pre)
					want, err := SeqOf(s)
					if err != nil || want != seq {
						t.Errorf("snapshot signs at %d, its KEL ends at %d", seq, want)
					}
					// the key that signed is the one the snapshot's KEL names at seq (a full
					// VerifyObject, which replays, once a round)
					if kel := s.KEL(); !ed25519.Verify(kel[seq].Event.Keys[0], pre, sig) {
						t.Errorf("snapshot not consistent with itself at seq %d", seq)
					}
					if i == 0 {
						if err := VerifyObject(s.KEL(), s.AID(), seq, 0, pre, sig); err != nil {
							t.Errorf("snapshot not consistent with itself: %v", err)
						}
					}
					record(signed{pre, sig, seq})
				}
			}()
			wg.Wait()
		}
		states, err := Replay(c.KEL())
		if err != nil {
			t.Fatal(err)
		}
		if len(states) != rounds+1 {
			t.Fatalf("%d states after %d rotations", len(states), rounds)
		}
		for _, s := range made {
			if s.seq >= uint64(len(states)) || !ed25519.Verify(states[s.seq].CurrentKeys[0], s.pre, s.sig) {
				t.Fatalf("a signature reported at seq %d does not verify under that seq's key", s.seq)
			}
		}
	}
}

// ---- C-25: identity file v2 --------------------------------------------------------------------

func exportFile(t *testing.T, c *Controller) *IdentityFile {
	t.Helper()
	b, err := c.Export()
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseIdentityFile(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func marshalFile(t *testing.T, f *IdentityFile) []byte {
	t.Helper()
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func kelEqual(a, b []SignedEvent) bool {
	x, _ := coredet.Marshal(a)
	y, _ := coredet.Marshal(b)
	return bytes.Equal(x, y)
}

// sameController says whether r is c as far as the file goes: Export gives the same bytes.
func sameController(t *testing.T, c, r *Controller) {
	t.Helper()
	a, err := c.Export()
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Export()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("restored controller exports other bytes:\n%x\n%x", a, b)
	}
}

// Export then Restore gives the same controller, in every state the file can hold: just incepted
// (hot key), a witness designation pending, adopted, a rot pending under its hub URL, with
// local_commit and witnesses to push, stopped, deactivated.
func TestExportRestoreRoundTrip(t *testing.T) {
	c, _ := InceptAgent(1000)
	check := func(what string) *Controller {
		t.Helper()
		b, err := c.Export()
		if err != nil {
			t.Fatal(err)
		}
		r, err := Restore(b)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		sameController(t, c, r)
		if r.AID() != c.AID() || r.CurrentSeq() != c.CurrentSeq() || !kelEqual(r.KEL(), c.KEL()) {
			t.Fatalf("%s: restored controller differs", what)
		}
		pre := []byte(what)
		sig, seq := r.Sign(pre)
		// nothing signed under a dip verifies (its state has no key), pending or adopted
		if kel := r.KEL(); kel[len(kel)-1].Event.Type != Deactivation {
			if err := VerifyObject(r.KEL(), r.AID(), seq, 0, pre, sig); err != nil {
				t.Fatalf("%s: restored controller signs unverifiably: %v", what, err)
			}
		}
		return r
	}
	check("incepted")
	if err := c.SetLocalCommit(testNewNext()); err != nil {
		t.Fatal(err)
	}
	w := SuiteController().AID()
	ev, err := c.BuildWitnessDesignation(w, testNewNext(), 2000)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetPendingHubURL("https://w1.example"); err != nil {
		t.Fatal(err)
	}
	r := check("witness designation pending")
	// a crash here: the restored controller adopts the same bytes (KEL D-35)
	if err := r.Adopt(ev); err != nil {
		t.Fatalf("restored controller cannot adopt its pending event: %v", err)
	}
	if err := c.Adopt(ev); err != nil {
		t.Fatal(err)
	}
	check("adopted")
	k, _ := testNextKey(c)
	if _, err := c.BuildRotation(k, testNewNext(), "bafyreiotherhub", true, 3000); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPendingHubURL("https://w2.example"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetWitnessesToPush([]WitnessPush{{HubAID: w, HubURL: "https://w1.example", AckedSeq: 2, NextTry: 4000}}); err != nil {
		t.Fatal(err)
	}
	check("emergency hub switch pending")
	if err := c.SetState(StateStopped); err != nil {
		t.Fatal(err)
	}
	check("stopped")
	if err := c.SetState(StateOK); err != nil {
		t.Fatal(err)
	}
	p, _ := c.Pending()
	evb := p.Event
	var ev2 SignedEvent
	if err := coredet.Unmarshal(evb, &ev2); err != nil {
		t.Fatal(err)
	}
	if err := c.Adopt(ev2); err != nil {
		t.Fatal(err)
	}
	k, _ = testNextKey(c)
	dip, err := c.BuildDeactivation(k, 5000)
	if err != nil {
		t.Fatal(err)
	}
	check("dip pending")
	if err := c.Adopt(dip); err != nil {
		t.Fatal(err)
	}
	if err := c.SetState(StateDeactivated); err != nil {
		t.Fatal(err)
	}
	check("deactivated")
}

// The file a recover writes (KEL D-45): the KEL as the witness has it, no current key, and the
// material of an emergency rot that has no event yet. Restore takes it; Restamp builds the rot,
// naming the head's witness; the controller signs nothing before that.
func TestRestoreARecoverFile(t *testing.T) {
	c, _ := InceptAgent(1000)
	w := SuiteController().AID()
	if err := identitytestSwitch(c, w, 2000); err != nil {
		t.Fatal(err)
	}
	k, _ := testNextKey(c)
	next := testNewNext()
	kelb := mustMarshal(t, c.Accepted())
	f := &IdentityFile{T: IdentityFileType, KEL: kelb, State: StateOK,
		Pending: &Pending{Kind: PendingRot, Revealed: k.Seed(), Next: next, HubURL: "https://w1.example", Emergency: true, Since: 3000}}
	r, err := Restore(marshalFile(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if sig, seq := r.Sign([]byte("x")); sig != nil || seq != 1 {
		t.Fatal("a recovered identity signed before its rotation was built")
	}
	// a snapshot of it holds no key either, and signs nothing (rather than failing on a nil key)
	if sig, seq := r.Snapshot().Sign([]byte("x")); sig != nil || seq != 1 {
		t.Fatal("a snapshot of a recovered identity signed before its rotation was built")
	}
	if _, err := r.BuildRotation(k, next, w, true, 3000); !errors.Is(err, ErrEventPending) {
		t.Fatalf("a second event over the recover's material: %v", err)
	}
	ev, err := r.Restamp(3000)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event.Seq != 2 || !ev.Event.Emergency || ev.Event.Witnesses[0] != w || !bytes.Equal(ev.Event.NextDigest, next) {
		t.Fatalf("recover rot %+v", ev.Event)
	}
	pre := []byte("after the recover rot is built")
	sig, seq := r.Sign(pre)
	if seq != 2 || VerifyObject(r.KEL(), r.AID(), seq, 0, pre, sig) != nil {
		t.Fatal("the recovered identity does not sign with the revealed key")
	}
	if err := r.Adopt(ev); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(mustExport(t, r)); err != nil {
		t.Fatal(err)
	}
	// without pending material, a file without a current key is refused
	f.Pending = nil
	if _, err := Restore(marshalFile(t, f)); !errors.Is(err, ErrIdentityFileInconsistent) {
		t.Fatalf("no key and nothing pending: %v", err)
	}
}

func identitytestSwitch(c *Controller, witness string, ts uint64) error {
	ev, err := c.BuildWitnessDesignation(witness, testNewNext(), ts)
	if err != nil {
		return err
	}
	return c.Adopt(ev)
}

func mustExport(t *testing.T, c *Controller) []byte {
	t.Helper()
	b, err := c.Export()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Restore refuses every file whose parts contradict each other (C-25), and anything that is not an
// identity file v2.
func TestRestoreRefusesInconsistentFiles(t *testing.T) {
	agent, _ := InceptAgent(1000)
	w := SuiteController().AID()
	pendingWitness := func() *IdentityFile {
		c, _ := InceptAgent(1000)
		if _, err := c.BuildWitnessDesignation(w, testNewNext(), 2000); err != nil {
			t.Fatal(err)
		}
		return exportFile(t, c)
	}
	rotated := func() (*Controller, *IdentityFile) {
		c, _ := InceptAgent(1000)
		if err := identitytestSwitch(c, w, 2000); err != nil {
			t.Fatal(err)
		}
		return c, exportFile(t, c)
	}
	pendingRot := func(emergency bool) *IdentityFile {
		c, _ := rotated()
		k, _ := testNextKey(c)
		if _, err := c.BuildRotation(k, testNewNext(), w, emergency, 3000); err != nil {
			t.Fatal(err)
		}
		return exportFile(t, c)
	}
	_, other := rotated()
	// recoverFile is the file a recover writes (KEL D-45): the KEL, no current key, and the material
	// of an emergency rot without its event. With wrongKey, the material reveals a key the head did
	// not commit; nothing but the digest check sees it, as there is no event to rebuild.
	recoverFile := func(wrongKey bool) *IdentityFile {
		c, f := rotated()
		k, _ := testNextKey(c)
		key := k.Seed()
		if wrongKey {
			key = other.Cur
		}
		f.Cur = nil
		f.Pending = &Pending{Kind: PendingRot, Revealed: key, Next: testNewNext(), HubURL: "https://w1.example", Emergency: true, Since: 3000}
		return f
	}
	// deactivatedWithPending is a deactivated identity with rot material that reveals the key its
	// dip revealed: that key is the one the last rot committed, so the digest check passes it.
	deactivatedWithPending := func() *IdentityFile {
		c, _ := testIncept()
		if err := testRotate(c, 2000); err != nil {
			t.Fatal(err)
		}
		k, _ := testNextKey(c)
		if err := testDeactivate(c, 3000); err != nil {
			t.Fatal(err)
		}
		f := exportFile(t, c)
		f.Pending = &Pending{Kind: PendingRot, Revealed: k.Seed(), Next: testNewNext(), Since: 4000}
		return f
	}
	// witnessEmergency is a witness designation pending with key 12, its event built to match
	// its material, so that only the rule on the material refuses it (D-13 has no emergency).
	witnessEmergency := func() *IdentityFile {
		c, _ := InceptAgent(1000)
		p := &pending{kind: PendingWitness, revealed: c.hot, next: testNewNext(), emergency: true, since: 2000}
		ev, err := c.buildEvent(p, w, 2000)
		if err != nil {
			t.Fatal(err)
		}
		f := exportFile(t, c)
		f.Pending = &Pending{Kind: PendingWitness, Revealed: c.hot.Seed(), Next: p.next, Emergency: true, Event: mustCoredet(t, ev), Since: 2000}
		return f
	}
	cases := []struct {
		name string
		f    func() *IdentityFile
		want error
	}{
		{"recover material whose key the head did not commit", func() *IdentityFile { return recoverFile(true) }, ErrIdentityFileInconsistent},
		{"an event pending after the deactivation", deactivatedWithPending, ErrIdentityFileInconsistent},
		{"a witness designation pending as an emergency", witnessEmergency, ErrIdentityFileInconsistent},
		{"an agent's first rot pending as kind rot", func() *IdentityFile { f := pendingWitness(); f.Pending.Kind = PendingRot; return f }, ErrIdentityFileInconsistent},
		{"cur is not the head's key", func() *IdentityFile { f := exportFile(t, agent); f.Cur = f.HotNext; return f }, ErrIdentityFileInconsistent},
		{"cur of another identity", func() *IdentityFile { _, f := rotated(); f.Cur = other.Cur; return f }, ErrIdentityFileInconsistent},
		{"cur is not a seed", func() *IdentityFile { f := exportFile(t, agent); f.Cur = f.Cur[:31]; return f }, ErrIdentityFileInconsistent},
		{"hot_next is not the committed key", func() *IdentityFile { f := exportFile(t, agent); f.HotNext = other.Cur; return f }, ErrIdentityFileInconsistent},
		{"hot_next kept after the first rotation", func() *IdentityFile { _, f := rotated(); f.HotNext = f.Cur; return f }, ErrIdentityFileInconsistent},
		{"pending key is not the committed one", func() *IdentityFile { f := pendingRot(false); f.Pending.Revealed = other.Cur; return f }, ErrIdentityFileInconsistent},
		{"pending event of another time", func() *IdentityFile {
			f := pendingRot(false)
			var ev SignedEvent
			coredet.Unmarshal(f.Pending.Event, &ev)
			ev.Event.Timestamp++
			f.Pending.Event, _ = coredet.Marshal(ev)
			return f
		}, ErrIdentityFileInconsistent},
		{"pending event with a flipped signature bit", func() *IdentityFile {
			f := pendingRot(false)
			var ev SignedEvent
			coredet.Unmarshal(f.Pending.Event, &ev)
			ev.Sig[5] ^= 1
			f.Pending.Event, _ = coredet.Marshal(ev)
			return f
		}, ErrIdentityFileInconsistent},
		{"pending event not emergency, material emergency", func() *IdentityFile { f := pendingRot(false); f.Pending.Emergency = true; return f }, ErrIdentityFileInconsistent},
		{"pending event emergency, material not", func() *IdentityFile { f := pendingRot(true); f.Pending.Emergency = false; return f }, ErrIdentityFileInconsistent},
		{"pending next is not the event's", func() *IdentityFile { f := pendingRot(false); f.Pending.Next = testNewNext(); return f }, ErrIdentityFileInconsistent},
		{"pending event that does not decode", func() *IdentityFile { f := pendingRot(false); f.Pending.Event = []byte{0xa0}; return f }, ErrIdentityFileInconsistent},
		{"pending kind unknown", func() *IdentityFile { f := pendingRot(false); f.Pending.Kind = "ixn"; return f }, ErrIdentityFileInconsistent},
		{"pending dip with a next key", func() *IdentityFile {
			f := pendingRot(false)
			f.Pending.Kind = PendingDip
			f.Pending.Event = nil
			return f
		}, ErrIdentityFileInconsistent},
		{"pending witness designation after the first rot", func() *IdentityFile { f := pendingRot(false); f.Pending.Kind = PendingWitness; return f }, ErrIdentityFileInconsistent},
		{"witness designation pending without its event", func() *IdentityFile { f := pendingWitness(); f.Pending.Event = nil; return f }, ErrIdentityFileInconsistent},
		{"state unknown", func() *IdentityFile { f := exportFile(t, agent); f.State = "stopped_elsewhere"; return f }, ErrIdentityFileInconsistent},
		{"local_commit of 31 bytes", func() *IdentityFile { f := exportFile(t, agent); f.LocalCommit = make([]byte, 31); return f }, ErrIdentityFileInconsistent},
		{"a witness to push without its AID", func() *IdentityFile {
			f := exportFile(t, agent)
			f.WitnessesToPush = []WitnessPush{{HubURL: "x"}}
			return f
		}, ErrIdentityFileInconsistent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Restore(marshalFile(t, tc.f()))
			if !errors.Is(err, tc.want) || !strings.HasPrefix(err.Error(), "identity: identity file inconsistent") {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	// the controls of the cases above: the same shapes with the right key, or without the one
	// contradiction, restore
	if _, err := Restore(marshalFile(t, recoverFile(false))); err != nil {
		t.Fatalf("recover material revealing the committed key: %v", err)
	}
	if f := deactivatedWithPending(); true {
		f.Pending = nil
		if _, err := Restore(marshalFile(t, f)); err != nil {
			t.Fatalf("the deactivated identity without material: %v", err)
		}
	}
	if _, err := Restore(marshalFile(t, pendingWitness())); err != nil {
		t.Fatalf("a witness designation pending as kind witness: %v", err)
	}
	// the written seed of the pending key is the one key the event may reveal; a file written
	// after switching cur to it (and so without the head's key) is still the same identity
	f := pendingRot(false)
	f.Cur = f.Pending.Revealed
	if r, err := Restore(marshalFile(t, f)); err != nil || r.CurrentSeq() != 2 {
		t.Fatalf("cur = the pending key: %v", err)
	}
	// a pending event whose KEL does not replay with it
	f = pendingRot(false)
	var ev SignedEvent
	coredet.Unmarshal(f.Pending.Event, &ev)
	f.KEL = mustMarshal(t, mustUnmarshalKEL(t, f.KEL)[:1])
	if _, err := Restore(marshalFile(t, f)); err == nil {
		t.Fatal("a pending event that does not extend the KEL")
	}
}

func mustUnmarshalKEL(t *testing.T, b []byte) []SignedEvent {
	t.Helper()
	kel, err := UnmarshalKEL(b)
	if err != nil {
		t.Fatal(err)
	}
	return kel
}

// A v0.2 identity, another file, garbage, an unregistered key or a non-canonical encoding are not
// identity files v2 (ErrNotIdentityV2 for the first ones, a decoding error for the others).
func TestRestoreRefusesWhatIsNotAnIdentityFileV2(t *testing.T) {
	// the v0.2 controller export: {1: cur seed, 2: next seed, 3: KEL}
	c, _ := testIncept()
	v02, err := coredet.Marshal(map[int]any{1: make([]byte, 32), 2: make([]byte, 32), 3: c.KEL()})
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"v0.2 identity": v02, "garbage": []byte("garbage"), "empty": nil,
		"another type tag": func() []byte { f := exportFile(t, c); f.T = "anet.identity/1"; return marshalFile(t, f) }(),
		"the mbox file":    mustCoredet(t, map[int]any{0: "anet.mbox/1", 1: 1, 2: make([]byte, 32)}),
	} {
		if _, err := Restore(b); !errors.Is(err, ErrNotIdentityV2) {
			t.Errorf("%s: %v", name, err)
		}
	}
	good := mustExport(t, c)
	var m map[int]any
	if err := coredet.Unmarshal(good, &m); err != nil {
		t.Fatal(err)
	}
	m[8] = "extra"
	if _, err := Restore(mustCoredet(t, m)); err == nil {
		t.Error("a file with key 8 was restored")
	}
	// the same file with its keys in another order: not canonical
	f := exportFile(t, c)
	type reversed struct {
		State   string `cbor:"6,keyasint"`
		HotNext []byte `cbor:"3,keyasint"`
		Cur     []byte `cbor:"2,keyasint"`
		KEL     []byte `cbor:"1,keyasint"`
		T       string `cbor:"0,keyasint"`
	}
	rev, err := cbor.Marshal(reversed{State: f.State, HotNext: f.HotNext, Cur: f.Cur, KEL: f.KEL, T: f.T})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rev, good) {
		t.Fatal("test: the reversed encoding is the canonical one")
	}
	if _, err := Restore(rev); !errors.Is(err, ErrIdentityFileInconsistent) {
		t.Errorf("a non-canonical file: %v", err)
	}
	if _, err := Restore(append([]byte(nil), good[:len(good)-1]...)); err == nil {
		t.Error("a truncated file was restored")
	}
	if _, err := Restore(append(append([]byte(nil), good...), 0x00)); err == nil {
		t.Error("a file with a trailing byte was restored")
	}
}

func mustCoredet(t *testing.T, v any) []byte {
	t.Helper()
	b, err := coredet.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The exported file holds what IdentityFile v2 says (KEL §2.9): the KEL the witness accepted
// (without the pending event, which is in key 4), the current key, the hot key only before the
// first rotation, and the state.
func TestExportWritesTheFileOfKEL29(t *testing.T) {
	c, _ := InceptAgent(1000)
	f := exportFile(t, c)
	if f.T != IdentityFileType || f.State != StateOK || f.Pending != nil || f.HotNext == nil || f.Cur == nil || f.LocalCommit != nil {
		t.Fatalf("incepted: %+v", f)
	}
	ev, err := c.BuildWitnessDesignation(SuiteController().AID(), testNewNext(), 2000)
	if err != nil {
		t.Fatal(err)
	}
	f = exportFile(t, c)
	if len(mustUnmarshalKEL(t, f.KEL)) != 1 || f.Pending == nil || f.HotNext == nil {
		t.Fatalf("pending: %+v", f)
	}
	evb, _ := coredet.Marshal(ev)
	if !bytes.Equal(f.Pending.Event, evb) || !bytes.Equal(f.Pending.Revealed, f.HotNext) || f.Pending.Kind != PendingWitness {
		t.Fatal("the pending event in the file")
	}
	// Cur stays the head's key until the witness accepts
	if !bytes.Equal(publicOf(ed25519.NewKeyFromSeed(f.Cur)), c.Accepted()[0].Event.Keys[0]) {
		t.Fatal("cur moved before Adopt")
	}
	if err := c.Adopt(ev); err != nil {
		t.Fatal(err)
	}
	f = exportFile(t, c)
	if len(mustUnmarshalKEL(t, f.KEL)) != 2 || f.Pending != nil || f.HotNext != nil ||
		!bytes.Equal(publicOf(ed25519.NewKeyFromSeed(f.Cur)), ev.Event.Keys[0]) {
		t.Fatalf("adopted: %+v", f)
	}
	sum := sha256.Sum256([]byte("x"))
	if err := c.SetLocalCommit(sum[:]); err != nil || !bytes.Equal(exportFile(t, c).LocalCommit, sum[:]) {
		t.Fatal("local_commit")
	}
	if c.SetLocalCommit(nil) == nil || c.SetState("paused") == nil || c.SetWitnessesToPush([]WitnessPush{{}}) == nil {
		t.Fatal("a setter took a value the file cannot hold")
	}
}
