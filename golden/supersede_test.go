// supersede_test.go pins identity.Replay's SupersededAt post-pass (A2A-DESIGN §3.6 and §17, review
// item C4a) on KELs whose bytes are fixed.
//
// identity/supersede_test.go checks the same rule on KELs built with Controller.Rotate, which draws
// a fresh next key from crypto/rand, so those KELs differ on every run. The KELs here are built
// event by event from published seeds, so a second implementation can rebuild the identical bytes
// from this file and must derive the identical state table and verification outcomes.
//
// Keys (seeds are SHA-256 of the quoted strings):
//
//	K0   "anet-suite-identity-v1/cur"          the suite identity's inception key
//	K1   "anet-suite-identity-v1/nxt"          committed by the inception, revealed by the rot
//	K2   "anet-suite-supersede-v1/next-after-rot"  committed by the rot
//	host "anet-suite-supersede-v1/host"         the key delegated by the drt
//
// VEC-KEL-SUPERSEDE-1 is icp → drt(1000) → rot(5000); VEC-KEL-SUPERSEDE-2 is icp → drt(1000) →
// dip(8000). In both, the drt does not change the signing key, so the key of state 0 and state 1
// (K0) is retired by the third event, and both states carry that event's timestamp.
//
// The pinned KEL CIDs (CIDv1 dag-cbor sha2-256 over MarshalKEL bytes) were reproduced outside this
// module by a separate deterministic-CBOR encoder in Python with the cryptography package's
// Ed25519, from the seeds above.
package golden

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

func seedKey(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(s[:])
}

func pubDigest(k ed25519.PrivateKey) []byte {
	h := sha256.Sum256(k.Public().(ed25519.PublicKey))
	return h[:]
}

// appendEvent signs e with signer, links it to the last event of kel and appends it.
func appendEvent(t *testing.T, kel []identity.SignedEvent, e identity.KeyEvent, signer ed25519.PrivateKey) []identity.SignedEvent {
	t.Helper()
	last := kel[len(kel)-1]
	e.AID = kel[0].EventID
	e.Seq = last.Event.Seq + 1
	e.Prev = last.EventID
	pre, err := coredet.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	id, err := anetcid.Sum(pre)
	if err != nil {
		t.Fatal(err)
	}
	return append(kel, identity.SignedEvent{Event: e, Sig: ed25519.Sign(signer, pre), EventID: id})
}

// supersedeKEL builds icp → drt(1000) → third, where third is a rot(5000) or a dip(8000).
func supersedeKEL(t *testing.T, third identity.EventType) (kel []identity.SignedEvent, k0 ed25519.PrivateKey) {
	t.Helper()
	k0 = seedKey("anet-suite-identity-v1/cur")
	k1 := seedKey("anet-suite-identity-v1/nxt")
	k2 := seedKey("anet-suite-supersede-v1/next-after-rot")
	host := seedKey("anet-suite-supersede-v1/host")

	kel = append([]identity.SignedEvent(nil), identity.SuiteController().KEL()...)
	if kel[0].EventID != suiteAID {
		t.Fatalf("suite inception moved: %s", kel[0].EventID)
	}
	kel = appendEvent(t, kel, identity.KeyEvent{
		Type: identity.Delegation, Keys: [][]byte{host.Public().(ed25519.PublicKey)},
		NextDigest: pubDigest(k1), Threshold: 1, Timestamp: 1000,
	}, k0)
	switch third {
	case identity.Rotation:
		kel = appendEvent(t, kel, identity.KeyEvent{
			Type: identity.Rotation, Keys: [][]byte{k1.Public().(ed25519.PublicKey)},
			NextDigest: pubDigest(k2), Threshold: 1, Timestamp: 5000,
		}, k0)
	case identity.Deactivation:
		kel = appendEvent(t, kel, identity.KeyEvent{
			Type: identity.Deactivation, Keys: [][]byte{k0.Public().(ed25519.PublicKey)},
			Threshold: 1, Timestamp: 8000,
		}, k0)
	}
	return kel, k0
}

type supersedeRow struct {
	status       string
	supersededAt uint64
}

func checkSupersede(t *testing.T, name string, kel []identity.SignedEvent, wantCID string, want []supersedeRow) {
	t.Helper()
	b, err := identity.MarshalKEL(kel)
	if err != nil {
		t.Fatal(err)
	}
	if got := anetcid.MustSum(b); got != wantCID {
		t.Errorf("%s KEL CID\n got  %s\n want %s", name, got, wantCID)
	}
	states, err := identity.Replay(kel)
	if err != nil {
		t.Fatalf("%s does not replay: %v", name, err)
	}
	if len(states) != len(want) {
		t.Fatalf("%s: %d states, want %d", name, len(states), len(want))
	}
	for i, w := range want {
		if states[i].Status != w.status || states[i].SupersededAt != w.supersededAt {
			t.Errorf("%s state %d = {%s, %d}, want {%s, %d}", name, i,
				states[i].Status, states[i].SupersededAt, w.status, w.supersededAt)
		}
	}
}

// verifyAt reports the VerifyObject reason for an object signed by k at declared seq, "" if accepted.
func verifyAt(kel []identity.SignedEvent, k ed25519.PrivateKey, seq, msgTime uint64) string {
	obj := []byte("golden object")
	err := identity.VerifyObject(kel, suiteAID, seq, msgTime, obj, ed25519.Sign(k, obj))
	if err == nil {
		return ""
	}
	var ve *identity.VErr
	if errors.As(err, &ve) {
		return ve.Reason
	}
	return err.Error()
}

func TestVEC_KEL_SUPERSEDE_1(t *testing.T) {
	kel, k0 := supersedeKEL(t, identity.Rotation)
	checkSupersede(t, "icp→drt→rot", kel, "bafyreicgk5kqaahyq5cpkfve6nkpjkeyukujfcspz76rbwriie2q7cm65q", []supersedeRow{
		{identity.StatusRotated, 5000},
		{identity.StatusRotated, 5000},
		{identity.StatusActive, 0},
	})
	for _, seq := range []uint64{0, 1} {
		if r := verifyAt(kel, k0, seq, 4999); r != "" {
			t.Errorf("seq %d at 4999: want accepted, got %s", seq, r)
		}
		for _, at := range []uint64{5000, 5001} {
			if r := verifyAt(kel, k0, seq, at); r != "REVOKED_KEY" {
				t.Errorf("seq %d at %d: want REVOKED_KEY, got %q", seq, at, r)
			}
		}
	}
	if r := verifyAt(kel, seedKey("anet-suite-identity-v1/nxt"), 2, 5000); r != "" {
		t.Errorf("the rotated-in key at seq 2: want accepted, got %s", r)
	}
}

func TestVEC_KEL_SUPERSEDE_2(t *testing.T) {
	kel, k0 := supersedeKEL(t, identity.Deactivation)
	checkSupersede(t, "icp→drt→dip", kel, "bafyreihy6jiyflwrg7uozkjfdcg2uymzcql34acwdtuut5yfathkyfgpna", []supersedeRow{
		{identity.StatusRotated, 8000},
		{identity.StatusRotated, 8000},
		{identity.StatusDeactivated, 0},
	})
	for _, seq := range []uint64{0, 1} {
		if r := verifyAt(kel, k0, seq, 7999); r != "" {
			t.Errorf("seq %d at 7999: want accepted, got %s", seq, r)
		}
		for _, at := range []uint64{8000, 8001} {
			if r := verifyAt(kel, k0, seq, at); r != "REVOKED_KEY" {
				t.Errorf("seq %d at %d: want REVOKED_KEY, got %q", seq, at, r)
			}
		}
	}
	// The dip's own state is terminal: refused at every time, including the unknown time 0.
	for _, at := range []uint64{0, 7999, 8000} {
		if r := verifyAt(kel, k0, 2, at); r != "REVOKED_KEY" {
			t.Errorf("dip seq 2 at %d: want REVOKED_KEY, got %q", at, r)
		}
	}
}
