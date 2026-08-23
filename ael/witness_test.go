package ael_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/ael"
	"github.com/ANetResearch/ANetCore/identity"
)

func attest(t *testing.T, w *identity.Controller, chainDID, headID string, seq uint64) *ael.HeadAttestation {
	t.Helper()
	a := &ael.HeadAttestation{
		ChainDID: chainDID, Seq: seq, HeadID: headID,
		ObservedAt: time.Now().UnixMilli(),
	}
	if err := a.Sign(w); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAGenuineAttestationVerifies(t *testing.T) {
	w, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	a := attest(t, w, "did:anet:hub", "bafy-head-7", 7)
	if err := a.Verify(w.KEL(), w.AID(), time.Now().UnixMilli()); err != nil {
		t.Fatalf("a genuine attestation must verify: %v", err)
	}
	if a.WitnessAID() != w.AID() {
		t.Errorf("witness = %s", a.WitnessAID())
	}
	id1, _ := a.ID()
	id2, _ := a.ID()
	if id1 == "" || id1 != id2 {
		t.Errorf("attestation id is not stable: %q vs %q", id1, id2)
	}
}

func TestAttestationsThatMustBeRefused(t *testing.T) {
	w, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	other, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()

	t.Run("signed by somebody other than the expected witness", func(t *testing.T) {
		// A chain owner collecting attestations could otherwise supply
		// ones signed by keys it controls.
		a := attest(t, other, "did:anet:hub", "bafy-head-7", 7)
		err := a.Verify(other.KEL(), w.AID(), now)
		if err == nil {
			t.Fatal("accepted an attestation from an unexpected signer")
		}
		if !strings.Contains(err.Error(), "expected witness") {
			t.Errorf("refused for the wrong reason: %v", err)
		}
	})

	t.Run("a chain witnessing itself", func(t *testing.T) {
		// Carries no information: a chain asserting its own head is what
		// the chain already does.
		a := &ael.HeadAttestation{ChainDID: w.AID(), Seq: 7, HeadID: "bafy-head-7", ObservedAt: now}
		if err := a.Sign(w); err == nil {
			t.Error("a controller signed an attestation of its own chain")
		}
	})

	t.Run("head id changed after signing", func(t *testing.T) {
		a := attest(t, w, "did:anet:hub", "bafy-head-7", 7)
		a.HeadID = "bafy-head-forged"
		if err := a.Verify(w.KEL(), w.AID(), now); err == nil {
			t.Error("accepted an attestation whose head was altered")
		}
	})

	t.Run("unsigned", func(t *testing.T) {
		a := &ael.HeadAttestation{ChainDID: "did:anet:hub", Seq: 7, HeadID: "x", ObservedAt: now}
		if err := a.Verify(w.KEL(), w.AID(), now); err == nil {
			t.Error("accepted an unsigned attestation")
		}
	})

	t.Run("names no head", func(t *testing.T) {
		a := &ael.HeadAttestation{ChainDID: "did:anet:hub", ObservedAt: now}
		if err := a.Sign(w); err == nil {
			t.Error("signed an attestation that names no head")
		}
	})
}

func TestAnAttestationSurvivesTheWire(t *testing.T) {
	w, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	a := attest(t, w, "did:anet:hub", "bafy-head-7", 7)
	raw, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ael.UnmarshalHeadAttestation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Verify(w.KEL(), w.AID(), time.Now().UnixMilli()); err != nil {
		t.Fatalf("an attestation off the wire must still verify: %v", err)
	}
	if back.Seq != 7 || back.HeadID != "bafy-head-7" || back.ChainDID != "did:anet:hub" {
		t.Errorf("attestation = %+v", back)
	}
}

// The pair is the proof: a record signed by the chain owner and an
// attestation signed by a witness, naming the same position in the same
// chain with different contents. Neither party has to agree for the
// contradiction to be checkable.
func TestAnAttestationDetectsARewrittenHistory(t *testing.T) {
	w, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	a := attest(t, w, "did:anet:hub", "bafy-original", 7)

	rewritten := &ael.EventRecord{ChainDID: "did:anet:hub", Seq: 7, ID: "bafy-replaced"}
	if !a.ContradictedBy(rewritten) {
		t.Error("a record replacing the witnessed one at the same seq was not detected")
	}
	same := &ael.EventRecord{ChainDID: "did:anet:hub", Seq: 7, ID: "bafy-original"}
	if a.ContradictedBy(same) {
		t.Error("the record the witness actually saw was reported as a contradiction")
	}
	// A different position, or a different chain, is not a contradiction.
	if a.ContradictedBy(&ael.EventRecord{ChainDID: "did:anet:hub", Seq: 8, ID: "bafy-next"}) {
		t.Error("a later record was reported as contradicting an earlier attestation")
	}
	if a.ContradictedBy(&ael.EventRecord{ChainDID: "did:anet:other", Seq: 7, ID: "bafy-x"}) {
		t.Error("another chain's record was reported as a contradiction")
	}
}
