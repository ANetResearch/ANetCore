package ael

// Fuzz targets for head attestations, event records and the ledger (ANet docs/notes/0033).
//
// FuzzLedgerImport decodes a batch of records and, when asked, re-signs each with the suite
// identity (as a chain owner would), then imports it; whatever the batch, the ledger must keep
// its chain invariants: an ACTIVE chain is a gap-free, prev-linked run from the genesis sentinel.

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

const fuzzTS = int64(1767225600000)

func FuzzHeadAttestation(f *testing.F) {
	c := identity.SuiteController()
	a := &HeadAttestation{ChainDID: "did:anet:other", Seq: 0, HeadID: "bafyreihead", ObservedAt: fuzzTS}
	if err := a.Sign(c); err != nil {
		f.Fatal(err)
	}
	b, _ := a.Marshal()
	f.Add(b, false)
	f.Add(b, true)
	f.Fuzz(func(t *testing.T, b []byte, resign bool) {
		a, err := UnmarshalHeadAttestation(b)
		if err != nil {
			return
		}
		if rb, err := a.Marshal(); err == nil {
			back, err := UnmarshalHeadAttestation(rb)
			if err != nil || !reflect.DeepEqual(back, a) {
				t.Fatalf("attestation round trip: %v", err)
			}
		}
		_, _ = a.ID()
		_ = a.ContradictedBy(&EventRecord{ChainDID: a.ChainDID, Seq: a.Seq, ID: a.HeadID + "x"})
		if resign && a.Sign(c) != nil {
			return
		}
		if err := a.Verify(c.KEL(), c.AID(), a.ObservedAt); err == nil {
			if a.WitnessAID() != c.AID() || a.WitnessAID() == a.ChainDID {
				t.Fatalf("accepted an attestation of %s witnessed by %s", a.ChainDID, a.WitnessAID())
			}
		}
	})
}

func seedChain(tb testing.TB, c *identity.Controller, n int) []*EventRecord {
	tb.Helper()
	var recs []*EventRecord
	prev := GenesisPrev()
	for i := 0; i < n; i++ {
		r := &EventRecord{ChainDID: "did:anet:" + c.AID(), Seq: uint64(i), PrevID: prev, EventType: "x.event",
			VersionMajor: VersionMajor2, Payload: map[string]any{"i": uint64(i)}, Timestamp: fuzzTS + int64(i)}
		if i == 0 {
			r.EventType = EvGenesis
		}
		if err := r.Sign(c); err != nil {
			tb.Fatal(err)
		}
		prev = r.ID
		recs = append(recs, r)
	}
	return recs
}

func FuzzLedgerImport(f *testing.F) {
	c := identity.SuiteController()
	chain := seedChain(f, c, 3)
	b, err := coredet.Marshal(chain)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b, false)
	f.Add(b, true)
	swapped, _ := coredet.Marshal([]*EventRecord{chain[0], chain[2], chain[1]})
	f.Add(swapped, false)
	f.Fuzz(func(t *testing.T, b []byte, resign bool) {
		var recs []*EventRecord
		if coredet.Unmarshal(b, &recs) != nil || len(recs) > 64 {
			return
		}
		for i, r := range recs {
			if r == nil {
				recs[i] = &EventRecord{}
				r = recs[i]
			}
			if resign {
				if r.Sign(c) != nil {
					return
				}
			}
			if err := r.Verify(c.KEL()); err == nil {
				if id, err := r.ComputeID(); err != nil || id != r.ID || r.SignerAID != c.AID() {
					t.Fatalf("record verified with id %s (computed %s) signer %s", r.ID, id, r.SignerAID)
				}
			}
		}
		l := NewLedger()
		res, err := l.ImportBatch(recs, c.KEL())
		var proof *EquivocationProof
		if errors.As(err, &proof) {
			if l.State(proof.ChainDID) != ChainQuarantined {
				t.Fatal("equivocation proof without a quarantined chain")
			}
			if proof.NodeA.ID == proof.NodeB.ID || proof.NodeA.Seq != proof.NodeB.Seq {
				t.Fatalf("equivocation proof over %s@%d and %s@%d", proof.NodeA.ID, proof.NodeA.Seq, proof.NodeB.ID, proof.NodeB.Seq)
			}
		}
		if res != nil && res.Applied+res.Staged+res.Dups > len(recs)*2 {
			t.Fatalf("import result %+v for %d records", res, len(recs))
		}
		for did, ch := range l.chains {
			if ch.state != ChainActive {
				continue
			}
			for i, r := range ch.events {
				if r.Seq != uint64(i) || r.ChainDID != did {
					t.Fatalf("active chain %s holds seq %d at %d", did, r.Seq, i)
				}
				want := GenesisPrev()
				if i > 0 {
					want = ch.events[i-1].ID
				}
				if r.PrevID != want {
					t.Fatalf("active chain %s: record %d does not link", did, i)
				}
				if err := r.Verify(c.KEL()); err != nil {
					t.Fatalf("active chain %s holds a record that does not verify: %v", did, err)
				}
			}
			if id, seq, ok := l.Head(did); ok {
				last := ch.events[len(ch.events)-1]
				if id != last.ID || seq != last.Seq {
					t.Fatalf("head %s@%d, last record %s@%d", id, seq, last.ID, last.Seq)
				}
			}
			if len(ch.staged) > ImportBufferCap {
				t.Fatalf("staged %d records", len(ch.staged))
			}
		}
	})
}
