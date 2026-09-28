package evidence_test

// Fuzz targets for receipts, reviews and their interlock (ANet docs/notes/0033).

import (
	"reflect"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
)

const fuzzTS = 1767225600000

func FuzzReceiptReview(f *testing.F) {
	c := identity.SuiteController()
	request, deliverable := []byte("request"), []byte("deliverable")
	rc := &evidence.Receipt{InteractionID: "ix", RequesterAID: c.AID(), RequestCID: anetcid.MustSum(request),
		ResultCID: anetcid.MustSum(deliverable), CompletedAt: fuzzTS}
	if err := rc.Sign(c); err != nil {
		f.Fatal(err)
	}
	rcb, _ := rc.Marshal()
	rcid, _ := rc.CID()
	rv := &evidence.Review{InteractionID: "ix", SubjectAID: c.AID(), Rating: 5, Comment: "ok", ReceiptCID: rcid, CreatedAt: fuzzTS + 1}
	if err := rv.Sign(c); err != nil {
		f.Fatal(err)
	}
	rvb, _ := rv.Marshal()
	f.Add(rcb, rvb, false)
	f.Add(rcb, rvb, true)
	f.Fuzz(func(t *testing.T, rb, vb []byte, resign bool) {
		r, rerr := evidence.UnmarshalReceipt(rb)
		v, verr := evidence.UnmarshalReview(vb)
		if rerr == nil {
			if b, err := r.Marshal(); err == nil {
				back, err := evidence.UnmarshalReceipt(b)
				if err != nil || !reflect.DeepEqual(back, r) {
					t.Fatalf("receipt round trip: %v", err)
				}
			}
			if resign && r.Sign(c) != nil {
				return
			}
			if err := r.Verify(c.KEL(), r.CompletedAt); err == nil && (r.Envelope.SignerAID != r.ProviderAID || r.ProviderAID != c.AID()) {
				t.Fatalf("accepted a receipt for provider %s signed by %s", r.ProviderAID, r.Envelope.SignerAID)
			}
		}
		if verr == nil {
			if b, err := v.Marshal(); err == nil {
				back, err := evidence.UnmarshalReview(b)
				if err != nil || !reflect.DeepEqual(back, v) {
					t.Fatalf("review round trip: %v", err)
				}
			}
			if resign && v.Sign(c) != nil {
				return
			}
			if err := v.Verify(c.KEL(), v.CreatedAt); err == nil && (v.Envelope.SignerAID != v.ReviewerAID || v.ReviewerAID != c.AID()) {
				t.Fatalf("accepted a review by %s signed by %s", v.ReviewerAID, v.Envelope.SignerAID)
			}
		}
		if rerr != nil || verr != nil {
			return
		}
		if err := evidence.VerifyInterlock(r, v, request, deliverable, c.KEL(), c.KEL()); err == nil {
			cid, _ := r.CID()
			if v.ReceiptCID != cid || v.InteractionID != r.InteractionID || v.ReviewerAID != r.RequesterAID ||
				v.SubjectAID != r.ProviderAID || !v.ValidRating() ||
				r.RequestCID != anetcid.MustSum(request) || r.ResultCID != anetcid.MustSum(deliverable) {
				t.Fatalf("interlock accepted a pair that does not interlock:\n%+v\n%+v", r, v)
			}
		}
	})
}
