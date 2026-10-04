package evidence_test

// Fuzz targets for the evidence v2 decoders and the interlock.
//
// Each decoder must either refuse its input or return an object whose own encoding is exactly the
// input (CORE-E2: one object, one byte form), and must never panic. FuzzCheckV2 re-signs what it
// decoded with fixed keys, so the interlock's binding checks run on arbitrary field values under
// good signatures — which is where an interlock accepting what it should not would show.

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
)

func fuzzSeeds(f *testing.F) (receipt, review, att []byte) {
	c := identity.SuiteController()
	w := signReceipt(f, c, testBody(f, ""))
	rv, err := testReview(f, w).Sign(reviewKey())
	if err != nil {
		f.Fatal(err)
	}
	tag, _ := evidence.ReviewTag(seed32("tag-key"), "bafyreirequester", c.AID())
	a, err := (&evidence.ReviewAttBody{ReviewCID: "bafyreview", ReceiptCID: "bafyreceipt", Subject: c.AID(), Tag: tag,
		TagKeyID: 1, Day: day}).Sign(c)
	if err != nil {
		f.Fatal(err)
	}
	return mustMarshal(f, w), mustMarshal(f, rv), mustMarshal(f, a)
}

func FuzzReceiptWire(f *testing.F) {
	receipt, review, att := fuzzSeeds(f)
	for _, s := range [][]byte{receipt, review, att, {0xa0}, {0xf6}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		w, err := evidence.UnmarshalReceiptWire(b)
		if err != nil {
			if body, err := evidence.UnmarshalReceiptBody(b); err == nil {
				if back, err := body.Marshal(); err != nil || !bytes.Equal(back, b) {
					t.Fatalf("accepted body re-encodes differently (%v)", err)
				}
			}
			return
		}
		back, err := w.Marshal()
		if err != nil || !bytes.Equal(back, b) {
			t.Fatalf("accepted receipt re-encodes differently (%v)", err)
		}
		body, err := w.Open()
		if err != nil {
			t.Fatalf("accepted receipt with a body that does not open: %v", err)
		}
		c1, _ := w.CID()
		c2, _ := body.CID()
		if c1 != c2 {
			t.Fatalf("receipt_cid %s from the wire, %s from the body", c1, c2)
		}
		if len(body.IXCommit) != evidence.CommitSize || len(body.RequesterCommit) != evidence.CommitSize ||
			len(body.ReviewKey) != evidence.ReviewKeySize || body.Type != evidence.ReceiptType {
			t.Fatalf("accepted a body out of form: %+v", body)
		}
	})
}

func FuzzReviewWire(f *testing.F) {
	receipt, review, att := fuzzSeeds(f)
	for _, s := range [][]byte{review, receipt, att} {
		f.Add(s, review)
	}
	f.Fuzz(func(t *testing.T, b, key []byte) {
		w, err := evidence.UnmarshalReviewWire(b)
		if err != nil {
			if body, err := evidence.UnmarshalReviewBody(b); err == nil {
				if back, err := body.Marshal(); err != nil || !bytes.Equal(back, b) {
					t.Fatalf("accepted review body re-encodes differently (%v)", err)
				}
			}
			return
		}
		back, err := w.Marshal()
		if err != nil || !bytes.Equal(back, b) {
			t.Fatalf("accepted review re-encodes differently (%v)", err)
		}
		body, err := w.Open()
		if err != nil || body.Rating < evidence.RatingMin || body.Rating > evidence.RatingMax {
			t.Fatalf("accepted a review out of form: %+v, %v", body, err)
		}
		if len(key) > evidence.ReviewKeySize {
			key = key[:evidence.ReviewKeySize]
		}
		if _, err := w.Verify(key); err == nil && !bytes.Equal(key, w.Pub) {
			t.Fatal("a review verified under a key that is not its own")
		}
		_, _ = w.Verify(w.Pub)
	})
}

func FuzzReviewAttWire(f *testing.F) {
	receipt, review, att := fuzzSeeds(f)
	for _, s := range [][]byte{att, receipt, review} {
		f.Add(s)
	}
	kel := identity.SuiteController().KEL()
	f.Fuzz(func(t *testing.T, b []byte) {
		w, err := evidence.UnmarshalReviewAttWire(b)
		if err != nil {
			if body, err := evidence.UnmarshalReviewAttBody(b); err == nil {
				if back, err := body.Marshal(); err != nil || !bytes.Equal(back, b) {
					t.Fatalf("accepted attestation body re-encodes differently (%v)", err)
				}
			}
			return
		}
		back, err := w.Marshal()
		if err != nil || !bytes.Equal(back, b) {
			t.Fatalf("accepted attestation re-encodes differently (%v)", err)
		}
		if body, err := w.Verify(kel, day*evidence.DayMS); err == nil && (body.Hub != w.Env.SignerAID || len(body.Tag) != evidence.TagSize) {
			t.Fatalf("verified an attestation out of form: %+v", body)
		}
	})
}

// FuzzCheckV2 decodes a receipt and a review, re-signs them with the suite identity and a fixed
// review key when asked, and checks every verdict against what the bodies say.
func FuzzCheckV2(f *testing.F) {
	receipt, review, _ := fuzzSeeds(f)
	f.Add(receipt, review, true, true)
	f.Add(receipt, review, false, false)
	c := identity.SuiteController()
	key := reviewKey()
	f.Fuzz(func(t *testing.T, rb, vb []byte, resignReceipt, resignReview bool) {
		w, err := evidence.UnmarshalReceiptWire(rb)
		if err != nil {
			return
		}
		rv, err := evidence.UnmarshalReviewWire(vb)
		if err != nil {
			return
		}
		if resignReceipt {
			if body, err := w.Open(); err == nil {
				body.Provider = ""
				if again, err := body.Sign(c); err == nil {
					w = again
				}
			}
		}
		if resignReview {
			if body, err := rv.Open(); err == nil {
				if again, err := body.Sign(key); err == nil {
					rv = again
				}
			}
		}
		rc, body, err := evidence.CheckV2(w, rv, c.KEL())
		if err != nil {
			return
		}
		cid, _ := w.CID()
		switch {
		case body.ReceiptCID != cid:
			t.Fatalf("interlocked a review of %s with receipt %s", body.ReceiptCID, cid)
		case body.Subject != rc.Provider:
			t.Fatalf("interlocked a review of %s with a receipt by %s", body.Subject, rc.Provider)
		case !bytes.Equal(rv.Pub, rc.ReviewKey) || !ed25519.Verify(rv.Pub, rv.Body, rv.Sig):
			t.Fatal("interlocked a review not signed by the receipt's review key")
		case rc.Provider != c.AID() || w.Env.SignerAID != c.AID():
			t.Fatalf("interlocked a receipt by %s against the suite KEL", rc.Provider)
		}
	})
}

// FuzzCommitments: no input that holds U+0000 or is empty is ever committed to, and the rest always
// are.
func FuzzCommitments(f *testing.F) {
	f.Add("ix-1", "nonce", "bafyreir")
	f.Add("a\x00b", "c", "")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		bad := func(s string) bool { return s == "" || bytes.IndexByte([]byte(s), 0) >= 0 }
		if _, err := evidence.IXCommit(a, b); (err != nil) != (bad(a) || bad(b)) {
			t.Fatalf("IXCommit(%q, %q): %v", a, b, err)
		}
		if _, err := evidence.RequesterCommit(a, make([]byte, evidence.RSaltSize)); (err != nil) != bad(a) {
			t.Fatalf("RequesterCommit(%q): %v", a, err)
		}
		if _, err := evidence.ReviewTag(make([]byte, evidence.TagKeySize), a, c); (err != nil) != (bad(a) || bad(c)) {
			t.Fatalf("ReviewTag(%q, %q): %v", a, c, err)
		}
		if _, err := evidence.SettleGuard(b, c); (err != nil) != (bad(b) || bad(c)) {
			t.Fatalf("SettleGuard(%q, %q): %v", b, c, err)
		}
	})
}
