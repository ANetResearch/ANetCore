package evidence_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
)

func TestAGenuineTaskInterlocks(t *testing.T) {
	p := incept(t)
	w := signReceipt(t, p, testBody(t, ""))
	rv, _ := testReview(t, w).Sign(reviewKey())
	rc, body, err := evidence.CheckV2(w, rv, p.KEL())
	if err != nil {
		t.Fatalf("a genuine receipt and review must interlock: %v", err)
	}
	if rc.Provider != p.AID() || body.Subject != p.AID() {
		t.Fatalf("returned bodies %+v %+v", rc, body)
	}
}

// Each case is a way to manufacture a rating that would otherwise pass.
func TestEveryWayOfManufacturingARating(t *testing.T) {
	p, other := incept(t), incept(t)
	w := signReceipt(t, p, testBody(t, ""))
	review := func(edit func(*evidence.ReviewBody)) *evidence.ReviewWire {
		b := testReview(t, w)
		if edit != nil {
			edit(b)
		}
		rv, err := b.Sign(reviewKey())
		if err != nil {
			t.Fatal(err)
		}
		return rv
	}
	otherReceipt := signReceipt(t, p, func() *evidence.ReceiptBody {
		b := testBody(t, "")
		b.ResultCID = "bafyreianotherresult"
		return b
	}())
	cases := []struct {
		name    string
		receipt *evidence.ReceiptWire
		review  *evidence.ReviewWire
		kel     []identity.SignedEvent
		want    error
	}{
		{"a review of another receipt", w, review(func(b *evidence.ReviewBody) {
			b.ReceiptCID, _ = otherReceipt.CID()
		}), p.KEL(), evidence.ErrNotThisReceipt},
		{"praise for someone who was not the provider", w, review(func(b *evidence.ReviewBody) { b.Subject = other.AID() }),
			p.KEL(), evidence.ErrNotThisReceipt},
		{"a review not written with the task's review key", w, func() *evidence.ReviewWire {
			rv, _ := testReview(t, w).Sign(ed25519.NewKeyFromSeed(seed32("someone")))
			return rv
		}(), p.KEL(), evidence.ErrSigner},
		{"a receipt the provider never signed", w, review(nil), other.KEL(), evidence.ErrSignature},
		{"a receipt by someone else naming the provider", func() *evidence.ReceiptWire {
			raw, _ := testBody(t, p.AID()).Marshal()
			sig, seq := other.Sign(raw)
			return &evidence.ReceiptWire{Body: raw, Env: &aobj.Envelope{SignerAID: other.AID(), KeyStateSeq: seq, Alg: aobj.AlgEdDSA, Sig: sig}}
		}(), review(nil), other.KEL(), evidence.ErrSigner},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := evidence.CheckV2(tc.receipt, tc.review, tc.kel); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
	if _, _, err := evidence.CheckV2(nil, review(nil), p.KEL()); !errors.Is(err, evidence.ErrMalformed) {
		t.Errorf("no receipt: %v", err)
	}
	if _, _, err := evidence.CheckV2(w, nil, p.KEL()); !errors.Is(err, evidence.ErrMalformed) {
		t.Errorf("no review: %v", err)
	}
}

// CheckV2 judges the provider's signature at the start of the receipt's own completed_day (SI-36):
// a key the provider retired on an earlier day signs nothing dated later; a key retired later the
// same day still signed that day's receipts.
func TestCheckV2JudgesTheReceiptAtItsOwnDay(t *testing.T) {
	early := incept(t)
	w := signReceipt(t, early, testBody(t, ""))
	if err := early.Rotate(uint64(day)*evidence.DayMS - 1); err != nil { // the evening before
		t.Fatal(err)
	}
	rv, _ := testReview(t, w).Sign(reviewKey())
	if _, _, err := evidence.CheckV2(w, rv, early.KEL()); !errors.Is(err, evidence.ErrSignature) {
		t.Fatalf("key retired the day before: want ErrSignature, got %v", err)
	}
	late := incept(t)
	w = signReceipt(t, late, testBody(t, ""))
	if err := late.Rotate(uint64(day)*evidence.DayMS + 1); err != nil { // just after midnight
		t.Fatal(err)
	}
	rv, _ = testReview(t, w).Sign(reviewKey())
	if _, _, err := evidence.CheckV2(w, rv, late.KEL()); err != nil {
		t.Fatalf("key retired later that day: must verify, got %v", err)
	}
	// A day that does not fit a millisecond count is not a day.
	b := testBody(t, "")
	b.CompletedDay = 1 << 63
	far := signReceipt(t, late, b)
	if _, _, err := evidence.CheckV2(far, rv, late.KEL()); !errors.Is(err, evidence.ErrMalformed) {
		t.Fatalf("an impossible day: want ErrMalformed, got %v", err)
	}
}

// SI-81: the provider's identity key signs receipts and payment authorizations. A receipt's
// signature must not authorize a payment, nor a payment's signature vouch for a receipt: the two
// signed inputs are told apart by class (class A with key 0 here, class D there).
func TestAReceiptSignatureIsNotAPaymentSignature(t *testing.T) {
	c := incept(t)
	w := signReceipt(t, c, testBody(t, ""))
	// The receipt body is not an authorization preimage under any reading.
	var a struct {
		Payer string `cbor:"1,keyasint"`
	}
	if err := coredet.UnmarshalStrict(w.Body, &a); err == nil {
		t.Fatal("a receipt body decodes as a payment authorization")
	}
	auth := &payment.Authorization{Payer: c.AID(), PayTo: "bafyreipayee", Amount: 7, Network: payment.CreditNetwork("bafyreihub"),
		Nonce: "n", IssuedAt: 1767225600000, NotAfter: 1767225900000, InteractionID: "ab12"}
	auth.Envelope = &aobj.Envelope{SignerAID: c.AID(), KeyStateSeq: w.Env.KeyStateSeq, Alg: aobj.AlgEdDSA, Sig: w.Env.Sig}
	if err := auth.Verify(c.KEL(), 1767225600001); err == nil {
		t.Fatal("a receipt's signature authorized a payment")
	}
	if err := auth.Sign(c); err != nil {
		t.Fatal(err)
	}
	moved := &evidence.ReceiptWire{Body: w.Body, Env: auth.Envelope}
	if _, err := moved.Verify(c.KEL(), day*evidence.DayMS); !errors.Is(err, evidence.ErrSignature) {
		t.Fatalf("a payment's signature vouched for a receipt: %v", err)
	}
}

// The commitments are exactly their labelled preimages, and none takes a field that holds U+0000
// or is empty (CORE-E9).
func TestTheCommitmentsAreTheirPreimages(t *testing.T) {
	sum := func(parts ...[]byte) []byte {
		h := sha256.New()
		for _, p := range parts {
			h.Write(p)
		}
		return h.Sum(nil)
	}
	z := []byte{0}
	rsalt := seed32("rsalt")
	key := seed32("tag-key")
	got, _ := evidence.IXCommit("ix-1", "nonce")
	if want := sum([]byte("anet-receipt-ix/v2"), z, []byte("ix-1"), z, []byte("nonce")); !bytes.Equal(got, want) {
		t.Errorf("ix_commit %x, want %x", got, want)
	}
	got, _ = evidence.RequesterCommit("bafyreir", rsalt)
	if want := sum([]byte("anet-receipt-requester/v2"), z, []byte("bafyreir"), z, rsalt); !bytes.Equal(got, want) {
		t.Errorf("requester_commit %x, want %x", got, want)
	}
	got, _ = evidence.SettleGuard("bafyreipayer", "ab12")
	if want := sum([]byte("anet-settle-guard/v1"), z, []byte("bafyreipayer"), z, []byte("ab12")); !bytes.Equal(got, want) {
		t.Errorf("settle guard %x, want %x", got, want)
	}
	got, _ = evidence.ReviewTag(key, "bafyreir", "bafyreis")
	m := hmac.New(sha256.New, key)
	m.Write([]byte("anet-review-tag/v1\x00bafyreir\x00bafyreis"))
	if want := m.Sum(nil)[:16]; !bytes.Equal(got, want) {
		t.Errorf("review tag %x, want %x", got, want)
	}

	// The case CORE-E9 is about: two splits of one byte string.
	if _, err := evidence.IXCommit("a\x00b", "c"); !errors.Is(err, evidence.ErrNUL) {
		t.Errorf("ix with U+0000: %v", err)
	}
	if _, err := evidence.IXCommit("a", "b\x00c"); !errors.Is(err, evidence.ErrNUL) {
		t.Errorf("nonce with U+0000: %v", err)
	}
	for name, call := range map[string]func() error{
		"empty ix":           func() error { _, err := evidence.IXCommit("", "n"); return err },
		"empty nonce":        func() error { _, err := evidence.IXCommit("i", ""); return err },
		"requester U+0000":   func() error { _, err := evidence.RequesterCommit("a\x00", rsalt); return err },
		"empty requester":    func() error { _, err := evidence.RequesterCommit("", rsalt); return err },
		"reviewer U+0000":    func() error { _, err := evidence.ReviewTag(key, "\x00", "s"); return err },
		"subject U+0000":     func() error { _, err := evidence.ReviewTag(key, "r", "s\x00"); return err },
		"payer U+0000":       func() error { _, err := evidence.SettleGuard("p\x00", "b"); return err },
		"pay_bind U+0000":    func() error { _, err := evidence.SettleGuard("p", "\x00b"); return err },
		"empty pay_bind":     func() error { _, err := evidence.SettleGuard("p", ""); return err },
		"empty subject":      func() error { _, err := evidence.ReviewTag(key, "r", ""); return err },
		"empty payer":        func() error { _, err := evidence.SettleGuard("", "b"); return err },
		"empty reviewer":     func() error { _, err := evidence.ReviewTag(key, "", "s"); return err },
		"nonce of only NULs": func() error { _, err := evidence.IXCommit("i", "\x00\x00"); return err },
	} {
		if err := call(); !errors.Is(err, evidence.ErrNUL) {
			t.Errorf("%s: want ErrNUL, got %v", name, err)
		}
	}
	if _, err := evidence.RequesterCommit("r", rsalt[:31]); !errors.Is(err, evidence.ErrMalformed) {
		t.Errorf("31-byte rsalt: %v", err)
	}
	if _, err := evidence.ReviewTag(key[:16], "r", "s"); !errors.Is(err, evidence.ErrMalformed) {
		t.Errorf("16-byte tag key: %v", err)
	}
	// A tag says nothing across reviewers, subjects or keys.
	a, _ := evidence.ReviewTag(key, "r1", "s")
	b, _ := evidence.ReviewTag(key, "r2", "s")
	c, _ := evidence.ReviewTag(key, "r1", "s2")
	d, _ := evidence.ReviewTag(seed32("another key"), "r1", "s")
	if bytes.Equal(a, b) || bytes.Equal(a, c) || bytes.Equal(a, d) {
		t.Error("review tags collide across reviewer, subject or key")
	}
}
