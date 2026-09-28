package payment_test

// Fuzz targets for the anet-credit wire objects and amounts (ANet docs/notes/0033).
//
// Each target decodes, checks the round trip, optionally re-signs the decoded object with the
// suite identity and verifies it; an accepted object must be signed by the declared signer and
// lie inside its window, computed here without int64 overflow.

import (
	"bytes"
	"math"
	"math/big"
	"reflect"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
)

const fuzzNow = int64(1767225600000)

func inWindow(now, from, to int64) bool {
	n, lo, hi := big.NewInt(now), big.NewInt(from), big.NewInt(to)
	skew := big.NewInt(payment.ClockSkew)
	lo.Sub(lo, skew)
	hi.Add(hi, skew)
	return n.Cmp(lo) >= 0 && n.Cmp(hi) <= 0
}

func FuzzAuthorization(f *testing.F) {
	c := identity.SuiteController()
	a := &payment.Authorization{PayTo: "bafyreipayee", Amount: 250, Network: payment.CreditNetwork("bafyreihub"),
		Nonce: "n-1", IssuedAt: fuzzNow, NotAfter: fuzzNow + 60_000, InteractionID: "ix-1"}
	if err := a.Sign(c); err != nil {
		f.Fatal(err)
	}
	b, err := a.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b, false, fuzzNow)
	f.Add(b, true, fuzzNow+59_000)
	f.Add(b, true, int64(math.MaxInt64))
	// Never expires (TestWindowEdgesDoNotOverflow).
	forever := *a
	forever.NotAfter = math.MaxInt64
	if err := forever.Sign(c); err != nil {
		f.Fatal(err)
	}
	fb, _ := forever.Marshal()
	f.Add(fb, true, fuzzNow)
	f.Fuzz(func(t *testing.T, b []byte, resign bool, now int64) {
		a, err := payment.UnmarshalAuthorization(b)
		if err != nil {
			return
		}
		if rb, err := a.Marshal(); err == nil {
			back, err := payment.UnmarshalAuthorization(rb)
			if err != nil || !reflect.DeepEqual(back, a) {
				t.Fatalf("authorization round trip: %v\n%+v\n%+v", err, a, back)
			}
		}
		_, _ = a.ID()
		if resign {
			payer := a.Payer
			if err := a.Sign(c); err != nil {
				return
			}
			if payer != "" {
				a.Payer = payer // keep the fuzzed payer: the signature then names someone else
			}
		}
		if err := a.Verify(c.KEL(), now); err != nil {
			// A correctly signed authorization inside its window is accepted, whatever its values.
			if resign && a.Payer == c.AID() && a.IssuedAt > 0 && a.NotAfter > a.IssuedAt && inWindow(now, a.IssuedAt, a.NotAfter) {
				t.Fatalf("refused a signed authorization inside its window (issued %d, not after %d, now %d): %v",
					a.IssuedAt, a.NotAfter, now, err)
			}
			return
		}
		if a.Envelope.SignerAID != a.Payer || a.Payer != c.AID() {
			t.Fatalf("accepted an authorization from %s signed by %s", a.Payer, a.Envelope.SignerAID)
		}
		if !inWindow(now, a.IssuedAt, a.NotAfter) || a.IssuedAt <= 0 || a.NotAfter <= a.IssuedAt {
			t.Fatalf("accepted an authorization outside its window (issued %d, not after %d, now %d)", a.IssuedAt, a.NotAfter, now)
		}
	})
}

func FuzzReceiptVoucher(f *testing.F) {
	c := identity.SuiteController()
	r := &payment.Receipt{AuthID: "bafyreiauth", Payer: "p", PayTo: "q", Amount: 7, Network: "hub:x", SettleAt: fuzzNow}
	if err := r.Sign(c); err != nil {
		f.Fatal(err)
	}
	rb, _ := r.Marshal()
	v := &payment.Voucher{AuthID: "bafyreiauth", Payer: "p", PayTo: "q", Capability: "cap", Amount: 7,
		Network: "hub:x", NotAfter: fuzzNow + 60_000, Nonce: "n", ArgsCID: "bafyreiargs"}
	if err := v.Sign(c); err != nil {
		f.Fatal(err)
	}
	vb, _ := v.Marshal()
	f.Add(rb, false, fuzzNow)
	f.Add(vb, true, fuzzNow)
	f.Add(vb, true, int64(math.MinInt64))
	f.Fuzz(func(t *testing.T, b []byte, resign bool, now int64) {
		if r, err := payment.UnmarshalReceipt(b); err == nil {
			if rb, err := r.Marshal(); err == nil {
				back, err := payment.UnmarshalReceipt(rb)
				if err != nil || !reflect.DeepEqual(back, r) {
					t.Fatalf("receipt round trip: %v", err)
				}
			}
			if resign && r.Sign(c) != nil {
				return
			}
			if err := r.Verify(c.KEL(), c.AID(), now); err == nil && r.Envelope.SignerAID != c.AID() {
				t.Fatalf("accepted a receipt signed by %s", r.Envelope.SignerAID)
			}
		}
		if v, err := payment.UnmarshalVoucher(b); err == nil {
			if vb, err := v.Marshal(); err == nil {
				back, err := payment.UnmarshalVoucher(vb)
				if err != nil || !reflect.DeepEqual(back, v) {
					t.Fatalf("voucher round trip: %v", err)
				}
			}
			if resign && v.Sign(c) != nil {
				return
			}
			err := v.Verify(c.KEL(), c.AID(), v.PayTo, v.Capability, v.Network, now)
			expired := v.NotAfter != 0 && !inWindow(now, math.MinInt64+payment.ClockSkew, v.NotAfter)
			if err == nil {
				if v.Envelope.SignerAID != c.AID() || v.Nonce == "" || expired {
					t.Fatalf("accepted voucher %+v at %d", v, now)
				}
			} else if resign && v.Nonce != "" && !expired {
				t.Fatalf("refused a signed, unexpired voucher (not after %d, now %d): %v", v.NotAfter, now, err)
			}
		}
	})
}

func FuzzParseAmount(f *testing.F) {
	for _, s := range []string{"0", "1", "007", "18446744073709551615", "18446744073709551616", "-1", "+1", "1_0", " 1", "1e3"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := payment.ParseAmount(s)
		if err != nil {
			return
		}
		// Only decimal digits are accepted, and the value is the one they spell.
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				t.Fatalf("amount %q with a non-digit accepted as %d", s, n)
			}
		}
		if want, _ := new(big.Int).SetString(s, 10); want == nil || want.Cmp(new(big.Int).SetUint64(n)) != 0 {
			t.Fatalf("amount %q parsed as %d", s, n)
		}
		if back, err := payment.ParseAmount(payment.Amount(n)); err != nil || back != n {
			t.Fatalf("Amount(%d) does not parse back", n)
		}
		if canon := payment.Amount(n); canon != s && !bytes.HasPrefix([]byte(s), []byte("0")) {
			t.Fatalf("amount %q has another canonical form %q", s, canon)
		}
	})
}
