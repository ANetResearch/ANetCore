package payment_test

import (
	"math"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
)

// The validity window is compared without adding the skew to the signer's value. NotAfter +
// ClockSkew used to overflow for a NotAfter near math.MaxInt64 and wrap negative, so an
// authorization or voucher meant never to expire was refused as expired at every moment (ANet
// docs/notes/0033).
func TestWindowEdgesDoNotOverflow(t *testing.T) {
	c := identity.SuiteController()
	const now = int64(1767225600000)
	for _, notAfter := range []int64{math.MaxInt64, math.MaxInt64 - payment.ClockSkew + 1, math.MaxInt64 - 1} {
		a := &payment.Authorization{PayTo: "p", Amount: 1, Network: "hub:x", Nonce: "n", IssuedAt: now - 1000, NotAfter: notAfter}
		if err := a.Sign(c); err != nil {
			t.Fatal(err)
		}
		if err := a.Verify(c.KEL(), now); err != nil {
			t.Errorf("authorization valid until %d refused at %d: %v", notAfter, now, err)
		}
		v := &payment.Voucher{AuthID: "a", PayTo: "q", Capability: "cap", Network: "hub:x", NotAfter: notAfter, Nonce: "n"}
		if err := v.Sign(c); err != nil {
			t.Fatal(err)
		}
		if err := v.Verify(c.KEL(), c.AID(), "q", "cap", "hub:x", now); err != nil {
			t.Errorf("voucher valid until %d refused at %d: %v", notAfter, now, err)
		}
	}
	// The window still closes: just past NotAfter + ClockSkew, and before IssuedAt - ClockSkew.
	a := &payment.Authorization{PayTo: "p", Amount: 1, Network: "hub:x", Nonce: "n", IssuedAt: now, NotAfter: now + 60_000}
	if err := a.Sign(c); err != nil {
		t.Fatal(err)
	}
	for _, at := range []int64{now + 60_000 + payment.ClockSkew + 1, now - payment.ClockSkew - 1, math.MaxInt64, math.MinInt64} {
		if err := a.Verify(c.KEL(), at); err == nil {
			t.Errorf("authorization for %d..%d accepted at %d", a.IssuedAt, a.NotAfter, at)
		}
	}
	for _, at := range []int64{now + 60_000 + payment.ClockSkew, now - payment.ClockSkew} {
		if err := a.Verify(c.KEL(), at); err != nil {
			t.Errorf("authorization for %d..%d refused at the skew edge %d: %v", a.IssuedAt, a.NotAfter, at, err)
		}
	}
	v := &payment.Voucher{AuthID: "a", PayTo: "q", Capability: "cap", Network: "hub:x", NotAfter: math.MinInt64 + 5, Nonce: "n"}
	if err := v.Sign(c); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(c.KEL(), c.AID(), "q", "cap", "hub:x", math.MaxInt64); err == nil {
		t.Error("voucher long expired accepted")
	}
}
