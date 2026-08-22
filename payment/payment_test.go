package payment_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
)

func auth(t *testing.T, payer *identity.Controller, payTo string, amount uint64) *payment.Authorization {
	t.Helper()
	now := time.Now().UnixMilli()
	a := &payment.Authorization{
		PayTo: payTo, Amount: amount, Network: payment.CreditNetwork("did:anet:hub"),
		Nonce: "n-1", IssuedAt: now, NotAfter: now + 60_000, InteractionID: "ix-1",
	}
	if err := a.Sign(payer); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAGenuineAuthorizationVerifies(t *testing.T) {
	payer, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	a := auth(t, payer, "did:anet:provider", 100)
	if a.Payer != payer.AID() {
		t.Errorf("signing must set the payer to the signer, got %s", a.Payer)
	}
	if err := a.Verify(payer.KEL(), time.Now().UnixMilli()); err != nil {
		t.Fatalf("a genuine authorization must verify: %v", err)
	}
	// The id is the hub's idempotency key, so it must derive from content
	// rather than from when it was asked for.
	id1, _ := a.ID()
	id2, _ := a.ID()
	if id1 == "" || id1 != id2 {
		t.Errorf("authorization id is not stable: %q vs %q", id1, id2)
	}
}

// Each of these is a way to spend money that was not authorised.
func TestEveryWayOfPayingWithoutPermission(t *testing.T) {
	payer, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	// The instant of verification is taken per case rather than up front:
	// an authorization signed a millisecond after "now" was captured is
	// not yet valid, and the window check would fire before the signature
	// check the case is actually about.
	cases := []struct {
		fraud    string
		make     func() *payment.Authorization
		kel      []identity.SignedEvent
		atOffset time.Duration
		want     string
	}{
		{
			fraud: "raise the amount after it was signed",
			make: func() *payment.Authorization {
				a := auth(t, payer, "did:anet:provider", 100)
				a.Amount = 100000
				return a
			},
			kel: payer.KEL(), want: "signature",
		},
		{
			fraud: "redirect it to a different payee",
			make: func() *payment.Authorization {
				a := auth(t, payer, "did:anet:provider", 100)
				a.PayTo = "did:anet:mallory"
				return a
			},
			kel: payer.KEL(), want: "signature",
		},
		{
			fraud: "spend it on a different interaction",
			make: func() *payment.Authorization {
				a := auth(t, payer, "did:anet:provider", 100)
				a.InteractionID = "ix-something-else"
				return a
			},
			kel: payer.KEL(), want: "signature",
		},
		{
			fraud: "settle it on another hub's ledger",
			make: func() *payment.Authorization {
				a := auth(t, payer, "did:anet:provider", 100)
				a.Network = payment.CreditNetwork("did:anet:other-hub")
				return a
			},
			kel: payer.KEL(), want: "signature",
		},
		{
			fraud: "sign it yourself and name someone else as payer",
			make: func() *payment.Authorization {
				a := auth(t, stranger, "did:anet:provider", 100)
				a.Payer = payer.AID()
				return a
			},
			kel: payer.KEL(), want: "not the payer",
		},
		{
			fraud: "present it after it expired",
			make:  func() *payment.Authorization { return auth(t, payer, "did:anet:provider", 100) },
			kel:   payer.KEL(), atOffset: 2 * time.Minute, want: "validity window",
		},
		{
			fraud: "present it before it was issued",
			make:  func() *payment.Authorization { return auth(t, payer, "did:anet:provider", 100) },
			kel:   payer.KEL(), atOffset: -2 * time.Minute, want: "validity window",
		},
		{
			fraud: "hand over no signature at all",
			make: func() *payment.Authorization {
				a := auth(t, payer, "did:anet:provider", 100)
				a.Envelope = nil
				return a
			},
			kel: payer.KEL(), want: "unsigned",
		},
	}
	for _, tc := range cases {
		t.Run(tc.fraud, func(t *testing.T) {
			at := time.Now().Add(tc.atOffset).UnixMilli()
			err := tc.make().Verify(tc.kel, at)
			if err == nil {
				t.Fatalf("accepted an authorization that would %s", tc.fraud)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: %v (want %q)", err, tc.want)
			}
		})
	}
}

// The signature must survive the wire. cbor:"-" keeps the envelope out of
// the bytes it covers, so marshalling the object alone would ship an
// unsigned authorization — the bug the org credential once had.
func TestTheSignatureSurvivesTheWire(t *testing.T) {
	payer, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	a := auth(t, payer, "did:anet:provider", 250)
	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := payment.UnmarshalAuthorization(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.Envelope == nil {
		t.Fatal("the signature did not survive — every authorization would arrive unsigned")
	}
	if err := back.Verify(payer.KEL(), time.Now().UnixMilli()); err != nil {
		t.Errorf("a round-tripped authorization must still verify: %v", err)
	}
	idA, _ := a.ID()
	idB, _ := back.ID()
	if idA != idB {
		t.Errorf("the idempotency key changed on the wire: %s vs %s", idA, idB)
	}
}

// The x402 objects are JSON on the wire and must keep the spec's field
// names — a facilitator written against the spec has to understand them.
func TestTheX402ObjectsKeepTheSpecFieldNames(t *testing.T) {
	req := payment.PaymentRequired{
		X402Version: payment.Version,
		Accepts: []payment.PaymentOption{{
			Scheme: payment.SchemeCredit, Network: payment.CreditNetwork("did:anet:hub"),
			Amount: payment.Amount(100), Asset: payment.AssetCredit, PayTo: "did:anet:provider",
		}},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"x402Version":2`, `"accepts"`, `"scheme":"anet-credit"`,
		`"network":"hub:did:anet:hub"`, `"amount":"100"`, `"payTo"`,
	} {
		if !strings.Contains(string(b), field) {
			t.Errorf("missing %s in %s", field, b)
		}
	}
	// Amounts are strings, so what someone owes never passes through a
	// JSON number.
	if strings.Contains(string(b), `"amount":100`) {
		t.Error("amount was encoded as a number")
	}
}

func TestAmountRoundTrip(t *testing.T) {
	for _, n := range []uint64{0, 1, 999999999999} {
		got, err := payment.ParseAmount(payment.Amount(n))
		if err != nil || got != n {
			t.Errorf("%d round-tripped to %d (%v)", n, got, err)
		}
	}
	for _, bad := range []string{"", "-1", "1.5", "abc", "0x10"} {
		if _, err := payment.ParseAmount(bad); err == nil {
			t.Errorf("%q must not parse as an amount", bad)
		}
	}
}
