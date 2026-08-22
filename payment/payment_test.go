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

// A settlement receipt is what lets one hub credit its own user on
// another hub's word. That word has to be attributable, and pinned to the
// hub whose ledger it claims to have moved.
func TestASettlementReceiptIsAttributable(t *testing.T) {
	hubA, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	hubB, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	r := &payment.Receipt{
		AuthID: "bafyauth", Payer: "did:anet:payer", PayTo: "did:anet:provider",
		Amount: 120, Network: payment.CreditNetwork(hubA.AID()),
		SettleAt: time.Now().UnixMilli(),
	}
	if err := r.Sign(hubA); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	if err := r.Verify(hubA.KEL(), hubA.AID(), now); err != nil {
		t.Fatalf("a genuine receipt must verify: %v", err)
	}
	// Signed by a hub other than the one whose ledger it names. Without
	// pinning the signer, a reader has no reason to notice.
	if err := r.Verify(hubB.KEL(), hubB.AID(), now); err == nil {
		t.Error("a receipt verified against the wrong hub")
	}
	// Altered after signing.
	r.Amount = 12000
	if err := r.Verify(hubA.KEL(), hubA.AID(), now); err == nil {
		t.Error("an inflated receipt verified")
	}

	// And the signature survives the wire, since the envelope is detached.
	r.Amount = 120
	if err := r.Sign(hubA); err != nil {
		t.Fatal(err)
	}
	b, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := payment.UnmarshalReceipt(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.Envelope == nil {
		t.Fatal("the signature did not survive the wire")
	}
	if err := back.Verify(hubA.KEL(), hubA.AID(), now); err != nil {
		t.Errorf("a round-tripped receipt must verify: %v", err)
	}
}

func voucher(t *testing.T, hub *identity.Controller, payTo, capID string) *payment.Voucher {
	t.Helper()
	v := &payment.Voucher{
		AuthID: "auth-1", Payer: "did:anet:buyer", PayTo: payTo, Capability: capID,
		Amount: 100, Network: payment.CreditNetwork("did:anet:hub"),
		NotAfter: time.Now().Add(time.Minute).UnixMilli(), Nonce: "v-1",
	}
	if err := v.Sign(hub); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAGenuineVoucherVerifies(t *testing.T) {
	hub, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	v := voucher(t, hub, "did:anet:provider", "image.caption")
	err = v.Verify(hub.KEL(), hub.AID(), "did:anet:provider", "image.caption",
		payment.CreditNetwork("did:anet:hub"), time.Now().UnixMilli())
	if err != nil {
		t.Fatalf("a genuine voucher must verify: %v", err)
	}
}

// Each of these is a real signature over a real statement that does not
// authorise the work about to be done. The voucher travels through the
// buyer's hands, so every one of them is something the buyer can attempt.
func TestEveryWayOfRedeemingAVoucherYouShouldNot(t *testing.T) {
	hub, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	net := payment.CreditNetwork("did:anet:hub")

	cases := []struct {
		name string
		make func() (*payment.Voucher, []identity.SignedEvent)
		// what the redeeming provider believes it is doing
		payTo, capID, network string
		want                  string
	}{
		{
			name: "bought somebody else's capability and presented here",
			make: func() (*payment.Voucher, []identity.SignedEvent) {
				return voucher(t, hub, "did:anet:elsewhere", "image.caption"), hub.KEL()
			},
			payTo: "did:anet:provider", capID: "image.caption", network: net,
			want: "payable to",
		},
		{
			name: "paid for the cheap capability, redeemed against the expensive one",
			make: func() (*payment.Voucher, []identity.SignedEvent) {
				return voucher(t, hub, "did:anet:provider", "image.thumbnail"), hub.KEL()
			},
			payTo: "did:anet:provider", capID: "image.caption", network: net,
			want: "bought",
		},
		{
			// The right hub signing the wrong ledger. Defence in depth
			// rather than paranoia: a hub that federates settles on more
			// than one network, and an off-by-one there would have a
			// provider doing paid work against credit it cannot draw on.
			name: "settled on a ledger this provider has no account on",
			make: func() (*payment.Voucher, []identity.SignedEvent) {
				v := &payment.Voucher{
					AuthID: "auth-1", Payer: "did:anet:buyer", PayTo: "did:anet:provider",
					Capability: "image.caption", Amount: 100,
					Network:  payment.CreditNetwork("did:anet:other-hub"),
					NotAfter: now + 60_000, Nonce: "v-1",
				}
				if err := v.Sign(hub); err != nil {
					t.Fatal(err)
				}
				return v, hub.KEL()
			},
			payTo: "did:anet:provider", capID: "image.caption", network: net,
			want: "settles on",
		},
		{
			name: "expired, kept, presented later",
			make: func() (*payment.Voucher, []identity.SignedEvent) {
				v := &payment.Voucher{
					AuthID: "auth-1", Payer: "did:anet:buyer", PayTo: "did:anet:provider",
					Capability: "image.caption", Amount: 100, Network: net,
					NotAfter: now - 1, Nonce: "v-1",
				}
				if err := v.Sign(hub); err != nil {
					t.Fatal(err)
				}
				return v, hub.KEL()
			},
			payTo: "did:anet:provider", capID: "image.caption", network: net,
			want: "expired",
		},
		{
			name: "no nonce, so it could be spent for ever",
			make: func() (*payment.Voucher, []identity.SignedEvent) {
				v := &payment.Voucher{
					AuthID: "auth-1", Payer: "did:anet:buyer", PayTo: "did:anet:provider",
					Capability: "image.caption", Amount: 100, Network: net,
					NotAfter: now + 60_000,
				}
				if err := v.Sign(hub); err != nil {
					t.Fatal(err)
				}
				return v, hub.KEL()
			},
			payTo: "did:anet:provider", capID: "image.caption", network: net,
			want: "spent only once",
		},
		{
			name: "amount raised after the hub signed it",
			make: func() (*payment.Voucher, []identity.SignedEvent) {
				v := voucher(t, hub, "did:anet:provider", "image.caption")
				v.Amount = 1
				return v, hub.KEL()
			},
			payTo: "did:anet:provider", capID: "image.caption", network: net,
			want: "signature",
		},
		{
			name: "unsigned",
			make: func() (*payment.Voucher, []identity.SignedEvent) {
				v := voucher(t, hub, "did:anet:provider", "image.caption")
				v.Envelope = nil
				return v, hub.KEL()
			},
			payTo: "did:anet:provider", capID: "image.caption", network: net,
			want: "unsigned",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, kel := tc.make()
			err := v.Verify(kel, hub.AID(), tc.payTo, tc.capID, tc.network, now)
			if err == nil {
				t.Fatal("this must be refused, and was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: %v (want mention of %q)", err, tc.want)
			}
		})
	}
}

// A provider that trusts its own hub must not accept a voucher signed by
// a stranger, even a well-formed one. Signature validity is not identity.
func TestAVoucherFromAnUnexpectedSignerIsRefused(t *testing.T) {
	hub, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	impostor, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	v := voucher(t, impostor, "did:anet:provider", "image.caption")
	err = v.Verify(impostor.KEL(), hub.AID(), "did:anet:provider", "image.caption",
		payment.CreditNetwork("did:anet:hub"), time.Now().UnixMilli())
	if err == nil {
		t.Fatal("a voucher signed by an unexpected hub must be refused")
	}
	if !strings.Contains(err.Error(), "not the expected hub") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

func TestAVoucherSurvivesTheWire(t *testing.T) {
	hub, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	v := voucher(t, hub, "did:anet:provider", "image.caption")
	raw, err := v.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := payment.UnmarshalVoucher(raw)
	if err != nil {
		t.Fatal(err)
	}
	// The buyer carries this between two parties that never speak. If the
	// signature did not ride along, the provider would have nothing to
	// check and would be trusting the buyer's word for the payment.
	err = back.Verify(hub.KEL(), hub.AID(), "did:anet:provider", "image.caption",
		payment.CreditNetwork("did:anet:hub"), time.Now().UnixMilli())
	if err != nil {
		t.Fatalf("a voucher off the wire must still verify: %v", err)
	}
	id1, _ := v.ID()
	id2, _ := back.ID()
	if id1 != id2 || id1 == "" {
		t.Errorf("voucher id changed across the wire: %q vs %q", id1, id2)
	}
}
