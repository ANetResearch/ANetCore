package delegation

import (
	"errors"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
)

// The request binding: a receipt names the request it answers, and a
// requester that holds the request it sent holds the provider to it. A
// provider's receipt for any other request — bytes it made up, whose CID it
// can compute — is refused, not verified (red-team F15).
func TestVerifyResultForRequestBindsTheRequest(t *testing.T) {
	provider, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	const (
		ix   = "ix-1"
		reqA = "did:anet:requester"
		at   = 1767225600000
	)
	sent := []byte("the request this requester signed and sent")
	sentCID, err := anetcid.Sum(sent)
	if err != nil {
		t.Fatal(err)
	}
	madeUp, err := anetcid.Sum([]byte("a request nobody made"))
	if err != nil {
		t.Fatal(err)
	}
	deliverable := []byte(`{"answer":42}`)
	resultCID, err := anetcid.Sum(deliverable)
	if err != nil {
		t.Fatal(err)
	}
	completion := func(requestCID string) *ResultResp {
		rc := &evidence.Receipt{InteractionID: ix, RequesterAID: reqA, ProviderAID: provider.AID(),
			RequestCID: requestCID, ResultCID: resultCID, CompletedAt: at}
		if err := rc.Sign(provider); err != nil {
			t.Fatal(err)
		}
		b, err := rc.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return &ResultResp{Status: StatusDone, Deliverable: deliverable, Receipt: b}
	}
	kel := provider.KEL()

	if rc, err := VerifyResultForRequest(completion(sentCID), kel, ix, reqA, provider.AID(), sentCID, at); err != nil ||
		rc.RequestCID != sentCID {
		t.Fatalf("a receipt for the request sent must verify: %v", err)
	}
	_, err = VerifyResultForRequest(completion(madeUp), kel, ix, reqA, provider.AID(), sentCID, at)
	if !errors.Is(err, ErrRequestMismatch) {
		t.Fatalf("a receipt for another request: want ErrRequestMismatch, got %v", err)
	}
	// An empty requestCID skips the one binding (a row that kept no
	// request CID), like the other identifiers.
	if _, err := VerifyResultForRequest(completion(madeUp), kel, ix, reqA, provider.AID(), "", at); err != nil {
		t.Fatalf("no request CID to bind: %v", err)
	}
	// VerifyResultWithKEL is the same check without the binding.
	if _, err := VerifyResultWithKEL(completion(madeUp), kel, ix, reqA, provider.AID(), at); err != nil {
		t.Fatalf("VerifyResultWithKEL: %v", err)
	}
	// The other bindings still apply alongside it.
	if _, err := VerifyResultForRequest(completion(sentCID), kel, "ix-99", reqA, provider.AID(), sentCID, at); err == nil {
		t.Fatal("a receipt for another interaction verified")
	}
}
