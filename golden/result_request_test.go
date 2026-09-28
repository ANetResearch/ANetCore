package golden

import (
	"errors"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/delegation"
	"github.com/ANetResearch/ANetCore/identity"
)

// VEC-RESULT-2-REQ: the VEC-RESULT-2 completion checked with the request
// binding (delegation.VerifyResultForRequest). It verifies against the
// request CID its receipt carries and is refused, ErrRequestMismatch,
// against any other: an implementation that skips the binding accepts the
// second case and fails this vector.
func TestVEC_RESULT_2_RequestBinding(t *testing.T) {
	c := identity.SuiteController()
	deliverable := []byte(`{"ok":true}`)
	rc := goldenReceipt()
	cid, err := anetcid.Sum(deliverable)
	if err != nil {
		t.Fatal(err)
	}
	rc.ResultCID = cid
	if err := rc.Sign(c); err != nil {
		t.Fatal(err)
	}
	receipt, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	rr := &delegation.ResultResp{Status: delegation.StatusDone, Deliverable: deliverable, Receipt: receipt,
		Metadata: []byte(goldenMetadata)}
	if _, err := delegation.VerifyResultForRequest(rr, c.KEL(), rc.InteractionID, rc.RequesterAID,
		rc.ProviderAID, "bafyreigoldenrequest", rc.CompletedAt); err != nil {
		t.Errorf("bound to the request its receipt names, the golden completion must verify: %v", err)
	}
	_, err = delegation.VerifyResultForRequest(rr, c.KEL(), rc.InteractionID, rc.RequesterAID,
		rc.ProviderAID, "bafyreianotherrequest", rc.CompletedAt)
	if !errors.Is(err, delegation.ErrRequestMismatch) {
		t.Errorf("bound to another request: want ErrRequestMismatch, got %v", err)
	}
}
