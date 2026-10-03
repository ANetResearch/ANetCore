package golden

import (
	"errors"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/delegation"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/tsir"
)

// VEC-RESULT-2-REQ: the VEC-RESULT-2 completion checked with the request binding
// (delegation.VerifyResultForRequest). It verifies against the TaskDoc its receipt names, and is
// refused, ErrRequestMismatch, against another TaskDoc that carries the same task binding: an
// implementation that skips the request CID accepts the second case and fails this vector.
func TestVEC_RESULT_2_RequestBinding(t *testing.T) {
	c := identity.SuiteController()
	ev := goldenReceiptV2(t)
	rr := &delegation.ResultResp{Status: delegation.StatusDone, Deliverable: ev.Deliverable, Receipt: ev.Wire,
		Metadata: []byte(goldenMetadata)}
	check := delegation.ResultCheck{IX: ev.IX, Provider: c.AID(), TaskDoc: ev.TaskDoc,
		DelegatedDay: ev.CompletedDay, Today: ev.CompletedDay}
	at := ev.CompletedDay * 86_400_000
	if _, err := delegation.VerifyResultForRequest(rr, c.KEL(), check, at); err != nil {
		t.Errorf("bound to the request its receipt names, the golden completion must verify: %v", err)
	}
	var doc tsir.TaskDoc
	if err := coredet.Unmarshal(ev.TaskDoc, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Tasks[0].Intent.Body = "caption another image"
	other, err := coredet.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	check.TaskDoc = other
	if _, err := delegation.VerifyResultForRequest(rr, c.KEL(), check, at); !errors.Is(err, delegation.ErrRequestMismatch) {
		t.Errorf("bound to another request: want ErrRequestMismatch, got %v", err)
	}
}
