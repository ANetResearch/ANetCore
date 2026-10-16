package delegation_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/delegation"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/tsir"
)

// testDay is the UTC day the test tasks run on (2026-01-01).
const testDay = 20454

func label32(label string) []byte {
	s := sha256.Sum256([]byte("anet-test/delegation/" + label))
	return s[:]
}

// task is one delegated task as its requester holds it.
type task struct {
	ix        string
	taskDoc   []byte // the TaskDoc bytes as sent
	binding   *delegation.TaskBinding
	reviewKey ed25519.PrivateKey
}

// newTask builds a TaskDoc carrying a task binding for requester, signed by requester.
func newTask(tb testing.TB, requester *identity.Controller, ix string) *task {
	tb.Helper()
	rk := ed25519.NewKeyFromSeed(label32("review/" + ix))
	rc, err := evidence.RequesterCommit(requester.AID(), label32("rsalt/"+ix))
	if err != nil {
		tb.Fatal(err)
	}
	b := &delegation.TaskBinding{
		Nonce:           base64.RawURLEncoding.EncodeToString(label32("nonce/" + ix)[:16]),
		RequesterCommit: rc,
		ReviewKey:       rk.Public().(ed25519.PublicKey),
	}
	ctx, err := b.Contexts()
	if err != nil {
		tb.Fatal(err)
	}
	doc := &tsir.TaskDoc{
		Version: tsir.VersionPair{Major: 1},
		Tasks:   []tsir.Task{{Intent: tsir.Intent{Summary: "caption", Body: "caption the image"}, Contexts: ctx}},
	}
	if err := doc.Sign(requester); err != nil {
		tb.Fatal(err)
	}
	raw, err := coredet.Marshal(*doc)
	if err != nil {
		tb.Fatal(err)
	}
	return &task{ix: ix, taskDoc: raw, binding: b, reviewKey: rk}
}

// receipt is the body a provider signs for the task, before any edit.
func (tk *task) receipt(tb testing.TB, deliverable []byte) *evidence.ReceiptBody {
	tb.Helper()
	ixc, err := evidence.IXCommit(tk.ix, tk.binding.Nonce)
	if err != nil {
		tb.Fatal(err)
	}
	return &evidence.ReceiptBody{IXCommit: ixc, RequesterCommit: tk.binding.RequesterCommit, ReviewKey: tk.binding.ReviewKey,
		RequestCID: anetcid.MustSum(tk.taskDoc), ResultCID: anetcid.MustSum(deliverable), CompletedDay: testDay}
}

// completion is the ResultResp provider sends for the task, with body edited by edit (if any) before
// provider signs it.
func (tk *task) completion(tb testing.TB, provider *identity.Controller, deliverable []byte, edit func(*evidence.ReceiptBody)) *delegation.ResultResp {
	tb.Helper()
	body := tk.receipt(tb, deliverable)
	if edit != nil {
		edit(body)
	}
	w, err := body.Sign(provider)
	if err != nil {
		tb.Fatal(err)
	}
	raw, err := w.Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	return &delegation.ResultResp{Status: delegation.StatusDone, Deliverable: deliverable, Receipt: raw}
}

// check is what the requester holds about the task it sent to provider.
func (tk *task) check(provider string) delegation.ResultCheck {
	return delegation.ResultCheck{IX: tk.ix, Provider: provider, TaskDoc: tk.taskDoc, DelegatedDay: testDay, Today: testDay}
}
