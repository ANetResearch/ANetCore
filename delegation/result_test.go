package delegation_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/delegation"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
)

func incept(t testing.TB) *identity.Controller {
	t.Helper()
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const msgTime = uint64(testDay)*evidence.DayMS + 1000

func TestAGenuineCompletionVerifies(t *testing.T) {
	requester, provider := incept(t), incept(t)
	tk := newTask(t, requester, "ix-1")
	deliverable := []byte(`{"answer":42}`)
	rc, err := delegation.VerifyResultForRequest(tk.completion(t, provider, deliverable, nil), provider.KEL(), tk.check(provider.AID()), msgTime)
	if err != nil {
		t.Fatalf("a genuine completion must verify: %v", err)
	}
	if rc.Provider != provider.AID() || rc.ResultCID != anetcid.MustSum(deliverable) {
		t.Fatalf("receipt %+v", rc)
	}
}

// Each case is a lie a provider can tell while holding a perfectly valid signature (HPP PAY-V8).
func TestAResultMustBeTheAnswerToTheRequestItClaims(t *testing.T) {
	requester, provider, other := incept(t), incept(t), incept(t)
	tk := newTask(t, requester, "ix-1")
	another := newTask(t, requester, "ix-2")
	deliverable := []byte(`{"answer":42}`)
	cases := []struct {
		lie  string
		rr   *delegation.ResultResp
		kel  []identity.SignedEvent
		want error
		text string
	}{
		{"sign a receipt for different content", tk.completion(t, provider, deliverable, func(b *evidence.ReceiptBody) {
			b.ResultCID = anetcid.MustSum([]byte("something else"))
		}), provider.KEL(), delegation.ErrReceiptMismatch, "receipt covers"},
		{"swap the deliverable after signing", func() *delegation.ResultResp {
			rr := tk.completion(t, provider, deliverable, nil)
			rr.Deliverable = []byte(`{"answer":0}`)
			return rr
		}(), provider.KEL(), delegation.ErrReceiptMismatch, "receipt covers"},
		{"answer with someone else's receipt", tk.completion(t, other, deliverable, nil), other.KEL(),
			delegation.ErrReceiptMismatch, "the task went to"},
		{"recycle a receipt from another interaction", tk.completion(t, provider, deliverable, func(b *evidence.ReceiptBody) {
			b.IXCommit, _ = evidence.IXCommit("ix-2", tk.binding.Nonce)
		}), provider.KEL(), delegation.ErrReceiptMismatch, "ix_commit"},
		{"a receipt for another task of this requester", another.completion(t, provider, deliverable, nil), provider.KEL(),
			delegation.ErrReceiptMismatch, "ix_commit"},
		{"name another requester", tk.completion(t, provider, deliverable, func(b *evidence.ReceiptBody) {
			b.RequesterCommit, _ = evidence.RequesterCommit(other.AID(), make([]byte, 32))
		}), provider.KEL(), delegation.ErrReceiptMismatch, "requester_commit"},
		{"substitute a review key the provider holds", tk.completion(t, provider, deliverable, func(b *evidence.ReceiptBody) {
			b.ReviewKey = another.binding.ReviewKey
		}), provider.KEL(), delegation.ErrReceiptMismatch, "review_key"},
		{"name a request that was never made", tk.completion(t, provider, deliverable, func(b *evidence.ReceiptBody) {
			b.RequestCID = anetcid.MustSum([]byte("a request nobody made"))
		}), provider.KEL(), delegation.ErrRequestMismatch, "the request sent was"},
		{"date it before the task", tk.completion(t, provider, deliverable, func(b *evidence.ReceiptBody) { b.CompletedDay = testDay - 2 }),
			provider.KEL(), delegation.ErrReceiptMismatch, "completed on day"},
		{"date it after tomorrow", tk.completion(t, provider, deliverable, func(b *evidence.ReceiptBody) { b.CompletedDay = testDay + 2 }),
			provider.KEL(), delegation.ErrReceiptMismatch, "completed on day"},
		{"sign with a key the KEL does not contain", tk.completion(t, provider, deliverable, nil), other.KEL(),
			evidence.ErrSignature, "signature invalid"},
		{"send no receipt at all", &delegation.ResultResp{Status: delegation.StatusDone, Deliverable: deliverable}, provider.KEL(),
			nil, "no receipt"},
		{"send a receipt that is not one", &delegation.ResultResp{Status: delegation.StatusDone, Deliverable: deliverable, Receipt: []byte{0xa0}},
			provider.KEL(), evidence.ErrMalformed, "undecodable receipt"},
	}
	for _, tc := range cases {
		t.Run(tc.lie, func(t *testing.T) {
			_, err := delegation.VerifyResultForRequest(tc.rr, tc.kel, tk.check(provider.AID()), msgTime)
			if err == nil {
				t.Fatalf("accepted a completion that would %s", tc.lie)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("refused as %v, want %v", err, tc.want)
			}
			if !strings.Contains(err.Error(), tc.text) {
				t.Errorf("refused for the wrong reason: %v (want %q)", err, tc.text)
			}
		})
	}
}

// The day window is DelegatedDay − 1 … Today + 1, edges included.
func TestTheReceiptsDayWindow(t *testing.T) {
	requester, provider := incept(t), incept(t)
	tk := newTask(t, requester, "ix-1")
	want := tk.check(provider.AID())
	want.DelegatedDay, want.Today = testDay, testDay+3
	for day, ok := range map[uint64]bool{testDay - 2: false, testDay - 1: true, testDay: true, testDay + 4: true, testDay + 5: false} {
		rr := tk.completion(t, provider, []byte("x"), func(b *evidence.ReceiptBody) { b.CompletedDay = day })
		_, err := delegation.VerifyResultForRequest(rr, provider.KEL(), want, msgTime)
		if (err == nil) != ok {
			t.Errorf("completed_day %d (task from %d, today %d): accepted %v, want %v (%v)", day, want.DelegatedDay, want.Today, err == nil, ok, err)
		}
	}
	// A delegation on day 0 does not underflow the window.
	want.DelegatedDay, want.Today = 0, 0
	rr := tk.completion(t, provider, []byte("x"), func(b *evidence.ReceiptBody) { b.CompletedDay = 0 })
	if _, err := delegation.VerifyResultForRequest(rr, provider.KEL(), want, msgTime); err != nil {
		t.Errorf("day 0: %v", err)
	}
}

// Not knowing and knowing-it-is-false are different states, and the caller must be able to tell
// them apart; a check missing what it binds against is refused rather than half done.
func TestWhatTheCheckNeeds(t *testing.T) {
	requester, provider := incept(t), incept(t)
	tk := newTask(t, requester, "ix-1")
	rr := tk.completion(t, provider, []byte("x"), nil)
	if _, err := delegation.VerifyResultForRequest(rr, nil, tk.check(provider.AID()), msgTime); !errors.Is(err, delegation.ErrUnverifiable) {
		t.Fatalf("no KEL: want ErrUnverifiable, got %v", err)
	}
	for name, edit := range map[string]func(*delegation.ResultCheck){
		"no interaction": func(c *delegation.ResultCheck) { c.IX = "" },
		"no provider":    func(c *delegation.ResultCheck) { c.Provider = "" },
		"no TaskDoc":     func(c *delegation.ResultCheck) { c.TaskDoc = nil },
	} {
		want := tk.check(provider.AID())
		edit(&want)
		if _, err := delegation.VerifyResultForRequest(rr, provider.KEL(), want, msgTime); err == nil || errors.Is(err, delegation.ErrUnverifiable) {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}
	// A TaskDoc that carries no binding has nothing to check the receipt against.
	unbound := tk.check(provider.AID())
	unbound.TaskDoc = func() []byte {
		other := newTask(t, requester, "ix-1")
		return other.taskDoc[:len(other.taskDoc)-1]
	}()
	if _, err := delegation.VerifyResultForRequest(rr, provider.KEL(), unbound, msgTime); err == nil {
		t.Error("an undecodable TaskDoc must refuse")
	}
}

// The KEL in the body is never what the receipt is checked against; when present it must be the
// resolved KEL or a prefix of it.
func TestTheBodyKELNeverDecides(t *testing.T) {
	requester, provider, other := incept(t), incept(t), incept(t)
	tk := newTask(t, requester, "ix-1")
	marshal := func(kel []identity.SignedEvent) []byte {
		b, err := identity.MarshalKEL(kel)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	rr := tk.completion(t, provider, []byte("x"), nil)
	rr.KEL = marshal(provider.KEL())
	if _, err := delegation.VerifyResultForRequest(rr, provider.KEL(), tk.check(provider.AID()), msgTime); err != nil {
		t.Fatalf("body KEL equal to the resolved one: %v", err)
	}
	rr.KEL = marshal(other.KEL())
	if _, err := delegation.VerifyResultForRequest(rr, provider.KEL(), tk.check(provider.AID()), msgTime); !errors.Is(err, delegation.ErrBodyKELMismatch) ||
		!errors.Is(err, identity.ErrKELFork) {
		t.Fatalf("body KEL forks: want ErrBodyKELMismatch wrapping ErrKELFork, got %v", err)
	}
	rr.KEL = []byte("not a kel")
	if _, err := delegation.VerifyResultForRequest(rr, provider.KEL(), tk.check(provider.AID()), msgTime); err == nil ||
		!strings.Contains(err.Error(), "bad body KEL") {
		t.Fatalf("undecodable body KEL: %v", err)
	}
}

// msgTime and the resolved KEL drive revocation: a receipt signed with a key the provider retired
// is accepted only for a result that arrived before the retirement.
func TestMsgTimeDrivesRevocation(t *testing.T) {
	requester, provider := incept(t), incept(t)
	tk := newTask(t, requester, "ix-1")
	rr := tk.completion(t, provider, []byte("x"), nil)
	if err := provider.Rotate(msgTime + 5000); err != nil {
		t.Fatal(err)
	}
	if _, err := delegation.VerifyResultForRequest(rr, provider.KEL(), tk.check(provider.AID()), msgTime+4999); err != nil {
		t.Errorf("before the rotation: must verify, got %v", err)
	}
	if _, err := delegation.VerifyResultForRequest(rr, provider.KEL(), tk.check(provider.AID()), msgTime+5000); err == nil ||
		!strings.Contains(err.Error(), "REVOKED_KEY") {
		t.Errorf("at the rotation: want REVOKED_KEY, got %v", err)
	}
}
