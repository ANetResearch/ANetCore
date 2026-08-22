package evidence_test

import (
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
)

type pair struct {
	provider, requester  *identity.Controller
	rc                   *evidence.Receipt
	rv                   *evidence.Review
	request, deliverable []byte
}

// genuine builds a complete, honest interaction.
func genuine(t *testing.T) *pair {
	t.Helper()
	prov, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	req, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	request := []byte(`{"goal":"translate the whitepaper"}`)
	deliverable := []byte(`{"text":"…"}`)
	reqCID, err := anetcid.Sum(request)
	if err != nil {
		t.Fatal(err)
	}
	resCID, err := anetcid.Sum(deliverable)
	if err != nil {
		t.Fatal(err)
	}
	rc := &evidence.Receipt{
		InteractionID: "ix-1", RequesterAID: req.AID(), ProviderAID: prov.AID(),
		RequestCID: reqCID, ResultCID: resCID, CompletedAt: 1767225600000,
	}
	if err := rc.Sign(prov); err != nil {
		t.Fatal(err)
	}
	cid, err := rc.CID()
	if err != nil {
		t.Fatal(err)
	}
	rv := &evidence.Review{
		InteractionID: "ix-1", ReviewerAID: req.AID(), SubjectAID: prov.AID(),
		ReceiptCID: cid, Rating: 5, Comment: "fast", CreatedAt: 1767225600001,
	}
	if err := rv.Sign(req); err != nil {
		t.Fatal(err)
	}
	return &pair{prov, req, rc, rv, request, deliverable}
}

func (p *pair) check() error {
	return evidence.VerifyInterlock(p.rc, p.rv, p.request, p.deliverable,
		p.provider.KEL(), p.requester.KEL())
}

func TestAGenuineInteractionInterlocks(t *testing.T) {
	if err := genuine(t).check(); err != nil {
		t.Fatalf("a real interaction must verify: %v", err)
	}
}

// Every case is a way to manufacture a rating. A reputation system is
// defined by which of these it refuses.
func TestEveryWayOfManufacturingARating(t *testing.T) {
	cases := []struct {
		fraud  string
		break_ func(t *testing.T, p *pair)
		want   string
	}{
		{
			fraud:  "give yourself a nine-star review",
			break_: func(t *testing.T, p *pair) { p.rv.Rating = 9; resignReview(t, p) },
			want:   "out of range",
		},
		{
			fraud:  "attach a review of a different job",
			break_: func(t *testing.T, p *pair) { p.rv.InteractionID = "ix-other"; resignReview(t, p) },
			want:   "receipt is for interaction",
		},
		{
			fraud: "rate work you did not commission",
			break_: func(t *testing.T, p *pair) {
				stranger, _ := identity.Incept()
				p.rv.ReviewerAID = stranger.AID()
				p.requester = stranger
				resignReview(t, p)
			},
			want: "not the interaction's requester",
		},
		{
			fraud: "praise a provider who was not there",
			break_: func(t *testing.T, p *pair) {
				other, _ := identity.Incept()
				p.rv.SubjectAID = other.AID()
				resignReview(t, p)
			},
			want: "rates someone other than the provider",
		},
		{
			// The subtle one: a real receipt, a real review, signed by the
			// right people — pointing at a different receipt.
			fraud: "pair a real receipt with a review naming another",
			break_: func(t *testing.T, p *pair) {
				p.rv.ReceiptCID = "bafyreisomeotherreceipt"
				resignReview(t, p)
			},
			want: "references receipt",
		},
		{
			fraud:  "show a job that was never asked for",
			break_: func(t *testing.T, p *pair) { p.request = []byte(`{"goal":"something easier"}`) },
			want:   "request bytes hash to",
		},
		{
			fraud:  "show work that was never delivered",
			break_: func(t *testing.T, p *pair) { p.deliverable = []byte(`{"text":"a much better answer"}`) },
			want:   "deliverable hashes to",
		},
		{
			fraud: "issue a receipt the provider never signed",
			break_: func(t *testing.T, p *pair) {
				impostor, _ := identity.Incept()
				p.provider = impostor // the KEL no longer matches the signature
			},
			want: "receipt signature invalid",
		},
		{
			fraud: "write a review the requester never signed",
			break_: func(t *testing.T, p *pair) {
				impostor, _ := identity.Incept()
				p.requester = impostor
			},
			want: "review signature invalid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.fraud, func(t *testing.T) {
			p := genuine(t)
			tc.break_(t, p)
			err := p.check()
			if err == nil {
				t.Fatalf("accepted a rating manufactured by: %s", tc.fraud)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: %v (want %q)", err, tc.want)
			}
		})
	}
}

// An auditor given only the signed objects can still confirm everything
// except the content binding — and must be told that is what happened,
// not handed a pass that looks complete.
func TestContentBindingIsOptionalButNamed(t *testing.T) {
	p := genuine(t)
	if err := evidence.VerifyInterlock(p.rc, p.rv, nil, nil,
		p.provider.KEL(), p.requester.KEL()); err != nil {
		t.Fatalf("the signed objects alone must still interlock: %v", err)
	}
	// Skipping the bytes must not skip the anchoring between the objects.
	p.rv.ReceiptCID = "bafyreisomeotherreceipt"
	resignReview(t, p)
	if err := evidence.VerifyInterlock(p.rc, p.rv, nil, nil,
		p.provider.KEL(), p.requester.KEL()); err == nil {
		t.Error("without content, the receipt anchor is the only link left — it must still be checked")
	}
}

func TestNilsAreRefused(t *testing.T) {
	p := genuine(t)
	if err := evidence.VerifyInterlock(nil, p.rv, nil, nil, nil, nil); err == nil {
		t.Error("a missing receipt must be refused, not dereferenced")
	}
	if err := evidence.VerifyInterlock(p.rc, nil, nil, nil, nil, nil); err == nil {
		t.Error("a missing review must be refused, not dereferenced")
	}
}

func resignReview(t *testing.T, p *pair) {
	t.Helper()
	if err := p.rv.Sign(p.requester); err != nil {
		t.Fatal(err)
	}
}
