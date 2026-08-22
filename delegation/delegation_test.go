package delegation

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/tsir"
)

// VerifyDelegateReq is where a stranger becomes an accountable peer.
//
// Everything downstream trusts the AID it returns: the interaction is
// recorded against it, the receipt names it, the KEL cache remembers it,
// and a shared blackboard later merges contributions on its authority. It
// had no tests of its own — it was exercised only through daemon tests
// that feed it well-formed input, which is the shape that tests a verifier
// least. A verifier is defined by what it refuses.

func signedReq(t *testing.T, c *identity.Controller, goal string) *DelegateReq {
	t.Helper()
	doc := &tsir.TaskDoc{
		Version: tsir.VersionPair{Major: 1},
		Tasks:   []tsir.Task{{Intent: tsir.Intent{Summary: goal, Body: goal}}},
	}
	if err := doc.Sign(c); err != nil {
		t.Fatal(err)
	}
	raw, err := coredet.Marshal(*doc)
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	return &DelegateReq{TaskDoc: raw, Envelope: doc.Envelope, KEL: kel, InteractionID: "ix-1"}
}

func TestAGenuineDelegationVerifies(t *testing.T) {
	alice, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	req := signedReq(t, alice, "move the camera")

	aid, doc, docBytes, err := VerifyDelegateReq(req)
	if err != nil {
		t.Fatalf("a genuine delegation must verify: %v", err)
	}
	if aid != alice.AID() {
		t.Errorf("accountable aid = %s, want %s", aid, alice.AID())
	}
	if TaskGoal(doc) != "move the camera" {
		t.Errorf("goal = %q", TaskGoal(doc))
	}
	// The returned bytes are the request CID's anchor: they must be the
	// exact bytes that were signed, not a re-encoding of the decoded doc.
	if string(docBytes) != string(req.TaskDoc) {
		t.Error("the signed bytes must come back unaltered — the request CID is taken over them")
	}
}

// Each of these is a way to claim to be someone else. The names describe
// the attack, because a table of "bad input" is a table nobody reads.
func TestVerifyRefusesEveryWayOfLyingAboutWhoSent(t *testing.T) {
	alice, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	mallory, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		attack string
		mutate func(r *DelegateReq)
		want   string
	}{
		{
			// The obvious one: keep Alice's signed TaskDoc, swap in your own
			// key history. If the KEL were taken on faith, anyone could
			// replay a delegation they intercepted as their own.
			attack: "substitute the sender's key history",
			mutate: func(r *DelegateReq) {
				kel, _ := identity.MarshalKEL(mallory.KEL())
				r.KEL = kel
			},
			want: "signature invalid",
		},
		{
			// Sign it yourself, then claim to be Alice. The envelope's
			// SignerAID is what the daemon records as accountable, so it
			// must be bound to the key that actually signed.
			attack: "sign as yourself but claim another AID",
			mutate: func(r *DelegateReq) {
				forged := signedReq(t, mallory, "move the camera")
				r.TaskDoc, r.KEL = forged.TaskDoc, forged.KEL
				r.Envelope = forged.Envelope
				r.Envelope.SignerAID = alice.AID()
			},
			want: "signature invalid",
		},
		{
			// Change what was asked after it was signed.
			attack: "alter the task after signing",
			mutate: func(r *DelegateReq) {
				tampered := signedReq(t, alice, "wipe the recordings")
				r.TaskDoc = tampered.TaskDoc
			},
			want: "signature invalid",
		},
		{
			attack: "arrive with no signature at all",
			mutate: func(r *DelegateReq) { r.Envelope = nil },
			want:   "missing envelope",
		},
		{
			// Without an id the delegation cannot be correlated with its
			// result or its receipt — an interaction nobody can point to.
			attack: "omit the interaction id",
			mutate: func(r *DelegateReq) { r.InteractionID = "" },
			want:   "missing interaction id",
		},
		{
			attack: "send an undecodable TaskDoc",
			mutate: func(r *DelegateReq) { r.TaskDoc = []byte{0xff, 0xff, 0xff} },
			want:   "undecodable",
		},
		{
			// A TaskDoc with no tasks asks for nothing, and TaskGoal would
			// read past the end of the slice.
			attack: "send a TaskDoc with no tasks",
			mutate: func(r *DelegateReq) {
				empty := &tsir.TaskDoc{Version: tsir.VersionPair{Major: 1}}
				_ = empty.Sign(alice)
				raw, _ := coredet.Marshal(*empty)
				r.TaskDoc, r.Envelope = raw, empty.Envelope
			},
			want: "task-less",
		},
		{
			attack: "send a malformed key history",
			mutate: func(r *DelegateReq) { r.KEL = []byte("not a kel") },
			want:   "bad KEL",
		},
	}

	for _, tc := range cases {
		t.Run(tc.attack, func(t *testing.T) {
			req := signedReq(t, alice, "move the camera")
			tc.mutate(req)
			aid, _, _, err := VerifyDelegateReq(req)
			if err == nil {
				t.Fatalf("accepted a delegation that %s, as %s", tc.attack, aid)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: %v (want %q)", err, tc.want)
			}
			if aid != "" {
				t.Errorf("a refused delegation must name nobody, got %s", aid)
			}
		})
	}
}

func TestVerifyRefusesNil(t *testing.T) {
	if _, _, _, err := VerifyDelegateReq(nil); err == nil {
		t.Error("nil must be refused, not dereferenced")
	}
}

// The wire round-trips. Each of these carries a signature or a receipt, so
// a field lost in encoding is a message that fails verification at the far
// end for a reason nobody can find from the far end.
func TestWireTypesRoundTrip(t *testing.T) {
	alice, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	req := signedReq(t, alice, "move the camera")
	req.Attachments = []Attachment{{
		Name: "plan.png", Mime: "image/png", Size: 3, CID: "bafyexample", Data: []byte{1, 2, 3},
	}}
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalDelegateReq(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := VerifyDelegateReq(back); err != nil {
		t.Fatalf("a delegation must still verify after the wire: %v", err)
	}
	if len(back.Attachments) != 1 || string(back.Attachments[0].Data) != "\x01\x02\x03" {
		t.Errorf("attachment bytes lost: %+v", back.Attachments)
	}

	res := &ResultResp{Status: StatusDone, Deliverable: []byte(`{"ok":true}`), Receipt: []byte{9, 9}}
	rb, err := res.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	rback, err := UnmarshalResultResp(rb)
	if err != nil {
		t.Fatal(err)
	}
	if string(rback.Deliverable) != `{"ok":true}` || string(rback.Receipt) != "\x09\x09" {
		t.Errorf("result lost on the wire: %+v", rback)
	}

	msg := &ChatMsg{Kind: ChatText, Body: "on my way"}
	mb, err := msg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	mback, err := UnmarshalChatMsg(mb)
	if err != nil {
		t.Fatal(err)
	}
	if mback.Body != "on my way" || mback.Kind != ChatText {
		t.Errorf("chat message lost on the wire: %+v", mback)
	}
}

// The divergence this package exists to end.
//
// A hub-sent stream preview must reach the daemon whole. Before the two
// copies were merged the daemon's ChatMsg stopped at key 3, so keys 4-7
// simply were not there on arrival — CBOR keyasint drops an unknown key
// without a word — and the message itself was discarded on an unrecognised
// kind. The hub streamed; the far side showed nothing until the reply was
// finished; no log said why.
func TestAStreamingReplySurvivesTheWire(t *testing.T) {
	sent := &ChatMsg{
		Kind: ChatStreamPreview, Body: "partial answer so far",
		StreamSeq: 7, StreamAtMS: 1767225600000,
		ReasoningBody: "considering the second approach", ReasoningStreamAtMS: 1767225599000,
	}
	b, err := sent.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalChatMsg(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, sent) {
		t.Errorf("a streaming preview was altered on the wire:\n got %+v\nwant %+v", *got, *sent)
	}
}

// The keys are the contract. Two implementations agree by agreeing on
// these numbers, so moving one renames a field for everyone at once —
// silently, because an unknown key decodes as an absent one.
func TestChatMsgKeysArePinned(t *testing.T) {
	// Encoded alone, each field must land on its documented key.
	for _, tc := range []struct {
		key uint64
		msg ChatMsg
	}{
		{1, ChatMsg{Kind: "x"}},
		{2, ChatMsg{Kind: "x", Body: "b"}},
		{4, ChatMsg{Kind: "x", StreamSeq: 9}},
		{5, ChatMsg{Kind: "x", StreamAtMS: 9}},
		{6, ChatMsg{Kind: "x", ReasoningBody: "r"}},
		{7, ChatMsg{Kind: "x", ReasoningStreamAtMS: 9}},
		{9, ChatMsg{Kind: "x", MsgID: "m-1"}},
	} {
		b, err := tc.msg.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		var raw map[uint64]any
		if err := coredet.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		if _, ok := raw[tc.key]; !ok {
			t.Errorf("key %d missing for %+v — encoded keys %v", tc.key, tc.msg, keysOf(raw))
		}
	}
}

func keysOf(m map[uint64]any) []uint64 {
	out := make([]uint64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A signature proves less than it looks like it proves.
//
// It says some provider signed some receipt. It does not say the receipt
// belongs to this interaction, names us as the requester, or covers the
// bytes that actually arrived. The daemon checked none of this — it called
// Receipt.Verify nowhere at all, and could not have: a completion carried
// no provider KEL, so the requester held a signed object and no key.
//
// Each case below is a lie a provider can tell while holding a perfectly
// valid signature.
func TestAResultMustBeTheAnswerToTheRequestItClaims(t *testing.T) {
	provider, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	other, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	const (
		ix   = "ix-1"
		reqA = "did:anet:requester"
	)
	deliverable := []byte(`{"answer":42}`)
	cid, err := anetcid.Sum(deliverable)
	if err != nil {
		t.Fatal(err)
	}
	kelOf := func(c *identity.Controller) []byte {
		b, err := identity.MarshalKEL(c.KEL())
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sign := func(c *identity.Controller, rc *evidence.Receipt) []byte {
		if err := rc.Sign(c); err != nil {
			t.Fatal(err)
		}
		b, err := rc.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	good := func() *evidence.Receipt {
		return &evidence.Receipt{
			InteractionID: ix, RequesterAID: reqA, ProviderAID: provider.AID(),
			RequestCID: "bafyrequest", ResultCID: cid, CompletedAt: 1767225600000,
		}
	}

	t.Run("a genuine completion verifies", func(t *testing.T) {
		rr := &ResultResp{Status: StatusDone, Deliverable: deliverable,
			Receipt: sign(provider, good()), KEL: kelOf(provider)}
		rc, err := VerifyResult(rr, ix, reqA, provider.AID(), 1767225600000)
		if err != nil {
			t.Fatalf("a genuine completion must verify: %v", err)
		}
		if rc.ResultCID != cid {
			t.Errorf("result cid = %s", rc.ResultCID)
		}
	})

	cases := []struct {
		lie  string
		make func() *ResultResp
		want string
	}{
		{
			// The one that matters most: a valid receipt for content that
			// is not what arrived.
			lie: "sign a receipt for different content",
			make: func() *ResultResp {
				rc := good()
				rc.ResultCID = "bafysomethingelse"
				return &ResultResp{Status: StatusDone, Deliverable: deliverable,
					Receipt: sign(provider, rc), KEL: kelOf(provider)}
			},
			want: "receipt covers",
		},
		{
			lie: "swap the deliverable after signing",
			make: func() *ResultResp {
				return &ResultResp{Status: StatusDone, Deliverable: []byte(`{"answer":0}`),
					Receipt: sign(provider, good()), KEL: kelOf(provider)}
			},
			want: "receipt covers",
		},
		{
			lie: "answer with someone else's receipt",
			make: func() *ResultResp {
				rc := good()
				rc.ProviderAID = other.AID()
				return &ResultResp{Status: StatusDone, Deliverable: deliverable,
					Receipt: sign(other, rc), KEL: kelOf(other)}
			},
			want: "the task went to",
		},
		{
			lie: "recycle a receipt from another interaction",
			make: func() *ResultResp {
				rc := good()
				rc.InteractionID = "ix-99"
				return &ResultResp{Status: StatusDone, Deliverable: deliverable,
					Receipt: sign(provider, rc), KEL: kelOf(provider)}
			},
			want: "is for interaction",
		},
		{
			lie: "issue the receipt to a different requester",
			make: func() *ResultResp {
				rc := good()
				rc.RequesterAID = "did:anet:someone-else"
				return &ResultResp{Status: StatusDone, Deliverable: deliverable,
					Receipt: sign(provider, rc), KEL: kelOf(provider)}
			},
			want: "as requester, not us",
		},
		{
			lie: "sign with a key the KEL does not contain",
			make: func() *ResultResp {
				return &ResultResp{Status: StatusDone, Deliverable: deliverable,
					Receipt: sign(provider, good()), KEL: kelOf(other)}
			},
			want: "signature invalid",
		},
		{
			lie: "send no receipt at all",
			make: func() *ResultResp {
				return &ResultResp{Status: StatusDone, Deliverable: deliverable, KEL: kelOf(provider)}
			},
			want: "no receipt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.lie, func(t *testing.T) {
			_, err := VerifyResult(tc.make(), ix, reqA, provider.AID(), 1767225600000)
			if err == nil {
				t.Fatalf("accepted a completion that would %s", tc.lie)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: %v (want %q)", err, tc.want)
			}
		})
	}
}

// An older provider sends no KEL. That is not a lie and must not read like
// one: not knowing and knowing-it-is-fine are different states, and the
// caller needs to tell them apart to record the difference honestly.
func TestAMissingKELIsUnverifiableNotInvalid(t *testing.T) {
	provider, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	rc := &evidence.Receipt{InteractionID: "ix-1", RequesterAID: "did:anet:r",
		ProviderAID: provider.AID(), ResultCID: "bafy", CompletedAt: 1}
	if err := rc.Sign(provider); err != nil {
		t.Fatal(err)
	}
	b, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyResult(&ResultResp{Status: StatusDone, Deliverable: []byte("x"), Receipt: b},
		"ix-1", "did:anet:r", provider.AID(), 1)
	if !errors.Is(err, ErrUnverifiable) {
		t.Fatalf("a completion with no KEL must be unverifiable, distinctly: %v", err)
	}
}

// A message id must survive the wire, and must be absent when unset.
//
// Absent matters as much as present: an older sender does not mint one,
// and a receiver that saw an empty string as an id would treat every such
// message as the same message and drop all but the first.
func TestAMessageIDSurvivesAndStaysOptional(t *testing.T) {
	with := &ChatMsg{Kind: ChatText, Body: "on my way", MsgID: "01J8ZQ"}
	b, err := with.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalChatMsg(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.MsgID != "01J8ZQ" {
		t.Errorf("message id lost on the wire: %q", got.MsgID)
	}

	without := &ChatMsg{Kind: ChatText, Body: "on my way"}
	b, err = without.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[uint64]any
	if err := coredet.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if _, present := raw[9]; present {
		t.Error("an unset message id must not occupy key 9 — an older sender mints none")
	}
	back, err := UnmarshalChatMsg(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.MsgID != "" {
		t.Errorf("an absent id must decode as empty, got %q", back.MsgID)
	}
}
