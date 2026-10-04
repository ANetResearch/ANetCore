package delegation

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/tsir"
)

// VerifyDelegateReqWithKEL is where a stranger becomes an accountable peer.
//
// Everything downstream trusts the AID it returns: the interaction is
// recorded against it, the receipt names it, the KEL cache remembers it,
// and a shared blackboard later merges contributions on its authority. A
// verifier is defined by what it refuses.

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
	return &DelegateReq{TaskDoc: raw, Envelope: doc.Envelope, InteractionID: "ix-1"}
}

func TestAGenuineDelegationVerifies(t *testing.T) {
	alice, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	req := signedReq(t, alice, "move the camera")

	aid, doc, docBytes, err := VerifyDelegateReqWithKEL(req, alice.KEL(), 1767225600000)
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
// the attack, because a table of "bad input" is a table nobody reads. The
// KEL is the one the receiver resolved for the sender of the envelope:
// Alice's.
func TestVerifyRefusesEveryWayOfLyingAboutWhoSent(t *testing.T) {
	alice, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	mallory, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		attack string
		mutate func(r *DelegateReq)
		want   string
	}{
		{
			// Sign it yourself, then claim to be Alice. The envelope's
			// SignerAID is what the daemon records as accountable, so it
			// must be bound to the key that actually signed.
			attack: "sign as yourself but claim another AID",
			mutate: func(r *DelegateReq) {
				forged := signedReq(t, mallory, "move the camera")
				r.TaskDoc = forged.TaskDoc
				r.Envelope = forged.Envelope
				r.Envelope.SignerAID = alice.AID()
			},
			want: "signature invalid",
		},
		{
			// Sign it yourself and say so: the receiver resolved Alice's
			// key history for the envelope, so Mallory's signature is not
			// hers.
			attack: "sign as yourself inside another's envelope",
			mutate: func(r *DelegateReq) {
				forged := signedReq(t, mallory, "wipe the recordings")
				r.TaskDoc, r.Envelope = forged.TaskDoc, forged.Envelope
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
				empty := &tsir.TaskDoc{Version: tsir.VersionPair{Major: 1}, Tasks: []tsir.Task{}}
				_ = empty.Sign(alice)
				raw, _ := coredet.Marshal(*empty)
				r.TaskDoc, r.Envelope = raw, empty.Envelope
			},
			want: "task-less",
		},
	}

	for _, tc := range cases {
		t.Run(tc.attack, func(t *testing.T) {
			req := signedReq(t, alice, "move the camera")
			tc.mutate(req)
			aid, _, _, err := VerifyDelegateReqWithKEL(req, alice.KEL(), 1767225600000)
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
	alice, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := VerifyDelegateReqWithKEL(nil, alice.KEL(), 1); err == nil {
		t.Error("nil must be refused, not dereferenced")
	}
}

// The wire round-trips. Each of these carries a signature or a receipt, so
// a field lost in encoding is a message that fails verification at the far
// end for a reason nobody can find from the far end.
func TestWireTypesRoundTrip(t *testing.T) {
	alice, err := identitytest.Hub()
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
	if _, _, _, err := VerifyDelegateReqWithKEL(back, alice.KEL(), 1767225600000); err != nil {
		t.Fatalf("a delegation must still verify after the wire: %v", err)
	}
	if len(back.Attachments) != 1 || string(back.Attachments[0].Data) != "\x01\x02\x03" {
		t.Errorf("attachment bytes lost: %+v", back.Attachments)
	}

	res := &ResultResp{Status: StatusDone, Deliverable: []byte(`{"ok":true}`), Receipt: []byte{9, 9},
		Reply: &ReplyMsg{Kind: ChatText, Body: "done", MsgID: "m-9"}}
	rb, err := res.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	rback, err := UnmarshalResultResp(rb)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rback, res) {
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
// A preview frame must reach the far side whole. Before the two copies
// were merged the daemon's ChatMsg stopped at key 3, so keys 4-7 simply
// were not there on arrival — a lax CBOR decoder drops an unknown key
// without a word — and the message itself was discarded on an
// unrecognised kind. Every field of a frame, keys 11-13 included, must
// survive the wire.
func TestAStreamingReplySurvivesTheWire(t *testing.T) {
	sent := &ChatMsg{
		Kind: ChatStreamPreview, Body: "partial answer so far",
		StreamSeq: 1767225600001, StreamAtMS: 1767225600000,
		ReasoningBody: "considering the second approach", ReasoningStreamAtMS: 1767225599000,
		MsgID: "p-1", Omitted: 12, ReasoningOmitted: 40, Answers: "m-1",
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
		t.Errorf("a preview frame was altered on the wire:\n got %+v\nwant %+v", *got, *sent)
	}
	if err := ValidatePreview(got); err != nil {
		t.Errorf("a well-formed preview frame is refused: %v", err)
	}
}

// The keys are the contract. Two implementations agree by agreeing on
// these numbers, so moving one renames a field for everyone at once.
func TestChatMsgKeysArePinned(t *testing.T) {
	// Encoded alone, each field must land on its documented key.
	for _, tc := range []struct {
		key uint64
		msg ChatMsg
	}{
		{1, ChatMsg{Kind: "x"}},
		{2, ChatMsg{Kind: "x", Body: "b"}},
		{3, ChatMsg{Kind: "x", Attachments: []Attachment{{Name: "a", Size: 1, CID: "c"}}}},
		{4, ChatMsg{Kind: "x", StreamSeq: 9}},
		{5, ChatMsg{Kind: "x", StreamAtMS: 9}},
		{6, ChatMsg{Kind: "x", ReasoningBody: "r"}},
		{7, ChatMsg{Kind: "x", ReasoningStreamAtMS: 9}},
		{9, ChatMsg{Kind: "x", MsgID: "m-1"}},
		{10, ChatMsg{Kind: "x", Metadata: []byte(`{}`)}},
		{11, ChatMsg{Kind: "x", Omitted: 9}},
		{12, ChatMsg{Kind: "x", ReasoningOmitted: 9}},
		{13, ChatMsg{Kind: "x", Answers: "m-0"}},
	} {
		b, err := tc.msg.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		var raw map[uint64]any
		if err := coredet.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		if _, ok := raw[tc.key]; !ok || (tc.key != 1 && len(raw) != 2) {
			t.Errorf("key %d missing or not alone for %+v — encoded keys %v", tc.key, tc.msg, keysOf(raw))
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

// A message id must survive the wire, and must be absent when unset.
//
// Absent matters as much as present: a receiver that saw an empty string
// as an id would treat every such message as the same message and drop
// all but the first.
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
		t.Error("an unset message id must not occupy key 9")
	}
	back, err := UnmarshalChatMsg(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.MsgID != "" {
		t.Errorf("an absent id must decode as empty, got %q", back.MsgID)
	}
}
