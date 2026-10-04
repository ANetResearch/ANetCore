package delegation

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// Tests for the ANetCore v0.15.0 delegation increments (A2A-DESIGN §3.4): the new optional fields,
// StatusMsg, KindCancel, and the verifiers that take an externally resolved KEL (review item C4d).

func encodedKeys(t *testing.T, v interface{ Marshal() ([]byte, error) }) []uint64 {
	t.Helper()
	b, err := v.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[uint64]any
	if err := coredet.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	ks := keysOf(raw)
	sort.Slice(ks, func(i, j int) bool { return ks[i] < ks[j] })
	return ks
}

// Each new field lands on its assigned key, and is absent when empty. Absent-when-empty is what
// keeps every message an older sender produces byte-identical (the v1 golden vectors check the
// bytes; this checks the keys directly).
func TestNewFieldKeysAreAssignedAndOptional(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    interface{ Marshal() ([]byte, error) }
		want []uint64
	}{
		{"ChatMsg.Metadata", &ChatMsg{Kind: "x", Metadata: []byte(`{}`)}, []uint64{1, 10}},
		{"ChatMsg without metadata", &ChatMsg{Kind: "x"}, []uint64{1}},
		// Keys 3 (the body KEL) and 6 (the prepayment) are retired: no field encodes to them.
		{"DelegateReq.ContextID", &DelegateReq{ContextID: "ctx"}, []uint64{1, 2, 4, 7}},
		{"DelegateReq.Metadata", &DelegateReq{Metadata: []byte(`{}`)}, []uint64{1, 2, 4, 8}},
		{"DelegateReq without new fields", &DelegateReq{}, []uint64{1, 2, 4}},
		{"ResultResp.Metadata", &ResultResp{Status: StatusDone, Metadata: []byte(`{}`)}, []uint64{1, 5}},
		// Key 4 (the body KEL) is retired; key 6 is the reply.
		{"ResultResp.Reply", &ResultResp{Status: StatusDone, Reply: &ReplyMsg{Kind: ChatText, MsgID: "m"}}, []uint64{1, 6}},
		{"ResultResp without metadata", &ResultResp{Status: StatusDone}, []uint64{1}},
		{"StatusMsg full", &StatusMsg{State: StateWorking, Text: "t", Metadata: []byte(`{}`), At: 1}, []uint64{1, 2, 3, 4}},
		// One optional field at a time, so two fields that swap keys are caught here and not only
		// by the golden vector.
		{"StatusMsg.Text", &StatusMsg{State: StateWorking, Text: "t", At: 1}, []uint64{1, 2, 4}},
		{"StatusMsg.Metadata", &StatusMsg{State: StateWorking, Metadata: []byte(`{}`), At: 1}, []uint64{1, 3, 4}},
		// State and At are always encoded, even when zero.
		{"StatusMsg minimal", &StatusMsg{}, []uint64{1, 4}},
	} {
		if got := encodedKeys(t, tc.v); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: encoded keys %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNewFieldsRoundTrip(t *testing.T) {
	meta := []byte(`{"a2a.serviceParameters":{"A2A-Version":"1.0"}}`)

	cm := &ChatMsg{Kind: KindCancel, Body: "stop", MsgID: "m-1", Metadata: meta}
	b, err := cm.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cback, err := UnmarshalChatMsg(b)
	if err != nil || !reflect.DeepEqual(cback, cm) {
		t.Errorf("ChatMsg round trip: %+v, %v", cback, err)
	}

	alice, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	dr := signedReq(t, alice, "x")
	dr.ContextID, dr.Metadata = "ctx-1", meta
	b, err = dr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	dback, err := UnmarshalDelegateReq(b)
	if err != nil || dback.ContextID != "ctx-1" || string(dback.Metadata) != string(meta) {
		t.Errorf("DelegateReq round trip: %+v, %v", dback, err)
	}

	rr := &ResultResp{Status: StatusDone, Metadata: meta}
	b, err = rr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	rback, err := UnmarshalResultResp(b)
	if err != nil || string(rback.Metadata) != string(meta) {
		t.Errorf("ResultResp round trip: %+v, %v", rback, err)
	}

	sm := &StatusMsg{State: StateInputRequired, Text: "need a file", Metadata: meta, At: 1767225600000}
	b, err = sm.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sback, err := UnmarshalStatusMsg(b)
	if err != nil || !reflect.DeepEqual(sback, sm) {
		t.Errorf("StatusMsg round trip: %+v, %v", sback, err)
	}
	if _, err := UnmarshalStatusMsg([]byte{0xff}); err == nil {
		t.Error("undecodable StatusMsg bytes must be an error")
	}
}

// The state and kind strings are wire constants shared with the peer daemon.
func TestStatusStatesAndCancelKindArePinned(t *testing.T) {
	// A slice, not a map literal keyed by the constants: two constants mutated to the same value
	// must fail this test, not fail to compile.
	for _, c := range []struct{ got, want string }{
		{StateSubmitted, "submitted"}, {StateWorking, "working"}, {StateInputRequired, "input-required"},
		{StateRejected, "rejected"}, {StateCanceled, "canceled"}, {StateFailed, "failed"},
		{KindCancel, "cancel"},
	} {
		if c.got != c.want {
			t.Errorf("constant %q, want %q", c.got, c.want)
		}
	}
	for _, s := range []string{StateSubmitted, StateWorking, StateInputRequired, StateRejected, StateCanceled, StateFailed} {
		if !ValidStatusState(s) {
			t.Errorf("%q must be a valid state", s)
		}
	}
	// completed is reported by ResultResp, never by StatusMsg; the others are not states.
	for _, s := range []string{"", "completed", "done", "queued", "Working", "input_required"} {
		if ValidStatusState(s) {
			t.Errorf("%q must not be a valid StatusMsg state", s)
		}
	}
}

func TestVerifyDelegateReqWithKEL(t *testing.T) {
	alice, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	mallory, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	req := signedReq(t, alice, "move the camera")
	aliceAtSigning := append([]identity.SignedEvent(nil), alice.KEL()...)

	t.Run("the resolved KEL at signing time", func(t *testing.T) {
		aid, doc, docBytes, err := VerifyDelegateReqWithKEL(req, aliceAtSigning, 1767225600000)
		if err != nil {
			t.Fatalf("a genuine delegation must verify: %v", err)
		}
		if aid != alice.AID() || TaskGoal(doc) != "move the camera" || string(docBytes) != string(req.TaskDoc) {
			t.Errorf("got aid %s goal %q", aid, TaskGoal(doc))
		}
	})

	t.Run("a resolved KEL that extends the signing one", func(t *testing.T) {
		a2, _ := identity.Incept()
		r := signedReq(t, a2, "x")
		if err := a2.Rotate(1767225601000); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := VerifyDelegateReqWithKEL(r, a2.KEL(), 1767225600000); err != nil {
			t.Fatalf("a signature by a key the resolved KEL still lists at the message time must verify: %v", err)
		}
	})

	// The case C4d is about. Mallory signs a TaskDoc as himself; the envelope came from Alice, so
	// the receiver resolved Alice's KEL, and the signature does not verify against it. There is no
	// KEL in the body any more for him to offer instead.
	t.Run("TaskDoc signed by someone other than the resolved sender", func(t *testing.T) {
		forged := signedReq(t, mallory, "wipe the recordings")
		aid, _, _, err := VerifyDelegateReqWithKEL(forged, aliceAtSigning, 1767225600000)
		if err == nil || !strings.Contains(err.Error(), "signature invalid") {
			t.Errorf("want signature invalid, got aid %q err %v", aid, err)
		}
		if aid != "" {
			t.Errorf("a refused delegation must name nobody, got %s", aid)
		}
	})

	t.Run("no resolved KEL", func(t *testing.T) {
		if _, _, _, err := VerifyDelegateReqWithKEL(req, nil, 1); err == nil ||
			!strings.Contains(err.Error(), "no resolved requester KEL") {
			t.Fatalf("verification without a resolved KEL must fail and say so, got %v", err)
		}
	})

	t.Run("structural checks still apply", func(t *testing.T) {
		if _, _, _, err := VerifyDelegateReqWithKEL(nil, aliceAtSigning, 1); err == nil {
			t.Error("nil must be refused")
		}
		r := *req
		r.InteractionID = ""
		if _, _, _, err := VerifyDelegateReqWithKEL(&r, aliceAtSigning, 1); err == nil ||
			!strings.Contains(err.Error(), "missing interaction id") {
			t.Errorf("want missing interaction id, got %v", err)
		}
	})

	// A DelegateReq built in memory is held to the decoder's TaskDoc rule: a key no TaskDoc
	// object assigns, or a second encoding of the same TaskDoc, is refused before the signature
	// is looked at.
	t.Run("the TaskDoc rule of the decoder", func(t *testing.T) {
		for name, edit := range map[string]func([]byte) []byte{
			"unassigned key": func(b []byte) []byte { return addTopKey(t, b, 5) },
			"not canonical":  func(b []byte) []byte { return nonCanonical(t, b) },
		} {
			r := *req
			r.TaskDoc = edit(req.TaskDoc)
			if _, _, _, err := VerifyDelegateReqWithKEL(&r, aliceAtSigning, 1767225600000); !errors.Is(err, ErrBody) {
				t.Errorf("%s: want ErrBody, got %v", name, err)
			}
		}
	})
}

// msgTime, not the verifier's clock, drives the revocation gate, and the gate is evaluated on the
// resolved KEL. Bob signs at seq 0 and later rotates at t=5000.
func TestVerifyDelegateReqWithKELUsesMsgTimeAndResolvedKEL(t *testing.T) {
	bob, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	req := signedReq(t, bob, "x") // signed at key state 0
	if err := bob.Rotate(5000); err != nil {
		t.Fatal(err)
	}
	resolved := bob.KEL() // [icp, rot@5000]

	if _, _, _, err := VerifyDelegateReqWithKEL(req, resolved, 4999); err != nil {
		t.Errorf("signed before the rotation: must verify, got %v", err)
	}
	_, _, _, err = VerifyDelegateReqWithKEL(req, resolved, 5000)
	if err == nil || !strings.Contains(err.Error(), "REVOKED_KEY") {
		t.Errorf("message time at the rotation: want REVOKED_KEY, got %v", err)
	}
}
