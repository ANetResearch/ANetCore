package delegation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/evidence"
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
		{"DelegateReq.ContextID", &DelegateReq{ContextID: "ctx"}, []uint64{1, 2, 3, 4, 7}},
		{"DelegateReq.Metadata", &DelegateReq{Metadata: []byte(`{}`)}, []uint64{1, 2, 3, 4, 8}},
		{"DelegateReq without new fields", &DelegateReq{}, []uint64{1, 2, 3, 4}},
		{"ResultResp.Metadata", &ResultResp{Status: StatusDone, Metadata: []byte(`{}`)}, []uint64{1, 5}},
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

	dr := &DelegateReq{TaskDoc: []byte{0xa0}, InteractionID: "ix", ContextID: "ctx-1", Metadata: meta}
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

func marshalKEL(t *testing.T, kel []identity.SignedEvent) []byte {
	t.Helper()
	b, err := identity.MarshalKEL(kel)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hostKey() ed25519.PublicKey {
	seed := sha256.Sum256([]byte("anet-test/delegation/host"))
	return ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
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
	req := signedReq(t, alice, "move the camera") // body KEL = alice's KEL at signing time
	aliceAtSigning := append([]identity.SignedEvent(nil), alice.KEL()...)

	t.Run("body KEL equal to the resolved KEL", func(t *testing.T) {
		aid, doc, docBytes, err := VerifyDelegateReqWithKEL(req, aliceAtSigning, 1767225600000)
		if err != nil {
			t.Fatalf("a genuine delegation must verify: %v", err)
		}
		if aid != alice.AID() || TaskGoal(doc) != "move the camera" || string(docBytes) != string(req.TaskDoc) {
			t.Errorf("got aid %s goal %q", aid, TaskGoal(doc))
		}
	})

	t.Run("no body KEL", func(t *testing.T) {
		r := *req
		r.KEL = nil
		if _, _, _, err := VerifyDelegateReqWithKEL(&r, aliceAtSigning, 1767225600000); err != nil {
			t.Fatalf("an absent body KEL must be accepted: %v", err)
		}
	})

	t.Run("body KEL is a prefix of the resolved KEL", func(t *testing.T) {
		a2, _ := identity.Incept()
		r := signedReq(t, a2, "x")
		if err := a2.Delegate(hostKey(), 1000); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := VerifyDelegateReqWithKEL(r, a2.KEL(), 1767225600000); err != nil {
			t.Fatalf("a body KEL that the resolved KEL extends must be accepted: %v", err)
		}
	})

	t.Run("body KEL forks from the resolved KEL", func(t *testing.T) {
		r := *req
		r.KEL = marshalKEL(t, mallory.KEL())
		_, _, _, err := VerifyDelegateReqWithKEL(&r, aliceAtSigning, 1767225600000)
		if !errors.Is(err, ErrBodyKELMismatch) || !errors.Is(err, identity.ErrKELFork) {
			t.Fatalf("want ErrBodyKELMismatch wrapping ErrKELFork, got %v", err)
		}
	})

	t.Run("body KEL runs ahead of the resolved KEL", func(t *testing.T) {
		a3, _ := identity.Incept()
		r := signedReq(t, a3, "x")
		stale := append([]identity.SignedEvent(nil), a3.KEL()...)
		if err := a3.Delegate(hostKey(), 1000); err != nil {
			t.Fatal(err)
		}
		r.KEL = marshalKEL(t, a3.KEL())
		_, _, _, err := VerifyDelegateReqWithKEL(r, stale, 1767225600000)
		if !errors.Is(err, ErrBodyKELMismatch) || !errors.Is(err, identity.ErrKELRollback) {
			t.Fatalf("want ErrBodyKELMismatch wrapping ErrKELRollback, got %v", err)
		}
	})

	t.Run("undecodable body KEL", func(t *testing.T) {
		r := *req
		r.KEL = []byte("not a kel")
		if _, _, _, err := VerifyDelegateReqWithKEL(&r, aliceAtSigning, 1); err == nil ||
			!strings.Contains(err.Error(), "bad body KEL") {
			t.Fatalf("want bad body KEL, got %v", err)
		}
	})

	// The case C4d is about. Mallory signs a TaskDoc as himself and ships his own KEL in the body;
	// the envelope came from Alice, so the receiver resolved Alice's KEL. The body KEL decides
	// nothing: with it the request is a mismatch, without it the signature does not verify
	// against Alice's key history.
	t.Run("TaskDoc signed by someone other than the resolved sender", func(t *testing.T) {
		forged := signedReq(t, mallory, "wipe the recordings")
		if _, _, _, err := VerifyDelegateReqWithKEL(forged, aliceAtSigning, 1767225600000); !errors.Is(err, ErrBodyKELMismatch) {
			t.Errorf("with Mallory's body KEL: want ErrBodyKELMismatch, got %v", err)
		}
		forged.KEL = nil
		aid, _, _, err := VerifyDelegateReqWithKEL(forged, aliceAtSigning, 1767225600000)
		if err == nil || !strings.Contains(err.Error(), "signature invalid") {
			t.Errorf("without a body KEL: want signature invalid, got aid %q err %v", aid, err)
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
}

// msgTime, not the verifier's clock, drives the revocation gate, and the gate is evaluated on the
// resolved KEL, not on the shorter KEL the body carried. Bob signs at seq 0 and later rotates at
// t=5000; his message still carries the pre-rotation KEL.
func TestVerifyDelegateReqWithKELUsesMsgTimeAndResolvedKEL(t *testing.T) {
	bob, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	req := signedReq(t, bob, "x") // body KEL = [icp]
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

func TestVerifyResultWithKEL(t *testing.T) {
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
		at   = 1767225600000
	)
	deliverable := []byte(`{"answer":42}`)
	cid, err := anetcid.Sum(deliverable)
	if err != nil {
		t.Fatal(err)
	}
	receiptBy := func(c *identity.Controller, mutate func(*evidence.Receipt)) []byte {
		rc := &evidence.Receipt{InteractionID: ix, RequesterAID: reqA, ProviderAID: c.AID(),
			RequestCID: "bafyrequest", ResultCID: cid, CompletedAt: at}
		if mutate != nil {
			mutate(rc)
		}
		if err := rc.Sign(c); err != nil {
			t.Fatal(err)
		}
		b, err := rc.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pKEL := append([]identity.SignedEvent(nil), provider.KEL()...)

	t.Run("genuine, body KEL equal", func(t *testing.T) {
		rr := &ResultResp{Status: StatusDone, Deliverable: deliverable,
			Receipt: receiptBy(provider, nil), KEL: marshalKEL(t, pKEL)}
		rc, err := VerifyResultWithKEL(rr, pKEL, ix, reqA, provider.AID(), at)
		if err != nil || rc.ResultCID != cid {
			t.Fatalf("a genuine completion must verify: %v", err)
		}
	})

	// VerifyResult reports this case as ErrUnverifiable, because it had no other KEL. With a resolved
	// KEL the receipt can be checked, so an absent body KEL is not a reason to give up.
	t.Run("genuine, no body KEL", func(t *testing.T) {
		rr := &ResultResp{Status: StatusDone, Deliverable: deliverable, Receipt: receiptBy(provider, nil)}
		if _, err := VerifyResultWithKEL(rr, pKEL, ix, reqA, provider.AID(), at); err != nil {
			t.Fatalf("an absent body KEL must be accepted: %v", err)
		}
	})

	t.Run("no resolved KEL is unverifiable, not invalid", func(t *testing.T) {
		rr := &ResultResp{Status: StatusDone, Deliverable: deliverable,
			Receipt: receiptBy(provider, nil), KEL: marshalKEL(t, pKEL)}
		if _, err := VerifyResultWithKEL(rr, nil, ix, reqA, provider.AID(), at); !errors.Is(err, ErrUnverifiable) {
			t.Fatalf("want ErrUnverifiable, got %v", err)
		}
	})

	t.Run("body KEL forks from the resolved KEL", func(t *testing.T) {
		rr := &ResultResp{Status: StatusDone, Deliverable: deliverable,
			Receipt: receiptBy(provider, nil), KEL: marshalKEL(t, other.KEL())}
		_, err := VerifyResultWithKEL(rr, pKEL, ix, reqA, provider.AID(), at)
		if !errors.Is(err, ErrBodyKELMismatch) || !errors.Is(err, identity.ErrKELFork) {
			t.Fatalf("want ErrBodyKELMismatch wrapping ErrKELFork, got %v", err)
		}
	})

	// A receipt signed by another identity, with that identity's KEL in the body, while the
	// envelope came from the provider. The resolved KEL decides.
	t.Run("receipt by someone other than the resolved sender", func(t *testing.T) {
		rr := &ResultResp{Status: StatusDone, Deliverable: deliverable,
			Receipt: receiptBy(other, nil)}
		_, err := VerifyResultWithKEL(rr, pKEL, ix, reqA, "", at)
		if err == nil || !strings.Contains(err.Error(), "signature invalid") {
			t.Fatalf("want signature invalid, got %v", err)
		}
	})

	t.Run("bindings still apply", func(t *testing.T) {
		rr := &ResultResp{Status: StatusDone, Deliverable: []byte(`{"answer":0}`),
			Receipt: receiptBy(provider, nil)}
		if _, err := VerifyResultWithKEL(rr, pKEL, ix, reqA, provider.AID(), at); err == nil ||
			!strings.Contains(err.Error(), "receipt covers") {
			t.Errorf("swapped deliverable: want receipt covers, got %v", err)
		}
		rr = &ResultResp{Status: StatusDone, Deliverable: deliverable,
			Receipt: receiptBy(provider, func(r *evidence.Receipt) { r.InteractionID = "ix-99" })}
		if _, err := VerifyResultWithKEL(rr, pKEL, ix, reqA, provider.AID(), at); err == nil ||
			!strings.Contains(err.Error(), "is for interaction") {
			t.Errorf("recycled receipt: want is for interaction, got %v", err)
		}
		if _, err := VerifyResultWithKEL(&ResultResp{Status: StatusDone}, pKEL, ix, reqA, "", at); err == nil ||
			!strings.Contains(err.Error(), "no receipt") {
			t.Errorf("no receipt: got %v", err)
		}
		// The requester binding is not implied by the resolved KEL: the provider's own key can sign
		// a receipt that names another requester, and accepting it would credit the wrong party.
		rr = &ResultResp{Status: StatusDone, Deliverable: deliverable,
			Receipt: receiptBy(provider, func(r *evidence.Receipt) { r.RequesterAID = "did:anet:someone-else" })}
		if _, err := VerifyResultWithKEL(rr, pKEL, ix, reqA, provider.AID(), at); err == nil ||
			!strings.Contains(err.Error(), "as requester, not us") {
			t.Errorf("receipt for another requester: want as requester, not us, got %v", err)
		}
		// The provider binding: the KEL resolved for the envelope sender verifies the receipt, but the
		// interaction was addressed to a different provider. The caller's providerAID decides.
		rr = &ResultResp{Status: StatusDone, Deliverable: deliverable, Receipt: receiptBy(other, nil)}
		if _, err := VerifyResultWithKEL(rr, other.KEL(), ix, reqA, provider.AID(), at); err == nil ||
			!strings.Contains(err.Error(), "the task went to") {
			t.Errorf("receipt from a provider the task did not go to: want the task went to, got %v", err)
		}
	})

	t.Run("body KEL runs ahead of the resolved KEL", func(t *testing.T) {
		p3, _ := identity.Incept()
		receipt := receiptBy(p3, nil)
		stale := append([]identity.SignedEvent(nil), p3.KEL()...)
		if err := p3.Delegate(hostKey(), 1000); err != nil {
			t.Fatal(err)
		}
		rr := &ResultResp{Status: StatusDone, Deliverable: deliverable, Receipt: receipt,
			KEL: marshalKEL(t, p3.KEL())}
		_, err := VerifyResultWithKEL(rr, stale, ix, reqA, p3.AID(), at)
		if !errors.Is(err, ErrBodyKELMismatch) || !errors.Is(err, identity.ErrKELRollback) {
			t.Fatalf("want ErrBodyKELMismatch wrapping ErrKELRollback, got %v", err)
		}
	})

	t.Run("undecodable body KEL", func(t *testing.T) {
		rr := &ResultResp{Status: StatusDone, Deliverable: deliverable,
			Receipt: receiptBy(provider, nil), KEL: []byte("not a kel")}
		if _, err := VerifyResultWithKEL(rr, pKEL, ix, reqA, provider.AID(), at); err == nil ||
			!strings.Contains(err.Error(), "bad body KEL") {
			t.Fatalf("want bad body KEL, got %v", err)
		}
	})

	t.Run("msgTime and the resolved KEL drive revocation", func(t *testing.T) {
		p2, _ := identity.Incept()
		receipt := receiptBy(p2, nil)
		body := marshalKEL(t, p2.KEL()) // [icp]
		if err := p2.Rotate(5000); err != nil {
			t.Fatal(err)
		}
		rr := &ResultResp{Status: StatusDone, Deliverable: deliverable, Receipt: receipt, KEL: body}
		if _, err := VerifyResultWithKEL(rr, p2.KEL(), ix, reqA, p2.AID(), 4999); err != nil {
			t.Errorf("before the rotation: must verify, got %v", err)
		}
		if _, err := VerifyResultWithKEL(rr, p2.KEL(), ix, reqA, p2.AID(), 5000); err == nil ||
			!strings.Contains(err.Error(), "REVOKED_KEY") {
			t.Errorf("at the rotation: want REVOKED_KEY, got %v", err)
		}
	})
}
