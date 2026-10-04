package delegation_test

// Fuzz targets for the relayed delegation payloads and their verifiers (ANet an internal note).
//
// A mutated signed object almost never keeps its signature, so FuzzDelegateReq and
// FuzzResultResp can re-sign what they decoded (the TaskDoc, the receipt) with a fixed identity
// before verifying it: the verifiers then run their binding checks on arbitrary field values
// under a good signature, which is where a verifier accepting something it should not would show.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/delegation"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/tsir"
)

const fuzzTS = 1767225600000

// rotatedSuite returns the suite identity after one rotation (icp → rot), built from fixed seeds
// so every fuzz worker holds the same KEL. Its KEL extends identity.SuiteController()'s.
func rotatedSuite(tb testing.TB) *identity.Controller {
	tb.Helper()
	k2 := sha256.Sum256([]byte("anet-fuzz/delegation/k2"))
	next := sha256.Sum256(ed25519.NewKeyFromSeed(k2[:]).Public().(ed25519.PublicKey))
	c := identity.SuiteController()
	// The first rot reveals the hot key the suite icp committed (nil), signed by it (KEL v2).
	rot, err := c.BuildRotation(nil, next[:], "", false, fuzzTS-1000)
	if err != nil {
		tb.Fatal(err)
	}
	if err := c.Adopt(rot); err != nil {
		tb.Fatal(err)
	}
	return c
}

func kelBytes(tb testing.TB, c *identity.Controller) []byte {
	tb.Helper()
	b, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// signers are the identities a fuzz input can pick with its selector byte.
func signers(tb testing.TB) []*identity.Controller {
	return []*identity.Controller{identity.SuiteController(), rotatedSuite(tb)}
}

func seedDelegateReq(tb testing.TB, c *identity.Controller, bodyKEL []byte) []byte {
	tb.Helper()
	doc := &tsir.TaskDoc{
		Version: tsir.VersionPair{Major: 1, Minor: 2},
		Meta:    []tsir.MetaEntry{{Name: "n", Value: "v"}},
		Links:   []tsir.Link{{Rel: "related", Href: "x"}},
		Tasks: []tsir.Task{{ID: "t1", Intent: tsir.Intent{Summary: "golden task", Body: "describe the image"},
			Requires: []tsir.Require{{ID: "r", Necessity: "must"}},
			Accepts:  []tsir.Accept{{Type: "artifact", Outputs: []tsir.Output{{Format: "text/plain"}}}}}},
	}
	if err := doc.Sign(c); err != nil {
		tb.Fatal(err)
	}
	raw, err := coredet.Marshal(*doc)
	if err != nil {
		tb.Fatal(err)
	}
	req := &delegation.DelegateReq{TaskDoc: raw, Envelope: doc.Envelope, KEL: bodyKEL, InteractionID: "ix-golden-1",
		Attachments: []delegation.Attachment{{Name: "a.txt", Mime: "text/plain", Size: 3, CID: anetcid.MustSum([]byte("abc")), Data: []byte("abc")}},
		ContextID:   "ctx", Metadata: []byte(`{}`)}
	b, err := req.Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// roundTrip asserts that an accepted payload re-encodes to bytes that decode to the same value
// and re-encode to the same bytes.
func roundTrip[T any](t *testing.T, v *T, marshal func(*T) ([]byte, error), unmarshal func([]byte) (*T, error)) {
	t.Helper()
	b, err := marshal(v)
	if err != nil {
		return // a decoded string may hold bytes the encoder refuses; that is coredet's contract
	}
	back, err := unmarshal(b)
	if err != nil {
		t.Fatalf("re-encoded payload does not decode: %v", err)
	}
	if !reflect.DeepEqual(back, v) {
		b2, _ := marshal(back)
		if !bytes.Equal(b, b2) {
			t.Fatalf("round trip changed the payload:\n%+v\n%+v", v, back)
		}
	}
}

func FuzzDelegateReq(f *testing.F) {
	ss := signers(f)
	suite, rotated := ss[0], ss[1]
	f.Add(seedDelegateReq(f, suite, kelBytes(f, suite)), false, byte(0), uint64(fuzzTS))
	f.Add(seedDelegateReq(f, rotated, kelBytes(f, suite)), false, byte(1), uint64(fuzzTS))
	f.Add(seedDelegateReq(f, rotated, nil), true, byte(1), uint64(0))
	f.Add(seedDelegateReq(f, suite, kelBytes(f, rotated)), true, byte(0), uint64(fuzzTS))
	f.Fuzz(func(t *testing.T, b []byte, resign bool, sel byte, msgTime uint64) {
		r, err := delegation.UnmarshalDelegateReq(b)
		if err != nil {
			return
		}
		roundTrip(t, r, (*delegation.DelegateReq).Marshal, delegation.UnmarshalDelegateReq)
		c := ss[int(sel)%len(ss)]
		if resign {
			var doc tsir.TaskDoc
			if coredet.Unmarshal(r.TaskDoc, &doc) == nil && doc.Sign(c) == nil {
				r.Envelope = doc.Envelope
			}
		}
		_, _, _, _ = delegation.VerifyDelegateReq(r)
		requester, td, tdBytes, err := delegation.VerifyDelegateReqWithKEL(r, c.KEL(), msgTime)
		if err != nil {
			return
		}
		if requester != c.AID() || td.Envelope == nil || td.Envelope.SignerAID != c.AID() {
			t.Fatalf("accepted a delegation from %q (envelope %+v) against the KEL of %s", requester, td.Envelope, c.AID())
		}
		if len(td.Tasks) == 0 || !bytes.Equal(tdBytes, r.TaskDoc) {
			t.Fatal("accepted a task-less TaskDoc, or returned bytes other than the ones carried")
		}
		pre, err := td.CanonicalPreimage()
		if err != nil {
			t.Fatal(err)
		}
		states, err := identity.Replay(c.KEL())
		if err != nil {
			t.Fatal(err)
		}
		seq := td.Envelope.KeyStateSeq
		if seq >= uint64(len(states)) || !ed25519.Verify(states[seq].CurrentKeys[0], pre, td.Envelope.Sig) {
			t.Fatal("accepted a TaskDoc whose signature is not by the declared key state")
		}
		if len(r.KEL) > 0 {
			body, err := identity.UnmarshalKEL(r.KEL)
			if err != nil || identity.ExtendsKEL(body, c.KEL()) != nil {
				t.Fatalf("accepted a body KEL that is not a prefix of the resolved KEL (%v)", err)
			}
		}
	})
}

// fuzzTask is the suite identity's task the result seeds answer; the fuzz target checks every
// completion against it.
func fuzzTask(tb testing.TB) *task { return newTask(tb, identity.SuiteController(), "ix-golden-1") }

func seedResultResp(tb testing.TB, tk *task, c *identity.Controller, bodyKEL []byte) []byte {
	tb.Helper()
	rr := tk.completion(tb, c, []byte(`{"ok":true}`), nil)
	rr.KEL, rr.Metadata = bodyKEL, []byte(`{}`)
	b, err := rr.Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// FuzzResultResp decodes a completion, re-signs its receipt with one of two fixed identities when
// asked, and checks every accepted receipt against what the requester holds.
func FuzzResultResp(f *testing.F) {
	ss := signers(f)
	suite, rotated := ss[0], ss[1]
	tk := fuzzTask(f)
	f.Add(seedResultResp(f, tk, suite, kelBytes(f, suite)), false, byte(0), uint64(fuzzTS))
	f.Add(seedResultResp(f, tk, rotated, kelBytes(f, suite)), true, byte(1), uint64(fuzzTS))
	f.Add(seedResultResp(f, tk, rotated, nil), true, byte(1), uint64(0))
	f.Fuzz(func(t *testing.T, b []byte, resign bool, sel byte, msgTime uint64) {
		r, err := delegation.UnmarshalResultResp(b)
		if err != nil {
			return
		}
		roundTrip(t, r, (*delegation.ResultResp).Marshal, delegation.UnmarshalResultResp)
		c := ss[int(sel)%len(ss)]
		if resign {
			if w, err := evidence.UnmarshalReceiptWire(r.Receipt); err == nil {
				if body, err := w.Open(); err == nil {
					body.Provider = ""
					if again, err := body.Sign(c); err == nil {
						if rb, err := again.Marshal(); err == nil {
							r.Receipt = rb
						}
					}
				}
			}
		}
		want := tk.check(c.AID())
		want.Today = testDay + 1
		rc, err := delegation.VerifyResultForRequest(r, c.KEL(), want, msgTime)
		if err != nil {
			if errors.Is(err, delegation.ErrUnverifiable) {
				t.Fatalf("ErrUnverifiable with a resolved KEL: %v", err)
			}
			return
		}
		w, err := evidence.UnmarshalReceiptWire(r.Receipt)
		if err != nil {
			t.Fatalf("accepted a receipt that does not decode: %v", err)
		}
		ixc, _ := evidence.IXCommit(tk.ix, tk.binding.Nonce)
		switch {
		case w.Env.SignerAID != c.AID() || rc.Provider != c.AID():
			t.Fatalf("accepted a receipt signed by %s for provider %s against the KEL of %s", w.Env.SignerAID, rc.Provider, c.AID())
		case rc.ResultCID != anetcid.MustSum(r.Deliverable):
			t.Fatalf("accepted a receipt for %s over a deliverable hashing to %s", rc.ResultCID, anetcid.MustSum(r.Deliverable))
		case rc.RequestCID != anetcid.MustSum(tk.taskDoc) || !bytes.Equal(rc.IXCommit, ixc) ||
			!bytes.Equal(rc.RequesterCommit, tk.binding.RequesterCommit) || !bytes.Equal(rc.ReviewKey, tk.binding.ReviewKey):
			t.Fatalf("accepted a receipt that does not bind the task: %+v", rc)
		case rc.CompletedDay+1 < want.DelegatedDay || rc.CompletedDay > want.Today+1:
			t.Fatalf("accepted a receipt dated day %d", rc.CompletedDay)
		}
		states, _ := identity.Replay(c.KEL())
		if seq := w.Env.KeyStateSeq; seq >= uint64(len(states)) || !ed25519.Verify(states[seq].CurrentKeys[0], w.Body, w.Env.Sig) {
			t.Fatal("accepted a receipt whose signature is not by the declared key state")
		}
	})
}

func FuzzChatStatusMsg(f *testing.F) {
	chat, _ := (&delegation.ChatMsg{Kind: delegation.ChatText, Body: "hi", MsgID: "m1", StreamSeq: 3,
		Attachments: []delegation.Attachment{{Name: "a", Size: 1, CID: "c", Data: []byte{1}}}, Metadata: []byte(`{}`)}).Marshal()
	status, _ := (&delegation.StatusMsg{State: delegation.StateWorking, Text: "t", Metadata: []byte(`{}`), At: fuzzTS}).Marshal()
	f.Add(chat)
	f.Add(status)
	f.Fuzz(func(t *testing.T, b []byte) {
		if m, err := delegation.UnmarshalChatMsg(b); err == nil {
			roundTrip(t, m, (*delegation.ChatMsg).Marshal, delegation.UnmarshalChatMsg)
		}
		if m, err := delegation.UnmarshalStatusMsg(b); err == nil {
			roundTrip(t, m, (*delegation.StatusMsg).Marshal, delegation.UnmarshalStatusMsg)
			_ = delegation.ValidStatusState(m.State)
		}
	})
}
