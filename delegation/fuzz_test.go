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
	"testing"
	"unicode/utf8"

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
	seed := func(label string) []byte { s := sha256.Sum256([]byte(label)); return s[:] }
	k1Seed, k2Seed := seed("anet-suite-identity-v1/nxt"), seed("anet-fuzz/delegation/k2")
	k1, k2 := ed25519.NewKeyFromSeed(k1Seed), ed25519.NewKeyFromSeed(k2Seed)
	kel := identity.SuiteController().KEL()
	d := sha256.Sum256(k2.Public().(ed25519.PublicKey))
	rot := identity.KeyEvent{KELType: identity.KELType, AID: kel[0].EventID, Seq: 1, Prev: kel[0].EventID,
		Type: identity.Rotation, Keys: [][]byte{k1.Public().(ed25519.PublicKey)}, NextDigest: d[:], Threshold: 1,
		Timestamp: fuzzTS - 1000, Toad: identity.ToadField(identity.ToadHub)}
	pre, err := coredet.Marshal(rot)
	if err != nil {
		tb.Fatal(err)
	}
	// A rot is signed by the key it reveals (KEL v2).
	kel = append(kel, identity.SignedEvent{Event: rot, Sig: ed25519.Sign(k1, pre), EventID: anetcid.MustSum(pre)})
	blob, err := coredet.Marshal(struct {
		Cur []byte                 `cbor:"1,keyasint"`
		Nxt []byte                 `cbor:"2,keyasint"`
		KEL []identity.SignedEvent `cbor:"3,keyasint"`
	}{k1Seed, k2Seed, kel})
	if err != nil {
		tb.Fatal(err)
	}
	c, err := identity.Restore(blob)
	if err != nil {
		tb.Fatal(err)
	}
	return c
}

// signers are the identities a fuzz input can pick with its selector byte.
func signers(tb testing.TB) []*identity.Controller {
	return []*identity.Controller{identity.SuiteController(), rotatedSuite(tb)}
}

func seedDelegateReq(tb testing.TB, c *identity.Controller) []byte {
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
	req := &delegation.DelegateReq{TaskDoc: raw, Envelope: doc.Envelope, InteractionID: "ix-golden-1",
		Attachments: []delegation.Attachment{{Name: "a.txt", Mime: "text/plain", Size: 3, CID: anetcid.MustSum([]byte("abc")), Data: []byte("abc")}},
		ContextID:   "ctx", Metadata: []byte(`{}`)}
	b, err := req.Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// FuzzDelegateReq decodes a delegation (body and TaskDoc by the body rule), re-signs its TaskDoc
// with one of two fixed identities when asked, and checks every accepted delegation against the
// KEL of the identity picked.
func FuzzDelegateReq(f *testing.F) {
	ss := signers(f)
	suite, rotated := ss[0], ss[1]
	f.Add(seedDelegateReq(f, suite), false, byte(0), uint64(fuzzTS))
	f.Add(seedDelegateReq(f, rotated), false, byte(1), uint64(fuzzTS))
	f.Add(seedDelegateReq(f, rotated), true, byte(1), uint64(0))
	f.Add(seedDelegateReq(f, suite), true, byte(0), uint64(fuzzTS))
	f.Fuzz(func(t *testing.T, b []byte, resign bool, sel byte, msgTime uint64) {
		r, err := delegation.UnmarshalDelegateReq(b)
		if err != nil {
			if !errors.Is(err, delegation.ErrBody) {
				t.Fatalf("a refusal that is not ErrBody: %v", err)
			}
			return
		}
		// Accepted means canonical: the bytes are the encoding of what they decoded to, and the
		// TaskDoc inside them is the encoding of its own decoding.
		if again, err := r.Marshal(); err != nil || !bytes.Equal(again, b) {
			t.Fatalf("accepted a delegation that is not its canonical encoding (%v)", err)
		}
		var doc tsir.TaskDoc
		if err := coredet.UnmarshalStrict(r.TaskDoc, &doc); err != nil || len(doc.Tasks) == 0 {
			t.Fatalf("accepted a TaskDoc that does not decode strictly, or has no task (%v)", err)
		}
		if again, err := coredet.Marshal(doc); err != nil || !bytes.Equal(again, r.TaskDoc) {
			t.Fatalf("accepted a TaskDoc that is not its canonical encoding (%v)", err)
		}
		if r.Envelope == nil || r.InteractionID == "" {
			t.Fatal("accepted a delegation without its signature or interaction id")
		}
		c := ss[int(sel)%len(ss)]
		if resign && doc.Sign(c) == nil {
			r.Envelope = doc.Envelope
		}
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
	})
}

// fuzzTask is the suite identity's task the result seeds answer; the fuzz target checks every
// completion against it.
func fuzzTask(tb testing.TB) *task { return newTask(tb, identity.SuiteController(), "ix-golden-1") }

func seedResultResp(tb testing.TB, tk *task, c *identity.Controller, reply *delegation.ReplyMsg) []byte {
	tb.Helper()
	rr := tk.completion(tb, c, []byte(`{"ok":true}`), nil)
	rr.Metadata, rr.Reply = []byte(`{}`), reply
	b, err := rr.Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// FuzzResultResp decodes a completion by the body rule, checks the shape of every accepted one
// (status, reply), re-signs its receipt with one of two fixed identities when asked, and checks
// every accepted receipt against what the requester holds.
func FuzzResultResp(f *testing.F) {
	ss := signers(f)
	suite, rotated := ss[0], ss[1]
	tk := fuzzTask(f)
	reply := &delegation.ReplyMsg{Kind: delegation.ChatText, Body: "the answer", MsgID: "m-1",
		Attachments: []delegation.Attachment{{Name: "a", Size: 1, CID: "c", Data: []byte{1}}}}
	f.Add(seedResultResp(f, tk, suite, reply), false, byte(0), uint64(fuzzTS))
	f.Add(seedResultResp(f, tk, rotated, nil), true, byte(1), uint64(fuzzTS))
	f.Add(seedResultResp(f, tk, rotated, reply), true, byte(1), uint64(0))
	f.Fuzz(func(t *testing.T, b []byte, resign bool, sel byte, msgTime uint64) {
		r, err := delegation.UnmarshalResultResp(b)
		if err != nil {
			if !errors.Is(err, delegation.ErrBody) {
				t.Fatalf("a refusal that is not ErrBody: %v", err)
			}
			return
		}
		if again, err := r.Marshal(); err != nil || !bytes.Equal(again, b) {
			t.Fatalf("accepted a result that is not its canonical encoding (%v)", err)
		}
		if r.Status != delegation.StatusDone && r.Status != delegation.StatusFailed {
			t.Fatalf("accepted status %q", r.Status)
		}
		if r.Reply != nil && (r.Status != delegation.StatusDone || delegation.ValidateReply(r.Reply) != nil) {
			t.Fatalf("accepted a reply %+v on a %s result", r.Reply, r.Status)
		}
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

// FuzzChatMsg decodes a message by the body rule; an accepted message is canonical, of a known
// kind, carries the preview keys only as a preview frame (CORE-K6), and a preview frame that
// passes ValidatePreview holds every CUX-P2 property.
func FuzzChatMsg(f *testing.F) {
	for _, m := range []*delegation.ChatMsg{
		{Kind: delegation.ChatText, Body: "hi", MsgID: "m1",
			Attachments: []delegation.Attachment{{Name: "a", Size: 1, CID: "c", Data: []byte{1}}}, Metadata: []byte(`{}`)},
		{Kind: delegation.ChatStreamPreview, Body: "partial", StreamSeq: fuzzTS + 1, StreamAtMS: fuzzTS,
			ReasoningBody: "thinking", ReasoningStreamAtMS: fuzzTS - 1, MsgID: "p1", Omitted: 3, ReasoningOmitted: 4, Answers: "m1"},
		{Kind: delegation.KindCancel, MsgID: "m2"},
		{Kind: delegation.ChatEndRequest},
	} {
		b, err := m.Marshal()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := delegation.UnmarshalChatMsg(b)
		if err != nil {
			if !errors.Is(err, delegation.ErrBody) {
				t.Fatalf("a refusal that is not ErrBody: %v", err)
			}
			return
		}
		if again, err := m.Marshal(); err != nil || !bytes.Equal(again, b) {
			t.Fatalf("accepted a message that is not its canonical encoding (%v)", err)
		}
		switch m.Kind {
		case delegation.ChatText, delegation.ChatEndRequest, delegation.KindCancel:
			if m.StreamSeq != 0 || m.StreamAtMS != 0 || m.ReasoningBody != "" || m.ReasoningStreamAtMS != 0 ||
				m.Omitted != 0 || m.ReasoningOmitted != 0 || m.Answers != "" {
				t.Fatalf("accepted a %s message with preview keys: %+v", m.Kind, m)
			}
			if delegation.ValidatePreview(m) == nil {
				t.Fatalf("ValidatePreview accepted a %s message", m.Kind)
			}
		case delegation.ChatStreamPreview:
			if delegation.ValidatePreview(m) != nil {
				return
			}
			if len(m.Attachments) > 0 || len(m.Metadata) > 0 || len(m.Body) > delegation.MaxPreviewTail ||
				len(m.ReasoningBody) > delegation.MaxPreviewTail || !utf8.ValidString(m.Body) || !utf8.ValidString(m.ReasoningBody) ||
				m.StreamSeq == 0 || m.StreamAtMS == 0 || m.MsgID == "" || m.Answers == "" {
				t.Fatalf("ValidatePreview accepted %+v", m)
			}
		default:
			t.Fatalf("accepted kind %q", m.Kind)
		}
	})
}

// FuzzStatusMsg decodes a status by the body rule; an accepted status is canonical.
func FuzzStatusMsg(f *testing.F) {
	status, _ := (&delegation.StatusMsg{State: delegation.StateWorking, Text: "t", Metadata: []byte(`{}`), At: fuzzTS}).Marshal()
	f.Add(status)
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := delegation.UnmarshalStatusMsg(b)
		if err != nil {
			if !errors.Is(err, delegation.ErrBody) {
				t.Fatalf("a refusal that is not ErrBody: %v", err)
			}
			return
		}
		if again, err := m.Marshal(); err != nil || !bytes.Equal(again, b) {
			t.Fatalf("accepted a status that is not its canonical encoding (%v)", err)
		}
		_ = delegation.ValidStatusState(m.State)
	})
}
