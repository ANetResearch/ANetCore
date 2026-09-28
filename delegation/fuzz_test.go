package delegation_test

// Fuzz targets for the relayed delegation payloads and their verifiers (ANet docs/notes/0033).
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
	seed := func(label string) []byte { s := sha256.Sum256([]byte(label)); return s[:] }
	k0 := ed25519.NewKeyFromSeed(seed("anet-suite-identity-v1/cur"))
	k1Seed, k2Seed := seed("anet-suite-identity-v1/nxt"), seed("anet-fuzz/delegation/k2")
	k1, k2 := ed25519.NewKeyFromSeed(k1Seed), ed25519.NewKeyFromSeed(k2Seed)
	kel := identity.SuiteController().KEL()
	d := sha256.Sum256(k2.Public().(ed25519.PublicKey))
	rot := identity.KeyEvent{AID: kel[0].EventID, Seq: 1, Prev: kel[0].EventID, Type: identity.Rotation,
		Keys: [][]byte{k1.Public().(ed25519.PublicKey)}, NextDigest: d[:], Threshold: 1, Timestamp: fuzzTS - 1000}
	pre, err := coredet.Marshal(rot)
	if err != nil {
		tb.Fatal(err)
	}
	kel = append(kel, identity.SignedEvent{Event: rot, Sig: ed25519.Sign(k0, pre), EventID: anetcid.MustSum(pre)})
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
		Payment:     []byte(`{"x402Version":2}`), ContextID: "ctx", Metadata: []byte(`{}`)}
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

func seedResultResp(tb testing.TB, c *identity.Controller, bodyKEL []byte) []byte {
	tb.Helper()
	deliverable := []byte(`{"ok":true}`)
	rc := &evidence.Receipt{InteractionID: "ix-golden-1", RequesterAID: "did:anet:golden-requester",
		RequestCID: "bafyreigoldenrequest", ResultCID: anetcid.MustSum(deliverable), CompletedAt: fuzzTS}
	if err := rc.Sign(c); err != nil {
		tb.Fatal(err)
	}
	receipt, err := rc.Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	b, err := (&delegation.ResultResp{Status: delegation.StatusDone, Deliverable: deliverable, Receipt: receipt,
		KEL: bodyKEL, Metadata: []byte(`{}`)}).Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func FuzzResultResp(f *testing.F) {
	ss := signers(f)
	suite, rotated := ss[0], ss[1]
	f.Add(seedResultResp(f, suite, kelBytes(f, suite)), false, byte(0), true, uint64(fuzzTS))
	f.Add(seedResultResp(f, rotated, kelBytes(f, suite)), true, byte(1), false, uint64(fuzzTS))
	f.Add(seedResultResp(f, rotated, nil), true, byte(1), true, uint64(0))
	f.Fuzz(func(t *testing.T, b []byte, resign bool, sel byte, bind bool, msgTime uint64) {
		r, err := delegation.UnmarshalResultResp(b)
		if err != nil {
			return
		}
		roundTrip(t, r, (*delegation.ResultResp).Marshal, delegation.UnmarshalResultResp)
		c := ss[int(sel)%len(ss)]
		decoded, derr := evidence.UnmarshalReceipt(r.Receipt)
		if resign && derr == nil {
			if decoded.Sign(c) == nil {
				if rb, err := decoded.Marshal(); err == nil {
					r.Receipt = rb
				}
			}
		}
		_, _ = delegation.VerifyResult(r, "", "", "", msgTime)
		ix, req, prov, reqCID := "", "", "", ""
		if bind {
			ix, req, prov, reqCID = "ix-golden-1", "did:anet:golden-requester", c.AID(), "bafyreigoldenrequest"
		}
		rc, err := delegation.VerifyResultForRequest(r, c.KEL(), ix, req, prov, reqCID, msgTime)
		if err != nil {
			if len(c.KEL()) > 0 && errors.Is(err, delegation.ErrUnverifiable) {
				t.Fatalf("ErrUnverifiable with a resolved KEL: %v", err)
			}
			return
		}
		if rc.Envelope == nil || rc.Envelope.SignerAID != c.AID() || rc.ProviderAID != c.AID() {
			t.Fatalf("accepted a receipt signed by %+v for provider %s against the KEL of %s", rc.Envelope, rc.ProviderAID, c.AID())
		}
		if got := anetcid.MustSum(r.Deliverable); rc.ResultCID != got {
			t.Fatalf("accepted a receipt for %s over a deliverable hashing to %s", rc.ResultCID, got)
		}
		if bind && (rc.InteractionID != ix || rc.RequesterAID != req || rc.RequestCID != reqCID) {
			t.Fatalf("accepted a receipt that does not bind what was asked: %+v", rc)
		}
		pre, err := rc.CanonicalPreimage()
		if err != nil {
			t.Fatal(err)
		}
		states, _ := identity.Replay(c.KEL())
		if seq := rc.Envelope.KeyStateSeq; seq >= uint64(len(states)) || !ed25519.Verify(states[seq].CurrentKeys[0], pre, rc.Envelope.Sig) {
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
