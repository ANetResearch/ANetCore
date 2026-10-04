package ael

import (
	"errors"
	"sync"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
)

// rotatesOnSign is a live signer whose identity rotates the first time it is asked to sign: after
// the record's key_state_seq was stamped and before the signature is made.
type rotatesOnSign struct {
	c    *identity.Controller
	once sync.Once
	err  error
}

func (r *rotatesOnSign) AID() string                 { return r.c.AID() }
func (r *rotatesOnSign) KEL() []identity.SignedEvent { return r.c.KEL() }
func (r *rotatesOnSign) Snapshot() identity.Signer   { return r.c.Snapshot() }
func (r *rotatesOnSign) Sign(p []byte) ([]byte, uint64) {
	r.once.Do(func() { r.err = identitytest.Rotate(r.c, 5000) })
	return r.c.Sign(p)
}

// The key_state_seq a record carries is inside its preimage, so it is stamped before signing. Sign
// takes both from one snapshot of the signer (KEL C-22): a rotation of the live identity in
// between does not produce a record that names one key state and is signed under another.
func TestEventRecordSignUsesOneKeyState(t *testing.T) {
	c, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	live := &rotatesOnSign{c: c}
	r := &EventRecord{ChainDID: c.DID(), Seq: 0, PrevID: GenesisPrev(), EventType: "anet.test", VersionMajor: 2,
		Payload: map[string]any{"k": "v"}, Timestamp: 1000}
	if err := r.Sign(live); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if live.err != nil {
		t.Fatal(live.err)
	}
	if r.KeyStateSeq != 0 || r.SignerAID != c.AID() {
		t.Fatalf("stamped %s at %d", r.SignerAID, r.KeyStateSeq)
	}
	if err := r.Verify(c.KEL()); err != nil {
		t.Fatalf("the record does not verify under the KEL: %v", err)
	}
	// a signer whose Sign names another key state than its KEL gets no record
	if err := (&EventRecord{ChainDID: c.DID(), EventType: "anet.test", VersionMajor: 2, Timestamp: 6000}).Sign(lying{c.Snapshot()}); !errors.Is(err, identity.ErrSignerSeq) {
		t.Fatalf("a lying signer: %v", err)
	}
}

type lying struct{ identity.Signer }

func (l lying) Sign(p []byte) ([]byte, uint64) { sig, seq := l.Signer.Sign(p); return sig, seq + 1 }
