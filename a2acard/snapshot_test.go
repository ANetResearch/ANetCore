package a2acard

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
)

// KEL C-23 and P4: the kid's seq and the key that signs come from one key state, even while the
// identity rotates. Cards are signed with the live controller (SignWithSnapshot snapshots it)
// while another goroutine builds and adopts rotations; every card's signature verifies under the
// key the final KEL gives the kid's seq.
func TestSignWithSnapshotKidNamesTheSigningKey(t *testing.T) {
	c, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var cards [][]byte
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			out, err := SignWithSnapshot(marshal(t, baseCard(c.AID())), c, jku(c.AID()))
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			cards = append(cards, out)
			mu.Unlock()
		}
	}()
	for i := 0; i < 30; i++ {
		if err := identitytest.Rotate(c, uint64(1000*(i+2))); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	states, err := identity.Replay(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) == 0 {
		t.Fatal("no card signed")
	}
	for _, card := range cards {
		sig := signaturesOf(t, card)[0]
		hdr, err := parseHeader(sig.Protected)
		if err != nil {
			t.Fatal(err)
		}
		_, seq, err := ParseKID(hdr.Kid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifySignature(card, sig, ed25519.PublicKey(states[seq].CurrentKeys[0])); err != nil {
			t.Fatalf("a card's kid names seq %d, whose key did not sign it: %v", seq, err)
		}
	}
	// the last card is current; one signed under a snapshot from before the last rotation is
	// not, whatever its time (KEL C-11)
	old := c.Snapshot()
	if err := identitytest.Rotate(c, 100000); err != nil {
		t.Fatal(err)
	}
	stale, err := SignWithSnapshot(marshal(t, baseCard(c.AID())), old, jku(c.AID()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(stale, newResolver(c).resolve, t0); !IsCode(err, CodeKeyNotCurrent) {
		t.Fatalf("a card of a rotated key state: %v", err)
	}
	fresh, err := SignWithSnapshot(marshal(t, baseCard(c.AID())), c.Snapshot(), jku(c.AID()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(fresh, newResolver(c).resolve, t0); err != nil {
		t.Fatalf("a card of the current key state: %v", err)
	}
}

// lyingSigner reports a key_state_seq that is not the last of its KEL.
type lyingSigner struct{ identity.Signer }

func (l lyingSigner) Sign(p []byte) ([]byte, uint64) {
	sig, seq := l.Signer.Sign(p)
	return sig, seq + 1
}

// emptySigner holds no key: it signs nothing.
type emptySigner struct{ identity.Signer }

func (emptySigner) Sign(p []byte) ([]byte, uint64) { return nil, 0 }

// A Signer whose Sign disagrees with its KEL about the key state, or that makes no signature, gets
// no card.
func TestSignWithSnapshotRefusesAnInconsistentSigner(t *testing.T) {
	c := incept(t)
	card := marshal(t, baseCard(c.AID()))
	if _, err := SignWithSnapshot(card, lyingSigner{c.Snapshot()}, ""); !errors.Is(err, identity.ErrSignerSeq) {
		t.Fatalf("a signer that names another seq: %v", err)
	}
	if _, err := SignWithSnapshot(card, emptySigner{c.Snapshot()}, ""); !IsCode(err, CodeInvalidSignature) {
		t.Fatalf("a signer that signs nothing: %v", err)
	}
}

// midRotation is a live signer whose identity rotates the first time it signs, between the kid
// being written and the signature being made.
type midRotation struct {
	c    *identity.Controller
	once sync.Once
	err  error
}

func (m *midRotation) AID() string                 { return m.c.AID() }
func (m *midRotation) KEL() []identity.SignedEvent { return m.c.KEL() }
func (m *midRotation) Snapshot() identity.Signer   { return m.c.Snapshot() }
func (m *midRotation) Sign(p []byte) ([]byte, uint64) {
	m.once.Do(func() { m.err = identitytest.Rotate(m.c, 5000) })
	return m.c.Sign(p)
}

// The kid and the signature come from one snapshot taken before anything else: the live signer,
// whose own Sign would rotate the identity under the kid already written, is never asked to sign.
// The card names seq 0 and is signed by the key of seq 0 (a deterministic form of the race above).
func TestSignWithSnapshotSurvivesARotationMidSign(t *testing.T) {
	m := &midRotation{c: incept(t)}
	k0 := ed25519.PublicKey(m.c.KEL()[0].Event.Keys[0])
	card, err := SignWithSnapshot(marshal(t, baseCard(m.c.AID())), m, "")
	if err != nil {
		t.Fatalf("signing across a rotation: %v", err)
	}
	if m.err != nil {
		t.Fatal(m.err)
	}
	sig := signaturesOf(t, card)[0]
	hdr, err := VerifySignature(card, sig, k0)
	if err != nil || hdr.Kid != KID(m.c.AID(), 0) {
		t.Fatalf("kid %v, signature %v", hdr, err)
	}
}
