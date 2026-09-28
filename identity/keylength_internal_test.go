package identity

import (
	"crypto/ed25519"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
)

// signedEvent signs e with k and fills its event id, as a KEL's author does.
func signedEvent(t *testing.T, e KeyEvent, k ed25519.PrivateKey) SignedEvent {
	t.Helper()
	pre, err := preimage(e)
	if err != nil {
		t.Fatal(err)
	}
	id, err := anetcid.Sum(pre)
	if err != nil {
		t.Fatal(err)
	}
	return SignedEvent{Event: e, Sig: ed25519.Sign(k, pre), EventID: id}
}

// A KEL whose icp or rot key is not 32 bytes is refused by Replay, and so
// by VerifyObject, rather than panicking in ed25519.Verify. A KEL is what a
// stranger hands the verifier (a message's sender, a registrant, a peer
// hub), and the panic took down the goroutine that replayed it: a daemon's
// receive loop, a hub's federation sync, a hub starting up over pinned peer
// KELs [redteam:F34].
func TestAKeyOfTheWrongLengthIsRefusedNotAPanic(t *testing.T) {
	_, k0, _ := ed25519.GenerateKey(nil)
	short := make([]byte, ed25519.PublicKeySize-1)

	// icp carrying a 31-byte key.
	icp := signedEvent(t, KeyEvent{Type: Inception, Keys: [][]byte{short}, Threshold: 1}, k0)
	if _, err := Replay([]SignedEvent{icp}); err == nil {
		t.Fatal("an icp with a 31-byte key replayed")
	}

	// A well-formed icp that pre-commits to a 31-byte next key, and the rot
	// that reveals it, signed by the icp key as a rot must be.
	icp = signedEvent(t, KeyEvent{Type: Inception, Keys: [][]byte{k0.Public().(ed25519.PublicKey)},
		NextDigest: nextDigest(short), Threshold: 1}, k0)
	aid := icp.EventID
	icp.Event.AID = ""
	rot := signedEvent(t, KeyEvent{AID: aid, Seq: 1, Prev: aid, Type: Rotation, Keys: [][]byte{short},
		NextDigest: nextDigest(short), Threshold: 1, Timestamp: 1}, k0)
	kel := []SignedEvent{icp, rot}
	if _, err := Replay(kel); err == nil {
		t.Fatal("a rot to a 31-byte key replayed")
	}
	if err := VerifyObject(kel, aid, 1, 2, []byte("x"), make([]byte, 64)); err == nil {
		t.Fatal("an object verified against a KEL whose key is 31 bytes")
	}
}
