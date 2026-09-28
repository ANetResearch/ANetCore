package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

// Pre-rotation against a stolen current key (ANet docs/notes/0033, found by FuzzReplayProgram).
//
// Replay used to check a rot's key against the next_digest of the event directly before the rot.
// An ixn or drt is signed by the current key alone, so whoever held a stolen current key could
// append one naming a key of its own as the "next" key and then rotate to that key, signing the
// rot with the stolen key: the owner's pre-committed next key never came into it. The commitment a
// rot must match is the one made by the last establishment event (icp or rot).

// preRotationKeys returns the owner's current key k0, its pre-committed next key k1 (which the
// attacker does not have) and a key of the attacker's.
func preRotationKeys() (k0, k1, attacker ed25519.PrivateKey) {
	key := func(label string) ed25519.PrivateKey {
		s := sha256.Sum256([]byte("anet-test/prerotation/" + label))
		return ed25519.NewKeyFromSeed(s[:])
	}
	return key("k0"), key("k1"), key("attacker")
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func TestAStolenCurrentKeyCannotRecommitThroughADrtOrIxnAndRotate(t *testing.T) {
	k0, k1, atk := preRotationKeys()
	for _, typ := range []EventType{Delegation, Interaction} {
		t.Run(string(typ), func(t *testing.T) {
			icp := signedEvent(t, KeyEvent{Type: Inception, Keys: [][]byte{pubOf(k0)},
				NextDigest: nextDigest(pubOf(k1)), Threshold: 1}, k0)
			aid := icp.EventID
			// Signed with the stolen k0; the "next" digest names the attacker's key.
			mid := signedEvent(t, KeyEvent{AID: aid, Seq: 1, Prev: aid, Type: typ, Keys: [][]byte{pubOf(atk)},
				NextDigest: nextDigest(pubOf(atk)), Threshold: 1, Timestamp: 1000}, k0)
			rot := signedEvent(t, KeyEvent{AID: aid, Seq: 2, Prev: mid.EventID, Type: Rotation, Keys: [][]byte{pubOf(atk)},
				NextDigest: nextDigest(pubOf(atk)), Threshold: 1, Timestamp: 2000}, k0)
			kel := []SignedEvent{icp, mid, rot}
			if _, err := Replay(kel); err == nil {
				t.Fatalf("a rot to the attacker's key, re-committed by a %s signed with the stolen current key, replayed", typ)
			}
			pre := []byte("object signed by the attacker")
			if err := VerifyObject(kel, aid, 2, 3000, pre, ed25519.Sign(atk, pre)); err == nil {
				t.Fatal("an object signed by the attacker's key verified as the AID's")
			}
		})
	}
}

// The owner's own rotation to the pre-committed key still replays when an ixn or drt in between
// carries another digest or none at all: those events never made the commitment.
func TestARotToTheCommittedKeyReplaysAcrossAnIxnOrDrtWithAnotherDigest(t *testing.T) {
	k0, k1, atk := preRotationKeys()
	for _, next := range [][]byte{nil, nextDigest(pubOf(atk))} {
		icp := signedEvent(t, KeyEvent{Type: Inception, Keys: [][]byte{pubOf(k0)},
			NextDigest: nextDigest(pubOf(k1)), Threshold: 1}, k0)
		aid := icp.EventID
		ixn := signedEvent(t, KeyEvent{AID: aid, Seq: 1, Prev: aid, Type: Interaction, Keys: [][]byte{pubOf(k0)},
			NextDigest: next, Threshold: 1, Timestamp: 1000}, k0)
		drt := signedEvent(t, KeyEvent{AID: aid, Seq: 2, Prev: ixn.EventID, Type: Delegation, Keys: [][]byte{pubOf(atk)},
			NextDigest: next, Threshold: 1, Timestamp: 1500}, k0)
		rot := signedEvent(t, KeyEvent{AID: aid, Seq: 3, Prev: drt.EventID, Type: Rotation, Keys: [][]byte{pubOf(k1)},
			NextDigest: nextDigest(pubOf(atk)), Threshold: 1, Timestamp: 2000}, k0)
		states, err := Replay([]SignedEvent{icp, ixn, drt, rot})
		if err != nil {
			t.Fatalf("owner's rotation to the committed key (ixn/drt digest %x): %v", next, err)
		}
		if got := states[3].CurrentKeys[0]; !pubOf(k1).Equal(ed25519.PublicKey(got)) {
			t.Fatalf("current key after rot = %x, want k1", got)
		}
	}
}
