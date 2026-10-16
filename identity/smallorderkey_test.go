package identity_test

import (
	"crypto/sha256"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// TestInceptionRefusesSmallOrderKey: an icp whose key is the Ed25519 identity point replayed, and
// the signature 0x01 00..00 then verified over any message, so the AID's signatures were
// universally forgeable.
func TestInceptionRefusesSmallOrderKey(t *testing.T) {
	nd := sha256.Sum256([]byte("next"))
	toad := uint64(0)
	for _, first := range []byte{0x01, 0x00} {
		pub := make([]byte, 32)
		pub[0] = first
		ev := identity.KeyEvent{KELType: identity.KELType, Seq: 0, Type: identity.Inception, Keys: [][]byte{pub},
			NextDigest: nd[:], Threshold: 1, Timestamp: 5, Toad: &toad}
		pre, err := coredet.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := anetcid.Sum(pre)
		sig := make([]byte, 64)
		sig[0] = 1
		se := identity.SignedEvent{Event: ev, Sig: sig, EventID: id}
		if _, err := identity.Replay([]identity.SignedEvent{se}); err == nil {
			t.Errorf("key %#x...: icp with a small-order key replayed", first)
		}
	}
}
