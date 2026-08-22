package identity

import (
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/ANetResearch/ANetCore/anetcid"
)

// The frozen conformance identity (design3/spec/_CONVENTIONS §8).
//
// Golden vectors for signed objects need an identity that is the same in
// every run and every implementation. aobj already froze a suite key for
// raw-signature vectors; anything carrying a KEL — a receipt, a
// delegation, a credential — needs a whole identity, because the AID is
// the hash of the inception event and every id downstream folds it in.
//
// The seeds are derived rather than stored so a second implementation can
// reproduce this identity from the spec text alone:
//
//	cur = SHA-256("anet-suite-identity-v1/cur")
//	nxt = SHA-256("anet-suite-identity-v1/nxt")
//
// Both private keys are published, by construction. This identity is for
// conformance vectors and nothing else — an object signed by it proves an
// encoding, never a fact about anyone.
var (
	suiteCurSeed = sha256.Sum256([]byte("anet-suite-identity-v1/cur"))
	suiteNxtSeed = sha256.Sum256([]byte("anet-suite-identity-v1/nxt"))
)

// SuiteController returns the frozen conformance identity.
//
// It is rebuilt on each call rather than shared, because a Controller
// carries rotation state and a vector that mutated a package-level
// identity would make the next vector depend on the order tests ran in.
func SuiteController() *Controller {
	k0 := ed25519.NewKeyFromSeed(suiteCurSeed[:])
	k1 := ed25519.NewKeyFromSeed(suiteNxtSeed[:])
	icp := KeyEvent{
		Seq:        0,
		Type:       Inception,
		Keys:       [][]byte{k0.Public().(ed25519.PublicKey)},
		NextDigest: nextDigest(k1.Public().(ed25519.PublicKey)),
		Threshold:  1,
	}
	pre, err := preimage(icp)
	if err != nil {
		// preimage over a fixed, valid inception cannot fail; if it does,
		// the encoder is broken and every vector below is meaningless.
		panic("identity: suite inception preimage: " + err.Error())
	}
	aid, err := anetcid.Sum(pre)
	if err != nil {
		panic("identity: suite inception cid: " + err.Error())
	}
	c := &Controller{aid: aid, cur: k0, nxt: k1}
	c.kel = append(c.kel, SignedEvent{Event: icp, Sig: ed25519.Sign(k0, pre), EventID: aid})
	return c
}
