package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
)

// The frozen conformance identities (design3/spec/_CONVENTIONS §8).
//
// Golden vectors for signed objects need an identity that is the same in
// every run and every implementation. aobj already froze a suite key for
// raw-signature vectors; anything carrying a KEL — a receipt, a
// delegation, a credential — needs a whole identity, because the AID is
// the hash of the inception event and every id downstream folds it in.
//
// The seeds are derived rather than stored so a second implementation can
// reproduce these identities from the spec text alone:
//
//	cur = SHA-256("anet-suite-identity-v1/cur")
//	nxt = SHA-256("anet-suite-identity-v1/nxt")
//
// Each icp is a KEL v2 inception at ts 1760000000000 that k0 = cur signs
// and that commits the hot key k1 = nxt (KEL C-5): toad 0 for the hub
// identity (SuiteController), toad 1 for the agent identity
// (SuiteAgentController). The two share their keys and differ in their AID,
// since toad is part of the icp.
//
// Both private keys are published, by construction. These identities are
// for conformance vectors and nothing else — an object signed by one proves
// an encoding, never a fact about anyone.
var (
	suiteCurSeed = sha256.Sum256([]byte("anet-suite-identity-v1/cur"))
	suiteNxtSeed = sha256.Sum256([]byte("anet-suite-identity-v1/nxt"))
)

// SuiteInceptionTS is the ts of the conformance identities' icp.
const SuiteInceptionTS uint64 = 1760000000000

// SuiteController returns the frozen conformance hub identity (toad 0).
//
// It is rebuilt on each call rather than shared, because a Controller
// carries rotation state and a vector that mutated a package-level
// identity would make the next vector depend on the order tests ran in.
func SuiteController() *Controller { return suiteIdentity(ToadHub) }

// SuiteAgentController returns the frozen conformance agent identity
// (toad 1): its icp names no witness yet, and the hot key it commits is
// held, so a test can designate one (BuildWitnessDesignation).
func SuiteAgentController() *Controller { return suiteIdentity(ToadAgent) }

func suiteIdentity(toad uint64) *Controller {
	k0 := ed25519.NewKeyFromSeed(suiteCurSeed[:])
	k1 := ed25519.NewKeyFromSeed(suiteNxtSeed[:])
	c, err := inceptWith(k0, k1, SuiteInceptionTS, toad)
	if err != nil {
		// The inception of fixed, valid keys cannot fail; if it does, the
		// encoder is broken and every vector anchored here is meaningless.
		panic("identity: suite inception: " + err.Error())
	}
	return c
}
