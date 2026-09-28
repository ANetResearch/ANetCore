package aobj_test

// Fuzz target for the P1 signature envelope and Verify (ANet docs/notes/0033).

import (
	"crypto/ed25519"
	"testing"

	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
)

func FuzzEnvelopeVerify(f *testing.F) {
	pre := []byte("agent-network v3")
	sig := aobj.SuiteSign(pre)
	env, _ := coredet.Marshal(aobj.Envelope{SignerAID: "a", KeyStateSeq: 1, Alg: aobj.AlgEdDSA, Sig: sig, PreimageRef: "r"})
	f.Add(env, []byte(aobj.SuitePub), pre, sig)
	f.Fuzz(func(t *testing.T, envb, pub, pre, sig []byte) {
		var e aobj.Envelope
		if coredet.Unmarshal(envb, &e) == nil {
			if err := e.Validate(); err == nil && (e.Alg != aobj.AlgEdDSA || len(e.Sig) != ed25519.SignatureSize) {
				t.Fatalf("Validate accepted %+v", e)
			}
		}
		if err := aobj.Verify(pub, pre, sig); err == nil {
			if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, pre, sig) {
				t.Fatal("Verify accepted a signature ed25519 rejects")
			}
		}
	})
}
