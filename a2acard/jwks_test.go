package a2acard

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
)

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

func parseJWKS(t *testing.T, kel []identity.SignedEvent) []jwk {
	t.Helper()
	b, err := JWKS(kel)
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(b, &set); err != nil {
		t.Fatal(err)
	}
	if set.Keys == nil {
		t.Fatalf("keys member missing or null: %s", b)
	}
	return set.Keys
}

func jwkFor(aid string, seq uint64, pub ed25519.PublicKey) jwk {
	return jwk{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(pub), Kid: KID(aid, seq), Alg: "EdDSA", Use: "sig"}
}

func pubOf(c *identity.Controller) ed25519.PublicKey {
	return c.CurrentPrivateKey().Public().(ed25519.PublicKey)
}

func TestJWKSKeyStates(t *testing.T) {
	host := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	c := incept(t)
	aid := c.AID()
	p0 := pubOf(c)

	assertKeys := func(step string, want ...jwk) {
		t.Helper()
		got := parseJWKS(t, c.KEL())
		if len(got) != len(want) {
			t.Fatalf("%s: %d keys %+v, want %d", step, len(got), got, len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: key %d = %+v, want %+v", step, i, got[i], want[i])
			}
		}
	}

	assertKeys("icp", jwkFor(aid, 0, p0))
	if err := c.Delegate(host, t0); err != nil {
		t.Fatal(err)
	}
	assertKeys("icp->drt", jwkFor(aid, 0, p0), jwkFor(aid, 1, p0))
	if err := c.Rotate(t0); err != nil {
		t.Fatal(err)
	}
	p2 := pubOf(c)
	assertKeys("icp->drt->rot", jwkFor(aid, 2, p2))
	if err := c.Delegate(host, t0); err != nil {
		t.Fatal(err)
	}
	assertKeys("icp->drt->rot->drt", jwkFor(aid, 2, p2), jwkFor(aid, 3, p2))
	if err := c.Deactivate(t0); err != nil {
		t.Fatal(err)
	}
	assertKeys("deactivated")
	b, err := JWKS(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"keys":[]}` {
		t.Fatalf("deactivated JWKS = %s", b)
	}
}

// JWKS and Verify apply one rule: a card signed under key state s is accepted exactly when
// kid #s is listed. A disagreement would let a JWKS-based verifier (a2a-go with jku) accept
// cards that the hub and daemons reject, or the reverse.
func TestJWKSAgreesWithVerify(t *testing.T) {
	host := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	c := incept(t)
	keyAt := []ed25519.PrivateKey{c.CurrentPrivateKey()} // key held at each seq
	step := func(f func() error) {
		if err := f(); err != nil {
			t.Fatal(err)
		}
		keyAt = append(keyAt, c.CurrentPrivateKey())
	}
	step(func() error { return c.Delegate(host, t0) })
	step(func() error { return c.Rotate(t0) })
	step(func() error { return c.Delegate(host, t0) })
	step(func() error { return c.Rotate(t0) })
	step(func() error { return c.Delegate(host, t0) })

	listed := map[string]bool{}
	for _, k := range parseJWKS(t, c.KEL()) {
		listed[k.Kid] = true
	}
	for seq, key := range keyAt {
		kid := KID(c.AID(), uint64(seq))
		_, err := Verify(signAs(t, baseCard(c.AID()), key, kid), newResolver(c).resolve, t0)
		if accepted := err == nil; accepted != listed[kid] {
			t.Errorf("seq %d: Verify accepted=%v (err %v), JWKS lists=%v", seq, accepted, err, listed[kid])
		}
	}
	if len(listed) != 2 {
		t.Fatalf("JWKS lists %d kids, want 2 (the rot and the drt after it)", len(listed))
	}
}

func TestJWKSRejectsInvalidKEL(t *testing.T) {
	c := incept(t)
	if _, err := JWKS(corruptKEL(c.KEL())); !IsCode(err, CodeUnknownAID) {
		t.Fatalf("corrupt KEL: %v", err)
	}
	if _, err := JWKS(nil); !IsCode(err, CodeUnknownAID) {
		t.Fatalf("empty KEL: %v", err)
	}
}
