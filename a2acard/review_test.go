package a2acard

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

// encoding/base64 skips '\r' and '\n' even in strict mode. The decoders here accept only the
// base64url alphabet, so a signature or protected header has one accepted spelling.
func TestBase64LineBreaksRejected(t *testing.T) {
	v, key := loadCrossSDKVector(t)
	pub := key.Public().(ed25519.PublicKey)
	for _, brk := range []string{"\n", "\r", "\r\n"} {
		s := v.SignatureB64[:10] + brk + v.SignatureB64[10:]
		if _, err := VerifySignature(v.CardJSON, Signature{Protected: v.ProtectedB64, Signature: s}, pub); !IsCode(err, CodeInvalidSignature) {
			t.Errorf("signature with %q: err %v, want %s", brk, err, CodeInvalidSignature)
		}

		// A protected header with a line break, signed as given, so that only the decoding
		// rule can reject it.
		p := v.ProtectedB64[:8] + brk + v.ProtectedB64[8:]
		payload, err := SigningPayload(v.CardJSON)
		if err != nil {
			t.Fatal(err)
		}
		sig := Signature{Protected: p, Signature: b64.EncodeToString(ed25519.Sign(key, signingInput(p, payload)))}
		if _, err := VerifySignature(v.CardJSON, sig, pub); !IsCode(err, CodeBadHeader) {
			t.Errorf("protected header with %q: err %v, want %s", brk, err, CodeBadHeader)
		}
	}
}

// The same rule through Verify: a stored card whose signature string was re-spelled with a
// line break is rejected, so a relaying party cannot produce a second accepted byte form of a
// signed card by editing the signature entry.
func TestVerifyRejectsRespelledSignature(t *testing.T) {
	c := incept(t)
	good := signCard(t, baseCard(c.AID()), c)
	respelled := edit(t, good, func(m map[string]any) {
		s := m["signatures"].([]any)[0].(map[string]any)
		sig := s["signature"].(string)
		s["signature"] = sig[:20] + "\n" + sig[20:]
	})
	_, err := Verify(respelled, newResolver(c).resolve, t0)
	wantCode(t, err, CodeInvalidSignature)
}

// When the KEL lookup fails, no signature that names the card's AID could be checked, so the
// card's validity is unknown. Verify must report CodeKELUnavailable even when another
// signature, checked first, failed for a definite reason; otherwise a caller would record a
// permanent rejection of a card that may be valid.
func TestVerifyKELUnavailableIsNotMaskedByEarlierSignature(t *testing.T) {
	a := incept(t)
	b := incept(t)
	card := marshal(t, baseCard(a.AID()))

	// First signature: a non-anet kid (for example one added by an a2a-go signer).
	foreign, err := Sign(card, b.CurrentPrivateKey(), "key-1", "")
	if err != nil {
		t.Fatal(err)
	}
	// First signature: a kid of another AID.
	otherAID, err := Sign(card, b.CurrentPrivateKey(), KID(b.AID(), 0), "")
	if err != nil {
		t.Fatal(err)
	}
	for name, first := range map[string][]byte{"non-anet kid": foreign, "kid of another AID": otherAID} {
		both, err := SignWithController(first, a, "")
		if err != nil {
			t.Fatal(err)
		}
		// With the KEL available the card verifies through the second signature.
		if _, err := Verify(both, newResolver(a).resolve, t0); err != nil {
			t.Fatalf("%s: baseline rejected: %v", name, err)
		}
		// With the lookup failing, the result is "unknown", not the first signature's error.
		_, err = Verify(both, newResolver().resolve, t0)
		if !IsCode(err, CodeKELUnavailable) {
			t.Errorf("%s: err %v, want %s", name, err, CodeKELUnavailable)
		}
	}
}

// Member names that are equal under Unicode simple case folding are rejected at any depth.
// Go's encoding/json matches struct fields case-insensitively and keeps the last match in
// document order, so a card carrying both "protocolBinding" and "PROTOCOLBINDING" would be
// checked by Verify under one value and read by a2a-go's AgentCard decoder under the other.
func TestVerifyRejectsCaseFoldedDuplicateNames(t *testing.T) {
	a := incept(t)
	b := incept(t)
	cases := map[string]func(m map[string]any){
		"top-level name": func(m map[string]any) { m["NAME"] = "Other" },
		"relay interface binding": func(m map[string]any) {
			iface(m, 0)["protocolBinding"] = "JSONRPC"
			iface(m, 0)["tenant"] = b.AID()
			iface(m, 0)["PROTOCOLBINDING"] = BindingRelayURI
		},
		"relay interface tenant": func(m map[string]any) { iface(m, 0)["Tenant"] = b.AID() },
		"skill id":               func(m map[string]any) { skill(m, 0)["Id"] = "other" },
		"anet-card params":       func(m map[string]any) { params(m)["AID"] = b.AID() },
		// U+212A KELVIN SIGN folds to 'k', as bytes.EqualFold and encoding/json treat it.
		"non-ASCII fold": func(m map[string]any) { m["x-Key"] = 1; m["x-key"] = 2 },
	}
	for name, f := range cases {
		card := baseCard(a.AID())
		f(card)
		signed := signLoose(t, card, a) // Sign's publish-form check would refuse these first
		r := newResolver(a, b)
		_, err := Verify(signed, r.resolve, t0)
		if !IsCode(err, CodeInvalidCard) {
			t.Errorf("%s: err %v, want %s", name, err, CodeInvalidCard)
		}
		if r.calls != 0 {
			t.Errorf("%s: resolver called %d times; the check is structural", name, r.calls)
		}
	}

	// Names that differ in more than case stay distinct, including '_' and '-', which
	// encoding/json v1 does not ignore.
	card := baseCard(a.AID())
	card["x-key"] = 1
	card["x_key"] = 2
	card["xkey"] = 3
	skill(card, 0)["examples"] = []any{"e"}
	if _, err := Verify(signLoose(t, card, a), newResolver(a).resolve, t0); err != nil {
		t.Fatalf("distinct names rejected: %v", err)
	}
}

// Error() renders the code, the detail and the wrapped cause.
func TestErrorString(t *testing.T) {
	e := &Error{Code: CodeKELUnavailable, Detail: "resolving KEL of x", Err: errNoKEL}
	if got, want := e.Error(), "KEL_UNAVAILABLE: resolving KEL of x: "+errNoKEL.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if got := newErr(CodeUnsigned, "").Error(); got != "UNSIGNED" {
		t.Fatalf("Error() = %q, want UNSIGNED", got)
	}
}

// Sign's output contains no line breaks, and its payload is unchanged when a Go consumer
// decodes the card into a map with encoding/json and encodes it again (member order and
// encoding/json's HTML escaping do not reach the canonical form).
func TestSignOutputIsStrict(t *testing.T) {
	c := incept(t)
	card := baseCard(c.AID())
	// encoding/json writes these as \u003c, \u0026, \u003e and \u2028; the canonical form
	// writes them literally.
	card["description"] = "a<b & c>d \u2028 e"
	signed := signCard(t, card, c)
	if strings.ContainsAny(string(signed), "\r\n") {
		t.Fatalf("signed card contains a line break: %s", signed)
	}
	var m map[string]any
	if err := json.Unmarshal(signed, &m); err != nil {
		t.Fatal(err)
	}
	re := marshal(t, m)
	p1, err := SigningPayload(signed)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := SigningPayload(re)
	if err != nil {
		t.Fatal(err)
	}
	if string(p1) != string(p2) {
		t.Fatalf("payload changed by an encoding/json round trip:\n%s\n%s", p1, p2)
	}
}

// A network card also carries the a2a-x402, anet-pricing and anet-evidence extensions
// (A2A-DESIGN §10.1), in any order. The anet-card extension is found wherever it appears.
func TestVerifyFindsCardExtensionAmongOthers(t *testing.T) {
	c := incept(t)
	card := baseCard(c.AID())
	anet := extensions(card)[0]
	card["capabilities"].(map[string]any)["extensions"] = []any{
		// Not required: the member is omitted, not written as false (A2A-DESIGN §8.7).
		map[string]any{"uri": "https://github.com/google-agentic-commerce/a2a-x402/blob/main/spec/v0.2"},
		map[string]any{"uri": "https://agentnetwork.org.cn/a2a/ext/anet-pricing/v1", "params": map[string]any{
			"network": "anet", "prices": []any{map[string]any{"skillId": "echo", "amount": "10"}},
		}},
		anet,
		map[string]any{"uri": "https://agentnetwork.org.cn/a2a/ext/anet-evidence/v1"},
	}
	v, err := Verify(signCard(t, card, c), newResolver(c).resolve, t0)
	if err != nil {
		t.Fatalf("card with the anet-card extension third rejected: %v", err)
	}
	if v.AID != c.AID() || v.Seq != t0 {
		t.Fatalf("Verified = %+v", v)
	}
}

// The relay tenant must equal the AID byte for byte (A2A-DESIGN §10.3). AIDs are lower-case
// base32, and a hub routes by the tenant string, so a tenant that differs only in case names no
// registered agent, or another one if a hub normalized case differently.
func TestVerifyRelayTenantIsExact(t *testing.T) {
	c := incept(t)
	for name, tenant := range map[string]string{
		"upper case":        strings.ToUpper(c.AID()),
		"trailing space":    c.AID() + " ",
		"did form":          c.DID(),
		"prefix of the AID": c.AID()[:len(c.AID())-1],
	} {
		card := baseCard(c.AID())
		iface(card, 0)["tenant"] = tenant
		_, err := Verify(signCard(t, card, c), newResolver(c).resolve, t0)
		if !IsCode(err, CodeBindingMismatch) {
			t.Errorf("%s: err %v, want %s", name, err, CodeBindingMismatch)
		}
	}
}
