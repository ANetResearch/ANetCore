package a2acard

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
)

func TestVerifyAcceptsSignedCard(t *testing.T) {
	c := incept(t)
	card := baseCard(c.AID())
	card["skills"] = append(card["skills"].([]any), map[string]any{
		"id": "translate", "name": "Translate", "description": "Translates text.",
		"tags": []any{"text", "translation"}, "examples": []any{"translate hello"},
	})
	signed := signCard(t, card, c)
	r := newResolver(c)
	v, err := Verify(signed, r.resolve, t0)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := SigningPayload(signed)
	if err != nil {
		t.Fatal(err)
	}
	want := &Verified{
		AID: c.AID(), KeyStateSeq: 0, Seq: t0, IssuedAt: t0, NotBefore: t0 - 60_000,
		PayloadHash: sha256.Sum256(payload), Name: "Test Agent",
		Skills: []Skill{
			{ID: "echo", Name: "Echo", Description: "Returns the input text.", Tags: []string{"text", "echo"}},
			{ID: "translate", Name: "Translate", Description: "Translates text.", Tags: []string{"text", "translation"}},
		},
	}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("Verified =\n%+v\nwant\n%+v", v, want)
	}
	if r.calls != 1 {
		t.Fatalf("resolver called %d times, want 1", r.calls)
	}
	if m := v.Mark(); m.Seq != t0 || m.PayloadHash != v.PayloadHash {
		t.Fatalf("Mark = %+v", m)
	}
}

// A card signed under the current key after a rotation is accepted with the new key-state seq.
func TestVerifyAfterRotation(t *testing.T) {
	c := incept(t)
	if err := c.Rotate(t0 - 1000); err != nil {
		t.Fatal(err)
	}
	v, err := Verify(signCard(t, baseCard(c.AID()), c), newResolver(c).resolve, t0)
	if err != nil {
		t.Fatal(err)
	}
	if v.KeyStateSeq != 1 {
		t.Fatalf("KeyStateSeq = %d, want 1", v.KeyStateSeq)
	}
}

// Each §10.3 rejection, with the code it must produce. Every case starts from a card that
// verifies, so a case that passes shows that one check is live.
func TestVerifyRejections(t *testing.T) {
	a := incept(t)
	b := incept(t)
	rotated := incept(t)
	oldKey := rotated.CurrentPrivateKey()
	if err := rotated.Rotate(t0 - 1000); err != nil {
		t.Fatal(err)
	}
	good := signCard(t, baseCard(a.AID()), a)
	if _, err := Verify(good, newResolver(a).resolve, t0); err != nil {
		t.Fatalf("baseline card rejected: %v", err)
	}

	withCard := func(f func(map[string]any)) []byte {
		card := baseCard(a.AID())
		f(card)
		return signCard(t, card, a)
	}
	after := func(f func(map[string]any)) []byte { return edit(t, good, f) }

	cases := []struct {
		name string
		card []byte
		res  *resolver // nil: the resolver for a and b
		want Code
	}{
		// Signature coverage.
		{"skill id changed after signing", after(func(m map[string]any) { skill(m, 0)["id"] = "echo2" }), nil, CodeInvalidSignature},
		{"tag changed after signing", after(func(m map[string]any) { skill(m, 0)["tags"] = []any{"text", "other"} }), nil, CodeInvalidSignature},
		{"name changed after signing", after(func(m map[string]any) { m["name"] = "Other" }), nil, CodeInvalidSignature},
		{"member added after signing", after(func(m map[string]any) { m["iconUrl"] = "https://x.example/i.png" }), nil, CodeInvalidSignature},
		{"seq changed after signing", after(func(m map[string]any) { params(m)["seq"] = dec(t0 + 1) }), nil, CodeInvalidSignature},
		{"signature value replaced", after(func(m map[string]any) {
			s := m["signatures"].([]any)[0].(map[string]any)
			s["signature"] = b64.EncodeToString(make([]byte, 64))
		}), nil, CodeInvalidSignature},
		{"signed by another key under a's kid", signAs(t, baseCard(a.AID()), b.CurrentPrivateKey(), KID(a.AID(), 0)), nil, CodeInvalidSignature},

		// Unsigned.
		{"signatures removed", after(func(m map[string]any) { delete(m, "signatures") }), nil, CodeUnsigned},
		{"signatures empty", after(func(m map[string]any) { m["signatures"] = []any{} }), nil, CodeUnsigned},
		{"signatures null", after(func(m map[string]any) { m["signatures"] = nil }), nil, CodeInvalidCard},
		{"signature entry without signature", after(func(m map[string]any) {
			delete(m["signatures"].([]any)[0].(map[string]any), "signature")
		}), nil, CodeInvalidCard},
		{"signature entry not an object", after(func(m map[string]any) { m["signatures"] = []any{"x"} }), nil, CodeInvalidCard},

		// Binding of the kid, params.aid and relay tenant to one AID.
		{"kid with another AID", signAs(t, baseCard(a.AID()), b.CurrentPrivateKey(), KID(b.AID(), 0)), nil, CodeBindingMismatch},
		{"relay tenant is another AID", withCard(func(m map[string]any) { iface(m, 0)["tenant"] = b.AID() }), nil, CodeBindingMismatch},
		{"relay tenant missing", withCard(func(m map[string]any) { delete(iface(m, 0), "tenant") }), nil, CodeBindingMismatch},
		{"relay tenant changed after signing", after(func(m map[string]any) { iface(m, 0)["tenant"] = b.AID() }), nil, CodeBindingMismatch},
		{"second relay interface with another tenant", withCard(func(m map[string]any) {
			m["supportedInterfaces"] = append(m["supportedInterfaces"].([]any), map[string]any{
				"url": "https://hub2.example.org/relay/v2", "protocolBinding": BindingRelayURI,
				"protocolVersion": "1.0", "tenant": b.AID(),
			})
		}), nil, CodeBindingMismatch},
		{"params.aid is another AID", withCard(func(m map[string]any) { params(m)["aid"] = b.AID(); iface(m, 0)["tenant"] = b.AID() }), nil, CodeBindingMismatch},

		// KEL and key state.
		{"kid seq points to a rotated key state", signAs(t, baseCard(rotated.AID()), oldKey, KID(rotated.AID(), 0)), newResolver(rotated), CodeKeyNotCurrent},
		{"kid seq beyond the KEL", signAs(t, baseCard(a.AID()), a.CurrentPrivateKey(), KID(a.AID(), 1)), nil, CodeKeyNotCurrent},
		{"resolver returns another AID's KEL", good, &resolver{kels: map[string][]identity.SignedEvent{a.AID(): b.KEL()}}, CodeUnknownAID},
		{"resolver returns a KEL with a bad signature", good, &resolver{kels: map[string][]identity.SignedEvent{a.AID(): corruptKEL(a.KEL())}}, CodeUnknownAID},
		{"resolver returns an empty KEL", good, &resolver{kels: map[string][]identity.SignedEvent{a.AID(): {}}}, CodeUnknownAID},
		{"resolver fails", good, newResolver(b), CodeKELUnavailable},

		// notBefore.
		{"notBefore beyond the skew", withCard(func(m map[string]any) { params(m)["notBefore"] = dec(t0 + NotBeforeSkewMillis + 1) }), nil, CodeNotYetValid},

		// anet-card extension.
		{"params.seq as a JSON number", withCard(func(m map[string]any) { params(m)["seq"] = json.Number("9007199254740993") }), nil, CodeInvalidCard},
		{"params.seq with a leading zero", withCard(func(m map[string]any) { params(m)["seq"] = "0" + dec(t0) }), nil, CodeInvalidCard},
		{"params.seq with a sign", withCard(func(m map[string]any) { params(m)["seq"] = "+" + dec(t0) }), nil, CodeInvalidCard},
		{"params.seq empty", withCard(func(m map[string]any) { params(m)["seq"] = "" }), nil, CodeInvalidCard},
		{"params.seq above uint64", withCard(func(m map[string]any) { params(m)["seq"] = "18446744073709551616" }), nil, CodeInvalidCard},
		{"params.seq decimal point", withCard(func(m map[string]any) { params(m)["seq"] = "1.0" }), nil, CodeInvalidCard},
		{"params.issuedAt missing", withCard(func(m map[string]any) { delete(params(m), "issuedAt") }), nil, CodeInvalidCard},
		{"params.notBefore as a number", withCard(func(m map[string]any) { params(m)["notBefore"] = 1 }), nil, CodeInvalidCard},
		{"params.aid missing", withCard(func(m map[string]any) { delete(params(m), "aid") }), nil, CodeInvalidCard},
		{"params missing", withCard(func(m map[string]any) { delete(extensions(m)[0].(map[string]any), "params") }), nil, CodeInvalidCard},
		{"no anet-card extension", withCard(func(m map[string]any) { extensions(m)[0].(map[string]any)["uri"] = "https://example.org/other" }), nil, CodeInvalidCard},
		{"extensions missing", withCard(func(m map[string]any) { delete(m["capabilities"].(map[string]any), "extensions") }), nil, CodeInvalidCard},
		{"extension without uri", withCard(func(m map[string]any) {
			caps := m["capabilities"].(map[string]any)
			caps["extensions"] = append([]any{map[string]any{"required": false}}, extensions(m)...)
		}), nil, CodeInvalidCard},
		{"two anet-card extensions", withCard(func(m map[string]any) {
			caps := m["capabilities"].(map[string]any)
			caps["extensions"] = append(extensions(m), extensions(m)[0])
		}), nil, CodeInvalidCard},

		// Required members.
		{"name missing", withCard(func(m map[string]any) { delete(m, "name") }), nil, CodeInvalidCard},
		{"name empty", withCard(func(m map[string]any) { m["name"] = "" }), nil, CodeInvalidCard},
		{"description missing", withCard(func(m map[string]any) { delete(m, "description") }), nil, CodeInvalidCard},
		{"version missing", withCard(func(m map[string]any) { delete(m, "version") }), nil, CodeInvalidCard},
		{"version not a string", withCard(func(m map[string]any) { m["version"] = 1 }), nil, CodeInvalidCard},
		{"supportedInterfaces missing", withCard(func(m map[string]any) { delete(m, "supportedInterfaces") }), nil, CodeInvalidCard},
		{"supportedInterfaces empty", withCard(func(m map[string]any) { m["supportedInterfaces"] = []any{} }), nil, CodeInvalidCard},
		{"interface url missing", withCard(func(m map[string]any) { delete(iface(m, 0), "url") }), nil, CodeInvalidCard},
		{"interface protocolBinding empty", withCard(func(m map[string]any) { iface(m, 0)["protocolBinding"] = "" }), nil, CodeInvalidCard},
		{"interface protocolVersion missing", withCard(func(m map[string]any) { delete(iface(m, 0), "protocolVersion") }), nil, CodeInvalidCard},
		{"interface not an object", withCard(func(m map[string]any) { m["supportedInterfaces"] = []any{"x"} }), nil, CodeInvalidCard},
		{"capabilities missing", withCard(func(m map[string]any) { delete(m, "capabilities") }), nil, CodeInvalidCard},
		{"capabilities not an object", withCard(func(m map[string]any) { m["capabilities"] = []any{} }), nil, CodeInvalidCard},
		{"defaultInputModes missing", withCard(func(m map[string]any) { delete(m, "defaultInputModes") }), nil, CodeInvalidCard},
		{"defaultOutputModes missing", withCard(func(m map[string]any) { delete(m, "defaultOutputModes") }), nil, CodeInvalidCard},
		{"defaultOutputModes null", withCard(func(m map[string]any) { m["defaultOutputModes"] = nil }), nil, CodeInvalidCard},
		{"defaultInputModes non-string", withCard(func(m map[string]any) { m["defaultInputModes"] = []any{1} }), nil, CodeInvalidCard},
		{"skills missing", withCard(func(m map[string]any) { delete(m, "skills") }), nil, CodeInvalidCard},
		{"skills empty", withCard(func(m map[string]any) { m["skills"] = []any{} }), nil, CodeInvalidCard},
		{"skill id empty", withCard(func(m map[string]any) { skill(m, 0)["id"] = "" }), nil, CodeInvalidCard},
		{"skill name missing", withCard(func(m map[string]any) { delete(skill(m, 0), "name") }), nil, CodeInvalidCard},
		{"skill description empty", withCard(func(m map[string]any) { skill(m, 0)["description"] = "" }), nil, CodeInvalidCard},
		{"skill tags missing", withCard(func(m map[string]any) { delete(skill(m, 0), "tags") }), nil, CodeInvalidCard},
		{"skill tags empty", withCard(func(m map[string]any) { skill(m, 0)["tags"] = []any{} }), nil, CodeInvalidCard},
		{"skill tag empty", withCard(func(m map[string]any) { skill(m, 0)["tags"] = []any{"text", ""} }), nil, CodeInvalidCard},
		{"duplicate skill id", withCard(func(m map[string]any) { m["skills"] = append(m["skills"].([]any), skill(m, 0)) }), nil, CodeInvalidCard},

		// Size limits.
		{"name over 128 bytes", withCard(func(m map[string]any) { m["name"] = strings.Repeat("n", MaxNameBytes+1) }), nil, CodeTooLarge},
		{"name over 128 bytes in UTF-8", withCard(func(m map[string]any) { m["name"] = strings.Repeat("\U00004E2D", 43) }), nil, CodeTooLarge},
		{"description over 4096 bytes", withCard(func(m map[string]any) { m["description"] = strings.Repeat("d", MaxDescriptionBytes+1) }), nil, CodeTooLarge},
		{"more than 256 skills", withCard(func(m map[string]any) { m["skills"] = manySkills(MaxSkills + 1) }), nil, CodeTooLarge},
		{"more than 16 tags", withCard(func(m map[string]any) { skill(m, 0)["tags"] = manyTags(MaxTagsPerSkill + 1) }), nil, CodeTooLarge},
		{"card over 64 KiB", withCard(func(m map[string]any) { m["documentationUrl"] = strings.Repeat("u", MaxCardBytes) }), nil, CodeTooLarge},
		{"more than 8 signatures", tooManySignatures(t, good), nil, CodeTooLarge},

		// Protected header.
		{"kid not did:anet", signAs(t, baseCard(a.AID()), a.CurrentPrivateKey(), "key-1"), nil, CodeBadHeader},
		{"kid seq with leading zero", signAs(t, baseCard(a.AID()), a.CurrentPrivateKey(), "did:anet:"+a.AID()+"#00"), nil, CodeBadHeader},
		{"alg not EdDSA", withHeader(t, baseCard(a.AID()), a.CurrentPrivateKey(), `{"alg":"ES256","kid":"`+KID(a.AID(), 0)+`"}`), nil, CodeBadHeader},

		// Parsing.
		{"not an object", []byte(`[1]`), nil, CodeInvalidCard},
		{"not JSON", []byte(`{"name":`), nil, CodeMalformedJSON},
		{"duplicate member", []byte(strings.Replace(string(good), `{`, `{"name":"Evil",`, 1)), nil, CodeMalformedJSON},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.res
			if r == nil {
				r = newResolver(a, b)
			}
			v, err := Verify(tc.card, r.resolve, t0)
			if err == nil {
				t.Fatalf("accepted: %+v", v)
			}
			wantCode(t, err, tc.want)
		})
	}
}

func corruptKEL(kel []identity.SignedEvent) []identity.SignedEvent {
	out := append([]identity.SignedEvent(nil), kel...)
	sig := append([]byte(nil), out[0].Sig...)
	sig[0] ^= 1
	out[0].Sig = sig
	return out
}

func manySkills(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = map[string]any{"id": "s" + dec(uint64(i)), "name": "S", "description": "D", "tags": []any{"t"}}
	}
	return out
}

func manyTags(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = "t" + dec(uint64(i))
	}
	return out
}

func tooManySignatures(t *testing.T, signed []byte) []byte {
	return edit(t, signed, func(m map[string]any) {
		s := m["signatures"].([]any)
		for len(s) <= MaxSignatures {
			s = append(s, s[0])
		}
		m["signatures"] = s
	})
}

// withHeader signs card under an arbitrary protected header, so that the signature is valid
// and only a header rule can reject it.
func withHeader(t *testing.T, card map[string]any, priv ed25519.PrivateKey, header string) []byte {
	t.Helper()
	cj := marshal(t, card)
	payload, err := SigningPayload(cj)
	if err != nil {
		t.Fatal(err)
	}
	protected := b64.EncodeToString([]byte(header))
	sig := b64.EncodeToString(ed25519.Sign(priv, signingInput(protected, payload)))
	return edit(t, cj, func(m map[string]any) {
		m["signatures"] = []any{map[string]any{"protected": protected, "signature": sig}}
	})
}

// The limits are inclusive: a card exactly at each limit is accepted.
func TestVerifyLimitsAreInclusive(t *testing.T) {
	c := incept(t)
	card := baseCard(c.AID())
	card["name"] = strings.Repeat("n", MaxNameBytes)
	card["description"] = strings.Repeat("d", MaxDescriptionBytes)
	card["skills"] = manySkills(MaxSkills)
	skill(card, 0)["tags"] = manyTags(MaxTagsPerSkill)
	params(card)["notBefore"] = dec(t0 + NotBeforeSkewMillis)
	signed := signCard(t, card, c)
	if _, err := Verify(signed, newResolver(c).resolve, t0); err != nil {
		t.Fatalf("card at the limits rejected: %v", err)
	}
	signed = edit(t, signed, func(m map[string]any) {
		s := m["signatures"].([]any)
		for len(s) < MaxSignatures {
			s = append(s, s[0])
		}
		m["signatures"] = s
	})
	if _, err := Verify(signed, newResolver(c).resolve, t0); err != nil {
		t.Fatalf("%d signatures rejected: %v", MaxSignatures, err)
	}

	// A card of exactly MaxCardBytes is within the limit. Pad with whitespace, which does not
	// change the payload.
	base := signCard(t, baseCard(c.AID()), c)
	exact := append(append([]byte(nil), base...), strings.Repeat(" ", MaxCardBytes-len(base))...)
	if _, err := Verify(exact, newResolver(c).resolve, t0); err != nil {
		t.Fatalf("card of %d bytes rejected: %v", len(exact), err)
	}
	if _, err := Verify(append(exact, ' '), newResolver(c).resolve, t0); !IsCode(err, CodeTooLarge) {
		t.Fatalf("card of %d bytes: err %v, want %s", len(exact)+1, err, CodeTooLarge)
	}
}

// Interfaces with other bindings may carry any tenant; only relay interfaces are bound.
func TestVerifyOtherBindingTenantIsFree(t *testing.T) {
	c := incept(t)
	card := baseCard(c.AID())
	card["supportedInterfaces"] = append(card["supportedInterfaces"].([]any), map[string]any{
		"url": "https://direct.example.org/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0", "tenant": "someone-else",
	})
	if _, err := Verify(signCard(t, card, c), newResolver(c).resolve, t0); err != nil {
		t.Fatalf("rejected: %v", err)
	}
}

// Structural failures are decided before any KEL lookup, so a hostile card cannot make the
// verifier fetch KELs. The kid of another AID is rejected without resolving it.
func TestVerifyResolvesOnlyWhenNeeded(t *testing.T) {
	a := incept(t)
	b := incept(t)
	with := func(f func(map[string]any)) map[string]any {
		m := baseCard(a.AID())
		f(m)
		return m
	}
	cases := map[string][]byte{
		"missing skills":  signCard(t, with(func(m map[string]any) { delete(m, "skills") }), a),
		"future card":     signCard(t, with(func(m map[string]any) { params(m)["notBefore"] = dec(t0 + 10*NotBeforeSkewMillis) }), a),
		"tenant mismatch": signCard(t, with(func(m map[string]any) { iface(m, 0)["tenant"] = b.AID() }), a),
		"kid of b":        signAs(t, baseCard(a.AID()), b.CurrentPrivateKey(), KID(b.AID(), 0)),
	}
	for name, card := range cases {
		r := newResolver(a, b)
		if _, err := Verify(card, r.resolve, t0); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if r.calls != 0 {
			t.Errorf("%s: resolver called %d times, want 0", name, r.calls)
		}
	}
}

// With several signatures the card is accepted if one passes; the KEL is resolved once.
func TestVerifyMultipleSignatures(t *testing.T) {
	a := incept(t)
	b := incept(t)
	oldKey := a.CurrentPrivateKey()
	if err := a.Rotate(t0 - 1000); err != nil {
		t.Fatal(err)
	}
	card := marshal(t, baseCard(a.AID()))
	s1, err := Sign(card, b.CurrentPrivateKey(), KID(b.AID(), 0), "")
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Sign(s1, oldKey, KID(a.AID(), 0), "")
	if err != nil {
		t.Fatal(err)
	}
	s3, err := SignWithController(s2, a, "")
	if err != nil {
		t.Fatal(err)
	}
	r := newResolver(a, b)
	v, err := Verify(s3, r.resolve, t0)
	if err != nil {
		t.Fatalf("rejected: %v", err)
	}
	if v.KeyStateSeq != 1 {
		t.Fatalf("KeyStateSeq = %d, want 1 (the signature under the current key)", v.KeyStateSeq)
	}
	if r.calls != 1 {
		t.Fatalf("resolver called %d times, want 1", r.calls)
	}

	// Without the current-key signature, the first signature's error is reported.
	r = newResolver(a, b)
	if _, err := Verify(s2, r.resolve, t0); !IsCode(err, CodeBindingMismatch) {
		t.Fatalf("err %v, want %s from the first signature", err, CodeBindingMismatch)
	}
	if r.calls != 1 {
		t.Fatalf("resolver called %d times, want 1", r.calls)
	}
}

func TestVerifyResolverErrorIsWrapped(t *testing.T) {
	c := incept(t)
	_, err := Verify(signCard(t, baseCard(c.AID()), c), newResolver().resolve, t0)
	wantCode(t, err, CodeKELUnavailable)
	if !errors.Is(err, errNoKEL) {
		t.Fatalf("err %v does not wrap the resolver's error", err)
	}
	if _, err := Verify(signCard(t, baseCard(c.AID()), c), nil, t0); !IsCode(err, CodeKELUnavailable) {
		t.Fatalf("nil resolver: %v", err)
	}
}

// Key-state rule across ixn/drt events (see CurrentKey): the states after the last rotation
// share the current key and are accepted; every state before it is rejected, including one
// separated from the rotation by a drt; a deactivated AID has no accepted state.
func TestVerifyKeyStateRule(t *testing.T) {
	host := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)

	// icp(0) -> drt(1): both states hold the inception key.
	c := incept(t)
	k0 := c.CurrentPrivateKey()
	if err := c.Delegate(host, t0-3000); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint64{0, 1} {
		if _, err := Verify(signAs(t, baseCard(c.AID()), k0, KID(c.AID(), seq)), newResolver(c).resolve, t0); err != nil {
			t.Errorf("icp->drt, kid seq %d: %v", seq, err)
		}
	}

	// -> rot(2): states 0 and 1 are retired; 2 is current.
	if err := c.Rotate(t0 - 2000); err != nil {
		t.Fatal(err)
	}
	k2 := c.CurrentPrivateKey()
	for _, seq := range []uint64{0, 1} {
		_, err := Verify(signAs(t, baseCard(c.AID()), k0, KID(c.AID(), seq)), newResolver(c).resolve, t0)
		if !IsCode(err, CodeKeyNotCurrent) {
			t.Errorf("icp->drt->rot, kid seq %d: err %v, want %s", seq, err, CodeKeyNotCurrent)
		}
	}
	if _, err := Verify(signAs(t, baseCard(c.AID()), k2, KID(c.AID(), 2)), newResolver(c).resolve, t0); err != nil {
		t.Errorf("icp->drt->rot, kid seq 2: %v", err)
	}

	// -> dip(3): nothing is current.
	if err := c.Deactivate(t0 - 1000); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint64{2, 3} {
		_, err := Verify(signAs(t, baseCard(c.AID()), k2, KID(c.AID(), seq)), newResolver(c).resolve, t0)
		if !IsCode(err, CodeKeyNotCurrent) {
			t.Errorf("deactivated, kid seq %d: err %v, want %s", seq, err, CodeKeyNotCurrent)
		}
	}
}

func TestCurrentKey(t *testing.T) {
	c := incept(t)
	if err := c.Rotate(t0); err != nil {
		t.Fatal(err)
	}
	pub, err := CurrentKey(KID(c.AID(), 1), c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(c.CurrentPrivateKey().Public()) {
		t.Fatal("CurrentKey returned a key other than the controller's current key")
	}
	if _, err := CurrentKey(KID(c.AID(), 0), c.KEL()); !IsCode(err, CodeKeyNotCurrent) {
		t.Fatalf("rotated state: %v", err)
	}
	other := incept(t)
	if _, err := CurrentKey(KID(other.AID(), 0), c.KEL()); !IsCode(err, CodeUnknownAID) {
		t.Fatalf("kid of another AID: %v", err)
	}
	if _, err := CurrentKey("key-1", c.KEL()); !IsCode(err, CodeBadHeader) {
		t.Fatalf("non-anet kid: %v", err)
	}
}

// A JSON number above 2^53 does not survive canonicalization: 9007199254740993 and
// 9007199254740992 produce the same payload, so a signature over one also covers the other.
// That is why params.seq is a decimal string, and Verify rejects it as a number.
func TestLargeJSONNumberCollapsesInCanonicalForm(t *testing.T) {
	c := incept(t)
	card := baseCard(c.AID())
	card["x-count"] = json.Number("9007199254740993")
	signed := signCard(t, card, c)
	// Sign returns the canonical card, which already shows the rounded value.
	if !strings.Contains(string(signed), `"x-count":9007199254740992`) {
		t.Fatalf("signed card does not show the binary64 value: %s", signed)
	}
	changed := []byte(strings.Replace(string(signed), "9007199254740992", "9007199254740993", 1))
	if string(changed) == string(signed) {
		t.Fatal("replacement did not change the card bytes")
	}
	p1, err := SigningPayload(signed)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := SigningPayload(changed)
	if err != nil {
		t.Fatal(err)
	}
	if string(p1) != string(p2) {
		t.Fatalf("payloads differ; expected binary64 rounding to merge them:\n%s\n%s", p1, p2)
	}
	if _, err := Verify(changed, newResolver(c).resolve, t0); err != nil {
		t.Fatalf("the changed card should verify under the original signature: %v", err)
	}

	// As a string the value is exact.
	card = baseCard(c.AID())
	params(card)["seq"] = "9007199254740993"
	v, err := Verify(signCard(t, card, c), newResolver(c).resolve, t0)
	if err != nil {
		t.Fatal(err)
	}
	if v.Seq != 9007199254740993 {
		t.Fatalf("Seq = %d, want 9007199254740993", v.Seq)
	}
	// As a number it is rejected.
	params(card)["seq"] = json.Number("9007199254740993")
	_, err = Verify(signCard(t, card, c), newResolver(c).resolve, t0)
	wantCode(t, err, CodeInvalidCard)
}

// The stored card bytes need not be canonical: whitespace and member order do not affect
// verification, because the payload is recomputed from the parsed card.
func TestVerifyIgnoresLayout(t *testing.T) {
	c := incept(t)
	signed := signCard(t, baseCard(c.AID()), c)
	var m map[string]any
	if err := json.Unmarshal(signed, &m); err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(m, "", "   ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pretty, newResolver(c).resolve, t0); err != nil {
		t.Fatalf("re-indented card rejected: %v", err)
	}
}
