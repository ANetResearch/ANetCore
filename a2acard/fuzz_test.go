package a2acard

// Fuzz targets for RFC 8785 canonicalization, the publish form, default stripping, the JWS
// header and card verification (ANet docs/notes/0033).
//
// FuzzVerify feeds whole signed cards: a mutated card keeps a valid signature only when the
// mutation stays outside what the signature covers, so an accepted card must carry a payload the
// fuzz fixture signed. FuzzVerifySigned signs each fuzzed card first, so Verify's structural and
// binding checks run on arbitrary members under a good signature, and compares what Verify
// admitted with what encoding/json (the decoder the daemon, the hub and a2a-go put the stored
// bytes through) reads from the same bytes.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// fuzzSigner is one key state the fixture signs under.
type fuzzSigner struct {
	priv ed25519.PrivateKey
	kid  string
}

type cardFixture struct {
	aid     string
	kels    [][]identity.SignedEvent // suite KEL, then the same identity after one rotation
	signers []fuzzSigner             // seq 0 under kels[0], seq 1 under kels[1]
	signed  map[string]bool          // signing inputs the fixture signed
}

func newCardFixture(tb testing.TB) *cardFixture {
	tb.Helper()
	seed := func(label string) []byte { s := sha256.Sum256([]byte(label)); return s[:] }
	k0 := ed25519.NewKeyFromSeed(seed("anet-suite-identity-v1/cur"))
	k1 := ed25519.NewKeyFromSeed(seed("anet-suite-identity-v1/nxt"))
	k2 := ed25519.NewKeyFromSeed(seed("anet-fuzz/a2acard/k2"))
	suite := identity.SuiteController().KEL()
	aid := suite[0].EventID
	d := sha256.Sum256(k2.Public().(ed25519.PublicKey))
	rot := identity.KeyEvent{AID: aid, Seq: 1, Prev: aid, Type: identity.Rotation,
		Keys: [][]byte{k1.Public().(ed25519.PublicKey)}, NextDigest: d[:], Threshold: 1, Timestamp: t0 - 1000}
	pre, err := coredet.Marshal(rot)
	if err != nil {
		tb.Fatal(err)
	}
	rotated := append(append([]identity.SignedEvent(nil), suite...),
		identity.SignedEvent{Event: rot, Sig: ed25519.Sign(k0, pre), EventID: anetcid.MustSum(pre)})
	return &cardFixture{
		aid:     aid,
		kels:    [][]identity.SignedEvent{suite, rotated},
		signers: []fuzzSigner{{k0, KID(aid, 0)}, {k1, KID(aid, 1)}},
		signed:  map[string]bool{},
	}
}

// sign signs cardJSON over its proto-stripped payload without the publish-form check and records
// the signing inputs the new signature covers.
func (fx *cardFixture) sign(cardJSON []byte, s fuzzSigner) ([]byte, error) {
	out, err := sign(cardJSON, s.priv, s.kid, jku(fx.aid), false)
	if err != nil {
		return nil, err
	}
	fx.record(out)
	return out, nil
}

// record remembers the signing input of every signature in a card the fixture produced.
func (fx *cardFixture) record(cardJSON []byte) {
	card, err := parseCard(cardJSON)
	if err != nil {
		return
	}
	stripped, _, err := payloads(card)
	if err != nil {
		return
	}
	sigs, ok := card.member("signatures")
	if !ok {
		return
	}
	for _, e := range sigs.arr {
		if p, ok := e.member("protected"); ok {
			fx.signed[string(signingInput(p.str, stripped))] = true
		}
	}
}

func (fx *cardFixture) resolver(sel byte) Resolver {
	kel := fx.kels[int(sel)%len(fx.kels)]
	return func(aid string) ([]identity.SignedEvent, error) {
		if aid != fx.aid {
			return nil, errNoKEL
		}
		return kel, nil
	}
}

func (fx *cardFixture) seedCards(tb testing.TB) [][]byte {
	tb.Helper()
	var out [][]byte
	add := func(card map[string]any) {
		b, err := json.Marshal(card)
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, b)
	}
	c := baseCard(fx.aid)
	add(c)
	c2 := baseCard(fx.aid)
	c2["provider"] = map[string]any{"organization": "org", "url": "https://example.org"}
	skill(c2, 0)["examples"] = []any{"x"}
	skill(c2, 0)["inputModes"] = []any{"text/plain"}
	c2["securitySchemes"] = map[string]any{"k": map[string]any{"apiKeySecurityScheme": map[string]any{"location": "header", "name": "X"}}}
	c2["securityRequirements"] = []any{map[string]any{"schemes": map[string]any{"k": map[string]any{"list": []any{"s"}}}}}
	extensions(c2)[0].(map[string]any)["required"] = true
	add(c2)
	c3 := baseCard(fx.aid)
	c3["supportedInterfaces"] = append(c3["supportedInterfaces"].([]any), map[string]any{
		"url": "https://x", "protocolBinding": "JSONRPC", "protocolVersion": "1.0", "tenant": ""})
	c3["capabilities"].(map[string]any)["extensions"] = append(extensions(c3), map[string]any{"uri": "urn:x", "required": false})
	add(c3)
	if raw, err := os.ReadFile("testdata/golden-card.json"); err == nil {
		out = append(out, bytes.TrimSpace(raw))
	}
	return out
}

// jsonView is what a struct decoder reads from a card: the members Verify's checks cover.
type jsonView struct {
	Name                string `json:"name"`
	SupportedInterfaces []struct {
		ProtocolBinding string `json:"protocolBinding"`
		Tenant          string `json:"tenant"`
	} `json:"supportedInterfaces"`
	Capabilities struct {
		Extensions []struct {
			URI    string         `json:"uri"`
			Params map[string]any `json:"params"`
		} `json:"extensions"`
	} `json:"capabilities"`
	Skills []struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	} `json:"skills"`
}

// checkAdmitted asserts that a card Verify admitted says, to encoding/json, what Verify read.
func (fx *cardFixture) checkAdmitted(t *testing.T, cardJSON []byte, v *Verified) {
	t.Helper()
	if v.AID != fx.aid {
		t.Fatalf("admitted a card for %s", v.AID)
	}
	sp, err := SigningPayload(cardJSON)
	if err != nil {
		t.Fatalf("admitted card has no signing payload: %v", err)
	}
	if v.PayloadHash != sha256.Sum256(sp) {
		t.Fatal("PayloadHash is not the hash of the proto-stripped payload")
	}
	if d, err := CheckHighWater(&Mark{Seq: v.Seq, PayloadHash: v.PayloadHash}, v.Mark()); err != nil || d != Same {
		t.Fatalf("a card is not the Same as its own mark: %v %v", d, err)
	}
	var view jsonView
	if err := json.Unmarshal(cardJSON, &view); err != nil {
		t.Fatalf("encoding/json cannot read an admitted card: %v", err)
	}
	if view.Name != v.Name {
		t.Fatalf("Verify read name %q, encoding/json reads %q", v.Name, view.Name)
	}
	for i, it := range view.SupportedInterfaces {
		if it.ProtocolBinding == BindingRelayURI && it.Tenant != v.AID {
			t.Fatalf("encoding/json reads interface %d as a relay interface for tenant %q, card AID %s", i, it.Tenant, v.AID)
		}
	}
	anet := 0
	for _, e := range view.Capabilities.Extensions {
		if e.URI == ExtCardURI {
			anet++
			if e.Params["aid"] != v.AID {
				t.Fatalf("encoding/json reads anet-card aid %v, Verify %s", e.Params["aid"], v.AID)
			}
		}
	}
	if anet != 1 {
		t.Fatalf("encoding/json reads %d anet-card extensions", anet)
	}
	if len(view.Skills) != len(v.Skills) {
		t.Fatalf("encoding/json reads %d skills, Verify %d", len(view.Skills), len(v.Skills))
	}
	for i, s := range view.Skills {
		w := v.Skills[i]
		if s.ID != w.ID || s.Name != w.Name || s.Description != w.Description || !reflect.DeepEqual(s.Tags, w.Tags) {
			t.Fatalf("skill %d: encoding/json reads %+v, Verify %+v", i, s, w)
		}
	}
}

func FuzzCanonicalize(f *testing.F) {
	for _, s := range []string{`{"b":1,"a":[1e21,1e-7,-0,0.1]}`, `"é😀 "`, `[null,true,false,"\/"]`,
		`{"𐀀":1,"￮":2}`, `1E400`, `{"a":1,"a":2}`, `"\ud800"`, `{"x":"﷐"}`, `9007199254740993`} {
		f.Add([]byte(s))
	}
	fx := newCardFixture(f)
	for _, c := range fx.seedCards(f) {
		f.Add(c)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := Canonicalize(b)
		if err != nil {
			if !IsCode(err, CodeMalformedJSON) {
				t.Fatalf("Canonicalize error %v has code other than MALFORMED_JSON", err)
			}
			return
		}
		again, err := Canonicalize(out)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("canonical form is not a fixed point: %v\n%s\n%s", err, out, again)
		}
		if !json.Valid(out) {
			t.Fatalf("canonical form is not JSON: %s", out)
		}
		var a, c any
		if err := json.Unmarshal(b, &a); err != nil {
			t.Fatalf("Canonicalize accepted what encoding/json refuses: %v", err)
		}
		if err := json.Unmarshal(out, &c); err != nil || !reflect.DeepEqual(a, c) {
			t.Fatalf("canonical form reads differently to encoding/json: %v\n%#v\n%#v", err, a, c)
		}
	})
}

func FuzzPublishForm(f *testing.F) {
	fx := newCardFixture(f)
	for _, c := range fx.seedCards(f) {
		f.Add(c)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		card, err := parseCard(b)
		if err != nil {
			return
		}
		// stripDefaults is idempotent.
		s1 := stripDefaults(card, schemaAgentCard)
		p1, err1 := canonicalPayload(s1)
		p2, err2 := canonicalPayload(stripDefaults(s1, schemaAgentCard))
		if (err1 == nil) != (err2 == nil) || !bytes.Equal(p1, p2) {
			t.Fatalf("stripDefaults is not idempotent:\n%s\n%s", p1, p2)
		}
		if err := CheckPublishForm(b); err != nil {
			return
		}
		// On a card in publish form the two payload forms are the same bytes.
		stripped, raw, err := payloads(card)
		if err != nil || !bytes.Equal(stripped, raw) {
			t.Fatalf("publish form, but the payloads differ (%v):\n%s\n%s", err, stripped, raw)
		}
		signedCard, err := Sign(b, fx.signers[0].priv, fx.signers[0].kid, "")
		if err != nil {
			t.Fatalf("Sign refused a card in publish form: %v", err)
		}
		if err := CheckPublishForm(signedCard); err != nil {
			t.Fatalf("a signed card left publish form: %v", err)
		}
		sc, err := parseCard(signedCard)
		if err != nil {
			t.Fatal(err)
		}
		sigs, _ := sc.member("signatures")
		last := sigs.arr[len(sigs.arr)-1]
		sig := Signature{Protected: last.obj["protected"].str, Signature: last.obj["signature"].str}
		pub := fx.signers[0].priv.Public().(ed25519.PublicKey)
		if _, form, err := VerifySignatureForm(signedCard, sig, pub); err != nil || form != FormProtoStripped {
			t.Fatalf("own signature does not verify over the proto-stripped payload: %v %v", form, err)
		}
	})
}

func FuzzVerify(f *testing.F) {
	fx := newCardFixture(f)
	for _, c := range fx.seedCards(f) {
		fx.record(c) // the golden card arrives signed by the suite key already
		for i, s := range fx.signers {
			if out, err := fx.sign(c, s); err == nil {
				f.Add(out, byte(i), t0)
			}
		}
	}
	// Every fuzz process signs the seeds itself, so it knows what was signed.
	f.Fuzz(func(t *testing.T, b []byte, sel byte, now uint64) {
		v, err := Verify(b, fx.resolver(sel), now)
		if err != nil {
			var e *Error
			if !asError(err, &e) {
				t.Fatalf("Verify returned a non-*Error: %v", err)
			}
			return
		}
		// Admitted: some signature covers a payload of this card that the fixture signed.
		card, _ := parseCard(b)
		stripped, raw, err := payloads(card)
		if err != nil {
			t.Fatal(err)
		}
		sigs, _ := signatureEntries(card)
		known := false
		for _, s := range sigs {
			if fx.signed[string(signingInput(s.Protected, stripped))] || fx.signed[string(signingInput(s.Protected, raw))] {
				known = true
			}
		}
		if !known {
			t.Fatalf("admitted a card whose payload the signer never signed:\n%s", b)
		}
		fx.checkAdmitted(t, b, v)
	})
}

func FuzzVerifySigned(f *testing.F) {
	fx := newCardFixture(f)
	for _, c := range fx.seedCards(f) {
		f.Add(c, byte(0), t0)
		f.Add(c, byte(1), t0)
	}
	f.Fuzz(func(t *testing.T, b []byte, sel byte, now uint64) {
		i := int(sel) % len(fx.signers)
		signedCard, err := sign(b, fx.signers[i].priv, fx.signers[i].kid, jku(fx.aid), false)
		if err != nil {
			return
		}
		v, err := Verify(signedCard, fx.resolver(sel), now)
		if err != nil {
			return
		}
		if v.KeyStateSeq != uint64(i) || v.CanonicalForm != FormProtoStripped {
			t.Fatalf("admitted under seq %d form %s, signed under seq %d", v.KeyStateSeq, v.CanonicalForm, i)
		}
		fx.checkAdmitted(t, signedCard, v)
	})
}

func FuzzJWSHeader(f *testing.F) {
	hdr, _ := json.Marshal(map[string]string{"alg": AlgEdDSA, "kid": KID("bafyreiabc", 3), "typ": TypJOSE})
	f.Add(KID("bafyreiabc", 3), b64.EncodeToString(hdr), b64.EncodeToString(make([]byte, 64)))
	f.Add("did:anet:a#01", "eyJhbGciOiJub25lIn0", "AA\nAA")
	f.Add("did:anet:A#1", b64.EncodeToString([]byte(`{"alg":"EdDSA","crit":["b64"]}`)), "")
	f.Fuzz(func(t *testing.T, kid, protected, sig string) {
		if aid, seq, err := ParseKID(kid); err == nil {
			if KID(aid, seq) != kid {
				t.Fatalf("kid %q parses to %q#%d, whose kid is %q", kid, aid, seq, KID(aid, seq))
			}
			if !validAID(aid) || strings.ContainsAny(aid, "#/") {
				t.Fatalf("kid %q gave AID %q", kid, aid)
			}
		}
		for _, s := range []string{protected, sig} {
			if raw, err := decodeB64(s); err == nil && b64.EncodeToString(raw) != s {
				t.Fatalf("%q decodes to bytes whose encoding is %q", s, b64.EncodeToString(raw))
			}
		}
		if h, err := parseHeader(protected); err == nil && h.Alg != AlgEdDSA {
			t.Fatalf("header with alg %q accepted", h.Alg)
		}
	})
}

func asError(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}
