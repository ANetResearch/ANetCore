package a2acard

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// testdata/a2a-python-golden.json is copied unchanged from a2a-go
// (github.com/a2aproject/a2a-go/v2, a2acrypto/testdata/golden.json, commit ebf17c56,
// Apache License 2.0). a2a-go states that it was produced by the a2a-python reference SDK
// (a2acrypto/testdata/gen_golden.py): an AgentCard signed with the Ed25519 key whose seed is
// 00 01 .. 1f, kid "golden-ed25519-1", no jku.
type crossSDKVector struct {
	Kid          string          `json:"kid"`
	SeedHex      string          `json:"ed25519_seed_hex"`
	CardJSON     json.RawMessage `json:"card_json_unsigned"`
	ProtectedB64 string          `json:"protected_b64"`
	SignatureB64 string          `json:"signature_b64"`
}

func loadCrossSDKVector(t *testing.T) (crossSDKVector, ed25519.PrivateKey) {
	t.Helper()
	b, err := os.ReadFile("testdata/a2a-python-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var v crossSDKVector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(v.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	return v, ed25519.NewKeyFromSeed(seed)
}

// The reference SDK's signature verifies under this package's JWS verification.
func TestCrossSDKVectorVerifies(t *testing.T) {
	v, key := loadCrossSDKVector(t)
	sig := Signature{Protected: v.ProtectedB64, Signature: v.SignatureB64}
	hdr, err := VerifySignature(v.CardJSON, sig, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("reference signature rejected: %v", err)
	}
	if hdr.Alg != AlgEdDSA || hdr.Kid != v.Kid || hdr.Typ != TypJOSE || hdr.Jku != "" {
		t.Fatalf("header = %+v", hdr)
	}

	// The same signature must fail on a changed card and under another key.
	tampered := strings.Replace(string(v.CardJSON), "Golden Agent", "Golden AgenT", 1)
	if _, err := VerifySignature([]byte(tampered), sig, key.Public().(ed25519.PublicKey)); !IsCode(err, CodeInvalidSignature) {
		t.Fatalf("tampered card: err %v, want %s", err, CodeInvalidSignature)
	}
	other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	if _, err := VerifySignature(v.CardJSON, sig, other.Public().(ed25519.PublicKey)); !IsCode(err, CodeInvalidSignature) {
		t.Fatalf("other key: err %v, want %s", err, CodeInvalidSignature)
	}
}

// Sign reproduces the reference SDK's protected header and signature byte for byte. Ed25519 is
// deterministic, so equal signatures mean equal signing inputs: the same canonical payload and
// the same header serialization.
func TestSignReproducesCrossSDKVector(t *testing.T) {
	v, key := loadCrossSDKVector(t)
	signed, err := Sign(v.CardJSON, key, v.Kid, "")
	if err != nil {
		t.Fatal(err)
	}
	sigs := signaturesOf(t, signed)
	if len(sigs) != 1 {
		t.Fatalf("%d signatures, want 1", len(sigs))
	}
	if sigs[0].Protected != v.ProtectedB64 {
		t.Errorf("protected = %s, want %s", sigs[0].Protected, v.ProtectedB64)
	}
	if sigs[0].Signature != v.SignatureB64 {
		t.Errorf("signature = %s, want %s", sigs[0].Signature, v.SignatureB64)
	}
}

func signaturesOf(t *testing.T, cardJSON []byte) []Signature {
	t.Helper()
	var c struct {
		Signatures []Signature `json:"signatures"`
	}
	if err := json.Unmarshal(cardJSON, &c); err != nil {
		t.Fatal(err)
	}
	return c.Signatures
}

// The protected header has the form A2A-DESIGN §10.3 specifies, with keys in sorted order.
func TestProtectedHeaderBytes(t *testing.T) {
	c := incept(t)
	signed := signCard(t, baseCard(c.AID()), c)
	raw, err := b64.DecodeString(signaturesOf(t, signed)[0].Protected)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"alg":"EdDSA","jku":"https://hub.example.org/agents/` + c.AID() + `/jwks.json","kid":"did:anet:` +
		c.AID() + `#0","typ":"JOSE"}`
	if string(raw) != want {
		t.Fatalf("protected header\n got %s\nwant %s", raw, want)
	}
}

// Signing a signed card appends a second signature. The payload excludes "signatures", so the
// first signature still verifies after the second is added.
func TestSignAppendsAndExcludesSignatures(t *testing.T) {
	c := incept(t)
	card := marshal(t, baseCard(c.AID()))
	once, err := Sign(card, c.CurrentPrivateKey(), KID(c.AID(), 0), "")
	if err != nil {
		t.Fatal(err)
	}
	other := incept(t)
	twice, err := Sign(once, other.CurrentPrivateKey(), "second", "")
	if err != nil {
		t.Fatal(err)
	}
	sigs := signaturesOf(t, twice)
	if len(sigs) != 2 || sigs[0] != signaturesOf(t, once)[0] {
		t.Fatalf("signatures = %+v, want the first kept and a second appended", sigs)
	}
	if _, err := VerifySignature(twice, sigs[0], c.CurrentPrivateKey().Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("first signature after append: %v", err)
	}
	if _, err := VerifySignature(twice, sigs[1], other.CurrentPrivateKey().Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("second signature: %v", err)
	}
	p1, _ := SigningPayload(card)
	p2, _ := SigningPayload(twice)
	if string(p1) != string(p2) {
		t.Fatalf("payload changed by signing:\n%s\n%s", p1, p2)
	}
	if strings.Contains(string(p2), "signatures") {
		t.Fatalf("payload contains signatures: %s", p2)
	}
}

// Only the top-level "signatures" member is excluded; a nested member of that name is signed.
func TestNestedSignaturesMemberIsSigned(t *testing.T) {
	a, err := SigningPayload([]byte(`{"x":{"signatures":[1]},"signatures":[2]}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"x":{"signatures":[1]}}`; string(a) != want {
		t.Fatalf("got %s, want %s", a, want)
	}
}

func TestSignRejects(t *testing.T) {
	c := incept(t)
	card := marshal(t, baseCard(c.AID()))
	if _, err := Sign(card, c.CurrentPrivateKey()[:10], "k", ""); !IsCode(err, CodeBadHeader) {
		t.Errorf("short key: %v", err)
	}
	if _, err := Sign(card, c.CurrentPrivateKey(), "", ""); !IsCode(err, CodeBadHeader) {
		t.Errorf("empty kid: %v", err)
	}
	if _, err := Sign([]byte(`[1]`), c.CurrentPrivateKey(), "k", ""); !IsCode(err, CodeInvalidCard) {
		t.Errorf("array card: %v", err)
	}
	if _, err := Sign([]byte(`{"signatures":{}}`), c.CurrentPrivateKey(), "k", ""); !IsCode(err, CodeInvalidCard) {
		t.Errorf("signatures object: %v", err)
	}
	if _, err := Sign([]byte(`{"a":1,"a":2}`), c.CurrentPrivateKey(), "k", ""); !IsCode(err, CodeMalformedJSON) {
		t.Errorf("duplicate member: %v", err)
	}
}

// The signing input uses the protected string exactly as it appears in the card. A header
// that decodes to the same JSON but is encoded differently is a different signing input.
func TestSigningInputUsesProtectedAsGiven(t *testing.T) {
	v, key := loadCrossSDKVector(t)
	raw, err := b64.DecodeString(v.ProtectedB64)
	if err != nil {
		t.Fatal(err)
	}
	spaced := strings.Replace(string(raw), ",", ", ", 1)
	sig := Signature{Protected: b64.EncodeToString([]byte(spaced)), Signature: v.SignatureB64}
	if _, err := VerifySignature(v.CardJSON, sig, key.Public().(ed25519.PublicKey)); !IsCode(err, CodeInvalidSignature) {
		t.Fatalf("re-encoded header: err %v, want %s", err, CodeInvalidSignature)
	}
}

func TestHeaderRejections(t *testing.T) {
	v, key := loadCrossSDKVector(t)
	pub := key.Public().(ed25519.PublicKey)
	cases := map[string]string{
		"alg none":        `{"alg":"none","kid":"k"}`,
		"alg ES256":       `{"alg":"ES256","kid":"k"}`,
		"alg missing":     `{"kid":"k"}`,
		"alg not string":  `{"alg":1,"kid":"k"}`,
		"crit":            `{"alg":"EdDSA","kid":"k","crit":["b64"]}`,
		"duplicate alg":   `{"alg":"EdDSA","alg":"none","kid":"k"}`,
		"not an object":   `["EdDSA"]`,
		"not JSON":        `alg=EdDSA`,
		"kid not string":  `{"alg":"EdDSA","kid":7}`,
		"jku not string":  `{"alg":"EdDSA","kid":"k","jku":false}`,
		"typ not string":  `{"alg":"EdDSA","kid":"k","typ":null}`,
		"trailing object": `{"alg":"EdDSA"}{}`,
	}
	for name, hdr := range cases {
		// Sign the exact header bytes so the signature itself is valid; only the header rule
		// can reject.
		protected := b64.EncodeToString([]byte(hdr))
		payload, err := SigningPayload(v.CardJSON)
		if err != nil {
			t.Fatal(err)
		}
		sig := Signature{Protected: protected, Signature: b64.EncodeToString(ed25519.Sign(key, signingInput(protected, payload)))}
		if _, err := VerifySignature(v.CardJSON, sig, pub); !IsCode(err, CodeBadHeader) {
			t.Errorf("%s: err %v, want %s", name, err, CodeBadHeader)
		}
	}
	if _, err := VerifySignature(v.CardJSON, Signature{Protected: "e30=", Signature: v.SignatureB64}, pub); !IsCode(err, CodeBadHeader) {
		t.Errorf("padded base64 header: %v", err)
	}
}

func TestSignatureEncodingRejections(t *testing.T) {
	v, key := loadCrossSDKVector(t)
	pub := key.Public().(ed25519.PublicKey)
	cases := map[string]string{
		"padding":    v.SignatureB64 + "==",
		"std base64": strings.NewReplacer("-", "+", "_", "/").Replace(v.SignatureB64),
		"truncated":  v.SignatureB64[:len(v.SignatureB64)-4],
		"empty":      "",
	}
	for name, s := range cases {
		if name == "std base64" && s == v.SignatureB64 {
			continue // the vector happens to contain neither character
		}
		sig := Signature{Protected: v.ProtectedB64, Signature: s}
		if _, err := VerifySignature(v.CardJSON, sig, pub); !IsCode(err, CodeInvalidSignature) {
			t.Errorf("%s: err %v, want %s", name, err, CodeInvalidSignature)
		}
	}
	if _, err := VerifySignature(v.CardJSON, Signature{Protected: v.ProtectedB64, Signature: v.SignatureB64}, pub[:31]); !IsCode(err, CodeInvalidSignature) {
		t.Errorf("short public key: %v", err)
	}
}

func TestParseKID(t *testing.T) {
	const aid = "bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay"
	gotAID, seq, err := ParseKID("did:anet:" + aid + "#17")
	if err != nil || gotAID != aid || seq != 17 {
		t.Fatalf("ParseKID = %q, %d, %v", gotAID, seq, err)
	}
	if KID(aid, 17) != "did:anet:"+aid+"#17" {
		t.Fatalf("KID = %s", KID(aid, 17))
	}
	if a, s, err := ParseKID(KID(aid, 0)); err != nil || a != aid || s != 0 {
		t.Fatalf("round trip seq 0: %q %d %v", a, s, err)
	}
	bad := []string{
		"",
		aid + "#0",
		"did:key:" + aid + "#0",
		"did:anet:" + aid,
		"did:anet:#0",
		"did:anet:" + strings.ToUpper(aid) + "#0",
		"did:anet:ab/c#0",
		"did:anet:ab%2Fc#0",
		"did:anet:" + strings.Repeat("a", 129) + "#0",
		"did:anet:" + aid + "#",
		"did:anet:" + aid + "#01",
		"did:anet:" + aid + "#+1",
		"did:anet:" + aid + "#-1",
		"did:anet:" + aid + "#1#2",
		"did:anet:" + aid + "#18446744073709551616",
		"did:anet:" + aid + "# 1",
	}
	for _, kid := range bad {
		if _, _, err := ParseKID(kid); !IsCode(err, CodeBadHeader) {
			t.Errorf("ParseKID(%q): err %v, want %s", kid, err, CodeBadHeader)
		}
	}
	if _, s, err := ParseKID("did:anet:" + aid + "#18446744073709551615"); err != nil || s != 1<<64-1 {
		t.Errorf("max uint64 seq: %d %v", s, err)
	}
}

// Base64url decoding is strict: an encoding whose unused trailing bits are not zero is
// rejected, so a signature has one accepted spelling. A lenient decoder would map this
// string to the same 64 bytes and accept it.
func TestSignatureTrailingBitsRejected(t *testing.T) {
	v, key := loadCrossSDKVector(t)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, v.SignatureB64[len(v.SignatureB64)-1])
	if last&0xF != 0 {
		t.Fatalf("vector's last character %q already has trailing bits set", v.SignatureB64[len(v.SignatureB64)-1])
	}
	loose := v.SignatureB64[:len(v.SignatureB64)-1] + string(alphabet[last|1])
	sig := Signature{Protected: v.ProtectedB64, Signature: loose}
	if _, err := VerifySignature(v.CardJSON, sig, key.Public().(ed25519.PublicKey)); !IsCode(err, CodeInvalidSignature) {
		t.Fatalf("non-canonical base64: err %v, want %s", err, CodeInvalidSignature)
	}
}
