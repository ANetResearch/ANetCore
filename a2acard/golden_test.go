package a2acard

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"os"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// goldenCard is the pinned anet network card, signed by the frozen conformance identity
// (identity.SuiteController). It carries non-ASCII text so the vector covers UTF-8 in the
// payload, and a string seq above 2^53 so it covers the exact decimal carriage.
func goldenCard(aid string) map[string]any {
	card := baseCard(aid)
	card["name"] = "Suite Agent"
	card["description"] = "Conformance vector for anet A2A card signing. \U00004E2D\U00006587\U00008BF4\U0000660E."
	params(card)["seq"] = "9007199254740993"
	card["skills"] = []any{
		map[string]any{
			"id": "echo", "name": "Echo", "description": "Returns the input text.",
			"tags": []any{"text", "echo"}, "examples": []any{"echo hello"},
		},
		map[string]any{
			"id": "translate", "name": "\U00007FFB\U00008BD1", "description": "Translates between Chinese and English.",
			"tags": []any{"text", "translation", "\U00004E2D\U00006587"},
		},
	}
	return card
}

// goldenPayloadHash pins SHA-256 of the golden card's canonical payload. It was also computed
// outside this package, with Python's json.dumps(sort_keys=True, separators=(",", ":"),
// ensure_ascii=False), which equals RFC 8785 for this card (ASCII member names, no numbers, no
// control characters); the signature was checked with the Python cryptography package.
const goldenPayloadHash = "3802f58cc6e81352777f108b183acb6c96233f851d1b5668aa6fc49c94b5fe98"

func checkGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -run Golden -update to create it)", err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s moved:\n got %s\nwant %s", path, got, want)
	}
}

// Signing the golden card with the suite identity reproduces the pinned bytes. Ed25519 and
// RFC 8785 are deterministic, so any change here is a change in canonicalization, header
// serialization or signing input, and every card already published would stop verifying.
func TestGoldenCardBytes(t *testing.T) {
	c := identity.SuiteController()
	signed := signCard(t, goldenCard(c.AID()), c)
	checkGolden(t, "testdata/golden-card.json", signed)
}

// The pinned card verifies, and its signature checks against the suite key derived from the
// seed text in identity/suite.go, independently of SuiteController.
func TestGoldenCardVerifies(t *testing.T) {
	b, err := os.ReadFile("testdata/golden-card.json")
	if err != nil {
		t.Fatal(err)
	}
	c := identity.SuiteController()
	v, err := Verify(b, newResolver(c).resolve, t0)
	if err != nil {
		t.Fatal(err)
	}
	if v.AID != c.AID() || v.KeyStateSeq != 0 || v.Seq != 9007199254740993 || v.IssuedAt != t0 || v.NotBefore != t0-60_000 {
		t.Fatalf("Verified = %+v", v)
	}
	if len(v.Skills) != 2 || v.Skills[1].Name != "\U00007FFB\U00008BD1" || v.Skills[1].Tags[2] != "\U00004E2D\U00006587" {
		t.Fatalf("skills = %+v", v.Skills)
	}
	if got := hex.EncodeToString(v.PayloadHash[:]); got != goldenPayloadHash {
		t.Fatalf("payload hash = %s, want %s", got, goldenPayloadHash)
	}

	seed := sha256.Sum256([]byte("anet-suite-identity-v1/cur"))
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	sigs := signaturesOf(t, b)
	if len(sigs) != 1 {
		t.Fatalf("%d signatures", len(sigs))
	}
	hdr, err := VerifySignature(b, sigs[0], pub)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Kid != KID(c.AID(), 0) || hdr.Jku != jku(c.AID()) || hdr.Typ != TypJOSE {
		t.Fatalf("header = %+v", hdr)
	}
}

func TestGoldenJWKS(t *testing.T) {
	b, err := JWKS(identity.SuiteController().KEL())
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "testdata/golden-jwks.json", b)
}
