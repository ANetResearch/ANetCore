package seal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
)

// VEC-SEALED-1: one envelope from the frozen conformance identity to a
// recipient whose key is derived from a published ikm (§17).
//
// Sealing is randomized (the HPKE sender key comes from the system source),
// so the vector is on the opening side: the envelope bytes were produced
// once and are pinned in testdata; this test opens them with the derived
// key and checks every step. A second implementation reproduces the
// recipient key and the sender identity from the seeds below and must open
// the same bytes to the same fields, the same HPKE info and the same
// signature preimage.
//
// The HPKE info and the preimage are pinned separately from the envelope.
// A failure then says which layer moved: info is a function of the header
// constants only; the preimage also depends on the decrypted fields.
//
// Seeds:
//
//	sender identity   identity.SuiteController()
//	sender enc key    DeriveKeyPair(suite 1, SHA-256("anet-seal-golden-v1/sender-enc"))
//	recipient enc key DeriveKeyPair(suite 1, SHA-256("anet-seal-golden-v1/recipient-enc"))
//	mid               SHA-256("anet-seal-golden-v1/mid")[:16]
const (
	goldenFile         = "testdata/vec-sealed-1.json"
	goldenRecipientAID = "bafyreigoldenrecipient"
	goldenSenderAID    = "bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y"
	goldenTS           = t0
	goldenNow          = t0 + minuteMS
	goldenBody         = "anet seal golden vector 1"
	goldenIX           = "ix-golden-1"
)

type goldenVector struct {
	Description  string `json:"description"`
	RecipientPub string `json:"recipient_pub"`
	RecipientKID string `json:"recipient_kid"`
	HPKEInfo     string `json:"hpke_info"`
	SigPreimage  string `json:"sig_preimage"`
	Envelope     string `json:"envelope"`
}

func seed(label string) []byte {
	h := sha256.Sum256([]byte("anet-seal-golden-v1/" + label))
	return h[:]
}

func goldenKeys(t *testing.T) (sender, recipient *KeyPair) {
	t.Helper()
	var err error
	sender, err = DeriveKeyPair(SuiteX25519, seed("sender-enc"), goldenTS-dayMS, goldenTS+13*dayMS)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err = DeriveKeyPair(SuiteX25519, seed("recipient-enc"), goldenTS-dayMS, goldenTS+13*dayMS)
	if err != nil {
		t.Fatal(err)
	}
	return sender, recipient
}

// goldenInner is the inner before signing. Everything in it is a function of
// the seeds; Ed25519 signatures are deterministic, so the key set bytes are
// too.
func goldenInner(t *testing.T) *SealedInner {
	t.Helper()
	c := identity.SuiteController()
	senderKP, _ := goldenKeys(t)
	set := &EncKeySet{Type: EncKeySetType, AID: c.AID(), Seq: goldenTS, Keys: []EncKey{senderKP.Public}, IssuedAt: goldenTS}
	signed, err := SignEncKeySet(set, c.Sign)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	return &SealedInner{
		From: c.AID(), KeyStateSeq: c.CurrentSeq(), To: goldenRecipientAID,
		Type: TypeMessage, IX: goldenIX, MID: seed("mid")[:MIDLen],
		TS: goldenTS, Exp: goldenTS + dayMS, Body: []byte(goldenBody),
		KEL: kel, Keys: keys,
	}
}

func readGolden(t *testing.T) (goldenVector, map[string][]byte) {
	t.Helper()
	raw, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatal(err)
	}
	var v goldenVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for name, s := range map[string]string{
		"recipient_pub": v.RecipientPub, "recipient_kid": v.RecipientKID,
		"hpke_info": v.HPKEInfo, "sig_preimage": v.SigPreimage, "envelope": v.Envelope,
	} {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = b
	}
	return v, out
}

func TestVEC_SEALED_1(t *testing.T) {
	_, g := readGolden(t)

	if aid := identity.SuiteController().AID(); aid != goldenSenderAID {
		t.Fatalf("the conformance identity moved: %s", aid)
	}
	_, rk := goldenKeys(t)
	if !bytes.Equal(rk.Public.Pub, g["recipient_pub"]) {
		t.Fatalf("recipient public key\n got  %x\n want %x", rk.Public.Pub, g["recipient_pub"])
	}
	if !bytes.Equal(rk.Public.KID, g["recipient_kid"]) {
		t.Fatalf("recipient kid\n got  %x\n want %x", rk.Public.KID, g["recipient_kid"])
	}

	// HPKE info from the header constants alone. It is deterministic, so it
	// is pinned here as well as in the file: regenerating the file cannot
	// move it unnoticed.
	const wantInfo = "a4016d616e65742d72656c61792f7631027662616679726569676f6c64656e726563697069656e7403010450841e6e853cc8d0ae17192d52e54d4f84"
	info, err := HPKEInfo(goldenRecipientAID, SuiteX25519, rk.Public.KID)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(info) != wantInfo || !bytes.Equal(info, g["hpke_info"]) {
		t.Fatalf("HPKE info\n got  %x\n want %s\n file %x", info, wantInfo, g["hpke_info"])
	}

	o, err := Open(g["envelope"], goldenRecipientAID, StaticKeyRing{rk})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(o.Preimage, g["sig_preimage"]) {
		t.Fatalf("signature preimage\n got  %x\n want %x", o.Preimage, g["sig_preimage"])
	}

	// The opened fields are the ones the seeds determine.
	want := goldenInner(t)
	got := o.Inner
	if got.From != want.From || got.KeyStateSeq != want.KeyStateSeq || got.To != want.To ||
		got.Type != want.Type || got.IX != want.IX || !bytes.Equal(got.MID, want.MID) ||
		got.TS != want.TS || got.Exp != want.Exp || !bytes.Equal(got.Body, want.Body) ||
		!bytes.Equal(got.KEL, want.KEL) || !bytes.Equal(got.Keys, want.Keys) || len(got.Ext) != 0 {
		t.Fatalf("opened inner differs from the seeds:\n got  %+v\n want %+v", got, *want)
	}
	if Padme(len(o.Outer.CT)-16) != len(o.Outer.CT)-16 {
		t.Fatalf("inner length %d is not a Padmé length", len(o.Outer.CT)-16)
	}

	if err := CheckTime(&o.Inner, goldenNow); err != nil {
		t.Fatalf("time: %v", err)
	}
	if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, goldenNow, DefaultRotationGrace); err != nil {
		t.Fatalf("signature: %v", err)
	}
	if _, _, err := VerifyInnerKeys(&o.Inner, o.KEL, goldenNow); err != nil {
		t.Fatalf("attached key set: %v", err)
	}

	// The pinned preimage is what the signature is over: one changed byte
	// in it fails.
	bad := append([]byte(nil), g["sig_preimage"]...)
	bad[len(bad)-1] ^= 1
	wantReason(t, VerifyInnerSig(&o.Inner, bad, o.KEL, goldenNow, DefaultRotationGrace), ReasonBadSig)
}

// TestWriteVEC_SEALED_1 regenerates the vector file. It runs only with
// SEAL_WRITE_GOLDEN=1 and is for a deliberate format change: the new file
// is a new vector, and every other implementation has to be updated to it.
// A failing TestVEC_SEALED_1 is not a reason to run it.
func TestWriteVEC_SEALED_1(t *testing.T) {
	if os.Getenv("SEAL_WRITE_GOLDEN") != "1" {
		t.Skip("set SEAL_WRITE_GOLDEN=1 to regenerate " + goldenFile)
	}
	c := identity.SuiteController()
	_, rk := goldenKeys(t)
	env, err := Seal(goldenInner(t), &rk.Public, c.Sign)
	if err != nil {
		t.Fatal(err)
	}
	info, err := HPKEInfo(goldenRecipientAID, SuiteX25519, rk.Public.KID)
	if err != nil {
		t.Fatal(err)
	}
	o, err := Open(env, goldenRecipientAID, StaticKeyRing{rk})
	if err != nil {
		t.Fatal(err)
	}
	v := goldenVector{
		Description: "VEC-SEALED-1: SealedEnvelope from identity.SuiteController() to " + goldenRecipientAID +
			"; see seal/golden_test.go for the seeds. Opening side only.",
		RecipientPub: hex.EncodeToString(rk.Public.Pub),
		RecipientKID: hex.EncodeToString(rk.Public.KID),
		HPKEInfo:     hex.EncodeToString(info),
		SigPreimage:  hex.EncodeToString(o.Preimage),
		Envelope:     hex.EncodeToString(env),
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goldenFile, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
