package seal

import (
	"bytes"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Suite 1 is the RFC 9180 ciphersuite 0x0020/0x0001/0x0003. The published
// vector is run through the same HPKE instantiation Open uses; only the
// receiving side is exercised, because Go's sender draws its ephemeral key
// from the system source and cannot reproduce ikmE (§17).
func TestRFC9180Suite1Vector(t *testing.T) {
	raw, err := os.ReadFile("testdata/rfc9180-a2-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		KEM         uint16 `json:"kem_id"`
		KDF         uint16 `json:"kdf_id"`
		AEAD        uint16 `json:"aead_id"`
		Info        string `json:"info"`
		IkmR        string `json:"ikmR"`
		PkRm        string `json:"pkRm"`
		Enc         string `json:"enc"`
		Encryptions []struct {
			Aad string `json:"aad"`
			Ct  string `json:"ct"`
			Pt  string `json:"pt"`
		} `json:"encryptions"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	h := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	p := params(SuiteX25519)
	if p.kem.ID() != v.KEM || p.kdf.ID() != v.KDF || p.aead.ID() != v.AEAD {
		t.Fatalf("suite 1 is %04x/%04x/%04x, vector is %04x/%04x/%04x",
			p.kem.ID(), p.kdf.ID(), p.aead.ID(), v.KEM, v.KDF, v.AEAD)
	}

	kp, err := DeriveKeyPair(SuiteX25519, h(v.IkmR), t0, t0+1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kp.Public.Pub, h(v.PkRm)) {
		t.Fatalf("DeriveKeyPair public key\n got  %x\n want %s", kp.Public.Pub, v.PkRm)
	}
	sk, err := p.kem.NewPrivateKey(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	r, err := hpke.NewRecipient(h(v.Enc), sk, p.kdf, p.aead, h(v.Info))
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range v.Encryptions {
		pt, err := r.Open(h(e.Aad), h(e.Ct))
		if err != nil {
			t.Fatalf("encryption %d: %v", i, err)
		}
		if !bytes.Equal(pt, h(e.Pt)) {
			t.Fatalf("encryption %d: plaintext %x, want %s", i, pt, e.Pt)
		}
	}
}
