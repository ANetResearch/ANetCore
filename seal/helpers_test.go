package seal

import (
	"crypto/hpke"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// t0 is 2026-01-01T00:00:00Z in unix ms. Tests use fixed times so a failure
// reproduces.
const t0 uint64 = 1767225600000

// party is one daemon as the tests see it: an identity, one encryption key
// pair and the signed key set that publishes it.
type party struct {
	c      *identity.Controller
	kp     *KeyPair
	set    *EncKeySet
	signed *SignedEncKeySet
}

func newParty(t *testing.T) *party {
	t.Helper()
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	return partyFor(t, c)
}

func partyFor(t *testing.T, c *identity.Controller) *party {
	t.Helper()
	kp, err := GenerateKeyPair(SuiteX25519, t0-dayMS, t0+13*dayMS)
	if err != nil {
		t.Fatal(err)
	}
	p := &party{c: c, kp: kp}
	p.resign(t, t0)
	return p
}

// resign publishes p's current key pairs as a new set with seq.
func (p *party) resign(t *testing.T, seq uint64, extra ...EncKey) {
	t.Helper()
	keys := append([]EncKey{p.kp.Public}, extra...)
	p.set = &EncKeySet{Type: EncKeySetType, AID: p.c.AID(), Seq: seq, Keys: keys, IssuedAt: seq}
	s, err := SignEncKeySet(p.set, p.c.Sign)
	if err != nil {
		t.Fatal(err)
	}
	p.signed = s
}

func (p *party) aid() string { return p.c.AID() }

func (p *party) kelBytes(t *testing.T) []byte {
	t.Helper()
	b, err := identity.MarshalKEL(p.c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (p *party) keysBytes(t *testing.T) []byte {
	t.Helper()
	b, err := p.signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (p *party) ring() KeyRing { return StaticKeyRing{p.kp} }

// innerFrom returns an unsigned inner from -> to at ts.
func innerFrom(t *testing.T, from, to *party, ts uint64) *SealedInner {
	t.Helper()
	return &SealedInner{
		From:        from.aid(),
		KeyStateSeq: from.c.CurrentSeq(),
		To:          to.aid(),
		Type:        TypeMessage,
		IX:          "ix-1",
		MID:         NewMID(),
		TS:          ts,
		Exp:         ts + dayMS,
		Body:        []byte("hello"),
		KEL:         from.kelBytes(t),
		Keys:        from.keysBytes(t),
	}
}

func mustSeal(t *testing.T, in *SealedInner, to *EncKey, sign SignFunc) []byte {
	t.Helper()
	env, err := Seal(in, to, sign)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return env
}

func mustOpen(t *testing.T, env []byte, self *party) *Opened {
	t.Helper()
	o, err := Open(env, self.aid(), self.ring())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return o
}

// decryptFields decrypts env with kp and returns the inner field map, the
// view a recipient has after a successful open.
func decryptFields(t *testing.T, env []byte, kp *KeyPair) fieldMap {
	t.Helper()
	outer, err := ParseOuter(env)
	if err != nil {
		t.Fatal(err)
	}
	p := params(outer.Suite)
	sk, err := p.kem.NewPrivateKey(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	info, err := HPKEInfo(outer.To, outer.Suite, outer.KID)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := hpke.Open(sk, p.kdf, p.aead, info, append(append([]byte(nil), outer.Enc...), outer.CT...))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decodeFields(pt)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// encryptFields encrypts an inner field map to recipient under a fresh HPKE
// context, as a party holding a decrypted message could do. It does not
// re-sign.
func encryptFields(t *testing.T, m fieldMap, to string, recipient *EncKey) []byte {
	t.Helper()
	pt, err := coredet.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return encryptPlaintext(t, pt, to, recipient)
}

// encryptPlaintext encrypts arbitrary inner bytes to recipient. Tests use it
// for plaintexts a Go map cannot represent, such as a map with a repeated
// key.
func encryptPlaintext(t *testing.T, pt []byte, to string, recipient *EncKey) []byte {
	t.Helper()
	p := params(recipient.Suite)
	pk, err := p.kem.NewPublicKey(recipient.Pub)
	if err != nil {
		t.Fatal(err)
	}
	info, err := HPKEInfo(to, recipient.Suite, recipient.KID)
	if err != nil {
		t.Fatal(err)
	}
	enc, s, err := hpke.NewSender(pk, p.kdf, p.aead, info)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := s.Seal(nil, pt)
	if err != nil {
		t.Fatal(err)
	}
	env := SealedEnvelope{V: EnvelopeVersion, To: to, Suite: recipient.Suite, KID: recipient.KID, Enc: enc, CT: ct}
	b, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func enc(t *testing.T, v any) []byte {
	t.Helper()
	b, err := encodeField(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// wantReason fails the test unless err carries reason.
func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want reason %q, got nil error", reason)
	}
	if got := ReasonOf(err); got != reason {
		t.Fatalf("want reason %q, got %q (%v)", reason, got, err)
	}
}
