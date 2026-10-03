package seal

import (
	"crypto/hpke"
	"testing"

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

// testNotice stands in for a witness notice in key 11. This package checks
// only that key 11 is one byte string of at most MaxNoticeBytes that goes with
// key 10; the notice itself is checked by CheckNotice (KEL-4).
var testNotice = []byte("notice")

// testGrant is a grant-shaped map for key 14; its content is CheckGrant's.
var testGrant = []byte{0xa1, 0x03, 0x61, 0x68} // {3: "h"}

// innerFrom returns an unsigned inner from -> to at ts, of the shape every
// queued message has: keys 10, 11 and 12.
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
		Notices:     [][]byte{testNotice},
		Keys:        from.keysBytes(t),
	}
}

// session is the access a first-contact delivery carries.
var session = &Access{Kind: AccessKindSession}

// mustSeal seals and adds a session access, the form a hub accepts.
func mustSeal(t *testing.T, in *SealedInner, to *EncKey, sign SignFunc) []byte {
	t.Helper()
	env, _ := mustSealAck(t, in, to, sign, SealOpts{})
	return env
}

func mustSealAck(t *testing.T, in *SealedInner, to *EncKey, sign SignFunc, o SealOpts) ([]byte, AckKey) {
	t.Helper()
	env, ack, err := Seal(in, to, sign, o)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return withSession(t, env), ack
}

// sealHooked is Seal with test hooks, plus a session access.
func sealHooked(t *testing.T, in *SealedInner, to *EncKey, sign SignFunc, o SealOpts, h sealHooks) []byte {
	t.Helper()
	env, _, err := seal(in, to, sign, o, &h)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return withSession(t, env)
}

func withSession(t *testing.T, env []byte) []byte {
	t.Helper()
	out, err := SetAccess(env, session)
	if err != nil {
		t.Fatalf("set access: %v", err)
	}
	return out
}

func mustOpen(t *testing.T, env []byte, self *party) *Opened {
	t.Helper()
	o, err := Open(env, self.aid(), self.ring(), nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return o
}

// openLayer1 decrypts env with kp and returns the layer-1 plaintext (the
// Wrap), the view a recipient has after layer 1 opens.
func openLayer1(t *testing.T, env []byte, kp *KeyPair) []byte {
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
	return pt
}

// decryptFields decrypts env with kp and returns the inner field map.
func decryptFields(t *testing.T, env []byte, kp *KeyPair) fieldMap {
	t.Helper()
	w, err := decodeWrap(openLayer1(t, env, kp))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decodeFields(w.body)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// wrapOf returns the padded single-layer Wrap encoding of inner bytes.
func wrapOf(t *testing.T, inner []byte) []byte {
	t.Helper()
	w := fieldMap{wrapKeyBody: enc(t, inner)}
	applyPad(w)
	return mustMarshalFields(t, w)
}

// encryptFields encrypts an inner field map, wrapped and padded, to
// recipient under a fresh HPKE context, as a party holding a decrypted
// message could do. It does not re-sign.
func encryptFields(t *testing.T, m fieldMap, to string, recipient *EncKey) []byte {
	t.Helper()
	return encryptWrap(t, wrapOf(t, mustMarshalFields(t, m)), to, recipient)
}

// encryptPlaintext wraps arbitrary inner bytes and encrypts them to
// recipient. Tests use it for plaintexts a Go map cannot represent, such as a
// map with a repeated key.
func encryptPlaintext(t *testing.T, pt []byte, to string, recipient *EncKey) []byte {
	t.Helper()
	return encryptWrap(t, wrapOf(t, pt), to, recipient)
}

// encryptWrap encrypts arbitrary layer-1 plaintext to recipient and returns
// an envelope with a session access.
func encryptWrap(t *testing.T, pt []byte, to string, recipient *EncKey) []byte {
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
	env := SealedEnvelope{V: EnvelopeVersion, To: to, Suite: recipient.Suite, KID: recipient.KID, Enc: enc, CT: ct, Access: session}
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

// wantOpenFails fails the test unless Open's error carries reason, and an
// ack_key exactly when layer 1 opened (ack).
func wantOpenFails(t *testing.T, err error, reason string, ack bool) {
	t.Helper()
	wantReason(t, err, reason)
	if _, ok := AckKeyOf(err); ok != ack {
		t.Fatalf("%s: AckKeyOf = %v, want %v", reason, ok, ack)
	}
}
