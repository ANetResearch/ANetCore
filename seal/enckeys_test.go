package seal

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// signRaw signs arbitrary set bytes, bypassing SignEncKeySet's refusal of
// malformed sets, so the verifier's own checks can be exercised.
func signRaw(t *testing.T, c *identity.Controller, set any) *SignedEncKeySet {
	t.Helper()
	b, err := coredet.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	sig, seq := c.Sign(b)
	return &SignedEncKeySet{Set: b, KeyStateSeq: seq, Sig: sig}
}

func TestKID(t *testing.T) {
	pub := bytes.Repeat([]byte{0xab}, 32)
	h := sha256.Sum256(append(append([]byte("anet-enc-kid/v1"), 1), pub...))
	if got := KID(SuiteX25519, pub); !bytes.Equal(got, h[:16]) {
		t.Fatalf("KID\n got  %x\n want %x", got, h[:16])
	}
	if bytes.Equal(KID(SuiteX25519, pub), KID(SuiteXWing, pub)) {
		t.Fatal("the suite must be inside the kid hash")
	}
}

func TestVerifyEncKeySetAccepts(t *testing.T) {
	a := newParty(t)
	set, err := VerifyEncKeySet(a.signed, a.aid(), a.c.KEL(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if set.AID != a.aid() || len(set.Keys) != 1 || !bytes.Equal(set.Keys[0].Pub, a.kp.Public.Pub) {
		t.Fatalf("decoded set %+v", set)
	}
	// The signed object survives its wire encoding.
	b, err := a.signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalSignedEncKeySet(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEncKeySet(back, a.aid(), a.c.KEL(), t0); err != nil {
		t.Fatalf("after round trip: %v", err)
	}
}

// §3.1 rule 1 [C0]: a transport that answers a key lookup for A with B's
// valid KEL and key set must not get B's key accepted as A's.
func TestVerifyEncKeySetRecipientSubstitution(t *testing.T) {
	a, b := newParty(t), newParty(t)

	// B's own, fully valid material, offered for A.
	_, err := VerifyEncKeySet(b.signed, a.aid(), b.c.KEL(), t0)
	wantReason(t, err, ReasonAIDMismatch)

	// A set that names A, signed by B, with B's KEL.
	claim := EncKeySet{Type: EncKeySetType, AID: a.aid(), Seq: t0, Keys: []EncKey{b.kp.Public}, IssuedAt: t0}
	forged := signRaw(t, b.c, claim)
	_, err = VerifyEncKeySet(forged, a.aid(), b.c.KEL(), t0)
	wantReason(t, err, ReasonAIDMismatch)

	// The same set with A's KEL: the AIDs agree, the signature does not.
	_, err = VerifyEncKeySet(forged, a.aid(), a.c.KEL(), t0)
	wantReason(t, err, ReasonBadSig)

	// B's set with A's KEL.
	_, err = VerifyEncKeySet(b.signed, a.aid(), a.c.KEL(), t0)
	wantReason(t, err, ReasonAIDMismatch)
}

// §3.1 rule 2: only the key in force at the KEL head signs a key set; no
// rotation grace.
func TestVerifyEncKeySetKeyState(t *testing.T) {
	t.Run("ixn-like events keep the key", func(t *testing.T) {
		a := newParty(t) // signed at seq 0
		if err := a.c.Delegate(make([]byte, 32), t0); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyEncKeySet(a.signed, a.aid(), a.c.KEL(), t0); err != nil {
			t.Fatalf("a drt does not change the signing key: %v", err)
		}
	})
	t.Run("rotated away", func(t *testing.T) {
		a := newParty(t)
		if err := a.c.Rotate(t0 - 1); err != nil {
			t.Fatal(err)
		}
		_, err := VerifyEncKeySet(a.signed, a.aid(), a.c.KEL(), t0)
		wantReason(t, err, ReasonBadKeyState)
		a.resign(t, t0+1)
		if _, err := VerifyEncKeySet(a.signed, a.aid(), a.c.KEL(), t0); err != nil {
			t.Fatalf("re-signed after rotation: %v", err)
		}
	})
	t.Run("rotated away through a drt", func(t *testing.T) {
		a := newParty(t) // signed at seq 0
		if err := a.c.Delegate(make([]byte, 32), t0); err != nil {
			t.Fatal(err)
		}
		if err := a.c.Rotate(t0 + 1); err != nil {
			t.Fatal(err)
		}
		// Signed before the rotation. VerifyObject alone would accept it
		// (now < SupersededAt); a key set gets no grace.
		_, err := VerifyEncKeySet(a.signed, a.aid(), a.c.KEL(), t0)
		wantReason(t, err, ReasonBadKeyState)
	})
	t.Run("deactivated", func(t *testing.T) {
		a := newParty(t)
		if err := a.c.Deactivate(t0 + 1); err != nil {
			t.Fatal(err)
		}
		_, err := VerifyEncKeySet(a.signed, a.aid(), a.c.KEL(), t0)
		wantReason(t, err, ReasonRevokedKey)
	})
	t.Run("seq beyond KEL", func(t *testing.T) {
		a := newParty(t)
		s := *a.signed
		s.KeyStateSeq = 1
		_, err := VerifyEncKeySet(&s, a.aid(), a.c.KEL(), t0)
		wantReason(t, err, ReasonBadKeyState)
	})
	t.Run("bad signature", func(t *testing.T) {
		a := newParty(t)
		s := *a.signed
		s.Sig = append([]byte(nil), s.Sig...)
		s.Sig[0] ^= 1
		_, err := VerifyEncKeySet(&s, a.aid(), a.c.KEL(), t0)
		wantReason(t, err, ReasonBadSig)
		s.Sig = s.Sig[:63]
		_, err = VerifyEncKeySet(&s, a.aid(), a.c.KEL(), t0)
		wantReason(t, err, ReasonBadSig)
	})
	t.Run("KEL does not replay", func(t *testing.T) {
		a := newParty(t)
		kel := append([]identity.SignedEvent(nil), a.c.KEL()...)
		kel[0].Sig = make([]byte, 64)
		_, err := VerifyEncKeySet(a.signed, a.aid(), kel, t0)
		wantReason(t, err, ReasonBadKEL)
	})
}

// §3.1 rule 3.
func TestVerifyEncKeySetStructure(t *testing.T) {
	a := newParty(t)
	good := a.kp.Public
	key := func(nb, na uint64) EncKey {
		kp, err := GenerateKeyPair(SuiteX25519, nb, na)
		if err != nil {
			t.Fatal(err)
		}
		return kp.Public
	}
	k1 := key(t0-10*dayMS, t0+4*dayMS)
	k2 := key(t0-3*dayMS, t0+11*dayMS)
	set := func(keys ...EncKey) EncKeySet {
		return EncKeySet{Type: EncKeySetType, AID: a.aid(), Seq: t0, Keys: keys, IssuedAt: t0}
	}
	badKID := good
	badKID.KID = bytes.Repeat([]byte{1}, KIDLen)
	// The per-key fixtures below are valid at t0 + ClockSkewMS except for
	// the one rule each case breaks, so a case cannot pass because the set
	// has no key valid now.
	shortPub := NewEncKey(SuiteX25519, make([]byte, 31), t0-1, t0+dayMS)
	shortKID := good
	shortKID.KID = good.KID[:15]
	inverted := NewEncKey(SuiteX25519, good.Pub, t0+1, t0)
	// A distinct public key, so the set fails on the empty window and not
	// on a repeated kid.
	empty := NewEncKey(SuiteX25519, k2.Pub, t0, t0)
	tooLong := NewEncKey(SuiteX25519, good.Pub, t0-1, t0-1+MaxKeyValidityMS+1)
	atLimit := NewEncKey(SuiteX25519, good.Pub, t0-1, t0-1+MaxKeyValidityMS)
	suite0 := NewEncKey(0, good.Pub, t0-1, t0+dayMS)
	expired := NewEncKey(SuiteX25519, good.Pub, t0-2*dayMS, t0-dayMS)
	future := NewEncKey(SuiteX25519, good.Pub, t0+ClockSkewMS+1, t0+dayMS)
	nearFuture := NewEncKey(SuiteX25519, good.Pub, t0+ClockSkewMS, t0+dayMS)
	xwing := NewEncKey(SuiteXWing, make([]byte, 1216), t0-1, t0+dayMS)
	xwingNoPub := NewEncKey(SuiteXWing, nil, t0-1, t0+dayMS)

	wrongType := set(good)
	wrongType.Type = "anet.enckeys/2"
	noAID := set(good)
	noAID.AID = ""

	cases := []struct {
		name   string
		set    any
		reason string
	}{
		{"one key", set(good), ""},
		{"four keys ascending", set(k1, k2, good, key(t0, t0+dayMS)), ""},
		{"equal not_before", set(good, key(good.NotBefore, t0+dayMS)), ""},
		{"validity at 30 days", set(atLimit), ""},
		{"only key starts within skew", set(nearFuture), ""},
		{"reserved suite listed", set(good, xwing), ""},
		{"no keys", set(), ReasonBadKeySet},
		{"five keys", set(k1, k2, good, key(t0, t0+dayMS), key(t0+1, t0+dayMS)), ReasonBadKeySet},
		{"descending", set(k2, k1), ReasonBadKeySet},
		{"duplicate kid", set(good, good), ReasonBadKeySet},
		{"kid mismatch", set(badKID), ReasonBadKeySet},
		{"kid 15 bytes", set(shortKID), ReasonBadKeySet},
		{"pub 31 bytes", set(shortPub), ReasonBadKeySet},
		{"not_after before not_before", set(inverted), ReasonBadKeySet},
		{"not_after equals not_before", set(good, empty), ReasonBadKeySet},
		{"validity over 30 days", set(tooLong), ReasonBadKeySet},
		{"suite 0", set(suite0), ReasonBadKeySet},
		{"reserved suite with empty pub", set(good, xwingNoPub), ReasonBadKeySet},
		{"all expired", set(expired), ReasonBadKeySet},
		{"only key starts beyond skew", set(future), ReasonBadKeySet},
		{"wrong type", wrongType, ReasonBadKeySet},
		{"empty aid", noAID, ReasonAIDMismatch},
		{"unknown field", struct {
			EncKeySet
			X string `cbor:"5,keyasint"`
		}{set(good), "x"}, ReasonBadKeySet},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyEncKeySet(signRaw(t, a.c, tc.set), a.aid(), a.c.KEL(), t0)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				return
			}
			wantReason(t, err, tc.reason)
		})
	}

	// Non-canonical encoding of an otherwise valid set: seq 5 written as a
	// two-byte integer (0x18 0x05) instead of 0x05.
	small := set(good)
	small.Seq = 5
	b, err := coredet.Marshal(small)
	if err != nil {
		t.Fatal(err)
	}
	m, err := decodeFields(b)
	if err != nil {
		t.Fatal(err)
	}
	m[2] = []byte{0x18, 0x05}
	nc, err := coredet.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back EncKeySet
	if err := coredet.Unmarshal(nc, &back); err != nil || back.Seq != 5 || bytes.Equal(nc, b) {
		t.Fatalf("setup: non-canonical variant %x (%v)", nc, err)
	}
	sig, ks := a.c.Sign(nc)
	_, err = VerifyEncKeySet(&SignedEncKeySet{Set: nc, KeyStateSeq: ks, Sig: sig}, a.aid(), a.c.KEL(), t0)
	wantReason(t, err, ReasonBadKeySet)
	// The canonical form of the same set is accepted.
	sig, ks = a.c.Sign(b)
	if _, err := VerifyEncKeySet(&SignedEncKeySet{Set: b, KeyStateSeq: ks, Sig: sig}, a.aid(), a.c.KEL(), t0); err != nil {
		t.Fatalf("canonical control: %v", err)
	}
}

func TestSignEncKeySetRefusesInvalidSet(t *testing.T) {
	a := newParty(t)
	s := EncKeySet{Type: EncKeySetType, AID: a.aid(), Seq: t0, IssuedAt: t0}
	_, err := SignEncKeySet(&s, a.c.Sign)
	wantReason(t, err, ReasonInvalidInput)
	s.Keys = []EncKey{a.kp.Public}
	_, err = SignEncKeySet(&s, func([]byte) ([]byte, uint64) { return make([]byte, 10), 0 })
	wantReason(t, err, ReasonInvalidInput)
}

func TestSelectKey(t *testing.T) {
	mk := func(s Suite, nb, na uint64) EncKey {
		if s != SuiteX25519 {
			return NewEncKey(s, make([]byte, 1216), nb, na)
		}
		kp, err := GenerateKeyPair(s, nb, na)
		if err != nil {
			t.Fatal(err)
		}
		return kp.Public
	}
	old := mk(SuiteX25519, t0-10*dayMS, t0+4*dayMS)
	cur := mk(SuiteX25519, t0-3*dayMS, t0+11*dayMS)
	next := mk(SuiteX25519, t0+dayMS, t0+15*dayMS)
	soon := mk(SuiteX25519, t0+2*minuteMS, t0+14*dayMS)
	soon2 := mk(SuiteX25519, t0+3*minuteMS, t0+14*dayMS)
	xwing := mk(SuiteXWing, t0-dayMS, t0+13*dayMS)

	cases := []struct {
		name string
		keys []EncKey
		now  uint64
		want *EncKey
	}{
		{"latest not_before among valid", []EncKey{old, cur, next}, t0, &cur},
		{"old only valid", []EncKey{old, next}, t0, &old},
		{"not_after is exclusive", []EncKey{old}, old.NotAfter, nil},
		{"not_before is inclusive", []EncKey{next}, next.NotBefore, &next},
		{"unsupported suite skipped", []EncKey{old, xwing}, t0, &old},
		{"only unsupported", []EncKey{xwing}, t0, nil},
		{"within skew, earliest", []EncKey{soon, soon2}, t0, &soon},
		{"beyond skew", []EncKey{next}, t0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SelectKey(&EncKeySet{Keys: tc.keys}, tc.now)
			if tc.want == nil {
				wantReason(t, err, ReasonNoUsableKey)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.KID, tc.want.KID) {
				t.Fatalf("picked not_before %d, want %d", got.NotBefore, tc.want.NotBefore)
			}
		})
	}
}

func TestNextSeq(t *testing.T) {
	for _, c := range []struct{ now, last, want uint64 }{
		{t0, 0, t0},
		{t0, t0, t0 + 1},
		{t0, t0 + 50, t0 + 51}, // clock moved back
		{t0 + 50, t0, t0 + 50},
	} {
		if got := NextSeq(c.now, c.last); got != c.want {
			t.Errorf("NextSeq(%d, %d) = %d, want %d", c.now, c.last, got, c.want)
		}
	}
}

func TestKeyPairAndRetention(t *testing.T) {
	kp, err := GenerateKeyPair(SuiteX25519, t0, t0+KeyLifetimeMS)
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.Public.Pub) != 32 || !bytes.Equal(kp.Public.KID, KID(SuiteX25519, kp.Public.Pub)) {
		t.Fatalf("key pair %+v", kp.Public)
	}
	k := kp.Public
	if !k.ValidAt(t0) || k.ValidAt(t0-1) || k.ValidAt(t0+KeyLifetimeMS) {
		t.Fatal("ValidAt bounds")
	}
	if !k.Retained(t0+KeyLifetimeMS+KeyRetentionMS-1) || k.Retained(t0+KeyLifetimeMS+KeyRetentionMS) {
		t.Fatal("Retained bounds")
	}
	if ForwardSecrecyWindowMS != 29*dayMS {
		t.Fatalf("forward-secrecy window %d ms, §21 states 29 days", ForwardSecrecyWindowMS)
	}
	if _, err := GenerateKeyPair(SuiteX25519, t0, t0+MaxKeyValidityMS+1); ReasonOf(err) != ReasonInvalidInput {
		t.Fatalf("over-long validity: %v", err)
	}
	if _, err := GenerateKeyPair(SuiteXWing, t0, t0+1); ReasonOf(err) != ReasonUnknownSuite {
		t.Fatalf("reserved suite: %v", err)
	}
	// Derivation is deterministic in ikm.
	ikm := bytes.Repeat([]byte{5}, 32)
	d1, err := DeriveKeyPair(SuiteX25519, ikm, t0, t0+1)
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := DeriveKeyPair(SuiteX25519, ikm, t0, t0+1)
	if !bytes.Equal(d1.Public.Pub, d2.Public.Pub) || !bytes.Equal(d1.Private, d2.Private) {
		t.Fatal("DeriveKeyPair is not deterministic")
	}
}

// The integer keys of §3.1 and §3.3, read back from the encodings. The
// golden vector pins them too; this test names the object and key when one
// moves.
func TestWireKeyNumbers(t *testing.T) {
	a := newParty(t)
	keysOf := func(b []byte) map[uint64]bool {
		t.Helper()
		m, err := decodeFields(b)
		if err != nil {
			t.Fatal(err)
		}
		out := map[uint64]bool{}
		for k := range m {
			out[k] = true
		}
		return out
	}
	same := func(name string, got map[uint64]bool, want ...uint64) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s keys %v, want %v", name, got, want)
		}
		for _, k := range want {
			if !got[k] {
				t.Fatalf("%s keys %v, want %v", name, got, want)
			}
		}
	}
	setBytes, err := a.set.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	same("EncKeySet", keysOf(setBytes), 0, 1, 2, 3, 4)
	keyBytes, err := coredet.Marshal(a.kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	same("EncKey", keysOf(keyBytes), 1, 2, 3, 4, 5)
	signedBytes, err := a.signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	same("SignedEncKeySet", keysOf(signedBytes), 1, 2, 3)

	b := newParty(t)
	env := mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign)
	same("SealedEnvelope", keysOf(env), 1, 2, 3, 4, 5, 6)
	same("SealedInner", keysOf(mustMarshalFields(t, decryptFields(t, env, b.kp))), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 20, 21)
	info, err := HPKEInfo(b.aid(), SuiteX25519, b.kp.Public.KID)
	if err != nil {
		t.Fatal(err)
	}
	same("HPKE info", keysOf(info), 1, 2, 3, 4)
	o := mustOpen(t, env, b)
	same("signature preimage", keysOf(o.Preimage), 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 30, 31, 32)
}

func mustMarshalFields(t *testing.T, m fieldMap) []byte {
	t.Helper()
	b, err := coredet.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
