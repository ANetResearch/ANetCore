package seal

// Fuzz targets for the envelope, the inner message and the key set (ANet docs/notes/0033).
//
// Open needs the recipient's private key and a signature to get past its first steps, so the
// targets fix the recipient to the VEC-SEALED-1 key and the sender to the suite identity:
//   - FuzzOpenEnvelope feeds whole envelopes (the hub's ParseOuter and the daemon's Open);
//   - FuzzOpenInner feeds the plaintext, encrypts it to the recipient itself and, when asked,
//     re-signs the fuzzed field map with the suite key over the preimage Open will build, so
//     VerifyInnerSig and VerifyInnerKeys run on arbitrary field values under a good signature;
//   - FuzzEncKeySet feeds SignedEncKeySet bytes, optionally re-signing the set;
//   - FuzzPadme checks Padmé and the inner padding arithmetic.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"reflect"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

type fuzzFixture struct {
	sender    *identity.Controller
	senderKEL []identity.SignedEvent
	senderKP  *KeyPair
	recipient *KeyPair
	ring      KeyRing
	inner     *SealedInner // unsigned golden inner
	golden    []byte       // VEC-SEALED-1 envelope
}

func newFuzzFixture(tb testing.TB) *fuzzFixture {
	tb.Helper()
	sk, err := DeriveKeyPair(SuiteX25519, seed("sender-enc"), goldenTS-dayMS, goldenTS+13*dayMS)
	if err != nil {
		tb.Fatal(err)
	}
	rk, err := DeriveKeyPair(SuiteX25519, seed("recipient-enc"), goldenTS-dayMS, goldenTS+13*dayMS)
	if err != nil {
		tb.Fatal(err)
	}
	c := identity.SuiteController()
	set := &EncKeySet{Type: EncKeySetType, AID: c.AID(), Seq: goldenTS, Keys: []EncKey{sk.Public}, IssuedAt: goldenTS}
	signed, err := SignEncKeySet(set, c.Sign)
	if err != nil {
		tb.Fatal(err)
	}
	keys, err := signed.Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		tb.Fatal(err)
	}
	raw, err := os.ReadFile(goldenFile)
	if err != nil {
		tb.Fatal(err)
	}
	var v goldenVector
	if err := json.Unmarshal(raw, &v); err != nil {
		tb.Fatal(err)
	}
	env, err := hex.DecodeString(v.Envelope)
	if err != nil {
		tb.Fatal(err)
	}
	return &fuzzFixture{
		sender: c, senderKEL: c.KEL(), senderKP: sk, recipient: rk, ring: StaticKeyRing{rk},
		inner: &SealedInner{
			From: c.AID(), KeyStateSeq: c.CurrentSeq(), To: goldenRecipientAID,
			Type: TypeMessage, IX: goldenIX, MID: seed("mid")[:MIDLen],
			TS: goldenTS, Exp: goldenTS + dayMS, Body: []byte(goldenBody),
			KEL: kel, Keys: keys,
		},
		golden: env,
	}
}

// sealedPlaintext seals in to the fixture recipient and returns the envelope and the inner
// plaintext as sent.
func (fx *fuzzFixture) sealedPlaintext(tb testing.TB, in *SealedInner) (env, pt []byte) {
	tb.Helper()
	env, err := seal(in, &fx.recipient.Public, fx.sender.Sign, func(m fieldMap) {
		b, err := coredet.Marshal(m)
		if err != nil {
			tb.Fatal(err)
		}
		pt = b
	})
	if err != nil {
		tb.Fatal(err)
	}
	return env, pt
}

// fuzzSeedInners are variants of the golden inner used as seeds. The last carries the suite
// KEL after a rotation at goldenTS+1000 and still declares key state 0: signed with the
// pre-rotation key before the rotation, it reaches VerifyInnerSig's rotation-grace branch.
func (fx *fuzzFixture) fuzzSeedInners(tb testing.TB) []*SealedInner {
	a := *fx.inner
	b := *fx.inner
	b.Type, b.Body, b.Ext = TypeDelegate, bytes.Repeat([]byte{7}, 300), map[uint64][]byte{64: {0x01}, 100: {0x63, 'a', 'b', 'c'}}
	c := *fx.inner
	c.Exp, c.IX, c.Body = c.TS, "", nil
	d := *fx.inner
	d.KEL = rotatedSuiteKEL(tb, goldenTS+1000)
	return []*SealedInner{&a, &b, &c, &d}
}

// rotatedSuiteKEL is the suite identity's KEL after one rotation (to its committed next key) at
// ts, encoded.
func rotatedSuiteKEL(tb testing.TB, ts uint64) []byte {
	tb.Helper()
	k := func(label string) ed25519.PrivateKey {
		s := sha256.Sum256([]byte(label))
		return ed25519.NewKeyFromSeed(s[:])
	}
	k0, k1, k2 := k("anet-suite-identity-v1/cur"), k("anet-suite-identity-v1/nxt"), k("anet-fuzz/seal/k2")
	kel := identity.SuiteController().KEL()
	d := sha256.Sum256(k2.Public().(ed25519.PublicKey))
	rot := identity.KeyEvent{AID: kel[0].EventID, Seq: 1, Prev: kel[0].EventID, Type: identity.Rotation,
		Keys: [][]byte{k1.Public().(ed25519.PublicKey)}, NextDigest: d[:], Threshold: 1, Timestamp: ts}
	pre, err := coredet.Marshal(rot)
	if err != nil {
		tb.Fatal(err)
	}
	kel = append(kel, identity.SignedEvent{Event: rot, Sig: ed25519.Sign(k0, pre), EventID: anetcid.MustSum(pre)})
	b, err := identity.MarshalKEL(kel)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func FuzzOpenEnvelope(f *testing.F) {
	fx := newFuzzFixture(f)
	f.Add(fx.golden)
	for _, in := range fx.fuzzSeedInners(f) {
		env, _ := fx.sealedPlaintext(f, in)
		f.Add(env)
	}
	f.Fuzz(func(t *testing.T, env []byte) {
		outer, err := ParseOuter(env)
		if err == nil {
			// The structural checks the hub relies on.
			if outer.V != EnvelopeVersion || outer.To == "" || len(outer.KID) != KIDLen ||
				len(outer.Enc) != params(outer.Suite).encLen || len(outer.CT) == 0 {
				t.Fatalf("ParseOuter accepted %+v", outer)
			}
			b, err := outer.Marshal()
			if err != nil {
				t.Fatalf("an accepted outer does not encode: %v", err)
			}
			again, err := ParseOuter(b)
			if err != nil || !reflect.DeepEqual(again, outer) {
				t.Fatalf("outer round trip: %v\n%+v\n%+v", err, outer, again)
			}
		} else if ReasonOf(err) == "" {
			t.Fatalf("ParseOuter returned a non-*Error: %v", err)
		}
		o, err := Open(env, goldenRecipientAID, fx.ring)
		if err != nil {
			if ReasonOf(err) == "" || !IsPermanent(err) {
				t.Fatalf("Open returned %v (reason %q)", err, ReasonOf(err))
			}
			return
		}
		fx.checkOpened(t, o)
	})
}

func FuzzOpenInner(f *testing.F) {
	fx := newFuzzFixture(f)
	for _, in := range fx.fuzzSeedInners(f) {
		_, pt := fx.sealedPlaintext(f, in)
		f.Add(pt, true)
		f.Add(pt, false)
	}
	f.Fuzz(func(t *testing.T, pt []byte, resign bool) {
		p := params(SuiteX25519)
		pk, err := p.kem.NewPublicKey(fx.recipient.Public.Pub)
		if err != nil {
			t.Fatal(err)
		}
		info, err := HPKEInfo(goldenRecipientAID, SuiteX25519, fx.recipient.Public.KID)
		if err != nil {
			t.Fatal(err)
		}
		encKey, sender, err := hpke.NewSender(pk, p.kdf, p.aead, info)
		if err != nil {
			t.Fatal(err)
		}
		if resign {
			// Sign the fuzzed field map over the preimage Open will build from it.
			if fields, err := decodeFields(pt); err == nil {
				if pre, err := sigPreimage(fields, encKey, fx.recipient.Public.KID, SuiteX25519); err == nil {
					sig, _ := fx.sender.Sign(pre)
					fields[keySig] = enc(t, sig)
					if b, err := coredet.Marshal(fields); err == nil {
						pt = b
					}
				}
			}
		}
		ct, err := sender.Seal(nil, pt)
		if err != nil {
			t.Fatal(err)
		}
		env, err := (&SealedEnvelope{V: EnvelopeVersion, To: goldenRecipientAID, Suite: SuiteX25519,
			KID: fx.recipient.Public.KID, Enc: encKey, CT: ct}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		o, err := Open(env, goldenRecipientAID, fx.ring)
		if err != nil {
			if ReasonOf(err) == "" || !IsPermanent(err) {
				t.Fatalf("Open returned %v (reason %q)", err, ReasonOf(err))
			}
			if r := ReasonOf(err); r == ReasonDecrypt || r == ReasonUnknownKey || r == ReasonBadOuter {
				t.Fatalf("an envelope built for the recipient failed before decoding: %v", err)
			}
			return
		}
		fx.checkOpened(t, o)
	})
}

// checkOpened asserts what an opened message must satisfy, then runs the later receive steps.
func (fx *fuzzFixture) checkOpened(t *testing.T, o *Opened) {
	t.Helper()
	in := &o.Inner
	if in.To != goldenRecipientAID || o.Outer.To != goldenRecipientAID {
		t.Fatalf("opened a message to %q (outer %q)", in.To, o.Outer.To)
	}
	if len(in.MID) != MIDLen || len(in.Sig) != SigLen {
		t.Fatalf("opened mid %d bytes, sig %d bytes", len(in.MID), len(in.Sig))
	}
	for _, b := range in.Pad {
		if b != 0 {
			t.Fatal("opened a message with a non-zero pad")
		}
	}
	for k := range in.Ext {
		if k < FirstIgnorableKey {
			t.Fatalf("extension key %d below %d", k, FirstIgnorableKey)
		}
	}
	if len(in.KEL) > MaxKELBytes || len(o.KEL) == 0 || len(o.KEL) > MaxKELEvents {
		t.Fatalf("opened a KEL of %d bytes, %d events", len(in.KEL), len(o.KEL))
	}
	// The preimage never carries the signature or the pad, and carries the outer header.
	pm, err := decodeFields(o.Preimage)
	if err != nil {
		t.Fatalf("preimage does not decode: %v", err)
	}
	if _, ok := pm[keySig]; ok {
		t.Fatal("preimage carries the signature")
	}
	if _, ok := pm[keyPad]; ok {
		t.Fatal("preimage carries the pad")
	}
	if kid, err := rawBytes(pm, preKeyKID); err != nil || !bytes.Equal(kid, o.Outer.KID) {
		t.Fatalf("preimage kid %x, outer %x (%v)", kid, o.Outer.KID, err)
	}
	if e, err := rawBytes(pm, preKeyEnc); err != nil || !bytes.Equal(e, o.Outer.Enc) {
		t.Fatalf("preimage enc %x, outer %x (%v)", e, o.Outer.Enc, err)
	}

	for _, now := range []uint64{0, in.TS, in.Exp, math.MaxUint64} {
		_ = CheckTime(in, now)
	}
	now := in.TS
	if err := VerifyInnerSig(in, o.Preimage, o.KEL, now, DefaultRotationGrace); err == nil {
		// Accepted: the declared sender is the AID the KEL replays to, and the signature is by
		// the key the declared key state holds.
		states, rerr := identity.Replay(o.KEL)
		if rerr != nil {
			t.Fatalf("VerifyInnerSig accepted a KEL that does not replay: %v", rerr)
		}
		if states[len(states)-1].AID != in.From {
			t.Fatalf("accepted from %s, KEL replays to %s", in.From, states[len(states)-1].AID)
		}
		key := states[in.KeyStateSeq].CurrentKeys[0]
		if !ed25519.Verify(key, o.Preimage, in.Sig) {
			t.Fatal("accepted a signature that is not by the declared key state")
		}
	} else if ReasonOf(err) == "" {
		t.Fatalf("VerifyInnerSig returned a non-*Error: %v", err)
	}
	if _, set, err := VerifyInnerKeys(in, o.KEL, now); err == nil {
		if set.AID != in.From {
			t.Fatalf("attached key set for %s accepted for sender %s", set.AID, in.From)
		}
	} else if ReasonOf(err) == "" {
		t.Fatalf("VerifyInnerKeys returned a non-*Error: %v", err)
	}
}

func FuzzEncKeySet(f *testing.F) {
	fx := newFuzzFixture(f)
	signed, err := SignEncKeySet(&EncKeySet{Type: EncKeySetType, AID: fx.sender.AID(), Seq: goldenTS,
		Keys: []EncKey{fx.senderKP.Public}, IssuedAt: goldenTS}, fx.sender.Sign)
	if err != nil {
		f.Fatal(err)
	}
	b, err := signed.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b, false, goldenTS)
	f.Add(b, true, goldenTS+dayMS)
	two := NewEncKey(SuiteXWing, bytes.Repeat([]byte{9}, 1216), goldenTS, goldenTS+dayMS)
	signed2, err := SignEncKeySet(&EncKeySet{Type: EncKeySetType, AID: fx.sender.AID(), Seq: goldenTS + 1,
		Keys: []EncKey{fx.senderKP.Public, two}, IssuedAt: goldenTS}, fx.sender.Sign)
	if err != nil {
		f.Fatal(err)
	}
	b2, _ := signed2.Marshal()
	f.Add(b2, true, goldenTS)
	f.Fuzz(func(t *testing.T, b []byte, resign bool, now uint64) {
		s, err := UnmarshalSignedEncKeySet(b)
		if err != nil {
			return
		}
		if resign {
			s.Sig, s.KeyStateSeq = fx.sender.Sign(s.Set)
		}
		_, _ = DecideHighWaterSigned(nil, s)
		_, _ = DecideHighWaterSigned(&Seen{Seq: goldenTS, Set: signed.Set}, s)
		set, err := VerifyEncKeySet(s, fx.sender.AID(), fx.senderKEL, now)
		if err != nil {
			if ReasonOf(err) == "" {
				t.Fatalf("VerifyEncKeySet returned a non-*Error: %v", err)
			}
			return
		}
		if set.AID != fx.sender.AID() || set.Type != EncKeySetType {
			t.Fatalf("accepted a set for %q of type %q", set.AID, set.Type)
		}
		re, err := set.Marshal()
		if err != nil || !bytes.Equal(re, s.Set) {
			t.Fatalf("accepted set bytes are not the canonical encoding of the set (%v)", err)
		}
		if !ed25519.Verify(fx.sender.KEL()[0].Event.Keys[0], s.Set, s.Sig) {
			t.Fatal("accepted a set whose signature is not by the sender's key")
		}
		if len(set.Keys) == 0 || len(set.Keys) > MaxKeysPerSet {
			t.Fatalf("accepted %d keys", len(set.Keys))
		}
		kids := map[string]bool{}
		valid := false
		for i := range set.Keys {
			k := &set.Keys[i]
			if err := k.check(); err != nil {
				t.Fatalf("accepted key %d: %v", i, err)
			}
			if kids[string(k.KID)] {
				t.Fatalf("accepted a repeated kid")
			}
			kids[string(k.KID)] = true
			if t2 := satAdd(now, ClockSkewMS); k.NotBefore <= t2 && t2 < k.NotAfter {
				valid = true
			}
		}
		if !valid {
			t.Fatal("accepted a set with no key valid at now + skew")
		}
		if k, err := SelectKey(set, now); err == nil {
			if !Supported(k.Suite) || !kids[string(k.KID)] {
				t.Fatalf("SelectKey chose %x (suite %d), not a supported key of the set", k.KID, k.Suite)
			}
		}
	})
}

func FuzzPadme(f *testing.F) {
	for _, n := range []int64{0, 1, 2, 9, 255, 256, 65537, 1 << 40, math.MaxInt64} {
		f.Add(n, uint32(n))
	}
	f.Fuzz(func(t *testing.T, n64 int64, body uint32) {
		n := int(n64)
		p := Padme(n)
		if n < 2 {
			if p != n {
				t.Fatalf("Padme(%d) = %d", n, p)
			}
		} else {
			if p < n {
				t.Fatalf("Padme(%d) = %d, below n", n, p)
			}
			if p-n > n/8 {
				t.Fatalf("Padme(%d) = %d, overhead above 12.5%%", n, p)
			}
			if Padme(p) != p {
				t.Fatalf("Padme(Padme(%d)) = %d, not %d", n, Padme(p), p)
			}
		}
		// The padding Seal applies reaches its target exactly.
		fields := fieldMap{keyBody: mustEncode(t, bytes.Repeat([]byte{1}, int(body%70000)))}
		if body&1 != 0 {
			fields[keyKEL] = mustEncode(t, make([]byte, int(body>>20)))
		}
		want := applyPad(fields)
		b, err := coredet.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != want || Padme(want) != want || encodedLen(fields) != want {
			t.Fatalf("padded inner is %d bytes, target %d, encodedLen %d", len(b), want, encodedLen(fields))
		}
	})
}

func mustEncode(tb testing.TB, v any) []byte {
	tb.Helper()
	b, err := encodeField(v)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}
