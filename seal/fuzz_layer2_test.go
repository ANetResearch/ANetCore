package seal

// Fuzz targets for the second layer (FS §2.5-§2.8), beside those of fuzz_test.go, whose fixture
// they share:
//   - FuzzRKDecode feeds inner key 15 (rk) to its decoder and, inside an inner, to Open's step 4;
//   - FuzzOpenLayer2 feeds the second layer's plaintext (or its ciphertext) inside a Wrap sealed to
//     the recipient, optionally re-signed for the second layer it travels in, and checks every
//     refusal after layer 1 and every acceptance against the interaction key that opened it.

import (
	"bytes"
	"crypto/hpke"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
)

// fuzzIXKey is an interaction key of the fixture recipient in interaction ix with the suite
// identity, derived from the seed of role so every run uses the same key.
func (fx *fuzzFixture) fuzzIXKey(tb testing.TB, ix, role string) *IXKey {
	tb.Helper()
	kp, err := DeriveKeyPair(SuiteX25519, goldenSeed("SEALED-2B", role), 0, dayMS)
	if err != nil {
		tb.Fatal(err)
	}
	return &IXKey{IX: ix, PeerAID: fx.sender.AID(), Suite: SuiteX25519, Pub: kp.Public.Pub, Private: kp.Private}
}

func FuzzRKDecode(f *testing.F) {
	fx := newFuzzFixture(f)
	good := mustEncode(f, &RK{Suite: SuiteX25519, Pub: bytes.Repeat([]byte{5}, 32)})
	f.Add(good)
	f.Add(mustEncode(f, &RK{Suite: SuiteXWing, Pub: bytes.Repeat([]byte{5}, 32)}))
	f.Add(mustEncode(f, &RK{Suite: SuiteX25519, Pub: bytes.Repeat([]byte{5}, 31)}))
	f.Add(mustEncode(f, map[uint64]any{1: uint64(1), 2: make([]byte, 32), 3: "x"}))
	f.Add(mustEncode(f, map[uint64]any{1: uint64(1)}))
	f.Add(append([]byte{0xa2, 0x01, 0x18, 0x01, 0x02, 0x58, 0x20}, make([]byte, 32)...))       // suite in two bytes
	f.Add(append([]byte{0xa2, 0x01, 0x19, 0x01, 0x01, 0x02, 0x58, 0x20}, make([]byte, 32)...)) // suite 257, 1 as a uint8
	f.Add([]byte{0xf6})
	_, _, plain := fx.sealed(f, fx.inner, SealOpts{})
	base, err := decodeFields(plain)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := decodeRK(b)
		if err == nil {
			// Accepted: suite 1 and a 32-byte key, from a map of exactly keys 1 and 2, and the
			// value round-trips through the canonical encoding.
			m, ferr := decodeFields(b)
			if ferr != nil || len(m) != 2 || m[1] == nil || m[2] == nil {
				t.Fatalf("accepted rk %x of keys %v (%v)", b, m, ferr)
			}
			if s, err := rawUint(m, 1); err != nil || s != uint64(SuiteX25519) {
				t.Fatalf("accepted rk %x whose suite on the wire is %d (%v)", b, s, err)
			}
			if r.Suite != SuiteX25519 || len(r.Pub) != 32 || r.check() != nil {
				t.Fatalf("accepted rk %+v", r)
			}
			re, err := decodeRK(mustEncode(t, r))
			if err != nil || re.Suite != r.Suite || !bytes.Equal(re.Pub, r.Pub) {
				t.Fatalf("rk round trip: %v", err)
			}
			if !bytes.Equal(r.KID(), KID(SuiteX25519, r.Pub)) {
				t.Fatal("rk kid is not L15")
			}
		}
		// Open's step 4 refuses exactly the rk decodeRK refuses, and with bad-rk (FS-C11).
		if !wellFormedItem(b) {
			return
		}
		fields := cloneFields(base)
		fields[keyRK] = b
		pt, merr := coredet.Marshal(fields)
		if merr != nil {
			return // an item the decoder takes but CoreDet does not write (indefinite length)
		}
		_, in, ierr := decodeInner(pt)
		switch {
		case err == nil && ierr != nil:
			t.Fatalf("inner with an accepted rk refused: %v", ierr)
		case err == nil && (in.RK == nil || in.RK.Suite != r.Suite || !bytes.Equal(in.RK.Pub, r.Pub)):
			t.Fatal("inner carries another rk than decodeRK read")
		case err != nil && ReasonOf(ierr) != ReasonBadRK:
			t.Fatalf("inner with a refused rk: %v, want %s", ierr, ReasonBadRK)
		}
	})
}

func FuzzOpenLayer2(f *testing.F) {
	fx := newFuzzFixture(f)
	key := fx.fuzzIXKey(f, "ix-fuzz", "fuzz/recipient-ix")
	otherIX := fx.fuzzIXKey(f, "ix-fuzz-other", "fuzz/recipient-ix-other")
	otherIX.Pub, otherIX.Private = key.Pub, key.Private // the same key, filed under another interaction (mode 2)
	for _, in := range fx.seedInners(f) {
		in2 := *in
		in2.IX = key.IX
		_, _, pt := fx.sealed(f, &in2, SealOpts{PeerRK: key.RK()})
		for mode := uint8(0); mode < 4; mode++ {
			f.Add(pt, true, mode)
		}
		f.Add(pt, false, uint8(0))
	}
	f.Fuzz(func(t *testing.T, pt []byte, resign bool, mode uint8) {
		mode %= 4
		// Both sender contexts first, as Seal sets them up: the signature covers enc, ikid and enc2.
		p := params(SuiteX25519)
		pk, _ := p.kem.NewPublicKey(fx.recipient.Public.Pub)
		info, _ := HPKEInfo(fx.self, SuiteX25519, fx.recipient.Public.KID)
		encKey, sender, err := hpke.NewSender(pk, p.kdf, p.aead, info)
		if err != nil {
			t.Fatal(err)
		}
		exported, err := sender.Export(DAckExporterContext, AckKeyLen)
		if err != nil {
			t.Fatal(err)
		}
		two, err := newLayer2Sender(fx.self, key.RK())
		if err != nil {
			t.Fatal(err)
		}
		if resign && mode != 1 {
			if fields, err := decodeFields(pt); err == nil {
				if pre, err := sigPreimage(fields, encKey, fx.recipient.Public.KID, SuiteX25519, two.ikid, two.enc2); err == nil {
					sig, _ := fx.sender.Sign(pre)
					fields[keySig] = enc(t, sig)
					pt = mustMarshal(t, fields)
				}
			}
		}
		ct2 := pt // mode 1: the fuzzed bytes are the layer-2 ciphertext
		if mode != 1 {
			if ct2, err = two.sender.Seal(nil, pt); err != nil {
				t.Fatal(err)
			}
		}
		m, _, err := (&wrapFields{ikid: two.ikid, enc2: two.enc2, body: ct2}).paddedMap()
		if err != nil {
			t.Fatal(err)
		}
		ct, err := sender.Seal(nil, mustMarshal(t, m))
		if err != nil {
			t.Fatal(err)
		}
		env, err := (&SealedEnvelope{V: EnvelopeVersion, To: fx.self, Suite: SuiteX25519,
			KID: fx.recipient.Public.KID, Enc: encKey, CT: ct, Access: session}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		var look IXKeyLookup = ixKeys{key}
		switch mode {
		case 2: // the lookup files the key under another interaction
			look = ixLookupFunc(func([]byte) (*IXKey, error) { return otherIX, nil })
		case 3: // the recipient no longer holds the key
			look = ixKeys{}
		}
		o, err := Open(env, fx.self, fx.ring, look)
		if err != nil {
			ack, ok := AckKeyOf(err)
			if !ok || !bytes.Equal(ack[:], exported) {
				t.Fatalf("%v: no ack_key, or not the layer-1 export", err)
			}
			if r := ReasonOf(err); (!openReasons[r] && r != ReasonIKeyMismatch) || !IsPermanent(err) {
				t.Fatalf("Open returned %v (reason %q) after layer 1", err, r)
			}
			switch {
			case mode == 3 && ReasonOf(err) != ReasonSealedToClosedInteraction:
				t.Fatalf("no key held, but %v", err)
			case mode == 1 && ReasonOf(err) != ReasonDecrypt:
				t.Fatalf("arbitrary layer-2 ciphertext, but %v", err)
			}
			return
		}
		switch mode {
		case 1:
			t.Fatal("arbitrary bytes opened as a second layer")
		case 3:
			t.Fatal("opened without the interaction key")
		}
		want := key
		if mode == 2 {
			want = otherIX
		}
		if o.Layers != 2 || !bytes.Equal(o.IKID, key.KID()) || !bytes.Equal(o.AckKey[:], exported) {
			t.Fatalf("opened %d layers, ikid %x", o.Layers, o.IKID)
		}
		// Accepted only under the interaction and peer the key that opened it is filed under.
		if o.Inner.IX != want.IX || o.Inner.From != want.PeerAID {
			t.Fatalf("opened ix %q from %s under the key of (%q, %s)", o.Inner.IX, o.Inner.From, want.IX, want.PeerAID)
		}
		fx.checkOpened(t, o)
	})
}
