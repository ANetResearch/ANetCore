package seal

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// A message sealed by A to B opens at B, passes every receive step this
// package implements, and yields the fields A put in.
func TestSealOpenRoundTrip(t *testing.T) {
	a, b := newParty(t), newParty(t)
	in := innerFrom(t, a, b, t0)
	in.Ext = map[uint64][]byte{64: enc(t, "ext-64"), 1000: enc(t, uint64(7))}
	env := mustSeal(t, in, &b.kp.Public, a.c.Sign)

	outer, err := ParseOuter(env)
	if err != nil {
		t.Fatalf("hub structural check: %v", err)
	}
	if outer.To != b.aid() || !bytes.Equal(outer.KID, b.kp.Public.KID) || outer.Suite != SuiteX25519 {
		t.Fatalf("outer header %+v", outer)
	}

	o := mustOpen(t, env, b)
	if err := CheckTime(&o.Inner, t0+60000); err != nil {
		t.Fatalf("time: %v", err)
	}
	if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000, DefaultRotationGrace); err != nil {
		t.Fatalf("signature: %v", err)
	}
	_, set, err := VerifyInnerKeys(&o.Inner, o.KEL, t0+60000)
	if err != nil {
		t.Fatalf("attached keys: %v", err)
	}
	if set.AID != a.aid() {
		t.Fatalf("attached key set AID %s", set.AID)
	}

	got := o.Inner
	if got.From != in.From || got.To != in.To || got.Type != in.Type || got.IX != in.IX ||
		!bytes.Equal(got.MID, in.MID) || got.TS != in.TS || got.Exp != in.Exp ||
		!bytes.Equal(got.Body, in.Body) || !bytes.Equal(got.KEL, in.KEL) ||
		!bytes.Equal(got.Keys, in.Keys) || got.KeyStateSeq != in.KeyStateSeq {
		t.Fatalf("inner changed in transit:\n got  %+v\n want %+v", got, *in)
	}
	if len(got.Ext) != 2 || !bytes.Equal(got.Ext[64], in.Ext[64]) || !bytes.Equal(got.Ext[1000], in.Ext[1000]) {
		t.Fatalf("extensions: got %v want %v", got.Ext, in.Ext)
	}
	// Seal must not write into the caller's struct.
	if in.Sig != nil || in.Pad != nil {
		t.Fatal("Seal modified its input")
	}
}

// Sealing the same inner twice gives different bytes: the HPKE sender key
// is fresh each time. Retries must resend the first
// bytes rather than reseal (§3.3), and this is why.
func TestSealIsRandomized(t *testing.T) {
	a, b := newParty(t), newParty(t)
	in := innerFrom(t, a, b, t0)
	e1 := mustSeal(t, in, &b.kp.Public, a.c.Sign)
	e2 := mustSeal(t, in, &b.kp.Public, a.c.Sign)
	if bytes.Equal(e1, e2) {
		t.Fatal("two seals of one inner produced identical envelopes")
	}
}

// Every signed inner field, altered after signing while the HPKE context is
// kept, is rejected. The hook runs inside the sender, after the signature,
// so the AEAD is valid and only the signature (or a structural rule) can
// catch the change.
func TestSignedInnerFieldMutations(t *testing.T) {
	a, b := newParty(t), newParty(t)
	// A second state with the same key, so a changed key_state_seq still
	// resolves to a key and only the preimage differs.
	if err := a.c.Delegate(make([]byte, 32), t0-dayMS); err != nil {
		t.Fatal(err)
	}
	a.resign(t, t0)
	other := newParty(t)

	longerKEL := func() []byte {
		// Same AID, different bytes: A's KEL extended by one more drt.
		cp, err := identity.Restore(mustExport(t, a.c))
		if err != nil {
			t.Fatal(err)
		}
		if err := cp.Delegate(bytes.Repeat([]byte{1}, 32), t0-dayMS+1); err != nil {
			t.Fatal(err)
		}
		k, err := identity.MarshalKEL(cp.KEL())
		if err != nil {
			t.Fatal(err)
		}
		return k
	}()
	newerKeys := func() []byte {
		set := *a.set
		set.Seq++
		s, err := SignEncKeySet(&set, a.c.Sign)
		if err != nil {
			t.Fatal(err)
		}
		b, err := s.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}()

	cases := []struct {
		name       string
		key        uint64
		value      any
		openReason string // reason Open must fail with; "" means Open succeeds
		sigReason  string // reason VerifyInnerSig must fail with
	}{
		{"from", keyFrom, other.aid(), "", ReasonFromMismatch},
		{"seq", keySeq, uint64(0), "", ReasonBadSig},
		{"to", keyTo, other.aid(), ReasonToMismatch, ""},
		{"type", keyType, TypeResult, "", ReasonBadSig},
		{"ix", keyIX, "ix-2", "", ReasonBadSig},
		{"mid", keyMID, bytes.Repeat([]byte{9}, MIDLen), "", ReasonBadSig},
		{"ts", keyTS, t0 - 1, "", ReasonBadSig},
		{"exp", keyExp, t0 + dayMS + 1, "", ReasonBadSig},
		{"body", keyBody, []byte("hellp"), "", ReasonBadSig},
		{"kel", keyKEL, longerKEL, "", ReasonBadSig},
		{"keys", keyKeys, newerKeys, "", ReasonBadSig},
		{"sig", keySig, bytes.Repeat([]byte{7}, SigLen), "", ReasonBadSig},
		{"ext-64", 64, "ext-changed", "", ReasonBadSig},
		{"ext-added", 70, "added-after-signing", "", ReasonBadSig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := innerFrom(t, a, b, t0)
			in.Ext = map[uint64][]byte{64: enc(t, "ext")}
			env, err := seal(in, &b.kp.Public, a.c.Sign, func(m fieldMap) { m[tc.key] = enc(t, tc.value) })
			if err != nil {
				t.Fatal(err)
			}
			o, err := Open(env, b.aid(), b.ring())
			if tc.openReason != "" {
				wantReason(t, err, tc.openReason)
				return
			}
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			// Verify against the sender's real KEL, as step 6 would resolve
			// it from storage; for the kel case the carried KEL is the
			// mutated one and must not rescue the signature either.
			wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, a.c.KEL(), t0+60000, DefaultRotationGrace), tc.sigReason)
			wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000, DefaultRotationGrace), tc.sigReason)
		})
	}

	// Control: the same hook writing the original value back verifies. This
	// shows the rejections above come from the change, not from the hook.
	in := innerFrom(t, a, b, t0)
	env, err := seal(in, &b.kp.Public, a.c.Sign, func(m fieldMap) { m[keyIX] = enc(t, in.IX) })
	if err != nil {
		t.Fatal(err)
	}
	o := mustOpen(t, env, b)
	if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000, DefaultRotationGrace); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func mustExport(t *testing.T, c *identity.Controller) []byte {
	t.Helper()
	b, err := c.Export()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The outer header fields are covered by the signature preimage. A party
// that decrypted a message (the recipient) and re-encrypts the same signed
// plaintext under a new HPKE context produces an envelope that opens but does
// not verify.
func TestOuterFieldsAreSigned(t *testing.T) {
	a, b, c := newParty(t), newParty(t), newParty(t)
	env := mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign)
	fields := decryptFields(t, env, b.kp)

	t.Run("enc", func(t *testing.T) {
		// Same recipient, same key, fresh enc.
		re := encryptFields(t, fields, b.aid(), &b.kp.Public)
		o := mustOpen(t, re, b)
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000, DefaultRotationGrace), ReasonBadSig)
	})
	t.Run("kid", func(t *testing.T) {
		// Same recipient, its second key.
		kp2, err := GenerateKeyPair(SuiteX25519, t0-dayMS, t0+13*dayMS)
		if err != nil {
			t.Fatal(err)
		}
		re := encryptFields(t, fields, b.aid(), &kp2.Public)
		o, err := Open(re, b.aid(), StaticKeyRing{b.kp, kp2})
		if err != nil {
			t.Fatal(err)
		}
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000, DefaultRotationGrace), ReasonBadSig)
	})
	t.Run("to", func(t *testing.T) {
		// B forwards A's message to C, rewriting to on both layers.
		fwd := make(fieldMap, len(fields))
		for k, v := range fields {
			fwd[k] = v
		}
		fwd[keyTo] = enc(t, c.aid())
		re := encryptFields(t, fwd, c.aid(), &c.kp.Public)
		o := mustOpen(t, re, c)
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000, DefaultRotationGrace), ReasonBadSig)
		// Without rewriting inner to, C's Open rejects it.
		re = encryptFields(t, fields, c.aid(), &c.kp.Public)
		_, err := Open(re, c.aid(), c.ring())
		wantReason(t, err, ReasonToMismatch)
	})
	t.Run("suite", func(t *testing.T) {
		// Only suite 1 exists, so a re-encryption under another suite cannot
		// be built. Two checks instead: an envelope naming suite 2 is refused
		// before decryption, and the preimage for suite 2 differs, so a
		// signature made for suite 1 does not verify under it.
		outer, err := ParseOuter(env)
		if err != nil {
			t.Fatal(err)
		}
		outer.Suite = SuiteXWing
		b2, err := outer.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		_, err = Open(b2, b.aid(), b.ring())
		wantReason(t, err, ReasonUnknownSuite)

		o := mustOpen(t, env, b)
		pre2, err := sigPreimage(fields, o.Outer.Enc, o.Outer.KID, SuiteXWing)
		if err != nil {
			t.Fatal(err)
		}
		wantReason(t, VerifyInnerSig(&o.Inner, pre2, o.KEL, t0+60000, DefaultRotationGrace), ReasonBadSig)
	})
	t.Run("outer-header-edit", func(t *testing.T) {
		// Editing enc or kid in the outer without re-encrypting breaks the
		// HPKE key schedule.
		outer, _ := ParseOuter(env)
		for name, edit := range map[string]func(*SealedEnvelope){
			"enc": func(e *SealedEnvelope) { e.Enc = append([]byte(nil), e.Enc...); e.Enc[0] ^= 1 },
			"ct":  func(e *SealedEnvelope) { e.CT = append([]byte(nil), e.CT...); e.CT[0] ^= 1 },
		} {
			e := *outer
			edit(&e)
			bb, _ := e.Marshal()
			_, err := Open(bb, b.aid(), b.ring())
			if ReasonOf(err) != ReasonDecrypt {
				t.Errorf("%s edit: want %s, got %v", name, ReasonDecrypt, err)
			}
		}
		e := *outer
		e.KID = bytes.Repeat([]byte{3}, KIDLen)
		bb, _ := e.Marshal()
		_, err := Open(bb, b.aid(), b.ring())
		wantReason(t, err, ReasonUnknownKey)
	})
}

// Keys 0-63 are must-understand; keys >= 64 are skipped by the receiver but
// signed by the sender.
func TestInnerKeySpace(t *testing.T) {
	a, b := newParty(t), newParty(t)
	for _, k := range []uint64{0, 11, 13, 19, 22, 30, 31, 32, 63} {
		env, err := seal(innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, func(m fieldMap) { m[k] = enc(t, "x") })
		if err != nil {
			t.Fatal(err)
		}
		_, err = Open(env, b.aid(), b.ring())
		if ReasonOf(err) != ReasonUnknownField {
			t.Errorf("key %d: want %s, got %v", k, ReasonUnknownField, err)
		}
	}
	for _, k := range []uint64{64, 65, 1 << 20} {
		in := innerFrom(t, a, b, t0)
		in.Ext = map[uint64][]byte{k: enc(t, "x")}
		env := mustSeal(t, in, &b.kp.Public, a.c.Sign)
		o := mustOpen(t, env, b)
		if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000, DefaultRotationGrace); err != nil {
			t.Errorf("key %d: %v", k, err)
		}
		if !bytes.Contains(o.Preimage, enc(t, "x")) {
			t.Errorf("key %d: value not in the signature preimage", k)
		}
	}
	// Seal refuses an extension below 64: it would be rejected on arrival.
	in := innerFrom(t, a, b, t0)
	in.Ext = map[uint64][]byte{63: enc(t, "x")}
	_, err := Seal(in, &b.kp.Public, a.c.Sign)
	wantReason(t, err, ReasonInvalidInput)
}

// Structural failures of the inner map.
func TestInnerStructure(t *testing.T) {
	a, b := newParty(t), newParty(t)
	cases := []struct {
		name   string
		hook   func(fieldMap)
		reason string
	}{
		{"missing from", func(m fieldMap) { delete(m, keyFrom) }, ReasonBadInner},
		{"missing keys", func(m fieldMap) { delete(m, keyKeys) }, ReasonBadInner},
		{"missing sig", func(m fieldMap) { delete(m, keySig) }, ReasonBadInner},
		{"from as bytes", func(m fieldMap) { m[keyFrom] = enc(t, []byte("x")) }, ReasonBadInner},
		{"ts as text", func(m fieldMap) { m[keyTS] = enc(t, "1") }, ReasonBadInner},
		{"body null", func(m fieldMap) { m[keyBody] = []byte{0xf6} }, ReasonBadInner},
		// A CBOR null decodes into a Go string or integer as "" or 0 without
		// error; the major-type checks keep null apart from those values.
		{"type null", func(m fieldMap) { m[keyType] = []byte{0xf6} }, ReasonBadInner},
		{"ix null", func(m fieldMap) { m[keyIX] = []byte{0xf6} }, ReasonBadInner},
		{"seq null", func(m fieldMap) { m[keySeq] = []byte{0xf6} }, ReasonBadInner},
		{"exp null", func(m fieldMap) { m[keyExp] = []byte{0xf6} }, ReasonBadInner},
		{"pad null", func(m fieldMap) { m[keyPad] = []byte{0xf6} }, ReasonBadInner},
		{"mid 15 bytes", func(m fieldMap) { m[keyMID] = enc(t, make([]byte, 15)) }, ReasonBadInner},
		{"sig 63 bytes", func(m fieldMap) { m[keySig] = enc(t, make([]byte, 63)) }, ReasonBadInner},
		{"pad non-zero", func(m fieldMap) { m[keyPad] = enc(t, []byte{0, 0, 1}) }, ReasonBadPad},
		{"kel garbage", func(m fieldMap) { m[keyKEL] = enc(t, []byte{0x01}) }, ReasonBadKEL},
		{"kel over byte cap", func(m fieldMap) { m[keyKEL] = enc(t, make([]byte, MaxKELBytes+1)) }, ReasonKELTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, err := seal(innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, tc.hook)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Open(env, b.aid(), b.ring())
			wantReason(t, err, tc.reason)
		})
	}

	// The pad is outside the signature: a different all-zero pad length
	// still verifies.
	env, err := seal(innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, func(m fieldMap) { m[keyPad] = enc(t, make([]byte, 3)) })
	if err != nil {
		t.Fatal(err)
	}
	o := mustOpen(t, env, b)
	if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000, DefaultRotationGrace); err != nil {
		t.Fatalf("pad must not be signed: %v", err)
	}
	// And an absent pad is accepted (the field is optional on receive).
	env, err = seal(innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, func(m fieldMap) { delete(m, keyPad) })
	if err != nil {
		t.Fatal(err)
	}
	o = mustOpen(t, env, b)
	if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000, DefaultRotationGrace); err != nil {
		t.Fatalf("absent pad: %v", err)
	}
}

func TestOpenRecipientAndKey(t *testing.T) {
	a, b, c := newParty(t), newParty(t), newParty(t)
	env := mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign)

	_, err := Open(env, c.aid(), b.ring())
	wantReason(t, err, ReasonWrongRecipient)

	_, err = Open(env, b.aid(), StaticKeyRing{})
	wantReason(t, err, ReasonUnknownKey)

	_, err = Open(env, b.aid(), c.ring())
	wantReason(t, err, ReasonUnknownKey)

	// A ring that answers for the kid with the wrong private key.
	wrong := &KeyPair{Public: b.kp.Public, Private: c.kp.Private}
	_, err = Open(env, b.aid(), StaticKeyRing{wrong})
	wantReason(t, err, ReasonDecrypt)

	// A ring that answers with a key whose kid differs from the one asked.
	liar := keyRingFunc(func([]byte) (*KeyPair, bool) { return c.kp, true })
	_, err = Open(env, b.aid(), liar)
	wantReason(t, err, ReasonUnknownKey)
}

type keyRingFunc func([]byte) (*KeyPair, bool)

func (f keyRingFunc) Key(kid []byte) (*KeyPair, bool) { return f(kid) }

func TestParseOuter(t *testing.T) {
	a, b := newParty(t), newParty(t)
	env := mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign)
	base, err := decodeFields(env)
	if err != nil {
		t.Fatal(err)
	}
	with := func(edit func(fieldMap)) []byte {
		m := make(fieldMap, len(base))
		for k, v := range base {
			m[k] = v
		}
		edit(m)
		out, err := coredet.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	cases := []struct {
		name   string
		env    []byte
		reason string
	}{
		{"ok", env, ""},
		{"ignorable key 64", with(func(m fieldMap) { m[64] = enc(t, "x") }), ""},
		{"v 2", with(func(m fieldMap) { m[outerKeyV] = enc(t, uint64(2)) }), ReasonBadVersion},
		{"v missing", with(func(m fieldMap) { delete(m, outerKeyV) }), ReasonBadOuter},
		{"reserved key 7", with(func(m fieldMap) { m[7] = enc(t, []byte("token")) }), ReasonUnknownField},
		{"key 0", with(func(m fieldMap) { m[0] = enc(t, "x") }), ReasonUnknownField},
		{"suite 2", with(func(m fieldMap) { m[outerKeySuite] = enc(t, uint64(2)) }), ReasonUnknownSuite},
		{"suite 257", with(func(m fieldMap) { m[outerKeySuite] = enc(t, uint64(257)) }), ReasonUnknownSuite},
		{"kid 15", with(func(m fieldMap) { m[outerKeyKID] = enc(t, make([]byte, 15)) }), ReasonBadOuter},
		{"enc 31", with(func(m fieldMap) { m[outerKeyEnc] = enc(t, make([]byte, 31)) }), ReasonBadOuter},
		{"enc 33", with(func(m fieldMap) { m[outerKeyEnc] = enc(t, make([]byte, 33)) }), ReasonBadOuter},
		{"ct empty", with(func(m fieldMap) { m[outerKeyCT] = enc(t, []byte{}) }), ReasonBadOuter},
		{"ct missing", with(func(m fieldMap) { delete(m, outerKeyCT) }), ReasonBadOuter},
		{"to empty", with(func(m fieldMap) { m[outerKeyTo] = enc(t, "") }), ReasonBadOuter},
		{"to as bytes", with(func(m fieldMap) { m[outerKeyTo] = enc(t, []byte(b.aid())) }), ReasonBadOuter},
		{"to null", with(func(m fieldMap) { m[outerKeyTo] = []byte{0xf6} }), ReasonBadOuter},
		{"suite null", with(func(m fieldMap) { m[outerKeySuite] = []byte{0xf6} }), ReasonBadOuter},
		{"v null", with(func(m fieldMap) { m[outerKeyV] = []byte{0xf6} }), ReasonBadOuter},
		{"null", []byte{0xf6}, ReasonBadOuter},
		{"empty", nil, ReasonBadOuter},
		{"trailing byte", append(append([]byte(nil), env...), 0), ReasonBadOuter},
		{"text key", []byte{0xa1, 0x61, 0x61, 0x01}, ReasonBadOuter},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseOuter(tc.env)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				return
			}
			wantReason(t, err, tc.reason)
		})
	}
}

func TestCheckTime(t *testing.T) {
	in := func(ts, exp uint64) *SealedInner { return &SealedInner{TS: ts, Exp: exp} }
	cases := []struct {
		name   string
		inner  *SealedInner
		now    uint64
		reason string
	}{
		{"inside", in(t0, t0+dayMS), t0 + 1, ""},
		{"now == exp", in(t0, t0+dayMS), t0 + dayMS, ""},
		{"now > exp", in(t0, t0+dayMS), t0 + dayMS + 1, ReasonExpired},
		{"ts at skew limit", in(t0+ClockSkewMS, t0+dayMS), t0, ""},
		{"ts past skew limit", in(t0+ClockSkewMS+1, t0+dayMS), t0, ReasonFromFuture},
		{"lifetime at limit", in(t0, t0+MaxMessageLifetimeMS), t0, ""},
		{"lifetime over limit", in(t0, t0+MaxMessageLifetimeMS+1), t0, ReasonBadLifetime},
		{"exp before ts", in(t0, t0-1), t0 - 2, ReasonBadLifetime},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckTime(tc.inner, tc.now)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				return
			}
			wantReason(t, err, tc.reason)
		})
	}
}

// §3.6 step 7 with identity.Controller.Rotate.
func TestRotationGrace(t *testing.T) {
	b := newParty(t)
	const rot = t0 + 10*minuteMS
	grace := time.Hour
	graceMS := uint64(grace.Milliseconds())

	// sealBefore seals from a fresh A at key state 0 with ts, then rotates A
	// at rotTS and returns the opened message and A's KEL after rotation.
	sealBefore := func(t *testing.T, ts, rotTS uint64, between func(*identity.Controller)) (*Opened, []identity.SignedEvent) {
		t.Helper()
		a := newParty(t)
		if between != nil {
			between(a.c)
			a.resign(t, t0)
		}
		env := mustSeal(t, innerFrom(t, a, b, ts), &b.kp.Public, a.c.Sign)
		if err := a.c.Rotate(rotTS); err != nil {
			t.Fatal(err)
		}
		return mustOpen(t, env, b), a.c.KEL()
	}

	t.Run("old key inside grace", func(t *testing.T) {
		o, kel := sealBefore(t, t0, rot, nil)
		if err := VerifyInnerSig(&o.Inner, o.Preimage, kel, rot+graceMS, grace); err != nil {
			t.Fatalf("at the grace limit: %v", err)
		}
		if err := VerifyInnerSig(&o.Inner, o.Preimage, kel, rot-1, grace); err != nil {
			t.Fatalf("before the rotation by our clock: %v", err)
		}
	})
	t.Run("old key past grace", func(t *testing.T) {
		o, kel := sealBefore(t, t0, rot, nil)
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, kel, rot+graceMS+1, grace), ReasonGraceExpired)
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, kel, rot+1, 0), ReasonGraceExpired)
	})
	t.Run("old key, ts not before rotation", func(t *testing.T) {
		o, kel := sealBefore(t, rot, rot, nil)
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, kel, rot+1, grace), ReasonRevokedKey)
	})
	t.Run("rotation without timestamp", func(t *testing.T) {
		o, kel := sealBefore(t, t0, 0, nil)
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, kel, t0+1, grace), ReasonRevokedKey)
	})
	t.Run("carried KEL predates rotation, stored KEL does not", func(t *testing.T) {
		// The message verifies under the KEL it carries (top state at the
		// time) and is still subject to the grace rule under the resolved
		// longer KEL; step 6 passes the resolved one.
		o, kel := sealBefore(t, t0, rot, nil)
		if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, rot+graceMS+1, grace); err != nil {
			t.Fatalf("under the carried KEL: %v", err)
		}
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, kel, rot+graceMS+1, grace), ReasonGraceExpired)
	})
	t.Run("new key after rotation", func(t *testing.T) {
		a := newParty(t)
		if err := a.c.Rotate(rot); err != nil {
			t.Fatal(err)
		}
		a.resign(t, rot)
		o := mustOpen(t, mustSeal(t, innerFrom(t, a, b, rot+1), &b.kp.Public, a.c.Sign), b)
		if err := VerifyInnerSig(&o.Inner, o.Preimage, a.c.KEL(), rot+10*dayMS, grace); err != nil {
			t.Fatalf("current key: %v", err)
		}
	})
	t.Run("drt between signing state and rotation", func(t *testing.T) {
		// icp -> drt -> rot, message signed at seq 1 (the drt state, same
		// key as icp). The retirement is read from the rot at seq 2.
		withDrt := func(c *identity.Controller) {
			if err := c.Delegate(make([]byte, 32), t0-dayMS); err != nil {
				t.Fatal(err)
			}
		}
		o, kel := sealBefore(t, t0, rot, withDrt)
		if o.Inner.KeyStateSeq != 1 {
			t.Fatalf("setup: signed at %d", o.Inner.KeyStateSeq)
		}
		if err := VerifyInnerSig(&o.Inner, o.Preimage, kel, rot+graceMS, grace); err != nil {
			t.Fatalf("inside grace: %v", err)
		}
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, kel, rot+graceMS+1, grace), ReasonGraceExpired)
	})
	t.Run("drt between icp state and rotation, signed at icp", func(t *testing.T) {
		// icp -> drt -> rot, message signed at seq 0. The drt between the
		// signing state and the rotation must not hide the retirement
		// (identity.Replay, A2A-DESIGN §3.6 [C4a]).
		a := newParty(t)
		in := innerFrom(t, a, b, rot) // ts not before the rotation
		env := mustSeal(t, in, &b.kp.Public, a.c.Sign)
		if err := a.c.Delegate(make([]byte, 32), t0); err != nil {
			t.Fatal(err)
		}
		if err := a.c.Rotate(rot); err != nil {
			t.Fatal(err)
		}
		o := mustOpen(t, env, b)
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, a.c.KEL(), rot+1, grace), ReasonRevokedKey)

		a2 := newParty(t)
		env = mustSeal(t, innerFrom(t, a2, b, t0), &b.kp.Public, a2.c.Sign)
		if err := a2.c.Delegate(make([]byte, 32), t0); err != nil {
			t.Fatal(err)
		}
		if err := a2.c.Rotate(rot); err != nil {
			t.Fatal(err)
		}
		o = mustOpen(t, env, b)
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, a2.c.KEL(), rot+graceMS+1, grace), ReasonGraceExpired)
		if err := VerifyInnerSig(&o.Inner, o.Preimage, a2.c.KEL(), rot+graceMS, grace); err != nil {
			t.Fatalf("inside grace: %v", err)
		}
	})
	t.Run("deactivated", func(t *testing.T) {
		a := newParty(t)
		if err := a.c.Deactivate(rot); err != nil {
			t.Fatal(err)
		}
		// Signed at the dip state itself: no key is in force.
		in := innerFrom(t, a, b, rot+1)
		env := mustSeal(t, in, &b.kp.Public, a.c.Sign)
		o := mustOpen(t, env, b)
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, a.c.KEL(), rot+2, grace), ReasonRevokedKey)
	})
}

func TestVerifyInnerSigInputs(t *testing.T) {
	a, b, c := newParty(t), newParty(t), newParty(t)
	o := mustOpen(t, mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign), b)

	// Another identity's KEL.
	wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, c.c.KEL(), t0, DefaultRotationGrace), ReasonFromMismatch)
	// A KEL that does not replay.
	bad := append([]identity.SignedEvent(nil), a.c.KEL()...)
	bad[0].Sig = make([]byte, 64)
	wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, bad, t0, DefaultRotationGrace), ReasonBadKEL)
	wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, nil, t0, DefaultRotationGrace), ReasonBadKEL)
	// Declared seq beyond the KEL.
	in := o.Inner
	in.KeyStateSeq = 5
	wantReason(t, VerifyInnerSig(&in, o.Preimage, a.c.KEL(), t0, DefaultRotationGrace), ReasonBadKeyState)
	// ts 0 is refused rather than handed to the weaker "unknown time" gate.
	in = o.Inner
	in.TS = 0
	wantReason(t, VerifyInnerSig(&in, o.Preimage, a.c.KEL(), t0, DefaultRotationGrace), ReasonBadInner)
}

// Seal refuses an inner its receiver would refuse for structural reasons,
// and a signer whose key state moved.
func TestSealInputChecks(t *testing.T) {
	a, b := newParty(t), newParty(t)
	cases := []struct {
		name string
		edit func(*SealedInner)
	}{
		{"no from", func(in *SealedInner) { in.From = "" }},
		{"no to", func(in *SealedInner) { in.To = "" }},
		{"no type", func(in *SealedInner) { in.Type = "" }},
		{"mid 8", func(in *SealedInner) { in.MID = in.MID[:8] }},
		{"ts 0", func(in *SealedInner) { in.TS = 0 }},
		{"exp before ts", func(in *SealedInner) { in.Exp = in.TS - 1 }},
		{"lifetime too long", func(in *SealedInner) { in.Exp = in.TS + MaxMessageLifetimeMS + 1 }},
		{"no keys", func(in *SealedInner) { in.Keys = nil }},
		{"no kel", func(in *SealedInner) { in.KEL = nil }},
		{"seq not the signer's", func(in *SealedInner) { in.KeyStateSeq = 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := innerFrom(t, a, b, t0)
			tc.edit(in)
			_, err := Seal(in, &b.kp.Public, a.c.Sign)
			wantReason(t, err, ReasonInvalidInput)
		})
	}
	// A recipient key whose kid does not match its public key.
	k := b.kp.Public
	k.KID = bytes.Repeat([]byte{1}, KIDLen)
	_, err := Seal(innerFrom(t, a, b, t0), &k, a.c.Sign)
	wantReason(t, err, ReasonInvalidInput)
	// A recipient key of an unimplemented suite.
	k2 := NewEncKey(SuiteXWing, make([]byte, 1216), t0, t0+dayMS)
	_, err = Seal(innerFrom(t, a, b, t0), &k2, a.c.Sign)
	wantReason(t, err, ReasonUnknownSuite)
}

func TestParseKELCaps(t *testing.T) {
	// 257 events that decode; they are not a valid KEL, but the count cap
	// applies before any replay.
	events := make([]identity.SignedEvent, MaxKELEvents+1)
	b, err := identity.MarshalKEL(events)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxKELBytes {
		t.Fatalf("setup: %d bytes exceeds the byte cap", len(b))
	}
	_, err = ParseKEL(b)
	wantReason(t, err, ReasonKELTooLarge)

	b, err = identity.MarshalKEL(events[:MaxKELEvents])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKEL(b); err != nil {
		t.Fatalf("256 events: %v", err)
	}

	_, err = ParseKEL(make([]byte, MaxKELBytes+1))
	wantReason(t, err, ReasonKELTooLarge)
	_, err = ParseKEL([]byte{0x80})
	wantReason(t, err, ReasonBadKEL)
}

func TestErrorClassification(t *testing.T) {
	a, b := newParty(t), newParty(t)
	env := mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign)
	_, err := Open(env, b.aid(), StaticKeyRing{})
	var se *Error
	if !errors.As(err, &se) || se.Reason != ReasonUnknownKey || !se.Permanent() || !IsPermanent(err) {
		t.Fatalf("want permanent *Error %s, got %#v", ReasonUnknownKey, err)
	}
	if IsPermanent(errors.New("other")) || ReasonOf(errors.New("other")) != "" || ReasonOf(nil) != "" {
		t.Fatal("foreign errors must not classify")
	}
	if (&Error{Reason: ReasonInternalError}).Permanent() {
		t.Fatal("internal errors are not a property of the input")
	}
	// The identity error stays reachable for callers that want its detail.
	o := mustOpen(t, env, b)
	err = VerifyInnerSig(&o.Inner, o.Preimage[:len(o.Preimage)-1], a.c.KEL(), t0, DefaultRotationGrace)
	var ve *identity.VErr
	if !errors.As(err, &ve) || ve.Reason != "INVALID_SIGNATURE" {
		t.Fatalf("want wrapped identity.VErr, got %v", err)
	}
}
