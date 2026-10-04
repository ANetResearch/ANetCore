package seal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/fxamacker/cbor/v2"
)

// A message sealed by A to B opens at B, passes every receive step this
// package implements, and yields the fields A put in, with the ack_key Seal
// returned.
func TestSealOpenRoundTrip(t *testing.T) {
	a, b := newParty(t), newParty(t)
	in := innerFrom(t, a, b, t0)
	in.Ext = map[uint64][]byte{64: enc(t, "ext-64"), 1000: enc(t, uint64(7))}
	in.Grant = testGrant
	rkPub := bytes.Repeat([]byte{9}, 32)
	in.RK = &RK{Suite: SuiteX25519, Pub: rkPub}
	sealed, ack, err := Seal(in, &b.kp.Public, a.c.Sign, SealOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOuter(sealed); ReasonOf(err) != ReasonAccessInvalid {
		t.Fatalf("Seal's output has no access yet; ParseOuter: %v", err)
	}
	env := withSession(t, sealed)

	outer, err := ParseOuter(env)
	if err != nil {
		t.Fatalf("hub structural check: %v", err)
	}
	if outer.V != 2 || outer.To != b.aid() || !bytes.Equal(outer.KID, b.kp.Public.KID) || outer.Suite != SuiteX25519 ||
		outer.Access == nil || outer.Access.Kind != AccessKindSession || outer.Exp != nil {
		t.Fatalf("outer header %+v", outer)
	}

	o := mustOpen(t, env, b)
	if o.AckKey != ack || o.Layers != 1 || o.IKID != nil {
		t.Fatalf("ack_key, layers, ikid: %x %d %x; Seal gave %x", o.AckKey, o.Layers, o.IKID, ack)
	}
	if err := CheckTime(&o.Inner, t0+60000); err != nil {
		t.Fatalf("time: %v", err)
	}
	if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000); err != nil {
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
		!bytes.Equal(got.Keys, in.Keys) || got.KeyStateSeq != in.KeyStateSeq ||
		len(got.Notices) != 1 || !bytes.Equal(got.Notices[0], testNotice) ||
		!bytes.Equal(got.Grant, testGrant) || got.RK == nil || got.RK.Suite != SuiteX25519 || !bytes.Equal(got.RK.Pub, rkPub) {
		t.Fatalf("inner changed in transit:\n got  %+v\n want %+v", got, *in)
	}
	if len(got.Ext) != 2 || !bytes.Equal(got.Ext[64], in.Ext[64]) || !bytes.Equal(got.Ext[1000], in.Ext[1000]) {
		t.Fatalf("extensions: got %v want %v", got.Ext, in.Ext)
	}
	// CORE-A2: Opened names the credential, rk, notices and grant itself.
	if o.Access == nil || o.Access != o.Outer.Access || o.Access.Kind != AccessKindSession ||
		o.RK == nil || o.RK != o.Inner.RK || !bytes.Equal(o.RK.Pub, rkPub) ||
		len(o.Notices) != 1 || !bytes.Equal(o.Notices[0], testNotice) || !bytes.Equal(o.Grant, testGrant) {
		t.Fatalf("Opened access %+v, rk %+v, notices %x, grant %x", o.Access, o.RK, o.Notices, o.Grant)
	}
	// Seal must not write into the caller's struct.
	if in.Sig != nil {
		t.Fatal("Seal modified its input")
	}
}

// The keys a message type may leave out are left out, not written as empty
// values: a preview frame carries neither 10, 11, 12 nor 14 (core CORE-K5).
func TestOptionalInnerKeysStayAbsent(t *testing.T) {
	a, b := newParty(t), newParty(t)
	in := innerFrom(t, a, b, t0)
	in.KEL, in.Notices, in.Keys = nil, nil, nil
	in.RK = &RK{Suite: SuiteX25519, Pub: make([]byte, 32)}
	env := mustSeal(t, in, &b.kp.Public, a.c.Sign)
	fields := decryptFields(t, env, b.kp)
	for _, k := range []uint64{keyKEL, keyNotice, keyKeys, keyGrant} {
		if _, ok := fields[k]; ok {
			t.Errorf("key %d written though absent", k)
		}
	}
	o := mustOpen(t, env, b)
	if o.Inner.KEL != nil || o.Inner.Notices != nil || o.Inner.Keys != nil || o.Inner.Grant != nil || o.KEL != nil ||
		o.Notices != nil || o.Grant != nil {
		t.Fatalf("absent keys came back: %+v", o.Inner)
	}
	// The signature is still checkable under the sender's KEL from storage.
	if err := VerifyInnerSig(&o.Inner, o.Preimage, a.c.KEL(), t0+60000); err != nil {
		t.Fatal(err)
	}
}

// Sealing the same inner twice gives different bytes and a different
// ack_key: the HPKE sender key is fresh each time. Retries resend the first
// bytes rather than reseal, and this is why.
func TestSealIsRandomized(t *testing.T) {
	a, b := newParty(t), newParty(t)
	in := innerFrom(t, a, b, t0)
	e1, k1 := mustSealAck(t, in, &b.kp.Public, a.c.Sign, SealOpts{})
	e2, k2 := mustSealAck(t, in, &b.kp.Public, a.c.Sign, SealOpts{})
	if bytes.Equal(e1, e2) || k1 == k2 {
		t.Fatal("two seals of one inner produced identical envelopes or ack_keys")
	}
}

// Every signed inner field, altered after signing while the HPKE context is
// kept, is rejected. The hook runs inside the sender, after the signature,
// so the AEAD is valid and only the signature (or a structural rule) can
// catch the change.
func TestSignedInnerFieldMutations(t *testing.T) {
	a, b := newParty(t), newParty(t)
	// A second key state, so a changed key_state_seq still resolves to a key.
	if err := identitytest.Rotate(a.c, t0-dayMS); err != nil {
		t.Fatal(err)
	}
	a.resign(t, t0)
	other := newParty(t)

	longerKEL := func() []byte {
		// Same AID, different bytes: A's KEL extended by one more rot, after
		// the message, so only the bytes differ for the signature.
		cp, err := identity.Restore(mustExport(t, a.c))
		if err != nil {
			t.Fatal(err)
		}
		if err := identitytest.Rotate(cp, t0+1); err != nil {
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
		{"notice", keyNotice, [][]byte{[]byte("other notice")}, "", ReasonBadSig},
		{"keys", keyKeys, newerKeys, "", ReasonBadSig},
		{"grant", keyGrant, map[uint64]string{3: "elsewhere"}, "", ReasonBadSig},
		{"rk", keyRK, &RK{Suite: SuiteX25519, Pub: bytes.Repeat([]byte{8}, 32)}, "", ReasonBadSig},
		{"sig", keySig, bytes.Repeat([]byte{7}, SigLen), "", ReasonBadSig},
		{"ext-64", 64, "ext-changed", "", ReasonBadSig},
		{"ext-added", 70, "added-after-signing", "", ReasonBadSig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := innerFrom(t, a, b, t0)
			in.Ext = map[uint64][]byte{64: enc(t, "ext")}
			in.Grant = testGrant
			in.RK = &RK{Suite: SuiteX25519, Pub: make([]byte, 32)}
			env := sealHooked(t, in, &b.kp.Public, a.c.Sign, SealOpts{}, sealHooks{inner: func(m fieldMap) { m[tc.key] = enc(t, tc.value) }})
			o, err := Open(env, b.aid(), b.ring(), nil)
			if tc.openReason != "" {
				wantOpenFails(t, err, tc.openReason, true)
				return
			}
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			// Verify against the sender's real KEL, as step 6 would resolve
			// it from storage; for the kel case the carried KEL is the
			// mutated one and must not rescue the signature either.
			wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, a.c.KEL(), t0+60000), tc.sigReason)
			wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000), tc.sigReason)
		})
	}

	// Control: the same hook writing the original value back verifies. This
	// shows the rejections above come from the change, not from the hook.
	in := innerFrom(t, a, b, t0)
	env := sealHooked(t, in, &b.kp.Public, a.c.Sign, SealOpts{}, sealHooks{inner: func(m fieldMap) { m[keyIX] = enc(t, in.IX) }})
	o := mustOpen(t, env, b)
	if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000); err != nil {
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
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000), ReasonBadSig)
	})
	t.Run("kid", func(t *testing.T) {
		// Same recipient, its second key.
		kp2, err := GenerateKeyPair(SuiteX25519, t0-dayMS, t0+dayMS)
		if err != nil {
			t.Fatal(err)
		}
		re := encryptFields(t, fields, b.aid(), &kp2.Public)
		o, err := Open(re, b.aid(), StaticKeyRing{b.kp, kp2}, nil)
		if err != nil {
			t.Fatal(err)
		}
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000), ReasonBadSig)
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
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000), ReasonBadSig)
		// Without rewriting inner to, C's Open rejects it.
		re = encryptFields(t, fields, c.aid(), &c.kp.Public)
		_, err := Open(re, c.aid(), c.ring(), nil)
		wantOpenFails(t, err, ReasonToMismatch, true)
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
		_, err = Open(b2, b.aid(), b.ring(), nil)
		wantOpenFails(t, err, ReasonUnknownSuite, false)

		o := mustOpen(t, env, b)
		pre2, err := sigPreimage(fields, o.Outer.Enc, o.Outer.KID, SuiteXWing, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		wantReason(t, VerifyInnerSig(&o.Inner, pre2, o.KEL, t0+60000), ReasonBadSig)
	})
	t.Run("layering", func(t *testing.T) {
		// The same fields under a preimage that claims a second layer (SI-31):
		// the single-layer signature does not verify.
		o := mustOpen(t, env, b)
		pre2, err := sigPreimage(fields, o.Outer.Enc, o.Outer.KID, o.Outer.Suite, make([]byte, KIDLen), make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		wantReason(t, VerifyInnerSig(&o.Inner, pre2, o.KEL, t0+60000), ReasonBadSig)
	})
	t.Run("outer-header-edit", func(t *testing.T) {
		// Editing enc or ct in the outer without re-encrypting breaks the
		// HPKE key schedule.
		outer, _ := ParseOuter(env)
		for name, edit := range map[string]func(*SealedEnvelope){
			"enc": func(e *SealedEnvelope) { e.Enc = append([]byte(nil), e.Enc...); e.Enc[0] ^= 1 },
			"ct":  func(e *SealedEnvelope) { e.CT = append([]byte(nil), e.CT...); e.CT[0] ^= 1 },
		} {
			e := *outer
			edit(&e)
			bb, _ := e.Marshal()
			_, err := Open(bb, b.aid(), b.ring(), nil)
			if ReasonOf(err) != ReasonDecrypt {
				t.Errorf("%s edit: want %s, got %v", name, ReasonDecrypt, err)
			}
			if _, ok := AckKeyOf(err); ok {
				t.Errorf("%s edit: an ack_key before layer 1 opened", name)
			}
		}
		e := *outer
		e.KID = bytes.Repeat([]byte{3}, KIDLen)
		bb, _ := e.Marshal()
		_, err := Open(bb, b.aid(), b.ring(), nil)
		wantOpenFails(t, err, ReasonUnknownKey, false)
	})
}

// Keys 0-63 outside the v2 set are must-understand: the reserved keys, the
// retired 21 and the preimage-only 0 and 30-34. Keys >= 64 are skipped by
// the receiver but signed by the sender.
func TestInnerKeySpace(t *testing.T) {
	a, b := newParty(t), newParty(t)
	for _, k := range []uint64{0, 13, 16, 19, 21, 22, 29, 30, 31, 32, 33, 34, 35, 63} {
		env := sealHooked(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, SealOpts{}, sealHooks{inner: func(m fieldMap) { m[k] = enc(t, "x") }})
		_, err := Open(env, b.aid(), b.ring(), nil)
		if ReasonOf(err) != ReasonUnknownField {
			t.Errorf("key %d: want %s, got %v", k, ReasonUnknownField, err)
		}
		if _, ok := AckKeyOf(err); !ok {
			t.Errorf("key %d: no ack_key after layer 1", k)
		}
	}
	for _, k := range []uint64{64, 65, 1 << 20} {
		in := innerFrom(t, a, b, t0)
		in.Ext = map[uint64][]byte{k: enc(t, "x")}
		env := mustSeal(t, in, &b.kp.Public, a.c.Sign)
		o := mustOpen(t, env, b)
		if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0+60000); err != nil {
			t.Errorf("key %d: %v", k, err)
		}
		if !bytes.Contains(o.Preimage, enc(t, "x")) {
			t.Errorf("key %d: value not in the signature preimage", k)
		}
	}
	// Seal refuses an extension below 64: it would be rejected on arrival.
	in := innerFrom(t, a, b, t0)
	in.Ext = map[uint64][]byte{63: enc(t, "x")}
	_, _, err := Seal(in, &b.kp.Public, a.c.Sign, SealOpts{})
	wantReason(t, err, ReasonInvalidInput)
}

// Structural failures of the inner map: each the seal reason of receive step 4,
// with the ack_key (layer 1 opened).
func TestInnerStructure(t *testing.T) {
	a, b := newParty(t), newParty(t)
	notices := func(items ...any) []byte { return enc(t, items) }
	cases := []struct {
		name   string
		hook   func(fieldMap)
		reason string
	}{
		{"missing from", func(m fieldMap) { delete(m, keyFrom) }, ReasonBadInner},
		{"missing body", func(m fieldMap) { delete(m, keyBody) }, ReasonBadInner},
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
		{"kel null", func(m fieldMap) { m[keyKEL] = []byte{0xf6} }, ReasonBadInner},
		{"keys null", func(m fieldMap) { m[keyKeys] = []byte{0xf6} }, ReasonBadInner},
		{"mid 15 bytes", func(m fieldMap) { m[keyMID] = enc(t, make([]byte, 15)) }, ReasonBadInner},
		{"sig 63 bytes", func(m fieldMap) { m[keySig] = enc(t, make([]byte, 63)) }, ReasonBadInner},
		// CORE-K3, C-52: the notice goes exactly with the KEL.
		{"notice without kel", func(m fieldMap) { delete(m, keyKEL) }, ReasonBadInner},
		{"kel without notice", func(m fieldMap) { delete(m, keyNotice) }, ReasonBadInner},
		{"no notice in the array", func(m fieldMap) { m[keyNotice] = notices() }, ReasonBadInner},
		{"two notices", func(m fieldMap) { m[keyNotice] = notices([]byte("n1"), []byte("n2")) }, ReasonBadInner},
		{"notice as text", func(m fieldMap) { m[keyNotice] = notices("n") }, ReasonBadInner},
		{"notice not an array", func(m fieldMap) { m[keyNotice] = enc(t, []byte("n")) }, ReasonBadInner},
		{"notice over its cap", func(m fieldMap) { m[keyNotice] = notices(make([]byte, MaxNoticeBytes+1)) }, ReasonBadInner},
		// CORE-E9: from, to and ix carry no U+0000.
		{"from with NUL", func(m fieldMap) { m[keyFrom] = enc(t, a.aid()+"\x00") }, ReasonBadInner},
		{"to with NUL", func(m fieldMap) { m[keyTo] = enc(t, b.aid()+"\x00") }, ReasonBadInner},
		{"ix with NUL", func(m fieldMap) { m[keyIX] = enc(t, "a\x00b") }, ReasonBadInner},
		// FS-C11.
		{"rk suite 2", func(m fieldMap) { m[keyRK] = enc(t, map[uint64]any{1: uint64(2), 2: make([]byte, 32)}) }, ReasonBadRK},
		{"rk pub 31 bytes", func(m fieldMap) { m[keyRK] = enc(t, map[uint64]any{1: uint64(1), 2: make([]byte, 31)}) }, ReasonBadRK},
		{"rk without pub", func(m fieldMap) { m[keyRK] = enc(t, map[uint64]any{1: uint64(1)}) }, ReasonBadRK},
		{"rk with key 3", func(m fieldMap) { m[keyRK] = enc(t, map[uint64]any{1: uint64(1), 2: make([]byte, 32), 3: "x"}) }, ReasonBadRK},
		{"rk with key 64", func(m fieldMap) { m[keyRK] = enc(t, map[uint64]any{1: uint64(1), 2: make([]byte, 32), 64: "x"}) }, ReasonBadRK},
		{"rk as bytes", func(m fieldMap) { m[keyRK] = enc(t, make([]byte, 32)) }, ReasonBadRK},
		{"kel garbage", func(m fieldMap) { m[keyKEL] = enc(t, []byte{0x01}) }, ReasonBadKEL},
		{"kel over byte cap", func(m fieldMap) { m[keyKEL] = enc(t, make([]byte, MaxKELBytes+1)) }, ReasonKELTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := sealHooked(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, SealOpts{}, sealHooks{inner: tc.hook})
			_, err := Open(env, b.aid(), b.ring(), nil)
			wantOpenFails(t, err, tc.reason, true)
		})
	}

	// A grant is never a reason to refuse the message, whatever it holds
	// (CORE-K4): CheckGrant decides, later, whether to keep it.
	for name, v := range map[string][]byte{"text": enc(t, "not a grant"), "null": {0xf6}, "unknown keys": enc(t, map[uint64]string{99: "x"})} {
		env := sealHooked(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, SealOpts{}, sealHooks{inner: func(m fieldMap) { m[keyGrant] = v }})
		o, err := Open(env, b.aid(), b.ring(), nil)
		if err != nil {
			t.Fatalf("grant %s: %v", name, err)
		}
		if !bytes.Equal(o.Inner.Grant, v) {
			t.Fatalf("grant %s came back as %x", name, o.Inner.Grant)
		}
	}
}

// The Wrap rules of FS-C8, each bad-wrap with the ack_key; keys >= 64 are
// ignored; and the second-layer lookup (FS-C13) as far as this package goes
// before FS-2: no key is sealed-to-closed-interaction, a store failure comes
// back as it is.
func TestWrapDecodeRules(t *testing.T) {
	a, b := newParty(t), newParty(t)
	env := mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign)
	good, err := decodeFields(openLayer1(t, env, b.kp))
	if err != nil {
		t.Fatal(err)
	}
	with := func(edit func(fieldMap)) []byte {
		m := make(fieldMap, len(good))
		for k, v := range good {
			m[k] = v
		}
		edit(m)
		return encryptWrap(t, mustMarshalFields(t, m), b.aid(), &b.kp.Public)
	}
	open := func(env []byte, ix IXKeyLookup) error {
		_, err := Open(env, b.aid(), b.ring(), ix)
		return err
	}
	cases := []struct {
		name string
		edit func(fieldMap)
	}{
		{"key 0", func(m fieldMap) { m[0] = enc(t, "x") }},
		{"key 4", func(m fieldMap) { m[4] = enc(t, "x") }},
		{"key 5", func(m fieldMap) { m[5] = enc(t, "x") }},
		{"key 20", func(m fieldMap) { m[20] = enc(t, "x") }},
		{"key 22", func(m fieldMap) { m[22] = enc(t, "x") }},
		{"key 63", func(m fieldMap) { m[63] = enc(t, "x") }},
		{"body missing", func(m fieldMap) { delete(m, wrapKeyBody) }},
		{"body as text", func(m fieldMap) { m[wrapKeyBody] = enc(t, "x") }},
		{"pad missing", func(m fieldMap) { delete(m, wrapKeyPad) }},
		{"pad null", func(m fieldMap) { m[wrapKeyPad] = []byte{0xf6} }},
		{"pad not zero", func(m fieldMap) { m[wrapKeyPad] = enc(t, []byte{0, 0, 1}) }},
		{"ikid without enc2", func(m fieldMap) { m[wrapKeyIKID] = enc(t, make([]byte, KIDLen)) }},
		{"enc2 without ikid", func(m fieldMap) { m[wrapKeyEnc2] = enc(t, make([]byte, 32)) }},
		{"ikid 15 bytes", func(m fieldMap) {
			m[wrapKeyIKID], m[wrapKeyEnc2] = enc(t, make([]byte, KIDLen-1)), enc(t, make([]byte, 32))
		}},
		{"enc2 31 bytes", func(m fieldMap) {
			m[wrapKeyIKID], m[wrapKeyEnc2] = enc(t, make([]byte, KIDLen)), enc(t, make([]byte, 31))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantOpenFails(t, open(with(tc.edit), nil), ReasonBadWrap, true)
		})
	}
	t.Run("not a map", func(t *testing.T) {
		wantOpenFails(t, open(encryptWrap(t, enc(t, []byte("x")), b.aid(), &b.kp.Public), nil), ReasonBadWrap, true)
	})
	t.Run("key 64 is ignored", func(t *testing.T) {
		if err := open(with(func(m fieldMap) { m[64] = enc(t, "x") }), nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a pad of any length", func(t *testing.T) {
		// Receivers check that the pad is zero, not its length (FS-C9).
		for _, n := range []int{0, 1, 300} {
			if err := open(with(func(m fieldMap) { m[wrapKeyPad] = enc(t, make([]byte, n)) }), nil); err != nil {
				t.Fatalf("pad of %d: %v", n, err)
			}
		}
	})
	two := with(func(m fieldMap) {
		m[wrapKeyIKID], m[wrapKeyEnc2] = enc(t, bytes.Repeat([]byte{4}, KIDLen)), enc(t, make([]byte, 32))
	})
	t.Run("second layer, no lookup", func(t *testing.T) {
		wantOpenFails(t, open(two, nil), ReasonSealedToClosedInteraction, true)
	})
	t.Run("second layer, no such key", func(t *testing.T) {
		var asked []byte
		err := open(two, ixLookupFunc(func(ikid []byte) (*IXKey, error) { asked = ikid; return nil, nil }))
		wantOpenFails(t, err, ReasonSealedToClosedInteraction, true)
		if !bytes.Equal(asked, bytes.Repeat([]byte{4}, KIDLen)) {
			t.Fatalf("looked up %x", asked)
		}
	})
	t.Run("second layer, store failure", func(t *testing.T) {
		storeErr := errors.New("database is locked")
		err := open(two, ixLookupFunc(func([]byte) (*IXKey, error) { return nil, storeErr }))
		if errors.Unwrap(err) != storeErr || ReasonOf(err) != "" || IsPermanent(err) {
			t.Fatalf("store failure must come back as it is: %v (reason %q)", err, ReasonOf(err))
		}
		if _, ok := AckKeyOf(err); !ok {
			t.Fatal("store failure without the ack_key")
		}
	})
}

type ixLookupFunc func([]byte) (*IXKey, error)

func (f ixLookupFunc) IXKey(ikid []byte) (*IXKey, error) { return f(ikid) }

// The Wrap of every sealed message has a Padmé length (FS-C9), including
// inners whose natural offset is one of the unreachable ones, and the inner
// inside it is not padded.
func TestWrapIsPadded(t *testing.T) {
	a, b := newParty(t), newParty(t)
	hitUnreachable := false
	sizes := []int{0, 1, 2, 50, 100, 500, 1000, 1500, 4000, 70000}
	for n := 0; n < 1200; n++ {
		sizes = append(sizes, n)
	}
	for _, n := range sizes {
		in := innerFrom(t, a, b, t0)
		in.Body = make([]byte, n)
		fields, err := in.fieldMap()
		if err != nil {
			t.Fatal(err)
		}
		fields[keySig] = enc(t, make([]byte, SigLen))
		innerLen := encodedLen(fields)
		w := fieldMap{wrapKeyBody: enc(t, make([]byte, innerLen)), wrapKeyPad: []byte{0x40}}
		base := encodedLen(w)
		if _, ok := padLenFor(Padme(base) - base); !ok {
			hitUnreachable = true
		}

		env := mustSeal(t, in, &b.kp.Public, a.c.Sign)
		outer, err := ParseOuter(env)
		if err != nil {
			t.Fatal(err)
		}
		pt := len(outer.CT) - 16 // ChaCha20-Poly1305 tag
		if pt < base || Padme(pt) != pt {
			t.Fatalf("body %d: wrap is %d bytes (unpadded %d), not a Padmé length", n, pt, base)
		}
		if n < 1190 && n != 70000 {
			continue
		}
		wrap := openLayer1(t, env, b.kp)
		wf, err := decodeWrap(wrap)
		if err != nil {
			t.Fatal(err)
		}
		if len(wf.body) != innerLen {
			t.Fatalf("body %d: inner is %d bytes, unpadded %d", n, len(wf.body), innerLen)
		}
		o := mustOpen(t, env, b)
		if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0); err != nil {
			t.Fatalf("body %d: %v", n, err)
		}
	}
	if !hitUnreachable {
		t.Fatal("no size exercised an unreachable pad offset; widen the range")
	}
}

func TestOpenRecipientAndKey(t *testing.T) {
	a, b, c := newParty(t), newParty(t), newParty(t)
	env := mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign)

	_, err := Open(env, c.aid(), b.ring(), nil)
	wantOpenFails(t, err, ReasonWrongRecipient, false)

	_, err = Open(env, b.aid(), StaticKeyRing{}, nil)
	wantOpenFails(t, err, ReasonUnknownKey, false)

	_, err = Open(env, b.aid(), nil, nil)
	wantOpenFails(t, err, ReasonUnknownKey, false)

	_, err = Open(env, b.aid(), c.ring(), nil)
	wantOpenFails(t, err, ReasonUnknownKey, false)

	// A ring that answers for the kid with the wrong private key.
	wrong := &KeyPair{Public: b.kp.Public, Private: c.kp.Private}
	_, err = Open(env, b.aid(), StaticKeyRing{wrong}, nil)
	wantOpenFails(t, err, ReasonDecrypt, false)

	// A ring that answers with a key whose kid differs from the one asked.
	liar := keyRingFunc(func([]byte) (*KeyPair, bool) { return c.kp, true })
	_, err = Open(env, b.aid(), liar, nil)
	wantOpenFails(t, err, ReasonUnknownKey, false)
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
		return mustMarshalFields(t, m)
	}
	cases := []struct {
		name   string
		env    []byte
		reason string
	}{
		{"ok", env, ""},
		{"ignorable key 64", with(func(m fieldMap) { m[64] = enc(t, "x") }), ""},
		{"exp", with(func(m fieldMap) { m[outerKeyExp] = enc(t, t0) }), ""},
		{"v 1", with(func(m fieldMap) { m[outerKeyV] = enc(t, uint64(1)) }), ReasonBadVersion},
		{"v 3", with(func(m fieldMap) { m[outerKeyV] = enc(t, uint64(3)) }), ReasonBadVersion},
		{"v missing", with(func(m fieldMap) { delete(m, outerKeyV) }), ReasonBadOuter},
		{"key 0", with(func(m fieldMap) { m[0] = enc(t, "x") }), ReasonUnknownField},
		{"key 9", with(func(m fieldMap) { m[9] = enc(t, "x") }), ReasonUnknownField},
		{"key 63", with(func(m fieldMap) { m[63] = enc(t, "x") }), ReasonUnknownField},
		{"access missing", with(func(m fieldMap) { delete(m, outerKeyAccess) }), ReasonAccessInvalid},
		{"access null", with(func(m fieldMap) { m[outerKeyAccess] = []byte{0xf6} }), ReasonAccessInvalid},
		{"exp as text", with(func(m fieldMap) { m[outerKeyExp] = enc(t, "1") }), ReasonBadOuter},
		{"exp null", with(func(m fieldMap) { m[outerKeyExp] = []byte{0xf6} }), ReasonBadOuter},
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
			o, err := ParseOuter(tc.env)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				// An accepted outer encodes back to the same bytes, but for
				// the keys >= 64, which are not kept.
				back, err := o.Marshal()
				if err != nil {
					t.Fatal(err)
				}
				if tc.name != "ignorable key 64" && !bytes.Equal(back, tc.env) {
					t.Fatalf("re-encoded outer differs:\n %x\n %x", back, tc.env)
				}
				return
			}
			wantOpenFails(t, err, tc.reason, false)
		})
	}
}

// Outer key 7 (SSR-W5, CORE-K1): required, an Access of kind 0 without cap
// and proof or of kind 1 with both, nothing else; any other form is
// access-invalid with Detail "parse".
func TestParseOuterV2Access(t *testing.T) {
	a, b := newParty(t), newParty(t)
	sealed, _, err := Seal(innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, SealOpts{})
	if err != nil {
		t.Fatal(err)
	}
	base, err := decodeFields(sealed)
	if err != nil {
		t.Fatal(err)
	}
	withAccess := func(v any) []byte {
		m := make(fieldMap, len(base)+1)
		for k, x := range base {
			m[k] = x
		}
		m[outerKeyAccess] = enc(t, v)
		return mustMarshalFields(t, m)
	}
	sig := make([]byte, SigLen)
	capMap := map[uint64]any{1: []byte("cap body"), 2: sig}
	cases := []struct {
		name  string
		value any // nil: the key is absent
		ok    bool
	}{
		{"kind 0", map[uint64]any{1: uint64(0)}, true},
		{"kind 1", map[uint64]any{1: uint64(1), 2: capMap, 3: sig}, true},
		{"absent", nil, false},
		{"kind 2 (reserved)", map[uint64]any{1: uint64(2)}, false},
		{"kind 3", map[uint64]any{1: uint64(3)}, false},
		{"no kind", map[uint64]any{2: capMap, 3: sig}, false},
		{"kind as text", map[uint64]any{1: "0"}, false},
		{"kind 0 with a cap", map[uint64]any{1: uint64(0), 2: capMap}, false},
		{"kind 0 with a proof", map[uint64]any{1: uint64(0), 3: sig}, false},
		{"kind 1 without a proof", map[uint64]any{1: uint64(1), 2: capMap}, false},
		{"kind 1 without a cap", map[uint64]any{1: uint64(1), 3: sig}, false},
		{"proof 63 bytes", map[uint64]any{1: uint64(1), 2: capMap, 3: make([]byte, 63)}, false},
		{"cap sig 65 bytes", map[uint64]any{1: uint64(1), 2: map[uint64]any{1: []byte("b"), 2: make([]byte, 65)}, 3: sig}, false},
		{"cap body as text", map[uint64]any{1: uint64(1), 2: map[uint64]any{1: "b", 2: sig}, 3: sig}, false},
		{"cap with key 3", map[uint64]any{1: uint64(1), 2: map[uint64]any{1: []byte("b"), 2: sig, 3: "x"}, 3: sig}, false},
		{"key 4", map[uint64]any{1: uint64(0), 4: "x"}, false},
		{"key 9", map[uint64]any{1: uint64(0), 9: "x"}, false},
		{"key 64 (no extension range)", map[uint64]any{1: uint64(0), 64: "x"}, false},
		{"not a map", []byte{0}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := sealed
			if tc.value != nil {
				env = withAccess(tc.value)
			}
			o, err := ParseOuter(env)
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				if o.Access == nil {
					t.Fatal("no access")
				}
				return
			}
			wantOpenFails(t, err, ReasonAccessInvalid, false)
			var se *Error
			if !errors.As(err, &se) || se.Detail != "parse" {
				t.Fatalf("detail %q, want parse", se.Detail)
			}
		})
	}
}

// env_digest (L4) is computed as core §3.2 states it, with the label and key
// numbers written out here; it ignores key 7 and nothing else (SSR-W1).
func TestEnvDigestIgnoresOnlyKey7(t *testing.T) {
	a, b := newParty(t), newParty(t)
	in := innerFrom(t, a, b, t0)
	sealed, _, err := Seal(in, &b.kp.Public, a.c.Sign, SealOpts{Exp: in.Exp})
	if err != nil {
		t.Fatal(err)
	}
	base, err := decodeFields(sealed)
	if err != nil {
		t.Fatal(err)
	}
	base[64] = enc(t, "ext")
	sealed = mustMarshalFields(t, base)
	digest := func(env []byte) [32]byte {
		t.Helper()
		d, err := EnvDigest(env)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	want := sha256.Sum256(append([]byte("anet-env/v2\x00"), sealed...))
	d0 := digest(sealed)
	if d0 != want {
		t.Fatalf("env_digest %x, want SHA-256(label 0x00 outer) %x", d0, want)
	}
	kind1 := &Access{Kind: AccessKindCap, Cap: &Cap{Body: []byte("cap"), Sig: make([]byte, SigLen)}, Proof: make([]byte, SigLen)}
	for _, a := range []*Access{session, kind1} {
		env, err := SetAccess(sealed, a)
		if err != nil {
			t.Fatal(err)
		}
		if digest(env) != d0 {
			t.Fatalf("access kind %d changed env_digest", a.Kind)
		}
	}
	for _, k := range []uint64{outerKeyV, outerKeyTo, outerKeySuite, outerKeyKID, outerKeyEnc, outerKeyCT, outerKeyExp, 64} {
		m := make(fieldMap, len(base))
		for kk, v := range base {
			m[kk] = v
		}
		m[k] = append(cbor.RawMessage(nil), m[k]...)
		m[k][len(m[k])-1] ^= 1
		if digest(mustMarshalFields(t, m)) == d0 {
			t.Errorf("key %d changed, env_digest did not", k)
		}
		delete(m, k)
		if digest(mustMarshalFields(t, m)) == d0 {
			t.Errorf("key %d dropped, env_digest did not change", k)
		}
	}
	added := make(fieldMap, len(base)+1)
	for k, v := range base {
		added[k] = v
	}
	added[65] = enc(t, "added")
	if digest(mustMarshalFields(t, added)) == d0 {
		t.Error("a key >= 64 added, env_digest did not change")
	}
	if _, err := EnvDigest([]byte{0x01}); ReasonOf(err) != ReasonBadOuter {
		t.Fatalf("not a map: %v", err)
	}
}

// SetAccess writes or replaces key 7 and leaves every other byte as it was;
// it refuses a malformed access and never returns an envelope ParseOuter
// refuses.
func TestSetAccess(t *testing.T) {
	a, b := newParty(t), newParty(t)
	sealed, _, err := Seal(innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, SealOpts{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := decodeFields(sealed)
	if err != nil {
		t.Fatal(err)
	}
	m[64] = enc(t, "ext")
	sealed = mustMarshalFields(t, m)
	kind1 := &Access{Kind: AccessKindCap, Cap: &Cap{Body: []byte("cap"), Sig: make([]byte, SigLen)}, Proof: make([]byte, SigLen)}
	e1, err := SetAccess(sealed, session)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := SetAccess(e1, kind1)
	if err != nil {
		t.Fatal(err)
	}
	for name, env := range map[string][]byte{"set": e1, "replaced": e2} {
		got, err := decodeFields(env)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range m {
			if !bytes.Equal(got[k], v) {
				t.Fatalf("%s: key %d changed", name, k)
			}
		}
		if len(got) != len(m)+1 {
			t.Fatalf("%s: %d keys, want %d", name, len(got), len(m)+1)
		}
	}
	o, err := ParseOuter(e2)
	if err != nil || o.Access.Kind != AccessKindCap || !bytes.Equal(o.Access.Cap.Body, []byte("cap")) {
		t.Fatalf("replaced access: %+v %v", o, err)
	}
	// It still opens: key 7 is outside the signature and the HPKE info.
	if _, err := Open(e2, b.aid(), b.ring(), nil); err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string]*Access{
		"nil":                nil,
		"kind 2":             {Kind: 2},
		"kind 0 with a cap":  {Kind: 0, Cap: kind1.Cap},
		"kind 1 no proof":    {Kind: 1, Cap: kind1.Cap},
		"kind 1 short proof": {Kind: 1, Cap: kind1.Cap, Proof: make([]byte, 10)},
	} {
		_, err := SetAccess(sealed, a)
		wantReason(t, err, ReasonInvalidInput)
		_ = name
	}
	// A malformed envelope stays malformed.
	m[outerKeyV] = enc(t, uint64(1))
	_, err = SetAccess(mustMarshalFields(t, m), session)
	wantReason(t, err, ReasonBadVersion)
	_, err = SetAccess([]byte{0x01}, session)
	wantReason(t, err, ReasonBadOuter)
}

// Outer key 8 (CUX-E3, core G11): written only through SealOpts.Exp, which
// must equal the inner exp; on receipt it must equal the inner exp.
func TestOuterExp(t *testing.T) {
	a, b := newParty(t), newParty(t)
	in := innerFrom(t, a, b, t0)
	in.Type = "anet.card.get/1"
	env, ack := mustSealAck(t, in, &b.kp.Public, a.c.Sign, SealOpts{Exp: in.Exp})
	o := mustOpen(t, env, b)
	if o.Outer.Exp == nil || *o.Outer.Exp != in.Exp || o.AckKey != ack {
		t.Fatalf("outer exp %v, want %d", o.Outer.Exp, in.Exp)
	}
	// A queued message has no key 8.
	o = mustOpen(t, mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign), b)
	if o.Outer.Exp != nil {
		t.Fatal("key 8 without SealOpts.Exp")
	}
	_, _, err := Seal(in, &b.kp.Public, a.c.Sign, SealOpts{Exp: in.Exp + 1})
	wantReason(t, err, ReasonInvalidInput)

	for _, exp := range []uint64{in.Exp + 1, in.Exp - 1, 0} {
		env := sealHooked(t, in, &b.kp.Public, a.c.Sign, SealOpts{Exp: in.Exp}, sealHooks{outer: func(m fieldMap) { m[outerKeyExp] = enc(t, exp) }})
		_, err := Open(env, b.aid(), b.ring(), nil)
		wantOpenFails(t, err, ReasonExpMismatch, true)
	}
	// Outer key 8 is outside the signature: dropping it keeps the message
	// valid at this layer (the daemon requires it by type, receive step 4a)
	// but changes env_digest, which the access proof covers.
	sealedWith, _, err := seal(in, &b.kp.Public, a.c.Sign, SealOpts{Exp: in.Exp}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := decodeFields(sealedWith)
	d1, _ := EnvDigest(sealedWith)
	delete(m, outerKeyExp)
	stripped := mustMarshalFields(t, m)
	d2, _ := EnvDigest(stripped)
	if d1 == d2 {
		t.Fatal("env_digest does not cover key 8")
	}
	o = mustOpen(t, withSession(t, stripped), b)
	if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0); err != nil {
		t.Fatal(err)
	}
}

// AckKeyOf is true exactly after layer 1 opened (DLV-C-API-1, C-API-2), with
// the key Seal returned, and the wrapper keeps the *Error reachable.
func TestAckKeyOf(t *testing.T) {
	a, b := newParty(t), newParty(t)
	in := innerFrom(t, a, b, t0)
	env, ack := mustSealAck(t, in, &b.kp.Public, a.c.Sign, SealOpts{})
	if ack == (AckKey{}) {
		t.Fatal("zero ack_key")
	}
	bad := sealHooked(t, in, &b.kp.Public, a.c.Sign, SealOpts{}, sealHooks{wrap: func(m fieldMap) { m[5] = enc(t, "x") }})
	_, err := Open(bad, b.aid(), b.ring(), nil)
	k, ok := AckKeyOf(err)
	if !ok || k == (AckKey{}) {
		t.Fatalf("bad-wrap: AckKeyOf = %x, %v", k, ok)
	}
	var se *Error
	if !errors.As(err, &se) || se.Reason != ReasonBadWrap || !IsPermanent(err) {
		t.Fatalf("the *Error is not reachable through the wrapper: %#v", err)
	}
	// The key is the envelope's: the same envelope, opened, gives the same key.
	o := mustOpen(t, env, b)
	if o.AckKey != ack {
		t.Fatalf("Open %x, Seal %x", o.AckKey, ack)
	}
	for _, e := range []error{nil, errors.New("other"), fail(ReasonBadInner, "x")} {
		if _, ok := AckKeyOf(e); ok {
			t.Fatalf("AckKeyOf(%v) is true", e)
		}
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

// Receive step 7 across a rotation of the sender (KEL C-54): arrival, not the receiver's clock,
// decides the planned rotation's grace, which is identity.RotationGrace; an emergency rotation or a
// deactivation leaves the old key nothing, whatever arrival says (SenderKeyUsable, C-13).
func TestRotationGrace(t *testing.T) {
	b := newParty(t)
	const rot = t0 + 10*minuteMS
	graceMS := identity.RotationGrace

	// sealBefore seals from a fresh A with ts, then rotates A at rotTS (an emergency rotation when
	// emergency is set) and returns the opened message and A's KEL after rotation.
	sealBefore := func(t *testing.T, ts, rotTS uint64, emergency bool, between func(*identity.Controller)) (*Opened, []identity.SignedEvent) {
		t.Helper()
		a := newParty(t)
		if between != nil {
			between(a.c)
			a.resign(t, t0)
		}
		env := mustSeal(t, innerFrom(t, a, b, ts), &b.kp.Public, a.c.Sign)
		rotate := identitytest.Rotate
		if emergency {
			rotate = identitytest.RotateEmergency
		}
		if err := rotate(a.c, rotTS); err != nil {
			t.Fatal(err)
		}
		return mustOpen(t, env, b), a.c.KEL()
	}

	if graceMS != uint64(time.Hour.Milliseconds()) {
		t.Fatalf("identity.RotationGrace is %d ms, want one hour", graceMS)
	}
	t.Run("old key, arrival inside the grace", func(t *testing.T) {
		o, kel := sealBefore(t, t0, rot, false, nil)
		if err := VerifyInnerSig(&o.Inner, o.Preimage, kel, rot+graceMS); err != nil {
			t.Fatalf("at the grace limit: %v", err)
		}
		if err := VerifyInnerSig(&o.Inner, o.Preimage, kel, rot-1); err != nil {
			t.Fatalf("arrived before the rotation: %v", err)
		}
	})
	t.Run("old key, arrival past the grace", func(t *testing.T) {
		o, kel := sealBefore(t, t0, rot, false, nil)
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, kel, rot+graceMS+1), ReasonGraceExpired)
	})
	t.Run("old key, ts not before rotation", func(t *testing.T) {
		o, kel := sealBefore(t, rot, rot, false, nil)
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, kel, rot+1), ReasonRevokedKey)
	})
	// M13, M40 (KEL §7.3): an emergency rotation retires the old key urgently. A message under it
	// is refused one minute after the rotation (where a planned one would still be in its grace),
	// and also when the receiver's hub dates its arrival before the rotation.
	t.Run("old key, emergency rotation", func(t *testing.T) {
		o, kel := sealBefore(t, t0, rot, true, nil)
		for _, arrival := range []uint64{rot + minuteMS, rot, rot - 1, t0} {
			wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, kel, arrival), ReasonRevokedKey)
		}
	})
	t.Run("carried KEL predates rotation, stored KEL does not", func(t *testing.T) {
		// The message verifies under the KEL it carries (top state at the
		// time) and is still subject to the grace rule under the resolved
		// longer KEL; step 6 passes the resolved one.
		o, kel := sealBefore(t, t0, rot, false, nil)
		if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, rot+graceMS+1); err != nil {
			t.Fatalf("under the carried KEL: %v", err)
		}
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, kel, rot+graceMS+1), ReasonGraceExpired)
	})
	t.Run("new key after rotation", func(t *testing.T) {
		a := newParty(t)
		if err := identitytest.Rotate(a.c, rot); err != nil {
			t.Fatal(err)
		}
		a.resign(t, rot)
		o := mustOpen(t, mustSeal(t, innerFrom(t, a, b, rot+1), &b.kp.Public, a.c.Sign), b)
		if err := VerifyInnerSig(&o.Inner, o.Preimage, a.c.KEL(), rot+10*dayMS); err != nil {
			t.Fatalf("current key: %v", err)
		}
	})
	t.Run("signed at a rot state, retired by the next rot", func(t *testing.T) {
		// icp -> rot -> rot, message signed at seq 1. The retirement is read
		// from the rot at seq 2.
		rotEarly := func(c *identity.Controller) {
			if err := identitytest.Rotate(c, t0-dayMS); err != nil {
				t.Fatal(err)
			}
		}
		o, kel := sealBefore(t, t0, rot, false, rotEarly)
		if o.Inner.KeyStateSeq != 1 {
			t.Fatalf("setup: signed at %d", o.Inner.KeyStateSeq)
		}
		if err := VerifyInnerSig(&o.Inner, o.Preimage, kel, rot+graceMS); err != nil {
			t.Fatalf("inside grace: %v", err)
		}
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, kel, rot+graceMS+1), ReasonGraceExpired)
	})
	t.Run("deactivated", func(t *testing.T) {
		a := newParty(t)
		env := mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign)
		if err := identitytest.Deactivate(a.c, rot); err != nil {
			t.Fatal(err)
		}
		// Signed before the dip: the dip retires the key urgently, so not even an arrival dated
		// before it helps.
		o := mustOpen(t, env, b)
		for _, arrival := range []uint64{rot + 1, rot - 1} {
			wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, a.c.KEL(), arrival), ReasonRevokedKey)
		}
		// Signed at the dip state itself: no key is in force.
		in := innerFrom(t, a, b, rot+1)
		o = mustOpen(t, mustSeal(t, in, &b.kp.Public, a.c.Sign), b)
		wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, a.c.KEL(), rot+2), ReasonRevokedKey)
	})
}

func TestVerifyInnerSigInputs(t *testing.T) {
	a, b, c := newParty(t), newParty(t), newParty(t)
	o := mustOpen(t, mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign), b)

	// Another identity's KEL.
	wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, c.c.KEL(), t0), ReasonFromMismatch)
	// A KEL that does not replay.
	bad := append([]identity.SignedEvent(nil), a.c.KEL()...)
	bad[0].Sig = make([]byte, 64)
	wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, bad, t0), ReasonBadKEL)
	wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, nil, t0), ReasonBadKEL)
	// Declared seq beyond the KEL.
	in := o.Inner
	in.KeyStateSeq = 5
	wantReason(t, VerifyInnerSig(&in, o.Preimage, a.c.KEL(), t0), ReasonBadKeyState)
	// ts 0 is refused rather than handed to the weaker "unknown time" gate.
	in = o.Inner
	in.TS = 0
	wantReason(t, VerifyInnerSig(&in, o.Preimage, a.c.KEL(), t0), ReasonBadInner)
	// An arrival of 0 is no time either: a caller that has none gets a refusal, not a key a
	// planned rotation retired accepted for good.
	wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, a.c.KEL(), 0), ReasonInvalidInput)
	if err := identitytest.Rotate(a.c, t0+minuteMS); err != nil {
		t.Fatal(err)
	}
	wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, a.c.KEL(), 0), ReasonInvalidInput)
	wantReason(t, VerifyInnerSig(&o.Inner, o.Preimage, a.c.KEL(), t0+minuteMS+identity.RotationGrace+1), ReasonGraceExpired)
}

// Seal refuses an inner its receiver would refuse for structural reasons,
// options it cannot honour, and a signer whose key state moved.
func TestSealInputChecks(t *testing.T) {
	a, b := newParty(t), newParty(t)
	cases := []struct {
		name string
		edit func(*SealedInner, *SealOpts)
	}{
		{"no from", func(in *SealedInner, _ *SealOpts) { in.From = "" }},
		{"no to", func(in *SealedInner, _ *SealOpts) { in.To = "" }},
		{"no type", func(in *SealedInner, _ *SealOpts) { in.Type = "" }},
		{"from with NUL", func(in *SealedInner, _ *SealOpts) { in.From += "\x00" }},
		{"to with NUL", func(in *SealedInner, _ *SealOpts) { in.To += "\x00" }},
		{"ix with NUL", func(in *SealedInner, _ *SealOpts) { in.IX = "a\x00b" }},
		{"mid 8", func(in *SealedInner, _ *SealOpts) { in.MID = in.MID[:8] }},
		{"ts 0", func(in *SealedInner, _ *SealOpts) { in.TS = 0 }},
		{"exp before ts", func(in *SealedInner, _ *SealOpts) { in.Exp = in.TS - 1 }},
		{"lifetime too long", func(in *SealedInner, _ *SealOpts) { in.Exp = in.TS + MaxMessageLifetimeMS + 1 }},
		{"kel without notice", func(in *SealedInner, _ *SealOpts) { in.Notices = nil }},
		{"notice without kel", func(in *SealedInner, _ *SealOpts) { in.KEL = nil }},
		{"two notices", func(in *SealedInner, _ *SealOpts) { in.Notices = append(in.Notices, testNotice) }},
		{"notice over its cap", func(in *SealedInner, _ *SealOpts) { in.Notices = [][]byte{make([]byte, MaxNoticeBytes+1)} }},
		{"kel that does not decode", func(in *SealedInner, _ *SealOpts) { in.KEL = []byte{0x01} }},
		{"grant not a map", func(in *SealedInner, _ *SealOpts) { in.Grant = enc(t, "grant") }},
		{"grant not CBOR", func(in *SealedInner, _ *SealOpts) { in.Grant = []byte{0xa1} }},
		{"rk suite 2", func(in *SealedInner, _ *SealOpts) { in.RK = &RK{Suite: SuiteXWing, Pub: make([]byte, 32)} }},
		{"rk pub 31", func(in *SealedInner, _ *SealOpts) { in.RK = &RK{Suite: SuiteX25519, Pub: make([]byte, 31)} }},
		{"extension not CBOR", func(in *SealedInner, _ *SealOpts) { in.Ext = map[uint64][]byte{64: {0xa1}} }},
		{"outer exp not the inner exp", func(in *SealedInner, o *SealOpts) { o.Exp = in.Exp - 1 }},
		// The peer's interaction key (FS-C10, FS-C11): suite 1, 32 bytes, and a
		// point a shared secret can be made with (all zero is of small order).
		{"peer rk suite 2", func(in *SealedInner, o *SealOpts) {
			o.PeerRK = &RK{Suite: SuiteXWing, Pub: bytes.Repeat([]byte{9}, 32)}
		}},
		{"peer rk pub 31", func(in *SealedInner, o *SealOpts) {
			o.PeerRK = &RK{Suite: SuiteX25519, Pub: bytes.Repeat([]byte{9}, 31)}
		}},
		{"peer rk of small order", func(in *SealedInner, o *SealOpts) { o.PeerRK = &RK{Suite: SuiteX25519, Pub: make([]byte, 32)} }},
		{"seq not the signer's", func(in *SealedInner, _ *SealOpts) { in.KeyStateSeq = 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := innerFrom(t, a, b, t0)
			var o SealOpts
			tc.edit(in, &o)
			_, ack, err := Seal(in, &b.kp.Public, a.c.Sign, o)
			wantReason(t, err, ReasonInvalidInput)
			if ack != (AckKey{}) {
				t.Fatal("an ack_key with an error")
			}
		})
	}
	// A recipient key whose kid does not match its public key.
	k := b.kp.Public
	k.KID = bytes.Repeat([]byte{1}, KIDLen)
	_, _, err := Seal(innerFrom(t, a, b, t0), &k, a.c.Sign, SealOpts{})
	wantReason(t, err, ReasonInvalidInput)
	// A recipient key of an unimplemented suite.
	k2 := NewEncKey(SuiteXWing, make([]byte, 1216), t0, t0+dayMS)
	_, _, err = Seal(innerFrom(t, a, b, t0), &k2, a.c.Sign, SealOpts{})
	wantReason(t, err, ReasonUnknownSuite)
	_, _, err = Seal(nil, &b.kp.Public, a.c.Sign, SealOpts{})
	wantReason(t, err, ReasonInvalidInput)
}

func TestParseKELCaps(t *testing.T) {
	// 257 events that decode; they are not a valid KEL, but the count cap
	// applies before any replay.
	events := make([]identity.SignedEvent, MaxKELEvents+1)
	for i := range events {
		events[i].Event.KELType = identity.KELType
	}
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
	_, err := Open(env, b.aid(), StaticKeyRing{}, nil)
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
	err = VerifyInnerSig(&o.Inner, o.Preimage[:len(o.Preimage)-1], a.c.KEL(), t0)
	var ve *identity.VErr
	if !errors.As(err, &ve) || ve.Reason != "INVALID_SIGNATURE" {
		t.Fatalf("want wrapped identity.VErr, got %v", err)
	}
}

// The reasons this package defines are exactly the registered ones it may
// produce; a constant that drifted from its string would split a counter.
func TestReasonStrings(t *testing.T) {
	for want, got := range map[string]string{
		"access-invalid": ReasonAccessInvalid, "bad-wrap": ReasonBadWrap, "bad-rk": ReasonBadRK,
		"exp-mismatch": ReasonExpMismatch, "sealed-to-closed-interaction": ReasonSealedToClosedInteraction,
		"ikey-mismatch": ReasonIKeyMismatch, "bad-version": ReasonBadVersion,
		"unknown-critical-field": ReasonUnknownField, "bad-inner": ReasonBadInner,
	} {
		if got != want {
			t.Errorf("reason %q is %q", want, got)
		}
	}
}
