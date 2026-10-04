package seal

// Fuzz targets for the envelope, the Wrap, the inner message and the key set.
//
// Open needs the recipient's private key and a signature to get past its first steps, so the
// targets fix the recipient to the SEALED-2A key and the sender to the suite identity:
//   - FuzzParseOuter feeds outer envelopes to the hub's structural check, EnvDigest and SetAccess;
//   - FuzzOpenEnvelope feeds whole envelopes to Open and checks that an ack_key comes back
//     exactly when layer 1 opened, and is the one the recipient context exports;
//   - FuzzOpenWrap feeds the layer-1 plaintext, encrypted to the recipient: every refusal is
//     after layer 1, so it carries the ack_key;
//   - FuzzOpenInner feeds the inner plaintext inside a padded Wrap and, when asked, re-signs the
//     fuzzed field map with the suite key over the preimage Open will build, so VerifyInnerSig
//     and VerifyInnerKeys run on arbitrary field values under a good signature;
//   - FuzzEncKeySet feeds SignedEncKeySet bytes, optionally re-signing the set;
//   - FuzzPadme checks Padmé and the Wrap padding arithmetic.
//
// The second layer's targets, FuzzRKDecode and FuzzOpenLayer2, are in fuzz_layer2_test.go.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

const fuzzTS = t0

type fuzzFixture struct {
	sender    *identity.Controller
	senderKEL []identity.SignedEvent
	senderKP  *KeyPair
	self      string // the recipient AID
	recipient *KeyPair
	ring      KeyRing
	inner     *SealedInner // unsigned inner from the suite identity to the recipient
	golden    []byte       // the SEALED-2A envelope
}

// fuzzMbox is the mailbox signing key of the fixture's key sets, derived from a fixed seed so
// the seeds are the same in every run.
var fuzzMbox = Mbox{Epoch: 1, Pub: ed25519.NewKeyFromSeed(goldenSeed("SEALED-2A", "fuzz/mbox")).Public().(ed25519.PublicKey)}

func newFuzzFixture(tb testing.TB) *fuzzFixture {
	tb.Helper()
	var v vecSealed2A
	readVector(tb, fileSealed2A, &v)
	rk, err := DeriveKeyPair(SuiteX25519, goldenSeed("SEALED-2A", "recipient-enc"), fuzzTS-dayMS, fuzzTS+dayMS)
	if err != nil {
		tb.Fatal(err)
	}
	sk, err := DeriveKeyPair(SuiteX25519, goldenSeed("SEALED-2A", "fuzz/sender-enc"), fuzzTS-dayMS, fuzzTS+dayMS)
	if err != nil {
		tb.Fatal(err)
	}
	c := identity.SuiteController()
	set := &EncKeySet{Type: EncKeySetType, AID: c.AID(), Seq: fuzzTS, Keys: []EncKey{sk.Public}, IssuedAt: fuzzTS, Mbox: fuzzMbox}
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
	return &fuzzFixture{
		sender: c, senderKEL: c.KEL(), senderKP: sk, self: v.Recipient.AID, recipient: rk, ring: StaticKeyRing{rk},
		inner: &SealedInner{
			From: c.AID(), KeyStateSeq: c.CurrentSeq(), To: v.Recipient.AID,
			Type: TypeMessage, IX: "ix-fuzz", MID: goldenSeed("SEALED-2A", "fuzz/mid")[:MIDLen],
			TS: fuzzTS, Exp: fuzzTS + dayMS, Body: []byte("anet seal v2 fuzz"),
			KEL: kel, Notices: [][]byte{v.Inner.Notice[0]}, Keys: keys,
		},
		golden: v.Envelope,
	}
}

// sealed seals in to the fixture recipient with a session access and returns the envelope, the
// Wrap and the inner plaintext as sent.
func (fx *fuzzFixture) sealed(tb testing.TB, in *SealedInner, o SealOpts) (env, wrap, inner []byte) {
	tb.Helper()
	env, _, err := seal(in, &fx.recipient.Public, fx.sender.Sign, o, &sealHooks{
		inner: func(m fieldMap) { inner = mustMarshal(tb, m) },
		wrap:  func(m fieldMap) { wrap = mustMarshal(tb, m) },
	})
	if err != nil {
		tb.Fatal(err)
	}
	env, err = SetAccess(env, session)
	if err != nil {
		tb.Fatal(err)
	}
	return env, wrap, inner
}

// seedInners are variants of the fixture inner used as seeds. The last carries the suite KEL
// after a rotation at fuzzTS+1000 and still declares key state 0: signed with the pre-rotation
// key before the rotation, it reaches VerifyInnerSig's rotation-grace branch.
func (fx *fuzzFixture) seedInners(tb testing.TB) []*SealedInner {
	a := *fx.inner
	b := *fx.inner
	b.Type, b.Body, b.Ext = TypeDelegate, bytes.Repeat([]byte{7}, 300), map[uint64][]byte{64: {0x01}, 100: {0x63, 'a', 'b', 'c'}}
	b.Grant, b.RK = testGrant, &RK{Suite: SuiteX25519, Pub: bytes.Repeat([]byte{5}, 32)}
	c := *fx.inner
	c.Exp, c.IX, c.Body = c.TS, "", nil
	c.KEL, c.Notices, c.Keys = nil, nil, nil // a preview frame's shape
	d := *fx.inner
	d.KEL = rotatedSuiteKEL(tb, fuzzTS+1000)
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
	k1, k2 := k("anet-suite-identity-v1/nxt"), k("anet-fuzz/seal/k2")
	kel := identity.SuiteController().KEL()
	d := sha256.Sum256(k2.Public().(ed25519.PublicKey))
	rot := identity.KeyEvent{KELType: identity.KELType, AID: kel[0].EventID, Seq: 1, Prev: kel[0].EventID,
		Type: identity.Rotation, Keys: [][]byte{k1.Public().(ed25519.PublicKey)}, NextDigest: d[:], Threshold: 1,
		Timestamp: ts, Toad: identity.ToadField(identity.ToadHub)}
	pre, err := coredet.Marshal(rot)
	if err != nil {
		tb.Fatal(err)
	}
	// A rot is signed by the key it reveals (KEL v2).
	kel = append(kel, identity.SignedEvent{Event: rot, Sig: ed25519.Sign(k1, pre), EventID: anetcid.MustSum(pre)})
	b, err := identity.MarshalKEL(kel)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func FuzzParseOuter(f *testing.F) {
	fx := newFuzzFixture(f)
	f.Add(fx.golden)
	for _, in := range fx.seedInners(f) {
		env, _, _ := fx.sealed(f, in, SealOpts{})
		f.Add(env)
	}
	one := *fx.inner
	env, _, _ := fx.sealed(f, &one, SealOpts{Exp: one.Exp})
	f.Add(env)
	kind1, err := SetAccess(env, &Access{Kind: AccessKindCap, Cap: &Cap{Body: []byte("b"), Sig: make([]byte, SigLen)}, Proof: make([]byte, SigLen)})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(kind1)
	f.Fuzz(func(t *testing.T, env []byte) {
		d, derr := EnvDigest(env)
		outer, err := ParseOuter(env)
		if err != nil {
			if ReasonOf(err) == "" || !IsPermanent(err) {
				t.Fatalf("ParseOuter returned %v (reason %q)", err, ReasonOf(err))
			}
			if _, ok := AckKeyOf(err); ok {
				t.Fatal("ParseOuter returned an ack_key")
			}
			return
		}
		// The structural checks the hub relies on.
		if outer.V != EnvelopeVersion || outer.To == "" || len(outer.KID) != KIDLen ||
			len(outer.Enc) != params(outer.Suite).encLen || len(outer.CT) == 0 || outer.Access == nil {
			t.Fatalf("ParseOuter accepted %+v", outer)
		}
		a := outer.Access
		switch a.Kind {
		case AccessKindSession:
			if a.Cap != nil || a.Proof != nil {
				t.Fatalf("accepted kind 0 with %+v", a)
			}
		case AccessKindCap:
			if a.Cap == nil || len(a.Cap.Sig) != SigLen || len(a.Proof) != SigLen {
				t.Fatalf("accepted kind 1 with %+v", a)
			}
		default:
			t.Fatalf("accepted access kind %d", a.Kind)
		}
		if derr != nil {
			t.Fatalf("an accepted outer has no env_digest: %v", derr)
		}
		b, err := outer.Marshal()
		if err != nil {
			t.Fatalf("an accepted outer does not encode: %v", err)
		}
		again, err := ParseOuter(b)
		if err != nil || !reflect.DeepEqual(again, outer) {
			t.Fatalf("outer round trip: %v\n%+v\n%+v", err, outer, again)
		}
		// Replacing the credential keeps env_digest and the structure.
		re, err := SetAccess(env, session)
		if err != nil {
			t.Fatalf("SetAccess on an accepted outer: %v", err)
		}
		if d2, err := EnvDigest(re); err != nil || d2 != d {
			t.Fatalf("SetAccess changed env_digest (%v)", err)
		}
		if o2, err := ParseOuter(re); err != nil || o2.Access.Kind != AccessKindSession {
			t.Fatalf("after SetAccess: %v", err)
		}
	})
}

// layer1Opens reports whether env opens at layer 1 for the fixture, by the test's own HPKE
// calls, and the ack_key the recipient context exports.
func (fx *fuzzFixture) layer1Opens(env []byte) (AckKey, bool) {
	var ack AckKey
	outer, err := ParseOuter(env)
	if err != nil || outer.To != fx.self || !bytes.Equal(outer.KID, fx.recipient.Public.KID) {
		return ack, false
	}
	p := params(outer.Suite)
	sk, err := p.kem.NewPrivateKey(fx.recipient.Private)
	if err != nil {
		return ack, false
	}
	info, _ := HPKEInfo(outer.To, outer.Suite, outer.KID)
	r, err := hpke.NewRecipient(outer.Enc, sk, p.kdf, p.aead, info)
	if err != nil {
		return ack, false
	}
	if _, err := r.Open(nil, outer.CT); err != nil {
		return ack, false
	}
	k, err := r.Export(DAckExporterContext, AckKeyLen)
	if err != nil {
		return ack, false
	}
	copy(ack[:], k)
	return ack, true
}

func FuzzOpenEnvelope(f *testing.F) {
	fx := newFuzzFixture(f)
	f.Add(fx.golden)
	for _, in := range fx.seedInners(f) {
		env, _, _ := fx.sealed(f, in, SealOpts{})
		f.Add(env)
	}
	f.Fuzz(func(t *testing.T, env []byte) {
		want, opened := fx.layer1Opens(env)
		o, err := Open(env, fx.self, fx.ring, nil)
		if err != nil {
			if ReasonOf(err) == "" || !IsPermanent(err) {
				t.Fatalf("Open returned %v (reason %q)", err, ReasonOf(err))
			}
			ack, ok := AckKeyOf(err)
			if ok != opened || (ok && ack != want) {
				t.Fatalf("%s: AckKeyOf = %x %v; layer 1 opened: %v, export %x", ReasonOf(err), ack, ok, opened, want)
			}
			return
		}
		if !opened || o.AckKey != want {
			t.Fatalf("opened, but layer 1 by itself: %v; ack %x, export %x", opened, o.AckKey, want)
		}
		fx.checkOpened(t, o)
	})
}

// openReasons are the reasons Open may give once layer 1 opened.
var openReasons = map[string]bool{
	ReasonBadWrap: true, ReasonSealedToClosedInteraction: true, ReasonDecrypt: true, ReasonBadInner: true,
	ReasonUnknownField: true, ReasonToMismatch: true, ReasonExpMismatch: true, ReasonBadRK: true,
	ReasonKELTooLarge: true, ReasonBadKEL: true,
}

// encryptToFixture encrypts pt as a layer-1 plaintext to the fixture recipient.
func (fx *fuzzFixture) encryptToFixture(t *testing.T, pt []byte, exp *uint64) ([]byte, []byte, []byte) {
	p := params(SuiteX25519)
	pk, err := p.kem.NewPublicKey(fx.recipient.Public.Pub)
	if err != nil {
		t.Fatal(err)
	}
	info, err := HPKEInfo(fx.self, SuiteX25519, fx.recipient.Public.KID)
	if err != nil {
		t.Fatal(err)
	}
	encKey, sender, err := hpke.NewSender(pk, p.kdf, p.aead, info)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sender.Seal(nil, pt)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := sender.Export(DAckExporterContext, AckKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	env, err := (&SealedEnvelope{V: EnvelopeVersion, To: fx.self, Suite: SuiteX25519,
		KID: fx.recipient.Public.KID, Enc: encKey, CT: ct, Access: session, Exp: exp}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return env, encKey, ack
}

func FuzzOpenWrap(f *testing.F) {
	fx := newFuzzFixture(f)
	for _, in := range fx.seedInners(f) {
		_, wrap, _ := fx.sealed(f, in, SealOpts{})
		f.Add(wrap)
	}
	f.Add([]byte{0xa2, 0x01, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0x40})
	f.Fuzz(func(t *testing.T, wrap []byte) {
		env, _, want := fx.encryptToFixture(t, wrap, nil)
		o, err := Open(env, fx.self, fx.ring, nil)
		if err != nil {
			ack, ok := AckKeyOf(err)
			if !ok || !bytes.Equal(ack[:], want) {
				t.Fatalf("%v: no ack_key, or not the export (%x)", err, ack)
			}
			if !openReasons[ReasonOf(err)] || !IsPermanent(err) {
				t.Fatalf("Open returned %v (reason %q) after layer 1", err, ReasonOf(err))
			}
			return
		}
		if !bytes.Equal(o.AckKey[:], want) {
			t.Fatal("opened with another ack_key")
		}
		// Accepted: the Wrap follows FS-C8 (P-8).
		w, err := decodeWrap(wrap)
		if err != nil || w.ikid != nil {
			t.Fatalf("Open accepted a Wrap decodeWrap refuses or with a second layer (%v)", err)
		}
		m, _ := decodeFields(wrap)
		var pad []byte
		if err := coredet.Unmarshal(m[wrapKeyPad], &pad); err != nil {
			t.Fatalf("accepted a pad that does not decode: %v", err)
		}
		for _, x := range pad {
			if x != 0 {
				t.Fatal("accepted a non-zero pad")
			}
		}
		fx.checkOpened(t, o)
	})
}

func FuzzOpenInner(f *testing.F) {
	fx := newFuzzFixture(f)
	for _, in := range fx.seedInners(f) {
		_, _, pt := fx.sealed(f, in, SealOpts{})
		f.Add(pt, true, false)
		f.Add(pt, false, true)
	}
	f.Fuzz(func(t *testing.T, pt []byte, resign, oneShot bool) {
		var exp *uint64
		if oneShot {
			if fields, err := decodeFields(pt); err == nil {
				if e, err := rawUint(fields, keyExp); err == nil {
					exp = &e
				}
			}
		}
		// The envelope's enc is in the preimage, so the plaintext is signed for the very HPKE
		// context it travels in: the sender context exists before the plaintext is final.
		p := params(SuiteX25519)
		pk, _ := p.kem.NewPublicKey(fx.recipient.Public.Pub)
		info, _ := HPKEInfo(fx.self, SuiteX25519, fx.recipient.Public.KID)
		encKey, sender, err := hpke.NewSender(pk, p.kdf, p.aead, info)
		if err != nil {
			t.Fatal(err)
		}
		if resign {
			if fields, err := decodeFields(pt); err == nil {
				if pre, err := sigPreimage(fields, encKey, fx.recipient.Public.KID, SuiteX25519, nil, nil); err == nil {
					sig, _ := fx.sender.Sign(pre)
					fields[keySig] = enc(t, sig)
					pt = mustMarshal(t, fields)
				}
			}
		}
		w := fieldMap{wrapKeyBody: enc(t, pt)}
		applyPad(w)
		ct, err := sender.Seal(nil, mustMarshal(t, w))
		if err != nil {
			t.Fatal(err)
		}
		env, err := (&SealedEnvelope{V: EnvelopeVersion, To: fx.self, Suite: SuiteX25519,
			KID: fx.recipient.Public.KID, Enc: encKey, CT: ct, Access: session, Exp: exp}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		o, err := Open(env, fx.self, fx.ring, nil)
		if err != nil {
			if _, ok := AckKeyOf(err); !ok || !openReasons[ReasonOf(err)] || !IsPermanent(err) {
				t.Fatalf("Open returned %v (reason %q) after layer 1", err, ReasonOf(err))
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
	if in.To != fx.self || o.Outer.To != fx.self || o.Layers < 1 || o.Layers > 2 || (o.Layers == 1) != (o.IKID == nil) {
		t.Fatalf("opened a message to %q (outer %q), %d layers, ikid %x", in.To, o.Outer.To, o.Layers, o.IKID)
	}
	if o.Access == nil || o.Access != o.Outer.Access || o.RK != in.RK || !bytes.Equal(o.Grant, in.Grant) ||
		len(o.Notices) != len(in.Notices) || (o.Notices == nil) != (in.Notices == nil) {
		t.Fatal("Opened.Access, RK, Notices or Grant is not what Outer and Inner hold")
	}
	if len(in.MID) != MIDLen || len(in.Sig) != SigLen {
		t.Fatalf("opened mid %d bytes, sig %d bytes", len(in.MID), len(in.Sig))
	}
	if strings.ContainsRune(in.From, 0) || strings.ContainsRune(in.To, 0) || strings.ContainsRune(in.IX, 0) {
		t.Fatal("opened a from, to or ix with U+0000")
	}
	if (in.KEL != nil) != (in.Notices != nil) || (in.Notices != nil && len(in.Notices) != 1) {
		t.Fatalf("opened kel %v with %d notices", in.KEL != nil, len(in.Notices))
	}
	for _, n := range in.Notices {
		if len(n) > MaxNoticeBytes {
			t.Fatalf("opened a notice of %d bytes", len(n))
		}
	}
	if in.RK != nil && in.RK.check() != nil {
		t.Fatalf("opened rk %+v", in.RK)
	}
	if o.Outer.Exp != nil && *o.Outer.Exp != in.Exp {
		t.Fatalf("opened outer exp %d, inner exp %d", *o.Outer.Exp, in.Exp)
	}
	for k := range in.Ext {
		if k < FirstIgnorableKey {
			t.Fatalf("extension key %d below %d", k, FirstIgnorableKey)
		}
	}
	if in.KEL != nil && (len(in.KEL) > MaxKELBytes || len(o.KEL) == 0 || len(o.KEL) > MaxKELEvents) {
		t.Fatalf("opened a KEL of %d bytes, %d events", len(in.KEL), len(o.KEL))
	}
	// The preimage never carries the signature, carries the outer header and the digest of
	// the body, and null for the second layer.
	pm, err := decodeFields(o.Preimage)
	if err != nil {
		t.Fatalf("preimage does not decode: %v", err)
	}
	if _, ok := pm[keySig]; ok {
		t.Fatal("preimage carries the signature")
	}
	if kid, err := rawBytes(pm, preKeyKID); err != nil || !bytes.Equal(kid, o.Outer.KID) {
		t.Fatalf("preimage kid %x, outer %x (%v)", kid, o.Outer.KID, err)
	}
	if e, err := rawBytes(pm, preKeyEnc); err != nil || !bytes.Equal(e, o.Outer.Enc) {
		t.Fatalf("preimage enc %x, outer %x (%v)", e, o.Outer.Enc, err)
	}
	digest := sha256.Sum256(in.Body)
	if b, err := rawBytes(pm, keyBody); err != nil || !bytes.Equal(b, digest[:]) {
		t.Fatalf("preimage key 9 is not the body digest (%v)", err)
	}
	if o.Layers == 1 && (!bytes.Equal(pm[preKeyIKID], cborNull) || !bytes.Equal(pm[preKeyEnc2], cborNull)) {
		t.Fatal("a single layer's preimage has a second layer")
	}
	if o.Layers == 2 {
		ikid, err := rawBytes(pm, preKeyIKID)
		if err != nil || !bytes.Equal(ikid, o.IKID) {
			t.Fatalf("preimage key 33 %x, ikid %x (%v)", ikid, o.IKID, err)
		}
		if e2, err := rawBytes(pm, preKeyEnc2); err != nil || len(e2) != params(SuiteX25519).encLen {
			t.Fatalf("preimage key 34 is not an enc2 (%v)", err)
		}
	}

	for _, now := range []uint64{0, in.TS, in.Exp, math.MaxUint64} {
		_ = CheckTime(in, now)
	}
	if o.KEL == nil {
		return
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
	signed, err := SignEncKeySet(&EncKeySet{Type: EncKeySetType, AID: fx.sender.AID(), Seq: fuzzTS,
		Keys: []EncKey{fx.senderKP.Public}, IssuedAt: fuzzTS, Mbox: fuzzMbox}, fx.sender.Sign)
	if err != nil {
		f.Fatal(err)
	}
	b, err := signed.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b, false, fuzzTS)
	f.Add(b, true, fuzzTS+dayMS)
	two := NewEncKey(SuiteXWing, bytes.Repeat([]byte{9}, 1216), fuzzTS, fuzzTS+dayMS)
	signed2, err := SignEncKeySet(&EncKeySet{Type: EncKeySetType, AID: fx.sender.AID(), Seq: fuzzTS + 1,
		Keys: []EncKey{fx.senderKP.Public, two}, IssuedAt: fuzzTS, Mbox: fuzzMbox}, fx.sender.Sign)
	if err != nil {
		f.Fatal(err)
	}
	b2, _ := signed2.Marshal()
	f.Add(b2, true, fuzzTS)
	f.Fuzz(func(t *testing.T, b []byte, resign bool, now uint64) {
		s, err := UnmarshalSignedEncKeySet(b)
		if err != nil {
			return
		}
		if resign {
			s.Sig, s.KeyStateSeq = fx.sender.Sign(s.Set)
		}
		_, _ = DecideHighWaterSigned(nil, s)
		_, _ = DecideHighWaterSigned(&Seen{Seq: fuzzTS, Set: signed.Set}, s)
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
		// The padding Seal applies to the Wrap reaches its target exactly.
		w := fieldMap{wrapKeyBody: mustEncode(t, bytes.Repeat([]byte{1}, int(body%70000)))}
		if body&1 != 0 {
			w[wrapKeyIKID] = mustEncode(t, make([]byte, KIDLen))
			w[wrapKeyEnc2] = mustEncode(t, make([]byte, int(body>>20)))
		}
		want := applyPad(w)
		b, err := coredet.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != want || Padme(want) != want || encodedLen(w) != want {
			t.Fatalf("padded wrap is %d bytes, target %d, encodedLen %d", len(b), want, encodedLen(w))
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

func mustMarshal(tb testing.TB, m fieldMap) []byte {
	tb.Helper()
	b, err := coredet.Marshal(m)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// The decoders of the delivery credential and the grant (Access, Cap, CapBody, Grant), each
// with the check that consumes it. The fixtures are those of ACCESS-1 and GRANT-1, so the seeds
// reach every step; with resign set, a target signs what it decoded again with the fixture's
// mailbox and holder keys, so the steps after sig run on arbitrary field values.

// accessFuzzFixture is the verifier of ACCESS-1: its owner, the owner's mailbox key, the
// holder key of its capability and the env_digest of its envelope.
type accessFuzzFixture struct {
	owner  string
	mbox   ed25519.PrivateKey
	pub    Mbox
	holder ed25519.PrivateKey
	digest [32]byte
	seeds  [][]byte // encoded accesses: the vector's and each case's
}

func newAccessFuzzFixture(tb testing.TB) *accessFuzzFixture {
	tb.Helper()
	var v vecAccess1
	readVector(tb, fileAccess1, &v)
	fx := &accessFuzzFixture{owner: v.Owner, mbox: ed25519.NewKeyFromSeed(goldenSeed(v.ID, "mbox")),
		holder: ed25519.NewKeyFromSeed(goldenSeed(v.ID, "holder"))}
	fx.pub = Mbox{Epoch: v.Mbox.Epoch, Pub: fx.mbox.Public().(ed25519.PublicKey)}
	copy(fx.digest[:], v.EnvDigest)
	for _, env := range append([]hexBytes{v.Envelope}, func() (out []hexBytes) {
		for _, c := range v.Cases {
			out = append(out, c.Envelope)
		}
		return
	}()...) {
		m, err := decodeFields(env)
		if err != nil {
			tb.Fatal(err)
		}
		fx.seeds = append(fx.seeds, m[outerKeyAccess])
	}
	return fx
}

// accessSteps are the Detail values of a VerifyAccess failure.
var accessSteps = map[string]bool{"parse": true, "decode": true, "type": true, "owner": true, "epoch": true, "sig": true, "exp": true, "proof": true}

func FuzzAccess(f *testing.F) {
	fx := newAccessFuzzFixture(f)
	for i, s := range fx.seeds {
		f.Add(s, i%2 == 1, uint64(capFuzzNow))
	}
	f.Add([]byte{0xa1, 0x01, 0x00}, false, uint64(0))
	f.Fuzz(func(t *testing.T, raw []byte, resign bool, now uint64) {
		a, err := decodeAccess(raw)
		if err != nil {
			return
		}
		if resign && a.Kind == AccessKindCap {
			a.Cap.Sig = ed25519.Sign(fx.mbox, a.Cap.Body)
			if body, err := decodeCapBody(a.Cap.Body); err == nil {
				a.Proof = ed25519.Sign(fx.holder, accessInput(body.CapID, fx.digest))
			}
		}
		err = VerifyAccess(a, fx.digest, fx.pub, fx.owner, now)
		if err != nil {
			var se *Error
			if !errors.As(err, &se) || se.Reason != ReasonAccessInvalid || !accessSteps[se.Detail] || !se.Permanent() {
				t.Fatalf("VerifyAccess returned %v", err)
			}
			if a.Kind == AccessKindSession && se.Detail != "parse" {
				t.Fatalf("kind 0 failed at %q, not parse", se.Detail)
			}
			return
		}
		// Accepted: every property VerifyAccess promises holds.
		body, err := UnmarshalCapBody(a.Cap.Body)
		if err != nil {
			t.Fatalf("accepted a cap body that does not decode: %v", err)
		}
		re, _ := body.Marshal()
		switch {
		case a.Kind != AccessKindCap:
			t.Fatalf("accepted kind %d", a.Kind)
		case !bytes.Equal(re, a.Cap.Body):
			t.Fatal("accepted a cap body that is not its CoreDet encoding")
		case body.Type != CapType || body.Owner != fx.owner || body.Epoch != fx.pub.Epoch:
			t.Fatalf("accepted %+v", body)
		case body.Class != CapClassContact && body.Class != CapClassStranger:
			t.Fatalf("accepted class %d", body.Class)
		case !ed25519.Verify(fx.pub.Pub, a.Cap.Body, a.Cap.Sig):
			t.Fatal("accepted a cap the mailbox key did not sign")
		case !capExpInWindow(body.CapExp, now):
			t.Fatalf("accepted cap_exp %d at %d", body.CapExp, now)
		case !ed25519.Verify(body.Holder, accessInput(body.CapID, fx.digest), a.Proof):
			t.Fatal("accepted a proof the holder did not make over this envelope")
		}
		// Moved to another envelope, it is refused at proof.
		other := fx.digest
		other[0] ^= 1
		wantStep(t, VerifyAccess(a, other, fx.pub, fx.owner, now), "proof")
		// The accepted access encodes and decodes to itself.
		b, err := encodeAccess(a)
		if err != nil {
			t.Fatalf("an accepted access does not encode: %v", err)
		}
		if again, err := decodeAccess(b); err != nil || !reflect.DeepEqual(again, a) {
			t.Fatalf("access round trip: %v", err)
		}
	})
}

// capFuzzNow is a time inside the window of the ACCESS-1 and GRANT-1 capabilities.
const capFuzzNow = t0

func FuzzCap(f *testing.F) {
	fx := newAccessFuzzFixture(f)
	for _, s := range fx.seeds {
		if m, err := decodeFields(s); err == nil && m[2] != nil {
			f.Add([]byte(m[2]))
		}
	}
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := UnmarshalCap(raw)
		if err != nil {
			var se *Error
			if !errors.As(err, &se) || se.Reason != ReasonAccessInvalid || se.Detail != "parse" {
				t.Fatalf("UnmarshalCap returned %v", err)
			}
			return
		}
		if len(c.Sig) != SigLen || c.Body == nil {
			t.Fatalf("accepted %+v", c)
		}
		b, err := c.Marshal()
		if err != nil {
			t.Fatalf("an accepted cap does not encode: %v", err)
		}
		if again, err := UnmarshalCap(b); err != nil || !reflect.DeepEqual(again, c) {
			t.Fatalf("cap round trip: %v", err)
		}
		// It goes into an access and a grant as it is.
		if _, err := encodeAccess(&Access{Kind: AccessKindCap, Cap: c, Proof: make([]byte, SigLen)}); err != nil {
			t.Fatalf("an accepted cap does not make an access: %v", err)
		}
		g := Grant{Cap: *c, HolderSeed: make([]byte, ed25519.SeedSize), Home: "h"}
		if d, err := decodeGrant(mustEncode(t, g)); err != nil || !reflect.DeepEqual(d.Cap, *c) {
			t.Fatalf("an accepted cap does not make a grant: %v", err)
		}
	})
}

func FuzzCapBody(f *testing.F) {
	fx := newAccessFuzzFixture(f)
	for _, s := range fx.seeds {
		if a, err := decodeAccess(s); err == nil && a.Cap != nil {
			f.Add(a.Cap.Body, uint64(capFuzzNow))
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte, now uint64) {
		body, err := UnmarshalCapBody(raw)
		// An independent statement of the strict decode: the struct decoder refusing unknown
		// keys, then CORE-E2 (the bytes are the encoding of what they decode to, which also
		// rules out a missing key and a null) and the two sizes.
		var c CapBody
		ok := coredet.UnmarshalStrict(raw, &c) == nil
		if ok {
			re, err := c.Marshal()
			ok = err == nil && bytes.Equal(re, raw) && len(c.CapID) == CapIDLen && len(c.Holder) == ed25519.PublicKeySize
		}
		if (err == nil) != ok {
			t.Fatalf("UnmarshalCapBody: %v; the struct decode with CORE-E2 says %v", err, ok)
		}
		if err != nil {
			if ReasonOf(err) != ReasonAccessInvalid {
				t.Fatalf("UnmarshalCapBody returned %v", err)
			}
			return
		}
		if !reflect.DeepEqual(*body, c) {
			t.Fatalf("decoded %+v, the struct decoder %+v", body, c)
		}
		// Signed by the fixture's mailbox key for its owner, with the holder's proof, it is
		// refused only at the steps the body's own values fail, in order.
		a := &Access{Kind: AccessKindCap, Cap: &Cap{Body: raw, Sig: ed25519.Sign(fx.mbox, raw)},
			Proof: ed25519.Sign(fx.holder, accessInput(body.CapID, fx.digest))}
		want := ""
		switch {
		case body.Class != CapClassContact && body.Class != CapClassStranger:
			want = "decode"
		case body.Type != CapType:
			want = "type"
		case body.Owner != fx.owner:
			want = "owner"
		case body.Epoch != fx.pub.Epoch:
			want = "epoch"
		case !capExpInWindow(body.CapExp, now):
			want = "exp"
		case !bytes.Equal(body.Holder, fx.holder.Public().(ed25519.PublicKey)):
			want = "proof"
		}
		wantStep(t, VerifyAccess(a, fx.digest, fx.pub, fx.owner, now), want)
		// SignCap signs exactly the bodies that pass checkIssue, and gives back the same bytes.
		if cp, err := SignCap(fx.mbox, body); (err == nil) != (body.checkIssue() == nil) {
			t.Fatalf("SignCap: %v, checkIssue: %v", err, body.checkIssue())
		} else if err == nil && !bytes.Equal(cp.Body, raw) {
			t.Fatal("SignCap re-encoded an accepted body differently")
		}
	})
}

// grantFuzzFixture is the receiver of GRANT-1: the issuer, the interaction and the issuer's key
// set (its AID and mailbox key; CheckGrant reads nothing else).
type grantFuzzFixture struct {
	issuer, ix string
	mbox       ed25519.PrivateKey
	keys       EncKeySet
	seeds      [][]byte
}

func newGrantFuzzFixture(tb testing.TB) *grantFuzzFixture {
	tb.Helper()
	var v vecGrant1
	readVector(tb, fileGrant1, &v)
	fx := &grantFuzzFixture{issuer: v.Issuer, ix: v.IX, mbox: ed25519.NewKeyFromSeed(goldenSeed(v.ID, "mbox"))}
	fx.keys = EncKeySet{AID: v.Issuer, Mbox: Mbox{Epoch: v.Mbox.Epoch, Pub: fx.mbox.Public().(ed25519.PublicKey)}}
	for _, g := range v.Grants {
		fx.seeds = append(fx.seeds, g.Grant)
	}
	for _, c := range v.Cases {
		fx.seeds = append(fx.seeds, c.Grant)
	}
	var s vecSealed2A
	readVector(tb, fileSealed2A, &s)
	fx.seeds = append(fx.seeds, s.Inner.Grant)
	return fx
}

// grantSteps are the Detail values of a CheckGrant failure.
var grantSteps = map[string]bool{"decode": true, "body": true, "type": true, "owner": true, "keys": true, "epoch": true,
	"sig": true, "holder": true, "class": true, "exp": true, "ix": true, "p2p": true, "pay": true}

func FuzzGrant(f *testing.F) {
	fx := newGrantFuzzFixture(f)
	for i, s := range fx.seeds {
		f.Add(s, i%2 == 0, uint64(capFuzzNow))
	}
	f.Fuzz(func(t *testing.T, raw []byte, resign bool, now uint64) {
		if resign {
			if g, err := decodeGrant(raw); err == nil {
				g.Cap.Sig = ed25519.Sign(fx.mbox, g.Cap.Body)
				raw = mustEncode(t, g)
			}
		}
		in := &SealedInner{From: fx.issuer, IX: fx.ix, Grant: raw}
		g, body, err := CheckGrant(in, &fx.keys, now)
		if err != nil {
			var se *Error
			if !errors.As(err, &se) || se.Reason != ReasonAccessInvalid || !grantSteps[se.Detail] || !se.Permanent() || g != nil || body != nil {
				t.Fatalf("CheckGrant returned %v (%v, %v)", err, g, body)
			}
			return
		}
		// Kept: every property CheckGrant promises holds.
		re, _ := body.Marshal()
		switch {
		case !bytes.Equal(re, g.Cap.Body):
			t.Fatal("kept a cap body that is not its CoreDet encoding")
		case body.Type != CapType || body.Owner != fx.issuer || body.Epoch != fx.keys.Mbox.Epoch:
			t.Fatalf("kept %+v", body)
		case !ed25519.Verify(fx.keys.Mbox.Pub, g.Cap.Body, g.Cap.Sig):
			t.Fatal("kept a cap the sender's mailbox key did not sign")
		case !bytes.Equal(g.HolderKey().Public().(ed25519.PublicKey), body.Holder):
			t.Fatal("kept a holder seed that is not the capability's holder")
		case body.Class != CapClassContact && body.Class != CapClassStranger:
			t.Fatalf("kept class %d", body.Class)
		case !capExpInWindow(body.CapExp, now):
			t.Fatalf("kept cap_exp %d at %d", body.CapExp, now)
		case g.IX != nil && *g.IX != fx.ix:
			t.Fatalf("kept a one-shot grant for %q", *g.IX)
		case g.P2P != nil && (body.Class != CapClassContact || g.IX != nil):
			t.Fatal("kept p2p outside a contact peer grant")
		case g.Pay != nil && g.IX != nil:
			t.Fatal("kept pay in a one-shot grant")
		case g.Home == "" || strings.IndexByte(g.Home, 0) >= 0:
			t.Fatalf("kept home %q", g.Home)
		}
		if u, err := UnmarshalGrant(raw); err != nil || !reflect.DeepEqual(u, g) {
			t.Fatalf("UnmarshalGrant disagrees with CheckGrant: %v", err)
		}
		// The issuer could have sent it: Marshal takes every kept grant whose expiry is set.
		if body.CapExp != 0 {
			if _, err := g.Marshal(); err != nil {
				t.Fatalf("a kept grant does not marshal: %v", err)
			}
		}
		// The kept grant delivers: its holder key's proof passes VerifyAccess for the issuer.
		d := sha256.Sum256(raw)
		a := &Access{Kind: AccessKindCap, Cap: &g.Cap, Proof: SignAccess(g.HolderKey(), body.CapID, d)}
		if err := VerifyAccess(a, d, fx.keys.Mbox, fx.issuer, now); err != nil {
			t.Fatalf("a kept grant does not deliver: %v", err)
		}
		// In another interaction a one-shot grant is refused; from another sender any grant is.
		if g.IX != nil {
			wantGrantStep(t, &SealedInner{From: fx.issuer, IX: fx.ix + "-other", Grant: raw}, &fx.keys, now, "ix")
		}
		wantGrantStep(t, &SealedInner{From: fx.issuer + "x", IX: fx.ix, Grant: raw}, &fx.keys, now, "owner")
	})
}

func wantGrantStep(t *testing.T, in *SealedInner, keys *EncKeySet, now uint64, step string) {
	t.Helper()
	_, _, err := CheckGrant(in, keys, now)
	wantStep(t, err, step)
}
