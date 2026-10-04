package seal

// Tests of the second layer (FS §2.5-§2.8, FS-C10 to FS-C14, FS-C17; core §2.2, §3.2 L2, §3.3).

import (
	"bytes"
	"crypto/hpke"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
)

// ixKeys is an IXKeyLookup over a fixed set of interaction keys, by kid.
type ixKeys []*IXKey

func (s ixKeys) IXKey(ikid []byte) (*IXKey, error) {
	for _, k := range s {
		if bytes.Equal(k.KID(), ikid) {
			return k, nil
		}
	}
	return nil, nil
}

func mustIXKey(t testing.TB, ix, peer string) *IXKey {
	t.Helper()
	k, err := GenerateIXKey(SuiteX25519, ix, peer)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sealTwo seals in to recipient with a second layer to peer's interaction key and adds a
// session access.
func sealTwo(t *testing.T, in *SealedInner, recipient *EncKey, sign SignFunc, peer *IXKey, o SealOpts) ([]byte, AckKey) {
	t.Helper()
	o.PeerRK = peer.RK()
	return mustSealAck(t, in, recipient, sign, o)
}

// openBoth decrypts both layers of env with the recipient's epoch key and interaction key, by
// the test's own HPKE calls, and returns the Wrap and the inner bytes.
func openBoth(t *testing.T, env []byte, kp *KeyPair, key *IXKey) (*wrapFields, []byte) {
	t.Helper()
	outer, err := ParseOuter(env)
	if err != nil {
		t.Fatal(err)
	}
	w, err := decodeWrap(openLayer1(t, env, kp))
	if err != nil {
		t.Fatal(err)
	}
	if w.ikid == nil {
		t.Fatal("no second layer")
	}
	p := params(key.Suite)
	sk, err := p.kem.NewPrivateKey(key.Private)
	if err != nil {
		t.Fatal(err)
	}
	info, err := IXInfo(outer.To, key.Suite, w.ikid)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := hpke.Open(sk, p.kdf, p.aead, info, append(append([]byte(nil), w.enc2...), w.body...))
	if err != nil {
		t.Fatalf("second layer: %v", err)
	}
	return w, pt
}

// encryptInner2 seals the inner bytes pt with a second layer to key for the recipient to (L2), a
// padded Wrap and layer 1 to recipient, as a party holding a decrypted message could do. It
// does not sign.
func encryptInner2(t *testing.T, pt []byte, to string, recipient *EncKey, key *IXKey) []byte {
	t.Helper()
	two, err := newLayer2Sender(to, key.RK())
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := two.sender.Seal(nil, pt)
	if err != nil {
		t.Fatal(err)
	}
	return encryptWrapFields(t, &wrapFields{ikid: two.ikid, enc2: two.enc2, body: ct2}, to, recipient)
}

// encryptFields2 is encryptInner2 for an inner field map.
func encryptFields2(t *testing.T, m fieldMap, to string, recipient *EncKey, key *IXKey) []byte {
	t.Helper()
	return encryptInner2(t, mustMarshalFields(t, m), to, recipient, key)
}

// encryptWrapFields pads w and encrypts it to recipient at layer 1.
func encryptWrapFields(t *testing.T, w *wrapFields, to string, recipient *EncKey) []byte {
	t.Helper()
	m, _, err := w.paddedMap()
	if err != nil {
		t.Fatal(err)
	}
	return encryptWrap(t, mustMarshalFields(t, m), to, recipient)
}

func cloneFields(m fieldMap) fieldMap {
	c := make(fieldMap, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func TestGenerateIXKey(t *testing.T) {
	k, err := GenerateIXKey(SuiteX25519, "ix-1", "bpeer")
	if err != nil {
		t.Fatal(err)
	}
	if k.IX != "ix-1" || k.PeerAID != "bpeer" || k.Suite != SuiteX25519 || len(k.Pub) != 32 || len(k.Private) != 32 {
		t.Fatalf("key %+v", k)
	}
	sk, err := params(SuiteX25519).kem.NewPrivateKey(k.Private)
	if err != nil || !bytes.Equal(sk.PublicKey().Bytes(), k.Pub) {
		t.Fatalf("the private half is not the key of the public half (%v)", err)
	}
	if !bytes.Equal(k.KID(), KID(SuiteX25519, k.Pub)) || !bytes.Equal(k.RK().KID(), k.KID()) {
		t.Fatal("KID is not L15 of the public half")
	}
	rk := k.RK()
	if rk.Suite != SuiteX25519 || !bytes.Equal(rk.Pub, k.Pub) || rk.check() != nil {
		t.Fatalf("RK %+v", rk)
	}
	rk.Pub[0] ^= 1
	if k.Pub[0] == rk.Pub[0] {
		t.Fatal("RK shares its bytes with the key")
	}
	// Printing a key never prints its private half.
	for _, out := range []string{fmt.Sprint(k), fmt.Sprintf("%v %+v %#v %s", k, k, k, *k), fmt.Sprintf("%+v", []*IXKey{k})} {
		if strings.Contains(out, fmt.Sprintf("%x", k.Private)) || strings.Contains(out, fmt.Sprint(k.Private)) ||
			!strings.Contains(out, fmt.Sprintf("%x", k.KID())) {
			t.Fatalf("printed key: %s", out)
		}
	}
	k2 := mustIXKey(t, "ix-1", "bpeer")
	if bytes.Equal(k2.Pub, k.Pub) {
		t.Fatal("two keys for the same interaction are the same key")
	}
	for name, c := range map[string]struct {
		suite    Suite
		ix, peer string
		reason   string
	}{
		"suite 2":       {SuiteXWing, "ix", "p", ReasonUnknownSuite},
		"suite 0":       {0, "ix", "p", ReasonUnknownSuite},
		"no ix":         {SuiteX25519, "", "p", ReasonInvalidInput},
		"no peer":       {SuiteX25519, "ix", "", ReasonInvalidInput},
		"ix with NUL":   {SuiteX25519, "i\x00x", "p", ReasonInvalidInput},
		"peer with NUL": {SuiteX25519, "ix", "p\x00", ReasonInvalidInput},
	} {
		t.Run(name, func(t *testing.T) {
			k, err := GenerateIXKey(c.suite, c.ix, c.peer)
			if k != nil {
				t.Fatal("a key with an error")
			}
			wantReason(t, err, c.reason)
		})
	}
}

// A message sealed with a second layer opens under the recipient's interaction key: two
// layers, the ikid of that key, the inner as sent, a preimage with ikid and enc2, and the
// layer-1 ack_key (FS-C10, FS-C13, FS-C14, FS-C17).
func TestSecondLayerRoundTrip(t *testing.T) {
	a, b := newParty(t), newParty(t)
	bk := mustIXKey(t, "ix-1", a.aid()) // b's key in ix-1 with a
	ak := mustIXKey(t, "ix-1", b.aid()) // a's key in ix-1 with b
	for _, tc := range []struct {
		name string
		body int
		exp  bool
	}{{"empty body", 0, false}, {"short", 5, false}, {"long", 70000, false}, {"one-shot", 100, true}} {
		t.Run(tc.name, func(t *testing.T) {
			in := innerFrom(t, a, b, t0)
			in.Body = bytes.Repeat([]byte{0x61}, tc.body)
			in.RK = ak.RK()
			in.Ext = map[uint64][]byte{64: enc(t, "ext")}
			var o SealOpts
			if tc.exp {
				o.Exp = in.Exp
			}
			env, ack := sealTwo(t, in, &b.kp.Public, a.c.Sign, bk, o)
			got, err := Open(env, b.aid(), b.ring(), ixKeys{bk})
			if err != nil {
				t.Fatal(err)
			}
			if got.Layers != 2 || !bytes.Equal(got.IKID, bk.KID()) || got.AckKey != ack {
				t.Fatalf("layers %d, ikid %x (want %x), ack_key from Seal %v", got.Layers, got.IKID, bk.KID(), got.AckKey == ack)
			}
			g := got.Inner
			if g.From != in.From || g.To != in.To || g.IX != in.IX || !bytes.Equal(g.MID, in.MID) || g.TS != in.TS ||
				g.Exp != in.Exp || !bytes.Equal(g.Body, in.Body) || !bytes.Equal(g.KEL, in.KEL) || !bytes.Equal(g.Keys, in.Keys) ||
				g.RK == nil || !bytes.Equal(g.RK.Pub, ak.Pub) || got.RK != g.RK || !bytes.Equal(g.Ext[64], in.Ext[64]) {
				t.Fatalf("opened inner %+v", g)
			}
			if err := VerifyInnerSig(&g, got.Preimage, got.KEL, t0+minuteMS, DefaultRotationGrace); err != nil {
				t.Fatal(err)
			}
			if tc.exp && (got.Outer.Exp == nil || *got.Outer.Exp != in.Exp) {
				t.Fatal("outer key 8 lost")
			}

			// The Wrap: keys 1, 2, 3 and 21 on a Padmé length; ikid is the kid of the
			// interaction key; the second layer opens under L2 to the inner bytes, unpadded.
			wrap := openLayer1(t, env, b.kp)
			if Padme(len(wrap)) != len(wrap) {
				t.Fatalf("Wrap of %d bytes is not on a Padmé length", len(wrap))
			}
			wm, err := decodeFields(wrap)
			if err != nil {
				t.Fatal(err)
			}
			for k := range wm {
				if k != wrapKeyIKID && k != wrapKeyEnc2 && k != wrapKeyBody && k != wrapKeyPad {
					t.Fatalf("Wrap key %d", k)
				}
			}
			w, inner := openBoth(t, env, b.kp, bk)
			if !bytes.Equal(w.ikid, KID(SuiteX25519, bk.Pub)) || len(w.enc2) != 32 {
				t.Fatalf("ikid %x, enc2 of %d bytes", w.ikid, len(w.enc2))
			}
			fields, err := decodeFields(inner)
			if err != nil {
				t.Fatal(err)
			}
			if re := mustMarshalFields(t, fields); !bytes.Equal(re, inner) {
				t.Fatal("the layer-2 plaintext is not exactly the inner (padding inside?)")
			}
			if _, ok := fields[21]; ok {
				t.Fatal("the inner carries a pad")
			}
			// The preimage carries ikid and enc2 (core §3.3), as the design writes it.
			want := designPreimage(t, fields, got.Outer.Enc, got.Outer.KID, uint64(got.Outer.Suite), w.ikid, w.enc2)
			if !bytes.Equal(got.Preimage, want) {
				t.Fatal("the preimage does not follow core §3.3 with a second layer")
			}
			// The ack_key is the layer-1 export (FS-C14), not anything of layer 2.
			if l1 := layer1Export(t, env, b.kp); l1 != ack {
				t.Fatal("ack_key is not the layer-1 export")
			}
		})
	}
	// The second layer uses its own label: under the layer-1 info it does not open.
	t.Run("L2 is not L1", func(t *testing.T) {
		in := innerFrom(t, a, b, t0)
		env, _ := sealTwo(t, in, &b.kp.Public, a.c.Sign, bk, SealOpts{})
		w, err := decodeWrap(openLayer1(t, env, b.kp))
		if err != nil {
			t.Fatal(err)
		}
		p := params(SuiteX25519)
		sk, _ := p.kem.NewPrivateKey(bk.Private)
		l1, _ := HPKEInfo(b.aid(), SuiteX25519, w.ikid)
		if _, err := hpke.Open(sk, p.kdf, p.aead, l1, append(append([]byte(nil), w.enc2...), w.body...)); err == nil {
			t.Fatal("the second layer opens under the layer-1 label")
		}
		l2, _ := IXInfo(b.aid(), SuiteX25519, w.ikid)
		var info map[uint64]any
		if err := coredet.Unmarshal(l2, &info); err != nil || info[1] != IXLabel || info[2] != b.aid() ||
			info[3] != uint64(1) || !bytes.Equal(info[4].([]byte), w.ikid) {
			t.Fatalf("L2 info %v (%v)", info, err)
		}
	})
	// Each Seal draws a fresh layer-2 ephemeral key.
	t.Run("randomized", func(t *testing.T) {
		in := innerFrom(t, a, b, t0)
		e1, _ := sealTwo(t, in, &b.kp.Public, a.c.Sign, bk, SealOpts{})
		e2, _ := sealTwo(t, in, &b.kp.Public, a.c.Sign, bk, SealOpts{})
		w1, _ := openBoth(t, e1, b.kp, bk)
		w2, _ := openBoth(t, e2, b.kp, bk)
		if bytes.Equal(w1.enc2, w2.enc2) {
			t.Fatal("two seals share enc2")
		}
	})
}

// layer1Export is the ack_key the recipient context of env exports.
func layer1Export(t *testing.T, env []byte, kp *KeyPair) AckKey {
	t.Helper()
	outer, err := ParseOuter(env)
	if err != nil {
		t.Fatal(err)
	}
	p := params(outer.Suite)
	sk, _ := p.kem.NewPrivateKey(kp.Private)
	info, _ := HPKEInfo(outer.To, outer.Suite, outer.KID)
	r, err := hpke.NewRecipient(outer.Enc, sk, p.kdf, p.aead, info)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Open(nil, outer.CT); err != nil {
		t.Fatal(err)
	}
	k, err := r.Export(DAckExporterContext, AckKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	var ack AckKey
	copy(ack[:], k)
	return ack
}

// FS-C13: Open runs its steps in order; each failure gives its reason, with an ack_key exactly
// from the Wrap on; a store failure of the interaction-key lookup comes back as it is. Where
// one envelope fails two steps, the earlier one is reported.
func TestOpenOrder(t *testing.T) {
	a, b, c := newParty(t), newParty(t), newParty(t)
	bk := mustIXKey(t, "ix-1", a.aid())
	other := mustIXKey(t, "ix-2", a.aid())
	in := innerFrom(t, a, b, t0)
	good, _ := sealTwo(t, in, &b.kp.Public, a.c.Sign, bk, SealOpts{})
	_, innerBytes := openBoth(t, good, b.kp, bk)
	fields, err := decodeFields(innerBytes)
	if err != nil {
		t.Fatal(err)
	}
	with := func(edit func(fieldMap)) []byte {
		m := cloneFields(fields)
		edit(m)
		return encryptFields2(t, m, b.aid(), &b.kp.Public, bk)
	}
	w0, _ := openBoth(t, good, b.kp, bk)
	storeErr := errors.New("database is locked")
	asked := 0
	counting := func(l IXKeyLookup) IXKeyLookup {
		return ixLookupFunc(func(ikid []byte) (*IXKey, error) { asked++; return l.IXKey(ikid) })
	}
	wrongPriv := *bk
	wrongPriv.Private = other.Private
	suite2 := *bk
	suite2.Suite = SuiteXWing
	outerV1 := func() []byte {
		o, err := ParseOuter(good)
		if err != nil {
			t.Fatal(err)
		}
		o.V = 1
		bb, _ := o.Marshal()
		return bb
	}
	flipCT := func() []byte {
		o, _ := ParseOuter(good)
		o.CT = append([]byte(nil), o.CT...)
		o.CT[len(o.CT)-1] ^= 1
		bb, _ := o.Marshal()
		return bb
	}
	cases := []struct {
		name   string
		env    []byte
		as     *party // the node that opens; its AID with b's key ring
		ix     IXKeyLookup
		reason string // "" with ok false: the store error
		ack    bool
		ok     bool
		asks   int // lookups made
	}{
		// Steps 1-3: no ack_key, no lookup.
		{"1: outer v = 1", outerV1(), b, ixKeys{bk}, ReasonBadVersion, false, false, 0},
		{"1: not this node", good, c, ixKeys{bk}, ReasonWrongRecipient, false, false, 0},
		{"2: unknown kid", func() []byte {
			// Addressed to b, sealed to an epoch key b does not hold.
			env, _ := sealTwo(t, innerFrom(t, a, b, t0), &c.kp.Public, a.c.Sign, bk, SealOpts{})
			o, _ := ParseOuter(env)
			o.To = b.aid()
			bb, _ := o.Marshal()
			return bb
		}(), b, ixKeys{bk}, ReasonUnknownKey, false, false, 0},
		{"3: layer 1 does not open", flipCT(), b, ixKeys{bk}, ReasonDecrypt, false, false, 0},
		// Step 3a: the Wrap, then the lookup, then the second layer.
		{"3a: Wrap with key 4", encryptWrap(t, func() []byte {
			m, _, _ := w0.paddedMap()
			m[4] = enc(t, "x")
			return mustMarshalFields(t, m)
		}(), b.aid(), &b.kp.Public), b, ixKeys{bk}, ReasonBadWrap, true, false, 0},
		{"3a: no lookup", good, b, nil, ReasonSealedToClosedInteraction, true, false, 0},
		{"3a: no such key", good, b, ixKeys{other}, ReasonSealedToClosedInteraction, true, false, 1},
		{"3a: lookup fails", good, b, ixLookupFunc(func([]byte) (*IXKey, error) { return nil, storeErr }), "", true, false, 1},
		{"3a: lookup answers another key", good, b, ixLookupFunc(func([]byte) (*IXKey, error) { return other, nil }), ReasonSealedToClosedInteraction, true, false, 1},
		{"3a: lookup answers a key of suite 2", good, b, ixLookupFunc(func([]byte) (*IXKey, error) { return &suite2, nil }), ReasonSealedToClosedInteraction, true, false, 1},
		{"3a: the private half is not the key's", good, b, ixLookupFunc(func([]byte) (*IXKey, error) { return &wrongPriv, nil }), ReasonDecrypt, true, false, 1},
		{"3a: second-layer ciphertext changed", encryptWrapFields(t, &wrapFields{ikid: w0.ikid, enc2: w0.enc2,
			body: append(append([]byte(nil), w0.body[:len(w0.body)-1]...), w0.body[len(w0.body)-1]^1)}, b.aid(), &b.kp.Public),
			b, ixKeys{bk}, ReasonDecrypt, true, false, 1},
		{"3a: enc2 of another seal", encryptWrapFields(t, &wrapFields{ikid: w0.ikid, enc2: func() []byte {
			w, _ := openBoth(t, with(func(fieldMap) {}), b.kp, bk)
			return w.enc2
		}(), body: w0.body}, b.aid(), &b.kp.Public), b, ixKeys{bk}, ReasonDecrypt, true, false, 1},
		// Step 4, on the inner the second layer carried.
		{"4: inner not a map", encryptInner2(t, enc(t, "x"), b.aid(), &b.kp.Public, bk), b, ixKeys{bk}, ReasonBadInner, true, false, 1},
		{"4: inner key 21", with(func(m fieldMap) { m[21] = enc(t, []byte{0}) }), b, ixKeys{bk}, ReasonUnknownField, true, false, 1},
		{"4: rk of suite 2", with(func(m fieldMap) { m[keyRK] = enc(t, &RK{Suite: SuiteXWing, Pub: make([]byte, 32)}) }), b, ixKeys{bk}, ReasonBadRK, true, false, 1},
		{"4: another interaction", with(func(m fieldMap) { m[keyIX] = enc(t, "ix-2") }), b, ixKeys{bk}, ReasonIKeyMismatch, true, false, 1},
		{"4: another sender", with(func(m fieldMap) { m[keyFrom] = enc(t, c.aid()) }), b, ixKeys{bk}, ReasonIKeyMismatch, true, false, 1},
		{"4: inner to is not outer to", with(func(m fieldMap) { m[keyTo] = enc(t, c.aid()) }), b, ixKeys{bk}, ReasonToMismatch, true, false, 1},
		{"4: KEL over its cap", with(func(m fieldMap) { m[keyKEL] = enc(t, make([]byte, MaxKELBytes+1)) }), b, ixKeys{bk}, ReasonKELTooLarge, true, false, 1},
		{"ok", good, b, ixKeys{bk}, "", false, true, 1},
		// One envelope, two failures: the earlier step is reported.
		{"closed before a broken inner", encryptInner2(t, enc(t, "x"), b.aid(), &b.kp.Public, bk), b, ixKeys{other}, ReasonSealedToClosedInteraction, true, false, 1},
		{"store failure before a broken inner", encryptInner2(t, enc(t, "x"), b.aid(), &b.kp.Public, bk), b, ixLookupFunc(func([]byte) (*IXKey, error) { return nil, storeErr }), "", true, false, 1},
		{"a malformed inner before ikey-mismatch", with(func(m fieldMap) { m[keyIX] = enc(t, "ix-2\x00") }), b, ixKeys{bk}, ReasonBadInner, true, false, 1},
		{"ikey-mismatch before to-mismatch", with(func(m fieldMap) { m[keyIX] = enc(t, "ix-2"); m[keyTo] = enc(t, c.aid()) }), b, ixKeys{bk}, ReasonIKeyMismatch, true, false, 1},
		{"ikey-mismatch before the KEL cap", with(func(m fieldMap) { m[keyFrom] = enc(t, c.aid()); m[keyKEL] = enc(t, make([]byte, MaxKELBytes+1)) }), b, ixKeys{bk}, ReasonIKeyMismatch, true, false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asked = 0
			var look IXKeyLookup
			if tc.ix != nil {
				look = counting(tc.ix)
			}
			o, err := Open(tc.env, tc.as.aid(), b.ring(), look)
			if asked != tc.asks {
				t.Errorf("the lookup was asked %d times, want %d", asked, tc.asks)
			}
			if tc.ok {
				if err != nil || o.Layers != 2 {
					t.Fatalf("open: %v", err)
				}
				return
			}
			if tc.reason == "" {
				// The store failure, passed through (ENG-V8).
				if !errors.Is(err, storeErr) || errors.Unwrap(err) != storeErr || ReasonOf(err) != "" || IsPermanent(err) {
					t.Fatalf("store failure came back as %v (reason %q)", err, ReasonOf(err))
				}
				if _, ok := AckKeyOf(err); !ok {
					t.Fatal("store failure without the ack_key")
				}
				return
			}
			wantOpenFails(t, err, tc.reason, tc.ack)
			if tc.ack {
				if k, _ := AckKeyOf(err); k != layer1Export(t, tc.env, b.kp) {
					t.Fatal("the ack_key is not the layer-1 export")
				}
			}
		})
	}
	t.Run("one layer never asks the lookup", func(t *testing.T) {
		env := mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign)
		o, err := Open(env, b.aid(), b.ring(), ixLookupFunc(func([]byte) (*IXKey, error) {
			t.Fatal("asked for an interaction key with one layer")
			return nil, nil
		}))
		if err != nil || o.Layers != 1 || o.IKID != nil {
			t.Fatalf("open: %v", err)
		}
	})
}

// Mutation 12: the interaction key that opens the second layer must be the key of the inner's
// interaction and sender. A peer that seals a message of one interaction to the key of another,
// or a third party that seals to a key it learned, is refused (ikey-mismatch, FS-C13).
func TestIKeyMismatchAcrossInteractions(t *testing.T) {
	a, b, c := newParty(t), newParty(t), newParty(t)
	k1 := mustIXKey(t, "ix-1", a.aid()) // b's keys: two interactions with a, one with c
	k2 := mustIXKey(t, "ix-2", a.aid())
	k3 := mustIXKey(t, "ix-3", c.aid())
	keys := ixKeys{k1, k2, k3}
	msg := func(from *party, ix string, to *IXKey) []byte {
		in := innerFrom(t, from, b, t0)
		in.IX = ix
		env, _ := sealTwo(t, in, &b.kp.Public, from.c.Sign, to, SealOpts{})
		return env
	}
	for _, tc := range []struct {
		name   string
		env    []byte
		reason string
	}{
		{"a, ix-1, key of ix-1", msg(a, "ix-1", k1), ""},
		{"a, ix-2, key of ix-2", msg(a, "ix-2", k2), ""},
		{"c, ix-3, key of ix-3", msg(c, "ix-3", k3), ""},
		{"a, ix-2, key of ix-1", msg(a, "ix-2", k1), ReasonIKeyMismatch},
		{"a, ix-1, key of ix-2", msg(a, "ix-1", k2), ReasonIKeyMismatch},
		{"c, ix-1, key of ix-1 (a's)", msg(c, "ix-1", k1), ReasonIKeyMismatch},
		{"a, ix-3, key of ix-3 (c's)", msg(a, "ix-3", k3), ReasonIKeyMismatch},
		{"c, ix-3, key of ix-1", msg(c, "ix-3", k1), ReasonIKeyMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, err := Open(tc.env, b.aid(), b.ring(), keys)
			if tc.reason == "" {
				if err != nil {
					t.Fatal(err)
				}
				if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0, DefaultRotationGrace); err != nil {
					t.Fatal(err)
				}
				return
			}
			wantOpenFails(t, err, tc.reason, true)
		})
	}
}

// SI-31, CORE-L6: the signature binds the layering. Stripping the second layer, replacing its
// enc2 or ikid, or moving a single-layer message under a second layer all leave a signature
// that does not verify.
func TestLayeringIsSigned(t *testing.T) {
	a, b := newParty(t), newParty(t)
	bk := mustIXKey(t, "ix-1", a.aid())
	other := mustIXKey(t, "ix-1", a.aid())
	verify := func(o *Opened, pre []byte) error {
		return VerifyInnerSig(&o.Inner, pre, o.KEL, t0+minuteMS, DefaultRotationGrace)
	}
	two, _ := sealTwo(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, bk, SealOpts{})
	o2, err := Open(two, b.aid(), b.ring(), ixKeys{bk})
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(o2, o2.Preimage); err != nil {
		t.Fatal(err)
	}
	w2, inner2 := openBoth(t, two, b.kp, bk)
	fields2, _ := decodeFields(inner2)
	otherW, _ := openBoth(t, mustSealTwoOnly(t, a, b, other), b.kp, other)

	// The same fields and the same layer-1 header, under another layering: the preimages a
	// receiver would build. Only the second-layer values differ from the signed one.
	for name, l2 := range map[string][2][]byte{
		"stripped":      {nil, nil},
		"enc2 replaced": {w2.ikid, otherW.enc2},
		"ikid replaced": {otherW.ikid, w2.enc2},
	} {
		t.Run(name, func(t *testing.T) {
			pre, err := sigPreimage(fields2, o2.Outer.Enc, o2.Outer.KID, o2.Outer.Suite, l2[0], l2[1])
			if err != nil {
				t.Fatal(err)
			}
			wantReason(t, verify(o2, pre), ReasonBadSig)
		})
	}
	// Whole envelopes, as a party holding the plaintext can build them.
	t.Run("stripped envelope", func(t *testing.T) {
		re := encryptFields(t, fields2, b.aid(), &b.kp.Public)
		o, err := Open(re, b.aid(), b.ring(), ixKeys{bk})
		if err != nil || o.Layers != 1 {
			t.Fatalf("open: %v", err)
		}
		wantReason(t, verify(o, o.Preimage), ReasonBadSig)
	})
	t.Run("second layer sealed again", func(t *testing.T) {
		re := encryptFields2(t, fields2, b.aid(), &b.kp.Public, bk)
		o, err := Open(re, b.aid(), b.ring(), ixKeys{bk})
		if err != nil || o.Layers != 2 {
			t.Fatalf("open: %v", err)
		}
		wantReason(t, verify(o, o.Preimage), ReasonBadSig)
	})
	t.Run("one layer moved under a second", func(t *testing.T) {
		one := mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign)
		re := encryptFields2(t, decryptFields(t, one, b.kp), b.aid(), &b.kp.Public, bk)
		o, err := Open(re, b.aid(), b.ring(), ixKeys{bk})
		if err != nil || o.Layers != 2 {
			t.Fatalf("open: %v", err)
		}
		wantReason(t, verify(o, o.Preimage), ReasonBadSig)
	})
}

// mustSealTwoOnly seals a message from a to b with a second layer to key.
func mustSealTwoOnly(t *testing.T, a, b *party, key *IXKey) []byte {
	t.Helper()
	env, _ := sealTwo(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign, key, SealOpts{})
	return env
}

// P-8: for any inner length, with or without a second layer, the Wrap decodes to what was
// encoded and its encoding has a Padmé length.
func TestWrapRoundTrip(t *testing.T) {
	r := rand.New(rand.NewPCG(8, 8))
	lengths := []int{0, 1, 2, 22, 23, 24, 255, 256, 257, 65535, 65536, 65537, 200000}
	for i := 0; i < 3000; i++ {
		lengths = append(lengths, r.IntN(5000))
	}
	unreachable := 0
	for i, n := range lengths {
		w := wrapFields{body: make([]byte, n)}
		for j := range w.body {
			w.body[j] = byte(r.Uint32())
		}
		if i%2 == 1 {
			w.ikid, w.enc2 = make([]byte, KIDLen), make([]byte, 32)
			for j := range w.ikid {
				w.ikid[j] = byte(r.Uint32())
			}
			for j := range w.enc2 {
				w.enc2[j] = byte(r.Uint32())
			}
		}
		m, want, err := w.paddedMap()
		if err != nil {
			t.Fatal(err)
		}
		b := mustMarshalFields(t, m)
		if len(b) != want || Padme(len(b)) != len(b) {
			t.Fatalf("length %d (layers %d): Wrap of %d bytes, target %d", n, 1+i%2, len(b), want)
		}
		unpadded := m
		unpadded[wrapKeyPad] = []byte{0x40}
		if Padme(encodedLen(unpadded)) != len(b) {
			unreachable++
		}
		got, err := decodeWrap(b)
		if err != nil {
			t.Fatalf("length %d: %v", n, err)
		}
		if !bytes.Equal(got.body, w.body) || !bytes.Equal(got.ikid, w.ikid) || !bytes.Equal(got.enc2, w.enc2) ||
			(got.ikid == nil) != (w.ikid == nil) {
			t.Fatalf("length %d (layers %d): decode(encode(w)) != w", n, 1+i%2)
		}
	}
	if unreachable == 0 {
		t.Fatal("no length hit an unreachable pad offset; widen the range")
	}
	if _, _, err := (&wrapFields{ikid: make([]byte, KIDLen), body: nil}).paddedMap(); err == nil {
		t.Fatal("an ikid without enc2 was encoded")
	}
}

// Both sides of an interaction: each announces its own rk and seals to the rk the other
// announced, so the requester's later messages and the provider's replies all have two layers,
// each opening under the recipient's own interaction key (FS-X4, FS-X5).
func TestBothSidesSealToEachOther(t *testing.T) {
	a, b := newParty(t), newParty(t)
	bk := mustIXKey(t, "ix-1", a.aid()) // b's key in ix-1
	ak := mustIXKey(t, "ix-1", b.aid()) // a's key in ix-1
	in := innerFrom(t, a, b, t0)
	in.RK = ak.RK()
	env, _ := sealTwo(t, in, &b.kp.Public, a.c.Sign, bk, SealOpts{})
	o, err := Open(env, b.aid(), b.ring(), ixKeys{bk})
	if err != nil {
		t.Fatal(err)
	}
	// b answers to the rk a announced, which a opens with ak.
	reply := innerFrom(t, b, a, t0+1)
	reply.RK = bk.RK()
	env2, _ := mustSealAck(t, reply, &a.kp.Public, b.c.Sign, SealOpts{PeerRK: o.RK})
	o2, err := Open(env2, a.aid(), a.ring(), ixKeys{ak})
	if err != nil {
		t.Fatal(err)
	}
	if o2.Layers != 2 || !bytes.Equal(o2.IKID, ak.KID()) || o2.RK == nil || !bytes.Equal(o2.RK.Pub, bk.Pub) {
		t.Fatalf("reply: layers %d, ikid %x", o2.Layers, o2.IKID)
	}
	if err := VerifyInnerSig(&o2.Inner, o2.Preimage, o2.KEL, t0+minuteMS, DefaultRotationGrace); err != nil {
		t.Fatal(err)
	}
	// Neither side can open the other's: b does not hold ak, a does not hold bk.
	_, err = Open(env2, a.aid(), a.ring(), ixKeys{bk})
	wantOpenFails(t, err, ReasonSealedToClosedInteraction, true)
}
