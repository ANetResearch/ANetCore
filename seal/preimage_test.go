package seal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/fxamacker/cbor/v2"
)

// designPreimage builds the signature preimage v2 from a decrypted inner field
// map by the rule as core §3.3 states it: copy every key but 20; key 9 becomes
// the SHA-256 of the body as a byte string; add 0: "anet-relay-sig/v2",
// 30: enc, 31: kid, 32: suite, 33: ikid and 34: enc2 (CBOR null, 0xf6, for a
// single layer); CoreDet-encode. It uses literal key numbers and the literal
// label and does not call sigPreimage, so a change to the package constants
// or to sigPreimage makes the two disagree.
func designPreimage(t *testing.T, inner fieldMap, enc1, kid []byte, suite uint64, ikid, enc2 []byte) []byte {
	t.Helper()
	m := map[uint64]cbor.RawMessage{}
	for k, v := range inner {
		if k == 20 {
			continue
		}
		m[k] = v
	}
	put := func(k uint64, v any) {
		b, err := coredet.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		m[k] = b
	}
	var body []byte
	if err := coredet.Unmarshal(inner[9], &body); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(body)
	put(9, d[:])
	put(0, "anet-relay-sig/v2")
	put(30, enc1)
	put(31, kid)
	put(32, suite)
	m[33], m[34] = cbor.RawMessage{0xf6}, cbor.RawMessage{0xf6}
	if ikid != nil {
		put(33, ikid)
		put(34, enc2)
	}
	b, err := coredet.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sigOf returns the raw signature bytes carried at inner key 20.
func sigOf(t *testing.T, inner fieldMap) []byte {
	t.Helper()
	var sig []byte
	if err := coredet.Unmarshal(inner[20], &sig); err != nil {
		t.Fatal(err)
	}
	return sig
}

// The preimage Open returns is the one core §3.3 defines, and the sender's
// signature is over exactly those bytes. The check uses ed25519 directly
// with the sender's current public key, not identity.VerifyObject, so it
// does not depend on the verification path under test elsewhere.
func TestSigPreimageFollowsDesign(t *testing.T) {
	a, b := newParty(t), newParty(t)
	in := innerFrom(t, a, b, t0)
	in.Ext = map[uint64][]byte{64: enc(t, "ext"), 100000: enc(t, []byte{1, 2, 3})}
	in.Grant, in.RK = testGrant, &RK{Suite: SuiteX25519, Pub: make([]byte, 32)}
	env := mustSeal(t, in, &b.kp.Public, a.c.Sign)
	o := mustOpen(t, env, b)
	fields := decryptFields(t, env, b.kp)

	want := designPreimage(t, fields, o.Outer.Enc, o.Outer.KID, uint64(o.Outer.Suite), nil, nil)
	if !bytes.Equal(o.Preimage, want) {
		t.Fatalf("Open preimage differs from the §3.3 rule\n got  %x\n want %x", o.Preimage, want)
	}
	if bytes.Contains(o.Preimage, in.Body) {
		t.Fatal("the preimage carries the body, not its digest")
	}
	kel := a.c.KEL()
	pub := ed25519.PublicKey(kel[len(kel)-1].Event.Keys[0])
	if !ed25519.Verify(pub, want, sigOf(t, fields)) {
		t.Fatal("the sender's signature is not over the §3.3 preimage")
	}

	// Two layers: 33 and 34 carry ikid and enc2, so the preimage differs
	// from the single-layer one (SI-31).
	ikid, enc2 := bytes.Repeat([]byte{1}, KIDLen), bytes.Repeat([]byte{2}, 32)
	two, err := sigPreimage(fields, o.Outer.Enc, o.Outer.KID, o.Outer.Suite, ikid, enc2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(two, designPreimage(t, fields, o.Outer.Enc, o.Outer.KID, uint64(o.Outer.Suite), ikid, enc2)) || bytes.Equal(two, want) {
		t.Fatal("the two-layer preimage does not follow §3.3")
	}
	for _, half := range [][2][]byte{{ikid, nil}, {nil, enc2}} {
		if _, err := sigPreimage(fields, o.Outer.Enc, o.Outer.KID, o.Outer.Suite, half[0], half[1]); err == nil {
			t.Fatal("ikid without enc2 (or the reverse) built a preimage")
		}
	}
	for _, k := range []uint64{0, 30, 31, 32, 33, 34} {
		m := make(fieldMap, len(fields)+1)
		for kk, v := range fields {
			m[kk] = v
		}
		m[k] = enc(t, "x")
		if _, err := sigPreimage(m, o.Outer.Enc, o.Outer.KID, o.Outer.Suite, nil, nil); err == nil {
			t.Fatalf("an inner with key %d built a preimage", k)
		}
	}
}

// A decrypted inner that repeats a key is rejected. With a repeated key the
// value a decoder keeps (first or last) is an implementation choice, so the
// signed preimage and the fields a caller acts on could come from different
// occurrences.
func TestInnerDuplicateKeyRejected(t *testing.T) {
	a, b := newParty(t), newParty(t)
	env := mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign)
	fields := decryptFields(t, env, b.kp)
	pt, err := coredet.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if pt[0] != 0xa0+byte(len(fields)) || len(fields) >= 23 {
		t.Fatalf("setup: map header %x for %d fields", pt[0], len(fields))
	}
	// Append a second key 5 (ix) and bump the map count by one.
	dup := append([]byte{pt[0] + 1}, pt[1:]...)
	dup = append(dup, 0x05)
	dup = append(dup, enc(t, "ix-other")...)
	_, err = Open(encryptPlaintext(t, dup, b.aid(), &b.kp.Public), b.aid(), b.ring(), nil)
	wantOpenFails(t, err, ReasonBadInner, true)

	// Control: the unmodified plaintext, re-encrypted, opens.
	if _, err := Open(encryptPlaintext(t, pt, b.aid(), &b.kp.Public), b.aid(), b.ring(), nil); err != nil {
		t.Fatalf("control: %v", err)
	}
}
