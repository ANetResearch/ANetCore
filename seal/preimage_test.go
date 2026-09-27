package seal

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/fxamacker/cbor/v2"
)

// designPreimage builds the §3.3 signature preimage from a decrypted inner
// field map by the rule as the design states it: drop keys 20 and 21, add
// 0: "anet-relay-sig/v1", 30: outer.enc, 31: outer.kid, 32: outer.suite, and
// CoreDet-encode. It uses literal key numbers and the literal label and does
// not call sigPreimage, so a change to the package constants or to
// sigPreimage makes the two disagree.
func designPreimage(t *testing.T, inner fieldMap, outer *SealedEnvelope) []byte {
	t.Helper()
	m := map[uint64]cbor.RawMessage{}
	for k, v := range inner {
		if k == 20 || k == 21 {
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
	put(0, "anet-relay-sig/v1")
	put(30, outer.Enc)
	put(31, outer.KID)
	put(32, uint64(outer.Suite))
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

// The preimage Open returns is the one the design defines, and the sender's
// signature is over exactly those bytes. The check uses ed25519 directly
// with the sender's current public key, not identity.VerifyObject, so it
// does not depend on the verification path under test elsewhere.
func TestSigPreimageFollowsDesign(t *testing.T) {
	a, b := newParty(t), newParty(t)
	in := innerFrom(t, a, b, t0)
	in.Ext = map[uint64][]byte{64: enc(t, "ext"), 100000: enc(t, []byte{1, 2, 3})}
	env := mustSeal(t, in, &b.kp.Public, a.c.Sign)
	o := mustOpen(t, env, b)
	fields := decryptFields(t, env, b.kp)

	want := designPreimage(t, fields, &o.Outer)
	if !bytes.Equal(o.Preimage, want) {
		t.Fatalf("Open preimage differs from the §3.3 rule\n got  %x\n want %x", o.Preimage, want)
	}
	kel := a.c.KEL()
	pub := ed25519.PublicKey(kel[len(kel)-1].Event.Keys[0])
	if !ed25519.Verify(pub, want, sigOf(t, fields)) {
		t.Fatal("the sender's signature is not over the §3.3 preimage")
	}
}

// The pinned VEC-SEALED-1 preimage is the §3.3 preimage of the pinned
// envelope, and the pinned signature is the conformance identity's signature
// over it. Without this, the file only records what the implementation
// produced when the vector was generated.
func TestVEC_SEALED_1_PreimageFollowsDesign(t *testing.T) {
	_, g := readGolden(t)
	_, rk := goldenKeys(t)
	outer, err := ParseOuter(g["envelope"])
	if err != nil {
		t.Fatal(err)
	}
	fields := decryptFields(t, g["envelope"], rk)
	want := designPreimage(t, fields, outer)
	if !bytes.Equal(g["sig_preimage"], want) {
		t.Fatalf("pinned preimage differs from the §3.3 rule\n file %x\n want %x", g["sig_preimage"], want)
	}
	kel := identity.SuiteController().KEL()
	pub := ed25519.PublicKey(kel[0].Event.Keys[0])
	if !ed25519.Verify(pub, want, sigOf(t, fields)) {
		t.Fatal("the pinned signature is not the conformance identity's signature over the §3.3 preimage")
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
	_, err = Open(encryptPlaintext(t, dup, b.aid(), &b.kp.Public), b.aid(), b.ring())
	wantReason(t, err, ReasonBadInner)

	// Control: the unmodified plaintext, re-encrypted, opens.
	if _, err := Open(encryptPlaintext(t, pt, b.aid(), &b.kp.Public), b.aid(), b.ring()); err != nil {
		t.Fatalf("control: %v", err)
	}
}
