package seal

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/wire"
)

// testMbox is a mailbox signing key for test key sets: epoch 1, a fresh Ed25519 public key.
func testMbox(t testing.TB) Mbox {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return Mbox{Epoch: 1, Pub: pub}
}

// epochKeys returns n fresh suite-1 keys, one per epoch, the first starting at the epoch that
// holds from: what a publisher lists for the current epoch and the ones after it.
func epochKeys(t testing.TB, from uint64, n int) []EncKey {
	t.Helper()
	first := from / EpochMS * EpochMS
	keys := make([]EncKey, n)
	for i := range keys {
		nb := first + uint64(i)*EpochMS
		kp, err := GenerateKeyPair(SuiteX25519, nb, nb+EpochMS)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = kp.Public
	}
	return keys
}

// rawEdit decodes an encoded map, lets edit change it, and re-encodes it canonically.
func rawEdit(t testing.TB, b []byte, edit func(m fieldMap)) []byte {
	t.Helper()
	m, err := decodeFields(b)
	if err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := coredet.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// rawEditKey changes the i-th EncKey inside an encoded EncKeySet.
func rawEditKey(t testing.TB, set []byte, i int, edit func(m fieldMap)) []byte {
	t.Helper()
	return rawEdit(t, set, func(m fieldMap) {
		var keys []cbor.RawMessage
		if err := coredet.Unmarshal(m[3], &keys); err != nil {
			t.Fatal(err)
		}
		keys[i] = rawEdit(t, keys[i], edit)
		b, err := coredet.Marshal(keys)
		if err != nil {
			t.Fatal(err)
		}
		m[3] = b
	})
}

// The five classes of key set a v0.3.0 signer and verifier refuse, each with the reason
// bad-keyset: (1) a type other than anet.enckeys/2 or a key the format does not register,
// (2) no keys, more than 32, or a key valid for more than two days, (3) a repeated kid, a kid
// that is not KID(suite, pub), or not_before out of order, (4) no mailbox signing key, epoch 0,
// or a public key that is not 32 bytes, (5) no key valid at now + ClockSkewMS. Every case is a
// valid set with one thing changed, signed by the owner's current key, so it fails for that
// thing alone; the detail says which.
func TestEncKeySetV2Rejects(t *testing.T) {
	a := newParty(t)
	now := t0 + 3*hourMS
	keys := epochKeys(t, t0, 15) // epochs of t0 .. t0 + 14 days
	mbox := testMbox(t)
	base := func() EncKeySet {
		return EncKeySet{Type: EncKeySetType, AID: a.aid(), Seq: now, Keys: append([]EncKey(nil), keys...), IssuedAt: now, Mbox: mbox}
	}
	encSet := func(s EncKeySet) []byte {
		b, err := coredet.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	with := func(f func(s *EncKeySet)) EncKeySet { s := base(); f(&s); return s }
	threeDays := keys[14]
	threeDays.NotAfter = threeDays.NotBefore + 3*dayMS
	twoDays := keys[14]
	twoDays.NotAfter = twoDays.NotBefore + 2*dayMS
	badKID := keys[3]
	badKID.KID = append([]byte(nil), keys[3].KID...)
	badKID.KID[KIDLen-1] ^= 1
	thirtyTwo := epochKeys(t, t0, 32)
	thirtyThree := epochKeys(t, t0, 33)

	type tc struct {
		name   string
		set    any    // an EncKeySet (also given to SignEncKeySet) or encoded bytes
		at     uint64 // verification time; 0 means now
		detail string // "" means accepted
	}
	cases := []tc{
		// Accepted, at each limit.
		{"fifteen epoch keys", base(), 0, ""},
		{"32 keys", with(func(s *EncKeySet) { s.Keys = thirtyTwo }), 0, ""},
		{"a key valid for exactly two days", with(func(s *EncKeySet) { s.Keys[14] = twoDays }), 0, ""},
		{"mbox epoch 1", with(func(s *EncKeySet) { s.Mbox.Epoch = 1 }), 0, ""},
		{"valid from now + skew", base(), keys[0].NotBefore - ClockSkewMS, ""},
		{"valid until now + skew", base(), keys[14].NotAfter - ClockSkewMS - 1, ""},

		// (1) type and registered keys.
		{"type anet.enckeys/1", with(func(s *EncKeySet) { s.Type = "anet.enckeys/1" }), 0, "type"},
		{"empty type", with(func(s *EncKeySet) { s.Type = "" }), 0, "type"},
		{"unregistered key 6", rawEdit(t, encSet(base()), func(m fieldMap) { m[6] = enc(t, nil) }), 0, "not a key of"},
		{"key 64 (no extension space)", rawEdit(t, encSet(base()), func(m fieldMap) { m[64] = enc(t, nil) }), 0, "not a key of"},
		{"unregistered key in an EncKey", rawEditKey(t, encSet(base()), 0, func(m fieldMap) { m[6] = enc(t, nil) }), 0, "unknown field"},
		{"unregistered key in the mbox", rawEdit(t, encSet(base()), func(m fieldMap) {
			m[5] = rawEdit(t, m[5], func(mb fieldMap) { mb[3] = enc(t, nil) })
		}), 0, "unknown field"},
		{"seq missing", rawEdit(t, encSet(base()), func(m fieldMap) { delete(m, 2) }), 0, "key 2 (seq) is missing"},
		{"not canonical", rawEdit(t, encSet(base()), func(m fieldMap) { m[2] = []byte{0x1b, 0, 0, 0, 0, 0, 0, 0, 5} }), 0, "canonical"},

		// (2) number of keys and validity.
		{"no keys", with(func(s *EncKeySet) { s.Keys = nil }), 0, "keys, want 1..32"},
		{"33 keys", with(func(s *EncKeySet) { s.Keys = thirtyThree }), 0, "keys, want 1..32"},
		{"a key valid for three days", with(func(s *EncKeySet) { s.Keys[14] = threeDays }), 0, "exceeds"},
		{"a key valid two days and 1 ms", with(func(s *EncKeySet) { s.Keys[14].NotAfter = s.Keys[14].NotBefore + 2*dayMS + 1 }), 0, "exceeds"},
		{"not_after equals not_before", with(func(s *EncKeySet) { s.Keys[14].NotAfter = s.Keys[14].NotBefore }), 0, "not_after is not after not_before"},

		// (3) kids and order.
		{"kid repeated", with(func(s *EncKeySet) { s.Keys = append([]EncKey{keys[0]}, keys...) }), 0, "repeats a kid"},
		{"kid is not KID(suite, pub)", with(func(s *EncKeySet) { s.Keys[3] = badKID }), 0, "kid does not match"},
		{"not_before out of order", with(func(s *EncKeySet) { s.Keys[2], s.Keys[3] = s.Keys[3], s.Keys[2] }), 0, "ascending not_before"},

		// (4) mailbox signing key.
		{"mbox missing", rawEdit(t, encSet(base()), func(m fieldMap) { delete(m, 5) }), 0, "key 5 (mbox) is missing"},
		{"mbox epoch 0", with(func(s *EncKeySet) { s.Mbox.Epoch = 0 }), 0, "mbox epoch is 0"},
		{"mbox pub 31 bytes", with(func(s *EncKeySet) { s.Mbox.Pub = s.Mbox.Pub[:31] }), 0, "mbox pub is 31 bytes"},
		{"mbox pub 33 bytes", with(func(s *EncKeySet) { s.Mbox.Pub = append(append([]byte(nil), s.Mbox.Pub...), 0) }), 0, "mbox pub is 33 bytes"},
		{"mbox pub empty", with(func(s *EncKeySet) { s.Mbox.Pub = nil }), 0, "mbox pub is 0 bytes"},

		// (5) a key valid at now + ClockSkewMS.
		{"day 15", base(), keys[14].NotAfter + hourMS, "no key valid"},
		{"last key ends at now + skew", base(), keys[14].NotAfter - ClockSkewMS, "no key valid"},
		{"first key starts after now + skew", base(), keys[0].NotBefore - ClockSkewMS - 1, "no key valid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			at := c.at
			if at == 0 {
				at = now
			}
			var b []byte
			if s, ok := c.set.(EncKeySet); ok {
				b = encSet(s)
				// The signer refuses the same sets, judging (5) at the set's issued_at.
				signAt := s
				signAt.IssuedAt = at
				_, err := SignEncKeySet(&signAt, a.c.Sign)
				checkDetail(t, "SignEncKeySet", err, c.detail)
			} else {
				b = c.set.([]byte)
			}
			sig, seq := a.c.Sign(b)
			_, err := VerifyEncKeySet(&SignedEncKeySet{Set: b, KeyStateSeq: seq, Sig: sig}, a.aid(), a.c.KEL(), at)
			checkDetail(t, "VerifyEncKeySet", err, c.detail)
		})
	}
}

func checkDetail(t *testing.T, who string, err error, detail string) {
	t.Helper()
	if detail == "" {
		if err != nil {
			t.Fatalf("%s: want accepted, got %v", who, err)
		}
		return
	}
	if err == nil {
		t.Fatalf("%s: accepted; want bad-keyset (%s)", who, detail)
	}
	if ReasonOf(err) != ReasonBadKeySet {
		t.Fatalf("%s: reason %q, want %q (%v)", who, ReasonOf(err), ReasonBadKeySet, err)
	}
	if !strings.Contains(err.Error(), detail) {
		t.Fatalf("%s: refused for another rule: %v (want %q)", who, err, detail)
	}
}

// Every key the registry does not assign to EncKeySet, EncKey, Mbox or SignedEncKeySet makes the
// decoder refuse the object (closed key spaces: no extension range either).
func TestEncKeySetV2RefusesUnregisteredKeys(t *testing.T) {
	r := wire.MustLoad()
	a := newParty(t)
	setBytes, err := a.set.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	contentOK := func(b []byte) error {
		_, err := decodeEncKeySet(b)
		return err
	}
	expect := func(t *testing.T, object string, valid []byte, splice func([]byte) []byte, decode func([]byte) error) {
		t.Helper()
		if err := decode(splice(valid)); err != nil {
			t.Fatalf("%s: the valid encoding is refused: %v", object, err)
		}
		negs, err := wire.Negatives(r, object, valid)
		if err != nil {
			t.Fatal(err)
		}
		if len(negs) == 0 {
			t.Fatalf("%s: no negatives", object)
		}
		for _, n := range negs {
			if decode(splice(n.Bytes)) == nil {
				t.Errorf("%s: key %d (%s) accepted", object, n.Key, n.Why)
			}
		}
	}
	same := func(b []byte) []byte { return b }

	t.Run("EncKeySet", func(t *testing.T) { expect(t, "EncKeySet", setBytes, same, contentOK) })
	t.Run("EncKey", func(t *testing.T) {
		m, err := decodeFields(setBytes)
		if err != nil {
			t.Fatal(err)
		}
		var keys []cbor.RawMessage
		if err := coredet.Unmarshal(m[3], &keys); err != nil {
			t.Fatal(err)
		}
		expect(t, "EncKey", keys[0], func(k []byte) []byte {
			return rawEdit(t, setBytes, func(m fieldMap) { m[3] = enc(t, []cbor.RawMessage{k}) })
		}, contentOK)
	})
	t.Run("Mbox", func(t *testing.T) {
		m, err := decodeFields(setBytes)
		if err != nil {
			t.Fatal(err)
		}
		expect(t, "Mbox", m[5], func(mb []byte) []byte {
			return rawEdit(t, setBytes, func(m fieldMap) { m[5] = mb })
		}, contentOK)
	})
	t.Run("SignedEncKeySet", func(t *testing.T) {
		signed, err := a.signed.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		expect(t, "SignedEncKeySet", signed, same, func(b []byte) error {
			_, err := UnmarshalSignedEncKeySet(b)
			return err
		})
	})
}

// UnmarshalSignedEncKeySet requires all three keys; DecideHighWaterSigned decodes the set as
// strictly as VerifyEncKeySet does.
func TestSignedEncKeySetDecodeV2(t *testing.T) {
	a := newParty(t)
	signed, err := a.signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for k, name := range map[uint64]string{1: "set", 2: "key_state_seq", 3: "sig"} {
		b := rawEdit(t, signed, func(m fieldMap) { delete(m, k) })
		_, err := UnmarshalSignedEncKeySet(b)
		wantReason(t, err, ReasonBadKeySet)
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	if _, err := UnmarshalSignedEncKeySet([]byte{0xf6}); ReasonOf(err) != ReasonBadKeySet {
		t.Fatalf("null: %v", err)
	}
	setBytes, _ := a.set.Marshal()
	unknown := rawEdit(t, setBytes, func(m fieldMap) { m[9] = enc(t, uint64(1)) })
	if _, err := DecideHighWaterSigned(nil, &SignedEncKeySet{Set: unknown}); ReasonOf(err) != ReasonBadKeySet {
		t.Fatalf("DecideHighWaterSigned took a set with key 9: %v", err)
	}
	if d, err := DecideHighWaterSigned(nil, a.signed); err != nil || d != Replace {
		t.Fatalf("DecideHighWaterSigned on a valid set: %v %v", d, err)
	}
}

// The mailbox key is inside the signed bytes: a set re-signed with another mbox is another set.
func TestEncKeySetMboxIsSigned(t *testing.T) {
	a := newParty(t)
	set := *a.set
	set.Mbox = testMbox(t)
	other, err := set.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyEncKeySet(&SignedEncKeySet{Set: other, KeyStateSeq: a.signed.KeyStateSeq, Sig: a.signed.Sig}, a.aid(), a.c.KEL(), t0)
	wantReason(t, err, ReasonBadSig)
	got, err := VerifyEncKeySet(a.signed, a.aid(), a.c.KEL(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mbox.Epoch != a.set.Mbox.Epoch || !bytes.Equal(got.Mbox.Pub, a.set.Mbox.Pub) {
		t.Fatalf("decoded mbox %+v, want %+v", got.Mbox, a.set.Mbox)
	}
}

// FuzzEncKeySetDecode: whatever the bytes, the time-independent and time-dependent checks of a
// key set either refuse with bad-keyset or accept a set that satisfies every rule.
func FuzzEncKeySetDecode(f *testing.F) {
	set := EncKeySet{Type: EncKeySetType, AID: "bafy-fuzz", Seq: t0, Keys: epochKeys(f, t0, 15), IssuedAt: t0, Mbox: testMbox(f)}
	good, err := set.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good, t0)
	f.Add(good, t0+2*dayMS)
	m, _ := decodeFields(good)
	delete(m, 5)
	noMbox, _ := coredet.Marshal(m)
	f.Add(noMbox, t0)
	f.Add([]byte{0xa0}, uint64(0))
	f.Fuzz(func(t *testing.T, b []byte, now uint64) {
		s, err := decodeEncKeySet(b)
		if err == nil {
			err = s.checkStructure()
		}
		if err == nil {
			err = s.checkValidAt(now)
		}
		if err != nil {
			if ReasonOf(err) != ReasonBadKeySet {
				t.Fatalf("refused with reason %q: %v", ReasonOf(err), err)
			}
			return
		}
		re, err := s.Marshal()
		if err != nil || !bytes.Equal(re, b) {
			t.Fatalf("accepted bytes are not the canonical encoding of the set (%v)", err)
		}
		if s.Type != EncKeySetType || s.AID == "" {
			t.Fatalf("accepted type %q aid %q", s.Type, s.AID)
		}
		if len(s.Keys) == 0 || len(s.Keys) > MaxKeysPerSet {
			t.Fatalf("accepted %d keys", len(s.Keys))
		}
		if s.Mbox.Epoch == 0 || len(s.Mbox.Pub) != ed25519.PublicKeySize {
			t.Fatalf("accepted mbox %+v", s.Mbox)
		}
		kids := map[string]bool{}
		valid := false
		for i := range s.Keys {
			k := &s.Keys[i]
			if k.NotAfter <= k.NotBefore || k.NotAfter-k.NotBefore > MaxKeyValidityMS {
				t.Fatalf("accepted key %d valid [%d, %d)", i, k.NotBefore, k.NotAfter)
			}
			if !bytes.Equal(k.KID, KID(k.Suite, k.Pub)) || kids[string(k.KID)] {
				t.Fatalf("accepted key %d with a wrong or repeated kid", i)
			}
			kids[string(k.KID)] = true
			if i > 0 && k.NotBefore < s.Keys[i-1].NotBefore {
				t.Fatal("accepted keys out of order")
			}
			if t2 := satAdd(now, ClockSkewMS); k.NotBefore <= t2 && t2 < k.NotAfter {
				valid = true
			}
		}
		if !valid {
			t.Fatal("accepted a set with no key valid at now + skew")
		}
	})
}
