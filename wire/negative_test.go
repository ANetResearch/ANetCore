package wire_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/ael"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/wire"
)

// encKey mirrors the registered EncKey object (keys 1-5).
type encKey struct {
	KID       []byte `cbor:"1,keyasint"`
	Suite     uint8  `cbor:"2,keyasint"`
	Pub       []byte `cbor:"3,keyasint"`
	NotBefore uint64 `cbor:"4,keyasint"`
	NotAfter  uint64 `cbor:"5,keyasint"`
}

func validEncKey(t testing.TB) []byte {
	b, err := coredet.Marshal(encKey{KID: make([]byte, 16), Suite: 1, Pub: make([]byte, 32), NotBefore: 1, NotAfter: 2})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeMap(t testing.TB, b []byte) map[uint64]cbor.RawMessage {
	var m map[uint64]cbor.RawMessage
	if err := coredet.Unmarshal(b, &m); err != nil {
		t.Fatalf("negative does not decode as a map: %v", err)
	}
	return m
}

// CORE-S4: one negative per unassigned key 0-63, plus two beyond 63 for a closed object; each
// is the valid encoding with exactly that key added.
func TestNegativesCoverEveryUnassignedKey(t *testing.T) {
	r := reg(t)
	valid := validEncKey(t)
	negs, err := wire.Negatives(r, "EncKey", valid)
	if err != nil {
		t.Fatal(err)
	}
	if len(negs) != 64-5+2 {
		t.Fatalf("%d negatives for EncKey, want %d", len(negs), 64-5+2)
	}
	base := decodeMap(t, valid)
	seen := map[uint64]bool{}
	for _, n := range negs {
		m := decodeMap(t, n.Bytes)
		if len(m) != len(base)+1 || seen[n.Key] {
			t.Fatalf("key %d: %d keys", n.Key, len(m))
		}
		seen[n.Key] = true
		if _, ok := m[n.Key]; !ok {
			t.Fatalf("key %d not inserted", n.Key)
		}
		for k, v := range base {
			if !bytes.Equal(m[k], v) {
				t.Fatalf("key %d: base key %d changed", n.Key, k)
			}
		}
		again, err := coredet.Marshal(m)
		if err != nil || !bytes.Equal(again, n.Bytes) {
			t.Fatalf("key %d: negative is not canonical", n.Key)
		}
	}
	for _, k := range []uint64{0, 6, 63, 64, 65535} {
		if !seen[k] {
			t.Errorf("no negative for key %d", k)
		}
	}
}

// A decoder built on coredet.UnmarshalStrict passes CORE-S4; the lax decoder does not. This is
// the check every object's own package runs with its decoder.
func TestNegativesSeparateStrictFromLaxDecoders(t *testing.T) {
	r := reg(t)
	valid := validEncKey(t)
	negs, err := wire.Negatives(r, "EncKey", valid)
	if err != nil {
		t.Fatal(err)
	}
	var v encKey
	if err := coredet.UnmarshalStrict(valid, &v); err != nil {
		t.Fatalf("valid refused: %v", err)
	}
	laxAccepts := 0
	for _, n := range negs {
		if err := coredet.UnmarshalStrict(n.Bytes, &v); err == nil {
			t.Errorf("strict decoder took key %d (%s)", n.Key, n.Why)
		}
		if err := coredet.Unmarshal(n.Bytes, &v); err == nil {
			laxAccepts++
		}
	}
	if laxAccepts != len(negs) {
		t.Fatalf("the lax decoder refused %d negatives; the generator should expose it on every one", len(negs)-laxAccepts)
	}
}

// encKeyStale is a decoder that still has a field for key 6, which EncKey does not assign, and
// of a type (bstr) other than whatever a generator might insert.
type encKeyStale struct {
	encKey
	Old []byte `cbor:"6,keyasint,omitempty"`
}

// A decoder that knows a key the object does not assign is caught whatever the type of its field:
// the negative's value is null, which decodes into any field, so the strict decoder's refusal can
// only come from the key itself.
func TestNegativesExposeADecoderThatKnowsAnUnassignedKey(t *testing.T) {
	r := reg(t)
	negs, err := wire.Negatives(r, "EncKey", validEncKey(t))
	if err != nil {
		t.Fatal(err)
	}
	took := map[uint64]bool{}
	for _, n := range negs {
		var v encKeyStale
		if coredet.UnmarshalStrict(n.Bytes, &v) == nil {
			took[n.Key] = true
		}
	}
	if len(took) != 1 || !took[6] {
		t.Fatalf("a decoder with a field for key 6 took %v; want exactly key 6 exposed", took)
	}
}

// The valid encoding must be valid: one that already holds a key the object does not assign is
// refused rather than silently left without that key's negative.
func TestNegativesRefuseAnInvalidBase(t *testing.T) {
	r := reg(t)
	for name, v := range map[string]any{
		"reserved key 6":      encKeyStale{Old: []byte{1}},
		"64 in closed object": map[uint64]any{1: []byte{1}, 64: 0},
	} {
		b, err := coredet.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wire.Negatives(r, "EncKey", b); err == nil {
			t.Errorf("%s: base accepted", name)
		}
	}
	// an extension key of a critical object is fine in the base
	wrap, _ := coredet.Marshal(map[uint64]any{3: []byte{1}, 21: []byte{0}, 64: 0})
	if _, err := wire.Negatives(r, "Wrap", wrap); err != nil {
		t.Fatalf("Wrap with an extension key: %v", err)
	}
}

func TestNegativesFollowTheKeyspace(t *testing.T) {
	r := reg(t)
	// Wrap: keys >= 64 are ignorable, so no negative beyond 63; keys 1-3 and 21 are active.
	wrap, _ := coredet.Marshal(map[uint64]any{3: []byte{1}, 21: []byte{0}})
	negs, err := wire.Negatives(r, "Wrap", wrap)
	if err != nil {
		t.Fatal(err)
	}
	if len(negs) != 64-4 {
		t.Fatalf("%d negatives for Wrap, want %d", len(negs), 64-4)
	}
	for _, n := range negs {
		if n.Key > 63 {
			t.Fatalf("Wrap negative for key %d: keys >= 64 are extensions there", n.Key)
		}
	}
	// SealedInner: 21 is retired, 0 and 30-34 forbidden, all three refused.
	inner, _ := coredet.Marshal(map[uint64]any{1: "a"})
	negs, _ = wire.Negatives(r, "SealedInner", inner)
	why := map[uint64]string{}
	for _, n := range negs {
		why[n.Key] = n.Why
	}
	if why[21] != wire.StatusRetired || why[0] != wire.StatusForbidden || why[32] != wire.StatusForbidden || why[13] != wire.StatusReserved {
		t.Fatalf("SealedInner reasons: 21 %q, 0 %q, 32 %q, 13 %q", why[21], why[0], why[32], why[13])
	}
	// the empty CardGet: every key is a negative
	empty, _ := coredet.Marshal(map[uint64]any{})
	if negs, _ := wire.Negatives(r, "CardGet", empty); len(negs) != 66 {
		t.Fatalf("CardGet: %d negatives, want 66", len(negs))
	}
	if _, err := wire.Negatives(r, "InnerSigPreimage", inner); err == nil {
		t.Fatal("a derived object has no negatives")
	}
	if _, err := wire.Negatives(r, "A2ACardJWS", empty); err == nil {
		t.Fatal("an external object (not a CBOR map) has no negatives")
	}
	if _, err := wire.Negatives(r, "NoSuchObject", inner); err == nil {
		t.Fatal("unknown object accepted")
	}
	if _, err := wire.Negatives(r, "EncKey", []byte{0xa1, 0x61, 'a', 0x01}); err == nil {
		t.Fatal("a text-keyed map is not an object encoding")
	}
}

// The decoders of carried objects that exist today. They decode with the lax Unmarshal, which
// CORE-E3 no longer allows; the work item that owns each switches it to UnmarshalStrict and
// removes the skip (the row fails once the decoder is strict and the skip is still there).
func TestCarriedDecodersRefuseUnregisteredKeys(t *testing.T) {
	r := reg(t)
	rows := []struct {
		object string
		todo   string // "v030-todo(<work item>)" while the decoder is still lax
		valid  func() ([]byte, error)
		decode func([]byte) error
	}{
		{"PaymentAuthorizationWire", "",
			func() ([]byte, error) {
				a := &payment.Authorization{Payer: "p", PayTo: "q", Amount: 1, Network: "n", Nonce: "x", IssuedAt: 1, NotAfter: 2}
				return a.Marshal()
			},
			func(b []byte) error { _, err := payment.UnmarshalAuthorization(b); return err }},
		{"PaymentReceiptWire", "",
			func() ([]byte, error) {
				rc := &payment.Receipt{AuthID: "a", Payer: "p", PayTo: "q", Amount: 1, Network: "n", SettleAt: 1}
				return rc.Marshal()
			},
			func(b []byte) error { _, err := payment.UnmarshalReceipt(b); return err }},
		{"AELHeadAttestationWire", "",
			func() ([]byte, error) {
				h := &ael.HeadAttestation{ChainDID: "c", Seq: 1, HeadID: "h", ObservedAt: 1}
				return h.Marshal()
			},
			func(b []byte) error { _, err := ael.UnmarshalHeadAttestation(b); return err }},
	}
	for _, row := range rows {
		t.Run(row.object, func(t *testing.T) {
			valid, err := row.valid()
			if err != nil {
				t.Fatal(err)
			}
			if err := row.decode(valid); err != nil {
				t.Fatalf("valid encoding refused: %v", err)
			}
			negs, err := wire.Negatives(r, row.object, valid)
			if err != nil {
				t.Fatal(err)
			}
			accepted := 0
			for _, n := range negs {
				if row.decode(n.Bytes) == nil {
					accepted++
				}
			}
			if row.todo != "" {
				if accepted == 0 {
					t.Fatalf("the decoder refuses every unregistered key now: drop the %s skip", row.todo)
				}
				t.Skipf("%s: decoder still accepts %d of %d unregistered keys", row.todo, accepted, len(negs))
			}
			if accepted > 0 {
				t.Fatalf("decoder accepts %d of %d unregistered keys (CORE-S4)", accepted, len(negs))
			}
		})
	}
}

// FuzzNegatives: for any input, Negatives either refuses it or returns encodings that are the
// input's map with exactly one unassigned key added.
func FuzzNegatives(f *testing.F) {
	f.Add(validEncKey(f))
	for _, h := range []string{"a0", "a1016161", "a201410002f6", "a3000001000200", "bf01ff", "a1a10101", "f6", "80", "c1a0"} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
	r := wire.MustLoad()
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, name := range []string{"EncKey", "Wrap"} {
			negs, err := wire.Negatives(r, name, b)
			if err != nil {
				continue
			}
			base := decodeMap(t, b)
			o := r.Object(name)
			for _, n := range negs {
				if n.Key <= 63 && o.KeyStatus(int(n.Key)) == wire.StatusActive {
					t.Fatalf("%s: negative for active key %d", name, n.Key)
				}
				m := decodeMap(t, n.Bytes)
				if len(m) != len(base)+1 {
					t.Fatalf("%s: key %d: %d keys from %d", name, n.Key, len(m), len(base))
				}
			}
		}
	})
}
