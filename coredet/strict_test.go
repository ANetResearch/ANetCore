package coredet

import (
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

type strictInner struct {
	A uint64 `cbor:"1,keyasint"`
}

type strictOuter struct {
	X  string        `cbor:"1,keyasint"`
	In strictInner   `cbor:"2,keyasint"`
	L  []strictInner `cbor:"3,keyasint,omitempty"`
	P  *strictInner  `cbor:"4,keyasint,omitempty"`
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnmarshalStrictAcceptsKnownKeys(t *testing.T) {
	want := strictOuter{X: "x", In: strictInner{A: 7}, L: []strictInner{{A: 1}}, P: &strictInner{A: 2}}
	b := mustMarshal(t, want)
	var got strictOuter
	if err := UnmarshalStrict(b, &got); err != nil {
		t.Fatalf("UnmarshalStrict: %v", err)
	}
	if got.X != "x" || got.In.A != 7 || len(got.L) != 1 || got.L[0].A != 1 || got.P == nil || got.P.A != 2 {
		t.Fatalf("decoded %+v", got)
	}
}

// The whole point (CORE-E4): an unknown key is an error, at the top and in nested structs,
// where Unmarshal drops it without a word.
func TestUnmarshalStrictRefusesUnknownKeys(t *testing.T) {
	cases := map[string]any{
		"top":          map[uint64]any{1: "x", 2: map[uint64]any{1: 7}, 9: 0},
		"top ≥64":      map[uint64]any{1: "x", 2: map[uint64]any{1: 7}, 64: 0},
		"nested":       map[uint64]any{1: "x", 2: map[uint64]any{1: 7, 2: 0}},
		"in slice":     map[uint64]any{1: "x", 2: map[uint64]any{1: 7}, 3: []any{map[uint64]any{1: 1, 5: "y"}}},
		"via pointer":  map[uint64]any{1: "x", 2: map[uint64]any{1: 7}, 4: map[uint64]any{1: 2, 0: "t"}},
		"text key":     map[any]any{uint64(1): "x", uint64(2): map[uint64]any{1: 7}, "1": "y"},
		"negative key": map[any]any{uint64(1): "x", uint64(2): map[uint64]any{1: 7}, int64(-1): 0},
	}
	for name, v := range cases {
		b := mustMarshal(t, v)
		var lax strictOuter
		if err := Unmarshal(b, &lax); err != nil {
			t.Fatalf("%s: the lax decoder should take it (that is the bug being fixed): %v", name, err)
		}
		var got strictOuter
		err := UnmarshalStrict(b, &got)
		var uf *cbor.UnknownFieldError
		if !errors.As(err, &uf) {
			t.Errorf("%s: UnmarshalStrict = %v, want an unknown field error", name, err)
		}
	}
}

func TestUnmarshalStrictKeepsTheProfileRules(t *testing.T) {
	var v strictOuter
	// {1: "x", 1: "y"}: duplicate key.
	if err := UnmarshalStrict([]byte{0xa2, 0x01, 0x61, 'x', 0x01, 0x61, 'y'}, &v); err == nil {
		t.Error("duplicate map key accepted")
	}
	// tag 1 around a map.
	if err := UnmarshalStrict([]byte{0xc1, 0xa1, 0x01, 0x61, 'x'}, &v); err == nil {
		t.Error("CBOR tag accepted")
	}
	// invalid UTF-8 in a text string.
	if err := UnmarshalStrict([]byte{0xa1, 0x01, 0x61, 0xff}, &v); err == nil {
		t.Error("invalid UTF-8 accepted")
	}
}

// ANetLink cannot import this package (it pins an older ANetCore) and builds its own C1 decoder
// with these exact options. Pin them so a change here is a deliberate one.
func TestStrictDecOptionsArePinned(t *testing.T) {
	o := strictDecOptions()
	want := cbor.DecOptions{
		TagsMd:            cbor.TagsForbidden,
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}
	if o != want {
		t.Fatalf("strict decoder options changed:\n got %+v\nwant %+v", o, want)
	}
}
