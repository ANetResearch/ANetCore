package coredet

import (
	"encoding/hex"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The targets of CORE-E4 revision 7: a null into any of these is refused.
type nullInner struct {
	A uint64 `cbor:"1,keyasint"`
}

type nullOuter struct {
	S   string            `cbor:"1,keyasint"`
	B   []byte            `cbor:"2,keyasint"`
	N   uint64            `cbor:"3,keyasint"`
	I   int64             `cbor:"4,keyasint"`
	T   bool              `cbor:"5,keyasint"`
	In  nullInner         `cbor:"6,keyasint"`
	L   []nullInner       `cbor:"7,keyasint"`
	M   map[uint64]string `cbor:"8,keyasint"`
	Arr [2]uint64         `cbor:"9,keyasint"`
	F   float64           `cbor:"10,keyasint"`
	// May be null: a pointer, an interface, a raw message.
	P   *nullInner            `cbor:"20,keyasint"`
	Any any                   `cbor:"21,keyasint"`
	Raw cbor.RawMessage       `cbor:"22,keyasint"`
	PL  *[]byte               `cbor:"23,keyasint"`
	MA  map[string]any        `cbor:"24,keyasint"`
	LA  []any                 `cbor:"25,keyasint"`
	MP  map[uint64]*nullInner `cbor:"26,keyasint"`
}

// toarray, embedded structs and text names: the decoder's other ways of matching a field.
type nullArray struct {
	_ struct{} `cbor:",toarray"`
	A uint64
	B *uint64
	C []byte
}

type nullEmbedded struct {
	X string `cbor:"x"`
}

type nullNamed struct {
	nullEmbedded
	Name  string  `cbor:"name"`
	Ptr   *string `cbor:"ptr"`
	Plain []byte  // matched by its Go name, and case-insensitively
	JSON  int     `json:"j"`
}

// nullSelf decodes itself, and strictly: a null given to it is refused inside.
type nullSelf struct{ V uint64 }

func (s *nullSelf) UnmarshalCBOR(b []byte) error {
	var f struct {
		V uint64 `cbor:"1,keyasint"`
	}
	if err := UnmarshalStrict(b, &f); err != nil {
		return err
	}
	s.V = f.V
	return nil
}

type nullHasSelf struct {
	S  nullSelf  `cbor:"1,keyasint"`
	PS *nullSelf `cbor:"2,keyasint"`
}

func h(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The table of the revision: f6, f7, 81 f6, 82 f6 f6 and a map member that is null, into each kind
// of target the rule names (struct, array, slice, map, string, byte string, number, bool), are all
// refused with a NullError; the decoder without the check takes every one of them.
func TestUnmarshalStrictRefusesNullAndUndefined(t *testing.T) {
	type tc struct {
		name string
		in   string
		into func() any
		path string
	}
	cases := []tc{
		{"f6 into a struct", "f6", func() any { return new(nullInner) }, ""},
		{"f6 into a slice", "f6", func() any { return new([]nullInner) }, ""},
		{"f6 into a map", "f6", func() any { return new(map[uint64]string) }, ""},
		{"f6 into a string", "f6", func() any { return new(string) }, ""},
		{"f6 into a byte string", "f6", func() any { return new([]byte) }, ""},
		{"f6 into a number", "f6", func() any { return new(uint64) }, ""},
		{"f6 into a bool", "f6", func() any { return new(bool) }, ""},
		{"f6 into an array", "f6", func() any { return new([2]uint64) }, ""},
		{"f7 into a struct", "f7", func() any { return new(nullInner) }, ""},
		{"f7 into a pointer", "f7", func() any { return new(*nullInner) }, ""},
		{"f7 into an interface", "f7", func() any { return new(any) }, ""},
		{"81 f6 into a slice of structs", "81 f6", func() any { return new([]nullInner) }, "[0]"},
		{"81 f6 into a slice of strings", "81 f6", func() any { return new([]string) }, "[0]"},
		{"81 f7 into a slice of structs", "81 f7", func() any { return new([]nullInner) }, "[0]"},
		{"81 f7 into a slice of pointers", "81 f7", func() any { return new([]*nullInner) }, "[0]"},
		{"81 f7 into a slice of anything", "81 f7", func() any { return new([]any) }, "[0]"},
		{"82 f6 f6 into a slice of numbers", "82 f6 f6", func() any { return new([]uint64) }, "[0]"},
		{"82 f6 f6 into an array", "82 f6 f6", func() any { return new([2]uint64) }, "[0]"},
		{"map member null: string", "a1 01 f6", func() any { return new(nullOuter) }, ".1"},
		{"map member null: byte string", "a1 02 f6", func() any { return new(nullOuter) }, ".2"},
		{"map member null: number", "a1 03 f6", func() any { return new(nullOuter) }, ".3"},
		{"map member null: negative number", "a1 04 f6", func() any { return new(nullOuter) }, ".4"},
		{"map member null: bool", "a1 05 f6", func() any { return new(nullOuter) }, ".5"},
		{"map member null: struct", "a1 06 f6", func() any { return new(nullOuter) }, ".6"},
		{"map member null: slice", "a1 07 f6", func() any { return new(nullOuter) }, ".7"},
		{"map member null: map", "a1 08 f6", func() any { return new(nullOuter) }, ".8"},
		{"map member null: array", "a1 09 f6", func() any { return new(nullOuter) }, ".9"},
		{"map member null: float", "a1 0a f6", func() any { return new(nullOuter) }, ".10"},
		{"map member undefined: pointer", "a1 14 f7", func() any { return new(nullOuter) }, ".20"},
		{"map member undefined: raw message", "a1 16 f7", func() any { return new(nullOuter) }, ".22"},
		{"undefined deep in a raw message", "a1 16 81 a1 01 f7", func() any { return new(nullOuter) }, ".22[0].1"},
		{"undefined deep in an interface", "a1 15 a1 61 6b 82 01 f7", func() any { return new(nullOuter) }, `.21."k"[1]`},
		{"null in a struct in a slice", "a1 07 81 a1 01 f6", func() any { return new(nullOuter) }, ".7[0].1"},
		{"null as a map value", "a1 08 a1 01 f6", func() any { return new(nullOuter) }, ".8.1"},
		{"null as a map key", "a1 08 a1 f6 60", func() any { return new(nullOuter) }, ".8.key"},
		{"null in an array of numbers", "a1 09 82 01 f6", func() any { return new(nullOuter) }, ".9[1]"},
		{"null into a toarray field", "83 f6 f6 40", func() any { return new(nullArray) }, "[0]"},
		{"null into a toarray byte field", "83 01 f6 f6", func() any { return new(nullArray) }, "[2]"},
		{"null into a named field", `a1 64 6e616d65 f6`, func() any { return new(nullNamed) }, `."name"`},
		{"null into a promoted field", `a1 61 78 f6`, func() any { return new(nullNamed) }, `."x"`},
		{"null into a field matched by its Go name", `a1 65 506c61696e f6`, func() any { return new(nullNamed) }, `."Plain"`},
		{"null into a field matched case-insensitively", `a1 65 706c61696e f6`, func() any { return new(nullNamed) }, `."plain"`},
		{"null into a field named by its json tag", `a1 61 6a f6`, func() any { return new(nullNamed) }, `."j"`},
		{"null into a type that decodes itself", "a1 01 f6", func() any { return new(nullHasSelf) }, ""},
		{"indefinite array with a null", "9f f6 ff", func() any { return new([]uint64) }, "[0]"},
		{"indefinite map with a null", "bf 01 f6 ff", func() any { return new(nullOuter) }, ".1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := h(t, c.in)
			if err := Unmarshal(b, c.into()); err != nil && !strings.Contains(c.name, "decodes itself") {
				t.Fatalf("the decoder alone refuses it (%v): the case tests nothing", err)
			}
			err := UnmarshalStrict(b, c.into())
			if !errors.Is(err, ErrNullOrUndefined) {
				t.Fatalf("UnmarshalStrict(%s) = %v, want a NullError", c.in, err)
			}
			var ne *NullError
			if errors.As(err, &ne) && c.path != "" && ne.Path != c.path {
				t.Fatalf("path %q, want %q (%v)", ne.Path, c.path, err)
			}
		})
	}
}

// A null into a pointer, an interface or a raw message is what the encoder writes for a nil one,
// and decodes: those targets can be absent.
func TestUnmarshalStrictTakesNullWhereAValueMayBeAbsent(t *testing.T) {
	type tc struct {
		name string
		in   string
		into func() any
	}
	cases := []tc{
		{"f6 into a pointer", "f6", func() any { return new(*nullInner) }},
		{"f6 into an interface", "f6", func() any { return new(any) }},
		{"f6 into a raw message", "f6", func() any { return new(cbor.RawMessage) }},
		{"81 f6 into a slice of pointers", "81 f6", func() any { return new([]*nullInner) }},
		{"81 f6 into a slice of anything", "81 f6", func() any { return new([]any) }},
		{"pointer member", "a1 14 f6", func() any { return new(nullOuter) }},
		{"interface member", "a1 15 f6", func() any { return new(nullOuter) }},
		{"raw message member", "a1 16 f6", func() any { return new(nullOuter) }},
		{"pointer to a slice", "a1 17 f6", func() any { return new(nullOuter) }},
		{"null inside an interface", "a1 15 82 f6 a1 01 f6", func() any { return new(nullOuter) }},
		{"null inside a raw message", "a1 16 a1 01 f6", func() any { return new(nullOuter) }},
		{"null as a map[string]any value", "a1 18 18 a1 61 6b f6", func() any { return new(nullOuter) }},
		{"null in a []any", "a1 18 19 82 f6 01", func() any { return new(nullOuter) }},
		{"null as a map value of pointers", "a1 18 1a a1 01 f6", func() any { return new(nullOuter) }},
		{"null into a toarray pointer field", "83 01 f6 40", func() any { return new(nullArray) }},
		{"null into a named pointer field", `a1 63 707472 f6`, func() any { return new(nullNamed) }},
		{"null into a pointer to a type that decodes itself", "a1 02 f6", func() any { return new(nullHasSelf) }},
		{"a byte string holding f6 and f7", "a1 02 42 f6f7", func() any { return new(nullOuter) }},
		{"a text key holding f6", "a1 61 f6 01", func() any { return new(map[string]uint64) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := h(t, c.in)
			if c.name == "a text key holding f6" {
				b = []byte{0xa1, 0x62, 0xc3, 0xb6, 0x01} // "ö" is c3 b6; f6 itself is not UTF-8
			}
			if err := UnmarshalStrict(b, c.into()); err != nil {
				t.Fatalf("UnmarshalStrict(%x) = %v", b, err)
			}
		})
	}
}

// What a canonical encoder writes for values without a null where one cannot be absent decodes
// again: the check refuses nothing a writer of the suite produces from a complete value.
func TestUnmarshalStrictTakesWhatTheEncoderWrites(t *testing.T) {
	two := uint64(2)
	ptrBytes := []byte{1}
	values := []any{
		nullOuter{S: "s", B: []byte{}, L: []nullInner{}, M: map[uint64]string{}, MA: map[string]any{"k": nil}, LA: []any{nil}, MP: map[uint64]*nullInner{}},
		nullOuter{S: "s", B: []byte{0xf6, 0xf7}, L: []nullInner{{A: 1}}, M: map[uint64]string{1: "x"},
			P: &nullInner{A: 3}, Any: []any{nil, "x"}, Raw: cbor.RawMessage{0xf6}, PL: &ptrBytes, MA: map[string]any{},
			LA: []any{}, MP: map[uint64]*nullInner{1: nil}},
		nullArray{A: 1, B: &two, C: []byte{}},
		nullArray{A: 1, C: []byte{2}},
		nullNamed{nullEmbedded: nullEmbedded{X: "x"}, Name: "n", Plain: []byte{}},
		[]*nullInner{nil, {A: 1}},
		big.NewInt(1 << 62),
	}
	for _, v := range values {
		b, err := Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		back := reflect.New(reflect.TypeOf(v))
		if err := UnmarshalStrict(b, back.Interface()); err != nil {
			t.Errorf("%T %x: %v", v, b, err)
		}
	}
}

// The errors say where and what: a path into the input and the Go type the null would have gone
// into.
func TestNullErrorSaysWhereAndWhat(t *testing.T) {
	err := UnmarshalStrict(h(t, "a1 07 81 a1 01 f6"), new(nullOuter))
	var ne *NullError
	if !errors.As(err, &ne) || ne.Undefined || ne.Path != ".7[0].1" || ne.Into != "uint64" {
		t.Fatalf("%#v", err)
	}
	if !strings.Contains(err.Error(), "CBOR null at .7[0].1") || !strings.Contains(err.Error(), "uint64") {
		t.Fatalf("message %q", err)
	}
	err = UnmarshalStrict(h(t, "f7"), new(any))
	if !errors.As(err, &ne) || !ne.Undefined || ne.Path != "" || !strings.Contains(err.Error(), "undefined at the top level") {
		t.Fatalf("%#v", err)
	}
}

// The plain decoder is left as it was: only UnmarshalStrict refuses.
func TestUnmarshalKeepsTakingNull(t *testing.T) {
	var v nullOuter
	if err := Unmarshal(h(t, "a2 01 f6 06 f6"), &v); err != nil {
		t.Fatal(err)
	}
	var l []nullInner
	if err := Unmarshal(h(t, "81 f7"), &l); err != nil || len(l) != 1 {
		t.Fatalf("%v %v", l, err)
	}
}

// How the walk finds a struct's fields is fxamacker/cbor's: the visible field of a name is the
// least nested, then the tagged one, and two that tie hide each other; an embedded struct of a
// type that appears twice at one level is ignored.
func TestNullWalkMatchesFieldsAsTheDecoderDoes(t *testing.T) {
	type deep struct {
		Y []byte `cbor:"y"`
	}
	type mid struct {
		deep
		Y2 string `cbor:"y2"`
	}
	type a struct {
		Z uint64 `cbor:"z"`
	}
	type b struct {
		Z uint64 `cbor:"z"`
	}
	type top struct {
		mid
		a
		b
		W *string `cbor:"w"`
	}
	si := structInfoOf(reflect.TypeFor[top]())
	if _, ok := si.byName["y"]; !ok {
		t.Fatal("a field promoted two levels is missing")
	}
	if _, ok := si.byName["z"]; ok {
		t.Fatal("two fields z at one level tie and hide each other")
	}
	if si.byName["w"] != reflect.TypeFor[*string]() {
		t.Fatal("w")
	}
	// What the decoder does with the same inputs agrees: y is a field (strict decoding takes
	// it), z is not (an unknown field).
	if err := UnmarshalStrict(h(t, "a1 61 79 40"), new(top)); err != nil {
		t.Fatal(err)
	}
	var uf *cbor.UnknownFieldError
	if err := UnmarshalStrict(h(t, "a1 61 7a 01"), new(top)); !errors.As(err, &uf) {
		t.Fatalf("z: %v", err)
	}
	if err := UnmarshalStrict(h(t, "a1 61 79 f6"), new(top)); !errors.Is(err, ErrNullOrUndefined) {
		t.Fatalf("null into the promoted y: %v", err)
	}
}

// The walk does not trust its input: cut short, it returns an error rather than reading past the
// end, whatever the target.
func TestNullWalkOnBrokenInput(t *testing.T) {
	for _, in := range []string{"81", "a1 01", "9f f6", "5f 41", "63 61", "1b 00", "a1 07 81 a1 01 f6 00", "f8"} {
		b := h(t, in)
		w := nullWalk{b: b}
		_ = w.item(target{t: reflect.TypeFor[nullOuter]()}, 0) // must not panic
		if err := refuseNulls(append(b, 0xf6), reflect.TypeFor[nullOuter]()); err == nil && in != "f8" {
			t.Errorf("%s f6: no error", in)
		}
	}
}
