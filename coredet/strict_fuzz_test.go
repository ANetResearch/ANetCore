package coredet

import (
	"encoding/hex"
	"reflect"
	"testing"
)

// FuzzUnmarshalStrict: UnmarshalStrict never panics; whatever it accepts, Unmarshal accepts too
// and decodes to the same value (strict only ever refuses more); and whatever it accepts
// re-encodes to bytes that it accepts again.
func FuzzUnmarshalStrict(f *testing.F) {
	for _, h := range []string{
		"a201617802a10107",
		"a301617802a1010703",
		"a201617802a1010209",
		"a2016178016179",
		"c1a1016178",
		"a1016a",
		"a40161780281a101010381a1010104a10102",
	} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var s strictOuter
		if err := UnmarshalStrict(b, &s); err != nil {
			return
		}
		var l strictOuter
		if err := Unmarshal(b, &l); err != nil {
			t.Fatalf("strict accepted what lax refused: %v", err)
		}
		if !reflect.DeepEqual(s, l) {
			t.Fatalf("strict and lax disagree:\n%#v\n%#v", s, l)
		}
		enc, err := Marshal(s)
		if err != nil {
			t.Fatalf("accepted value does not encode: %v", err)
		}
		var again strictOuter
		if err := UnmarshalStrict(enc, &again); err != nil {
			t.Fatalf("re-encoding is refused: %v", err)
		}
	})
}
