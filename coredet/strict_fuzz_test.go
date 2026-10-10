package coredet

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
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

// FuzzUnmarshalStrictNull (CORE-E4 revision 7): on a type with every kind of target, a null that
// UnmarshalStrict accepts is one the decoder alone also takes to the same value, and it sits where
// a value may be absent: written as undefined instead, the same input is refused. A NullError only
// ever follows what the decoder alone took. The walk never panics and never reads past the input.
func FuzzUnmarshalStrictNull(f *testing.F) {
	for _, s := range []string{
		"f6", "f7", "81f6", "81f7", "82f6f6",
		"a114f6", "a115f6", "a116f6", "a117f6", "a101f6", "a106f6", "a107f6",
		"a11681a101f7", "a11581f6", "a1181aa101f6", "a10881f6", "a108a101f6",
		"bf01f6ff", "9ff6ff", "a1189fa101f6",
	} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var s nullOuter
		err := UnmarshalStrict(b, &s)
		var l nullOuter
		lerr := Unmarshal(b, &l)
		if errors.Is(err, ErrNullOrUndefined) && lerr != nil {
			t.Fatalf("a null refusal of what the decoder itself refused: %v / %v", err, lerr)
		}
		if err != nil {
			return
		}
		if lerr != nil {
			t.Fatalf("strict accepted what lax refused: %v", lerr)
		}
		// Compared by their deterministic encodings rather than DeepEqual: a
		// NaN under the interface member is not equal to itself.
		se, err1 := sameEnc.Marshal(s)
		le, err2 := sameEnc.Marshal(l)
		if err1 != nil || err2 != nil || !bytes.Equal(se, le) {
			t.Fatalf("strict and lax disagree:\n%#v\n%#v", s, l)
		}
		for _, off := range nullOffsets(t, b) {
			u := append([]byte(nil), b...)
			u[off] = 0xf7
			var again nullOuter
			if err := UnmarshalStrict(u, &again); !errors.Is(err, ErrNullOrUndefined) {
				t.Fatalf("the null at %d accepted, but undefined there gives %v", off, err)
			}
		}
	})
}

// sameEnc writes a decoded value deterministically, NaN included, so that two
// decodings can be compared byte for byte.
var sameEnc = func() cbor.EncMode {
	m, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic}.EncMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// nullOffsets lists where the null items of a well-formed input are.
func nullOffsets(t *testing.T, b []byte) []int {
	var out []int
	w := nullWalk{b: b}
	var item func() bool
	item = func() bool {
		if w.off >= len(b) {
			return false
		}
		if b[w.off] == 0xf6 {
			out = append(out, w.off)
			w.off++
			return true
		}
		major, ai, arg, err := w.head()
		if err != nil {
			return false
		}
		n := int(arg)
		switch {
		case major == 2 || major == 3:
			if ai == 31 {
				for b[w.off] != 0xff {
					if !item() {
						return false
					}
				}
				w.off++
				return true
			}
			return w.skip(arg) == nil
		case major == 4 || major == 5:
			per := 1
			if major == 5 {
				per = 2
			}
			if ai == 31 {
				for w.off < len(b) && b[w.off] != 0xff {
					if !item() {
						return false
					}
				}
				w.off++
				return true
			}
			for i := 0; i < n*per; i++ {
				if !item() {
					return false
				}
			}
			return true
		case major == 6:
			return item()
		}
		return true
	}
	if !item() {
		t.Fatalf("an accepted input does not scan: %x", b)
	}
	return out
}
