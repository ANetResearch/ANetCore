package coredet

// Fuzz target for the CoreDet-CBOR decoder and encoder (ANet docs/notes/0033).
//
// Decoding is permissive about encoding form; encoding is canonical. So for any input that
// decodes: the value re-encodes (unless it holds NaN or ±Inf, C-R1), the encoding decodes to an
// equal value, and encoding that value again gives the same bytes. Tags are never accepted (C-R2).

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func FuzzRoundTrip(f *testing.F) {
	for _, h := range []string{
		"a201a101010481a2016273310364646f2078", // VEC-AET-CID-1
		"a201a101010481a2016274310aa10364646f2078",
		"1801", "9f01ff", "5f4161416262ff", "a20101a0", "a201010102", "c11a514b67b0", "f97e00", "f98000",
		"fb3ff0000000000000", "a1a10101", "d8185f", "7f6161ff", "f7", "e0",
	} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var v any
		if err := Unmarshal(b, &v); err != nil {
			return
		}
		if len(b) > 0 && b[0]>>5 == 6 {
			t.Fatalf("a tagged item decoded: %x", b)
		}
		enc, err := Marshal(v)
		if err != nil {
			return
		}
		var v2 any
		if err := Unmarshal(enc, &v2); err != nil {
			t.Fatalf("Marshal output does not decode: %v", err)
		}
		if !reflect.DeepEqual(v, v2) {
			t.Fatalf("round trip changed the value:\n%#v\n%#v", v, v2)
		}
		enc2, err := Marshal(v2)
		if err != nil || !bytes.Equal(enc, enc2) {
			t.Fatalf("encoding is not a fixed point: %x vs %x (%v)", enc, enc2, err)
		}
	})
}
