package identity

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// An entry of a KEL that carries no event is refused by UnmarshalKEL as a KEL that does not decode.
// A null or undefined entry, an empty map or a map with only the signature decodes to a zero
// SignedEvent without the event's own decoder ever running, so nothing else refuses it there; it
// must not come back as a KEL of that length, nor be refused as a v0.2 KEL (the wrong reason).
func TestUnmarshalKELRefusesAnEntryWithoutAnEvent(t *testing.T) {
	one := mustMarshalKEL(t, kel2A()[:1])
	if one[0] != 0x81 {
		t.Fatalf("a one-entry KEL starts with % x, want 81", one[:1])
	}
	entry := one[1:]
	for _, tc := range []struct {
		name string
		b    []byte
	}{
		{"undefined", []byte{0x81, 0xf7}},
		{"null", []byte{0x81, 0xf6}},
		{"two nulls", []byte{0x82, 0xf6, 0xf6}},
		{"empty map", []byte{0x81, 0xa0}},
		{"only a signature", []byte{0x81, 0xa1, 0x02, 0x40}},
		{"an event then null", append(append([]byte{0x82}, entry...), 0xf6)},
		{"null then an event", append([]byte{0x82, 0xf6}, entry...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kel, err := UnmarshalKEL(tc.b)
			if err == nil {
				t.Fatalf("UnmarshalKEL = %d entries, want a refusal", len(kel))
			}
			if errors.Is(err, ErrKELv1) || !strings.Contains(err.Error(), "KEL does not decode") {
				t.Fatalf("UnmarshalKEL: %v, want a KEL that does not decode", err)
			}
		})
	}
	// The entry on its own still decodes, and to the same bytes.
	kel, err := UnmarshalKEL(one)
	if err != nil || len(kel) != 1 {
		t.Fatalf("a one-entry KEL: %d entries, %v", len(kel), err)
	}
	if back := mustMarshalKEL(t, kel); !bytes.Equal(back, one) {
		t.Fatal("a one-entry KEL does not encode back to its bytes")
	}
}
