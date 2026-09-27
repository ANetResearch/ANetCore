package seal

import (
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
)

func TestPadmeValues(t *testing.T) {
	// Values computed by hand from the definition: E = floor(log2 n),
	// S = floor(log2 E) + 1, the low E - S bits are rounded up.
	for _, c := range []struct{ n, want int }{
		{0, 0}, {1, 1}, {2, 2}, {3, 3}, {4, 4}, {5, 5}, {7, 7},
		{8, 8}, {9, 10}, {11, 12}, {100, 104}, {1000, 1024},
		{1025, 1088}, {5000, 5120}, {65536, 65536}, {65537, 67584},
	} {
		if got := Padme(c.n); got != c.want {
			t.Errorf("Padme(%d) = %d, want %d", c.n, got, c.want)
		}
	}
	for n := 0; n < 200000; n++ {
		p := Padme(n)
		if p < n || Padme(p) != p {
			t.Fatalf("Padme(%d) = %d: not >= n or not a fixed point", n, p)
		}
		if n >= 256 && float64(p-n) > 0.12*float64(n) {
			t.Fatalf("Padme(%d) = %d: overhead above 12%%", n, p)
		}
	}
}

// Four pad offsets below 2^32 are unreachable because the byte-string
// header grows by one byte at 24 and 256 bytes and by two at 65536; every
// other offset has exactly the length asked.
func TestPadLenFor(t *testing.T) {
	unreachable := map[int]bool{24: true, 257: true, 65538: true, 65539: true}
	for d := 0; d < 70000; d++ {
		n, ok := padLenFor(d)
		if ok == unreachable[d] {
			t.Fatalf("padLenFor(%d) ok=%v", d, ok)
		}
		// Encoding every candidate up to 70000 bytes costs seconds; the
		// thresholds and a sample of the rest are checked against the
		// encoder.
		if !ok || (d > 300 && (d < 65500 || d > 65600) && d%97 != 0) {
			continue
		}
		b, err := coredet.Marshal(make([]byte, n))
		if err != nil {
			t.Fatal(err)
		}
		if len(b)-1 != d {
			t.Fatalf("padLenFor(%d) = %d, which encodes %d bytes longer than empty", d, n, len(b)-1)
		}
	}
}

// The encoded inner of every sealed message has a Padmé length, including
// bodies whose natural offset is one of the unreachable ones.
func TestSealedInnerIsPadded(t *testing.T) {
	a, b := newParty(t), newParty(t)
	hitUnreachable := false
	sizes := []int{0, 1, 2, 50, 100, 500, 1000, 1500, 4000, 70000}
	for n := 0; n < 1200; n++ {
		sizes = append(sizes, n)
	}
	for _, n := range sizes {
		in := innerFrom(t, a, b, t0)
		in.Body = make([]byte, n)
		fields, err := in.fieldMap()
		if err != nil {
			t.Fatal(err)
		}
		fields[keySig] = enc(t, make([]byte, SigLen))
		fields[keyPad] = []byte{0x40}
		base := encodedLen(fields)
		if _, ok := padLenFor(Padme(base) - base); !ok {
			hitUnreachable = true
		}

		env := mustSeal(t, in, &b.kp.Public, a.c.Sign)
		outer, err := ParseOuter(env)
		if err != nil {
			t.Fatal(err)
		}
		pt := len(outer.CT) - 16 // ChaCha20-Poly1305 tag
		if pt < base || Padme(pt) != pt {
			t.Fatalf("body %d: inner is %d bytes (unpadded %d), not a Padmé length", n, pt, base)
		}
		if n < 1200 {
			continue
		}
		o := mustOpen(t, env, b)
		if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, t0, DefaultRotationGrace); err != nil {
			t.Fatalf("body %d: %v", n, err)
		}
	}
	if !hitUnreachable {
		t.Fatal("no size exercised an unreachable pad offset; widen the range")
	}
}

func TestEncodedLenMatchesEncoder(t *testing.T) {
	a, b := newParty(t), newParty(t)
	in := innerFrom(t, a, b, t0)
	in.Ext = map[uint64][]byte{64: enc(t, "x"), 70000: enc(t, make([]byte, 300))}
	fields, err := in.fieldMap()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		fields[uint64(1000+i)] = enc(t, uint64(i))
	}
	got, err := coredet.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if encodedLen(fields) != len(got) {
		t.Fatalf("encodedLen %d, encoder %d", encodedLen(fields), len(got))
	}
}
