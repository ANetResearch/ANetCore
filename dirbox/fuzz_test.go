package dirbox

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzDirEntry: the DirEntry decoder never panics, refuses with ErrEntry only, and accepts only
// canonical bytes: an accepted plaintext re-encodes to itself, and seals and opens to the same
// entry.
func FuzzDirEntry(f *testing.F) {
	v := loadDirVector(f)
	for _, c := range v.Cases {
		f.Add(unhex(f, c.Plaintext))
	}
	valid, err := sample().Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{0xa0})
	f.Add([]byte{0xbf, 0xff})
	f.Add(append(bytes.Clone(valid), 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := UnmarshalDirEntry(b)
		if err != nil {
			if !errors.Is(err, ErrEntry) {
				t.Fatalf("error %v is not ErrEntry", err)
			}
			if e != nil {
				t.Fatal("an entry came back with the error")
			}
			return
		}
		again, err := e.Marshal()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("accepted %x, which re-encodes to %x (%v)", b, again, err)
		}
		if len(b)+Overhead > MaxBoxLen {
			return
		}
		box, err := Seal(e.AID, e, nil)
		if err != nil {
			t.Fatalf("an accepted entry does not seal: %v", err)
		}
		h, err := Hash(e.AID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Open(e.AID, h, box)
		if err != nil || !entriesEqual(got, e) {
			t.Fatalf("round trip: %+v, %v", got, err)
		}
	})
}

// FuzzOpen: opening whatever a directory hands over never panics and refuses with the package's
// errors only; a box that opens yields an entry naming the AID it was opened with, and a box with
// any byte changed does not open.
func FuzzOpen(f *testing.F) {
	v := loadDirVector(f)
	for _, c := range v.Cases {
		f.Add(c.AID, unhex(f, c.H), unhex(f, c.Box), 0)
	}
	for _, r := range v.Refused {
		f.Add(r.AID, unhex(f, r.H), unhex(f, r.Box), 3)
	}
	f.Fuzz(func(t *testing.T, aid string, h, box []byte, at int) {
		e, err := Open(aid, h, box)
		if err != nil {
			for _, known := range []error{ErrAID, ErrHash, ErrOpen, ErrEntry, ErrTooLarge} {
				if errors.Is(err, known) {
					return
				}
			}
			t.Fatalf("unexpected error %v", err)
		}
		if e.AID != aid {
			t.Fatalf("opened under %q, the entry names %q", aid, e.AID)
		}
		if len(box) == 0 {
			t.Fatal("an empty box opened")
		}
		i := int(uint(at) % uint(len(box)))
		changed := bytes.Clone(box)
		changed[i] ^= 0x80
		if _, err := Open(aid, h, changed); err == nil {
			t.Fatalf("the box opens with byte %d changed", i)
		}
	})
}

// FuzzPrefix: CheckPrefix accepts exactly the prefixes Prefix produces, and h is in the bucket of
// each of its own prefixes.
func FuzzPrefix(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0xa5}, HashLen), []byte{0xa4}, 6)
	f.Add(bytes.Repeat([]byte{0xff}, HashLen), []byte{}, 0)
	f.Fuzz(func(t *testing.T, h, prefix []byte, bits int) {
		okPrefix := CheckPrefix(prefix, bits) == nil
		if len(h) != HashLen {
			if InBucket(h, prefix, bits) {
				t.Fatal("a malformed hash is in a bucket")
			}
			return
		}
		p, err := Prefix(h, bits)
		if err != nil {
			if okPrefix {
				t.Fatalf("CheckPrefix accepts %d bits but Prefix refuses them", bits)
			}
			return
		}
		if CheckPrefix(p, bits) != nil {
			t.Fatalf("Prefix(%x, %d) = %x, which CheckPrefix refuses", h, bits, p)
		}
		if !InBucket(h, p, bits) {
			t.Fatal("h is not in its own bucket")
		}
		if InBucket(h, prefix, bits) != (okPrefix && bytes.Equal(p, prefix)) {
			t.Fatalf("InBucket(%x, %x, %d) disagrees with Prefix", h, prefix, bits)
		}
	})
}
