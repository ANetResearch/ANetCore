package seal

// Fuzz targets of the delivery tokens (seal/dack.go), the decoders of what a sender receives
// from a hub or a peer:
//   - FuzzVerifyDAck feeds arbitrary bytes to VerifyDAck under the two DACK-1 keys and a third,
//     in an order the input picks, and checks the result against the derivations: a token is
//     accepted only as tok(1) or tok(2) of the first key that has it, an accepted note reads as
//     the reference reader reads it, and a dack that reads cleanly is the one MakeDAck makes
//     from what was read;
//   - FuzzNoteOpen seals an arbitrary note plaintext under a fixed key (so the AEAD opens and
//     the reader sees every byte), or hands arbitrary bytes to the note opener, and compares the
//     reader with a reference written from DLV-W-7 and CORE-K19 alone.
//
// The envelope's own targets are in fuzz_test.go and fuzz_layer2_test.go.

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// fuzzDAckKeys are the ack_keys of DACK-1 (SEALED-2A, SEALED-2B) and a third key.
func fuzzDAckKeys(tb testing.TB) ([]AckKey, *vecDAck1) {
	tb.Helper()
	var v vecDAck1
	readVector(tb, fileDAck1, &v)
	keys := make([]AckKey, 0, 3)
	for _, k := range v.Keys {
		keys = append(keys, AckKey(k.AckKey))
	}
	var third AckKey
	copy(third[:], goldenSeed("DACK-1", "fuzz-third-key"))
	return append(keys, third), &v
}

// refCode is CORE-K19, as the specification writes it.
var refCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,29}$`)

// refNote reads a note plaintext as DLV-W-7 says, independently of decodeNotePT.
func refNote(pt []byte) (Note, bool) {
	if len(pt) != 36 || pt[0] != 0x01 || pt[5] > 30 {
		return Note{}, false
	}
	l := int(pt[5])
	if l > 0 && !refCode.Match(pt[6:6+l]) {
		return Note{}, false
	}
	if !bytes.Equal(pt[6+l:], make([]byte, 30-l)) {
		return Note{}, false
	}
	return Note{Reason: string(pt[6 : 6+l]), RetryAfterS: min(binary.BigEndian.Uint32(pt[1:5]), 86_400)}, true
}

func FuzzVerifyDAck(f *testing.F) {
	keys, v := fuzzDAckKeys(f)
	for _, d := range v.DAcks {
		f.Add([]byte(d.DAck), uint8(0))
		f.Add([]byte(d.DAck), uint8(5))
	}
	for _, c := range v.Verify {
		f.Add([]byte(c.DAck), uint8(len(c.Keys)))
	}
	f.Add([]byte{}, uint8(0))
	f.Add(make([]byte, DAckLen), uint8(3))
	// The orders the selector picks: every key list of up to three of the keys.
	orders := [][]int{{}, {0}, {1}, {2}, {0, 1}, {1, 0}, {0, 2}, {2, 1}, {0, 1, 2}, {2, 1, 0}, {1, 1, 0}, {2, 0, 1}}
	f.Fuzz(func(t *testing.T, dack []byte, sel uint8) {
		order := orders[int(sel)%len(orders)]
		ks := make([]AckKey, len(order))
		for i, j := range order {
			ks[i] = keys[j]
		}
		idx, o, n, noteOK, ok := VerifyDAck(ks, dack)
		if !ok {
			if idx != -1 || o != 0 || n != (Note{}) || noteOK {
				t.Fatalf("refused, yet idx %d o %d note %+v noteOK %v", idx, o, n, noteOK)
			}
			if len(dack) == DAckLen {
				for i := range ks {
					for _, out := range []Outcome{OutcomeProcessed, OutcomeRefused} {
						if tok := ks[i].token(out); bytes.Equal(tok[:], dack[:TokenLen]) {
							t.Fatalf("tok(%d) of key %d refused", out, i)
						}
					}
				}
			}
			return
		}
		if len(dack) != DAckLen || idx < 0 || idx >= len(ks) || (o != OutcomeProcessed && o != OutcomeRefused) {
			t.Fatalf("accepted: len %d idx %d o %d", len(dack), idx, o)
		}
		if tok := ks[idx].token(o); !bytes.Equal(tok[:], dack[:TokenLen]) {
			t.Fatal("accepted a token that is not the key's")
		}
		for i := range idx {
			for _, out := range []Outcome{OutcomeProcessed, OutcomeRefused} {
				if tok := ks[i].token(out); bytes.Equal(tok[:], dack[:TokenLen]) {
					t.Fatalf("key %d matches first, VerifyDAck said %d", i, idx)
				}
			}
		}
		// The note, opened by the test's own AEAD call and read by the reference.
		aead, err := chacha20poly1305.New(ks[idx].noteKey())
		if err != nil {
			t.Fatal(err)
		}
		tok := ks[idx].token(o)
		pt, err := aead.Open(nil, dack[TokenLen:TokenLen+12], dack[TokenLen+12:], tok[:])
		want, wantOK := Note{}, false
		if err == nil {
			want, wantOK = refNote(pt)
		}
		if noteOK != wantOK || n != want {
			t.Fatalf("note %+v ok %v; the reference reads %+v ok %v", n, noteOK, want, wantOK)
		}
		if !noteOK {
			return
		}
		// A note that reads cleanly is the one MakeDAck writes from what was read, unless it
		// says more than MakeDAck would write (a capped wait, or a reason on a processed token).
		if binary.BigEndian.Uint32(pt[1:5]) > MaxRetryAfterS || (o == OutcomeProcessed && n != (Note{})) {
			return
		}
		again, err := ks[idx].makeDAck(o, n, [noteNonceLen]byte(dack[TokenLen:TokenLen+noteNonceLen]))
		if err != nil || !bytes.Equal(again[:], dack) {
			t.Fatalf("MakeDAck of the note read does not give the dack back (%v)", err)
		}
	})
}

func FuzzNoteOpen(f *testing.F) {
	keys, v := fuzzDAckKeys(f)
	k := keys[0]
	for _, d := range v.DAcks {
		f.Add([]byte(d.PT), uint8(d.Outcome), false)
		f.Add([]byte(d.Note), uint8(d.Outcome), true)
	}
	f.Add(rawNotePT(1, 30, 4, []byte("busy")), uint8(2), false)
	f.Add(rawNotePT(1, 1<<32-1, 30, bytes.Repeat([]byte("a"), 30)), uint8(2), false)
	f.Add(rawNotePT(1, 0, 31, nil), uint8(2), false)
	f.Add(rawNotePT(2, 0, 0, nil), uint8(1), false)
	f.Add(rawNotePT(1, 0, 4, []byte("busy\x01")), uint8(2), false)
	f.Add(rawNotePT(1, 0, 4, []byte("Busy")), uint8(2), false)
	f.Add(rawNotePT(1, 0, 4, []byte("bUsy")), uint8(2), false)
	f.Add(rawNotePT(1, 0, 1, []byte("_")), uint8(2), false)
	f.Add(rawNotePT(1, 0, 1, []byte("b")), uint8(2), false)
	f.Add(make([]byte, NoteLen), uint8(1), true)
	f.Fuzz(func(t *testing.T, in []byte, ob uint8, raw bool) {
		o := Outcome(ob%2 + 1)
		if raw {
			// Arbitrary note bytes: the opener must not fail on them, and whatever opens is read
			// as the reference reads it.
			n, ok := k.openNote(o, in)
			if len(in) != NoteLen && ok {
				t.Fatalf("a note of %d bytes opened", len(in))
			}
			if ok {
				if (n.Reason != "" && !ValidNoteReason(n.Reason)) || n.RetryAfterS > MaxRetryAfterS {
					t.Fatalf("read %+v", n)
				}
			} else if n != (Note{}) {
				t.Fatalf("a note that does not open reads as %+v", n)
			}
			return
		}
		if len(in) != notePTLen {
			if n, ok := decodeNotePT(in); ok || n != (Note{}) {
				t.Fatalf("a %d-byte plaintext reads as %+v", len(in), n)
			}
			return
		}
		// An authentic note with the fuzzed plaintext.
		d := resealNote(t, k, o, make([]byte, DAckLen), in)
		_, gotO, n, noteOK, ok := VerifyDAck([]AckKey{k}, d)
		want, wantOK := refNote(in)
		if !ok || gotO != o || noteOK != wantOK || n != want {
			t.Fatalf("VerifyDAck: o %d note %+v ok %v %v; the reference reads %+v ok %v", gotO, n, noteOK, ok, want, wantOK)
		}
		if dn, dok := decodeNotePT(in); dok != wantOK || dn != want {
			t.Fatalf("decodeNotePT %+v %v", dn, dok)
		}
		if !noteOK {
			return
		}
		// Writing what was read gives the plaintext back, the wait capped.
		pt := encodeNotePT(n)
		capped := append([]byte(nil), in...)
		binary.BigEndian.PutUint32(capped[1:5], min(binary.BigEndian.Uint32(in[1:5]), MaxRetryAfterS))
		if !bytes.Equal(pt[:], capped) {
			t.Fatalf("encodeNotePT(%+v) = %x, read from %x", n, pt, in)
		}
	})
}
