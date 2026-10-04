package seal

// Tests of the delivery tokens (seal/dack.go; DLV §2.1, §2.2, §4.1 DLV-C-3 to C-7, §7.1 G2,
// §7.2 P1-P3; core §2.7, §2.15.2, CORE-K19, K21, K22). The ack_key itself, and Seal's and Open's
// export of it, are tested in ackkey_test.go.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/wire"
	"golang.org/x/crypto/chacha20poly1305"
)

const fileDAck1 = "testdata/vec-dack-1.json"

// randAckKey is a reproducible ack_key for the property tests.
func randAckKey(r *rand.Rand) AckKey {
	var k AckKey
	for i := range k {
		k[i] = byte(r.Uint32())
	}
	return k
}

func mustDAck(t testing.TB, k AckKey, o Outcome, n Note) [DAckLen]byte {
	t.Helper()
	d, err := k.MakeDAck(o, n)
	if err != nil {
		t.Fatalf("MakeDAck(%d, %+v): %v", o, n, err)
	}
	return d
}

// notePT opens the note of d under k and returns the plaintext as it is, without reading it.
func notePT(t testing.TB, k AckKey, o Outcome, d []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.New(k.noteKey())
	if err != nil {
		t.Fatal(err)
	}
	tok := k.token(o)
	pt, err := aead.Open(nil, d[TokenLen:TokenLen+noteNonceLen], d[TokenLen+noteNonceLen:], tok[:])
	if err != nil {
		t.Fatalf("the note does not open: %v", err)
	}
	return pt
}

// resealNote is d with its note replaced by pt sealed under k's note key with the aad tok(o) and
// d's nonce: an authentic note with any plaintext.
func resealNote(t testing.TB, k AckKey, o Outcome, d []byte, pt []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.New(k.noteKey())
	if err != nil {
		t.Fatal(err)
	}
	tok := k.token(o)
	out := append([]byte(nil), d[:TokenLen+noteNonceLen]...)
	copy(out, tok[:])
	return aead.Seal(out, out[TokenLen:], pt, tok[:])
}

// rawNotePT builds a note plaintext field by field, valid or not.
func rawNotePT(format byte, retry uint32, l byte, rest []byte) []byte {
	pt := make([]byte, notePTLen)
	pt[0] = format
	binary.BigEndian.PutUint32(pt[1:5], retry)
	pt[5] = l
	copy(pt[6:], rest)
	return pt
}

// --- DACK-1 (core §5.2) ------------------------------------------------------------------------

type vecDAck1 struct {
	Keys []struct {
		From    string   `json:"from"`
		AckKey  hexBytes `json:"ack_key"`
		Handle  hexBytes `json:"handle"`
		Tok1    hexBytes `json:"tok1"`
		Tok2    hexBytes `json:"tok2"`
		NoteKey hexBytes `json:"note_key"`
	} `json:"keys"`
	DAcks []struct {
		Name       string   `json:"name"`
		Key        int      `json:"key"`
		Outcome    Outcome  `json:"outcome"`
		Reason     string   `json:"reason"`
		RetryAfter uint32   `json:"retry_after"`
		NowMS      *uint64  `json:"now_ms"`
		Nonce      hexBytes `json:"nonce"`
		PT         hexBytes `json:"pt"`
		Note       hexBytes `json:"note"`
		DAck       hexBytes `json:"dack"`
	} `json:"dacks"`
	Verify []struct {
		Name       string   `json:"name"`
		DAck       hexBytes `json:"dack"`
		Keys       []int    `json:"keys"`
		OK         bool     `json:"ok"`
		Index      int      `json:"index"`
		Outcome    Outcome  `json:"outcome"`
		NoteOK     bool     `json:"note_ok"`
		Reason     string   `json:"reason"`
		RetryAfter uint32   `json:"retry_after"`
	} `json:"verify"`
	MakeRefuses []struct {
		Outcome    Outcome `json:"outcome"`
		Reason     string  `json:"reason"`
		RetryAfter uint32  `json:"retry_after"`
	} `json:"make_refuses"`
	RetryBucket []struct {
		Seconds   uint32 `json:"seconds"`
		DayWindow bool   `json:"day_window"`
		NowMS     uint64 `json:"now_ms"`
		Want      uint32 `json:"want"`
	} `json:"retry_bucket"`
}

// goldenAckKeys opens SEALED-2A and SEALED-2B with the recipient keys derived from their seeds
// and returns the two ack_keys Open exports, with the two vectors.
func goldenAckKeys(t *testing.T) ([2]AckKey, *vecSealed2A, *vecSealed2B) {
	t.Helper()
	var a vecSealed2A
	readVector(t, fileSealed2A, &a)
	kpA, _ := a.keys(t, "SEALED-2A")
	oa, err := Open(a.Envelope, a.Recipient.AID, StaticKeyRing{kpA}, nil)
	if err != nil {
		t.Fatalf("SEALED-2A: %v", err)
	}
	var b vecSealed2B
	readVector(t, fileSealed2B, &b)
	kpB, _ := b.keys(t, "SEALED-2B")
	ob, err := Open(b.Envelope, b.Recipient.AID, StaticKeyRing{kpB}, ixKeys{b.RecipientIX.key(t, "SEALED-2B", b.Sender.AID)})
	if err != nil {
		t.Fatalf("SEALED-2B: %v", err)
	}
	return [2]AckKey{oa.AckKey, ob.AckKey}, &a, &b
}

// TestDACK_1: Go reproduces every value of the vector gen_v016.py writes from the ack_keys of
// SEALED-2A and SEALED-2B (G2).
func TestDACK_1(t *testing.T) {
	var v vecDAck1
	readVector(t, fileDAck1, &v)
	keys, a, b := goldenAckKeys(t)
	if len(v.Keys) != 2 || v.Keys[0].From != "SEALED-2A" || v.Keys[1].From != "SEALED-2B" {
		t.Fatalf("keys %+v", v.Keys)
	}

	t.Run("keys", func(t *testing.T) {
		for i, k := range v.Keys {
			key := keys[i]
			h, t1, t2 := key.Handle(), key.token(OutcomeProcessed), key.token(OutcomeRefused)
			if !bytes.Equal(key[:], k.AckKey) || !bytes.Equal(h[:], k.Handle) || !bytes.Equal(t1[:], k.Tok1) ||
				!bytes.Equal(t2[:], k.Tok2) || !bytes.Equal(key.noteKey(), k.NoteKey) {
				t.Fatalf("%s: ack_key, handle, tok or note_key differs from the file", k.From)
			}
		}
		// The seal vectors pin the same handle and tokens; dack.go computes them.
		for _, s := range []struct {
			name           string
			key            AckKey
			handle, t1, t2 []byte
		}{{"SEALED-2A", keys[0], a.Handle, a.Tok1, a.Tok2}, {"SEALED-2B", keys[1], b.Handle, b.Tok1, b.Tok2}} {
			h, t1, t2 := s.key.Handle(), s.key.token(OutcomeProcessed), s.key.token(OutcomeRefused)
			if !bytes.Equal(h[:], s.handle) || !bytes.Equal(t1[:], s.t1) || !bytes.Equal(t2[:], s.t2) {
				t.Fatalf("%s: dack.go's handle or tokens are not the vector's", s.name)
			}
		}
	})
	t.Run("dacks", func(t *testing.T) {
		if len(v.DAcks) != 6 {
			t.Fatalf("%d dacks, want 6", len(v.DAcks))
		}
		for _, d := range v.DAcks {
			key := keys[d.Key]
			n := Note{Reason: d.Reason, RetryAfterS: d.RetryAfter}
			got, err := key.makeDAck(d.Outcome, n, [noteNonceLen]byte(d.Nonce))
			if err != nil {
				t.Fatalf("%s: %v", d.Name, err)
			}
			if !bytes.Equal(got[:], d.DAck) || !bytes.Equal(got[TokenLen:], d.Note) {
				t.Fatalf("%s: dack\n got  %x\n file %x", d.Name, got, d.DAck)
			}
			pt := encodeNotePT(n)
			if !bytes.Equal(pt[:], d.PT) || !bytes.Equal(notePT(t, key, d.Outcome, got[:]), d.PT) {
				t.Fatalf("%s: note plaintext", d.Name)
			}
			if d.NowMS != nil && RetryBucket(0, true, *d.NowMS) != d.RetryAfter {
				t.Fatalf("%s: RetryBucket at %d gives %d, the file %d", d.Name, *d.NowMS, RetryBucket(0, true, *d.NowMS), d.RetryAfter)
			}
		}
	})
	t.Run("verify", func(t *testing.T) {
		for _, c := range v.Verify {
			var ks []AckKey
			for _, i := range c.Keys {
				ks = append(ks, keys[i])
			}
			idx, o, n, noteOK, ok := VerifyDAck(ks, c.DAck)
			want := fmt.Sprintf("ok %v idx %d o %d noteOK %v note %+v", c.OK, -1, 0, false, Note{})
			if c.OK {
				want = fmt.Sprintf("ok %v idx %d o %d noteOK %v note %+v", true, c.Index, c.Outcome, c.NoteOK, Note{c.Reason, c.RetryAfter})
			}
			if got := fmt.Sprintf("ok %v idx %d o %d noteOK %v note %+v", ok, idx, o, noteOK, n); got != want {
				t.Errorf("%s:\n got  %s\n file %s", c.Name, got, want)
			}
		}
	})
	t.Run("make refuses", func(t *testing.T) {
		if len(v.MakeRefuses) == 0 {
			t.Fatal("no refused inputs")
		}
		for _, c := range v.MakeRefuses {
			if _, err := keys[0].MakeDAck(c.Outcome, Note{c.Reason, c.RetryAfter}); ReasonOf(err) != ReasonInvalidInput {
				t.Errorf("MakeDAck(%d, %q, %d): %v, want invalid-input", c.Outcome, c.Reason, c.RetryAfter, err)
			}
		}
	})
	t.Run("retry bucket", func(t *testing.T) {
		for _, c := range v.RetryBucket {
			if got := RetryBucket(c.Seconds, c.DayWindow, c.NowMS); got != c.Want {
				t.Errorf("RetryBucket(%d, %v, %d) = %d, file %d", c.Seconds, c.DayWindow, c.NowMS, got, c.Want)
			}
		}
	})
}

// --- P1-P3 (DLV §7.2) --------------------------------------------------------------------------

// P1: for random ack_keys, tok(1) != tok(2), the handle is neither token, and every value is a
// function of the key alone.
func TestDAckDerivationP1(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 1))
	seen := map[[TokenLen]byte]bool{}
	for range 2000 {
		k := randAckKey(r)
		h, t1, t2 := k.Handle(), k.token(OutcomeProcessed), k.token(OutcomeRefused)
		if t1 == t2 || bytes.Equal(h[:], t1[:]) || bytes.Equal(h[:], t2[:]) {
			t.Fatalf("key %x: handle %x, tok(1) %x, tok(2) %x are not distinct", k, h, t1, t2)
		}
		if k.Handle() != h || k.token(OutcomeProcessed) != t1 || k.token(OutcomeRefused) != t2 ||
			!bytes.Equal(k.noteKey(), k.noteKey()) {
			t.Fatal("a derivation is not deterministic")
		}
		for _, x := range [][TokenLen]byte{t1, t2} {
			if seen[x] {
				t.Fatalf("token %x repeats across keys", x)
			}
			seen[x] = true
		}
		// The token of a dack is the derivation, whatever the note.
		d := mustDAck(t, k, OutcomeRefused, Note{Reason: NoteBusy, RetryAfterS: 5})
		if [TokenLen]byte(d[:TokenLen]) != t2 {
			t.Fatal("a refused dack does not start with tok(2)")
		}
	}
}

// randNote is a random note a refused token may carry: the empty reason, a code of core §2.15.2,
// or another well-formed code, with a retry_after from anywhere in the u32 range.
func randNote(r *rand.Rand) Note {
	var n Note
	switch r.IntN(3) {
	case 1:
		n.Reason = noteCodes[r.IntN(len(noteCodes))]
	case 2:
		b := []byte{byte('a' + r.IntN(26))}
		for range r.IntN(MaxNoteReasonLen) {
			b = append(b, "abcdefghijklmnopqrstuvwxyz0123456789_"[r.IntN(37)])
		}
		n.Reason = string(b)
	}
	switch r.IntN(3) {
	case 1:
		n.RetryAfterS = r.Uint32N(MaxRetryAfterS + 1)
	case 2:
		n.RetryAfterS = r.Uint32()
	}
	return n
}

// P2: VerifyDAck finds the key a dack was made under, in a list of keys, with its outcome and
// note; any changed bit of the token makes it no token at all, and any changed bit of the note
// leaves the outcome and voids the note.
func TestVerifyDAckP2(t *testing.T) {
	r := rand.New(rand.NewPCG(2, 2))
	for i := range 300 {
		keys := make([]AckKey, 1+r.IntN(5))
		for j := range keys {
			keys[j] = randAckKey(r)
		}
		at := r.IntN(len(keys))
		o, n := OutcomeProcessed, Note{}
		if r.IntN(2) == 1 {
			o, n = OutcomeRefused, randNote(r)
		}
		d := mustDAck(t, keys[at], o, n)
		want := n
		want.RetryAfterS = min(n.RetryAfterS, MaxRetryAfterS)
		idx, got, gn, noteOK, ok := VerifyDAck(keys, d[:])
		if !ok || idx != at || got != o || !noteOK || gn != want {
			t.Fatalf("case %d: VerifyDAck = %d, %d, %+v, %v, %v; made under key %d, outcome %d, note %+v",
				i, idx, got, gn, noteOK, ok, at, o, want)
		}
		if i%10 != 0 {
			continue
		}
		for bit := range DAckLen * 8 {
			x := d
			x[bit/8] ^= 1 << (bit % 8)
			idx, got, gn, noteOK, ok := VerifyDAck(keys, x[:])
			switch {
			case bit < TokenLen*8:
				if ok || idx != -1 {
					t.Fatalf("case %d: token bit %d changed and the dack still verifies (key %d)", i, bit, idx)
				}
			default:
				if !ok || idx != at || got != o || noteOK || gn != (Note{}) {
					t.Fatalf("case %d: note bit %d changed: %d, %d, %+v, %v, %v", i, bit, idx, got, gn, noteOK, ok)
				}
			}
		}
	}
}

// P3: a dack is DAckLen bytes and its note NoteLen bytes, with a 36-byte plaintext, for every
// outcome, reason and wait; a reason that is not a code is refused; RetryBucket gives a tier, or
// a multiple of 900 seconds for the day window.
func TestDAckShapeP3(t *testing.T) {
	// dack, note, token, handle, and the note's parts (CORE-K11, core §2.7).
	if got := []int{DAckLen, NoteLen, TokenLen, HandleLen, noteNonceLen + notePTLen + chacha20poly1305.Overhead}; !slices.Equal(got, []int{80, 64, 16, 16, 64}) {
		t.Fatalf("lengths %v", got)
	}
	r := rand.New(rand.NewPCG(3, 3))
	k := randAckKey(r)
	check := func(o Outcome, n Note) {
		t.Helper()
		d := mustDAck(t, k, o, n)
		if len(d) != DAckLen || len(d[TokenLen:]) != NoteLen {
			t.Fatal("lengths")
		}
		if pt := notePT(t, k, o, d[:]); len(pt) != notePTLen {
			t.Fatalf("outcome %d, note %+v: a %d-byte note plaintext", o, n, len(pt))
		}
		if _, _, _, noteOK, ok := VerifyDAck([]AckKey{k}, d[:]); !ok || !noteOK {
			t.Fatalf("outcome %d, note %+v does not verify with its note", o, n)
		}
	}
	check(OutcomeProcessed, Note{})
	for _, c := range noteCodes {
		check(OutcomeRefused, Note{Reason: c})
		check(OutcomeRefused, Note{Reason: c, RetryAfterS: RetryBucket(1000, false, 0)})
	}
	for range 500 {
		check(OutcomeRefused, randNote(r))
	}
	for _, bad := range badNoteReasons() {
		if _, err := k.MakeDAck(OutcomeRefused, Note{Reason: bad}); ReasonOf(err) != ReasonInvalidInput {
			t.Fatalf("MakeDAck takes the reason %q: %v", bad, err)
		}
	}
	tiers := map[uint32]bool{0: true}
	for _, x := range retryTiers {
		tiers[x] = true
	}
	for range 10000 {
		s, now := r.Uint32(), r.Uint64()
		if s%3 == 0 {
			s %= 4000
		}
		if got := RetryBucket(s, false, now); !tiers[got] || (s <= 3600 && got < s) {
			t.Fatalf("RetryBucket(%d) = %d", s, got)
		}
		got := RetryBucket(s, true, now)
		left := (dayMS - now%dayMS + 999) / 1000
		if got%900 != 0 || got == 0 || got > MaxRetryAfterS || uint64(got) < left || uint64(got) >= left+900 {
			t.Fatalf("RetryBucket(day, %d) = %d, %d s to midnight", now, got, left)
		}
	}
}

// badNoteReasons are strings that are not reason codes (CORE-K19).
func badNoteReasons() []string {
	return []string{
		"Busy", "BUSY", "1busy", "_busy", "busy-x", "busy x", "busy ", " busy", "busy.x", "busy/x",
		"busy\x00", "bus\u00ff", "büsy", strings.Repeat("a", MaxNoteReasonLen+1), "a\tb", "a\nb",
	}
}

// --- MakeDAck and VerifyDAck rules ---------------------------------------------------------------

// DLV-C-3, DLV-W-5, DLV-W-6: what MakeDAck writes and refuses.
func TestMakeDAck(t *testing.T) {
	r := rand.New(rand.NewPCG(4, 4))
	k := randAckKey(r)
	t.Run("a processed token carries the empty note", func(t *testing.T) {
		d := mustDAck(t, k, OutcomeProcessed, Note{})
		if !bytes.Equal(notePT(t, k, OutcomeProcessed, d[:]), rawNotePT(noteFormat, 0, 0, nil)) {
			t.Fatal("the processed note is not the format byte and zeros")
		}
		for _, n := range []Note{{Reason: NoteBusy}, {RetryAfterS: 1}, {Reason: "x"}} {
			if _, err := k.MakeDAck(OutcomeProcessed, n); ReasonOf(err) != ReasonInvalidInput {
				t.Fatalf("a processed token with note %+v: %v", n, err)
			}
		}
	})
	t.Run("only outcomes 1 and 2", func(t *testing.T) {
		for _, o := range []Outcome{0, 3, 255} {
			if _, err := k.MakeDAck(o, Note{}); ReasonOf(err) != ReasonInvalidInput {
				t.Fatalf("outcome %d: %v", o, err)
			}
		}
	})
	t.Run("a reason is written as given or refused", func(t *testing.T) {
		long := strings.Repeat("a", MaxNoteReasonLen)
		d := mustDAck(t, k, OutcomeRefused, Note{Reason: long})
		if pt := notePT(t, k, OutcomeRefused, d[:]); pt[5] != MaxNoteReasonLen || string(pt[6:]) != long {
			t.Fatal("a 30-byte reason is not written whole")
		}
		// One byte more is refused, not cut to 30.
		if _, err := k.MakeDAck(OutcomeRefused, Note{Reason: long + "a"}); ReasonOf(err) != ReasonInvalidInput {
			t.Fatalf("a 31-byte reason: %v", err)
		}
		d = mustDAck(t, k, OutcomeRefused, Note{Reason: NoteQuotaCallerPerDay, RetryAfterS: 900})
		if !bytes.Equal(notePT(t, k, OutcomeRefused, d[:]), rawNotePT(noteFormat, 900, 20, []byte(NoteQuotaCallerPerDay))) {
			t.Fatal("the note plaintext is not format, retry_after, L, reason, zeros")
		}
	})
	t.Run("retry_after is capped at 86 400", func(t *testing.T) {
		for _, s := range []uint32{MaxRetryAfterS, MaxRetryAfterS + 1, 1 << 31, 1<<32 - 1} {
			d := mustDAck(t, k, OutcomeRefused, Note{Reason: NoteBusy, RetryAfterS: s})
			if got := binary.BigEndian.Uint32(notePT(t, k, OutcomeRefused, d[:])[1:5]); got != MaxRetryAfterS {
				t.Fatalf("retry_after %d written as %d", s, got)
			}
		}
	})
	t.Run("a fresh nonce each time", func(t *testing.T) {
		n := Note{Reason: NoteCallerBusy, RetryAfterS: 5}
		d1, d2 := mustDAck(t, k, OutcomeRefused, n), mustDAck(t, k, OutcomeRefused, n)
		if !bytes.Equal(d1[:TokenLen], d2[:TokenLen]) || bytes.Equal(d1[TokenLen:], d2[TokenLen:]) {
			t.Fatal("two dacks of one key, outcome and note: same token, different notes expected")
		}
	})
	t.Run("the zero ack_key", func(t *testing.T) {
		if _, err := (AckKey{}).MakeDAck(OutcomeProcessed, Note{}); ReasonOf(err) != ReasonInvalidInput {
			t.Fatalf("the zero ack_key makes a dack: %v", err)
		}
	})
}

// DLV-C-4, DLV-W-7: how VerifyDAck reads what it is given.
func TestVerifyDAck(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 5))
	k1, k2, k3 := randAckKey(r), randAckKey(r), randAckKey(r)
	busy := mustDAck(t, k2, OutcomeRefused, Note{Reason: NoteBusy, RetryAfterS: 60})
	type res struct {
		idx    int
		o      Outcome
		n      Note
		noteOK bool
		ok     bool
	}
	verify := func(keys []AckKey, d []byte) res {
		idx, o, n, noteOK, ok := VerifyDAck(keys, d)
		return res{idx, o, n, noteOK, ok}
	}
	none := res{-1, 0, Note{}, false, false}
	broken := res{1, OutcomeRefused, Note{}, false, true}
	for _, c := range []struct {
		name string
		keys []AckKey
		dack []byte
		want res
	}{
		{"the version's key among others", []AckKey{k1, k2, k3}, busy[:], res{1, OutcomeRefused, Note{NoteBusy, 60}, true, true}},
		{"no key", nil, busy[:], none},
		{"other keys", []AckKey{k1, k3}, busy[:], none},
		{"the zero key", []AckKey{{}}, func() []byte {
			// A dack under the zero key, made by hand: whoever made it, it confirms nothing.
			var z AckKey
			return resealNote(t, z, OutcomeProcessed, make([]byte, DAckLen), rawNotePT(noteFormat, 0, 0, nil))
		}(), none},
		{"empty", []AckKey{k2}, nil, none},
		{"79 bytes", []AckKey{k2}, busy[:79], none},
		{"81 bytes", []AckKey{k2}, append(busy[:], 0), none},
		{"twice", []AckKey{k2}, append(busy[:], busy[:]...), none},
		{"the note of another key's dack", []AckKey{k1, k2}, func() []byte {
			d := mustDAck(t, k1, OutcomeRefused, Note{Reason: NoteBusy, RetryAfterS: 60})
			return append(busy[:TokenLen:TokenLen], d[TokenLen:]...)
		}(), broken},
		{"the note made for the other outcome", []AckKey{k1, k2}, func() []byte {
			d := mustDAck(t, k2, OutcomeProcessed, Note{})
			return append(busy[:TokenLen:TokenLen], d[TokenLen:]...)
		}(), broken},
		{"format 0x02", []AckKey{k1, k2}, resealNote(t, k2, OutcomeRefused, busy[:], rawNotePT(2, 60, 4, []byte("busy"))), broken},
		{"format 0x00", []AckKey{k1, k2}, resealNote(t, k2, OutcomeRefused, busy[:], rawNotePT(0, 60, 4, []byte("busy"))), broken},
		{"L = 31", []AckKey{k1, k2}, resealNote(t, k2, OutcomeRefused, busy[:], rawNotePT(1, 60, 31, []byte("busy"))), broken},
		{"L = 255", []AckKey{k1, k2}, resealNote(t, k2, OutcomeRefused, busy[:], rawNotePT(1, 60, 255, []byte("busy"))), broken},
		{"a byte after the reason", []AckKey{k1, k2}, resealNote(t, k2, OutcomeRefused, busy[:], rawNotePT(1, 60, 4, []byte("busyx"))), broken},
		{"a byte in the last place", []AckKey{k1, k2}, resealNote(t, k2, OutcomeRefused, busy[:], func() []byte {
			pt := rawNotePT(1, 60, 4, []byte("busy"))
			pt[notePTLen-1] = 1
			return pt
		}()), broken},
		{"L = 0 and a reason", []AckKey{k1, k2}, resealNote(t, k2, OutcomeRefused, busy[:], rawNotePT(1, 60, 0, []byte("busy"))), broken},
		{"L covers a NUL", []AckKey{k1, k2}, resealNote(t, k2, OutcomeRefused, busy[:], rawNotePT(1, 60, 5, []byte("busy"))), broken},
		{"an upper-case reason", []AckKey{k1, k2}, resealNote(t, k2, OutcomeRefused, busy[:], rawNotePT(1, 60, 4, []byte("Busy"))), broken},
		{"a reason that starts with a digit", []AckKey{k1, k2}, resealNote(t, k2, OutcomeRefused, busy[:], rawNotePT(1, 60, 5, []byte("1busy"))), broken},
		{"retry_after over 86 400", []AckKey{k1, k2}, resealNote(t, k2, OutcomeRefused, busy[:], rawNotePT(1, 1<<32-1, 4, []byte("busy"))),
			res{1, OutcomeRefused, Note{NoteBusy, MaxRetryAfterS}, true, true}},
		{"a well-formed code outside core §2.15.2 is kept", []AckKey{k1, k2}, resealNote(t, k2, OutcomeRefused, busy[:], rawNotePT(1, 0, 13, []byte("over_capacity"))),
			res{1, OutcomeRefused, Note{"over_capacity", 0}, true, true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := verify(c.keys, c.dack); got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
	t.Run("the first key that matches", func(t *testing.T) {
		// Two versions with one key cannot happen; a key listed twice answers at its first place.
		if got := verify([]AckKey{k1, k2, k2}, busy[:]); got.idx != 1 {
			t.Fatalf("index %d", got.idx)
		}
	})
	t.Run("the dack is not changed", func(t *testing.T) {
		d := busy
		VerifyDAck([]AckKey{k2}, d[:])
		if d != busy {
			t.Fatal("VerifyDAck wrote to its input")
		}
	})
}

// --- RetryBucket (DLV-C-6, CORE-K22) -------------------------------------------------------------

func TestRetryBucket(t *testing.T) {
	const day = 86_400_000
	midnight := uint64(20370) * day // 2025-10-09T00:00:00Z
	for _, c := range []struct {
		seconds uint32
		day     bool
		now     uint64
		want    uint32
	}{
		// The tiers: the smallest not below the wait; 0 for none; 3600 above 3600.
		{0, false, 0, 0},
		{1, false, 0, 1}, {2, false, 0, 5}, {4, false, 0, 5}, {5, false, 0, 5},
		{6, false, 0, 15}, {15, false, 0, 15}, {16, false, 0, 60}, {30, false, 0, 60}, {60, false, 0, 60},
		{61, false, 0, 300}, {300, false, 0, 300}, {301, false, 0, 900}, {900, false, 0, 900},
		{901, false, 0, 3600}, {3599, false, 0, 3600}, {3600, false, 0, 3600},
		{3601, false, 0, 3600}, {86_400, false, 0, 3600}, {1<<32 - 1, false, 0, 3600},
		// The time is not read without the day window.
		{30, false, midnight + 123, 60},
		// The day window: to the next UTC midnight, whole seconds rounded up, then up to a
		// multiple of 900; the wait given is ignored.
		{0, true, midnight, 86_400},
		{0, true, midnight + 1, 86_400},
		{0, true, midnight + 900_000 - 1, 86_400},
		{0, true, midnight + 900_000, 85_500},
		{0, true, midnight + 900_001, 85_500},
		{5, true, midnight + 12*3_600_000, 43_200},
		{1<<32 - 1, true, midnight + 12*3_600_000, 43_200},
		{0, true, midnight + day - 900_001, 1800},
		{0, true, midnight + day - 900_000, 900},
		{0, true, midnight + day - 1000, 900},
		{0, true, midnight + day - 1, 900},
		{0, true, 0, 86_400},
		{0, true, 1<<64 - 1, 35_100},
	} {
		if got := RetryBucket(c.seconds, c.day, c.now); got != c.want {
			t.Errorf("RetryBucket(%d, %v, %d) = %d, want %d", c.seconds, c.day, c.now, got, c.want)
		}
	}
}

// --- the note codes and the imports (DLV-C-5, DLV-C-7) -----------------------------------------

// noteCodes are the values of the Note* constants of dack.go, read from the source.
var noteCodes = func() []string {
	codes, err := noteConstants()
	if err != nil {
		panic(err)
	}
	return codes
}()

// noteConstants reads the string constants named Note* from dack.go.
func noteConstants() ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), "dack.go", nil, 0)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, id := range vs.Names {
				if !strings.HasPrefix(id.Name, "Note") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					return nil, err
				}
				out = append(out, s)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// DLV-C-7: the note code constants are the registry's reasons.note, one for one; each is a code
// a note can carry; the three codes decided after the message was taken are not among them
// (CORE-K21). TestWireRegistry checks the same set from the "complete" directive.
func TestNoteCodesAreTheRegistrySet(t *testing.T) {
	reg := wire.MustLoad().ReasonCodes("note")
	if len(reg) != 18 || !slices.Equal(noteCodes, reg) {
		t.Fatalf("Note* constants %v\nregistry reasons.note %v", noteCodes, reg)
	}
	for _, c := range noteCodes {
		if !ValidNoteReason(c) {
			t.Errorf("%q is not a reason code (CORE-K19)", c)
		}
	}
	for _, c := range []string{"sandbox_unavailable", "budget", "provider_policy"} {
		if slices.Contains(noteCodes, c) {
			t.Errorf("%q is decided after the message is taken; it is not a note code (CORE-K21)", c)
		}
	}
	for _, s := range badNoteReasons() {
		if ValidNoteReason(s) {
			t.Errorf("ValidNoteReason(%q)", s)
		}
	}
	if ValidNoteReason("") {
		t.Error("the empty reason is not a code")
	}
}

// DLV-C-5: dack.go does no I/O and reads no clock. Its imports are crypto packages (the
// standard library has no ChaCha20-Poly1305 of its own: golang.org/x/crypto's is the one
// crypto/hpke uses), encoding/binary and errors.
func TestDAckImports(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "dack.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Imports) == 0 {
		t.Fatal("no imports read")
	}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		switch {
		case strings.HasPrefix(p, "crypto/"), p == "encoding/binary", p == "errors",
			p == "golang.org/x/crypto/chacha20poly1305":
		default:
			t.Errorf("dack.go imports %q: only crypto/*, encoding/binary and errors (DLV-C-5)", p)
		}
	}
}

// The labels and the layout are the registry's (core §3.2 L12-L14, §2.7).
func TestDAckLabelsAndLayoutAreRegistered(t *testing.T) {
	reg := wire.MustLoad()
	for id, label := range map[string]string{"L11": DAckExporterContext, "L12": dackHandleLabel, "L13": dackTokLabel, "L14": dackNoteLabel} {
		tag := reg.Tag(label)
		if tag == nil || tag.ID != id || tag.Class != "C" {
			t.Errorf("%s %q: registry has %+v", id, label, tag)
		}
	}
	var layout *wire.Layout
	for _, l := range reg.Layouts {
		if l.Name == "dack" {
			layout = l
		}
	}
	if layout == nil || layout.Len != DAckLen {
		t.Fatalf("registry layout dack %+v, want %d bytes", layout, DAckLen)
	}
	want := map[string][2]int{"dack/0": {0, TokenLen}, "dack/16": {TokenLen, NoteLen},
		"note/0": {0, noteNonceLen}, "note/12": {noteNonceLen, NoteLen - noteNonceLen},
		"pt/0": {0, 1}, "pt/1": {1, 4}, "pt/5": {5, 1}, "pt/6": {6, MaxNoteReasonLen}}
	for _, p := range layout.Parts {
		key := fmt.Sprintf("%s/%d", p.Of, p.Off)
		if w, ok := want[key]; !ok || w != [2]int{p.Off, p.Len} {
			t.Errorf("layout part %s of %d bytes, dack.go has %v", key, p.Len, w)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Errorf("layout parts missing from the registry: %v", want)
	}
}
