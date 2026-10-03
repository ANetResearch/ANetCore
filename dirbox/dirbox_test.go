package dirbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/wire"
)

// dirVector is dirbox/testdata/vec-dir-1.json (DIR-1), made by golden/py/gen_session_dir.py with
// its own SHA-256, HKDF, ChaCha20-Poly1305 and CBOR encoder. Go must reproduce h, K, the plaintext
// and the box byte for byte, open every case, and refuse every refused box for the recorded reason.
type dirVector struct {
	ID    string `json:"id"`
	Cases []struct {
		Name      string            `json:"name"`
		AID       string            `json:"aid"`
		Entry     map[string]string `json:"entry"`
		Plaintext string            `json:"plaintext"`
		H         string            `json:"h"`
		K         string            `json:"k"`
		Nonce     string            `json:"nonce"`
		Box       string            `json:"box"`
	} `json:"cases"`
	Refused []struct {
		Name  string `json:"name"`
		AID   string `json:"aid"`
		H     string `json:"h"`
		Box   string `json:"box"`
		Error string `json:"error"`
	} `json:"refused"`
	HashRefused []struct {
		Name  string `json:"name"`
		AID   string `json:"aid"`
		Error string `json:"error"`
	} `json:"hash_refused"`
}

var errorKind = map[string]error{
	"open":  ErrOpen,
	"hash":  ErrHash,
	"entry": ErrEntry,
	"aid":   ErrAID,
}

func loadDirVector(t testing.TB) *dirVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/vec-dir-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v dirVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.ID != "DIR-1" {
		t.Fatalf("vector id %q", v.ID)
	}
	return &v
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func entryOf(t testing.TB, m map[string]string) *DirEntry {
	t.Helper()
	e := &DirEntry{AID: m["aid"], Home: m["home"], KEL: unhex(t, m["kel"]), Keys: unhex(t, m["keys"])}
	if c, ok := m["card"]; ok {
		e.Card = unhex(t, c)
	}
	if n, ok := m["notice"]; ok {
		e.Notice = unhex(t, n)
	}
	return e
}

// DIR-1: Go and the independent implementation agree on h, K, the plaintext and the box, and
// each opens the other's box to the same entry.
func TestDirVector(t *testing.T) {
	v := loadDirVector(t)
	if len(v.Cases) < 2 {
		t.Fatalf("%d cases", len(v.Cases))
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			h, err := Hash(c.AID)
			if err != nil || !bytes.Equal(h, unhex(t, c.H)) {
				t.Fatalf("h\n got  %x (%v)\n want %s", h, err, c.H)
			}
			k, err := Key(c.AID)
			if err != nil || !bytes.Equal(k, unhex(t, c.K)) {
				t.Fatalf("K\n got  %x (%v)\n want %s", k, err, c.K)
			}
			e := entryOf(t, c.Entry)
			pt, err := e.Marshal()
			if err != nil || !bytes.Equal(pt, unhex(t, c.Plaintext)) {
				t.Fatalf("plaintext\n got  %x (%v)\n want %s", pt, err, c.Plaintext)
			}
			box, err := Seal(c.AID, e, bytes.NewReader(unhex(t, c.Nonce)))
			if err != nil || !bytes.Equal(box, unhex(t, c.Box)) {
				t.Fatalf("box\n got  %x (%v)\n want %s", box, err, c.Box)
			}
			got, err := Open(c.AID, h, unhex(t, c.Box))
			if err != nil {
				t.Fatalf("the vector's box does not open: %v", err)
			}
			if !entriesEqual(got, e) {
				t.Fatalf("opened %+v, want %+v", got, e)
			}
		})
	}
	if len(v.Refused) < 10 {
		t.Fatalf("only %d refused boxes", len(v.Refused))
	}
	for _, r := range v.Refused {
		t.Run("refused/"+r.Name, func(t *testing.T) {
			want, ok := errorKind[r.Error]
			if !ok {
				t.Fatalf("unknown error kind %q", r.Error)
			}
			e, err := Open(r.AID, unhex(t, r.H), unhex(t, r.Box))
			if !errors.Is(err, want) {
				t.Fatalf("got %+v, %v; want %v", e, err, want)
			}
			if e != nil {
				t.Fatal("an entry came back with the error")
			}
		})
	}
	for _, r := range v.HashRefused {
		t.Run("hash refused/"+r.Name, func(t *testing.T) {
			if _, err := Hash(r.AID); !errors.Is(err, errorKind[r.Error]) {
				t.Fatalf("Hash: got %v, want %v", err, r.Error)
			}
			if _, err := Key(r.AID); !errors.Is(err, errorKind[r.Error]) {
				t.Fatalf("Key: got %v, want %v", err, r.Error)
			}
		})
	}
}

func entriesEqual(a, b *DirEntry) bool {
	return a.AID == b.AID && a.Home == b.Home && bytes.Equal(a.KEL, b.KEL) && bytes.Equal(a.Keys, b.Keys) &&
		bytes.Equal(a.Card, b.Card) && bytes.Equal(a.Notice, b.Notice)
}

func sample() *DirEntry {
	return &DirEntry{
		AID:  "bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay",
		Home: "bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y",
		KEL:  []byte("kel bytes"), Keys: []byte("key set bytes"),
		Card: []byte(`{"name":"a hidden agent"}`), Notice: []byte("notice bytes"),
	}
}

// A hidden entry cannot be read without its AID (M20). The box shows no byte run of the entry,
// and the hash it is filed under is labelled: it is not the plain SHA-256 of the AID, and it is
// not the box key, so publishing h gives nothing towards opening the box.
func TestBoxHidesTheEntry(t *testing.T) {
	e := sample()
	box, err := Seal(e.AID, e, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(box) != len(pt)+Overhead {
		t.Fatalf("box is %d bytes for a %d-byte entry", len(box), len(pt))
	}
	for _, secret := range [][]byte{[]byte(e.AID), []byte(e.Home), e.KEL, e.Keys, e.Card, e.Notice, pt[:8]} {
		if bytes.Contains(box, secret) {
			t.Fatalf("the box shows %q in the clear", secret)
		}
	}
	h, err := Hash(e.AID)
	if err != nil {
		t.Fatal(err)
	}
	plain := sha256.Sum256([]byte(e.AID))
	if bytes.Equal(h, plain[:]) {
		t.Fatal("h is the plain SHA-256 of the AID: anyone with a list of AIDs can match entries without the label")
	}
	k, err := Key(e.AID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(h, k) {
		t.Fatal("h equals the box key: the published hash opens the box")
	}
	if _, err := Open("bafyreisomeoneelse", h, box); !errors.Is(err, ErrHash) {
		t.Fatalf("another AID with this h: %v", err)
	}
	other, _ := Hash("bafyreisomeoneelse")
	if _, err := Open("bafyreisomeoneelse", other, box); !errors.Is(err, ErrOpen) {
		t.Fatalf("another AID: %v", err)
	}
	// Two boxes of the same entry differ (fresh nonce): a hub cannot tell a re-sealed entry from a
	// changed one by comparing boxes, and neither can anyone watching.
	box2, err := Seal(e.AID, e, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(box, box2) {
		t.Fatal("two seals of one entry are the same bytes")
	}
	got, err := Open(e.AID, h, box2)
	if err != nil || !entriesEqual(got, e) {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
}

// Seal refuses what a directory must not carry: an entry missing a required key, an entry that
// names another AID, an unusable AID, and an entry whose box would exceed MaxBoxLen.
func TestSealRefuses(t *testing.T) {
	for name, c := range map[string]struct {
		aid  string
		edit func(*DirEntry)
		err  error
	}{
		"no aid":             {"x", func(e *DirEntry) { e.AID = "" }, ErrEntry},
		"no home":            {"", func(e *DirEntry) { e.Home = "" }, ErrEntry},
		"no kel":             {"", func(e *DirEntry) { e.KEL = nil }, ErrEntry},
		"no keys":            {"", func(e *DirEntry) { e.Keys = []byte{} }, ErrEntry},
		"another AID":        {"bafyreisomeoneelse", func(*DirEntry) {}, ErrEntry},
		"NUL in AID":         {"a\x00b", func(e *DirEntry) { e.AID = "a\x00b" }, ErrAID},
		"NUL in home":        {"", func(e *DirEntry) { e.Home = "h\x00" }, ErrEntry},
		"invalid UTF-8 home": {"", func(e *DirEntry) { e.Home = "h\xff" }, ErrEntry},
		"empty AID":          {"-", func(*DirEntry) {}, ErrAID},
		"too large": {"", func(e *DirEntry) {
			e.Card = make([]byte, MaxBoxLen)
		}, ErrTooLarge},
	} {
		e := sample()
		c.edit(e)
		aid := c.aid
		switch aid {
		case "":
			aid = e.AID
		case "-":
			aid = ""
		}
		if box, err := Seal(aid, e, nil); !errors.Is(err, c.err) {
			t.Errorf("%s: got %x, %v; want %v", name, box, err, c.err)
		}
	}
	if _, err := Seal(sample().AID, nil, nil); !errors.Is(err, ErrEntry) {
		t.Errorf("nil entry: %v", err)
	}
}

// The largest entry a directory carries seals and opens; one byte more does not seal, and a box
// larger than MaxBoxLen is refused before any work.
func TestMaxBoxLen(t *testing.T) {
	e := sample()
	e.Card = nil
	pt, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// A card of n bytes adds 1 (key) + its length header + n; find the n that lands on the limit.
	for n := MaxBoxLen - len(pt) - Overhead - 8; n < MaxBoxLen; n++ {
		e.Card = bytes.Repeat([]byte{'c'}, n)
		pt, _ := e.Marshal()
		if len(pt)+Overhead == MaxBoxLen {
			break
		}
	}
	box, err := Seal(e.AID, e, nil)
	if err != nil || len(box) != MaxBoxLen {
		t.Fatalf("an entry of exactly the limit: %d bytes, %v", len(box), err)
	}
	h, _ := Hash(e.AID)
	if _, err := Open(e.AID, h, box); err != nil {
		t.Fatalf("a box of exactly the limit does not open: %v", err)
	}
	e.Card = append(e.Card, 'c')
	if _, err := Seal(e.AID, e, nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("one byte over the limit: %v", err)
	}
	if _, err := Open(e.AID, h, append(box, 0)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a box one byte over the limit: %v", err)
	}
}

// CORE-S4: every key DirEntry does not assign (0, 7..63, 64, 65535) is refused by the decoder,
// with the value CBOR null so that a refusal can only come from the key itself.
func TestDirEntryRefusesUnassignedKeys(t *testing.T) {
	valid, err := sample().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalDirEntry(valid); err != nil {
		t.Fatalf("the valid encoding is refused: %v", err)
	}
	negs, err := wire.Negatives(wire.MustLoad(), "DirEntry", valid)
	if err != nil {
		t.Fatal(err)
	}
	if len(negs) < 60 {
		t.Fatalf("only %d negatives", len(negs))
	}
	for _, n := range negs {
		if e, err := UnmarshalDirEntry(n.Bytes); !errors.Is(err, ErrEntry) {
			t.Errorf("key %d (%s): got %+v, %v", n.Key, n.Why, e, err)
		}
	}
}

// The decoder takes the canonical encoding of a valid entry and nothing else.
func TestUnmarshalDirEntryRefuses(t *testing.T) {
	enc := func(v any) []byte {
		b, err := coredet.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	e := sample()
	base := map[uint64]any{1: e.AID, 2: e.Home, 3: e.KEL, 4: e.Keys}
	with := func(k uint64, v any) map[uint64]any {
		m := map[uint64]any{}
		for a, b := range base {
			m[a] = b
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, b := range map[string][]byte{
		"empty":                  nil,
		"an array":               enc([]any{e.AID}),
		"a text string":          enc("entry"),
		"missing aid":            enc(with(1, nil)),
		"missing home":           enc(with(2, nil)),
		"missing kel":            enc(with(3, nil)),
		"missing keys":           enc(with(4, nil)),
		"aid as bytes":           enc(with(1, []byte(e.AID))),
		"kel as text":            enc(with(3, "kel")),
		"card as text":           enc(with(5, "card")),
		"empty card":             enc(with(5, []byte{})),
		"empty home":             enc(with(2, "")),
		"text key":               enc(map[any]any{"1": e.AID, 2: e.Home, 3: e.KEL, 4: e.Keys}),
		"trailing byte":          append(enc(base), 0),
		"duplicate key":          append([]byte{0xa5}, append(enc(base)[1:], 0x01, 0x61, 'x')...),
		"non-shortest length":    append([]byte{0xb8, 0x04}, enc(base)[1:]...),
		"indefinite-length map":  append(append([]byte{0xbf}, enc(base)[1:]...), 0xff),
		"NUL in aid":             enc(with(1, "a\x00b")),
		"keys out of order":      reorder(t, enc(base)),
		"null optional":          enc(with(6, cborNull{})),
		"negative key":           enc(map[any]any{-1: "x", 1: e.AID, 2: e.Home, 3: e.KEL, 4: e.Keys}),
		"tagged value":           append(append([]byte{0xa4, 0x01, 0xd8, 0x20}, enc(e.AID)...), enc(base)[1+len(enc(uint64(1)))+len(enc(e.AID)):]...),
		"aid with invalid UTF-8": []byte{0xa4, 0x01, 0x61, 0xff, 0x02, 0x61, 'h', 0x03, 0x41, 'k', 0x04, 0x41, 'y'},
	} {
		if got, err := UnmarshalDirEntry(b); !errors.Is(err, ErrEntry) {
			t.Errorf("%s: got %+v, %v", name, got, err)
		}
	}
	if got, err := UnmarshalDirEntry(enc(base)); err != nil || got.Card != nil || got.Notice != nil {
		t.Fatalf("required keys only: %+v, %v", got, err)
	}
}

// cborNull marshals as CBOR null.
type cborNull struct{}

func (cborNull) MarshalCBOR() ([]byte, error) { return []byte{0xf6}, nil }

// reorder swaps the first two key/value pairs of a canonical map of text values under keys 1 and 2.
func reorder(t *testing.T, b []byte) []byte {
	t.Helper()
	var m map[uint64]any
	if err := coredet.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	k1, _ := coredet.Marshal(uint64(1))
	v1, _ := coredet.Marshal(m[1])
	k2, _ := coredet.Marshal(uint64(2))
	v2, _ := coredet.Marshal(m[2])
	first := len(k1) + len(v1) + len(k2) + len(v2)
	out := []byte{b[0]}
	out = append(out, k2...)
	out = append(out, v2...)
	out = append(out, k1...)
	out = append(out, v1...)
	return append(out, b[1+first:]...)
}

// CORE-E9 and the AID rules: Hash and Key refuse what could make two AIDs share an entry.
func TestHashRefusesUnusableAIDs(t *testing.T) {
	for name, aid := range map[string]string{
		"empty": "", "NUL": "\x00", "NUL inside": "a\x00b", "NUL at end": "ab\x00", "invalid UTF-8": "a\xffb",
	} {
		if _, err := Hash(aid); !errors.Is(err, ErrAID) {
			t.Errorf("Hash %s: %v", name, err)
		}
		if _, err := Key(aid); !errors.Is(err, ErrAID) {
			t.Errorf("Key %s: %v", name, err)
		}
		if _, err := Open(aid, make([]byte, 32), make([]byte, 64)); !errors.Is(err, ErrAID) {
			t.Errorf("Open %s: %v", name, err)
		}
	}
	h, err := Hash("ab")
	if err != nil || len(h) != HashLen {
		t.Fatalf("Hash(ab) = %x, %v", h, err)
	}
	// The label and the separator are in the hash: "a" under the label is not "" under a label
	// ending in "a", and not "a" without the separator.
	plain := sha256.Sum256([]byte(hashLabel + "ab"))
	if bytes.Equal(h, plain[:]) {
		t.Fatal("the 0x00 separator is missing from h")
	}
}

func TestPrefix(t *testing.T) {
	h := bytes.Repeat([]byte{0xff}, HashLen)
	for _, c := range []struct {
		bits int
		want string
	}{{0, ""}, {1, "80"}, {7, "fe"}, {8, "ff"}, {9, "ff80"}, {10, "ffc0"}, {16, "ffff"}, {HashBits, strings.Repeat("ff", 32)}} {
		p, err := Prefix(h, c.bits)
		if err != nil || hex.EncodeToString(p) != c.want {
			t.Errorf("Prefix(ff…, %d) = %x, %v; want %s", c.bits, p, err, c.want)
		}
		if err := CheckPrefix(p, c.bits); err != nil {
			t.Errorf("CheckPrefix(%x, %d): %v", p, c.bits, err)
		}
		if !InBucket(h, p, c.bits) {
			t.Errorf("h is not in its own bucket at %d bits", c.bits)
		}
	}
	for name, c := range map[string]struct {
		p    string
		bits int
	}{
		"trailing bit set":      {"ff", 7},
		"trailing bits set":     {"ffc1", 10},
		"one byte too many":     {"ff00", 8},
		"one byte too few":      {"ff", 9},
		"prefix for zero bits":  {"00", 0},
		"negative bits":         {"", -1},
		"more bits than a hash": {strings.Repeat("00", 33), HashBits + 1},
	} {
		p, _ := hex.DecodeString(c.p)
		if err := CheckPrefix(p, c.bits); !errors.Is(err, ErrPrefix) {
			t.Errorf("CheckPrefix %s: %v", name, err)
		}
		if InBucket(h, p, c.bits) {
			t.Errorf("InBucket with a malformed prefix (%s)", name)
		}
	}
	if InBucket(h, []byte{0x7f}, 8) || InBucket(h, []byte{0x00}, 1) {
		t.Fatal("h is in a bucket it does not match")
	}
	if _, err := Prefix(h[:31], 8); !errors.Is(err, ErrPrefix) {
		t.Fatal("Prefix of a short hash")
	}
}
