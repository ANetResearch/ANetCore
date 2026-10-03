package liabtree

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestBuildRefuses(t *testing.T) {
	cases := []struct {
		name   string
		leaves []Leaf
		want   string
	}{
		{"empty AID", []Leaf{{AID: "a"}, {AID: ""}}, "empty AID"},
		{"duplicate", []Leaf{{AID: "a", Balance: 1}, {AID: "b"}, {AID: "a", Balance: 2}}, "appears twice"},
		{"invalid UTF-8", []Leaf{{AID: "a\xff"}}, "leaf content"},
	}
	for _, c := range cases {
		if _, err := Build(c.leaves, 1, rand.Reader); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error saying %q", c.name, err, c.want)
		}
	}
	// a nil source means crypto/rand
	if tree, err := Build([]Leaf{{AID: "a", Balance: 1}}, 1, nil); err != nil || tree.Outstanding() != 1 {
		t.Errorf("nil rand: %v", err)
	}
	// rand runs dry: Build reports it and returns no tree
	if _, err := Build([]Leaf{{AID: "a"}}, 1, bytes.NewReader(make([]byte, 40))); !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Errorf("short rand: %v", err)
	}
}

func TestBuildShape(t *testing.T) {
	for _, c := range []struct{ accounts, leaves, depth int }{
		{0, 16, 4}, {1, 16, 4}, {16, 16, 4}, {17, 32, 5}, {64, 64, 6}, {65, 128, 7},
	} {
		leaves := make([]Leaf, c.accounts)
		for i := range leaves {
			leaves[i] = Leaf{AID: string(rune('A'+i%26)) + strings.Repeat("x", i/26), Balance: uint64(i)}
		}
		tree, err := Build(leaves, 7, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		es := tree.Entries()
		if len(es) != c.leaves || tree.Depth() != c.depth {
			t.Errorf("%d accounts: %d leaves, depth %d; want %d, %d", c.accounts, len(es), tree.Depth(), c.leaves, c.depth)
		}
		pad := 0
		salts := map[[SaltSize]byte]bool{}
		for _, e := range es {
			if e.Padding() {
				pad++
				if e.Balance != 0 {
					t.Errorf("padding with balance %d", e.Balance)
				}
			}
			salts[e.Salt] = true
		}
		if pad != c.leaves-c.accounts {
			t.Errorf("%d accounts: %d padding leaves", c.accounts, pad)
		}
		if len(salts) != c.leaves {
			t.Errorf("%d accounts: salts repeat", c.accounts)
		}
		if _, ok := tree.Proof(""); ok {
			t.Error("a proof for the empty AID (padding)")
		}
		if _, ok := tree.Proof("nobody"); ok {
			t.Error("a proof for an account not in the tree")
		}
	}
}

// TestShuffleMovesLeaves: the leaf order does not follow the input order (with a fixed source the
// result is fixed, so this is one fixed check, not a statistical one), and Entries is a copy.
func TestShuffleMovesLeaves(t *testing.T) {
	leaves := make([]Leaf, 16)
	for i := range leaves {
		leaves[i] = Leaf{AID: string(rune('a' + i)), Balance: uint64(i)}
	}
	tree, err := Build(leaves, 1, newStream("shuffle"))
	if err != nil {
		t.Fatal(err)
	}
	es := tree.Entries()
	same := 0
	for i := range es {
		if es[i].AID == leaves[i].AID {
			same++
		}
	}
	if same == len(es) {
		t.Error("the leaves were not shuffled")
	}
	es[0].Balance = 999
	if tree.Entries()[0].Balance == 999 {
		t.Error("Entries hands out the tree's own slice")
	}
}

func TestUniform(t *testing.T) {
	// m = 3: 2^64 mod 3 = 1, so the largest u64 is rejected and the next draw is used.
	src := bytes.NewReader([]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // rejected
		0, 0, 0, 0, 0, 0, 0, 5, // 5 mod 3 = 2
	})
	if j, err := uniform(src, 3); err != nil || j != 2 {
		t.Fatalf("uniform(3) = %d, %v", j, err)
	}
	// m = 2^k never rejects
	src = bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if j, err := uniform(src, 16); err != nil || j != 15 {
		t.Fatalf("uniform(16) = %d, %v", j, err)
	}
	if j, err := uniform(bytes.NewReader(make([]byte, 8)), 1); err != nil || j != 0 {
		t.Fatalf("uniform(1) = %d, %v", j, err)
	}
}

func TestRebuildRefuses(t *testing.T) {
	tree, err := Build([]Leaf{{AID: "a", Balance: 3}, {AID: "b", Balance: 4}}, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := tree.Entries()
	if _, err := Rebuild(2, good); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		edit func([]Entry) []Entry
	}{
		{"15 leaves", func(e []Entry) []Entry { return e[:15] }},
		{"8 leaves", func(e []Entry) []Entry { return e[:8] }},
		{"24 leaves", func(e []Entry) []Entry { return append(e, e[:8]...) }},
		{"padding with a balance", func(e []Entry) []Entry {
			for i := range e {
				if e[i].Padding() {
					e[i].Balance = 1
					break
				}
			}
			return e
		}},
		{"an account twice", func(e []Entry) []Entry {
			var acct Entry
			for _, x := range e {
				if !x.Padding() {
					acct = x
				}
			}
			for i := range e {
				if e[i].Padding() {
					e[i] = acct
					break
				}
			}
			return e
		}},
		{"a balance of 2^63", func(e []Entry) []Entry {
			for i := range e {
				if !e[i].Padding() {
					e[i].Balance = MaxSum + 1
					break
				}
			}
			return e
		}},
	} {
		if _, err := Rebuild(2, c.edit(tree.Entries())); err == nil {
			t.Errorf("%s: Rebuild accepted", c.name)
		}
	}
}

func TestVerifyRefusesShape(t *testing.T) {
	tree, err := Build([]Leaf{{AID: "a", Balance: 3}}, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := tree.Proof("a")
	if err := Verify(p, tree.Root(), 3, 3); !errors.Is(err, ErrMalformed) {
		t.Errorf("depth 3: %v", err)
	}
	if err := Verify(p, tree.Root(), 3, 33); !errors.Is(err, ErrMalformed) {
		t.Errorf("depth 33: %v", err)
	}
	if err := Verify(p, tree.Root(), MaxSum+1, 4); !errors.Is(err, ErrOverflow) {
		t.Errorf("outstanding 2^63: %v", err)
	}
	q := p
	q.Path = append([]Step(nil), p.Path...)
	q.Path[2].Side = 'X'
	if err := Verify(q, tree.Root(), 3, 4); !errors.Is(err, ErrMalformed) {
		t.Errorf("side X: %v", err)
	}
	q = p
	q.AID = "a\xff"
	if err := Verify(q, tree.Root(), 3, 4); !errors.Is(err, ErrMalformed) {
		t.Errorf("invalid UTF-8 AID: %v", err)
	}
}

func TestWireRoundTrip(t *testing.T) {
	tree, err := Build([]Leaf{{AID: "a", Balance: 3}, {AID: "b", Balance: 1 << 62}}, 9, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := tree.Proof("b")
	w := p.Wire()
	back, err := w.Parse()
	if err != nil {
		t.Fatal(err)
	}
	if !equalProof(back, p) {
		t.Fatal("Parse(Wire(p)) != p")
	}
	if err := Verify(back, tree.Root(), tree.Outstanding(), tree.Depth()); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		edit func(*WireProof)
	}{
		{"upper-case salt", func(w *WireProof) { w.Salt = strings.ToUpper(w.Salt) }},
		{"short salt", func(w *WireProof) { w.Salt = w.Salt[:62] }},
		{"salt with a space", func(w *WireProof) { w.Salt = " " + w.Salt[1:] }},
		{"upper-case h", func(w *WireProof) { w.Path[0].H = strings.ToUpper(w.Path[0].H) }},
		{"h with 0x", func(w *WireProof) { w.Path[1].H = "0x" + w.Path[1].H[2:] }},
		{"side l", func(w *WireProof) { w.Path[0].Side = "l" }},
		{"side empty", func(w *WireProof) { w.Path[0].Side = "" }},
		{"side LR", func(w *WireProof) { w.Path[0].Side = "LR" }},
		{"33 steps", func(w *WireProof) {
			for len(w.Path) <= MaxDepth {
				w.Path = append(w.Path, w.Path[0])
			}
		}},
	} {
		w := p.Wire()
		c.edit(&w)
		if _, err := w.Parse(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// the one spelling
	var b [32]byte
	for i := range b {
		b[i] = byte(i * 17)
	}
	if h, err := ParseHex(Hex(b)); err != nil || h != b {
		t.Fatalf("hex round trip: %v", err)
	}
}
