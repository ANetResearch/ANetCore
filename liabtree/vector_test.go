package liabtree

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
)

// LIAB-1 (core §5.2): golden/py/gen_v016.py writes testdata/vec-liab-1.json from its own
// implementation; every value here is recomputed with this package and must agree byte for byte.

type vecLeaf struct {
	AID      string `json:"aid"`
	ToDay    uint64 `json:"to_day"`
	Balance  uint64 `json:"balance"`
	Salt     string `json:"salt"`
	Content  string `json:"content"`
	Preimage string `json:"preimage"`
	Hash     string `json:"hash"`
}

type vecNeg struct {
	Name        string    `json:"name"`
	Note        string    `json:"note"`
	Proof       WireProof `json:"proof"`
	Root        string    `json:"root"`
	Outstanding *uint64   `json:"outstanding"`
	Depth       int       `json:"depth"`
	Error       string    `json:"error"`
}

type vecLiab1 struct {
	ID     string            `json:"id"`
	Labels map[string]string `json:"labels"`
	Leaf   vecLeaf           `json:"leaf"`
	Pad    vecLeaf           `json:"padding_leaf"`
	Node   struct {
		Left     WireStep `json:"left"`
		Right    WireStep `json:"right"`
		Preimage string   `json:"preimage"`
		Hash     string   `json:"hash"`
		Sum      uint64   `json:"sum"`
	} `json:"node"`
	Build struct {
		RandLabel string `json:"rand_label"`
		ToDay     uint64 `json:"to_day"`
		Accounts  []struct {
			AID     string `json:"aid"`
			Balance uint64 `json:"balance"`
		} `json:"accounts"`
		Leaves  int `json:"leaves"`
		Depth   int `json:"depth"`
		Entries []struct {
			AID     string `json:"aid"`
			Balance uint64 `json:"balance"`
			Salt    string `json:"salt"`
			Hash    string `json:"hash"`
		} `json:"entries"`
		Root        string `json:"root"`
		Outstanding uint64 `json:"outstanding"`
	} `json:"build"`
	Proof      json.RawMessage `json:"proof"`
	Negatives  []vecNeg        `json:"negatives"`
	MovedSplit struct {
		Note   string      `json:"note"`
		Hidden uint64      `json:"hidden"`
		Proofs []WireProof `json:"proofs"`
		Roots  []string    `json:"roots"`
		Sum    uint64      `json:"sum"`
		Depth  int         `json:"depth"`
	} `json:"moved_split"`
}

func loadLiab1(t *testing.T) *vecLiab1 {
	t.Helper()
	b, err := os.ReadFile("testdata/vec-liab-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vecLiab1
	d := json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.ID != "LIAB-1" {
		t.Fatalf("id %q", v.ID)
	}
	return &v
}

// stream is the golden random source: SHA-256(label || u64be(i)) for i = 0, 1, …, concatenated.
type stream struct {
	label []byte
	i     uint64
	buf   []byte
}

func newStream(label string) *stream { return &stream{label: []byte(label)} }

func (s *stream) Read(p []byte) (int, error) {
	for len(s.buf) < len(p) {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], s.i)
		blk := sha256.Sum256(append(append([]byte(nil), s.label...), c[:]...))
		s.buf = append(s.buf, blk[:]...)
		s.i++
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	h, err := ParseHex(s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return h
}

func checkLeaf(t *testing.T, l vecLeaf) {
	t.Helper()
	content, err := coredet.Marshal(leafContent{AID: l.AID, ToDay: l.ToDay, Balance: l.Balance})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(content); got != l.Content {
		t.Errorf("content\n got  %s\n want %s", got, l.Content)
	}
	salt := mustHex32(t, l.Salt)
	pre := append(append(append([]byte(leafLabel), 0), salt[:]...), content...)
	if got := hex.EncodeToString(pre); got != l.Preimage {
		t.Errorf("preimage\n got  %s\n want %s", got, l.Preimage)
	}
	h, err := LeafHash(l.AID, l.ToDay, l.Balance, salt)
	if err != nil {
		t.Fatal(err)
	}
	if Hex(h) != l.Hash {
		t.Errorf("leaf hash\n got  %s\n want %s", Hex(h), l.Hash)
	}
}

func TestLIAB1(t *testing.T) {
	v := loadLiab1(t)
	if v.Labels["leaf"] != leafLabel || v.Labels["node"] != nodeLabel {
		t.Fatalf("labels %v", v.Labels)
	}

	t.Run("leaf", func(t *testing.T) { checkLeaf(t, v.Leaf) })
	t.Run("padding leaf", func(t *testing.T) { checkLeaf(t, v.Pad) })

	t.Run("node", func(t *testing.T) {
		l := Node{Hash: mustHex32(t, v.Node.Left.H), Sum: v.Node.Left.Sum}
		r := Node{Hash: mustHex32(t, v.Node.Right.H), Sum: v.Node.Right.Sum}
		var pre []byte
		pre = append(append(pre, nodeLabel...), 0)
		pre = append(pre, l.Hash[:]...)
		pre = binary.BigEndian.AppendUint64(pre, l.Sum)
		pre = append(pre, r.Hash[:]...)
		pre = binary.BigEndian.AppendUint64(pre, r.Sum)
		if got := hex.EncodeToString(pre); got != v.Node.Preimage {
			t.Errorf("preimage\n got  %s\n want %s", got, v.Node.Preimage)
		}
		if got := Hex(NodeHash(l, r)); got != v.Node.Hash {
			t.Errorf("node hash\n got  %s\n want %s", got, v.Node.Hash)
		}
		if sum, ok := addSum(l.Sum, r.Sum); !ok || sum != v.Node.Sum {
			t.Errorf("sum %d %v, want %d", sum, ok, v.Node.Sum)
		}
	})

	b := v.Build
	leaves := make([]Leaf, len(b.Accounts))
	for i, a := range b.Accounts {
		leaves[i] = Leaf{AID: a.AID, Balance: a.Balance}
	}
	tree, err := Build(leaves, b.ToDay, newStream(b.RandLabel))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("build", func(t *testing.T) {
		es := tree.Entries()
		if len(es) != b.Leaves || tree.Depth() != b.Depth {
			t.Fatalf("%d leaves, depth %d; want %d, %d", len(es), tree.Depth(), b.Leaves, b.Depth)
		}
		for i, want := range b.Entries {
			e := es[i]
			if e.AID != want.AID || e.Balance != want.Balance || Hex(e.Salt) != want.Salt {
				t.Errorf("entry %d: %q %d %s; want %q %d %s", i, e.AID, e.Balance, Hex(e.Salt), want.AID, want.Balance, want.Salt)
			}
			if got := Hex(tree.levels[0][i].Hash); got != want.Hash {
				t.Errorf("entry %d hash %s, want %s", i, got, want.Hash)
			}
		}
		if Hex(tree.Root()) != b.Root || tree.Outstanding() != b.Outstanding || tree.ToDay() != b.ToDay {
			t.Errorf("root %s outstanding %d day %d; want %s %d %d", Hex(tree.Root()), tree.Outstanding(), tree.ToDay(), b.Root, b.Outstanding, b.ToDay)
		}
		// A hub stores the entries and rebuilds the same tree.
		again, err := Rebuild(b.ToDay, es)
		if err != nil {
			t.Fatal(err)
		}
		if again.Root() != tree.Root() || again.Outstanding() != tree.Outstanding() {
			t.Error("Rebuild of the entries gives another root")
		}
	})

	// The third account's proof, in its response form.
	var want WireProof
	d := json.NewDecoder(bytes.NewReader(v.Proof))
	d.DisallowUnknownFields()
	if err := d.Decode(&want); err != nil {
		t.Fatal(err)
	}
	t.Run("proof", func(t *testing.T) {
		if want.AID != b.Accounts[2].AID {
			t.Fatalf("the vector's proof is for %q, not the third account", want.AID)
		}
		p, ok := tree.Proof(want.AID)
		if !ok {
			t.Fatal("no proof for the third account")
		}
		if got := p.Wire(); !reflect.DeepEqual(got, want) {
			t.Errorf("proof\n got  %+v\n want %+v", got, want)
		}
		// The JSON a hub writes has exactly the vector's members and values.
		js, err := json.Marshal(p.Wire())
		if err != nil {
			t.Fatal(err)
		}
		var a, c any
		if json.Unmarshal(js, &a) != nil || json.Unmarshal(v.Proof, &c) != nil || !reflect.DeepEqual(a, c) {
			t.Errorf("response JSON\n got  %s\n want %s", js, v.Proof)
		}
		parsed, err := want.Parse()
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(parsed, mustHex32(t, b.Root), b.Outstanding, b.Depth); err != nil {
			t.Errorf("the vector's proof does not verify: %v", err)
		}
	})

	// The refused proofs. Those on the built tree are checked against the root and sum this
	// package folds from the valid proof, not the vector's bytes: a moved-sum path then passes
	// exactly when the node hash covers no sums (M-PAY-1; moved split below covers a hash over
	// the parent's total alone). The overflow trees carry
	// their own root (they cannot be built), so they pass exactly when the sum check is gone
	// (M-PAY-2).
	valid, err := want.Parse()
	if err != nil {
		t.Fatal(err)
	}
	top, err := fold(valid)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Negatives) < 12 {
		t.Fatalf("%d negatives", len(v.Negatives))
	}
	for _, n := range v.Negatives {
		t.Run("refuse "+n.Name, func(t *testing.T) {
			root, outstanding, depth := top.Hash, top.Sum, b.Depth
			if n.Root != "" {
				root = mustHex32(t, n.Root)
			}
			if n.Outstanding != nil {
				outstanding = *n.Outstanding
			}
			if n.Depth != 0 {
				depth = n.Depth
			}
			p, err := n.Proof.Parse()
			if err != nil {
				t.Fatalf("%s: the proof does not parse: %v", n.Note, err)
			}
			err = Verify(p, root, outstanding, depth)
			wantErr := map[string]error{"root": ErrRoot, "sum": ErrSum, "overflow": ErrOverflow, "malformed": ErrMalformed}[n.Error]
			if wantErr == nil {
				t.Fatalf("unknown error class %q", n.Error)
			}
			if !errors.Is(err, wantErr) {
				t.Errorf("%s: Verify = %v, want %v", n.Note, err, wantErr)
			}
		})
	}

	// Moved split (the "moved sum" of PAY-K1 across two views): two sibling accounts, each shown a
	// different split of one parent sum. Each path is checked against the root the other one folds
	// to with this package, so the case turns red whenever the node hash stops covering both child
	// sums, whether it covers no sum (M-PAY-1) or only the parent's total.
	t.Run("refuse moved split", func(t *testing.T) {
		s := v.MovedSplit
		if len(s.Proofs) != 2 || len(s.Roots) != 2 || s.Hidden == 0 {
			t.Fatalf("moved_split: %d proofs, %d roots, hidden %d", len(s.Proofs), len(s.Roots), s.Hidden)
		}
		var ps [2]Proof
		var tops [2]Node
		for i := range ps {
			p, err := s.Proofs[i].Parse()
			if err != nil {
				t.Fatal(err)
			}
			top, err := fold(p)
			if err != nil {
				t.Fatal(err)
			}
			if Hex(top.Hash) != s.Roots[i] || top.Sum != s.Sum {
				t.Errorf("proof %d folds to %s sum %d; want %s sum %d", i, Hex(top.Hash), top.Sum, s.Roots[i], s.Sum)
			}
			ps[i], tops[i] = p, top
		}
		// The vector really is a moved split: siblings with the same steps above their parent, the
		// same parent total, and each shown the other's balance minus Hidden.
		a, b := ps[0], ps[1]
		if !reflect.DeepEqual(a.Path[1:], b.Path[1:]) || a.Path[0].Side == b.Path[0].Side ||
			a.Path[0].Sum+s.Hidden != b.Balance || b.Path[0].Sum+s.Hidden != a.Balance {
			t.Fatalf("moved_split is not two siblings shown different splits of one parent sum")
		}
		for i := range ps {
			o := tops[1-i]
			if err := Verify(ps[i], o.Hash, o.Sum, s.Depth); !errors.Is(err, ErrRoot) {
				t.Errorf("%s: proof %d against the other's root: Verify = %v, want %v", s.Note, i, err, ErrRoot)
			}
		}
	})
}
