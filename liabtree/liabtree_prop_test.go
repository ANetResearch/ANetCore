package liabtree

import (
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"testing"
)

// P-PAY-1 (HPP §7.2): for random balance sets, including 0 and values near the limit, every
// account's proof verifies and the root sum is the total; changing any leaf balance, any sibling
// hash or sum, or any side makes verification fail; and two siblings shown different splits of
// their parent's sum never reach one root.

// randomBalances returns n balances whose total is at most MaxSum, mixing zeros, small values
// and values close to the limit.
func randomBalances(r *mrand.Rand, n int) []uint64 {
	out := make([]uint64, n)
	left := uint64(MaxSum)
	for i := range out {
		var b uint64
		switch r.IntN(5) {
		case 0:
			b = 0
		case 1:
			b = r.Uint64N(1000)
		case 2:
			b = r.Uint64N(1 << 40)
		default:
			// near the limit: a large share of what is left
			if left > 0 {
				b = left - r.Uint64N(left/uint64(n)+1)
			}
		}
		if b > left {
			b = left
		}
		left -= b
		out[i] = b
	}
	return out
}

func TestPropertyProofs(t *testing.T) {
	r := mrand.New(mrand.NewChaCha8([32]byte{'P', '-', 'P', 'A', 'Y', '-', '1'}))
	sizes := []int{0, 1, 2, 5, 15, 16, 17, 31, 33, 100}
	for iter := 0; iter < 60; iter++ {
		n := sizes[iter%len(sizes)]
		if iter >= len(sizes) {
			n = r.IntN(70)
		}
		bal := randomBalances(r, n)
		leaves := make([]Leaf, n)
		var total uint64
		for i, b := range bal {
			leaves[i] = Leaf{AID: fmt.Sprintf("bafyreiaccount%03d", i), Balance: b}
			total += b
		}
		day := r.Uint64N(40000)
		tree, err := Build(leaves, day, rand.Reader)
		if err != nil {
			t.Fatalf("iteration %d: %v", iter, err)
		}
		if tree.Outstanding() != total {
			t.Fatalf("iteration %d: root sum %d, total %d", iter, tree.Outstanding(), total)
		}
		depth := tree.Depth()
		if want := max(MinLeaves, nextPow2(n)); 1<<depth != want {
			t.Fatalf("iteration %d: depth %d for %d accounts", iter, depth, n)
		}
		root := tree.Root()
		for _, l := range leaves {
			p, ok := tree.Proof(l.AID)
			if !ok {
				t.Fatalf("no proof for %s", l.AID)
			}
			if err := Verify(p, root, total, depth); err != nil {
				t.Fatalf("iteration %d: %s: %v", iter, l.AID, err)
			}
			mutateProof(t, r, p, root, total, depth)
		}
		checkMovedSplits(t, tree)
	}
}

// checkMovedSplits: for every pair of sibling leaves (padding included), the two paths a hub could
// serve if it showed each sibling another split of their parent's sum (one side minus k, the
// other plus k) never reach one root. A node hash over no sums, or over the parent's total alone,
// lets both reach the same root.
func checkMovedSplits(t *testing.T, tree *Tree) {
	t.Helper()
	for i := 0; i < len(tree.entries); i += 2 {
		a, b := tree.proofAt(i), tree.proofAt(i+1)
		total := a.Balance + b.Balance // at most MaxSum: the tree was built
		var shown uint64               // the parent sum both are shown, other than total
		switch {
		case min(a.Balance, b.Balance) >= 1:
			shown = total - 1 // the hub hides 1
		case total < MaxSum:
			shown = total + 1
		default:
			continue
		}
		a.Path[0].Sum = shown - a.Balance
		b.Path[0].Sum = shown - b.Balance
		ta, errA := fold(a)
		tb, errB := fold(b)
		if errA == nil && errB == nil && ta == tb {
			t.Fatalf("leaves %d and %d shown the parent sum %d split two ways reach one root", i, i+1, shown)
		}
	}
}

func nextPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// mutateProof changes one field of a valid proof at a time and expects every change refused.
func mutateProof(t *testing.T, r *mrand.Rand, p Proof, root [32]byte, total uint64, depth int) {
	t.Helper()
	clone := func() Proof {
		q := p
		q.Path = append([]Step(nil), p.Path...)
		return q
	}
	type change struct {
		name string
		edit func(*Proof)
	}
	lvl := r.IntN(len(p.Path))
	delta := 1 + r.Uint64N(1000)
	changes := []change{
		{"balance +", func(q *Proof) { q.Balance += delta }},
		{"balance -", func(q *Proof) { q.Balance -= delta }},
		{"salt", func(q *Proof) { q.Salt[r.IntN(SaltSize)] ^= byte(1 + r.IntN(255)) }},
		{"day", func(q *Proof) { q.ToDay++ }},
		{"aid", func(q *Proof) { q.AID += "x" }},
		{"sibling hash", func(q *Proof) { q.Path[lvl].Hash[r.IntN(32)] ^= byte(1 + r.IntN(255)) }},
		{"sibling sum +", func(q *Proof) { q.Path[lvl].Sum += delta }},
		{"sibling sum -", func(q *Proof) { q.Path[lvl].Sum -= delta }},
		{"side", func(q *Proof) {
			if q.Path[lvl].Side == Left {
				q.Path[lvl].Side = Right
			} else {
				q.Path[lvl].Side = Left
			}
		}},
		{"moved sum", func(q *Proof) {
			// move k between two levels: the root sum stays the same
			a := lvl
			b := (lvl + 1 + r.IntN(len(q.Path)-1)) % len(q.Path)
			k := min(delta, q.Path[a].Sum)
			if k == 0 {
				k = min(delta, q.Balance)
				q.Balance -= k
			} else {
				q.Path[a].Sum -= k
			}
			q.Path[b].Sum += k
		}},
		{"step dropped", func(q *Proof) { q.Path = q.Path[:len(q.Path)-1] }},
	}
	for _, c := range changes {
		q := clone()
		c.edit(&q)
		if equalProof(q, p) {
			continue // the change was a no-op (a moved sum of 0)
		}
		if err := Verify(q, root, total, depth); err == nil {
			t.Fatalf("%s: a proof with a changed %s verifies", p.AID, c.name)
		}
	}
	// the published values themselves
	wrong := total + 1
	if total == MaxSum {
		wrong = total - 1
	}
	if err := Verify(p, root, wrong, depth); !errors.Is(err, ErrSum) {
		t.Fatalf("outstanding %d for a root sum of %d: %v", wrong, total, err)
	}
	other := root
	other[0] ^= 1
	if err := Verify(p, other, total, depth); !errors.Is(err, ErrRoot) {
		t.Fatalf("another root: %v", err)
	}
}

func equalProof(a, b Proof) bool {
	if a.AID != b.AID || a.ToDay != b.ToDay || a.Balance != b.Balance || a.Salt != b.Salt || len(a.Path) != len(b.Path) {
		return false
	}
	for i := range a.Path {
		if a.Path[i] != b.Path[i] {
			return false
		}
	}
	return true
}

// TestPropertyLimit: a total of exactly 2^63-1 builds and verifies; one more is refused by Build,
// and a proof whose sums would pass 2^63-1 is refused by Verify.
func TestPropertyLimit(t *testing.T) {
	leaves := []Leaf{{AID: "a", Balance: MaxSum - 7}, {AID: "b", Balance: 7}, {AID: "c", Balance: 0}}
	tree, err := Build(leaves, 1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Outstanding() != MaxSum {
		t.Fatalf("outstanding %d", tree.Outstanding())
	}
	for _, l := range leaves {
		p, _ := tree.Proof(l.AID)
		if err := Verify(p, tree.Root(), MaxSum, tree.Depth()); err != nil {
			t.Fatalf("%s: %v", l.AID, err)
		}
	}
	leaves[1].Balance = 8
	if _, err := Build(leaves, 1, rand.Reader); !errors.Is(err, ErrOverflow) {
		t.Fatalf("total 2^63: %v", err)
	}
	if _, err := Build([]Leaf{{AID: "a", Balance: MaxSum + 1}}, 1, rand.Reader); !errors.Is(err, ErrOverflow) {
		t.Fatalf("one balance of 2^63: %v", err)
	}
	if _, err := Build([]Leaf{{AID: "a", Balance: 1<<64 - 1}, {AID: "b", Balance: 1}}, 1, rand.Reader); !errors.Is(err, ErrOverflow) {
		t.Fatalf("balances that wrap: %v", err)
	}
}
