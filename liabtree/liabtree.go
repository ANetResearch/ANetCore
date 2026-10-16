// Package liabtree is the liability tree a hub publishes once per supply epoch: a Merkle sum tree
// over every account's balance at the close. The epoch record carries only the root hash, the
// root sum (outstanding) and the depth; an account fetches a path from its own leaf to the root
// and checks that its balance is counted.
//
// Each parent hash covers both child sums, not only their total, so a hub cannot move value from
// one subtree to another ("moved sums"): it cannot show two sibling accounts different splits of
// one parent sum and give both a path to the same root. Every sum is at most 2^63-1, so a hub
// cannot wrap a sum around to make liabilities vanish.
//
// The hashes (wire registry labels L25 and L26):
//
//	leaf = SHA-256("anet-liab-leaf/v1" || 0x00 || salt(32) || coredet(LiabLeafContent))
//	node = SHA-256("anet-liab-node/v1" || 0x00 || L.h || u64be(L.sum) || R.h || u64be(R.sum))
//
// LiabLeafContent is {1: aid, 2: to_day, 3: balance}. A padding leaf has aid "" and balance 0 and,
// like every leaf, a fresh random salt. Leaves are shuffled with the caller's random source before
// the tree is built, so a leaf's position says nothing about the account.
//
// The package uses only SHA-256 and CoreDet and does no I/O.
package liabtree

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/ANetResearch/ANetCore/coredet"
)

const (
	// MinLeaves is the smallest tree: a hub with fewer accounts pads to 16 leaves.
	MinLeaves = 16
	// MinDepth and MaxDepth bound the number of levels above the leaves (16 to 2^32 leaves).
	MinDepth = 4
	MaxDepth = 32
	// MaxSum is the largest balance, node sum and outstanding a tree may hold (2^63-1).
	MaxSum = math.MaxInt64
	// SaltSize is the length of a leaf salt.
	SaltSize = 32
)

const (
	leafLabel = "anet-liab-leaf/v1" // L25
	nodeLabel = "anet-liab-node/v1" // L26
)

// The errors Verify returns, wrapped with detail. A daemon tells them apart with errors.Is:
// ErrRoot is a path that does not reach the signed root (audit finding proof_invalid); ErrSum is a
// root whose sum is not the published outstanding (root_sum_mismatch).
var (
	ErrMalformed = errors.New("liabtree: the proof is malformed")
	ErrOverflow  = errors.New("liabtree: a balance or sum is over 2^63-1")
	ErrRoot      = errors.New("liabtree: the path does not reach the published root")
	ErrSum       = errors.New("liabtree: the root's sum is not the published outstanding")
)

// leafContent is the CBOR content of a leaf. It is only ever encoded and hashed, never decoded.
//
//anet:wire LiabLeafContent
type leafContent struct {
	AID     string `cbor:"1,keyasint"`
	ToDay   uint64 `cbor:"2,keyasint"`
	Balance uint64 `cbor:"3,keyasint"`
}

// Leaf is one account and its balance at the close.
type Leaf struct {
	AID     string
	Balance uint64
}

// Entry is a leaf at its place in a tree: an account, or padding (AID "" and Balance 0).
type Entry struct {
	AID     string
	Balance uint64
	Salt    [SaltSize]byte
}

// Padding reports whether e is a padding leaf.
func (e Entry) Padding() bool { return e.AID == "" }

// Node is a tree node: its hash and the sum of the balances under it.
type Node struct {
	Hash [32]byte
	Sum  uint64
}

// Side says on which side of the path a sibling lies.
type Side byte

const (
	// Left: the sibling is the left child, the path continues from the right child.
	Left Side = 'L'
	// Right: the sibling is the right child, the path continues from the left child.
	Right Side = 'R'
)

// Step is one level of a path: the sibling's hash and sum, and the side the sibling is on.
type Step struct {
	Hash [32]byte
	Sum  uint64
	Side Side
}

// Proof shows that an account's balance is a leaf of a tree: the leaf's fields and the path from
// the leaf to the root (Path[0] is the leaf's sibling, len(Path) is the tree's depth).
type Proof struct {
	AID     string
	ToDay   uint64
	Balance uint64
	Salt    [SaltSize]byte
	Path    []Step
}

// Tree is a built liability tree. It is immutable and safe for concurrent reads.
type Tree struct {
	toDay   uint64
	entries []Entry
	levels  [][]Node // levels[0] are the leaves, levels[depth] is the root
	pos     map[string]int
}

// LeafHash is the L25 hash of a leaf. It fails only when aid is not valid UTF-8.
func LeafHash(aid string, toDay, balance uint64, salt [SaltSize]byte) ([32]byte, error) {
	content, err := coredet.Marshal(leafContent{AID: aid, ToDay: toDay, Balance: balance})
	if err != nil {
		return [32]byte{}, fmt.Errorf("liabtree: leaf content: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(leafLabel))
	h.Write([]byte{0})
	h.Write(salt[:])
	h.Write(content)
	var out [32]byte
	h.Sum(out[:0])
	return out, nil
}

// NodeHash is the L26 hash of a parent over its two children. It covers both child sums.
func NodeHash(l, r Node) [32]byte {
	var b [len(nodeLabel) + 1 + 2*(32+8)]byte
	n := copy(b[:], nodeLabel)
	n++ // 0x00
	n += copy(b[n:], l.Hash[:])
	binary.BigEndian.PutUint64(b[n:], l.Sum)
	n += 8
	n += copy(b[n:], r.Hash[:])
	binary.BigEndian.PutUint64(b[n:], r.Sum)
	return sha256.Sum256(b[:])
}

// addSum is the one overflow check of the package: a+b when a, b and the total are all at most
// MaxSum. (With a, b <= 2^63-1 the uint64 total cannot wrap.)
func addSum(a, b uint64) (uint64, bool) {
	if a > MaxSum || b > MaxSum || a+b > MaxSum {
		return 0, false
	}
	return a + b, true
}

// Build makes the tree of the given accounts for the epoch ending on UTC day toDay. It pads to
// max(16, the smallest power of two not below the number of accounts) leaves, shuffles all leaves
// and draws every salt from rand. A nil rand means crypto/rand; tests pass a fixed source.
//
// Build fails when an account has the empty AID (it marks padding) or appears twice, when there
// are more than 2^32 accounts, when a balance or any node sum is over 2^63-1, or when rand fails.
//
// rand is consumed in a fixed order, which the LIAB-1 golden vector pins: first a Fisher-Yates
// shuffle of the leaves (accounts in the given order, then the padding) for i = n-1 down to 1,
// swapping i with j = uniform(i+1); then one 32-byte salt per position, from position 0 up.
// uniform(m) reads 8 bytes as a big-endian x and returns x mod m, reading again while
// x >= 2^64 - (2^64 mod m).
func Build(leaves []Leaf, toDay uint64, rand io.Reader) (*Tree, error) {
	if rand == nil {
		rand = crand.Reader
	}
	if uint64(len(leaves)) > 1<<MaxDepth {
		return nil, fmt.Errorf("liabtree: %d accounts is more than a tree of depth %d holds", len(leaves), MaxDepth)
	}
	size := MinLeaves
	for size < len(leaves) {
		size <<= 1
	}
	entries := make([]Entry, size)
	seen := make(map[string]bool, len(leaves))
	for i, l := range leaves {
		if l.AID == "" {
			return nil, errors.New("liabtree: an account has the empty AID, which marks a padding leaf")
		}
		if seen[l.AID] {
			return nil, fmt.Errorf("liabtree: account %q appears twice", l.AID)
		}
		seen[l.AID] = true
		entries[i] = Entry{AID: l.AID, Balance: l.Balance}
	}
	for i := size - 1; i > 0; i-- {
		j, err := uniform(rand, uint64(i)+1)
		if err != nil {
			return nil, err
		}
		entries[i], entries[j] = entries[j], entries[i]
	}
	for i := range entries {
		if _, err := io.ReadFull(rand, entries[i].Salt[:]); err != nil {
			return nil, fmt.Errorf("liabtree: reading a salt: %w", err)
		}
	}
	return build(toDay, entries)
}

// uniform returns a uniformly distributed integer in [0, m), m >= 1, read from rand.
func uniform(rand io.Reader, m uint64) (uint64, error) {
	limit := math.MaxUint64 - (math.MaxUint64%m+1)%m // 2^64 - (2^64 mod m) - 1
	var b [8]byte
	for {
		if _, err := io.ReadFull(rand, b[:]); err != nil {
			return 0, fmt.Errorf("liabtree: reading for the shuffle: %w", err)
		}
		if x := binary.BigEndian.Uint64(b[:]); x <= limit {
			return x % m, nil
		}
	}
}

// Rebuild makes the tree whose leaves are exactly entries, in that order: the leaves a hub stored
// at the close (Entries of the tree it built), padding included. It does not shuffle or pad.
//
// Rebuild fails when the number of entries is not a power of two from 16 to 2^32, when a padding
// entry has a balance, when an account appears twice, or when a balance or sum is over 2^63-1.
func Rebuild(toDay uint64, entries []Entry) (*Tree, error) {
	n := uint64(len(entries))
	if n < MinLeaves || n > 1<<MaxDepth || n&(n-1) != 0 {
		return nil, fmt.Errorf("liabtree: %d leaves: a tree has a power of two from %d to 2^%d", n, MinLeaves, MaxDepth)
	}
	seen := make(map[string]bool)
	for _, e := range entries {
		if e.Padding() {
			if e.Balance != 0 {
				return nil, fmt.Errorf("liabtree: a padding leaf has balance %d; padding is 0", e.Balance)
			}
			continue
		}
		if seen[e.AID] {
			return nil, fmt.Errorf("liabtree: account %q appears twice", e.AID)
		}
		seen[e.AID] = true
	}
	return build(toDay, append([]Entry(nil), entries...))
}

// build hashes entries (a power of two, checked by the callers) into a tree. It owns entries.
func build(toDay uint64, entries []Entry) (*Tree, error) {
	leaves := make([]Node, len(entries))
	pos := make(map[string]int, len(entries))
	for i, e := range entries {
		h, err := LeafHash(e.AID, toDay, e.Balance, e.Salt)
		if err != nil {
			return nil, err
		}
		leaves[i] = Node{Hash: h, Sum: e.Balance}
		if !e.Padding() {
			pos[e.AID] = i
		}
	}
	levels := [][]Node{leaves}
	for cur := leaves; len(cur) > 1; {
		next := make([]Node, len(cur)/2)
		for i := range next {
			l, r := cur[2*i], cur[2*i+1]
			sum, ok := addSum(l.Sum, r.Sum)
			if !ok {
				return nil, fmt.Errorf("%w: %d + %d", ErrOverflow, l.Sum, r.Sum)
			}
			next[i] = Node{Hash: NodeHash(l, r), Sum: sum}
		}
		levels = append(levels, next)
		cur = next
	}
	return &Tree{toDay: toDay, entries: entries, levels: levels, pos: pos}, nil
}

// ToDay is the last UTC day of the epoch the tree closes.
func (t *Tree) ToDay() uint64 { return t.toDay }

// Depth is the number of levels above the leaves (4 to 32).
func (t *Tree) Depth() int { return len(t.levels) - 1 }

// Root is the root hash that goes into the epoch record.
func (t *Tree) Root() [32]byte { return t.levels[len(t.levels)-1][0].Hash }

// Outstanding is the root sum: the total of all balances.
func (t *Tree) Outstanding() uint64 { return t.levels[len(t.levels)-1][0].Sum }

// Entries returns a copy of the leaves in tree order, padding included: what a hub stores to
// Rebuild the tree later.
func (t *Tree) Entries() []Entry { return append([]Entry(nil), t.entries...) }

// Proof returns the proof of the account's leaf, or false when the account is not in the tree.
func (t *Tree) Proof(aid string) (Proof, bool) {
	i, ok := t.pos[aid]
	if !ok || aid == "" {
		return Proof{}, false
	}
	return t.proofAt(i), true
}

// proofAt is the proof of the leaf at position i, padding included; Path is a fresh slice.
func (t *Tree) proofAt(i int) Proof {
	e := t.entries[i]
	p := Proof{AID: e.AID, ToDay: t.toDay, Balance: e.Balance, Salt: e.Salt, Path: make([]Step, t.Depth())}
	for lvl := range p.Path {
		sib, side := i+1, Right
		if i%2 == 1 {
			sib, side = i-1, Left
		}
		n := t.levels[lvl][sib]
		p.Path[lvl] = Step{Hash: n.Hash, Sum: n.Sum, Side: side}
		i /= 2
	}
	return p
}

// Verify checks that p is a leaf of the tree whose root hash is root, whose root sum is
// outstanding and whose depth is depth (the three values of a signed epoch record). It recomputes
// the leaf and every node on the path and refuses any sum over 2^63-1. The error wraps
// ErrMalformed, ErrOverflow, ErrRoot or ErrSum.
//
// Verify does not compare p's AID or day with anything: the caller checks that the proof is for
// its own AID and the record's to_day.
func Verify(p Proof, root [32]byte, outstanding uint64, depth int) error {
	if depth < MinDepth || depth > MaxDepth {
		return fmt.Errorf("%w: depth %d is not from %d to %d", ErrMalformed, depth, MinDepth, MaxDepth)
	}
	if len(p.Path) != depth {
		return fmt.Errorf("%w: the path has %d steps; the tree's depth is %d", ErrMalformed, len(p.Path), depth)
	}
	if p.AID == "" {
		return fmt.Errorf("%w: the empty AID marks a padding leaf, which belongs to no account", ErrMalformed)
	}
	if outstanding > MaxSum {
		return fmt.Errorf("%w: outstanding %d", ErrOverflow, outstanding)
	}
	top, err := fold(p)
	if err != nil {
		return err
	}
	if top.Hash != root {
		return ErrRoot
	}
	if top.Sum != outstanding {
		return fmt.Errorf("%w: the root's sum is %d, the record says %d", ErrSum, top.Sum, outstanding)
	}
	return nil
}

// fold recomputes the root from a proof's leaf and path.
func fold(p Proof) (Node, error) {
	h, err := LeafHash(p.AID, p.ToDay, p.Balance, p.Salt)
	if err != nil {
		return Node{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	cur := Node{Hash: h, Sum: p.Balance}
	for i, s := range p.Path {
		sum, ok := addSum(cur.Sum, s.Sum)
		if !ok {
			return Node{}, fmt.Errorf("%w: step %d adds %d and %d", ErrOverflow, i, cur.Sum, s.Sum)
		}
		sib := Node{Hash: s.Hash, Sum: s.Sum}
		switch s.Side {
		case Left:
			cur = Node{Hash: NodeHash(sib, cur), Sum: sum}
		case Right:
			cur = Node{Hash: NodeHash(cur, sib), Sum: sum}
		default:
			return Node{}, fmt.Errorf("%w: step %d has side %q", ErrMalformed, i, s.Side)
		}
	}
	return cur, nil
}
