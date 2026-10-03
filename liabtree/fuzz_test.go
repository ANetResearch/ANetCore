package liabtree

import (
	"encoding/json"
	"errors"
	"testing"
)

// fuzzTree is a fixed tree of three accounts the fuzz targets work against.
var fuzzTree = func() *Tree {
	t, err := Build([]Leaf{{AID: "acct-a", Balance: 5}, {AID: "acct-b", Balance: 1 << 40}, {AID: "acct-c", Balance: 0}}, 20454, newStream("fuzz"))
	if err != nil {
		panic(err)
	}
	return t
}()

// FuzzVerify: Verify never panics, and it accepts only a real leaf of the tree. The fuzzer edits a
// valid proof (the leaf's fields, any step's hash, sum and side, the path length) and the published
// values; whatever Verify accepts against the tree's root must be one of the tree's accounts with
// its exact balance, salt and day — otherwise SHA-256 collided or the sum binding failed.
func FuzzVerify(f *testing.F) {
	f.Add("acct-a", uint64(5), uint64(20454), []byte{}, uint64(0), int64(0), 4)
	f.Add("acct-b", uint64(1<<40), uint64(20454), []byte{1, 2, 0xff}, uint64(1), int64(-1), 4)
	f.Add("acct-c", uint64(0), uint64(20454), []byte{3, 0x80, 7, 0, 9}, uint64(1<<63), int64(1), 5)
	f.Add("", uint64(0), uint64(20454), []byte{}, uint64(0), int64(0), 4)
	f.Fuzz(func(t *testing.T, aid string, balance, day uint64, edits []byte, moved uint64, dOutstanding int64, depth int) {
		base, ok := fuzzTree.Proof(aid)
		if !ok {
			base, _ = fuzzTree.Proof("acct-a")
			base.AID = aid
		}
		p := base
		p.Balance = balance
		p.ToDay = day
		p.Path = append([]Step(nil), base.Path...)
		// edits: groups of 3 bytes (step, what, value)
		for i := 0; i+2 < len(edits) && len(p.Path) > 0; i += 3 {
			s := int(edits[i]) % len(p.Path)
			v := edits[i+2]
			switch edits[i+1] % 5 {
			case 0:
				p.Path[s].Hash[v%32] ^= 1 << (v % 8)
			case 1:
				p.Path[s].Sum += uint64(v) << (v % 64)
			case 2:
				p.Path[s].Side = Side(v)
			case 3:
				p.Path = p.Path[:s]
			case 4:
				p.Salt[v%32] ^= 1
			}
		}
		if len(p.Path) >= 2 { // move value between the first two steps
			p.Path[0].Sum -= moved
			p.Path[1].Sum += moved
		}
		outstanding := fuzzTree.Outstanding() + uint64(dOutstanding)
		err := Verify(p, fuzzTree.Root(), outstanding, depth)
		if err == nil {
			real, ok := fuzzTree.Proof(p.AID)
			if !ok || !equalProof(p, real) || outstanding != fuzzTree.Outstanding() || depth != fuzzTree.Depth() {
				t.Fatalf("Verify accepted a proof that is not a leaf of the tree: %+v (outstanding %d, depth %d)", p, outstanding, depth)
			}
			return
		}
		if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrOverflow) && !errors.Is(err, ErrRoot) && !errors.Is(err, ErrSum) {
			t.Fatalf("Verify error %v wraps none of the package errors", err)
		}
	})
}

// FuzzParseWire: the response decoder. Whatever JSON comes from a hub, Parse never panics; what it
// accepts has one spelling (Wire of the result gives back the same members), and its errors wrap
// ErrMalformed.
func FuzzParseWire(f *testing.F) {
	p, _ := fuzzTree.Proof("acct-b")
	good, _ := json.Marshal(p.Wire())
	f.Add(good)
	f.Add([]byte(`{"to_day":1,"aid":"a","balance":2,"salt":"` + Hex([32]byte{1}) + `","path":[{"h":"` + Hex([32]byte{2}) + `","sum":3,"side":"L"}]}`))
	f.Add([]byte(`{"salt":"ABCDEF","path":[{"h":"","sum":-1,"side":"X"}]}`))
	f.Add([]byte(`{"path":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var w WireProof
		if json.Unmarshal(b, &w) != nil {
			return
		}
		q, err := w.Parse()
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("Parse error %v does not wrap ErrMalformed", err)
			}
			return
		}
		back := q.Wire()
		if back.ToDay != w.ToDay || back.AID != w.AID || back.Balance != w.Balance || back.Salt != w.Salt || len(back.Path) != len(w.Path) {
			t.Fatalf("Parse then Wire changed the proof: %+v -> %+v", w, back)
		}
		for i := range w.Path {
			if back.Path[i] != w.Path[i] {
				t.Fatalf("step %d: %+v -> %+v", i, w.Path[i], back.Path[i])
			}
		}
		// and Verify takes whatever Parse gives without panicking
		_ = Verify(q, fuzzTree.Root(), fuzzTree.Outstanding(), len(q.Path))
	})
}
