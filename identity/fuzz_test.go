package identity

// Fuzz targets for the KEL decoder and Replay (ANet docs/notes/0033).
//
// FuzzUnmarshalKEL feeds raw bytes to UnmarshalKEL and Replay, the path a KEL a stranger sends
// takes. Mutated bytes rarely keep a valid signature, so FuzzReplayProgram builds KELs from a
// small program instead: each 4-byte op names an event type, the keys, the next-key digest and
// the signer from a fixed key pool, and the event is then signed for real. A model of the KEL
// rules decides independently whether the KEL is valid and what each key state is; Replay must
// agree with it.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
)

// fuzzKeys is a fixed key pool. Programs name keys by index, so an input reproduces exactly.
var fuzzKeys = func() []ed25519.PrivateKey {
	ks := make([]ed25519.PrivateKey, 8)
	for i := range ks {
		s := sha256.Sum256([]byte(fmt.Sprintf("anet-fuzz/identity/key-%d", i)))
		ks[i] = ed25519.NewKeyFromSeed(s[:])
	}
	return ks
}()

func fuzzPub(i byte) ed25519.PublicKey { return fuzzKeys[i&7].Public().(ed25519.PublicKey) }

// kelOp is one program step. The first op builds the inception event.
//
//	typ:  low 3 bits pick the type (0 icp, 1 rot, 2 ixn, 3 dip, 4 drt, 5 rot, 6 ixn, 7 unknown);
//	      for the first op the type is icp unless bit 7 is set.
//	keys: top 3 bits pick the shape (0-4 one pool key, 5 one key of len keys&31, 6 none,
//	      7 two pool keys); low 3 bits the pool index.
//	next: top 2 bits pick the digest (0-1 digest of pool key next&7, 2 none, 3 32 junk bytes).
//	sign: low 3 bits the signing pool key; bit 3 seq off by one; bit 4 wrong prev; bit 5 wrong
//	      AID; bit 6 timestamp = sign*1000 instead of (i+1)*1000; bit 7 corrupt signature.
type kelOp struct{ typ, keys, next, sign byte }

func kelOps(data []byte) []kelOp {
	var ops []kelOp
	for len(data) >= 4 && len(ops) < 10 {
		ops = append(ops, kelOp{data[0], data[1], data[2], data[3]})
		data = data[4:]
	}
	return ops
}

var fuzzTypes = [8]EventType{Inception, Rotation, Interaction, Deactivation, Delegation, Rotation, Interaction, "xyz"}

// buildKEL signs the program's events. Every event is built and signed; whether the KEL is valid
// is for Replay and the model to decide.
func buildKEL(tb testing.TB, ops []kelOp) []SignedEvent {
	var kel []SignedEvent
	aid, prev := "", ""
	for i, op := range ops {
		typ := fuzzTypes[op.typ&7]
		if i == 0 {
			typ = Inception
			if op.typ&0x80 != 0 {
				typ = fuzzTypes[op.typ&7]
			}
		}
		e := KeyEvent{Type: typ, Threshold: 1, Seq: uint64(i), Timestamp: uint64(i+1) * 1000}
		switch op.keys >> 5 {
		case 5:
			e.Keys = [][]byte{bytes.Repeat([]byte{op.keys}, int(op.keys&31))}
		case 6:
			e.Keys = [][]byte{}
		case 7:
			e.Keys = [][]byte{fuzzPub(op.keys), fuzzPub(op.keys + 1)}
		default:
			e.Keys = [][]byte{fuzzPub(op.keys)}
		}
		switch op.next >> 6 {
		case 2:
		case 3:
			e.NextDigest = bytes.Repeat([]byte{op.next}, 32)
		default:
			e.NextDigest = nextDigest(fuzzPub(op.next))
		}
		if i > 0 {
			e.AID, e.Prev = aid, prev
		}
		if op.sign&0x08 != 0 {
			e.Seq++
		}
		if op.sign&0x10 != 0 {
			e.Prev += "x"
		}
		if op.sign&0x20 != 0 {
			e.AID += "y"
		}
		if op.sign&0x40 != 0 {
			e.Timestamp = uint64(op.sign) * 1000
		}
		pre, err := preimage(e)
		if err != nil {
			tb.Fatalf("preimage of a built event: %v", err)
		}
		id, err := anetcid.Sum(pre)
		if err != nil {
			tb.Fatal(err)
		}
		sig := ed25519.Sign(fuzzKeys[op.sign&7], pre)
		if op.sign&0x80 != 0 {
			sig[0] ^= 1
		}
		if i == 0 {
			aid = id
		}
		prev = id
		kel = append(kel, SignedEvent{Event: e, Sig: sig, EventID: id})
	}
	return kel
}

// modelState is what the model expects Replay to report for one event.
type modelState struct {
	key       []byte
	seq       uint64
	status    string
	delegated [][]byte
}

// modelReplay decides validity from the KEL rules written out plainly:
//   - icp: first, seq 0, no prev, AID empty or its own CID, one 32-byte key, signed by it;
//   - later events: same AID, seq+1, prev = previous event id, no event after a dip;
//   - rot: one 32-byte key whose SHA-256 is the next-key digest committed by the last
//     establishment event (the icp or the latest rot), signed by the prior current key;
//   - ixn, dip: signed by the current key; drt: one key of any length, signed by the current key;
//   - any other type is invalid.
//
// An ixn or drt does not change the commitment: it is signed by the current key alone, so
// letting it re-commit would let whoever holds the current key choose the next one.
func modelReplay(kel []SignedEvent, ops []kelOp) ([]modelState, bool) {
	var out []modelState
	var cur, committed []byte
	var delegated [][]byte
	aid, last := "", ""
	status := StatusActive
	for i, se := range kel {
		e := se.Event
		pre, err := preimage(e)
		if err != nil {
			return nil, false
		}
		id := anetcid.MustSum(pre)
		signer := []byte(fuzzPub(ops[i].sign))
		sigOK := ops[i].sign&0x80 == 0
		signedBy := func(k []byte) bool { return sigOK && bytes.Equal(signer, k) }
		if i == 0 {
			if e.Type != Inception || e.Seq != 0 || e.Prev != "" || (e.AID != "" && e.AID != id) {
				return nil, false
			}
			if len(e.Keys) != 1 || len(e.Keys[0]) != 32 || !signedBy(e.Keys[0]) {
				return nil, false
			}
			aid, cur, committed = id, e.Keys[0], e.NextDigest
		} else {
			if e.AID != aid || e.Seq != uint64(i) || e.Prev != last || status != StatusActive {
				return nil, false
			}
			switch e.Type {
			case Rotation:
				if len(e.Keys) != 1 || len(e.Keys[0]) != 32 {
					return nil, false
				}
				d := sha256.Sum256(e.Keys[0])
				if !bytes.Equal(d[:], committed) || !signedBy(cur) {
					return nil, false
				}
				cur, committed = e.Keys[0], e.NextDigest
			case Interaction:
				if !signedBy(cur) {
					return nil, false
				}
			case Delegation:
				if len(e.Keys) != 1 || !signedBy(cur) {
					return nil, false
				}
				delegated = append(append([][]byte(nil), delegated...), e.Keys[0])
			case Deactivation:
				if !signedBy(cur) {
					return nil, false
				}
				status = StatusDeactivated
			default:
				return nil, false
			}
		}
		last = id
		out = append(out, modelState{key: cur, seq: uint64(i), status: status, delegated: delegated})
	}
	// Retirement: a state is retired by the first later rot or dip.
	for i := range out {
		for j := i + 1; j < len(kel); j++ {
			if t := kel[j].Event.Type; t == Rotation || t == Deactivation {
				if out[i].status == StatusActive {
					out[i].status = StatusRotated
				}
				break
			}
		}
	}
	return out, len(out) > 0
}

// checkReplayed asserts the properties every KEL that replays must have.
func checkReplayed(t *testing.T, kel []SignedEvent, states []KeyState) {
	t.Helper()
	if len(states) != len(kel) {
		t.Fatalf("Replay returned %d states for %d events", len(states), len(kel))
	}
	icpPre, err := preimage(kel[0].Event)
	if err != nil {
		t.Fatalf("icp of a replayed KEL does not encode: %v", err)
	}
	aid := anetcid.MustSum(icpPre)
	for i, s := range states {
		if s.AID != aid {
			t.Fatalf("state %d AID %s, icp CID %s", i, s.AID, aid)
		}
		if s.KeyStateSeq != uint64(i) {
			t.Fatalf("state %d has key_state_seq %d", i, s.KeyStateSeq)
		}
		if len(s.CurrentKeys) != 1 || len(s.CurrentKeys[0]) != ed25519.PublicKeySize {
			t.Fatalf("state %d current keys %d (lens %v): VerifyObject would panic or misread", i, len(s.CurrentKeys), s.CurrentKeys)
		}
	}
	// Every prefix of a KEL that replays replays too (ExtendsKEL's doc relies on it), and the
	// KEL extends each of its prefixes; a prefix does not extend the KEL. A cache is installed
	// so the repeated replays inside ExtendsKEL cost one replay per distinct KEL.
	prevCache := SetReplayCache(NewReplayCache(1 << 20))
	defer SetReplayCache(prevCache)
	for k := 1; k <= len(kel); k++ {
		if _, err := Replay(kel[:k]); err != nil {
			t.Fatalf("prefix of %d events does not replay: %v", k, err)
		}
		if err := ExtendsKEL(kel[:k], kel); err != nil {
			t.Fatalf("KEL does not extend its own prefix of %d: %v", k, err)
		}
		if k < len(kel) {
			if err := ExtendsKEL(kel, kel[:k]); !errors.Is(err, ErrKELRollback) {
				t.Fatalf("prefix of %d accepted as an extension of the KEL: %v", k, err)
			}
		}
	}
	// A round trip through the wire form replays to the same states.
	b, err := MarshalKEL(kel)
	if err != nil {
		t.Fatalf("a replayed KEL does not encode: %v", err)
	}
	back, err := UnmarshalKEL(b)
	if err != nil {
		t.Fatalf("an encoded KEL does not decode: %v", err)
	}
	states2, err := replay(back)
	if err != nil {
		t.Fatalf("a round-tripped KEL does not replay: %v", err)
	}
	if fmt.Sprint(states2) != fmt.Sprint(states) {
		t.Fatalf("round trip changed the states:\n%v\n%v", states, states2)
	}
}

// checkCache replays kel through a fresh cache twice and compares with the uncached result.
func checkCache(t *testing.T, kel []SignedEvent, want []KeyState, wantErr error) {
	t.Helper()
	c := NewReplayCache(1 << 20)
	for round := 0; round < 2; round++ {
		got, err := c.replay(kel)
		if (err == nil) != (wantErr == nil) {
			t.Fatalf("cache round %d: err %v, uncached %v", round, err, wantErr)
		}
		if err == nil && fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("cache round %d changed the states:\n%v\n%v", round, want, got)
		}
	}
}

func fuzzSeedPrograms() [][]byte {
	return [][]byte{
		{0, 0, 1, 0},                               // icp alone
		{0, 0, 1, 0, 1, 1, 2, 0},                   // icp, rot
		{0, 0, 1, 0, 4, 3, 1, 0, 1, 1, 2, 0},       // icp, drt (carrying the commitment), rot
		{0, 0, 1, 0, 2, 0, 1, 0, 3, 0, 0x80, 0},    // icp, ixn, dip
		{0, 0, 1, 0, 1, 1, 2, 0, 1, 2, 3, 1},       // two rotations
		{0, 0, 1, 0, 4, 0xbf, 0x80, 0, 2, 0, 1, 0}, // drt with a 31-byte key, ixn
		{0, 0xbf, 1, 0},                            // icp with a 31-byte key
		{0, 0, 1, 0, 1, 0xa0, 1, 0},                // rot to an empty key
	}
}

func FuzzReplayProgram(f *testing.F) {
	for _, p := range fuzzSeedPrograms() {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ops := kelOps(data)
		if len(ops) == 0 {
			return
		}
		kel := buildKEL(t, ops)
		states, err := replay(kel)
		want, ok := modelReplay(kel, ops)
		if ok != (err == nil) {
			t.Fatalf("Replay err=%v, model valid=%v\nKEL: %+v", err, ok, kel)
		}
		checkCache(t, kel, states, err)
		if err != nil {
			return
		}
		for i, s := range states {
			w := want[i]
			if !bytes.Equal(s.CurrentKeys[0], w.key) || s.Status != w.status {
				t.Fatalf("state %d: key %x status %s, model key %x status %s", i, s.CurrentKeys[0], s.Status, w.key, w.status)
			}
			if fmt.Sprint(s.DelegatedKeys) != fmt.Sprint(w.delegated) {
				t.Fatalf("state %d delegated %x, model %x", i, s.DelegatedKeys, w.delegated)
			}
		}
		checkReplayed(t, kel, states)
		// An object verifies under the key the declared state holds and under no other pool
		// key: the signer is the one the key state names.
		prevCache := SetReplayCache(NewReplayCache(1 << 20))
		defer SetReplayCache(prevCache)
		pre := []byte("fuzz object")
		final := states[len(states)-1]
		for seq, s := range states {
			for k := byte(0); k < 8; k++ {
				own := bytes.Equal(fuzzPub(k), s.CurrentKeys[0])
				err := VerifyObject(kel, s.AID, uint64(seq), 0, pre, ed25519.Sign(fuzzKeys[k], pre))
				terminal := final.Status == StatusDeactivated && uint64(seq) == final.KeyStateSeq
				if own && !terminal && err != nil {
					t.Fatalf("object signed by the key of state %d refused: %v", seq, err)
				}
				if !own && err == nil {
					t.Fatalf("object signed by pool key %d verified at seq %d, whose key is %x", k, seq, s.CurrentKeys[0])
				}
			}
		}
	})
}

func FuzzUnmarshalKEL(f *testing.F) {
	for _, p := range fuzzSeedPrograms() {
		b, err := MarshalKEL(buildKEL(f, kelOps(p)))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add(mustMarshalKEL(f, SuiteController().KEL()))
	f.Fuzz(func(t *testing.T, b []byte) {
		kel, err := UnmarshalKEL(b)
		if err != nil {
			return
		}
		states, err := replay(kel)
		checkCache(t, kel, states, err)
		for seq := uint64(0); seq < uint64(len(kel))+1; seq++ {
			_ = VerifyObject(kel, "", seq, seq, b, make([]byte, 64))
		}
		_ = ExtendsKEL(kel, kel)
		if err != nil {
			return
		}
		checkReplayed(t, kel, states)
	})
}

func mustMarshalKEL(tb testing.TB, kel []SignedEvent) []byte {
	b, err := MarshalKEL(kel)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}
