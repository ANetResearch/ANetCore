package identity

// Fuzz targets for the KEL decoder and Replay (KEL §7.2 P1, P3).
//
// FuzzReplayProgram builds KELs from a small program, signs every event for real, encodes the
// KEL the way a sender might (canonically, without key 0, with another type tag, or in a
// non-CoreDet form) and hands the bytes to UnmarshalKEL and Replay, and the events to Replay as
// they are. A model of the KEL v2 rules, written out plainly below, decides independently whether
// each is valid and what every key state is; both paths must agree with it.
//
// FuzzUnmarshalKEL feeds raw bytes to UnmarshalKEL and Replay, the path a KEL a stranger sends
// takes.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
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

// fuzzWitnesses are two witness hub AIDs: "b" and the base32 of the CIDv1 dag-cbor sha2-256 of
// "anet-test/fuzz-witness-a" and "-b" (R-3 wants an AID, ValidAID).
var fuzzWitnesses = [2]string{
	"bafyreiayr7vdpaleqapd3fcfxzjb3f6mgt6tv2fqlkhqlazmyucdltsenq",
	"bafyreignwvzwhendb4ex5geg5cdcv3fzn2rw4qi7iy7j4q7a6o6layxoaq",
}

// kelOp is one program step (6 bytes). The first op builds the icp unless its typ has bit 7 set.
//
//	typ:   bits 0-1 the type: 0 icp, 1 rot, 2 dip, 3 a v0.2 type (bit 2: ixn, else drt)
//	keys:  bits 0-2 the pool key; bits 3-4 kt (0, 1: 1; 2: 2; 3: 0); bits 5-7 the shape
//	       (0-4 the pool key; 5 a key of keys&31 bytes; 6 none; 7 two pool keys)
//	next:  bits 0-2 the pool key; bits 6-7 the digest (0-1 of that key; 2 none; 3 31 junk bytes)
//	sign:  bits 0-2 the signing pool key; bit 3 seq off by one; bit 4 wrong prev; bit 5 an AID on
//	       the icp, the wrong AID later; bit 6 corrupt signature; bit 7 wrong event id
//	ts:    bits 0-1: 0 later than the previous by 1 + (ts>>2)*1000; 1 equal to the previous;
//	       2 zero; 3 one less than the previous (for the icp: 1+(ts>>2)*1000, 1000, 0, 1<<40)
//	flags: bits 0-1 toad: 0 the right value (icp: 0), 1 the other value (icp: 1), 2 absent, 3 two;
//	       for a dip 0 and 2 leave it out and 1 writes the icp's;
//	       bits 2-3 witnesses: 0 the right shape (a toad-1 rot names fuzzWitnesses[bit 4], every
//	       other event none), 1 none, 2 the AID itself (the icp: fuzzWitnesses[0]), 3 both
//	       witnesses; bit 5 emergency;
//	       bits 6-7 the encoding: 0 canonical, 1 key 0 left out, 2 key 0 "anet.kel/1",
//	       3 non-CoreDet (key 12 written false, or two keys swapped when emergency is set)
type kelOp struct{ typ, keys, next, sign, ts, flags byte }

func kelOps(data []byte) []kelOp {
	var ops []kelOp
	for len(data) >= 6 && len(ops) < 8 {
		ops = append(ops, kelOp{data[0], data[1], data[2], data[3], data[4], data[5]})
		data = data[6:]
	}
	return ops
}

const (
	formCanonical = iota
	formNoKey0
	formOtherTag
	formNonCoreDet
)

func (op kelOp) form() int { return int(op.flags >> 6) }

func (op kelOp) eventType(first bool) EventType {
	if first && op.typ&0x80 == 0 {
		return Inception
	}
	switch op.typ & 3 {
	case 0:
		return Inception
	case 1:
		return Rotation
	case 2:
		return Deactivation
	}
	if op.typ&4 != 0 {
		return "ixn"
	}
	return "drt"
}

// built is a program's KEL in memory and on the wire.
type built struct {
	kel  []SignedEvent
	wire []byte
	toad uint64 // the icp's toad as written (2 when absent or two)
}

func buildKEL(tb testing.TB, ops []kelOp) built {
	var out built
	var raws []rawSigned
	aid, prev := "", ""
	var prevTS uint64
	icpToad := uint64(2)
	for i, op := range ops {
		typ := op.eventType(i == 0)
		e := KeyEvent{KELType: KELType, Type: typ, Seq: uint64(i)}
		switch (op.keys >> 3) & 3 {
		case 2:
			e.Threshold = 2
		case 3:
			e.Threshold = 0
		default:
			e.Threshold = 1
		}
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
			e.NextDigest = bytes.Repeat([]byte{op.next}, 31)
		default:
			e.NextDigest = nextDigest(fuzzPub(op.next))
		}
		step := 1 + uint64(op.ts>>2)*1000
		if i == 0 {
			e.Timestamp = [4]uint64{step, 1000, 0, 1 << 40}[op.ts&3]
		} else {
			e.Timestamp = [4]uint64{prevTS + step, prevTS, 0, prevTS - 1}[op.ts&3]
		}
		toadMode := op.flags & 3
		switch {
		case i == 0:
			e.Toad = [4]*uint64{ToadField(0), ToadField(1), nil, ToadField(2)}[toadMode]
		case typ == Deactivation:
			if toadMode == 1 {
				e.Toad = ToadField(icpToad)
			} else if toadMode == 3 {
				e.Toad = ToadField(2)
			}
		default:
			e.Toad = [4]*uint64{ToadField(icpToad), ToadField(1 - icpToad%2), nil, ToadField(2)}[toadMode]
		}
		w := fuzzWitnesses[(op.flags>>4)&1]
		switch (op.flags >> 2) & 3 {
		case 0:
			if typ == Rotation && icpToad == ToadAgent {
				e.Witnesses = []string{w}
			}
		case 2:
			if i == 0 {
				e.Witnesses = []string{fuzzWitnesses[0]}
			} else {
				e.Witnesses = []string{aid}
			}
		case 3:
			e.Witnesses = []string{fuzzWitnesses[0], fuzzWitnesses[1]}
		}
		e.Emergency = op.flags&0x20 != 0
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
		switch op.form() {
		case formNoKey0:
			e.KELType = ""
		case formOtherTag:
			e.KELType = "anet.kel/1"
		}
		pre, err := preimage(e)
		if err != nil {
			tb.Fatalf("preimage of a built event: %v", err)
		}
		id := anetcid.MustSum(pre)
		sig := ed25519.Sign(fuzzKeys[op.sign&7], pre)
		if op.sign&0x40 != 0 {
			sig[0] ^= 1
		}
		sentID := id
		if op.sign&0x80 != 0 {
			sentID = id + "z"
		}
		if i == 0 {
			aid = id
			if e.Toad != nil {
				icpToad = *e.Toad
			}
			out.toad = icpToad
		}
		prev, prevTS = id, e.Timestamp
		out.kel = append(out.kel, SignedEvent{Event: e, Sig: sig, EventID: sentID})
		raws = append(raws, rawSigned{Event: wireEvent(tb, e, pre, op.form()), Sig: sig, EventID: sentID})
	}
	wire, err := coredet.Marshal(raws)
	if err != nil {
		tb.Fatalf("encoding the KEL: %v", err)
	}
	out.wire = wire
	return out
}

// wireEvent writes the event in the program's encoding form.
func wireEvent(tb testing.TB, e KeyEvent, canon []byte, form int) []byte {
	if form == formCanonical || form == formOtherTag {
		return canon
	}
	m := map[uint64]cbor.RawMessage{}
	if err := coredet.Unmarshal(canon, &m); err != nil {
		tb.Fatal(err)
	}
	if form == formNoKey0 {
		delete(m, 0)
		return encodeMap(tb, m, sortedKeys(m))
	}
	if !e.Emergency {
		m[12] = cbor.RawMessage{0xf4}
		return encodeMap(tb, m, sortedKeys(m))
	}
	order := sortedKeys(m)
	order[0], order[1] = order[1], order[0]
	return encodeMap(tb, m, order)
}

// modelState is what the model expects Replay to report for one event.
type modelState struct {
	key       []byte // nil for the dip
	status    string
	toad      uint64
	witness   string
	supersede uint64
	urgent    bool
}

// modelReplay decides validity from the KEL v2 rules written out plainly. It sees the program and
// the events as built; inMemory leaves out the rules that only bytes can break.
//
//   - every event: key 0 is "anet.kel/2"; kt 1; exactly one 32-byte key; ts > 0; the event id is
//     the CID of the event; the signature is by the event's own key (keys[0]) and intact;
//     on the wire also: written in the one CoreDet form;
//   - icp: first, seq 0, no aid, no prev, a 32-byte next digest, toad 0 or 1 written, no
//     witnesses, no emergency;
//   - later events: the icp's AID, seq + 1, prev = the previous id, ts > the previous ts, not
//     after a dip, and only rot or dip; the key hashes to the digest committed by the last icp or
//     rot;
//   - rot: a 32-byte next digest; toad written and equal to the icp's; toad 0: no witnesses;
//     toad 1: exactly one witness, not empty, not the AID itself;
//   - dip: no next, no witnesses, no toad, no emergency.
func modelReplay(b built, ops []kelOp, inMemory bool) ([]modelState, bool) {
	var out []modelState
	var committed []byte
	var aid, witness string
	var lastTS uint64
	toad := b.toad
	dead := false
	for i, se := range b.kel {
		e := se.Event
		op := ops[i]
		form := op.form()
		if form == formNoKey0 || form == formOtherTag || (!inMemory && form == formNonCoreDet) {
			return nil, false
		}
		pre, err := preimage(e)
		if err != nil {
			return nil, false
		}
		id := anetcid.MustSum(pre)
		oneKey := len(e.Keys) == 1 && len(e.Keys[0]) == 32
		if !oneKey || e.Threshold != 1 || e.Timestamp == 0 || op.sign&0x80 != 0 || op.sign&0x40 != 0 ||
			!bytes.Equal(fuzzPub(op.sign), e.Keys[0]) {
			return nil, false
		}
		typ := op.eventType(i == 0)
		if i == 0 {
			if typ != Inception || op.sign&0x38 != 0 || len(e.NextDigest) != 32 ||
				(op.flags&3) >= 2 || len(e.Witnesses) != 0 || e.Emergency {
				return nil, false
			}
			aid, toad, committed = id, uint64(op.flags&1), e.NextDigest
			out = append(out, modelState{key: e.Keys[0], status: StatusActive, toad: toad})
		} else {
			if op.sign&0x38 != 0 || dead || e.Timestamp <= lastTS || (typ != Rotation && typ != Deactivation) {
				return nil, false
			}
			d := sha256.Sum256(e.Keys[0])
			if !bytes.Equal(d[:], committed) {
				return nil, false
			}
			if typ == Rotation {
				if len(e.NextDigest) != 32 || e.Toad == nil || *e.Toad != toad {
					return nil, false
				}
				if toad == ToadHub && len(e.Witnesses) != 0 {
					return nil, false
				}
				if toad == ToadAgent && (len(e.Witnesses) != 1 || e.Witnesses[0] == "" || e.Witnesses[0] == aid) {
					return nil, false
				}
				if toad == ToadAgent {
					witness = e.Witnesses[0]
				}
				committed = e.NextDigest
				out = append(out, modelState{key: e.Keys[0], status: StatusActive, toad: toad, witness: witness})
			} else {
				if len(e.NextDigest) != 0 || len(e.Witnesses) != 0 || e.Toad != nil || e.Emergency {
					return nil, false
				}
				dead = true
				out = append(out, modelState{status: StatusDeactivated, toad: toad, witness: witness})
			}
			prevState := &out[len(out)-2]
			prevState.status = StatusRotated
			prevState.supersede = e.Timestamp
			prevState.urgent = typ == Deactivation || e.Emergency
		}
		lastTS = e.Timestamp
	}
	return out, len(out) > 0
}

// checkReplayed asserts the properties every KEL that replays must have (P3 among them).
func checkReplayed(t *testing.T, kel []SignedEvent, states []KeyState) {
	t.Helper()
	if len(states) != len(kel) {
		t.Fatalf("Replay returned %d states for %d events", len(states), len(kel))
	}
	aid := kel[0].EventID
	for i, s := range states {
		if s.AID != aid || s.KeyStateSeq != uint64(i) || s.LastEventID != kel[i].EventID {
			t.Fatalf("state %d: %+v", i, s)
		}
		wantKeys := 1
		if s.Status == StatusDeactivated {
			wantKeys = 0
		}
		if len(s.CurrentKeys) != wantKeys || (wantKeys == 1 && len(s.CurrentKeys[0]) != ed25519.PublicKeySize) {
			t.Fatalf("state %d (%s) has keys %x", i, s.Status, s.CurrentKeys)
		}
		if s.Status != StatusActive && s.Status != StatusDeactivated && (s.SupersededAt == 0 || s.Status != StatusRotated) {
			t.Fatalf("state %d: %+v", i, s)
		}
	}
	// Every prefix of a KEL that replays replays too, the KEL extends each of its prefixes, and a
	// prefix does not extend the KEL (P3). A cache is installed so the repeated replays inside
	// ExtendsKEL cost one replay per distinct KEL.
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
	// R-9 holds at the head's ts and fails 5 minutes and 1 ms before it.
	head := kel[len(kel)-1].Event.Timestamp
	if err := CheckNewEvents(nil, kel, head, nil); err != nil {
		t.Fatalf("CheckNewEvents at the head's ts: %v", err)
	}
	if head > EventClockWindow+1 {
		if err := CheckNewEvents(nil, kel, head-EventClockWindow-1, nil); !errors.Is(err, ErrEventFromFuture) {
			t.Fatalf("CheckNewEvents 5 min + 1 ms before the head: %v", err)
		}
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
		{0, 0, 1, 0, 0, 0},                   // a hub icp
		{0, 0, 1, 0, 0, 0, 1, 1, 2, 1, 4, 0}, // icp, rot
		{0, 0, 1, 0, 0, 0, 1, 1, 2, 1, 4, 0, 1, 2, 3, 2, 4, 0x20, 2, 3, 0x80, 3, 4, 0}, // icp, rot, emergency rot, dip
		{0, 0, 1, 0, 0, 1, 1, 1, 2, 1, 4, 0, 1, 2, 3, 2, 4, 0x10},                      // agent icp, rot to W0, rot to W1
		{0, 0, 1, 0, 0, 1, 1, 1, 2, 1, 4, 0, 1, 2, 3, 2, 4, 0x04},                      // agent clears its witness
		{0, 0, 1, 0, 0, 0, 1, 1, 2, 0, 4, 0},                                           // rot signed by the prior key
		{0, 0, 1, 0, 0, 0, 2, 1, 0x80, 0, 4, 0},                                        // dip signed by the prior key
		{0, 0, 1, 0, 0, 0, 7, 0, 1, 0, 4, 0},                                           // icp, ixn
		{0, 0, 1, 0, 0, 0, 1, 1, 2, 1, 1, 0},                                           // rot at the icp's ts
		{0, 0, 1, 0, 0, 0, 1, 1, 2, 1, 4, 0xc0},                                        // rot written in a non-CoreDet form
		{0, 0, 1, 0, 0, 0x40, 1, 1, 2, 1, 4, 0},                                        // icp without key 0
		{0, 0xbf, 1, 0, 0, 0},                                                          // icp with a 31-byte key
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
		b := buildKEL(t, ops)
		memStates, memErr := replay(b.kel)
		want, memOK := modelReplay(b, ops, true)
		if memOK != (memErr == nil) {
			t.Fatalf("Replay of the events: err=%v, model valid=%v\nKEL: %+v", memErr, memOK, b.kel)
		}
		decoded, decErr := UnmarshalKEL(b.wire)
		var wireStates []KeyState
		wireErr := decErr
		if decErr == nil {
			wireStates, wireErr = replay(decoded)
		}
		_, wireOK := modelReplay(b, ops, false)
		if wireOK != (wireErr == nil) {
			t.Fatalf("UnmarshalKEL+Replay of the bytes: err=%v, model valid=%v\nKEL: %+v", wireErr, wireOK, b.kel)
		}
		checkCache(t, b.kel, memStates, memErr)
		if memErr != nil {
			return
		}
		if wireErr == nil && fmt.Sprint(wireStates) != fmt.Sprint(memStates) {
			t.Fatalf("bytes and memory replay to different states:\n%v\n%v", wireStates, memStates)
		}
		for i, s := range memStates {
			w := want[i]
			var key []byte
			if len(s.CurrentKeys) == 1 {
				key = s.CurrentKeys[0]
			}
			if !bytes.Equal(key, w.key) || s.Status != w.status || s.Toad != w.toad || s.Witness != w.witness ||
				s.SupersededAt != w.supersede || s.RetiredUrgently != w.urgent {
				t.Fatalf("state %d: %+v, model %+v", i, s, w)
			}
		}
		checkReplayed(t, b.kel, memStates)
		// An object verifies under the key its declared state holds and under no other pool key,
		// a retired state's only for times before it was retired, the dip's state never.
		prevCache := SetReplayCache(NewReplayCache(1 << 20))
		defer SetReplayCache(prevCache)
		pre := []byte("fuzz object")
		for seq, s := range memStates {
			for k := byte(0); k < 8; k++ {
				own := len(s.CurrentKeys) == 1 && bytes.Equal(fuzzPub(k), s.CurrentKeys[0])
				sig := ed25519.Sign(fuzzKeys[k], pre)
				for _, at := range []uint64{0, 1, s.SupersededAt - 1, s.SupersededAt, s.SupersededAt + 1} {
					err := VerifyObject(b.kel, s.AID, uint64(seq), at, pre, sig)
					accept := own && (s.Status == StatusActive || s.Status == StatusRotated && at != 0 && at < s.SupersededAt)
					if accept != (err == nil) {
						t.Fatalf("state %d (%s, superseded %d), pool key %d own=%v, msgTime %d: %v",
							seq, s.Status, s.SupersededAt, k, own, at, err)
					}
				}
			}
			if s.Status == StatusRotated {
				g := RotationGrace
				if s.RetiredUrgently {
					g = 0
				}
				if !RetiredUsableAt(s, s.SupersededAt+g) || RetiredUsableAt(s, s.SupersededAt+g+1) {
					t.Fatalf("state %d: RetiredUsableAt boundary at %d + %d", seq, s.SupersededAt, g)
				}
			}
		}
	})
}

func FuzzUnmarshalKEL(f *testing.F) {
	for _, p := range fuzzSeedPrograms() {
		f.Add(buildKEL(f, kelOps(p)).wire)
	}
	f.Add(mustMarshalKEL(f, SuiteController().KEL()))
	f.Add(mustMarshalKEL(f, kel2A()))
	f.Add(mustMarshalKEL(f, kel2B()))
	f.Fuzz(func(t *testing.T, b []byte) {
		kel, err := UnmarshalKEL(b)
		if err != nil {
			return
		}
		// Every event that decoded is in its one canonical form.
		for i, se := range kel {
			if se.Event.KELType != KELType {
				t.Fatalf("event %d decoded with key 0 %q", i, se.Event.KELType)
			}
			enc, err := coredet.Marshal(se.Event)
			if err != nil {
				t.Fatalf("event %d does not encode: %v", i, err)
			}
			var back KeyEvent
			if err := coredet.UnmarshalStrict(enc, &back); err != nil {
				t.Fatalf("event %d does not decode again: %v", i, err)
			}
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
