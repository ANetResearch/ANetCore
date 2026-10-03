package identity

// KEL v2 replay, retirement and acceptance rules (KEL §2.1, §2.2, §4.1 C-1–C-4, C-10–C-12).
//
// The KELs here are built event by event from keys whose seeds are SHA-256 of a label, so every
// run builds the same bytes; kelvec_test.go writes the same KELs out as the KEL-2A, KEL-2B and
// KEL-2N vectors. Each negative case breaks exactly one rule of an otherwise valid KEL, so that
// removing the rule's check lets the case through (KEL §7.3 M1–M7, M29, M30).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
)

// ---- building KELs ----------------------------------------------------------------------------

// testKey is the Ed25519 key whose seed is SHA-256(label).
func testKey(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(s[:])
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func digestOf(k ed25519.PrivateKey) []byte { return nextDigest(pubOf(k)) }

// icpEvent is a valid icp of k0 committing k1.
func icpEvent(k0, k1 ed25519.PrivateKey, ts, toad uint64) KeyEvent {
	return KeyEvent{KELType: KELType, Type: Inception, Keys: [][]byte{pubOf(k0)},
		NextDigest: digestOf(k1), Threshold: 1, Timestamp: ts, Toad: ToadField(toad)}
}

// rotEvent is a rot revealing rev and committing next; witness "" leaves key 9 out.
func rotEvent(rev, next ed25519.PrivateKey, ts, toad uint64, witness string, emergency bool) KeyEvent {
	e := KeyEvent{KELType: KELType, Type: Rotation, Keys: [][]byte{pubOf(rev)},
		NextDigest: digestOf(next), Threshold: 1, Timestamp: ts, Toad: ToadField(toad), Emergency: emergency}
	if witness != "" {
		e.Witnesses = []string{witness}
	}
	return e
}

// dipEvent is a dip revealing rev.
func dipEvent(rev ed25519.PrivateKey, ts uint64) KeyEvent {
	return KeyEvent{KELType: KELType, Type: Deactivation, Keys: [][]byte{pubOf(rev)}, Threshold: 1, Timestamp: ts}
}

// after links e to the head of kel: the AID, the next seq and the head's id.
func after(kel []SignedEvent, e KeyEvent) KeyEvent {
	head := kel[len(kel)-1]
	e.AID = kel[0].EventID
	e.Seq = head.Event.Seq + 1
	e.Prev = head.EventID
	return e
}

// signEvent signs e with k and sets its event id, without checking anything about e.
func signEvent(e KeyEvent, k ed25519.PrivateKey) SignedEvent {
	pre, err := preimage(e)
	if err != nil {
		panic(err)
	}
	return SignedEvent{Event: e, Sig: ed25519.Sign(k, pre), EventID: anetcid.MustSum(pre)}
}

// extend appends e, linked after kel and signed by k, to a copy of kel.
func extend(kel []SignedEvent, e KeyEvent, k ed25519.PrivateKey) []SignedEvent {
	return append(append([]SignedEvent(nil), kel...), signEvent(after(kel, e), k))
}

// Times of the vectors (unix ms). The KEL-2A hub incepts at hubT0 and is deactivated at hubDipTS;
// the KEL-2B agent's whole KEL, which names that hub as its second witness, lies in between.
const (
	hubT0    uint64 = 1760000000000
	hubDipTS uint64 = hubT0 + 10*60*1000
	agentT0  uint64 = 1760000180000 // the agent incepts after the hub's emergency rot, and ends before its dip
	minute   uint64 = 60 * 1000
)

// hubKeys and agentKeys are the KEL-2A and KEL-2B keys: k0 incepts, k1 is the hot next key the
// icp commits, k2 and k3 are revealed by the second rot and the dip.
func vecKeys(id string) []ed25519.PrivateKey {
	ks := make([]ed25519.PrivateKey, 4)
	for i := range ks {
		ks[i] = testKey(fmt.Sprintf("anet-golden/v016/%s/k%d", id, i))
	}
	return ks
}

// attackerKey is a key nobody committed to.
func attackerKey() ed25519.PrivateKey { return testKey("anet-golden/v016/KEL-2N/attacker") }

// kel2A is the KEL-2A hub identity (toad 0): icp → rot 1 (setup-recovery) → rot 2 (emergency) →
// dip 3.
func kel2A() []SignedEvent {
	k := vecKeys("KEL-2A")
	kel := []SignedEvent{signEvent(icpEvent(k[0], k[1], hubT0, ToadHub), k[0])}
	kel = extend(kel, rotEvent(k[1], k[2], hubT0+1*minute, ToadHub, "", false), k[1])
	kel = extend(kel, rotEvent(k[2], k[3], hubT0+2*minute, ToadHub, "", true), k[2])
	kel = extend(kel, dipEvent(k[3], hubDipTS), k[3])
	return kel
}

// w1KEL is the inception of the second hub KEL-2B names (W1); W2 is the KEL-2A hub.
func w1KEL() []SignedEvent {
	k0, k1 := testKey("anet-golden/v016/KEL-2B/w1-k0"), testKey("anet-golden/v016/KEL-2B/w1-k1")
	return []SignedEvent{signEvent(icpEvent(k0, k1, hubT0, ToadHub), k0)}
}

// kel2B is the KEL-2B agent identity (toad 1): icp (witness pending) → rot 1 (designates W1) →
// rot 2 (moves to W2) → dip 3.
func kel2B() []SignedEvent {
	k := vecKeys("KEL-2B")
	w1, w2 := w1KEL()[0].EventID, kel2A()[0].EventID
	kel := []SignedEvent{signEvent(icpEvent(k[0], k[1], agentT0, ToadAgent), k[0])}
	kel = extend(kel, rotEvent(k[1], k[2], agentT0+1*minute, ToadAgent, w1, false), k[1])
	kel = extend(kel, rotEvent(k[2], k[3], agentT0+2*minute, ToadAgent, w2, false), k[2])
	kel = extend(kel, dipEvent(k[3], agentT0+3*minute), k[3])
	return kel
}

func clone(kel []SignedEvent) []SignedEvent { return append([]SignedEvent(nil), kel...) }

// ---- R-0 to R-8: replay -----------------------------------------------------------------------

// replayBytes decodes and replays b, as a KEL a stranger sends is checked.
func replayBytes(b []byte) ([]KeyState, error) {
	kel, err := UnmarshalKEL(b)
	if err != nil {
		return nil, err
	}
	return replay(kel)
}

func mustMarshal(t testing.TB, kel []SignedEvent) []byte {
	t.Helper()
	b, err := MarshalKEL(kel)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKEL2AAnd2BReplay(t *testing.T) {
	a, b := kel2A(), kel2B()
	w2 := a[0].EventID
	w1 := w1KEL()[0].EventID
	type row struct {
		status    string
		key       []byte
		toad      uint64
		witness   string
		supersede uint64
		urgent    bool
	}
	ka, kb := vecKeys("KEL-2A"), vecKeys("KEL-2B")
	cases := []struct {
		name string
		kel  []SignedEvent
		want []row
	}{
		{"KEL-2A", a, []row{
			{StatusRotated, pubOf(ka[0]), 0, "", hubT0 + minute, false},
			{StatusRotated, pubOf(ka[1]), 0, "", hubT0 + 2*minute, true},
			{StatusRotated, pubOf(ka[2]), 0, "", hubDipTS, true},
			{StatusDeactivated, nil, 0, "", 0, false},
		}},
		{"KEL-2B", b, []row{
			{StatusRotated, pubOf(kb[0]), 1, "", agentT0 + minute, false},
			{StatusRotated, pubOf(kb[1]), 1, w1, agentT0 + 2*minute, false},
			{StatusRotated, pubOf(kb[2]), 1, w2, agentT0 + 3*minute, true},
			{StatusDeactivated, nil, 1, w2, 0, false},
		}},
	}
	for _, tc := range cases {
		for _, viaBytes := range []bool{false, true} {
			var states []KeyState
			var err error
			if viaBytes {
				states, err = replayBytes(mustMarshal(t, tc.kel))
			} else {
				states, err = replay(tc.kel)
			}
			if err != nil {
				t.Fatalf("%s (bytes %v): %v", tc.name, viaBytes, err)
			}
			for i, w := range tc.want {
				s := states[i]
				var key []byte
				if len(s.CurrentKeys) == 1 {
					key = s.CurrentKeys[0]
				} else if len(s.CurrentKeys) != 0 {
					t.Fatalf("%s state %d has %d keys", tc.name, i, len(s.CurrentKeys))
				}
				if s.AID != tc.kel[0].EventID || s.KeyStateSeq != uint64(i) || s.LastEventID != tc.kel[i].EventID ||
					s.Status != w.status || !bytes.Equal(key, w.key) || s.Toad != w.toad || s.Witness != w.witness ||
					s.SupersededAt != w.supersede || s.RetiredUrgently != w.urgent {
					t.Errorf("%s state %d = %+v, want %+v", tc.name, i, s, w)
				}
			}
		}
	}
}

// negCase is one KEL that breaks one rule, and the error text Replay (or UnmarshalKEL) gives.
type negCase struct {
	name string
	kel  []byte
	err  string
}

// rawMap is an event's encoding as key → value bytes, to write forms coredet never would.
func rawMap(t testing.TB, e KeyEvent) map[uint64]cbor.RawMessage {
	t.Helper()
	b, err := coredet.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	m := map[uint64]cbor.RawMessage{}
	if err := coredet.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// encodeMap writes m as a CBOR map with its keys in the given order (all keys of m).
func encodeMap(t testing.TB, m map[uint64]cbor.RawMessage, order []uint64) []byte {
	t.Helper()
	if len(order) != len(m) || len(m) > 23 {
		t.Fatalf("encodeMap: %d keys, order of %d", len(m), len(order))
	}
	out := []byte{0xa0 | byte(len(m))}
	for _, k := range order {
		kb, err := coredet.Marshal(k)
		if err != nil {
			t.Fatal(err)
		}
		v, ok := m[k]
		if !ok {
			t.Fatalf("encodeMap: key %d not in the map", k)
		}
		out = append(append(out, kb...), v...)
	}
	return out
}

func sortedKeys(m map[uint64]cbor.RawMessage) []uint64 {
	var ks []uint64
	for k := range m {
		ks = append(ks, k)
	}
	for i := range ks {
		for j := i + 1; j < len(ks); j++ {
			if ks[j] < ks[i] {
				ks[i], ks[j] = ks[j], ks[i]
			}
		}
	}
	return ks
}

// rawSigned is a SignedEvent whose event bytes are given as they are.
type rawSigned struct {
	Event   cbor.RawMessage `cbor:"1,keyasint"`
	Sig     []byte          `cbor:"2,keyasint"`
	EventID string          `cbor:"3,keyasint"`
	Extra   []byte          `cbor:"4,keyasint,omitempty"`
}

// rawKEL encodes prefix followed by an event whose bytes are head, signed by k and identified
// over head itself, with extra as key 4 of that event's signed event when it is not nil.
func rawKEL(t testing.TB, prefix []SignedEvent, head []byte, k ed25519.PrivateKey, extra []byte) []byte {
	t.Helper()
	return rawKELOver(t, prefix, head, head, k, extra)
}

// rawKELOver is rawKEL with the signature and the event id over signed instead of head: the same
// event carried in other bytes (CORE-E2).
func rawKELOver(t testing.TB, prefix []SignedEvent, head, signed []byte, k ed25519.PrivateKey, extra []byte) []byte {
	t.Helper()
	var out []rawSigned
	for _, se := range prefix {
		b, err := coredet.Marshal(se.Event)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rawSigned{Event: b, Sig: se.Sig, EventID: se.EventID})
	}
	out = append(out, rawSigned{Event: head, Sig: ed25519.Sign(k, signed), EventID: anetcid.MustSum(signed), Extra: extra})
	b, err := coredet.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// negativeCases are the KEL-2N cases. Each is an otherwise valid KEL with one rule broken.
func negativeCases(t testing.TB) []negCase {
	a, b := kel2A(), kel2B()
	ka, kb := vecKeys("KEL-2A"), vecKeys("KEL-2B")
	atk := attackerKey()
	icpA, icpB := a[:1], b[:1]
	aid := a[0].EventID
	w1 := w1KEL()[0].EventID
	ts1 := hubT0 + minute
	rot1A := rotEvent(ka[1], ka[2], ts1, ToadHub, "", false)
	enc := func(kel []SignedEvent) []byte { return mustMarshal(t, kel) }
	var cs []negCase
	add := func(name string, kel []byte, err string) { cs = append(cs, negCase{name, kel, err}) }

	// Pre-rotation and who signs (R-3, R-5; PoC of KEL §1.1 P1, P2).
	add("fork rot signed by the stolen prior key (PoC)", enc(extend(icpA,
		rotEvent(ka[1], atk, hubT0+10*365*24*60*minute, ToadHub, "", false), ka[0])),
		"identity: rot not signed by the key it reveals")
	add("dip revealing k1 but signed by the stolen k0", enc(extend(icpA, dipEvent(ka[1], ts1), ka[0])),
		"identity: dip not signed by the key it reveals")
	add("dip revealing the current key k0 (v0.2 dip)", enc(extend(icpA, dipEvent(ka[0], ts1), ka[0])),
		"identity: dip key does not match pre-committed digest")
	add("rot revealing a key nobody committed", enc(extend(icpA, rotEvent(atk, atk, ts1, ToadHub, "", false), atk)),
		"identity: rot key does not match pre-committed digest")
	add("rot signed by a stranger", enc(extend(icpA, rot1A, atk)),
		"identity: rot not signed by the key it reveals")
	add("icp not self-signed", enc([]SignedEvent{func() SignedEvent {
		se := signEvent(icpEvent(ka[0], ka[1], hubT0, ToadHub), atk)
		return se
	}()}), "identity: icp not self-signed by its key")

	// Event types (R-2).
	for _, typ := range []EventType{"ixn", "drt"} {
		e := KeyEvent{KELType: KELType, Type: typ, Keys: [][]byte{pubOf(ka[0])}, NextDigest: digestOf(ka[1]),
			Threshold: 1, Timestamp: ts1}
		add(string(typ)+" (removed in v0.3.0)", enc(extend(icpA, e, ka[0])),
			fmt.Sprintf("identity: unsupported event type %q", typ))
	}
	add("a second icp", enc(extend(icpA, icpEvent(ka[1], ka[2], ts1, ToadHub), ka[1])),
		`identity: unsupported event type "icp"`)
	add("first event a rot", enc([]SignedEvent{signEvent(rotEvent(ka[1], ka[2], ts1, ToadHub, "", false), ka[1])}),
		"identity: first event must be icp")

	// Timestamps (R-1, R-2).
	add("rot ts 0", enc(extend(icpA, rotEvent(ka[1], ka[2], 0, ToadHub, "", false), ka[1])),
		"identity: event ts must be greater than 0")
	add("rot ts equal to the previous event's", enc(extend(icpA, rotEvent(ka[1], ka[2], hubT0, ToadHub, "", false), ka[1])),
		"identity: event ts must be greater than the previous event's")
	add("rot ts before the previous event's", enc(extend(icpA, rotEvent(ka[1], ka[2], hubT0-1, ToadHub, "", false), ka[1])),
		"identity: event ts must be greater than the previous event's")
	add("icp ts 0", enc([]SignedEvent{signEvent(icpEvent(ka[0], ka[1], 0, ToadHub), ka[0])}),
		"identity: event ts must be greater than 0")

	// Witnesses and toad (R-1, R-3, R-4).
	add("rot clears the witness (truncates to witness pending)", enc(extend(b[:2],
		rotEvent(kb[2], kb[3], agentT0+2*minute, ToadAgent, "", false), kb[2])),
		"identity: rot of a toad-1 identity must name its witness")
	add("first rot of an agent names no witness", enc(extend(icpB,
		rotEvent(kb[1], kb[2], agentT0+minute, ToadAgent, "", false), kb[1])),
		"identity: rot of a toad-1 identity must name its witness")
	add("rot changes toad from 0 to 1", enc(extend(icpA, rotEvent(ka[1], ka[2], ts1, ToadAgent, "", false), ka[1])),
		"identity: rot changes toad")
	add("rot changes toad from 1 to 0", enc(extend(icpB, rotEvent(kb[1], kb[2], agentT0+minute, ToadHub, w1, false), kb[1])),
		"identity: rot changes toad")
	add("rot without toad", enc(extend(icpA, func() KeyEvent {
		e := rot1A
		e.Toad = nil
		return e
	}(), ka[1])), "identity: rot must carry toad")
	add("rot of a hub names a witness", enc(extend(icpA, rotEvent(ka[1], ka[2], ts1, ToadHub, w1, false), ka[1])),
		"identity: rot of a toad-0 identity must not carry witnesses")
	add("rot names two witnesses", enc(extend(icpB, func() KeyEvent {
		e := rotEvent(kb[1], kb[2], agentT0+minute, ToadAgent, w1, false)
		e.Witnesses = []string{w1, aid}
		return e
	}(), kb[1])), "identity: rot must name exactly one witness")
	add("rot names its own AID as witness", enc(extend(icpB,
		rotEvent(kb[1], kb[2], agentT0+minute, ToadAgent, b[0].EventID, false), kb[1])),
		"identity: rot names its own AID as witness")
	add("rot names an empty witness", enc(extend(icpB, func() KeyEvent {
		e := rotEvent(kb[1], kb[2], agentT0+minute, ToadAgent, w1, false)
		e.Witnesses = []string{""}
		return e
	}(), kb[1])), "identity: rot witness is empty")
	add("icp carries witnesses (key 9)", enc([]SignedEvent{signEvent(func() KeyEvent {
		e := icpEvent(kb[0], kb[1], agentT0, ToadAgent)
		e.Witnesses = []string{w1}
		return e
	}(), kb[0])}), "identity: icp must not carry witnesses")
	add("icp toad 2", enc([]SignedEvent{signEvent(icpEvent(ka[0], ka[1], hubT0, 2), ka[0])}),
		"identity: toad must be 0 or 1")
	add("icp without toad", enc([]SignedEvent{signEvent(func() KeyEvent {
		e := icpEvent(ka[0], ka[1], hubT0, ToadHub)
		e.Toad = nil
		return e
	}(), ka[0])}), "identity: icp must carry toad")
	add("icp carries emergency (key 12)", enc([]SignedEvent{signEvent(func() KeyEvent {
		e := icpEvent(ka[0], ka[1], hubT0, ToadHub)
		e.Emergency = true
		return e
	}(), ka[0])}), "identity: icp must not carry emergency")

	// dip (R-5).
	dipWith := func(f func(e *KeyEvent)) []byte {
		e := dipEvent(ka[1], ts1)
		f(&e)
		return enc(extend(icpA, e, ka[1]))
	}
	add("dip carries next (key 6)", dipWith(func(e *KeyEvent) { e.NextDigest = digestOf(ka[2]) }),
		"identity: dip must not carry next")
	add("dip carries emergency (key 12)", dipWith(func(e *KeyEvent) { e.Emergency = true }),
		"identity: dip must not carry emergency")
	add("dip carries toad (key 11)", dipWith(func(e *KeyEvent) { e.Toad = ToadField(ToadHub) }),
		"identity: dip must not carry toad")
	add("dip carries witnesses (key 9)", dipWith(func(e *KeyEvent) { e.Witnesses = []string{w1} }),
		"identity: dip must not carry witnesses")
	add("event after the dip", enc(extend(a, rotEvent(ka[3], ka[0], hubT0+4*minute, ToadHub, "", false), ka[3])),
		"identity: event after deactivation")

	// Shape (R-1, R-6).
	add("icp carries aid (key 1)", enc([]SignedEvent{signEvent(func() KeyEvent {
		e := icpEvent(ka[0], ka[1], hubT0, ToadHub)
		e.AID = aid
		return e
	}(), ka[0])}), "identity: icp must not carry aid or prev")
	add("icp seq 1", enc([]SignedEvent{signEvent(func() KeyEvent {
		e := icpEvent(ka[0], ka[1], hubT0, ToadHub)
		e.Seq = 1
		return e
	}(), ka[0])}), "identity: icp seq must be 0")
	add("icp without next (key 6)", enc([]SignedEvent{signEvent(func() KeyEvent {
		e := icpEvent(ka[0], ka[1], hubT0, ToadHub)
		e.NextDigest = nil
		return e
	}(), ka[0])}), "identity: icp needs a 32-byte next-key digest")
	add("rot next of 31 bytes", enc(extend(icpA, func() KeyEvent {
		e := rot1A
		e.NextDigest = e.NextDigest[:31]
		return e
	}(), ka[1])), "identity: rot needs a 32-byte next-key digest")
	add("rot kt 2", enc(extend(icpA, func() KeyEvent {
		e := rot1A
		e.Threshold = 2
		return e
	}(), ka[1])), "identity: kt must be 1")
	add("rot with two keys", enc(extend(icpA, func() KeyEvent {
		e := rot1A
		e.Keys = append(e.Keys, pubOf(atk))
		return e
	}(), ka[1])), "identity: rot needs exactly one 32-byte Ed25519 key")
	add("rot to a 31-byte key", enc(extend(icpA, func() KeyEvent {
		e := rot1A
		e.Keys = [][]byte{pubOf(ka[1])[:31]}
		return e
	}(), ka[1])), "identity: rot needs exactly one 32-byte Ed25519 key")
	add("icp with no key", enc([]SignedEvent{signEvent(func() KeyEvent {
		e := icpEvent(ka[0], ka[1], hubT0, ToadHub)
		e.Keys = [][]byte{}
		return e
	}(), ka[0])}), "identity: icp needs exactly one 32-byte Ed25519 key")

	// Linkage (R-2).
	add("rot names another AID", enc(append(clone(icpA), signEvent(func() KeyEvent {
		e := after(icpA, rot1A)
		e.AID = b[0].EventID
		return e
	}(), ka[1]))), "identity: event AID mismatch")
	add("rot skips a seq", enc(append(clone(icpA), signEvent(func() KeyEvent {
		e := after(icpA, rot1A)
		e.Seq = 2
		return e
	}(), ka[1]))), "identity: non-monotonic seq 2 after 0")
	add("rot links to another event", enc(append(clone(icpA), signEvent(func() KeyEvent {
		e := after(icpA, rot1A)
		e.Prev = b[0].EventID
		return e
	}(), ka[1]))), "identity: broken prev linkage")
	add("event_id is not the event's CID", enc(func() []SignedEvent {
		kel := extend(icpA, rot1A, ka[1])
		kel[1].EventID = b[0].EventID
		return kel
	}()), "identity: event_id is not the CID of the event")
	add("signature of 63 bytes", enc(func() []SignedEvent {
		kel := extend(icpA, rot1A, ka[1])
		kel[1].Sig = kel[1].Sig[:63]
		return kel
	}()), "identity: event signature is not 64 bytes")

	// Encoding (R-0). The head event's bytes are written by hand and signed as written, so
	// nothing but the encoding is wrong.
	rot1 := after(icpA, rot1A)
	m := rawMap(t, rot1)
	noKey0 := map[uint64]cbor.RawMessage{}
	for k, v := range m {
		if k != 0 {
			noKey0[k] = v
		}
	}
	add("rot without key 0", rawKEL(t, icpA, encodeMap(t, noKey0, sortedKeys(noKey0)), ka[1], nil), ErrKELv1.Error())
	icpNo0 := rawMap(t, icpEvent(ka[0], ka[1], hubT0, ToadHub))
	delete(icpNo0, 0)
	add("icp without key 0 (a v0.2 KEL)", rawKEL(t, nil, encodeMap(t, icpNo0, sortedKeys(icpNo0)), ka[0], nil),
		ErrKELv1.Error())
	wrong := func(tag string) []byte {
		e := rot1
		e.KELType = tag
		b, err := coredet.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		return rawKEL(t, icpA, b, ka[1], nil)
	}
	add(`key 0 is "anet.kel/1"`, wrong("anet.kel/1"), ErrKELv1.Error())
	add(`key 0 is "anet.kel/2 "`, wrong("anet.kel/2 "), ErrKELv1.Error())
	headBytes, err := coredet.Marshal(rot1)
	if err != nil {
		t.Fatal(err)
	}
	// with writes rot 1 with key k set to v. A new key is signed as written; another form of a key
	// the event already has is the same event, so it carries the canonical form's signature and id.
	with := func(k uint64, v []byte) []byte {
		mm := rawMap(t, rot1)
		_, same := mm[k]
		mm[k] = v
		b := encodeMap(t, mm, sortedKeys(mm))
		if same || k == 12 || k == 9 {
			return rawKELOver(t, icpA, b, headBytes, ka[1], nil)
		}
		return rawKEL(t, icpA, b, ka[1], nil)
	}
	add("key 12 written as false (same event, non-CoreDet bytes)", with(12, []byte{0xf4}), ErrNonCanonicalEvent.Error())
	add("key 9 written as an empty list (same event, non-CoreDet bytes)", with(9, []byte{0x80}), ErrNonCanonicalEvent.Error())
	add("key 1 written as an empty string (same event, non-CoreDet bytes)", func() []byte {
		icp := icpEvent(ka[0], ka[1], hubT0, ToadHub)
		canon, err := coredet.Marshal(icp)
		if err != nil {
			t.Fatal(err)
		}
		mm := rawMap(t, icp)
		mm[1] = []byte{0x60}
		return rawKELOver(t, nil, encodeMap(t, mm, sortedKeys(mm)), canon, ka[0], nil)
	}(), ErrNonCanonicalEvent.Error())
	add("keys out of order (same event, non-CoreDet bytes)", func() []byte {
		order := sortedKeys(m)
		order[7], order[8] = order[8], order[7]
		return rawKELOver(t, icpA, encodeMap(t, m, order), headBytes, ka[1], nil)
	}(), ErrNonCanonicalEvent.Error())
	add("seq written in two bytes (same event, non-CoreDet bytes)", with(2, []byte{0x18, 0x01}), ErrNonCanonicalEvent.Error())
	add("retired key 10 (revoked_since)", with(10, []byte{0x01}), errUnregisteredEventKey.Error())
	add("reserved key 13", with(13, []byte{0x01}), errUnregisteredEventKey.Error())
	add("key 64", with(64, []byte{0x01}), errUnregisteredEventKey.Error())
	add("signed event carries reserved key 4", rawKEL(t, icpA, headBytes, ka[1], []byte{1}), errUnregisteredSignedKey.Error())
	add("empty KEL", []byte{0x80}, "identity: empty KEL")
	return cs
}

// The KEL-2N cases each fail with their own fixed error text, through UnmarshalKEL and Replay.
func TestKEL2NCasesFailWithTheirText(t *testing.T) {
	for _, c := range negativeCases(t) {
		_, err := replayBytes(c.kel)
		if err == nil {
			t.Errorf("%s: replayed", c.name)
			continue
		}
		if err.Error() != c.err {
			t.Errorf("%s:\n got  %q\n want %q", c.name, err.Error(), c.err)
		}
	}
}

// R-0: a v0.2 KEL, whatever its events, does not replay, from bytes or in memory; there is no v1
// decoding path.
func TestKELv1IsNotAccepted(t *testing.T) {
	k := vecKeys("KEL-2A")
	v1 := KeyEvent{Type: Inception, Keys: [][]byte{pubOf(k[0])}, NextDigest: digestOf(k[1]), Threshold: 1}
	kel := []SignedEvent{signEvent(v1, k[0])}
	if _, err := replay(kel); !errors.Is(err, ErrKELv1) {
		t.Fatalf("a v1 icp in memory: %v", err)
	}
	// The v0.2 encoding: no key 0, no key 11, ts omitted when 0.
	m := rawMap(t, v1)
	delete(m, 0)
	delete(m, 8)
	if _, err := replayBytes(rawKEL(t, nil, encodeMap(t, m, sortedKeys(m)), k[0], nil)); !errors.Is(err, ErrKELv1) {
		t.Fatalf("a v1 icp from bytes: %v", err)
	}
	if ErrKELv1.Error() != "identity: KEL v1 (v0.2) is not accepted" {
		t.Fatalf("the fixed text of R-0 changed: %q", ErrKELv1)
	}
}

// R-0: the canonical check runs wherever a KeyEvent is decoded, not only in UnmarshalKEL.
func TestKeyEventDecodingIsStrictEverywhere(t *testing.T) {
	rot := after(kel2A()[:1], rotEvent(vecKeys("KEL-2A")[1], vecKeys("KEL-2A")[2], hubT0+minute, ToadHub, "", false))
	m := rawMap(t, rot)
	m[12] = []byte{0xf4}
	var e KeyEvent
	if err := coredet.Unmarshal(encodeMap(t, m, sortedKeys(m)), &e); !errors.Is(err, ErrNonCanonicalEvent) {
		t.Fatalf("coredet.Unmarshal of a non-canonical event: %v", err)
	}
	good, err := coredet.Marshal(rot)
	if err != nil {
		t.Fatal(err)
	}
	if err := coredet.Unmarshal(good, &e); err != nil {
		t.Fatalf("the canonical event: %v", err)
	}
	// The event decodes to the struct it was built from.
	back, err := coredet.Marshal(e)
	if err != nil || !bytes.Equal(back, good) {
		t.Fatalf("round trip: %x, %v", back, err)
	}
}

// The KEL-2A and KEL-2B prefixes are the valid cases: every one replays, from memory and from
// bytes, and ExtendsKEL accepts each longer one after each shorter one (P3).
func TestValidPrefixesReplayAndExtend(t *testing.T) {
	for name, kel := range map[string][]SignedEvent{"KEL-2A": kel2A(), "KEL-2B": kel2B()} {
		for n := 1; n <= len(kel); n++ {
			if _, err := replay(kel[:n]); err != nil {
				t.Fatalf("%s prefix %d: %v", name, n, err)
			}
			if _, err := replayBytes(mustMarshal(t, kel[:n])); err != nil {
				t.Fatalf("%s prefix %d from bytes: %v", name, n, err)
			}
			for m := 1; m <= n; m++ {
				if err := ExtendsKEL(kel[:m], kel[:n]); err != nil {
					t.Fatalf("%s: %d events do not extend %d: %v", name, n, m, err)
				}
				if m < n {
					if err := ExtendsKEL(kel[:n], kel[:m]); !errors.Is(err, ErrKELRollback) {
						t.Fatalf("%s: %d events accepted after %d: %v", name, m, n, err)
					}
				}
			}
		}
	}
}

// An agent's rot cannot drop its witness: the KEL would read as "witness pending" again, which only
// an icp may be (R-3, R-4; M6). Neither Replay nor ExtendsKEL takes it.
func TestRotCannotTruncateToWitnessPending(t *testing.T) {
	b, kb := kel2B(), vecKeys("KEL-2B")
	cleared := extend(b[:2], rotEvent(kb[2], kb[3], agentT0+2*minute, ToadAgent, "", false), kb[2])
	if _, err := Replay(cleared); err == nil {
		t.Fatal("a rot without a witness replayed after the witness was designated")
	}
	if err := ExtendsKEL(b[:2], cleared); err == nil {
		t.Fatal("ExtendsKEL took a rot back to witness pending")
	}
	states, err := Replay(b[:3])
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range states[1:] {
		if s.Witness == "" {
			t.Fatalf("state %d after the designation is witness pending", i+1)
		}
	}
}

// ---- PoC of the original review (KEL §7.4) ----------------------------------------------------

// The thief holds k0 and, once the owner's rot has made k1's public key known, mints a rot at the
// same seq revealing k1, committing to its own key, dated ten years ahead, signed with k0. Under
// KEL v1 it replayed, k0 objects verified under it for ten years, and the owner's KEL became a
// fork. Under v2 a rot is signed by the key it reveals, which the thief does not have.
func TestDuplicitousRotByStolenPriorKey(t *testing.T) {
	k := vecKeys("KEL-2A")
	atk := attackerKey()
	icp := kel2A()[:1]
	aid := icp[0].EventID
	owner := extend(icp, rotEvent(k[1], k[2], hubT0+minute, ToadHub, "", false), k[1])
	thief := extend(icp, rotEvent(k[1], atk, hubT0+10*365*24*60*minute, ToadHub, "", false), k[0])
	if _, err := Replay(thief); err == nil {
		t.Fatal("the thief's rot, signed by the stolen prior key, replayed")
	}
	obj := []byte("object signed with the stolen k0 a day after the rotation")
	if err := VerifyObject(thief, aid, 0, hubT0+24*60*minute, obj, ed25519.Sign(k[0], obj)); err == nil {
		t.Fatal("a k0 object verified under the thief's KEL")
	}
	if err := ExtendsKEL(icp, thief); err == nil {
		t.Fatal("a verifier holding the icp took the thief's KEL")
	}
	if err := ExtendsKEL(icp, owner); err != nil {
		t.Fatalf("the owner's rot: %v", err)
	}
	// Nor can the thief end the AID: a dip, too, is signed by the key it reveals.
	if _, err := Replay(extend(icp, dipEvent(k[1], hubT0+minute), k[0])); err == nil {
		t.Fatal("a dip signed with the stolen k0 replayed")
	}
	if _, err := Replay(extend(icp, dipEvent(k[0], hubT0+minute), k[0])); err == nil {
		t.Fatal("a v0.2 dip (k0 revealed and signing) replayed")
	}
}

// A key retired by a rot no longer verifies an object that carries no time (C-10 step 6). Under
// v1, msgTime 0 meant "unknown, so accept" for every state but the dip's.
func TestRetiredKeyWithZeroMsgTime(t *testing.T) {
	c, err := Incept()
	if err != nil {
		t.Fatal(err)
	}
	obj := []byte("object")
	sig0, seq0 := c.Sign(obj)
	if err := VerifyObject(c.KEL(), c.AID(), seq0, 0, obj, sig0); err != nil {
		t.Fatalf("the active key at msgTime 0: %v", err)
	}
	if err := c.Rotate(5000); err != nil {
		t.Fatal(err)
	}
	err = VerifyObject(c.KEL(), c.AID(), seq0, 0, obj, sig0)
	var ve *VErr
	if !errors.As(err, &ve) || ve.Reason != "REVOKED_KEY" {
		t.Fatalf("retired key state 0 at msgTime 0: %v, want REVOKED_KEY", err)
	}
}

// ---- C-10: VerifyObject -----------------------------------------------------------------------

func TestVerifyObjectOrder(t *testing.T) {
	a := kel2A()
	k := vecKeys("KEL-2A")
	aid := a[0].EventID
	obj := []byte("object")
	sign := func(i int) []byte { return ed25519.Sign(k[i], obj) }
	reason := func(err error) string {
		if err == nil {
			return ""
		}
		var ve *VErr
		if errors.As(err, &ve) {
			return ve.Reason
		}
		return err.Error()
	}
	broken := clone(a)
	broken[2].Sig = make([]byte, 64)
	cases := []struct {
		name    string
		kel     []SignedEvent
		aid     string
		seq     uint64
		msgTime uint64
		sig     []byte
		want    string
	}{
		{"KEL does not replay", broken, aid, 0, 1, sign(0), "UNKNOWN_AID"},
		{"another AID", a, kel2B()[0].EventID, 0, 1, sign(0), "UNKNOWN_AID"},
		{"seq beyond the KEL", a, aid, 4, 1, sign(0), "KEY_STATE_DOWNGRADE"},
		{"dip state, before the signature", a, aid, 3, 1, make([]byte, 64), "REVOKED_KEY"},
		{"dip state, signed by the revealed key", a, aid, 3, 1, sign(3), "REVOKED_KEY"},
		{"wrong signature at an active state", a[:2], aid, 1, 1, sign(0), "INVALID_SIGNATURE"},
		{"wrong signature at a retired state", a, aid, 0, hubT0 + 2*minute, sign(1), "INVALID_SIGNATURE"},
		{"active state, msgTime 0", a[:2], aid, 1, 0, sign(1), ""},
		{"active state, msgTime far ahead", a[:2], aid, 1, 1 << 62, sign(1), ""},
		{"retired state, msgTime 0", a, aid, 0, 0, sign(0), "REVOKED_KEY"},
		{"retired state, msgTime 1", a, aid, 0, 1, sign(0), ""},
		{"retired state, msgTime just before SupersededAt", a, aid, 0, hubT0 + minute - 1, sign(0), ""},
		{"retired state, msgTime = SupersededAt", a, aid, 0, hubT0 + minute, sign(0), "REVOKED_KEY"},
		{"retired state, msgTime after SupersededAt", a, aid, 0, hubT0 + minute + 1, sign(0), "REVOKED_KEY"},
		{"urgently retired state, before SupersededAt", a, aid, 2, hubDipTS - 1, sign(2), ""},
		{"urgently retired state, at SupersededAt", a, aid, 2, hubDipTS, sign(2), "REVOKED_KEY"},
	}
	for _, c := range cases {
		if got := reason(VerifyObject(c.kel, c.aid, c.seq, c.msgTime, obj, c.sig)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// P2: when VerifyObject accepts an object at msgTime t, it accepts it at every 0 < t' < t.
func TestVerifyObjectMonotoneInMsgTime(t *testing.T) {
	prev := SetReplayCache(NewReplayCache(1 << 22))
	defer SetReplayCache(prev)
	rng := rand.New(rand.NewSource(2))
	obj := []byte("object")
	for n := 0; n < 60; n++ {
		kel, keys := randomKEL(rng)
		aid := kel[0].EventID
		for seq := range kel {
			sig := ed25519.Sign(keys[seq], obj)
			for i := 0; i < 8; i++ {
				ts := kel[len(kel)-1].Event.Timestamp
				tm := uint64(rng.Int63n(int64(ts)+3*int64(minute))) + 1
				if VerifyObject(kel, aid, uint64(seq), tm, obj, sig) != nil {
					continue
				}
				for _, t2 := range []uint64{1, tm / 2, tm - 1, uint64(rng.Int63n(int64(tm))) + 1} {
					if t2 == 0 || t2 >= tm {
						continue
					}
					if err := VerifyObject(kel, aid, uint64(seq), t2, obj, sig); err != nil {
						t.Fatalf("seq %d accepted at %d but not at %d: %v", seq, tm, t2, err)
					}
				}
			}
		}
	}
}

// randomKEL is a valid KEL of random length, toad, emergencies and ending, with the private key
// of each state (for a dip state, the key it revealed).
func randomKEL(rng *rand.Rand) ([]SignedEvent, []ed25519.PrivateKey) {
	key := func() ed25519.PrivateKey {
		var s [32]byte
		rng.Read(s[:])
		return ed25519.NewKeyFromSeed(s[:])
	}
	toad := uint64(rng.Intn(2))
	keys := []ed25519.PrivateKey{key(), key()}
	ts := uint64(rng.Int63n(1<<40)) + 1
	kel := []SignedEvent{signEvent(icpEvent(keys[0], keys[1], ts, toad), keys[0])}
	n := rng.Intn(5)
	for i := 0; i < n; i++ {
		ts += uint64(rng.Int63n(int64(3*minute))) + 1
		rev := keys[len(keys)-1]
		if i == n-1 && rng.Intn(3) == 0 {
			kel = extend(kel, dipEvent(rev, ts), rev)
			break
		}
		next := key()
		w := ""
		if toad == ToadAgent {
			w = fmt.Sprintf("witness-%d", rng.Intn(3))
		}
		kel = extend(kel, rotEvent(rev, next, ts, toad, w, rng.Intn(3) == 0), rev)
		keys = append(keys, next)
	}
	return kel, keys[:len(kel)]
}

// ---- C-12: RetiredUsableAt (P6) ---------------------------------------------------------------

func TestRetiredUsableAt(t *testing.T) {
	const sup = hubT0 + minute
	planned := KeyState{Status: StatusRotated, SupersededAt: sup}
	urgent := KeyState{Status: StatusRotated, SupersededAt: sup, RetiredUrgently: true}
	cases := []struct {
		name    string
		ks      KeyState
		arrival uint64
		want    bool
	}{
		{"active, any arrival", KeyState{Status: StatusActive}, 1 << 63, true},
		{"active, arrival 0", KeyState{Status: StatusActive}, 0, true},
		{"planned, before SupersededAt", planned, sup - 1, true},
		{"planned, at SupersededAt + 1 h", planned, sup + RotationGrace, true},
		{"planned, 1 ms past the grace", planned, sup + RotationGrace + 1, false},
		{"urgent, before SupersededAt", urgent, sup - 1, true},
		{"urgent, at SupersededAt", urgent, sup, true},
		{"urgent, 1 ms after", urgent, sup + 1, false},
		{"the dip's own state", KeyState{Status: StatusDeactivated}, 0, false},
		{"the dip's own state, later", KeyState{Status: StatusDeactivated}, sup, false},
		{"planned near the top of uint64", KeyState{Status: StatusRotated, SupersededAt: ^uint64(0) - 10}, ^uint64(0), true},
	}
	for _, c := range cases {
		if got := RetiredUsableAt(c.ks, c.arrival); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if RotationGrace != 3600000 {
		t.Fatalf("RotationGrace %d ms, want 1 h", RotationGrace)
	}
	// The states Replay gives KEL-2A: k0 retired by a planned rot, k1 and k2 urgently.
	states, err := Replay(kel2A())
	if err != nil {
		t.Fatal(err)
	}
	if !RetiredUsableAt(states[0], hubT0+minute+RotationGrace) || RetiredUsableAt(states[0], hubT0+minute+RotationGrace+1) {
		t.Error("KEL-2A state 0 (planned rot): grace boundary")
	}
	if !RetiredUsableAt(states[1], hubT0+2*minute) || RetiredUsableAt(states[1], hubT0+2*minute+1) {
		t.Error("KEL-2A state 1 (emergency rot): zero grace")
	}
	if !RetiredUsableAt(states[2], hubDipTS) || RetiredUsableAt(states[2], hubDipTS+1) {
		t.Error("KEL-2A state 2 (dip): zero grace")
	}
}

// ---- C-4: CheckNewEvents (R-9, R-10) ----------------------------------------------------------

func TestCheckNewEvents(t *testing.T) {
	b := kel2B()
	w1 := w1KEL()[0].EventID
	rotTS := b[1].Event.Timestamp // rot 1, naming W1
	isW1 := func(e KeyEvent) bool { return len(e.Witnesses) == 1 && e.Witnesses[0] == w1 }
	cases := []struct {
		name  string
		old   []SignedEvent
		now   uint64
		first func(KeyEvent) bool
		want  error
	}{
		{"ts = now", b[:1], rotTS, isW1, nil},
		{"ts = now + 5 min", b[:1], rotTS - EventClockWindow, nil, nil},
		{"ts = now + 5 min + 1 ms", b[:1], rotTS - EventClockWindow - 1, nil, ErrEventFromFuture},
		{"from the future, at the witness too", b[:1], rotTS - EventClockWindow - 1, isW1, ErrEventFromFuture},
		{"witness: ts = now - 5 min", b[:1], rotTS + EventClockWindow, isW1, nil},
		{"witness: ts = now - 5 min - 1 ms", b[:1], rotTS + EventClockWindow + 1, isW1, ErrEventTooOld},
		{"another hub: an old event is fine", b[:1], rotTS + 24*60*minute, func(KeyEvent) bool { return false }, nil},
		{"nil isFirstWitness: an old event is fine", b[:1], rotTS + 24*60*minute, nil, nil},
		{"events already known are not checked", b[:2], rotTS + 24*60*minute, isW1, nil},
		{"nothing stored: the icp is new too", nil, b[0].Event.Timestamp - EventClockWindow - 1, nil, ErrEventFromFuture},
		{"a clock before the epoch window", b[:1], 1, nil, ErrEventFromFuture},
	}
	for _, c := range cases {
		err := CheckNewEvents(c.old, b[:2], c.now, c.first)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	// A dip's first witness is the hub the state before it names; the caller says so from the
	// replayed states.
	states, err := Replay(b)
	if err != nil {
		t.Fatal(err)
	}
	dipTS := b[3].Event.Timestamp
	w2 := states[2].Witness
	isDipWitness := func(e KeyEvent) bool { return e.Type == Deactivation && states[e.Seq-1].Witness == w2 }
	if err := CheckNewEvents(b[:3], b, dipTS+EventClockWindow+1, isDipWitness); !errors.Is(err, ErrEventTooOld) {
		t.Errorf("a late dip at its witness: %v", err)
	}
	if EventClockWindow != 5*minute {
		t.Fatalf("EventClockWindow %d", EventClockWindow)
	}
}

// ---- C-1: the v0.2 event types and delegated keys are gone ------------------------------------

// TestNoIxnDrtSymbols: no identifier of the package, in code or tests, is named after the v0.2
// interaction or delegation events or their delegated keys.
func TestNoIxnDrtSymbols(t *testing.T) {
	banned := map[string]bool{"Interaction": true, "Delegation": true, "Delegate": true, "DelegatedKeys": true}
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v %v", files, err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && banned[id.Name] {
				t.Errorf("%s: identifier %s (KEL C-1 deletes it)", fset.Position(id.Pos()), id.Name)
			}
			return true
		})
	}
}

// ---- Controller (interim, until KEL-2) ---------------------------------------------------------

// The interim Controller builds v2 events: its rot and dip are signed by the key they reveal, and
// it refuses a ts that does not follow the previous event's.
func TestControllerBuildsV2Events(t *testing.T) {
	c, err := Incept()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Rotate(1); err == nil {
		t.Fatal("a rot at the icp's ts was built")
	}
	if err := c.Rotate(2000); err != nil {
		t.Fatal(err)
	}
	if err := c.Rotate(3000); err != nil {
		t.Fatal(err)
	}
	if err := c.Deactivate(4000); err != nil {
		t.Fatal(err)
	}
	b := mustMarshal(t, c.KEL())
	states, err := replayBytes(b)
	if err != nil {
		t.Fatalf("the controller's KEL: %v", err)
	}
	if got := states[len(states)-1].Status; got != StatusDeactivated {
		t.Fatalf("head %s", got)
	}
	if !states[2].RetiredUrgently || states[1].RetiredUrgently {
		t.Fatalf("urgency %v %v", states[1].RetiredUrgently, states[2].RetiredUrgently)
	}
	if err := c.Rotate(5000); err == nil {
		t.Fatal("rotated after the dip")
	}
	s := SuiteController()
	if s.KEL()[0].Event.Timestamp != SuiteInceptionTS || *s.KEL()[0].Event.Toad != ToadHub {
		t.Fatalf("suite icp %+v", s.KEL()[0].Event)
	}
	if _, err := Replay(s.KEL()); err != nil {
		t.Fatal(err)
	}
}

// The source names no element of the v0.2 KEL in strings either where it would mean the type
// (a guard against reintroducing them through a constant).
func TestNoV1EventTypeStringsInCode(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []string{`"ixn"`, `"drt"`} {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("%s contains %s", f, s)
			}
		}
	}
}
