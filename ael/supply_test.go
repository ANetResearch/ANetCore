package ael

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

func testEpoch() SupplyEpoch {
	var root [32]byte
	for i := range root {
		root[i] = byte(i * 7)
	}
	return SupplyEpoch{FromDay: 20450, ToDay: 20456, Root: root, Outstanding: 123456, Depth: 4}
}

func signedEpoch(t testing.TB, c *identity.Controller, p SupplyEpoch) *EventRecord {
	t.Helper()
	rec, err := SupplyEpochRecord(c.AID(), p)
	if err != nil {
		t.Fatal(err)
	}
	rec.Seq, rec.PrevID, rec.Timestamp = 0, GenesisPrev(), 1767225600000
	if err := rec.Sign(c); err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestASupplyEpochRecordSurvivesTheWire(t *testing.T) {
	c := identity.SuiteController()
	rec := signedEpoch(t, c, testEpoch())
	raw, err := coredet.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalEventRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Verify(c.KEL()); err != nil {
		t.Fatalf("a signed epoch must verify after the wire: %v", err)
	}
	p, err := ParseSupplyEpoch(back)
	if err != nil || *p != testEpoch() {
		t.Fatalf("parse after the wire: %+v, %v", p, err)
	}
	// And straight from the record that was built, before any wire.
	if p, err := ParseSupplyEpoch(rec); err != nil || *p != testEpoch() {
		t.Fatalf("parse of the built record: %+v, %v", p, err)
	}
	// A ledger takes it as the genesis of the hub's chain.
	if err := NewLedger().Append(back, c.KEL()); err != nil {
		t.Fatalf("ledger append: %v", err)
	}
}

func TestSupplyEpochRecordRefusesWhatItCannotState(t *testing.T) {
	for name, edit := range map[string]func(*SupplyEpoch){
		"from after to":    func(p *SupplyEpoch) { p.FromDay = p.ToDay + 1 },
		"outstanding 2^63": func(p *SupplyEpoch) { p.Outstanding = 1 << 63 },
		"depth 3":          func(p *SupplyEpoch) { p.Depth = 3 },
		"depth 33":         func(p *SupplyEpoch) { p.Depth = 33 },
		"depth negative":   func(p *SupplyEpoch) { p.Depth = -4 },
	} {
		p := testEpoch()
		edit(&p)
		if _, err := SupplyEpochRecord("bafyreihub", p); !errors.Is(err, ErrSupplyEpoch) {
			t.Errorf("%s: want ErrSupplyEpoch, got %v", name, err)
		}
	}
	if _, err := SupplyEpochRecord("", testEpoch()); !errors.Is(err, ErrSupplyEpoch) {
		t.Errorf("no hub: %v", err)
	}
	p := testEpoch()
	p.FromDay, p.Depth, p.Outstanding = p.ToDay, SupplyMaxDepth, MaxOutstanding
	if _, err := SupplyEpochRecord("bafyreihub", p); err != nil {
		t.Errorf("the edges are in range: %v", err)
	}
}

// The payload says the six things and nothing else (HPP §2.3): a member more — an AID, an amount,
// a count — is refused, as is any other departure from its one form.
func TestParseSupplyEpochIsStrict(t *testing.T) {
	good := func() map[string]any {
		return map[string]any{"v": uint64(2), "from_day": uint64(20450), "to_day": uint64(20456),
			"root": strings.Repeat("ab", 32), "outstanding": uint64(5), "depth": uint64(4)}
	}
	rec := func(payload any) *EventRecord {
		return &EventRecord{ChainDID: "bafyreihub", EventType: EvSupplyEpoch, VersionMajor: VersionMajor2, Payload: payload}
	}
	if _, err := ParseSupplyEpoch(rec(good())); err != nil {
		t.Fatalf("the good payload: %v", err)
	}
	payloads := map[string]func(m map[string]any){
		"an aid":                 func(m map[string]any) { m["aid"] = "bafyreiaccount" },
		"an issued count":        func(m map[string]any) { m["issued"] = uint64(9) },
		"no root":                func(m map[string]any) { delete(m, "root") },
		"no from_day":            func(m map[string]any) { delete(m, "from_day") },
		"no outstanding":         func(m map[string]any) { delete(m, "outstanding") },
		"no v":                   func(m map[string]any) { delete(m, "v") },
		"v 1":                    func(m map[string]any) { m["v"] = uint64(1) },
		"v as text":              func(m map[string]any) { m["v"] = "2" },
		"from_day negative":      func(m map[string]any) { m["from_day"] = int64(-1) },
		"to_day before from":     func(m map[string]any) { m["to_day"] = uint64(20449) },
		"root upper case":        func(m map[string]any) { m["root"] = strings.Repeat("AB", 32) },
		"root 62 digits":         func(m map[string]any) { m["root"] = strings.Repeat("ab", 31) },
		"root not hex":           func(m map[string]any) { m["root"] = strings.Repeat("zz", 32) },
		"root as bytes":          func(m map[string]any) { m["root"] = bytes.Repeat([]byte{0xab}, 32) },
		"outstanding 2^63":       func(m map[string]any) { m["outstanding"] = uint64(1 << 63) },
		"outstanding as a float": func(m map[string]any) { m["outstanding"] = 5.0 },
		"depth 3":                func(m map[string]any) { m["depth"] = uint64(3) },
		"depth 2^40":             func(m map[string]any) { m["depth"] = uint64(1 << 40) },
	}
	for name, edit := range payloads {
		m := good()
		edit(m)
		if _, err := ParseSupplyEpoch(rec(m)); !errors.Is(err, ErrSupplyEpoch) {
			t.Errorf("%s: want ErrSupplyEpoch, got %v", name, err)
		}
	}
	for name, r := range map[string]*EventRecord{
		"another event type": {ChainDID: "bafyreihub", EventType: "anet.credit.issued", VersionMajor: VersionMajor2, Payload: good()},
		"version 1":          {ChainDID: "bafyreihub", EventType: EvSupplyEpoch, VersionMajor: 1, Payload: good()},
		"minor version 1":    {ChainDID: "bafyreihub", EventType: EvSupplyEpoch, VersionMajor: VersionMajor2, VersionMinor: 1, Payload: good()},
		"no chain":           {EventType: EvSupplyEpoch, VersionMajor: VersionMajor2, Payload: good()},
		"critical extension": {ChainDID: "bafyreihub", EventType: EvSupplyEpoch, VersionMajor: VersionMajor2, Payload: good(), CriticalExtensions: []string{"x"}},
		"correlation id":     {ChainDID: "bafyreihub", EventType: EvSupplyEpoch, VersionMajor: VersionMajor2, Payload: good(), CorrID: "c"},
		"integer-keyed map":  rec(map[uint64]any{1: uint64(2)}),
		"a list":             rec([]any{uint64(2)}),
		"no payload":         rec(nil),
		"nil record":         nil,
	} {
		if _, err := ParseSupplyEpoch(r); !errors.Is(err, ErrSupplyEpoch) {
			t.Errorf("%s: want ErrSupplyEpoch, got %v", name, err)
		}
	}
}

func TestUnmarshalEventRecordIsStrict(t *testing.T) {
	c := identity.SuiteController()
	raw, err := coredet.Marshal(signedEpoch(t, c, testEpoch()))
	if err != nil {
		t.Fatal(err)
	}
	var m map[uint64]any
	if err := coredet.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m[15] = uint64(1)
	extra, _ := coredet.Marshal(m)
	for name, b := range map[string][]byte{
		"key 15":        extra,
		"null":          {0xf6},
		"empty":         nil,
		"trailing byte": append(bytes.Clone(raw), 0),
	} {
		if _, err := UnmarshalEventRecord(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// FuzzSupplyEpoch: a record that decodes and parses states exactly what SupplyEpochRecord would
// write for the values read back.
func FuzzSupplyEpoch(f *testing.F) {
	c := identity.SuiteController()
	raw, err := coredet.Marshal(signedEpoch(f, c, testEpoch()))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, b []byte) {
		rec, err := UnmarshalEventRecord(b)
		if err != nil {
			return
		}
		if back, err := coredet.Marshal(rec); err != nil || !bytes.Equal(back, b) {
			t.Fatalf("accepted record re-encodes differently (%v)", err)
		}
		p, err := ParseSupplyEpoch(rec)
		if err != nil {
			return
		}
		again, err := SupplyEpochRecord(rec.ChainDID, *p)
		if err != nil {
			t.Fatalf("parsed epoch %+v does not build: %v", p, err)
		}
		want, _ := coredet.Marshal(again.Payload)
		got, _ := coredet.Marshal(rec.Payload)
		if !bytes.Equal(want, got) {
			t.Fatalf("parsed epoch states %x, the record %x", want, got)
		}
		_ = rec.Verify(c.KEL())
	})
}
