package golden

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/ANetResearch/ANetCore/ael"
	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// supplyEpoch1 is the epoch SUPPLY-EPOCH-1 states: the liability tree of the golden vector LIAB-1,
// closed on its to_day, covering the week before.
func supplyEpoch1(t *testing.T) ael.SupplyEpoch {
	t.Helper()
	b, err := os.ReadFile("../liabtree/testdata/vec-liab-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Build struct {
			ToDay       uint64 `json:"to_day"`
			Depth       int    `json:"depth"`
			Root        string `json:"root"`
			Outstanding uint64 `json:"outstanding"`
		} `json:"build"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	p := ael.SupplyEpoch{FromDay: v.Build.ToDay - 6, ToDay: v.Build.ToDay, Outstanding: v.Build.Outstanding, Depth: v.Build.Depth}
	root, err := hex.DecodeString(v.Build.Root)
	if err != nil || len(root) != 32 {
		t.Fatalf("LIAB-1 root %q", v.Build.Root)
	}
	copy(p.Root[:], root)
	return p
}

// SUPPLY-EPOCH-1: the ael anet.supply.epoch record (VersionMajor2) a hub publishes, signed by the
// hub (here the conformance identity, a toad-0 identity like a hub's): its bytes, id and signature,
// pinned; and a payload with any member beyond the six is refused even under a good signature
// (HPP §2.3). golden/py/test_gen_v016.py (hpp_go_pins) checks the pinned bytes against the
// independent encoder.
func TestSUPPLY_EPOCH_1(t *testing.T) {
	c := identity.SuiteController()
	p := supplyEpoch1(t)
	rec, err := ael.SupplyEpochRecord(c.AID(), p)
	if err != nil {
		t.Fatal(err)
	}
	rec.Seq, rec.PrevID = 0, ael.GenesisPrev()
	rec.Timestamp = int64(p.ToDay+1) * 86_400_000 // published at the UTC midnight that closes the epoch
	if err := rec.Sign(c); err != nil {
		t.Fatal(err)
	}
	pre, err := rec.Preimage()
	if err != nil {
		t.Fatal(err)
	}
	const wantPreimage = "a901783b62616679726569687134326a3765736c6a6a3564727867696575646832617234677373706f6770656a6d64786d67346e657a6661337477646d6b65020003783b626166797265696669323364336772773735626d326f783773736a336671336d7274777879623634366f6a7a6162616b7563667066353237636c6d0471616e65742e737570706c792e65706f6368050206a661760264726f6f747840303663633737643134353430653833613639363232636462376136653462333962636237336164666163363137383562333635303936646539303665333736336564657074680466746f5f646179194fe66866726f6d5f646179194fe06b6f75747374616e64696e671a000f61d1071b0000019b7c01040008783b62616679726569687134326a3765736c6a6a3564727867696575646832617234677373706f6770656a6d64786d67346e657a6661337477646d6b650900"
	if got := hex.EncodeToString(pre); got != wantPreimage {
		t.Errorf("record preimage\n got  %s\n want %s", got, wantPreimage)
	}
	if rec.ID != anetcid.MustSum(pre) {
		t.Errorf("id %s is not the CID of the preimage", rec.ID)
	}
	const wantSig = "447ea340bff1ca178dec61ae04bc70683c6923e4a617fd715438ca344b2c465fa6986d8da857c6a8d0360e7334630a7735e3f019794f01dbeeaf58e20e638201"
	if got := hex.EncodeToString(rec.Sig); got != wantSig {
		t.Errorf("signature\n got  %s\n want %s", got, wantSig)
	}
	wire, err := coredet.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	const wantWire = "ab01783b62616679726569687134326a3765736c6a6a3564727867696575646832617234677373706f6770656a6d64786d67346e657a6661337477646d6b65020003783b626166797265696669323364336772773735626d326f783773736a336671336d7274777879623634366f6a7a6162616b7563667066353237636c6d0471616e65742e737570706c792e65706f6368050206a661760264726f6f747840303663633737643134353430653833613639363232636462376136653462333962636237336164666163363137383562333635303936646539303665333736336564657074680466746f5f646179194fe66866726f6d5f646179194fe06b6f75747374616e64696e671a000f61d1071b0000019b7c01040008783b62616679726569687134326a3765736c6a6a3564727867696575646832617234677373706f6770656a6d64786d67346e657a6661337477646d6b6509000b783b62616679726569646776706b767033346e62757176376f69656d716a637536773373783262696d78797468786f6d706d68366e6c696e776a706e690c5840447ea340bff1ca178dec61ae04bc70683c6923e4a617fd715438ca344b2c465fa6986d8da857c6a8d0360e7334630a7735e3f019794f01dbeeaf58e20e638201"
	if got := hex.EncodeToString(wire); got != wantWire {
		t.Errorf("record as it travels\n got  %s\n want %s", got, wantWire)
	}
	back, err := ael.UnmarshalEventRecord(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Verify(c.KEL()); err != nil {
		t.Fatalf("the record must verify: %v", err)
	}
	if got, err := ael.ParseSupplyEpoch(back); err != nil || *got != p {
		t.Fatalf("parse: %+v, %v", got, err)
	}

	// A payload with a seventh member — an AID — signed by the same hub: the signature verifies, the
	// record is refused.
	bad := *back
	m := back.Payload.(map[any]any)
	extra := map[any]any{"aid": "bafyreiaccount"}
	for k, v := range m {
		extra[k] = v
	}
	bad.Payload = extra
	if err := bad.Sign(c); err != nil {
		t.Fatal(err)
	}
	if err := bad.Verify(c.KEL()); err != nil {
		t.Fatalf("the extra member is signed: %v", err)
	}
	if _, err := ael.ParseSupplyEpoch(&bad); !errors.Is(err, ael.ErrSupplyEpoch) {
		t.Fatalf("a payload with an AID: want ErrSupplyEpoch, got %v", err)
	}
	// And the other departures from the one form.
	for name, edit := range map[string]func(r *ael.EventRecord){
		"another event type": func(r *ael.EventRecord) { r.EventType = "anet.credit.issued" },
		"version 1":          func(r *ael.EventRecord) { r.VersionMajor = 1 },
		"no depth": func(r *ael.EventRecord) {
			q := map[any]any{}
			for k, v := range m {
				if k != "depth" {
					q[k] = v
				}
			}
			r.Payload = q
		},
	} {
		r := *back
		edit(&r)
		if _, err := ael.ParseSupplyEpoch(&r); !errors.Is(err, ael.ErrSupplyEpoch) {
			t.Errorf("%s: want ErrSupplyEpoch, got %v", name, err)
		}
	}
}
