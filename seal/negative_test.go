package seal

import (
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/wire"
	"github.com/fxamacker/cbor/v2"
)

// CORE-S4: for each object this package decodes, every key 0-63 the registry does not assign
// (and, for the closed Access, Cap, CapBody, Grant and RK, keys 64 and 65535 as well), inserted
// into a valid encoding, is refused by the object's own decoder.
func TestRegistryNegatives(t *testing.T) {
	reg := wire.MustLoad()
	a, b := newParty(t), newParty(t)
	in := innerFrom(t, a, b, t0)
	in.Grant, in.RK = testGrant, &RK{Suite: SuiteX25519, Pub: make([]byte, 32)}
	env := mustSeal(t, in, &b.kp.Public, a.c.Sign)
	capV := &Cap{Body: []byte("cap body"), Sig: make([]byte, SigLen)}
	accessV := &Access{Kind: AccessKindCap, Cap: capV, Proof: make([]byte, SigLen)}
	mustEnc := func(v any) []byte {
		t.Helper()
		b, err := coredet.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// A CapBody and a Grant with every key they may carry.
	gs := newGrantScene()
	gs.p2p, gs.pay = strp("192.0.2.1:1"), boolp(true)
	full := gs.grantBytes(t)
	one := newGrantScene()
	one.ix = strp(one.inIX)
	capBody, err := gs.body.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range [][]byte{full, one.grantBytes(t)} {
		if _, _, err := CheckGrant(&SealedInner{From: gs.from, IX: gs.inIX, Grant: g}, &gs.keys, gs.now); err != nil {
			t.Fatalf("the base grant is refused: %v", err)
		}
	}
	// Key 4 goes with neither 5 nor 6, so the grant negatives start from the grant with 5 and 6;
	// the one-shot grant shows key 4 is accepted on its own.
	grant := full
	inAccess := func(capBytes []byte) []byte {
		m := fieldMap{1: enc(t, AccessKindCap), 2: capBytes, 3: enc(t, make([]byte, SigLen))}
		return mustMarshalFields(t, m)
	}
	cases := []struct {
		object string
		valid  []byte
		decode func([]byte) error
	}{
		{"SealedEnvelope", env, func(b []byte) error { _, err := ParseOuter(b); return err }},
		{"Access", mustEnc(accessV), func(b []byte) error { _, err := decodeAccess(b); return err }},
		{"Cap", mustEnc(capV), func(b []byte) error { _, err := decodeAccess(inAccess(b)); return err }},
		{"Wrap", openLayer1(t, env, b.kp), func(b []byte) error { _, err := decodeWrap(b); return err }},
		{"SealedInner", mustMarshalFields(t, decryptFields(t, env, b.kp)), func(b []byte) error { _, _, err := decodeInner(b); return err }},
		{"RK", mustEnc(in.RK), func(b []byte) error { _, err := decodeRK(cbor.RawMessage(b)); return err }},
		{"CapBody", capBody, func(b []byte) error { _, err := UnmarshalCapBody(b); return err }},
		{"Grant", grant, func(b []byte) error { _, err := UnmarshalGrant(b); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.object, func(t *testing.T) {
			if err := tc.decode(tc.valid); err != nil {
				t.Fatalf("the valid encoding is refused: %v", err)
			}
			negs, err := wire.Negatives(reg, tc.object, tc.valid)
			if err != nil {
				t.Fatal(err)
			}
			if len(negs) == 0 {
				t.Fatal("no negatives")
			}
			for _, n := range negs {
				if tc.decode(n.Bytes) == nil {
					t.Errorf("%s with key %d (%s) is accepted", tc.object, n.Key, n.Why)
				}
			}
		})
	}
}
