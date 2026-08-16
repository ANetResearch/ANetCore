// Package golden verifies the v3 foundation (coredet, anetcid, aobj) against the
// frozen golden vectors in design3/spec/_CONVENTIONS §8 and the spec object vectors.
// These tests are the same oracle as design3/tools/vectors.py: byte-for-byte agreement
// proves the Go implementation realizes the spec's deterministic encoding and CID.
package golden

import (
	"encoding/hex"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
)

// VEC-AET-CID-1 (design3/spec/aet-spec.md §6.1): the AET preimage and CID must
// reproduce byte-for-byte. Object: {1:{1:1}, 4:[{1:"s1", 3:"do x"}]}.
func TestVEC_AET_CID_1(t *testing.T) {
	obj := map[uint64]any{
		1: map[uint64]any{1: uint64(1)},
		4: []any{map[uint64]any{1: "s1", 3: "do x"}},
	}
	pre, err := coredet.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const wantHex = "a201a101010481a2016273310364646f2078"
	if got := hex.EncodeToString(pre); got != wantHex {
		t.Fatalf("preimage_hex\n got  %s\n want %s", got, wantHex)
	}
	const wantCID = "bafyreibgtk5ei4nbd2vho4ty7ws3z3ovqq243iu2pcjixu7bgdvqz67wdm"
	if got := anetcid.MustSum(pre); got != wantCID {
		t.Fatalf("CID\n got  %s\n want %s", got, wantCID)
	}
}

// VEC-TSIR-CID-1 (design3/spec/tsir-spec.md §6.1): TaskDoc preimage + CID.
// Object: {1:{1:1}, 4:[{1:"t1", 10:{3:"do x"}}]}.
func TestVEC_TSIR_CID_1(t *testing.T) {
	obj := map[uint64]any{
		1: map[uint64]any{1: uint64(1)},
		4: []any{map[uint64]any{1: "t1", 10: map[uint64]any{3: "do x"}}},
	}
	pre, err := coredet.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const wantHex = "a201a101010481a2016274310aa10364646f2078"
	if got := hex.EncodeToString(pre); got != wantHex {
		t.Fatalf("preimage_hex\n got  %s\n want %s", got, wantHex)
	}
	const wantCID = "bafyreif46dhnfcecy7fapphwd5y5fqht3c454h24haarppz6g2ez44qafq"
	if got := anetcid.MustSum(pre); got != wantCID {
		t.Fatalf("CID\n got  %s\n want %s", got, wantCID)
	}
}

// Suite test key (design3/spec/_CONVENTIONS §8): public key must match.
func TestSuiteKey(t *testing.T) {
	const wantPub = "ae5ec9a111f7af2b7981b4d5afc401ce41dac0c3ce1b70429b2b85ba071e802e"
	if got := hex.EncodeToString(aobj.SuitePub); got != wantPub {
		t.Fatalf("suite pub\n got  %s\n want %s", got, wantPub)
	}
	const wantSeed = "4700ce56fd7bd46d6523e5c2360f22151120678c42b0b18b2fe215f3d1b9d170"
	if got := hex.EncodeToString(aobj.SuiteSeed()); got != wantSeed {
		t.Fatalf("suite seed\n got  %s\n want %s", got, wantSeed)
	}
}

// AObj sign/verify round-trip + tamper rejection + 64-byte enforcement.
func TestAObjSignVerify(t *testing.T) {
	pre := []byte("agent-network v3")
	sig := aobj.SuiteSign(pre)
	if len(sig) != 64 {
		t.Fatalf("sig len = %d, want 64", len(sig))
	}
	if err := aobj.Verify(aobj.SuitePub, pre, sig); err != nil {
		t.Fatalf("verify good sig: %v", err)
	}
	if err := aobj.Verify(aobj.SuitePub, []byte("tampered"), sig); err == nil {
		t.Fatal("verify tampered preimage: want error, got nil")
	}
	if err := aobj.Verify(aobj.SuitePub, pre, sig[:63]); err == nil {
		t.Fatal("verify short sig: want error, got nil")
	}
}
