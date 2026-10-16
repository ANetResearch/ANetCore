// a2a_wire_test.go pins the one wire object of ANetCore v0.15.0 that 0.3.0 carries unchanged: the
// anet.status/1 body (VEC_STATUS_1). The v0.15.0 vectors of the other bodies (VEC_CHATMSG_2,
// VEC_DELEGATE_2, VEC_RESULT_2) are retired: body v3 replaced them with CHATMSG-3, DELEGATE-3 and
// RESULT-3 (a2a_wire_v3_test.go). The relay v2 authentication it also pinned (VEC_RELAYAUTH_2) is
// retired: RELAYAUTH-3 (relayauth_v3_test.go) pins the same preimage form for every action.
//
// Every vector here populates every field of its type: a vector over a partly filled object
// cannot detect a field that one implementation encodes and another drops.
package golden

import (
	"encoding/hex"
	"reflect"
	"sort"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/delegation"
)

// goldenMetadata is the JSON object used for every Metadata field below. It carries the reserved
// service-parameter key so the vector exercises a realistic value.
const goldenMetadata = `{"a2a.serviceParameters":{"A2A-Version":"1.0"}}`

// topLevelKeys decodes b as an integer-keyed map and returns its keys in ascending order. The
// vectors assert this set so that a vector which silently stopped populating a field fails with
// the key named, not only with a changed hash.
func topLevelKeys(t *testing.T, b []byte) []uint64 {
	t.Helper()
	var raw map[uint64]any
	if err := coredet.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	ks := make([]uint64, 0, len(raw))
	for k := range raw {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i] < ks[j] })
	return ks
}

func assertKeys(t *testing.T, what string, b []byte, want []uint64) {
	t.Helper()
	if got := topLevelKeys(t, b); !reflect.DeepEqual(got, want) {
		t.Errorf("%s keys %v, want %v — a field is missing or moved", what, got, want)
	}
}

// goldenAttachments is one attachment whose CID is the raw CID of its bytes, checked here so the
// vectors stay self-consistent.
func goldenAttachments(t *testing.T) []delegation.Attachment {
	t.Helper()
	a := delegation.Attachment{
		Name: "a.txt", Mime: "text/plain", Size: 3,
		CID: "bafkreif2pall7dybz7vecqka3zo24irdwabwdi4wc55jznaq75q7eaavvu", Data: []byte("abc"),
	}
	if got, err := anetcid.SumRaw(a.Data); err != nil || got != a.CID {
		t.Fatalf("golden attachment CID %s does not match its bytes (%s, %v)", a.CID, got, err)
	}
	return []delegation.Attachment{a}
}

// VEC-STATUS-1: the anet.status/1 body, every field populated.
func TestVEC_STATUS_1(t *testing.T) {
	m := &delegation.StatusMsg{
		State:    delegation.StateInputRequired,
		Text:     "need the source file",
		Metadata: []byte(goldenMetadata),
		At:       1767225600000,
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, "status", b, []uint64{1, 2, 3, 4})
	// Cross-checked against an independent deterministic-CBOR encoder (Python, RFC 8949 §4.2.1).
	const wantWire = "a4016e696e7075742d726571756972656402746e6565642074686520736f757263652066696c6503582f7b226132612e73657276696365506172616d6574657273223a7b224132412d56657273696f6e223a22312e30227d7d041b0000019b76daa800"
	if got := hex.EncodeToString(b); got != wantWire {
		t.Fatalf("status wire\n got  %s\n want %s", got, wantWire)
	}
	back, err := delegation.UnmarshalStatusMsg(b)
	if err != nil || !reflect.DeepEqual(back, m) {
		t.Errorf("status did not round-trip: %+v, %v", back, err)
	}
}
