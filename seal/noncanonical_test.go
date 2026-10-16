package seal

import (
	"bytes"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
)

// rawIndefMap writes fields as an indefinite-length map, keys ascending or descending.
func rawIndefMap(fields fieldMap, descending bool) []byte {
	var keys []uint64
	for k := range fields {
		keys = append(keys, k)
	}
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if (keys[j] > keys[i]) == descending {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	out := []byte{0xbf}
	for _, k := range keys {
		kb, _ := coredet.Marshal(k)
		out = append(out, kb...)
		out = append(out, fields[k]...)
	}
	return append(out, 0xff)
}

// TestOuterRefusesNonCanonicalEncodings: the outer envelope has one spelling (CORE-E2/G4). An
// indefinite-length map, either key order, and a non-shortest integer all decoded before, and
// EnvDigest was unchanged by the first two, so a third party could re-spell a sealed message.
func TestOuterRefusesNonCanonicalEncodings(t *testing.T) {
	a, b := newParty(t), newParty(t)
	env := mustSeal(t, innerFrom(t, a, b, t0), &b.kp.Public, a.c.Sign)
	f, err := decodeFields(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOuter(env); err != nil {
		t.Fatalf("canonical envelope refused: %v", err)
	}
	longV := fieldMap{}
	for k, v := range f {
		longV[k] = v
	}
	longV[outerKeyV] = []byte{0x18, 0x02}
	for name, v := range map[string][]byte{
		"indefinite ascending":  rawIndefMap(f, false),
		"indefinite descending": rawIndefMap(f, true),
		"non-shortest v":        rawIndefMap(longV, false),
	} {
		if bytes.Equal(v, env) {
			t.Fatalf("%s: test bug, same bytes", name)
		}
		if _, err := ParseOuter(v); err == nil {
			t.Errorf("%s: ParseOuter accepted it", name)
		}
		if _, err := EnvDigest(v); err == nil {
			t.Errorf("%s: EnvDigest accepted it", name)
		}
		if _, err := Open(v, b.aid(), b.ring(), nil); err == nil {
			t.Errorf("%s: Open accepted it", name)
		}
	}
}
