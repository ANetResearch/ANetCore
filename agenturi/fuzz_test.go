package agenturi

// Fuzz target for the agent:// canonical form (ANet docs/notes/0033).
//
// canonical(s) = serialize(parse(s)) is "the only form that may be signed, content-addressed,
// resolved, relayed, or compared", so it must be a fixed point: the canonical form of a
// canonical form is itself, and parses to the same value. Otherwise two parties that
// canonicalize a different number of times disagree on equality.

import (
	"reflect"
	"sort"
	"testing"
)

// comparable is v with the query pairs in canonical order: Parse keeps the input order and
// Serialize sorts, so the order is not part of the value.
func comparable(v *ParseValue) ParseValue {
	c := *v
	c.Query = append([]QPair(nil), v.Query...)
	sort.Slice(c.Query, func(i, j int) bool {
		return encLabel(c.Query[i].Key)+"="+encLabel(c.Query[i].Value) < encLabel(c.Query[j].Key)+"="+encLabel(c.Query[j].Value)
	})
	return c
}

func FuzzCanonical(f *testing.F) {
	for _, s := range []string{
		"agent://Acme/ns=Billing/svc=Pay/inst=1?b=2&a=1",
		"AGENT://%C3%9Fa/svc=x%2Fy",
		"agent://*/translate.zh-en",
		"agent://caf%C3%A9/inst=%CF%82",
		"agent://%E2%84%AA",      // TestKelvinSignFoldsToLowercaseK
		"agent://a/ns=%E2%80%8D", // TestLabelOfOnlyJoinersIsEmpty
		"agent://0?a%800=",       // TestQueryInvalidUTF8IsRejected
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := Parse(s)
		if err != nil {
			return
		}
		c := Serialize(v)
		v2, err := Parse(c)
		if err != nil {
			t.Fatalf("canonical form %q of %q does not parse: %v", c, s, err)
		}
		if c2 := Serialize(v2); c2 != c {
			t.Fatalf("canonical form is not a fixed point: %q -> %q -> %q", s, c, c2)
		}
		if !reflect.DeepEqual(comparable(v), comparable(v2)) {
			t.Fatalf("canonical form %q parses to %+v, the input %q to %+v", c, v2, s, v)
		}
		if eq, err := Equals(s, c); err != nil || !eq {
			t.Fatalf("%q is not Equals to its canonical form %q (%v)", s, c, err)
		}
	})
}
