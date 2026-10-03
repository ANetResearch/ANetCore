package wire_test

import (
	"testing"

	"github.com/ANetResearch/ANetCore/wire"
)

// FuzzParseRegistry: Parse never panics, and a register it accepts is indexed consistently: every
// key number of every object resolves to its entry and every label to its row.
func FuzzParseRegistry(f *testing.F) {
	f.Add(wire.RegistryJSON())
	f.Add([]byte(`{"format":"anet-wire-registry/1","objects":[{"name":"X","keys":[{"n":1,"to":3,"status":"reserved"}]}]}`))
	f.Add([]byte(`{"format":"anet-wire-registry/1","tags":[{"id":"L1","values":["a","a"]}]}`))
	f.Add([]byte(`{"format":"x"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := wire.Parse(b)
		if err != nil {
			return
		}
		for _, o := range r.Objects {
			if r.Object(o.Name) != o {
				t.Fatalf("object %q not indexed", o.Name)
			}
			for _, k := range o.Keys {
				for n := k.N; n <= k.Last(); n++ {
					if o.Key(n) != k {
						t.Fatalf("%s key %d not indexed", o.Name, n)
					}
				}
			}
		}
		for _, tg := range r.Tags {
			for _, v := range tg.Values {
				if r.Tag(v) != tg {
					t.Fatalf("label %q not indexed", v)
				}
			}
		}
	})
}

// FuzzParseTransition: ParseTransition never panics and accepts only well-formed entries.
func FuzzParseTransition(f *testing.F) {
	f.Add([]byte(`{"about":"x","entries":[{"todo":"v030-todo(FS-1)","repo":"ANetCore","kind":"string","value":"anet.x/1"}]}`))
	f.Add([]byte(`{"entries":[{"todo":"v030-todo(KEL-8a)","repo":"ANet","kind":"struct","go":"a.B","keys":["1 A string"]}]}`))
	f.Add([]byte(`{"entries":[{"todo":"todo","repo":"ANet","kind":"struct"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		tr, err := wire.ParseTransition(b)
		if err != nil {
			return
		}
		for _, e := range tr.Entries {
			if !wire.TodoPattern.MatchString(e.Todo) {
				t.Fatalf("accepted todo %q", e.Todo)
			}
		}
	})
}
