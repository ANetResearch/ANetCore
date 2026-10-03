package scan_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/wire"
	"github.com/ANetResearch/ANetCore/wire/scan"
)

// The fixture module in testdata/fx is a small repository with its own registry and transition
// list. Each case copies it, makes one edit and checks the scan reports exactly what that edit
// broke. The first six cases are CORE-S8's mutations.

type edit struct {
	path     string
	old, new string // old == "": create path with new
}

func fixture(t *testing.T, edits ...edit) ([]scan.Problem, string) {
	t.Helper()
	src := filepath.Join("testdata", "fx")
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range edits {
		p := filepath.Join(dst, e.path)
		if e.old == "" {
			os.MkdirAll(filepath.Dir(p), 0o755)
			if err := os.WriteFile(p, []byte(e.new), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), e.old) {
			t.Fatalf("fixture edit: %q not in %s", e.old, e.path)
		}
		os.WriteFile(p, []byte(strings.Replace(string(b), e.old, e.new, 1)), 0o644)
	}
	rb, err := os.ReadFile(filepath.Join(dst, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := wire.Parse(rb)
	if err != nil {
		t.Fatal(err)
	}
	tb, _ := os.ReadFile(filepath.Join(dst, "transition.json"))
	tr, err := wire.ParseTransition(tb)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := scan.Check(scan.Config{Dir: dst, Repo: "ANetCore", Registry: reg, Transition: tr,
		Env: []string{"GOWORK=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local"}})
	if err != nil {
		t.Fatal(err)
	}
	var all []string
	for _, p := range ps {
		all = append(all, p.String())
	}
	return ps, strings.Join(all, "\n")
}

// expect asserts exactly one problem, of rule, whose message holds every fragment.
func expect(t *testing.T, ps []scan.Problem, all, rule string, frags ...string) scan.Problem {
	t.Helper()
	if len(ps) != 1 {
		t.Fatalf("want one %s problem, got %d:\n%s", rule, len(ps), all)
	}
	p := ps[0]
	if p.Rule != rule {
		t.Fatalf("want rule %s, got %s", rule, p)
	}
	for _, f := range frags {
		if !strings.Contains(p.Msg, f) {
			t.Fatalf("problem lacks %q: %s", f, p)
		}
	}
	return p
}

func TestFixtureIsClean(t *testing.T) {
	ps, all := fixture(t)
	if len(ps) != 0 {
		t.Fatalf("clean fixture has problems:\n%s", all)
	}
}

// CORE-S8 (1): a key number changed in a keyasint struct.
func TestS8KeyNumberChanged(t *testing.T) {
	ps, all := fixture(t, edit{"thing/thing.go", "B     uint64 `cbor:\"2,keyasint,omitempty\"`", "B     uint64 `cbor:\"5,keyasint,omitempty\"`"})
	expect(t, ps, all, "struct", "Thing key 5 is reserved")
}

// CORE-S8 (2): an unregistered key added.
func TestS8UnregisteredKeyAdded(t *testing.T) {
	ps, all := fixture(t, edit{"thing/thing.go", "\tCache []byte", "\tD     string `cbor:\"9,keyasint,omitempty\"`\n\tCache []byte"})
	expect(t, ps, all, "struct", "Thing key 9 is reserved", "field D", "register the key")
}

// CORE-S8 (3): a label changed by one character.
func TestS8LabelChanged(t *testing.T) {
	ps, all := fixture(t, edit{"thing/thing.go", `const Label = "anet.fx-thing/1"`, `const Label = "anet.fx-thing/2"`})
	expect(t, ps, all, "string", `"anet.fx-thing/2" is not registered`)
}

// CORE-S8 (4): a retired key reused.
func TestS8RetiredKeyReused(t *testing.T) {
	ps, all := fixture(t, edit{"thing/thing.go", "\tCache []byte", "\tC     string `cbor:\"3,keyasint,omitempty\"`\n\tCache []byte"})
	expect(t, ps, all, "struct", "Thing key 3 is retired (was c)", "never reused")
}

// CORE-S8 (5): an unregistered relayauth action, as a constant and as an argument.
func TestS8UnregisteredAction(t *testing.T) {
	ps, all := fixture(t, edit{"relayauth/relayauth.go", `ActionKeys = "keys"`, "ActionKeys = \"keys\"\n\tActionZZ   = \"zz\""})
	expect(t, ps, all, "action", `"zz"`, "not registered")
	ps, all = fixture(t, edit{"thing/thing.go", `return signed(aid, "keys")`, `return signed(aid, "keyz")`})
	expect(t, ps, all, "action", `"keyz"`, "signed")
	ps, all = fixture(t, edit{"thing/thing.go", `return signed(aid, "keys")`, `return signed(aid, "send")`})
	expect(t, ps, all, "action", `"send"`, "retired")
}

// CORE-S8 (6, CORE-L9): a signing call outside the registered signers.
func TestS8SignerOutsideRegistry(t *testing.T) {
	ps, all := fixture(t, edit{"thing/extra.go", "", `package thing

import "example.com/fx/identity"

// Rogue signs something unregistered.
func Rogue(c *identity.Controller) []byte {
	sig, _ := c.Sign([]byte("x"))
	return sig
}
`})
	p := expect(t, ps, all, "signer", "thing.Rogue", "not in registry signers")
	if p.Fix == nil || p.Fix.Kind != wire.TransSigner || p.Fix.Go != "thing.Rogue" {
		t.Fatalf("fix suggestion: %+v", p.Fix)
	}
}

// A call through anything that implements the registered signing interface is a signing call.
func TestSignerInterfaceImplementers(t *testing.T) {
	ps, all := fixture(t, edit{"thing/wrap.go", "", `package thing

type wrap struct{}

func (wrap) Sign(p []byte) ([]byte, uint64) { return p, 0 }

func useWrap(w wrap) []byte {
	sig, _ := w.Sign(nil)
	return sig
}
`})
	expect(t, ps, all, "signer", "thing.useWrap")
	// the method set may not name a method that does not exist
	ps, all = fixture(t, edit{"registry.json", "(example.com/fx/identity.Signer).Sign", "(example.com/fx/identity.Signer).Sing"})
	expect(t, ps, all, "signer", "Sing does not exist")
}

func TestStructRules(t *testing.T) {
	cases := []struct {
		name  string
		e     edit
		frags []string
	}{
		{"field name", edit{"thing/thing.go", "\tA     string `cbor:\"1,keyasint\"`", "\tAlpha string `cbor:\"1,keyasint\"`"}, []string{`Thing key 1 is "a"`, "Alpha"}},
		{"field type", edit{"thing/thing.go", "\tA     string `cbor:\"1,keyasint\"`", "\tA     uint64 `cbor:\"1,keyasint\"`"}, []string{"is tstr", "uint"}},
		{"required key missing", edit{"thing/thing.go", "\tA     string `cbor:\"1,keyasint\"`\n", ""}, []string{"key 1 (a) is required"}},
		{"nested object", edit{"thing/thing.go", "//anet:wire Part\n", "//anet:wire Thing\n"}, []string{"a struct bound to Thing"}},
		{"unknown object", edit{"thing/thing.go", "//anet:wire Thing\n", "//anet:wire Thingy\n"}, []string{"Thingy, which is not an object"}},
		{"untagged field", edit{"thing/thing.go", "\tCache []byte `cbor:\"-\"`", "\tCache []byte"}, []string{"field Cache", "no cbor key"}},
		{"unbound struct", edit{"thing/more.go", "", "package thing\n\ntype loose struct {\n\tZ int `cbor:\"1,keyasint\"`\n}\n"}, []string{"thing.loose is not bound"}},
		{"anonymous struct", edit{"thing/anon.go", "", "package thing\n\nfunc anon() any {\n\treturn struct {\n\t\tZ int `cbor:\"1,keyasint\"`\n\t}{1}\n}\n"}, []string{"thing.anon#1 is not bound"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ps, all := fixture(t, c.e)
			if c.name == "nested object" {
				// binding Part to Thing also breaks Part itself; the nested check is the one
				// that matters here
				if !strings.Contains(all, c.frags[0]) {
					t.Fatalf("no %q in:\n%s", c.frags[0], all)
				}
				return
			}
			expect(t, ps, all, "struct", c.frags...)
		})
	}
}

func TestTransitionRules(t *testing.T) {
	// a v0.2 struct edited without being migrated
	ps, all := fixture(t, edit{"legacy/legacy.go", "Y []byte `cbor:\"2,keyasint,omitempty\"`", "Y []byte `cbor:\"3,keyasint,omitempty\"`"})
	expect(t, ps, all, "struct", "v0.2 struct legacy.Old changed")
	// migrated without deleting the entry: the entry is stale
	ps, all = fixture(t, edit{"legacy/legacy.go", "type Old struct {\n\tX string `cbor:\"1,keyasint\"`\n\tY []byte `cbor:\"2,keyasint,omitempty\"`\n}", "type Old struct{}"})
	expect(t, ps, all, "transition", "legacy.Old", "matches nothing", "FX-1")
	ps, all = fixture(t, edit{"legacy/legacy.go", `const OldLabel = "anet-fx-old/v1"`, `const OldLabel = "x"`})
	expect(t, ps, all, "transition", `"anet-fx-old/v1"`, "delete it")
}

func TestConstAndReasonRules(t *testing.T) {
	ps, all := fixture(t, edit{"seal/seal.go", "outerKeyTo = 2", "outerKeyTo = 3"})
	expect(t, ps, all, "const", "seal.outerKeyTo = 3", `key "to" is 2`)
	ps, all = fixture(t, edit{"seal/seal.go", "outerKeyTo = 2", "outerKeyTo = 2\n\touterKeyCT = 6"})
	expect(t, ps, all, "const", "seal.outerKeyCT = 6 names no key of Outer")
	ps, all = fixture(t, edit{"reasons/reasons.go", "\t\"denied\":     \"denied\",\n", ""})
	expect(t, ps, all, "reasons", `has "denied", this table has no row`)
	ps, all = fixture(t, edit{"reasons/reasons.go", "\t\"denied\":     \"denied\",\n", "\t\"denied\":     \"denied\",\n\t\"nope\":       \"nope\",\n"})
	expect(t, ps, all, "reasons", `code "nope" is not in registry reasons.user`)
}

func TestProseIsExempt(t *testing.T) {
	ps, all := fixture(t, edit{"thing/log.go", "", "package thing\n\nconst msg = \"anet-fx: %v failed\"\n"})
	if len(ps) != 0 {
		t.Fatalf("a log format string was flagged:\n%s", all)
	}
}
