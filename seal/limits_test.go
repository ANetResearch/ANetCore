package seal

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// The forward-secrecy constants of v0.3.0 and the v0.2 key policy they replace. The values are
// stated in the design and in its public limits; a change here must change those too, which is why
// each is pinned by number rather than by expression.
func TestSealConstantsV030(t *testing.T) {
	const (
		minute = uint64(60 * 1000)
		hour   = 60 * minute
		day    = 24 * hour
	)
	for _, c := range []struct {
		name      string
		got, want uint64
	}{
		{"EpochMS (E, one encryption epoch)", EpochMS, day},
		{"PublishAheadMS (H, epoch keys published ahead)", PublishAheadMS, 14 * day},
		{"DeliveryDeadlineMS (D, last acceptance after not_after)", DeliveryDeadlineMS, hour},
		{"MaxKeyValidityMS (one EncKey)", MaxKeyValidityMS, 2 * day},
		{"MaxKeysPerSet", MaxKeysPerSet, 32},
		{"ClockSkewMS (unchanged)", ClockSkewMS, 5 * minute},
		{"MaxMessageLifetimeMS (L, unchanged)", MaxMessageLifetimeMS, 15 * day},
		{"KIDLen (unchanged)", KIDLen, 16},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if EncKeySetType != "anet.enckeys/2" {
		t.Errorf("EncKeySetType = %q, want anet.enckeys/2", EncKeySetType)
	}
	// A publisher holds a key for the current epoch and each of the next H/E, and keeps the
	// previous epoch's key in its set for D plus a margin past the epoch's end: all of them must
	// fit in one set.
	if n := PublishAheadMS/EpochMS + 2; n > MaxKeysPerSet {
		t.Errorf("a set of the previous, the current and %d future epoch keys (%d keys) does not fit in MaxKeysPerSet = %d",
			PublishAheadMS/EpochMS, n, MaxKeysPerSet)
	}
	// One epoch key spans exactly one epoch, which must be a valid EncKey.
	if EpochMS > MaxKeyValidityMS {
		t.Errorf("an epoch (%d ms) is longer than a key may be valid (%d ms)", EpochMS, MaxKeyValidityMS)
	}
	// The four seal reasons of the second layer exist under the names the design gives them.
	for got, want := range map[string]string{
		ReasonBadWrap:                   "bad-wrap",
		ReasonBadRK:                     "bad-rk",
		ReasonSealedToClosedInteraction: "sealed-to-closed-interaction",
		ReasonIKeyMismatch:              "ikey-mismatch",
	} {
		if got != want {
			t.Errorf("reason %q, want %q", got, want)
		}
	}

	// The v0.2 key policy is gone from the package, not only unused: key rotation, lifetime and
	// retention are the publisher's policy, not constants of the format, and the 29-day window
	// they derived no longer describes anything.
	deleted := map[string]bool{
		"KeyRotationIntervalMS":  true,
		"KeyLifetimeMS":          true,
		"KeyRetentionMS":         true,
		"ForwardSecrecyWindowMS": true,
		"EncKey.Retained":        true,
	}
	for _, name := range declaredNames(t) {
		if deleted[name] {
			t.Errorf("package seal declares %s again; it was removed in v0.3.0", name)
		}
	}
}

// declaredNames returns every top-level name the package's non-test files declare, methods as
// "Type.Method".
func declaredNames(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var out []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil && len(d.Recv.List) == 1 {
					r := d.Recv.List[0].Type
					if s, ok := r.(*ast.StarExpr); ok {
						r = s.X
					}
					if id, ok := r.(*ast.Ident); ok {
						out = append(out, id.Name+"."+d.Name.Name)
						continue
					}
				}
				out = append(out, d.Name.Name)
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.ValueSpec:
						for _, n := range s.Names {
							out = append(out, n.Name)
						}
					case *ast.TypeSpec:
						out = append(out, s.Name.Name)
					}
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no declarations found; is the test running in the package directory?")
	}
	return out
}
