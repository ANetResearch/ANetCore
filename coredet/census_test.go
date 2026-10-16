package coredet_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet/coredettest"
)

// TestEveryStrictDecoderRefusesNullAndUndefined (core CORE-E4, revision 7), the census of the
// three repositories: every package whose code decodes with UnmarshalStrict has a test of this
// name, which feeds each of its call sites f6 and 81 f7 (coredettest.Check). ANet and ANetHub are
// checked when they sit next to this checkout (or in Refs/ beside it); ANET_GOLDEN_ALL_REPOS=1
// makes a missing one a failure.
func TestEveryStrictDecoderRefusesNullAndUndefined(t *testing.T) {
	core, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	roots := map[string]string{"ANetCore": core}
	for _, name := range []string{"ANet", "ANetHub"} {
		if d, ok := siblingRepo(filepath.Dir(core), name); ok {
			roots[name] = d
		} else if os.Getenv("ANET_GOLDEN_ALL_REPOS") == "1" {
			t.Errorf("%s is not next to this ANetCore checkout", name)
		} else {
			t.Logf("%s is not next to this ANetCore checkout; its strict decoders are not counted", name)
		}
	}
	for repo, root := range roots {
		missing, n, err := coredettest.Census(root)
		if err != nil {
			t.Fatalf("%s: %v", repo, err)
		}
		if n == 0 {
			t.Errorf("%s: no package decodes with UnmarshalStrict; the census did not see the code", repo)
		}
		for _, m := range missing {
			t.Errorf("%s/%s decodes with coredet.UnmarshalStrict and has no %s", repo, m, coredettest.TestName)
		}
		t.Logf("%s: %d packages decode with UnmarshalStrict", repo, n)
	}
}

// The census finds a package that decodes strictly without the test, and leaves one with it
// alone; a call through a wrapper of the package counts, and a test file does not.
func TestCensusCatches(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/m\n\ngo 1.26\n")
	const imp = "import cd \"github.com/ANetResearch/ANetCore/coredet\"\n"
	write("a/a.go", "package a\n\n"+imp+"\ntype T struct{}\n\nfunc D(b []byte) error { var v T; return cd.UnmarshalStrict(b, &v) }\n")
	write("b/b.go", "package b\n\n"+imp+"\nfunc dec(b []byte, v any) error { return cd.UnmarshalStrict(b, v) }\n\n"+
		"type U struct{}\n\nfunc D(b []byte) error { var u U; return dec(b, &u) }\n")
	write("b/b_test.go", "package b\n\nimport \"testing\"\n\nfunc "+coredettest.TestName+"(t *testing.T) {}\n")
	write("c/c_test.go", "package c\n\n"+imp+"\nfunc f(b []byte) error { var x int; return cd.UnmarshalStrict(b, &x) }\n")
	write("c/c.go", "package c\n")
	write("d/d.go", "package d\n\nfunc UnmarshalStrict(b []byte, v any) error { return nil }\n\nfunc D(b []byte) error { var x int; return UnmarshalStrict(b, &x) }\n")
	missing, n, err := coredettest.Census(root)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || strings.Join(missing, ",") != "a" {
		t.Fatalf("census: %d with sites, missing %v; want 2 (a and b), missing [a]", n, missing)
	}
	sites, err := coredettest.Sites(filepath.Join(root, "b"))
	if err != nil || len(sites) != 1 || sites[0].Key() != "D &u via dec" || sites[0].Type != "U" {
		t.Fatalf("sites of b: %+v, %v", sites, err)
	}
}

// siblingRepo is the checkout of name next to the ANetCore checkout in parent, or in Refs/ there,
// told by its go.mod module path.
func siblingRepo(parent, name string) (string, bool) {
	for _, d := range []string{filepath.Join(parent, name), filepath.Join(parent, "Refs", name)} {
		b, err := os.ReadFile(filepath.Join(d, "go.mod"))
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(l) == "module github.com/ANetResearch/"+name {
				return d, true
			}
		}
	}
	return "", false
}
