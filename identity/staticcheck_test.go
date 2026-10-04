package identity_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// repoRoot is the directory holding go.mod above this package.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		up := filepath.Dir(dir)
		if up == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = up
	}
}

// goFiles parses every Go file of the repository (tests included when withTests), skipping
// testdata and hidden directories.
func goFiles(t *testing.T, withTests bool) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	root := repoRoot(t)
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || !withTests && strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out[rel] = f
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return fset, out
}

// KEL C-23: Controller.CurrentPrivateKey is deleted. No identifier of that name exists anywhere in
// the repository, tests included, and no exported function or method of package identity hands out
// a private key: the identity signs through identity.Signer, and nothing else gets its key.
func TestNoCurrentPrivateKey(t *testing.T) {
	fset, files := goFiles(t, true)
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "CurrentPrivateKey" {
				t.Errorf("%s: identifier CurrentPrivateKey (KEL C-23 deletes it)", fset.Position(id.Pos()))
			}
			return true
		})
	}
	for rel, f := range files {
		if filepath.Dir(rel) != "identity" || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || !fd.Name.IsExported() || fd.Type.Results == nil {
				continue
			}
			for _, r := range fd.Type.Results.List {
				if sel, ok := r.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "PrivateKey" {
					t.Errorf("%s: exported %s returns a private key", fset.Position(fd.Pos()), fd.Name.Name)
				}
			}
		}
	}
}

// KEL C-58: no identifier of the non-test code is named ksn or has ksn as one of its words, and no
// JSON or CBOR field is tagged ksn (core §0.3, G8). The term is "witness notice" in code and
// "key confirmation" for users.
func TestNoKSNIdentifiers(t *testing.T) {
	fset, files := goFiles(t, false)
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if hasWord(x.Name, "ksn") {
					t.Errorf("%s: identifier %s", fset.Position(x.Pos()), x.Name)
				}
			case *ast.Field:
				if x.Tag != nil {
					tag, err := strconv.Unquote(x.Tag.Value)
					if err != nil {
						return true
					}
					for _, key := range []string{"json", "cbor"} {
						name, _, _ := strings.Cut(reflect.StructTag(tag).Get(key), ",")
						if strings.EqualFold(name, "ksn") {
							t.Errorf("%s: %s field tagged %q", fset.Position(x.Pos()), key, name)
						}
					}
				}
			}
			return true
		})
	}
}

// words splits an identifier at underscores and at case changes: ksnCache, KSNCache and ksn_cache
// all hold the word ksn; ksnow does not.
func words(name string) []string {
	var out []string
	rs := []rune(name)
	start := 0
	flush := func(i int) {
		if i > start {
			out = append(out, string(rs[start:i]))
		}
		start = i
	}
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '_':
			flush(i)
			start = i + 1
		case i > start && unicode.IsUpper(r) && (unicode.IsLower(rs[i-1]) || unicode.IsDigit(rs[i-1]) ||
			i+1 < len(rs) && unicode.IsUpper(rs[i-1]) && unicode.IsLower(rs[i+1])):
			flush(i)
		}
	}
	flush(len(rs))
	return out
}

func hasWord(name, word string) bool {
	for _, w := range words(name) {
		if strings.EqualFold(w, word) {
			return true
		}
	}
	return false
}

func TestWordsOfAnIdentifier(t *testing.T) {
	for name, want := range map[string]bool{
		"ksn": true, "KSN": true, "ksnCache": true, "KSNCache": true, "noticeKSN": true, "ksn_cache": true,
		"keyKsnSeq": true, "ksnow": false, "Ksnap": false, "Notice": false, "asks": false,
	} {
		if got := hasWord(name, "ksn"); got != want {
			t.Errorf("%s: %v (words %q)", name, got, words(name))
		}
	}
}
