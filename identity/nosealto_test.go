package identity_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The identity key signs and does nothing else. Version 0.2 also offered an anonymous sealed box
// to a peer's identity key (SealTo, (*Controller).Open, X25519PublicFromEd25519): the same key
// material used for Ed25519 signatures and for X25519 key agreement, with no forward secrecy and
// no caller in any repository. Encryption to a peer goes through package seal, to the peer's
// published epoch keys. This test reads the package's exported API from its source and fails if
// the sealed box, or any way to turn the identity key into a Diffie-Hellman key, comes back.
func TestIdentityAPIHasNoSealTo(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var exported []string
	forbiddenImports := map[string]bool{
		"golang.org/x/crypto/nacl/box":   true,
		"golang.org/x/crypto/curve25519": true,
		"filippo.io/edwards25519":        true,
		"crypto/ecdh":                    true,
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if forbiddenImports[p] {
				t.Errorf("%s imports %s: the identity key must not be converted into a key-agreement key", name, p)
			}
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || !fd.Name.IsExported() {
				continue
			}
			sym := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				sym = "(" + recvName(fd.Recv.List[0].Type) + ")." + sym
			}
			exported = append(exported, sym)
		}
	}
	if len(exported) == 0 {
		t.Fatal("found no exported function in package identity; is the test running in its directory?")
	}
	sort.Strings(exported)
	for _, sym := range exported {
		bare := sym[strings.LastIndex(sym, ".")+1:]
		switch {
		case sym == "SealTo", sym == "X25519PublicFromEd25519", sym == "(*Controller).Open", sym == "(Controller).Open":
			t.Errorf("identity exports %s again: encryption to a peer goes to its epoch keys through package seal, never to its identity key", sym)
		case strings.Contains(strings.ToLower(bare), "x25519"), strings.Contains(strings.ToLower(bare), "curve25519"):
			t.Errorf("identity exports %s: the identity key must not be converted into a key-agreement key", sym)
		}
	}
	if _, err := os.Stat("encrypt.go"); err == nil {
		t.Error("identity/encrypt.go is back; it held the v0.2 sealed box and must stay deleted")
	}
}

func recvName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return "*" + recvName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvName(t.X)
	}
	return "?"
}
