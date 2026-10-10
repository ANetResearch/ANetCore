// Package coredettest holds every strict decoder in a repository to coredet's null and undefined
// rule (CORE-E4, revision 7): TestEveryStrictDecoderRefusesNullAndUndefined.
//
// The rule lives in coredet.UnmarshalStrict, so it holds for a type as soon as the type is decoded
// with it; what this package checks is that it is, everywhere it should be. It reads a package's
// code with go/ast and lists each call of coredet.UnmarshalStrict (a Site), including a call made
// through a function of the package that passes one of its own parameters on as the destination
// (a wrapper such as delegation's decodeBody): there the call of the wrapper is the site. The
// package's test gives, for each site, the type the site decodes into, and Check feeds that type
// the two inputs every strict decoder must refuse:
//
//	f6     null as the whole input, which decodes into the zero value of anything that is not a pointer
//	81 f7  a list holding one undefined, the two bytes that decoded into a zero KEL entry
//
// A site with no entry, or an entry with no site, is a failure: a new call of UnmarshalStrict does
// not go unchecked, and a removed one does not leave a stale row. Census lists the packages of a
// module that have a site, so that a package that starts calling UnmarshalStrict must also have
// the test.
//
// It is for tests only. It reads source files from disk and is not built into any program.
package coredettest

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ANetResearch/ANetCore/coredet"
)

// TestName is the name of the test every package with a site defines.
const TestName = "TestEveryStrictDecoderRefusesNullAndUndefined"

// coredetPath is the import path of coredet.
const coredetPath = "github.com/ANetResearch/ANetCore/coredet"

// Site is one place a package decodes with coredet.UnmarshalStrict.
type Site struct {
	File string // the file's base name
	Line int
	// Func is the function the call is in: "Name", "(*Recv).Name" or "(Recv).Name"; "" for a
	// package-level initializer.
	Func string
	// Arg is the destination as written, e.g. "&f".
	Arg string
	// Via is the wrapper the call goes through, "" for a direct call of UnmarshalStrict.
	Via string
	// Type is the destination's type as declared in Func, when the site's destination is &x for
	// a local x declared with a type (var x T, x := T{}, var x = T{}); "" when it cannot be told
	// from the source.
	Type string
}

// Key is how a package's test names the site: "Func Arg", with " via Wrapper" for a call
// through a wrapper and "#2", "#3" … for a repeat of the same text in one function.
func (s Site) Key() string {
	k := s.Func + " " + s.Arg
	if s.Via != "" {
		k += " via " + s.Via
	}
	return k
}

// Sites lists the sites in the package in dir: the files the default build context builds,
// without the tests. They are in file and line order, with Key unique.
func Sites(dir string) ([]Site, error) {
	files, fset, err := parsePackage(dir)
	if err != nil {
		return nil, err
	}
	// Pass 1: direct calls, and which functions are wrappers (pass a parameter on).
	type wrapper struct{ param int }
	wrappers := map[string]wrapper{}
	var sites []Site
	type call struct {
		file *ast.File
		fn   *ast.FuncDecl
		expr *ast.CallExpr
		via  string
		arg  int
	}
	var calls []call
	for _, f := range files {
		local := coredetName(f)
		for _, d := range f.Decls {
			fn, _ := d.(*ast.FuncDecl)
			ast.Inspect(d, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok || local == "" || !isSel(ce.Fun, local, "UnmarshalStrict") || len(ce.Args) != 2 {
					return true
				}
				if fn != nil {
					if i, ok := paramIndex(fn, ce.Args[1]); ok {
						wrappers[fn.Name.Name] = wrapper{param: i}
						return true
					}
				}
				calls = append(calls, call{file: f, fn: fn, expr: ce, arg: 1})
				return true
			})
		}
	}
	// Pass 2: calls of the wrappers, until no new wrapper turns up (a wrapper of a wrapper).
	for changed := true; changed; {
		changed = false
		for _, f := range files {
			for _, d := range f.Decls {
				fn, _ := d.(*ast.FuncDecl)
				ast.Inspect(d, func(n ast.Node) bool {
					ce, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					name := calledName(ce.Fun)
					w, isW := wrappers[name]
					if !isW || w.param >= len(ce.Args) || (fn != nil && fn.Name.Name == name) {
						return true
					}
					if fn != nil {
						if i, ok := paramIndex(fn, ce.Args[w.param]); ok {
							if _, seen := wrappers[fn.Name.Name]; !seen {
								wrappers[fn.Name.Name] = wrapper{param: i}
								changed = true
							}
							return true
						}
					}
					return true
				})
			}
		}
	}
	for _, f := range files {
		for _, d := range f.Decls {
			fn, _ := d.(*ast.FuncDecl)
			ast.Inspect(d, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := calledName(ce.Fun)
				w, isW := wrappers[name]
				if !isW || w.param >= len(ce.Args) {
					return true
				}
				if fn != nil {
					if _, ok := paramIndex(fn, ce.Args[w.param]); ok {
						return true // a wrapper itself
					}
				}
				calls = append(calls, call{file: f, fn: fn, expr: ce, via: name, arg: w.param})
				return true
			})
		}
	}
	for _, c := range calls {
		pos := fset.Position(c.expr.Pos())
		arg := c.expr.Args[c.arg]
		s := Site{File: filepath.Base(pos.Filename), Line: pos.Line, Func: funcName(c.fn), Arg: exprText(fset, arg), Via: c.via}
		if c.fn != nil {
			s.Type = declaredType(fset, c.fn, arg)
		}
		sites = append(sites, s)
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
	seen := map[string]int{}
	for i := range sites {
		k := sites[i].Key()
		seen[k]++
		if n := seen[k]; n > 1 {
			sites[i].Arg += "#" + strconv.Itoa(n)
		}
	}
	return sites, nil
}

// The inputs every strict decoder refuses.
var (
	nullInput      = []byte{0xf6}
	undefinedInput = []byte{0x81, 0xf7}
)

// Check is the test for the package in dir. table maps each site's Key to a function returning a
// new destination of the site's type (a pointer, as the site passes it). It returns what is wrong:
// a site without a row, a row without a site, a row whose type is not the one the site declares,
// and every row whose type takes f6 without coredet's NullError, or takes 81 f7 at all.
func Check(dir string, table map[string]func() any) ([]string, error) {
	sites, err := Sites(dir)
	if err != nil {
		return nil, err
	}
	pkg, err := packageName(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	have := map[string]bool{}
	for _, s := range sites {
		k := s.Key()
		have[k] = true
		mk, ok := table[k]
		if !ok {
			out = append(out, fmt.Sprintf("%s:%d: %q has no row: give the type it decodes into", s.File, s.Line, k))
			continue
		}
		v := mk()
		rt := reflect.TypeOf(v)
		if rt == nil || rt.Kind() != reflect.Pointer {
			out = append(out, fmt.Sprintf("%q: the row's function returns %T, not a pointer to a new destination", k, v))
			continue
		}
		if s.Type != "" && s.Type != typeText(rt.Elem(), pkg) {
			out = append(out, fmt.Sprintf("%s:%d: %q decodes into %s, the row gives %s", s.File, s.Line, k, s.Type, typeText(rt.Elem(), pkg)))
		}
		if err := coredet.UnmarshalStrict(nullInput, mk()); !errors.Is(err, coredet.ErrNullOrUndefined) {
			out = append(out, fmt.Sprintf("%q: %s takes f6 (null) with %v, want coredet's null refusal", k, rt.Elem(), err))
		}
		if err := coredet.UnmarshalStrict(undefinedInput, mk()); err == nil {
			out = append(out, fmt.Sprintf("%q: %s takes 81 f7 (a list holding undefined)", k, rt.Elem()))
		}
	}
	var stale []string
	for k := range table {
		if !have[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	for _, k := range stale {
		out = append(out, fmt.Sprintf("row %q has no site: the code no longer decodes there", k))
	}
	if len(sites) == 0 {
		out = append(out, "no site in "+dir+": the package no longer calls coredet.UnmarshalStrict, so drop its "+TestName)
	}
	return out, nil
}

// Census returns, for the module at root, every package directory (relative to root) with a site
// whose tests do not define TestName, and how many directories with a site it found. Nested
// modules, testdata and directories whose name starts with "." or "_" are left out, as the go
// command leaves them out; so are coredet, where UnmarshalStrict is defined, and this package.
func Census(root string) (missing []string, withSites int, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if path != root {
			if name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
		}
		if (name == "coredet" || name == "coredettest") && isCoredetItself(path) {
			return nil
		}
		sites, err := Sites(path)
		if err != nil {
			var nogo *build.NoGoError
			if errors.As(err, &nogo) {
				return nil
			}
			return err
		}
		if len(sites) == 0 {
			return nil
		}
		withSites++
		ok, err := definesTest(path)
		if err != nil {
			return err
		}
		if !ok {
			rel, _ := filepath.Rel(root, path)
			missing = append(missing, rel)
		}
		return nil
	})
	sort.Strings(missing)
	return missing, withSites, err
}

// isCoredetItself reports whether dir, a directory named coredet or coredettest, holds that
// package: coredet, where UnmarshalStrict is defined, or this one, whose Check calls it on the
// types it is given.
func isCoredetItself(dir string) bool {
	n, err := packageName(dir)
	return err == nil && n == filepath.Base(dir)
}

// definesTest reports whether a test file in dir defines TestName.
func definesTest(dir string) (bool, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	fset := token.NewFileSet()
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			return false, err
		}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == TestName {
				return true, nil
			}
		}
	}
	return false, nil
}

// parsePackage parses the files of the package in dir that the default build context builds,
// tests excluded.
func parsePackage(dir string) ([]*ast.File, *token.FileSet, error) {
	ctx := build.Default
	pkg, err := ctx.ImportDir(dir, 0)
	if err != nil {
		return nil, nil, err
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range append(append([]string(nil), pkg.GoFiles...), pkg.CgoFiles...) {
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, f)
	}
	return files, fset, nil
}

func packageName(dir string) (string, error) {
	pkg, err := build.Default.ImportDir(dir, 0)
	if err != nil {
		return "", err
	}
	return pkg.Name, nil
}

// coredetName is the name f imports coredet under, "" when it does not import it.
func coredetName(f *ast.File) string {
	for _, im := range f.Imports {
		p, err := strconv.Unquote(im.Path.Value)
		if err != nil || p != coredetPath {
			continue
		}
		if im.Name != nil {
			if im.Name.Name == "_" {
				return ""
			}
			return im.Name.Name
		}
		return "coredet"
	}
	return ""
}

func isSel(e ast.Expr, x, sel string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != sel {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == x
}

// calledName is the name a call calls: f for f(…), m for x.m(…).
func calledName(e ast.Expr) string {
	switch f := e.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.IndexExpr: // a generic function instantiated explicitly
		return calledName(f.X)
	}
	return ""
}

// paramIndex reports whether e is one of fn's parameters, and which (counting each name).
func paramIndex(fn *ast.FuncDecl, e ast.Expr) (int, bool) {
	id, ok := e.(*ast.Ident)
	if !ok || fn.Type.Params == nil {
		return 0, false
	}
	i := 0
	for _, fld := range fn.Type.Params.List {
		if len(fld.Names) == 0 {
			i++
			continue
		}
		for _, n := range fld.Names {
			if n.Name == id.Name {
				return i, true
			}
			i++
		}
	}
	return 0, false
}

// funcName names fn as Site.Func does.
func funcName(fn *ast.FuncDecl) string {
	if fn == nil {
		return ""
	}
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	rt := fn.Recv.List[0].Type
	star := ""
	if s, ok := rt.(*ast.StarExpr); ok {
		star, rt = "*", s.X
	}
	if ix, ok := rt.(*ast.IndexExpr); ok {
		rt = ix.X
	}
	if ix, ok := rt.(*ast.IndexListExpr); ok {
		rt = ix.X
	}
	name := "?"
	if id, ok := rt.(*ast.Ident); ok {
		name = id.Name
	}
	return "(" + star + name + ")." + fn.Name.Name
}

func exprText(fset *token.FileSet, e ast.Expr) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, e); err != nil {
		return "?"
	}
	return b.String()
}

// declaredType is the type of x where e is &x and x is declared in fn with a type that can be
// read from the source; "" otherwise.
func declaredType(fset *token.FileSet, fn *ast.FuncDecl, e ast.Expr) string {
	u, ok := e.(*ast.UnaryExpr)
	if !ok || u.Op != token.AND {
		return ""
	}
	id, ok := u.X.(*ast.Ident)
	if !ok {
		return ""
	}
	typ := ""
	found := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.ValueSpec:
			for i, nm := range s.Names {
				if nm.Name != id.Name {
					continue
				}
				found++
				switch {
				case s.Type != nil:
					typ = exprText(fset, s.Type)
				case i < len(s.Values):
					typ = literalType(fset, s.Values[i])
				}
			}
		case *ast.AssignStmt:
			if s.Tok != token.DEFINE {
				return true
			}
			for i, l := range s.Lhs {
				if lid, ok := l.(*ast.Ident); ok && lid.Name == id.Name && i < len(s.Rhs) && len(s.Lhs) == len(s.Rhs) {
					found++
					typ = literalType(fset, s.Rhs[i])
				}
			}
		}
		return true
	})
	if found != 1 {
		return "" // not declared here, or declared more than once: no telling which
	}
	return typ
}

// literalType is T for a composite literal T{…}; "" for anything else.
func literalType(fset *token.FileSet, e ast.Expr) string {
	if cl, ok := e.(*ast.CompositeLit); ok && cl.Type != nil {
		return exprText(fset, cl.Type)
	}
	return ""
}

// typeText writes t as the source of package pkg would: without pkg's own qualifier.
func typeText(t reflect.Type, pkg string) string {
	re := regexp.MustCompile(`(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(pkg) + `\.`)
	return re.ReplaceAllString(t.String(), "$1")
}
