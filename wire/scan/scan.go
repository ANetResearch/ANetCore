// Package scan checks the non-test Go code of one repository against the wire registry
// (wire/registry.json) and the transition list (wire/transition.json). It is meant to be called
// from a test: ANetCore, ANet and ANetHub each have a TestWireRegistry that runs Check on their
// own tree and fails on every Problem.
//
// What it checks:
//
//   - every struct with a `cbor:"N,keyasint"` field: annotated `//anet:wire <Object>` and equal
//     to the registered object (key numbers active, field names, Go types, required keys), or,
//     without the annotation, listed in transition.json with exactly its current keys;
//   - integer constants named after a registered object's keys (seal's outerKey*, key*, preKey*,
//     wrapKey*): the value is the registered key number;
//   - every string literal that starts with "anet-", "anet." or "anet/": registered, or in an
//     exempt class (prose, program names), or listed in transition.json;
//   - relayauth Action* constants: registered and active;
//   - declarations annotated `//anet:wire reasons.<namespace>`: their codes are registered (and,
//     with "complete", every registered code has a row);
//   - every call of an identity signing method: made from a function the registry lists under
//     signers (or transition.json does);
//   - every transition.json entry of the repository still matches something.
//
// Every Problem says what is wrong and what to change.
package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/ANetResearch/ANetCore/wire"
)

// Config says which repository to scan.
type Config struct {
	// Dir is the repository root, the directory holding its go.mod.
	Dir string
	// Repo is the repository name used in the registry: ANetCore, ANet or ANetHub.
	Repo string
	// Tags are extra build-tag sets to type-check besides the default build, so that signing
	// calls in optional modules are seen. Files no configuration builds are still scanned for
	// structs, constants and strings, without type information.
	Tags [][]string
	// Env is added to the environment of the go command (e.g. GOWORK=off for a tree outside the
	// workspace).
	Env []string
	// Registry and Transition default to the embedded ones.
	Registry   *wire.Registry
	Transition *wire.Transition
}

// Problem is one finding.
type Problem struct {
	Pos  string // path:line relative to the repository root
	Rule string // struct, const, string, action, reasons, signer, transition, load
	Msg  string
	// Fix, when set, is the transition.json entry that would accept the finding as a v0.2
	// leftover (its Todo still to be filled in with the work item that removes it).
	Fix *wire.TransitionEntry
}

func (p Problem) String() string { return p.Pos + ": [" + p.Rule + "] " + p.Msg }

// Directive is the comment that binds a struct or declaration to the registry.
const Directive = "//anet:wire"

type file struct {
	path string // relative, slash-separated
	pkg  string // package directory relative to the root ("." for the root)
	ast  *ast.File
	info *types.Info    // nil when no type-checked configuration built the file
	tpkg *types.Package // ditto
	conf int            // the configuration (tag set) that type-checked it
}

type scanner struct {
	cfg      Config
	reg      *wire.Registry
	tr       *wire.Transition
	modPath  string
	fset     *token.FileSet
	files    []*file
	byAbs    map[string]*file
	probs    []Problem
	used     map[*wire.TransitionEntry]bool
	usedSign map[*wire.Signer]bool
	annot    map[string]string // "<pkg path>.<Type>" -> registry object, for nested type checks
	localTyp map[string]map[string]ast.Expr
	ifaces   [][]*types.Interface // per configuration: the signing interfaces
}

// Check scans cfg.Dir and returns its problems in file order.
func Check(cfg Config) ([]Problem, error) {
	s := &scanner{cfg: cfg, reg: cfg.Registry, tr: cfg.Transition, fset: token.NewFileSet(),
		byAbs: map[string]*file{}, used: map[*wire.TransitionEntry]bool{}, usedSign: map[*wire.Signer]bool{},
		annot: map[string]string{}, localTyp: map[string]map[string]ast.Expr{}}
	var err error
	if s.reg == nil {
		if s.reg, err = wire.Load(); err != nil {
			return nil, err
		}
	}
	if s.tr == nil {
		if s.tr, err = wire.LoadTransition(); err != nil {
			return nil, err
		}
	}
	if s.modPath, err = modulePath(cfg.Dir); err != nil {
		return nil, err
	}
	if err := s.parse(); err != nil {
		return nil, err
	}
	if err := s.typecheck(); err != nil {
		return nil, err
	}
	s.collectAnnotations()
	actionParams := s.actionParams()
	for _, f := range s.files {
		s.checkStructs(f)
		s.checkConsts(f)
		s.checkStrings(f)
		s.checkActions(f)
		s.checkReasonDecls(f)
		s.checkSigners(f)
		s.checkActionArgs(f, actionParams)
	}
	s.checkSignerMethods()
	s.checkStale()
	sort.SliceStable(s.probs, func(i, j int) bool { return lessPos(s.probs[i].Pos, s.probs[j].Pos) })
	return s.probs, nil
}

func lessPos(a, b string) bool {
	ai, bi := strings.LastIndexByte(a, ':'), strings.LastIndexByte(b, ':')
	if ai < 0 || bi < 0 || a[:ai] != b[:bi] {
		return a < b
	}
	x, _ := strconv.Atoi(a[ai+1:])
	y, _ := strconv.Atoi(b[bi+1:])
	return x < y
}

func (s *scanner) add(pos token.Pos, rule, format string, args ...any) {
	p := s.fset.Position(pos)
	rel := p.Filename
	if r, err := filepath.Rel(s.cfg.Dir, p.Filename); err == nil {
		rel = filepath.ToSlash(r)
	}
	s.probs = append(s.probs, Problem{Pos: fmt.Sprintf("%s:%d", rel, p.Line), Rule: rule, Msg: fmt.Sprintf(format, args...)})
}

func (s *scanner) fix(e *wire.TransitionEntry) {
	if n := len(s.probs); n > 0 {
		e.Repo = s.cfg.Repo
		e.Todo = "v030-todo(?)"
		s.probs[n-1].Fix = e
	}
}

func (s *scanner) addAt(where, rule, format string, args ...any) {
	s.probs = append(s.probs, Problem{Pos: where, Rule: rule, Msg: fmt.Sprintf(format, args...)})
}

func modulePath(dir string) (string, error) {
	f, err := os.Open(filepath.Join(dir, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("scan: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); strings.HasPrefix(line, "module ") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "module")), `"`), nil
		}
	}
	return "", fmt.Errorf("scan: no module line in %s/go.mod", dir)
}

// parse reads every non-test .go file under Dir, whatever its build constraints, skipping
// testdata, vendor, hidden directories and nested modules.
func (s *scanner) parse() error {
	root, err := filepath.Abs(s.cfg.Dir)
	if err != nil {
		return err
	}
	s.cfg.Dir = root
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			n := d.Name()
			if p != root && (n == "testdata" || n == "vendor" || n == "node_modules" || strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_")) {
				return filepath.SkipDir
			}
			if p != root {
				if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		af, err := parser.ParseFile(s.fset, p, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		rel, _ := filepath.Rel(root, p)
		pkg := filepath.ToSlash(filepath.Dir(rel))
		f := &file{path: filepath.ToSlash(rel), pkg: pkg, ast: af}
		s.files = append(s.files, f)
		s.byAbs[p] = f
		if s.localTyp[pkg] == nil {
			s.localTyp[pkg] = map[string]ast.Expr{}
		}
		for _, decl := range af.Decls {
			if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.TYPE {
				for _, sp := range gd.Specs {
					ts := sp.(*ast.TypeSpec)
					s.localTyp[pkg][ts.Name.Name] = ts.Type
				}
			}
		}
		return nil
	})
}

type listPkg struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	CgoFiles   []string
	Export     string
	DepOnly    bool
	Standard   bool
	ImportMap  map[string]string
	Error      *struct{ Err string }
	Module     *struct{ Path string }
}

func goCmd() string {
	if g := runtime.GOROOT(); g != "" {
		p := filepath.Join(g, "bin", "go")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "go"
}

// goEnv is the environment of the go commands the scan runs. A test binary often points
// XDG_CACHE_HOME at a temporary directory (ANet's daemon tests do), and the go command derives
// its build cache from it: every scan would then recompile every dependency to get export data.
// So unless GOCACHE is set, the scan asks the go command where the cache is without that
// variable and passes it explicitly.
func (s *scanner) goEnv() []string {
	env := append(os.Environ(), s.cfg.Env...)
	if os.Getenv("GOCACHE") != "" {
		return env
	}
	var clean []string
	for _, e := range env {
		if !strings.HasPrefix(e, "XDG_CACHE_HOME=") {
			clean = append(clean, e)
		}
	}
	cmd := exec.Command(goCmd(), "env", "GOCACHE")
	cmd.Dir = s.cfg.Dir
	cmd.Env = clean
	if out, err := cmd.Output(); err == nil {
		if c := strings.TrimSpace(string(out)); c != "" && c != "off" {
			env = append(env, "GOCACHE="+c)
		}
	}
	return env
}

// typecheck type-checks the repository's packages in the default build and in each extra tag
// set, importing dependencies from the export data `go list -export` produces.
func (s *scanner) typecheck() error {
	sets := append([][]string{nil}, s.cfg.Tags...)
	env := s.goEnv()
	var lists [][]*listPkg
	for _, tags := range sets {
		args := []string{"list", "-e", "-export", "-deps", "-json=ImportPath,Dir,GoFiles,CgoFiles,Export,DepOnly,Standard,ImportMap,Error,Module"}
		if len(tags) > 0 {
			args = append(args, "-tags", strings.Join(tags, ","))
		}
		args = append(args, "./...")
		cmd := exec.Command(goCmd(), args...)
		cmd.Dir = s.cfg.Dir
		cmd.Env = env
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("scan: go list %v: %v\n%s", tags, err, errb.String())
		}
		dec := json.NewDecoder(&out)
		var pkgs []*listPkg
		for {
			var p listPkg
			if err := dec.Decode(&p); err == io.EOF {
				break
			} else if err != nil {
				return fmt.Errorf("scan: go list output: %w", err)
			}
			pkgs = append(pkgs, &p)
		}
		lists = append(lists, pkgs)
	}
	// one importer per configuration: a package's export data differs between tag sets
	imps := make([]types.ImporterFrom, len(lists))
	s.ifaces = make([][]*types.Interface, len(lists))
	for i, pkgs := range lists {
		exports := map[string]string{}
		for _, p := range pkgs {
			if p.Export != "" {
				exports[p.ImportPath] = p.Export
			}
		}
		imps[i] = importer.ForCompiler(s.fset, "gc", func(path string) (io.ReadCloser, error) {
			e, ok := exports[path]
			if !ok {
				return nil, fmt.Errorf("no export data for %q", path)
			}
			return os.Open(e)
		}).(types.ImporterFrom)
		for _, m := range s.reg.Signers.Methods {
			recv, name, ok := splitMethod(m)
			if !ok || strings.HasPrefix(recv, "*") {
				continue
			}
			// an interface method: its implementers sign too
			pkgPath, tname, ok := splitQualified(recv)
			if !ok {
				continue
			}
			if tp, err := imps[i].Import(pkgPath); err == nil {
				if obj := tp.Scope().Lookup(tname); obj != nil {
					if it, ok := obj.Type().Underlying().(*types.Interface); ok && hasMethod(it, name) {
						s.ifaces[i] = append(s.ifaces[i], it)
					}
				}
			}
		}
	}
	for i, pkgs := range lists {
		for _, p := range pkgs {
			if p.DepOnly || p.Standard || p.Module == nil || p.Module.Path != s.modPath {
				continue
			}
			if p.Error != nil && len(p.GoFiles) == 0 {
				s.addAt(relDir(s.cfg.Dir, p.Dir), "load", "package %s does not load: %s", p.ImportPath, p.Error.Err)
				continue
			}
			if len(p.CgoFiles) > 0 {
				continue // left to the AST checks
			}
			var files []*ast.File
			var fs []*file
			fresh := false
			for _, g := range p.GoFiles {
				f := s.byAbs[filepath.Join(p.Dir, g)]
				if f == nil {
					continue
				}
				if f.info == nil {
					fresh = true
				}
				files = append(files, f.ast)
				fs = append(fs, f)
			}
			if !fresh || len(files) == 0 {
				continue
			}
			info := &types.Info{
				Types:      map[ast.Expr]types.TypeAndValue{},
				Defs:       map[*ast.Ident]types.Object{},
				Uses:       map[*ast.Ident]types.Object{},
				Selections: map[*ast.SelectorExpr]*types.Selection{},
			}
			imap := p.ImportMap
			conf := types.Config{
				Importer: importerFunc(func(path string) (*types.Package, error) {
					if m, ok := imap[path]; ok {
						path = m
					}
					return imps[i].Import(path)
				}),
				Error: func(error) {},
			}
			tp, err := conf.Check(p.ImportPath, s.fset, files, info)
			if err != nil {
				var te types.Error
				if errors.As(err, &te) {
					s.add(te.Pos, "load", "package %s does not type-check (tags %v): %s", p.ImportPath, sets[i], te.Msg)
				} else {
					s.addAt(relDir(s.cfg.Dir, p.Dir), "load", "package %s does not type-check (tags %v): %v", p.ImportPath, sets[i], err)
				}
			}
			for _, f := range fs {
				if f.info == nil {
					f.info, f.tpkg, f.conf = info, tp, i
				}
			}
		}
	}
	return nil
}

type importerFunc func(string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

func relDir(root, dir string) string {
	if r, err := filepath.Rel(root, dir); err == nil {
		return filepath.ToSlash(r)
	}
	return dir
}

func hasMethod(it *types.Interface, name string) bool {
	for i := 0; i < it.NumMethods(); i++ {
		if it.Method(i).Name() == name {
			return true
		}
	}
	return false
}

// splitMethod splits "(*pkg/path.Type).Name" or "(pkg/path.Type).Name".
func splitMethod(full string) (recv, name string, ok bool) {
	if !strings.HasPrefix(full, "(") {
		return "", "", false
	}
	i := strings.Index(full, ").")
	if i < 0 {
		return "", "", false
	}
	return full[1:i], full[i+2:], true
}

func splitQualified(s string) (pkgPath, name string, ok bool) {
	s = strings.TrimPrefix(s, "*")
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// ---- annotations ----

// directiveFor returns the //anet:wire argument in the comment group that ends on the line
// above line, or on line itself after the code.
func directiveFor(fset *token.FileSet, f *ast.File, node ast.Node) (string, bool) {
	line := fset.Position(node.Pos()).Line
	for _, cg := range f.Comments {
		end := fset.Position(cg.End()).Line
		if end != line-1 && end != line {
			continue
		}
		if end == line && fset.Position(cg.Pos()).Line != line {
			continue
		}
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, Directive+" ") || c.Text == Directive {
				return strings.TrimSpace(strings.TrimPrefix(c.Text, Directive)), true
			}
		}
	}
	return "", false
}

func (s *scanner) collectAnnotations() {
	for _, f := range s.files {
		for _, decl := range f.ast.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, sp := range gd.Specs {
				ts := sp.(*ast.TypeSpec)
				if _, ok := ts.Type.(*ast.StructType); !ok {
					continue
				}
				anchor := ast.Node(ts)
				if gd.Lparen == 0 {
					anchor = gd
				}
				if name, ok := directiveFor(s.fset, f.ast, anchor); ok && name != "" {
					s.annot[s.pkgPath(s.cfg.Repo, f.pkg)+"."+ts.Name.Name] = name
				}
			}
		}
	}
}

// ---- structs ----

type keyField struct {
	n     int
	name  string
	goTyp string // as written
	expr  ast.Expr
	pos   token.Pos
}

func cborKey(tag *ast.BasicLit) (n int, isKey bool, skip bool) {
	if tag == nil {
		return 0, false, false
	}
	raw, err := strconv.Unquote(tag.Value)
	if err != nil {
		return 0, false, false
	}
	v, ok := reflect.StructTag(raw).Lookup("cbor")
	if !ok {
		return 0, false, false
	}
	if v == "-" {
		return 0, false, true
	}
	parts := strings.Split(v, ",")
	keyasint := false
	for _, p := range parts[1:] {
		if p == "keyasint" {
			keyasint = true
		}
	}
	if !keyasint {
		return 0, false, false
	}
	n, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, false, false
	}
	return n, true, false
}

func (s *scanner) exprString(e ast.Expr) string {
	var b bytes.Buffer
	printer.Fprint(&b, s.fset, e)
	return b.String()
}

// structID names a struct for transition.json: "<pkg>.<Type>", or "<pkg>.<Func>#<n>" for the
// n-th anonymous keyasint struct in a function.
func (s *scanner) checkStructs(f *file) {
	anonCount := map[string]int{}
	var stack []ast.Node
	ast.Inspect(f.ast, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		st, ok := n.(*ast.StructType)
		if !ok {
			return true
		}
		var fields []keyField
		var untagged []*ast.Field
		for _, fl := range st.Fields.List {
			num, isKey, skip := cborKey(fl.Tag)
			if skip {
				continue
			}
			if !isKey {
				untagged = append(untagged, fl)
				continue
			}
			name := "_"
			if len(fl.Names) > 0 {
				name = fl.Names[0].Name
			}
			fields = append(fields, keyField{n: num, name: name, goTyp: s.exprString(fl.Type), expr: fl.Type, pos: fl.Pos()})
		}
		if len(fields) == 0 {
			return true
		}
		// Find the declaration that owns the struct: a type spec, or an anonymous use.
		var id string
		var anchor ast.Node = st
		if len(stack) >= 2 {
			if ts, ok := stack[len(stack)-2].(*ast.TypeSpec); ok {
				id = f.pkg + "." + ts.Name.Name
				anchor = ts
				if len(stack) >= 3 {
					if gd, ok := stack[len(stack)-3].(*ast.GenDecl); ok && gd.Lparen == 0 {
						anchor = gd
					}
				}
			}
		}
		if id == "" {
			fn := "<pkg>"
			for i := len(stack) - 1; i >= 0; i-- {
				if fd, ok := stack[i].(*ast.FuncDecl); ok {
					fn = fd.Name.Name
					if fd.Recv != nil && len(fd.Recv.List) > 0 {
						fn = recvName(fd.Recv.List[0].Type) + "." + fn
					}
					break
				}
			}
			anonCount[fn]++
			id = fmt.Sprintf("%s.%s#%d", f.pkg, fn, anonCount[fn])
		}
		for _, fl := range untagged {
			name := "embedded field"
			if len(fl.Names) > 0 {
				name = "field " + fl.Names[0].Name
			}
			s.add(fl.Pos(), "struct", "%s of keyasint struct %s has no cbor key: it would be encoded under its Go name; give it `cbor:\"N,keyasint\"` (registered) or `cbor:\"-\"`", name, id)
		}
		if objName, ok := directiveFor(s.fset, f.ast, anchor); ok {
			s.checkAnnotated(f, id, objName, fields, st)
			return true
		}
		s.checkTransitionStruct(f, id, fields, st)
		return true
	})
}

func recvName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvName(t.X)
	}
	return "?"
}

func (s *scanner) checkTransitionStruct(f *file, id string, fields []keyField, st *ast.StructType) {
	var have []string
	for _, k := range fields {
		have = append(have, fmt.Sprintf("%d %s %s", k.n, k.name, k.goTyp))
	}
	for _, e := range s.tr.For(s.cfg.Repo, wire.TransStruct) {
		if e.Go != id {
			continue
		}
		s.used[e] = true
		if strings.Join(e.Keys, "|") != strings.Join(have, "|") {
			s.add(st.Pos(), "struct", "v0.2 struct %s changed (transition.json has [%s], the code has [%s]): if this is the v0.3.0 version, annotate it `%s <Object>` and delete its transition entry (%s); otherwise put the v0.2 keys back",
				id, strings.Join(e.Keys, "; "), strings.Join(have, "; "), Directive, e.Todo)
		}
		return
	}
	s.add(st.Pos(), "struct", "keyasint struct %s is not bound to the registry: register its object in wire/registry.json and annotate the struct `%s <Object>` (CORE-S3)", id, Directive)
	s.fix(&wire.TransitionEntry{Kind: wire.TransStruct, Go: id, Keys: have})
}

func (s *scanner) checkAnnotated(f *file, id, objName string, fields []keyField, st *ast.StructType) {
	if objName == "" || strings.ContainsAny(objName, " \t") {
		s.add(st.Pos(), "struct", "struct %s: %s needs exactly one registered object name, got %q", id, Directive, objName)
		return
	}
	obj := s.reg.Object(objName)
	if obj == nil {
		s.add(st.Pos(), "struct", "struct %s is annotated %s %s, which is not an object in wire/registry.json", id, Directive, objName)
		return
	}
	seen := map[int]bool{}
	for _, k := range fields {
		if seen[k.n] {
			s.add(k.pos, "struct", "%s: key %d appears twice in struct %s", objName, k.n, id)
			continue
		}
		seen[k.n] = true
		reg := obj.Key(k.n)
		status := obj.KeyStatus(k.n)
		if status != wire.StatusActive {
			what, next := status, "register the key in wire/registry.json first"
			switch status {
			case wire.StatusRetired:
				if reg != nil && reg.Was != "" {
					what += " (was " + reg.Was + ")"
				}
				next = "a retired key is never reused: give the field a newly registered key"
			case wire.StatusForbidden:
				next = "it is for preimages only and never on the wire"
			}
			s.add(k.pos, "struct", "%s key %d is %s; field %s of %s may not use it: %s", objName, k.n, what, k.name, id, next)
			continue
		}
		if !contains(reg.Names(), wire.NormName(k.name)) {
			s.add(k.pos, "struct", "%s key %d is %q; field %s of %s has another name (wrong key number, or register the Go name as an alias)", objName, k.n, reg.Name, k.name, id)
		}
		if ok, got := s.typeCompatible(f, k.expr, reg.Type); !ok {
			s.add(k.pos, "struct", "%s key %d (%s) is %s; field %s of %s is %s (%s)", objName, k.n, reg.Name, reg.Type, k.name, id, k.goTyp, got)
		}
	}
	for _, rk := range obj.ActiveKeys() {
		if rk.Req == "must" && !seen[rk.N] {
			s.add(st.Pos(), "struct", "%s key %d (%s) is required; struct %s has no field for it", objName, rk.N, rk.Name, id)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// goKind classifies a field type: bool, int, uint, float, tstr, bstr, raw, array, map, struct,
// any, or unknown (named type the scanner cannot see through without type information).
func (s *scanner) goKind(f *file, e ast.Expr) string {
	if f.info != nil {
		if tv, ok := f.info.Types[e]; ok && tv.Type != nil {
			return kindOfType(tv.Type)
		}
	}
	return s.astKind(f.pkg, e, 0)
}

func kindOfType(t types.Type) string {
	if n, ok := t.(*types.Named); ok {
		if o := n.Obj(); o != nil && o.Pkg() != nil && o.Pkg().Path() == "github.com/fxamacker/cbor/v2" && o.Name() == "RawMessage" {
			return "raw"
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		switch {
		case u.Info()&types.IsBoolean != 0:
			return "bool"
		case u.Info()&types.IsUnsigned != 0:
			return "uint"
		case u.Info()&types.IsInteger != 0:
			return "int"
		case u.Info()&types.IsFloat != 0:
			return "float"
		case u.Info()&types.IsString != 0:
			return "tstr"
		}
	case *types.Slice:
		if b, ok := u.Elem().Underlying().(*types.Basic); ok && b.Kind() == types.Uint8 {
			return "bstr"
		}
		return "array"
	case *types.Array:
		if b, ok := u.Elem().Underlying().(*types.Basic); ok && b.Kind() == types.Uint8 {
			return "bstr"
		}
		return "array"
	case *types.Map:
		return "map"
	case *types.Pointer:
		return kindOfType(u.Elem())
	case *types.Struct:
		return "struct"
	case *types.Interface:
		return "any"
	}
	return "unknown"
}

func (s *scanner) astKind(pkg string, e ast.Expr, depth int) string {
	if depth > 8 {
		return "unknown"
	}
	switch t := e.(type) {
	case *ast.Ident:
		switch t.Name {
		case "bool":
			return "bool"
		case "int", "int8", "int16", "int32", "int64":
			return "int"
		case "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "byte":
			return "uint"
		case "float32", "float64":
			return "float"
		case "string":
			return "tstr"
		case "any":
			return "any"
		}
		if d, ok := s.localTyp[pkg][t.Name]; ok {
			return s.astKind(pkg, d, depth+1)
		}
		return "unknown"
	case *ast.ArrayType:
		if id, ok := t.Elt.(*ast.Ident); ok && (id.Name == "byte" || id.Name == "uint8") {
			return "bstr"
		}
		return "array"
	case *ast.MapType:
		return "map"
	case *ast.StarExpr:
		return s.astKind(pkg, t.X, depth+1)
	case *ast.StructType:
		return "struct"
	case *ast.InterfaceType:
		return "any"
	case *ast.SelectorExpr:
		if x, ok := t.X.(*ast.Ident); ok && x.Name == "cbor" && t.Sel.Name == "RawMessage" {
			return "raw"
		}
	}
	return "unknown"
}

// typeCompatible says whether a field of Go type e can carry registry type want.
func (s *scanner) typeCompatible(f *file, e ast.Expr, want string) (bool, string) {
	got := s.goKind(f, e)
	if got == "raw" || got == "any" || got == "unknown" || want == "any" {
		return true, got
	}
	for _, alt := range strings.Split(want, "|") {
		alt = strings.TrimSpace(alt)
		switch {
		case alt == "null":
			continue
		case alt == "uint" || alt == "int" || alt == "bool" || alt == "float" || alt == "tstr":
			if got == alt {
				return true, got
			}
		case alt == "bstr" || strings.HasPrefix(alt, "bstr<"):
			if got == "bstr" {
				return true, got
			}
		case strings.HasPrefix(alt, "["):
			if got == "array" {
				return true, got
			}
		case strings.HasPrefix(alt, "tuple("):
			if got == "array" || got == "struct" {
				return true, got
			}
		case alt == "map":
			if got == "map" || got == "struct" {
				return true, got
			}
		case strings.HasPrefix(alt, "<") && strings.HasSuffix(alt, ">"):
			if got == "map" {
				return true, got
			}
			if got == "struct" {
				if name := s.annotationOf(f, e); name != "" && name != alt[1:len(alt)-1] {
					return false, "a struct bound to " + name
				}
				return true, got
			}
		}
	}
	return false, got
}

// annotationOf returns the registry object a named struct type is bound to, when the scanner
// saw its declaration.
func (s *scanner) annotationOf(f *file, e ast.Expr) string {
	if f.info != nil {
		if tv, ok := f.info.Types[e]; ok && tv.Type != nil {
			t := tv.Type
			if p, ok := t.(*types.Pointer); ok {
				t = p.Elem()
			}
			if n, ok := t.(*types.Named); ok && n.Obj().Pkg() != nil {
				return s.annot[n.Obj().Pkg().Path()+"."+n.Obj().Name()]
			}
		}
		return ""
	}
	if st, ok := e.(*ast.StarExpr); ok {
		e = st.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return s.annot[s.pkgPath(s.cfg.Repo, f.pkg)+"."+id.Name]
	}
	return ""
}

// ---- constants ----

func (s *scanner) constRules(f *file) []*wire.ConstRule {
	var out []*wire.ConstRule
	for _, r := range s.reg.Scan.Consts {
		if r.Repo == s.cfg.Repo && r.Pkg == f.pkg {
			out = append(out, r)
		}
	}
	// longest prefix first: "preKey" before "key"
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].Prefix) > len(out[j].Prefix) })
	return out
}

func hasPrefixWord(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
		return false
	}
	c := name[len(prefix)]
	return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func (s *scanner) constValue(f *file, id *ast.Ident, v ast.Expr) (constant.Value, bool) {
	if f.info != nil {
		if obj, ok := f.info.Defs[id].(*types.Const); ok {
			return obj.Val(), true
		}
	}
	if bl, ok := v.(*ast.BasicLit); ok {
		switch bl.Kind {
		case token.INT, token.STRING:
			cv := constant.MakeFromLiteral(bl.Value, bl.Kind, 0)
			return cv, cv.Kind() != constant.Unknown
		}
	}
	return nil, false
}

func (s *scanner) checkConsts(f *file) {
	rules := s.constRules(f)
	if len(rules) == 0 {
		return
	}
	for _, decl := range f.ast.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, id := range vs.Names {
				var rule *wire.ConstRule
				for _, r := range rules {
					if hasPrefixWord(id.Name, r.Prefix) {
						rule = r
						break
					}
				}
				if rule == nil {
					continue
				}
				var vexpr ast.Expr
				if i < len(vs.Values) {
					vexpr = vs.Values[i]
				}
				cv, ok := s.constValue(f, id, vexpr)
				if !ok || cv.Kind() != constant.Int {
					continue
				}
				val, _ := constant.Int64Val(cv)
				s.checkConst(f, id, rule, int(val))
			}
		}
	}
}

func (s *scanner) checkConst(f *file, id *ast.Ident, rule *wire.ConstRule, val int) {
	goName := f.pkg + "." + id.Name
	obj := s.reg.Object(rule.Object)
	suffix := wire.NormName(id.Name[len(rule.Prefix):])
	var match *wire.Key
	if obj != nil {
		for _, k := range obj.Keys {
			if contains(k.Names(), suffix) {
				match = k
				break
			}
		}
	}
	if match != nil && match.Status == wire.StatusActive && match.N == val {
		return
	}
	for _, e := range s.tr.For(s.cfg.Repo, wire.TransConst) {
		if e.Go == goName && e.Value == strconv.Itoa(val) {
			s.used[e] = true
			return
		}
	}
	defer s.fix(&wire.TransitionEntry{Kind: wire.TransConst, Go: goName, Value: strconv.Itoa(val)})
	switch {
	case obj == nil:
		s.add(id.Pos(), "const", "%s: registry object %q of scan rule %s* does not exist", goName, rule.Object, rule.Prefix)
	case match == nil:
		s.add(id.Pos(), "const", "%s = %d names no key of %s; register the key (or an alias) or rename the constant", goName, val, rule.Object)
	case match.Status != wire.StatusActive:
		s.add(id.Pos(), "const", "%s = %d: %s key %d is %s; drop the constant", goName, val, rule.Object, match.N, match.Status)
	default:
		s.add(id.Pos(), "const", "%s = %d, but %s key %q is %d", goName, val, rule.Object, match.Name, match.N)
	}
}

// ---- strings ----

func (s *scanner) pattern() *regexp.Regexp {
	p := s.reg.Scan.Pattern
	if p == "" {
		p = `^anet[-./]`
	}
	return regexp.MustCompile(p)
}

func (s *scanner) exempt(v string) bool {
	for _, x := range s.reg.Exempt {
		switch x.Match {
		case "exact":
			if v == x.Value {
				return true
			}
		case "prefix":
			if strings.HasPrefix(v, x.Value) {
				return true
			}
		case "regexp":
			if regexp.MustCompile(x.Value).MatchString(v) {
				return true
			}
		}
	}
	return false
}

func (s *scanner) checkStrings(f *file) {
	re := s.pattern()
	ast.Inspect(f.ast, func(n ast.Node) bool {
		// struct tags and import paths are not string values
		switch t := n.(type) {
		case *ast.Field:
			if t.Type != nil {
				ast.Inspect(t.Type, func(m ast.Node) bool { return s.inspectString(re, m) })
			}
			return false
		case *ast.ImportSpec:
			return false
		}
		return s.inspectString(re, n)
	})
}

func (s *scanner) inspectString(re *regexp.Regexp, n ast.Node) bool {
	bl, ok := n.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return true
	}
	v, err := strconv.Unquote(bl.Value)
	if err != nil || !re.MatchString(v) {
		return true
	}
	// a B-class prefix is written with its 0x00 separator; the label is what comes before it
	v = strings.TrimRight(v, "\x00")
	status, where := s.reg.StringStatus(v)
	if status == wire.StatusActive || status == "" && s.exempt(v) {
		return true
	}
	for _, e := range s.tr.For(s.cfg.Repo, wire.TransString) {
		if e.Value == v {
			s.used[e] = true
			return true
		}
	}
	if status != "" {
		s.add(bl.Pos(), "string", "%q is %s in this release (%s): remove it", v, status, where)
	} else {
		s.add(bl.Pos(), "string", "%q is not registered: add it to wire/registry.json (label, type tag, metadata key, event or string) or rename it", v)
	}
	s.fix(&wire.TransitionEntry{Kind: wire.TransString, Value: v})
	return true
}

// ---- relayauth actions ----

func (s *scanner) checkActions(f *file) {
	rule := s.reg.Scan.Actions
	if rule == nil || rule.Repo != s.cfg.Repo || rule.Pkg != f.pkg {
		return
	}
	for _, decl := range f.ast.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, id := range vs.Names {
				if !hasPrefixWord(id.Name, rule.Prefix) {
					continue
				}
				var vexpr ast.Expr
				if i < len(vs.Values) {
					vexpr = vs.Values[i]
				}
				cv, ok := s.constValue(f, id, vexpr)
				if !ok || cv.Kind() != constant.String {
					continue
				}
				s.checkActionValue(id.Pos(), constant.StringVal(cv), id.Name)
			}
		}
	}
}

// actionParams finds the parameters that carry a relayauth action: the string parameters named
// rule.Param of package relayauth's functions, and, to a fixed point, every parameter of this
// repository's functions that is passed on unchanged into one of those (a daemon's signed-request
// helper, a hub route's auth helper). The key is the function's full name and the parameter
// index.
func (s *scanner) actionParams() map[string]map[int]bool {
	rule := s.reg.Scan.Actions
	out := map[string]map[int]bool{}
	if rule == nil || rule.Param == "" {
		return out
	}
	relay := s.pkgPath(rule.Repo, rule.Pkg)
	isAction := func(fn *types.Func, i int) bool {
		if fn == nil {
			return false
		}
		if fn.Pkg() != nil && fn.Pkg().Path() == relay {
			sig := fn.Type().(*types.Signature)
			if i < sig.Params().Len() {
				p := sig.Params().At(i)
				b, ok := p.Type().Underlying().(*types.Basic)
				return p.Name() == rule.Param && ok && b.Info()&types.IsString != 0
			}
			return false
		}
		return out[fn.FullName()][i]
	}
	type decl struct {
		f  *file
		fd *ast.FuncDecl
		fn *types.Func
	}
	var decls []decl
	for _, f := range s.files {
		if f.info == nil {
			continue
		}
		for _, d := range f.ast.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				if fn, ok := f.info.Defs[fd.Name].(*types.Func); ok {
					decls = append(decls, decl{f, fd, fn})
				}
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, d := range decls {
			sig := d.fn.Type().(*types.Signature)
			params := map[types.Object]int{}
			for i := 0; i < sig.Params().Len(); i++ {
				if b, ok := sig.Params().At(i).Type().Underlying().(*types.Basic); ok && b.Info()&types.IsString != 0 {
					params[sig.Params().At(i)] = i
				}
			}
			if len(params) == 0 {
				continue
			}
			ast.Inspect(d.fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				callee := calleeFunc(d.f.info, call)
				for ai, arg := range call.Args {
					id, ok := arg.(*ast.Ident)
					if !ok {
						continue
					}
					pi, ok := params[d.f.info.Uses[id]]
					if !ok || !isAction(callee, ai) {
						continue
					}
					name := d.fn.FullName()
					if out[name] == nil {
						out[name] = map[int]bool{}
					}
					if !out[name][pi] {
						out[name][pi] = true
						changed = true
					}
				}
				return true
			})
		}
	}
	// the seeds themselves, by name, for calls from other repositories
	return out
}

// pkgPath is the import path of package pkg (relative to its module root) in repository repo.
func (s *scanner) pkgPath(repo, pkg string) string {
	mod := "github.com/ANetResearch/" + repo
	if repo == s.cfg.Repo {
		mod = s.modPath
	}
	if pkg == "." || pkg == "" {
		return mod
	}
	return mod + "/" + pkg
}

func calleeFunc(info *types.Info, call *ast.CallExpr) *types.Func {
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		if sel := info.Selections[f]; sel != nil {
			fn, _ := sel.Obj().(*types.Func)
			return fn
		}
		fn, _ := info.Uses[f.Sel].(*types.Func)
		return fn
	case *ast.Ident:
		fn, _ := info.Uses[f].(*types.Func)
		return fn
	}
	return nil
}

// checkActionArgs: a constant string passed as a relayauth action (see actionParams) must be a
// registered, active action.
func (s *scanner) checkActionArgs(f *file, params map[string]map[int]bool) {
	rule := s.reg.Scan.Actions
	if rule == nil || rule.Param == "" || f.info == nil {
		return
	}
	relay := s.pkgPath(rule.Repo, rule.Pkg)
	ast.Inspect(f.ast, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn := calleeFunc(f.info, call)
		if fn == nil {
			return true
		}
		sig := fn.Type().(*types.Signature)
		for i, arg := range call.Args {
			if i >= sig.Params().Len() {
				break
			}
			isParam := params[fn.FullName()][i]
			if !isParam && fn.Pkg() != nil && fn.Pkg().Path() == relay {
				p := sig.Params().At(i)
				b, ok := p.Type().Underlying().(*types.Basic)
				isParam = p.Name() == rule.Param && ok && b.Info()&types.IsString != 0
			}
			if !isParam {
				continue
			}
			av, ok := f.info.Types[arg]
			if !ok || av.Value == nil || av.Value.Kind() != constant.String {
				continue
			}
			s.checkActionValue(arg.Pos(), constant.StringVal(av.Value), "action argument of "+s.relFunc(fn.FullName()))
		}
		return true
	})
}

func (s *scanner) checkActionValue(pos token.Pos, name, what string) {
	a := s.reg.Action(name)
	if a != nil && a.Status == wire.StatusActive {
		return
	}
	found := false
	for _, e := range s.tr.For(s.cfg.Repo, wire.TransAction) {
		if e.Value == name {
			s.used[e] = true
			found = true
		}
	}
	if found {
		return
	}
	if a == nil {
		s.add(pos, "action", "relayauth action %q (%s) is not registered: add it to registry relayauth.actions (hub routes check it)", name, what)
	} else {
		s.add(pos, "action", "relayauth action %q (%s) is %s: remove it", name, what, a.Status)
	}
	s.fix(&wire.TransitionEntry{Kind: wire.TransAction, Value: name})
}

// ---- reason tables ----

func (s *scanner) checkReasonDecls(f *file) {
	for _, decl := range f.ast.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
			continue
		}
		arg, ok := directiveFor(s.fset, f.ast, gd)
		if !ok || !strings.HasPrefix(arg, "reasons.") {
			continue
		}
		fields := strings.Fields(arg)
		ns := strings.TrimPrefix(fields[0], "reasons.")
		complete := len(fields) > 1 && fields[1] == "complete"
		if _, known := s.reg.Reasons.Namespaces()[ns]; !known {
			s.add(gd.Pos(), "reasons", "%s %s: no such reason namespace", Directive, fields[0])
			continue
		}
		codes := map[string]token.Pos{}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, id := range vs.Names {
				var v ast.Expr
				if i < len(vs.Values) {
					v = vs.Values[i]
				}
				if gd.Tok == token.CONST {
					if cv, ok := s.constValue(f, id, v); ok && cv.Kind() == constant.String {
						codes[constant.StringVal(cv)] = id.Pos()
					}
					continue
				}
				s.tableKeys(f, v, codes)
			}
		}
		for c, pos := range codes {
			if strings.ContainsAny(c, ".:") {
				continue // sentence keys and variants live only in the table (CORE-K25, K28)
			}
			if s.reg.Reason(ns, c) == nil {
				s.add(pos, "reasons", "code %q is not in registry reasons.%s: add it there (and to the UX reason table) first", c, ns)
			}
		}
		if complete {
			for _, c := range s.reg.ReasonCodes(ns) {
				if _, ok := codes[c]; !ok {
					s.add(gd.Pos(), "reasons", "registry reasons.%s has %q, this table has no row for it", ns, c)
				}
			}
		}
	}
}

// tableKeys collects the string keys of a reason table literal: the keys of a map literal, or
// the code of each element of a slice literal (its Code/code field, else its first string).
func (s *scanner) tableKeys(f *file, v ast.Expr, out map[string]token.Pos) {
	cl, ok := v.(*ast.CompositeLit)
	if !ok {
		return
	}
	str := func(e ast.Expr) (string, bool) {
		if f.info != nil {
			if tv, ok := f.info.Types[e]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
				return constant.StringVal(tv.Value), true
			}
		}
		if bl, ok := e.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			u, err := strconv.Unquote(bl.Value)
			return u, err == nil
		}
		return "", false
	}
	for _, el := range cl.Elts {
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			if k, ok := str(kv.Key); ok {
				out[k] = kv.Pos()
				continue
			}
			el = kv.Value
		}
		inner, ok := el.(*ast.CompositeLit)
		if !ok {
			continue
		}
		var first string
		found := false
		for _, e := range inner.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok && strings.EqualFold(id.Name, "code") {
					if c, ok := str(kv.Value); ok {
						first, found = c, true
						break
					}
				}
				continue
			}
			if c, ok := str(e); ok && !found {
				first, found = c, true
			}
		}
		if found {
			out[first] = inner.Pos()
		}
	}
}

// ---- signers ----

func (s *scanner) relFunc(full string) string {
	for _, m := range []string{"github.com/ANetResearch/ANetCore", "github.com/ANetResearch/ANetHub", "github.com/ANetResearch/ANet", s.modPath} {
		full = strings.ReplaceAll(full, m+"/", "")
		full = strings.ReplaceAll(full, m+".", "")
	}
	return full
}

func (s *scanner) isSigning(f *file, fn *types.Func, recv types.Type) bool {
	full := fn.FullName()
	for _, m := range s.reg.Signers.Methods {
		if full == m {
			return true
		}
	}
	if recv == nil {
		return false
	}
	for _, it := range s.ifaces[f.conf] {
		if !hasMethod(it, fn.Name()) {
			continue
		}
		if types.Implements(recv, it) || types.Implements(types.NewPointer(recv), it) {
			return true
		}
	}
	return false
}

func (s *scanner) checkSigners(f *file) {
	if f.info == nil {
		return
	}
	for _, decl := range f.ast.Decls {
		var owner string
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if obj, ok := f.info.Defs[d.Name].(*types.Func); ok {
				owner = s.relFunc(obj.FullName())
			} else {
				owner = f.pkg + "." + d.Name.Name
			}
		default:
			owner = f.pkg + ".<init>"
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			var fn *types.Func
			var recv types.Type
			if selection := f.info.Selections[sel]; selection != nil {
				fn, _ = selection.Obj().(*types.Func)
				recv = selection.Recv()
			} else if obj, ok := f.info.Uses[sel.Sel].(*types.Func); ok {
				fn = obj
			}
			if fn == nil || !s.isSigning(f, fn, recv) {
				return true
			}
			s.signerCall(call.Pos(), owner, s.relFunc(fn.FullName()))
			return true
		})
	}
}

func (s *scanner) signerCall(pos token.Pos, owner, method string) {
	for _, c := range s.reg.Signers.Calls {
		if c.Repo == s.cfg.Repo && c.Func == owner {
			s.usedSign[c] = true
			return
		}
	}
	for _, e := range s.tr.For(s.cfg.Repo, wire.TransSigner) {
		if e.Go == owner {
			s.used[e] = true
			return
		}
	}
	s.add(pos, "signer", "%s signs with an identity key (%s) but is not in registry signers: list it with the object it signs; a new signed object needs a key-0 type tag first (CORE-L9)", owner, method)
	s.fix(&wire.TransitionEntry{Kind: wire.TransSigner, Go: owner})
}

func (s *scanner) checkSignerMethods() {
	for _, m := range s.reg.Signers.Methods {
		recv, name, ok := splitMethod(m)
		if !ok {
			s.addAt("wire/registry.json", "signer", "signers.methods entry %q is not of the form (pkg.Type).Method", m)
			continue
		}
		pkgPath, tname, ok := splitQualified(recv)
		if !ok {
			s.addAt("wire/registry.json", "signer", "signers.methods entry %q has no package", m)
			continue
		}
		if pkgPath != s.modPath && !strings.HasPrefix(pkgPath, s.modPath+"/") {
			continue // declared in another repository; checked there
		}
		var found bool
		for _, f := range s.files {
			if f.tpkg == nil || f.tpkg.Path() != pkgPath {
				continue
			}
			if obj := f.tpkg.Scope().Lookup(tname); obj != nil {
				ms := types.NewMethodSet(types.NewPointer(obj.Type()))
				for i := 0; i < ms.Len(); i++ {
					if ms.At(i).Obj().Name() == name {
						found = true
					}
				}
				if it, ok := obj.Type().Underlying().(*types.Interface); ok && hasMethod(it, name) {
					found = true
				}
			}
			break
		}
		if !found {
			s.addAt("wire/registry.json", "signer", "signing method %s does not exist: update registry signers.methods to the identity package's signing method", m)
		}
	}
}

// ---- stale entries ----

func (s *scanner) checkStale() {
	for _, c := range s.reg.Signers.Calls {
		if c.Repo == s.cfg.Repo && !s.usedSign[c] {
			s.addAt("wire/registry.json", "signer", "registry signers lists %s (%s) but it no longer calls an identity signing method: remove or rename the entry", c.Func, s.cfg.Repo)
		}
	}
	for _, e := range s.tr.Entries {
		if e.Repo != s.cfg.Repo || s.used[e] {
			continue
		}
		what := e.Go
		if what == "" {
			what = strconv.Quote(e.Value)
		}
		s.addAt("wire/transition.json", "transition", "%s entry %s (%s) matches nothing in %s any more: delete it", e.Kind, what, e.Todo, s.cfg.Repo)
	}
}
