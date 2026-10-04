package golden

// index_test.go checks golden/testdata/index.json, the register of every golden vector (CORE-G1).
//
// The index is what makes "every label and every object has a vector" checkable. Without it a
// vector can be planned and never written, written and never read, or deleted with nobody
// noticing, and a label can lose its last vector the same way. So:
//
//   - every A, B and C label of wire/registry.json, and every object, is covered by a row of the
//     index (an object with no vector at all is listed under "uncovered", with the reason; only a
//     node-local object or one carried unchanged from 0.2.1 may be, CORE-G1's one exception, so a
//     new object that travels between nodes always needs a vector);
//   - every file and test the index names exists, unless it is marked todo; one marked todo must
//     not exist yet (the change that delivers it removes the marker); a retired vector must be
//     gone unless it is marked todo, and must not be gone while it is;
//   - every vector file is read by a Go test of its repository;
//   - every vector the index says gen_v016.py writes has a generator there, and only those.
//
// The repositories other than ANetCore are checked when they sit next to this checkout (or under
// Refs/); otherwise their rows are listed as not checked. ANET_GOLDEN_ALL_REPOS=1 turns a missing
// repository into a failure (the integration workspace sets it).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ANetResearch/ANetCore/wire"
)

const (
	indexPath     = "testdata/index.json"
	generatorPath = "py/gen_v016.py"
	indexFormat   = "anet-golden-index/1"
)

// The kinds of "gen": who produces a vector's bytes. pyGens are the kinds gen_v016.py writes.
var (
	allGens   = []string{"python", "go+python", "go", "rfc", "a2a-python"}
	pyGens    = map[string]bool{"python": true, "go+python": true, "rfc": true}
	repoNames = []string{"ANetCore", "ANet", "ANetHub", "ANetLink"}
)

type goldenIndex struct {
	Format    string             `json:"format"`
	About     string             `json:"about"`
	Seeds     string             `json:"seeds"`
	Gens      map[string]string  `json:"gens"`
	Vectors   []*goldenVector    `json:"vectors"`
	Retired   []*retiredVector   `json:"retired"`
	Uncovered []*uncoveredObject `json:"uncovered"`
}

type goldenVector struct {
	ID      string      `json:"id"`
	Gen     string      `json:"gen"`
	Owner   string      `json:"owner"`
	Covers  string      `json:"covers"`
	Labels  []string    `json:"labels"`
	Objects []string    `json:"objects"`
	At      []*artifact `json:"at"`
}

type retiredVector struct {
	ID  string      `json:"id"`
	Why string      `json:"why"`
	At  []*artifact `json:"at"`
}

type uncoveredObject struct {
	Object string `json:"object"`
	Why    string `json:"why"`
}

// artifact is where (part of) a vector lives: a file, a directory of files (Path ends in "/",
// Glob says which), or a test function in a Go file.
type artifact struct {
	Repo   string `json:"repo"`
	Path   string `json:"path"`
	Glob   string `json:"glob,omitempty"`
	Test   string `json:"test,omitempty"`
	Todo   string `json:"todo,omitempty"`   // not delivered yet: must not exist
	Rework string `json:"rework,omitempty"` // exists in its v0.2 form, still to be rewritten
}

func (a *artifact) String() string {
	if a.Test != "" {
		return a.Repo + "/" + a.Path + "#" + a.Test
	}
	return a.Repo + "/" + a.Path
}

func (a *artifact) isDir() bool { return strings.HasSuffix(a.Path, "/") }

// ref is what a Go test that reads the artifact must mention: the file name, or the directory's.
func (a *artifact) ref() string { return path.Base(strings.TrimSuffix(a.Path, "/")) }

func parseIndex(b []byte) (*goldenIndex, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var ix goldenIndex
	if err := dec.Decode(&ix); err != nil {
		return nil, fmt.Errorf("%s: %w", indexPath, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: data after the object", indexPath)
	}
	// A null where a row belongs is a broken file, not an empty row.
	for i, v := range ix.Vectors {
		if v == nil || hasNil(v.At) {
			return nil, fmt.Errorf("%s: vectors[%d] is null or has a null artifact", indexPath, i)
		}
	}
	for i, r := range ix.Retired {
		if r == nil || hasNil(r.At) {
			return nil, fmt.Errorf("%s: retired[%d] is null or has a null artifact", indexPath, i)
		}
	}
	for i, u := range ix.Uncovered {
		if u == nil {
			return nil, fmt.Errorf("%s: uncovered[%d] is null", indexPath, i)
		}
	}
	return &ix, nil
}

func hasNil(at []*artifact) bool {
	for _, a := range at {
		if a == nil {
			return true
		}
	}
	return false
}

// regView is the part of the registry the index is checked against.
type regView struct {
	labels  map[string]string   // tag id → its strings, for A, B and C labels (CORE-G1)
	tags    map[string]bool     // every tag id
	objects map[string]bool     // every object
	waits   map[string]bool     // objects that may sit under "uncovered": node-local or carried
	golden  map[string][]string // tag id → the vectors its "golden" column names
}

func viewOf(r *wire.Registry) *regView {
	v := &regView{labels: map[string]string{}, tags: map[string]bool{}, objects: map[string]bool{}, waits: map[string]bool{}, golden: map[string][]string{}}
	for _, t := range r.Tags {
		v.tags[t.ID] = true
		if t.Class == "A" || t.Class == "B" || t.Class == "C" {
			v.labels[t.ID] = strings.Join(t.Values, ", ")
		}
		for _, g := range strings.Split(t.Golden, ",") {
			g, _, _ = strings.Cut(strings.TrimSpace(g), " (")
			if g != "" && g != "-" && g != "unchanged" {
				v.golden[t.ID] = append(v.golden[t.ID], g)
			}
		}
	}
	for _, o := range r.Objects {
		v.objects[o.Name] = true
		if o.Group == "local" || o.Carried {
			v.waits[o.Name] = true
		}
	}
	return v
}

var testName = regexp.MustCompile(`^Test[A-Za-z0-9_]+$`)

func checkArtifactShape(where string, a *artifact, retired bool) []string {
	var p []string
	bad := func(f string, args ...any) { p = append(p, where+": "+fmt.Sprintf(f, args...)) }
	if !contains(repoNames, a.Repo) {
		bad("repository %q is not one of %s", a.Repo, strings.Join(repoNames, ", "))
	}
	// fs.ValidPath refuses "", "/x", "x/", "x//y" and every "." or ".." element, so ".." on its
	// own is refused as well as "../x"; "." is valid there but names the repository, not a vector.
	p0 := strings.TrimSuffix(a.Path, "/")
	if !fs.ValidPath(p0) || p0 == "." || strings.Contains(a.Path, `\`) {
		bad("path %q is not a clean path inside the repository", a.Path)
	}
	switch {
	case a.isDir() && (a.Glob == "" || a.Test != ""):
		bad("a directory (%s) needs a glob of the files in it, and no test", a.Path)
	case !a.isDir() && a.Glob != "":
		bad("glob %q is only for a directory (a path ending in /)", a.Glob)
	case a.Test != "" && (!testName.MatchString(a.Test) || !strings.HasSuffix(a.Path, "_test.go")):
		bad("test %q must be a Test… function in a _test.go file", a.Test)
	}
	if a.Glob != "" {
		if _, err := path.Match(a.Glob, "x"); err != nil {
			bad("glob %q: %v", a.Glob, err)
		}
	}
	for _, m := range []string{a.Todo, a.Rework} {
		if m != "" && !wire.TodoPattern.MatchString(m) {
			bad("marker %q is not %s", m, wire.TodoMarker("<work item>"))
		}
	}
	if a.Todo != "" && a.Rework != "" {
		bad("todo and rework together: an artifact is either still to come or still to be rewritten")
	}
	if retired && a.Rework != "" {
		bad("a retired vector is deleted, not reworked")
	}
	return p
}

// checkShape checks the index on its own and against the registry's names.
func checkShape(ix *goldenIndex, rv *regView) []string {
	var p []string
	bad := func(f string, args ...any) { p = append(p, fmt.Sprintf(f, args...)) }
	if ix.Format != indexFormat {
		bad("format is %q, want %q", ix.Format, indexFormat)
	}
	var kinds []string
	for k := range ix.Gens {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	want := append([]string(nil), allGens...)
	sort.Strings(want)
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		bad("gens lists %v; the kinds index_test.go and gen_v016.py know are %v", kinds, want)
	}
	ids := map[string]bool{}
	seen := func(id string) {
		if id == "" || strings.ContainsAny(id, " \t\n") {
			bad("vector id %q is empty or has a space", id)
		}
		if ids[id] {
			bad("vector %s is listed twice", id)
		}
		ids[id] = true
	}
	for _, v := range ix.Vectors {
		seen(v.ID)
		if !contains(allGens, v.Gen) {
			bad("%s: gen %q is not one of %v", v.ID, v.Gen, allGens)
		}
		if v.Owner == "" || v.Covers == "" || len(v.At) == 0 {
			bad("%s: owner, covers and at must all be given", v.ID)
		}
		if dup := firstDup(v.Labels); dup != "" {
			bad("%s: label %s twice", v.ID, dup)
		}
		if dup := firstDup(v.Objects); dup != "" {
			bad("%s: object %s twice", v.ID, dup)
		}
		for _, l := range v.Labels {
			if !rv.tags[l] {
				bad("%s: unknown label %q (labels are wire/registry.json tag ids, L1…)", v.ID, l)
			}
		}
		for _, o := range v.Objects {
			if !rv.objects[o] {
				bad("%s: unknown object %q (objects are wire/registry.json object names)", v.ID, o)
			}
		}
		for _, a := range v.At {
			p = append(p, checkArtifactShape(v.ID+": "+a.String(), a, false)...)
			if pyGens[v.Gen] && (a.Test != "" || a.isDir()) {
				bad("%s: gen %s is written by gen_v016.py, so %s must be a file", v.ID, v.Gen, a)
			}
		}
	}
	for _, r := range ix.Retired {
		seen(r.ID)
		if r.Why == "" || len(r.At) == 0 {
			bad("%s: a retired vector needs why and at", r.ID)
		}
		for _, a := range r.At {
			p = append(p, checkArtifactShape(r.ID+": "+a.String(), a, true)...)
		}
	}
	listed := map[string]bool{}
	for _, u := range ix.Uncovered {
		switch {
		case !rv.objects[u.Object]:
			bad("uncovered: unknown object %q", u.Object)
		case !rv.waits[u.Object]:
			bad("uncovered: %s is new in 0.3.0 and is not a node-local file, so CORE-G1 needs a vector for it; add it to the objects of the vector that covers it", u.Object)
		}
		if u.Why == "" {
			bad("uncovered: %s needs the reason it has no vector", u.Object)
		}
		if listed[u.Object] {
			bad("uncovered: %s is listed twice", u.Object)
		}
		listed[u.Object] = true
	}
	return p
}

// checkCoverage is CORE-G1: every A, B and C label and every object is covered by a vector, and
// the registry's "golden" column agrees with the index.
func checkCoverage(ix *goldenIndex, rv *regView) []string {
	var p []string
	labelBy := map[string][]string{}
	objectBy := map[string][]string{}
	byID := map[string]*goldenVector{}
	for _, v := range ix.Vectors {
		byID[v.ID] = v
		for _, l := range v.Labels {
			labelBy[l] = append(labelBy[l], v.ID)
		}
		for _, o := range v.Objects {
			objectBy[o] = append(objectBy[o], v.ID)
		}
	}
	for _, id := range sortedKeys(rv.labels) {
		if len(labelBy[id]) == 0 {
			p = append(p, fmt.Sprintf("label %s (%s) is covered by no vector; add it to the labels of the vector that covers it (CORE-G1)", id, rv.labels[id]))
		}
	}
	uncovered := map[string]bool{}
	for _, u := range ix.Uncovered {
		uncovered[u.Object] = true
		if by := objectBy[u.Object]; len(by) > 0 {
			p = append(p, fmt.Sprintf("object %s is listed under uncovered but %s covers it; remove it from uncovered", u.Object, strings.Join(by, ", ")))
		}
	}
	for _, o := range sortedKeys(rv.objects) {
		if len(objectBy[o]) == 0 && !uncovered[o] {
			p = append(p, fmt.Sprintf("object %s is covered by no vector; add it to the objects of the vector that covers it, or list it under uncovered with the reason (CORE-G1)", o))
		}
	}
	for _, id := range sortedKeys(rv.golden) {
		for _, g := range rv.golden[id] {
			v := byID[g]
			switch {
			case v == nil:
				p = append(p, fmt.Sprintf("wire/registry.json names vector %s for label %s, but the index has no vector %s", g, id, g))
			case !contains(v.Labels, id):
				p = append(p, fmt.Sprintf("wire/registry.json says vector %s covers label %s, but its row in the index does not list %s", g, id, id))
			}
		}
	}
	return p
}

// present says whether an artifact exists in fsys: the file, a file matching the glob in the
// directory, or the test function in the Go file.
func present(fsys fs.FS, a *artifact) (bool, error) {
	switch {
	case a.isDir():
		m, err := fs.Glob(fsys, path.Join(strings.TrimSuffix(a.Path, "/"), a.Glob))
		return len(m) > 0, err
	case a.Test != "":
		src, err := fs.ReadFile(fsys, a.Path)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		f, err := parser.ParseFile(token.NewFileSet(), a.Path, src, parser.SkipObjectResolution)
		if err != nil {
			return false, err
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == a.Test {
				return true, nil
			}
		}
		return false, nil
	default:
		st, err := fs.Stat(fsys, a.Path)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return st.Mode().IsRegular(), nil
	}
}

// checkArtifacts checks that what the index names is there (or, for todo, not yet there). Rows
// in a repository that is not in repos come back as unchecked.
func checkArtifacts(ix *goldenIndex, repos map[string]fs.FS) (p, unchecked []string) {
	look := func(id string, a *artifact) (bool, bool) {
		fsys := repos[a.Repo]
		if fsys == nil {
			unchecked = append(unchecked, id+": "+a.String())
			return false, false
		}
		ok, err := present(fsys, a)
		if err != nil {
			p = append(p, fmt.Sprintf("%s: %s cannot be read: %v", id, a, err))
			return false, false
		}
		return ok, true
	}
	for _, v := range ix.Vectors {
		for _, a := range v.At {
			ok, checked := look(v.ID, a)
			switch {
			case !checked:
			case a.Todo != "" && ok:
				p = append(p, fmt.Sprintf("%s: %s is delivered, but the index still marks it %s; remove the marker from golden/testdata/index.json", v.ID, a, a.Todo))
			case a.Todo == "" && !ok:
				p = append(p, fmt.Sprintf("%s: %s is missing; the index registers it as delivered, so restore it (or, if the vector really moved, update its row)", v.ID, a))
			}
		}
	}
	for _, r := range ix.Retired {
		for _, a := range r.At {
			ok, checked := look(r.ID, a)
			switch {
			case !checked:
			case a.Todo != "" && !ok:
				p = append(p, fmt.Sprintf("retired %s: %s is gone, but the index still marks it %s; remove the marker", r.ID, a, a.Todo))
			case a.Todo == "" && ok:
				p = append(p, fmt.Sprintf("retired %s: %s still exists; delete it (%s)", r.ID, a, r.Why))
			}
		}
	}
	return p, unchecked
}

// testSources returns the Go test files of a repository, by path (Go's own rules for which
// directories hold packages: none starting with "." or "_", no testdata).
func testSources(fsys fs.FS) (map[string][]byte, error) {
	out := map[string][]byte{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != "." && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor" || name == "node_modules") {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(name, "_test.go") {
			b, err := fs.ReadFile(fsys, p)
			if err != nil {
				return err
			}
			out[p] = b
		}
		return nil
	})
	return out, err
}

// checkReaders: every vector file or directory that exists is read by a Go test of its
// repository, which names it. A vector no test reads checks nothing.
func checkReaders(ix *goldenIndex, repos map[string]fs.FS) []string {
	var p []string
	srcs := map[string]map[string][]byte{}
	for _, v := range ix.Vectors {
		for _, a := range v.At {
			fsys := repos[a.Repo]
			if a.Test != "" || a.Todo != "" || fsys == nil {
				continue
			}
			if ok, _ := present(fsys, a); !ok {
				continue // checkArtifacts reports it
			}
			if srcs[a.Repo] == nil {
				s, err := testSources(fsys)
				if err != nil {
					p = append(p, fmt.Sprintf("%s: reading the tests of %s: %v", v.ID, a.Repo, err))
					continue
				}
				srcs[a.Repo] = s
			}
			found := false
			for _, b := range srcs[a.Repo] {
				if bytes.Contains(b, []byte(a.ref())) {
					found = true
					break
				}
			}
			if !found {
				p = append(p, fmt.Sprintf("%s: no Go test in %s names %s; the Go side of a vector is a test that opens or reproduces it", v.ID, a.Repo, a.ref()))
			}
		}
	}
	return p
}

var generatorRx = regexp.MustCompile(`(?m)^@vector\(\s*"([^"]+)"`)

// checkGenerators: gen_v016.py has a generator for every vector the index says it writes once
// a file of it exists, and none for any other vector.
func checkGenerators(ix *goldenIndex, py []byte, repos map[string]fs.FS) []string {
	var p []string
	gens := map[string]bool{}
	for _, m := range generatorRx.FindAllSubmatch(py, -1) {
		gens[string(m[1])] = true
	}
	byID := map[string]*goldenVector{}
	for _, v := range ix.Vectors {
		byID[v.ID] = v
	}
	for _, id := range sortedKeys(gens) {
		switch v := byID[id]; {
		case v == nil:
			p = append(p, fmt.Sprintf("gen_v016.py has a generator for %s, which the index does not list; add its row", id))
		case !pyGens[v.Gen]:
			p = append(p, fmt.Sprintf("gen_v016.py has a generator for %s, whose row says gen %q; make it one of python, go+python, rfc", id, v.Gen))
		}
	}
	for _, v := range ix.Vectors {
		if !pyGens[v.Gen] || gens[v.ID] {
			continue
		}
		for _, a := range v.At {
			if fsys := repos[a.Repo]; fsys != nil {
				if ok, _ := present(fsys, a); ok {
					p = append(p, fmt.Sprintf("%s: %s exists but gen_v016.py has no generator for it, so golden-xcheck cannot reproduce it; register one with @vector(%q, …)", v.ID, a, v.ID))
					break
				}
			}
		}
	}
	return p
}

// findRepos returns this ANetCore checkout and the other repositories found next to it (or in
// Refs/ beside it), each checked by its go.mod module path.
func findRepos(t *testing.T) map[string]fs.FS {
	t.Helper()
	core, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	repos := map[string]fs.FS{"ANetCore": os.DirFS(core)}
	parent := filepath.Dir(core)
	for _, name := range repoNames[1:] {
		for _, dir := range []string{filepath.Join(parent, name), filepath.Join(parent, "Refs", name)} {
			if moduleOf(dir) == "github.com/ANetResearch/"+name {
				repos[name] = os.DirFS(dir)
				break
			}
		}
	}
	return repos
}

func moduleOf(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if m, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.Trim(strings.TrimSpace(m), `"`)
		}
	}
	return ""
}

// TestGoldenIndex checks the real index against the registry, the repositories and
// gen_v016.py. A failure names the vector and what to do.
func TestGoldenIndex(t *testing.T) {
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	ix, err := parseIndex(raw)
	if err != nil {
		t.Fatal(err)
	}
	py, err := os.ReadFile(generatorPath)
	if err != nil {
		t.Fatal(err)
	}
	rv := viewOf(wire.MustLoad())
	repos := findRepos(t)

	problems := checkShape(ix, rv)
	problems = append(problems, checkCoverage(ix, rv)...)
	ap, unchecked := checkArtifacts(ix, repos)
	problems = append(problems, ap...)
	problems = append(problems, checkReaders(ix, repos)...)
	problems = append(problems, checkGenerators(ix, py, repos)...)
	for _, s := range problems {
		t.Error(s)
	}

	var pending []string
	for _, v := range ix.Vectors {
		for _, a := range v.At {
			if a.Todo != "" || a.Rework != "" {
				pending = append(pending, fmt.Sprintf("%s (%s%s)", v.ID, a.Todo, a.Rework))
			}
		}
	}
	t.Logf("%d vectors, %d retired, %d objects with no vector; open: %s", len(ix.Vectors), len(ix.Retired), len(ix.Uncovered), strings.Join(pending, ", "))
	if len(unchecked) > 0 {
		msg := "not checked, repository not next to ANetCore: " + strings.Join(unchecked, "; ")
		if os.Getenv("ANET_GOLDEN_ALL_REPOS") == "1" {
			t.Error(msg)
		} else {
			t.Log(msg)
		}
	}
}

// TestGoldenIndexCatches runs every check on a small made-up index and tree, then changes one
// thing at a time: each change must be reported. These are the mutations the checks exist for.
func TestGoldenIndexCatches(t *testing.T) {
	rv := &regView{
		labels:  map[string]string{"L1": "anet-one/v1", "L2": "anet.two/1"},
		tags:    map[string]bool{"L1": true, "L2": true, "L9": true},
		objects: map[string]bool{"A": true, "B": true, "C": true},
		waits:   map[string]bool{"C": true},
		golden:  map[string][]string{"L1": {"V1"}},
	}
	baseIndex := func() *goldenIndex {
		return &goldenIndex{
			Format: indexFormat,
			Gens:   map[string]string{"python": ".", "go+python": ".", "go": ".", "rfc": ".", "a2a-python": "."},
			Vectors: []*goldenVector{
				{ID: "V1", Gen: "python", Owner: "X", Covers: ".", Labels: []string{"L1"}, Objects: []string{"A"},
					At: []*artifact{{Repo: "ANetCore", Path: "x/testdata/v1.json"}}},
				{ID: "V2", Gen: "go", Owner: "X", Covers: ".", Labels: []string{"L2"}, Objects: []string{"B"},
					At: []*artifact{{Repo: "ANetCore", Path: "x/v2_test.go", Test: "TestV2"}}},
				{ID: "V3", Gen: "go+python", Owner: "X", Covers: ".",
					At: []*artifact{{Repo: "ANet", Path: "y/testdata/v3.json", Todo: wire.TodoMarker("XX-3")}}},
				{ID: "V4", Gen: "go", Owner: "X", Covers: ".",
					At: []*artifact{{Repo: "ANetHub", Path: "z/testdata/v4/", Glob: "*.json"}}},
			},
			Retired:   []*retiredVector{{ID: "R1", Why: "gone", At: []*artifact{{Repo: "ANetCore", Path: "x/old_test.go", Test: "TestOld", Todo: wire.TodoMarker("XX-1")}}}},
			Uncovered: []*uncoveredObject{{Object: "C", Why: "local"}},
		}
	}
	baseRepos := func() map[string]fstest.MapFS {
		return map[string]fstest.MapFS{
			"ANetCore": {
				"x/testdata/v1.json": {Data: []byte("{}\n")},
				"x/v1_test.go":       {Data: []byte("package x\n\nvar f = \"testdata/v1.json\"\n")},
				"x/v2_test.go":       {Data: []byte("package x\n\nimport \"testing\"\n\nfunc TestV2(t *testing.T) {}\n")},
				"x/old_test.go":      {Data: []byte("package x\n\nimport \"testing\"\n\nfunc TestOld(t *testing.T) {}\n")},
			},
			"ANet": {"y/doc.go": {Data: []byte("package y\n")}},
			"ANetHub": {
				"z/testdata/v4/a.json": {Data: []byte("{}\n")},
				"z/v4_test.go":         {Data: []byte("package z\n\nvar d = \"testdata/v4\"\n")},
			},
		}
	}
	basePy := "@vector(\"V1\", \"ANetCore/x/testdata/v1.json\")\ndef gen_v1():\n    return {}\n"

	run := func(ix *goldenIndex, trees map[string]fstest.MapFS, py string) (problems, unchecked []string) {
		repos := map[string]fs.FS{}
		for k, v := range trees {
			if v != nil {
				repos[k] = v
			}
		}
		problems = append(checkShape(ix, rv), checkCoverage(ix, rv)...)
		ap, un := checkArtifacts(ix, repos)
		problems = append(problems, ap...)
		problems = append(problems, checkReaders(ix, repos)...)
		problems = append(problems, checkGenerators(ix, []byte(py), repos)...)
		return problems, un
	}

	if p, un := run(baseIndex(), baseRepos(), basePy); len(p) > 0 || len(un) > 0 {
		t.Fatalf("the unchanged example must pass: problems %q, unchecked %q", p, un)
	}

	cases := []struct {
		name string
		edit func(ix *goldenIndex, trees map[string]fstest.MapFS, py *string)
		want string
	}{
		{"registered file deleted", func(ix *goldenIndex, tr map[string]fstest.MapFS, _ *string) {
			delete(tr["ANetCore"], "x/testdata/v1.json")
		}, "V1: ANetCore/x/testdata/v1.json is missing"},
		{"registered test function deleted", func(ix *goldenIndex, tr map[string]fstest.MapFS, _ *string) {
			tr["ANetCore"]["x/v2_test.go"] = &fstest.MapFile{Data: []byte("package x\n")}
		}, "V2: ANetCore/x/v2_test.go#TestV2 is missing"},
		{"registered directory emptied", func(ix *goldenIndex, tr map[string]fstest.MapFS, _ *string) {
			delete(tr["ANetHub"], "z/testdata/v4/a.json")
		}, "V4: ANetHub/z/testdata/v4/ is missing"},
		{"vector row removed", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors = ix.Vectors[1:]
		}, "label L1 (anet-one/v1) is covered by no vector"},
		{"label dropped from a row", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[1].Labels = nil
		}, "label L2 (anet.two/1) is covered by no vector"},
		{"registry golden column disagrees", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[1].Labels = []string{"L1", "L2"}
			ix.Vectors[0].Labels = nil
		}, "says vector V1 covers label L1"},
		{"object dropped", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[0].Objects = nil
		}, "object A is covered by no vector"},
		{"uncovered entry removed", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Uncovered = nil
		}, "object C is covered by no vector"},
		{"stale uncovered entry", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[0].Objects = append(ix.Vectors[0].Objects, "C")
		}, "object C is listed under uncovered but V1 covers it"},
		{"todo left on a delivered file", func(ix *goldenIndex, tr map[string]fstest.MapFS, _ *string) {
			tr["ANet"]["y/testdata/v3.json"] = &fstest.MapFile{Data: []byte("{}")}
			tr["ANet"]["y/v3_test.go"] = &fstest.MapFile{Data: []byte("package y\nvar f = \"v3.json\"\n")}
		}, "V3: ANet/y/testdata/v3.json is delivered, but the index still marks it " + wire.TodoMarker("XX-3")},
		{"todo added to a present file", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[0].At[0].Todo = wire.TodoMarker("XX-1")
		}, "is delivered, but the index still marks it"},
		{"retired vector deleted, todo left", func(ix *goldenIndex, tr map[string]fstest.MapFS, _ *string) {
			delete(tr["ANetCore"], "x/old_test.go")
		}, "retired R1: ANetCore/x/old_test.go#TestOld is gone, but the index still marks it"},
		{"retired vector kept without todo", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Retired[0].At[0].Todo = ""
		}, "retired R1: ANetCore/x/old_test.go#TestOld still exists"},
		{"vector file no test reads", func(ix *goldenIndex, tr map[string]fstest.MapFS, _ *string) {
			delete(tr["ANetCore"], "x/v1_test.go")
		}, "V1: no Go test in ANetCore names v1.json"},
		{"generator missing", func(ix *goldenIndex, _ map[string]fstest.MapFS, py *string) {
			*py = ""
		}, "V1: ANetCore/x/testdata/v1.json exists but gen_v016.py has no generator"},
		{"generator for a Go vector", func(ix *goldenIndex, _ map[string]fstest.MapFS, py *string) {
			*py += "@vector(\"V2\", \"ANetCore/x/v2.json\")\n"
		}, "has a generator for V2, whose row says gen \"go\""},
		{"generator without a row", func(ix *goldenIndex, _ map[string]fstest.MapFS, py *string) {
			*py += "@vector(\"V7\", \"ANetCore/x/v7.json\")\n"
		}, "has a generator for V7, which the index does not list"},
		{"duplicate id", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Retired[0].ID = "V2"
		}, "vector V2 is listed twice"},
		{"bad todo marker", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[2].At[0].Todo = "todo(XX-3)"
		}, "is not " + wire.TodoMarker("<work item>")},
		{"path escapes the repository", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[0].At[0].Path = "../ANet/x.json"
		}, "is not a clean path inside the repository"},
		{"unknown label", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[0].Labels = append(ix.Vectors[0].Labels, "L7")
		}, "unknown label \"L7\""},
		{"unknown object", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[0].Objects = append(ix.Vectors[0].Objects, "Nope")
		}, "unknown object \"Nope\""},
		{"unknown gen", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[1].Gen = "rust"
		}, "gen \"rust\" is not one of"},
		{"python vector as a test", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[0].At = append(ix.Vectors[0].At, &artifact{Repo: "ANetCore", Path: "x/v2_test.go", Test: "TestV2"})
		}, "is written by gen_v016.py, so ANetCore/x/v2_test.go#TestV2 must be a file"},
		{"rework on a retired vector", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Retired[0].At[0].Todo, ix.Retired[0].At[0].Rework = "", wire.TodoMarker("XX-1")
		}, "a retired vector is deleted, not reworked"},
		{"unknown repository", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[3].At[0].Repo = "Other"
		}, "repository \"Other\" is not one of"},
		// The shape of the index itself: each rule, broken once.
		{"wrong format", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Format = "anet-golden-index/2"
		}, "format is \"anet-golden-index/2\""},
		{"gens table out of step", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			delete(ix.Gens, "rfc")
		}, "gens lists [a2a-python go go+python python]"},
		{"empty vector id", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[3].ID = ""
		}, "vector id \"\" is empty or has a space"},
		{"vector id with a space", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[3].ID = "V 4"
		}, "vector id \"V 4\" is empty or has a space"},
		{"row without owner", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[3].Owner = ""
		}, "V4: owner, covers and at must all be given"},
		{"row without artifacts", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[3].At = nil
		}, "V4: owner, covers and at must all be given"},
		{"label listed twice", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[0].Labels = []string{"L1", "L1"}
		}, "V1: label L1 twice"},
		{"object listed twice", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[0].Objects = []string{"A", "A"}
		}, "V1: object A twice"},
		{"directory without a glob", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[3].At[0].Glob = ""
		}, "a directory (z/testdata/v4/) needs a glob"},
		{"glob that is not a pattern", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[3].At[0].Glob = "["
		}, "glob \"[\": syntax error in pattern"},
		{"glob on a file", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[0].At[0].Glob = "*.json"
		}, "glob \"*.json\" is only for a directory"},
		{"test outside a _test.go file", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[1].At[0].Path = "x/v2.go"
		}, "test \"TestV2\" must be a Test… function in a _test.go file"},
		{"test name that is not a Test function", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[1].At[0].Test = "V2"
		}, "test \"V2\" must be a Test… function"},
		{"todo and rework together", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[2].At[0].Rework = wire.TodoMarker("XX-3")
		}, "todo and rework together"},
		{"path is the parent directory", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[3].At[0].Path = "../"
		}, "path \"../\" is not a clean path inside the repository"},
		{"path with an empty element", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[0].At[0].Path = "x//testdata/v1.json"
		}, "is not a clean path inside the repository"},
		{"retired vector without why", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Retired[0].Why = ""
		}, "R1: a retired vector needs why and at"},
		{"retired vector without artifacts", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Retired[0].At = nil
		}, "R1: a retired vector needs why and at"},
		{"uncovered object unknown", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Uncovered = append(ix.Uncovered, &uncoveredObject{Object: "Nope", Why: "local"})
		}, "uncovered: unknown object \"Nope\""},
		{"uncovered object without a reason", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Uncovered[0].Why = ""
		}, "uncovered: C needs the reason it has no vector"},
		{"uncovered object listed twice", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Uncovered = append(ix.Uncovered, &uncoveredObject{Object: "C", Why: "again"})
		}, "uncovered: C is listed twice"},
		{"new wire object parked under uncovered", func(ix *goldenIndex, _ map[string]fstest.MapFS, _ *string) {
			ix.Vectors[1].Objects = nil
			ix.Uncovered = append(ix.Uncovered, &uncoveredObject{Object: "B", Why: "later"})
		}, "uncovered: B is new in 0.3.0 and is not a node-local file, so CORE-G1 needs a vector for it"},
		// What must exist and be read.
		{"reworked vector file no test reads", func(ix *goldenIndex, tr map[string]fstest.MapFS, _ *string) {
			ix.Vectors[0].At[0].Rework = wire.TodoMarker("XX-1")
			delete(tr["ANetCore"], "x/v1_test.go")
		}, "V1: no Go test in ANetCore names v1.json"},
		{"a method with the test's name is not the test", func(ix *goldenIndex, tr map[string]fstest.MapFS, _ *string) {
			tr["ANetCore"]["x/v2_test.go"] = &fstest.MapFile{Data: []byte("package x\n\nimport \"testing\"\n\ntype s struct{}\n\nfunc (s) TestV2(t *testing.T) {}\n")}
		}, "V2: ANetCore/x/v2_test.go#TestV2 is missing"},
		{"a directory where the vector file belongs", func(ix *goldenIndex, tr map[string]fstest.MapFS, _ *string) {
			delete(tr["ANetCore"], "x/testdata/v1.json")
			tr["ANetCore"]["x/testdata/v1.json/a"] = &fstest.MapFile{Data: []byte("{}")}
		}, "V1: ANetCore/x/testdata/v1.json is missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ix, trees, py := baseIndex(), baseRepos(), basePy
			c.edit(ix, trees, &py)
			problems, _ := run(ix, trees, py)
			for _, p := range problems {
				if strings.Contains(p, c.want) {
					return
				}
			}
			t.Errorf("want a problem containing %q, got %q", c.want, problems)
		})
	}

	// A repository that is not there is reported as not checked, never as passing silently.
	trees := baseRepos()
	trees["ANet"] = nil
	if _, un := run(baseIndex(), trees, basePy); len(un) != 1 || !strings.Contains(un[0], "V3: ANet/y/testdata/v3.json") {
		t.Errorf("a missing repository must leave its rows unchecked, got %q", un)
	}
}

// TestGoldenIndexParseIsStrict: a misspelled member must not silently drop a rule, and a null
// must not stand for a row.
func TestGoldenIndexParseIsStrict(t *testing.T) {
	for _, b := range []string{
		`{"format":"anet-golden-index/1","vectors":[{"id":"V1","todos":"` + wire.TodoMarker("X-1") + `"}]}`,
		`{"format":"anet-golden-index/1","vector":[]}`,
		`{"format":"anet-golden-index/1"} {}`,
		`{"format":"anet-golden-index/1","vectors":[null]}`,
		`{"format":"anet-golden-index/1","vectors":[{"id":"V1","at":[null]}]}`,
		`{"format":"anet-golden-index/1","retired":[{"id":"R1","at":[null]}]}`,
		`{"format":"anet-golden-index/1","uncovered":[null]}`,
	} {
		if _, err := parseIndex([]byte(b)); err == nil {
			t.Errorf("parseIndex accepted %s", b)
		}
	}
}

// TestGoldenIndexRegistryView: the coverage rules are only as strong as the view they read, so the
// view is checked on its own: exactly the A, B and C tags are labels CORE-G1 counts, the "golden"
// column is split into vector ids, and only node-local or carried objects may wait uncovered.
func TestGoldenIndexRegistryView(t *testing.T) {
	r := &wire.Registry{
		Tags: []*wire.Tag{
			{ID: "L1", Class: "A", Values: []string{"anet.a/1"}, Golden: "V1, V2"},
			{ID: "L2", Class: "B", Values: []string{"anet-b/v1"}, Golden: "V2 (NUL cases)"},
			{ID: "L3", Class: "C", Values: []string{"anet-c/v1", "anet-c2/v1"}, Golden: "V3"},
			{ID: "L4", Class: "D", Golden: "-"},
			{ID: "L5", Class: "text", Golden: "V5"},
			{ID: "L6", Class: "type"},
			{ID: "L7", Class: "file", Golden: "-"},
			{ID: "L8", Class: "carried", Golden: "unchanged"},
		},
		Objects: []*wire.Object{
			{Name: "New", Group: "seal"},
			{Name: "Local", Group: "local"},
			{Name: "Old", Group: "tsir", Carried: true},
		},
	}
	v := viewOf(r)
	if got := strings.Join(sortedKeys(v.labels), ","); got != "L1,L2,L3" {
		t.Errorf("labels CORE-G1 counts: %s, want L1,L2,L3 (the A, B and C tags)", got)
	}
	if v.labels["L3"] != "anet-c/v1, anet-c2/v1" {
		t.Errorf("label L3 reads %q", v.labels["L3"])
	}
	if len(v.tags) != 8 {
		t.Errorf("%d tags known, want 8", len(v.tags))
	}
	golden := fmt.Sprint(v.golden)
	if golden != "map[L1:[V1 V2] L2:[V2] L3:[V3] L5:[V5]]" {
		t.Errorf("golden column read as %s", golden)
	}
	if got := strings.Join(sortedKeys(v.objects), ","); got != "Local,New,Old" {
		t.Errorf("objects %s", got)
	}
	if got := strings.Join(sortedKeys(v.waits), ","); got != "Local,Old" {
		t.Errorf("objects that may wait uncovered: %s, want Local,Old", got)
	}

	// The real registry: every A, B and C tag is a label, so a registry edit cannot drop one.
	reg := wire.MustLoad()
	n := 0
	for _, tg := range reg.Tags {
		if tg.Class == "A" || tg.Class == "B" || tg.Class == "C" {
			n++
		}
	}
	if rv := viewOf(reg); n == 0 || len(rv.labels) != n {
		t.Errorf("the registry has %d A, B and C tags, the view counts %d", n, len(rv.labels))
	}
}

// FuzzParseIndex: whatever parseIndex accepts, every check runs on it without panicking.
func FuzzParseIndex(f *testing.F) {
	if real, err := os.ReadFile(indexPath); err == nil {
		f.Add(real)
	}
	f.Add([]byte(`{"format":"anet-golden-index/1","gens":{},"vectors":[{"id":"V","gen":"python","owner":"X","covers":".","labels":["L1","L1"],"objects":["Nope"],"at":[{"repo":"ANetCore","path":"x/../y/","glob":"[","test":"T"},{"repo":"ANetCore","path":"x/v_test.go","test":"TestV","todo":"` + wire.TodoMarker("A-1") + `"}]}],"retired":[{"id":"V","why":"","at":[{"repo":"ANet","path":"/abs","rework":"x"}]}],"uncovered":[{"object":"Nope","why":""}]}`))
	rv := viewOf(wire.MustLoad())
	repos := map[string]fs.FS{
		"ANetCore": fstest.MapFS{
			"x/v_test.go":        {Data: []byte("package x\n\nfunc TestV() {}\n")},
			"x/bad_test.go":      {Data: []byte("package x\nfunc (")},
			"x/testdata/v.json":  {Data: []byte("{}")},
			"y/testdata/d/a.bin": {Data: []byte{0}},
		},
		"ANet": fstest.MapFS{"z/z_test.go": {Data: []byte("package z // v.json")}},
	}
	py := []byte("@vector(\"V\", \"ANetCore/x/testdata/v.json\")\n@vector(\"W\")\n")
	f.Fuzz(func(t *testing.T, b []byte) {
		ix, err := parseIndex(b)
		if err != nil {
			return
		}
		checkShape(ix, rv)
		checkCoverage(ix, rv)
		checkArtifacts(ix, repos)
		checkReaders(ix, repos)
		checkGenerators(ix, py, repos)
	})
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func firstDup(list []string) string {
	seen := map[string]bool{}
	for _, x := range list {
		if seen[x] {
			return x
		}
		seen[x] = true
	}
	return ""
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
