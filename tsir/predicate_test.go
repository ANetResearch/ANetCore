package tsir

import (
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
)

func u64(v uint64) *uint64 { return &v }

// §3.3d red/green: an acceptance ArtifactClause is true iff an artifact matches path-glob
// and meets min_size_bytes; one byte below the floor is false.
func TestArtifactRedGreen(t *testing.T) {
	clause := &Predicate{Op: OpArtifact, Artifact: &ArtifactClause{
		PathGlob: "build/*.bin", MinSizeBytes: u64(1024),
	}}
	if err := clause.Validate(); err != nil {
		t.Fatal(err)
	}
	green := &EffectRecord{Artifacts: []Artifact{{Path: "build/out.bin", SizeBytes: 1024}}}
	if !clause.Evaluate(green) {
		t.Fatal("green: artifact at floor should satisfy")
	}
	red := &EffectRecord{Artifacts: []Artifact{{Path: "build/out.bin", SizeBytes: 1023}}}
	if clause.Evaluate(red) {
		t.Fatal("red: artifact one byte below floor should NOT satisfy")
	}
	// path-glob '*' does not cross '/'.
	nested := &EffectRecord{Artifacts: []Artifact{{Path: "build/sub/out.bin", SizeBytes: 4096}}}
	if clause.Evaluate(nested) {
		t.Fatal("'*' must not cross '/'")
	}
}

// Negative action-scope hard gate: a delete over secrets/** is a SCOPE_VIOLATION.
func TestEvaluateScope(t *testing.T) {
	neg := &Predicate{Op: OpScope, Scope: &ScopeClause{
		Verb: VerbDelete, Kind: 1, Match: ResourceMatch{Kind: MatchGlob, Val: "secrets/**"},
	}}
	if err := neg.Validate(); err != nil {
		t.Fatal(err)
	}
	violating := &EffectRecord{Effects: []EffectRef{
		{Verb: VerbDelete, Resource: ResourceRef{Kind: 1, ID: "secrets/api/key.pem"}},
	}}
	if EvaluateScope(neg, violating) != ScopeViolation {
		t.Fatal("delete under secrets/** must be SCOPE_VIOLATION")
	}
	clean := &EffectRecord{Effects: []EffectRef{
		{Verb: VerbDelete, Resource: ResourceRef{Kind: 1, ID: "tmp/cache"}},
	}}
	if EvaluateScope(neg, clean) != ScopeOK {
		t.Fatal("delete outside secrets/** must be OK")
	}
	// a read (get) under secrets/** is not a delete → OK (verb-specific).
	readOnly := &EffectRecord{Effects: []EffectRef{
		{Verb: VerbGet, Resource: ResourceRef{Kind: 1, ID: "secrets/api/key.pem"}},
	}}
	if EvaluateScope(neg, readOnly) != ScopeOK {
		t.Fatal("get under secrets/** is not the forbidden delete → OK")
	}
}

// Threshold + test + boolean composition.
func TestComposite(t *testing.T) {
	p := &Predicate{Op: OpAND, Children: []*Predicate{
		{Op: OpTest, Test: &TestClause{TestID: "unit", Expect: StatusPass}},
		{Op: OpThreshold, Thresh: &ThresholdClause{Metric: "coverage", Op: CmpGE, Value: 0.8}},
		{Op: OpNOT, Children: []*Predicate{
			{Op: OpThreshold, Thresh: &ThresholdClause{Metric: "errors", Op: CmpGT, Value: 0}},
		}},
	}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	good := &EffectRecord{
		Tests:   []TestResult{{ID: "unit", Status: StatusPass}},
		Metrics: map[string]float64{"coverage": 0.85, "errors": 0},
	}
	if !p.Evaluate(good) {
		t.Fatal("good run should satisfy")
	}
	bad := &EffectRecord{
		Tests:   []TestResult{{ID: "unit", Status: StatusPass}},
		Metrics: map[string]float64{"coverage": 0.5, "errors": 0},
	}
	if p.Evaluate(bad) {
		t.Fatal("low coverage should fail")
	}
}

// Malformed predicates fail closed (unknown op, wrong arity, bad enum).
func TestMalformed(t *testing.T) {
	cases := []*Predicate{
		{Op: 99},                   // unknown op
		{Op: OpNOT, Children: nil}, // NOT needs one child
		{Op: OpAND, Children: []*Predicate{{Op: OpTest, Test: &TestClause{TestID: "x", Expect: StatusPass}}}}, // AND needs ≥2
		{Op: OpThreshold, Thresh: &ThresholdClause{Metric: "m", Op: 9, Value: 1}},                             // bad cmp op
		{Op: OpScope, Scope: &ScopeClause{Verb: 7, Kind: 1, Match: ResourceMatch{Kind: 1}}},                   // bad verb
		// schema_ref / contains[] need resolved CAS content the EffectRecord lacks → fail-loud (§3.4).
		{Op: OpArtifact, Artifact: &ArtifactClause{PathGlob: "doc/*.json", SchemaRef: "cid:abc"}},
		{Op: OpArtifact, Artifact: &ArtifactClause{PathGlob: "doc/*.txt", Contains: []string{"TODO"}}},
	}
	for i, p := range cases {
		if err := p.Validate(); err != ErrMalformed {
			t.Errorf("case %d: want ErrMalformed, got %v", i, err)
		}
	}
	// over-depth fails closed.
	deep := &Predicate{Op: OpNOT, Children: []*Predicate{{Op: OpTest, Test: &TestClause{TestID: "x", Expect: StatusPass}}}}
	for i := 0; i < MaxPredicateDepth+2; i++ {
		deep = &Predicate{Op: OpNOT, Children: []*Predicate{deep}}
	}
	if err := deep.Validate(); err != ErrMalformed {
		t.Errorf("over-depth: want ErrMalformed, got %v", err)
	}
}

// globMatch takes time linear in the pattern and the string. The recursive matcher it replaced
// tried every split at every star, so a pattern of twenty-one stars against twenty bytes ran for
// minutes (ANet docs/notes/0033, found by FuzzGlobMatch: "*********************0").
func TestGlobMatchIsNotExponential(t *testing.T) {
	long := strings.Repeat("a", 4000)
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"*********************0", "\x84|\x82;_\xf4\x85f1\xec\x00i{\x87\x02\xe0\xe6\xf6Nd", false},
		{strings.Repeat("**a", 30) + "b", long, false},
		{strings.Repeat("*a", 30) + "b", long, false},
		{strings.Repeat("*a", 30), long, true},
		{"**/" + strings.Repeat("*/", 20) + "x", strings.Repeat("d/", 200) + "x", true},
	}
	// Each match runs in its own goroutine against a deadline, so an exponential matcher fails
	// the test within seconds instead of holding it until go test's own timeout (ten minutes by
	// default). The linear matcher takes microseconds; the deadline is generous for a loaded
	// machine. A match that misses it is left running: the test binary exits after the failure.
	const deadline = 5 * time.Second
	for _, c := range cases {
		done := make(chan bool, 1)
		go func() { done <- globMatch(c.pat, c.s) }()
		select {
		case got := <-done:
			if got != c.want {
				t.Errorf("globMatch(%.30q..., %d bytes) = %v, want %v", c.pat, len(c.s), got, c.want)
			}
		case <-time.After(deadline):
			t.Fatalf("globMatch(%.30q..., %d bytes) did not finish within %v", c.pat, len(c.s), deadline)
		}
	}
}

// The dialect is unchanged by the rewrite: '*' stays inside a segment, '**' crosses '/' and
// swallows the '/' after it.
func TestGlobMatchDialect(t *testing.T) {
	for _, c := range []struct {
		pat, s string
		want   bool
	}{
		{"build/*.bin", "build/out.bin", true}, {"build/*.bin", "build/sub/out.bin", false},
		{"build/**/*.bin", "build/out.bin", true}, {"build/**/*.bin", "build/a/b/out.bin", true},
		{"secrets/**", "secrets/api/key.pem", true}, {"secrets/**", "secret", false},
		{"a/**/b", "a/xb", true}, {"*", "", true}, {"", "", true}, {"", "a", false}, {"a*", "a/b", false},
	} {
		if got := globMatch(c.pat, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pat, c.s, got, c.want)
		}
	}
}

// A CBOR null among a connective's children decodes to a nil *Predicate. Validate reports it as
// MALFORMED instead of dereferencing it; Compile, which validates a signed TaskDoc's scopes,
// used to panic on one (ANet docs/notes/0033).
func TestValidateRefusesANullChild(t *testing.T) {
	// {1: 1, 2: [null, {1: 11, 11: {1: "t", 2: 1}}]}: AND of null and a test clause.
	b := []byte{0xa2, 0x01, 0x01, 0x02, 0x82, 0xf6, 0xa2, 0x01, 0x0b, 0x0b, 0xa2, 0x01, 0x61, 't', 0x02, 0x01}
	var p Predicate
	if err := coredet.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	for _, q := range []*Predicate{&p, {Op: OpNOT, Children: []*Predicate{nil}}, nil} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Validate panicked: %v", r)
				}
			}()
			if err := q.Validate(); err != ErrMalformed {
				t.Errorf("Validate = %v, want MALFORMED", err)
			}
		}()
	}
}
