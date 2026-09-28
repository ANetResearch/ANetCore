package tsir

// Fuzz targets for the TaskDoc and the predicate calculus (ANet docs/notes/0033).
//
// The calculus is meant to be total and bounded ("non-Turing-complete, so two conformant
// implementations compute the same verdict"): Validate and Evaluate must not panic on any
// decoded predicate, and Evaluate must finish quickly on small inputs. A watchdog turns an
// evaluation that runs for seconds into a crash the fuzzer records.

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// watchdog panics (crashing the fuzz worker, which records the input) if f runs longer than d.
func watchdog(d time.Duration, what string, f func()) {
	done := make(chan struct{})
	timer := time.AfterFunc(d, func() {
		select {
		case <-done:
		default:
			panic(fmt.Sprintf("%s did not finish within %v", what, d))
		}
	})
	f()
	close(done)
	timer.Stop()
}

func mustCBOR(tb testing.TB, v any) []byte {
	tb.Helper()
	b, err := coredet.Marshal(v)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func fuzzSeedPredicates() []*Predicate {
	yes := true
	return []*Predicate{
		{Op: OpArtifact, Artifact: &ArtifactClause{PathGlob: "build/**/*.bin", Exists: &yes, MinSizeBytes: u64(1)}},
		{Op: OpScope, Scope: &ScopeClause{Verb: VerbDelete, Kind: 1, Match: ResourceMatch{Kind: MatchGlob, Val: "secrets/**"}}},
		{Op: OpAND, Children: []*Predicate{
			{Op: OpTest, Test: &TestClause{TestID: "t", Expect: StatusPass}},
			{Op: OpNOT, Children: []*Predicate{{Op: OpThreshold, Thresh: &ThresholdClause{Metric: "m", Op: CmpGE, Value: 0.5}}}},
		}},
		{Op: OpOR, Children: []*Predicate{
			{Op: OpScope, Scope: &ScopeClause{Verb: VerbCall, Kind: 2, Match: ResourceMatch{Kind: MatchSet, Val: "a,b"}}},
			{Op: OpScope, Scope: &ScopeClause{Verb: VerbGet, Kind: 3, Match: ResourceMatch{Kind: MatchPrefix, Val: "x/"}}},
		}},
	}
}

func fuzzSeedEffect() *EffectRecord {
	return &EffectRecord{
		Artifacts: []Artifact{{Path: "build/a/b.bin", SizeBytes: 10}},
		Tests:     []TestResult{{ID: "t", Status: StatusPass}},
		Metrics:   map[string]float64{"m": 0.75},
		Resources: []ResourceRef{{Kind: 1, ID: "secrets/k"}},
		Effects:   []EffectRef{{Verb: VerbDelete, Resource: ResourceRef{Kind: 1, ID: "secrets/api/key.pem"}}},
	}
}

func FuzzPredicateEvaluate(f *testing.F) {
	eff := mustCBOR(f, fuzzSeedEffect())
	for _, p := range fuzzSeedPredicates() {
		f.Add(mustCBOR(f, p), eff)
	}
	// AND of a CBOR null and a test clause (TestValidateRefusesANullChild).
	f.Add([]byte{0xa2, 0x01, 0x01, 0x02, 0x82, 0xf6, 0xa2, 0x01, 0x0b, 0x0b, 0xa2, 0x01, 0x61, 't', 0x02, 0x01}, eff)
	f.Fuzz(func(t *testing.T, pb, eb []byte) {
		var p Predicate
		if coredet.Unmarshal(pb, &p) != nil {
			return
		}
		var e EffectRecord
		if coredet.Unmarshal(eb, &e) != nil {
			return
		}
		if p.Validate() != nil {
			return
		}
		watchdog(2*time.Second, "Evaluate", func() {
			v1 := p.Evaluate(&e)
			if v2 := p.Evaluate(&e); v1 != v2 {
				t.Fatal("Evaluate is not deterministic")
			}
			_ = EvaluateScope(&p, &e)
		})
	})
}

// globRecursive is the recursive matcher globMatch replaced, kept as the reference for its
// semantics. It is exponential in the number of stars, so the fuzz target compares only
// patterns with a few.
func globRecursive(pat, s string) bool {
	for len(pat) > 0 {
		if strings.HasPrefix(pat, "**") {
			rest := strings.TrimLeft(pat[2:], "/")
			if rest == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if globRecursive(rest, s[i:]) {
					return true
				}
			}
			return false
		}
		if pat[0] == '*' {
			rest := pat[1:]
			for i := 0; i <= len(s); i++ {
				if i > 0 && s[i-1] == '/' {
					break
				}
				if globRecursive(rest, s[i:]) {
					return true
				}
			}
			return false
		}
		if len(s) == 0 || pat[0] != s[0] {
			return false
		}
		pat, s = pat[1:], s[1:]
	}
	return len(s) == 0
}

func FuzzGlobMatch(f *testing.F) {
	f.Add("build/**/*.bin", "build/a/b/c.bin")
	f.Add("secrets/**", "secrets/api/key.pem")
	f.Add("*a*", "bab")
	f.Fuzz(func(t *testing.T, pat, s string) {
		if len(pat) > 64 || len(s) > 256 {
			return
		}
		watchdog(2*time.Second, "globMatch", func() {
			got := globMatch(pat, s)
			// '*' never crosses '/': a pattern without "**" matches only strings with as many
			// '/' as the pattern has.
			if got && !bytes.Contains([]byte(pat), []byte("**")) &&
				bytes.Count([]byte(pat), []byte("/")) != bytes.Count([]byte(s), []byte("/")) {
				t.Fatalf("%q matched %q across a '/'", pat, s)
			}
			// A pattern with no '*' matches exactly itself.
			if !bytes.ContainsRune([]byte(pat), '*') && got != (pat == s) {
				t.Fatalf("literal %q vs %q: %v", pat, s, got)
			}
			// Same verdict as the recursive matcher, where that one finishes.
			if strings.Count(pat, "*") <= 4 {
				if want := globRecursive(pat, s); got != want {
					t.Fatalf("globMatch(%q, %q) = %v, recursive matcher %v", pat, s, got, want)
				}
			}
		})
	})
}

func FuzzTaskDocCompile(f *testing.F) {
	c := identity.SuiteController()
	for i, p := range fuzzSeedPredicates() {
		d := &TaskDoc{Version: VersionPair{Major: 1, Minor: uint64(i)}, Meta: []MetaEntry{{Name: "n", Value: "v"}},
			Tasks: []Task{{ID: "t1", Intent: Intent{Body: "do x"}, NegativeScope: p, PositiveScope: p,
				Accepts: []Accept{{Type: "artifact"}}, CouplingHint: i}}, Critical: []uint64{9}}
		f.Add(mustCBOR(f, d), true, uint64(1767225600000))
	}
	f.Fuzz(func(t *testing.T, b []byte, resign bool, msgTime uint64) {
		var d TaskDoc
		if coredet.Unmarshal(b, &d) != nil {
			return
		}
		for _, task := range d.Tasks {
			for _, p := range []*Predicate{task.PositiveScope, task.NegativeScope} {
				if p != nil {
					_ = p.Validate()
				}
			}
		}
		cid, err := d.CID()
		if err != nil {
			return
		}
		// MINOR-only fields are not CID-significant (tsir-spec §3.3).
		d2 := d
		d2.Version.Minor++
		d2.Meta = append(append([]MetaEntry(nil), d.Meta...), MetaEntry{Name: "x", Value: "y"})
		d2.Critical = append(append([]uint64(nil), d.Critical...), 7)
		if cid2, err := d2.CID(); err != nil || cid2 != cid {
			t.Fatalf("a MINOR-only change moved the CID: %s -> %s (%v)", cid, cid2, err)
		}
		// The CID survives the TaskDoc's wire round trip.
		if wb, err := coredet.Marshal(d); err == nil {
			var back TaskDoc
			if err := coredet.Unmarshal(wb, &back); err != nil {
				t.Fatalf("re-encoded TaskDoc does not decode: %v", err)
			}
			if cid3, err := back.CID(); err != nil || cid3 != cid {
				t.Fatalf("CID changed across a round trip: %s -> %s (%v)", cid, cid3, err)
			}
		}
		if resign {
			if err := d.Sign(c); err != nil {
				return
			}
		}
		var res *CompileResult
		watchdog(2*time.Second, "Compile", func() { res, err = Compile(&d, c.KEL(), msgTime) })
		if err != nil {
			return
		}
		if res.TaskCID != cid {
			t.Fatalf("compiled CID %s, TaskDoc CID %s", res.TaskCID, cid)
		}
		if d.Envelope.SignerAID != c.AID() {
			t.Fatalf("compiled a TaskDoc signed by %s", d.Envelope.SignerAID)
		}
		if h := res.CouplingHint; h < 0 || h > 4 {
			t.Fatalf("compiled coupling hint %d", h)
		}
	})
}
