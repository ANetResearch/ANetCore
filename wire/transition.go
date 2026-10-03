package wire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
)

// Transition is transition.json: the v0.2 shapes still in the code while the v0.3.0 rewrite is
// under way. Each entry names the work item that removes it. The scan accepts an entry only as
// it is written here (a v0.2 struct with exactly these keys, a string with exactly this value),
// so editing a v0.2 shape still fails the scan; and it fails when an entry no longer matches
// anything in its repository, so the work item that migrates the code also deletes the entry.
type Transition struct {
	About   string             `json:"about"`
	Entries []*TransitionEntry `json:"entries"`
}

// Transition entry kinds.
const (
	TransStruct = "struct" // an unannotated keyasint struct; Go is "<pkg>.<Type>" or "<pkg>.<Func>#<n>"
	TransConst  = "const"  // a seal key constant; Go is "<pkg>.<name>", Value its value
	TransString = "string" // an "anet…" string literal; Value
	TransAction = "action" // a relayauth Action* constant; Value the action
	TransSigner = "signer" // a function that calls an identity signing method; Go is its name
)

// TransitionEntry is one v0.2 item and the work item that removes it.
type TransitionEntry struct {
	Todo  string   `json:"todo"`
	Repo  string   `json:"repo"`
	Kind  string   `json:"kind"`
	Go    string   `json:"go,omitempty"`
	Value string   `json:"value,omitempty"`
	Keys  []string `json:"keys,omitempty"` // TransStruct: "<n> <Field> <Go type>" in key order
	Note  string   `json:"note,omitempty"`
}

// TodoPattern is the form of TransitionEntry.Todo, the same marker R-5 asks for in code
// ("// v030-todo(<id>)"), so one grep finds every open item.
var TodoPattern = regexp.MustCompile(`^v030-todo\(([A-Z0-9]+-[0-9]+[a-z]?)\)$`)

var (
	transOnce sync.Once
	trans     *Transition
	transErr  error
)

// LoadTransition returns the embedded transition list.
func LoadTransition() (*Transition, error) {
	transOnce.Do(func() { trans, transErr = ParseTransition(transitionJSON) })
	return trans, transErr
}

// ParseTransition decodes transition bytes strictly and checks every entry's form.
func ParseTransition(b []byte) (*Transition, error) {
	var t Transition
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("wire: transition.json: %w", err)
	}
	seen := map[string]bool{}
	for i, e := range t.Entries {
		if !TodoPattern.MatchString(e.Todo) {
			return nil, fmt.Errorf("wire: transition.json entry %d: todo %q is not v030-todo(<work item>)", i, e.Todo)
		}
		switch e.Repo {
		case "ANetCore", "ANet", "ANetHub":
		default:
			return nil, fmt.Errorf("wire: transition.json entry %d: repo %q", i, e.Repo)
		}
		switch e.Kind {
		case TransStruct, TransSigner:
			if e.Go == "" {
				return nil, fmt.Errorf("wire: transition.json entry %d: %s without go", i, e.Kind)
			}
		case TransConst:
			if e.Go == "" || e.Value == "" {
				return nil, fmt.Errorf("wire: transition.json entry %d: const needs go and value", i)
			}
		case TransString, TransAction:
			if e.Value == "" {
				return nil, fmt.Errorf("wire: transition.json entry %d: %s without value", i, e.Kind)
			}
		default:
			return nil, fmt.Errorf("wire: transition.json entry %d: kind %q", i, e.Kind)
		}
		id := e.Repo + "|" + e.Kind + "|" + e.Go + "|" + e.Value
		if seen[id] {
			return nil, fmt.Errorf("wire: transition.json entry %d: duplicate of an earlier entry", i)
		}
		seen[id] = true
	}
	return &t, nil
}

// For returns the entries of one repository and kind.
func (t *Transition) For(repo, kind string) []*TransitionEntry {
	var out []*TransitionEntry
	for _, e := range t.Entries {
		if e.Repo == repo && e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}
