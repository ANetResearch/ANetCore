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

// TodoWord is the marker of an open v0.3.0 work item. In code it is written TodoWord, then the
// work item's id in parentheses, as a comment on a stopgap or as the reason of a skipped test;
// TransitionEntry.Todo and the golden index use the same form, so one search of the sources finds
// every open item and nothing else. That is why it is spelled here in two pieces: the framework
// that checks the markers must not be one of the hits.
const TodoWord = "v030" + "-todo"

// TodoMarker returns the marker of work item id: TodoWord, then id in parentheses.
func TodoMarker(id string) string { return TodoWord + "(" + id + ")" }

// TodoPattern is the form of TransitionEntry.Todo: the marker of one work item.
var TodoPattern = regexp.MustCompile(`^` + TodoWord + `\(([A-Z0-9]+-[0-9]+[a-z]?)\)$`)

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
			return nil, fmt.Errorf("wire: transition.json entry %d: todo %q is not %s", i, e.Todo, TodoMarker("<work item>"))
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
