package wire_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/wire"
)

// The marker of an open work item is spelled in two pieces in the framework that checks it, so
// that a search of the sources for the marker finds only real open items. The pieces must still
// make the marker the sources use; TodoPattern must match exactly what TodoMarker makes for a
// work item id; and a search for the marker built from TodoWord finds it in a line of code.
func TestTodoMarker(t *testing.T) {
	if wire.TodoWord != strings.Join([]string{"v030", "todo"}, "-") {
		t.Fatalf("TodoWord is %q", wire.TodoWord)
	}
	for _, id := range []string{"PAY-9", "KEL-8a", "CORE-5", ""} {
		m := wire.TodoMarker(id)
		if !wire.TodoPattern.MatchString(m) || wire.TodoPattern.FindStringSubmatch(m)[1] != id {
			t.Errorf("TodoPattern does not take %q for work item %s", m, id)
		}
	}
	for _, bad := range []string{"todo(PAY-9)", wire.TodoMarker("pay-9"), wire.TodoMarker(""), wire.TodoMarker("PAY"),
		wire.TodoMarker("PAY-9") + " ", " " + wire.TodoMarker("PAY-9"), wire.TodoWord + "[PAY-9]"} {
		if wire.TodoPattern.MatchString(bad) {
			t.Errorf("TodoPattern takes %q", bad)
		}
	}
	search := regexp.MustCompile(regexp.QuoteMeta(wire.TodoWord) + `\(([^)]*)\)`)
	line := "\tx := y // " + wire.TodoMarker("SS-6") + ": cross-hub send comes back with the federation"
	if m := search.FindStringSubmatch(line); m == nil || m[1] != "SS-6" {
		t.Fatalf("a search for the marker does not find it in %q", line)
	}
	tr, err := wire.LoadTransition()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range tr.Entries {
		if !search.MatchString(e.Todo) {
			t.Errorf("transition entry %s %s: a search for the marker does not find %q", e.Kind, e.Go+e.Value, e.Todo)
		}
	}
}
