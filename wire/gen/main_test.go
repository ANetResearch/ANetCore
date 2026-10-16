package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ANetResearch/ANetCore/wire"
)

// CORE-S7: the committed docs/wire-keys.md is what the registry renders.
func TestWireKeysDocIsUpToDate(t *testing.T) {
	r, err := wire.Load()
	if err != nil {
		t.Fatal(err)
	}
	have, err := os.ReadFile(filepath.Join("..", "..", DocPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(have, Render(r)) {
		t.Fatalf("%s is not what wire/registry.json renders: run `go run ./wire/gen` from the module root and commit the result", DocPath)
	}
}

// The document is public: it must not leak the internal names the registry keeps for its own
// checks (area owners, work-item markers).
func TestWireKeysDocHasNoInternalMarkers(t *testing.T) {
	doc := string(Render(wire.MustLoad()))
	for _, bad := range []string{wire.TodoWord, "private-ops", "OWNER", "Owner"} {
		if bytes.Contains([]byte(doc), []byte(bad)) {
			t.Errorf("document contains %q", bad)
		}
	}
}
