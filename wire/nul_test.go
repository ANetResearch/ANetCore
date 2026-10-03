package wire_test

import (
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/regpow"
)

// TestPreimageRejectsNUL (CORE-E9, ANetCore). B- and C-class inputs separate variable-length
// text fields with 0x00 (CORE-L1), so a field that holds U+0000 could move the boundary: ("a\0b",
// "c") and ("a", "b\0c") would hash alike. Every function that builds such an input refuses a
// field holding U+0000, as a second line behind the decoders.
//
// One row per registered guard of this repository (registry nul_guard). A row's function puts
// field into each 0x00-separated text position it has and returns the function's error. The
// work item that implements a function fills in its row and deletes the skip.
func TestPreimageRejectsNUL(t *testing.T) {
	rows := map[string]struct {
		fn   func(field string) error
		todo string
	}{
		"L7":  {nil, "v030-todo(SS-2)"},  // session key delivery: hubAID
		"L8":  {nil, "v030-todo(SS-2)"},  // session MAC: method, pathAndQuery, X-ANet-Home
		"L9":  {nil, "v030-todo(SS-2)"},  // dirbox h: aid
		"L19": {nil, "v030-todo(KEL-3)"}, // next-key derivation: aid
		"L23": {regpowNUL, ""},           // regpow hash: hub_aid, aid
		"L27": {nil, "v030-todo(PAY-2)"}, // ix_commit: ix, anet.nonce
		"L28": {nil, "v030-todo(PAY-2)"}, // requester_commit: requester_aid
	}
	r := reg(t)
	listed := map[string]bool{}
	for _, g := range r.NUL {
		if g.Repo != "ANetCore" {
			continue
		}
		listed[g.Label] = true
		row, ok := rows[g.Label]
		if !ok {
			t.Errorf("registry nul_guard %s (%s) has no row here", g.Label, g.What)
			continue
		}
		t.Run(g.Label+" "+g.What, func(t *testing.T) {
			if row.fn == nil {
				t.Skip(row.todo)
			}
			for _, f := range []string{"\x00", "a\x00", "\x00b", "a\x00b"} {
				if err := row.fn(f); err == nil {
					t.Errorf("%q accepted", f)
				}
			}
			if err := row.fn("ab"); err != nil {
				t.Errorf("a field without U+0000 refused: %v", err)
			}
		})
	}
	for label := range rows {
		if !listed[label] {
			t.Errorf("row %s is not a registered ANetCore nul_guard", label)
		}
	}
}

// regpowNUL puts field into hub_aid and into aid, one at a time. A field holding U+0000 counts as
// refused only when both positions refuse it; a clean field counts as accepted only when both
// accept it.
func regpowNUL(field string) error {
	var seed [32]byte
	nonce := []byte{1}
	_, errHub := regpow.Hash(field, "bafyreiaid", seed, nonce)
	_, errAID := regpow.Hash("bafyreihub", field, seed, nonce)
	if strings.Contains(field, "\x00") {
		if errHub == nil || errAID == nil {
			return nil
		}
		return errHub
	}
	if errHub != nil {
		return errHub
	}
	return errAID
}
