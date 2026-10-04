package wire_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/dirbox"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/regpow"
	"github.com/ANetResearch/ANetCore/relayauth"
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
		"L7":  {nulSessionKey, ""},       // session key delivery: hubAID
		"L8":  {nulSessionMAC, ""},       // session MAC: method, pathAndQuery, X-ANet-Home
		"L9":  {nulDirHash, ""},          // dirbox h: aid
		"L19": {nil, "v030-todo(KEL-3)"}, // next-key derivation: aid
		"L23": {regpowNUL, ""},           // regpow hash: hub_aid, aid
		"L27": {nulIXCommit, ""},         // ix_commit: ix, anet.nonce
		"L28": {nulRequesterCommit, ""},  // requester_commit: requester_aid
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

// nulSessionKey seals and opens a session key with field as the hub AID (L7). Both ends must
// refuse U+0000: the row reports an acceptance when either end accepts a field holding it, and a
// refusal when either end refuses a clean field.
func nulSessionKey(field string) error {
	esk, epk, err := relayauth.NewSessionKey()
	if err != nil {
		return err
	}
	sid := bytes.Repeat([]byte{1}, relayauth.SessionIDLen)
	k := bytes.Repeat([]byte{2}, relayauth.SessionKeyLen)
	enc, ct, sealErr := relayauth.SealSessionKey(epk, field, sid, k)
	if sealErr != nil {
		// Open still gets a well-formed answer to refuse: one sealed for a clean hub AID.
		if enc, ct, err = relayauth.SealSessionKey(epk, "h", sid, k); err != nil {
			return err
		}
	}
	_, openErr := relayauth.OpenSessionKey(esk, field, sid, enc, ct)
	if sealErr != nil && !errors.Is(openErr, relayauth.ErrNUL) {
		openErr = nil // it failed to open a key sealed for another hub, but took the field
	}
	if strings.Contains(field, "\x00") {
		if sealErr == nil || openErr == nil {
			return nil
		}
		return sealErr
	}
	return errors.Join(sealErr, openErr)
}

// nulSessionMAC computes a session MAC with field in each 0x00-separated text position (method,
// request target, X-ANet-Home) in turn. It reports an acceptance when a field holding U+0000 is
// accepted in any position, and a refusal when a clean field is refused in any position.
func nulSessionMAC(field string) error {
	k := make([]byte, relayauth.SessionKeyLen)
	sid := make([]byte, relayauth.SessionIDLen)
	var errs []error
	for _, in := range [][3]string{{field, "/relay/send", ""}, {"POST", field, ""}, {"POST", "/relay/send", field}} {
		_, err := relayauth.SessionMAC(k, sid, 1, in[0], in[1], in[2], nil)
		errs = append(errs, err)
	}
	if strings.Contains(field, "\x00") {
		for _, err := range errs {
			if err == nil {
				return nil
			}
		}
		return errs[0]
	}
	return errors.Join(errs...)
}

// nulDirHash hashes field as the AID of a directory entry (L9).
func nulDirHash(field string) error {
	_, err := dirbox.Hash(field)
	return err
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

// nulIXCommit puts field into ix and into anet.nonce, one at a time (L27). A field holding U+0000
// counts as refused only when both positions refuse it; a clean field counts as accepted only when
// both accept it.
func nulIXCommit(field string) error {
	_, errIX := evidence.IXCommit(field, "nonce")
	_, errNonce := evidence.IXCommit("ix-1", field)
	if strings.Contains(field, "\x00") {
		if errIX == nil || errNonce == nil {
			return nil
		}
		return errIX
	}
	return errors.Join(errIX, errNonce)
}

// nulRequesterCommit puts field into requester_aid (L28).
func nulRequesterCommit(field string) error {
	_, err := evidence.RequesterCommit(field, make([]byte, evidence.RSaltSize))
	return err
}
