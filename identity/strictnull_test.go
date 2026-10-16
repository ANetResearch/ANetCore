package identity

import (
	"testing"

	"github.com/ANetResearch/ANetCore/coredet/coredettest"
)

// TestEveryStrictDecoderRefusesNullAndUndefined (core CORE-E4, revision 7): every type this
// package decodes with coredet.UnmarshalStrict refuses f6 (null) and 81 f7 (a list holding
// undefined). The rows are the package's call sites, found with go/ast: a new call without a row,
// or a row without a call, fails.
func TestEveryStrictDecoderRefusesNullAndUndefined(t *testing.T) {
	probs, err := coredettest.Check(".", map[string]func() any{
		"(*KeyEvent).UnmarshalCBOR &f": func() any { return new(keyEventFields) },
		"UnmarshalKEL &kel":            func() any { return new([]SignedEvent) },
		"ParseIdentityFile &f":         func() any { return new(IdentityFile) },
		"restorePending &ev":           func() any { return new(SignedEvent) },
		"decodeNotice &w":              func() any { return new(NoticeWire) },
		"decodeNotice &body":           func() any { return new(NoticeBody) },
		"decodeRecoveryBlob &b":        func() any { return new(recoveryBlob) },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range probs {
		t.Error(p)
	}
}
