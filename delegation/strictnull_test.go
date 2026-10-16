package delegation

import (
	"testing"

	"github.com/ANetResearch/ANetCore/coredet/coredettest"
	"github.com/ANetResearch/ANetCore/tsir"
)

// TestEveryStrictDecoderRefusesNullAndUndefined (core CORE-E4, revision 7): every type this
// package decodes with coredet.UnmarshalStrict refuses f6 (null) and 81 f7 (a list holding
// undefined). The rows are the package's call sites, found with go/ast: a new call without a row,
// or a row without a call, fails.
func TestEveryStrictDecoderRefusesNullAndUndefined(t *testing.T) {
	probs, err := coredettest.Check(".", map[string]func() any{
		"UnmarshalCardResp &r":                   func() any { return new(CardResp) },
		"UnmarshalDelegateReq &r via decodeBody": func() any { return new(DelegateReq) },
		"decodeTaskDoc &doc via decodeBody":      func() any { return new(tsir.TaskDoc) },
		"UnmarshalResultResp &r via decodeBody":  func() any { return new(ResultResp) },
		"UnmarshalChatMsg &m via decodeBody":     func() any { return new(ChatMsg) },
		"UnmarshalStatusMsg &m via decodeBody":   func() any { return new(StatusMsg) },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range probs {
		t.Error(p)
	}
}
