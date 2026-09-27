package a2acard

import (
	"bytes"

	"github.com/ANetResearch/ANetCore/identity"
)

// JWKS returns the JSON Web Key Set (RFC 7517) for an AID: one OKP/Ed25519 key (RFC 8037) per
// current key state, in seq order, each with kid did:anet:<AID>#<seq>, alg EdDSA and use sig.
// Current is defined as in CurrentKey, so a kid listed here is exactly a kid Verify accepts;
// several entries share one key when ixn or drt events follow the last rotation. A deactivated
// AID yields {"keys":[]}.
//
// The output is RFC 8785 canonical JSON, so a hub serves identical bytes for an unchanged KEL
// and can derive an ETag from them.
//
// A JWKS served by a hub is that hub's statement about the KEL. A verifier that holds the KEL
// should use CurrentKey instead (A2A-DESIGN §10.3).
func JWKS(kel []identity.SignedEvent) ([]byte, error) {
	states, err := identity.Replay(kel)
	if err != nil {
		return nil, &Error{Code: CodeUnknownAID, Detail: "KEL does not replay", Err: err}
	}
	aid := states[len(states)-1].AID
	keys := &value{kind: kindArray, arr: []*value{}}
	if lo, ok := currentRange(kel); ok {
		for seq := lo; seq < len(states); seq++ {
			pub := states[seq].CurrentKeys
			if len(pub) != 1 {
				return nil, newErr(CodeKeyNotCurrent, "key state does not hold exactly one key")
			}
			keys.arr = append(keys.arr, &value{kind: kindObject, obj: map[string]*value{
				"kty": {kind: kindString, str: "OKP"},
				"crv": {kind: kindString, str: "Ed25519"},
				"x":   {kind: kindString, str: b64.EncodeToString(pub[0])},
				"kid": {kind: kindString, str: KID(aid, uint64(seq))},
				"alg": {kind: kindString, str: AlgEdDSA},
				"use": {kind: kindString, str: "sig"},
			}})
		}
	}
	set := &value{kind: kindObject, obj: map[string]*value{"keys": keys}}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, set, ""); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
