package thing

import (
	"example.com/fx/identity"
	"example.com/fx/relayauth"
)

// Label is the thing's type tag.
const Label = "anet.fx-thing/1"

// Thing is a registered object.
//
//anet:wire Thing
type Thing struct {
	T     string `cbor:"0,keyasint"`
	A     string `cbor:"1,keyasint"`
	B     uint64 `cbor:"2,keyasint,omitempty"`
	Inner *Part  `cbor:"4,keyasint,omitempty"`
	Cache []byte `cbor:"-"`
}

//anet:wire Part
type Part struct {
	N uint8 `cbor:"1,keyasint"`
}

// Sign is the registered signer of Thing.
func (t *Thing) Sign(c *identity.Controller) []byte {
	sig, _ := c.Sign([]byte(t.T))
	return sig
}

func signed(aid string, action string) []byte { return relayauth.PreimageV2(action, aid) }

// Poll signs a poll.
func Poll(aid string) []byte { return signed(aid, relayauth.ActionPoll) }

// Keys signs a key publication.
func Keys(aid string) []byte { return signed(aid, "keys") }
