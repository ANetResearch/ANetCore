package delegation

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ANetResearch/ANetCore/coredet"
)

// The extended card exchange (HPP §2.6, core §2.4.2): a requester asks a provider for its signed
// extended AgentCard with an anet.card.get/1 message and gets an anet.card/1 answer. Both are
// one-shot envelopes (core G11) and neither creates or changes an interaction on either side.

// Inner types of the two messages (L39). The seal package carries them as opaque type strings.
const (
	TypeCardGet = "anet.card.get/1" // CardGet, requester -> provider
	TypeCard    = "anet.card/1"     // CardResp, provider -> requester
)

// Refusals a provider may answer a card request with (CardResp key 2). The set is closed.
const (
	// CardNotConfigured: the card the caller would get is the public card — no prices and no skill
	// beyond it (CORE-K23 rule 1).
	CardNotConfigured = "not_configured"
	// CardBusy: the caller asked too often (HPP PAY-C8); ask again later.
	CardBusy = "busy"
)

// MaxCardBytes bounds the extended card a CardResp carries (64 KiB).
const MaxCardBytes = 64 << 10

// ErrCard: a card message that is not exactly one of the shapes core §2.4.2 allows.
var ErrCard = errors.New("delegation: not a well-formed card message")

// CardGet is the body of anet.card.get/1: the empty map. The type string carries the version, so
// the body has nothing to say.
//
//anet:wire CardGet
type CardGet struct{}

// cardGetBytes is coredet({}), the one encoding of a CardGet.
var cardGetBytes = []byte{0xa0}

// Marshal returns the one encoding of a CardGet, the empty map.
func (CardGet) Marshal() ([]byte, error) { return bytes.Clone(cardGetBytes), nil }

// UnmarshalCardGet accepts exactly the empty map. Anything else — a key, a null, a non-canonical
// empty map — is ErrCard.
func UnmarshalCardGet(b []byte) (*CardGet, error) {
	if !bytes.Equal(b, cardGetBytes) {
		return nil, fmt.Errorf("%w: a card request is the empty map", ErrCard)
	}
	return &CardGet{}, nil
}

// CardResp is the body of anet.card/1: the provider-signed extended card, or why there is none.
// Exactly one of the two is present.
//
//anet:wire CardResp
type CardResp struct {
	Card  []byte `cbor:"1,keyasint,omitempty"` // the extended card's bytes as the provider signed them
	Error string `cbor:"2,keyasint,omitempty"` // CardNotConfigured or CardBusy
}

func (r *CardResp) check() error {
	switch {
	case len(r.Card) > 0 && r.Error != "":
		return fmt.Errorf("%w: a card answer carries a card or an error, not both", ErrCard)
	case len(r.Card) > MaxCardBytes:
		return fmt.Errorf("%w: the card is %d bytes, over %d", ErrCard, len(r.Card), MaxCardBytes)
	case len(r.Card) > 0:
		return nil
	case r.Error == CardNotConfigured, r.Error == CardBusy:
		return nil
	case r.Error == "":
		return fmt.Errorf("%w: a card answer carries neither a card nor an error", ErrCard)
	default:
		return fmt.Errorf("%w: %q is not a card error (want %s or %s)", ErrCard, r.Error, CardNotConfigured, CardBusy)
	}
}

// Marshal encodes a CardResp; a value that is not exactly one card or one known error is ErrCard.
func (r *CardResp) Marshal() ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	return coredet.Marshal(*r)
}

// UnmarshalCardResp decodes a CardResp strictly: no other key, its one canonical encoding, exactly
// one of card and error, a known error, a card of at most MaxCardBytes.
func UnmarshalCardResp(b []byte) (*CardResp, error) {
	var r CardResp
	if err := coredet.UnmarshalStrict(b, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCard, err)
	}
	if back, err := coredet.Marshal(r); err != nil || !bytes.Equal(back, b) {
		return nil, fmt.Errorf("%w: not its one canonical encoding", ErrCard)
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	return &r, nil
}
