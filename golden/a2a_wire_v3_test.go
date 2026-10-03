package golden

// a2a_wire_v3_test.go pins the inner bodies of wire 3 (core §2.4.2). CARD-1 is hub and payment
// privacy's part; DELEGATE-3, CHATMSG-3 and RESULT-3 join this file with the body v3 work.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/delegation"
)

// CARD-1: the extended card request and answer (L39 anet.card.get/1, anet.card/1). A request is
// the empty map and nothing else; an answer is exactly one of a card (at most 64 KiB) and a known
// error. golden/py/test_gen_v016.py (hpp_go_pins) checks the pinned bytes against the independent
// encoder.
func TestCARD_1(t *testing.T) {
	if delegation.TypeCardGet != "anet.card.get/1" || delegation.TypeCard != "anet.card/1" {
		t.Fatalf("inner types %q, %q", delegation.TypeCardGet, delegation.TypeCard)
	}
	get, err := delegation.CardGet{}.Marshal()
	if err != nil || hex.EncodeToString(get) != "a0" {
		t.Fatalf("CardGet: %x, %v", get, err)
	}
	card := []byte(`{"name":"golden","capabilities":{"extendedAgentCard":true}}`)
	for _, tc := range []struct {
		name string
		resp delegation.CardResp
		want string
	}{
		{"card", delegation.CardResp{Card: card}, "a101583b7b226e616d65223a22676f6c64656e222c226361706162696c6974696573223a7b22657874656e6465644167656e7443617264223a747275657d7d"},
		{"not_configured", delegation.CardResp{Error: delegation.CardNotConfigured}, "a1026e6e6f745f636f6e66696775726564"},
		{"busy", delegation.CardResp{Error: delegation.CardBusy}, "a1026462757379"},
	} {
		b, err := tc.resp.Marshal()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := hex.EncodeToString(b); got != tc.want {
			t.Errorf("CardResp %s\n got  %s\n want %s", tc.name, got, tc.want)
		}
		back, err := delegation.UnmarshalCardResp(b)
		if err != nil || !bytes.Equal(back.Card, tc.resp.Card) || back.Error != tc.resp.Error {
			t.Errorf("%s did not round-trip: %+v, %v", tc.name, back, err)
		}
	}
	enc := func(m map[uint64]any) []byte {
		b, err := coredet.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, b := range map[string][]byte{
		"both keys":          enc(map[uint64]any{1: card, 2: delegation.CardBusy}),
		"neither key":        enc(map[uint64]any{}),
		"unknown error":      enc(map[uint64]any{2: "rate_limited"}),
		"unregistered key":   enc(map[uint64]any{1: card, 3: uint64(0)}),
		"a card of 64 KiB+1": enc(map[uint64]any{1: bytes.Repeat([]byte{'x'}, delegation.MaxCardBytes+1)}),
	} {
		if _, err := delegation.UnmarshalCardResp(b); !errors.Is(err, delegation.ErrCard) {
			t.Errorf("CardResp %s: want ErrCard, got %v", name, err)
		}
	}
	for name, b := range map[string][]byte{"a key": enc(map[uint64]any{1: card}), "null": {0xf6}} {
		if _, err := delegation.UnmarshalCardGet(b); !errors.Is(err, delegation.ErrCard) {
			t.Errorf("CardGet %s: want ErrCard, got %v", name, err)
		}
	}
}
