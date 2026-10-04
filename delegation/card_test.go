package delegation_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/delegation"
)

func TestACardRequestIsTheEmptyMapAndNothingElse(t *testing.T) {
	b, err := delegation.CardGet{}.Marshal()
	if err != nil || !bytes.Equal(b, []byte{0xa0}) {
		t.Fatalf("CardGet encodes as %x, %v; want a0", b, err)
	}
	if _, err := delegation.UnmarshalCardGet(b); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string][]byte{
		"empty":                 nil,
		"null":                  {0xf6},
		"key 1":                 {0xa1, 0x01, 0x01},
		"indefinite empty map":  {0xbf, 0xff},
		"empty array":           {0x80},
		"two-byte map header":   {0xb8, 0x00},
		"empty map then a byte": {0xa0, 0x00},
	} {
		if _, err := delegation.UnmarshalCardGet(in); !errors.Is(err, delegation.ErrCard) {
			t.Errorf("%s (%x): want ErrCard, got %v", name, in, err)
		}
	}
}

func TestACardAnswerIsExactlyOneThing(t *testing.T) {
	card := []byte(`{"name":"face"}`)
	for _, r := range []*delegation.CardResp{
		{Card: card},
		{Error: delegation.CardNotConfigured},
		{Error: delegation.CardBusy},
		{Card: bytes.Repeat([]byte("x"), delegation.MaxCardBytes)},
	} {
		b, err := r.Marshal()
		if err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
		back, err := delegation.UnmarshalCardResp(b)
		if err != nil || !bytes.Equal(back.Card, r.Card) || back.Error != r.Error {
			t.Fatalf("round trip of %q/%q: %+v, %v", r.Card[:min(len(r.Card), 8)], r.Error, back, err)
		}
	}
	enc := func(m map[uint64]any) []byte {
		b, err := coredet.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, in := range map[string][]byte{
		"both":                   enc(map[uint64]any{1: card, 2: delegation.CardBusy}),
		"neither":                enc(map[uint64]any{}),
		"unknown error":          enc(map[uint64]any{2: "nope"}),
		"error in upper case":    enc(map[uint64]any{2: "BUSY"}),
		"an empty card":          enc(map[uint64]any{1: []byte{}}),
		"an empty error":         enc(map[uint64]any{2: ""}),
		"a card over 64 KiB":     enc(map[uint64]any{1: bytes.Repeat([]byte("x"), delegation.MaxCardBytes+1)}),
		"key 3":                  enc(map[uint64]any{1: card, 3: 1}),
		"key 0":                  enc(map[uint64]any{0: "anet.card/1", 1: card}),
		"card as text":           enc(map[uint64]any{1: string(card)}),
		"null":                   {0xf6},
		"trailing byte":          append(enc(map[uint64]any{1: card}), 0),
		"indefinite-length card": {0xa1, 0x01, 0x5f, 0x41, 'x', 0xff},
	} {
		if _, err := delegation.UnmarshalCardResp(in); !errors.Is(err, delegation.ErrCard) {
			t.Errorf("%s: want ErrCard, got %v", name, err)
		}
	}
	for _, r := range []*delegation.CardResp{{Card: card, Error: delegation.CardBusy}, {}, {Error: "nope"}} {
		if _, err := r.Marshal(); !errors.Is(err, delegation.ErrCard) {
			t.Errorf("marshal %+v: want ErrCard, got %v", r, err)
		}
	}
}

// FuzzCardMessages: the two card decoders refuse or return a value whose one encoding is the input.
func FuzzCardMessages(f *testing.F) {
	for _, s := range [][]byte{{0xa0}, {0xa1, 0x02, 0x64, 'b', 'u', 's', 'y'}, {0xa1, 0x01, 0x41, 'x'}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := delegation.UnmarshalCardGet(b); err == nil && !bytes.Equal(b, []byte{0xa0}) {
			t.Fatalf("accepted a card request of %x", b)
		}
		r, err := delegation.UnmarshalCardResp(b)
		if err != nil {
			return
		}
		back, err := r.Marshal()
		if err != nil || !bytes.Equal(back, b) {
			t.Fatalf("accepted card answer re-encodes differently (%v)", err)
		}
		if (len(r.Card) > 0) == (r.Error != "") || len(r.Card) > delegation.MaxCardBytes {
			t.Fatalf("accepted a card answer that is not exactly one thing: %d bytes, %q", len(r.Card), r.Error)
		}
	})
}
