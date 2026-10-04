package golden

// a2a_wire_v3_test.go pins the inner bodies of wire 3 (core §2.4.2): DELEGATE-3, CHATMSG-3 and
// RESULT-3 (correctness and usability's part) and CARD-1 (hub and payment privacy's). Each fills
// every key its object may carry, and each comes with negatives: a retired key, a key the object
// does not assign, a required key dropped, a byte changed. golden/py/test_gen_v016.py checks every
// pinned value against the independent encoder of golden/py/gen_v016.py (cux_go_pins,
// hpp_go_pins).

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/delegation"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/tsir"
)

// v3Edit returns the map b with key k set to the encoding of v, or removed when v is absentKey.
func v3Edit(t *testing.T, b []byte, k uint64, v any) []byte {
	t.Helper()
	var m map[uint64]cbor.RawMessage
	if err := coredet.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if v == absentKey {
		delete(m, k)
	} else {
		raw, err := coredet.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		m[k] = raw
	}
	out, err := coredet.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type absent struct{}

var absentKey = absent{}

// refusedAsBody asserts that decode refuses every case as a malformed body.
func refusedAsBody(t *testing.T, what string, cases map[string][]byte, decode func([]byte) error) {
	t.Helper()
	for name, b := range cases {
		if err := decode(b); !errors.Is(err, delegation.ErrBody) {
			t.Errorf("%s %s: want ErrBody, got %v", what, name, err)
		}
	}
}

// goldenTaskDoc is a TaskDoc signed by the conformance identity. Ed25519 signing is deterministic,
// so its bytes and envelope are the same in every run.
func goldenTaskDoc(t *testing.T) ([]byte, *tsir.TaskDoc) {
	t.Helper()
	doc := &tsir.TaskDoc{
		Version: tsir.VersionPair{Major: 1},
		Tasks:   []tsir.Task{{Intent: tsir.Intent{Summary: "golden task", Body: "describe the image"}}},
	}
	if err := doc.Sign(identity.SuiteController()); err != nil {
		t.Fatal(err)
	}
	raw, err := coredet.Marshal(*doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw, doc
}

// DELEGATE-3: the body of anet.delegate/1 with every key it may carry (1, 2, 4, 5, 7, 8); keys 3
// (the KEL of 0.2) and 6 (the prepayment) are retired and refused. The TaskDoc inside decodes by
// the same rule as the body: a key no TaskDoc object assigns, or another encoding of it, is
// refused before its signature is looked at.
func TestDELEGATE_3(t *testing.T) {
	c := identity.SuiteController()
	raw, doc := goldenTaskDoc(t)
	req := &delegation.DelegateReq{TaskDoc: raw, Envelope: doc.Envelope, InteractionID: "ix-golden-1",
		Attachments: goldenAttachments(t), ContextID: "ctx-golden-1", Metadata: []byte(goldenMetadata)}
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, "delegation", b, []uint64{1, 2, 4, 5, 7, 8})
	const wantWire = "a601582ba201a101010481a10aa2016b676f6c64656e207461736b037264657363726962652074686520696d61676502a401783b62616679726569687134326a3765736c6a6a3564727867696575646832617234677373706f6770656a6d64786d67346e657a6661337477646d6b6502000327045840b4377c54e444f5321192706056fa918971f8a0bf4f34f865a0e83117a69e3b2aa72a95a7ffaf3795d682bead03775648746dd2fc650962239769ffad65de990a046b69782d676f6c64656e2d310581a50165612e747874026a746578742f706c61696e030304783b6261666b726569663270616c6c376479627a37766563716b61337a6f323469726477616277646934776335356a7a6e6171373571376561617676750543616263076c6374782d676f6c64656e2d3108582f7b226132612e73657276696365506172616d6574657273223a7b224132412d56657273696f6e223a22312e30227d7d"
	if got := hex.EncodeToString(b); got != wantWire {
		t.Fatalf("delegation wire\n got  %s\n want %s", got, wantWire)
	}
	back, err := delegation.UnmarshalDelegateReq(b)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := back.Marshal(); !bytes.Equal(again, b) {
		t.Fatalf("the delegation did not round-trip: %+v", back)
	}
	if aid, _, tdBytes, err := delegation.VerifyDelegateReqWithKEL(back, c.KEL(), 1767225600000); err != nil ||
		aid != c.AID() || !bytes.Equal(tdBytes, raw) {
		t.Fatalf("the golden delegation must verify as the conformance identity's: %s, %v", aid, err)
	}

	var kel []byte
	if kel, err = identity.MarshalKEL(c.KEL()); err != nil {
		t.Fatal(err)
	}
	withTaskDoc := func(td []byte) []byte { return v3Edit(t, b, 1, td) }
	strayTask := v3Edit(t, raw, 4, []any{map[uint64]any{2: "stray", 10: map[uint64]any{1: "golden task", 3: "describe the image"}}})
	indefinite := append(append([]byte{0xbf}, raw[1:]...), 0xff)
	refusedAsBody(t, "delegation", map[string][]byte{
		"with retired key 3 (a KEL)":           v3Edit(t, b, 3, kel),
		"with retired key 6 (a prepayment)":    v3Edit(t, b, 6, []byte{0xa0}),
		"without required key 4":               v3Edit(t, b, 4, absentKey),
		"with unassigned key 9":                v3Edit(t, b, 9, nil),
		"whose TaskDoc has unassigned key 5":   withTaskDoc(v3Edit(t, raw, 5, nil)),
		"whose task has unassigned key 2":      withTaskDoc(strayTask),
		"whose TaskDoc is in another encoding": withTaskDoc(indefinite),
	}, func(b []byte) error { _, err := delegation.UnmarshalDelegateReq(b); return err })
	// One byte of the signed TaskDoc changed: it decodes, and its signature no longer verifies.
	changed := bytes.Replace(raw, []byte("describe the image"), []byte("describe the imagf"), 1)
	other, err := delegation.UnmarshalDelegateReq(withTaskDoc(changed))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := delegation.VerifyDelegateReqWithKEL(other, c.KEL(), 1767225600000); err == nil ||
		!strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("a changed TaskDoc byte: want signature invalid, got %v", err)
	}
}

// CHATMSG-3: a preview frame with every key it may carry (1, 2, 4-7, 9, 11-13) and a text message
// with every key it may carry (1, 2, 3, 9, 10). The preview keys 4-7 and 11-13 belong to a preview
// frame only (CORE-K6); end_accept is retired.
func TestCHATMSG_3(t *testing.T) {
	frame := &delegation.ChatMsg{Kind: delegation.ChatStreamPreview, Body: "the caption so far",
		StreamSeq: 1767225600123, StreamAtMS: 1767225600000,
		ReasoningBody: "weighing the second approach", ReasoningStreamAtMS: 1767225599000,
		MsgID: "p-golden-1", Omitted: 1024, ReasoningOmitted: 2048, Answers: "m-golden-1"}
	text := &delegation.ChatMsg{Kind: delegation.ChatText, Body: "hello", Attachments: goldenAttachments(t),
		MsgID: "m-golden-2", Metadata: []byte(goldenMetadata)}
	for _, tc := range []struct {
		name string
		msg  *delegation.ChatMsg
		keys []uint64
		want string
	}{
		{"preview frame", frame, []uint64{1, 2, 4, 5, 6, 7, 9, 11, 12, 13}, "aa016e73747265616d5f7072657669657702727468652063617074696f6e20736f20666172041b0000019b76daa87b051b0000019b76daa80006781c7765696768696e6720746865207365636f6e6420617070726f616368071b0000019b76daa418096a702d676f6c64656e2d310b1904000c1908000d6a6d2d676f6c64656e2d31"},
		{"text message", text, []uint64{1, 2, 3, 9, 10}, "a5016474657874026568656c6c6f0381a50165612e747874026a746578742f706c61696e030304783b6261666b726569663270616c6c376479627a37766563716b61337a6f323469726477616277646934776335356a7a6e6171373571376561617676750543616263096a6d2d676f6c64656e2d320a582f7b226132612e73657276696365506172616d6574657273223a7b224132412d56657273696f6e223a22312e30227d7d"},
	} {
		b, err := tc.msg.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		assertKeys(t, tc.name, b, tc.keys)
		if got := hex.EncodeToString(b); got != tc.want {
			t.Fatalf("%s wire\n got  %s\n want %s", tc.name, got, tc.want)
		}
		back, err := delegation.UnmarshalChatMsg(b)
		if err != nil {
			t.Fatal(err)
		}
		if again, _ := back.Marshal(); !bytes.Equal(again, b) {
			t.Fatalf("%s did not round-trip: %+v", tc.name, back)
		}
	}
	if err := delegation.ValidatePreview(frame); err != nil {
		t.Fatalf("the golden preview frame is refused: %v", err)
	}
	fb, _ := frame.Marshal()
	tb, _ := text.Marshal()
	decode := func(b []byte) error { _, err := delegation.UnmarshalChatMsg(b); return err }
	notPreviewKeys := map[string][]byte{}
	for _, k := range []uint64{4, 5, 6, 7, 11, 12, 13} {
		var v any = uint64(1)
		if k == 6 || k == 13 {
			v = "x"
		}
		notPreviewKeys[fmt.Sprintf("text with key %d", k)] = v3Edit(t, tb, k, v)
	}
	refusedAsBody(t, "message", notPreviewKeys, decode)
	refusedAsBody(t, "message", map[string][]byte{
		"of retired kind end_accept":  v3Edit(t, tb, 1, "end_accept"),
		"of kind texu (one byte off)": bytes.Replace(tb, []byte("text"), []byte("texu"), 1),
		"with unassigned key 8":       v3Edit(t, tb, 8, nil),
		"preview frame with key 8":    v3Edit(t, fb, 8, nil),
		"preview frame with key 14":   v3Edit(t, fb, 14, uint64(1)),
	}, decode)
	// A preview frame that decodes but is not a well-formed frame (CUX-P2).
	for name, b := range map[string][]byte{
		"preview frame with attachments (key 3)": v3Edit(t, fb, 3, goldenAttachments(t)),
		"preview frame with metadata (key 10)":   v3Edit(t, fb, 10, []byte(goldenMetadata)),
		"preview frame without key 13":           v3Edit(t, fb, 13, absentKey),
		"preview frame without key 4":            v3Edit(t, fb, 4, absentKey),
	} {
		m, err := delegation.UnmarshalChatMsg(b)
		if err != nil {
			t.Fatalf("%s: does not decode: %v", name, err)
		}
		if err := delegation.ValidatePreview(m); !errors.Is(err, delegation.ErrBody) {
			t.Errorf("%s: want ErrBody from ValidatePreview, got %v", name, err)
		}
	}
}

// RESULT-3: a completion with every key it may carry (1, 2, 3, 5, 6): the EV2-1 receipt and its
// deliverable, metadata, and the final reply (ReplyMsg, keys 1, 2, 3, 9). Key 4 (the KEL of 0.2)
// is retired; the reply carries no key besides its four. The completion verifies against the task
// EV2-1 describes, and is refused against another request that carries the same task binding
// (the request binding VEC_RESULT_2_RequestBinding pinned before it).
func TestRESULT_3(t *testing.T) {
	c := identity.SuiteController()
	ev := goldenReceiptV2(t)
	reply := &delegation.ReplyMsg{Kind: delegation.ChatText, Body: "a cat on a red chair",
		Attachments: goldenAttachments(t), MsgID: "m-golden-3"}
	rr := &delegation.ResultResp{Status: delegation.StatusDone, Deliverable: ev.Deliverable, Receipt: ev.Wire,
		Metadata: []byte(goldenMetadata), Reply: reply}
	b, err := rr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, "result", b, []uint64{1, 2, 3, 5, 6})
	rb, err := coredet.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, "reply", rb, []uint64{1, 2, 3, 9})
	const wantReply = "a401647465787402746120636174206f6e2061207265642063686169720381a50165612e747874026a746578742f706c61696e030304783b6261666b726569663270616c6c376479627a37766563716b61337a6f323469726477616277646934776335356a7a6e6171373571376561617676750543616263096a6d2d676f6c64656e2d33"
	if got := hex.EncodeToString(rb); got != wantReply {
		t.Fatalf("reply wire\n got  %s\n want %s", got, wantReply)
	}
	// Pinned by CID: the object embeds the EV2-1 receipt; the key sets say which field went
	// missing when the CID moves.
	const wantCID = "bafyreihu4o56drajr5icj2sdwjncdagiap3vceqtsjh4h6n7ex4gbgufsu"
	if got := anetcid.MustSum(b); got != wantCID {
		t.Fatalf("result CID\n got  %s\n want %s", got, wantCID)
	}
	back, err := delegation.UnmarshalResultResp(b)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := back.Marshal(); !bytes.Equal(again, b) {
		t.Fatalf("the result did not round-trip: %+v", back)
	}
	check := delegation.ResultCheck{IX: ev.IX, Provider: c.AID(), TaskDoc: ev.TaskDoc,
		DelegatedDay: ev.CompletedDay, Today: ev.CompletedDay}
	at := ev.CompletedDay * 86_400_000
	if _, err := delegation.VerifyResultForRequest(back, c.KEL(), check, at); err != nil {
		t.Fatalf("bound to the request its receipt names, the golden completion must verify: %v", err)
	}
	// The request binding: another TaskDoc with the same task binding is another request.
	var doc tsir.TaskDoc
	if err := coredet.Unmarshal(ev.TaskDoc, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Tasks[0].Intent.Body = "caption another image"
	otherReq, err := coredet.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	bound := check
	bound.TaskDoc = otherReq
	if _, err := delegation.VerifyResultForRequest(back, c.KEL(), bound, at); !errors.Is(err, delegation.ErrRequestMismatch) {
		t.Fatalf("bound to another request: want ErrRequestMismatch, got %v", err)
	}
	// One deliverable byte changed: it decodes, and the receipt no longer covers it.
	changed := *back
	changed.Deliverable = bytes.Clone(back.Deliverable)
	changed.Deliverable[0] ^= 1
	if _, err := delegation.VerifyResultForRequest(&changed, c.KEL(), check, at); !errors.Is(err, delegation.ErrReceiptMismatch) {
		t.Fatalf("a changed deliverable byte: want ErrReceiptMismatch, got %v", err)
	}

	withReply := func(r []byte) []byte { return v3Edit(t, b, 6, cbor.RawMessage(r)) }
	cases := map[string][]byte{
		"with retired key 4 (a KEL)":         v3Edit(t, b, 4, []byte{0xa0}),
		"with unassigned key 7":              v3Edit(t, b, 7, nil),
		"without required key 1":             v3Edit(t, b, 1, absentKey),
		"of status queued":                   v3Edit(t, b, 1, delegation.StatusQueued),
		"with a reply on a failed result":    v3Edit(t, b, 1, delegation.StatusFailed),
		"whose reply is of kind end_request": withReply(v3Edit(t, rb, 1, delegation.ChatEndRequest)),
		"whose reply has no key 9":           withReply(v3Edit(t, rb, 9, absentKey)),
	}
	for _, k := range []uint64{4, 5, 6, 7, 8, 10, 11, 12, 13} {
		var v any = uint64(1)
		if k == 6 || k == 13 {
			v = "x"
		}
		cases[fmt.Sprintf("whose reply has key %d", k)] = withReply(v3Edit(t, rb, k, v))
	}
	refusedAsBody(t, "result", cases, func(b []byte) error { _, err := delegation.UnmarshalResultResp(b); return err })
}

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
