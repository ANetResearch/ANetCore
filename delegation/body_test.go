package delegation

// body_test.go: the one rule every body decodes by (core §0.2 CORE-E2, CORE-E4; CUX §4.1), the
// kinds and keys of a ChatMsg (CORE-K6), and the two validators the receive pipeline calls
// (ValidatePreview, CUX-P2; ValidateReply, CUX-R3).

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/tsir"
	"github.com/ANetResearch/ANetCore/wire"
)

func mustEnc(t testing.TB, v any) []byte {
	t.Helper()
	b, err := coredet.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rawMap decodes b as an integer-keyed map, keeping each value's bytes.
func rawMap(t testing.TB, b []byte) map[uint64]cbor.RawMessage {
	t.Helper()
	var m map[uint64]cbor.RawMessage
	if err := coredet.Unmarshal(b, &m); err != nil || m == nil {
		t.Fatalf("not a map: %v", err)
	}
	return m
}

// addTopKey is b, a map, with key k added (value null).
func addTopKey(t testing.TB, b []byte, k uint64) []byte {
	t.Helper()
	m := rawMap(t, b)
	if _, has := m[k]; has {
		t.Fatalf("key %d is already there", k)
	}
	m[k] = cbor.RawMessage{0xf6}
	return mustEnc(t, m)
}

// setTopKey is b, a map, with key k set to the encoding of v.
func setTopKey(t testing.TB, b []byte, k uint64, v any) []byte {
	t.Helper()
	m := rawMap(t, b)
	m[k] = mustEnc(t, v)
	return mustEnc(t, m)
}

// nonCanonical is the map b written with an indefinite length: the same map, another encoding.
func nonCanonical(t testing.TB, b []byte) []byte {
	t.Helper()
	var head int
	switch {
	case b[0] >= 0xa0 && b[0] <= 0xb7:
		head = 1
	case b[0] == 0xb8:
		head = 2
	case b[0] == 0xb9:
		head = 3
	default:
		t.Fatalf("not a short map: %x", b[:1])
	}
	out := append([]byte{0xbf}, b[head:]...)
	return append(out, 0xff)
}

// replaceAt returns doc with the value at path replaced by repl (path elements: a uint64 map key,
// an int array index, or inBstr, the bytes a bstr carries). at returns the value there.
type bstrStep struct{}

var inBstr = bstrStep{}

func replaceAt(t testing.TB, doc []byte, path []any, repl []byte) []byte {
	t.Helper()
	if len(path) == 0 {
		return repl
	}
	switch p := path[0].(type) {
	case uint64:
		m := rawMap(t, doc)
		m[p] = replaceAt(t, m[p], path[1:], repl)
		return mustEnc(t, m)
	case int:
		var a []cbor.RawMessage
		if err := coredet.Unmarshal(doc, &a); err != nil || p >= len(a) {
			t.Fatalf("no element %d (%v)", p, err)
		}
		a[p] = replaceAt(t, a[p], path[1:], repl)
		return mustEnc(t, a)
	case bstrStep:
		var inner []byte
		if err := coredet.Unmarshal(doc, &inner); err != nil {
			t.Fatal(err)
		}
		return mustEnc(t, replaceAt(t, inner, path[1:], repl))
	}
	t.Fatalf("bad path element %v", path[0])
	return nil
}

func at(t testing.TB, doc []byte, path []any) []byte {
	t.Helper()
	if len(path) == 0 {
		return doc
	}
	switch p := path[0].(type) {
	case uint64:
		return at(t, rawMap(t, doc)[p], path[1:])
	case int:
		var a []cbor.RawMessage
		if err := coredet.Unmarshal(doc, &a); err != nil || p >= len(a) {
			t.Fatalf("no element %d (%v)", p, err)
		}
		return at(t, a[p], path[1:])
	case bstrStep:
		var inner []byte
		if err := coredet.Unmarshal(doc, &inner); err != nil {
			t.Fatal(err)
		}
		return at(t, inner, path[1:])
	}
	t.Fatalf("bad path element %v", path[0])
	return nil
}

func boolp(b bool) *bool    { return &b }
func u64p(v uint64) *uint64 { return &v }
func intp(v int) *int       { return &v }
func att(name string) []Attachment {
	return []Attachment{{Name: name, Mime: "text/plain", Size: 3, CID: "bafkreif2pall7dybz7vecqka3zo24irdwabwdi4wc55jznaq75q7eaavvu", Data: []byte("abc")}}
}

// fullTaskDoc fills every key of every TaskDoc object a delegation can carry.
func fullTaskDoc() *tsir.TaskDoc {
	scope := &tsir.Predicate{Op: tsir.OpScope, Scope: &tsir.ScopeClause{Verb: tsir.VerbCall, Kind: 1,
		Match: tsir.ResourceMatch{Kind: tsir.MatchGlob, Val: "a/*"}, MergeClass: intp(1)}}
	return &tsir.TaskDoc{
		Version: tsir.VersionPair{Major: 1, Minor: 2},
		Meta:    []tsir.MetaEntry{{Name: "n", Value: "v"}},
		Links:   []tsir.Link{{Rel: "related", Href: "x", Title: "t"}},
		Tasks: []tsir.Task{{
			ID:       "t1",
			Intent:   tsir.Intent{Summary: "s", Format: "text", Body: "describe the image"},
			Requires: []tsir.Require{{ID: "image.caption", Type: "capability", Necessity: "must", Description: "d"}},
			Accepts: []tsir.Accept{{Type: "artifact", Description: "d", Outputs: []tsir.Output{{Format: "text/plain", MaxSize: "1k", Name: "o"}},
				Schema: &tsir.Schema{Type: "regex", Body: ".*"}}},
			Contexts: []tsir.Context{{Key: "args", Value: "{}", Src: "s", Format: "json", Visibility: "private"}},
			PositiveScope: &tsir.Predicate{Op: tsir.OpAND, Children: []*tsir.Predicate{scope},
				Artifact: &tsir.ArtifactClause{PathGlob: "*.txt", Exists: boolp(true), MinSizeBytes: u64p(1), SchemaRef: "r", Contains: []string{"x"}},
				Test:     &tsir.TestClause{TestID: "t", Expect: 1},
				Thresh:   &tsir.ThresholdClause{Metric: "m", Op: tsir.CmpLE, Value: 0.5},
				Scope:    scope.Scope},
			NegativeScope: &tsir.Predicate{Op: tsir.OpNOT, Children: []*tsir.Predicate{scope}},
			CouplingHint:  1,
		}},
		Critical: []uint64{1},
	}
}

// fullDelegation is a delegation with every key, carrying fullTaskDoc. It is not signed: the
// decoder does not check the signature.
func fullDelegation(t testing.TB) []byte {
	env := &aobj.Envelope{SignerAID: identity.SuiteController().AID(), KeyStateSeq: 0, Alg: aobj.AlgEdDSA,
		Sig: bytes.Repeat([]byte{7}, 64), PreimageRef: "ref"}
	return mustEnc(t, &DelegateReq{TaskDoc: mustEnc(t, fullTaskDoc()), Envelope: env,
		InteractionID: "ix-1", Attachments: att("a.txt"), ContextID: "ctx", Metadata: []byte(`{}`)})
}

func previewFrame() *ChatMsg {
	return &ChatMsg{Kind: ChatStreamPreview, Body: "partial", StreamSeq: 1767225600001, StreamAtMS: 1767225600000,
		ReasoningBody: "thinking", ReasoningStreamAtMS: 1767225599000, MsgID: "p-1", Omitted: 7, ReasoningOmitted: 9, Answers: "m-1"}
}

func fullResult(t testing.TB) []byte {
	return mustEnc(t, &ResultResp{Status: StatusDone, Deliverable: []byte("d"), Receipt: []byte("r"), Metadata: []byte(`{}`),
		Reply: &ReplyMsg{Kind: ChatText, Body: "the answer", Attachments: att("b.txt"), MsgID: "m-2"}})
}

func decodeDelegate(b []byte) error { _, err := UnmarshalDelegateReq(b); return err }
func decodeResult(b []byte) error   { _, err := UnmarshalResultResp(b); return err }
func decodeChat(b []byte) error     { _, err := UnmarshalChatMsg(b); return err }
func decodeStatus(b []byte) error   { _, err := UnmarshalStatusMsg(b); return err }

// CORE-S4: for every object a body carries — the four bodies, their attachments and reply, the
// TaskDoc and each object inside it — every key the registry does not assign (0-63, and 64 and
// 65535: none is an extension area), inserted into a valid encoding, is refused by the body's
// decoder, and refused as a key it does not assign, not only as a non-canonical encoding.
func TestBodiesRefuseUnassignedKeys(t *testing.T) {
	reg := wire.MustLoad()
	delegate, result := fullDelegation(t), fullResult(t)
	text := mustEnc(t, &ChatMsg{Kind: ChatText, Body: "hi", Attachments: att("c.txt"), MsgID: "m-3", Metadata: []byte(`{}`)})
	preview := mustEnc(t, previewFrame())
	status := mustEnc(t, &StatusMsg{State: StateWorking, Text: "t", Metadata: []byte(`{}`), At: 1})
	td := []any{uint64(1), inBstr}
	task := append(append([]any(nil), td...), uint64(4), 0)
	pos := append(append([]any(nil), task...), uint64(14))
	path := func(base []any, more ...any) []any { return append(append([]any(nil), base...), more...) }
	cases := []struct {
		object, where string
		body          []byte
		path          []any
		decode        func([]byte) error
	}{
		{"DelegateReq", "delegation", delegate, nil, decodeDelegate},
		{"aobj.Envelope", "delegation key 2", delegate, []any{uint64(2)}, decodeDelegate},
		{"Attachment", "delegation key 5", delegate, []any{uint64(5), 0}, decodeDelegate},
		{"TaskDoc", "delegation key 1", delegate, td, decodeDelegate},
		{"VersionPair", "TaskDoc version", delegate, path(td, uint64(1)), decodeDelegate},
		{"MetaEntry", "TaskDoc meta", delegate, path(td, uint64(2), 0), decodeDelegate},
		{"Link", "TaskDoc links", delegate, path(td, uint64(3), 0), decodeDelegate},
		{"Task", "TaskDoc tasks", delegate, task, decodeDelegate},
		{"Intent", "task intent", delegate, path(task, uint64(10)), decodeDelegate},
		{"Require", "task requires", delegate, path(task, uint64(11), 0), decodeDelegate},
		{"Accept", "task accepts", delegate, path(task, uint64(12), 0), decodeDelegate},
		{"Output", "accept outputs", delegate, path(task, uint64(12), 0, uint64(3), 0), decodeDelegate},
		{"Schema", "accept schema", delegate, path(task, uint64(12), 0, uint64(4)), decodeDelegate},
		{"Context", "task contexts", delegate, path(task, uint64(13), 0), decodeDelegate},
		{"Predicate", "positive scope", delegate, pos, decodeDelegate},
		{"Predicate", "predicate children", delegate, path(pos, uint64(2), 0), decodeDelegate},
		{"Predicate", "negative scope", delegate, path(task, uint64(15)), decodeDelegate},
		{"ArtifactClause", "predicate artifact", delegate, path(pos, uint64(10)), decodeDelegate},
		{"TestClause", "predicate test", delegate, path(pos, uint64(11)), decodeDelegate},
		{"ThresholdClause", "predicate thresh", delegate, path(pos, uint64(12)), decodeDelegate},
		{"ScopeClause", "predicate scope", delegate, path(pos, uint64(13)), decodeDelegate},
		{"ResourceMatch", "scope match", delegate, path(pos, uint64(13), uint64(3)), decodeDelegate},
		{"ResultResp", "result", result, nil, decodeResult},
		{"ReplyMsg", "result key 6", result, []any{uint64(6)}, decodeResult},
		{"Attachment", "reply key 3", result, []any{uint64(6), uint64(3), 0}, decodeResult},
		{"ChatMsg", "text message", text, nil, decodeChat},
		{"Attachment", "message key 3", text, []any{uint64(3), 0}, decodeChat},
		{"ChatMsg", "preview frame", preview, nil, decodeChat},
		{"StatusMsg", "status", status, nil, decodeStatus},
	}
	for _, tc := range cases {
		t.Run(tc.object+" in "+tc.where, func(t *testing.T) {
			if err := tc.decode(tc.body); err != nil {
				t.Fatalf("the valid body is refused: %v", err)
			}
			negs, err := wire.Negatives(reg, tc.object, at(t, tc.body, tc.path))
			if err != nil {
				t.Fatal(err)
			}
			if len(negs) == 0 {
				t.Fatal("no negatives")
			}
			for _, n := range negs {
				err := tc.decode(replaceAt(t, tc.body, tc.path, n.Bytes))
				if !errors.Is(err, ErrBody) || !strings.Contains(err.Error(), "does not assign") {
					t.Errorf("%s with key %d (%s): want a refusal of the key, got %v", tc.object, n.Key, n.Why, err)
				}
			}
		})
	}
}

// CORE-E2: a body is its one canonical encoding. Another encoding of the same value, a null for
// an absent field, an explicit empty value and trailing bytes are each refused — so a field is
// present exactly when it holds a value, and the bytes the inner signature covers have one meaning.
func TestBodiesAreCanonical(t *testing.T) {
	delegate, result := fullDelegation(t), fullResult(t)
	text := mustEnc(t, &ChatMsg{Kind: ChatText, Body: "hi", MsgID: "m-3"})
	status := mustEnc(t, &StatusMsg{State: StateWorking, At: 1})
	td := []any{uint64(1), inBstr}
	for name, tc := range map[string]struct {
		b      []byte
		decode func([]byte) error
	}{
		"delegation, indefinite map":      {nonCanonical(t, delegate), decodeDelegate},
		"TaskDoc, indefinite map":         {replaceAt(t, delegate, td, nonCanonical(t, at(t, delegate, td))), decodeDelegate},
		"TaskDoc, explicit empty task id": {replaceAt(t, delegate, append(td, uint64(4), 0), setTopKey(t, at(t, delegate, append(td, uint64(4), 0)), 1, "")), decodeDelegate},
		"delegation, null context id":     {setTopKey(t, delegate, 7, nil), decodeDelegate},
		"delegation, trailing byte":       {append(bytes.Clone(delegate), 0x00), decodeDelegate},
		"result, indefinite map":          {nonCanonical(t, result), decodeResult},
		"result, null reply":              {setTopKey(t, result, 6, nil), decodeResult},
		"result, explicit empty receipt":  {setTopKey(t, result, 3, []byte{}), decodeResult},
		"message, indefinite map":         {nonCanonical(t, text), decodeChat},
		"message, explicit empty body":    {setTopKey(t, text, 2, ""), decodeChat},
		"message, null attachments":       {setTopKey(t, text, 3, nil), decodeChat},
		"message, explicit empty array":   {setTopKey(t, text, 3, []any{}), decodeChat},
		"message, non-shortest integer":   {setTopKey(t, mustEnc(t, previewFrame()), 11, cbor.RawMessage{0x19, 0x00, 0x07}), decodeChat},
		"status, indefinite map":          {nonCanonical(t, status), decodeStatus},
		"status, null text":               {setTopKey(t, status, 2, nil), decodeStatus},
	} {
		if err := tc.decode(tc.b); !errors.Is(err, ErrBody) {
			t.Errorf("%s: want ErrBody, got %v", name, err)
		}
	}
	// The canonical forms decode.
	for name, tc := range map[string]struct {
		b      []byte
		decode func([]byte) error
	}{"delegation": {delegate, decodeDelegate}, "result": {result, decodeResult}, "message": {text, decodeChat}, "status": {status, decodeStatus}} {
		if err := tc.decode(tc.b); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A delegation carries a TaskDoc with at least one task, its signature and an interaction id;
// retired keys 3 (the body KEL) and 6 (the prepayment) are refused.
func TestADelegationCarriesWhatItMust(t *testing.T) {
	delegate := fullDelegation(t)
	m := func(edit func(map[uint64]cbor.RawMessage)) []byte {
		r := rawMap(t, delegate)
		edit(r)
		return mustEnc(t, r)
	}
	for name, b := range map[string][]byte{
		"no TaskDoc":                   m(func(r map[uint64]cbor.RawMessage) { delete(r, 1) }),
		"no envelope":                  m(func(r map[uint64]cbor.RawMessage) { delete(r, 2) }),
		"null envelope":                setTopKey(t, delegate, 2, nil),
		"no interaction id":            m(func(r map[uint64]cbor.RawMessage) { delete(r, 4) }),
		"empty interaction id":         setTopKey(t, delegate, 4, ""),
		"retired key 3 (a KEL)":        setTopKey(t, delegate, 3, []byte{0xa0}),
		"retired key 6 (a prepayment)": setTopKey(t, delegate, 6, []byte{0xa0}),
		"undecodable TaskDoc":          setTopKey(t, delegate, 1, []byte{0xff}),
		"TaskDoc of no task":           setTopKey(t, delegate, 1, mustEnc(t, &tsir.TaskDoc{Version: tsir.VersionPair{Major: 1}, Tasks: []tsir.Task{}})),
		"TaskDoc of null tasks":        setTopKey(t, delegate, 1, mustEnc(t, &tsir.TaskDoc{Version: tsir.VersionPair{Major: 1}})),
	} {
		if _, err := UnmarshalDelegateReq(b); !errors.Is(err, ErrBody) {
			t.Errorf("%s: want ErrBody, got %v", name, err)
		}
	}
}

// The kinds are a closed set; end_accept is retired. A message that is not a preview frame
// carries none of the preview keys 4-7 and 11-13 (CORE-K6).
func TestMessageKindsAndPreviewKeys(t *testing.T) {
	for _, k := range []string{ChatText, ChatEndRequest, KindCancel} {
		if _, err := UnmarshalChatMsg(mustEnc(t, &ChatMsg{Kind: k, MsgID: "m"})); err != nil {
			t.Errorf("kind %s: %v", k, err)
		}
	}
	if _, err := UnmarshalChatMsg(mustEnc(t, previewFrame())); err != nil {
		t.Errorf("preview frame: %v", err)
	}
	for _, k := range []string{"end_accept", "", "Text", "stream-preview", "future"} {
		_, err := UnmarshalChatMsg(mustEnc(t, &ChatMsg{Kind: k, MsgID: "m"}))
		if !errors.Is(err, ErrBody) {
			t.Errorf("kind %q: want ErrBody, got %v", k, err)
		}
		if k == "end_accept" && (err == nil || !strings.Contains(err.Error(), "retired")) {
			t.Errorf("end_accept must be refused as retired: %v", err)
		}
	}
	for key, set := range map[int]func(*ChatMsg){
		4:  func(m *ChatMsg) { m.StreamSeq = 1 },
		5:  func(m *ChatMsg) { m.StreamAtMS = 1 },
		6:  func(m *ChatMsg) { m.ReasoningBody = "r" },
		7:  func(m *ChatMsg) { m.ReasoningStreamAtMS = 1 },
		11: func(m *ChatMsg) { m.Omitted = 1 },
		12: func(m *ChatMsg) { m.ReasoningOmitted = 1 },
		13: func(m *ChatMsg) { m.Answers = "m-0" },
	} {
		for _, k := range []string{ChatText, ChatEndRequest, KindCancel} {
			m := &ChatMsg{Kind: k, Body: "b", MsgID: "m"}
			set(m)
			_, err := UnmarshalChatMsg(mustEnc(t, m))
			if !errors.Is(err, ErrBody) || !strings.Contains(err.Error(), "key "+strconv.Itoa(key)) {
				t.Errorf("%s with key %d: want a refusal naming the key, got %v", k, key, err)
			}
		}
	}
}

// CUX-P2: ValidatePreview, one case for each refusal the spec lists, and the frame that passes.
func TestValidatePreview(t *testing.T) {
	if err := ValidatePreview(previewFrame()); err != nil {
		t.Fatalf("a well-formed frame is refused: %v", err)
	}
	minimal := &ChatMsg{Kind: ChatStreamPreview, StreamSeq: 1, StreamAtMS: 1, MsgID: "p", Answers: "m"}
	if err := ValidatePreview(minimal); err != nil {
		t.Fatalf("a frame with only its required keys is refused: %v", err)
	}
	full := func(edit func(*ChatMsg)) *ChatMsg {
		m := previewFrame()
		edit(m)
		return m
	}
	atLimit := full(func(m *ChatMsg) {
		m.Body = strings.Repeat("a", MaxPreviewTail-3) + "€"
		m.ReasoningBody = strings.Repeat("r", MaxPreviewTail)
	})
	if err := ValidatePreview(atLimit); err != nil {
		t.Fatalf("tails of exactly %d bytes are refused: %v", MaxPreviewTail, err)
	}
	for name, m := range map[string]*ChatMsg{
		"with key 3 (attachments)": full(func(m *ChatMsg) { m.Attachments = att("a.png") }),
		"with key 10 (metadata)":   full(func(m *ChatMsg) { m.Metadata = []byte(`{}`) }),
		"key 2 of 8193 bytes":      full(func(m *ChatMsg) { m.Body = strings.Repeat("a", MaxPreviewTail+1) }),
		"key 6 of 8193 bytes":      full(func(m *ChatMsg) { m.ReasoningBody = strings.Repeat("a", MaxPreviewTail+1) }),
		"key 2 not valid UTF-8":    full(func(m *ChatMsg) { m.Body = "ab\xffc" }),
		"key 6 not valid UTF-8":    full(func(m *ChatMsg) { m.ReasoningBody = "\xc3" }),
		"without key 4":            full(func(m *ChatMsg) { m.StreamSeq = 0 }),
		"without key 5":            full(func(m *ChatMsg) { m.StreamAtMS = 0 }),
		"without key 9":            full(func(m *ChatMsg) { m.MsgID = "" }),
		"without key 13":           full(func(m *ChatMsg) { m.Answers = "" }),
		"a text message":           {Kind: ChatText, Body: "x"},
		"nil":                      nil,
	} {
		if err := ValidatePreview(m); !errors.Is(err, ErrBody) {
			t.Errorf("%s: want ErrBody, got %v", name, err)
		}
	}
	// Key 4 present with 0 is not a stream_seq either: as bytes it is not canonical, and decoded it
	// is the frame without key 4.
	zero := setTopKey(t, mustEnc(t, previewFrame()), 4, uint64(0))
	if m, err := UnmarshalChatMsg(zero); err == nil {
		if err := ValidatePreview(m); err == nil {
			t.Error("a frame whose key 4 is 0 is accepted")
		}
	} else if !errors.Is(err, ErrBody) {
		t.Errorf("key 4 = 0: %v", err)
	}
}

// CUX-R3: a reply is the ChatMsg subset {1 kind = text, 2, 3, 9 msg_id}. Its type has no other
// key, so a reply carrying one does not decode; ValidateReply checks the kind and the id.
func TestValidateReply(t *testing.T) {
	ok := &ReplyMsg{Kind: ChatText, Body: "the answer", Attachments: att("a.txt"), MsgID: "m-1"}
	if err := ValidateReply(ok); err != nil {
		t.Fatalf("a well-formed reply is refused: %v", err)
	}
	if err := ValidateReply(&ReplyMsg{Kind: ChatText, MsgID: "m-1"}); err != nil {
		t.Fatalf("a reply with only its required keys is refused: %v", err)
	}
	for name, r := range map[string]*ReplyMsg{
		"kind end_request":     {Kind: ChatEndRequest, MsgID: "m"},
		"kind stream_preview":  {Kind: ChatStreamPreview, MsgID: "m"},
		"no kind":              {MsgID: "m"},
		"without key 9":        {Kind: ChatText, Body: "x"},
		"body not valid UTF-8": {Kind: ChatText, Body: "\xff", MsgID: "m"},
		"nil":                  nil,
	} {
		if err := ValidateReply(r); !errors.Is(err, ErrBody) {
			t.Errorf("%s: want ErrBody, got %v", name, err)
		}
	}
	// As bytes, inside a result: keys 1, 2, 3 and 9 only; the checks above run when it decodes.
	result := fullResult(t)
	reply := []any{uint64(6)}
	for _, k := range []uint64{4, 5, 6, 7, 8, 10, 11, 12, 13} {
		b := replaceAt(t, result, reply, setTopKey(t, at(t, result, reply), k, uint64(1)))
		_, err := UnmarshalResultResp(b)
		if !errors.Is(err, ErrBody) || !strings.Contains(err.Error(), "does not assign") {
			t.Errorf("a reply with key %d: want a refusal of the key, got %v", k, err)
		}
	}
	for name, b := range map[string][]byte{
		"reply kind end_request":   replaceAt(t, result, reply, setTopKey(t, at(t, result, reply), 1, ChatEndRequest)),
		"reply without key 9":      replaceAt(t, result, reply, func() []byte { m := rawMap(t, at(t, result, reply)); delete(m, 9); return mustEnc(t, m) }()),
		"reply on a failed result": setTopKey(t, result, 1, StatusFailed),
	} {
		if _, err := UnmarshalResultResp(b); !errors.Is(err, ErrBody) {
			t.Errorf("%s: want ErrBody, got %v", name, err)
		}
	}
}

// A result's status is done or failed; queued never travels.
func TestResultStatus(t *testing.T) {
	for _, s := range []string{StatusDone, StatusFailed} {
		if _, err := UnmarshalResultResp(mustEnc(t, &ResultResp{Status: s})); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{StatusQueued, "", "Done", "completed"} {
		if _, err := UnmarshalResultResp(mustEnc(t, &ResultResp{Status: s})); !errors.Is(err, ErrBody) {
			t.Errorf("status %q: want ErrBody, got %v", s, err)
		}
	}
	// Key 4, the provider's KEL of 0.2, is retired.
	if _, err := UnmarshalResultResp(setTopKey(t, mustEnc(t, &ResultResp{Status: StatusDone}), 4, []byte{0xa0})); !errors.Is(err, ErrBody) {
		t.Errorf("result with retired key 4: %v", err)
	}
}
