// a2a_wire_test.go pins the wire objects added or extended in ANetCore v0.15.0: the delegation
// payloads (A2A-DESIGN §3.4: ChatMsg.Metadata, DelegateReq.ContextID and .Metadata,
// ResultResp.Metadata, and the new StatusMsg) and the relay v2 authentication (§3.7).
//
// Every vector here populates every field of its type, including the ones that existed before.
// The new fields are optional (omitempty), so the v1 vectors in wire_test.go stay byte-identical
// and keep pinning the old encodings; these vectors pin the new keys. A vector over a partly
// filled object cannot detect a field that one implementation encodes and another drops, which is
// the failure the v1 ChatMsg vector was written for.
//
// The numbering follows the design document. There was no DELEGATE_1 vector; VEC_DELEGATE_2 is
// the first vector for DelegateReq.
package golden

import (
	"encoding/hex"
	"reflect"
	"sort"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/delegation"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/tsir"
)

// goldenMetadata is the JSON object used for every Metadata field below. It carries the reserved
// service-parameter key so the vector exercises a realistic value.
const goldenMetadata = `{"a2a.serviceParameters":{"A2A-Version":"1.0"}}`

// topLevelKeys decodes b as an integer-keyed map and returns its keys in ascending order. The
// vectors assert this set so that a vector which silently stopped populating a field fails with
// the key named, not only with a changed hash.
func topLevelKeys(t *testing.T, b []byte) []uint64 {
	t.Helper()
	var raw map[uint64]any
	if err := coredet.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	ks := make([]uint64, 0, len(raw))
	for k := range raw {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i] < ks[j] })
	return ks
}

func assertKeys(t *testing.T, what string, b []byte, want []uint64) {
	t.Helper()
	if got := topLevelKeys(t, b); !reflect.DeepEqual(got, want) {
		t.Errorf("%s keys %v, want %v — a field is missing or moved", what, got, want)
	}
}

// goldenAttachments is one attachment whose CID is the raw CID of its bytes, checked here so the
// vectors stay self-consistent.
func goldenAttachments(t *testing.T) []delegation.Attachment {
	t.Helper()
	a := delegation.Attachment{
		Name: "a.txt", Mime: "text/plain", Size: 3,
		CID: "bafkreif2pall7dybz7vecqka3zo24irdwabwdi4wc55jznaq75q7eaavvu", Data: []byte("abc"),
	}
	if got, err := anetcid.SumRaw(a.Data); err != nil || got != a.CID {
		t.Fatalf("golden attachment CID %s does not match its bytes (%s, %v)", a.CID, got, err)
	}
	return []delegation.Attachment{a}
}

// VEC-CHATMSG-2: every ChatMsg field, including Metadata at key 10 (key 8 is unassigned).
func TestVEC_CHATMSG_2(t *testing.T) {
	msg := &delegation.ChatMsg{
		Kind: delegation.ChatText, Body: "hello",
		Attachments: goldenAttachments(t),
		StreamSeq:   7, StreamAtMS: 1767225600000,
		ReasoningBody: "thinking", ReasoningStreamAtMS: 1767225599000,
		MsgID:    "01J8ZQ",
		Metadata: []byte(goldenMetadata),
	}
	b, err := msg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, "chat message", b, []uint64{1, 2, 3, 4, 5, 6, 7, 9, 10})
	// Cross-checked against an independent deterministic-CBOR encoder (Python, RFC 8949 §4.2.1),
	// which also reproduces VEC-CHATMSG-1.
	const wantWire = "a9016474657874026568656c6c6f0381a50165612e747874026a746578742f706c61696e030304783b6261666b726569663270616c6c376479627a37766563716b61337a6f323469726477616277646934776335356a7a6e61713735713765616176767505436162630407051b0000019b76daa80006687468696e6b696e67071b0000019b76daa418096630314a385a510a582f7b226132612e73657276696365506172616d6574657273223a7b224132412d56657273696f6e223a22312e30227d7d"
	if got := hex.EncodeToString(b); got != wantWire {
		t.Fatalf("chat message wire\n got  %s\n want %s", got, wantWire)
	}
	back, err := delegation.UnmarshalChatMsg(b)
	if err != nil || !reflect.DeepEqual(back, msg) {
		t.Errorf("chat message did not round-trip: %+v, %v", back, err)
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

// VEC-DELEGATE-2: a delegation with every field populated, ContextID (7) and Metadata (8)
// included. Pinned by CID because the object embeds a signed TaskDoc and a KEL; the key set says
// which field went missing when the CID moves.
func TestVEC_DELEGATE_2(t *testing.T) {
	c := identity.SuiteController()
	raw, doc := goldenTaskDoc(t)
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	req := &delegation.DelegateReq{
		TaskDoc: raw, Envelope: doc.Envelope, KEL: kel, InteractionID: "ix-golden-1",
		Attachments: goldenAttachments(t),
		Payment:     []byte(`{"x402Version":2}`),
		ContextID:   "ctx-golden-1",
		Metadata:    []byte(goldenMetadata),
	}
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, "delegation", b, []uint64{1, 2, 3, 4, 5, 6, 7, 8})
	const wantCID = "bafyreife5tknp3dracamid2n2i6es4iog767qx4dxqztcpzpr4jdpacnma"
	if got := anetcid.MustSum(b); got != wantCID {
		t.Errorf("delegation wire CID\n got  %s\n want %s", got, wantCID)
	}
	back, err := delegation.UnmarshalDelegateReq(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.ContextID != req.ContextID || string(back.Metadata) != goldenMetadata {
		t.Errorf("new fields did not round-trip: %+v", back)
	}
	// The vector is also a valid delegation under the wire-2 verifier.
	if _, _, _, err := delegation.VerifyDelegateReqWithKEL(back, c.KEL(), 1767225600000); err != nil {
		t.Errorf("the golden delegation must verify: %v", err)
	}
}

// VEC-RESULT-2: a completion with every field populated, Metadata (5) included.
func TestVEC_RESULT_2(t *testing.T) {
	c := identity.SuiteController()
	deliverable := []byte(`{"ok":true}`)
	rc := goldenReceipt()
	cid, err := anetcid.Sum(deliverable)
	if err != nil {
		t.Fatal(err)
	}
	rc.ResultCID = cid // bound to the deliverable, so the vector also verifies
	if err := rc.Sign(c); err != nil {
		t.Fatal(err)
	}
	receipt, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	rr := &delegation.ResultResp{
		Status: delegation.StatusDone, Deliverable: deliverable, Receipt: receipt, KEL: kel,
		Metadata: []byte(goldenMetadata),
	}
	b, err := rr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, "result", b, []uint64{1, 2, 3, 4, 5})
	const wantCID = "bafyreihskdzrcgvwfcisk7fx2h7yfrh6kzdigtcf6wkypx2lqgjaexd64m"
	if got := anetcid.MustSum(b); got != wantCID {
		t.Errorf("result payload CID\n got  %s\n want %s", got, wantCID)
	}
	back, err := delegation.UnmarshalResultResp(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(back.Metadata) != goldenMetadata {
		t.Errorf("metadata did not round-trip: %q", back.Metadata)
	}
	if _, err := delegation.VerifyResultWithKEL(back, c.KEL(), rc.InteractionID, rc.RequesterAID,
		rc.ProviderAID, rc.CompletedAt); err != nil {
		t.Errorf("the golden completion must verify: %v", err)
	}
}

// VEC-STATUS-1: the anet.status/1 body, every field populated.
func TestVEC_STATUS_1(t *testing.T) {
	m := &delegation.StatusMsg{
		State:    delegation.StateInputRequired,
		Text:     "need the source file",
		Metadata: []byte(goldenMetadata),
		At:       1767225600000,
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, "status", b, []uint64{1, 2, 3, 4})
	// Cross-checked against the same independent encoder as VEC-CHATMSG-2.
	const wantWire = "a4016e696e7075742d726571756972656402746e6565642074686520736f757263652066696c6503582f7b226132612e73657276696365506172616d6574657273223a7b224132412d56657273696f6e223a22312e30227d7d041b0000019b76daa800"
	if got := hex.EncodeToString(b); got != wantWire {
		t.Fatalf("status wire\n got  %s\n want %s", got, wantWire)
	}
	back, err := delegation.UnmarshalStatusMsg(b)
	if err != nil || !reflect.DeepEqual(back, m) {
		t.Errorf("status did not round-trip: %+v, %v", back, err)
	}
}

// VEC-RELAYAUTH-2: a complete relay v2 authentication, preimage and header value.
//
// The daemon signs and the hub verifies; the two never exchange the preimage, only the signature,
// so a difference in any part of PreimageV2 (a separator, the digest alphabet, the padding, the
// order of method, target and body) shows up at the hub as an invalid signature from a valid key.
// Both expected values below were computed outside this module (Python hashlib, base64 and the
// cryptography package's Ed25519, from the published suite seed), not by the code under test.
func TestVEC_RELAYAUTH_2(t *testing.T) {
	const ts = 1767225600000
	pre := relayauth.PreimageV2(relayauth.ActionPoll, suiteAID, "bafyreigoldenhub", ts,
		"POST", "/relay/poll", []byte(`{"limit":50}`))
	const wantPre = "anet-relay/v2/poll/" + suiteAID + "/bafyreigoldenhub/1767225600000/" +
		"zLJEMi0-k4mBELamLpchUkYojTc9mrNK0RdGNm5raX8"
	if string(pre) != wantPre {
		t.Fatalf("relay v2 preimage\n got  %s\n want %s", pre, wantPre)
	}
	c := identity.SuiteController()
	sig, seq := c.Sign(pre)
	const wantSig = "PZ-Fe93H14oafwaoaGB1wge7kZQJSHylMPmyAjx94dqWjuOAEVBIl2ULwQ7cjzb59r56Pi_XQ5Rr2RyPyQgsBA"
	if got := relayauth.EncodeSig(sig); got != wantSig {
		t.Errorf("%s value\n got  %s\n want %s", relayauth.HeaderSig, got, wantSig)
	}
	back, err := relayauth.DecodeSig(wantSig)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.VerifyObject(c.KEL(), suiteAID, seq, ts, pre, back); err != nil {
		t.Errorf("the pinned signature must verify against the suite KEL: %v", err)
	}
}
