// wire_test.go pins the daemon↔Hub wire objects.
//
// These are the newest vectors and the ones with the most recent scar.
// delegation, evidence and relayauth were duplicated in two repositories
// until v0.5.x, and delegation had already drifted 28 lines apart — the
// Hub's ChatMsg had four fields and a message kind the daemon's did not.
// Neither side could detect it, because CBOR keyasint drops an unknown key
// without a word.
//
// One copy in one module fixes that for these two implementations. It does
// nothing for a third, in another language, written against the spec —
// and a wire whose only definition is one Go struct is a wire with no
// specification at all. These vectors are the specification's teeth:
// byte-for-byte agreement, reproducible from published seeds, with no key
// material to exchange and no network to reach.
package golden

import (
	"encoding/hex"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/delegation"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/relayauth"
)

// The frozen conformance identity every signed vector below is anchored
// to. An AID is the CID of its inception event, so this one number
// decides every id downstream: if it moves, nothing else here can match.
const suiteAID = "bafyreicg3paeuo2nt4n575adgnovtr2y7aizti7643fxhk6zbmiaaa7q7y"

func TestVEC_SUITE_IDENTITY_1(t *testing.T) {
	c := identity.SuiteController()
	if c.AID() != suiteAID {
		t.Fatalf("the conformance identity moved\n got  %s\n want %s\n"+
			"Every vector in this file is anchored to it.", c.AID(), suiteAID)
	}
	// It must also be a valid KEL, not just a stable string: a vector
	// signed by an identity that does not replay proves nothing.
	if _, err := identity.Replay(c.KEL()); err != nil {
		t.Fatalf("the conformance identity does not replay: %v", err)
	}
}

func goldenReceipt() *evidence.Receipt {
	return &evidence.Receipt{
		InteractionID: "ix-golden-1",
		RequesterAID:  "did:anet:golden-requester",
		ProviderAID:   suiteAID,
		RequestCID:    "bafyreigoldenrequest",
		ResultCID:     "bafyreigoldenresult",
		CompletedAt:   1767225600000,
	}
}

// VEC-RECEIPT-1: the provider-signed completion proof.
//
// The preimage is pinned as well as the CID because they fail differently.
// A changed CID says something moved; the preimage hex says which byte.
func TestVEC_RECEIPT_1(t *testing.T) {
	rc := goldenReceipt()
	pre, err := rc.CanonicalPreimage()
	if err != nil {
		t.Fatal(err)
	}
	const wantPre = "a6016b69782d676f6c64656e2d310278196469643a616e65743a676f6c64656e2d72657175657374657203783b62616679726569636733706165756f326e74346e3537356164676e6f76747232793761697a7469373634336678686b367a626d6961616137713779047462616679726569676f6c64656e72657175657374057362616679726569676f6c64656e726573756c74061b0000019b76daa800"
	if got := hex.EncodeToString(pre); got != wantPre {
		t.Errorf("receipt preimage\n got  %s\n want %s", got, wantPre)
	}
	const wantCID = "bafyreigtf7cdis7ixmicflpcjguilxuw4swic74dd23vkqqsidbuxp56oe"
	cid, err := rc.CID()
	if err != nil {
		t.Fatal(err)
	}
	if cid != wantCID {
		t.Errorf("receipt CID\n got  %s\n want %s", cid, wantCID)
	}
}

// VEC-RECEIPT-WIRE-1: the receipt as it actually travels, signature and all.
//
// Separate from the preimage vector, and this is the one that would have
// caught a bug the org credential shipped with: Envelope is cbor:"-", so
// marshalling the object alone silently drops the signature and every
// receipt arrives unsigned. The preimage vector cannot see that — the
// envelope is not in the preimage, by design. Only the wire form can.
func TestVEC_RECEIPT_WIRE_1(t *testing.T) {
	rc := goldenReceipt()
	c := identity.SuiteController()
	if err := rc.Sign(c); err != nil {
		t.Fatal(err)
	}
	const wantSig = "91b2908254fd9433af6c340f07d9738a9405411e08079f8e5e3b7652fed57b46" +
		"cd2e4e896632f77c6a583902ed3e7e1b277dafba5fa6edf2f7de07a6fb792803"
	if got := hex.EncodeToString(rc.Envelope.Sig); got != wantSig {
		t.Errorf("receipt signature\n got  %s\n want %s", got, wantSig)
	}
	wire, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	const wantWireCID = "bafyreicnprz7t2vftqpmivnss3eif4jwpeo6tusxugeo3atthwuak3y5vi"
	if got := anetcid.MustSum(wire); got != wantWireCID {
		t.Errorf("receipt wire CID\n got  %s\n want %s", got, wantWireCID)
	}
	// And it must survive the round trip carrying its signature.
	back, err := evidence.UnmarshalReceipt(wire)
	if err != nil {
		t.Fatal(err)
	}
	if back.Envelope == nil {
		t.Fatal("the signature did not survive the wire — every receipt would arrive unsigned")
	}
	if err := back.Verify(c.KEL(), rc.CompletedAt); err != nil {
		t.Errorf("the round-tripped receipt must still verify: %v", err)
	}
}

// VEC-REVIEW-1: the requester-signed rating, anchored to a receipt CID.
func TestVEC_REVIEW_1(t *testing.T) {
	rv := &evidence.Review{
		InteractionID: "ix-golden-1",
		ReviewerAID:   "did:anet:golden-requester",
		SubjectAID:    suiteAID,
		ReceiptCID:    "bafyreigtf7cdis7ixmicflpcjguilxuw4swic74dd23vkqqsidbuxp56oe",
		Rating:        5,
		Comment:       "golden",
		CreatedAt:     1767225600000,
	}
	pre, err := rv.CanonicalPreimage()
	if err != nil {
		t.Fatal(err)
	}
	const wantPre = "a7016b69782d676f6c64656e2d3102783b62616679726569636733706165756f326e74346e3537356164676e6f76747232793761697a7469373634336678686b367a626d69616161377137790378196469643a616e65743a676f6c64656e2d72657175657374657204050566676f6c64656e06783b6261667972656967746637636469733769786d6963666c70636a6775696c7875773473776963373464643233766b71717369646275787035366f65071b0000019b76daa800"
	if got := hex.EncodeToString(pre); got != wantPre {
		t.Errorf("review preimage\n got  %s\n want %s", got, wantPre)
	}
	const wantCID = "bafyreifgduxrtwuxzawpoq4wymaygk6joaqjrhewow3y6e4rw7grtuwfqm"
	if got := anetcid.MustSum(pre); got != wantCID {
		t.Errorf("review CID\n got  %s\n want %s", got, wantCID)
	}
}

// VEC-CHATMSG-1: every field of the message type that drifted.
//
// All seven keys populated on purpose. The drift was keys 4-7 existing on
// one side and not the other, which is exactly the shape a vector over a
// partially-filled object would have missed.
func TestVEC_CHATMSG_1(t *testing.T) {
	msg := &delegation.ChatMsg{
		Kind: delegation.ChatStreamPreview, Body: "partial",
		StreamSeq: 7, StreamAtMS: 1767225600000,
		ReasoningBody: "thinking", ReasoningStreamAtMS: 1767225599000,
	}
	b, err := msg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	const wantWire = "a6016e73747265616d5f7072657669657702677061727469616c0407051b0000019b76daa80006687468696e6b696e67071b0000019b76daa418"
	if got := hex.EncodeToString(b); got != wantWire {
		t.Fatalf("chat message wire\n got  %s\n want %s\n"+
			"An implementation that disagrees here drops fields silently.", got, wantWire)
	}
}

// VEC-RESULT-1: the completion payload carrying deliverable and receipt.
func TestVEC_RESULT_1(t *testing.T) {
	rc := goldenReceipt()
	if err := rc.Sign(identity.SuiteController()); err != nil {
		t.Fatal(err)
	}
	receipt, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	rr := &delegation.ResultResp{
		Status: delegation.StatusDone, Deliverable: []byte(`{"ok":true}`), Receipt: receipt,
	}
	b, err := rr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	const wantCID = "bafyreifwa7c3gid5su4oxvpxujwkxf4hoykd73yyvqifshajck4e4ss2nu"
	if got := anetcid.MustSum(b); got != wantCID {
		t.Errorf("result payload CID\n got  %s\n want %s", got, wantCID)
	}
}

// VEC-RELAYAUTH-1: the exact bytes a client signs to open its mailbox.
//
// Not CBOR — a plain octet string two implementations build independently
// and never exchange. It was duplicated in two repositories with nothing
// holding the copies together; this is the third party's copy.
func TestVEC_RELAYAUTH_1(t *testing.T) {
	got := string(relayauth.Preimage(relayauth.ActionPoll, suiteAID, 1767225600000))
	const want = "anet-relay/poll/" + suiteAID + "/1767225600000"
	if got != want {
		t.Fatalf("relay challenge\n got  %s\n want %s", got, want)
	}
}

// VEC-PAYMENT-AUTH-1: what a payer signs when they agree to pay.
//
// The newest wire and the one that decides who owes whom, so it is pinned
// hardest. A capability id that drifts costs a lookup; an authorization
// preimage that drifts means one implementation charging an amount
// another implementation did not agree to.
func TestVEC_PAYMENT_AUTH_1(t *testing.T) {
	a := goldenAuthorization()
	pre, err := a.CanonicalPreimage()
	if err != nil {
		t.Fatal(err)
	}
	const wantPre = "a801600278186469643a616e65743a676f6c64656e2d70726f7669646572031904e204776875623a6469643a616e65743a676f6c64656e2d687562056c676f6c64656e2d6e6f6e6365061b0000019b76daa800071b0000019b76df3be0086b69782d676f6c64656e2d31"
	if got := hex.EncodeToString(pre); got != wantPre {
		t.Errorf("authorization preimage\n got  %s\n want %s", got, wantPre)
	}
	// The id is the facilitator's idempotency key: two implementations
	// that disagree about it will settle the same payment twice.
	const wantID = "bafyreiaoua3g6ex7ltybwopp4pvxlvfhp6k5zxwlrnlb4vlv3iw3apgoy4"
	id, err := a.ID()
	if err != nil {
		t.Fatal(err)
	}
	if id != wantID {
		t.Errorf("authorization id\n got  %s\n want %s", id, wantID)
	}
}

// VEC-PAYMENT-AUTH-WIRE-1: the authorization as it travels, signature
// included — the envelope is detached, so the preimage vector above is
// blind to whether the signature ships at all.
func TestVEC_PAYMENT_AUTH_WIRE_1(t *testing.T) {
	a := goldenAuthorization()
	c := identity.SuiteController()
	if err := a.Sign(c); err != nil {
		t.Fatal(err)
	}
	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	const wantCID = "bafyreib4i3wlycc7bxgvgmt67ealkdhyjyc76xo6n7neu56kdlreknwms4"
	if got := anetcid.MustSum(b); got != wantCID {
		t.Errorf("authorization wire CID\n got  %s\n want %s", got, wantCID)
	}
	back, err := payment.UnmarshalAuthorization(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.Envelope == nil {
		t.Fatal("the signature did not travel — every authorization would arrive unsigned")
	}
	if err := back.Verify(c.KEL(), a.IssuedAt+1000); err != nil {
		t.Errorf("the round-tripped authorization must verify: %v", err)
	}
}

// VEC-PAYMENT-RECEIPT-1: what a hub signs when it settles. Two hubs
// clearing against each other read this from one another, so a drift here
// is one hub crediting its users against a statement the other did not
// make.
func TestVEC_PAYMENT_RECEIPT_1(t *testing.T) {
	r := &payment.Receipt{
		AuthID:   "bafyreiaoua3g6ex7ltybwopp4pvxlvfhp6k5zxwlrnlb4vlv3iw3apgoy4",
		Payer:    suiteAID,
		PayTo:    "did:anet:golden-provider",
		Amount:   1250,
		Network:  payment.CreditNetwork("did:anet:golden-hub"),
		SettleAt: 1767225700000,
	}
	pre, err := r.CanonicalPreimage()
	if err != nil {
		t.Fatal(err)
	}
	const wantCID = "bafyreideclcgxvtpf3vjkeljp2ewkkejo5hmvuz6xpg7pyz7y3j3l6zoma"
	if got := anetcid.MustSum(pre); got != wantCID {
		t.Errorf("settlement receipt CID\n got  %s\n want %s", got, wantCID)
	}
}

func goldenAuthorization() *payment.Authorization {
	return &payment.Authorization{
		Payer:         "",
		PayTo:         "did:anet:golden-provider",
		Amount:        1250,
		Network:       payment.CreditNetwork("did:anet:golden-hub"),
		Nonce:         "golden-nonce",
		IssuedAt:      1767225600000,
		NotAfter:      1767225900000,
		InteractionID: "ix-golden-1",
	}
}
