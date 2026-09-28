// Package delegation defines the payloads that ride the Hub relay for a task delegation, plus the
// verification a provider runs before storing a task and a requester runs before accepting a result.
//
//	DelegateReq — a SIGNED TaskDoc (the request) with its detached Envelope and the signer's KEL inline,
//	              so the provider can verify the signature without any shared registry, and the
//	              requester-chosen InteractionID both sides key the interaction by.
//	ResultResp  — the completion: status + the deliverable bytes + the provider-signed Receipt.
//	ChatMsg     — a conversation message within an interaction.
//	StatusMsg   — a provider's task-state update (anet.status/1, A2A-DESIGN §3.4).
//
// All are CoreDet-CBOR and travel as opaque relay payloads; the Hub never decodes them. Verification is
// end-to-end (VerifyDelegateReqWithKEL for the request and VerifyResultForRequest for the receipt, each
// against a KEL the receiver resolved; VerifyResultWithKEL is the latter without the request binding,
// and the older VerifyDelegateReq and VerifyResult read the KEL from the body), so the centralized
// relay moves bytes it cannot forge.
package delegation

import (
	"errors"
	"fmt"
	"time"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/tsir"
)

// Delegation status values shared on the wire (ResultResp.Status + the interactions store).
const (
	StatusQueued = "queued" // stored; the external agent has not produced a result yet
	StatusDone   = "done"   // deliverable present
	StatusFailed = "failed" // the provider marked the task failed
)

// DelegateReq is the relayed delegation payload. The TaskDoc bytes (coredet) exclude the detached
// Envelope (tsir taskdoc cbor:"-"), so the Envelope rides alongside; the signer's KEL rides inline so the
// provider verifies self-contained.
type DelegateReq struct {
	TaskDoc  []byte         `cbor:"1,keyasint"`
	Envelope *aobj.Envelope `cbor:"2,keyasint"`
	// KEL is the requester's KEL as the requester states it. VerifyDelegateReqWithKEL does not check
	// the signature against it; it only requires it to be absent, equal to, or a prefix of the KEL
	// the receiver resolved.
	KEL           []byte `cbor:"3,keyasint"`
	InteractionID string `cbor:"4,keyasint"`
	// Attachments ride alongside the initial delegation (e.g. reference material the requester hands the
	// provider up front). Like KEL/Envelope they are transport, NOT part of the signed TaskDoc/request
	// CID; each attachment is self-verified by its own content CID.
	Attachments []Attachment `cbor:"5,keyasint,omitempty"`
	// Payment is an x402 PaymentPayload (JSON), when this delegation is
	// paying for itself.
	//
	// Beside the TaskDoc rather than inside it, because the TaskDoc is
	// what the request CID covers and what the receipt anchors: a task is
	// the same task whether or not it was paid for, and folding the
	// payment in would make an unpaid retry of the identical work a
	// different request.
	Payment []byte `cbor:"6,keyasint,omitempty"`

	// ContextID is the A2A contextId the requester groups this task under (A2A-DESIGN §3.4). Like
	// Payment it is outside the signed TaskDoc, so it does not change the request CID. Under wire 2
	// the whole DelegateReq is the body of a sealed anet.delegate/1 envelope, and the envelope's
	// inner signature is what authenticates this field.
	ContextID string `cbor:"7,keyasint,omitempty"`
	// Metadata is a JSON object carried as raw bytes (A2A Message.metadata, including the reserved
	// keys listed in A2A-DESIGN §3.4 and the x402.payment.* keys). This package does not parse it.
	// Outside the TaskDoc for the same reason as ContextID.
	Metadata []byte `cbor:"8,keyasint,omitempty"`
}

// Attachment is a binary payload (image, media, archive/zip of a folder…) carried inline alongside a
// chat or delegation message so agents can exchange non-text deliverables. The bytes travel over the
// relay; integrity is pinned by CID = anetcid.SumRaw(Data), which the receiver re-checks and which is
// recorded (metadata only) in the receipt-bound transcript. Data is omitted once an attachment is stored
// and only its metadata is being moved.
type Attachment struct {
	Name string `cbor:"1,keyasint"`           // suggested filename, e.g. "screenshot.png" / "project.zip"
	Mime string `cbor:"2,keyasint,omitempty"` // media type, e.g. "image/png", "application/zip"
	Size int64  `cbor:"3,keyasint"`           // raw byte length (== len(Data) when present)
	CID  string `cbor:"4,keyasint"`           // content id: anetcid.SumRaw(Data)
	Data []byte `cbor:"5,keyasint,omitempty"` // inline bytes (v0.1: inline transport, bounded by relay caps)
}

// Marshal encodes a DelegateReq for the relay.
func (r *DelegateReq) Marshal() ([]byte, error) { return coredet.Marshal(*r) }

// UnmarshalDelegateReq decodes a relayed DelegateReq.
func UnmarshalDelegateReq(b []byte) (*DelegateReq, error) {
	var r DelegateReq
	if err := coredet.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ResultResp is the relayed completion payload: Status is queued/done/failed; when done, Deliverable and
// the provider-signed Receipt (evidence.Receipt.Marshal) are present.
type ResultResp struct {
	Status      string `cbor:"1,keyasint"`
	Deliverable []byte `cbor:"2,keyasint,omitempty"`
	Receipt     []byte `cbor:"3,keyasint,omitempty"`
	// KEL is the provider's key history, so the requester can verify the
	// receipt without asking anyone.
	//
	// A delegation has carried the requester's KEL inline since v0.1 — that
	// is how a provider verifies a stranger self-contained. The answer did
	// not carry the provider's, so the requester held a signed receipt and
	// no key to check it against. It could not verify what it was accepting
	// even in principle, and did not try.
	//
	// Absent from an older provider. A receipt that cannot be verified is
	// then recorded as unverified rather than treated as good: not knowing
	// and knowing-it-is-fine are different states, and a completion is
	// exactly where collapsing them is worst.
	KEL []byte `cbor:"4,keyasint,omitempty"`

	// Metadata is a JSON object carried as raw bytes (A2A-DESIGN §3.4), for example the anet.*
	// effect and receipt status keys that must reach the requester unchanged. Not covered by the
	// receipt; under wire 2 the sealed envelope's inner signature authenticates it.
	Metadata []byte `cbor:"5,keyasint,omitempty"`
}

// Marshal encodes a ResultResp for the relay.
func (r *ResultResp) Marshal() ([]byte, error) { return coredet.Marshal(*r) }

// UnmarshalResultResp decodes a relayed ResultResp.
func UnmarshalResultResp(b []byte) (*ResultResp, error) {
	var r ResultResp
	if err := coredet.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Chat message kinds (v0.1 multi-turn conversation). "text" is an ordinary message; end_request /
// end_accept are the two-step "wrap up this task" negotiation (mutual accept ⇒ the provider issues the
// signed Receipt over the transcript, after which the requester can review).
const (
	ChatText       = "text"
	ChatEndRequest = "end_request"
	// ChatEndAccept was the second step of the end negotiation.
	//
	// Deprecated: from ANetCore v0.15.0 (A2A-DESIGN §3.4) the provider completes a text task on its
	// own and accepts an end_request automatically, so senders must not emit end_accept; receivers
	// drop it. Kept so wire-1 code builds.
	ChatEndAccept = "end_accept"
	// KindCancel asks the peer to cancel the interaction (A2A CancelTask). Whether the provider
	// honors it depends on the task state; once a payment has been submitted it does not
	// (A2A-DESIGN §4.2). A task that is canceled produces no receipt.
	KindCancel = "cancel"
	// ChatStreamPreview is an ephemeral, replace-in-place snapshot of a
	// streaming reply. Receivers keep it in memory only; it is never a
	// conversation message and never participates in a receipt.
	ChatStreamPreview = "stream_preview"
)

// ChatMsg is a relayed conversation message for an ongoing interaction (RelayKindMessage). Unlike the
// delegation/result payloads it is NOT signed — chat is conversational and the Hub is trusted as the
// relay; the signed, Hub-verified trust anchor remains the end-of-task Receipt + Review. The interaction
// id rides in the relay envelope, so only the kind + body travel here.
//
// Under wire 2 (A2A-DESIGN §3.3) a ChatMsg is the body of a sealed anet.message/1 envelope. The
// struct itself still carries no signature; the envelope's inner signature covers its bytes and the
// hub no longer sees them.
type ChatMsg struct {
	Kind        string       `cbor:"1,keyasint"`
	Body        string       `cbor:"2,keyasint,omitempty"`
	Attachments []Attachment `cbor:"3,keyasint,omitempty"`

	// Streaming fields, for a reply that is still being written.
	//
	// These are why this package is here. There were two copies of this
	// struct — one in the daemon, one in the hub — and the hub's grew these
	// four fields and the stream_preview kind while the daemon's stayed at
	// three.
	//
	// Nothing had gone wrong yet: the fields were declared on the hub's copy
	// and wired to nothing, so no preview was ever sent. What existed was a
	// loaded gun. The first hub to actually stream would have reached a
	// daemon that decodes keys 1-3, finds keys 4-7 simply absent — CBOR
	// keyasint drops an unknown key without a word — and then discards the
	// whole message on an unrecognised kind. The sender would see a
	// successful send, the receiver would show nothing until the reply
	// finished, and no log on either side would say why.
	//
	// A wire type that lives in two repositories is a wire type that will
	// diverge, and this one already had. One copy, in the module both sides
	// already depend on.
	StreamSeq           uint64 `cbor:"4,keyasint,omitempty"`
	StreamAtMS          int64  `cbor:"5,keyasint,omitempty"`
	ReasoningBody       string `cbor:"6,keyasint,omitempty"`
	ReasoningStreamAtMS int64  `cbor:"7,keyasint,omitempty"`

	// MsgID identifies this message, so a receiver can tell a redelivery
	// from a repetition.
	//
	// Relay delivery is at-least-once by construction: a message is acked
	// only after it has been handled, because acking first would lose work
	// on a crash, and the price of that order is a redelivery whenever a
	// node dies in between. The delegation and result paths can dedupe on
	// the interaction id — there is one of each per interaction — but a
	// conversation has many messages and "same body from the same peer" is
	// not the same thing as "the message I already stored": people repeat
	// themselves, and an agent saying "ok" twice means it twice.
	//
	// The sender mints it, because the sender is the only party present on
	// every path. The hub's mailbox row id would have served for hub
	// relay and does not exist over p2p, and a receiver cannot invent one
	// without inventing exactly the ambiguity this removes.
	MsgID string `cbor:"9,keyasint,omitempty"`

	// Metadata is a JSON object carried as raw bytes (A2A Message.metadata; reserved keys in
	// A2A-DESIGN §3.4). This package does not parse it.
	//
	// Key 10, not 8: key 8 has never been assigned in this struct and its absence is not recorded
	// anywhere, so the new field takes the key after the highest one in use rather than filling a
	// gap whose history cannot be checked. Key 8 stays unassigned.
	Metadata []byte `cbor:"10,keyasint,omitempty"`
}

// Marshal encodes a ChatMsg for the relay.
func (m *ChatMsg) Marshal() ([]byte, error) { return coredet.Marshal(*m) }

// UnmarshalChatMsg decodes a relayed ChatMsg.
func UnmarshalChatMsg(b []byte) (*ChatMsg, error) {
	var m ChatMsg
	if err := coredet.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// VerifyDelegateReq verifies a relayed delegation before it is stored: the inline KEL must validly sign
// the TaskDoc (identity binding via td.Verify — a forged KEL cannot impersonate an AID; msgTime=now
// accepts only a currently-valid, non-revoked key). It returns the accountable requester AID (the
// verified signer), the decoded TaskDoc, and the exact signed TaskDoc bytes (the request CID anchor).
//
// Deprecated: the KEL is taken from the request body, so the sender chooses the key history its
// own signature is checked against, and the revocation gate is evaluated at the verifier's clock
// rather than at the message time. Wire-2 receivers use VerifyDelegateReqWithKEL with the KEL
// resolved from the sealed envelope and the peer record (A2A-DESIGN §3.6 step 6, C4d).
func VerifyDelegateReq(r *DelegateReq) (requesterAID string, td *tsir.TaskDoc, taskDocBytes []byte, err error) {
	doc, err := decodeDelegateReq(r)
	if err != nil {
		return "", nil, nil, err
	}
	kel, err := identity.UnmarshalKEL(r.KEL)
	if err != nil {
		return "", nil, nil, fmt.Errorf("delegation: bad KEL: %w", err)
	}
	return verifyTaskDoc(r, doc, kel, uint64(time.Now().UnixMilli()))
}

// VerifyDelegateReqWithKEL verifies a delegation against a KEL the caller resolved itself
// (A2A-DESIGN §3.4, §3.6 step 6 and the nested-object rule after the step table; review items C4b
// and C4d). kel is the requester's KEL as resolved from the sealed envelope and the stored peer
// record; msgTime is the envelope's inner ts, in unix milliseconds, and drives the revocation gate
// (0 selects the conservative rule in identity.VerifyObject).
//
// The body's own KEL field is never used to check the signature. When it is present it must be
// equal to kel or a prefix of it (identity.ExtendsKEL); otherwise the request is refused, because a
// body KEL that forks from or runs ahead of the resolved one means the sender's two statements of
// its key history disagree. An empty body KEL is accepted.
//
// identity.VerifyObject requires kel's AID to equal the envelope's SignerAID, so when kel was
// resolved for the authenticated sender the returned requester AID is that sender.
func VerifyDelegateReqWithKEL(r *DelegateReq, kel []identity.SignedEvent, msgTime uint64) (requesterAID string, td *tsir.TaskDoc, taskDocBytes []byte, err error) {
	doc, err := decodeDelegateReq(r)
	if err != nil {
		return "", nil, nil, err
	}
	if len(kel) == 0 {
		return "", nil, nil, errors.New("delegation: no resolved requester KEL")
	}
	if err := checkBodyKEL(r.KEL, kel); err != nil {
		return "", nil, nil, err
	}
	return verifyTaskDoc(r, doc, kel, msgTime)
}

// decodeDelegateReq performs the structural checks shared by both delegation verifiers, in the
// order the original VerifyDelegateReq performed them.
func decodeDelegateReq(r *DelegateReq) (*tsir.TaskDoc, error) {
	if r == nil || r.Envelope == nil {
		return nil, fmt.Errorf("delegation: missing envelope")
	}
	if r.InteractionID == "" {
		return nil, fmt.Errorf("delegation: missing interaction id")
	}
	var doc tsir.TaskDoc
	if coredet.Unmarshal(r.TaskDoc, &doc) != nil || len(doc.Tasks) == 0 {
		return nil, fmt.Errorf("delegation: undecodable or task-less TaskDoc")
	}
	return &doc, nil
}

func verifyTaskDoc(r *DelegateReq, doc *tsir.TaskDoc, kel []identity.SignedEvent, msgTime uint64) (string, *tsir.TaskDoc, []byte, error) {
	doc.Envelope = r.Envelope
	if err := doc.Verify(kel, msgTime); err != nil {
		return "", nil, nil, fmt.Errorf("delegation: TaskDoc signature invalid: %w", err)
	}
	return r.Envelope.SignerAID, doc, r.TaskDoc, nil
}

// ErrBodyKELMismatch is returned by the *WithKEL verifiers when the KEL carried in the body is
// neither equal to nor a prefix of the resolved KEL. It wraps the identity.ExtendsKEL error, so
// errors.Is also matches identity.ErrKELFork or identity.ErrKELRollback.
var ErrBodyKELMismatch = errors.New("delegation: body KEL is not a prefix of the resolved KEL")

// checkBodyKEL applies the body-KEL rule of the *WithKEL verifiers: absent is accepted; present must
// decode and be a prefix of (or equal to) the resolved KEL.
func checkBodyKEL(body []byte, resolved []identity.SignedEvent) error {
	if len(body) == 0 {
		return nil
	}
	bodyKEL, err := identity.UnmarshalKEL(body)
	if err != nil {
		return fmt.Errorf("delegation: bad body KEL: %w", err)
	}
	if err := identity.ExtendsKEL(bodyKEL, resolved); err != nil {
		return fmt.Errorf("%w: %w", ErrBodyKELMismatch, err)
	}
	return nil
}

// VerifiedKEL returns the requester's key history from a DelegateReq whose
// signature has already been checked.
//
// Separate from VerifyDelegateReq on purpose: this returns a key history
// that is only trustworthy because verification passed, and a caller that
// reaches for it without having verified is making a mistake the signature
// should have caught.
//
// Deprecated: pairs only with VerifyDelegateReq, which checks the signature against this same
// body KEL. After VerifyDelegateReqWithKEL the signature was checked against the caller's resolved
// KEL; the body KEL is then absent or a prefix of it, so storing the value returned here as the
// peer's KEL can replace a longer stored history with an older one (the rollback
// identity.ExtendsKEL refuses). Wire-2 callers keep the resolved KEL they passed in.
func VerifiedKEL(r *DelegateReq) ([]identity.SignedEvent, error) {
	return identity.UnmarshalKEL(r.KEL)
}

// TaskGoal extracts the human-readable goal from a TaskDoc's first task (Body preferred, else Summary).
func TaskGoal(td *tsir.TaskDoc) string {
	if td == nil || len(td.Tasks) == 0 {
		return ""
	}
	if b := td.Tasks[0].Intent.Body; b != "" {
		return b
	}
	return td.Tasks[0].Intent.Summary
}

// ErrUnverifiable is returned when a completion carries no key history, so
// its receipt cannot be checked at all. Distinct from a failed check: an
// older provider produces this, a lying one produces an error.
// VerifyResultWithKEL returns it (wrapped) when the caller supplies no KEL.
var ErrUnverifiable = errors.New("delegation: completion carries no provider KEL")

// VerifyResult checks that a completion is the signed answer to the request
// it claims to answer.
//
// The signature alone proves far less than it looks like it proves. It says
// some provider signed some receipt — not that the receipt belongs to this
// interaction, that it names us as the requester, or that it covers the
// bytes actually delivered. A provider could return one result and a valid
// receipt for a different one, and a caller checking only the signature
// would accept it. So every field the receipt asserts is bound here to
// something the caller already knows, and ResultCID is bound to the
// deliverable's own hash.
//
// now is the time the receipt is judged against for key revocation; pass 0
// to fall back to the conservative rule in identity.VerifyObject.
//
// Deprecated: the provider KEL is taken from the completion body, so the provider chooses the key
// history its own receipt is checked against. Wire-2 receivers use VerifyResultWithKEL with the KEL
// resolved from the sealed envelope and the peer record (A2A-DESIGN §3.4, C4d).
func VerifyResult(r *ResultResp, interactionID, requesterAID, providerAID string, now uint64) (*evidence.Receipt, error) {
	if r == nil || len(r.Receipt) == 0 {
		return nil, fmt.Errorf("delegation: completion carries no receipt")
	}
	if len(r.KEL) == 0 {
		return nil, ErrUnverifiable
	}
	rc, err := evidence.UnmarshalReceipt(r.Receipt)
	if err != nil {
		return nil, fmt.Errorf("delegation: undecodable receipt: %w", err)
	}
	kel, err := identity.UnmarshalKEL(r.KEL)
	if err != nil {
		return nil, fmt.Errorf("delegation: bad provider KEL: %w", err)
	}
	return bindReceipt(rc, r.Deliverable, kel, interactionID, requesterAID, providerAID, "", now)
}

// VerifyResultWithKEL is VerifyResult with the provider KEL supplied by the caller (A2A-DESIGN
// §3.4, §3.6; review items C4b and C4d). kel is the provider's KEL as resolved from the sealed
// envelope and the stored peer record; msgTime is the envelope's inner ts in unix milliseconds
// (0 selects the conservative rule in identity.VerifyObject). The receipt bindings are the same as
// VerifyResult's: signer, provider, requester, interaction and deliverable hash.
//
// The body's KEL field is never used to check the receipt. When present it must be equal to kel or
// a prefix of it, else the completion is refused with ErrBodyKELMismatch. An empty kel yields an
// error wrapping ErrUnverifiable: the receipt was not checked, which is a different state from a
// receipt that failed the check.
//
// It does not bind the receipt's RequestCID. A requester that holds the request it sent uses
// VerifyResultForRequest.
func VerifyResultWithKEL(r *ResultResp, kel []identity.SignedEvent, interactionID, requesterAID, providerAID string, msgTime uint64) (*evidence.Receipt, error) {
	return VerifyResultForRequest(r, kel, interactionID, requesterAID, providerAID, "", msgTime)
}

// ErrRequestMismatch is returned when a receipt names a request other than the one the caller
// sent.
var ErrRequestMismatch = errors.New("delegation: receipt is for another request")

// VerifyResultForRequest is VerifyResultWithKEL that also binds the receipt's RequestCID to
// requestCID, the CID of the request (TaskDoc) bytes the requester sent (anetcid.Sum over them).
// An empty requestCID skips that one binding, as for the other identifiers.
//
// Without it a provider can sign a receipt that names a request never made — the CID of any
// bytes it likes — for the result it delivered. The receipt verifies, the requester reviews the
// work, and a third party checking the pair with evidence.VerifyInterlock against those bytes is
// shown the requester vouching for a request it never sent, while the request it did send no
// longer matches. A mismatch is ErrRequestMismatch.
func VerifyResultForRequest(r *ResultResp, kel []identity.SignedEvent, interactionID, requesterAID, providerAID, requestCID string, msgTime uint64) (*evidence.Receipt, error) {
	if r == nil || len(r.Receipt) == 0 {
		return nil, fmt.Errorf("delegation: completion carries no receipt")
	}
	if len(kel) == 0 {
		return nil, fmt.Errorf("%w (no resolved provider KEL supplied)", ErrUnverifiable)
	}
	rc, err := evidence.UnmarshalReceipt(r.Receipt)
	if err != nil {
		return nil, fmt.Errorf("delegation: undecodable receipt: %w", err)
	}
	if err := checkBodyKEL(r.KEL, kel); err != nil {
		return nil, err
	}
	return bindReceipt(rc, r.Deliverable, kel, interactionID, requesterAID, providerAID, requestCID, msgTime)
}

// bindReceipt verifies the receipt signature against kel at msgTime and binds each field the
// receipt asserts to what the caller knows. An empty interactionID, requesterAID, providerAID or
// requestCID skips that one binding.
func bindReceipt(rc *evidence.Receipt, deliverable []byte, kel []identity.SignedEvent, interactionID, requesterAID, providerAID, requestCID string, msgTime uint64) (*evidence.Receipt, error) {
	if err := rc.Verify(kel, msgTime); err != nil {
		return nil, fmt.Errorf("delegation: receipt signature invalid: %w", err)
	}
	if providerAID != "" && rc.ProviderAID != providerAID {
		return nil, fmt.Errorf("delegation: receipt signed by %s, but the task went to %s",
			rc.ProviderAID, providerAID)
	}
	if requesterAID != "" && rc.RequesterAID != requesterAID {
		return nil, fmt.Errorf("delegation: receipt names %s as requester, not us", rc.RequesterAID)
	}
	if interactionID != "" && rc.InteractionID != interactionID {
		return nil, fmt.Errorf("delegation: receipt is for interaction %s, not %s",
			rc.InteractionID, interactionID)
	}
	if requestCID != "" && rc.RequestCID != requestCID {
		return nil, fmt.Errorf("%w: it names %s, the request sent was %s", ErrRequestMismatch,
			rc.RequestCID, requestCID)
	}
	// The binding that makes the rest worth having: the signature must cover
	// the bytes that actually arrived.
	cid, err := anetcid.Sum(deliverable)
	if err != nil {
		return nil, err
	}
	if rc.ResultCID != cid {
		return nil, fmt.Errorf("delegation: receipt covers %s but the deliverable hashes to %s",
			rc.ResultCID, cid)
	}
	return rc, nil
}
