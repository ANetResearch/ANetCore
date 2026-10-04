// Package delegation defines the payloads that ride the Hub relay for a task delegation, plus the
// verification a provider runs before storing a task and a requester runs before accepting a result.
//
//	DelegateReq — a SIGNED TaskDoc (the request) with its detached Envelope, and the
//	              requester-chosen InteractionID both sides key the interaction by. The TaskDoc's
//	              first task carries the task binding (binding.go).
//	ResultResp  — the completion: status + the deliverable bytes + the provider-signed receipt
//	              (evidence v2), and for a text task the provider's final reply (ReplyMsg).
//	ChatMsg     — a conversation message within an interaction, or a preview frame.
//	StatusMsg   — a provider's task-state update (anet.status/1, A2A-DESIGN §3.4).
//	CardGet,
//	CardResp    — the extended card request and answer (card.go).
//
// All are CoreDet-CBOR and travel as the body of a sealed envelope; the Hub never decodes them.
// Each body decodes with one rule (core §0.2, CORE-E2 and CORE-E4): a key the object does not
// assign is refused, and the bytes must be the one canonical encoding of what they decode to. A
// body that fails is ErrBody. Verification is end-to-end (VerifyDelegateReqWithKEL for the
// request and VerifyResultForRequest for the receipt, each against a KEL the receiver resolved
// from the sealed envelope), so the centralized relay moves bytes it cannot forge.
package delegation

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/tsir"
)

// Delegation status values shared on the wire (ResultResp.Status + the interactions store).
const (
	StatusQueued = "queued" // stored; the external agent has not produced a result yet (never on the wire)
	StatusDone   = "done"   // deliverable present
	StatusFailed = "failed" // the provider marked the task failed
)

// ErrBody is wrapped by every refusal of the body decoders (UnmarshalDelegateReq,
// UnmarshalResultResp, UnmarshalChatMsg, UnmarshalStatusMsg) and of ValidatePreview and
// ValidateReply: the bytes are not one of the shapes core §2.4.2 allows. A receiver drops such a
// message as bad-body; the error text says what is wrong with it.
var ErrBody = errors.New("delegation: not a well-formed body")

func bodyErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrBody}, args...)...)
}

// decodeBody decodes b into v, a pointer to a body struct, with the one rule every body follows:
//
//   - strictly (CORE-E4): a key the object does not assign — unregistered, reserved or retired,
//     at the top or in a nested object — is refused, never dropped;
//   - canonically (CORE-E2): b must be coredet of what it decodes to. A null in place of an
//     absent field, an explicit empty value, a second encoding of the same value or trailing
//     bytes are all refused, so a field is present exactly when it holds a value.
func decodeBody(what string, b []byte, v any) error {
	if err := coredet.UnmarshalStrict(b, v); err != nil {
		var unknown *cbor.UnknownFieldError
		if errors.As(err, &unknown) {
			return bodyErr("the %s carries a key it does not assign (%v)", what, err)
		}
		return bodyErr("the %s does not decode: %v", what, err)
	}
	back, err := coredet.Marshal(v)
	if err != nil || !bytes.Equal(back, b) {
		return bodyErr("the %s is not in its one canonical encoding", what)
	}
	return nil
}

// DelegateReq is the body of anet.delegate/1 (core §2.4.2). The TaskDoc bytes (coredet) exclude
// the detached Envelope (tsir taskdoc cbor:"-"), so the Envelope rides alongside.
//
// Key 3 is retired (it was the requester's KEL: the KEL travels only in inner key 10, where the
// seal layer checks it) and key 6 is retired (it was the prepayment the hub's gateway removal took
// with it; core G6). Neither is ever assigned again; a body that carries either is refused.
//
//anet:wire DelegateReq
type DelegateReq struct {
	TaskDoc  []byte         `cbor:"1,keyasint"`
	Envelope *aobj.Envelope `cbor:"2,keyasint"`
	// InteractionID must equal the inner ix of the envelope that carries the request.
	InteractionID string `cbor:"4,keyasint"`
	// Attachments ride alongside the initial delegation (e.g. reference material the requester hands the
	// provider up front). Like the Envelope they are transport, NOT part of the signed TaskDoc/request
	// CID; each attachment is self-verified by its own content CID. Their order is the order of the
	// $files of a capability call's args (CUX §2.5).
	Attachments []Attachment `cbor:"5,keyasint,omitempty"`

	// ContextID is the A2A contextId the requester groups this task under (A2A-DESIGN §3.4). It is
	// outside the signed TaskDoc, so it does not change the request CID; the envelope's inner
	// signature is what authenticates it.
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
//
//anet:wire Attachment
type Attachment struct {
	Name string `cbor:"1,keyasint"`           // suggested filename, e.g. "screenshot.png" / "project.zip"
	Mime string `cbor:"2,keyasint,omitempty"` // media type, e.g. "image/png", "application/zip"
	Size int64  `cbor:"3,keyasint"`           // raw byte length (== len(Data) when present)
	CID  string `cbor:"4,keyasint"`           // content id: anetcid.SumRaw(Data)
	Data []byte `cbor:"5,keyasint,omitempty"` // inline bytes (bounded by the relay's envelope cap)
}

// Marshal encodes a DelegateReq for the relay.
func (r *DelegateReq) Marshal() ([]byte, error) { return coredet.Marshal(*r) }

// UnmarshalDelegateReq decodes the body of an anet.delegate/1 and the TaskDoc inside it.
//
// The body decodes by the body rule (decodeBody); it must carry a TaskDoc, its Envelope and an
// interaction id. The TaskDoc decodes by the same rule (CORE-E3, CORE-E4; CORE-E2 for a signed
// object carried as bytes): a key no TaskDoc object assigns, at any depth, is refused, and the
// bytes must be the canonical encoding of the TaskDoc, so the request CID taken over them has
// one value per request. A TaskDoc without tasks asks for nothing and is refused too. Every
// refusal is ErrBody.
//
// The signature is not checked here; VerifyDelegateReqWithKEL does that against the KEL the
// receiver resolved.
func UnmarshalDelegateReq(b []byte) (*DelegateReq, error) {
	var r DelegateReq
	if err := decodeBody("delegation", b, &r); err != nil {
		return nil, err
	}
	switch {
	case len(r.TaskDoc) == 0:
		return nil, bodyErr("the delegation carries no TaskDoc")
	case r.Envelope == nil:
		return nil, bodyErr("the delegation carries no TaskDoc signature (missing envelope)")
	case r.InteractionID == "":
		return nil, bodyErr("the delegation names no interaction (missing interaction id)")
	}
	if _, err := decodeTaskDoc(r.TaskDoc); err != nil {
		return nil, err
	}
	return &r, nil
}

// decodeTaskDoc decodes the TaskDoc bytes of a delegation by the body rule and requires a task.
func decodeTaskDoc(b []byte) (*tsir.TaskDoc, error) {
	var doc tsir.TaskDoc
	if err := decodeBody("TaskDoc", b, &doc); err != nil {
		return nil, fmt.Errorf("%w (undecodable or task-less TaskDoc)", err)
	}
	if len(doc.Tasks) == 0 {
		return nil, bodyErr("undecodable or task-less TaskDoc: it has no task")
	}
	return &doc, nil
}

// ResultResp is the body of anet.result/1 (core §2.4.2): Status is done or failed; when done,
// Deliverable and the provider-signed receipt (an evidence.ReceiptWire) are present. Key 4 is
// retired (it was the provider's KEL, which travels only in inner key 10).
//
//anet:wire ResultResp
type ResultResp struct {
	Status      string `cbor:"1,keyasint"`
	Deliverable []byte `cbor:"2,keyasint,omitempty"`
	Receipt     []byte `cbor:"3,keyasint,omitempty"`

	// Metadata is a JSON object carried as raw bytes (A2A-DESIGN §3.4), for example the anet.*
	// effect and receipt status keys that must reach the requester unchanged. Not covered by the
	// receipt; the sealed envelope's inner signature authenticates it.
	Metadata []byte `cbor:"5,keyasint,omitempty"`

	// Reply is the provider's final reply to a text task, folded into the result so the requester
	// gets the completion and the answer in one message (CUX-R1 to R3). Only a done result may
	// carry it, and only for a text task: a capability task's result with a reply is refused by
	// the requester (it knows the task's kind; this package does not). It must be the last
	// provider entry of the transcript the receipt covers (CUX-R2, checked by the requester).
	Reply *ReplyMsg `cbor:"6,keyasint,omitempty"`
}

// ReplyMsg is ResultResp key 6 (core §2.4.2): the subset of ChatMsg a final reply is, keys 1, 2,
// 3 and 9 with the same meaning. Kind is always "text" and MsgID is required; any other key is
// refused when the result decodes (CUX-R3).
//
//anet:wire ReplyMsg
type ReplyMsg struct {
	Kind        string       `cbor:"1,keyasint"`
	Body        string       `cbor:"2,keyasint,omitempty"`
	Attachments []Attachment `cbor:"3,keyasint,omitempty"`
	// MsgID is the message id of the transcript entry the reply is (ChatMsg key 9).
	MsgID string `cbor:"9,keyasint"`
}

// Marshal encodes a ResultResp for the relay.
func (r *ResultResp) Marshal() ([]byte, error) { return coredet.Marshal(*r) }

// UnmarshalResultResp decodes the body of an anet.result/1 by the body rule (decodeBody). Status
// is done or failed (queued never travels); a reply is carried only by a done result and must
// pass ValidateReply. Every refusal is ErrBody.
func UnmarshalResultResp(b []byte) (*ResultResp, error) {
	var r ResultResp
	if err := decodeBody("result", b, &r); err != nil {
		return nil, err
	}
	switch r.Status {
	case StatusDone, StatusFailed:
	default:
		return nil, bodyErr("result status %q is neither %q nor %q", r.Status, StatusDone, StatusFailed)
	}
	if r.Reply != nil {
		if r.Status != StatusDone {
			return nil, bodyErr("a %s result carries a reply; only a %s result may", r.Status, StatusDone)
		}
		if err := ValidateReply(r.Reply); err != nil {
			return nil, err
		}
	}
	return &r, nil
}

// ValidateReply checks a final reply (CUX-R3): kind "text", a message id, and a body that is
// valid UTF-8. Its key set is fixed by its type: a reply with any key besides 1, 2, 3 and 9 does
// not decode. It does no I/O. The requester's check that the reply is the transcript's last
// provider entry (CUX-R2) needs the transcript and is the daemon's.
func ValidateReply(r *ReplyMsg) error {
	switch {
	case r == nil:
		return bodyErr("no reply")
	case r.Kind != ChatText:
		return bodyErr("a reply's kind is %q, not %q", r.Kind, ChatText)
	case r.MsgID == "":
		return bodyErr("a reply carries no message id (key 9)")
	case !utf8.ValidString(r.Body):
		return bodyErr("a reply's body is not valid UTF-8")
	}
	return nil
}

// Chat message kinds. The set is closed: a ChatMsg of any other kind is refused when it decodes.
// "end_accept", the second step of the 0.1 end negotiation, is retired (the provider completes a
// text task on its own and accepts an end_request automatically) and is refused like any unknown
// kind.
const (
	ChatText       = "text"
	ChatEndRequest = "end_request"
	// KindCancel asks the peer to cancel the interaction (A2A CancelTask). Whether the provider
	// honors it depends on the task state; once a payment has been submitted it does not
	// (A2A-DESIGN §4.2). A task that is canceled produces no receipt.
	KindCancel = "cancel"
	// ChatStreamPreview is an ephemeral, replace-in-place snapshot of a streaming reply: a
	// preview frame (CUX §2.3). Receivers keep it in memory only; it is never a conversation
	// message and never participates in a receipt. ValidatePreview checks one.
	ChatStreamPreview = "stream_preview"
)

// MaxPreviewTail bounds each of a preview frame's two tail windows, the body (key 2) and the
// reasoning (key 6), in bytes (CUX-P1, CUX-P2).
const MaxPreviewTail = 8192

// ChatMsg is the body of anet.message/1 (core §2.4.2): a conversation message for an ongoing
// interaction, or a preview frame (kind stream_preview). It carries no signature of its own: the
// sealed envelope's inner signature covers its bytes, and the hub never sees them.
//
// Keys 4-7 and 11-13 belong to preview frames only (CORE-K6); a message of another kind that
// carries any of them is refused when it decodes. Key 8 has never been assigned and never will be.
//
//anet:wire ChatMsg
type ChatMsg struct {
	Kind        string       `cbor:"1,keyasint"`
	Body        string       `cbor:"2,keyasint,omitempty"`
	Attachments []Attachment `cbor:"3,keyasint,omitempty"`

	// Preview fields (kind stream_preview only): Body is then the tail of the reply being
	// written, at most MaxPreviewTail bytes, and ReasoningBody the tail of the reasoning.
	//
	// The struct exists in this package because there were once two copies of it, one in the
	// daemon and one in the hub, and the hub's grew these fields while the daemon's did not: a
	// lax CBOR decoder drops an unknown key without a word, so a preview would have arrived
	// empty and been discarded with no log on either side. One copy in the module both sides
	// depend on, decoded strictly, so a key one side does not know is refused, never dropped.
	StreamSeq           uint64 `cbor:"4,keyasint,omitempty"` // strictly increasing within the interaction; never 0
	StreamAtMS          int64  `cbor:"5,keyasint,omitempty"` // when Body was taken, unix ms
	ReasoningBody       string `cbor:"6,keyasint,omitempty"`
	ReasoningStreamAtMS int64  `cbor:"7,keyasint,omitempty"` // when ReasoningBody was taken, unix ms

	// MsgID identifies this message, so a receiver can tell a redelivery from a repetition.
	//
	// Relay delivery is at-least-once by construction: a message is acked only after it has been
	// handled, because acking first would lose work on a crash, and the price of that order is a
	// redelivery whenever a node dies in between. A conversation has many messages, and "same
	// body from the same peer" is not "the message I already stored": people repeat themselves,
	// and an agent saying "ok" twice means it twice. The sender mints it, because the sender is
	// the only party present on every path.
	//
	// In a preview frame it is a random value for log correlation only, and required.
	MsgID string `cbor:"9,keyasint,omitempty"`

	// Metadata is a JSON object carried as raw bytes (A2A Message.metadata; reserved keys in
	// A2A-DESIGN §3.4). This package does not parse it. Never in a preview frame.
	Metadata []byte `cbor:"10,keyasint,omitempty"`

	// Omitted and ReasoningOmitted are the number of bytes before Body and ReasoningBody that the
	// preview frame leaves out (CUX-P1); 0 is not written.
	Omitted          uint64 `cbor:"11,keyasint,omitempty"`
	ReasoningOmitted uint64 `cbor:"12,keyasint,omitempty"`
	// Answers is the message id of the requester message this preview frame answers (CUX-P1):
	// the receiver shows a frame only while that message is the latest (CUX-P14). Required in a
	// preview frame.
	Answers string `cbor:"13,keyasint,omitempty"`
}

// Marshal encodes a ChatMsg for the relay.
func (m *ChatMsg) Marshal() ([]byte, error) { return coredet.Marshal(*m) }

// UnmarshalChatMsg decodes the body of an anet.message/1 by the body rule (decodeBody). The kind
// is one of ChatText, ChatEndRequest, KindCancel and ChatStreamPreview, and a message that is not
// a preview frame carries none of the preview keys 4-7 and 11-13 (CORE-K6). A preview frame is
// checked further by ValidatePreview. Every refusal is ErrBody.
func UnmarshalChatMsg(b []byte) (*ChatMsg, error) {
	var m ChatMsg
	if err := decodeBody("message", b, &m); err != nil {
		return nil, err
	}
	switch m.Kind {
	case ChatText, ChatEndRequest, KindCancel, ChatStreamPreview:
	case "end_accept":
		return nil, bodyErr("message kind %q is retired: the provider completes a text task on its own", m.Kind)
	default:
		return nil, bodyErr("message kind %q is not one of %s, %s, %s, %s", m.Kind, ChatText, ChatEndRequest, KindCancel, ChatStreamPreview)
	}
	if m.Kind != ChatStreamPreview {
		if k := m.previewKey(); k != 0 {
			return nil, bodyErr("a %s message carries key %d, which only a preview frame may carry", m.Kind, k)
		}
	}
	return &m, nil
}

// previewKey returns the lowest of the preview-only keys 4-7, 11-13 that m carries, or 0.
func (m *ChatMsg) previewKey() int {
	switch {
	case m.StreamSeq != 0:
		return 4
	case m.StreamAtMS != 0:
		return 5
	case m.ReasoningBody != "":
		return 6
	case m.ReasoningStreamAtMS != 0:
		return 7
	case m.Omitted != 0:
		return 11
	case m.ReasoningOmitted != 0:
		return 12
	case m.Answers != "":
		return 13
	}
	return 0
}

// ValidatePreview checks a preview frame (CUX-P2) and does no I/O. It refuses a message that is
// not a preview frame, and a frame that:
//
//   - carries attachments (key 3) or metadata (key 10);
//   - has a body (key 2) or reasoning (key 6) over MaxPreviewTail bytes, or not valid UTF-8;
//   - lacks stream_seq (key 4; 0 is no value), stream_at_ms (key 5), msg_id (key 9) or answers
//     (key 13).
//
// Whether the frame is shown — the interaction, the message it answers, its order — is the
// receiver's decision (CUX-P14), not this function's.
func ValidatePreview(m *ChatMsg) error {
	switch {
	case m == nil:
		return bodyErr("no preview frame")
	case m.Kind != ChatStreamPreview:
		return bodyErr("a %s message is not a preview frame", m.Kind)
	case len(m.Attachments) > 0:
		return bodyErr("a preview frame carries attachments (key 3)")
	case len(m.Metadata) > 0:
		return bodyErr("a preview frame carries metadata (key 10)")
	}
	for _, f := range []struct {
		key  int
		name string
		text string
	}{{2, "body", m.Body}, {6, "reasoning", m.ReasoningBody}} {
		if len(f.text) > MaxPreviewTail {
			return bodyErr("a preview frame's %s (key %d) is %d bytes, over %d", f.name, f.key, len(f.text), MaxPreviewTail)
		}
		if !utf8.ValidString(f.text) {
			return bodyErr("a preview frame's %s (key %d) is not valid UTF-8", f.name, f.key)
		}
	}
	switch {
	case m.StreamSeq == 0:
		return bodyErr("a preview frame needs a stream_seq above 0 (key 4)")
	case m.StreamAtMS == 0:
		return bodyErr("a preview frame needs stream_at_ms (key 5)")
	case m.MsgID == "":
		return bodyErr("a preview frame needs a msg_id (key 9)")
	case m.Answers == "":
		return bodyErr("a preview frame needs answers, the message it answers (key 13)")
	}
	return nil
}

// VerifyDelegateReqWithKEL verifies a delegation against a KEL the caller resolved itself
// (A2A-DESIGN §3.4, §3.6 step 6 and the nested-object rule after the step table; review items C4b
// and C4d). kel is the requester's KEL as resolved from the sealed envelope and the stored peer
// record; msgTime is the envelope's inner ts, in unix milliseconds, and drives the revocation gate
// (0 selects the conservative rule in identity.VerifyObject). It returns the accountable requester
// AID (the verified signer), the decoded TaskDoc, and the exact signed TaskDoc bytes (the request
// CID anchor).
//
// The TaskDoc decodes as UnmarshalDelegateReq decodes it, so a DelegateReq built in memory is held
// to the same rule as one that arrived.
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
	doc.Envelope = r.Envelope
	if err := doc.Verify(kel, msgTime); err != nil {
		return "", nil, nil, fmt.Errorf("delegation: TaskDoc signature invalid: %w", err)
	}
	return r.Envelope.SignerAID, doc, r.TaskDoc, nil
}

// decodeDelegateReq performs the structural checks of VerifyDelegateReqWithKEL.
func decodeDelegateReq(r *DelegateReq) (*tsir.TaskDoc, error) {
	if r == nil || r.Envelope == nil {
		return nil, fmt.Errorf("delegation: missing envelope")
	}
	if r.InteractionID == "" {
		return nil, fmt.Errorf("delegation: missing interaction id")
	}
	return decodeTaskDoc(r.TaskDoc)
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

// ErrUnverifiable is returned when the caller supplies no provider KEL, so the receipt could not be
// checked at all. Distinct from a failed check: not knowing and knowing-it-is-false are different
// states.
var ErrUnverifiable = errors.New("delegation: no provider KEL to check the receipt against")

// ErrRequestMismatch is returned when a receipt names a request other than the one the caller
// sent.
var ErrRequestMismatch = errors.New("delegation: receipt is for another request")

// ErrReceiptMismatch is returned when a receipt is well signed but is not the receipt for this
// task: another provider, another interaction, another requester or review key, another result,
// or a day outside the task's.
var ErrReceiptMismatch = errors.New("delegation: the receipt is not for this task")

// ResultCheck is what a requester holds about a task it sent; a completion's receipt is checked
// against it (HPP PAY-V8). Every field is required.
type ResultCheck struct {
	// IX is the interaction id.
	IX string
	// Provider is the AID the task went to: the receipt's signer and provider must both be it.
	Provider string
	// TaskDoc is the TaskDoc bytes the requester sent (DelegateReq key 1). Their CID is the
	// request CID the receipt must name, and their task binding gives the ix_commit,
	// requester_commit and review_key it must carry.
	TaskDoc []byte
	// DelegatedDay is the UTC day the delegation was sent, and Today the UTC day now. The receipt's
	// completed_day must lie in DelegatedDay − 1 … Today + 1.
	DelegatedDay uint64
	Today        uint64
}

// VerifyResultForRequest checks that a completion is the signed answer to the request the caller
// sent (HPP PAY-V8) and returns the receipt body.
//
// The signature alone proves less than it looks like. It says some provider signed some receipt —
// not that the receipt belongs to this task, carries the commitments this requester chose, or
// covers the bytes that actually arrived. So every field the receipt asserts is bound to something
// the caller holds:
//
//   - signer == receipt.provider == want.Provider, under kel (the provider's KEL as resolved from
//     the sealed envelope and the stored peer record) at msgTime (the envelope's inner ts, unix
//     ms);
//   - ix_commit == IXCommit(want.IX, the TaskDoc's anet.nonce); requester_commit and review_key
//     equal the TaskDoc's;
//   - request_cid == CID(want.TaskDoc) (ErrRequestMismatch);
//   - result_cid == CID(the deliverable that arrived);
//   - completed_day in want.DelegatedDay − 1 … want.Today + 1.
//
// With no kel the answer is ErrUnverifiable. Any other refusal means the result is refused
// (result-refused, engine §4.5).
func VerifyResultForRequest(r *ResultResp, kel []identity.SignedEvent, want ResultCheck, msgTime uint64) (*evidence.ReceiptBody, error) {
	if r == nil || len(r.Receipt) == 0 {
		return nil, fmt.Errorf("delegation: completion carries no receipt")
	}
	if want.IX == "" || want.Provider == "" || len(want.TaskDoc) == 0 {
		return nil, fmt.Errorf("delegation: the check needs the interaction, the provider and the TaskDoc sent")
	}
	if len(kel) == 0 {
		return nil, fmt.Errorf("%w (no resolved provider KEL supplied)", ErrUnverifiable)
	}
	w, err := evidence.UnmarshalReceiptWire(r.Receipt)
	if err != nil {
		return nil, fmt.Errorf("delegation: undecodable receipt: %w", err)
	}
	rc, err := w.Verify(kel, msgTime)
	if err != nil {
		return nil, fmt.Errorf("delegation: receipt signature invalid: %w", err)
	}
	if rc.Provider != want.Provider {
		return nil, fmt.Errorf("%w: receipt signed by %s, but the task went to %s", ErrReceiptMismatch, rc.Provider, want.Provider)
	}
	var td tsir.TaskDoc
	if err := coredet.Unmarshal(want.TaskDoc, &td); err != nil {
		return nil, fmt.Errorf("delegation: the TaskDoc sent does not decode: %w", err)
	}
	binding, err := ReadTaskBinding(&td)
	if err != nil {
		return nil, fmt.Errorf("delegation: the TaskDoc sent carries no task binding to check the receipt against: %w", err)
	}
	ixc, err := binding.IXCommit(want.IX)
	if err != nil {
		return nil, fmt.Errorf("delegation: ix_commit of %q: %w", want.IX, err)
	}
	switch {
	case !equal32(rc.IXCommit, ixc):
		return nil, fmt.Errorf("%w: its ix_commit is not that of interaction %s", ErrReceiptMismatch, want.IX)
	case !equal32(rc.RequesterCommit, binding.RequesterCommit):
		return nil, fmt.Errorf("%w: its requester_commit is not the one this requester sent", ErrReceiptMismatch)
	case !equal32(rc.ReviewKey, binding.ReviewKey):
		return nil, fmt.Errorf("%w: its review_key is not the one this requester sent", ErrReceiptMismatch)
	}
	requestCID, err := anetcid.Sum(want.TaskDoc)
	if err != nil {
		return nil, err
	}
	if rc.RequestCID != requestCID {
		return nil, fmt.Errorf("%w: it names %s, the request sent was %s", ErrRequestMismatch, rc.RequestCID, requestCID)
	}
	// The binding that makes the rest worth having: the signature must cover the bytes that
	// actually arrived.
	resultCID, err := anetcid.Sum(r.Deliverable)
	if err != nil {
		return nil, err
	}
	if rc.ResultCID != resultCID {
		return nil, fmt.Errorf("%w: receipt covers %s but the deliverable hashes to %s", ErrReceiptMismatch, rc.ResultCID, resultCID)
	}
	if rc.CompletedDay+1 < want.DelegatedDay || rc.CompletedDay > want.Today+1 {
		return nil, fmt.Errorf("%w: completed on day %d, the task ran from day %d to day %d", ErrReceiptMismatch,
			rc.CompletedDay, want.DelegatedDay, want.Today)
	}
	return rc, nil
}
