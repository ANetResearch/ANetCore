package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
)

// Witness notices (KEL §2.5, core §2.6, L18).
//
// An agent's witness hub is the hub its KEL tip names (key 9 of its last rot). The hub signs, for
// each agent it witnesses, a notice that states the tip of the KEL it holds: the AID, the tip's
// seq and event id, and when the hub observed it. A sender carries its latest notice in every
// message (inner key 11), and a recipient accepts the message only when the notice is fresh, is
// about the tip of the KEL the message carries, and is signed by the hub that tip names
// (VerifyNotice). A thief holding an old key can therefore impersonate the sender only for as long
// as a notice the witness signed before the rotation stays fresh: NoticeMaxAge.
//
// On the wire a notice is NoticeWire: the body as a byte string (coredet(NoticeBody), CORE-E2) and
// the hub's aobj signature envelope. User-facing text calls this "key confirmation".

// NoticeType is key 0 of every NoticeBody (core §2.6, L18).
const NoticeType = "anet.ksn/1"

// NoticeMaxAge is how old a witness notice may be when the message carrying it arrives (KEL §2.12):
// observed_at at most this long before the arrival time, in unix ms. It is not configurable.
const NoticeMaxAge uint64 = 6 * 60 * 60 * 1000

// NoticeBody is what a witness hub states about an agent's KEL (core §2.6): the KEL it holds for
// aid ends at seq with event head, as observed at observed_at by the hub witness. Its CoreDet
// encoding is what the hub signs.
//
//anet:wire NoticeBody
type NoticeBody struct {
	Type       string `cbor:"0,keyasint"` // NoticeType
	AID        string `cbor:"1,keyasint"` // the agent the notice is about
	Seq        uint64 `cbor:"2,keyasint"` // seq of the tip of the KEL the witness holds
	Head       string `cbor:"3,keyasint"` // event id of that tip
	ObservedAt uint64 `cbor:"4,keyasint"` // the witness hub's clock, unix ms
	Witness    string `cbor:"5,keyasint"` // AID of the witness hub that signs
}

// NoticeWire is a notice as it travels (core §2.6): in inner key 11, in a directory entry, in a hub
// answer.
//
//anet:wire NoticeWire
type NoticeWire struct {
	Body []byte        `cbor:"1,keyasint"` // coredet(NoticeBody)
	Env  aobj.Envelope `cbor:"2,keyasint"` // the witness hub's signature over Body; signer_aid is Body's witness
}

// HubKELSource gives the KEL this node holds for a hub, by the hub's AID (KEL C-50): for a daemon,
// the federation hub KEL set it keeps in step with its own hub (KEL D-24). ok is false when it
// holds none. VerifyNotice calls it while it judges a message, so it reads what is held and never
// goes to the network.
type HubKELSource func(hubAID string) (kel []SignedEvent, ok bool)

// The ways VerifyNotice refuses a notice, one for each of its steps (KEL C-51). seal.CheckNotice
// reports each under the seal reason of the same meaning (C-56): ErrNoticeMissing as
// witness-missing, ErrNoticeInvalid as witness-invalid, ErrNoticeMismatch as witness-mismatch,
// ErrNoticeUnknownWitness as witness-unknown and ErrNoticeStale as witness-stale. VerifyNotice
// wraps them with what failed; test them with errors.Is.
var (
	// ErrNoticeInvalid is a notice that does not decode as a NoticeWire of an "anet.ksn/1" body in
	// CoreDet form, whose signer is not the hub the KEL tip names, or whose signature does not
	// verify under that hub's KEL (steps 1, 4 and 5).
	ErrNoticeInvalid = errors.New("identity: the witness notice is not valid")
	// ErrNoticeMissing is a KEL no notice can confirm: a hub's (toad 0), or an agent's whose
	// witness is still pending (only an icp, R-4) (step 2).
	ErrNoticeMissing = errors.New("identity: the KEL names no witness, so no witness notice confirms it")
	// ErrNoticeMismatch is a notice about another AID, seq or event than the tip of the KEL it is
	// checked against (step 3).
	ErrNoticeMismatch = errors.New("identity: the witness notice is about another key state than the KEL's tip")
	// ErrNoticeUnknownWitness is a notice signed under a key state of its witness hub that this
	// node does not know: no KEL for the hub, or one that ends before the notice's seq (step 5). It
	// is not final: the caller refreshes the hub's KEL once and asks again (KEL D-24).
	ErrNoticeUnknownWitness = errors.New("identity: this node does not hold the witness hub's KEL as far as the notice's key state")
	// ErrNoticeStale is a notice observed more than NoticeMaxAge before the arrival time, or more
	// than EventClockWindow after it (step 6).
	ErrNoticeStale = errors.New("identity: the witness notice is not fresh")
)

func noticeError(kind error, format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{kind}, args...)...)
}

// DecodeNotice decodes a notice as it travels, the NoticeWire bytes, and returns its body and its
// signature envelope (KEL C-51 step 1). It checks the encoding alone: strict decoding (no key a
// NoticeWire, NoticeBody or aobj envelope does not define), each of the two maps in its CoreDet
// form, key 0 of the body "anet.ksn/1", no preimage reference in the envelope (the body is the
// preimage), alg EdDSA and a 64-byte signature. It verifies nothing else: VerifyNotice does. Every
// error is ErrNoticeInvalid.
func DecodeNotice(b []byte) (NoticeBody, aobj.Envelope, error) {
	w, body, err := decodeNotice(b)
	if err != nil {
		return NoticeBody{}, aobj.Envelope{}, err
	}
	return body, w.Env, nil
}

func decodeNotice(b []byte) (NoticeWire, NoticeBody, error) {
	var w NoticeWire
	if err := coredet.UnmarshalStrict(b, &w); err != nil {
		return NoticeWire{}, NoticeBody{}, noticeError(ErrNoticeInvalid, "it does not decode: %v", err)
	}
	if back, err := coredet.Marshal(w); err != nil || !bytes.Equal(back, b) {
		return NoticeWire{}, NoticeBody{}, noticeError(ErrNoticeInvalid, "it is not in its CoreDet form")
	}
	if w.Env.PreimageRef != "" {
		return NoticeWire{}, NoticeBody{}, noticeError(ErrNoticeInvalid, "its signature names a preimage reference; a notice's preimage is its body")
	}
	if err := w.Env.Validate(); err != nil {
		return NoticeWire{}, NoticeBody{}, noticeError(ErrNoticeInvalid, "its signature is not an EdDSA signature of %d bytes", ed25519.SignatureSize)
	}
	var body NoticeBody
	if err := coredet.UnmarshalStrict(w.Body, &body); err != nil {
		return NoticeWire{}, NoticeBody{}, noticeError(ErrNoticeInvalid, "its body does not decode: %v", err)
	}
	if back, err := coredet.Marshal(body); err != nil || !bytes.Equal(back, w.Body) {
		return NoticeWire{}, NoticeBody{}, noticeError(ErrNoticeInvalid, "its body is not in its CoreDet form")
	}
	if body.Type != NoticeType {
		return NoticeWire{}, NoticeBody{}, noticeError(ErrNoticeInvalid, "its body is of type %q, not %q", body.Type, NoticeType)
	}
	return w, body, nil
}

// VerifyNotice decides whether notice b confirms the tip of subjectKEL, a message arriving at
// arrival (unix ms; KEL D-20) (KEL C-51). It checks, in this order:
//
//  1. b decodes (DecodeNotice); else ErrNoticeInvalid;
//  2. the tip of subjectKEL has toad 1 and names a witness; else ErrNoticeMissing;
//  3. the notice's aid, seq and head are the tip's AID, seq and event id; else ErrNoticeMismatch;
//  4. its witness is the witness the tip names, and its signer is that witness; else
//     ErrNoticeInvalid;
//  5. hubKELs holds the witness's KEL, as far as the notice's key_state_seq (else
//     ErrNoticeUnknownWitness), and under that KEL — a hub's, toad 0 — the signature verifies
//     with VerifyObject at msgTime = observed_at, and a key state since retired is still usable at
//     arrival (RetiredUsableAt); else ErrNoticeInvalid;
//  6. observed_at is at most EventClockWindow after arrival and at most NoticeMaxAge before it;
//     else ErrNoticeStale.
//
// subjectKEL is the KEL the message carries, not the KEL the receiver holds after merging it
// (KEL D-21): a message sealed before a planned rotation carries the KEL and the notice of its
// time, and stays acceptable within the rotation grace. When subjectKEL does not replay, the error
// is the replay's, none of the five above.
func VerifyNotice(b []byte, subjectKEL []SignedEvent, hubKELs HubKELSource, arrival uint64) error {
	// Step 1.
	w, body, err := decodeNotice(b)
	if err != nil {
		return err
	}
	// Step 2.
	states, err := Replay(subjectKEL)
	if err != nil {
		return fmt.Errorf("identity: the KEL the notice is checked against does not replay: %w", err)
	}
	tip := states[len(states)-1]
	switch {
	case tip.Toad != ToadAgent:
		return noticeError(ErrNoticeMissing, "the KEL is a hub's (toad %d), which has no witness", tip.Toad)
	case tip.Witness == "":
		return noticeError(ErrNoticeMissing, "the KEL has not named its witness yet")
	}
	// Step 3.
	switch {
	case body.AID != tip.AID:
		return noticeError(ErrNoticeMismatch, "the notice is about %s, the KEL is %s's", body.AID, tip.AID)
	case body.Seq != tip.KeyStateSeq || body.Head != tip.LastEventID:
		return noticeError(ErrNoticeMismatch, "the notice states seq %d (%s), the KEL's tip is seq %d (%s)",
			body.Seq, body.Head, tip.KeyStateSeq, tip.LastEventID)
	}
	// Step 4.
	switch {
	case body.Witness != tip.Witness:
		return noticeError(ErrNoticeInvalid, "the notice is from %s, the KEL names %s as its witness", body.Witness, tip.Witness)
	case w.Env.SignerAID != body.Witness:
		return noticeError(ErrNoticeInvalid, "the notice is signed as %s, not as its witness %s", w.Env.SignerAID, body.Witness)
	}
	// Step 5.
	var wkel []SignedEvent
	ok := false
	if hubKELs != nil {
		wkel, ok = hubKELs(body.Witness)
	}
	switch {
	case !ok || len(wkel) == 0:
		return noticeError(ErrNoticeUnknownWitness, "no KEL is held for the witness hub %s", body.Witness)
	case w.Env.KeyStateSeq >= uint64(len(wkel)):
		return noticeError(ErrNoticeUnknownWitness, "the KEL held for the witness hub %s ends at seq %d; the notice is signed at seq %d",
			body.Witness, len(wkel)-1, w.Env.KeyStateSeq)
	}
	wstates, err := Replay(wkel)
	if err != nil {
		return noticeError(ErrNoticeInvalid, "the KEL held for the witness hub does not replay: %v", err)
	}
	if t := wstates[len(wstates)-1].Toad; t != ToadHub {
		return noticeError(ErrNoticeInvalid, "the witness %s is not a hub (toad %d)", body.Witness, t)
	}
	if err := VerifyObject(wkel, body.Witness, w.Env.KeyStateSeq, body.ObservedAt, w.Body, w.Env.Sig); err != nil {
		return noticeError(ErrNoticeInvalid, "the witness hub's signature: %v", err)
	}
	if ws := wstates[w.Env.KeyStateSeq]; ws.Status != StatusActive && !RetiredUsableAt(ws, arrival) {
		return noticeError(ErrNoticeInvalid, "the witness hub's key state %d was retired at %d, before the arrival at %d",
			ws.KeyStateSeq, ws.SupersededAt, arrival)
	}
	// Step 6.
	switch {
	case body.ObservedAt > arrival && body.ObservedAt-arrival > EventClockWindow:
		return noticeError(ErrNoticeStale, "observed at %d, %d ms after the arrival at %d", body.ObservedAt, body.ObservedAt-arrival, arrival)
	case arrival > body.ObservedAt && arrival-body.ObservedAt > NoticeMaxAge:
		return noticeError(ErrNoticeStale, "observed at %d, %d ms before the arrival at %d", body.ObservedAt, arrival-body.ObservedAt, arrival)
	}
	return nil
}

// SignNotice signs body as the witness hub s and returns the notice as it travels,
// coredet(NoticeWire) (KEL C-50). s must be a hub identity (toad 0). Type and Witness may be left
// empty; they are filled with NoticeType and s's AID, and any other value is refused. body.AID
// must be an AID, Head non-empty and ObservedAt the hub's clock (> 0).
//
// The signature is made under one key state of s (SnapshotOf), which the envelope names.
func SignNotice(s Signer, body NoticeBody) ([]byte, error) {
	if s == nil {
		return nil, errors.New("identity: no signer for the notice")
	}
	s = SnapshotOf(s)
	kel := s.KEL()
	if len(kel) == 0 {
		return nil, errors.New("identity: the notice signer has no KEL")
	}
	if t := kel[0].Event.Toad; t == nil || *t != ToadHub {
		return nil, errors.New("identity: only a hub identity (toad 0) signs witness notices")
	}
	switch {
	case body.Type == "":
		body.Type = NoticeType
	case body.Type != NoticeType:
		return nil, fmt.Errorf("identity: a notice body is of type %q; %q is not", NoticeType, body.Type)
	}
	switch {
	case body.Witness == "":
		body.Witness = s.AID()
	case body.Witness != s.AID():
		return nil, fmt.Errorf("identity: the notice names witness %s; it is signed by %s", body.Witness, s.AID())
	}
	switch {
	case !ValidAID(body.AID):
		return nil, fmt.Errorf("identity: a notice is about an AID; %q is not one", body.AID)
	case body.Head == "":
		return nil, errors.New("identity: a notice names the event id of the KEL's tip")
	case body.ObservedAt == 0:
		return nil, errors.New("identity: a notice needs the time the witness observed the tip (observed_at > 0)")
	}
	pre, err := coredet.Marshal(body)
	if err != nil {
		return nil, err
	}
	seq, err := SeqOf(s)
	if err != nil {
		return nil, err
	}
	sig, signed := s.Sign(pre)
	if signed != seq {
		return nil, ErrSignerSeq
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, errors.New("identity: the notice signer holds no key")
	}
	return coredet.Marshal(NoticeWire{Body: pre, Env: aobj.Envelope{SignerAID: s.AID(), KeyStateSeq: seq, Alg: aobj.AlgEdDSA, Sig: sig}})
}

// MergedEmergency reports whether next, a peer's KEL as this node holds it after a merge, adds to
// old, the KEL it held before, an emergency rot (key 12) (KEL D-44). The merge goes through
// ExtendsKEL, so next is old with events appended; only those appended count. When it is true the
// caller, in the transaction of the merge, drops the capabilities that peer issued and revokes
// those issued to it (engine ENG-K4). A planned rot does not count, nor does a dip: a deactivated
// peer's messages are refused anyway (SenderKeyUsable).
func MergedEmergency(old, next []SignedEvent) bool {
	for i := len(old); i < len(next); i++ {
		if e := next[i].Event; e.Type == Rotation && e.Emergency {
			return true
		}
	}
	return false
}
