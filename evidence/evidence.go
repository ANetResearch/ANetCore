// Package evidence defines the evidence v2 objects of anet 0.3.0: the receipt a provider signs when
// it completes a task, the review the requester writes about it, and the attestation a hub signs
// when it stores a review (core §2.9, labels L27–L33).
//
// Version 2 keeps what made the v1 pair worth having — a rating comes from a real counterparty of a
// real interaction, and anyone holding the objects can check that without asking the hub — and
// stops the pair from naming the parties to anyone they show it to:
//
//	ReceiptBody   signed by the PROVIDER's identity key. It names the provider, the request and the
//	              result, and holds three commitments in place of the v1 names: ix_commit (the
//	              interaction, L27), requester_commit (the requester, L28) and review_key (a one-time
//	              public key the requester chose for this task).
//	ReviewBody    signed by the one-time review key, not by the requester's identity. Only the party
//	              that chose the key — the requester — can sign it; nobody shown the review learns
//	              who that was. The hub that stores it checks requester_commit against the uploader.
//	ReviewAttBody signed by the hub that stored the review. Its tag (L31) counts distinct reviewers
//	              per subject without naming them, under a key only that hub holds.
//
// Every signed object travels as {1: body bstr, …}: the body is CoreDet-CBOR with a type tag in key
// 0 (CORE-L1 class A), signed and content-addressed as the exact bytes that travel. Decoders are
// strict (coredet.UnmarshalStrict) and refuse bytes that do not re-encode to themselves (CORE-E2),
// so one object has one byte form whatever path it took.
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// Type tags (key 0) of the three signed bodies (L29, L30, L32).
const (
	ReceiptType   = "anet.receipt/2"
	ReviewType    = "anet.review/2"
	ReviewAttType = "anet.review-att/1"
)

// Sizes and bounds of the fields.
const (
	// CommitSize is the length of ix_commit, requester_commit and a settle guard (SHA-256).
	CommitSize = 32
	// ReviewKeySize is the length of the one-time review public key (Ed25519).
	ReviewKeySize = ed25519.PublicKeySize
	// RSaltSize is the length of the requester's salt in requester_commit (L28).
	RSaltSize = 32
	// TagKeySize is the length of a hub's review tag key (HPP §3.3).
	TagKeySize = 32
	// TagSize is the length of a review tag (L31, HMAC-SHA256 truncated).
	TagSize = 16
	// RatingMin and RatingMax bound a rating (inclusive).
	RatingMin = 1
	RatingMax = 5
	// MaxCommentChars is the longest comment, in Unicode characters (code points).
	MaxCommentChars = 280
	// DayMS is the length of a UTC day in unix milliseconds; day numbers are floor(ms / DayMS)
	// (CORE-E6).
	DayMS = 86_400_000
)

// Errors. Each refusal wraps one of these, so a caller can map it without matching prose: the hub
// answers ErrRating and ErrComment (HPP PAY-V1 step 8) and ErrNUL (a review subject holding
// U+0000, core CORE-E9) with bad_request, and the others with receipt_not_reviewable (PAY-V1).
var (
	// ErrMalformed: the bytes are not the object — they do not decode strictly, do not re-encode to
	// themselves, carry another type tag, or hold a field of the wrong size or form.
	ErrMalformed = errors.New("evidence: not a well-formed evidence object")
	// ErrRating: a review rating outside RatingMin..RatingMax.
	ErrRating = errors.New("evidence: the rating is not between 1 and 5")
	// ErrComment: a review comment longer than MaxCommentChars characters.
	ErrComment = errors.New("evidence: the comment is longer than 280 characters")
	// ErrSigner: the envelope's signer is not the party the body names (the provider of a
	// receipt, the hub of an attestation), or the review's public key is not the receipt's
	// review_key.
	ErrSigner = errors.New("evidence: signed by someone other than the party the object names")
	// ErrSignature: the signature does not verify.
	ErrSignature = errors.New("evidence: the signature does not verify")
	// ErrNUL: a text field of a commitment input holds U+0000 (CORE-E9), or is empty; or a review's
	// subject, an AID, holds U+0000 (CORE-E9 names it: the hub answers bad_request).
	ErrNUL = errors.New("evidence: an AID or commitment input holds U+0000, or a commitment input is empty")
)

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrMalformed}, args...)...)
}

// decodeExact decodes raw into v strictly and requires raw to be exactly the CoreDet encoding of
// what it decoded to (CORE-E2, CORE-E4). v is a pointer to a struct.
func decodeExact(what string, raw []byte, v any) error {
	if len(raw) == 0 {
		return malformed("%s: no bytes", what)
	}
	if err := coredet.UnmarshalStrict(raw, v); err != nil {
		return malformed("%s does not decode: %v", what, err)
	}
	back, err := coredet.Marshal(v)
	if err != nil || !bytes.Equal(back, raw) {
		return malformed("%s is not in its one canonical encoding", what)
	}
	return nil
}

// textField checks a required text field: present and free of U+0000 (CORE-E9).
func textField(what, v string) error {
	if v == "" {
		return malformed("%s is empty", what)
	}
	if strings.IndexByte(v, 0) >= 0 {
		return malformed("%s holds U+0000", what)
	}
	return nil
}

func sizedField(what string, b []byte, n int) error {
	if len(b) != n {
		return malformed("%s is %d bytes, not %d", what, len(b), n)
	}
	return nil
}

func envelopeOf(what string, env *aobj.Envelope) error {
	if env == nil {
		return malformed("%s carries no signature envelope", what)
	}
	if err := env.Validate(); err != nil {
		return malformed("%s: %v", what, err)
	}
	if err := textField(what+" signer", env.SignerAID); err != nil {
		return err
	}
	if env.PreimageRef != "" {
		return malformed("%s: the envelope names a preimage reference; the body travels beside it", what)
	}
	return nil
}

// DayStart returns the first unix millisecond of UTC day day, the time an object dated by day is
// judged at; ok is false when the day does not fit a millisecond count.
func DayStart(day uint64) (ms uint64, ok bool) {
	if day > math.MaxUint64/DayMS {
		return 0, false
	}
	return day * DayMS, true
}

// ---- receipt ----

// ReceiptBody is the provider-signed completion proof of one task (core §2.9). Its CID is the
// receipt_cid a review names (CORE-K12).
//
//anet:wire ReceiptBody
type ReceiptBody struct {
	Type            string `cbor:"0,keyasint"` // ReceiptType
	IXCommit        []byte `cbor:"1,keyasint"` // IXCommit(ix, anet.nonce), 32 bytes (L27)
	RequesterCommit []byte `cbor:"2,keyasint"` // copied from the TaskDoc, 32 bytes (L28)
	ReviewKey       []byte `cbor:"3,keyasint"` // copied from the TaskDoc, 32 bytes
	Provider        string `cbor:"4,keyasint"` // the provider's AID; the signer
	RequestCID      string `cbor:"5,keyasint"`
	ResultCID       string `cbor:"6,keyasint"`
	CompletedDay    uint64 `cbor:"7,keyasint"` // UTC day number
}

func (b *ReceiptBody) check() error {
	if b.Type != ReceiptType {
		return malformed("receipt type tag is %q, not %q", b.Type, ReceiptType)
	}
	if err := sizedField("receipt ix_commit", b.IXCommit, CommitSize); err != nil {
		return err
	}
	if err := sizedField("receipt requester_commit", b.RequesterCommit, CommitSize); err != nil {
		return err
	}
	if err := sizedField("receipt review_key", b.ReviewKey, ReviewKeySize); err != nil {
		return err
	}
	if err := textField("receipt provider", b.Provider); err != nil {
		return err
	}
	if err := textField("receipt request_cid", b.RequestCID); err != nil {
		return err
	}
	return textField("receipt result_cid", b.ResultCID)
}

// withType returns a copy of b whose Type is ReceiptType when it was left empty.
func (b *ReceiptBody) withType() ReceiptBody {
	out := *b
	if out.Type == "" {
		out.Type = ReceiptType
	}
	return out
}

// Marshal returns coredet(ReceiptBody), the bytes the provider signs. An empty Type is written as
// ReceiptType; any other field out of form is an error.
func (b *ReceiptBody) Marshal() ([]byte, error) {
	out := b.withType()
	if err := out.check(); err != nil {
		return nil, err
	}
	return coredet.Marshal(out)
}

// UnmarshalReceiptBody decodes a receipt body strictly (CORE-E2, CORE-E4).
func UnmarshalReceiptBody(raw []byte) (*ReceiptBody, error) {
	var b ReceiptBody
	if err := decodeExact("receipt body", raw, &b); err != nil {
		return nil, err
	}
	if err := b.check(); err != nil {
		return nil, err
	}
	return &b, nil
}

// CID is the receipt_cid: the CID of the body bytes (CORE-K12).
func (b *ReceiptBody) CID() (string, error) {
	raw, err := b.Marshal()
	if err != nil {
		return "", err
	}
	return anetcid.Sum(raw)
}

// Sign returns the receipt as it travels, signed by c. c must be the provider: an empty Provider is
// filled with c's AID, and any other is refused (ErrSigner).
func (b *ReceiptBody) Sign(c identity.Signer) (*ReceiptWire, error) {
	body := b.withType()
	switch {
	case body.Provider == "":
		body.Provider = c.AID()
	case body.Provider != c.AID():
		return nil, fmt.Errorf("%w: the receipt names provider %s, the signer is %s", ErrSigner, body.Provider, c.AID())
	}
	raw, err := body.Marshal()
	if err != nil {
		return nil, err
	}
	sig, seq := c.Sign(raw)
	return &ReceiptWire{Body: raw, Env: &aobj.Envelope{SignerAID: c.AID(), KeyStateSeq: seq, Alg: aobj.AlgEdDSA, Sig: sig}}, nil
}

// ReceiptWire is a receipt as it travels (ResultResp key 3, the hub's POST /reviews): the body
// bytes and the provider's signature over exactly them.
//
//anet:wire ReceiptWire
type ReceiptWire struct {
	Body []byte         `cbor:"1,keyasint"`
	Env  *aobj.Envelope `cbor:"2,keyasint"`
}

func (w *ReceiptWire) check() error {
	if _, err := UnmarshalReceiptBody(w.Body); err != nil {
		return err
	}
	return envelopeOf("receipt", w.Env)
}

// Marshal encodes the receipt for the wire.
func (w *ReceiptWire) Marshal() ([]byte, error) {
	if err := w.check(); err != nil {
		return nil, err
	}
	return coredet.Marshal(w)
}

// UnmarshalReceiptWire decodes a receipt strictly. It does not verify the signature (Verify).
func UnmarshalReceiptWire(raw []byte) (*ReceiptWire, error) {
	var w ReceiptWire
	if err := decodeExact("receipt", raw, &w); err != nil {
		return nil, err
	}
	if err := w.check(); err != nil {
		return nil, err
	}
	return &w, nil
}

// Open decodes the body without checking the signature.
func (w *ReceiptWire) Open() (*ReceiptBody, error) { return UnmarshalReceiptBody(w.Body) }

// CID is the receipt_cid: the CID of the body bytes as they travel (CORE-K12).
func (w *ReceiptWire) CID() (string, error) {
	if len(w.Body) == 0 {
		return "", malformed("receipt: no body")
	}
	return anetcid.Sum(w.Body)
}

// Verify checks the provider's signature over the body against the provider's KEL and returns the
// body. The envelope's signer must be the body's provider (ErrSigner). msgTime is the time the
// receipt is judged at, in unix ms (identity.VerifyObject): the arrival of the result that carried
// it, or DayStart(CompletedDay) for one judged on its own (CheckV2).
func (w *ReceiptWire) Verify(providerKEL []identity.SignedEvent, msgTime uint64) (*ReceiptBody, error) {
	if w == nil {
		return nil, malformed("no receipt")
	}
	body, err := w.Open()
	if err != nil {
		return nil, err
	}
	if err := envelopeOf("receipt", w.Env); err != nil {
		return nil, err
	}
	if w.Env.SignerAID != body.Provider {
		return nil, fmt.Errorf("%w: the receipt is signed by %s for provider %s", ErrSigner, w.Env.SignerAID, body.Provider)
	}
	if err := identity.VerifyObject(providerKEL, w.Env.SignerAID, w.Env.KeyStateSeq, msgTime, w.Body, w.Env.Sig); err != nil {
		return nil, fmt.Errorf("%w: receipt: %w", ErrSignature, err)
	}
	return body, nil
}

// ---- review ----

// ReviewBody is the requester's rating of one task, signed with the one-time key whose public half
// the receipt carries (core §2.9, L30).
//
//anet:wire ReviewBody
type ReviewBody struct {
	Type       string `cbor:"0,keyasint"` // ReviewType
	ReceiptCID string `cbor:"1,keyasint"` // CID of the receipt body it rates
	Subject    string `cbor:"2,keyasint"` // the reviewed AID: the receipt's provider
	Rating     uint64 `cbor:"3,keyasint"` // RatingMin..RatingMax
	Comment    string `cbor:"4,keyasint,omitempty"`
	CreatedDay uint64 `cbor:"5,keyasint"` // UTC day number
}

func (b *ReviewBody) check() error {
	if b.Type != ReviewType {
		return malformed("review type tag is %q, not %q", b.Type, ReviewType)
	}
	if err := textField("review receipt_cid", b.ReceiptCID); err != nil {
		return err
	}
	// The subject is an AID, and CORE-E9 lists ReviewBody's subject among the fields a hub refuses
	// with bad_request when they hold U+0000, not as an unreviewable receipt: ErrNUL, not
	// ErrMalformed.
	if strings.IndexByte(b.Subject, 0) >= 0 {
		return fmt.Errorf("%w: review subject", ErrNUL)
	}
	if err := textField("review subject", b.Subject); err != nil {
		return err
	}
	if b.Rating < RatingMin || b.Rating > RatingMax {
		return fmt.Errorf("%w (it is %d)", ErrRating, b.Rating)
	}
	if n := utf8.RuneCountInString(b.Comment); n > MaxCommentChars {
		return fmt.Errorf("%w (it is %d)", ErrComment, n)
	}
	return nil
}

func (b *ReviewBody) withType() ReviewBody {
	out := *b
	if out.Type == "" {
		out.Type = ReviewType
	}
	return out
}

// Marshal returns coredet(ReviewBody), the bytes the review key signs.
func (b *ReviewBody) Marshal() ([]byte, error) {
	out := b.withType()
	if err := out.check(); err != nil {
		return nil, err
	}
	return coredet.Marshal(out)
}

// UnmarshalReviewBody decodes a review body strictly. A rating or comment out of bounds is
// ErrRating or ErrComment, and a subject holding U+0000 is ErrNUL.
func UnmarshalReviewBody(raw []byte) (*ReviewBody, error) {
	var b ReviewBody
	if err := decodeExact("review body", raw, &b); err != nil {
		return nil, err
	}
	if err := b.check(); err != nil {
		return nil, err
	}
	return &b, nil
}

// CID is the review_cid: the CID of the body bytes (CORE-K12).
func (b *ReviewBody) CID() (string, error) {
	raw, err := b.Marshal()
	if err != nil {
		return "", err
	}
	return anetcid.Sum(raw)
}

// Sign returns the review as it travels, signed with the one-time review key (the private key whose
// public half is the receipt's review_key).
func (b *ReviewBody) Sign(reviewKey ed25519.PrivateKey) (*ReviewWire, error) {
	if len(reviewKey) != ed25519.PrivateKeySize {
		return nil, malformed("review key is %d bytes, not %d", len(reviewKey), ed25519.PrivateKeySize)
	}
	raw, err := b.Marshal()
	if err != nil {
		return nil, err
	}
	pub := reviewKey.Public().(ed25519.PublicKey)
	return &ReviewWire{Body: raw, Pub: bytes.Clone(pub), Sig: ed25519.Sign(reviewKey, raw)}, nil
}

// ReviewWire is a review as it travels: the body, the review public key and the signature.
//
//anet:wire ReviewWire
type ReviewWire struct {
	Body []byte `cbor:"1,keyasint"`
	Pub  []byte `cbor:"2,keyasint"` // must equal the receipt's review_key
	Sig  []byte `cbor:"3,keyasint"` // Ed25519(review_sk, Body)
}

func (w *ReviewWire) check() error {
	if _, err := UnmarshalReviewBody(w.Body); err != nil {
		return err
	}
	if err := sizedField("review pub", w.Pub, ReviewKeySize); err != nil {
		return err
	}
	return sizedField("review sig", w.Sig, ed25519.SignatureSize)
}

// Marshal encodes the review for the wire.
func (w *ReviewWire) Marshal() ([]byte, error) {
	if err := w.check(); err != nil {
		return nil, err
	}
	return coredet.Marshal(w)
}

// UnmarshalReviewWire decodes a review strictly. It does not verify the signature (Verify).
func UnmarshalReviewWire(raw []byte) (*ReviewWire, error) {
	var w ReviewWire
	if err := decodeExact("review", raw, &w); err != nil {
		return nil, err
	}
	if err := w.check(); err != nil {
		return nil, err
	}
	return &w, nil
}

// Open decodes the body without checking the signature.
func (w *ReviewWire) Open() (*ReviewBody, error) { return UnmarshalReviewBody(w.Body) }

// CID is the review_cid: the CID of the body bytes as they travel (CORE-K12).
func (w *ReviewWire) CID() (string, error) {
	if len(w.Body) == 0 {
		return "", malformed("review: no body")
	}
	return anetcid.Sum(w.Body)
}

// Verify checks the review against reviewKey, the review_key of the receipt it rates, and returns
// the body. Only a review whose own public key is exactly reviewKey is accepted (ErrSigner): the
// key is what ties the review to the requester who chose it, and a review carrying any other key
// proves nothing about who wrote it.
func (w *ReviewWire) Verify(reviewKey []byte) (*ReviewBody, error) {
	if w == nil {
		return nil, malformed("no review")
	}
	if len(reviewKey) != ReviewKeySize {
		return nil, malformed("review_key is %d bytes, not %d", len(reviewKey), ReviewKeySize)
	}
	body, err := w.Open()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(w.Pub, reviewKey) {
		return nil, fmt.Errorf("%w: the review's key is not the receipt's review_key", ErrSigner)
	}
	if err := aobj.Verify(ed25519.PublicKey(w.Pub), w.Body, w.Sig); err != nil {
		return nil, fmt.Errorf("%w: review: %w", ErrSignature, err)
	}
	return body, nil
}

// ---- review attestation ----

// ReviewAttBody is a hub's signed statement that it stored a review (core §2.9, L32). It carries
// no reviewer: Tag (L31) lets readers count distinct reviewers per subject at that hub and nothing
// more.
//
//anet:wire ReviewAttBody
type ReviewAttBody struct {
	Type       string `cbor:"0,keyasint"` // ReviewAttType
	ReviewCID  string `cbor:"1,keyasint"`
	ReceiptCID string `cbor:"2,keyasint"`
	Subject    string `cbor:"3,keyasint"`
	Tag        []byte `cbor:"4,keyasint"` // ReviewTag(hub_tag_key, reviewer, subject), 16 bytes
	TagKeyID   uint64 `cbor:"5,keyasint"` // which of the hub's tag keys made Tag
	Day        uint64 `cbor:"6,keyasint"` // UTC day the hub stored the review
	Hub        string `cbor:"7,keyasint"` // the hub's AID; the signer
}

func (b *ReviewAttBody) check() error {
	if b.Type != ReviewAttType {
		return malformed("attestation type tag is %q, not %q", b.Type, ReviewAttType)
	}
	if err := textField("attestation review_cid", b.ReviewCID); err != nil {
		return err
	}
	if err := textField("attestation receipt_cid", b.ReceiptCID); err != nil {
		return err
	}
	if err := textField("attestation subject", b.Subject); err != nil {
		return err
	}
	if err := sizedField("attestation tag", b.Tag, TagSize); err != nil {
		return err
	}
	return textField("attestation hub", b.Hub)
}

func (b *ReviewAttBody) withType() ReviewAttBody {
	out := *b
	if out.Type == "" {
		out.Type = ReviewAttType
	}
	return out
}

// Marshal returns coredet(ReviewAttBody), the bytes the hub signs.
func (b *ReviewAttBody) Marshal() ([]byte, error) {
	out := b.withType()
	if err := out.check(); err != nil {
		return nil, err
	}
	return coredet.Marshal(out)
}

// UnmarshalReviewAttBody decodes an attestation body strictly.
func UnmarshalReviewAttBody(raw []byte) (*ReviewAttBody, error) {
	var b ReviewAttBody
	if err := decodeExact("attestation body", raw, &b); err != nil {
		return nil, err
	}
	if err := b.check(); err != nil {
		return nil, err
	}
	return &b, nil
}

// CID is the CID of the body bytes.
func (b *ReviewAttBody) CID() (string, error) {
	raw, err := b.Marshal()
	if err != nil {
		return "", err
	}
	return anetcid.Sum(raw)
}

// Sign returns the attestation as it travels, signed by the hub c. An empty Hub is filled with c's
// AID; any other is refused (ErrSigner).
func (b *ReviewAttBody) Sign(c identity.Signer) (*ReviewAttWire, error) {
	body := b.withType()
	switch {
	case body.Hub == "":
		body.Hub = c.AID()
	case body.Hub != c.AID():
		return nil, fmt.Errorf("%w: the attestation names hub %s, the signer is %s", ErrSigner, body.Hub, c.AID())
	}
	raw, err := body.Marshal()
	if err != nil {
		return nil, err
	}
	sig, seq := c.Sign(raw)
	return &ReviewAttWire{Body: raw, Env: &aobj.Envelope{SignerAID: c.AID(), KeyStateSeq: seq, Alg: aobj.AlgEdDSA, Sig: sig}}, nil
}

// ReviewAttWire is an attestation as it travels.
//
//anet:wire ReviewAttWire
type ReviewAttWire struct {
	Body []byte         `cbor:"1,keyasint"`
	Env  *aobj.Envelope `cbor:"2,keyasint"`
}

func (w *ReviewAttWire) check() error {
	if _, err := UnmarshalReviewAttBody(w.Body); err != nil {
		return err
	}
	return envelopeOf("attestation", w.Env)
}

// Marshal encodes the attestation for the wire.
func (w *ReviewAttWire) Marshal() ([]byte, error) {
	if err := w.check(); err != nil {
		return nil, err
	}
	return coredet.Marshal(w)
}

// UnmarshalReviewAttWire decodes an attestation strictly. It does not verify the signature.
func UnmarshalReviewAttWire(raw []byte) (*ReviewAttWire, error) {
	var w ReviewAttWire
	if err := decodeExact("attestation", raw, &w); err != nil {
		return nil, err
	}
	if err := w.check(); err != nil {
		return nil, err
	}
	return &w, nil
}

// Open decodes the body without checking the signature.
func (w *ReviewAttWire) Open() (*ReviewAttBody, error) { return UnmarshalReviewAttBody(w.Body) }

// Verify checks the hub's signature against the hub's KEL and returns the body. The signer must be
// the body's hub (ErrSigner). msgTime is the time it is judged at (identity.VerifyObject); a hub
// signature is judged by the hub's KEL at the time it was made (CORE-L8), so a reader that has
// only the attestation uses DayStart(Day).
func (w *ReviewAttWire) Verify(hubKEL []identity.SignedEvent, msgTime uint64) (*ReviewAttBody, error) {
	if w == nil {
		return nil, malformed("no attestation")
	}
	body, err := w.Open()
	if err != nil {
		return nil, err
	}
	if err := envelopeOf("attestation", w.Env); err != nil {
		return nil, err
	}
	if w.Env.SignerAID != body.Hub {
		return nil, fmt.Errorf("%w: the attestation is signed by %s for hub %s", ErrSigner, w.Env.SignerAID, body.Hub)
	}
	if err := identity.VerifyObject(hubKEL, w.Env.SignerAID, w.Env.KeyStateSeq, msgTime, w.Body, w.Env.Sig); err != nil {
		return nil, fmt.Errorf("%w: attestation: %w", ErrSignature, err)
	}
	return body, nil
}
