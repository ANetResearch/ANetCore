package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"
)

// The commitment and tag functions of evidence v2 (core §3.2). Each is a class B or C input
// (CORE-L1): a label, 0x00, then fields separated by 0x00. A text field that held U+0000 could move
// a boundary — ("a\0b", "c") and ("a", "b\0c") would hash alike — so every function refuses one
// (CORE-E9), and also an empty one, which no real input is.

const (
	labelIXCommit        = "anet-receipt-ix/v2"        // L27
	labelRequesterCommit = "anet-receipt-requester/v2" // L28
	labelReviewTag       = "anet-review-tag/v1"        // L31
	labelSettleGuard     = "anet-settle-guard/v1"      // L33
)

// commitText checks one text field of a commitment input.
func commitText(what, v string) error {
	if v == "" {
		return fmt.Errorf("%w: %s is empty", ErrNUL, what)
	}
	if strings.IndexByte(v, 0) >= 0 {
		return fmt.Errorf("%w: %s", ErrNUL, what)
	}
	return nil
}

// IXCommit is a receipt's ix_commit (L27):
//
//	SHA-256("anet-receipt-ix/v2" ‖ 0x00 ‖ ix ‖ 0x00 ‖ nonce)
//
// ix is the interaction id and nonce the TaskDoc's anet.nonce exactly as written (not decoded).
// The provider computes it when it signs the receipt; the requester recomputes it to check one.
// Neither may be empty or hold U+0000 (ErrNUL).
func IXCommit(ix, nonce string) ([]byte, error) {
	if err := commitText("ix", ix); err != nil {
		return nil, err
	}
	if err := commitText("anet.nonce", nonce); err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(labelIXCommit))
	h.Write([]byte{0})
	h.Write([]byte(ix))
	h.Write([]byte{0})
	h.Write([]byte(nonce))
	return h.Sum(nil), nil
}

// RequesterCommit is the TaskDoc's anet.requester_commit (L28):
//
//	SHA-256("anet-receipt-requester/v2" ‖ 0x00 ‖ requester_aid ‖ 0x00 ‖ rsalt)
//
// rsalt is the requester's 32 random bytes for the task. The requester writes it into the TaskDoc;
// the hub that stores a review recomputes it from the uploader's AID and the rsalt it uploads, so
// only the requester can have the review stored, while the receipt names nobody.
func RequesterCommit(requesterAID string, rsalt []byte) ([]byte, error) {
	if err := commitText("requester_aid", requesterAID); err != nil {
		return nil, err
	}
	if len(rsalt) != RSaltSize {
		return nil, fmt.Errorf("%w: rsalt is %d bytes, not %d", ErrMalformed, len(rsalt), RSaltSize)
	}
	h := sha256.New()
	h.Write([]byte(labelRequesterCommit))
	h.Write([]byte{0})
	h.Write([]byte(requesterAID))
	h.Write([]byte{0})
	h.Write(rsalt)
	return h.Sum(nil), nil
}

// ReviewTag is the tag a hub writes into a review attestation (L31):
//
//	HMAC-SHA256(hub_tag_key, "anet-review-tag/v1" ‖ 0x00 ‖ reviewer_aid ‖ 0x00 ‖ subject_aid)[0:16]
//
// One reviewer gets one tag per subject at one hub, so the hub can count distinct reviewers; a
// reader without the key cannot tell who they are, or match tags across subjects or hubs.
func ReviewTag(tagKey []byte, reviewerAID, subjectAID string) ([]byte, error) {
	if len(tagKey) != TagKeySize {
		return nil, fmt.Errorf("%w: the tag key is %d bytes, not %d", ErrMalformed, len(tagKey), TagKeySize)
	}
	if err := commitText("reviewer_aid", reviewerAID); err != nil {
		return nil, err
	}
	if err := commitText("subject_aid", subjectAID); err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, tagKey)
	m.Write([]byte(labelReviewTag))
	m.Write([]byte{0})
	m.Write([]byte(reviewerAID))
	m.Write([]byte{0})
	m.Write([]byte(subjectAID))
	return m.Sum(nil)[:TagSize], nil
}

// SettleGuard is the key under which a hub remembers that one payer settled one task (L33):
//
//	SHA-256("anet-settle-guard/v1" ‖ 0x00 ‖ payer ‖ 0x00 ‖ pay_bind)
//
// pay_bind is the authorization's InteractionID, the hex PayBind of the task (L34). The hub keeps
// only this hash, so its guard against a second settlement does not keep who paid for what.
func SettleGuard(payer, payBind string) ([]byte, error) {
	if err := commitText("payer", payer); err != nil {
		return nil, err
	}
	if err := commitText("pay_bind", payBind); err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(labelSettleGuard))
	h.Write([]byte{0})
	h.Write([]byte(payer))
	h.Write([]byte{0})
	h.Write([]byte(payBind))
	return h.Sum(nil), nil
}
