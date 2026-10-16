package evidence

import (
	"errors"
	"fmt"

	"github.com/ANetResearch/ANetCore/identity"
)

// ErrNotThisReceipt: the review rates another receipt, or another subject than the receipt's
// provider.
var ErrNotThisReceipt = errors.New("evidence: the review is not about this receipt")

// CheckV2 checks that a receipt and a review are two halves of one real task (interlock v2, HPP
// PAY-K3), and returns their bodies.
//
// It is the arithmetic behind "the hub cannot fake a rating", kept in a package anyone can import so
// an auditor with nothing but the objects reaches the hub's verdict:
//
//	the provider signed the receipt     — under its KEL, judged at the start of the receipt's own
//	                                      completed_day (SI-36): a key the provider retired before
//	                                      that day signs nothing for it
//	the review is signed by review_key  — the one-time key the requester put in the TaskDoc and the
//	                                      provider copied into the receipt; nobody else holds it
//	the review names this receipt       — review.receipt_cid is the CID of the receipt body
//	the review rates the provider       — review.subject is receipt.provider
//
// What it does not check needs state or a clock: that the uploader is the requester (the hub
// compares requester_commit with the uploader, HPP PAY-V1 step 6), the review window, and that the
// task was not rated before. Those are a hub's policy against its own store, not facts about the
// objects.
func CheckV2(receipt *ReceiptWire, review *ReviewWire, providerKEL []identity.SignedEvent) (*ReceiptBody, *ReviewBody, error) {
	if receipt == nil || review == nil {
		return nil, nil, malformed("an interlock needs both a receipt and a review")
	}
	rc, err := receipt.Open()
	if err != nil {
		return nil, nil, err
	}
	at, ok := DayStart(rc.CompletedDay)
	if !ok {
		return nil, nil, malformed("receipt completed_day %d is not a day", rc.CompletedDay)
	}
	if _, err := receipt.Verify(providerKEL, at); err != nil {
		return nil, nil, err
	}
	rv, err := review.Verify(rc.ReviewKey)
	if err != nil {
		return nil, nil, err
	}
	receiptCID, err := receipt.CID()
	if err != nil {
		return nil, nil, err
	}
	if rv.ReceiptCID != receiptCID {
		return nil, nil, fmt.Errorf("%w: the review names receipt %s, this receipt is %s", ErrNotThisReceipt, rv.ReceiptCID, receiptCID)
	}
	if rv.Subject != rc.Provider {
		return nil, nil, fmt.Errorf("%w: the review rates %s, the receipt's provider is %s", ErrNotThisReceipt, rv.Subject, rc.Provider)
	}
	return rc, rv, nil
}
