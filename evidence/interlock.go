package evidence

import (
	"errors"
	"fmt"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/identity"
)

// VerifyInterlock checks that a receipt and a review are two halves of one
// real interaction.
//
// This is the arithmetic behind "the Hub is a relay — it cannot fake a
// single rating", and it lived inside the Hub, in a package Go forbids
// anyone else from importing. So the claim was true of the Hub's own code
// and unavailable to the people it is addressed to: a rating is worth
// something precisely because a stranger can check it, and no stranger
// could.
//
// Ten checks, and every one of them is a way to manufacture a rating that
// would otherwise pass:
//
//	rating in range                 — a 9-star review
//	same interaction id             — a review of a different job
//	reviewer is the requester       — rating work you did not commission
//	subject is the provider         — praising someone who was not there
//	review anchored to this receipt — a real receipt paired with a review
//	                                  that names a different one
//	request bytes hash to RequestCID  — rating a job that was not asked
//	deliverable hashes to ResultCID   — rating work that was not delivered
//	receipt signed by the provider    — a receipt the provider never issued
//	review signed by the reviewer     — a review the requester never wrote
//	both signatures under a live key   — a key retired before it signed
//
// What it deliberately does NOT check is anything requiring state: that
// the parties are registered somewhere, or that this interaction has not
// already been rated. Those are policy a particular Hub enforces against
// its own store, not facts about the objects. Keeping them out is what
// lets an auditor with nothing but files reach the same verdict.
//
// requestDoc and deliverable are the interaction's actual bytes. Pass nil
// for either to skip that content binding — an auditor who was given only
// the signed objects can still confirm everything else, and saying so is
// better than pretending the content was checked.
func VerifyInterlock(rc *Receipt, rv *Review, requestDoc, deliverable []byte,
	providerKEL, reviewerKEL []identity.SignedEvent) error {
	if rc == nil || rv == nil {
		return errors.New("evidence: interlock needs both a receipt and a review")
	}
	if !rv.ValidRating() {
		return fmt.Errorf("evidence: rating %d out of range %d..%d", rv.Rating, RatingMin, RatingMax)
	}

	// The two objects must describe the same interaction and agree on who
	// was involved.
	if rc.InteractionID != rv.InteractionID {
		return fmt.Errorf("evidence: receipt is for interaction %s, review for %s",
			rc.InteractionID, rv.InteractionID)
	}
	if rv.ReviewerAID != rc.RequesterAID {
		return errors.New("evidence: the reviewer is not the interaction's requester")
	}
	if rv.SubjectAID != rc.ProviderAID {
		return errors.New("evidence: the review rates someone other than the provider")
	}

	// And the review must be anchored to THIS receipt, not merely to one.
	receiptCID, err := rc.CID()
	if err != nil {
		return err
	}
	if rv.ReceiptCID != receiptCID {
		return fmt.Errorf("evidence: review references receipt %s, not %s", rv.ReceiptCID, receiptCID)
	}

	// Content binding: what is shown must be what was signed for.
	if requestDoc != nil {
		cid, err := anetcid.Sum(requestDoc)
		if err != nil {
			return err
		}
		if cid != rc.RequestCID {
			return fmt.Errorf("evidence: request bytes hash to %s, receipt says %s", cid, rc.RequestCID)
		}
	}
	if deliverable != nil {
		cid, err := anetcid.Sum(deliverable)
		if err != nil {
			return err
		}
		if cid != rc.ResultCID {
			return fmt.Errorf("evidence: deliverable hashes to %s, receipt says %s", cid, rc.ResultCID)
		}
	}

	// Signatures last: they are the expensive part, and an object that
	// fails the cheap structural checks is not worth a curve operation.
	if err := rc.Verify(providerKEL, rc.CompletedAt); err != nil {
		return fmt.Errorf("evidence: receipt signature invalid: %w", err)
	}
	if err := rv.Verify(reviewerKEL, rv.CreatedAt); err != nil {
		return fmt.Errorf("evidence: review signature invalid: %w", err)
	}
	return nil
}
