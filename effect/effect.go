// Package effect defines the execution-effect envelope shared by the C1
// (CapabilityProvider) and C4 (Adapter) contracts of the ANet suite: what
// happened, whether it is verifiable, and the metrics a TSIR acceptance
// predicate can evaluate.
//
// The status axis is deliberately separate from the metric record: "the
// command was sent but the physical effect cannot be verified" (UNVERIFIED)
// is not a failure, and conflating the two poisons trust accounting upstream
// (see ANetLink trust ladder T0–T4).
package effect

import "github.com/ANetResearch/ANetCore/tsir"

// Status classifies an invocation outcome.
type Status string

const (
	// OK: executed and the effect is verifiable — Record carries the
	// metrics that back the claim.
	OK Status = "OK"
	// Unverified: executed as requested, but no verifiable effect signal
	// exists at this trust level. Not a failure.
	Unverified Status = "UNVERIFIED"
	// Failed: execution failed.
	Failed Status = "FAILED"
	// Unavailable: the target could not be reached at invocation time.
	Unavailable Status = "UNAVAILABLE"
)

// Effect is the envelope every capability invocation returns.
type Effect struct {
	Status  Status             `cbor:"1,keyasint"`
	Record  *tsir.EffectRecord `cbor:"2,keyasint,omitempty"` // nil when no metrics
	Message string             `cbor:"3,keyasint,omitempty"` // human-readable detail
}

// Verifiable reports whether the effect can back an acceptance-predicate
// evaluation: only OK effects with a non-nil record qualify.
func (e Effect) Verifiable() bool {
	return e.Status == OK && e.Record != nil
}
