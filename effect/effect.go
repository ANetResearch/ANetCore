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

// Evidence carries the structured provenance of an execution: not just
// "status ok", but what was requested, over which protocol, whether the
// device acknowledged natively, what state was actually observed, and how
// long it took. This is what lets an agent know the device REALLY executed —
// the difference between "I sent a command" and "I verified the effect".
type Evidence struct {
	Requested     string `cbor:"1,keyasint,omitempty"` // e.g. "light.onoff=on"
	Protocol      string `cbor:"2,keyasint,omitempty"` // "zigbee" | "modbus" | "opcua" | ...
	NativeAck     bool   `cbor:"3,keyasint,omitempty"` // the protocol itself acknowledged
	ObservedState string `cbor:"4,keyasint,omitempty"` // what a readback actually reported
	LatencyMS     int64  `cbor:"5,keyasint,omitempty"` // invoke → effect, milliseconds
	VerifyTrust   uint8  `cbor:"6,keyasint,omitempty"` // effect-verification level (V0-V4)
	AuthTrust     uint8  `cbor:"7,keyasint,omitempty"` // identity-authentication level (A0-A4)
	// Quirk names the vendor-deviation correction applied to this reading,
	// when one was. A corrected value is not the value the device put on the
	// wire, and a consumer that cannot tell the two apart cannot audit the
	// correction — which is exactly what Evidence exists to prevent.
	Quirk string `cbor:"8,keyasint,omitempty"`
}

// Effect is the envelope every capability invocation returns.
type Effect struct {
	Status   Status             `cbor:"1,keyasint"`
	Record   *tsir.EffectRecord `cbor:"2,keyasint,omitempty"` // nil when no metrics
	Message  string             `cbor:"3,keyasint,omitempty"` // human-readable detail
	Evidence *Evidence          `cbor:"4,keyasint,omitempty"` // structured provenance
}

// Verifiable reports whether the effect can back an acceptance-predicate
// evaluation: only OK effects with a non-nil record qualify.
func (e Effect) Verifiable() bool {
	return e.Status == OK && e.Record != nil
}
