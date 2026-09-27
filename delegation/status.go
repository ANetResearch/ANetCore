package delegation

import "github.com/ANetResearch/ANetCore/coredet"

// Task states carried by StatusMsg (A2A-DESIGN §3.4). The strings are the A2A TaskState names in
// lowercase-hyphen form. Completion is not among them: a completed task is reported by ResultResp
// (anet.result/1), which carries the deliverable and the receipt.
const (
	StateSubmitted     = "submitted"
	StateWorking       = "working"
	StateInputRequired = "input-required"
	StateRejected      = "rejected"
	StateCanceled      = "canceled"
	StateFailed        = "failed"
)

// ValidStatusState reports whether state is one of the six StatusMsg states. A receiver checks it
// before acting on a StatusMsg: an unknown state from a newer or faulty peer must not be mapped to
// any of the known ones.
func ValidStatusState(state string) bool {
	switch state {
	case StateSubmitted, StateWorking, StateInputRequired, StateRejected, StateCanceled, StateFailed:
		return true
	}
	return false
}

// StatusMsg is the body of an anet.status/1 message, provider → requester (A2A-DESIGN §3.4):
//
//	StatusMsg = {1: state tstr, 2: text tstr, 3: metadata bstr, 4: at uint}
//
// State and At are always encoded. Text and Metadata are optional and omitted when empty.
//
// Like ChatMsg it carries no signature of its own; under wire 2 it travels only inside a sealed
// envelope whose inner signature covers it.
type StatusMsg struct {
	State string `cbor:"1,keyasint"`
	// Text is a human-readable explanation, for example why input is required.
	Text string `cbor:"2,keyasint,omitempty"`
	// Metadata is a JSON object carried as raw bytes. Reserved keys include anet.a2aError (an A2A
	// §3.3.2 error name), anet.reason and anet.retry_after_ms. This package does not parse it.
	Metadata []byte `cbor:"3,keyasint,omitempty"`
	// At is the time the provider entered State, in unix milliseconds.
	At uint64 `cbor:"4,keyasint"`
}

// Marshal encodes a StatusMsg (CoreDet-CBOR).
func (m *StatusMsg) Marshal() ([]byte, error) { return coredet.Marshal(*m) }

// UnmarshalStatusMsg decodes a StatusMsg. It does not check State; see ValidStatusState.
func UnmarshalStatusMsg(b []byte) (*StatusMsg, error) {
	var m StatusMsg
	if err := coredet.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
