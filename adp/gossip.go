package adp

import (
	"encoding/json"
)

// GossipCardMessage is the §2.4 gossip envelope carried as the JSON portion of a gossip
// payload (after the 1-byte SchemaVersionTag). `card` is present iff action="publish";
// `tombstone` is present iff action="revoke". agent_id/seq/timestamp are always emitted
// (timestamp is an RFC3339 string, never an integer). AXP/ADP relays carry the descriptive
// keys byte-intact; ADP admission consumes only Card / Tombstone.
type GossipCardMessage struct {
	Action    string         `json:"action"` // "publish" | "revoke"
	Card      *AgentCard     `json:"card,omitempty"`
	Tombstone *CardTombstone `json:"tombstone,omitempty"`
	AgentID   string         `json:"agent_id,omitempty"`
	Seq       uint64         `json:"seq,omitempty"`
	Timestamp string         `json:"timestamp,omitempty"` // RFC3339 string (§2.4)
}

// SchemaVersionTag framing constants (§2.4).
const (
	// SchemaTagUntaggedLegacy (0x00) denotes the pre-versioned bare-JSON regime (reserved;
	// never transmitted). On the wire a legacy payload instead begins with '{' (0x7B), which
	// collides with MAJOR=123 (§2.4 first-byte caveat) — ParseGossip treats a leading '{' as
	// untagged-legacy bare JSON, NOT as MAJOR 123.
	SchemaTagUntaggedLegacy byte = 0x00
	// jsonOpenBrace is ASCII '{' — the first byte of an untagged-legacy bare-JSON payload.
	jsonOpenBrace byte = 0x7B
)

// ParseGossip decodes a §2.4 gossip payload = SchemaVersionTag(1 byte) ‖ JSON and returns
// the carried AgentCard for the caller to run through AdmitCard. The SchemaVersionTag is
// checked BEFORE any JSON parse (P2 P2.2 ignore-unknown-not-misparse): a tagged payload
// whose MAJOR is not in supportedMajors is held UNVERIFIABLE → UNSUPPORTED_SCHEMA_MAJOR with
// NO parse attempt, so a higher-MAJOR card can never be misparsed (§5.1 step 1 / §2.4).
//
// Framing:
//   - empty payload → MALFORMED_CARD;
//   - leading '{' (0x7B) → untagged-legacy: the WHOLE payload is the JSON (no tag stripped),
//     parsed regardless of supportedMajors (the MAJOR gate applies to TAGGED payloads only);
//     AdmitCard then rejects a legacy card lacking an envelope (ADP-GV-10);
//   - byte 0x00 → untagged-legacy marker: payload[1:] is the JSON, no MAJOR gate;
//   - otherwise byte[0] is the SchemaVersionTag MAJOR; if MAJOR ∉ supportedMajors →
//     UNSUPPORTED_SCHEMA_MAJOR before parse; else payload[1:] is the JSON.
//
// The JSON is decoded as a GossipCardMessage envelope when it carries one (action/card/
// tombstone, §2.4); a bare card object (no envelope wrapper) is accepted as a legacy
// AgentCard. A revoke envelope (action="revoke") carries a tombstone, not a card, so
// ParseGossip returns (nil, nil) for it — the caller routes tombstones to AdmitTombstone.
func ParseGossip(payload []byte, majors map[uint16]bool) (*AgentCard, error) {
	if len(payload) == 0 {
		return nil, &Error{Code: MALFORMED_CARD, Detail: "empty gossip payload"}
	}
	var jsonBytes []byte
	switch {
	case payload[0] == jsonOpenBrace:
		// Untagged-legacy bare JSON (the on-wire regime); MAJOR gate does not apply.
		jsonBytes = payload
	case payload[0] == SchemaTagUntaggedLegacy:
		// Reserved untagged-legacy marker; remainder is the JSON, no MAJOR gate.
		jsonBytes = payload[1:]
	default:
		// Tagged: byte[0] is the SchemaVersionTag MAJOR — gate BEFORE JSON parse (§2.4).
		if !majors[uint16(payload[0])] {
			return nil, &Error{Code: UNSUPPORTED_SCHEMA_MAJOR, Detail: "gossip SchemaVersionTag MAJOR not in supported set (held before JSON parse)"}
		}
		jsonBytes = payload[1:]
	}
	return parseGossipJSON(jsonBytes)
}

// parseGossipJSON decodes the JSON portion: a GossipCardMessage envelope when present, else
// a bare AgentCard (legacy). It mutates no cache (the caller runs AdmitCard/AdmitTombstone).
func parseGossipJSON(jsonBytes []byte) (*AgentCard, error) {
	var env GossipCardMessage
	if err := json.Unmarshal(jsonBytes, &env); err != nil {
		return nil, &Error{Code: MALFORMED_CARD, Detail: "gossip JSON not decodable: " + err.Error()}
	}
	switch {
	case env.Action == "publish" && env.Card != nil:
		return env.Card, nil
	case env.Action == "revoke":
		// Carries a tombstone, not a card — caller routes to AdmitTombstone.
		return nil, nil
	case env.Card != nil:
		return env.Card, nil
	default:
		// Bare-card / legacy regime: the JSON IS the AgentCard (no envelope wrapper).
		var card AgentCard
		if err := json.Unmarshal(jsonBytes, &card); err != nil {
			return nil, &Error{Code: MALFORMED_CARD, Detail: "gossip bare card not decodable: " + err.Error()}
		}
		return &card, nil
	}
}
