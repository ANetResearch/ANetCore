package ael

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/ANetResearch/ANetCore/coredet"
)

// A hub's supply epoch (HPP §2.3): one signed record per closed epoch on the hub's own chain
// (ChainDID = the hub's AID), saying only how much credit the hub owes in total and the root of the
// liability tree that sums to it. Each account checks its own balance leaf against the root; nobody
// learns anyone else's balance, and the record carries no AID, amount of a single event, or count.

// EvSupplyEpoch is the event type of a supply epoch record.
const EvSupplyEpoch = "anet.supply.epoch"

// Bounds of a supply epoch payload.
const (
	// SupplyEpochVersion is the payload's "v".
	SupplyEpochVersion = 2
	// SupplyMinDepth and SupplyMaxDepth bound the liability tree's depth (16 to 2^32 leaves).
	SupplyMinDepth = 4
	SupplyMaxDepth = 32
	// MaxOutstanding is the largest total a supply epoch can state (2^63 − 1, liabtree.MaxSum).
	MaxOutstanding = 1<<63 - 1
)

// ErrSupplyEpoch: a record that is not exactly a supply epoch record.
var ErrSupplyEpoch = errors.New("ael: not a well-formed supply epoch record")

// SupplyEpoch is what a supply epoch record states.
type SupplyEpoch struct {
	FromDay     uint64   // first UTC day the epoch covers
	ToDay       uint64   // last UTC day the epoch covers; the balances are as of its close
	Root        [32]byte // root hash of the liability tree (written as 64 lower-case hex digits)
	Outstanding uint64   // the total of every balance: the root's sum
	Depth       int      // the liability tree's depth
}

// supplyPayload is the record's payload: a text-keyed map with exactly these six members (HPP
// §2.3, core §2.9).
type supplyPayload struct {
	V           uint64 `cbor:"v"`
	FromDay     uint64 `cbor:"from_day"`
	ToDay       uint64 `cbor:"to_day"`
	Root        string `cbor:"root"`
	Outstanding uint64 `cbor:"outstanding"`
	Depth       uint64 `cbor:"depth"`
}

var supplyMembers = []string{"depth", "from_day", "outstanding", "root", "to_day", "v"}

func (p *SupplyEpoch) check() error {
	switch {
	case p.FromDay > p.ToDay:
		return fmt.Errorf("%w: from_day %d is after to_day %d", ErrSupplyEpoch, p.FromDay, p.ToDay)
	case p.Outstanding > MaxOutstanding:
		return fmt.Errorf("%w: outstanding %d is over 2^63 - 1", ErrSupplyEpoch, p.Outstanding)
	case p.Depth < SupplyMinDepth || p.Depth > SupplyMaxDepth:
		return fmt.Errorf("%w: depth %d is not %d..%d", ErrSupplyEpoch, p.Depth, SupplyMinDepth, SupplyMaxDepth)
	}
	return nil
}

// SupplyEpochRecord returns the unsigned supply epoch record of hub hubAID stating p. The caller
// sets Seq, PrevID and Timestamp (the publication time, not the time of any user's event) from its
// chain and signs it with the hub's identity (EventRecord.Sign). An out-of-range p is
// ErrSupplyEpoch.
func SupplyEpochRecord(hubAID string, p SupplyEpoch) (*EventRecord, error) {
	if hubAID == "" {
		return nil, fmt.Errorf("%w: no hub AID", ErrSupplyEpoch)
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	return &EventRecord{
		ChainDID:     hubAID,
		EventType:    EvSupplyEpoch,
		VersionMajor: VersionMajor2,
		Payload: supplyPayload{
			V: SupplyEpochVersion, FromDay: p.FromDay, ToDay: p.ToDay, Root: hex.EncodeToString(p.Root[:]),
			Outstanding: p.Outstanding, Depth: uint64(p.Depth),
		},
	}, nil
}

// ParseSupplyEpoch reads what a supply epoch record states. The record must be of type
// EvSupplyEpoch and version 2, carry no critical extensions or correlation id, and its payload
// must be exactly the six members with their values in range: anything else — a seventh member
// (an AID, an amount, a count), a member missing, a value of another type — is ErrSupplyEpoch. It
// does not check the signature (EventRecord.Verify, against the hub's KEL at the time it signed).
func ParseSupplyEpoch(rec *EventRecord) (*SupplyEpoch, error) {
	switch {
	case rec == nil:
		return nil, fmt.Errorf("%w: no record", ErrSupplyEpoch)
	case rec.EventType != EvSupplyEpoch:
		return nil, fmt.Errorf("%w: event type %q", ErrSupplyEpoch, rec.EventType)
	case rec.VersionMajor != VersionMajor2 || rec.VersionMinor != 0:
		return nil, fmt.Errorf("%w: version %d.%d", ErrSupplyEpoch, rec.VersionMajor, rec.VersionMinor)
	case rec.ChainDID == "":
		return nil, fmt.Errorf("%w: no chain", ErrSupplyEpoch)
	case len(rec.CriticalExtensions) > 0 || rec.CorrID != "":
		return nil, fmt.Errorf("%w: a supply epoch carries no extensions and no correlation id", ErrSupplyEpoch)
	}
	raw, err := coredet.Marshal(rec.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrSupplyEpoch, err)
	}
	var members map[string]any
	if err := coredet.Unmarshal(raw, &members); err != nil {
		return nil, fmt.Errorf("%w: the payload is not a map of text keys", ErrSupplyEpoch)
	}
	names := make([]string, 0, len(members))
	for k := range members {
		names = append(names, k)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != strings.Join(supplyMembers, ",") {
		return nil, fmt.Errorf("%w: the payload has members [%s], want exactly [%s]", ErrSupplyEpoch,
			strings.Join(names, ", "), strings.Join(supplyMembers, ", "))
	}
	var p supplyPayload
	if err := coredet.UnmarshalStrict(raw, &p); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrSupplyEpoch, err)
	}
	if back, err := coredet.Marshal(p); err != nil || !bytes.Equal(back, raw) {
		return nil, fmt.Errorf("%w: a payload member has a value of another type", ErrSupplyEpoch)
	}
	if p.V != SupplyEpochVersion {
		return nil, fmt.Errorf("%w: payload v is %d, not %d", ErrSupplyEpoch, p.V, SupplyEpochVersion)
	}
	var root [32]byte
	if len(p.Root) != 64 || strings.ToLower(p.Root) != p.Root {
		return nil, fmt.Errorf("%w: root is not 64 lower-case hex digits", ErrSupplyEpoch)
	}
	if _, err := hex.Decode(root[:], []byte(p.Root)); err != nil {
		return nil, fmt.Errorf("%w: root is not 64 lower-case hex digits", ErrSupplyEpoch)
	}
	if p.Depth > SupplyMaxDepth {
		return nil, fmt.Errorf("%w: depth %d is not %d..%d", ErrSupplyEpoch, p.Depth, SupplyMinDepth, SupplyMaxDepth)
	}
	out := &SupplyEpoch{FromDay: p.FromDay, ToDay: p.ToDay, Root: root, Outstanding: p.Outstanding, Depth: int(p.Depth)}
	if err := out.check(); err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalEventRecord decodes a record as it travels (coredet(EventRecord), signature included),
// strictly: a key the record does not define is refused, and so are bytes that are not the
// record's one canonical encoding (CORE-E3, CORE-E4). It does not verify the record.
func UnmarshalEventRecord(b []byte) (*EventRecord, error) {
	var r EventRecord
	if err := coredet.UnmarshalStrict(b, &r); err != nil {
		return nil, fmt.Errorf("ael: record does not decode: %w", err)
	}
	back, err := coredet.Marshal(&r)
	if err != nil || !bytes.Equal(back, b) {
		return nil, errors.New("ael: record is not in its one canonical encoding")
	}
	return &r, nil
}
