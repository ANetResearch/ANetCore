package wire

import (
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/coredet"
)

// Negative is one encoding a decoder must refuse (CORE-S4): a valid encoding of an object with
// one key it does not assign inserted.
type Negative struct {
	Key   uint64
	Bytes []byte
	Why   string // "reserved", "retired", "forbidden" or "beyond 63 in a closed object"
}

// Negatives returns, for the registered object name and a valid encoding of it, one encoding
// per key the decoder must refuse:
//
//   - every key number 0..63 that is not active in the object (reserved, retired, forbidden or
//     unlisted);
//   - for an object other than the outer envelope, Wrap and the inner message (a closed key
//     space), also 64 and 65535.
//
// Each negative is valid with that one key added and is re-encoded canonically. The added value
// is CBOR null: a Go decoder takes null into a field of any type, so a decoder that refuses the
// negative does so because of the key and not because of the value's type. (With a typed value,
// a decoder that still has a field for a retired key of another type would refuse it for the
// type and pass for the wrong reason.) Objects that are only built and never decoded (preimages,
// HPKE info) have no negatives, and a valid encoding that already holds a key the object does
// not assign is an error, not a base to build on.
func Negatives(r *Registry, name string, valid []byte) ([]Negative, error) {
	o := r.Object(name)
	if o == nil {
		return nil, fmt.Errorf("wire: no object %q", name)
	}
	if o.Keyspace == KeyspaceDerived {
		return nil, fmt.Errorf("wire: %s is built, never decoded: it has no negative encodings", name)
	}
	if o.Keyspace == KeyspaceExternal {
		return nil, fmt.Errorf("wire: %s is not a CBOR map: it has no negative encodings", name)
	}
	base, err := decodeIntMap(valid)
	if err != nil {
		return nil, fmt.Errorf("wire: %s: valid encoding: %w", name, err)
	}
	for k := range base {
		if k > 63 && o.Keyspace != KeyspaceClosed {
			continue // an extension key of a critical object
		}
		st := StatusReserved
		if k <= 63 {
			st = o.KeyStatus(int(k))
		}
		if st != StatusActive {
			return nil, fmt.Errorf("wire: %s: the valid encoding holds key %d, which is %s", name, k, st)
		}
	}
	var out []Negative
	add := func(k uint64, why string) error {
		if _, has := base[k]; has {
			return nil
		}
		m := make(map[uint64]cbor.RawMessage, len(base)+1)
		for kk, v := range base {
			m[kk] = v
		}
		m[k] = cbor.RawMessage{0xf6} // null
		b, err := coredet.Marshal(m)
		if err != nil {
			return err
		}
		out = append(out, Negative{Key: k, Bytes: b, Why: why})
		return nil
	}
	for n := 0; n <= 63; n++ {
		st := o.KeyStatus(n)
		if st == StatusActive {
			continue
		}
		if err := add(uint64(n), st); err != nil {
			return nil, err
		}
	}
	if o.Keyspace == KeyspaceClosed {
		for _, k := range []uint64{64, math.MaxUint16} {
			if err := add(k, "beyond 63 in a closed object"); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// decodeIntMap decodes a CBOR map whose keys are all unsigned integers, keeping each value's
// encoded bytes.
func decodeIntMap(b []byte) (map[uint64]cbor.RawMessage, error) {
	var m map[uint64]cbor.RawMessage
	if err := coredet.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("not a map")
	}
	return m, nil
}
