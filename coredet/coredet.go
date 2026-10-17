// Package coredet implements CoreDet-CBOR, the Agent Network suite's deterministic
// CBOR profile. It is the single encoder for every CID preimage and signature
// preimage in the stack.
//
// Normative source: design3/spec/_CONVENTIONS §2 = RFC 8949 §4.2 Core Deterministic
// Encoding (shortest-form integers/lengths, definite-length items, map keys sorted by
// bytewise-lexicographic order of their encoded bytes, preferred float serialization)
// plus the suite restrictions C-R1 (no NaN/±Infinity in any value) and C-R2 (no CBOR
// tags). RFC 7049 "canonical CBOR" (length-first key sort) MUST NOT be substituted.
package coredet

import (
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

var (
	encMode       cbor.EncMode
	decMode       cbor.DecMode
	strictDecMode cbor.DecMode
)

// strictDecOptions are the decoder options of UnmarshalStrict: the CoreDet profile's own (no tags,
// duplicate map keys rejected) plus an error for a map key the destination struct does not name.
// ANetLink pins a copy of these options in its own C1 decoder; a test here fixes them field by
// field so the two cannot drift apart unnoticed.
func strictDecOptions() cbor.DecOptions {
	return cbor.DecOptions{
		TagsMd:            cbor.TagsForbidden,
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}
}

func init() {
	opts := cbor.CoreDetEncOptions()        // RFC 8949 §4.2
	opts.NaNConvert = cbor.NaNConvertReject // C-R1
	opts.InfConvert = cbor.InfConvertReject // C-R1
	m, err := opts.EncMode()
	if err != nil {
		panic(fmt.Sprintf("coredet: invalid CoreDet enc options: %v", err))
	}
	encMode = m
	// C-R2: no CBOR tags. DupMapKeyEnforcedAPF: reject duplicate map keys — a canonical CoreDet
	// encoding (RFC 8949 §4.2) never has them, so a decoder that verifies the profile MUST reject
	// them rather than silently keep last-wins (which would let two implementations disagree).
	dm, err := cbor.DecOptions{TagsMd: cbor.TagsForbidden, DupMapKey: cbor.DupMapKeyEnforcedAPF}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("coredet: invalid dec options: %v", err))
	}
	decMode = dm
	sm, err := strictDecOptions().DecMode()
	if err != nil {
		panic(fmt.Sprintf("coredet: invalid strict dec options: %v", err))
	}
	strictDecMode = sm
}

// Marshal encodes v as CoreDet-CBOR. It returns an error if v contains NaN or
// ±Infinity (C-R1), or if the result would not decode under Unmarshal.
//
// That last check closes an asymmetry between the two modes. A Go string may
// hold arbitrary bytes and the encoder writes it as a CBOR text string without
// looking; the decoder refuses one that is not valid UTF-8, as RFC 8949
// requires. Without the check this package can emit a preimage it cannot read
// back, and the writer is told it succeeded.
//
// Where: coredet.Marshal. Behaviour: the encoder accepted a Go string that is
// not valid UTF-8 and the decoder refused it. Effect: the write succeeded and
// the data reached disk, and the failure was deferred to the next read, often
// in another process on another day. Found when the anet daemon wrote a
// command echo containing a 0xa2 byte into the evidence ledger; two days later
// the ledger could not be read on restart, the node crashed and restarted
// every 5 seconds under systemd, and only editing the ledger by hand
// recovered it.
//
// The fix is here rather than at each call site: this package is the only
// preimage encoder in the stack, so establishing "what encodes also decodes"
// here removes the defect for every caller at once. The cost is one extra
// decode per Marshal; if that ever matters on a hot path, change the approach
// then, with benchmark data.
func Marshal(v any) ([]byte, error) {
	b, err := encMode.Marshal(v)
	if err != nil {
		return nil, err
	}
	// Ask the decoder rather than reimplement its rules. Valid() only checks
	// structure — the UTF-8 rule lives in the value-building path — and a
	// hand-written scan would be a second copy of the decoder that is free to
	// drift from the first.
	var back any
	if err := decMode.Unmarshal(b, &back); err != nil {
		return nil, fmt.Errorf("coredet: encoded value will not decode (%w) — "+
			"a string almost certainly carries bytes that are not valid UTF-8; "+
			"arbitrary bytes belong in a []byte field", err)
	}
	return b, nil
}

// Unmarshal decodes CoreDet-CBOR bytes into v. Decoding determinism is not required
// (it is an encode property); re-encoding the result with Marshal reproduces canonical bytes.
func Unmarshal(b []byte, v any) error {
	return decMode.Unmarshal(b, v)
}

// UnmarshalStrict decodes CoreDet-CBOR bytes into v like Unmarshal, and also fails when a map
// carries a key that the destination struct has no field for, at any depth that decodes into a
// struct. Every object that has a closed key space decodes with it, so a key the reader does not
// know is refused instead of silently dropped: dropping one is how a writer and a reader end up
// agreeing on bytes and disagreeing on meaning.
//
// It also refuses (NullError, CORE-E4 revision 7) a CBOR undefined anywhere, and a CBOR null
// wherever the value would go into anything but a pointer, an interface or a cbor.RawMessage: a
// struct, an array, a slice, a map, a string, a byte string, a number or a bool. The decoder alone
// takes both into the zero value without a word — `81 f7` decodes into a list of one empty entry —
// and neither is how a canonical encoder writes any value. A type with its own UnmarshalCBOR is
// given its bytes as they are, null included, and answers for itself.
//
// Fields typed any or cbor.RawMessage still take whatever else they are given, and a map takes
// any key it can hold; a caller that wants those checked decodes them again into a struct. On
// error v may be partly filled and must not be used.
func UnmarshalStrict(b []byte, v any) error {
	if err := strictDecMode.Unmarshal(b, v); err != nil {
		return err
	}
	// The decoder accepted v: it is a non-nil pointer, and what b holds goes into its element.
	return refuseNulls(b, reflect.TypeOf(v).Elem())
}
