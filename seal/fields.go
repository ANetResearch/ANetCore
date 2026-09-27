package seal

import (
	"errors"
	"fmt"
	"math/bits"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/fxamacker/cbor/v2"
)

// fieldMap is an integer-keyed CBOR map with each value kept as its encoded
// bytes. Both the inner message and the outer envelope are decoded into this
// form first, so that
//   - unknown keys are visible (a struct decode drops them silently), and
//   - the signature preimage is built from the values exactly as received,
//     not from a struct re-encoding that would drop keys >= 64.
type fieldMap = map[uint64]cbor.RawMessage

// CBOR major types used in the strict field decoders.
const (
	majorUint  = 0
	majorBytes = 2
	majorText  = 3
	majorMap   = 5
)

// decodeFields decodes b as a map with unsigned integer keys. Duplicate keys,
// tags and trailing bytes are rejected by the CoreDet decoder.
func decodeFields(b []byte) (fieldMap, error) {
	// A CBOR null decodes into a nil Go map without error; require a map.
	if len(b) == 0 || b[0]>>5 != majorMap {
		return nil, errors.New("not a CBOR map")
	}
	var m fieldMap
	if err := coredet.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// firstUnknownCritical returns the smallest key below FirstIgnorableKey that
// is not in known, and whether there is one. The smallest is reported so the
// error text does not depend on map iteration order.
func firstUnknownCritical(m fieldMap, known map[uint64]bool) (uint64, bool) {
	found := false
	var least uint64
	for k := range m {
		if k < FirstIgnorableKey && !known[k] && (!found || k < least) {
			least, found = k, true
		}
	}
	return least, found
}

// The strict decoders check the CBOR major type before decoding. The
// generic decoder accepts a CBOR null for a []byte or string field and
// yields nil or ""; checking the major type keeps "null" apart from
// "empty", and the presence check keeps "absent" apart from both.

func rawUint(m fieldMap, k uint64) (uint64, error) {
	raw, ok := m[k]
	if !ok {
		return 0, fmt.Errorf("field %d missing", k)
	}
	if len(raw) == 0 || raw[0]>>5 != majorUint {
		return 0, fmt.Errorf("field %d is not an unsigned integer", k)
	}
	var v uint64
	if err := coredet.Unmarshal(raw, &v); err != nil {
		return 0, fmt.Errorf("field %d: %w", k, err)
	}
	return v, nil
}

func rawText(m fieldMap, k uint64) (string, error) {
	raw, ok := m[k]
	if !ok {
		return "", fmt.Errorf("field %d missing", k)
	}
	if len(raw) == 0 || raw[0]>>5 != majorText {
		return "", fmt.Errorf("field %d is not a text string", k)
	}
	var v string
	if err := coredet.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("field %d: %w", k, err)
	}
	return v, nil
}

func rawBytes(m fieldMap, k uint64) ([]byte, error) {
	raw, ok := m[k]
	if !ok {
		return nil, fmt.Errorf("field %d missing", k)
	}
	if len(raw) == 0 || raw[0]>>5 != majorBytes {
		return nil, fmt.Errorf("field %d is not a byte string", k)
	}
	var v []byte
	if err := coredet.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("field %d: %w", k, err)
	}
	if v == nil {
		v = []byte{}
	}
	return v, nil
}

// encodeField returns the CoreDet encoding of v for use as a fieldMap value.
// A nil []byte is written as an empty byte string rather than as null, so
// the value decodes under rawBytes.
func encodeField(v any) (cbor.RawMessage, error) {
	if b, ok := v.([]byte); ok && b == nil {
		v = []byte{}
	}
	return coredet.Marshal(v)
}

// Signature preimage keys (§3.3). They are below FirstIgnorableKey and not
// inner field keys, so a received inner that carries any of them fails the
// must-understand check before a preimage is built.
const (
	preKeyLabel = 0
	preKeyEnc   = 30
	preKeyKID   = 31
	preKeySuite = 32
)

// SigLabel is the value of preimage key 0 (§3.3).
const SigLabel = "anet-relay-sig/v1"

// sigPreimage builds the signature preimage of §3.3 from an inner field map:
// drop keys 20 (sig) and 21 (pad), add 0: SigLabel, 30: enc, 31: kid,
// 32: suite, and CoreDet-encode the result. Seal and Open both call this one
// function, Seal on the map it is about to encrypt and Open on the map it
// decrypted, so the two sides cannot compute the preimage differently.
//
// Values are copied as received. CoreDet sorts the keys; it does not
// re-encode a value, so a signer that wrote a value in a non-canonical form
// still verifies, and a receiver never needs to understand a key >= 64 to
// check that it was signed.
func sigPreimage(fields fieldMap, enc, kid []byte, suite Suite) ([]byte, error) {
	m := make(fieldMap, len(fields)+4)
	for k, v := range fields {
		switch k {
		case keySig, keyPad:
			continue
		case preKeyLabel, preKeyEnc, preKeyKID, preKeySuite:
			return nil, fmt.Errorf("field %d is reserved for the signature preimage", k)
		}
		m[k] = v
	}
	var err error
	if m[preKeyLabel], err = encodeField(SigLabel); err != nil {
		return nil, err
	}
	if m[preKeyEnc], err = encodeField(enc); err != nil {
		return nil, err
	}
	if m[preKeyKID], err = encodeField(kid); err != nil {
		return nil, err
	}
	if m[preKeySuite], err = encodeField(uint64(suite)); err != nil {
		return nil, err
	}
	return coredet.Marshal(m)
}

// Padme returns the Padmé padded length of n (Nikitin et al., "Reducing
// Metadata Leakage from Encrypted Files and Communication with PURBs",
// PETS 2019): n rounded up so that only the top floor(log2(E))+1 bits of the
// length are free, where E = floor(log2(n)). The overhead is at most about
// 12% and the number of distinct padded lengths grows as O(log log n).
func Padme(n int) int {
	if n < 2 {
		return n
	}
	e := bits.Len(uint(n)) - 1 // floor(log2(n))
	s := bits.Len(uint(e))     // floor(log2(e)) + 1, for e >= 1
	mask := (1 << (e - s)) - 1
	return (n + mask) &^ mask
}

// cborHeadLen is the length of a CBOR initial byte plus argument for n.
func cborHeadLen(n uint64) int {
	switch {
	case n < 24:
		return 1
	case n <= 0xff:
		return 2
	case n <= 0xffff:
		return 3
	case n <= 0xffffffff:
		return 5
	}
	return 9
}

// encodedLen is the length of the CoreDet encoding of m. Keys are unsigned
// integers and values are already encoded, so the length is a sum; the
// padding computation uses it to avoid encoding a large body twice.
func encodedLen(m fieldMap) int {
	n := cborHeadLen(uint64(len(m)))
	for k, v := range m {
		n += cborHeadLen(k) + len(v)
	}
	return n
}

// padLenFor returns the zero-byte count whose byte-string encoding is d bytes
// longer than the encoding of an empty byte string, if one exists. The
// encoding of n bytes is cborHeadLen(n) + n, so d = n + cborHeadLen(n) - 1.
// Where the header grows (n = 24, 256, 65536, 2^32) the sequence of d skips
// values: 24, 257, 65538 and 65539, and four more above 2^32. Those have
// no solution.
func padLenFor(d int) (int, bool) {
	if d < 0 {
		return 0, false
	}
	for _, h := range []int{1, 2, 3, 5, 9} {
		n := d - (h - 1)
		if n >= 0 && cborHeadLen(uint64(n)) == h {
			return n, true
		}
	}
	return 0, false
}

// applyPad sets fields[keyPad] to zero bytes so that the encoded map length
// is a Padmé length, and returns that length. When the Padmé length of the
// unpadded map is one of the unreachable offsets of padLenFor, the next
// Padmé length is used; the result is always a value Padme returns.
func applyPad(fields fieldMap) int {
	fields[keyPad] = cbor.RawMessage{0x40} // empty byte string
	base := encodedLen(fields)
	target := Padme(base)
	for {
		if n, ok := padLenFor(target - base); ok {
			pad, _ := encodeField(make([]byte, n)) // a byte string always encodes
			fields[keyPad] = pad
			return target
		}
		target = Padme(target + 1)
	}
}
