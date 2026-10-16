package seal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"math/bits"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/fxamacker/cbor/v2"
)

// fieldMap is an integer-keyed CBOR map with each value kept as its encoded
// bytes. The outer envelope, the Wrap and the inner message are all decoded
// into this form first, so that
//   - unknown keys are visible (a struct decode drops them silently), and
//   - the signature preimage is built from the values exactly as received,
//     not from a struct re-encoding that would drop keys >= 64.
type fieldMap = map[uint64]cbor.RawMessage

// CBOR major types used in the strict field decoders.
const (
	majorUint  = 0
	majorBytes = 2
	majorText  = 3
	majorArray = 4
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
	// The decoder also takes some spellings the core never writes: an indefinite-length map,
	// keys in another order, a longer-than-needed integer head. Each is a different byte string
	// for the same fields, so a third party could re-spell a message without breaking anything.
	// Only the canonical encoding is accepted: re-encode the fields and compare (CORE-E2/G4).
	// Values stay raw, so a nested map is held to the same rule by its own decodeFields.
	re, err := coredet.Marshal(m)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(re, b) {
		return nil, errors.New("not the canonical encoding")
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

// Signature preimage keys (core §3.3). They are not inner field keys: a
// received inner that carries 0 or 30-34 fails the must-understand check
// before a preimage is built, and sigPreimage refuses them as well.
const (
	preKeyLabel = 0
	preKeyEnc   = 30 // outer key 5, layer-1 enc
	preKeyKID   = 31 // outer key 4
	preKeySuite = 32 // outer key 3
	preKeyIKID  = 33 // Wrap key 1, CBOR null for a single layer
	preKeyEnc2  = 34 // Wrap key 2, CBOR null for a single layer
)

// SigLabel is the value of preimage key 0 (core §3.2 L3).
const SigLabel = "anet-relay-sig/v2"

// cborNull is the CBOR encoding of null, the value of preimage keys 33 and
// 34 for a single layer.
var cborNull = cbor.RawMessage{0xf6}

// sigPreimage builds the signature preimage v2 of core §3.3 from an inner
// field map: copy every key but 20 (sig) as received; replace key 9 by
// coredet(bstr(SHA-256(body))); add 0: SigLabel, 30: enc, 31: kid, 32: suite,
// 33: ikid and 34: enc2 (both CBOR null for a single layer, both byte strings
// for two); CoreDet-encode the result. Seal and Open both call this one
// function, Seal on the map it is about to encrypt and Open on the map it
// decrypted, so the two sides cannot compute the preimage differently
// (CORE-L6).
//
// Values are copied as received. CoreDet sorts the keys; it does not
// re-encode a value, so a receiver never needs to understand a key >= 64 to
// check that it was signed. Key 9 holds the digest of the body rather than
// the body, so a message can later be shown to a third party without its
// body (SS §2.4a). The second-layer values bind the layering: stripping the
// second layer, replacing enc2, or moving a message between one layer and two
// changes the preimage (SI-31).
func sigPreimage(fields fieldMap, enc, kid []byte, suite Suite, ikid, enc2 []byte) ([]byte, error) {
	if (ikid == nil) != (enc2 == nil) {
		return nil, errors.New("ikid and enc2 go together: both for two layers, neither for one")
	}
	m := make(fieldMap, len(fields)+6)
	for k, v := range fields {
		switch k {
		case keySig:
			continue
		case preKeyLabel, preKeyEnc, preKeyKID, preKeySuite, preKeyIKID, preKeyEnc2:
			return nil, fmt.Errorf("field %d is reserved for the signature preimage", k)
		}
		m[k] = v
	}
	body, err := rawBytes(fields, keyBody)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	if m[keyBody], err = encodeField(digest[:]); err != nil {
		return nil, err
	}
	for k, v := range map[uint64]any{preKeyLabel: SigLabel, preKeyEnc: enc, preKeyKID: kid, preKeySuite: uint64(suite)} {
		if m[k], err = encodeField(v); err != nil {
			return nil, err
		}
	}
	m[preKeyIKID], m[preKeyEnc2] = cborNull, cborNull
	if ikid != nil {
		if m[preKeyIKID], err = encodeField(ikid); err != nil {
			return nil, err
		}
		if m[preKeyEnc2], err = encodeField(enc2); err != nil {
			return nil, err
		}
	}
	return coredet.Marshal(m)
}

// Padme returns the Padmé padded length of n (Nikitin et al., "Reducing
// Metadata Leakage from Encrypted Files and Communication with PURBs",
// PETS 2019): n rounded up so that only the top floor(log2(E))+1 bits of the
// length are free, where E = floor(log2(n)). The overhead is at most about
// 12% and the number of distinct padded lengths grows as O(log log n).
//
// n below 2 is returned as is. So is an n whose Padmé length exceeds
// math.MaxInt (n > 2^63 - 2^56 on a 64-bit int): no message is that long,
// and rounding up would wrap to a negative length (ANet an internal note,
// found by FuzzPadme).
func Padme(n int) int {
	if n < 2 {
		return n
	}
	e := bits.Len(uint(n)) - 1 // floor(log2(n))
	s := bits.Len(uint(e))     // floor(log2(e)) + 1, for e >= 1
	mask := (1 << (e - s)) - 1
	if n > math.MaxInt-mask {
		return n
	}
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

// applyPad sets wrap[wrapKeyPad] to zero bytes so that the encoded Wrap has a
// Padmé length, and returns that length (FS-C9). Only the Wrap is padded: the
// inner and a second layer's plaintext are not. When the Padmé length of the
// map with an empty pad is one of the unreachable offsets of padLenFor, the
// next Padmé length is used; the result is always a value Padme returns.
func applyPad(wrap fieldMap) int {
	wrap[wrapKeyPad] = cbor.RawMessage{0x40} // empty byte string
	base := encodedLen(wrap)
	target := Padme(base)
	for {
		if n, ok := padLenFor(target - base); ok {
			pad, _ := encodeField(make([]byte, n)) // a byte string always encodes
			wrap[wrapKeyPad] = pad
			return target
		}
		target = Padme(target + 1)
	}
}
